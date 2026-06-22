mod arp;
mod config;
mod dhcp;
mod error;
mod frame;
mod ipc;
mod net_types;
mod proto_driver;
mod proto_rndis;
mod rndis;
mod stats;
mod usb_device;
mod utun;

use crate::config::TetherConfig;
use crate::dhcp::discover;
use crate::frame::{eth_to_utun, ip_to_eth};
use crate::ipc::{IpcCommand, IpcServer};
use crate::net_types::{MacAddr, ETH_BUF_SIZE, RNDIS_BUF_SIZE};
use crate::proto_driver::ProtocolDriver;
use crate::proto_rndis::RndisDriver;
use crate::stats::SharedStats;
use crate::usb_device::UsbDevice;
use crate::utun::Utun;
use log::{debug, error, info, warn};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

fn scutil_run(script: &str) {
    use std::io::Write;
    if let Ok(mut child) = std::process::Command::new("scutil")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(script.as_bytes());
        }
        let _ = child.wait();
    }
}

fn set_dns(dns1: Ipv4Addr, dns2: Ipv4Addr) {
    let script = format!(
        "d.init\nd.add ServerAddresses * {} {}\nset State:/Network/Global/DNS\nquit\n",
        dns1, dns2
    );
    scutil_run(&script);
    let _ = std::process::Command::new("sh")
        .arg("-c")
        .arg("dscacheutil -flushcache 2>/dev/null; killall -HUP mDNSResponder 2>/dev/null")
        .status();
    info!("DNS configured: {dns1}, {dns2}");
}

fn run_session(
    config: &TetherConfig,
    ipc: Option<&IpcServer>,
    running: &Arc<AtomicBool>,
) -> bool {
    let mut drv: Box<dyn ProtocolDriver> = Box::new(RndisDriver::new());

    info!("looking for Android {} device...", drv.name());
    let usb = match UsbDevice::find_rndis() {
        Ok(d) => Arc::new(Mutex::new(d)),
        Err(e) => {
            error!("{e}");
            return running.load(Ordering::Relaxed);
        }
    };

    info!("initializing {}...", drv.name());
    {
        let usb_lock = usb.lock().unwrap();
        if let Err(e) = drv.init(&usb_lock) {
            error!("init failed: {e}");
            return running.load(Ordering::Relaxed);
        }
    }

    let device_mac = drv.mac();
    let (ip, gateway, netmask, dns1, dns2) = if let Some(static_ip) = config.static_ip {
        let gw = config.gateway.unwrap_or(Ipv4Addr::new(192, 168, 42, 129));
        info!("using static IP: {static_ip}");
        (static_ip, gw, config.netmask, Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(8, 8, 4, 4))
    } else {
        info!("performing DHCP...");
        match discover(&usb.lock().unwrap(), &MacAddr(device_mac)) {
            Ok(lease) => (lease.ip, lease.gateway, lease.netmask, lease.dns1, lease.dns2),
            Err(e) => {
                warn!("DHCP failed: {e}, using defaults");
                (
                    Ipv4Addr::new(192, 168, 42, 100),
                    Ipv4Addr::new(192, 168, 42, 129),
                    Ipv4Addr::new(255, 255, 255, 0),
                    Ipv4Addr::new(8, 8, 8, 8),
                    Ipv4Addr::new(8, 8, 4, 4),
                )
            }
        }
    };

    let tun = match Utun::create() {
        Ok(t) => Arc::new(t),
        Err(e) => {
            error!("utun creation failed: {e}");
            return running.load(Ordering::Relaxed);
        }
    };

    if let Err(e) = tun.configure(&ip.to_string(), &gateway.to_string(), &netmask.to_string()) {
        error!("interface config failed: {e}");
        return running.load(Ordering::Relaxed);
    }

    if !config.no_dns {
        set_dns(dns1, dns2);
        Utun::register_service(
            &tun.ifname, &ip.to_string(), &gateway.to_string(),
            &netmask.to_string(), &dns1.to_string(), &dns2.to_string(),
        );
    } else if !config.no_route {
        Utun::register_service(
            &tun.ifname, &ip.to_string(), &gateway.to_string(),
            &netmask.to_string(), "", "",
        );
    }

    std::thread::sleep(Duration::from_millis(500));

    if !config.no_route {
        let _ = tun.set_default_route(&gateway.to_string());
    }

    let host_mac = device_mac;

    let _was_bound = true;
    {
        let usb_lock = usb.lock().unwrap();
        let _ = arp::send_gratuitous(&usb_lock, &host_mac, ip);
    }

    info!("tethering active on {} ({})", tun.ifname, ip);
    info!("gateway: {gateway}, DNS: {dns1}, {dns2}");

    if let Some(ipc) = ipc {
        ipc.send_state("connected", Some(&ip.to_string()), Some(&tun.ifname));
    }

    let running_bridge = Arc::new(AtomicBool::new(true));
    let stats = Arc::new(SharedStats::default());

    let drv = Arc::new(Mutex::new(drv));

    // Shared gateway MAC: RX thread learns it from first non-broadcast frame;
    // TX thread uses it as destination for all outgoing Ethernet frames.
    // Initialized to broadcast (matching C code approach).
    let gateway_mac = Arc::new(Mutex::new([0xFF; 6]));

    // TX queue: TX thread pushes RNDIS-wrapped frames here;
    // RX thread sends them via USB (avoids lock contention on usb).
    let tx_queue: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));

    // RX thread: USB (bulk in) -> RNDIS unwrap -> [ARP handling + gw MAC learning]
    //            -> eth_to_utun -> utun write
    //            -> also drains tx_queue and sends via USB
    let usb_rx = usb.clone();
    let drv_rx = drv.clone();
    let tun_rx = tun.clone();
    let stats_rx = stats.clone();
    let running_rx = running.clone();
    let bridge_rx = running_bridge.clone();
    let host_mac_rx = host_mac;
    let our_ip = ip;
    let gw_mac_rx = gateway_mac.clone();
    let tx_q_rx = tx_queue.clone();
    let drv_rx2 = drv.clone();

    let rx_handle = std::thread::spawn(move || {
        let mut rndis_buf = [0u8; RNDIS_BUF_SIZE];
        let mut utun_buf = [0u8; ETH_BUF_SIZE + 4];
        let mut frame_logged: u64 = 0;
        let mut usb_rx_err_count: u32 = 0;
        let mut recv_zero_count: u32 = 0;
        let mut tx_sent_count: u64 = 0;

        while running_rx.load(Ordering::SeqCst) && bridge_rx.load(Ordering::SeqCst) {
            // Receive first, then send queued TX data (prioritize RX)
            let n = {
                let usb_lock = usb_rx.lock().unwrap();
                usb_lock.recv_bulk(&mut rndis_buf, 200)
            };
            let n = match n {
                Ok(0) => {
                    recv_zero_count += 1;
                    if recv_zero_count % 100 == 0 {
                        debug!("USB RX: {} consecutive timeouts (0 bytes)", recv_zero_count);
                    }
                    0
                }
                Ok(n) => {
                    usb_rx_err_count = 0;
                    recv_zero_count = 0;
                    n
                }
                Err(e) => {
                    usb_rx_err_count += 1;
                    if usb_rx_err_count >= 5 {
                        debug!("USB RX error #{usb_rx_err_count}: {e}");
                        usb_rx_err_count = 0;
                    }
                    0
                }
            };
            if n > 0 {
                debug!("USB bulk IN: {} bytes", n);

                let drv_lock = drv_rx.lock().unwrap();
                let mut had_error = false;
                let mut arp_reply = Vec::new();

                let mut on_frame = |frame: &[u8]| {
                    if had_error {
                        return;
                    }
                    if frame.len() < 14 {
                        return;
                    }
                    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);

                    if frame_logged < 10 {
                        debug!("RX frame #{}: ethertype=0x{ethertype:04x} len={}", frame_logged + 1, frame.len());
                        frame_logged += 1;
                    }

                    let fsrc = &frame[6..12];

                    if fsrc[0] != 0xFF {
                        let mut gw = gw_mac_rx.lock().unwrap();
                        if *gw != *fsrc {
                            gw.copy_from_slice(fsrc);
                            debug!(
                                "gateway MAC now: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                                gw[0], gw[1], gw[2], gw[3], gw[4], gw[5]
                            );
                        }
                    }

                    if ethertype == crate::net_types::ARP_ETHERTYPE {
                        let mut reply_buf = [0u8; crate::net_types::ETH_BUF_SIZE];
                        if let Ok(len) = arp::handle_request(frame, &mut reply_buf, &host_mac_rx, our_ip) {
                            if len > 0 {
                                debug!("handled ARP request, queueing reply ({} bytes)", len);
                                arp_reply.extend_from_slice(&reply_buf[..len]);
                            }
                        }
                        return;
                    }

                    match eth_to_utun(frame, &mut utun_buf) {
                        Ok(0) => {}
                        Ok(utun_len) => {
                            let _ = tun_rx.write(&utun_buf[..utun_len]);
                            stats_rx.rx_pkts.fetch_add(1, Ordering::Relaxed);
                            stats_rx.rx_bytes.fetch_add(frame.len() as u64, Ordering::Relaxed);
                        }
                        Err(_) => {
                            had_error = true;
                        }
                    }
                };

                if let Err(e) = drv_lock.unwrap_data(&rndis_buf[..n], &mut on_frame) {
                    debug!("unwrap_data error: {e}");
                }
                drop(drv_lock);

                if !arp_reply.is_empty() {
                    let mut rndis_buf2 = [0u8; RNDIS_BUF_SIZE];
                    {
                        let drv_lock = drv_rx2.lock().unwrap();
                        if let Ok(rlen) = drv_lock.wrap_frame(&arp_reply, &mut rndis_buf2) {
                            let usb_lock = usb_rx.lock().unwrap();
                            let _ = usb_lock.send_bulk(&rndis_buf2[..rlen]);
                        }
                    }
                }
            }

            // Drain TX queue after processing RX
            {
                let packets: Vec<Vec<u8>> = tx_q_rx.lock().unwrap().drain(..).collect();
                if !packets.is_empty() {
                    let usb_lock = usb_rx.lock().unwrap();
                    for pkt in &packets {
                        match usb_lock.send_bulk(pkt) {
                            Ok(_) => {
                                tx_sent_count += 1;
                                stats_rx.tx_pkts.fetch_add(1, Ordering::Relaxed);
                                stats_rx.tx_bytes.fetch_add(pkt.len() as u64, Ordering::Relaxed);
                            }
                            Err(e) => {
                                debug!("TX send_bulk failed: {e}");
                            }
                        }
                    }
                    if tx_sent_count % 50 == 0 {
                        debug!("RX thread: {} TX packets sent to USB", tx_sent_count);
                    }
                }
            }
        }
    });

    // TX thread: utun read (poll) -> ip_to_eth -> RNDIS wrap -> push to tx_queue
    let tun_tx = tun.clone();
    let stats_tx = stats.clone();
    let bridge_tx = running_bridge.clone();
    let gw_mac_tx = gateway_mac.clone();
    let tx_q_tx = tx_queue.clone();
    let drv_tx = drv.clone();

    let tx_handle = std::thread::spawn(move || {
        let mut tbuf = [0u8; ETH_BUF_SIZE + 256];
        let mut ebuf = [0u8; ETH_BUF_SIZE];
        let mut rbuf = [0u8; RNDIS_BUF_SIZE];
        let our_mac = host_mac;
        let fd = tun_tx.fd;

        while bridge_tx.load(Ordering::SeqCst) {
            let mut poll_fds = [libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            }];
            let pret = unsafe { libc::poll(poll_fds.as_mut_ptr(), 1, 100) };
            if pret <= 0 || poll_fds[0].revents & libc::POLLIN == 0 {
                continue;
            }
            if !bridge_tx.load(Ordering::SeqCst) {
                break;
            }

            for _batch in 0..64 {
                let tlen = match tun_tx.read(&mut tbuf) {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(_) => break,
                };
                if !bridge_tx.load(Ordering::SeqCst) {
                    break;
                }
                if tlen >= 4 {
                    let af = u32::from_be_bytes(tbuf[..4].try_into().unwrap());
                    if stats_tx.tx_pkts.load(Ordering::Relaxed) < 10 {
                        let ip_proto = if tlen > 4 { tbuf[4] >> 4 } else { 0 };
                        debug!("TX utun pkt: af={af} ip_ver={ip_proto} len={tlen}");
                    }
                }
                let gw = *gw_mac_tx.lock().unwrap();
                let elen = match ip_to_eth(&tbuf[..tlen], &mut ebuf, &our_mac, &gw) {
                    Ok(n) => n,
                    Err(_) => continue,
                };
                if elen == 0 {
                    continue;
                }

                let rlen = {
                    let drv_lock = drv_tx.lock().unwrap();
                    match drv_lock.wrap_frame(&ebuf[..elen], &mut rbuf) {
                        Ok(n) => n,
                        Err(_) => continue,
                    }
                };

                tx_q_tx.lock().unwrap().push(rbuf[..rlen].to_vec());
            }
        }
    });

    // Main loop: keepalive, stats, IPC
    let mut last_keepalive = std::time::Instant::now();
    let mut last_stats = std::time::Instant::now();
    let mut prev_tx_bytes: u64 = 0;
    let mut prev_rx_bytes: u64 = 0;

    while running.load(Ordering::SeqCst) && running_bridge.load(Ordering::SeqCst) {
        let now = std::time::Instant::now();

        if now.duration_since(last_keepalive).as_secs() >= 5 {
            // Send a dummy ARP packet as keepalive (keeps RNDIS data path alive)
            let mut arp_buf = [0u8; crate::net_types::ETH_BUF_SIZE];
            let mut rndis_buf = [0u8; RNDIS_BUF_SIZE];
            let arp_len = {
                use crate::net_types::{EthHdr, ArpPacket, ARP_ETHERTYPE, ARP_HW_ETHERNET, ARP_OP_REQUEST};
                let total = std::mem::size_of::<EthHdr>() + std::mem::size_of::<ArpPacket>();
                let eth = EthHdr {
                    dst: [0xFF; 6],
                    src: host_mac,
                    ethertype: ARP_ETHERTYPE.to_be(),
                };
                unsafe { *(arp_buf.as_mut_ptr() as *mut EthHdr) = eth };
                let arp = ArpPacket {
                    hw_type: ARP_HW_ETHERNET.to_be(),
                    proto_type: 0x0800u16.to_be(),
                    hw_len: 6,
                    proto_len: 4,
                    opcode: ARP_OP_REQUEST.to_be(),
                    sender_mac: host_mac,
                    sender_ip: u32::from(ip).to_be(),
                    target_mac: [0xFF; 6],
                    target_ip: 0u32.to_be(),
                };
                unsafe { *(arp_buf.as_mut_ptr().add(std::mem::size_of::<EthHdr>()) as *mut ArpPacket) = arp };
                total
            };
            {
                let drv_lock = drv.lock().unwrap();
                if let Ok(rlen) = drv_lock.wrap_frame(&arp_buf[..arp_len], &mut rndis_buf) {
                    tx_queue.lock().unwrap().push(rndis_buf[..rlen].to_vec());
                }
            }
            last_keepalive = now;
        }

        if now.duration_since(last_stats).as_secs() >= 1 {
            let elapsed = now.duration_since(last_stats).as_secs_f64();
            if elapsed > 0.0 {
                let cur_tx = stats.tx_bytes.load(Ordering::Relaxed);
                let cur_rx = stats.rx_bytes.load(Ordering::Relaxed);
                let tx_mbps = (cur_tx - prev_tx_bytes) as f64 * 8.0 / elapsed / 1e6;
                let rx_mbps = (cur_rx - prev_rx_bytes) as f64 * 8.0 / elapsed / 1e6;
                let tx_pkts = stats.tx_pkts.load(Ordering::Relaxed);
                let rx_pkts = stats.rx_pkts.load(Ordering::Relaxed);

                info!("speed: TX {tx_mbps:.1} Mbps, RX {rx_mbps:.1} Mbps");
                debug!("totals: TX {} pkts, RX {} pkts", tx_pkts, rx_pkts);

                if let Some(ipc) = ipc {
                    ipc.send_stats(&crate::stats::TetherStats {
                        tx_mbps,
                        rx_mbps,
                        tx_bytes: cur_tx,
                        rx_bytes: cur_rx,
                        tx_pkts,
                        rx_pkts,
                    });
                }

                prev_tx_bytes = cur_tx;
                prev_rx_bytes = cur_rx;
            }
            last_stats = now;

            if let Some(ipc) = ipc {
                match ipc.poll() {
                    IpcCommand::Stop => {
                        info!("IPC stop received");
                        running_bridge.store(false, Ordering::Relaxed);
                        break;
                    }
                    IpcCommand::Disable => {
                        info!("IPC disable received");
                        running_bridge.store(false, Ordering::Relaxed);
                        break;
                    }
                    _ => {}
                }
            }
        }

        std::thread::sleep(Duration::from_millis(100));
    }

    running_bridge.store(false, Ordering::SeqCst);
    let _ = rx_handle.join();
    let _ = tx_handle.join();

    if _was_bound {
        info!("restoring network state...");
        if !config.no_route {
            let _ = std::process::Command::new("sh")
                .arg("-c")
                .arg("route delete -net 0.0.0.0/1 2>/dev/null")
                .status();
            let _ = std::process::Command::new("sh")
                .arg("-c")
                .arg("route delete -net 128.0.0.0/1 2>/dev/null")
                .status();
        }
        Utun::unregister_service();
        if !config.no_dns {
            scutil_run("remove State:/Network/Global/DNS\nquit\n");
        }
    }

    if let Some(ipc) = ipc {
        ipc.send_state("disconnected", None, None);
    }

    false
}

fn main() {
    let config = match TetherConfig::from_cli() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    };

    if unsafe { libc::geteuid() } != 0 {
        eprintln!("error: this tool must be run as root (use sudo)");
        std::process::exit(1);
    }

    env_logger::Builder::new()
        .filter_level(config.log_level)
        .format_timestamp_secs()
        .init();

    let running = Arc::new(AtomicBool::new(true));

    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .expect("failed to set Ctrl-C handler");

    info!("=== Android USB Tethering for macOS (Rust) ===");

    let ipc = IpcServer::new();
    let ipc_opt: Option<&IpcServer> = if config.watch_mode { Some(&ipc) } else { None };

    if config.watch_mode {
        ipc.send_state("idle", None, None);

        while running.load(Ordering::Relaxed) {
            if let Some(ipc) = ipc_opt {
                match ipc.poll() {
                    IpcCommand::Disable => {
                        info!("auto-connect disabled");
                        ipc.send_state("idle", None, None);
                        std::thread::sleep(Duration::from_millis(500));
                        continue;
                    }
                    IpcCommand::Enable | IpcCommand::Status => {
                        info!("auto-connect enabled");
                        ipc.send_state("watching", None, None);
                    }
                    IpcCommand::Stop => {}
                    IpcCommand::None => {}
                }
            }

            let reconnected = run_session(&config, ipc_opt, &running);
            if reconnected && running.load(Ordering::Relaxed) {
                info!("device disconnected, waiting for reconnect...");
                if let Some(ipc) = ipc_opt {
                    ipc.send_state("watching", None, None);
                }
                for _ in 0..6 {
                    if !running.load(Ordering::Relaxed) {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(500));
                }
            } else if running.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(1000));
            }
        }
    } else {
        run_session(&config, ipc_opt, &running);

        while running.load(Ordering::Relaxed) {
            if let Some(ipc) = ipc_opt {
                if ipc.poll() == IpcCommand::Stop {
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }

    info!("done.");
}
