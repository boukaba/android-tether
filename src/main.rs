mod arp;
mod config;
mod daemon;
mod dhcp;
mod dns_proxy;
mod error;
mod frame;
mod ipc;
mod net_types;
mod proto_driver;
mod proto_rndis;
mod rndis;
mod stats;
mod usb_device;
mod usb_io;
mod utun;

use crate::config::{DnsMode, DnsProvider, TetherConfig};
use crate::dhcp::discover;
use crate::frame::ip_to_eth;
use crate::ipc::{IpcCommand, IpcServer};
use crate::net_types::{MacAddr, ETH_BUF_SIZE, RNDIS_BUF_SIZE};
use crate::proto_driver::ProtocolDriver;
use crate::proto_rndis::RndisDriver;
use crate::stats::SharedStats;
use crate::usb_device::UsbDevice;
use crate::usb_io::UsbIo;
use crate::utun::Utun;
use log::{debug, error, info, warn};
use std::io::Write;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

static GLOBAL_RUNNING: AtomicBool = AtomicBool::new(true);

extern "C" fn sigterm_handler(_sig: i32) {
    GLOBAL_RUNNING.store(false, Ordering::SeqCst);
}

fn is_running(running: &AtomicBool) -> bool {
    running.load(Ordering::Relaxed) && GLOBAL_RUNNING.load(Ordering::Relaxed)
}

// (fn set_dns, etc. remain below)
use std::time::Duration;

/// DNS query for `opendns.com` type A — used to pre-warm encrypted DNS connections
const ROOT_DNS_QUERY: &[u8] = &[
    0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x07, b'o', b'p', b'e',
    b'n', b'd', b'n', b's', 0x03, b'c', b'o', b'm',
    0x00, 0x00, 0x01, 0x00, 0x01,
];

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

fn process_dot_serial(
    first_pkt: Vec<u8>,
    first_query: Vec<u8>,
    receiver: &mpsc::Receiver<(Vec<u8>, Vec<u8>)>,
    dot_conns: &mut Vec<crate::dns_proxy::DotPooledConn>,
    tun: &Arc<Utun>,
    warm: &Arc<AtomicBool>,
    provider: DnsProvider,
    running: &Arc<AtomicBool>,
) {
    const MAX_POOL: usize = 4;

    let mut queries = vec![(first_pkt, first_query)];
    while let Ok(item) = receiver.try_recv() {
        queries.push(item);
    }

    // Expand pool if needed (up to MAX_POOL, up to batch size)
    while dot_conns.len() < MAX_POOL.min(queries.len()) {
        match crate::dns_proxy::create_dot_conn(provider) {
            Ok(conn) => dot_conns.push(conn),
            Err(e) => {
                warn!("DoT pool expand failed: {e}");
                break;
            }
        }
    }

    // Drop stale connections (servers idle-timeout ~60s, refresh at 45s)
    // Connections carry their own creation time, stale ones will fail quickly
    // and get reconnected by workers. No need to pre-check.

    let num_workers = dot_conns.len().max(1);
    debug!("DNS resolver: DoT pool of {num_workers} conns for {} queries", queries.len());

    let (return_tx, return_rx) = mpsc::channel();
    let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let queries = Arc::new(queries);

    let mut handles = Vec::new();
    for _ in 0..num_workers {
        let conn = if let Some(c) = dot_conns.pop() {
            c
        } else {
            match crate::dns_proxy::create_dot_conn(provider) {
                Ok(c) => c,
                Err(e) => { warn!("DoT worker conn failed: {e}"); continue; }
            }
        };
        let tun = tun.clone();
        let warm = warm.clone();
        let running = running.clone();
        let return_tx = return_tx.clone();
        let counter = counter.clone();
        let queries = queries.clone();

        handles.push(std::thread::spawn(move || {
            let mut conn = conn;
            loop {
                let i = counter.fetch_add(1, Ordering::SeqCst);
                if i >= queries.len() || !running.load(Ordering::SeqCst) {
                    let _ = return_tx.send(conn);
                    break;
                }
                let (ref orig_pkt, ref dns_query) = queries[i];
                let resp = match crate::dns_proxy::dot_query_pooled(&mut conn, dns_query) {
                    Ok(r) => Some(r),
                    Err(e) => {
                        debug!("DoT worker: {e}, reconnecting...");
                        match crate::dns_proxy::create_dot_conn(provider) {
                            Ok(new_conn) => {
                                conn = new_conn;
                                info!("DoT worker reconnected");
                                crate::dns_proxy::dot_query_pooled(&mut conn, dns_query).ok()
                            }
                            Err(e2) => { warn!("DoT reconnect failed: {e2}"); None }
                        }
                    }
                };
                if let Some(dns_resp) = resp {
                    if !warm.load(Ordering::SeqCst) {
                        info!("first DoH/DoT response received — switching to encrypted-only DNS");
                        warm.store(true, Ordering::SeqCst);
                    }
                    let reply = crate::dns_proxy::build_reply(orig_pkt, &dns_resp);
                    match tun.write(&reply) {
                        Ok(n) => debug!("DNS resolver: wrote {n} byte reply to utun"),
                        Err(e) => warn!("DNS resolver: utun write failed: {e}"),
                    }
                }
            }
        }));
    }

    for h in handles { let _ = h.join(); }
    
    // Reclaim connections returned by workers
    while let Ok(conn) = return_rx.try_recv() {
        dot_conns.push(conn);
    }
    // Trim to MAX_POOL
    dot_conns.truncate(MAX_POOL);
}

fn run_session(
    config: &TetherConfig,
    ipc: Option<&IpcServer>,
    running: &Arc<AtomicBool>,
) -> bool {
    let mut drv: Box<dyn ProtocolDriver> = Box::new(RndisDriver::new());

    info!("looking for Android {} device...", drv.name());
    let usb = match UsbDevice::find_rndis() {
        Ok(d) => d,
        Err(e) => {
            error!("{e}");
            return false;
        }
    };

    info!("initializing {}...", drv.name());
    if let Err(e) = drv.init(&usb) {
        error!("init failed: {e}");
        return false;
    }

    let device_mac = drv.mac();
    let (ip, gateway, netmask, dns1, dns2) = if let Some(static_ip) = config.static_ip {
        let gw = config.gateway.unwrap_or(Ipv4Addr::new(192, 168, 42, 129));
        info!("using static IP: {static_ip}");
        (static_ip, gw, config.netmask, Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(8, 8, 4, 4))
    } else {
        info!("performing DHCP...");
        match discover(&usb, &MacAddr(device_mac)) {
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
            return false;
        }
    };

    if let Err(e) = tun.configure(&ip.to_string(), &gateway.to_string(), &netmask.to_string()) {
        error!("interface config failed: {e}");
        return false;
    }

    if !config.no_dns {
        let (cfg_dns1, cfg_dns2) = if config.dns_mode != DnsMode::System {
            // DoH/DoT: only configure gateway as DNS — we intercept all queries
            (dns1, dns1)
        } else {
            (dns1, dns2)
        };
        set_dns(cfg_dns1, cfg_dns2);
        Utun::register_service(
            &tun.ifname, &ip.to_string(), &gateway.to_string(),
            &netmask.to_string(), &cfg_dns1.to_string(), &cfg_dns2.to_string(),
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

    let _ = arp::send_gratuitous(&usb, &host_mac, ip);

    info!("tethering active on {} ({})", tun.ifname, ip);
    info!("gateway: {gateway}, DNS: {dns1}, {dns2}");

    if let Some(ipc) = ipc {
        ipc.send_state("connected", Some(&ip.to_string()), Some(&tun.ifname));
    }

    let running_bridge = Arc::new(AtomicBool::new(true));
    let device_gone = Arc::new(AtomicBool::new(false));
    let stats = Arc::new(SharedStats::default());

    let drv = Arc::new(drv);

    // Shared gateway MAC: RX thread learns it from first non-broadcast frame;
    // TX thread uses it as destination for all outgoing Ethernet frames.
    // Initialized to broadcast (matching C code approach).
    let gateway_mac = Arc::new(Mutex::new([0xFF; 6]));

    // TX queue: bounded channel prevents accumulating packets when USB is slow
    let (tx_sender, tx_receiver) = mpsc::sync_channel::<Vec<u8>>(4096);

    // DNS resolver thread for DoH/DoT: avoids blocking TX thread on encrypted DNS calls
    let (dns_sender, dns_receiver) = mpsc::channel::<(Vec<u8>, Vec<u8>)>();
    let doh_warmed_up = Arc::new(AtomicBool::new(false));
    let dns_handle = if config.dns_mode != DnsMode::System {
        let dns_tun = tun.clone();
        let dns_bridge = running_bridge.clone();
        let dns_mode_val = config.dns_mode;
        let dns_provider_val = config.dns_provider;
        let doh_warm = doh_warmed_up.clone();
        info!("starting DNS resolver thread (mode={dns_mode_val:?}, provider={dns_provider_val:?})");
        Some(std::thread::spawn(move || {
            let doh_agent = if matches!(dns_mode_val, DnsMode::DoH) {
                match crate::dns_proxy::create_doh_agent(dns_provider_val) {
                    Ok(a) => {
                        info!("DoH agent created (connection reuse enabled)");
                        // Pre-warm with a root DNS query
                        let warmup = ROOT_DNS_QUERY;
                        if let Some(_) = crate::dns_proxy::doh_resolve(&a, dns_provider_val, warmup) {
                            info!("DoH pre-warmed — encrypted-only from first query");
                            doh_warm.store(true, Ordering::SeqCst);
                        }
                        Some(a)
                    }
                    Err(e) => {
                        warn!("DoH agent creation failed: {e}");
                        None
                    }
                }
            } else {
                None
            };
            let mut dot_conns: Vec<crate::dns_proxy::DotPooledConn> = Vec::new();

            // Pre-warm DoT connection pool
            if matches!(dns_mode_val, DnsMode::DoT) {
                match crate::dns_proxy::create_dot_conn(dns_provider_val) {
                    Ok(mut conn) => {
                        if crate::dns_proxy::dot_query_pooled(&mut conn, ROOT_DNS_QUERY).is_ok() {
                            info!("DoT pre-warmed — encrypted-only from first query");
                            dot_conns.push(conn);
                            doh_warm.store(true, Ordering::SeqCst);
                        }
                    }
                    Err(e) => warn!("DoT warm-up failed: {e}"),
                }
            }


            while dns_bridge.load(Ordering::SeqCst) {
                match dns_receiver.recv_timeout(std::time::Duration::from_millis(200)) {
                    Ok((orig_pkt, dns_query)) => {
                        if matches!(dns_mode_val, DnsMode::DoH) {
                            // DoH: drain batch, process concurrently
                            let mut batch = vec![(orig_pkt, dns_query)];
                            while let Ok(item) = dns_receiver.try_recv() {
                                batch.push(item);
                            }
                            debug!("DNS resolver: DoH batch of {} queries", batch.len());
                            let agent = doh_agent.clone();
                            let tun = dns_tun.clone();
                            let warm = doh_warm.clone();
                            let prov = dns_provider_val;
                            let handles: Vec<_> = batch.into_iter().map(|(orig, query)| {
                                let agent = agent.clone();
                                let tun = tun.clone();
                                let warm = warm.clone();
                                std::thread::spawn(move || {
                                    let resp = agent.as_ref()
                                        .and_then(|a| crate::dns_proxy::doh_resolve(a, prov, &query));
                                    if let Some(dns_resp) = resp {
                                        if !warm.load(Ordering::SeqCst) {
                                            info!("first encrypted DNS response received — switching to encrypted-only DNS");
                                            warm.store(true, Ordering::SeqCst);
                                        }
                                        let reply = crate::dns_proxy::build_reply(&orig, &dns_resp);
                                        match tun.write(&reply) {
                                            Ok(n) => debug!("DNS resolver: wrote {n} byte reply to utun"),
                                            Err(e) => warn!("DNS resolver: utun write failed: {e}"),
                                        }
                                    }
                                })
                            }).collect();
                            for h in handles { let _ = h.join(); }

                        } else {
                            // DoT: serial with pooled connection
                            process_dot_serial(
                                orig_pkt, dns_query,
                                &dns_receiver,
                                &mut dot_conns,
                                &dns_tun,
                                &doh_warm,
                                dns_provider_val,
                                &dns_bridge,
                            );
                        }
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }
            info!("DNS resolver thread stopped");
        }))
    } else {
        None
    };

    // I/O thread: owns USB endpoints, handles RX (multi-URB submit/wait) + TX (drains channel)
    let (ep_in, ep_out) = usb.take_endpoints();
    let tun_io = tun.clone();
    let drv_io = drv.clone();
    let stats_io = stats.clone();
    let bridge_io = running_bridge.clone();
    let gw_mac_io = gateway_mac.clone();
    let tx_receiver_io = tx_receiver;
    let device_gone_io = device_gone.clone();

    let io_handle = std::thread::spawn(move || {
        let mut usb_io = UsbIo::new(ep_in, ep_out);
        usb_io.run(
            tun_io,
            tx_receiver_io,
            drv_io,
            stats_io,
            host_mac,
            ip,
            gw_mac_io,
            bridge_io,
            device_gone_io,
        );
    });

    // Main thread no longer holds USB — keepalive is sent via tx_sender

    // TX thread: utun read (poll) -> ip_to_eth -> RNDIS wrap -> push to tx_sender
    let tun_tx = tun.clone();
    let bridge_tx = running_bridge.clone();
    let gw_mac_tx = gateway_mac.clone();
    let tx_sender_tx = tx_sender.clone();
    let drv_tx = drv.clone();
    let dns_mode = config.dns_mode;
    let our_ip_u32 = u32::from(ip);
    let gw_ip_u32 = u32::from(gateway);
    let dns_sender_tx = dns_sender.clone();
    let doh_warm_tx = doh_warmed_up.clone();

    let tx_handle = std::thread::spawn(move || {
        let mut tbuf = [0u8; ETH_BUF_SIZE + 256];
        let mut ebuf = [0u8; ETH_BUF_SIZE];
        let mut rbuf = [0u8; RNDIS_BUF_SIZE];
        let our_mac = host_mac;
        let fd = tun_tx.fd;
        let mut tx_log_count: u64 = 0;

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

                if dns_mode != DnsMode::System {
                    if let Some(dns_len) = crate::dns_proxy::is_dns_to_gateway(
                        &tbuf[..tlen], our_ip_u32, gw_ip_u32,
                    ) {
                        let dns_query = tbuf[tlen - dns_len..tlen].to_vec();
                        let orig_pkt = tbuf[..tlen].to_vec();
                        debug!("TX: intercepted DNS query ({} bytes), forwarding to resolver", dns_query.len());
                        if dns_sender_tx.send((orig_pkt, dns_query)).is_err() {
                            warn!("TX: DNS resolver channel full/disconnected");
                        }
                        if doh_warm_tx.load(Ordering::SeqCst) {
                            continue; // DoH/DoT is active, skip phone DNS
                        }
                    }
                    // warming up: also forward to phone until first encrypted response arrives
                }

                if tlen >= 4 && tx_log_count < 10 {
                    let af = u32::from_be_bytes(tbuf[..4].try_into().unwrap());
                    let ip_proto = if tlen > 4 { tbuf[4] >> 4 } else { 0 };
                    debug!("TX utun pkt: af={af} ip_ver={ip_proto} len={tlen}");
                    tx_log_count += 1;
                }
                let gw = *gw_mac_tx.lock().unwrap();
                let elen = match ip_to_eth(&tbuf[..tlen], &mut ebuf, &our_mac, &gw) {
                    Ok(n) => n,
                    Err(_) => continue,
                };
                if elen == 0 {
                    continue;
                }

                let rlen = match drv_tx.wrap_frame(&ebuf[..elen], &mut rbuf) {
                    Ok(n) => n,
                    Err(_) => continue,
                };

                if tx_sender_tx.send(rbuf[..rlen].to_vec()).is_err() {
                    break;
                }
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
            if let Ok(rlen) = drv.wrap_frame(&arp_buf[..arp_len], &mut rndis_buf) {
                let _ = tx_sender.try_send(rndis_buf[..rlen].to_vec());
            }
            last_keepalive = now;
        }

        if now.duration_since(last_stats).as_secs() >= 5 {
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

        let _ = std::io::stderr().flush();

        std::thread::sleep(Duration::from_millis(100));
    }

    running_bridge.store(false, Ordering::SeqCst);
    if io_handle.join().is_err() {
        warn!("IO thread panicked");
        device_gone.store(true, Ordering::SeqCst);
    }
    let _ = tx_handle.join();
    if let Some(handle) = dns_handle {
        let _ = handle.join();
    }

    let was_disconnected = device_gone.load(Ordering::SeqCst);

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

    if let Some(ipc) = ipc {
        ipc.send_state("disconnected", None, None);
    }

    was_disconnected
}

fn main() {
    let config = match TetherConfig::from_cli() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    };

    // Install/uninstall handle themselves, root check done inside
    if config.install {
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("error: --install must be run as root (use sudo)");
            std::process::exit(1);
        }
        daemon::install_daemon(&config);
        return;
    }

    if config.uninstall {
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("error: --uninstall must be run as root (use sudo)");
            std::process::exit(1);
        }
        daemon::uninstall_daemon();
        return;
    }

    if unsafe { libc::geteuid() } != 0 {
        eprintln!("error: this tool must be run as root (use sudo)");
        std::process::exit(1);
    }

    if config.daemon {
        daemon::setup_daemon_logging(config.log_level == log::LevelFilter::Debug);
    } else {
        env_logger::Builder::new()
            .filter_level(config.log_level)
            .format_timestamp_secs()
            .init();
    }

    let running = Arc::new(AtomicBool::new(true));

    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
        GLOBAL_RUNNING.store(false, Ordering::SeqCst);
    })
    .expect("failed to set Ctrl-C handler");

    // Handle SIGTERM for launchd shutdown
    unsafe {
        libc::signal(libc::SIGTERM, sigterm_handler as libc::sighandler_t);
    }

    if !config.daemon {
        info!("=== Android USB Tethering for macOS (Rust) ===");
    }

    let ipc = IpcServer::new();
    let ipc_opt: Option<&IpcServer> = if config.watch_mode { Some(&ipc) } else { None };

    if config.watch_mode {
        ipc.send_state("idle", None, None);

        while is_running(&running) {
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
            if reconnected && is_running(&running) {
                info!("device disconnected, waiting for reconnect...");
                if let Some(ipc) = ipc_opt {
                    ipc.send_state("watching", None, None);
                }
                for _ in 0..6 {
                    if !is_running(&running) {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(500));
                }
            } else if is_running(&running) {
                std::thread::sleep(Duration::from_millis(1000));
            }
        }
    } else {
        run_session(&config, ipc_opt, &running);

        while is_running(&running) {
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
