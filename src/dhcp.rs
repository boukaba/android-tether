use crate::error::{Result, TetherError};
use crate::net_types::{
    DhcpLease, DhcpPacket, EthHdr, MacAddr, DEFAULT_DNS1, DEFAULT_DNS2, DEFAULT_GATEWAY,
    DEFAULT_NETMASK, DEFAULT_STATIC_IP, DHCP_CLIENT_PORT, DHCP_MAGIC_COOKIE, DHCP_SERVER_PORT,
    ETH_BUF_SIZE, RNDIS_BUF_SIZE,
};
use crate::rndis;
const DHCP_FIXED_SIZE: usize = 240;
use crate::usb_device::UsbDevice;
use log::{info, warn};
use std::net::Ipv4Addr;

fn checksum(iph: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in iph.chunks(2) {
        if chunk.len() == 2 {
            sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
        }
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}

fn build_discover(buf: &mut [u8], mac: &[u8; 6], xid: u32) -> Result<usize> {
    let eth_size = std::mem::size_of::<EthHdr>();
    let ip_size = 20usize;
    let udp_size = 8usize;
    let dhcp_min_size = 300usize;
    let total = eth_size + dhcp_min_size;

    if buf.len() < total {
        return Err(TetherError::BufferTooSmall { need: total, got: buf.len() });
    }

    buf.fill(0);

    let eth = EthHdr {
        dst: [0xFF; 6],
        src: *mac,
        ethertype: 0x0800u16.to_be(),
    };
    let eth_ptr = buf.as_mut_ptr() as *mut EthHdr;
    unsafe { eth_ptr.write_unaligned(eth) };

    let ip_start = eth_size;
    let udp_start = ip_start + ip_size;
    let dhcp_start = udp_start + udp_size;

    buf[ip_start] = 0x45;
    buf[ip_start + 8] = 64;
    buf[ip_start + 9] = 0x11;

    buf[udp_start] = (DHCP_CLIENT_PORT >> 8) as u8;
    buf[udp_start + 1] = DHCP_CLIENT_PORT as u8;
    buf[udp_start + 2] = (DHCP_SERVER_PORT >> 8) as u8;
    buf[udp_start + 3] = DHCP_SERVER_PORT as u8;

    let dhcp_len_val = dhcp_min_size - ip_size - udp_size;
    let udp_len = (udp_size + dhcp_len_val) as u16;
    buf[udp_start + 4] = (udp_len >> 8) as u8;
    buf[udp_start + 5] = udp_len as u8;

    let ip_len_val = (ip_size + udp_size + dhcp_len_val) as u16;
    buf[ip_start + 2] = (ip_len_val >> 8) as u8;
    buf[ip_start + 3] = ip_len_val as u8;

    // dst IP = 255.255.255.255 (broadcast)
    buf[ip_start + 16] = 0xFF;
    buf[ip_start + 17] = 0xFF;
    buf[ip_start + 18] = 0xFF;
    buf[ip_start + 19] = 0xFF;

    let dhcp = DhcpPacket {
        op: 1,
        htype: 1,
        hlen: 6,
        hops: 0,
        xid: xid.to_be(),
        secs: 0,
        flags: 0x8000u16.to_be(),
        ciaddr: 0,
        yiaddr: 0,
        siaddr: 0,
        giaddr: 0,
        chaddr: {
            let mut c = [0u8; 16];
            c[..6].copy_from_slice(mac);
            c
        },
        sname: [0u8; 64],
        file: [0u8; 128],
        magic: DHCP_MAGIC_COOKIE.to_be(),
        options: [0u8; 312],
    };

    let dhcp_ptr = unsafe { buf.as_mut_ptr().add(dhcp_start) } as *mut DhcpPacket;
    unsafe { dhcp_ptr.write_unaligned(dhcp) };

    let opts_start = dhcp_start + 240;
    let mut o = 0usize;
    buf[opts_start + o] = 53; o += 1;
    buf[opts_start + o] = 1;  o += 1;
    buf[opts_start + o] = 1;  o += 1;
    buf[opts_start + o] = 55; o += 1;
    buf[opts_start + o] = 3;  o += 1;
    buf[opts_start + o] = 1;  o += 1;
    buf[opts_start + o] = 3;  o += 1;
    buf[opts_start + o] = 6;  o += 1;
    buf[opts_start + o] = 0xFF;

    let ip_sum = checksum(&buf[ip_start..ip_start + ip_size]);
    buf[ip_start + 10] = (ip_sum >> 8) as u8;
    buf[ip_start + 11] = ip_sum as u8;

    Ok(total)
}

fn build_request(buf: &mut [u8], mac: &[u8; 6], xid: u32, offered_ip: Ipv4Addr, server_ip: Ipv4Addr) -> Result<usize> {
    let total = build_discover(buf, mac, xid)?;
    let opts_start = std::mem::size_of::<EthHdr>() + 20 + 8 + 240;

    buf[opts_start] = 53; buf[opts_start + 1] = 1; buf[opts_start + 2] = 3;
    buf[opts_start + 3] = 50; buf[opts_start + 4] = 4;
    buf[opts_start + 5..opts_start + 9].copy_from_slice(&u32::from(offered_ip).to_be_bytes());
    buf[opts_start + 9] = 54; buf[opts_start + 10] = 4;
    buf[opts_start + 11..opts_start + 15].copy_from_slice(&u32::from(server_ip).to_be_bytes());
    buf[opts_start + 15] = 55; buf[opts_start + 16] = 3;
    buf[opts_start + 17] = 1; buf[opts_start + 18] = 3; buf[opts_start + 19] = 6;
    buf[opts_start + 20] = 0xFF;

    Ok(total)
}

fn parse_dhcp_options(opts: &[u8]) -> (Option<Ipv4Addr>, Option<Ipv4Addr>, Option<Ipv4Addr>, Option<Ipv4Addr>) {
    let mut gateway = None;
    let mut netmask = None;
    let mut dns1 = None;
    let mut dns2 = None;
    let mut i = 0;

    while i < opts.len() {
        if opts[i] == 0xFF { break; }
        if opts[i] == 0x00 { i += 1; continue; }
        if i + 1 >= opts.len() { break; }
        let olen = opts[i + 1] as usize;
        if i + 2 + olen > opts.len() { break; }
        match opts[i] {
            1 if olen >= 4 => {
                netmask = Some(Ipv4Addr::from(u32::from_be_bytes(
                    opts[i + 2..i + 6].try_into().unwrap(),
                )));
            }
            3 if olen >= 4 => {
                gateway = Some(Ipv4Addr::from(u32::from_be_bytes(
                    opts[i + 2..i + 6].try_into().unwrap(),
                )));
            }
            6 if olen >= 4 => {
                dns1 = Some(Ipv4Addr::from(u32::from_be_bytes(
                    opts[i + 2..i + 6].try_into().unwrap(),
                )));
                if olen >= 8 {
                    dns2 = Some(Ipv4Addr::from(u32::from_be_bytes(
                        opts[i + 6..i + 10].try_into().unwrap(),
                    )));
                }
            }
            _ => {}
        }
        i += 2 + olen;
    }
    (gateway, netmask, dns1, dns2)
}

pub fn discover(usb: &UsbDevice, mac: &MacAddr) -> Result<DhcpLease> {
    let xid = 0x12345678;
    let mut rndis_buf = [0u8; RNDIS_BUF_SIZE];
    let mut eth_buf = [0u8; ETH_BUF_SIZE];
    let mac_bytes = &mac.0;

    info!("sending DHCP discover...");
    let len = build_discover(&mut eth_buf, mac_bytes, xid)?;
    let rndis_len = rndis::build_data_packet(&mut rndis_buf, &eth_buf[..len])?;
    usb.send_bulk(&rndis_buf[..rndis_len])?;

    let mut offered_addr = None;
    let mut server_addr = None;
    let mut final_gw = None;
    let mut final_mask = None;
    let mut final_d1 = None;
    let mut final_d2 = None;

    for _attempt in 0..50 {
        let n = usb.recv_bulk(&mut rndis_buf, 200)?;
        if n == 0 {
            continue;
        }
        let mut process_frame = |frame: &[u8]| {
            if frame.len() < std::mem::size_of::<EthHdr>() + 20 + 8 + DHCP_FIXED_SIZE {
                return;
            }
            let eth = unsafe { &*(frame.as_ptr() as *const EthHdr) };
            if u16::from_be(eth.ethertype) != 0x0800 {
                return;
            }
            let ip_hdr = &frame[std::mem::size_of::<EthHdr>()..];
            if ip_hdr.len() < 20 || ip_hdr[9] != 0x11 {
                return;
            }
            let ip_hl = (ip_hdr[0] & 0x0F) as usize * 4;
            let udp_start = std::mem::size_of::<EthHdr>() + ip_hl;
            if udp_start + 10 > frame.len() {
                return;
            }
            let dport = u16::from_be_bytes([frame[udp_start + 2], frame[udp_start + 3]]);
            if dport != DHCP_CLIENT_PORT {
                return;
            }
            let dhcp_start = udp_start + 8;
            let dhcp = unsafe { &*(frame.as_ptr().add(dhcp_start) as *const DhcpPacket) };
            if u32::from_be(dhcp.magic) != DHCP_MAGIC_COOKIE || u32::from_be(dhcp.xid) != xid {
                return;
            }

            let opts = &frame[dhcp_start + 240..];

            let mut msg_type = 0;
            let mut i = 0;
            while i < opts.len() {
                if opts[i] == 0xFF { break; }
                if opts[i] == 0x00 { i += 1; continue; }
                if i + 1 >= opts.len() { break; }
                let olen = opts[i + 1] as usize;
                if opts[i] == 53 && olen >= 1 {
                    msg_type = opts[i + 2];
                }
                if opts[i] == 54 && olen >= 4 {
                    let srv = u32::from_be_bytes(opts[i + 2..i + 6].try_into().unwrap());
                    server_addr = Some(Ipv4Addr::from(srv));
                }
                i += 2 + olen;
            }

            let yiaddr = Ipv4Addr::from(u32::from_be(dhcp.yiaddr));

            if msg_type == 2 {
                offered_addr = Some(yiaddr);
                let (gw, mask, d1, d2) = parse_dhcp_options(opts);
                final_gw = gw;
                final_mask = mask;
                final_d1 = d1;
                final_d2 = d2;
                info!("DHCP offer: {yiaddr}");
            }
        };

        let on_frame = &mut process_frame;
        rndis::RndisPacketIter::new(&rndis_buf[..n]).for_each(on_frame);

        if offered_addr.is_some() {
            break;
        }
    }

    let offered_ip = offered_addr.ok_or_else(|| TetherError::Dhcp("no DHCP offer received".into()))?;
    let srv_ip = server_addr.unwrap_or(Ipv4Addr::UNSPECIFIED);

    info!("sending DHCP request for {offered_ip}...");
    let len = build_request(&mut eth_buf, mac_bytes, xid, offered_ip, srv_ip)?;
    let rndis_len = rndis::build_data_packet(&mut rndis_buf, &eth_buf[..len])?;
    usb.send_bulk(&rndis_buf[..rndis_len])?;

    for _attempt in 0..50 {
        let n = usb.recv_bulk(&mut rndis_buf, 200)?;
        if n == 0 {
            continue;
        }

        let mut found = false;
        let mut result_lease = None;

        {
            let mut process_ack = |frame: &[u8]| {
                if found { return; }
                if frame.len() < std::mem::size_of::<EthHdr>() + 20 + 8 + DHCP_FIXED_SIZE {
                    return;
                }
                let eth = unsafe { &*(frame.as_ptr() as *const EthHdr) };
                if u16::from_be(eth.ethertype) != 0x0800 {
                    return;
                }
                let ip_hdr = &frame[std::mem::size_of::<EthHdr>()..];
                if ip_hdr.len() < 20 || ip_hdr[9] != 0x11 {
                    return;
                }
                let ip_hl = (ip_hdr[0] & 0x0F) as usize * 4;
                let udp_start = std::mem::size_of::<EthHdr>() + ip_hl;
                if udp_start + 10 > frame.len() {
                    return;
                }
                let dport = u16::from_be_bytes([frame[udp_start + 2], frame[udp_start + 3]]);
                if dport != DHCP_CLIENT_PORT {
                    return;
                }
                let dhcp_start = udp_start + 8;
                let dhcp = unsafe { &*(frame.as_ptr().add(dhcp_start) as *const DhcpPacket) };
                if u32::from_be(dhcp.magic) != DHCP_MAGIC_COOKIE || u32::from_be(dhcp.xid) != xid {
                    return;
                }

                let opts = &frame[dhcp_start + 240..];
                let opts_end = frame.len() - (dhcp_start + 240);

                let mut msg_type = 0;
                let mut i = 0;
                while i < opts.len() && i < opts_end {
                    if opts[i] == 0xFF { break; }
                    if opts[i] == 0x00 { i += 1; continue; }
                    if i + 1 >= opts.len() || i + 1 >= opts_end { break; }
                    let olen = opts[i + 1] as usize;
                    if i + 2 + olen > opts.len() || i + 2 + olen > opts_end { break; }
                    if opts[i] == 53 && olen >= 1 {
                        msg_type = opts[i + 2];
                    }
                    i += 2 + olen;
                }

                if msg_type == 5 {
                    let (gw, mask, d1, d2) = parse_dhcp_options(opts);
                    let yiaddr = Ipv4Addr::from(u32::from_be(dhcp.yiaddr));
                    result_lease = Some(DhcpLease {
                        ip: yiaddr,
                        gateway: gw.unwrap_or_else(|| DEFAULT_GATEWAY.parse().unwrap()),
                        netmask: mask.unwrap_or_else(|| DEFAULT_NETMASK.parse().unwrap()),
                        dns1: d1.unwrap_or_else(|| DEFAULT_DNS1.parse().unwrap()),
                        dns2: d2.unwrap_or_else(|| DEFAULT_DNS2.parse().unwrap()),
                    });
                    found = true;
                }
            };

            let on_frame = &mut process_ack;
            rndis::RndisPacketIter::new(&rndis_buf[..n]).for_each(on_frame);
        }

        if let Some(lease) = result_lease {
            info!("DHCP ACK: ip={} gw={} mask={} dns={},{}",
                lease.ip, lease.gateway, lease.netmask, lease.dns1, lease.dns2);
            return Ok(lease);
        }
    }

    warn!("DHCP failed, using defaults");
    Ok(DhcpLease {
        ip: DEFAULT_STATIC_IP.parse().unwrap(),
        gateway: DEFAULT_GATEWAY.parse().unwrap(),
        netmask: DEFAULT_NETMASK.parse().unwrap(),
        dns1: DEFAULT_DNS1.parse().unwrap(),
        dns2: DEFAULT_DNS2.parse().unwrap(),
    })
}
