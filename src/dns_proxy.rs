use crate::config::DnsProvider;
use log::{debug, info, warn};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

const DNS_QUERY_TIMEOUT: Duration = Duration::from_secs(5);

pub fn create_doh_agent(_provider: DnsProvider) -> Result<ureq::Agent, String> {
    let tls = native_tls::TlsConnector::new().map_err(|e| format!("tls init: {e}"))?;
    Ok(ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(5))
        .timeout_read(DNS_QUERY_TIMEOUT)
        .timeout_write(Duration::from_secs(2))
        .resolver(static_dns_resolver)
        .tls_connector(Arc::new(tls))
        .build())
}

pub fn doh_resolve(agent: &ureq::Agent, provider: DnsProvider, query: &[u8]) -> Option<Vec<u8>> {
    info!("DoH query: {} bytes via {:?}", query.len(), provider);
    match doh_query_with_agent(agent, provider, query) {
        Ok(resp) => {
            info!("DoH response: {} bytes", resp.len());
            Some(resp)
        }
        Err(e) => {
            warn!("DoH query failed: {e}");
            None
        }
    }
}

pub fn is_dns_to_gateway(utun_pkt: &[u8], our_ip: u32, _gateway_ip: u32) -> Option<usize> {
    if utun_pkt.len() < 4 + 20 + 8 + 12 {
        return None;
    }
    let af = u32::from_be_bytes(utun_pkt[..4].try_into().unwrap());
    if af != 2 {
        return None;
    }
    let ip = &utun_pkt[4..];
    let ver_ihl = ip[0];
    if ver_ihl & 0xF0 != 0x40 {
        return None;
    }
    let ihl = ((ver_ihl & 0x0F) * 4) as usize;
    if ip.len() < ihl + 8 {
        return None;
    }
    if ip[9] != 17 {
        return None;
    }
    let src = u32::from_be_bytes([ip[12], ip[13], ip[14], ip[15]]);
    if src != our_ip {
        return None;
    }
    // intercept ALL DNS queries from our utun IP, not just those to gateway
    let udp = &ip[ihl..];
    let dport = u16::from_be_bytes([udp[2], udp[3]]);
    if dport != 53 {
        return None;
    }
    let dns_start = 4 + ihl + 8;
    let dns_end = utun_pkt.len();
    Some(dns_end - dns_start)
}

pub fn build_reply(orig: &[u8], dns_resp: &[u8]) -> Vec<u8> {
    let orig_ip = &orig[4..];
    let ihl = ((orig_ip[0] & 0x0F) * 4) as usize;
    let udp_start = 4 + ihl;
    let ip_total = 20 + 8 + dns_resp.len();
    let reply_total = 4 + ip_total;

    let mut out = Vec::with_capacity(reply_total);
    out.extend_from_slice(&orig[..4]);
    out.push(0x45);
    out.push(0x00);
    out.push((ip_total >> 8) as u8);
    out.push(ip_total as u8);
    out.push(0x00);
    out.push(0x00);
    out.push(0x00);
    out.push(0x00);
    out.push(64);
    out.push(17);
    out.extend_from_slice(&[0u8; 2]);
    out.extend_from_slice(&orig_ip[16..20]);
    out.extend_from_slice(&orig_ip[12..16]);

    let ip_hdr_start = out.len() - 20;
    let csum = ip_checksum(&out[ip_hdr_start..ip_hdr_start + 20]);
    out[ip_hdr_start + 10] = (csum >> 8) as u8;
    out[ip_hdr_start + 11] = csum as u8;

    let orig_udp = &orig[udp_start..];
    out.extend_from_slice(&orig_udp[2..4]);
    out.extend_from_slice(&orig_udp[0..2]);
    let udp_len = (8 + dns_resp.len()) as u16;
    out.push((udp_len >> 8) as u8);
    out.push(udp_len as u8);
    out.push(0x00);
    out.push(0x00);
    out.extend_from_slice(dns_resp);
    out
}

fn ip_checksum(hdr: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for i in (0..hdr.len()).step_by(2) {
        let word = if i + 1 < hdr.len() {
            u16::from_be_bytes([hdr[i], hdr[i + 1]]) as u32
        } else {
            (hdr[i] as u32) << 8
        };
        sum += word;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

fn doh_query_with_agent(agent: &ureq::Agent, _provider: DnsProvider, query: &[u8]) -> Result<Vec<u8>, String> {
    let url = doh_url(_provider);
    match agent
        .post(url)
        .set("Content-Type", "application/dns-message")
        .set("Accept", "application/dns-message")
        .send_bytes(query)
    {
        Ok(resp) => {
            let mut body = Vec::new();
            resp.into_reader()
                .read_to_end(&mut body)
                .map_err(|e| format!("read body: {e}"))?;
            Ok(body)
        }
        Err(ureq::Error::Status(503, _)) => Err("server 503".into()),
        Err(e) => Err(format!("{e}")),
    }
}

fn static_dns_resolver(netloc: &str) -> io::Result<Vec<SocketAddr>> {
    let (host, port_str) = netloc.split_once(':')
        .map(|(h, p)| (h, p.parse::<u16>().unwrap_or(443)))
        .unwrap_or((netloc, 443));

    let ip: [u8; 4] = match host {
        "cloudflare-dns.com" => [1, 1, 1, 1],
        "dns.google" => [8, 8, 8, 8],
        "dns.quad9.net" => [9, 9, 9, 9],
        _ => return Err(io::Error::new(io::ErrorKind::NotFound,
            format!("static resolver: unknown host {netloc}"))),
    };
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port_str);
    debug!("static DNS: {netloc} -> {addr}");
    Ok(vec![addr])
}

// ── DoT connection pooling ──

pub struct DotPooledConn {
    stream: native_tls::TlsStream<TcpStream>,
}

pub fn create_dot_conn(provider: DnsProvider) -> Result<DotPooledConn, String> {
    let addr = dot_addr(provider);
    let hostname = dot_hostname(provider);
    let stream = TcpStream::connect_timeout(
        &addr.parse().map_err(|e| format!("parse: {e}"))?,
        Duration::from_secs(5),
    )
    .map_err(|e| format!("tcp connect: {e}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).map_err(|e| format!("set_read_to: {e}"))?;
    stream.set_write_timeout(Some(Duration::from_secs(5))).map_err(|e| format!("set_write_to: {e}"))?;
    let connector = native_tls::TlsConnector::new().map_err(|e| format!("tls init: {e}"))?;
    let tls = connector.connect(hostname, stream).map_err(|e| format!("tls handshake: {e}"))?;
    Ok(DotPooledConn { stream: tls })
}

pub fn dot_query_pooled(conn: &mut DotPooledConn, query: &[u8]) -> Result<Vec<u8>, String> {
    dot_query_inner(&mut conn.stream, query)
}

fn dot_query_inner(tls: &mut native_tls::TlsStream<TcpStream>, query: &[u8]) -> Result<Vec<u8>, String> {
    let len_be = (query.len() as u16).to_be_bytes();
    tls.write_all(&len_be).map_err(|e| format!("write: {e}"))?;
    tls.write_all(query).map_err(|e| format!("write: {e}"))?;
    let mut len_buf = [0u8; 2];
    tls.read_exact(&mut len_buf).map_err(|e| format!("read: {e}"))?;
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    if resp_len > 4096 {
        return Err("response too large".into());
    }
    let mut resp = vec![0u8; resp_len];
    tls.read_exact(&mut resp).map_err(|e| format!("read: {e}"))?;
    Ok(resp)
}

fn doh_url(p: DnsProvider) -> &'static str {
    match p {
        DnsProvider::Cloudflare => "https://cloudflare-dns.com/dns-query",
        DnsProvider::Google => "https://dns.google/dns-query",
        DnsProvider::Quad9 => "https://dns.quad9.net/dns-query",
    }
}

fn dot_addr(p: DnsProvider) -> &'static str {
    match p {
        DnsProvider::Cloudflare => "1.1.1.1:853",
        DnsProvider::Google => "8.8.8.8:853",
        DnsProvider::Quad9 => "9.9.9.9:853",
    }
}

fn dot_hostname(p: DnsProvider) -> &'static str {
    match p {
        DnsProvider::Cloudflare => "cloudflare-dns.com",
        DnsProvider::Google => "dns.google",
        DnsProvider::Quad9 => "dns.quad9.net",
    }
}
