//! DNSCrypt v2 client — certificate fetching, parsing, query encryption/decryption.
//! Uses `dryoc::classic` for raw-array-based X25519 + XSalsa20Poly1305.

use crate::config::DnsProvider;
use dryoc::classic::crypto_box::crypto_box_beforenm;
use dryoc::classic::crypto_secretbox::{
    crypto_secretbox_easy, crypto_secretbox_open_easy,
};
use dryoc::constants::{
    CRYPTO_SECRETBOX_KEYBYTES, CRYPTO_SECRETBOX_MACBYTES, CRYPTO_SECRETBOX_NONCEBYTES,
};
use dryoc::keypair::StackKeyPair;
use log::{debug, info};
use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const CERT_FETCH_TIMEOUT: Duration = Duration::from_secs(5);
const QUERY_TIMEOUT: Duration = Duration::from_secs(2);
const KEY_LIFETIME: Duration = Duration::from_secs(3600);

// ── Certificate ──

#[derive(Debug, Clone)]
pub struct DnscryptCert {
    pub server_pk: [u8; 32],
    pub client_magic: [u8; 8],
    pub serial: u32,
    pub valid_until: u32,
}

fn fetch_cert(addr: SocketAddr, provider_name: &str) -> Result<DnscryptCert, String> {
    // Build DNS TXT query
    let mut query = vec![
        0x00, 0x00, // ID
        0x01, 0x00, // flags: RD
        0x00, 0x01, // QDCOUNT
        0x00, 0x00, // ANCOUNT
        0x00, 0x00, // NSCOUNT
        0x00, 0x00, // ARCOUNT
    ];
    for label in provider_name.split('.') {
        if label.is_empty() { continue; }
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0x00); // terminating zero
    query.extend_from_slice(&[0x00, 0x10]); // TXT
    query.extend_from_slice(&[0x00, 0x01]); // IN

    // Try ports that bypass phone DNS interception
    for port in &[443u16, 5353, 8443] {
        let mut sock_addr = addr;
        sock_addr.set_port(*port);

        let sock = UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| format!("udp bind: {e}"))?;
        sock.set_read_timeout(Some(CERT_FETCH_TIMEOUT))
            .map_err(|e| format!("set_read_to: {e}"))?;
        sock.send_to(&query, sock_addr)
            .map_err(|e| format!("send cert query: {e}"))?;

        let mut buf = [0u8; 2048];
        let n = match sock.recv(&mut buf) {
            Ok(n) => n,
            Err(_) => continue,
        };

        if let Some(cert) = extract_cert_from_dns(&buf[..n]) {
            // Cert binary is 124+ bytes, starts with DNSC
            if cert.len() >= 124 && &cert[..4] == b"DNSC" {
                let client_magic: [u8; 8] = cert[104..112].try_into().unwrap();
                let server_pk: [u8; 32] = cert[72..104].try_into().unwrap();
                let serial = u32::from_be_bytes(cert[56..60].try_into().unwrap());
                debug!("DNSCrypt cert serial={serial}");
                return Ok(DnscryptCert { server_pk, client_magic, serial, valid_until: 0 });
            }
        }
    }
    Err("cert fetch: no response".into())
}

/// Extract the certificate binary from a DNS TXT response.
/// Returns the raw cert bytes (from the TXT record's first string).
fn extract_cert_from_dns(dns_response: &[u8]) -> Option<Vec<u8>> {
    if dns_response.len() < 12 { return None; }
    let mut pos = 12usize;
    // Skip question section
    let qdcount = u16::from_be_bytes([dns_response[4], dns_response[5]]) as usize;
    for _ in 0..qdcount {
        while pos < dns_response.len() && dns_response[pos] != 0 {
            let len = dns_response[pos] as usize;
            if pos + 1 + len > dns_response.len() { return None; }
            pos += 1 + len;
        }
        pos += 1; // zero byte
        pos += 4; // QTYPE + QCLASS
    }
    // Answer section
    let ancount = u16::from_be_bytes([dns_response[6], dns_response[7]]) as usize;
    for _ in 0..ancount {
        if pos + 10 > dns_response.len() { break; }
        // Handle name (may be compressed pointer)
        if dns_response[pos] & 0xC0 == 0xC0 {
            pos += 2;
        } else {
            while pos < dns_response.len() && dns_response[pos] != 0 {
                let len = dns_response[pos] as usize;
                if pos + 1 + len > dns_response.len() { return None; }
                pos += 1 + len;
            }
            pos += 1;
        }
        let rtype = u16::from_be_bytes([dns_response[pos], dns_response[pos+1]]);
        pos += 8; // type + class + ttl
        let rdlen = u16::from_be_bytes([dns_response[pos], dns_response[pos+1]]) as usize;
        pos += 2;
        if pos + rdlen > dns_response.len() { break; }
        if rtype == 16 {
            // TXT record: length-prefixed strings
            let txt_data = &dns_response[pos..pos + rdlen];
            // Concatenate all length-prefixed strings
            let mut cert = Vec::new();
            let mut tp = 0usize;
            while tp < txt_data.len() {
                let slen = txt_data[tp] as usize;
                tp += 1;
                if tp + slen > txt_data.len() { break; }
                cert.extend_from_slice(&txt_data[tp..tp + slen]);
                tp += slen;
            }
            if !cert.is_empty() { return Some(cert); }
        }
        pos += rdlen;
    }
    None
}

// ── Session ──

pub struct DnscryptSession {
    client_pk: [u8; 32],
    shared_key: [u8; CRYPTO_SECRETBOX_KEYBYTES],
    client_magic: [u8; 8],
    created: Instant,
}

impl DnscryptSession {
    pub fn new(cert: &DnscryptCert) -> Result<Self, String> {
        let kp = StackKeyPair::gen();
        let client_sk: [u8; 32] = (*kp.secret_key).try_into()
            .map_err(|_| "bad sk")?;
        let client_pk: [u8; 32] = (*kp.public_key).try_into()
            .map_err(|_| "bad pk")?;

        let shared = crypto_box_beforenm(&cert.server_pk, &client_sk);

        Ok(Self {
            client_pk,
            shared_key: shared,
            client_magic: cert.client_magic,
            created: Instant::now(),
        })
    }

    pub fn is_expired(&self) -> bool {
        self.created.elapsed() > KEY_LIFETIME
    }

    pub fn encrypt(&self, query: &[u8]) -> Result<Vec<u8>, String> {
        let nonce_vec = dryoc::rng::randombytes_buf(CRYPTO_SECRETBOX_NONCEBYTES / 2);
        let mut nonce = [0u8; CRYPTO_SECRETBOX_NONCEBYTES];
        nonce[..12].copy_from_slice(&nonce_vec); // random first 12, zeros last 12

        let mut ciphertext = vec![0u8; CRYPTO_SECRETBOX_MACBYTES + query.len()];
        crypto_secretbox_easy(&mut ciphertext, query, &nonce, &self.shared_key)
            .map_err(|_| "encrypt failed")?;

        let mut packet = Vec::with_capacity(52 + ciphertext.len());
        packet.extend_from_slice(&self.client_magic);
        packet.extend_from_slice(&self.client_pk);
        packet.extend_from_slice(&nonce_vec);
        packet.extend_from_slice(&ciphertext);
        Ok(packet)
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        debug!("DNSCrypt decrypt: {} bytes, expected_magic={:02x?}, got_magic={:02x?}",
            data.len(), &self.client_magic, &data[..8.min(data.len())]);
        if data.len() < 8 + 12 + CRYPTO_SECRETBOX_MACBYTES + 1 {
            return Err("response too short".into());
        }
        if &data[..8] != &self.client_magic {
            return Err("bad client magic".into());
        }
        let nonce_vec = &data[8..20];
        let encrypted = &data[20..];

        let mut nonce = [0u8; CRYPTO_SECRETBOX_NONCEBYTES];
        nonce[..12].copy_from_slice(nonce_vec); // random first 12, zeros last 12

        let mut plaintext = vec![0u8; encrypted.len() - CRYPTO_SECRETBOX_MACBYTES];
        crypto_secretbox_open_easy(&mut plaintext, encrypted, &nonce, &self.shared_key)
            .map_err(|_| "decrypt failed")?;
        Ok(plaintext)
    }
}

// ── Providers ──

struct DnscryptProvider {
    known_pk: Option<[u8; 32]>,
    addr: SocketAddr,
    provider_name: &'static str,
    client_magic: [u8; 8],
}

fn get_provider(provider: DnsProvider) -> DnscryptProvider {
    match provider {
        DnsProvider::Cloudflare | DnsProvider::Google | DnsProvider::Quad9 => {
            // dct-de2 — DNSCrypt on port 53 (works through phone USB tethering)
            // Known public key from sdns:// stamp
            DnscryptProvider {
                known_pk: Some([
                    0xaf, 0x32, 0xf5, 0xd2, 0xa9, 0x34, 0x12, 0x97,
                    0x9d, 0xe3, 0x65, 0x6f, 0x09, 0xa9, 0x1d, 0x96,
                    0x41, 0x52, 0xfa, 0x9f, 0x05, 0x79, 0xe8, 0x8e,
                    0x25, 0xba, 0x19, 0xdb, 0x69, 0xf2, 0x9e, 0xcf,
                ]),
                addr: "82.165.61.52:53".parse().unwrap(),
                provider_name: "2.dnscrypt-cert.dct-de2",
                // Client magic from cert — fetched once at startup via raw probe
                client_magic: [0u8; 8],
            }
        }
    }
}

// ── Pool ──

pub type SharedDnscryptPool = Arc<Mutex<DnscryptPool>>;

pub struct DnscryptPool {
    cert: DnscryptCert,
    session: Option<DnscryptSession>,
    last_cert_fetch: Instant,
    addr: SocketAddr,
    provider_name: &'static str,
}

pub fn create_dnscrypt_pool(provider: DnsProvider) -> Result<SharedDnscryptPool, String> {
    let prov = get_provider(provider);

    let cert = if let Some(pk) = prov.known_pk {
        // Known public key — try fetching cert via DNS TXT, fall back to known key
        match fetch_cert(prov.addr, prov.provider_name) {
            Ok(c) => {
                info!("DNSCrypt cert fetched (serial={})", c.serial);
                c
            }
            Err(e) => {
                info!("DNSCrypt cert fetch failed ({}), using known key", e);
                DnscryptCert {
                    server_pk: pk,
                    client_magic: prov.client_magic,
                    serial: 0,
                    valid_until: 0,
                }
            }
        }
    } else {
        fetch_cert(prov.addr, prov.provider_name)
            .map_err(|e| format!("DNSCrypt cert fetch: {e}"))?
    };

    info!("DNSCrypt cert ready (serial={})", cert.serial);
    Ok(Arc::new(Mutex::new(DnscryptPool {
        cert,
        session: None,
        last_cert_fetch: Instant::now(),
        addr: prov.addr,
        provider_name: prov.provider_name,
    })))
}

impl DnscryptPool {
    fn ensure_session(&mut self) -> Result<(), String> {
        if self.last_cert_fetch.elapsed() > Duration::from_secs(86400) {
            self.cert = fetch_cert(self.addr, self.provider_name)
                .map_err(|e| format!("DNSCrypt cert refresh: {e}"))?;
            self.last_cert_fetch = Instant::now();
            self.session = None;
            info!("DNSCrypt cert refreshed");
        }
        if self.session.as_ref().map_or(true, |s| s.is_expired()) {
            self.session = Some(DnscryptSession::new(&self.cert)?);
        }
        Ok(())
    }

    pub fn query(&mut self, dns_query: &[u8]) -> Result<Vec<u8>, String> {
        self.ensure_session()?;
        let session = self.session.as_ref().unwrap();
        let encrypted = session.encrypt(dns_query)?;

        let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("udp bind: {e}"))?;
        sock.set_read_timeout(Some(QUERY_TIMEOUT))
            .map_err(|e| format!("set_read_to: {e}"))?;
        sock.send_to(&encrypted, self.addr)
            .map_err(|e| format!("send query: {e}"))?;

        let mut buf = [0u8; 4096];
        let n = sock.recv(&mut buf).map_err(|e| format!("recv response: {e}"))?;
        session.decrypt(&buf[..n])
    }

    pub fn resolve(&mut self, dns_query: &[u8]) -> Option<Vec<u8>> {
        match self.query(dns_query) {
            Ok(resp) => {
                info!("DNSCrypt response: {} bytes", resp.len());
                Some(resp)
            }
            Err(e) => {
                debug!("DNSCrypt query failed: {e}");
                None
            }
        }
    }
}
