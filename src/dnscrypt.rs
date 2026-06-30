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
const QUERY_TIMEOUT: Duration = Duration::from_secs(5);
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
    let cert_magic: [u8; 8] = [0x72, 0x36, 0x66, 0x6e, 0x76, 0x57, 0x6a, 0x38];
    let n = provider_name.as_bytes().len();
    let pad = ((n + 63) / 64) * 64;
    let mut query = vec![0u8; 8 + pad + 32];
    query[..8].copy_from_slice(&cert_magic);
    query[8..8 + n].copy_from_slice(provider_name.as_bytes());

    let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("udp bind: {e}"))?;
    sock.set_read_timeout(Some(CERT_FETCH_TIMEOUT))
        .map_err(|e| format!("set_read_to: {e}"))?;
    sock.send_to(&query, addr)
        .map_err(|e| format!("send cert probe: {e}"))?;

    let mut buf = [0u8; 1024];
    let n = sock.recv(&mut buf).map_err(|e| format!("recv cert: {e}"))?;
    parse_cert(&buf[..n])
}

fn parse_cert(data: &[u8]) -> Result<DnscryptCert, String> {
    if data.len() < 124 || &data[..4] != b"DNSC" {
        return Err("bad cert".into());
    }
    if u16::from_be_bytes([data[4], data[5]]) != 2 {
        return Err("unsupported version".into());
    }
    let payload = &data[6..data.len() - 64];
    if payload.len() < 84 {
        return Err("truncated cert".into());
    }
    let client_magic: [u8; 8] = payload[32..40].try_into().unwrap();
    let serial = u32::from_be_bytes(payload[40..44].try_into().unwrap());
    let valid_until = u32::from_be_bytes(payload[48..52].try_into().unwrap());
    let server_pk: [u8; 32] = payload[52..84].try_into().unwrap();

    debug!("DNSCrypt cert serial={serial}");
    Ok(DnscryptCert { server_pk, client_magic, serial, valid_until })
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
        nonce[12..].copy_from_slice(&nonce_vec);

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
        if data.len() < 8 + 12 + CRYPTO_SECRETBOX_MACBYTES + 1 {
            return Err("response too short".into());
        }
        if &data[..8] != &self.client_magic {
            return Err("bad client magic".into());
        }
        let nonce_vec = &data[8..20];
        let encrypted = &data[20..];

        let mut nonce = [0u8; CRYPTO_SECRETBOX_NONCEBYTES];
        nonce[12..].copy_from_slice(nonce_vec);

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
            // Cisco OpenDNS — actually works on UDP 443 through phone tethering
            DnscryptProvider {
                // Known public key for Cisco OpenDNS (from dnscrypt.info stamp list)
                known_pk: Some([
                    0xb7, 0x35, 0x11, 0x40, 0x20, 0x6f, 0x22, 0x5d,
                    0x3e, 0x2b, 0xd8, 0x22, 0xd7, 0xfd, 0x69, 0x1e,
                    0xa1, 0xc3, 0x3c, 0xc8, 0xd6, 0x66, 0x8d, 0x0c,
                    0xbe, 0x04, 0xbf, 0xab, 0xca, 0x43, 0xfb, 0x79,
                ]),
                addr: "208.67.220.220:443".parse().unwrap(),
                provider_name: "2.dnscrypt-cert.opendns.com",
                // Magic: "r6fnx04" — from the 12-byte short cert response
                client_magic: [0x72, 0x36, 0x66, 0x6e, 0x78, 0x30, 0x34, 0xff],
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
        // Use hardcoded public key (short cert format — Cisco, etc.)
        info!("DNSCrypt using known key for {} ({})", prov.provider_name, prov.addr);
        DnscryptCert {
            server_pk: pk,
            client_magic: prov.client_magic,
            serial: 0,
            valid_until: 0,
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
