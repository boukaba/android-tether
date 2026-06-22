use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Default, Clone, Serialize)]
pub struct TetherStats {
    pub tx_mbps: f64,
    pub rx_mbps: f64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub tx_pkts: u64,
    pub rx_pkts: u64,
}

#[derive(Debug, Default)]
pub struct SharedStats {
    pub tx_bytes: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub tx_pkts: AtomicU64,
    pub rx_pkts: AtomicU64,
}

impl SharedStats {
    #[allow(dead_code)]
    pub fn snapshot(&self) -> TetherStats {
        TetherStats {
            tx_mbps: 0.0,
            rx_mbps: 0.0,
            tx_bytes: self.tx_bytes.load(Ordering::Relaxed),
            rx_bytes: self.rx_bytes.load(Ordering::Relaxed),
            tx_pkts: self.tx_pkts.load(Ordering::Relaxed),
            rx_pkts: self.rx_pkts.load(Ordering::Relaxed),
        }
    }
}
