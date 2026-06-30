use std::net::Ipv4Addr;

#[derive(Debug, thiserror::Error)]
#[allow(dead_code)]
pub enum TetherError {
    #[error("USB error: {0}")]
    Usb(#[from] nusb::Error),

    #[error("USB transfer error: {0}")]
    UsbTransfer(#[from] nusb::transfer::TransferError),

    #[error("RNDIS protocol error: {0}")]
    Rndis(String),

    #[error("Device not found: {0}")]
    DeviceNotFound(String),

    #[error("Network interface error: {0}")]
    Network(String),

    #[error("DHCP failed: {0}")]
    Dhcp(String),

    #[error("ARP error: {0}")]
    Arp(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("IPC error: {0}")]
    Ipc(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid IP address: {0}")]
    InvalidIp(String),

    #[error("Protocol {0} not supported")]
    UnsupportedProtocol(String),

    #[error("Buffer too small: need {need} got {got}")]
    BufferTooSmall { need: usize, got: usize },

    #[error("Operation timed out")]
    Timeout,
}

pub type Result<T> = std::result::Result<T, TetherError>;

#[allow(dead_code)]
pub fn parse_ip4(s: &str) -> Result<Ipv4Addr> {
    s.parse::<Ipv4Addr>()
        .map_err(|_| TetherError::InvalidIp(s.to_string()))
}
