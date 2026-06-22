use std::net::Ipv4Addr;

pub const RNDIS_BUF_SIZE: usize = 32768;
pub const ETH_BUF_SIZE: usize = 2048;

pub const ARP_ETHERTYPE: u16 = 0x0806;
pub const ARP_HW_ETHERNET: u16 = 1;
#[allow(dead_code)]
pub const ARP_OP_REQUEST: u16 = 1;
pub const ARP_OP_REPLY: u16 = 2;

pub const DHCP_SERVER_PORT: u16 = 67;
pub const DHCP_CLIENT_PORT: u16 = 68;
pub const DHCP_MAGIC_COOKIE: u32 = 0x63825363;

pub const DEFAULT_STATIC_IP: &str = "192.168.42.100";
pub const DEFAULT_GATEWAY: &str = "192.168.42.129";
pub const DEFAULT_NETMASK: &str = "255.255.255.0";
pub const DEFAULT_DNS1: &str = "8.8.8.8";
pub const DEFAULT_DNS2: &str = "8.8.4.4";

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct EthHdr {
    pub dst: [u8; 6],
    pub src: [u8; 6],
    pub ethertype: u16,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct ArpPacket {
    pub hw_type: u16,
    pub proto_type: u16,
    pub hw_len: u8,
    pub proto_len: u8,
    pub opcode: u16,
    pub sender_mac: [u8; 6],
    pub sender_ip: u32,
    pub target_mac: [u8; 6],
    pub target_ip: u32,
}

#[repr(C, packed)]
pub struct DhcpPacket {
    pub op: u8,
    pub htype: u8,
    pub hlen: u8,
    pub hops: u8,
    pub xid: u32,
    pub secs: u16,
    pub flags: u16,
    pub ciaddr: u32,
    pub yiaddr: u32,
    pub siaddr: u32,
    pub giaddr: u32,
    pub chaddr: [u8; 16],
    pub sname: [u8; 64],
    pub file: [u8; 128],
    pub magic: u32,
    pub options: [u8; 312],
}

impl Default for DhcpPacket {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    #[allow(dead_code)]
    pub fn new(bytes: [u8; 6]) -> Self {
        Self(bytes)
    }

    #[allow(dead_code)]
    pub fn broadcast() -> Self {
        Self([0xFF; 6])
    }

    #[allow(dead_code)]
    pub fn is_broadcast(&self) -> bool {
        self.0.iter().all(|&b| b == 0xFF)
    }
}

impl std::fmt::Display for MacAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl From<[u8; 6]> for MacAddr {
    fn from(b: [u8; 6]) -> Self {
        Self(b)
    }
}

#[derive(Debug, Clone)]
pub struct DhcpLease {
    pub ip: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub dns1: Ipv4Addr,
    pub dns2: Ipv4Addr,
}
