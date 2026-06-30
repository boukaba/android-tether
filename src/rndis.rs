use crate::error::{Result, TetherError};

#[allow(dead_code)]
pub const RNDIS_MSG_INIT: u32 = 0x00000002;
#[allow(dead_code)]
pub const RNDIS_MSG_INIT_C: u32 = 0x80000002;
#[allow(dead_code)]
pub const RNDIS_MSG_HALT: u32 = 0x00000003;
pub const RNDIS_MSG_QUERY: u32 = 0x00000004;
#[allow(dead_code)]
pub const RNDIS_MSG_QUERY_C: u32 = 0x80000004;
pub const RNDIS_MSG_SET: u32 = 0x00000005;
#[allow(dead_code)]
pub const RNDIS_MSG_SET_C: u32 = 0x80000005;
#[allow(dead_code)]
pub const RNDIS_MSG_RESET: u32 = 0x00000006;
#[allow(dead_code)]
pub const RNDIS_MSG_RESET_C: u32 = 0x80000006;
#[allow(dead_code)]
pub const RNDIS_MSG_INDICATE: u32 = 0x00000001;
#[allow(dead_code)]
pub const RNDIS_MSG_KEEPALIVE: u32 = 0x00000008;
#[allow(dead_code)]
pub const RNDIS_MSG_KEEPALIVE_C: u32 = 0x80000008;
#[allow(dead_code)]
pub const RNDIS_MSG_PACKET: u32 = 0x00000001;

#[allow(dead_code)]
pub const RNDIS_STATUS_SUCCESS: u32 = 0x00000000;
#[allow(dead_code)]
pub const RNDIS_STATUS_MEDIA_CONNECT: u32 = 0x4001000B;

pub const OID_GEN_CURRENT_PACKET_FILTER: u32 = 0x0001010E;
pub const OID_802_3_PERMANENT_ADDRESS: u32 = 0x01010101;
#[allow(dead_code)]
pub const OID_802_3_CURRENT_ADDRESS: u32 = 0x01010102;

pub const RNDIS_PACKET_TYPE_DIRECTED: u32 = 0x00000001;
pub const RNDIS_PACKET_TYPE_MULTICAST: u32 = 0x00000002;
pub const RNDIS_PACKET_TYPE_ALL_MULTICAST: u32 = 0x00000004;
pub const RNDIS_PACKET_TYPE_BROADCAST: u32 = 0x00000008;

pub const RNDIS_MAJOR_VERSION: u32 = 1;
pub const RNDIS_MINOR_VERSION: u32 = 0;
pub const RNDIS_MAX_TRANSFER_SIZE: u32 = 0x8000;

fn read_u32(buf: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(buf[offset..offset + 4].try_into().unwrap())
}

fn write_u32(buf: &mut [u8], offset: usize, val: u32) {
    buf[offset..offset + 4].copy_from_slice(&val.to_le_bytes());
}

#[derive(Debug, Clone)]
pub struct RndisState {
    pub request_id: u32,
    pub max_transfer_size: u32,
    pub medium: u32,
    pub mac_addr: [u8; 6],
    pub link_up: bool,
}

impl Default for RndisState {
    fn default() -> Self {
        Self {
            request_id: 0,
            max_transfer_size: RNDIS_MAX_TRANSFER_SIZE,
            medium: 0,
            mac_addr: [0; 6],
            link_up: false,
        }
    }
}

pub fn build_init(buf: &mut [u8], state: &mut RndisState) -> Result<usize> {
    let msg_size = 24;
    if buf.len() < msg_size {
        return Err(TetherError::BufferTooSmall {
            need: msg_size,
            got: buf.len(),
        });
    }
    state.request_id += 1;
    write_u32(buf, 0, RNDIS_MSG_INIT);
    write_u32(buf, 4, msg_size as u32);
    write_u32(buf, 8, state.request_id);
    write_u32(buf, 12, RNDIS_MAJOR_VERSION);
    write_u32(buf, 16, RNDIS_MINOR_VERSION);
    write_u32(buf, 20, RNDIS_MAX_TRANSFER_SIZE);
    Ok(msg_size)
}

pub fn parse_init_cmplt(buf: &[u8], state: &mut RndisState) -> Result<()> {
    if buf.len() < 52 {
        return Err(TetherError::BufferTooSmall {
            need: 52,
            got: buf.len(),
        });
    }
    let msg_type = read_u32(buf, 0);
    let status = read_u32(buf, 12);
    if msg_type != RNDIS_MSG_INIT_C {
        return Err(TetherError::Rndis(format!(
            "expected INIT_C, got {msg_type:#x}"
        )));
    }
    if status != RNDIS_STATUS_SUCCESS {
        return Err(TetherError::Rndis(format!("INIT_C status {status:#x}")));
    }
    state.max_transfer_size = read_u32(buf, 40);
    state.medium = read_u32(buf, 28);
    Ok(())
}

pub fn build_query(buf: &mut [u8], oid: u32, state: &mut RndisState) -> Result<usize> {
    let msg_size = 28;
    if buf.len() < msg_size {
        return Err(TetherError::BufferTooSmall {
            need: msg_size,
            got: buf.len(),
        });
    }
    state.request_id += 1;
    write_u32(buf, 0, RNDIS_MSG_QUERY);
    write_u32(buf, 4, msg_size as u32);
    write_u32(buf, 8, state.request_id);
    write_u32(buf, 12, oid);
    write_u32(buf, 16, 0);
    write_u32(buf, 20, 20);
    write_u32(buf, 24, 0);
    Ok(msg_size)
}

pub fn parse_query_cmplt(buf: &[u8], data_out: &mut [u8]) -> Result<usize> {
    if buf.len() < 24 {
        return Err(TetherError::BufferTooSmall {
            need: 24,
            got: buf.len(),
        });
    }
    let msg_type = read_u32(buf, 0);
    let status = read_u32(buf, 12);
    if msg_type != RNDIS_MSG_QUERY_C {
        return Err(TetherError::Rndis(format!(
            "expected QUERY_C, got {msg_type:#x}"
        )));
    }
    if status != RNDIS_STATUS_SUCCESS {
        return Err(TetherError::Rndis(format!(
            "QUERY_C status {status:#x}"
        )));
    }
    let len = read_u32(buf, 16) as usize;
    let offset = read_u32(buf, 20) as usize;
    if len > 0 {
        let data_start = 8 + offset;
        let end = data_start + len;
        if end > buf.len() {
            return Err(TetherError::BufferTooSmall {
                need: end,
                got: buf.len(),
            });
        }
        let to_copy = len.min(data_out.len());
        data_out[..to_copy].copy_from_slice(&buf[data_start..data_start + to_copy]);
        Ok(to_copy)
    } else {
        Ok(0)
    }
}

pub fn build_set(
    buf: &mut [u8],
    oid: u32,
    data: &[u8],
    state: &mut RndisState,
) -> Result<usize> {
    let hdr_size = 28;
    let total = hdr_size + data.len();
    if buf.len() < total {
        return Err(TetherError::BufferTooSmall {
            need: total,
            got: buf.len(),
        });
    }
    state.request_id += 1;
    write_u32(buf, 0, RNDIS_MSG_SET);
    write_u32(buf, 4, total as u32);
    write_u32(buf, 8, state.request_id);
    write_u32(buf, 12, oid);
    write_u32(buf, 16, data.len() as u32);
    write_u32(buf, 20, 20);
    write_u32(buf, 24, 0);
    buf[hdr_size..total].copy_from_slice(data);
    Ok(total)
}

pub fn parse_set_cmplt(buf: &[u8]) -> Result<()> {
    if buf.len() < 16 {
        return Err(TetherError::BufferTooSmall {
            need: 16,
            got: buf.len(),
        });
    }
    let msg_type = read_u32(buf, 0);
    let status = read_u32(buf, 12);
    if msg_type != RNDIS_MSG_SET_C {
        return Err(TetherError::Rndis(format!(
            "expected SET_C, got {msg_type:#x}"
        )));
    }
    if status != RNDIS_STATUS_SUCCESS {
        return Err(TetherError::Rndis(format!("SET_C status {status:#x}")));
    }
    Ok(())
}

#[allow(dead_code)]
pub fn build_keepalive(buf: &mut [u8], state: &mut RndisState) -> Result<usize> {
    let msg_size = 12;
    if buf.len() < msg_size {
        return Err(TetherError::BufferTooSmall {
            need: msg_size,
            got: buf.len(),
        });
    }
    state.request_id += 1;
    write_u32(buf, 0, RNDIS_MSG_KEEPALIVE);
    write_u32(buf, 4, msg_size as u32);
    write_u32(buf, 8, state.request_id);
    Ok(msg_size)
}

pub fn build_data_packet(buf: &mut [u8], eth_frame: &[u8]) -> Result<usize> {
    let hdr_size = 44;
    let total = hdr_size + eth_frame.len();
    if buf.len() < total {
        return Err(TetherError::BufferTooSmall {
            need: total,
            got: buf.len(),
        });
    }
    write_u32(buf, 0, RNDIS_MSG_PACKET);
    write_u32(buf, 4, total as u32);
    write_u32(buf, 8, 36);
    write_u32(buf, 12, eth_frame.len() as u32);
    write_u32(buf, 16, 0);
    write_u32(buf, 20, 0);
    write_u32(buf, 24, 0);
    write_u32(buf, 28, 0);
    write_u32(buf, 32, 0);
    write_u32(buf, 36, 0);
    write_u32(buf, 40, 0);
    buf[hdr_size..total].copy_from_slice(eth_frame);
    Ok(total)
}

#[derive(Debug)]
pub struct RndisPacketIter<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> RndisPacketIter<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }
}

impl<'a> Iterator for RndisPacketIter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.offset + 8 > self.data.len() {
                return None;
            }
            let msg_len = read_u32(self.data, self.offset + 4) as usize;
            if msg_len == 0 || self.offset + msg_len > self.data.len() {
                return None;
            }
            let pkt_data = &self.data[self.offset..self.offset + msg_len];
            self.offset += msg_len;

            if pkt_data.len() < 8 {
                continue;
            }
            let dp_msg_type = read_u32(pkt_data, 0);
            if dp_msg_type != RNDIS_MSG_PACKET {
                continue;
            }
            if pkt_data.len() < 44 {
                continue;
            }
            let dp_data_offset = read_u32(pkt_data, 8);
            let dp_data_len = read_u32(pkt_data, 12);
            // Data packets have DataOffset >= 36 and DataLength > 0.
            // Indication messages use the same type byte but have Status at offset 8 and
            // StatusBufferLength at offset 12 — these won't pass this check.
            if dp_data_offset < 36 || dp_data_len == 0 {
                continue;
            }
            let data_start = (8 + dp_data_offset) as usize;
            let data_end = data_start + dp_data_len as usize;
            if data_end > pkt_data.len() {
                continue;
            }
            return Some(&pkt_data[data_start..data_end]);
        }
    }
}
