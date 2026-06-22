use crate::error::Result;
use crate::net_types::EthHdr;

const AF_INET: u32 = 2;
const AF_INET6: u32 = 30;

pub fn ip_to_eth(
    utun_pkt: &[u8],
    eth_buf: &mut [u8],
    src_mac: &[u8; 6],
    gateway_mac: &[u8; 6],
) -> Result<usize> {
    if utun_pkt.len() < 5 {
        return Ok(0);
    }

    let af_raw: [u8; 4] = utun_pkt[..4].try_into().unwrap();
    let af = u32::from_be_bytes(af_raw);

    let ip_len = utun_pkt.len() - 4;
    let total = std::mem::size_of::<EthHdr>() + ip_len;
    if total > eth_buf.len() {
        return Ok(0);
    }

    let eth = EthHdr {
        dst: *gateway_mac,
        src: *src_mac,
        ethertype: (if af == AF_INET {
            0x0800u16
        } else if af == AF_INET6 {
            0x86DDu16
        } else {
            let ver = utun_pkt[4] >> 4;
            if ver == 4 {
                0x0800u16
            } else if ver == 6 {
                0x86DDu16
            } else {
                return Ok(0);
            }
        }).to_be(),
    };

    let eth_ptr = eth_buf.as_mut_ptr() as *mut EthHdr;
    unsafe { eth_ptr.write_unaligned(eth) };
    eth_buf[std::mem::size_of::<EthHdr>()..total].copy_from_slice(&utun_pkt[4..]);
    Ok(total)
}

pub fn eth_to_utun(eth_frame: &[u8], utun_buf: &mut [u8]) -> Result<usize> {
    if eth_frame.len() < std::mem::size_of::<EthHdr>() {
        return Ok(0);
    }

    let eth = unsafe { &*(eth_frame.as_ptr() as *const EthHdr) };
    let ethertype = u16::from_be(eth.ethertype);
    let ip_len = eth_frame.len() - std::mem::size_of::<EthHdr>();
    let total = 4 + ip_len;
    if total > utun_buf.len() {
        return Ok(0);
    }

    let af_nbo = match ethertype {
        0x0800 => AF_INET.to_be(),
        0x86DD => AF_INET6.to_be(),
        _ => return Ok(0),
    };

    utun_buf[..4].copy_from_slice(&af_nbo.to_ne_bytes());
    utun_buf[4..total].copy_from_slice(&eth_frame[std::mem::size_of::<EthHdr>()..]);
    Ok(total)
}
