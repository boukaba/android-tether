use crate::error::{Result, TetherError};
use crate::net_types::{ArpPacket, EthHdr, ARP_ETHERTYPE, ARP_HW_ETHERNET, ARP_OP_REPLY, ARP_OP_REQUEST, ETH_BUF_SIZE};
use crate::rndis;
use crate::usb_device::UsbDevice;
use log::{debug, info};
use std::net::Ipv4Addr;

#[allow(dead_code)]
pub fn build_reply(
    buf: &mut [u8],
    our_mac: &[u8; 6],
    our_ip: Ipv4Addr,
    their_mac: &[u8; 6],
    their_ip: Ipv4Addr,
) -> Result<usize> {
    let total = std::mem::size_of::<EthHdr>() + std::mem::size_of::<ArpPacket>();
    if buf.len() < total {
        return Err(TetherError::BufferTooSmall { need: total, got: buf.len() });
    }

    let eth = EthHdr {
        dst: *their_mac,
        src: *our_mac,
        ethertype: ARP_ETHERTYPE.to_be(),
    };
    let eth_ptr = buf.as_mut_ptr() as *mut EthHdr;
    unsafe { eth_ptr.write_unaligned(eth) };

    let arp = ArpPacket {
        hw_type: ARP_HW_ETHERNET.to_be(),
        proto_type: 0x0800u16.to_be(),
        hw_len: 6,
        proto_len: 4,
        opcode: ARP_OP_REPLY.to_be(),
        sender_mac: *our_mac,
        sender_ip: u32::from(our_ip).to_be(),
        target_mac: *their_mac,
        target_ip: u32::from(their_ip).to_be(),
    };
    let arp_ptr = unsafe { buf.as_mut_ptr().add(std::mem::size_of::<EthHdr>()) as *mut ArpPacket };
    unsafe { arp_ptr.write_unaligned(arp) };

    Ok(total)
}

#[allow(dead_code)]
pub fn handle_request(
    frame: &[u8],
    reply_buf: &mut [u8],
    our_mac: &[u8; 6],
    our_ip: Ipv4Addr,
) -> Result<usize> {
    let hdr_size = std::mem::size_of::<EthHdr>() + std::mem::size_of::<ArpPacket>();
    if frame.len() < hdr_size {
        return Ok(0);
    }

    let eth = unsafe { &*(frame.as_ptr() as *const EthHdr) };
    if u16::from_be(eth.ethertype) != ARP_ETHERTYPE {
        return Ok(0);
    }

    let arp = unsafe { &*(frame.as_ptr().add(std::mem::size_of::<EthHdr>()) as *const ArpPacket) };
    let op = u16::from_be(arp.opcode);
    let target_ip = Ipv4Addr::from(u32::from_be(arp.target_ip));

    if op == ARP_OP_REQUEST && target_ip == our_ip {
        let sender_ip = Ipv4Addr::from(u32::from_be(arp.sender_ip));
        debug!("{sender_ip} asks who-has {target_ip} -> replying");
        build_reply(reply_buf, our_mac, our_ip, &arp.sender_mac, sender_ip)
    } else {
        Ok(0)
    }
}

pub fn send_gratuitous(usb: &UsbDevice, mac: &[u8; 6], ip: Ipv4Addr) -> Result<()> {
    let mut garp_eth = [0u8; ETH_BUF_SIZE];
    let total = std::mem::size_of::<EthHdr>() + std::mem::size_of::<ArpPacket>();

    let eth = EthHdr {
        dst: [0xFF; 6],
        src: *mac,
        ethertype: ARP_ETHERTYPE.to_be(),
    };
    let eth_ptr = garp_eth.as_mut_ptr() as *mut EthHdr;
    unsafe { eth_ptr.write_unaligned(eth) };

    let arp = ArpPacket {
        hw_type: ARP_HW_ETHERNET.to_be(),
        proto_type: 0x0800u16.to_be(),
        hw_len: 6,
        proto_len: 4,
        opcode: ARP_OP_REPLY.to_be(),
        sender_mac: *mac,
        sender_ip: u32::from(ip).to_be(),
        target_mac: [0xFF; 6],
        target_ip: u32::from(ip).to_be(),
    };
    let arp_ptr = unsafe { garp_eth.as_mut_ptr().add(std::mem::size_of::<EthHdr>()) as *mut ArpPacket };
    unsafe { arp_ptr.write_unaligned(arp) };

    let mut rndis_buf = [0u8; crate::net_types::RNDIS_BUF_SIZE];
    let rndis_len = rndis::build_data_packet(&mut rndis_buf, &garp_eth[..total])?;
    let _ = usb.send_bulk(&rndis_buf[..rndis_len])?;
    info!("sent gratuitous ARP");
    Ok(())
}
