use crate::error::Result;
use crate::proto_driver::ProtocolDriver;
use crate::rndis::{self, RndisPacketIter, RndisState};
use crate::usb_device::UsbDevice;
use log::{info, warn};
use std::time::Duration;

pub struct RndisDriver {
    state: RndisState,
}

impl RndisDriver {
    pub fn new() -> Self {
        Self {
            state: RndisState::default(),
        }
    }
}

impl ProtocolDriver for RndisDriver {
    fn name(&self) -> &str {
        "rndis"
    }

    fn init(&mut self, usb: &UsbDevice) -> Result<()> {
        let mut buf = [0u8; crate::net_types::RNDIS_BUF_SIZE];

        let len = rndis::build_init(&mut buf, &mut self.state)?;
        usb.send_ctrl(&buf[..len])?;

        std::thread::sleep(Duration::from_millis(100));

        let n = usb.recv_ctrl(&mut buf)?;
        rndis::parse_init_cmplt(&buf[..n], &mut self.state)?;

        for oid in &[rndis::OID_802_3_CURRENT_ADDRESS, rndis::OID_802_3_PERMANENT_ADDRESS] {
            let len = rndis::build_query(&mut buf, *oid, &mut self.state)?;
            usb.send_ctrl(&buf[..len])?;
            std::thread::sleep(Duration::from_millis(50));
            let n = usb.recv_ctrl(&mut buf)?;
            let mut mac = [0u8; 6];
            if rndis::parse_query_cmplt(&buf[..n], &mut mac).is_ok() {
                self.state.mac_addr = mac;
            }
        }

        info!(
            "MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.state.mac_addr[0], self.state.mac_addr[1], self.state.mac_addr[2],
            self.state.mac_addr[3], self.state.mac_addr[4], self.state.mac_addr[5]
        );

        let filter = rndis::RNDIS_PACKET_TYPE_DIRECTED
            | rndis::RNDIS_PACKET_TYPE_MULTICAST
            | rndis::RNDIS_PACKET_TYPE_ALL_MULTICAST
            | rndis::RNDIS_PACKET_TYPE_BROADCAST;

        let len = rndis::build_set(
            &mut buf,
            rndis::OID_GEN_CURRENT_PACKET_FILTER,
            &filter.to_le_bytes(),
            &mut self.state,
        )?;
        usb.send_ctrl(&buf[..len])?;

        std::thread::sleep(Duration::from_millis(50));

        let n = usb.recv_ctrl(&mut buf)?;
        if rndis::parse_set_cmplt(&buf[..n]).is_err() {
            warn!("failed to set packet filter");
        }

        self.state.link_up = true;
        info!("RNDIS initialization complete");
        Ok(())
    }

    fn mac(&self) -> [u8; 6] {
        self.state.mac_addr
    }

    fn wrap_frame(&self, eth: &[u8], out: &mut [u8]) -> Result<usize> {
        rndis::build_data_packet(out, eth)
    }

    fn unwrap_data(
        &self,
        usb_data: &[u8],
        on_frame: &mut dyn FnMut(&[u8]),
    ) -> Result<()> {
        for frame in RndisPacketIter::new(usb_data) {
            on_frame(frame);
        }
        Ok(())
    }

    fn keepalive(&mut self, usb: &UsbDevice) -> Result<()> {
        let mut buf = [0u8; crate::net_types::RNDIS_BUF_SIZE];
        let klen = rndis::build_keepalive(&mut buf, &mut self.state)?;
        if klen > 0 {
            let _ = usb.send_ctrl(&buf[..klen]);
            std::thread::sleep(Duration::from_millis(10));
            let _ = usb.recv_ctrl(&mut buf);
        }
        Ok(())
    }
}
