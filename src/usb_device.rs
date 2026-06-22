use crate::error::{Result, TetherError};
use log::{info, warn};
use rusb::{Context, DeviceDescriptor, DeviceHandle, UsbContext};

pub const USB_CTRL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
pub const USB_BULK_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(500);

const CDC_SEND_ENCAPSULATED: u8 = 0x00;
const CDC_GET_ENCAPSULATED: u8 = 0x01;

pub struct UsbDevice {
    pub handle: DeviceHandle<Context>,
    pub iface_comm: u8,
    #[allow(dead_code)]
    pub iface_data: u8,
    pub ep_in: u8,
    pub ep_out: u8,
    #[allow(dead_code)]
    pub ep_int: u8,
    #[allow(dead_code)]
    pub vid: u16,
    #[allow(dead_code)]
    pub pid: u16,
}

impl UsbDevice {
    fn is_rndis_interface(class: u8, subclass: u8, protocol: u8) -> bool {
        matches!(
            (class, subclass, protocol),
            (0xE0, 0x01, 0x03)
                | (0x02, 0x02, 0x03)
                | (0x02, 0xFF, 0x03)
                | (0xFF, 0x01, 0x03)
        )
    }

    fn is_data_interface(class: u8, _subclass: u8, _protocol: u8) -> bool {
        class == 0x0A
    }

    pub fn find_rndis() -> Result<Self> {
        let context: Context = Context::new()?;
        let devices = context.devices()?;

        for device in devices.iter() {
            let desc: DeviceDescriptor = match device.device_descriptor() {
                Ok(d) => d,
                Err(_) => continue,
            };

            let config = match device.active_config_descriptor() {
                Ok(c) => c,
                Err(_) => continue,
            };

            let mut comm_iface = None;
            let mut data_iface = None;

            for iface in config.interfaces() {
                for alt in iface.descriptors() {
                    if Self::is_rndis_interface(
                        alt.class_code(),
                        alt.sub_class_code(),
                        alt.protocol_code(),
                    ) {
                        comm_iface = Some(alt.interface_number());
                        info!(
                            "found RNDIS comm interface {} on {:04x}:{:04x} (class={:02x} sub={:02x} proto={:02x})",
                            alt.interface_number(),
                            desc.vendor_id(),
                            desc.product_id(),
                            alt.class_code(),
                            alt.sub_class_code(),
                            alt.protocol_code(),
                        );
                    }
                    if Self::is_data_interface(
                        alt.class_code(),
                        alt.sub_class_code(),
                        alt.protocol_code(),
                    ) && comm_iface.is_some()
                    {
                        data_iface = Some(alt.interface_number());
                    }
                }
            }

            if comm_iface.is_none() {
                continue;
            }
            if data_iface.is_none() {
                data_iface = comm_iface.map(|c| c + 1);
            }
            let data_iface: u8 = match data_iface {
                Some(d) => d,
                None => continue,
            };

            let handle: DeviceHandle<Context> = match device.open() {
                Ok(h) => h,
                Err(e) => {
                    warn!("failed to open device: {e}");
                    continue;
                }
            };

            if handle.kernel_driver_active(comm_iface.unwrap()).unwrap_or(false) {
                let _ = handle.detach_kernel_driver(comm_iface.unwrap());
            }
            if handle.kernel_driver_active(data_iface).unwrap_or(false) {
                let _ = handle.detach_kernel_driver(data_iface);
            }

            if handle.claim_interface(comm_iface.unwrap()).is_err() {
                warn!("failed to claim comm interface, skipping");
                continue;
            }
            if handle.claim_interface(data_iface).is_err() {
                let _ = handle.release_interface(comm_iface.unwrap());
                warn!("failed to claim data interface, skipping");
                continue;
            }

            let mut ep_in = 0;
            let mut ep_out = 0;
            let mut ep_int = 0;

            for iface in config.interfaces() {
                for alt in iface.descriptors() {
                    let inum = alt.interface_number();
                    if inum != comm_iface.unwrap() && inum != data_iface {
                        continue;
                    }
                    let is_comm = inum == comm_iface.unwrap();
                    for ep in alt.endpoint_descriptors() {
                        let ep_addr = ep.address();
                        let dir = ep_addr & 0x80;
                        let tp = ep.transfer_type();
                        match (tp, dir, is_comm) {
                            (rusb::TransferType::Interrupt, _, true) => ep_int = ep_addr,
                            (rusb::TransferType::Bulk, 0x80, _) => ep_in = ep_addr,
                            (rusb::TransferType::Bulk, 0x00, _) => ep_out = ep_addr,
                            _ => {}
                        }
                    }
                }
            }

            if ep_in == 0 || ep_out == 0 {
                if let Ok(()) = handle.set_alternate_setting(data_iface, 1) {
                    if let Ok(config2) = device.active_config_descriptor() {
                        for iface in config2.interfaces() {
                            for alt in iface.descriptors() {
                                if alt.interface_number() != data_iface
                                    || alt.setting_number() != 1
                                {
                                    continue;
                                }
                                for ep in alt.endpoint_descriptors() {
                                    let ep_addr = ep.address();
                                    let dir = ep_addr & 0x80;
                                    if ep.transfer_type() == rusb::TransferType::Bulk {
                                        match dir {
                                            0x80 => ep_in = ep_addr,
                                            _ => ep_out = ep_addr,
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            info!(
                "endpoints: IN=0x{ep_in:02x} OUT=0x{ep_out:02x} INT=0x{ep_int:02x}"
            );

            if ep_in != 0 && ep_out != 0 {
                info!(
                    "opened device {:04x}:{:04x}",
                    desc.vendor_id(),
                    desc.product_id()
                );
                return Ok(Self {
                    handle,
                    iface_comm: comm_iface.unwrap(),
                    iface_data: data_iface,
                    ep_in,
                    ep_out,
                    ep_int,
                    vid: desc.vendor_id(),
                    pid: desc.product_id(),
                });
            }

            let _ = handle.release_interface(data_iface);
            let _ = handle.release_interface(comm_iface.unwrap());
        }

        Err(TetherError::DeviceNotFound(
            "no Android RNDIS device found — ensure USB tethering is enabled".into(),
        ))
    }

    pub fn send_ctrl(&self, data: &[u8]) -> Result<usize> {
        let n = self.handle.write_control(
            0x21,
            CDC_SEND_ENCAPSULATED,
            0,
            self.iface_comm as u16,
            data,
            USB_CTRL_TIMEOUT,
        )?;
        Ok(n)
    }

    pub fn recv_ctrl(&self, buf: &mut [u8]) -> Result<usize> {
        let n = self.handle.read_control(
            0xA1,
            CDC_GET_ENCAPSULATED,
            0,
            self.iface_comm as u16,
            buf,
            USB_CTRL_TIMEOUT,
        )?;
        Ok(n)
    }

    pub fn send_bulk(&self, data: &[u8]) -> Result<usize> {
        let n = self
            .handle
            .write_bulk(self.ep_out, data, USB_BULK_TIMEOUT)?;
        Ok(n)
    }

    pub fn recv_bulk(&self, buf: &mut [u8], timeout_ms: u64) -> Result<usize> {
        let timeout = std::time::Duration::from_millis(timeout_ms);
        match self.handle.read_bulk(self.ep_in, buf, timeout) {
            Ok(n) => Ok(n),
            Err(rusb::Error::Timeout) => Ok(0),
            Err(e) => Err(e.into()),
        }
    }

    #[allow(dead_code)]
    pub fn recv_int(&self, buf: &mut [u8], timeout_ms: u64) -> Result<usize> {
        if self.ep_int == 0 {
            return Ok(0);
        }
        let timeout = std::time::Duration::from_millis(timeout_ms);
        match self.handle.read_interrupt(self.ep_int, buf, timeout) {
            Ok(n) => Ok(n),
            Err(rusb::Error::Timeout) => Ok(0),
            Err(e) => Err(e.into()),
        }
    }

}

impl Drop for UsbDevice {
    fn drop(&mut self) {
        let _ = self.handle.release_interface(self.iface_data);
        let _ = self.handle.release_interface(self.iface_comm);
    }
}

unsafe impl Send for UsbDevice {}
