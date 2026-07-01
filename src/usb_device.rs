use crate::error::{Result, TetherError};
use log::{debug, info, warn};
use nusb::{
    descriptors::TransferType,
    transfer::{Bulk, ControlIn, ControlOut, ControlType, In, Out, Recipient, TransferError},
    Device, Endpoint, Interface, MaybeFuture,
};
use std::time::Duration;

pub const USB_CTRL_TIMEOUT: Duration = Duration::from_secs(5);
pub const USB_BULK_TIMEOUT: Duration = Duration::from_millis(500);

const CDC_SEND_ENCAPSULATED: u8 = 0x00;
const CDC_GET_ENCAPSULATED: u8 = 0x01;

pub struct UsbDevice {
    _device: Device,
    iface_comm: Interface,
    iface_data: Option<Interface>,
    pub ep_in_addr: u8,
    pub ep_out_addr: u8,
    #[allow(dead_code)]
    pub ep_int_addr: u8,
    pub comm_iface: u8,
    #[allow(dead_code)]
    pub data_iface: u8,
}

impl UsbDevice {
    fn is_rndis_interface(class: u8, subclass: u8, protocol: u8) -> bool {
        matches!(
            (class, subclass, protocol),
            (0xE0, 0x01, 0x03)   // RNDIS (Wireless Controller)
            | (0x02, 0x02, 0x03)  // RNDIS (CDC)
            | (0x02, 0xFF, 0x03)  // RNDIS (vendor-specific)
            | (0xFF, 0x01, 0x03)  // RNDIS (vendor-specific)
            | (0x02, 0x0D, 0x00)  // CDC NCM (Network Control Model)
            | (0x02, 0x06, 0x00)  // CDC ECM (Ethernet Control Model)
        )
    }

    fn is_data_interface(class: u8, _subclass: u8, _protocol: u8) -> bool {
        class == 0x0A
    }

    pub fn find_rndis() -> Result<Self> {
        let device_list = nusb::list_devices().wait().map_err(TetherError::Usb)?;

        for dev_info in device_list {
            let vid = dev_info.vendor_id();
            let pid = dev_info.product_id();

            let device = match dev_info.open().wait() {
                Ok(d) => d,
                Err(_) => continue,
            };

            let config = match device.active_configuration() {
                Ok(c) => c,
                Err(e) => {
                    debug!("device {vid:04x}:{pid:04x}: active_config failed: {e}");
                    continue;
                }
            };

            let mut comm_iface = None;
            let mut data_iface = None;
            let mut iface_count = 0usize;

            for ifaces in config.interfaces() {
                for alt in ifaces.alt_settings() {
                    iface_count += 1;
                    let inum = alt.interface_number();
                    let class = alt.class();
                    let subclass = alt.subclass();
                    let protocol = alt.protocol();
                    debug!(
                        "device {vid:04x}:{pid:04x} iface {inum}: class={class:02x} sub={subclass:02x} proto={protocol:02x}"
                    );
                    if Self::is_rndis_interface(class, subclass, protocol) {
                        comm_iface = Some(inum);
                        info!(
                            "found RNDIS comm interface {inum} on {vid:04x}:{pid:04x} (class={class:02x} sub={subclass:02x} proto={protocol:02x})"
                        );
                    }
                    if Self::is_data_interface(class, subclass, protocol) && comm_iface.is_some() {
                        data_iface = Some(inum);
                    }
                }
            }

            debug!("device {vid:04x}:{pid:04x}: {iface_count} interfaces found");
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
            let comm_iface = comm_iface.unwrap();

            let iface_comm = match device.detach_and_claim_interface(comm_iface).wait() {
                Ok(i) => i,
                Err(e) => {
                    warn!("failed to claim comm interface: {e}");
                    continue;
                }
            };

            let iface_data = match device.claim_interface(data_iface).wait() {
                Ok(i) => Some(i),
                Err(e) => {
                    warn!("failed to claim data interface: {e}");
                    continue;
                }
            };

            let mut ep_in = 0;
            let mut ep_out = 0;
            let mut ep_int = 0;

            for ifaces in config.interfaces() {
                for alt in ifaces.alt_settings() {
                    let inum = alt.interface_number();
                    if inum != comm_iface && inum != data_iface {
                        continue;
                    }
                    for ep_desc in alt.endpoints() {
                        let addr = ep_desc.address();
                        let dir = addr & 0x80;
                        match (ep_desc.transfer_type(), dir, inum == comm_iface) {
                            (TransferType::Interrupt, _, true) => ep_int = addr,
                            (TransferType::Bulk, 0x80, _) => ep_in = addr,
                            (TransferType::Bulk, 0x00, _) => ep_out = addr,
                            _ => {}
                        }
                    }
                }
            }

            if ep_in == 0 || ep_out == 0 {
                if let Some(ref iface_data) = iface_data {
                    if let Ok(()) = iface_data.set_alt_setting(1).wait() {
                        if let Ok(config2) = device.active_configuration() {
                            for ifaces in config2.interfaces() {
                                for alt in ifaces.alt_settings() {
                                    if alt.interface_number() != data_iface
                                        || alt.alternate_setting() != 1
                                    {
                                        continue;
                                    }
                                    for ep_desc in alt.endpoints() {
                                        let addr = ep_desc.address();
                                        let dir = addr & 0x80;
                                        if ep_desc.transfer_type() == TransferType::Bulk {
                                            match dir {
                                                0x80 => ep_in = addr,
                                                _ => ep_out = addr,
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            info!("endpoints: IN=0x{ep_in:02x} OUT=0x{ep_out:02x} INT=0x{ep_int:02x}");

            if ep_in != 0 && ep_out != 0 {
                info!("opened device {vid:04x}:{pid:04x}");
                return Ok(Self {
                    _device: device,
                    iface_comm,
                    iface_data,
                    ep_in_addr: ep_in,
                    ep_out_addr: ep_out,
                    ep_int_addr: ep_int,
                    comm_iface,
                    data_iface,
                });
            }

            drop(iface_data);
            drop(iface_comm);
        }

        Err(TetherError::DeviceNotFound(
            "no Android RNDIS device found — ensure USB tethering is enabled".into(),
        ))
    }

    pub fn send_ctrl(&self, data: &[u8]) -> Result<usize> {
        self.iface_comm
            .control_out(
                ControlOut {
                    control_type: ControlType::Class,
                    recipient: Recipient::Interface,
                    request: CDC_SEND_ENCAPSULATED,
                    value: 0,
                    index: self.comm_iface as u16,
                    data,
                },
                USB_CTRL_TIMEOUT,
            )
            .wait()?;
        Ok(data.len())
    }

    pub fn recv_ctrl(&self, buf: &mut [u8]) -> Result<usize> {
        let response: Vec<u8> = self
            .iface_comm
            .control_in(
                ControlIn {
                    control_type: ControlType::Class,
                    recipient: Recipient::Interface,
                    request: CDC_GET_ENCAPSULATED,
                    value: 0,
                    index: self.comm_iface as u16,
                    length: buf.len() as u16,
                },
                USB_CTRL_TIMEOUT,
            )
            .wait()?;
        let n = response.len().min(buf.len());
        buf[..n].copy_from_slice(&response[..n]);
        Ok(n)
    }

    pub fn send_bulk(&self, data: &[u8]) -> Result<usize> {
        let ref_iface = self.iface_data.as_ref().unwrap_or(&self.iface_comm);
        let mut ep_out: Endpoint<Bulk, Out> = ref_iface.endpoint(self.ep_out_addr)?;
        let mut buf = nusb::transfer::Buffer::new(data.len());
        buf.extend_from_slice(data);
        let completion = ep_out.transfer_blocking(buf, USB_BULK_TIMEOUT);
        completion.into_result()?;
        Ok(data.len())
    }

    pub fn recv_bulk(&self, buf: &mut [u8], timeout_ms: u64) -> Result<usize> {
        let ref_iface = self.iface_data.as_ref().unwrap_or(&self.iface_comm);
        let mut ep_in: Endpoint<Bulk, In> = ref_iface.endpoint(self.ep_in_addr)?;
        let max_pkt = ep_in.max_packet_size();
        let requested = buf.len().div_ceil(max_pkt) * max_pkt;
        let xfer_buf = nusb::transfer::Buffer::new(requested);
        let completion = ep_in.transfer_blocking(xfer_buf, Duration::from_millis(timeout_ms));
        match completion.status {
            Ok(()) => {
                let n = completion.actual_len;
                let copy_len = n.min(buf.len());
                buf[..copy_len].copy_from_slice(&completion.buffer[..copy_len]);
                Ok(copy_len)
            }
            Err(TransferError::Cancelled) => Ok(0),
            Err(e) => Err(e.into()),
        }
    }

    #[allow(dead_code)]
    pub fn recv_int(&self, buf: &mut [u8], timeout_ms: u64) -> Result<usize> {
        if self.ep_int_addr == 0 {
            return Ok(0);
        }
        let mut ep_int: Endpoint<nusb::transfer::Interrupt, In> =
            self.iface_comm.endpoint(self.ep_int_addr)?;
        let max_pkt = ep_int.max_packet_size();
        let requested = buf.len().div_ceil(max_pkt) * max_pkt;
        let xfer_buf = nusb::transfer::Buffer::new(requested);
        let completion = ep_int.transfer_blocking(xfer_buf, Duration::from_millis(timeout_ms));
        match completion.status {
            Ok(()) => {
                let n = completion.actual_len;
                let copy_len = n.min(buf.len());
                buf[..copy_len].copy_from_slice(&completion.buffer[..copy_len]);
                Ok(copy_len)
            }
            Err(TransferError::Cancelled) => Ok(0),
            Err(e) => Err(e.into()),
        }
    }

    pub fn take_endpoints(&self) -> (Endpoint<Bulk, In>, Endpoint<Bulk, Out>) {
        let ref_iface = self.iface_data.as_ref().unwrap_or(&self.iface_comm);
        let ep_in: Endpoint<Bulk, In> = ref_iface
            .endpoint(self.ep_in_addr)
            .expect("bulk IN endpoint");
        let ep_out: Endpoint<Bulk, Out> = ref_iface
            .endpoint(self.ep_out_addr)
            .expect("bulk OUT endpoint");
        (ep_in, ep_out)
    }
}
