use crate::usb_device::UsbDevice;

pub trait ProtocolDriver: Send {
    fn name(&self) -> &str;

    fn init(&mut self, usb: &UsbDevice) -> crate::error::Result<()>;

    fn mac(&self) -> [u8; 6];

    fn wrap_frame(&self, eth: &[u8], out: &mut [u8]) -> crate::error::Result<usize>;

    fn unwrap_data(
        &self,
        usb_data: &[u8],
        on_frame: &mut dyn FnMut(&[u8]),
    ) -> crate::error::Result<()>;

    fn keepalive(&mut self, usb: &UsbDevice) -> crate::error::Result<()> {
        let _ = usb;
        Ok(())
    }
}
