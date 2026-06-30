use crate::frame::eth_to_utun;
use crate::net_types::{ETH_BUF_SIZE, RNDIS_BUF_SIZE};
use crate::proto_driver::ProtocolDriver;
use crate::stats::SharedStats;
use crate::utun::Utun;
use log::debug;
use nusb::transfer::{self, Buffer, Bulk, In, Out};
use nusb::Endpoint;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const NUM_RX_BUFS: usize = 16;
const MAX_OUT_URBS: usize = 32;

pub struct UsbIo {
    ep_in: Endpoint<Bulk, In>,
    ep_out: Endpoint<Bulk, Out>,
}

impl UsbIo {
    pub fn new(ep_in: Endpoint<Bulk, In>, ep_out: Endpoint<Bulk, Out>) -> Self {
        Self { ep_in, ep_out }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn run(
        &mut self,
        tun: Arc<Utun>,
        tx_receiver: mpsc::Receiver<Vec<u8>>,
        drv: Arc<Box<dyn ProtocolDriver>>,
        stats: Arc<SharedStats>,
        host_mac: [u8; 6],
        our_ip: Ipv4Addr,
        gateway_mac: Arc<Mutex<[u8; 6]>>,
        running: Arc<AtomicBool>,
        device_gone: Arc<AtomicBool>,
    ) {
        for _ in 0..NUM_RX_BUFS {
            let buf = Buffer::new(RNDIS_BUF_SIZE);
            self.ep_in.submit(buf);
        }

        let mut frame_logged: u64 = 0;
        let mut _tx_sent_count: u64 = 0;
        let mut active_rx: u32 = NUM_RX_BUFS as u32;

        // Submit initial OUT batch
        Self::refill_tx(&mut self.ep_out, &tx_receiver, &stats, &mut _tx_sent_count);

        while running.load(Ordering::SeqCst) {
            if let Some(comp) = self.ep_in.wait_next_complete(Duration::from_millis(1)) {
                let ok = Self::process_rx_completion(
                    comp,
                    &mut self.ep_in,
                    &mut self.ep_out,
                    &tun,
                    &**drv,
                    &stats,
                    &mut frame_logged,
                    &host_mac,
                    our_ip,
                    &gateway_mac,
                );
                if !ok {
                    active_rx = active_rx.saturating_sub(1);
                }
                while self.ep_in.pending() > 0 {
                    if let Some(extra) = self.ep_in.wait_next_complete(Duration::ZERO) {
                        let ok = Self::process_rx_completion(
                            extra,
                            &mut self.ep_in,
                            &mut self.ep_out,
                            &tun,
                            &**drv,
                            &stats,
                            &mut frame_logged,
                            &host_mac,
                            our_ip,
                            &gateway_mac,
                        );
                        if !ok {
                            active_rx = active_rx.saturating_sub(1);
                        }
                    } else {
                        break;
                    }
                }
            }

            if active_rx == 0 {
                debug!("device disconnected (all rx buffers lost)");
                device_gone.store(true, Ordering::SeqCst);
                running.store(false, Ordering::SeqCst);
                break;
            }

            // Drain OUT completions and refill from TX channel
            Self::drain_out_and_refill(
                &mut self.ep_out,
                &tx_receiver,
                &stats,
                &mut _tx_sent_count,
            );
        }
    }

    fn refill_tx(
        ep_out: &mut Endpoint<Bulk, Out>,
        tx_receiver: &mpsc::Receiver<Vec<u8>>,
        stats: &SharedStats,
        tx_sent_count: &mut u64,
    ) {
        while ep_out.pending() < MAX_OUT_URBS {
            match tx_receiver.try_recv() {
                Ok(pkt) => {
                    let len = pkt.len();
                    ep_out.submit(pkt.into());
                    *tx_sent_count += 1;
                    stats.tx_pkts.fetch_add(1, Ordering::Relaxed);
                    stats.tx_bytes.fetch_add(len as u64, Ordering::Relaxed);
                }
                Err(_) => break,
            }
        }
    }

    fn drain_out_and_refill(
        ep_out: &mut Endpoint<Bulk, Out>,
        tx_receiver: &mpsc::Receiver<Vec<u8>>,
        stats: &SharedStats,
        tx_sent_count: &mut u64,
    ) {
        while ep_out.pending() > 0 {
            if let Some(_comp) = ep_out.wait_next_complete(Duration::ZERO) {
                // Freed up one slot — submit next from channel
                match tx_receiver.try_recv() {
                    Ok(pkt) => {
                        let len = pkt.len();
                        ep_out.submit(pkt.into());
                        *tx_sent_count += 1;
                        stats.tx_pkts.fetch_add(1, Ordering::Relaxed);
                        stats.tx_bytes.fetch_add(len as u64, Ordering::Relaxed);
                    }
                    Err(_) => {}
                }
            } else {
                break;
            }
        }
        // Top up to MAX_OUT_URBS
        Self::refill_tx(ep_out, tx_receiver, stats, tx_sent_count);
    }

    #[allow(clippy::too_many_arguments)]
    fn process_rx_completion(
        comp: transfer::Completion,
        ep_in: &mut Endpoint<Bulk, In>,
        ep_out: &mut Endpoint<Bulk, Out>,
        tun: &Utun,
        drv: &dyn ProtocolDriver,
        stats: &SharedStats,
        frame_logged: &mut u64,
        host_mac: &[u8; 6],
        our_ip: Ipv4Addr,
        gateway_mac: &Arc<Mutex<[u8; 6]>>,
    ) -> bool {
        if comp.status.is_err() {
            return false;
        }

        if comp.actual_len == 0 {
            let pending_before = ep_in.pending();
            let mut buf = comp.buffer;
            buf.clear();
            ep_in.submit(buf);
            return ep_in.pending() > pending_before;
        }

        let n = comp.actual_len;
        let mut arp_replies: Vec<Vec<u8>> = Vec::new();

        {
            let mut utun_buf = [0u8; ETH_BUF_SIZE + 4];

            let mut on_frame = |frame: &[u8]| {
                if frame.len() < 14 {
                    return;
                }
                let ethertype = u16::from_be_bytes([frame[12], frame[13]]);

                if *frame_logged < 10 {
                    debug!(
                        "RX frame #{}: ethertype=0x{ethertype:04x} len={}",
                        *frame_logged + 1,
                        frame.len()
                    );
                    *frame_logged += 1;
                }

                let fsrc = &frame[6..12];
                if fsrc[0] != 0xFF {
                    let mut gw = gateway_mac.lock().unwrap();
                    if *gw != *fsrc {
                        gw.copy_from_slice(fsrc);
                        debug!(
                            "gateway MAC now: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                            gw[0], gw[1], gw[2], gw[3], gw[4], gw[5]
                        );
                    }
                }

                if ethertype == crate::net_types::ARP_ETHERTYPE {
                    let mut reply_buf = [0u8; crate::net_types::ETH_BUF_SIZE];
                    if let Ok(len) =
                        crate::arp::handle_request(frame, &mut reply_buf, host_mac, our_ip)
                    {
                        if len > 0 {
                            arp_replies.push(reply_buf[..len].to_vec());
                        }
                    }
                    return;
                }

                match eth_to_utun(frame, &mut utun_buf) {
                    Ok(0) => {}
                    Ok(utun_len) => {
                        let _ = tun.write(&utun_buf[..utun_len]);
                        stats.rx_pkts.fetch_add(1, Ordering::Relaxed);
                        stats.rx_bytes.fetch_add(frame.len() as u64, Ordering::Relaxed);
                    }
                    Err(_) => {}
                }
            };

            let _ = drv.unwrap_data(&comp.buffer[..n], &mut on_frame);
        }

        for reply in &arp_replies {
            let mut rndis_buf = [0u8; RNDIS_BUF_SIZE];
            if let Ok(rlen) = drv.wrap_frame(reply, &mut rndis_buf) {
                let usb_buf: Buffer = rndis_buf[..rlen].to_vec().into();
                ep_out.submit(usb_buf);
            }
        }

        let pending_before = ep_in.pending();
        let mut buf = comp.buffer;
        buf.clear();
        ep_in.submit(buf);
        ep_in.pending() > pending_before
    }
}
