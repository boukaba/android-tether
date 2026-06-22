use crate::stats::TetherStats;
use log::{error, info};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

const IPC_SOCK_PATH: &str = "/tmp/android-tether.sock";

#[derive(Serialize)]
struct StatsMsg<'a> {
    #[serde(rename = "type")]
    msg_type: &'a str,
    tx_mbps: f64,
    rx_mbps: f64,
    tx_bytes: u64,
    rx_bytes: u64,
    tx_pkts: u64,
    rx_pkts: u64,
}

#[derive(Serialize)]
struct StateMsg<'a> {
    #[serde(rename = "type")]
    msg_type: &'a str,
    state: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    ip: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    iface: Option<&'a str>,
}

#[derive(Deserialize)]
struct ClientMsg {
    #[serde(rename = "type")]
    msg_type: String,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum IpcCommand {
    None,
    Stop,
    Disable,
    Enable,
    #[allow(dead_code)]
    Status,
}

pub struct IpcServer {
    listener: Option<UnixListener>,
    clients: Mutex<Vec<UnixStream>>,
    stop_requested: Arc<AtomicBool>,
    disable_requested: Arc<AtomicBool>,
    enable_requested: Arc<AtomicBool>,
}

impl IpcServer {
    pub fn new() -> Self {
        let _ = std::fs::remove_file(IPC_SOCK_PATH);
        let listener = match UnixListener::bind(IPC_SOCK_PATH) {
            Ok(l) => {
                info!("IPC listening on {IPC_SOCK_PATH}");
                Some(l)
            }
            Err(e) => {
                error!("failed to create IPC socket: {e}");
                None
            }
        };

        Self {
            listener,
            clients: Mutex::new(Vec::new()),
            stop_requested: Arc::new(AtomicBool::new(false)),
            disable_requested: Arc::new(AtomicBool::new(false)),
            enable_requested: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn poll(&self) -> IpcCommand {
        if self.stop_requested.load(Ordering::Relaxed) {
            self.stop_requested.store(false, Ordering::Relaxed);
            return IpcCommand::Stop;
        }
        if self.disable_requested.load(Ordering::Relaxed) {
            self.disable_requested.store(false, Ordering::Relaxed);
            return IpcCommand::Disable;
        }
        if self.enable_requested.load(Ordering::Relaxed) {
            self.enable_requested.store(false, Ordering::Relaxed);
            return IpcCommand::Enable;
        }

        if let Some(ref listener) = self.listener {
            listener.set_nonblocking(true).ok();
            if let Ok((stream, _)) = listener.accept() {
                stream.set_nonblocking(true).ok();
                if let Ok(mut clients) = self.clients.lock() {
                    clients.push(stream);
                }
            }
        }

        let stop = self.stop_requested.clone();
        let disable = self.disable_requested.clone();
        let enable = self.enable_requested.clone();

        if let Ok(mut clients) = self.clients.lock() {
            clients.retain_mut(|stream| {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                match reader.read_line(&mut line) {
                    Ok(0) | Err(_) => false,
                    Ok(_) => {
                        if let Ok(msg) = serde_json::from_str::<ClientMsg>(&line) {
                            match msg.msg_type.as_str() {
                                "stop" => stop.store(true, Ordering::Relaxed),
                                "disable" => disable.store(true, Ordering::Relaxed),
                                "enable" => enable.store(true, Ordering::Relaxed),
                                _ => {}
                            }
                        }
                        true
                    }
                }
            });
        }

        IpcCommand::None
    }

    pub fn send_stats(&self, stats: &TetherStats) {
        let msg = StatsMsg {
            msg_type: "stats",
            tx_mbps: stats.tx_mbps,
            rx_mbps: stats.rx_mbps,
            tx_bytes: stats.tx_bytes,
            rx_bytes: stats.rx_bytes,
            tx_pkts: stats.tx_pkts,
            rx_pkts: stats.rx_pkts,
        };
        if let Ok(json) = serde_json::to_string(&msg) {
            self.broadcast((json + "\n").as_bytes());
        }
    }

    pub fn send_state(&self, state: &str, ip: Option<&str>, iface: Option<&str>) {
        let msg = StateMsg {
            msg_type: "state",
            state,
            ip,
            iface,
        };
        if let Ok(json) = serde_json::to_string(&msg) {
            self.broadcast((json + "\n").as_bytes());
        }
    }

    fn broadcast(&self, data: &[u8]) {
        if let Ok(mut clients) = self.clients.lock() {
            clients.retain_mut(|stream| {
                let _ = stream.set_nonblocking(true);
                stream.try_clone()
                    .map(|mut s| s.write_all(data))
                    .is_ok()
            });
        }
    }
}
