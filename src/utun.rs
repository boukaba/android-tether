use crate::error::{Result, TetherError};
use log::{info, warn};
use std::os::unix::io::{AsRawFd, RawFd};
use std::process::{Command, Stdio};
use std::io::Write;

const UTUN_CONTROL_NAME: &str = "com.apple.net.utun_control\0";

#[repr(C)]
struct CtlInfo {
    ctl_id: u32,
    ctl_name: [u8; 96],
}

#[repr(C)]
struct SockaddrCtl {
    sc_len: u8,
    sc_family: u8,
    ss_sysaddr: u16,
    sc_id: u32,
    sc_unit: u32,
    sc_reserved: [u32; 5],
}

const CTLIOCGINFO: u64 = 0xc0644e03;

fn scutil(script: &str) {
    let mut child = match Command::new("scutil")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return,
    };
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(script.as_bytes());
    }
    let _ = child.wait();
}

pub struct Utun {
    pub fd: RawFd,
    #[allow(dead_code)]
    pub unit: u32,
    pub ifname: String,
}

impl Utun {
    pub fn create() -> Result<Self> {
        let fd = unsafe { libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, 2) };
        if fd < 0 {
            return Err(TetherError::Network("failed to create utun socket".into()));
        }

        let name_bytes = UTUN_CONTROL_NAME.as_bytes();
        let mut ci = CtlInfo {
            ctl_id: 0,
            ctl_name: [0u8; 96],
        };
        let copy_len = name_bytes.len().min(95);
        ci.ctl_name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

        let ret = unsafe { libc::ioctl(fd, CTLIOCGINFO, &ci as *const _ as *const libc::c_void) };
        if ret < 0 {
            unsafe { libc::close(fd) };
            return Err(TetherError::Network("CTLIOCGINFO failed".into()));
        }

        let mut unit = None;
        for u in 0..256u32 {
            let sa = SockaddrCtl {
                sc_len: std::mem::size_of::<SockaddrCtl>() as u8,
                sc_family: libc::AF_SYSTEM as u8,
                ss_sysaddr: 2,
                sc_id: ci.ctl_id,
                sc_unit: u + 1,
                sc_reserved: [0; 5],
            };
            let ret = unsafe {
                libc::connect(
                    fd,
                    &sa as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<SockaddrCtl>() as u32,
                )
            };
            if ret == 0 {
                unit = Some(u);
                break;
            }
        }

        let unit = unit.ok_or_else(|| TetherError::Network("no available utun unit".into()))?;

        let ifname = format!("utun{unit}");

        let bufsize = 4 * 1024 * 1024;
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &bufsize as *const _ as *const libc::c_void,
                std::mem::size_of_val(&bufsize) as u32,
            );
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                &bufsize as *const _ as *const libc::c_void,
                std::mem::size_of_val(&bufsize) as u32,
            );
        }

        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL, 0) };
        if flags >= 0 {
            unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
        }

        info!("created interface {ifname}");
        Ok(Self { fd, unit, ifname })
    }

    pub fn read(&self, buf: &mut [u8]) -> Result<usize> {
        let n = unsafe { libc::read(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                return Ok(0);
            }
            return Err(TetherError::Network(format!("utun read: {err}")));
        }
        Ok(n as usize)
    }

    pub fn write(&self, buf: &[u8]) -> Result<usize> {
        let n = unsafe { libc::write(self.fd, buf.as_ptr() as *const libc::c_void, buf.len()) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                return Ok(0);
            }
            return Err(TetherError::Network(format!("utun write: {err}")));
        }
        Ok(n as usize)
    }

    pub fn configure(&self, local_ip: &str, remote_ip: &str, netmask: &str) -> Result<()> {
        let cmd = format!(
            "ifconfig {} inet {} {} netmask {} up",
            self.ifname, local_ip, remote_ip, netmask
        );
        info!("{cmd}");
        let status = Command::new("sh")
            .arg("-c")
            .arg(&cmd)
            .status()
            .map_err(|e| TetherError::Network(format!("ifconfig failed: {e}")))?;
        if !status.success() {
            warn!("ifconfig returned non-zero: {status:?}");
        }
        let mtu_cmd = format!("ifconfig {} mtu 1500", self.ifname);
        let _ = Command::new("sh").arg("-c").arg(&mtu_cmd).status();
        Ok(())
    }

    pub fn set_default_route(&self, gateway: &str) -> Result<()> {
        let _ = Command::new("sh")
            .arg("-c")
            .arg(format!("route delete {gateway} 2>/dev/null"))
            .status();
        let prefixes = ["0.0.0.0/1", "128.0.0.0/1"];
        for prefix in &prefixes {
            let _ = Command::new("sh")
                .arg("-c")
                .arg(format!("route delete -net {prefix} 2>/dev/null"))
                .status();
            let cmd = format!("route add -net {prefix} {gateway}");
            info!("{cmd}");
            let _ = Command::new("sh").arg("-c").arg(&cmd).status();
        }
        Ok(())
    }

    pub fn register_service(
        ifname: &str,
        ip: &str,
        gateway: &str,
        netmask: &str,
        dns1: &str,
        dns2: &str,
    ) {
        let service_id = "android-tether";
        let dns_part = if !dns1.is_empty() {
            if !dns2.is_empty() {
                format!("{dns1} {dns2}")
            } else {
                dns1.to_string()
            }
        } else {
            String::new()
        };

        let script = format!(
            "d.init\n\
             d.add Addresses * {ip}\n\
             d.add SubnetMasks * {netmask}\n\
             d.add Router {gateway}\n\
             d.add InterfaceName {ifname}\n\
             set State:/Network/Service/{service_id}/IPv4\n\
             quit\n"
        );
        scutil(&script);

        let script2 = format!(
            "d.init\n\
             d.add DeviceName {ifname}\n\
             d.add Type utun\n\
             set State:/Network/Service/{service_id}/Interface\n\
             quit\n"
        );
        scutil(&script2);

        if !dns_part.is_empty() {
            let script3 = format!(
                "d.init\n\
                 d.add ServerAddresses * {dns_part}\n\
                 d.add SupplementalMatchDomains * \"\"\n\
                 d.add SearchOrder # 1\n\
                 set State:/Network/Service/{service_id}/DNS\n\
                 quit\n"
            );
            scutil(&script3);
        }

        info!("registered network service '{service_id}' on {ifname}");
    }

    pub fn unregister_service() {
        let service_id = "android-tether";
        let script = format!(
            "remove State:/Network/Service/{service_id}/IPv4\n\
             remove State:/Network/Service/{service_id}/DNS\n\
             remove State:/Network/Service/{service_id}/Interface\n\
             quit\n"
        );
        scutil(&script);
        info!("unregistered network service");
    }
}

impl AsRawFd for Utun {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for Utun {
    fn drop(&mut self) {
        if self.fd >= 0 {
            unsafe { libc::close(self.fd) };
            info!("closed interface {}", self.ifname);
        }
    }
}
