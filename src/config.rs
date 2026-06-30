use crate::error::{Result, TetherError};
use clap::Parser;
use log::LevelFilter;
use std::net::Ipv4Addr;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DnsMode {
    System,
    DoH,
    DoT,
    Dnscrypt,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DnsProvider {
    Cloudflare,
    Google,
    Quad9,
}

#[derive(Parser, Debug)]
#[command(name = "android-tether", version, about = "Android USB Tethering for macOS (Rust)")]
pub struct CliArgs {
    #[arg(short = 'n', long = "no-route")]
    pub no_route: bool,

    #[arg(short = 'd', long = "no-dns")]
    pub no_dns: bool,

    #[arg(short = 's', long = "static")]
    pub static_ip: Option<String>,

    #[arg(short = 'g', long = "gateway")]
    pub gateway: Option<String>,

    #[arg(short = 'm', long = "netmask")]
    pub netmask: Option<String>,

    #[arg(short = 'c', long = "config")]
    pub config: Option<PathBuf>,

    #[arg(short = 'v', long = "verbose")]
    pub verbose: bool,

    #[arg(short = 'w', long = "watch")]
    pub watch: bool,

    #[arg(long = "dns-mode", value_name = "MODE", default_value = "system")]
    pub dns_mode: String,

    #[arg(long = "dns-provider", value_name = "PROVIDER", default_value = "cloudflare")]
    pub dns_provider: String,

    #[arg(long = "daemon", help = "Run in background mode (for use by launchd)")]
    pub daemon: bool,

    #[arg(long = "install", help = "Install as a launchd daemon (auto-start on device plug)")]
    pub install: bool,

    #[arg(long = "uninstall", help = "Remove the launchd daemon")]
    pub uninstall: bool,
}

#[derive(Debug)]
pub struct TetherConfig {
    pub no_route: bool,
    pub no_dns: bool,
    pub static_ip: Option<Ipv4Addr>,
    pub gateway: Option<Ipv4Addr>,
    pub netmask: Ipv4Addr,
    pub log_level: LevelFilter,
    pub watch_mode: bool,
    pub dns_mode: DnsMode,
    pub dns_provider: DnsProvider,
    pub daemon: bool,
    pub install: bool,
    pub uninstall: bool,
}

impl Default for TetherConfig {
    fn default() -> Self {
        Self {
            no_route: false,
            no_dns: false,
            static_ip: None,
            gateway: None,
            netmask: "255.255.255.0".parse().unwrap(),
            log_level: LevelFilter::Info,
            watch_mode: false,
            dns_mode: DnsMode::System,
            dns_provider: DnsProvider::Cloudflare,
            daemon: false,
            install: false,
            uninstall: false,
        }
    }
}

impl TetherConfig {
    pub fn from_cli() -> Result<Self> {
        let args = CliArgs::parse();

        let log_level = if args.verbose {
            LevelFilter::Debug
        } else {
            LevelFilter::Info
        };

        let mut self_ = Self {
            log_level,
            watch_mode: args.watch,
            daemon: args.daemon,
            install: args.install,
            uninstall: args.uninstall,
            ..Default::default()
        };

        // In daemon mode, --no-route is the default (don't hijack default route)
        if args.daemon && !args.no_route {
            // only override if user didn't explicitly pass --no-route
            // We don't force no_route here; the daemon plist passes --no-route by default
            // Users can edit the plist to add routes if they want
        }
        if args.no_route {
            self_.no_route = true;
        }
        if args.no_dns {
            self_.no_dns = true;
        }

        let config_path = args.config
            .or_else(|| {
                dirs_next::config_dir().map(|p| p.join("android-tether").join("config"))
            });

        if let Some(ref path) = config_path {
            if path.exists() {
                if let Ok(contents) = std::fs::read_to_string(path) {
                    self_.merge_ini(&contents);
                }
            }
        }

        if let Some(ip) = args.static_ip {
            self_.static_ip = Some(
                ip.parse()
                    .map_err(|_| TetherError::Config(format!("invalid IP: {ip}")))?,
            );
        }
        if let Some(gw) = args.gateway {
            self_.gateway = Some(
                gw.parse()
                    .map_err(|_| TetherError::Config(format!("invalid gateway: {gw}")))?,
            );
        }
        if let Some(mask) = args.netmask {
            self_.netmask = mask
                .parse()
                .map_err(|_| TetherError::Config(format!("invalid netmask: {mask}")))?;
        }

        self_.dns_mode = parse_dns_mode(&args.dns_mode);
        self_.dns_provider = parse_dns_provider(&args.dns_provider);

        if self_.static_ip.is_some() && self_.gateway.is_none() {
            self_.gateway = Some("192.168.42.129".parse().unwrap());
        }

        Ok(self_)
    }

    fn merge_ini(&mut self, contents: &str) {
        let mut section = String::new();
        for line in contents.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
                continue;
            }
            if line.starts_with('[') && line.ends_with(']') {
                section = line[1..line.len() - 1].to_lowercase();
                continue;
            }
            if let Some(eq) = line.find('=') {
                let key = line[..eq].trim();
                let val = line[eq + 1..].trim();
                match (section.as_str(), key) {
                    ("network", "no_route") => self.no_route = val == "true",
                    ("network", "no_dns") => self.no_dns = val == "true",
                    ("network", "static_ip") if !val.is_empty() => {
                        if let Ok(ip) = val.parse() {
                            self.static_ip = Some(ip);
                        }
                    }
                    ("network", "gateway") if !val.is_empty() => {
                        if let Ok(ip) = val.parse() {
                            self.gateway = Some(ip);
                        }
                    }
                    ("network", "netmask") if !val.is_empty() => {
                        if let Ok(mask) = val.parse() {
                            self.netmask = mask;
                        }
                    }
                    ("logging", "level") => {
                        self.log_level = match val.to_lowercase().as_str() {
                            "debug" => LevelFilter::Debug,
                            "info" => LevelFilter::Info,
                            "warn" => LevelFilter::Warn,
                            "error" => LevelFilter::Error,
                            _ => LevelFilter::Info,
                        };
                    }
                    ("dns", "mode") => {
                        self.dns_mode = parse_dns_mode(val);
                    }
                    ("dns", "provider") => {
                        self.dns_provider = parse_dns_provider(val);
                    }
                    _ => {}
                }
            }
        }
    }
}

fn parse_dns_mode(s: &str) -> DnsMode {
    match s.to_lowercase().as_str() {
        "doh" => DnsMode::DoH,
        "dot" => DnsMode::DoT,
        "dnscrypt" => DnsMode::Dnscrypt,
        _ => DnsMode::System,
    }
}

fn parse_dns_provider(s: &str) -> DnsProvider {
    match s.to_lowercase().as_str() {
        "google" => DnsProvider::Google,
        "quad9" => DnsProvider::Quad9,
        _ => DnsProvider::Cloudflare,
    }
}
