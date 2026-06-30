use crate::config::TetherConfig;
use log::{error, info};
use std::process::Command;

const PLIST_PATH: &str = "/Library/LaunchDaemons/com.tetherd.daemon.plist";
const LOG_DIR: &str = "/var/log";

// Common Android RNDIS VID/PID pairs
const VIDPIDS: &[(&str, &str)] = &[
    ("0x18d1", "0x4eeb"), // Google Nexus/Pixel
    ("0x18d1", "0x4ee1"), // Google Nexus MTP+ADB
    ("0x18d1", "0x4ee2"), // Google Nexus ADB
    ("0x18d1", "0x4ee3"), // Google
    ("0x18d1", "0x4ee4"), // Google Nexus/Pixel RNDIS + ADB
    ("0x18d1", "0x4ee5"), // Google
    ("0x18d1", "0x4ee6"), // Google
    ("0x18d1", "0x4ee7"), // Google
    ("0x22d9", "0x2766"), // OPPO/OnePlus
    ("0x22b8", "0x2e82"), // Motorola
    ("0x0bb4", "0x0ffe"), // HTC
    ("0x0bb4", "0x0c02"), // HTC
    ("0x04e8", "0x6863"), // Samsung
    ("0x04e8", "0x6864"), // Samsung
    ("0x04e8", "0x6865"), // Samsung
    ("0x04e8", "0x6866"), // Samsung
    ("0x2717", "0xff08"), // Xiaomi
    ("0x2717", "0xff80"), // Xiaomi
    ("0x2a70", "0x9011"), // OnePlus
    ("0x1004", "0x633e"), // LG
];

pub fn install_daemon(config: &TetherConfig) {
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            error!("cannot determine current executable: {e}");
            return;
        }
    };

    info!("installing launchd daemon to {PLIST_PATH}");

    let mut args = vec![
        "--daemon".to_string(),
        "--no-route".to_string(),
        "--watch".to_string(),
        format!("--dns-mode={}", dns_mode_flag(config)),
        format!("--dns-provider={}", dns_provider_flag(config)),
    ];

    if let Some(ip) = config.static_ip {
        args.push(format!("--static={ip}"));
    }
    if let Some(gw) = config.gateway {
        args.push(format!("--gateway={gw}"));
    }
    if config.log_level == log::LevelFilter::Debug {
        args.push("--verbose".to_string());
    }

    let program_args_xml: String = args
        .iter()
        .map(|a| format!("            <string>{a}</string>"))
        .collect::<Vec<_>>()
        .join("\n");

    let matching_dicts: String = VIDPIDS
        .iter()
        .map(|(vid, pid)| {
            let vid_int = u32::from_str_radix(vid.trim_start_matches("0x"), 16).unwrap_or(0);
            let pid_int = u32::from_str_radix(pid.trim_start_matches("0x"), 16).unwrap_or(0);
            format!(
                "                <dict>\n\
                 <key>idVendor</key>\n\
                 <integer>{vid_int}</integer>\n\
                 <key>idProduct</key>\n\
                 <integer>{pid_int}</integer>\n\
                 <key>IOProviderClass</key>\n\
                 <string>IOUSBDevice</string>\n\
                 </dict>"
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    let log_file = format!("{LOG_DIR}/tetherd.log");
    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.tetherd.daemon</string>
    <key>ProgramArguments</key>
    <array>
        <string>{exe_path}</string>
{program_args}
    </array>
    <key>LaunchEvents</key>
    <dict>
        <key>com.apple.iokit.matching</key>
        <dict>
            <key>com.apple.device-attach</key>
            <array>
{matching_dicts}
            </array>
        </dict>
    </dict>
    <key>KeepAlive</key>
    <false/>
    <key>RunAtLoad</key>
    <false/>
    <key>StandardOutPath</key>
    <string>{log_file}</string>
    <key>StandardErrorPath</key>
    <string>{log_file}</string>
    <key>UserName</key>
    <string>root</string>
    <key>GroupName</key>
    <string>wheel</string>
</dict>
</plist>"#,
        exe_path = exe.display(),
        program_args = program_args_xml,
        matching_dicts = matching_dicts,
        log_file = log_file,
    );

    if let Err(e) = std::fs::write(PLIST_PATH, &plist) {
        error!("failed to write plist: {e}");
        return;
    }
    info!("plist written to {PLIST_PATH}");

    // Unload any previous instance, then load with -w (persist across reboots)
    let _ = Command::new("launchctl")
        .args(["unload", PLIST_PATH])
        .stderr(std::process::Stdio::null())
        .status();

    match Command::new("launchctl")
        .args(["load", "-w", PLIST_PATH])
        .status()
    {
        Ok(s) if s.success() => {
            info!("daemon installed — will auto-start on next Android device plug");
        }
        Ok(s) => {
            let code = s.code().unwrap_or(-1);
            error!("launchctl load -w failed (exit {code})");
            error!("try manually: sudo launchctl load -w {PLIST_PATH}");
        }
        Err(e) => error!("launchctl load -w failed: {e}"),
    }
}

pub fn uninstall_daemon() {
    info!("uninstalling launchd daemon");

    let _ = Command::new("launchctl")
        .args(["unload", PLIST_PATH])
        .stderr(std::process::Stdio::null())
        .status();

    match std::fs::remove_file(PLIST_PATH) {
        Ok(()) => info!("removed {PLIST_PATH}"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            info!("plist not found at {PLIST_PATH} (already removed)");
        }
        Err(e) => error!("failed to remove plist: {e}"),
    }
}

pub fn setup_daemon_logging(verbose: bool) {
    let log_dir = std::path::PathBuf::from(LOG_DIR);
    let _ = std::fs::create_dir_all(&log_dir);

    let log_file = log_dir.join("tetherd.log");

    let level = if verbose {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Info
    };

    let file = match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_file)
    {
        Ok(f) => f,
        Err(e) => {
            eprintln!("tetherd: cannot open log file: {e}");
            return;
        }
    };

    let _ = env_logger::Builder::new()
        .filter_level(level)
        .format_timestamp_secs()
        .target(env_logger::Target::Pipe(Box::new(file)))
        .try_init();

    info!("tetherd daemon started (pid={})", std::process::id());
}

fn dns_mode_flag(config: &TetherConfig) -> &'static str {
    match config.dns_mode {
        crate::config::DnsMode::System => "system",
        crate::config::DnsMode::DoH => "doh",
        crate::config::DnsMode::DoT => "dot",
    }
}

fn dns_provider_flag(config: &TetherConfig) -> &'static str {
    match config.dns_provider {
        crate::config::DnsProvider::Cloudflare => "cloudflare",
        crate::config::DnsProvider::Google => "google",
        crate::config::DnsProvider::Quad9 => "quad9",
    }
}
