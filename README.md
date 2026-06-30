# android-tether

> Android USB Tethering for macOS — fast, encrypted, pure Rust.

Bridges a USB-tethered Android phone to a macOS `utun` virtual interface, providing internet access via the phone's cellular or WiFi connection. Zero dependencies — no `libusb`, no kernel extensions, no SIP disabled.

## Features

- **Pure Rust** — `nusb` talks directly to IOKit. No C, no libusb, no kexts.
- **Encrypted DNS** — built-in DNS-over-HTTPS (DoH) and DNS-over-TLS (DoT) with Cloudflare, Google, or Quad9. Intercepts all outbound DNS queries. No DNS leaks.
- **Auto-config** — DHCP, `ifconfig`, `scutil`, routing, DNS registration. One command.
- **Watch mode** — auto-reconnect on unplug/replug. JSON IPC socket for external control.
- **Daemon mode** — install as a `launchd` LaunchDaemon. Auto-starts when phone is plugged in. No terminal needed.
- **Zero-conf** — no static IP needed. Works with any Android phone that supports USB tethering.
- **Apple Silicon native** — arm64 binary, no Rosetta needed.

## Quick Start

```bash
brew install boukaba/tap/android-tether
sudo android-tether --watch --dns-mode doh
```

## Installation

### Homebrew

```bash
brew install boukaba/tap/android-tether
```

For the latest development version:

```bash
brew install --HEAD boukaba/tap/android-tether
```

### From Source

```bash
git clone https://github.com/boukaba/android-tether.git
cd android-tether
cargo build --release
sudo cp target/release/android-tether /usr/local/bin/
```

## Usage

```
android-tether [OPTIONS]

Options:
  -w, --watch              Watch mode: auto-reconnect on device removal
  -v, --verbose            Enable debug logging
  -n, --no-route           Skip adding default routes
  -d, --no-dns             Skip DNS/scutil registration
  -s, --static <IP>        Use static IP instead of DHCP
  -g, --gateway <IP>       Override gateway (with --static)
  -m, --netmask <MASK>     Override netmask
      --dns-mode <MODE>    DNS mode: system, doh, dot [default: system]
      --dns-provider <P>   DNS provider: cloudflare, google, quad9 [default: cloudflare]
      --install            Install as launchd daemon (auto-start on plug)
      --uninstall          Remove the launchd daemon
```

### Daemon Mode

Install once, forget about it:

```bash
sudo android-tether --install --dns-mode doh
sudo android-tether --uninstall
```

The daemon runs silently in the background. Logs go to `/var/log/tetherd.log`. By default, it uses `--no-route` (won't steal your WiFi/Ethernet internet). To make the phone the default gateway:

```bash
sudo sed -i '' '/--no-route/d' /Library/LaunchDaemons/com.tetherd.daemon.plist
sudo launchctl unload /Library/LaunchDaemons/com.tetherd.daemon.plist
sudo launchctl load -w /Library/LaunchDaemons/com.tetherd.daemon.plist
```

### IPC Control

In watch mode, a Unix domain socket at `/tmp/android-tether.sock` accepts JSON commands:

```json
{"command":"status"}
{"command":"stop"}
{"command":"disable"}
```

Stats are pushed every 5 seconds:

```json
{"type":"stats","tx_mbps":1.2,"rx_mbps":15.3,"tx_pkts":420,"rx_pkts":1337}
```

## How It Works

```
[Android Phone] ──USB──▶ [nusb/IOKit] ──▶ [I/O Thread] ──▶ [utun interface] ──▶ [macOS]
                              │                    │
                              │  16 concurrent     │  RNDIS unwrap
                              │  RX URBs           │  eth_to_utun
                              │                    │  ARP handling
                              │                    │
                              ◀── TX Channel ────── TX Thread ◀── utun read
                                   (mpsc, 4096)       ip_to_eth → RNDIS wrap
```

- **I/O Thread**: 16 concurrent RX URBs, 32 pending OUT URBs, interleaved TX/RX processing
- **TX Thread**: Polls `utun` with 100ms timeout, batches up to 64 packets
- **DNS Interceptor**: Transparently intercepts outbound DNS queries (IPv4 UDP port 53), forwards to DoH/DoT resolver thread
- **Connection Pooling**: DoH reuses TLS connections via `ureq` agent, DoT maintains a 4-connection pool with automatic reconnection

## DNS Modes

| Mode | How it works | Speed | Privacy |
|------|-------------|-------|---------|
| `system` | Passes DNS through to phone's resolver | Fastest | None (phone sees plaintext) |
| `doh` | HTTPS POST to Cloudflare/Google/Quad9 | Fast (connection pooling) | Full (TLS encrypted) |
| `dot` | TLS connection to port 853 | Good (4-conn pool) | Full (TLS encrypted) |

All DNS queries from the `utun` interface are intercepted regardless of destination IP. No DNS leaks possible in DoH/DoT mode.

## Requirements

- macOS 11+ (Big Sur or later)
- Root privileges (`sudo`) — required for `ifconfig`, `route`, `scutil`
- Android phone with USB tethering enabled
- Rust 1.71+ (build from source only)

## License

MIT © 2026 Mohammed Boukaba
