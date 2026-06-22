# AGENTS.md — Android USB Tether for macOS (Rust)

## Project Goal
Rewrite [android-usb-tether-macos](https://github.com/jamiegilmartin/android-usb-tether-macos) (C/libusb) in Rust. It bridges USB-tethered Android RNDIS to a macOS `utun` virtual interface, providing internet via the phone's cellular/WiFi.

## Build & Run
```bash
cargo build --release
echo "061828" | sudo -S ./target/release/android-tether --verbose
```

## Key CLI Flags
- `--watch` — Unix domain socket IPC (JSON), auto-reconnect on device removal
- `--verbose` — INFO+ logging
- `--no-route` — Skip adding 0/1, 128/1 default routes
- `--no-dns` — Skip DNS/scutil service registration
- `--static <IP>` — Static IP instead of DHCP
- `--gateway / --netmask` — Override defaults when using `--static`

## Current Status (June 2026)
- **DHCP**: Fully working. Discovers IP, gateway, netmask, DNS.
- **RNDIS init**: Complete. INIT→QUERY(mac)→SET(packet filter) via control endpoint.
- **USB I/O**: Control + bulk (IN/OUT). Interrupt endpoint NOT read.
- **utun**: Created, configured with `ifconfig`, registered via `scutil`.
- **Routing**: `0.0.0.0/1` + `128.0.0.0/1` split routes via gateway. Stale route cleanup.
- **RX path**: Bulk IN → RNDIS unwrap → `eth_to_utun()` → utun write.
- **TX path**: utun poll → `ip_to_eth()` → RNDIS wrap → push to shared TX queue. RX thread drains queue → `send_bulk`.
- **Bridge data flows (WORKING!)**: TX~130+ pkts, RX~120+ pkts during curl/ping. Ping to gateway (13ms), ping to 8.8.8.8 (~250ms), curl HTTP 200 — **all working!**

## Architecture
```
                      ┌──────────────────────────────────────┐
                      │             RX Thread                │
[Android] ──USB──▶   │ recv_bulk → unwrap → eth_to_utun     │ ──utun write──▶ [macOS kernel]
           ◀──USB──   │ drain tx_queue → send_bulk           │
                      └──────┬───────────────────────────────┘
                             │ tx_queue (shared mutex)
                      ┌──────┴───────────────────────────────┐
                      │             TX Thread                │
[macOS kernel] ──utun FD──▶ poll/read → ip_to_eth → wrap → push to queue
                      └──────────────────────────────────────┘
```

## Key Design Decisions

### RNDIS Parsing: Byte-offset, NOT packed C structs
- `#[repr(C, packed)]` on ARM64 macOS can misalign 32-bit fields when 6-byte MAC fields precede them.
- Solution: `read_u32(buf, offset)` / `write_u32(buf, offset, val)` using explicit little-endian byte reads.

### Single-threaded USB access
- `Arc<Mutex<UsbDevice>>` is shared between main and RX threads (ARP keepalive + RX data path).
- TX thread never touches USB directly — pushes RNDIS-wrapped packets to `Arc<Mutex<Vec<Vec<u8>>>>` queue.
- RX thread drains queue and sends via `send_bulk` between `recv_bulk` calls.
- Eliminates lock contention that previously caused TX thread to block permanently on `usb.lock()`.

### Host MAC = device_mac (C code compatible)
- Unlike Ethernet bridging, RNDIS is a point-to-point link. The phone accepts frames with src=device_mac.
- The C code uses `device_mac` directly as source MAC. Our derived `host_mac ^ 0x02` caused the phone to never respond.

### Gateway MAC = broadcast at startup, learned from RX
- Initialized to `[0xFF; 6]` so all outbound frames are broadcast until phone sends first frame.
- RX thread learns phone's actual source MAC from first non-broadcast inbound frame and updates shared `Arc<Mutex<[u8;6]>>`.

### No Ethernet padding
- Minimum Ethernet frame = 60 bytes (without FCS), but RNDIS does NOT require padding.
- The C code does NOT pad either. Padding was removed and Android phone works fine.

### Routing Cleanup
- Route `0.0.0.0/1` + `128.0.0.0/1` via gateway. Also delete any stale host route for gateway.
- Cleanup at startup prevents stale routes from prior sessions interfering.

### Utun Configuration
- `ifconfig utun{unit} inet {local_ip} {remote_ip} netmask {netmask} up`
- `scutil` registers the interface as a network service via stdin piping.

---

## CRITICAL BUGS FIXED — READ BEFORE EDITING

### 1. `eth_to_utun()` AF header byte order (KILLED ALL RECEIVED PACKETS)
- **Root cause**: `let af_nbo = AF_INET.to_be()` produces a BE value whose native LE memory is `[0x00,0x00,0x00,0x02]`. Then `.to_be_bytes()` converted the numeric VALUE of `af_nbo` (33554432) to BE, yielding `[0x02,0x00,0x00,0x00]`. Kernel expected `[0x00,0x00,0x00,0x02]` for AF_INET (2).
- **Fix**: Use `.to_ne_bytes()` instead of `.to_be_bytes()`, since `af_nbo` already stores the value in the byte representation we need.
- **Consequence**: Every received packet was silently dropped by the kernel. Ping, curl, all IP responses were lost.
- **Source**: `src/frame.rs`, `eth_to_utun()` function

### 2. Host MAC derivation (KILLED ALL RX FROM PHONE)
- **Root cause**: Using `host_mac = device_mac[0] ^ 0x02` as source MAC + `device_mac` as dest MAC caused phone to never respond. Phone's RNDIS doesn't accept unicast frames with derived host MAC.
- **Fix**: Use `device_mac` directly as source MAC and `[0xFF; 6]` (broadcast) as initial gw_mac (matched C code).
- **Consequence**: Phone never sent any data back. Zero RX packets forever.
- **Source**: `src/main.rs`, host_mac derivation

### 3. USB lock contention between TX and RX threads (KILLED ALL TX)
- **Root cause**: Both threads shared `Arc<Mutex<UsbDevice>>`. RX thread held lock for `recv_bulk` (200ms timeout). TX thread needed lock for `send_bulk` — got stuck permanently on `lock()` because RX thread re-acquired before TX thread woke up (lock convoy).
- **Fix**: TX thread pushes RNDIS-wrapped packets to `Arc<Mutex<Vec<Vec<u8>>>>` queue. RX thread drains queue and calls `send_bulk` between `recv_bulk` calls. Only RX thread ever locks `usb`.
- **Consequence**: TX thread never reached `send_bulk`. Phone never received any outbound data. Zero TX throughput.
- **Source**: `src/main.rs`, thread architecture

### 4. DHCP minimum size check (KILLED ALL DHCP PACKETS)
- **Root cause**: `DhcpPacket` struct is 576 bytes (includes 312-byte options array). Real DHCP packets are ~300 bytes. `frame.len() < sizeof(DhcpPacket)` rejected ALL real packets.
- **Fix**: Use `const DHCP_FIXED_SIZE: usize = 240` instead of `std::mem::size_of::<DhcpPacket>()`.
- **Consequence**: DHCP always fell back to hardcoded defaults. Wrong subnet, no internet.

### 5. Ethernet frame ethertype byte order
- **Root cause**: `EthHdr.ethertype` written as raw `0x0800u16`. On little-endian macOS, stored as `[0x00, 0x08]` in memory. Wire expects `[0x08, 0x00]` for IPv4.
- **Fix**: `0x0800u16.to_be()` ensures bytes `[0x08, 0x00]` on wire.
- **Source**: `src/frame.rs`, `ip_to_eth()` and `src/net_types.rs`

### 6. TX kill-switch on first USB error
- **Root cause**: `Err(_) => { bridge_tx.store(false); break; }` — first `send_bulk` failure killed entire bridge permanently.
- **Fix**: Log error and continue. `Err(e) => debug!("TX USB send failed: {e}")`.
- **Source**: `src/main.rs`, TX thread

### 7. `continue` inside lock scope prevented lock release
- **Root cause**: `{ let usb_lock = usb_rx.lock().unwrap(); match { Ok(0) => continue, ... } }` — the `continue` was INSIDE the block where `usb_lock` was defined. Compiler may not drop the lock before the loop jump.
- **Fix**: Restructure so lock guard scope is fully closed before `continue`. Use `match n {}` after the block.

---

## NEVER DO THESE AGAIN

### DO NOT use `.to_be().to_be_bytes()` for utun AF header
`AF_INET.to_be()` creates a value whose native memory bytes are already in BE order. Calling `.to_be_bytes()` on it converts the numeric VALUE again, producing wrong bytes on LE. Use `.to_ne_bytes()` instead.

### DO NOT derive host_mac by XORing device_mac bit 0x02
The phone's RNDIS driver does not accept unicast Ethernet frames from a host MAC that differs from device_mac on this device. Use device_mac directly as source MAC and broadcast as initial gw_mac.

### DO NOT share USB between TX and RX threads
Synchronous `rusb` read_bulk/write_bulk with `Arc<Mutex>` creates lock contention. Use a TX queue: TX thread prepares RNDIS-wrapped packets, RX thread sends them.

### DO NOT put `continue` or `break` inside a scope that holds a mutex lock
Always ensure the lock guard (`MutexGuard`) is dropped before the control flow jump. Pattern: `{ let lock = ...; /* work */ } match result { ... continue }`.

### DO NOT kill the entire bridge on a single TX error
First `send_bulk` failure should not tear down all threads. Log and continue. The phone may recover.

### DO NOT trust `repr(packed)` struct layouts for cross-platform parsing
Always use byte-offset reads/writes for wire protocols (RNDIS, Ethernet, DHCP, ARP).

### DO NOT use `std::mem::size_of::<DhcpPacket>()` as a minimum size check
DHCP has fixed 240-byte header + variable options. The struct's options array inflates it to 576 bytes.

### DO NOT write raw `u16` literals to Ethernet frames
Without `.to_be()`, little-endian machines produce wrong byte order on the wire.

### DO NOT assume `scutil -c` exists
macOS `scutil` does not have a `-c` flag. Use stdin piping: `echo "cmd\nquit\n" | scutil`.

### DO NOT leave stale routes between sessions
Always `route delete` before `route add` for both split routes AND the gateway host route.

### DO NOT use 192.168.42.0/24 as fallback
The phone (Android 14+) may use a completely different subnet (e.g., 10.243.242.0/24). Always use DHCP-derived addresses.

### DO NOT use `Ordering::Relaxed` for cross-thread visibility
`Ordering::Relaxed` on Apple Silicon (M1/M2/M3) does not guarantee visibility across cores. Use `SeqCst` for flags and `Release`/`Acquire` for data.

### DO NOT add Ethernet padding
Minimum Ethernet frame = 60 bytes (without FCS), but RNDIS does NOT require padding. Padding breaks compatibility with some phones.

### DO NOT read the interrupt endpoint unless necessary
The C code does NOT read the interrupt endpoint. Reading it creates unnecessary lock contention. Only implement if a specific phone requires it.

---

## Next Steps / Open Issues
1. **Async/multi-urb I/O** — Original C code uses 16 async RX URBs and 64 async TX URBs for throughput. Current Rust uses synchronous blocking. This limits performance.
2. **`--version` flag** — Not yet implemented.
3. **Manpage** — Not yet generated.
4. **.app bundle packaging** — Consider `macos/` build script like the original project.
5. **Port to Windows/Linux** — The `ProtocolDriver` trait makes it easy to add ECM/NCM drivers.

## Sudo Password
`061828` — needed for `ifconfig`, `route`, `scutil`.

## Relevant Files
| File | Purpose |
|------|---------|
| `src/main.rs` | Entry point, session orchestration, RX/TX bridge threads, TX queue |
| `src/dhcp.rs` | DHCP discover/request/ACK, option parsing |
| `src/rndis.rs` | RNDIS message builders, parsers, packet iterator |
| `src/frame.rs` | `ip_to_eth()` / `eth_to_utun()` frame conversion |
| `src/usb_device.rs` | libusb device discovery, ctrl/bulk I/O |
| `src/utun.rs` | utun create, ifconfig, scutil, route setup |
| `src/proto_rndis.rs` | RNDIS driver: init, wrap, unwrap |
| `src/proto_driver.rs` | ProtocolDriver trait (extensible for ECM/NCM) |
| `src/arp.rs` | ARP reply builder, gratuitous ARP sender |
| `src/net_types.rs` | Ethernet/DHCP/ARP structs, constants |
| `src/config.rs` | CLI parser + INI config file loader |
| `src/ipc.rs` | Unix socket JSON IPC server |
| `src/stats.rs` | Shared atomic counters |
| `src/error.rs` | Error enum with thiserror |
