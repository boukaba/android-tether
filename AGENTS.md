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
- **Migration to nusb**: Complete. `rusb` (libusb C dep) replaced with `nusb` v0.2.4 (pure Rust via macOS IOKit).
- **USB I/O engine**: New async multi-URB engine (`usb_io.rs`) — 8 concurrent RX buffers, event loop with 1ms polling, TX channel drain, frame processing in dedicated I/O thread. No mutex contention.
- **DHCP**: Uses synchronous `recv_bulk`/`send_bulk` on `UsbDevice` (temp endpoints) before I/O thread starts. RNDIS indications properly skipped during iteration.
- **RNDIS init**: Complete. INIT→QUERY(mac)→SET(packet filter) via control endpoint.
- **utun**: Created, configured with `ifconfig`, registered via `scutil`.
- **Routing**: `0.0.0.0/1` + `128.0.0.0/1` split routes via gateway. Stale route cleanup.
- **RX path**: 8 concurrent URBs (multi-URB) → RNDIS unwrap → `eth_to_utun()` → utun write.
- **TX path**: utun poll → `ip_to_eth()` → RNDIS wrap → push to bounded mpsc channel. I/O thread drains channel and submits OUT transfers.
- **Bridge data flows (WORKING!)**: DHCP discovery works, multi-URB RX path delivers frames, TX path sends packets. Ping to gateway (1-2ms), internet reachable.
- **Auto-reconnect on USB disconnect**: I/O thread detects disconnection via 50 consecutive USB errors or 10s idle with zero pending URBs. Signals `device_gone` + stops bridge → watch loop waits 3s → retries `run_session()`. Works with `--watch` mode.
- **Debug memory auto-clear**: Periodic `stderr.flush()` every loop iteration (~100ms) prevents buffered log accumulation. Stats logging reduced to every 5s (was 1s). Per-frame debug capped at 10 lines.

## Architecture
```
                      ┌──────────────────────────────────────────┐
                      │           I/O Thread (UsbIo)             │
                      │  8 concurrent RX URB submissions          │
[Android] ──USB──▶   │  event loop: wait_next_complete(1ms)      │ ──utun write──▶ [macOS kernel]
           ◀──USB──   │  → RNDIS unwrap → eth_to_utun             │
                      │  → ARP handling → gateway MAC learning    │
                      │  drain tx_receiver → send_bulk (OUT)     │
                      └───────────────┬──────────────────────────┘
                                      │ mpsc::sync_channel<Vec<u8>>(256)
                               ┌──────┴──────────────────────────┐
                               │         TX Thread               │
[macOS kernel] ──utun FD──▶    │ poll/read → ip_to_eth → wrap → push
                               └─────────────────────────────────┘
```

## Key Design Decisions

### RNDIS Parsing: Byte-offset, NOT packed C structs
- `#[repr(C, packed)]` on ARM64 macOS can misalign 32-bit fields when 6-byte MAC fields precede them.
- Solution: `read_u32(buf, offset)` / `write_u32(buf, offset, val)` using explicit little-endian byte reads.

### Multi-URB I/O with nusb
- Replaced `rusb` (C libusb binding) with `nusb` v0.2.4 (pure Rust, uses IOKit on macOS).
- `UsbIo` struct owns permanent `Endpoint<Bulk, In>` and `Endpoint<Bulk, Out>`.
- 8 RX buffers submitted upfront, resubmitted after each completion (including error/timeout).
- Event loop: `wait_next_complete(1ms)` for RX completions → process frames → drain TX completions → drain TX channel → loop.
- Single thread owns all USB endpoints — zero mutex contention.
- Before I/O thread starts, DHCP uses `UsbDevice::send_bulk/recv_bulk` which create temp endpoints per-call.

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

### 8. `ep_out.wait_next_complete(Duration::ZERO)` without pending check (KILLED BRIDGE)
- **Root cause**: nusb panics when `wait_next_complete(ZERO)` is called if `pending() == 0`. The TX completion drain loop ran unconditionally.
- **Fix**: Guard with `while self.ep_out.pending() > 0` before calling `wait_next_complete`.
- **Consequence**: Bridge panicked immediately on startup if no TX transfers were pending.
- **Source**: `src/usb_io.rs`

### 9. RndisPacketIter stopped at non-data RNDIS messages (KILLED DHCP)
- **Root cause**: `RndisPacketIter::next()` returned `None` when encountering any non-data RNDIS message (indications, etc.), stopping iteration prematurely. Phone floods 860-byte indication messages at connection, so DHCP OFFER was never reached.
- **Fix**: Changed `next()` to skip non-data messages with `continue` instead of returning `None`. Added robust distinction: data packets have `DataOffset >= 36` and `DataLength > 0`. Indications share type `0x00000001` but have `Status` (not `DataOffset`) at offset 8.
- **Consequence**: DHCP always fell back to static IP.
- **Source**: `src/rndis.rs`

### 7. `continue` inside lock scope prevented lock release (retained numbering)
- **Root cause**: `{ let usb_lock = usb_rx.lock().unwrap(); match { Ok(0) => continue, ... } }` — the `continue` was INSIDE the block where `usb_lock` was defined. Compiler may not drop the lock before the loop jump.
- **Fix**: Restructure so lock guard scope is fully closed before `continue`. Use `match n {}` after the block.

### 10. Infinite resubmit loop on USB disconnect (KILLED ALL DISCONNECT/RECONNECT + CTRL-C)
- **Root cause**: `process_rx_completion()` resubmitted URBs on every completion, even USB errors (`comp.status.is_err()`). On disconnect, nusb's `Endpoint::submit()` on a dead endpoint immediately completes the buffer with an error or drops it and the error is returned instantly by nusb. This created an infinite `while let Some(extra)` drain loop — each error completion triggered another `submit()`, which immediately returned another completion, ad infinitum. The IO thread never exited, so `running_bridge` was never set to false, and the global `running` (Ctrl-C) flag was never checked.
- **Fix**: `process_rx_completion()` now returns immediately on `comp.status.is_err()` WITHOUT resubmitting the buffer. This causes `ep_in.pending()` to drop by 1. When all NUM_RX_BUFS (8) URBs are consumed, `pending() == 0` triggers immediate disconnect detection via `device_gone` + `running.store(false)`.
- **Consequence**: On cable disconnect: infinite nusb ERROR log spam, no reconnect, Ctrl-C was completely unresponsive — process had to be SIGKILL'd.
- **Source**: `src/usb_io.rs`, `process_rx_completion()`

---

## NEVER DO THESE AGAIN

### DO NOT use `.to_be().to_be_bytes()` for utun AF header
`AF_INET.to_be()` creates a value whose native memory bytes are already in BE order. Calling `.to_be_bytes()` on it converts the numeric VALUE again, producing wrong bytes on LE. Use `.to_ne_bytes()` instead.

### DO NOT derive host_mac by XORing device_mac bit 0x02
The phone's RNDIS driver does not accept unicast Ethernet frames from a host MAC that differs from device_mac on this device. Use device_mac directly as source MAC and broadcast as initial gw_mac.

### DO NOT share USB between TX and RX threads
Synchronous `rusb` read_bulk/write_bulk with `Arc<Mutex>` creates lock contention. Use a TX queue: TX thread prepares RNDIS-wrapped packets, RX thread sends them.

### DO NOT use `Arc<Mutex<Vec<Vec<u8>>>>` for the TX queue
It provides no backpressure — the TX thread fills the queue infinitely when USB is slow, causing unbounded memory growth. Use `mpsc::sync_channel(256)` instead: `send()` blocks the TX thread when the channel is full, which stalls utun reads and lets the kernel pace application output.

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

### DO NOT call `wait_next_complete(Duration::ZERO)` when `pending() == 0`
nusb panics with "no transfer pending" when `wait_next_complete` is called with zero duration and no transfers are pending. Always guard with `ep.pending() > 0`.

### DO NOT return `None` from `RndisPacketIter::next()` on non-data messages
RNDIS data stream can contain interleaved control messages (indications, etc.). The iterator must `continue` to skip them, not `return None`, or the caller misses subsequent data packets (like DHCP responses buried after indication messages).

### DO NOT assume RNDIS_MSG_PACKET and RNDIS_MSG_INDICATE have different type codes
Both are `0x00000001`. Distinguish them by structure: data packets have `DataOffset >= 36` (the header size) and `DataLength > 0`, while indications have `Status` (a status code, not offset) at byte offset 8.

### DO NOT resubmit URBs on USB error from `process_rx_completion`
When nusb's `Endpoint::submit()` is called on a dead endpoint (device disconnected), the buffer immediately completes with error or is returned instantly, creating an unbounded `while let Some(extra)` cycle. Instead: drop the error completion (don't resubmit), let `pending()` decay to 0, and detect disconnection when all URBs are consumed.

### DO NOT forget to set `running_bridge=false` when IO thread detects disconnect
The IO thread must set both `device_gone` AND `running` (bridge flag) before breaking. Otherwise the main loop spins forever waiting for bridge to stop. The `tx_receiver` drop from IO thread exit unblocks the TX thread.

### DO NOT store log output without periodic flush
`env_logger` buffers stderr output when piped. Call `std::io::stderr().flush()` regularly to prevent unbounded memory accumulation of buffered log data.

---

## Next Steps / Open Issues
1. **`--version` flag** — Not yet implemented.
2. **Manpage** — Not yet generated.
3. **.app bundle packaging** — Consider `macos/` build script like the original project.
4. **Port to Windows/Linux** — The `ProtocolDriver` trait makes it easy to add ECM/NCM drivers.

## Sudo Password
`061828` — needed for `ifconfig`, `route`, `scutil`.

## Relevant Files
| File | Purpose |
|------|---------|
| `src/main.rs` | Entry point, session orchestration, RX/TX bridge threads, TX queue |
| `src/dhcp.rs` | DHCP discover/request/ACK, option parsing |
| `src/rndis.rs` | RNDIS message builders, parsers, packet iterator |
| `src/frame.rs` | `ip_to_eth()` / `eth_to_utun()` frame conversion |
| `src/usb_device.rs` | nusb device discovery, ctrl/bulk I/O, take_endpoints |
| `src/usb_io.rs` | Async multi-URB I/O engine (8 RX buffers, event loop, TX drain) |
| `src/utun.rs` | utun create, ifconfig, scutil, route setup |
| `src/proto_rndis.rs` | RNDIS driver: init, wrap, unwrap |
| `src/proto_driver.rs` | ProtocolDriver trait (extensible for ECM/NCM) |
| `src/arp.rs` | ARP reply builder, gratuitous ARP sender |
| `src/net_types.rs` | Ethernet/DHCP/ARP structs, constants |
| `src/config.rs` | CLI parser + INI config file loader |
| `src/ipc.rs` | Unix socket JSON IPC server |
| `src/stats.rs` | Shared atomic counters |
| `src/error.rs` | Error enum with thiserror |
