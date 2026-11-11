# Architecture

## System Overview

GoPacketSniffer is a multi-stage concurrent pipeline. Each stage runs in its
own goroutine and communicates via channels or shared, mutex-protected state.

```
┌─────────────────────────────────────────────────────────────────┐
│                         Pipeline Stages                         │
│                                                                 │
│  [Kernel]          [Capture]       [Parse]        [Display]     │
│                                                                 │
│  AF_PACKET  ──►  CaptureLoop  ──►  parseWorker  ──►  ticker    │
│  + BPF filter    goroutine        goroutine         goroutine   │
│                      │                │                │        │
│                  frames chan      Statistics       terminal     │
│                  (chan Frame)      (mutex)          (stdout)    │
└─────────────────────────────────────────────────────────────────┘
```

---

## Components

### 1. Capture Layer (`internal/capture/`)

**capture.go**
- Opens an `AF_PACKET / SOCK_RAW` socket - gives access to raw Ethernet frames
  before the kernel's network stack processes them.
- Binds to a specific interface via `SockaddrLinklayer`.
- Enables promiscuous mode via `PACKET_MR_PROMISC` so the NIC passes all
  frames, not just those addressed to this host.
- On loopback, sets `PACKET_IGNORE_OUTGOING` so each packet is seen once
  instead of twice (outgoing and incoming copy).
- `CaptureLoop` calls `Recvfrom` in a loop, timestamps each frame, copies it
  into a fresh `[]byte`, and sends it to the frames channel as a
  `Frame{Data, Timestamp}`. The copy is necessary because the read buffer is
  reused for the next frame.
- The send is non-blocking. If the parser falls behind and the channel is
  full, the frame is discarded and counted as dropped.
- The socket has a 200 ms receive timeout (`SO_RCVTIMEO`), so the loop can
  notice a shutdown request even on an idle interface. Closing the fd from
  another goroutine does not reliably wake a blocked `recvfrom`.

**ringbuffer.go**
- Lock-free single-producer / single-consumer circular buffer using
  `atomic.Uint64` read/write pointers.
- Capacity is rounded up to a power of two so index wrapping is a bitmask
  (`& mask`) instead of a modulo, which avoids a division on every operation.
- Not wired into the main pipeline, which uses a buffered channel for its
  simpler shutdown semantics. The ring buffer is a drop-in alternative for
  that hand-off.

**bpf.go**
- Compiles a filter expression into BPF bytecode using `golang.org/x/net/bpf`.
  A small builder records jumps with symbolic targets (next / accept /
  reject) and resolves the relative skip counts at the end.
- Every filter first checks that the EtherType is IPv4. Port filters reject
  non-first IP fragments and locate the ports through the IP header length
  (`ldxb 4*([14]&0xf)`), so packets with IP options are matched correctly.
- Attaches the program to the socket via `SO_ATTACH_FILTER` (setsockopt).
- The kernel evaluates the BPF program for every incoming frame and drops
  non-matching packets before they reach userspace - this is the most
  efficient filtering point possible.

### 2. Parser Layer (`internal/parser/`)

Each parser is a pure function `Parse*([]byte) (*T, error)` with no side
effects, making them trivially testable and benchmarkable.

**Parsing chain:**
```
raw []byte
  └─ ParseEthernet  → EthernetFrame  (14 bytes)
       └─ ParseIPv4 → IPv4Packet     (20+ bytes)
            ├─ ParseTCP  → TCPSegment  (20+ bytes)
            │    └─ ParseHTTP → HTTPInfo (best-effort)
            ├─ ParseUDP  → UDPDatagram (8 bytes)
            └─ ParseICMP → ICMPPacket  (8 bytes)
```

**decoder.go** orchestrates the chain and returns a `*models.PacketInfo`
populated with all extracted fields. It uses a `sync.Pool` to reuse
`PacketInfo` allocations, reducing GC pressure in the hot path.

Two details matter for correctness on real traffic:
- `ParseIPv4` uses the Total Length field to cut off Ethernet padding
  (frames are padded to 60 bytes), so padding is never mistaken for payload.
- Non-first IP fragments carry no transport header. The decoder labels them
  with their protocol, sets `IsFragment`, and does not parse ports or flags.

**Protocol offsets (relative to start of Ethernet frame, for an IP header
without options):**

| Field | Offset | Size |
|---|---|---|
| Dst MAC | 0 | 6 |
| Src MAC | 6 | 6 |
| EtherType | 12 | 2 |
| IP version/IHL | 14 | 1 |
| IP protocol | 23 | 1 |
| IP src | 26 | 4 |
| IP dst | 30 | 4 |
| TCP src port | 34 | 2 |
| TCP dst port | 36 | 2 |
| TCP flags | 47 | 1 |

### 3. Statistics Engine (`internal/stats/`)

**stats.go**
- Single `sync.Mutex` protects all counters - chosen over atomics because
  the critical section is short and the lock is only contended between the
  parse worker and the display ticker (two goroutines).
- `GetSnapshot()` returns a deep copy of all state so the display goroutine
  can read without holding the lock.
- Bandwidth is computed per-interval: bytes accumulated since the last
  `GetSnapshot()` call, times 8, divided by elapsed seconds (bits per second).

**toptalkers.go**
- `map[string]uint64` (IP → bytes) updated on every packet.
- Sorted on each `GetSnapshot()` call, which is acceptable because the display
  refreshes at 1 Hz, not in the hot path. Ties are broken by address so the
  ranking does not flicker.
- The map is capped at 65,536 addresses. When full, the lighter half is
  discarded, so a scan with random source addresses cannot exhaust memory.

**flows.go**
- `map[FiveTuple]*FlowStats` tracks TCP connections.
- 5-tuple is normalised (lower IP/port first) so forward and reverse
  directions map to the same entry.
- State machine: `SYN_SENT → ESTABLISHED → CLOSING → CLOSED`. A flow first
  seen mid-stream (no SYN) starts as `ESTABLISHED`. `CLOSED` is reached on
  RST, or on the ACK that follows a FIN from each side.
- Closed flows are kept for 10 seconds, uncounted, so trailing ACKs and
  retransmissions are not mistaken for new connections.
- Idle flows are expired on every snapshot (5 minutes for established, 30
  seconds for half-open or closing), which bounds the size of the map.

### 4. Display Layer (`internal/display/`)

- Runs on a 1-second ticker.
- Emits the clear-screen sequence (ANSI `\033[H\033[2J`) and redraws the full
  dashboard, which gives a live-updating view without a TUI library. Each
  frame is built in memory and written with one call to avoid flicker.
- Rows are padded by visible width (escape sequences excluded), so the
  right-hand border stays aligned regardless of colors.
- All formatting helpers (`formatBytes`, `formatBPS`, `progressBar`) are
  pure functions, making them unit-testable without a real terminal.

### 5. PCAP Writer (`internal/pcap/`)

- Writes the 24-byte libpcap global header on creation, then appends
  16-byte per-packet records followed by raw frame data.
- Uses a 1 MB `bufio.Writer` to batch small writes into larger I/O
  operations - critical at high packet rates.
- Format is little-endian with magic `0xA1B2C3D4`, compatible with
  Wireshark, tcpdump, and any libpcap-based tool.

---

## Concurrency Model

```
main goroutine
  ├── signal handler (blocks on sigCh)
  ├── captureWorker  (blocked on Recvfrom, 200 ms timeout)
  ├── parseWorker    (blocked on the frames channel)
  └── displayWorker  (blocked on ticker.C)

Shutdown sequence:
  1. Signal received (or the capture loop fails) → close(done)
  2. captureWorker sees done within one receive timeout, closes the channel
  3. parseWorker drains the channel, exits its range loop
  4. displayWorker sees <-done, returns
  5. wg.Wait() unblocks, pcapWriter.Close() flushes the file
  6. The socket is closed last, once nothing is reading from it
```

---

## Design Decisions

**Why `AF_PACKET` instead of libpcap?**
`AF_PACKET` is the Linux kernel interface that libpcap itself uses underneath.
Going directly avoids a C dependency, keeps the binary fully static, and
makes the kernel interaction explicit and educational.

**Why a buffered channel instead of the ring buffer in the main pipeline?**
Go channels provide backpressure and clean shutdown semantics (`close` +
`range`). The ring buffer is available for a zero-copy `mmap` extension
(TPACKET_V3) where the kernel writes directly into a shared memory region.

**Why `sync.Mutex` in Statistics instead of atomics?**
The statistics struct has many fields that must be updated atomically as a
group (e.g. `totalPackets` and `totalBytes` together). A single mutex is
simpler and correct; the lock is held for microseconds and contended by at
most two goroutines.

**Why `sync.Pool` for PacketInfo?**
The parse worker allocates one `PacketInfo` per packet. At 1M pps that is
1M allocations/second, creating significant GC pressure. The pool reduces
this to near-zero by reusing structs across packets.

**Why not use `google/gopacket`?**
This project exists to demonstrate understanding of the underlying protocols.
Using gopacket would hide the binary parsing logic that is the core of the
technical showcase.
