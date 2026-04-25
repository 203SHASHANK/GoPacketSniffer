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
│                  packetChan       Statistics       terminal     │
│                  (chan []byte)     (mutex)          (stdout)    │
└─────────────────────────────────────────────────────────────────┘
```

---

## Components

### 1. Capture Layer (`internal/capture/`)

**capture.go**
- Opens an `AF_PACKET / SOCK_RAW` socket — gives access to raw Ethernet frames
  before the kernel's network stack processes them.
- Binds to a specific interface via `SockaddrLinklayer`.
- Enables promiscuous mode via `PACKET_MR_PROMISC` so the NIC passes all
  frames, not just those addressed to this host.
- `CaptureLoop` calls `Recvfrom` in a tight loop, copies each frame into a
  fresh `[]byte`, and sends it to `packetChan`. The copy is necessary because
  the kernel reuses the read buffer.

**ringbuffer.go**
- Lock-free single-producer / single-consumer circular buffer using
  `atomic.Uint64` read/write pointers.
- Size is always a power of two so index wrapping is a bitmask (`& mask`)
  instead of a modulo — avoids division on every operation.
- Used internally; the main pipeline uses a buffered channel for simplicity,
  but the ring buffer is available for zero-copy extensions.

**bpf.go**
- Compiles a filter expression into BPF bytecode using `golang.org/x/net/bpf`.
- Attaches the program to the socket via `SO_ATTACH_FILTER` (setsockopt).
- The kernel evaluates the BPF program for every incoming frame and drops
  non-matching packets before they reach userspace — this is the most
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

**Protocol offsets (all relative to start of Ethernet frame):**

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
- Single `sync.Mutex` protects all counters — chosen over atomics because
  the critical section is short and the lock is only contended between the
  parse worker and the display ticker (two goroutines).
- `GetSnapshot()` returns a deep copy of all state so the display goroutine
  can read without holding the lock.
- Bandwidth is computed per-interval: bytes accumulated since the last
  `GetSnapshot()` call divided by elapsed seconds.

**toptalkers.go**
- `map[string]uint64` (IP → bytes) updated on every packet.
- Sorted on each `GetSnapshot()` call — acceptable because the display
  refreshes at 1 Hz, not in the hot path.

**flows.go**
- `map[FiveTuple]*FlowStats` tracks TCP connections.
- 5-tuple is normalised (lower IP/port first) so forward and reverse
  directions map to the same entry.
- State machine: `SYN_SENT → ESTABLISHED → CLOSING → CLOSED`.
  Flows in `CLOSED` state are deleted immediately to bound memory.

### 4. Display Layer (`internal/display/`)

- Runs on a 1-second ticker.
- Calls `ClearScreen()` (ANSI `\033[H\033[2J`) then redraws the full
  dashboard — creates the "live update" effect without a TUI library.
- All formatting helpers (`formatBytes`, `formatBPS`, `progressBar`) are
  pure functions, making them unit-testable without a real terminal.

### 5. PCAP Writer (`internal/pcap/`)

- Writes the 24-byte libpcap global header on creation, then appends
  16-byte per-packet records followed by raw frame data.
- Uses a 1 MB `bufio.Writer` to batch small writes into larger I/O
  operations — critical at high packet rates.
- Format is little-endian with magic `0xA1B2C3D4`, compatible with
  Wireshark, tcpdump, and any libpcap-based tool.

---

## Concurrency Model

```
main goroutine
  ├── signal handler (blocks on sigCh)
  ├── captureWorker  (blocked on Recvfrom)
  ├── parseWorker    (blocked on packetChan)
  └── displayWorker  (blocked on ticker.C)

Shutdown sequence:
  1. Signal received → close(done)
  2. captureWorker exits Recvfrom loop, closes packetChan
  3. parseWorker drains packetChan, exits range loop
  4. displayWorker sees <-done, returns
  5. wg.Wait() unblocks, pcapWriter.Close() called
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
