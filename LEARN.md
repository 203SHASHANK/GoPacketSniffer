# GoPacketSniffer — Deep-Dive Learning Guide

> Read this document top to bottom once. By the end you will understand every
> line of every file in this project, every networking concept it touches, and
> every Go pattern it uses.

---

## Table of Contents

1. [What is a Packet Sniffer? (Real-World Analogy)](#1-what-is-a-packet-sniffer)
2. [How Computer Networks Work — From the Ground Up](#2-how-computer-networks-work)
3. [The OSI Model — The Layer Cake](#3-the-osi-model)
4. [Project Directory Map](#4-project-directory-map)
5. [Data Flow — The Big Picture](#5-data-flow)
6. [File-by-File Deep Dive](#6-file-by-file-deep-dive)
   - [cmd/gopacketsniffer/main.go](#61-cmdgopacketsniffermain-go)
   - [internal/capture/capture.go](#62-internalcapturecapturego)
   - [internal/capture/bpf.go](#63-internalcapturebpfgo)
   - [internal/capture/ringbuffer.go](#64-internalcaptureringbuffergo)
   - [internal/models/packet.go](#65-internalmodelspacketgo)
   - [internal/parser/ethernet.go](#66-internalparserethernetgo)
   - [internal/parser/ipv4.go](#67-internalparseripv4go)
   - [internal/parser/tcp.go](#68-internalparsertcpgo)
   - [internal/parser/udp.go](#69-internalparserudpgo)
   - [internal/parser/icmp.go](#610-internalparserictmpgo)
   - [internal/parser/http.go](#611-internalparserhttpgo)
   - [internal/parser/decoder.go](#612-internalparserdecoder-go)
   - [internal/stats/stats.go](#613-internalstatsstatsgo)
   - [internal/stats/flows.go](#614-internalstatsflowsgo)
   - [internal/stats/toptalkers.go](#615-internalstatstoptelkersgo)
   - [internal/display/colors.go](#616-internaldisplaycolorsgo)
   - [internal/display/terminal.go](#617-internaldisplayterminalgo)
   - [internal/pcap/writer.go](#618-internalpcapwritergo)
   - [test/testdata/packets.go](#619-testtestdatapacketsgo)
7. [Go Concurrency — Goroutines, Channels, WaitGroups](#7-go-concurrency)
8. [Memory Management — sync.Pool and the GC](#8-memory-management)
9. [Binary Parsing — Reading Bytes Like a Protocol Stack](#9-binary-parsing)
10. [Full Variable / Acronym Glossary](#10-full-variable--acronym-glossary)
11. [Build, Run, Test, Docker](#11-build-run-test-docker)
12. [Step-by-Step Packet Journey](#12-step-by-step-packet-journey)

---

## 1. What is a Packet Sniffer?

### The Post Office Analogy

Imagine every piece of data on a network is an **envelope** being carried by a
postal worker through your neighbourhood. Normally you only open envelopes
addressed to you. A **packet sniffer** is like standing at the neighbourhood
sorting office and reading every envelope that passes through — regardless of
who it is addressed to.

In networking terms:
- **Envelope** = a **packet** (or frame, segment, datagram — the name changes
  per layer, but the concept is the same: a chunk of bytes with a header that
  says where it came from and where it is going).
- **Sorting office** = the **network interface card (NIC)** in your computer.
- **Reading all envelopes** = **promiscuous mode** — a mode where the NIC
  forwards every frame to the operating system, even those not addressed to
  your machine's MAC address.

### Why Packet Sniffers Need Root

The Linux kernel tightly controls access to raw network traffic. Creating an
`AF_PACKET` socket — the interface this project uses — requires the
`CAP_NET_RAW` capability, which normal processes do not have. Running as root
grants all capabilities, which is why the tool must be started with `sudo`.

---

## 2. How Computer Networks Work

### Cables and Radio Waves

At the lowest level, computers communicate by sending electrical signals (on
copper cables), light pulses (on fibre), or radio waves (on Wi-Fi). This
project deals with **Ethernet** networks, the most common wired standard.

### Frames, Packets, Segments, Datagrams

The same data gets different names at different layers:

| Layer | Unit | Contains |
|---|---|---|
| Ethernet (Layer 2) | **Frame** | MAC header + IP packet |
| IP (Layer 3) | **Packet** | IP header + TCP segment or UDP datagram |
| TCP (Layer 4) | **Segment** | TCP header + application data |
| UDP (Layer 4) | **Datagram** | UDP header + application data |
| HTTP (Layer 7) | **Message** | HTTP headers + body |

Think of it like **Russian nesting dolls** (matryoshka): HTTP inside TCP inside
IP inside Ethernet. Each layer wraps the layer above it with its own envelope.

### MAC Addresses vs IP Addresses

- **MAC address** (Media Access Control): A 6-byte hardware identifier burned
  into every NIC at the factory. Like a **serial number on a house**. Used only
  within a single local network segment. Format: `00:11:22:33:44:55`.
- **IP address**: A logical, software-assigned address. Like the **postal
  address of a house**. Used to route traffic across the internet. Format:
  `192.168.1.100` (IPv4) or `2001:db8::1` (IPv6).

When you send data to `google.com`, your computer:
1. Looks up the IP address of `google.com` via DNS.
2. Wraps data in TCP segments → IP packets → Ethernet frames.
3. The Ethernet frame's destination MAC is your **router** (not Google), because
   Google is on a different network segment.
4. The router strips the Ethernet frame, reads the IP address, and forwards the
   IP packet toward Google through a chain of routers.

---

## 3. The OSI Model

The **OSI (Open Systems Interconnection)** model is a conceptual framework that
divides network communication into 7 layers. This project implements layers 2–7.

```
Layer 7  Application    HTTP, DNS, FTP, SMTP
Layer 6  Presentation   TLS/SSL (encryption, encoding)
Layer 5  Session        (not typically separate in practice)
Layer 4  Transport      TCP, UDP
Layer 3  Network        IP (IPv4, IPv6)
Layer 2  Data Link      Ethernet (MAC addresses)
Layer 1  Physical       Cables, radio waves, photons
```

**Real-world analogy**: Think of sending a letter internationally.

| OSI Layer | Letter Analogy |
|---|---|
| Application (7) | The message you write |
| Presentation (6) | Translating it into English |
| Transport (4) | Choosing courier vs standard post |
| Network (3) | The country address system |
| Data Link (2) | The neighbourhood postman's route |
| Physical (1) | The actual van, road, or plane |

### How This Project Walks the Stack

GoPacketSniffer receives a raw Ethernet **frame** from the kernel and peels
each layer like an onion:

```
Raw bytes from AF_PACKET socket
  ↓
ParseEthernet()  — reads 14-byte Ethernet header, exposes IP payload
  ↓
ParseIPv4()      — reads 20-byte IP header, exposes TCP/UDP/ICMP payload
  ↓
ParseTCP()   or ParseUDP()   or ParseICMP()
  ↓
ParseHTTP()  — best-effort scan of TCP payload for HTTP/1.x messages
```

---

## 4. Project Directory Map

```
GoPacketSniffer/
│
├── cmd/
│   └── gopacketsniffer/
│       └── main.go              ← Program entry point; wires all packages together
│
├── internal/
│   ├── capture/
│   │   ├── capture.go           ← Raw socket creation, promiscuous mode, capture loop
│   │   ├── bpf.go               ← BPF filter compiler + kernel attachment
│   │   └── ringbuffer.go        ← Lock-free circular buffer (SPSC)
│   │
│   ├── models/
│   │   └── packet.go            ← PacketInfo struct — the universal data carrier
│   │
│   ├── parser/
│   │   ├── decoder.go           ← Orchestrates the full parse chain; manages sync.Pool
│   │   ├── ethernet.go          ← Layer 2 parser (Ethernet II)
│   │   ├── ipv4.go              ← Layer 3 parser (IPv4)
│   │   ├── tcp.go               ← Layer 4 parser (TCP)
│   │   ├── udp.go               ← Layer 4 parser (UDP)
│   │   ├── icmp.go              ← Layer 4 parser (ICMP)
│   │   └── http.go              ← Layer 7 parser (HTTP/1.x, best-effort)
│   │
│   ├── stats/
│   │   ├── stats.go             ← Central metrics store (mutex-protected)
│   │   ├── flows.go             ← TCP connection state machine + five-tuple tracker
│   │   └── toptalkers.go        ← Top-N IPs by bytes (sorted on each snapshot)
│   │
│   ├── display/
│   │   ├── colors.go            ← ANSI escape code constants + Colorize helper
│   │   └── terminal.go          ← Full dashboard renderer + per-packet verbose printer
│   │
│   └── pcap/
│       └── writer.go            ← libpcap .pcap file format writer
│
├── test/
│   └── testdata/
│       └── packets.go           ← Hardcoded real packet bytes for unit tests
│
├── Makefile                     ← Build, test, lint, docker, release targets
├── Dockerfile                   ← Multi-stage Docker image
├── docker-compose.yml           ← Docker Compose configuration
├── go.mod                       ← Go module definition + dependency declarations
└── go.sum                       ← Cryptographic checksums for all dependencies
```

The `internal/` directory is a Go convention: packages inside `internal/` can
only be imported by code in the **same module**. This prevents external packages
from depending on implementation details you might want to change.

---

## 5. Data Flow

Here is the complete data journey from a network packet arriving at your NIC to
appearing on screen:

```
NIC hardware
   │  (DMA — Direct Memory Access: kernel puts bytes directly into RAM)
   ▼
Linux kernel AF_PACKET socket
   │  (BPF filter runs HERE in the kernel — non-matching packets never
   │   reach userspace, saving CPU)
   ▼
capture.CaptureLoop  (goroutine, blocked on unix.Recvfrom)
   │  copies frame into a fresh []byte slice
   ▼
packetChan  (buffered Go channel, capacity 4096)
   │
   ▼
Parse Worker goroutine  (range packetChan)
   │
   ├── pcap.Writer.WritePacket()   (if -w flag set, save raw frame to disk)
   │
   ├── parser.DecodePacket()
   │     ├── ParseEthernet
   │     ├── ParseIPv4
   │     ├── ParseTCP / ParseUDP / ParseICMP
   │     └── ParseHTTP (if TCP)
   │
   ├── metrics.Record()            (update Statistics under mutex)
   ├── metrics.FlowTracker.Update() (if TCP)
   ├── metrics.RecordHTTP()         (if HTTP detected)
   │
   └── display.PrintPacket()       (if -v verbose mode)
       OR
Display goroutine (1-second ticker)
   └── display.PrintStats()        (stats dashboard)
```

The three goroutines run **concurrently**. The capture goroutine is always
reading from the network. The parse worker is always processing frames. The
display goroutine wakes up every second to redraw the screen.

---

## 6. File-by-File Deep Dive

---

### 6.1 `cmd/gopacketsniffer/main.go`

**Purpose**: The entry point. Parses flags, wires all packages together, manages
goroutine lifecycle.

#### Imports Explained

```go
"flag"          // standard library: parses command-line arguments like -i eth0
"fmt"           // standard library: formatted I/O (Printf, Println)
"log"           // standard library: logging with timestamps to stderr
"os"            // standard library: OS interaction (Exit, Stderr, Signal)
"os/signal"     // standard library: subscribes to OS signals (Ctrl+C)
"sync"          // standard library: sync.WaitGroup for goroutine coordination
"syscall"       // standard library: OS-level constants (SIGINT, SIGTERM)
"time"          // standard library: time.Now(), time.Duration
```

#### Flag Variables

```go
iface   *string  // -i  the network interface name, e.g. "eth0", "wlan0", "lo"
verbose *bool    // -v  if true, print every decoded packet
filter  *string  // -f  BPF filter expression, e.g. "tcp port 80"
writeTo *string  // -w  file path to save .pcap output
```

The `flag` package uses pointer types so the library can write the parsed value
into the variable. You dereference with `*iface`, `*verbose`, etc.

#### `var version = "dev"`

This variable is intentionally overwritten at build time using linker flags:
```
-ldflags="-X main.version=v1.2.3"
```
The `-X` flag tells the Go linker to replace the named variable's value. This
is how released binaries embed their version string without hardcoding it in
source.

#### Channels and WaitGroups

```go
done       chan struct{}    // closed to broadcast shutdown to all goroutines
packetChan chan []byte      // raw frame bytes flowing from capture to parse worker
var wg     sync.WaitGroup  // wg.Wait() blocks main until all goroutines finish
```

**`chan struct{}`**: An empty struct channel is Go's idiom for a "signal-only"
channel. Sending a value costs memory; closing costs nothing and wakes up all
receivers. `close(done)` is the canonical Go broadcast mechanism.

**`sync.WaitGroup`**: Like a countdown timer. `wg.Add(1)` increments; `wg.Done()`
decrements; `wg.Wait()` blocks until the count reaches zero. Ensures main does
not return before goroutines have finished cleaning up.

#### Shutdown Sequence

```go
sigCh := make(chan os.Signal, 1)
signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
<-sigCh           // main goroutine blocks here until Ctrl+C
close(done)       // broadcast: "stop what you are doing"
capture.Close(fd) // close the socket so Recvfrom unblocks
wg.Wait()         // wait for all goroutines to finish
```

**SIGINT** = Signal Interrupt. Generated when you press Ctrl+C in a terminal.
**SIGTERM** = Signal Terminate. The default signal sent by `kill <pid>` and by
Docker when stopping a container.

---

### 6.2 `internal/capture/capture.go`

**Purpose**: Low-level Linux-specific code to capture every Ethernet frame
arriving on a network interface.

#### What is `AF_PACKET`?

In Linux, **sockets** are the universal API for network communication. The
socket type determines what you can see:

| Socket Type | Sees |
|---|---|
| `AF_INET / SOCK_STREAM` | TCP data only — kernel strips all headers |
| `AF_INET / SOCK_RAW` | IP packets (no Ethernet header) |
| `AF_PACKET / SOCK_RAW` | Full Ethernet frames — everything |

This project uses `AF_PACKET` to get complete frames including MAC addresses.
This is exactly what Wireshark and tcpdump use internally.

```
Analogy: AF_INET is like reading only the letter inside the envelope.
         AF_PACKET is like reading the envelope (MAC), the address label (IP),
         and the letter (TCP/UDP) together.
```

#### `OpenRawSocket` — Step by Step

```go
ethPAll := htons(unix.ETH_P_ALL)
```
- **ETH_P_ALL** = EtherType Protocol ALL. Value `0x0003`. Tells the kernel to
  hand us **every** frame regardless of EtherType.
- **htons** = Host TO Network Short. Converts a 16-bit integer from the CPU's
  byte order to **big-endian** (network byte order). Networks always use
  big-endian; x86 CPUs use little-endian.

```go
fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(ethPAll))
```
- **fd** = file descriptor. In Linux, everything is a file. A socket is just a
  special file. `fd` is an integer index into the kernel's open-file table for
  this process.
- `unix.Socket()` is the Go wrapper for the `socket(2)` system call.

```go
addr := unix.SockaddrLinklayer{
    Protocol: ethPAll,
    Ifindex:  iface.Index,
}
unix.Bind(fd, &addr)
```
- **Binding** ties the socket to a specific interface. Without this, you would
  receive frames from all interfaces simultaneously.
- **SockaddrLinklayer** = Socket Address Link Layer. The address structure for
  `AF_PACKET` sockets.
- **Ifindex** = Interface Index. The kernel's integer identifier for a NIC.
  `ip link show` lists these: `1: lo`, `2: eth0`, etc.

#### `SetPromiscuousMode` — What It Does

Normally a NIC's hardware filter only passes frames to the OS if:
- The destination MAC matches the NIC's own MAC, OR
- The destination MAC is the broadcast address (`ff:ff:ff:ff:ff:ff`), OR
- The NIC is subscribed to a multicast group matching the destination.

**Promiscuous mode** disables that filter — the NIC forwards **every** frame on
the wire to the OS.

```
Analogy: In a coffee shop, you normally only read mail addressed to you.
         Promiscuous mode means you read everyone's mail.
```

```go
mreq := unix.PacketMreq{
    Ifindex: int32(iface.Index),
    Type:    unix.PACKET_MR_PROMISC,
}
unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, &mreq)
```

- **PacketMreq** = Packet Membership Request. Kernel structure for modifying
  packet socket membership.
- **SOL_PACKET** = Socket Option Level PACKET. Identifies that the option
  belongs to the `AF_PACKET` layer, not a higher layer.
- **PACKET_MR_PROMISC** = Packet Membership Request PROMIScuous.
- **PACKET_ADD_MEMBERSHIP** = enable the membership type.
- **setsockopt** = Set Socket Option. A universal kernel API for configuring
  socket behaviour.

#### `CaptureLoop` — The Hot Path

```go
const maxFrameSize = 65535
buf := make([]byte, maxFrameSize)
```
The maximum Ethernet frame size is 65535 bytes (the limit of the IP Total
Length field). We allocate this once outside the loop to avoid allocating on
every iteration.

```go
bytesRead, _, err := unix.Recvfrom(fd, buf, 0)
```
- **Recvfrom** = Receive From. A system call that reads data from a socket.
  It **blocks** (pauses the goroutine) until a frame arrives. This is
  efficient — the OS wakes the goroutine only when there is data.
- `bytesRead` is how many bytes the kernel actually wrote into `buf`.

```go
frame := make([]byte, bytesRead)
copy(frame, buf[:bytesRead])
```
The kernel reuses `buf` for the next frame. We **must copy** the data into a
new slice before sending it to the channel, otherwise the parse worker would
read overwritten data.

```go
select {
case packetChan <- frame:
default:
    // Channel full — drop packet rather than block the capture goroutine.
}
```
The **non-blocking send** pattern. If `packetChan` has spare capacity, the
frame is queued. If the channel is full (parse worker is behind), the frame is
dropped and counted as a dropped packet. This prevents the capture goroutine
from blocking — it is more important to keep reading from the NIC than to
preserve every single packet.

#### `htons` — Byte Order Conversion

```go
func htons(v uint16) uint16 {
    b := (*[2]byte)(unsafe.Pointer(&v))
    return uint16(b[0])<<8 | uint16(b[1])
}
```

**Why byte order matters**: Computers store multi-byte integers in memory in
either:
- **Little-endian**: Least significant byte first. Used by x86/x64 CPUs.
  The number `0x0800` is stored as `00 08` in memory.
- **Big-endian** (network byte order): Most significant byte first. Used by
  network protocols. The number `0x0800` is stored as `08 00` in memory.

`htons` reinterprets the integer as a 2-byte array and swaps the bytes.

```
unsafe.Pointer(&v)    — get the memory address of v
(*[2]byte)(...)       — reinterpret that address as a pointer to a 2-byte array
b[0]<<8 | b[1]        — reconstruct with bytes swapped
```

---

### 6.3 `internal/capture/bpf.go`

**Purpose**: Compiles filter expressions (like `tcp port 80`) into BPF
bytecode and attaches them to the raw socket so the **kernel itself** discards
unwanted frames before they reach userspace.

#### What is BPF?

**BPF** = Berkeley Packet Filter. Originally designed at UC Berkeley in 1992,
BPF is a tiny virtual machine running inside the Linux kernel. You write a
program in BPF bytecode, attach it to a socket, and the kernel runs it on every
incoming packet. If the program returns 0, the packet is dropped; if it returns
a non-zero value, the packet is passed to userspace.

```
Analogy: BPF is a bouncer at a club door.
         Instead of checking every person's ID after they enter,
         the bouncer (BPF) checks at the door and only lets in matching people.
         This saves enormous CPU time — rejected packets never even reach Go.
```

Modern Linux eBPF (extended BPF) is used for tracing, firewalling, load
balancing, and much more. This project uses classic BPF, the original simpler
form.

#### BPF Instruction Set

A BPF program is a sequence of instructions. Each instruction is 8 bytes:

```
struct sock_filter {
    uint16 op;   // operation code
    uint8  jt;   // jump-if-true: skip this many instructions
    uint8  jf;   // jump-if-false: skip this many instructions
    uint32 k;    // constant operand
};
```

Key instructions used in this file:

| Instruction | Meaning |
|---|---|
| `LoadAbsolute{Off: 23, Size: 1}` | Load 1 byte from offset 23 of the packet into register A |
| `JumpIf{Cond: JumpEqual, Val: 6}` | If A == 6 (TCP protocol), skip `SkipTrue` instructions; else skip `SkipFalse` |
| `RetConstant{Val: 0xFFFF}` | Accept packet (return max size) |
| `RetConstant{Val: 0}` | Reject packet (return 0 bytes) |

#### Ethernet Frame Offsets Used in BPF

```
Offset 0–5   : Destination MAC address (6 bytes)
Offset 6–11  : Source MAC address (6 bytes)
Offset 12–13 : EtherType (2 bytes)  ← is this IPv4?
Offset 14–33 : IPv4 header (20 bytes minimum)
  Offset 14  : Version + IHL
  Offset 23  : IP Protocol (1 = ICMP, 6 = TCP, 17 = UDP)  ← BPF checks here
  Offset 26–29: Source IP
  Offset 30–33: Destination IP
Offset 34–35 : TCP/UDP Source Port   ← BPF checks here for "port" filters
Offset 36–37 : TCP/UDP Destination Port
```

#### Example: "tcp port 80" BPF Program

```
Instruction 0: Load byte at offset 23   (IP protocol field)
Instruction 1: If it equals 6 (TCP), skip 0 instructions forward; else skip 3
Instruction 2: Load 2 bytes at offset 34 (TCP source port)
Instruction 3: If it equals 80, skip 2 instructions forward; else skip 0
Instruction 4: Load 2 bytes at offset 36 (TCP destination port)
Instruction 5: If it equals 80, skip 0 instructions forward; else skip 1
Instruction 6: Return 0xFFFF (accept)
Instruction 7: Return 0 (reject)
```

This program accepts only TCP packets where either the source or destination
port is 80 (HTTP).

#### `attachRaw` — The `setsockopt` System Call

```go
unix.Syscall6(
    unix.SYS_SETSOCKOPT,     // system call number
    uintptr(fd),             // socket file descriptor
    unix.SOL_SOCKET,         // option level: generic socket layer
    unix.SO_ATTACH_FILTER,   // option name: attach a BPF filter
    uintptr(unsafe.Pointer(&prog)),  // pointer to the BPF program struct
    unsafe.Sizeof(prog),     // size of the struct
    0,                       // unused
)
```

**Syscall6** directly invokes a Linux system call with up to 6 arguments. This
is the raw interface to the kernel. Most Go code uses higher-level wrappers, but
here we need direct control because `SO_ATTACH_FILTER` is not wrapped by the
`unix` package.

**SOL_SOCKET** = Socket Option Level SOCKET. Options at this level apply to all
socket types (TCP, UDP, raw, etc.), in contrast to `SOL_TCP` which applies only
to TCP sockets.

**SO_ATTACH_FILTER** = Socket Option ATTACH FILTER. Tells the kernel to install
a BPF program on this socket.

---

### 6.4 `internal/capture/ringbuffer.go`

**Purpose**: A lock-free, single-producer/single-consumer circular buffer for
transferring packets between goroutines without mutex overhead.

#### What is a Ring Buffer?

A ring buffer (also called a circular buffer) is a fixed-size array where the
write position wraps back to the beginning when it reaches the end — like a
racetrack where laps repeat.

```
Physical memory:  [slot0][slot1][slot2][slot3][slot4][slot5][slot6][slot7]
                      ↑                           ↑
                   readIdx                     writeIdx

The space between readIdx and writeIdx contains unread data.
When writeIdx would pass readIdx, the buffer is full.
When readIdx == writeIdx, the buffer is empty.
```

#### Why Power-of-Two Capacity?

```go
mask: capacity - 1
...
rb.slots[writeIdx & rb.mask]  // wrap index using bitmask
```

If capacity is 8 (binary `1000`), then `mask = 7` (binary `0111`). Doing
`writeIdx & 0111` is equivalent to `writeIdx % 8` but is a single CPU
instruction instead of a division (slow). This is a classic performance
optimisation.

#### `atomic.Uint64` — Lock-Free Synchronisation

```go
write atomic.Uint64
read  atomic.Uint64
```

**Atomic operations** are CPU instructions that read-modify-write a memory
location as a single, uninterruptible operation. No mutex needed.

```
Analogy: Two people sharing a counter on a whiteboard.
         Normal variable: Person A reads "5", Person B reads "5",
                         both add 1, both write "6" — one increment lost!
         Atomic variable: The "read-add-write" happens as one step,
                         so one person sees "6" and the next sees "7".
```

The SPSC (Single-Producer Single-Consumer) design means exactly one goroutine
calls `Enqueue` and exactly one calls `Dequeue`. Under this constraint, atomic
read/write of the indices is sufficient for correctness without a mutex.

---

### 6.5 `internal/models/packet.go`

**Purpose**: Defines `PacketInfo` — the central data structure that carries
all decoded information about one packet through the pipeline.

#### `PacketInfo` Field-by-Field

```go
type PacketInfo struct {
    Timestamp time.Time   // when the packet was captured
    
    // Ethernet layer
    SrcMAC string         // source MAC address, e.g. "00:11:22:33:44:55"
    DstMAC string         // destination MAC address
    
    // IP layer
    SrcIP    string       // source IP, e.g. "192.168.1.1"
    DstIP    string       // destination IP, e.g. "8.8.8.8"
    Protocol string       // "TCP", "UDP", "ICMP", "ARP", "Other"
    TTL      uint8        // Time To Live — decremented at each router hop
    
    // Transport layer
    SrcPort uint16        // source port number (0–65535)
    DstPort uint16        // destination port number
    
    // TCP-specific
    TCPFlags    string    // human-readable: "[SYN,ACK]"
    TCPRawFlags uint8     // raw bit flags byte (used by flow tracker)
    SeqNum      uint32    // TCP Sequence Number
    AckNum      uint32    // TCP Acknowledgment Number
    
    // Application layer
    HTTP *HTTPInfo        // nil if not HTTP; populated if TCP payload is HTTP
    
    // Sizing
    TotalBytes int        // total frame size in bytes
}
```

**TTL (Time To Live)**: An integer in the IP header. Every router that
forwards the packet decrements TTL by 1. When TTL reaches 0, the router drops
the packet and sends an ICMP "Time Exceeded" message back to the sender. This
prevents packets from circling the internet forever if routing loops occur.
```
Analogy: TTL is like the number of post offices a letter is allowed to pass
         through. If it exceeds the limit, it is returned to sender.
```

**Sequence Number (SeqNum)**: TCP assigns a number to every byte it sends.
The SeqNum in a segment is the position of the first byte in that segment.
This allows the receiver to reassemble segments in order even if they arrive
out of order.

**Acknowledgment Number (AckNum)**: The SeqNum the sender expects next from the
other side. Saying "I have received everything up to byte X, now send X+1."

#### `HTTPInfo`

```go
type HTTPInfo struct {
    IsRequest  bool
    IsResponse bool
    
    // For requests:
    Method string    // "GET", "POST", "PUT", etc.
    URL    string    // the requested path, e.g. "/index.html"
    Host   string    // the Host header value, e.g. "example.com"
    
    // For responses:
    StatusCode int   // 200, 404, 500, etc.
    StatusText string // "200 OK", "404 Not Found", etc.
}
```

---

### 6.6 `internal/parser/ethernet.go`

**Purpose**: Parses the 14-byte Ethernet II header from raw bytes.

#### Ethernet II Frame Layout

```
Bytes  0 –  5 : Destination MAC (6 bytes)
Bytes  6 – 11 : Source MAC      (6 bytes)
Bytes 12 – 13 : EtherType       (2 bytes, big-endian)
Bytes 14 –    : Payload (next protocol, e.g. an IP packet)
```

Total minimum size: 14 bytes.

#### EtherType Constants

```go
EtherTypeIPv4 = 0x0800   // Internet Protocol version 4
EtherTypeARP  = 0x0806   // Address Resolution Protocol
EtherTypeIPv6 = 0x86DD   // Internet Protocol version 6
```

**ARP (Address Resolution Protocol)**: Used to discover the MAC address of a
device given its IP address. When your computer wants to send to `192.168.1.1`
(your router), it sends an ARP broadcast: "Who has 192.168.1.1? Tell
192.168.1.100." The router replies with its MAC address.

```go
func ParseEthernet(data []byte) (*EthernetFrame, error) {
    ...
    return &EthernetFrame{
        DstMAC:    net.HardwareAddr(data[0:6]),    // slice bytes 0–5, cast to HardwareAddr
        SrcMAC:    net.HardwareAddr(data[6:12]),   // slice bytes 6–11
        EtherType: binary.BigEndian.Uint16(data[12:14]),  // read 2 bytes as big-endian uint16
        Payload:   data[EthernetHeaderSize:],      // everything after the 14-byte header
    }, nil
}
```

`net.HardwareAddr` is just a `[]byte` type alias. Its `.String()` method
formats it as `"00:11:22:33:44:55"`.

`binary.BigEndian.Uint16()` reads two bytes in big-endian order: `data[12]` is
the high byte, `data[13]` is the low byte. This is needed because the EtherType
field in the wire format is big-endian.

---

### 6.7 `internal/parser/ipv4.go`

**Purpose**: Parses the IPv4 header (minimum 20 bytes).

#### IPv4 Header Layout (RFC 791)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |    DSCP/ECN   |         Total Length          |  Bytes 0–3
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags|      Fragment Offset    |  Bytes 4–7
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Time to Live |    Protocol   |         Header Checksum       |  Bytes 8–11
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Source Address                          |  Bytes 12–15
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Destination Address                        |  Bytes 16–19
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options (if IHL > 5)                       |  Bytes 20+
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

#### Key Fields Decoded

```go
version := data[0] >> 4       // top 4 bits of byte 0
ihl     := data[0] & 0x0F     // bottom 4 bits of byte 0
```

**Version**: Always 4 for IPv4. The `>> 4` operation shifts the byte right by 4
positions, moving the top nibble into the bottom nibble.

**IHL** = Internet Header Length. Measured in 32-bit **words** (groups of 4
bytes). Minimum value is 5, meaning `5 × 4 = 20 bytes`. A value of 6 would
mean a 24-byte header with 4 bytes of options.

```
data[0] = 0x45:
  Binary: 0100 0101
  Version = 0100 = 4 (IPv4)
  IHL     = 0101 = 5 (20 bytes)
```

**Protocol Constants**:
```go
IPProtocolICMP = 1    // Internet Control Message Protocol
IPProtocolTCP  = 6    // Transmission Control Protocol
IPProtocolUDP  = 17   // User Datagram Protocol
```

These are registered with IANA (Internet Assigned Numbers Authority), the
organisation that assigns protocol numbers, port numbers, and other internet
identifiers.

**Checksum**: A simple error-detection code. The sender computes a 16-bit
one's-complement sum of the header. The receiver recomputes; if it doesn't
match, the packet is corrupted and discarded. This project reads but does not
validate the checksum (validation would add CPU cost with limited value in a
sniffing context).

---

### 6.8 `internal/parser/tcp.go`

**Purpose**: Parses a TCP segment header (minimum 20 bytes).

#### TCP Header Layout (RFC 793)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |  Bytes 0–3
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |  Bytes 4–7
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Acknowledgment Number                      |  Bytes 8–11
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Data |           |U|A|P|R|S|F|                               |  Bytes 12–13
| Offset| Reserved  |R|C|S|S|Y|I|            Window             |
|       |           |G|K|H|T|N|N|                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Checksum            |         Urgent Pointer        |  Bytes 16–19
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

#### TCP Flags — The Control Bits

Each flag is one bit in byte 13 of the TCP header:

```go
TCPFlagFIN = 0x01  // 0000 0001  FINish: no more data from sender
TCPFlagSYN = 0x02  // 0000 0010  SYNchronize: start of connection
TCPFlagRST = 0x04  // 0000 0100  ReSeT: abort connection immediately
TCPFlagPSH = 0x08  // 0000 1000  PuSH: deliver data to application immediately
TCPFlagACK = 0x10  // 0001 0000  ACKnowledge: AckNum field is valid
TCPFlagURG = 0x20  // 0010 0000  URGent: urgent pointer field is valid
```

#### TCP Three-Way Handshake

Before exchanging data, TCP establishes a connection with three packets:

```
Client                          Server
  │                               │
  │──── SYN (SeqNum=X) ──────────►│   "I want to connect"
  │                               │
  │◄─── SYN+ACK (SeqNum=Y,        │   "OK, I'm ready"
  │           AckNum=X+1) ────────│
  │                               │
  │──── ACK (AckNum=Y+1) ────────►│   "Got it, let's talk"
  │                               │
  │    [data exchange begins]     │
```

This project's flow tracker detects these flag patterns to track connection
state: `SYN → ESTABLISHED → CLOSING → CLOSED`.

#### `tcpFlagsString` — Bit Manipulation

```go
for _, f := range names {
    if flags & f.bit != 0 {    // bitwise AND: test if this bit is set
        active = append(active, f.name)
    }
}
```

If `flags = 0x12` (binary `0001 0010`):
- `flags & 0x02` (SYN) = `0x02 ≠ 0` → SYN is set ✓
- `flags & 0x10` (ACK) = `0x10 ≠ 0` → ACK is set ✓
- Result: `"[SYN,ACK]"`

#### Data Offset (TCP Header Length)

```go
dataOffset := (data[12] >> 4) & 0x0F
headerLenBytes := int(dataOffset) * 4
```

Same concept as IHL in IPv4: the top 4 bits of byte 12 tell you the TCP header
length in 32-bit words. Multiply by 4 to get bytes. This handles TCP options
(e.g. MSS, SACK, Timestamps) that extend the header beyond the 20-byte minimum.

**Window Size**: How many bytes the receiver is willing to accept before it must
send an acknowledgment. This is TCP's **flow control** mechanism — the receiver
tells the sender how fast it can go.

---

### 6.9 `internal/parser/udp.go`

**Purpose**: Parses the 8-byte UDP header.

#### UDP vs TCP

| Feature | UDP | TCP |
|---|---|---|
| Connection | Connectionless | Connection-oriented |
| Reliability | No guarantee | Guaranteed delivery |
| Order | Not preserved | Preserved |
| Overhead | 8 bytes | 20+ bytes |
| Use cases | DNS, gaming, video | HTTP, email, file transfer |

```
Analogy: UDP is like sending a postcard — you drop it in the box and
         hope it arrives. TCP is like certified mail with a return receipt
         and retries if lost.
```

#### UDP Header (RFC 768)

```
Bytes 0–1: Source Port
Bytes 2–3: Destination Port
Bytes 4–5: Length (header + data, in bytes)
Bytes 6–7: Checksum (optional in IPv4)
Bytes 8+ : Data
```

Total header size: exactly 8 bytes, always. No options, no variable length.

**Well-known UDP ports**:
- **53**: DNS (Domain Name System) — translates names to IPs
- **67/68**: DHCP (Dynamic Host Configuration Protocol) — assigns IPs
- **123**: NTP (Network Time Protocol) — clock synchronisation
- **5353**: mDNS (multicast DNS) — local name resolution

---

### 6.10 `internal/parser/icmp.go`

**Purpose**: Parses the 8-byte ICMP header.

#### What is ICMP?

**ICMP** = Internet Control Message Protocol. A layer-3 protocol used for
network diagnostics and error reporting. Unlike TCP/UDP, ICMP is not used for
application data — it is the network's "error and status" language.

```
Analogy: ICMP is the postal system's notification cards:
         "Your letter could not be delivered" (Dest Unreachable)
         "Your letter took too many hops" (Time Exceeded)
         "Is anyone home?" (Echo Request = ping)
         "Yes, I am here!" (Echo Reply = pong)
```

#### ICMP Header (RFC 792)

```
Byte 0: Type    (what kind of ICMP message)
Byte 1: Code    (sub-type, meaning depends on Type)
Bytes 2–3: Checksum
Bytes 4–7: Type-specific data
Bytes 8+ : Data (often the original IP header + 8 bytes that caused the error)
```

#### ICMP Type Constants

```go
ICMPTypeEchoReply       = 0    // response to a ping
ICMPTypeDestUnreachable = 3    // packet could not reach destination
ICMPTypeEchoRequest     = 8    // "ping" — are you there?
ICMPTypeTimeExceeded    = 11   // TTL hit 0, traceroute uses this
```

**How `traceroute` works**: It sends UDP packets with TTL=1, 2, 3, ...
incrementing. Each router decrements TTL to 0 and sends back ICMP Time
Exceeded. By recording which IP sends each Time Exceeded, traceroute maps the
path to the destination.

---

### 6.11 `internal/parser/http.go`

**Purpose**: Best-effort detection and parsing of HTTP/1.x traffic in TCP
payloads.

#### Why "Best-Effort"?

HTTP sits at layer 7 (application). By the time we receive a TCP segment, the
HTTP message may be split across multiple segments, partially received, or
encrypted (HTTPS). This parser:
- Returns `nil` if the payload doesn't look like HTTP (no error).
- Only works on unencrypted HTTP (port 80 typically).
- Uses Go's standard `net/http` package to parse, which handles the complex
  HTTP grammar correctly.

#### HTTP Method Detection

```go
methods := []string{"GET ", "POST ", "PUT ", "DELETE ", "HEAD ",
    "OPTIONS ", "PATCH ", "CONNECT ", "TRACE "}
prefix := string(data[:min(16, len(data))])
for _, m := range methods {
    if strings.HasPrefix(prefix, m) {
        return true
    }
}
```

HTTP requests always start with an uppercase method followed by a space:
`GET /index.html HTTP/1.1\r\n`. Checking the first 16 bytes is a fast
heuristic to avoid parsing the whole payload for non-HTTP traffic.

#### HTTP Response Detection

```go
if bytes.HasPrefix(payload, []byte("HTTP/")) {
    return parseHTTPResponse(payload)
}
```

HTTP responses start with `HTTP/1.0 200 OK` or `HTTP/1.1 404 Not Found`.

#### Using `net/http` for Parsing

```go
req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(data)))
```

`bufio.NewReader(bytes.NewReader(data))` wraps the raw bytes in a buffered
reader that `http.ReadRequest` expects. This reuses the entire HTTP parsing
logic from Go's standard library, correctly handling headers, chunked encoding,
keep-alive, etc.

---

### 6.12 `internal/parser/decoder.go`

**Purpose**: Orchestrates the full parse chain and manages the `sync.Pool` for
`PacketInfo` reuse.

#### `sync.Pool` — Object Pooling

```go
var packetPool = sync.Pool{
    New: func() any { return &models.PacketInfo{} },
}
```

A `sync.Pool` is a thread-safe pool of temporary objects that can be reused to
reduce garbage collection pressure.

**The problem it solves**: The parse worker allocates one `PacketInfo` per
packet. At 1 million packets per second, that is 1 million allocations/second.
The Go garbage collector must find and free each one, pausing your program
briefly for each GC cycle.

**The solution**: Borrow a `PacketInfo` from the pool, use it, then return it.
The pool keeps recently-used objects in a cache, handing them back instead of
allocating new ones.

```go
func GetPacketInfo() *models.PacketInfo {
    return packetPool.Get().(*models.PacketInfo)   // borrow
}

func PutPacketInfo(p *models.PacketInfo) {
    *p = models.PacketInfo{}    // zero all fields to prevent data leakage
    packetPool.Put(p)           // return to pool
}
```

**Critical**: The zeroing step `*p = models.PacketInfo{}` is mandatory. Without
it, the next borrower would see stale data from the previous packet — a
hard-to-find bug.

#### `DecodePacket` — The Layer-Peeling Orchestrator

```go
func DecodePacket(raw []byte, ts time.Time) (*models.PacketInfo, error) {
    info := GetPacketInfo()    // borrow from pool
    info.Timestamp = ts
    info.TotalBytes = len(raw)
    info.Protocol = "Other"   // default if we can't decode further

    // Layer 2
    eth, err := ParseEthernet(raw)
    ...
    info.SrcMAC = eth.SrcMAC.String()
    info.DstMAC = eth.DstMAC.String()

    if eth.EtherType != EtherTypeIPv4 {
        return info, nil   // ARP, IPv6, etc. — stop here
    }

    // Layer 3
    ip, err := ParseIPv4(eth.Payload)
    ...
    
    // Layer 4
    switch ip.Protocol {
    case IPProtocolTCP:
        tcp, err := ParseTCP(ip.Payload)
        ...
        // Layer 7
        if len(tcp.Payload) > 0 {
            info.HTTP = ParseHTTP(tcp.Payload)
        }
    case IPProtocolUDP:
        ...
    case IPProtocolICMP:
        ...
    }

    return info, nil
}
```

Each layer calls the next with its **Payload** field — the bytes that remain
after stripping the current layer's header. This is the "peeling the onion"
pattern: each parser returns its header info plus a slice pointing to the next
layer's data.

---

### 6.13 `internal/stats/stats.go`

**Purpose**: Thread-safe central metrics store. Accumulates counters and
computes bandwidth.

#### `Statistics` Struct

```go
type Statistics struct {
    mu sync.Mutex          // single mutex protects all fields below

    totalPackets   uint64  // total frames captured
    totalBytes     uint64  // total bytes captured
    droppedPackets uint64  // frames dropped due to full channel

    protocols      map[string]*ProtoStats  // per-protocol counters

    // bandwidth tracking
    intervalBytes uint64   // bytes accumulated since last GetSnapshot()
    lastTick      time.Time
    currentBPS    float64  // bytes per second — computed in GetSnapshot()
    peakBPS       float64  // highest BPS ever observed
    peakBPSAt     time.Time

    // HTTP counters
    httpRequests uint64
    http2xx      uint64    // 200–299: success
    http4xx      uint64    // 400–499: client error
    http5xx      uint64    // 500–599: server error

    startTime   time.Time
    topTalkers  *TopTalkers   // top 10 IPs by bytes
    FlowTracker *FlowTracker  // TCP connection state machine
}
```

**Why `sync.Mutex` instead of `atomic.Uint64` for each field?**

Multiple fields must be updated together consistently. If the parse worker
updates `totalPackets` atomically and then `totalBytes` atomically, the display
goroutine could read between those two updates and see an inconsistent state
(e.g. N+1 packets but the bytes for packet N+1 not yet counted). The mutex
ensures both updates happen atomically as a group.

#### Bandwidth Computation

```go
func (s *Statistics) GetSnapshot() Snapshot {
    ...
    elapsed := now.Sub(s.lastTick).Seconds()
    if elapsed > 0 {
        s.currentBPS = float64(s.intervalBytes) / elapsed
    }
    s.intervalBytes = 0    // reset for next interval
    s.lastTick = now
    ...
}
```

**Bytes Per Second (BPS)** = total bytes in interval / duration of interval.

Called every second by the display ticker, so `elapsed ≈ 1.0` second. The
`intervalBytes` counter resets on each call, so it only counts bytes from the
most recent interval — giving a **current** (not cumulative) bandwidth reading.

#### Deep Copy in `GetSnapshot`

```go
protosCopy := make(map[string]ProtoStats, len(s.protocols))
for k, v := range s.protocols {
    protosCopy[k] = ProtoStats{Packets: v.Packets, Bytes: v.Bytes}
}
```

The display goroutine needs to read the protocol map **after** releasing the
mutex. If we returned a reference to the internal map, the parse worker could
modify it while the display goroutine is reading — a **data race**. Copying
creates an independent snapshot the display can read safely without holding any
lock.

The returned `Snapshot` type (value, not pointer) reinforces this: it is an
immutable copy.

---

### 6.14 `internal/stats/flows.go`

**Purpose**: Tracks TCP connection state using a five-tuple key.

#### Five-Tuple Flow Key

A TCP connection is uniquely identified by five fields:

```go
type FiveTuple struct {
    SrcIP, DstIP     string
    SrcPort, DstPort uint16
    Protocol         string   // always "TCP" here but struct is general
}
```

Two packets belong to the same **flow** if they share the same five-tuple —
regardless of direction. The `normalise` function ensures that
`(A:1234 → B:80)` and `(B:80 → A:1234)` map to the same key by always putting
the lexicographically smaller IP first.

#### TCP State Machine

```
[new connection: SYN seen]
         │
         ▼
      SYN_SENT
         │
    SYN+ACK seen
         │
         ▼
    ESTABLISHED
         │
      FIN seen
         │
         ▼
      CLOSING
         │
      FIN+ACK seen  or  RST seen
         │
         ▼
       CLOSED  ──► deleted from map
```

**RST (Reset)**: Immediately terminates a connection without the usual FIN
handshake. Happens when: the receiving end has no process listening on that
port, a firewall blocks the connection, or an application crashes.

Flows in `CLOSED` state are deleted immediately:
```go
if flow.State == "CLOSED" {
    delete(ft.flows, key)
}
```
This bounds the memory usage of the flow map — otherwise it would grow forever.

---

### 6.15 `internal/stats/toptalkers.go`

**Purpose**: Tracks the top 10 source IP addresses by bytes sent.

#### Design Pattern: Accumulate Then Sort

```go
type TopTalkers struct {
    n      int                // keep top N (configured as 10)
    counts map[string]uint64  // IP → total bytes seen
}
```

**On every packet**: `counts[srcIP] += bytes` (O(1) hash map update).

**On every snapshot** (1 Hz): Sort the full map and return top N.

```go
sort.Slice(talkers, func(i, j int) bool {
    return talkers[i].Bytes > talkers[j].Bytes  // descending
})
if len(talkers) > t.n {
    talkers = talkers[:t.n]  // truncate to top N
}
```

This is acceptable because sorting happens at display frequency (1 Hz), not at
packet frequency (potentially millions/second).

**Alternative approach** (not used): A min-heap of size N would keep the top N
in O(log N) per packet — better if N is large or packet rate is extremely high.
For N=10 and a 1 Hz display, the sort approach is simpler and fast enough.

---

### 6.16 `internal/display/colors.go`

**Purpose**: ANSI terminal color codes.

#### ANSI Escape Sequences

```
\033[0m   — Reset all attributes
\033[1m   — Bold
\033[31m  — Red foreground
\033[32m  — Green foreground
\033[33m  — Yellow foreground
\033[34m  — Blue foreground
\033[36m  — Cyan foreground
\033[90m  — Dark gray (bright black)
```

`\033` is the ESC character (ASCII 27, hexadecimal 0x1B). The format is:
```
ESC [ <parameter> m
```
where `m` is the SGR (Select Graphic Rendition) command. Modern terminals
(xterm, GNOME Terminal, Windows Terminal) all understand these codes.

```go
func Colorize(color, text string) string {
    return color + text + ColorReset
}
```

Concatenates: escape code + text + reset code. The reset ensures subsequent text
is not accidentally coloured.

---

### 6.17 `internal/display/terminal.go`

**Purpose**: Renders the live statistics dashboard and per-packet verbose output.

#### "Fake TUI" Pattern

Most terminal UIs use a library (ncurses, bubbletea, termbox). This project
uses a simpler technique:

```go
func ClearScreen() {
    fmt.Print("\033[H\033[2J")
}
```

- `\033[H` = move cursor to position (1,1) — top-left of terminal.
- `\033[2J` = erase the entire screen.

On every tick (1 Hz), the dashboard is completely redrawn from scratch. The
cursor jumps to the top-left and the screen is cleared before printing. This
creates the illusion of an updating UI without a real TUI framework.

#### Progress Bar

```go
func progressBar(pct float64, width int) string {
    filled := int(pct / 100 * float64(width))
    bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
    return Colorize(ColorGreen, bar)
}
```

`█` (U+2588 FULL BLOCK) for filled cells; `░` (U+2591 LIGHT SHADE) for empty
cells. A 20-wide bar for 75% traffic would be: `███████████████░░░░░`.

#### `formatBytes` — Human-Readable Sizes

```go
func formatBytes(b uint64) string {
    switch {
    case b >= 1<<30: return fmt.Sprintf("%6.1f GB", float64(b)/(1<<30))  // 1 GiB
    case b >= 1<<20: return fmt.Sprintf("%6.1f MB", float64(b)/(1<<20))  // 1 MiB
    case b >= 1<<10: return fmt.Sprintf("%6.1f KB", float64(b)/(1<<10))  // 1 KiB
    default:         return fmt.Sprintf("%6d  B", b)
    }
}
```

`1<<30` = 2^30 = 1,073,741,824 (1 gibibyte). Using bit-shifts is idiomatic for
powers of two — faster to read than `1073741824` and more precise than `1e9`
(which is a decimal billion, not a binary gibibyte).

#### `formatBPS` — Human-Readable Bandwidth

```go
case bps >= 1e9: return fmt.Sprintf("%.1f Gbps", bps/1e9)
case bps >= 1e6: return fmt.Sprintf("%.1f Mbps", bps/1e6)
case bps >= 1e3: return fmt.Sprintf("%.1f Kbps", bps/1e3)
```

`1e9` = 10^9 = 1,000,000,000. Bandwidth is conventionally measured in decimal
powers (Kbps = 1000 bps, Mbps = 1,000,000 bps) unlike storage which sometimes
uses binary powers.

---

### 6.18 `internal/pcap/writer.go`

**Purpose**: Writes captured frames to a `.pcap` file compatible with Wireshark
and tcpdump.

#### The libpcap File Format

A `.pcap` file has a simple layout:

```
[Global Header — 24 bytes]
[Packet Record 1 Header — 16 bytes][Packet 1 raw bytes]
[Packet Record 2 Header — 16 bytes][Packet 2 raw bytes]
...
```

#### Global Header (24 bytes)

```go
hdr := struct {
    Magic        uint32   // 0xA1B2C3D4 — identifies this as a pcap file
    VersionMajor uint16   // 2
    VersionMinor uint16   // 4
    ThisZone     int32    // UTC offset in seconds (always 0 — use UTC)
    SigFigs      uint32   // timestamp precision (always 0)
    SnapLen      uint32   // max bytes per packet saved (65535)
    Network      uint32   // link-layer type (1 = Ethernet)
}
```

**Magic Number** `0xA1B2C3D4`: A fixed byte sequence at the start of a file
that identifies its format. Wireshark reads this to know: "this is a pcap file,
timestamps are in microseconds, byte order is little-endian." Other magic
numbers: `0xD4C3B2A1` is big-endian pcap; `0x0A0D0D0A` is pcapng (next gen).

**SnapLen** = Snapshot Length. The maximum number of bytes captured per packet.
65535 captures the full frame (no truncation). Older tools used 65535 as the
max; modern pcapng supports arbitrary sizes.

**Link-Layer Type 1** = `LINKTYPE_ETHERNET`. Tells Wireshark that the packets
start with 14-byte Ethernet headers. Other values: 0 = loopback, 113 = Linux
SLL (cooked capture).

#### Per-Packet Header (16 bytes)

```go
// ts_sec:   timestamp seconds since 1970-01-01 00:00:00 UTC (Unix epoch)
// ts_usec:  timestamp microseconds
// incl_len: number of bytes actually saved (≤ snapLen)
// orig_len: original length of the packet (before any truncation)
tsSec  := uint32(ts.Unix())
tsUsec := uint32(ts.Nanosecond() / 1000)  // nanoseconds → microseconds
```

`ts.Unix()` returns seconds since the Unix epoch (January 1, 1970). The pcap
format stores timestamps as (seconds, microseconds) — a pair of 32-bit
integers.

#### Buffered Writing

```go
w := &Writer{f: f, buf: bufio.NewWriterSize(f, 1<<20)}
```

`bufio.NewWriterSize(f, 1<<20)` wraps the file with a 1 MB (2^20 bytes) write
buffer. Without buffering, each `WritePacket` call would issue a system call to
write 16 + N bytes to disk. System calls are expensive (context switch to
kernel and back). With buffering, writes accumulate in memory and are flushed to
disk in large chunks — dramatically improving throughput at high packet rates.

```go
func (w *Writer) Close() error {
    if err := w.buf.Flush(); err != nil {  // flush remaining buffer to disk
        return err
    }
    return w.f.Close()
}
```

`Flush()` must be called before `Close()` — otherwise the last partial buffer
(up to 1 MB) would be lost.

---

### 6.19 `test/testdata/packets.go`

**Purpose**: Hardcoded real packet bytes for deterministic unit tests.

#### Why Hardcoded Bytes?

Unit tests need predictable input. Real network traffic is random and
unpredictable. These byte arrays are actual valid frames with known contents,
allowing tests to assert exact values:

```go
// tcp.go test can assert:
assert(tcp.SrcPort == 50000)
assert(tcp.DstPort == 80)
assert(tcp.Flags == 0x02)  // SYN
```

The comments in the file annotate exactly what each byte means:

```go
var TCPSynPacket = []byte{
    // Ethernet header (14 bytes)
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,  // Dst MAC: broadcast
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55,  // Src MAC
    0x08, 0x00,                           // EtherType: IPv4

    // IPv4 header (20 bytes)
    0x45,             // Version=4, IHL=5
    0x00,             // DSCP/ECN
    0x00, 0x3c,       // Total Length: 60
    0x1c, 0x46,       // Identification
    0x40, 0x00,       // Flags=DF (Don't Fragment), Fragment Offset=0
    0x40,             // TTL=64
    0x06,             // Protocol=TCP
    0xb1, 0xe6,       // Header Checksum
    0xc0, 0xa8, 0x01, 0x64,  // Src IP: 192.168.1.100
    0x08, 0x08, 0x08, 0x08,  // Dst IP: 8.8.8.8

    // TCP header (20 bytes)
    0xc3, 0x50,  // Src Port: 50000  (0xC350 = 50000)
    0x00, 0x50,  // Dst Port: 80     (0x0050 = 80)
    0x00, 0x00, 0x00, 0x00,  // SeqNum: 0
    0x00, 0x00, 0x00, 0x00,  // AckNum: 0
    0x50,        // Data Offset=5, Reserved=0
    0x02,        // Flags: SYN (bit 1 = 0x02)
    0x20, 0x00,  // Window Size: 8192
    0xe6, 0x32,  // Checksum
    0x00, 0x00,  // Urgent Pointer
}
```

**Decoding `0xC350` = 50000**:
```
0xC350 in hex → 1100 0011 0101 0000 in binary
High byte: 0xC3 = 195
Low byte:  0x50 = 80
Value = 195 × 256 + 80 = 49920 + 80 = 50000
```

**DF flag (Don't Fragment)**: `0x40, 0x00` at bytes 6–7 of the IPv4 header.
The top 3 bits of byte 6 are IP flags: bit 1 is DF. `0x40 = 0100 0000`, so
bit 6 (DF) is set. This means the packet must not be fragmented — if it is too
large for a router, drop it and send ICMP "Fragmentation Needed" back.

---

## 7. Go Concurrency

### Goroutines

A **goroutine** is a lightweight thread managed by the Go runtime. Creating one
costs ~2KB of stack (vs ~1MB for an OS thread). Goroutines are multiplexed onto
OS threads by the Go scheduler.

```go
go func() {
    // this code runs concurrently
}()
```

This project has three goroutines after startup:
1. **Capture goroutine**: Blocked on `Recvfrom` waiting for network packets.
2. **Parse worker**: Blocked on `for frame := range packetChan`.
3. **Display goroutine**: Blocked on `ticker.C` (1-second timer).

The main goroutine is blocked on `<-sigCh` waiting for Ctrl+C.

### Channels

Channels are Go's primary mechanism for goroutine communication — they pass
data safely between goroutines.

```go
packetChan := make(chan []byte, 4096)
```

This is a **buffered channel** with capacity 4096. Think of it as a queue:
- The capture goroutine **sends**: `packetChan <- frame`
- The parse worker **receives**: `for frame := range packetChan`
- If the queue is full (4096 frames waiting), the non-blocking send drops the
  frame.

**Why 4096?** It absorbs bursts. If packets arrive in a burst of 4096 while the
parse worker is momentarily busy, they queue up rather than being dropped.

### `sync.WaitGroup`

```go
var wg sync.WaitGroup
wg.Add(1)
go func() {
    defer wg.Done()  // called when goroutine returns
    ...
}()
wg.Wait()  // blocks until all goroutines call Done()
```

Think of it as a counter. `Add(1)` → counter++. `Done()` → counter--. `Wait()`
blocks until counter reaches 0. Used to ensure all goroutines complete their
cleanup before the program exits.

### Graceful Shutdown Flow

```
1. User presses Ctrl+C
2. OS sends SIGINT to process
3. signal.Notify puts SIGINT into sigCh
4. main goroutine reads from sigCh, unblocks
5. close(done) — broadcasts shutdown signal
6. capture.Close(fd) — closes socket, unblocks Recvfrom
7. CaptureLoop returns, closes packetChan
8. Parse worker's "range packetChan" loop ends (channel closed = no more items)
9. Display goroutine receives from done channel, returns
10. wg.Wait() returns — all goroutines done
11. pcapWriter.Close() — flush and close the .pcap file
12. Print final summary, program exits
```

This sequence ensures no data is lost and all resources are properly released.

---

## 8. Memory Management

### Go's Garbage Collector (GC)

Go is a garbage-collected language. The runtime automatically frees memory
when objects are no longer referenced. However, creating millions of short-lived
objects per second causes **GC pressure** — frequent garbage collection pauses
that affect latency.

### `sync.Pool` Pattern

```go
var packetPool = sync.Pool{
    New: func() any { return &models.PacketInfo{} },
}
```

**Without pool**: Parse worker allocates `new(PacketInfo)` for each packet.
After processing, the old `PacketInfo` becomes garbage. GC must find and free
it. At 1M pps, GC runs constantly.

**With pool**: Parse worker calls `GetPacketInfo()` (returns a recycled struct).
After processing, calls `PutPacketInfo()` (returns it to pool). GC pressure
near-zero because objects are reused.

**Important**: The pool may discard objects at any time (e.g. during GC). This
is fine — the `New` function creates a replacement. The pool is a best-effort
optimisation, not a hard guarantee of reuse.

### Ring Buffer Memory

The `RingBuffer` pre-allocates all `capacity` slots at startup:

```go
slots: make([][]byte, capacity)
```

Each slot holds a `[]byte` slice header (24 bytes: pointer + length + capacity).
The actual packet bytes are stored in separate allocations (returned by the
capture loop's `make([]byte, bytesRead)`).

Setting `rb.slots[readIdx&rb.mask] = nil` in `Dequeue` releases the reference
to the packet bytes, allowing the GC to reclaim them.

---

## 9. Binary Parsing

### Reading Multi-Byte Integers

Network protocols use **big-endian** byte order (most significant byte first).
Go's `encoding/binary` package provides utilities:

```go
binary.BigEndian.Uint16(data[0:2])   // reads 2 bytes, big-endian → uint16
binary.BigEndian.Uint32(data[4:8])   // reads 4 bytes, big-endian → uint32
```

Example: TCP Source Port at bytes 0–1 of the TCP header.
```
data[0] = 0xC3 = 195
data[1] = 0x50 = 80
Uint16 = (195 << 8) | 80 = 49920 + 80 = 50000
```

### Bit Manipulation

The IPv4 Version and IHL fields share one byte:

```go
version := data[0] >> 4     // shift right 4: keeps top nibble
ihl     := data[0] & 0x0F   // AND with 00001111: keeps bottom nibble
```

For `data[0] = 0x45`:
```
0x45 = 0100 0101
>> 4 = 0000 0100 = 4   (version)
& 0x0F = 0000 0101 = 5 (IHL)
```

### Slice Tricks for Zero-Copy Parsing

```go
Payload: data[EthernetHeaderSize:]
```

`data[14:]` does not copy any bytes. It creates a new slice **header**
(pointer, length, capacity) pointing into the same underlying memory. This is
Go's zero-copy slicing — no bytes are duplicated when we "strip" a header.

The parse chain:
```
raw      → data[0:N]     (full frame)
eth.Payload → data[14:N]  (IP packet — same memory, new slice header)
ip.Payload  → data[34:N]  (TCP segment — same memory, new slice header)
tcp.Payload → data[54:N]  (application data)
```

All four slices point into the same original byte array. No copies.

---

## 10. Full Variable / Acronym Glossary

| Term | Full Form / Meaning |
|---|---|
| `ACK` | ACKnowledgment — TCP flag indicating the AckNum field is valid |
| `AF_PACKET` | Address Family PACKET — Linux socket domain for raw Ethernet frames |
| `AF_INET` | Address Family INternet — the standard IP socket domain |
| `ARP` | Address Resolution Protocol — maps IP addresses to MAC addresses |
| `BPS` | Bytes Per Second — bandwidth measurement |
| `BPF` | Berkeley Packet Filter — kernel-level packet filtering virtual machine |
| `buf` | buffer — temporary byte storage |
| `CAP_NET_RAW` | Linux capability: NET RAW — permission to create raw sockets |
| `chan` | channel — Go's typed pipe for goroutine communication |
| `CLOSED` | TCP connection state: fully terminated |
| `CLOSING` | TCP connection state: FIN sent, waiting for final ACK |
| `CGO_ENABLED=0` | Disable C Go — build a pure-Go binary with no C library dependencies |
| `DMA` | Direct Memory Access — hardware transfers data to RAM without CPU involvement |
| `DSCP` | Differentiated Services Code Point — IP QoS priority field |
| `DstIP` | Destination IP address |
| `DstMAC` | Destination MAC address |
| `DstPort` | Destination port number |
| `ECN` | Explicit Congestion Notification — IP flag for congestion signalling |
| `eBPF` | extended Berkeley Packet Filter — modern programmable kernel subsystem |
| `ETH_P_ALL` | EtherType Protocol ALL — receive all frame types |
| `EtherType` | 2-byte field in Ethernet header identifying the next-layer protocol |
| `fd` | file descriptor — integer handle for an open kernel resource (socket, file, etc.) |
| `FIN` | FINish — TCP flag: sender has no more data |
| `fps` | frames per second |
| `GC` | Garbage Collector — automatic memory reclamation in Go |
| `htons` | Host TO Network Short — convert uint16 from host to big-endian byte order |
| `HTTP` | HyperText Transfer Protocol — layer 7 web protocol |
| `HTTPS` | HTTP Secure — HTTP over TLS/SSL |
| `IANA` | Internet Assigned Numbers Authority — assigns protocol numbers, ports |
| `ICMP` | Internet Control Message Protocol — network diagnostics and error reporting |
| `IHL` | Internet Header Length — IPv4 header length in 32-bit words |
| `iface` | interface — network interface name (eth0, wlan0, etc.) |
| `Ifindex` | Interface Index — kernel's integer ID for a NIC |
| `insns` | instructions — slice of BPF bytecode instructions |
| `IP` | Internet Protocol — layer 3 addressing and routing |
| `IPv4` | Internet Protocol version 4 — 32-bit addresses |
| `IPv6` | Internet Protocol version 6 — 128-bit addresses |
| `ldflags` | linker flags — options passed to the Go linker at build time |
| `MAC` | Media Access Control — 6-byte hardware address |
| `mreq` | Membership REQuest — kernel structure for socket membership operations |
| `MTU` | Maximum Transmission Unit — largest frame a network link will carry (usually 1500 bytes for Ethernet) |
| `mu` | MUtex — short name convention for sync.Mutex fields |
| `NIC` | Network Interface Card — hardware that connects a computer to a network |
| `NTP` | Network Time Protocol — synchronises clocks over a network |
| `OSI` | Open Systems Interconnection — 7-layer network model |
| `pcap` | Packet CAPture — industry-standard file format for captured network traffic |
| `pcapng` | Packet CAPture Next Generation — newer, more flexible version of pcap |
| `pct` | percentage |
| `PeakBPS` | Peak Bytes Per Second — highest bandwidth ever recorded |
| `PSH` | PuSH — TCP flag: deliver buffered data to application immediately |
| `proto` | protocol |
| `RFC` | Request For Comments — IETF standards documents that define protocols |
| `RST` | ReSeT — TCP flag: immediately abort connection |
| `SigFigs` | SIGnificant FIGures — pcap timestamp precision (always 0) |
| `SIGINT` | SIGnal INTerrupt — OS signal from Ctrl+C |
| `SIGTERM` | SIGnal TERMinate — OS signal from `kill <pid>` or Docker stop |
| `SnapLen` | SNAPshot LENgth — maximum bytes captured per packet |
| `SOCK_RAW` | SOCKET RAW — socket type that bypasses protocol processing |
| `SOL_PACKET` | Socket Option Level PACKET — option level for AF_PACKET sockets |
| `SOL_SOCKET` | Socket Option Level SOCKET — option level for generic socket options |
| `SO_ATTACH_FILTER` | Socket Option ATTACH FILTER — installs a BPF program on a socket |
| `SPSC` | Single-Producer Single-Consumer — lock-free buffer design constraint |
| `SrcIP` | Source IP address |
| `SrcMAC` | Source MAC address |
| `SrcPort` | Source port number |
| `SYN` | SYNchronize — TCP flag: begin connection handshake |
| `SYN_SENT` | TCP connection state: SYN sent, waiting for SYN+ACK |
| `TCP` | Transmission Control Protocol — reliable, ordered, connection-oriented transport |
| `TLS` | Transport Layer Security — encryption protocol (formerly SSL) |
| `ts` | timestamp |
| `TTL` | Time To Live — decremented at each router hop; packet dropped when 0 |
| `TUI` | Terminal User Interface — text-based interactive UI |
| `UDP` | User Datagram Protocol — lightweight, connectionless transport |
| `URG` | URGent — TCP flag: urgent pointer field contains valid data |
| `wg` | WaitGroup — short name convention for sync.WaitGroup variables |
| `WAN` | Wide Area Network — network spanning large geographic areas (the Internet) |
| `LAN` | Local Area Network — network within a building or campus |

---

## 11. Build, Run, Test, Docker

### Building

```bash
make build
# equivalent to:
# go build -ldflags="-w -s -X main.version=$(git describe --tags)" \
#          -o bin/gopacketsniffer ./cmd/gopacketsniffer
```

- **`-w`**: Disable DWARF debug info (smaller binary).
- **`-s`**: Disable symbol table (smaller binary).
- **`-X main.version=...`**: Embed version string.

### Running

```bash
# Minimum: capture on eth0
sudo make run IFACE=eth0

# Verbose mode: print every packet
sudo ./bin/gopacketsniffer -i eth0 -v

# With BPF filter: only TCP port 80
sudo ./bin/gopacketsniffer -i eth0 -f "tcp port 80"

# Save to pcap file (view in Wireshark)
sudo ./bin/gopacketsniffer -i eth0 -w capture.pcap
```

### Testing

```bash
make test   # go test -v -race ./...
```

The `-race` flag enables Go's **race detector** — a runtime tool that detects
concurrent access to shared data without synchronisation. It instruments all
memory accesses with checks. Any data race causes the test to fail with a
detailed report.

```bash
make bench   # go test -bench=. -benchmem ./internal/...
```

Benchmarks measure operations per second and allocations per operation. The
`-benchmem` flag shows memory allocations — crucial for validating that
`sync.Pool` reduces allocations.

```bash
make cover   # generate HTML coverage report
```

Coverage measures what percentage of code paths are exercised by tests.

### Docker

```dockerfile
# Stage 1: Build (in a Go-equipped image)
FROM golang:1.25-alpine AS builder
RUN CGO_ENABLED=0 go build -o gopacketsniffer ./cmd/gopacketsniffer

# Stage 2: Run (minimal image, no Go toolchain)
FROM alpine:3.20
COPY --from=builder /build/gopacketsniffer /usr/local/bin/gopacketsniffer
ENTRYPOINT ["gopacketsniffer"]
```

**Multi-stage build**: The builder stage has the full Go toolchain (~800MB).
The final image only has the compiled binary (~6MB). This is the standard Docker
pattern for Go applications.

**`CGO_ENABLED=0`**: Disables C bindings, producing a **fully static binary**
that doesn't depend on any `.so` (shared library) files. The binary runs in an
Alpine container without glibc.

**Running with Docker**:
```bash
docker run --rm --network host \
    --cap-add=NET_RAW \
    --cap-add=NET_ADMIN \
    gopacketsniffer -i eth0
```

- **`--network host`**: Container shares the host's network namespace, giving
  it access to the host's interfaces.
- **`--cap-add=NET_RAW`**: Grant the `CAP_NET_RAW` capability (raw sockets).
- **`--cap-add=NET_ADMIN`**: Grant the `CAP_NET_ADMIN` capability (set
  promiscuous mode).

---

## 12. Step-by-Step Packet Journey

Let's trace a single HTTP request from your browser to a web server through
every layer of this project.

### Scenario

You open a browser and visit `http://example.com`. The browser sends:
```
GET / HTTP/1.1
Host: example.com
```

GoPacketSniffer is running with `sudo ./gopacketsniffer -i eth0 -f "tcp port 80"`.

### Step 1: Browser sends data

Your OS's TCP/IP stack:
1. Creates an HTTP message: `GET / HTTP/1.1\r\nHost: example.com\r\n\r\n`
2. Wraps it in a TCP segment: source port 49152, dest port 80, SYN flag
3. Wraps in an IP packet: source IP 192.168.1.100, dest IP 93.184.216.34
4. Wraps in an Ethernet frame: source MAC `aa:bb:cc:dd:ee:ff`, dest MAC
   (your router's MAC)
5. Sends electrical signals on the wire

### Step 2: BPF Filter (Kernel Space)

The Ethernet frame arrives at the NIC and is copied to kernel memory.

The BPF program (compiled from `"tcp port 80"`) runs in the kernel:
```
Instruction 0: Load byte at offset 23 (IP protocol) → value = 6 (TCP) ✓
Instruction 1: 6 == 6? Yes → skip 0 instructions
Instruction 2: Load 2 bytes at offset 34 (TCP src port) → 49152
Instruction 3: 49152 == 80? No → skip 0 instructions
Instruction 4: Load 2 bytes at offset 36 (TCP dst port) → 80
Instruction 5: 80 == 80? Yes → skip 0 instructions
Instruction 6: Return 0xFFFF → ACCEPT
```
The packet is accepted and copied to userspace.

### Step 3: `CaptureLoop` (Goroutine 1)

`unix.Recvfrom` unblocks. `bytesRead = 74` (14 Ethernet + 20 IP + 20 TCP + 20
HTTP data).

```go
frame := make([]byte, 74)
copy(frame, buf[:74])
packetChan <- frame    // enqueue in the buffered channel
```

### Step 4: Parse Worker (Goroutine 2)

```go
for frame := range packetChan {
    ts := time.Now()
    
    // PCAP write (if -w flag)
    pcapWriter.WritePacket(ts, frame)
    
    info, err := parser.DecodePacket(frame, ts)
```

**Inside `DecodePacket`**:

```go
// ParseEthernet: reads bytes 0–13
eth.DstMAC = "ff:ff:ff:ff:ff:ff"  // your router's MAC
eth.SrcMAC = "aa:bb:cc:dd:ee:ff"  // your NIC's MAC
eth.EtherType = 0x0800             // IPv4
eth.Payload = frame[14:]           // the IP packet

// eth.EtherType == EtherTypeIPv4, so continue...

// ParseIPv4: reads bytes 14–33
ip.Version = 4
ip.IHL = 5 (20 bytes)
ip.TTL = 64
ip.Protocol = 6 (TCP)
ip.SrcIP = "192.168.1.100"
ip.DstIP = "93.184.216.34"
ip.Payload = frame[34:]            // the TCP segment

// ip.Protocol == IPProtocolTCP, so continue...

// ParseTCP: reads bytes 34–53
tcp.SrcPort = 49152
tcp.DstPort = 80
tcp.SeqNum = 1234567890
tcp.AckNum = 0
tcp.Flags = 0x02 (SYN)
tcp.FlagsStr = "[SYN]"
tcp.Payload = frame[54:]           // the HTTP data (empty for SYN)

// tcp.Payload is empty for this SYN packet, no HTTP parsing

// Return:
info.Protocol = "TCP"
info.SrcIP = "192.168.1.100"
info.DstIP = "93.184.216.34"
info.SrcPort = 49152
info.DstPort = 80
info.TCPFlags = "[SYN]"
info.TotalBytes = 74
```

**Back in the parse worker**:
```go
metrics.Record("TCP", "192.168.1.100", 74)

metrics.FlowTracker.Update(
    "192.168.1.100", "93.184.216.34",
    49152, 80,
    "TCP", 0x02, 74,
)
// FlowTracker creates a new flow entry, state = "SYN_SENT"

// No HTTP (this is a SYN packet), so no metrics.RecordHTTP()

parser.PutPacketInfo(info)  // return struct to sync.Pool
```

### Step 5: Display Goroutine (Goroutine 3)

One second later, the ticker fires:

```go
snap := metrics.GetSnapshot()
display.PrintStats("eth0", snap)
```

The dashboard shows:
```
│  TCP    1 pkts (100.0%) │  74  B    ████████████████████  │
│  TOP TALKERS
│  1. 192.168.1.100       74  B   (100.0%)
│  Active TCP Flows: 1
```

### Step 6: Server Responds

A few milliseconds later, the server's SYN+ACK arrives, and then your browser
sends ACK, then the actual GET request. Each packet goes through the same
pipeline. When the GET request arrives, `ParseHTTP` detects it:

```go
info.HTTP = &models.HTTPInfo{
    IsRequest: true,
    Method: "GET",
    URL: "/",
    Host: "example.com",
}
metrics.RecordHTTP(true, 0)  // isRequest=true
```

After the server responds with `HTTP/1.1 200 OK`:

```go
info.HTTP = &models.HTTPInfo{
    IsResponse: true,
    StatusCode: 200,
    StatusText: "200 OK",
}
metrics.RecordHTTP(false, 200)  // isRequest=false, statusCode=200
```

The dashboard now shows:
```
│  HTTP TRAFFIC
│  Requests: 1  │  2xx: 1  4xx: 0  5xx: 0
```

### Step 7: Connection Closes

Browser sends FIN → flow state transitions to `CLOSING`.
Server sends FIN+ACK → flow state transitions to `CLOSED` → entry deleted from
flow map.

```
│  Active TCP Flows: 0
```

---

## Summary

You have now read about:

1. **What packet sniffing is** — intercepting frames at the network interface.
2. **The OSI model** — how protocols stack like Russian dolls.
3. **AF_PACKET sockets** — Linux's API for raw Ethernet capture.
4. **Promiscuous mode** — receiving all frames, not just those addressed to you.
5. **BPF filters** — kernel-level packet filtering before userspace involvement.
6. **Ethernet II frames** — 14-byte headers with MAC addresses and EtherType.
7. **IPv4 packets** — 20+ byte headers with IP addresses, TTL, and protocol.
8. **TCP segments** — connection-oriented transport with sequence numbers, flags,
   and flow control.
9. **UDP datagrams** — lightweight connectionless transport.
10. **ICMP packets** — network diagnostic and error messages.
11. **HTTP/1.x detection** — best-effort layer 7 parsing.
12. **Go goroutines and channels** — concurrent pipeline architecture.
13. **sync.Mutex** — protecting shared state between goroutines.
14. **sync.Pool** — reusing allocations to reduce GC pressure.
15. **Ring buffers** — lock-free SPSC queues using atomic operations.
16. **Binary parsing** — reading bytes with bit shifts and bigendian decoding.
17. **The pcap file format** — saving frames for Wireshark analysis.
18. **ANSI escape codes** — terminal colors and cursor control.
19. **Multi-stage Docker builds** — small production images.
20. **The complete lifecycle** of a single packet from NIC to dashboard.
