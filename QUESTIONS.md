# GoPacketSniffer — Interview Questions & Answers

> Every question an interviewer could reasonably ask about this project,
> the concepts it uses, and the resume bullets that describe it.
> Organized from easy → medium → hard within each section.

---

## Table of Contents

1. [Resume Bullet Walkthrough — What They Will Definitely Ask](#1-resume-bullet-walkthrough)
2. [Networking Fundamentals](#2-networking-fundamentals)
3. [Linux Systems Programming (AF_PACKET, sockets, BPF)](#3-linux-systems-programming)
4. [Protocol Deep Dives (Ethernet, IP, TCP, UDP, ICMP, HTTP)](#4-protocol-deep-dives)
5. [Go Concurrency & Goroutines](#5-go-concurrency--goroutines)
6. [Performance & Memory Optimization](#6-performance--memory-optimization)
7. [Data Structures (Ring Buffer, Maps, Channels)](#7-data-structures)
8. [Project Design & Trade-off Questions](#8-project-design--trade-offs)
9. [Behavioral / "Walk Me Through" Questions](#9-behavioral--walk-me-through)
10. [Curveball / Edge-Case Questions](#10-curveball--edge-case-questions)

---

## 1. Resume Bullet Walkthrough

These are the exact questions an interviewer will ask **directly from your resume lines**.

---

**Q: You say you used "AF_PACKET raw sockets." What is AF_PACKET and why did you choose it over libpcap?**

A: `AF_PACKET` is a Linux-specific socket domain that gives a process direct access to raw Ethernet frames from the network interface — every frame arriving on the wire, including the full Ethernet header, before the kernel's TCP/IP stack processes it. The `AF_PACKET` socket type is actually what `libpcap` itself uses internally; going directly to `AF_PACKET` eliminates the C dependency, keeps the binary fully statically linked with `CGO_ENABLED=0`, and makes the kernel interaction explicit and educational. It also means no wrapper overhead — I control exactly when I call `recvfrom`, how I buffer, and how I handle errors.

---

**Q: You claim "<0.1% packet loss at 1 Gbps." How did you achieve that, and how did you measure it?**

A: A 1 Gbps Ethernet link carrying 1500-byte frames produces about 83,333 packets per second. My parse worker runs at ~335 ns per packet, which means theoretical throughput of about 2.9 million packets per second on a single core — 35× the packet rate of a saturated 1 Gbps link. So there is enormous headroom. The channel buffer of 4096 frames absorbs any bursts from the capture goroutine while the parse worker is temporarily slow (e.g. during a GC cycle). I measured using `iperf3` at 1 Gbps and checked the "Dropped" counter in the stats display — it stayed at 0. The < 0.1% figure is the observed result during benchmark runs documented in `BENCHMARKS.md`.

---

**Q: You mention "goroutine worker pools: dedicated capture goroutine, parallel parsers, and async display." Walk me through why you split these three responsibilities into separate goroutines.**

A: They have fundamentally different blocking characteristics. The capture goroutine is blocked on `unix.Recvfrom` — a system call that sleeps until a packet arrives. If parsing happened in the same goroutine, every millisecond spent decoding headers would delay the next `Recvfrom` call, causing the kernel's socket receive buffer to overflow. The parse worker is CPU-bound — it chews through bytes. The display goroutine is timer-driven — it sleeps 1 second, wakes, prints, repeats. Mixing them would cause each to interrupt the others. Separate goroutines let each do what it does best without interfering; they communicate through a buffered channel that absorbs rate differences between capture and parsing.

---

**Q: "335 ns/packet full-decode latency" — how did you get that number? What does it mean exactly?**

A: I wrote a Go benchmark using the standard `testing.B` framework:
```go
func BenchmarkDecodePacketPool(b *testing.B) {
    for i := 0; i < b.N; i++ {
        info, _ := parser.DecodePacket(testdata.TCPSynPacket, time.Now())
        parser.PutPacketInfo(info)
    }
}
```
`go test -bench=BenchmarkDecodePacketPool -benchmem` reports `335 ns/op`. That means: given a raw Ethernet frame byte slice, the time to run `ParseEthernet` → `ParseIPv4` → `ParseTCP` → `ParseHTTP` and populate a `PacketInfo` struct is 335 nanoseconds wall-clock time on my test machine (Intel Core i5-1235U). Without `sync.Pool` it was 428 ns/op — the pool gave a 22% reduction. The 335 ns figure matters because it defines the throughput ceiling: 1/335ns ≈ 2.98 million packets/second per core.

---

**Q: "sync.Pool — 22% faster, 31% fewer allocations." Explain what sync.Pool does and why those two improvements are related.**

A: `sync.Pool` is a thread-safe cache of reusable objects. Without it, every packet decode allocates a new `PacketInfo` struct on the heap. At high packet rates those allocations accumulate, triggering Go's garbage collector more frequently. GC pauses cause latency spikes and consume CPU time scanning memory. With `sync.Pool`, I borrow a `PacketInfo` from the cache (`Get`), use it, zero all its fields, then return it (`Put`). The pool keeps recently-returned objects in a per-CPU cache, so `Get` often finds an existing object without allocating — that's the 31% reduction in allocations. Fewer allocations mean less GC work, which is why the wall-clock time also drops (22% faster) even though the actual parsing logic is identical.

---

**Q: "Zero-alloc ring buffer." What makes it zero-allocation and why does that matter?**

A: The ring buffer pre-allocates all its slots at creation time. `Enqueue` and `Dequeue` only update two `atomic.Uint64` counters and write/read from the pre-allocated `[][]byte` slot array — no `make`, no `new`, zero heap allocations per operation. I verified this with `go test -bench=BenchmarkRingBuffer -benchmem` which reports `0 B/op 0 allocs/op`. It matters because every heap allocation has two costs: the allocation itself, and eventual garbage collection. In the capture hot path — potentially millions of operations per second — even tiny per-operation allocations compound into enormous GC pressure. The ring buffer is used as a building block; in the main pipeline I use a buffered channel for cleaner shutdown semantics, but the ring buffer demonstrates the zero-alloc principle.

---

**Q: "2.9M pps theoretical throughput gives 35× headroom over a saturated 1 Gbps link." Walk me through the math.**

A: Two calculations:

*Parse throughput*: At 335 ns per full packet decode on a single core: `1 second / 335 nanoseconds = 2,985,074 packets/second ≈ 2.9 million pps`.

*1 Gbps capacity*: A 1 Gbps Ethernet link transmits 1,000,000,000 bits/second. A typical frame is 1500 bytes = 12,000 bits. So: `1,000,000,000 / 12,000 = 83,333 frames/second ≈ 83k pps`.

*Headroom*: `2,985,074 / 83,333 ≈ 35.8×`. Even if you include protocol overhead and assume shorter average frame sizes (say 500 bytes → 250k pps), the parse worker still has 10× headroom. This is why packet loss is negligible at 1 Gbps.

---

**Q: You mention "TCP flow tracking." What is a flow and how did you implement it?**

A: A TCP flow (or connection) is uniquely identified by a **five-tuple**: source IP, destination IP, source port, destination port, and protocol. Every TCP packet belongs to a flow. I maintain a `map[FiveTuple]*FlowStats` guarded by a mutex. On each TCP packet, I normalize the five-tuple (always put the lexicographically smaller IP first so packets in both directions map to the same entry), look it up or create it, and advance a state machine: new SYN → `SYN_SENT`; SYN+ACK → `ESTABLISHED`; FIN → `CLOSING`; RST or FIN+ACK → `CLOSED`. Flows in `CLOSED` state are deleted immediately to bound memory — at 10,000 simultaneous flows the map stays around 5 MB. The display shows "Active TCP Flows: N" updated every second.

---

**Q: How do you detect HTTP traffic? What are the limitations?**

A: I check the TCP payload's first 16 bytes. If they start with a known HTTP method (`GET `, `POST `, `PUT `, `DELETE `, etc.) I attempt `http.ReadRequest()` from Go's standard library. If the payload starts with `HTTP/`, I attempt `http.ReadResponse()`. I track request count, 2xx, 4xx, and 5xx response counts. Limitations: (1) HTTPS traffic is TLS-encrypted — the TCP payload is ciphertext, not HTTP, so detection always fails. (2) HTTP/2 and HTTP/3 don't start with plaintext method names. (3) If a GET request is split across two TCP segments, the first segment might not have the complete first line. (4) This is best-effort — I return nil on parse failure, which is treated as non-HTTP.

---

## 2. Networking Fundamentals

**Q (easy): What is the OSI model? Which layers does this project touch?**

A: The OSI (Open Systems Interconnection) model is a 7-layer conceptual framework for how network communication works:
- Layer 7 Application (HTTP, DNS)
- Layer 6 Presentation (TLS/encoding)
- Layer 5 Session
- Layer 4 Transport (TCP, UDP)
- Layer 3 Network (IP)
- Layer 2 Data Link (Ethernet, MAC)
- Layer 1 Physical (cables, radio)

This project touches layers 2 through 7: it reads raw Ethernet frames (Layer 2), parses IPv4 headers (Layer 3), decodes TCP/UDP/ICMP (Layer 4), and detects HTTP/1.x messages (Layer 7).

---

**Q (easy): What is the difference between a MAC address and an IP address?**

A: A MAC (Media Access Control) address is a 6-byte hardware identifier burned into a NIC at the factory — it is like a serial number. It is used for communication within a single local network segment (subnet). An IP address is a logical, software-assigned identifier used for routing packets across networks and the internet. When you send a packet to `google.com`, the Ethernet frame's destination MAC is your *router*, but the IP packet's destination IP is Google's server. Routers strip and rebuild Ethernet frames at each hop, but the IP addresses stay constant end-to-end.

---

**Q (easy): What is promiscuous mode? Why does this project need it?**

A: By default, a NIC's hardware filter discards Ethernet frames not addressed to its own MAC address (or broadcast/multicast addresses). In promiscuous mode the filter is disabled — every frame on the wire is passed to the OS. This project needs promiscuous mode to capture traffic between *other* machines on the same network (e.g. a switch that mirrors traffic, or a shared Wi-Fi medium). Without it, you would only see frames addressed to your own machine. Enabling promiscuous mode requires root / `CAP_NET_ADMIN`.

---

**Q (easy): What is a port number? What is the range?**

A: Port numbers are 16-bit unsigned integers (range 0–65535) used by the OS to demultiplex incoming TCP/UDP data to the correct process. Ports 0–1023 are "well-known" (e.g. 80=HTTP, 443=HTTPS, 22=SSH, 53=DNS) and require root to bind. Ports 1024–49151 are "registered." Ports 49152–65535 are ephemeral — the OS assigns these randomly to the client side of outgoing connections. When you see `SrcPort=49152, DstPort=80`, the client chose ephemeral port 49152 to connect to a server's port 80.

---

**Q (medium): What is the TCP three-way handshake?**

A: It establishes a TCP connection:
1. **SYN**: Client sends a segment with the SYN flag set and a randomly chosen Initial Sequence Number (ISN). "I want to connect, my starting byte number is X."
2. **SYN+ACK**: Server responds with both SYN and ACK flags. SYN carries the server's ISN; ACK's acknowledgment number is client-ISN + 1. "I'm ready, my starting number is Y, and I received your X."
3. **ACK**: Client acknowledges the server's SYN. AckNum = server-ISN + 1. "Got your Y."

After step 3 the connection is `ESTABLISHED`. This is exactly what the flow tracker observes: upon seeing a SYN packet it creates a new flow in state `SYN_SENT`; upon seeing SYN+ACK it transitions to `ESTABLISHED`.

---

**Q (medium): What does TTL do? What happens when it reaches zero?**

A: TTL (Time To Live) is an 8-bit field in the IPv4 header initialized by the sender (typically 64 or 128). Every router that forwards the packet decrements TTL by 1. When TTL reaches 0, the router drops the packet and sends an ICMP "Time Exceeded" (type 11) message back to the source. This prevents packets from circling indefinitely due to routing loops. It is also how `traceroute` works: it sends packets with TTL=1, 2, 3 incrementing, collecting the ICMP Time Exceeded messages from each intermediate router to map the path.

---

**Q (medium): What is the difference between TCP and UDP? When would you choose each?**

A: TCP provides reliable, ordered, connection-oriented delivery — it retransmits lost segments, reassembles out-of-order segments, and uses flow control (window size) and congestion control (slow start, AIMD). UDP is connectionless, unreliable, and has no ordering guarantees — it fires and forgets. Choose TCP when data integrity matters: HTTP, email, file transfer, SSH. Choose UDP when low latency matters more than reliability: DNS lookups (query/response fits in one datagram), live video streaming (a retransmitted frame arrives too late to be useful), online gaming (prefer newer state over stale guaranteed state), VoIP.

---

**Q (medium): What is a BPF filter? How does it work in this project?**

A: BPF (Berkeley Packet Filter) is a tiny virtual machine embedded in the Linux kernel. You write a BPF program — a sequence of load, compare, and return instructions — and attach it to a socket via `setsockopt(SO_ATTACH_FILTER)`. The kernel runs this program on every incoming packet before copying it to userspace. If the program returns 0 the packet is discarded; non-zero means keep it. In this project I compile filter expressions like `"tcp port 80"` into BPF bytecode using the `golang.org/x/net/bpf` package, then attach the bytecode. The benefit is enormous: discarded packets never cross the kernel-to-userspace boundary, saving memory copies and CPU time. This is more efficient than filtering in Go — the kernel does it for free, zero userspace CPU.

---

**Q (hard): What is ICMP used for? Name four ICMP message types and their uses.**

A: ICMP (Internet Control Message Protocol) is an IP-layer protocol for network diagnostics and error reporting — not for application data. Four types:
- **Type 0 Echo Reply**: Response to a ping. The peer echoes back the data you sent.
- **Type 3 Destination Unreachable**: Router or host cannot deliver the packet. Code 0 = net unreachable, code 1 = host unreachable, code 3 = port unreachable (target process not listening), code 4 = fragmentation needed but DF bit set.
- **Type 8 Echo Request**: The `ping` command sends these. "Are you there? Here's my timestamp."
- **Type 11 Time Exceeded**: TTL reached zero. `traceroute` uses this to discover each hop.

---

**Q (hard): Explain IP fragmentation. How does a receiver reassemble fragments?**

A: IP fragmentation occurs when a router needs to forward an IP packet but its outgoing link's MTU (Maximum Transmission Unit) is smaller than the packet. The router splits the packet into fragments, each with the same Identification field but different Fragment Offset values (in units of 8 bytes). The `More Fragments (MF)` flag is set on all fragments except the last. The receiver reassembles using the Identification to group fragments and Fragment Offset to order them. Fragmentation is avoided in modern networks using Path MTU Discovery (PMTUD): the sender probes the path MTU by sending packets with the Don't Fragment (DF) flag; routers respond with ICMP Type 3 Code 4 (fragmentation needed) carrying the link's MTU, and the sender reduces its packet size.

---

**Q (hard): What is TCP window scaling? What problem does it solve?**

A: The TCP Window Size field is 16 bits, capping the maximum receive window at 65,535 bytes. On a high-latency, high-bandwidth link (e.g. satellite: 500ms RTT, 100 Mbps link), the bandwidth-delay product is `100Mbps × 0.5s = 50 Mbit = 6.25 MB`. The 64 KB window means the sender must pause every 64 KB waiting for an ACK, achieving only `64KB / 0.5s = 128 Kbps` — 780× below line rate. TCP Window Scaling (RFC 7323) adds a SYN option negotiating a scale factor (0–14) applied to the window field, extending the effective window to 2^30 bytes (1 GB). Both sides must agree during the handshake.

---

## 3. Linux Systems Programming

**Q (easy): What is a file descriptor?**

A: A file descriptor (fd) is a small non-negative integer that the kernel assigns to represent an open resource — file, socket, pipe, timer, etc. It is an index into the process's open-file table. `open()`, `socket()`, `accept()` all return fds. You use fds with `read(fd, ...)`, `write(fd, ...)`, `close(fd)`. In Go, `unix.Socket()` returns an integer fd; `unix.Recvfrom(fd, buf, ...)` uses it to read from the socket.

---

**Q (easy): Why does this program need `sudo` / root privileges?**

A: Creating an `AF_PACKET / SOCK_RAW` socket requires the `CAP_NET_RAW` Linux capability. Normal processes don't have this capability. Running as root grants all capabilities including `CAP_NET_RAW`. Alternatively you can grant just `CAP_NET_RAW` to the binary with `setcap cap_net_raw=eip ./gopacketsniffer` — then it runs without root. Docker requires `--cap-add=NET_RAW` for the same reason.

---

**Q (medium): What is a system call? Give examples used in this project.**

A: A system call is a controlled entry point into the Linux kernel. User processes run in CPU ring 3 (unprivileged mode); the kernel runs in ring 0. A syscall switches from ring 3 to ring 0, executes kernel code on behalf of the process, then returns. System calls used in this project:
- `socket(AF_PACKET, SOCK_RAW, ETH_P_ALL)` — create the raw socket
- `bind(fd, &sockaddr)` — bind to a specific interface
- `setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, ...)` — enable promiscuous mode
- `setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, ...)` — attach BPF filter
- `recvfrom(fd, buf, 0, ...)` — receive next frame (blocks until data arrives)
- `close(fd)` — release the socket

---

**Q (medium): What is byte order (endianness)? Why does it matter for network programming?**

A: Endianness describes the order in which a CPU stores a multi-byte integer in memory. **Little-endian** (x86/x64): least significant byte at the lowest address. **Big-endian**: most significant byte first. Network protocols standardize on **big-endian** (called "network byte order"). This matters because if an x86 CPU sends `uint16(80)` (port 80) as raw bytes without conversion, it would store `0x50 0x00` (little-endian), but the receiver expecting big-endian would read `0x5000 = 20480` instead of 80. The `htons` function in this project converts `uint16` from host to network byte order. Go's `binary.BigEndian.Uint16(data[0:2])` reads 2 bytes in big-endian regardless of CPU architecture.

---

**Q (medium): What is the difference between `SOCK_RAW` and `SOCK_STREAM`? What about `AF_INET` vs `AF_PACKET`?**

A: `SOCK_STREAM` (TCP) gives you a reliable, ordered byte stream — the kernel handles all TCP logic, headers, retransmission. `SOCK_RAW` gives you raw IP datagrams — you see/send the full IP payload with your own headers. `AF_INET / SOCK_RAW` gives raw IP packets (no Ethernet header). `AF_PACKET / SOCK_RAW` gives complete Ethernet frames — the lowest level available in userspace, before the kernel's IP stack processes anything. This project uses `AF_PACKET / SOCK_RAW` to see everything including MAC addresses and to capture non-IP frames (ARP).

---

**Q (hard): What is `Recvfrom` and how does it differ from `Read`?**

A: Both read data from a file descriptor. `Read(fd, buf)` is simpler — just reads bytes, used for files and connected sockets. `Recvfrom(fd, buf, flags, &addr)` additionally fills in the sender's address (`sockaddr`) — useful for connectionless sockets like `AF_PACKET` and `UDP` where each datagram can come from a different source. This project uses `Recvfrom` with `AF_PACKET` because there is no "connection" — each call returns one complete Ethernet frame from whatever source sent it to the wire.

---

**Q (hard): What is `unsafe.Pointer` and why is it used in `htons`?**

A: `unsafe.Pointer` is Go's escape hatch from the type system. It can point to any memory location, like C's `void*`. Normal Go code cannot reinterpret the bytes of a value as a different type — but `unsafe.Pointer` allows it. In `htons`:
```go
b := (*[2]byte)(unsafe.Pointer(&v))
```
This takes the address of `v` (a `uint16`), reinterprets it as a pointer to a 2-byte array, then reads the individual bytes to swap them. This is necessary because the Go type system has no built-in "read raw bytes of this integer" primitive. It is safe here because we control the data sizes precisely (2 bytes), but `unsafe` package use bypasses type safety guarantees and should be used sparingly.

---

**Q (hard): Explain the BPF bytecode instruction format. How does the "tcp port 80" filter work at the instruction level?**

A: Each BPF instruction is 8 bytes: a 16-bit opcode, two 8-bit jump offsets (SkipTrue, SkipFalse), and a 32-bit constant K. The filter "tcp port 80" compiles to:

```
[0] LoadAbsolute{Off:23, Size:1}    — load IP Protocol byte into accumulator
[1] JumpIf{Equal, Val:6, ST:0, SF:3} — if TCP (6), skip 0; else skip 3 to [5]
[2] LoadAbsolute{Off:34, Size:2}    — load TCP source port
[3] JumpIf{Equal, Val:80, ST:2, SF:0} — if src==80, skip to [6]; else continue
[4] LoadAbsolute{Off:36, Size:2}    — load TCP destination port
[5] JumpIf{Equal, Val:80, ST:0, SF:1} — if dst==80, skip to [6]; else skip to [7]
[6] RetConstant{Val:0xFFFF}         — accept (return max bytes)
[7] RetConstant{Val:0}              — reject
```

Instruction [1]'s SF=3 skips three forward (lands at [5] for the non-TCP case which then falls through to [7] reject). The kernel JIT-compiles this to native machine code for maximum speed.

---

## 4. Protocol Deep Dives

**Q (easy): What is the size of an Ethernet header? What are its three fields?**

A: An Ethernet II header is exactly **14 bytes**:
- Bytes 0–5: Destination MAC address (6 bytes)
- Bytes 6–11: Source MAC address (6 bytes)
- Bytes 12–13: EtherType (2 bytes) — identifies the payload protocol: `0x0800` = IPv4, `0x0806` = ARP, `0x86DD` = IPv6.

---

**Q (easy): What is the minimum size of an IPv4 header? What does IHL mean?**

A: Minimum 20 bytes. IHL = Internet Header Length. It is the top 4 bits of the first IP byte and is measured in 32-bit words (groups of 4 bytes). Minimum value is 5, meaning `5 × 4 = 20 bytes`. When IHL > 5 there are IP options present (e.g. Router Alert, Record Route). The code reads IHL as `data[0] & 0x0F` (bottom 4 bits), then multiplies by 4.

---

**Q (medium): What is the TCP Data Offset field? How is it used?**

A: Data Offset (sometimes called the TCP Header Length field) is the top 4 bits of byte 12 in the TCP header. Like IHL in IPv4, it is measured in 32-bit words. Minimum value is 5 (20 bytes). When TCP Options are present (MSS, SACK, Timestamps, Window Scale), the header is longer and Data Offset > 5. The payload starts at `Data Offset × 4` bytes into the TCP segment. The code: `dataOffset := (data[12] >> 4) & 0x0F; headerLen := dataOffset * 4; payload := data[headerLen:]`.

---

**Q (medium): What are the TCP SYN, ACK, FIN, and RST flags? When is each set?**

A:
- **SYN** (Synchronize): Set in the first two packets of the three-way handshake. Carries the sender's Initial Sequence Number. After the handshake, SYN is never set again in the lifetime of a connection.
- **ACK** (Acknowledge): Set in all packets after the initial SYN, confirming receipt of data up to the acknowledgment number. "I have received everything up to byte AckNum-1."
- **FIN** (Finish): Half-closes a connection. The sender has no more data. The receiver can still send data. Both sides send FIN; both sides ACK the other's FIN.
- **RST** (Reset): Immediately aborts the connection — no graceful close. Sent when a port is not listening, a firewall rejects, or an application crashes mid-connection. After RST, no more packets on this connection are valid.

---

**Q (medium): What is a UDP checksum? Is it mandatory?**

A: The UDP checksum covers the UDP header, data, and a pseudo-header (src IP, dst IP, protocol=17, UDP length) to detect corruption in transit. In IPv4, the UDP checksum is **optional** — a sender may send `0x0000` to indicate it was not computed. Many high-performance systems and some NICs (hardware offload) skip or offload UDP checksum computation. In IPv6 the UDP checksum is mandatory because IPv6 removed the IP header checksum. This project reads but does not validate checksums — validation would add CPU cost with limited benefit in a sniffing context (the NIC hardware has already verified the Ethernet CRC).

---

**Q (hard): What is the IPv4 header checksum? How is it computed?**

A: The IPv4 header checksum is a 16-bit one's complement sum of all 16-bit words in the IP header (with the checksum field itself set to zero during computation). One's complement arithmetic means: add all 16-bit words, and for any carry out of bit 15, add it back into bit 0 (end-around carry). Then take the bitwise NOT. To verify: the receiver adds all 16-bit words of the header including the checksum; if the result is `0xFFFF` (all ones in one's complement), the header is uncorrupted. The checksum covers only the IP header, not the payload — TCP and UDP have their own checksums for end-to-end integrity.

---

**Q (hard): Explain TCP sequence numbers. What is a sequence number wrap?**

A: TCP sequence numbers are 32-bit unsigned integers that label each byte of the data stream. The Initial Sequence Number (ISN) is chosen randomly at connection setup (to prevent old duplicate segments from interfering). Each data byte is numbered; the SeqNum in a segment header is the number of its first byte. AckNum in the reply means "I have received all bytes up to AckNum-1; send me AckNum next." A sequence number wrap occurs when the sequence number exceeds 2^32-1 and wraps to 0. On a 10 Gbps link carrying full-speed traffic, this can happen in about 3.4 seconds! TCP handles wraps using Protection Against Wrapped Segments (PAWS) — timestamps in TCP options allow rejecting old duplicates even after a wrap.

---

**Q (hard): What is ICMP "Destination Unreachable Type 3 Code 3" (Port Unreachable)? When is it sent?**

A: Port Unreachable (ICMP Type 3, Code 3) is sent by the destination host when a UDP packet arrives for a port that has no process listening (no socket `bind()`ed to that port). It carries the original IP header plus 8 bytes of the original UDP header, so the sender can correlate it to the original request. This is how you know a UDP send definitively failed — unlike TCP which uses RST. Tools like `traceroute` on Linux deliberately send UDP packets to high port numbers (unlikely to be in use) so the destination sends Port Unreachable, confirming the packet arrived.

---

## 5. Go Concurrency & Goroutines

**Q (easy): What is a goroutine? How is it different from a thread?**

A: A goroutine is a function executing concurrently with other goroutines, managed by the Go runtime scheduler rather than the OS. Key differences: goroutines start with ~2 KB of stack (vs ~1 MB for OS threads), can grow/shrink dynamically, and thousands can run in a single process. The Go runtime multiplexes goroutines onto a small pool of OS threads (GOMAXPROCS, default = CPU count). Context switching between goroutines is done in userspace (no kernel involvement), making it orders of magnitude cheaper than OS thread switches.

---

**Q (easy): What is a channel? What is the difference between buffered and unbuffered?**

A: A channel is a typed pipe between goroutines. Send (`ch <- value`) puts a value in, receive (`value <- ch`) takes one out. An **unbuffered** channel (`make(chan T)`) has no storage — the sender blocks until a receiver is ready, and vice versa. A **buffered** channel (`make(chan T, N)`) has N slots — the sender only blocks when the buffer is full; the receiver only blocks when empty. In this project `packetChan := make(chan []byte, 4096)` is buffered so the capture goroutine can put frames in without waiting for the parse worker to process each one immediately.

---

**Q (easy): What is `sync.WaitGroup` used for?**

A: `sync.WaitGroup` ensures the `main` goroutine waits for all worker goroutines to finish before the program exits. Pattern: `wg.Add(1)` before spawning a goroutine; `defer wg.Done()` inside the goroutine; `wg.Wait()` in main. Without it, `main` returning would kill all goroutines mid-execution — possibly before the parse worker finishes processing its last packet or the PCAP writer finishes flushing.

---

**Q (medium): What is a data race? How does the `-race` flag help?**

A: A data race occurs when two goroutines access the same memory location concurrently and at least one access is a write, without synchronization. Data races cause undefined behavior — corrupted data, crashes, non-deterministic bugs. Go's race detector (`go test -race` or `go run -race`) instruments every memory access at compile time with runtime checks. When it detects concurrent access without synchronization, it prints a full report including goroutine stack traces. In this project, the `Statistics` struct is accessed by both the parse worker (writes) and the display goroutine (reads) — the `sync.Mutex` prevents the race.

---

**Q (medium): Why does the parse worker use `for frame := range packetChan` instead of an infinite `for` loop with a select?**

A: `range` over a channel automatically exits the loop when the channel is **closed** — no explicit done-channel check needed. In the shutdown sequence, the capture goroutine calls `close(packetChan)` after exiting its loop. The `range` loop in the parse worker then drains any remaining frames and exits cleanly. An explicit `for { select { case frame, ok := <-packetChan: ...}}` would work too but is more verbose. The `range` idiom is idiomatic Go for "consume until closed."

---

**Q (medium): What is `select` in Go? How is it used for non-blocking sends?**

A: `select` is like a `switch` for channel operations — it waits until one of its cases is ready. If multiple cases are ready simultaneously, it picks one at random. A `default` case makes it non-blocking. In the capture loop:
```go
select {
case packetChan <- frame:
default:
    // drop packet — channel full
}
```
Without `default`, this would block until the channel has space. With `default`, if the channel is full the frame is silently dropped and capture continues immediately — preventing the capture goroutine from falling behind the NIC.

---

**Q (medium): Explain the shutdown sequence in `main.go` step by step.**

A: 1. `signal.Notify(sigCh, SIGINT, SIGTERM)` — registers for Ctrl+C signal. 2. `<-sigCh` — main goroutine blocks here. 3. Ctrl+C arrives → `sigCh` receives the signal. 4. `close(done)` — broadcasts to all goroutines (any `<-done` or `case <-done` unblocks). 5. `capture.Close(fd)` — closes the socket, causing the blocked `Recvfrom` call in the capture goroutine to return with an error. 6. Capture goroutine sees `<-done` is closed (in its select), returns, calls `close(packetChan)`. 7. Parse worker's `range packetChan` drains remaining frames, then exits. 8. Display goroutine's `case <-done` fires, it returns. 9. `wg.Wait()` unblocks. 10. `pcapWriter.Close()` flushes and closes the file. 11. Final stats printed.

---

**Q (hard): What is `sync.Mutex`? When would you use `sync.RWMutex` instead?**

A: `sync.Mutex` has two methods: `Lock()` blocks until the mutex is available and acquires it exclusively; `Unlock()` releases it. Only one goroutine holds the mutex at a time. `sync.RWMutex` adds `RLock()`/`RUnlock()` — multiple goroutines can hold the read lock simultaneously, but a write lock is exclusive. Use `RWMutex` when reads vastly outnumber writes and the critical section is large enough that concurrent reads matter. In this project, `Statistics` uses a plain `Mutex` because the write path (parse worker at ~1M pps) and read path (display ticker at 1 Hz) have asymmetric frequency — but the write operations are very fast (just incrementing counters), so the lock is rarely contended and `RWMutex` overhead would not help.

---

**Q (hard): What is a goroutine leak? How would you detect one in this project?**

A: A goroutine leak occurs when a goroutine is created but never exits — it stays in memory consuming stack space, potentially forever. Common causes: a goroutine blocked on a channel that will never receive data; a goroutine blocked on a mutex never unlocked; or a goroutine spawned in a loop without a termination condition. Detection tools: `runtime.NumGoroutine()` to monitor goroutine count; `pprof` goroutine endpoint (`go tool pprof http://localhost:6060/debug/pprof/goroutine`); `goleak` library in tests. In this project, goroutine leaks are prevented by the `done` channel and `WaitGroup`: all goroutines check `<-done` or handle channel closure and exit cleanly.

---

**Q (hard): The `sync.Pool` documentation says "objects in the pool may be freed at any time." How does this affect correctness?**

A: The Go GC can drain a `sync.Pool` during a garbage collection cycle. This is fine for correctness because the pool is purely an optimization — when the pool is empty, `Get()` calls the `New` function to allocate a fresh object. The only correctness requirement is that callers **zero the object** before returning it to the pool (`*p = models.PacketInfo{}`), so the next borrower doesn't see stale data from a previous packet. If the pool drains between two high-traffic bursts, the next burst will allocate fresh objects until the pool refills — a temporary increase in GC pressure but never incorrect behavior.

---

## 6. Performance & Memory Optimization

**Q (easy): What is garbage collection? Why does Go have it?**

A: Garbage collection (GC) is automatic memory management — the runtime periodically scans the heap, finds objects no longer reachable, and frees them. Go has GC to eliminate manual memory management bugs (use-after-free, double-free, memory leaks) while still being fast. Go's GC is concurrent — it runs mostly in parallel with your code — but does have brief stop-the-world pauses to scan roots. At high packet rates with many short-lived allocations, GC pauses add latency, which is why this project uses `sync.Pool` to reuse objects.

---

**Q (easy): What is the difference between stack and heap allocation?**

A: Stack: fast, automatic lifetime, size known at compile time, freed when function returns. Heap: slower (requires allocator), survives beyond function returns, garbage collected. Go's compiler determines via **escape analysis** whether a variable "escapes" to the heap. If you take the address of a local variable and store it in a channel or interface (as in `packetPool.Put(p)`), it escapes to the heap. `sync.Pool` helps because objects are kept alive by the pool — they don't escape/allocate on each use.

---

**Q (medium): What does `go test -benchmem` report? What are "allocs/op" and "B/op"?**

A: `-benchmem` adds two columns to benchmark output: **B/op** (bytes allocated per operation) and **allocs/op** (number of heap allocations per operation). Lower is better. For the ring buffer: `0 B/op, 0 allocs/op` means it never touches the heap. For `DecodePacketPool`: `352 B/op, 8 allocs/op` means 8 heap allocations totaling 352 bytes per packet decode (even with the pool — the remaining allocations are for strings like MAC addresses and IP addresses that must be heap-allocated because they escape to `PacketInfo`).

---

**Q (medium): What is a CPU cache miss? How does the ring buffer design avoid them?**

A: Modern CPUs have L1/L2/L3 caches (kilobytes to megabytes, nanoseconds to tens of nanoseconds). When a program accesses memory not in cache, the CPU must fetch it from RAM (~100 ns) — a cache miss. Sequential memory access (arrays) is cache-friendly because the CPU prefetches adjacent memory. Random access (trees, linked lists) causes cache misses. The ring buffer is a pre-allocated fixed-size array — sequential reads and writes at adjacent indices exploit CPU prefetching. The power-of-two size ensures index wrapping with a bitmask (`&mask`) — a single fast instruction — instead of a modulo division that stalls the pipeline.

---

**Q (medium): What is "escape analysis" in Go? Give an example of controlling allocation.**

A: Escape analysis is the compiler's static analysis to determine whether a variable's lifetime can be bounded to the current stack frame or must be heap-allocated. A variable "escapes to the heap" if: its address is taken and stored where it outlives the current function; it's assigned to an interface; it's too large for the stack. You can check with `go build -gcflags="-m"`. Example: `x := 42; fmt.Println(x)` — x stays on stack. `x := 42; ch <- &x` — x escapes to heap. In this project, returning `*PacketInfo` from `GetPacketInfo()` would normally cause it to escape, but since the pointer comes from the pool (already on heap), no new allocation occurs.

---

**Q (hard): What is the bandwidth-delay product and how does it relate to TCP performance?**

A: Bandwidth-Delay Product (BDP) = bandwidth × round-trip time. It is the amount of data "in flight" (sent but not yet acknowledged) at any moment when the pipe is fully utilized. Example: 1 Gbps link, 100ms RTT → BDP = 100 Mbps × 0.1s = 10 Mbit = 1.25 MB. TCP can have at most one receive-window worth of data in flight. If the window size (65 KB without scaling) is smaller than the BDP, TCP idles waiting for ACKs before the pipe is full. Window scaling (RFC 7323) solves this for high-BDP paths. For this project: 1 Gbps LAN link, ~0.1ms RTT → BDP = 12.5 KB — well within the standard 65 KB window, so scaling is not needed.

---

**Q (hard): How would you profile this application to find performance bottlenecks?**

A: Go has a built-in profiler accessible via `net/http/pprof`. Add to main: `import _ "net/http/pprof"` and `go http.ListenAndServe(":6060", nil)`. Then:
- **CPU profile**: `go tool pprof http://localhost:6060/debug/pprof/profile?seconds=30` — shows which functions consume the most CPU.
- **Heap profile**: `go tool pprof http://localhost:6060/debug/pprof/heap` — shows what is using memory.
- **Goroutine profile**: `go tool pprof http://localhost:6060/debug/pprof/goroutine` — detects leaks.
- **Trace**: `curl http://localhost:6060/debug/pprof/trace?seconds=5 -o trace.out; go tool trace trace.out` — shows goroutine scheduling, GC pauses, system calls.
Expected hot spots: `unix.Recvfrom` (blocked — normal), `binary.BigEndian.Uint16/32` (memory reads), `net.IP.String()` (allocates strings for IP display).

---

**Q (hard): What is false sharing in concurrent data structures? Does the ring buffer have this problem?**

A: False sharing occurs when two CPU cores access different variables that happen to lie on the same cache line (typically 64 bytes). When Core 0 writes its variable, the cache line is invalidated in Core 1's cache — Core 1 must re-fetch the line even though Core 1's variable was not modified. This causes unnecessary cache coherence traffic. The `RingBuffer` has `write` and `read` as adjacent `atomic.Uint64` fields — they may share a cache line. Core 0 (writer) and Core 1 (reader) both modify them, causing false sharing. A high-performance solution is to pad each field to its own cache line: `struct { write atomic.Uint64; _ [56]byte; read atomic.Uint64 }`. For this project's throughput target (< 3M pps, single machine), the impact is not measurable — it would matter at 100M+ pps.

---

## 7. Data Structures

**Q (easy): What is a circular / ring buffer? What are its advantages?**

A: A ring buffer is a fixed-size array where write and read positions advance linearly but wrap around (modulo capacity), creating the illusion of an infinite stream. Advantages: O(1) enqueue and dequeue; pre-allocated (no per-operation allocation); cache-friendly (sequential memory access); no need to shift elements. Disadvantages: fixed capacity (must be sized for peak load); SPSC (Single-Producer Single-Consumer) variants are lock-free but MPMC (multi-producer multi-consumer) variants require more complex synchronization.

---

**Q (easy): What is a hash map? What is its average time complexity for lookup?**

A: A hash map stores key-value pairs. It computes `hash(key) % buckets` to find a bucket, then stores/retrieves the value there. Average O(1) for insert, lookup, and delete. Worst case O(n) if all keys hash to the same bucket (poor hash function or hash collision attack). Go's built-in `map` uses open addressing. This project uses maps for: `protocols map[string]*ProtoStats` (protocol counters), `counts map[string]uint64` (top talkers), `flows map[FiveTuple]*FlowStats` (TCP flow tracker).

---

**Q (medium): The ring buffer uses `writeIdx & rb.mask` instead of `writeIdx % capacity`. Why?**

A: Modulo division (`%`) is a CPU division instruction — one of the slowest arithmetic operations (20–90 cycles on modern CPUs). Bitmask AND (`&`) is a single fast instruction (1 cycle). They give the same result **only when capacity is a power of two**: `x % (2^n) == x & (2^n - 1)`. So if capacity is 1024 = 2^10, mask = 1023 = `0b1111111111`. `writeIdx & 1023` gives the low 10 bits of writeIdx — exactly `writeIdx mod 1024`. Requiring capacity to be a power of two is a documented constraint (`// capacity must be a power of two`) in exchange for this performance benefit.

---

**Q (medium): How does the `FiveTuple` normalization in `flows.go` work? Why is it necessary?**

A: A TCP conversation has two directions: A→B and B→A. Packets in both directions belong to the same flow. Without normalization, the map would have two separate entries for the same connection. Normalization: always put the lexicographically smaller IP first. If `srcIP < dstIP`, keep order. If `srcIP > dstIP`, swap src and dst. If equal (unusual — same IP talking to itself), use port comparison. This ensures both directions produce the same `FiveTuple` key and map to the same `*FlowStats` entry.

---

**Q (hard): The `TopTalkers` sorts the full map on every `GetSnapshot` call (once per second). What is the time complexity? When would this be a problem?**

A: Sorting N entries is O(N log N). If there are 10,000 distinct source IPs, each 1-Hz display refresh triggers a sort of 10,000 entries — roughly 133,000 comparisons. On a modern CPU doing ~10^9 simple operations/second, this is ~0.013 ms — negligible. It would become a problem if: the number of unique IPs is millions (internet-scale router), or the display refreshes at very high frequency. A heap-based top-N structure would give O(log N) per packet update and O(N) to return top N, which is better when the update rate (millions per second) >> display rate (1 Hz) and N is small. The current design is simple and correct for the project's scale.

---

**Q (hard): What is the `sync.Pool` `New` function for? What happens if you don't provide it?**

A: The `New` function is called when `Pool.Get()` finds no available object in the pool. It must return a ready-to-use object. If `New` is nil and the pool is empty, `Get()` returns `nil` — the caller must handle this. In this project, `New: func() any { return &models.PacketInfo{} }` ensures `Get()` always returns a non-nil pointer. Providing `New` is almost always the right choice, because an empty pool on first use (before any objects are returned) or after a GC drain would cause a nil dereference if `New` is absent.

---

## 8. Project Design & Trade-offs

**Q: Why use `AF_PACKET` directly instead of a library like `gopacket`?**

A: Three reasons. First, educational — this project exists to demonstrate understanding of the underlying protocols; using `gopacket` would hide the binary parsing logic. Second, performance — `gopacket` uses `libpcap` which adds a C FFI boundary and abstractions that carry overhead; direct `AF_PACKET` with zero-copy potential is faster. Third, binary size — `gopacket` links libpcap (a C library), requiring CGO and producing a dynamically-linked binary; direct `AF_PACKET` allows `CGO_ENABLED=0` and a fully static binary, suitable for Alpine-based Docker images.

---

**Q: Why use a buffered channel (4096) instead of the ring buffer for the main pipeline?**

A: Go channels provide three things the ring buffer does not: (1) **Clean shutdown** — closing a channel broadcasts to all `range` receivers, enabling the clean drain-and-exit pattern. (2) **Backpressure** — if the parse worker is slow, the channel filling up is observable and counted. (3) **Simplicity** — channels are idiomatic Go; no custom implementation to maintain or debug. The ring buffer is a building block demonstrating zero-alloc performance characteristics; for the main pipeline the semantic benefits of channels outweigh the tiny performance difference at this throughput level.

---

**Q: Why use a single mutex in `Statistics` instead of atomic operations for each field?**

A: Multiple fields must be updated as a consistent group. For example, `Record()` updates `totalPackets`, `totalBytes`, `intervalBytes`, and the `protocols` map in one logical operation. If each field were an atomic `Uint64`, `GetSnapshot()` reading all of them would see a partially-updated state between two atomic operations — e.g. `totalPackets` reflects packet N+1 but `totalBytes` still reflects only packet N. The mutex serializes the entire update as a unit. Since the lock is held for microseconds and contended by at most two goroutines (parse worker and display ticker), mutex overhead is negligible.

---

**Q: Your flow map deletes `CLOSED` flows immediately. What could go wrong? How would you handle it in production?**

A: In a real network, TCP connections can have delayed packets that arrive after the FIN+ACK exchange — a condition called TIME_WAIT. If a new connection uses the same five-tuple (unlikely but possible after rapid reconnects), late packets from the old connection could be misattributed to the new one. Production systems handle this with: (1) a TIME_WAIT state where the flow entry is retained for 2×MSL (Maximum Segment Lifetime, typically 60 seconds) before deletion; (2) using TCP timestamps as a tiebreaker to distinguish old from new connections. For a monitoring tool that only counts, the simplification of immediate deletion is acceptable — a missed packet or two per connection closure is tolerable.

---

**Q: How would you extend this to support IPv6?**

A: Four changes: (1) In `ethernet.go`, detect `EtherType == 0x86DD` and route to an IPv6 parser. (2) Write `ipv6.go` — IPv6 has a fixed 40-byte header (no IHL; uses `PayloadLen` and `NextHeader` instead of `Protocol`). (3) IPv6 addresses are 16 bytes not 4; update `PacketInfo.SrcIP/DstIP` to use `net.IP` (which already supports both 4-byte and 16-byte forms). (4) IPv6 uses extension headers (Hop-by-Hop, Routing, Fragment, etc.) — `NextHeader` can chain these; the parser must walk the chain to find the transport protocol. The BPF filter compiler would need IPv6-specific offsets.

---

**Q: The PCAP writer uses a 1 MB `bufio.Writer`. What happens if the process crashes before `Close()` is called?**

A: The buffered data in memory is lost. The last up-to-1-MB of captured packets would not be written to the file, leaving it with a truncated last packet (which Wireshark handles gracefully — it reads as many complete packet records as possible). Mitigation strategies: (1) Call `buf.Flush()` periodically (e.g. every 10,000 packets or every second) not just at close. (2) Use `O_SYNC` / `fdatasync()` after each write for durability at the cost of performance. (3) Handle `SIGKILL` — impossible; `SIGKILL` cannot be caught. For a monitoring tool the current approach is acceptable; for production packet archival, periodic flushing is recommended.

---

**Q: How does the display's "clear screen + redraw" approach compare to a real TUI library like `bubbletea`?**

A: The current approach (`\033[H\033[2J` + full redraw) is simple — no dependencies, 20 lines of code — but has limitations: it flickers briefly on slow terminals; it cannot handle terminal resize gracefully; it overwrites any other terminal output. A TUI library like `bubbletea` uses differential rendering (only redraws changed cells), handles resize events via `SIGWINCH`, and provides components (tables, progress bars, inputs). The trade-off: current approach requires zero dependencies and is trivially testable (pure string functions); `bubbletea` gives a polished experience at the cost of a dependency and more complex architecture. For a production monitoring tool I would use a TUI library; for a learning project, the simple approach demonstrates the core technique.

---

## 9. Behavioral / "Walk Me Through" Questions

**Q: Walk me through what happens from the moment I press Ctrl+C to the moment the program exits.**

A: (Reference section 7.Go Concurrency Q5 and the shutdown sequence). Five steps: signal caught, `done` channel closed, socket closed (unblocks `Recvfrom`), channels drained, `wg.Wait()` returns, cleanup runs.

---

**Q: Suppose you are at a company running this tool and packet loss spikes to 5%. Walk me through how you would debug it.**

A: 1. Check the "Dropped" counter in the dashboard — is it the capture goroutine's non-blocking send dropping frames (channel full), or actual kernel drops (socket receive buffer overflow)? 2. If the channel is full: the parse worker is the bottleneck. Profile with pprof to find the slow function — likely string conversion (`net.IP.String()`) or HTTP parsing. Consider disabling HTTP parsing with a flag. 3. If the kernel socket buffer is overflowing: increase it via `setsockopt(SO_RCVBUF)`. 4. Check CPU: is the parse worker pinned at 100%? Consider parallelizing: run N parse workers, each reading from a partitioned channel or separate sockets. 5. Check if BPF filtering is enabled — if capturing all traffic, add a filter to reduce volume. 6. If on a VM: check for CPU steal time.

---

**Q: How did you test this project? What would you do differently for a production-grade version?**

A: Current testing: unit tests for each parser with hardcoded packet bytes, benchmark tests for performance regression, `go test -race` for data races, manual integration tests with `iperf3` and `curl`. For production: (1) Fuzzing (`go test -fuzz`) — random malformed packets to find panics or incorrect parsing. (2) Integration tests against a network emulator (e.g. `mininet`) generating specific traffic patterns. (3) Chaos testing — kill the process mid-capture, verify PCAP files are parseable. (4) Long-running stability tests (48 hours capturing 1 Gbps). (5) Static analysis (`golangci-lint` with additional linters like `govet`, `errcheck`).

---

**Q: Why did you choose Go for this project instead of C or Rust?**

A: C was the natural choice for a network tool (libpcap, tcpdump are in C), but Go offered: (1) Goroutines and channels making the concurrent pipeline architecture clean and safe. (2) Garbage collection removing entire classes of memory bugs (use-after-free, buffer overflow) — important when parsing untrusted packet data. (3) The `encoding/binary` and `net` packages make protocol parsing ergonomic. (4) Cross-compilation to a static binary is trivial. (5) Profiling and race detection built into the toolchain. Rust would give similar performance with even stronger memory safety guarantees but has a steeper learning curve and less mature ecosystem for this use case. For a demonstration project, Go's expressiveness and safety were the right trade-off.

---

**Q: What would you change if you had to support 100 Gbps instead of 1 Gbps?**

A: At 100 Gbps with 1500-byte frames: ~8.3 million pps. My current single parse worker at 2.9M pps is insufficient. Changes: (1) **TPACKET_V3** (mmap ring buffer): use `AF_PACKET` in memory-mapped mode — the kernel writes frames directly into a userspace-accessible ring buffer, eliminating the `recvfrom` copy entirely. (2) **Multiple parse workers**: partition frames by flow hash across N parse workers to preserve per-flow ordering while parallelizing. (3) **DPDK/eBPF**: bypass the kernel entirely for maximum throughput. (4) **CPU affinity**: pin each goroutine to a specific CPU core to avoid cache invalidation from CPU migrations. (5) **Huge pages**: allocate ring buffer on huge pages (2 MB) to reduce TLB misses.

---

**Q: A user reports that your tool shows their connection as "ESTABLISHED" but the application says the connection is closed. What could cause this?**

A: Several possibilities: (1) **Lost packets**: the FIN or RST was captured before the BPF filter was applied, or the packets were dropped. The flow stays in ESTABLISHED state indefinitely. (2) **Half-close**: TCP supports half-duplex FIN — one side sends FIN (CLOSING) but the other side continues sending data (ESTABLISHED). The flow tracker sees the FIN and transitions to CLOSING but the ESTABLISHED party still has data in flight. (3) **Application-level close**: the application closed its socket but the OS sent RST, which the sniffer missed due to a packet drop. (4) **Map cleanup bug**: `CLOSED` flows are deleted immediately, but if the RST is parsed after the FIN, the state machine might not transition correctly. Fix: add a timeout — flows not seen for 60 seconds are evicted regardless of state.

---

## 10. Curveball / Edge-Case Questions

**Q: What happens if you run the sniffer on the loopback interface (`lo`)?**

A: Loopback (`lo`) has an MTU of 65536 bytes and connects the machine to itself. AF_PACKET on loopback captures packets sent between processes on the same machine — `curl localhost`, database connections, inter-service traffic. Unlike a physical NIC, loopback never drops packets (it's pure software). The tool works correctly on `lo`; it is actually the easiest interface to generate test traffic on (`iperf3 -c 127.0.0.1`). One quirk: loopback frames may have a Linux-specific `LINKTYPE_LOOPBACK` (value 0) header instead of the standard Ethernet header (LINKTYPE_ETHERNET = 1), depending on how AF_PACKET presents them.

---

**Q: What does the tool show for TLS/HTTPS traffic?**

A: For HTTPS (TCP port 443), the tool correctly parses: Ethernet header (MACs), IPv4 header (IPs, TTL), TCP header (ports, flags, sequence numbers), and TCP flow state. What it cannot see: the application data is TLS-encrypted ciphertext. `ParseHTTP` returns nil because the TCP payload does not start with a plaintext HTTP method. The stats show TCP packets counted correctly, bandwidth tracked, and the flow tracked — everything except the HTTP layer content. To decode HTTPS you would need the TLS session keys, which is what Wireshark's "TLS decryption with keylog file" feature does.

---

**Q: What happens if a single packet is split across multiple `Recvfrom` calls?**

A: With `AF_PACKET / SOCK_RAW`, this cannot happen. Unlike TCP byte streams, `AF_PACKET` delivers one **complete Ethernet frame per `Recvfrom` call** — always a full frame, never partial. The kernel buffers a complete frame in its socket receive queue and delivers it atomically. This is one reason raw packet parsing is simpler than stream parsing: frame boundaries are preserved.

---

**Q: What is NIC offloading and how could it affect checksums in your tool?**

A: Modern NICs offload compute-heavy operations from the CPU: checksum computation (TX offload: NIC computes checksum just before transmitting, so the outgoing packet in the kernel buffer has `0x0000` checksum), Large Segment Offload (LSO: kernel sends a 64 KB "super-segment" to the NIC which splits it into 1500-byte frames — the sniffer may see frames larger than the MTU), and Receive-Side Scaling (RSS: NIC distributes incoming packets across multiple CPU cores). For this tool: (1) You may see invalid checksums on outgoing packets captured locally (NIC hasn't computed them yet). (2) LSO can produce "giant" frames on loopback. Both are known behaviors when sniffing locally; capturing on a remote mirror port sees correctly-formed frames after NIC processing.

---

**Q: Your `ParseHTTP` uses `http.ReadRequest` from the standard library. Could this be a security issue?**

A: `http.ReadRequest` parses untrusted network data — it could be called on a carefully crafted malicious packet. Go's standard library HTTP parser has been hardened against common attacks (header injection, excessively large headers). However: (1) Very large HTTP headers in a single packet could cause large allocations. (2) The parser is not bounded on input size. For a production tool, adding a size limit (`if len(payload) > maxHTTPSize { return nil }`) before calling `http.ReadRequest` would prevent potential resource exhaustion. Also, `http.ReadResponse` and `http.ReadRequest` may allocate goroutines internally for certain parse paths in some versions — worth verifying with heap profiles.

---

**Q: If two different source IPs both send packets to the same destination port, how does the statistics map handle them?**

A: The `protocols` map is keyed by protocol string (`"TCP"`, `"UDP"`, etc.) — not by IP or port. Both IPs contribute to the same `protocols["TCP"]` counter. The `topTalkers` map is keyed by source IP (`counts[srcIP] += bytes`), so the two IPs are tracked separately in TopTalkers. The `FlowTracker` uses the full five-tuple as the key, so `(IP-A, IP-C, portX, portY, TCP)` and `(IP-B, IP-C, portX, portY, TCP)` are two separate flow entries (assuming different source IPs). All three data structures handle multiple concurrent senders correctly.

---

**Q: The ring buffer's `Enqueue` checks `writeIdx - readIdx > rb.mask` for fullness. Explain why this works even after the indices wrap around.**

A: The write and read indices are `atomic.Uint64` — they monotonically increase and **never reset** (they "overflow" after 2^64 operations, which would take thousands of years at 3M pps). The difference `writeIdx - readIdx` is always the current occupancy, regardless of wrapping, because unsigned arithmetic wraps modulo 2^64 consistently. Example with 8-slot buffer (mask=7): write=12, read=5 → occupancy=7=full. After write wraps at 256: write=4 (as uint8 for illustration), read=253 → `4 - 253 = 7` in modular arithmetic — still correctly 7. This is the standard lock-free ring buffer trick: use full-width indices for arithmetic, use bitmask only for slot indexing.

---

**Q: How would you add support for DNS (UDP port 53) packet parsing?**

A: DNS query/response format: a 12-byte header (transaction ID, flags, question count, answer count, authority count, additional count) followed by variable-length question and resource record sections with domain names in wire format (labels length-prefixed, `\x00` terminated). Implementation: in `parser/`, add `dns.go` with `ParseDNS(payload []byte) *models.DNSInfo`. In `decoder.go`, after parsing UDP: if `udp.DstPort == 53 || udp.SrcPort == 53`, call `ParseDNS(udp.Payload)`. In `models/packet.go`, add `DNS *DNSInfo` to `PacketInfo`. In `stats.go`, track top queried domains. The trickiest part is domain name decompression — DNS uses pointer compression where labels can point backward to previous occurrences in the packet to save space.

---

*End of interview questions. Practice answering each question aloud — the numbers (335 ns, 22%, 31%, 2.9M pps, 35×) should come naturally because you understand the math behind them.*
