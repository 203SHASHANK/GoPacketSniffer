# **Network Packet Analyzer - Complete Implementation Plan**

```markdown
# GoPacketSniffer - Network Packet Analyzer
## Production-Grade Packet Capture & Protocol Analysis Tool

---

## PROJECT METADATA

**Project Name**: GoPacketSniffer
**Language**: Go 1.21+
**Type**: Systems Programming / Network Analysis
**Complexity**: Advanced
**Timeline**: 3-4 weeks (part-time)
**Resume Impact**: ⭐⭐⭐⭐⭐ (Highest - Shows systems expertise)

**Core Value Proposition**: 
Lightweight, high-performance packet analyzer that captures and decodes network traffic at wire speed, providing real-time protocol statistics and traffic analysis without GUI overhead.

---

## TABLE OF CONTENTS

1. [Project Overview](#1-project-overview)
2. [Learning Objectives](#2-learning-objectives)
3. [Technical Architecture](#3-technical-architecture)
4. [Implementation Phases](#4-implementation-phases)
5. [Code Quality Standards](#5-code-quality-standards)
6. [Testing Strategy](#6-testing-strategy)
7. [CLI Output Specification](#7-cli-output-specification)
8. [Deployment & Dockerization](#8-deployment--dockerization)
9. [Benchmarking Requirements](#9-benchmarking-requirements)
10. [Documentation Requirements](#10-documentation-requirements)
11. [Progress Tracking](#11-progress-tracking)
12. [Success Criteria](#12-success-criteria)

---

## 1. PROJECT OVERVIEW

### 1.1 What You're Building

A command-line network packet analyzer that:
- Captures live network traffic from network interfaces
- Decodes packets layer-by-layer (Ethernet → IP → TCP/UDP → Application)
- Displays real-time statistics (protocol distribution, bandwidth, top talkers)
- Supports BPF-style filtering ("tcp port 80", "host 192.168.1.1")
- Processes traffic at 1+ Gbps without packet loss
- Exports captured data to PCAP format for Wireshark compatibility

### 1.2 Why This Project

**Technical Depth**: 
- Raw socket programming (kernel-level interaction)
- Binary protocol parsing (bit manipulation, RFC compliance)
- High-performance I/O (zero-copy, ring buffers)
- Concurrent processing (goroutines for capture + analysis)

**Career Impact**:
- Demonstrates systems programming beyond web APIs
- Shows debugging capabilities at network layer
- Proves low-level optimization skills
- Rare expertise (most backend devs never touch raw packets)

**Interview Leverage**:
- "Walk me through TCP handshake" → Show actual SYN/ACK/FIN packets
- "How would you debug network latency?" → Explain packet capture approach
- "Explain goroutines" → Describe your concurrent packet processing

---

## 2. LEARNING OBJECTIVES

By completing this project, you will master:

### 2.1 Core Concepts

**Network Fundamentals**:
- OSI model layers (practical, not theoretical)
- Ethernet frame structure (MAC addresses, EtherType)
- IPv4/IPv6 packet format (headers, fragmentation)
- TCP protocol internals (flags, sequence numbers, window size)
- UDP datagram structure

**Systems Programming**:
- Raw socket creation (`AF_PACKET` on Linux, `BPF` on BSD)
- Kernel interaction (syscalls, ioctl)
- Memory-mapped I/O (mmap for zero-copy)
- Signal handling (graceful shutdown)

**Go-Specific Skills**:
- unsafe package (pointer arithmetic for packet parsing)
- encoding/binary (network byte order)
- sync package (concurrent packet queue)
- context package (cancellation propagation)
- pprof profiling (CPU/memory optimization)

### 2.2 Advanced Techniques

**Performance Optimization**:
- Lock-free data structures (ring buffer)
- Batch processing (process N packets at once)
- CPU affinity (pin goroutines to cores)
- Memory pooling (reduce GC pressure)

**Protocol Analysis**:
- Checksum validation (IP, TCP, UDP)
- Sequence number tracking (detect retransmissions)
- Flow reconstruction (track TCP connections)
- Application-layer parsing (HTTP, DNS decoding)

---

## 3. TECHNICAL ARCHITECTURE

### 3.1 System Design

```
┌─────────────────────────────────────────────────────────┐
│                  GoPacketSniffer Architecture            │
└─────────────────────────────────────────────────────────┘

┌──────────────┐
│ Network Card │ (Physical layer - Ethernet frames)
└──────┬───────┘
       │
       ▼
┌──────────────────────────────────────────┐
│  Kernel Network Stack                    │
│  - AF_PACKET socket (raw access)         │
│  - BPF filter (pre-filter in kernel)     │
└──────────────┬───────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────┐
│  Capture Layer (capture.go)              │
│  - Read packets from raw socket          │
│  - Zero-copy ring buffer                 │
│  - Goroutine: captureWorker()            │
└──────────────┬───────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────┐
│  Packet Queue (lockfree ring buffer)     │
│  - Circular buffer (1M packets)          │
│  - Atomic read/write pointers            │
└──────────────┬───────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────┐
│  Parser Layer (parser/)                  │
│  - Goroutines: parseWorker() × NumCPU    │
│  - Decode: Ethernet → IP → TCP/UDP       │
│  - Extract metadata (5-tuple, flags)     │
└──────────────┬───────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────┐
│  Statistics Engine (stats.go)            │
│  - Protocol counters (map[Protocol]int)  │
│  - Bandwidth tracking (bytes/sec)        │
│  - Top talkers (IP → bytes sent)         │
└──────────────┬───────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────┐
│  Display Layer (display.go)              │
│  - Goroutine: displayWorker()            │
│  - Terminal UI refresh (every 1 sec)     │
│  - ANSI color codes                      │
└──────────────────────────────────────────┘

Optional:
┌──────────────────────────────────────────┐
│  PCAP Writer (pcap.go)                   │
│  - Save packets to .pcap file            │
│  - Wireshark-compatible format           │
└──────────────────────────────────────────┘
```

### 3.2 Data Flow

```
1. Raw Packet Arrives ([]byte - Ethernet frame)
   └─> captureWorker() reads from socket
   
2. Enqueue to Ring Buffer
   └─> Atomic write, no locks
   
3. parseWorker() Dequeues
   └─> Parse Ethernet header (14 bytes)
       ├─> If EtherType = 0x0800 (IPv4)
       │   └─> Parse IP header (20+ bytes)
       │       ├─> If Protocol = 6 (TCP)
       │       │   └─> Parse TCP header (20+ bytes)
       │       │       └─> Extract: srcIP, dstIP, srcPort, dstPort, flags
       │       └─> If Protocol = 17 (UDP)
       │           └─> Parse UDP header (8 bytes)
       └─> If EtherType = 0x0806 (ARP)
           └─> Parse ARP packet
   
4. Update Statistics
   └─> Atomic increment counters
   
5. Display (every 1 second)
   └─> Read stats, format, print to terminal
```

### 3.3 Directory Structure

```
gopacketsniffer/
│
├── cmd/
│   └── gopacketsniffer/
│       └── main.go                 # Entry point, CLI flags, orchestration
│
├── internal/
│   ├── capture/
│   │   ├── capture.go              # Raw socket creation, packet capture loop
│   │   ├── ringbuffer.go           # Lock-free ring buffer implementation
│   │   └── bpf.go                  # BPF filter compilation (optional)
│   │
│   ├── parser/
│   │   ├── ethernet.go             # Ethernet frame parser
│   │   ├── ipv4.go                 # IPv4 packet parser
│   │   ├── tcp.go                  # TCP segment parser
│   │   ├── udp.go                  # UDP datagram parser
│   │   ├── icmp.go                 # ICMP packet parser
│   │   └── http.go                 # HTTP request/response parser (optional)
│   │
│   ├── stats/
│   │   ├── stats.go                # Statistics aggregation
│   │   ├── counters.go             # Thread-safe counters
│   │   └── toptalkers.go           # Top N IPs by traffic
│   │
│   ├── display/
│   │   ├── terminal.go             # Terminal output formatting
│   │   └── colors.go               # ANSI color codes
│   │
│   ├── pcap/
│   │   └── writer.go               # PCAP file writer (Wireshark compat)
│   │
│   └── models/
│       └── packet.go               # Packet metadata structs
│
├── pkg/
│   └── utils/
│       ├── checksum.go             # IP/TCP/UDP checksum validation
│       └── conversion.go           # Byte order conversions
│
├── test/
│   ├── testdata/
│   │   └── sample.pcap             # Test PCAP file
│   ├── parser_test.go              # Unit tests for parsers
│   └── benchmark_test.go           # Performance benchmarks
│
├── scripts/
│   ├── setup.sh                    # Install dependencies
│   └── test_traffic.sh             # Generate test traffic (curl, ping)
│
├── Dockerfile                      # Container image
├── docker-compose.yml              # Multi-container setup (sniffer + traffic gen)
├── Makefile                        # Build automation
├── go.mod
├── go.sum
├── .gitignore
└── README.md
```

---

## 4. IMPLEMENTATION PHASES

### PHASE 1: Foundation & Raw Capture (Days 1-4)

#### Objective
Capture raw Ethernet frames from network interface and print hex dump.

#### Tasks

**Day 1: Project Setup**
- [ ] Initialize Go module: `go mod init gopacketsniffer`
- [ ] Create directory structure (see 3.3)
- [ ] Setup Makefile with `build`, `run`, `test`, `clean` targets
- [ ] Create .gitignore (bin/, *.pcap, vendor/)
- [ ] Write initial README.md (project overview, usage)

**Day 2: Raw Socket Capture**
- [ ] Implement `internal/capture/capture.go`:
  - [ ] `OpenRawSocket(interfaceName string) (int, error)` - Creates AF_PACKET socket
  - [ ] `SetPromiscuousMode(fd int) error` - Enable promiscuous mode
  - [ ] `CaptureLoop(fd int, packetChan chan<- []byte)` - Read packets in loop
- [ ] Handle errors: permission denied (needs root), interface not found
- [ ] Test: Capture 100 packets, print first 64 bytes in hex

**Day 3: Ring Buffer**
- [ ] Implement `internal/capture/ringbuffer.go`:
  - [ ] `type RingBuffer struct` with atomic read/write pointers
  - [ ] `Enqueue(packet []byte) bool` - Lock-free write
  - [ ] `Dequeue() ([]byte, bool)` - Lock-free read
  - [ ] Handle wrap-around, full buffer (drop or block)
- [ ] Test: Benchmark 1M enqueue/dequeue operations

**Day 4: Integration & Basic CLI**
- [ ] Implement `cmd/gopacketsniffer/main.go`:
  - [ ] Parse CLI flags: `-i <interface>` (e.g., eth0, wlan0)
  - [ ] Launch captureWorker goroutine
  - [ ] Launch parseWorker goroutine (placeholder - just prints packet count)
  - [ ] Graceful shutdown on Ctrl+C (signal.Notify, context.Cancel)
- [ ] Test: `sudo go run cmd/gopacketsniffer/main.go -i eth0` captures packets

**Deliverable**: Program that captures raw packets and prints "Captured 1234 packets" every second.

---

### PHASE 2: Protocol Parsing (Days 5-10)

#### Objective
Decode Ethernet, IP, TCP, UDP headers and extract metadata.

#### Tasks

**Day 5: Ethernet Parser**
- [ ] Implement `internal/parser/ethernet.go`:
  - [ ] `type EthernetFrame struct` (DstMAC, SrcMAC, EtherType)
  - [ ] `ParseEthernet(data []byte) (*EthernetFrame, error)`
  - [ ] Validate: Minimum 14 bytes, extract MAC addresses (6 bytes each)
  - [ ] Determine next layer: 0x0800 = IPv4, 0x86DD = IPv6, 0x0806 = ARP
- [ ] Write unit test with sample Ethernet frame bytes
- [ ] Document: Comment format: "// EtherType: 2 bytes at offset 12-13, network byte order"

**Day 6: IPv4 Parser**
- [ ] Implement `internal/parser/ipv4.go`:
  - [ ] `type IPv4Packet struct` (Version, HeaderLen, Protocol, SrcIP, DstIP, TTL, Checksum)
  - [ ] `ParseIPv4(data []byte) (*IPv4Packet, error)`
  - [ ] Extract: Version (4 bits), IHL (4 bits), Protocol (1 byte), addresses (4 bytes each)
  - [ ] Validate: Version == 4, HeaderLen >= 5, checksum correct
  - [ ] Handle: IP options (if IHL > 5), fragmentation flags
- [ ] Implement `pkg/utils/checksum.go` - IP header checksum validation
- [ ] Test: Parse sample IPv4 packet, verify fields

**Day 7: TCP Parser**
- [ ] Implement `internal/parser/tcp.go`:
  - [ ] `type TCPSegment struct` (SrcPort, DstPort, SeqNum, AckNum, Flags, WindowSize)
  - [ ] `ParseTCP(data []byte) (*TCPSegment, error)`
  - [ ] Extract: Ports (2 bytes each), sequence (4 bytes), flags (1 byte - SYN/ACK/FIN/RST)
  - [ ] Calculate: Header length from data offset field (4 bits)
  - [ ] Validate: Checksum (pseudo-header + TCP header + data)
- [ ] Implement TCP checksum in `pkg/utils/checksum.go`
- [ ] Test: Parse TCP handshake (SYN, SYN-ACK, ACK)

**Day 8: UDP Parser**
- [ ] Implement `internal/parser/udp.go`:
  - [ ] `type UDPDatagram struct` (SrcPort, DstPort, Length, Checksum)
  - [ ] `ParseUDP(data []byte) (*UDPDatagram, error)`
  - [ ] Extract: Ports (2 bytes each), length (2 bytes)
  - [ ] Validate: Length matches actual data, checksum (optional in IPv4)
- [ ] Test: Parse DNS query (UDP port 53)

**Day 9: Integration - Full Packet Decode**
- [ ] Implement `internal/parser/decoder.go`:
  - [ ] `DecodePacket(raw []byte) (*PacketInfo, error)` - Orchestrates all parsers
  - [ ] Chain: Ethernet → IP → TCP/UDP
  - [ ] Return: `PacketInfo` struct with all extracted fields
- [ ] Update parseWorker in main.go to use DecodePacket
- [ ] Test: Capture traffic, verify decoded fields match Wireshark

**Day 10: ICMP Parser (Bonus)**
- [ ] Implement `internal/parser/icmp.go`:
  - [ ] `type ICMPPacket struct` (Type, Code, Checksum, Data)
  - [ ] `ParseICMP(data []byte) (*ICMPPacket, error)`
  - [ ] Handle: Echo request/reply (ping), Time exceeded, Dest unreachable
- [ ] Test: `ping google.com`, capture ICMP packets

**Deliverable**: Program decodes packets and prints: "TCP 192.168.1.5:443 → 172.217.164.46:80 [SYN]"

---

### PHASE 3: Statistics & Display (Days 11-15)

#### Objective
Aggregate packet statistics and display real-time metrics in terminal.

#### Tasks

**Day 11: Statistics Engine**
- [ ] Implement `internal/stats/stats.go`:
  - [ ] `type Statistics struct` with sync.Mutex for thread-safety
  - [ ] Counters: TotalPackets, TotalBytes, map[Protocol]uint64
  - [ ] Methods: `IncrementProtocol(proto string, bytes int)`
  - [ ] Methods: `GetSnapshot() StatsSnapshot` - Returns copy for display
- [ ] Implement `internal/stats/toptalkers.go`:
  - [ ] Track: map[IP]uint64 (bytes sent per IP)
  - [ ] Method: `GetTopN(n int) []TopTalker` - Returns top N IPs sorted by bytes
- [ ] Test: Concurrent increments from 10 goroutines

**Day 12: Terminal Display - Basic**
- [ ] Implement `internal/display/terminal.go`:
  - [ ] `ClearScreen()` - ANSI escape code to clear terminal
  - [ ] `PrintStats(stats StatsSnapshot)` - Format and print statistics
  - [ ] Layout:
    ```
    ============================================
    GoPacketSniffer - Live Network Capture
    ============================================
    Captured: 45,234 packets | 23.5 MB
    Elapsed: 00:02:15
    
    Protocol Distribution:
      TCP   : 32,156 packets (71.0%) | 18.2 MB
      UDP   :  8,945 packets (19.8%) |  3.8 MB
      ICMP  :  4,133 packets  (9.1%) |  1.5 MB
    
    Top Talkers (by bytes sent):
      1. 192.168.1.100  →  8.2 MB
      2. 172.217.164.46 →  5.1 MB
      3. 10.0.0.5       →  2.3 MB
    ```
- [ ] Test: Mock stats, verify output formatting

**Day 13: Terminal Display - Colors**
- [ ] Implement `internal/display/colors.go`:
  - [ ] Define: ColorRed, ColorGreen, ColorYellow, ColorBlue, ColorReset
  - [ ] Function: `Colorize(text, color string) string`
- [ ] Update PrintStats to use colors:
  - [ ] Protocol names in blue
  - [ ] High traffic (>1GB) in red, medium in yellow, low in green
  - [ ] Top talker #1 in bold
- [ ] Test: Verify ANSI codes render correctly in terminal

**Day 14: Real-Time Updates**
- [ ] Add displayWorker goroutine in main.go:
  - [ ] Ticker: Every 1 second, get stats snapshot and print
  - [ ] Clear screen before each update (creates "live" effect)
- [ ] Add bandwidth calculation:
  - [ ] Track: bytes captured in last second
  - [ ] Display: "Current: 2.3 MB/s | Average: 1.8 MB/s"
- [ ] Test: Run sniffer, verify screen updates every second

**Day 15: Packet Details Mode**
- [ ] Add CLI flag: `-v` (verbose) to print each packet
- [ ] Implement: `PrintPacketDetails(packet PacketInfo)`
  - [ ] Format: "14:35:22.123456 TCP 192.168.1.5:443 → 8.8.8.8:53 Len=64 [SYN]"
  - [ ] Include: Timestamp, protocol, IPs, ports, length, flags
- [ ] Rate limit: Max 100 packets/sec to avoid terminal spam
- [ ] Test: `sudo go run . -i eth0 -v` shows packet stream

**Deliverable**: Live terminal display updating every second with colorized statistics.

---

### PHASE 4: Advanced Features (Days 16-21)

#### Objective
Add filtering, PCAP export, HTTP parsing, and performance optimization.

#### Tasks

**Day 16: BPF Filtering**
- [ ] Implement `internal/capture/bpf.go`:
  - [ ] Parse filter string: "tcp port 80", "host 192.168.1.1"
  - [ ] Compile to BPF bytecode (use `golang.org/x/net/bpf` package)
  - [ ] Attach filter to raw socket (`SO_ATTACH_FILTER`)
- [ ] Add CLI flag: `-f "tcp port 443"` to apply filter
- [ ] Benefit: Kernel filters packets before userspace (faster)
- [ ] Test: Filter "icmp", run ping, verify only ICMP captured

**Day 17: PCAP Writer**
- [ ] Implement `internal/pcap/writer.go`:
  - [ ] `type PCAPWriter struct` with file handle
  - [ ] `WriteHeader()` - PCAP file header (magic, version, snaplen)
  - [ ] `WritePacket(timestamp time.Time, data []byte)` - Packet record
  - [ ] Format: https://wiki.wireshark.org/Development/LibpcapFileFormat
- [ ] Add CLI flag: `-w capture.pcap` to save packets
- [ ] Test: Capture traffic, save to .pcap, open in Wireshark

**Day 18: HTTP Parser (Application Layer)**
- [ ] Implement `internal/parser/http.go`:
  - [ ] Detect: TCP payload starting with "GET ", "POST ", "HTTP/1.1"
  - [ ] Extract: Method, URL, Host header, Status code
  - [ ] `type HTTPRequest struct` and `type HTTPResponse struct`
- [ ] Update stats to track: HTTP requests, status codes (200, 404, 500)
- [ ] Display: "HTTP Requests: 234 | 2xx: 180, 4xx: 45, 5xx: 9"
- [ ] Test: `curl http://example.com`, verify HTTP parsed

**Day 19: Performance Optimization**
- [ ] Profile with pprof:
  - [ ] Add: `import _ "net/http/pprof"` and `http.ListenAndServe(":6060", nil)`
  - [ ] Run: `go tool pprof http://localhost:6060/debug/pprof/profile?seconds=30`
  - [ ] Identify: Hot paths (likely in parsing loops)
- [ ] Optimizations:
  - [ ] Pre-allocate packet buffer slices
  - [ ] Use sync.Pool for temporary objects
  - [ ] Batch parse: Process 100 packets at once
  - [ ] Reduce allocations: Reuse PacketInfo structs
- [ ] Benchmark: Before/after optimization (packets/sec, memory)

**Day 20: Zero-Copy with mmap**
- [ ] Research: Memory-mapped ring buffer (AF_PACKET TPACKET_V3)
  - [ ] Reference: https://www.kernel.org/doc/Documentation/networking/packet_mmap.txt
- [ ] Implement: Optional `-zerocopy` flag
  - [ ] Use syscall.Mmap to create shared memory with kernel
  - [ ] Read packets directly from mmap buffer (no copy)
- [ ] Benchmark: Compare with standard read() - expect 2x speedup
- [ ] Note: Linux-specific, falls back to read() on other OS

**Day 21: Flow Tracking**
- [ ] Implement `internal/stats/flows.go`:
  - [ ] Track TCP connections: map[FiveTuple]*FlowStats
  - [ ] FiveTuple: {SrcIP, DstIP, SrcPort, DstPort, Protocol}
  - [ ] FlowStats: Packets, Bytes, StartTime, LastSeen
  - [ ] Detect: New connections (SYN), closed (FIN/RST)
- [ ] Display: "Active TCP Flows: 42 | Avg lifetime: 12s"
- [ ] Test: Open browser, verify flows created/destroyed

**Deliverable**: Full-featured packet analyzer with filtering, export, HTTP parsing, optimized for 1+ Gbps.

---

### PHASE 5: Polish & Production Ready (Days 22-28)

#### Objective
Documentation, testing, Docker, benchmarking, and final touches.

#### Tasks

**Day 22: Unit Tests**
- [ ] Test coverage target: 80%+
- [ ] Write tests for:
  - [ ] Each parser (ethernet, ip, tcp, udp, icmp, http)
  - [ ] Statistics (concurrent increments)
  - [ ] Ring buffer (edge cases: full, empty, wrap-around)
  - [ ] Checksum validation (known good/bad packets)
- [ ] Use table-driven tests:
  ```go
  tests := []struct {
    name string
    input []byte
    want *IPv4Packet
    wantErr bool
  }{
    {"valid packet", validIPv4Bytes, &expectedPacket, false},
    {"too short", shortBytes, nil, true},
  }
  ```
- [ ] Run: `go test -v -cover ./...`

**Day 23: Benchmark Tests**
- [ ] Create `test/benchmark_test.go`:
  - [ ] `BenchmarkParseEthernet` - Parse 1M Ethernet frames
  - [ ] `BenchmarkParseIPv4` - Parse 1M IP packets
  - [ ] `BenchmarkParseTCP` - Parse 1M TCP segments
  - [ ] `BenchmarkRingBuffer` - Enqueue/dequeue 10M items
- [ ] Measure: ns/op, allocations/op, bytes/op
- [ ] Target: <100 ns/op for each parser
- [ ] Run: `go test -bench=. -benchmem ./test`

**Day 24: Documentation**
- [ ] Write comprehensive README.md:
  - [ ] Overview (what it does, why useful)
  - [ ] Features (protocol support, filtering, export)
  - [ ] Installation (build from source, Docker)
  - [ ] Usage (CLI flags, examples)
  - [ ] Architecture (high-level diagram)
  - [ ] Performance (benchmarks, throughput)
  - [ ] Contributing (code style, PR process)
- [ ] Add inline code comments:
  - [ ] Every exported function has godoc comment
  - [ ] Complex algorithms explained (e.g., ring buffer logic)
  - [ ] Link to RFCs where relevant (RFC 791 for IPv4)
- [ ] Create ARCHITECTURE.md (detailed design doc)
- [ ] Create BENCHMARKS.md (performance results)

**Day 25: Dockerization**
- [ ] Write `Dockerfile`:
  ```dockerfile
  FROM golang:1.21-alpine AS builder
  WORKDIR /build
  COPY go.mod go.sum ./
  RUN go mod download
  COPY . .
  RUN CGO_ENABLED=0 go build -o gopacketsniffer cmd/gopacketsniffer/main.go
  
  FROM alpine:latest
  RUN apk add --no-cache libpcap-dev
  COPY --from=builder /build/gopacketsniffer /usr/local/bin/
  ENTRYPOINT ["gopacketsniffer"]
  ```
- [ ] Write `docker-compose.yml`:
  ```yaml
  version: '3.8'
  services:
    sniffer:
      build: .
      network_mode: host
      cap_add:
        - NET_RAW
        - NET_ADMIN
      command: ["-i", "eth0", "-v"]
  ```
- [ ] Test: `docker-compose up` captures packets in container

**Day 26: CI/CD Setup**
- [ ] Create `.github/workflows/ci.yml`:
  - [ ] On push/PR: Run tests, linters
  - [ ] Jobs: `go test`, `golangci-lint`, `go build`
  - [ ] Upload coverage to codecov.io
- [ ] Add badges to README:
  - [ ] Build status
  - [ ] Test coverage
  - [ ] Go Report Card
  - [ ] License

**Day 27: Real-World Testing**
- [ ] Test scenarios:
  - [ ] Capture HTTP traffic: `curl http://example.com`
  - [ ] Capture HTTPS: Verify TCP handshake + encrypted payload
  - [ ] Capture DNS: `nslookup google.com`
  - [ ] High load: `iperf3 -c server` (generate 1 Gbps traffic)
  - [ ] Packet loss: Verify no drops at high rates
- [ ] Generate test traffic script:
  ```bash
  # scripts/test_traffic.sh
  curl http://example.com
  ping -c 10 8.8.8.8
  nslookup google.com
  ```
- [ ] Document: Test results in BENCHMARKS.md

**Day 28: Final Polish**
- [ ] Code cleanup:
  - [ ] Remove dead code, TODOs
  - [ ] Consistent error messages
  - [ ] Run `gofmt`, `goimports`
- [ ] Add examples/ directory:
  - [ ] `examples/basic_capture.sh` - Simple capture command
  - [ ] `examples/http_filter.sh` - Filter HTTP traffic
  - [ ] `examples/save_pcap.sh` - Save to file
- [ ] Create demo GIF/video:
  - [ ] Record terminal session with `asciinema`
  - [ ] Show: Capture, stats update, filtering
  - [ ] Add to README
- [ ] Tag release: `git tag v1.0.0`

**Deliverable**: Production-ready packet analyzer with docs, tests, Docker, CI/CD.

---

## 5. CODE QUALITY STANDARDS

### 5.1 Coding Guidelines

**MANDATORY Requirements**:

1. **Human-Readable Variables** (NOT single letters)
   ```go
   // ❌ BAD
   p := make([]byte, 1024)
   n, _ := r.Read(p)
   
   // ✅ GOOD
   packetBuffer := make([]byte, MaxPacketSize)
   bytesRead, err := rawSocket.Read(packetBuffer)
   ```

2. **Descriptive Function Names**
   ```go
   // ❌ BAD
   func proc(d []byte) error
   
   // ✅ GOOD
   func parseEthernetFrame(rawData []byte) (*EthernetFrame, error)
   ```

3. **Comment Every Exported Function**
   ```go
   // ParseIPv4 decodes an IPv4 packet from raw bytes.
   // It validates the IP version, header length, and checksum.
   // Returns an error if the packet is malformed or checksum fails.
   //
   // Format: https://tools.ietf.org/html/rfc791
   func ParseIPv4(data []byte) (*IPv4Packet, error) {
       // Implementation
   }
   ```

4. **Inline Comments for Complex Logic**
   ```go
   // Extract version (4 bits) and IHL (4 bits) from first byte
   versionAndIHL := data[0]
   version := versionAndIHL >> 4        // Top 4 bits
   headerLength := versionAndIHL & 0x0F // Bottom 4 bits
   
   // IHL is in 32-bit words, convert to bytes
   headerLengthBytes := int(headerLength) * 4
   ```

5. **Constants for Magic Numbers**
   ```go
   const (
       EthernetHeaderSize = 14
       IPv4MinHeaderSize  = 20
       TCPMinHeaderSize   = 20
       UDPHeaderSize      = 8
       
       EtherTypeIPv4 = 0x0800
       EtherTypeARP  = 0x0806
       EtherTypeIPv6 = 0x86DD
       
       IPProtocolTCP  = 6
       IPProtocolUDP  = 17
       IPProtocolICMP = 1
   )
   ```

6. **Error Handling - NEVER Ignore Errors**
   ```go
   // ❌ BAD
   bytesRead, _ := socket.Read(buffer)
   
   // ✅ GOOD
   bytesRead, err := socket.Read(buffer)
   if err != nil {
       return fmt.Errorf("failed to read from socket: %w", err)
   }
   ```

7. **Error Wrapping with Context**
   ```go
   func CapturePackets(interfaceName string) error {
       fd, err := openRawSocket(interfaceName)
       if err != nil {
           return fmt.Errorf("capture failed on interface %s: %w", interfaceName, err)
       }
       // ...
   }
   ```

### 5.2 Go Idioms

**Use These Patterns**:

1. **Struct Initialization**
   ```go
   stats := &Statistics{
       protocolCounts: make(map[string]uint64),
       topTalkers:     make(map[string]uint64),
       startTime:      time.Now(),
   }
   ```

2. **Interfaces for Abstraction**
   ```go
   type PacketParser interface {
       Parse(data []byte) (*PacketInfo, error)
   }
   
   type EthernetParser struct{}
   func (p *EthernetParser) Parse(data []byte) (*PacketInfo, error) {
       // Implementation
   }
   ```

3. **Table-Driven Tests**
   ```go
   func TestParseIPv4(t *testing.T) {
       tests := []struct {
           name    string
           input   []byte
           want    *IPv4Packet
           wantErr bool
       }{
           {
               name:  "valid IPv4 packet",
               input: []byte{0x45, 0x00, /* ... */},
               want:  &IPv4Packet{Version: 4, /* ... */},
           },
           {
               name:    "packet too short",
               input:   []byte{0x45},
               wantErr: true,
           },
       }
       
       for _, tt := range tests {
           t.Run(tt.name, func(t *testing.T) {
               got, err := ParseIPv4(tt.input)
               if (err != nil) != tt.wantErr {
                   t.Errorf("unexpected error: %v", err)
               }
               // Assert got == tt.want
           })
       }
   }
   ```

### 5.3 Performance Best Practices

1. **Pre-Allocate Slices**
   ```go
   // ❌ BAD - grows dynamically
   var packets []PacketInfo
   for i := 0; i < 1000; i++ {
       packets = append(packets, PacketInfo{})
   }
   
   // ✅ GOOD - pre-allocated
   packets := make([]PacketInfo, 0, 1000)
   for i := 0; i < 1000; i++ {
       packets = append(packets, PacketInfo{})
   }
   ```

2. **Use sync.Pool for Temporary Objects**
   ```go
   var packetPool = sync.Pool{
       New: func() interface{} {
           return &PacketInfo{}
       },
   }
   
   func processPacket(data []byte) {
       pkt := packetPool.Get().(*PacketInfo)
       defer packetPool.Put(pkt)
       // Use pkt...
   }
   ```

3. **Minimize Allocations in Hot Paths**
   ```go
   // ❌ BAD - allocates on every call
   func parseIP(data []byte) string {
       return fmt.Sprintf("%d.%d.%d.%d", data[0], data[1], data[2], data[3])
   }
   
   // ✅ GOOD - reuse buffer
   var ipBuf [16]byte
   func parseIP(data []byte) string {
       n := copy(ipBuf[:], fmt.Appendf(ipBuf[:0], "%d.%d.%d.%d", data[0], data[1], data[2], data[3]))
       return string(ipBuf[:n])
   }
   ```

---

## 6. TESTING STRATEGY

### 6.1 Unit Tests

**Coverage Target**: 80%+

**Test Files**:
- `internal/parser/ethernet_test.go`
- `internal/parser/ipv4_test.go`
- `internal/parser/tcp_test.go`
- `internal/parser/udp_test.go`
- `internal/capture/ringbuffer_test.go`
- `internal/stats/stats_test.go`

**Test Data**:
Create `test/testdata/packets.go` with sample packet bytes:
```go
package testdata

var (
    // Ethernet frame: TCP SYN packet
    TCPSynPacket = []byte{
        // Ethernet header (14 bytes)
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // Dst MAC
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Src MAC
        0x08, 0x00,                         // EtherType: IPv4
        
        // IPv4 header (20 bytes)
        0x45, 0x00, 0x00, 0x3c, // Version, IHL, ToS, Total Length
        0x1c, 0x46, 0x40, 0x00, // ID, Flags, Fragment Offset
        0x40, 0x06, 0xb1, 0xe6, // TTL, Protocol (TCP), Checksum
        0xc0, 0xa8, 0x01, 0x64, // Source IP: 192.168.1.100
        0x08, 0x08, 0x08, 0x08, // Dest IP: 8.8.8.8
        
        // TCP header (20 bytes)
        0xc3, 0x50,             // Source Port: 50000
        0x00, 0x50,             // Dest Port: 80
        0x00, 0x00, 0x00, 0x00, // Sequence Number
        0x00, 0x00, 0x00, 0x00, // Acknowledgment Number
        0x50, 0x02,             // Data Offset, Flags (SYN)
        0x20, 0x00,             // Window Size
        0xe6, 0x32,             // Checksum
        0x00, 0x00,             // Urgent Pointer
    }
)
```

### 6.2 Integration Tests

**Test Scenarios**:
1. End-to-end packet capture and parsing
2. Statistics aggregation accuracy
3. PCAP file write/read
4. Filter application

**Example**:
```go
func TestEndToEndCapture(t *testing.T) {
    // Start sniffer in background
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    
    stats := &Statistics{}
    go CaptureAndParse(ctx, "lo", stats) // Capture on loopback
    
    // Generate test traffic
    conn, _ := net.Dial("tcp", "127.0.0.1:8080")
    conn.Write([]byte("test"))
    conn.Close()
    
    // Wait for processing
    time.Sleep(1 * time.Second)
    
    // Verify stats
    if stats.TotalPackets == 0 {
        t.Error("No packets captured")
    }
}
```

### 6.3 Benchmark Tests

**File**: `test/benchmark_test.go`

```go
func BenchmarkParseIPv4(b *testing.B) {
    packet := testdata.TCPSynPacket[14:] // Skip Ethernet header
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _, _ = ParseIPv4(packet)
    }
}

func BenchmarkRingBufferThroughput(b *testing.B) {
    rb := NewRingBuffer(1024 * 1024)
    data := make([]byte, 1500)
    
    b.ResetTimer()
    b.RunParallel(func(pb *testing.PB) {
        for pb.Next() {
            rb.Enqueue(data)
            rb.Dequeue()
        }
    })
}
```

**Run**:
```bash
go test -bench=. -benchmem -cpuprofile cpu.prof ./test
go tool pprof cpu.prof
```

---

## 7. CLI OUTPUT SPECIFICATION

### 7.1 Standard Mode (Default)

**Refresh Rate**: Every 1 second
**Layout**:

```
================================================================================
                        GoPacketSniffer v1.0.0
                    Live Network Traffic Analysis
================================================================================
Interface: eth0                                    Uptime: 00:05:42
Captured: 127,456 packets | 58.3 MB               Dropped: 0 (0.0%)
--------------------------------------------------------------------------------

PROTOCOL DISTRIBUTION
  TCP   :  89,234 packets (70.0%) |  45.2 MB | ████████████████░░░░
  UDP   :  32,156 packets (25.2%) |  11.8 MB | ██████░░░░░░░░░░░░░░
  ICMP  :   4,891 packets  (3.8%) |   1.1 MB | █░░░░░░░░░░░░░░░░░░░
  Other :   1,175 packets  (0.9%) |   0.2 MB | ░░░░░░░░░░░░░░░░░░░░

BANDWIDTH
  Current:  2.3 MB/s ↑ 1.8 MB/s ↓
  Average:  1.9 MB/s ↑ 1.5 MB/s ↓
  Peak:     5.1 MB/s @ 14:23:15

TOP TALKERS (by bytes sent)
  1. 192.168.1.100     →   12.5 MB  (21.4%)  ████████░░░░░░░░░░░░
  2. 172.217.164.46    →    8.3 MB  (14.2%)  █████░░░░░░░░░░░░░░░
  3. 10.0.0.5          →    5.7 MB   (9.8%)  ███░░░░░░░░░░░░░░░░░
  4. 8.8.8.8           →    3.2 MB   (5.5%)  ██░░░░░░░░░░░░░░░░░░
  5. 1.1.1.1           →    2.1 MB   (3.6%)  █░░░░░░░░░░░░░░░░░░░

TCP CONNECTION STATES
  Established: 42 | SYN_SENT: 3 | TIME_WAIT: 8 | CLOSE_WAIT: 1

HTTP TRAFFIC (if parsed)
  Requests: 1,234 | 2xx: 980 (79.4%) | 4xx: 203 (16.4%) | 5xx: 51 (4.1%)

[Ctrl+C to stop | -h for help]
```

**Colors**:
- Headers: Cyan bold
- Protocol names: Blue
- High values (>1GB): Red
- Medium values (100MB-1GB): Yellow
- Low values (<100MB): Green
- Progress bars: Green fill, gray background

### 7.2 Verbose Mode (`-v`)

**Shows Each Packet**:
```
14:35:22.123456 ETH 00:11:22:33:44:55 → ff:ff:ff:ff:ff:ff Type=0x0800
                IPv4 192.168.1.100 → 8.8.8.8 Proto=TCP TTL=64 Len=60
                TCP 50000 → 80 Seq=0 Ack=0 Flags=[SYN] Win=65535

14:35:22.125831 ETH ff:ff:ff:ff:ff:ff → 00:11:22:33:44:55 Type=0x0800
                IPv4 8.8.8.8 → 192.168.1.100 Proto=TCP TTL=128 Len=60
                TCP 80 → 50000 Seq=0 Ack=1 Flags=[SYN,ACK] Win=65535

14:35:22.125912 ETH 00:11:22:33:44:55 → ff:ff:ff:ff:ff:ff Type=0x0800
                IPv4 192.168.1.100 → 8.8.8.8 Proto=TCP TTL=64 Len=52
                TCP 50000 → 80 Seq=1 Ack=1 Flags=[ACK] Win=65535

[Captured 3 packets in 0.003s]
```

### 7.3 Filter Mode (`-f "tcp port 80"`)

**Header Shows Active Filter**:
```
================================================================================
                        GoPacketSniffer v1.0.0
                Filter: tcp port 80 (Kernel BPF)
================================================================================
```

### 7.4 Export Mode (`-w capture.pcap`)

**Progress Indicator**:
```
Capturing to: capture.pcap
Packets written: 12,345 | Size: 5.2 MB
[Ctrl+C to stop and close file]
```

---

## 8. DEPLOYMENT & DOCKERIZATION

### 8.1 Dockerfile

```dockerfile
# Stage 1: Build
FROM golang:1.21-alpine AS builder

WORKDIR /build

# Install dependencies
RUN apk add --no-cache git make libpcap-dev

# Copy go.mod first for caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build static binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s" \
    -o gopacketsniffer \
    cmd/gopacketsniffer/main.go

# Stage 2: Runtime
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache libpcap ca-certificates

# Copy binary
COPY --from=builder /build/gopacketsniffer /usr/local/bin/

# Non-root user (note: needs NET_RAW capability)
RUN addgroup -S sniffer && adduser -S sniffer -G sniffer

# Default command
ENTRYPOINT ["gopacketsniffer"]
CMD ["-i", "eth0"]

# Metadata
LABEL maintainer="your.email@example.com"
LABEL description="High-performance network packet analyzer"
LABEL version="1.0.0"
```

### 8.2 docker-compose.yml

```yaml
version: '3.8'

services:
  sniffer:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: gopacketsniffer
    network_mode: host
    cap_add:
      - NET_RAW      # Required for raw sockets
      - NET_ADMIN    # Required for promiscuous mode
    command: ["-i", "eth0", "-v"]
    volumes:
      - ./captures:/captures  # Mount for PCAP files
    restart: unless-stopped

  # Optional: Traffic generator for testing
  traffic-gen:
    image: alpine:latest
    container_name: traffic-generator
    command: |
      sh -c "
        apk add --no-cache curl
        while true; do
          curl -s http://example.com > /dev/null
          sleep 5
        done
      "
    depends_on:
      - sniffer
```

### 8.3 Usage

```bash
# Build image
docker build -t gopacketsniffer:latest .

# Run (requires privileged mode for raw sockets)
docker run --rm --network host --cap-add=NET_RAW gopacketsniffer -i eth0

# Run with docker-compose
docker-compose up -d

# View logs
docker-compose logs -f sniffer

# Save capture to file
docker run --rm --network host --cap-add=NET_RAW \
  -v $(pwd)/captures:/captures \
  gopacketsniffer -i eth0 -w /captures/capture.pcap
```

### 8.4 Kubernetes Deployment (Optional)

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: gopacketsniffer
  namespace: monitoring
spec:
  selector:
    matchLabels:
      app: gopacketsniffer
  template:
    metadata:
      labels:
        app: gopacketsniffer
    spec:
      hostNetwork: true  # Access host network interfaces
      containers:
      - name: sniffer
        image: gopacketsniffer:latest
        args: ["-i", "eth0"]
        securityContext:
          capabilities:
            add:
            - NET_RAW
            - NET_ADMIN
        resources:
          limits:
            memory: 256Mi
            cpu: 500m
```

---

## 9. BENCHMARKING REQUIREMENTS

### 9.1 Performance Targets

**Throughput**:
- Capture rate: 1,000,000+ packets/sec (1 Gbps Ethernet)
- Parse rate: 800,000+ packets/sec
- Packet loss: <0.1% at 1 Gbps
- Memory usage: <500 MB at steady state

**Latency**:
- Packet-to-display: <100ms (p99)
- Parsing overhead: <100 ns/packet

### 9.2 Benchmark Commands

```bash
# Parser benchmarks
go test -bench=BenchmarkParse -benchmem ./internal/parser/

# Ring buffer benchmark
go test -bench=BenchmarkRingBuffer -benchmem ./internal/capture/

# End-to-end throughput test
# Terminal 1: Generate traffic with iperf3
iperf3 -s

# Terminal 2: Run sniffer with profiling
sudo go run cmd/gopacketsniffer/main.go -i eth0 -cpuprofile cpu.prof

# Terminal 3: Generate 1 Gbps traffic
iperf3 -c localhost -t 30 -b 1G

# Analyze profile
go tool pprof cpu.prof
```

### 9.3 Comparison Benchmarks

**Compare Against**:
- tcpdump
- Wireshark (tshark CLI)
- libpcap examples

**Metrics**:
- Packets captured per second
- CPU usage (%)
- Memory usage (MB)
- Packet drops

**Example Comparison**:
```bash
# tcpdump
sudo tcpdump -i eth0 -c 1000000 -w /dev/null
# Record: Time, CPU%, Memory

# GoPacketSniffer
sudo ./gopacketsniffer -i eth0
# Record: Time, CPU%, Memory (from stats display)

# Create table in BENCHMARKS.md
```

### 9.4 Stress Testing

```bash
# Generate maximum traffic
sudo hping3 -c 1000000 -d 1400 -S -p 80 --flood localhost

# Monitor sniffer performance
# Check: Dropped packets, CPU usage, memory growth
```

---

## 10. DOCUMENTATION REQUIREMENTS

### 10.1 README.md Structure

```markdown
# GoPacketSniffer

> High-performance network packet analyzer built from scratch in Go

[![Build Status](badge)](link)
[![Test Coverage](badge)](link)
[![Go Report Card](badge)](link)

## Overview

GoPacketSniffer is a lightweight, high-performance packet capture and analysis tool that decodes network traffic at wire speed. Built entirely from scratch without relying on heavy libraries, it demonstrates deep understanding of network protocols and systems programming.

## Features

- ✅ **Multi-Protocol Support**: Ethernet, IPv4, TCP, UDP, ICMP, HTTP
- ✅ **High Performance**: 1+ Gbps capture rate, <0.1% packet loss
- ✅ **Real-Time Statistics**: Live protocol distribution, bandwidth, top talkers
- ✅ **BPF Filtering**: Kernel-level packet filtering (tcpdump syntax)
- ✅ **PCAP Export**: Save captures in Wireshark-compatible format
- ✅ **Zero Dependencies**: Pure Go implementation (except libpcap for raw sockets)
- ✅ **Docker Support**: Containerized deployment with docker-compose

## Quick Start

### Prerequisites
- Go 1.21+
- Linux (for raw socket support)
- Root privileges (for packet capture)

### Installation

```bash
# Clone repository
git clone https://github.com/yourusername/gopacketsniffer
cd gopacketsniffer

# Build
make build

# Run (requires sudo)
sudo ./bin/gopacketsniffer -i eth0
```

### Docker

```bash
docker-compose up
```

## Usage

### Basic Capture
```bash
# Capture on eth0 interface
sudo gopacketsniffer -i eth0

# Capture with verbose output (show each packet)
sudo gopacketsniffer -i eth0 -v
```

### Filtering
```bash
# Capture only HTTP traffic
sudo gopacketsniffer -i eth0 -f "tcp port 80"

# Capture from specific host
sudo gopacketsniffer -i eth0 -f "host 192.168.1.100"
```

### Export to PCAP
```bash
# Save capture to file
sudo gopacketsniffer -i eth0 -w capture.pcap

# Open in Wireshark
wireshark capture.pcap
```

## Architecture

[Insert architecture diagram here]

GoPacketSniffer uses a multi-stage pipeline:

1. **Capture Layer**: Raw socket reads packets from network interface
2. **Ring Buffer**: Lock-free queue for zero-copy packet passing
3. **Parser Layer**: Concurrent goroutines decode protocol layers
4. **Stats Engine**: Aggregates metrics (protocol counts, bandwidth, flows)
5. **Display Layer**: Terminal UI with real-time updates

## Performance

Benchmarked on Intel i7-9700K @ 3.60GHz, 16GB RAM:

| Metric | Value |
|--------|-------|
| Capture Rate | 1,200,000 pps |
| Parse Rate | 850,000 pps |
| Packet Loss | 0.05% @ 1 Gbps |
| CPU Usage | 45% (single core) |
| Memory | 180 MB |

See [BENCHMARKS.md](BENCHMARKS.md) for detailed results.

## Protocol Support

- [x] Ethernet (802.3)
- [x] IPv4
- [x] TCP
- [x] UDP
- [x] ICMP
- [x] HTTP (basic)
- [ ] IPv6 (planned)
- [ ] TLS (planned)
- [ ] DNS (planned)

## Contributing

Contributions welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT License - see [LICENSE](LICENSE)

## Acknowledgments

Built as a learning project to understand network internals. Inspired by tcpdump, Wireshark, and libpcap.

## Author

**Your Name** - [GitHub](https://github.com/yourusername) - [LinkedIn](https://linkedin.com/in/yourprofile)
```

### 10.2 ARCHITECTURE.md

**Contents**:
- System design diagram
- Component breakdown (capture, parser, stats, display)
- Data flow diagrams
- Concurrency model (goroutines, channels)
- Performance optimizations (ring buffer, zero-copy, sync.Pool)
- Protocol parsing details (bit layouts, header formats)

### 10.3 BENCHMARKS.md

**Contents**:
- Test environment specs
- Throughput benchmarks (packets/sec)
- Latency measurements (p50, p95, p99)
- Memory profiling results
- Comparison vs tcpdump/Wireshark
- Graphs (throughput over time, CPU usage)

### 10.4 Inline Code Documentation

**Example**:
```go
// ParseTCP decodes a TCP segment from raw bytes following RFC 793.
//
// The function expects data to contain at least 20 bytes (minimum TCP header).
// It extracts source/destination ports, sequence/acknowledgment numbers,
// flags (SYN, ACK, FIN, RST, PSH, URG), window size, and checksum.
//
// TCP Header Format (20 bytes minimum):
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |          Source Port          |       Destination Port        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        Sequence Number                        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    Acknowledgment Number                      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | Offset| Res |     Flags     |            Window             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |           Checksum            |         Urgent Pointer        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// Flags (1 byte):
//  - URG (bit 5): Urgent pointer field significant
//  - ACK (bit 4): Acknowledgment field significant
//  - PSH (bit 3): Push function
//  - RST (bit 2): Reset the connection
//  - SYN (bit 1): Synchronize sequence numbers
//  - FIN (bit 0): No more data from sender
//
// Returns:
//  - *TCPSegment: Parsed TCP segment with all fields populated
//  - error: If data is too short, checksum invalid, or parsing fails
//
// Reference: https://tools.ietf.org/html/rfc793
func ParseTCP(data []byte) (*TCPSegment, error) {
    // Validate minimum length
    if len(data) < TCPMinHeaderSize {
        return nil, fmt.Errorf("TCP segment too short: got %d bytes, need at least %d",
            len(data), TCPMinHeaderSize)
    }
    
    // Extract source port (bytes 0-1, network byte order)
    sourcePort := binary.BigEndian.Uint16(data[0:2])
    
    // Extract destination port (bytes 2-3)
    destPort := binary.BigEndian.Uint16(data[2:4])
    
    // ... rest of implementation
}
```

---

## 11. PROGRESS TRACKING

### 11.1 Checklist Format

Use this template in your project README or separate PROGRESS.md:

```markdown
## Implementation Progress

Last Updated: 2024-04-26

### Phase 1: Foundation & Raw Capture ⬜ (0/15)
- [ ] Day 1: Project setup
  - [ ] Initialize Go module
  - [ ] Create directory structure
  - [ ] Setup Makefile
  - [ ] Write initial README
- [ ] Day 2: Raw socket capture
  - [ ] Implement OpenRawSocket()
  - [ ] Implement SetPromiscuousMode()
  - [ ] Implement CaptureLoop()
  - [ ] Test: Capture 100 packets
- [ ] Day 3: Ring buffer
  - [ ] Implement RingBuffer struct
  - [ ] Implement Enqueue()
  - [ ] Implement Dequeue()
  - [ ] Test: Benchmark operations
- [ ] Day 4: Integration
  - [ ] CLI flag parsing
  - [ ] Launch goroutines
  - [ ] Graceful shutdown
  - [ ] Test: End-to-end capture

### Phase 2: Protocol Parsing ⬜ (0/24)
[Similar detailed breakdown]

### Phase 3: Statistics & Display ⬜ (0/20)
[Similar detailed breakdown]

### Phase 4: Advanced Features ⬜ (0/24)
[Similar detailed breakdown]

### Phase 5: Polish & Production ⬜ (0/28)
[Similar detailed breakdown]

---

## Overall Progress: 0/111 tasks (0%)
```

### 11.2 Daily Log

Keep a development log:

```markdown
## Development Log

### 2024-04-26 (Day 1)
**Completed**:
- ✅ Initialized Go module
- ✅ Created directory structure
- ✅ Wrote Makefile

**In Progress**:
- 🔄 Writing initial README

**Blockers**:
- None

**Notes**:
- Decided on project name: GoPacketSniffer
- Choosing MIT license

**Next Session**:
- Finish README
- Start raw socket implementation

---

### 2024-04-27 (Day 2)
[Continue logging]
```

### 11.3 Milestone Tracking

**Key Milestones**:

| Milestone | Target Date | Status | Actual Date |
|-----------|-------------|--------|-------------|
| First packet captured | Day 4 | ⬜ | - |
| All parsers working | Day 10 | ⬜ | - |
| Live stats display | Day 15 | ⬜ | - |
| BPF filtering | Day 16 | ⬜ | - |
| PCAP export | Day 17 | ⬜ | - |
| HTTP parsing | Day 18 | ⬜ | - |
| Optimization complete | Day 21 | ⬜ | - |
| All tests passing | Day 22 | ⬜ | - |
| Documentation done | Day 24 | ⬜ | - |
| Docker working | Day 25 | ⬜ | - |
| v1.0.0 release | Day 28 | ⬜ | - |

---

## 12. SUCCESS CRITERIA

### 12.1 Functional Requirements ✅

**Must Have (P0)**:
- [x] Captures packets on specified network interface
- [x] Decodes Ethernet, IPv4, TCP, UDP headers
- [x] Displays real-time statistics (protocol counts, bandwidth)
- [x] Handles graceful shutdown (Ctrl+C)
- [x] Runs without crashes for 1+ hour
- [x] Processes 1+ Gbps traffic with <1% packet loss
- [x] Works on Linux (Ubuntu 20.04+)

**Should Have (P1)**:
- [x] BPF filtering support
- [x] PCAP file export
- [x] HTTP request/response parsing
- [x] Top talkers tracking
- [x] TCP flow tracking
- [x] Docker support

**Nice to Have (P2)**:
- [ ] IPv6 support
- [ ] TLS handshake parsing
- [ ] DNS query/response parsing
- [ ] Geo-IP lookup for IPs

### 12.2 Non-Functional Requirements ✅

**Performance**:
- [x] 1,000,000+ packets/sec capture rate
- [x] <100 ns/packet parsing overhead
- [x] <500 MB memory usage
- [x] <0.1% packet loss at 1 Gbps

**Code Quality**:
- [x] 80%+ test coverage
- [x] Zero linter warnings (`golangci-lint`)
- [x] All exported functions documented
- [x] Benchmarks for critical paths
- [x] No race conditions (`go test -race`)

**Usability**:
- [x] Clear, colorized terminal output
- [x] Helpful error messages
- [x] Comprehensive README with examples
- [x] Docker one-liner: `docker run gopacketsniffer`

**Portability**:
- [x] Builds on Linux
- [ ] Builds on macOS (optional)
- [x] Dockerized deployment
- [x] Single static binary

### 12.3 Resume Impact Checklist ✅

**Technical Depth**:
- [x] Demonstrates systems programming (raw sockets, kernel interaction)
- [x] Shows protocol expertise (RFC-compliant parsing)
- [x] Proves optimization skills (1+ Gbps throughput)
- [x] Exhibits concurrent programming (goroutines, channels)

**Project Quality**:
- [x] Professional README with badges
- [x] Comprehensive documentation
- [x] High test coverage (80%+)
- [x] Clean, well-structured code
- [x] Working Docker deployment

**Demonstrability**:
- [x] Works in live demo (capture real traffic)
- [x] Visual output (terminal UI, not just logs)
- [x] Quantifiable metrics (1M pps, 1 Gbps)
- [x] Comparison benchmarks (vs tcpdump)

**Interview Readiness**:
- [x] Can explain every component in detail
- [x] Can answer "Why did you build it this way?"
- [x] Can discuss trade-offs (ring buffer vs channels)
- [x] Can show profiling/optimization process

### 12.4 Final Acceptance Test

**Before Marking Complete, Verify**:

1. **Functionality**:
   - [ ] Run: `sudo gopacketsniffer -i eth0`
   - [ ] Open browser, navigate to websites
   - [ ] Verify: HTTP requests appear in stats
   - [ ] Verify: Top talkers shows browser IP
   - [ ] Press Ctrl+C, verify graceful shutdown

2. **Performance**:
   - [ ] Generate 1 Gbps traffic with iperf3
   - [ ] Verify: <1% packet drops in stats
   - [ ] Verify: CPU usage <80%
   - [ ] Verify: Memory stable (no leaks)

3. **Export**:
   - [ ] Run: `sudo gopacketsniffer -i eth0 -w test.pcap`
   - [ ] Generate traffic
   - [ ] Open test.pcap in Wireshark
   - [ ] Verify: Packets decode correctly

4. **Filtering**:
   - [ ] Run: `sudo gopacketsniffer -i eth0 -f "tcp port 443"`
   - [ ] Generate HTTP and HTTPS traffic
   - [ ] Verify: Only HTTPS (port 443) captured

5. **Docker**:
   - [ ] Run: `docker-compose up`
   - [ ] Verify: Container captures packets
   - [ ] Verify: Stats update in logs

6. **Documentation**:
   - [ ] Read README as if you're a new user
   - [ ] Follow install instructions
   - [ ] Verify: All links work
   - [ ] Verify: Examples run correctly

7. **Code Review**:
   - [ ] Run: `golangci-lint run`
   - [ ] Verify: No warnings
   - [ ] Run: `go test -race ./...`
   - [ ] Verify: No race conditions
   - [ ] Run: `go test -cover ./...`
   - [ ] Verify: Coverage >80%

---

## APPENDIX A: Common Issues & Solutions

### Issue: "Permission denied" when running

**Cause**: Raw sockets require root privileges

**Solution**:
```bash
# Option 1: Run with sudo
sudo ./gopacketsniffer -i eth0

# Option 2: Grant capabilities to binary
sudo setcap cap_net_raw,cap_net_admin=eip ./gopacketsniffer
./gopacketsniffer -i eth0
```

### Issue: "No such device" error

**Cause**: Interface name incorrect

**Solution**:
```bash
# List available interfaces
ip link show

# Use correct interface name
sudo ./gopacketsniffer -i wlan0  # Not eth0
```

### Issue: High packet drops

**Cause**: Ring buffer too small or parsing too slow

**Solution**:
- Increase ring buffer size in code
- Profile with pprof to find bottlenecks
- Enable zero-copy mode (`-zerocopy`)
- Reduce workload (e.g., skip HTTP parsing)

### Issue: Checksum validation fails

**Cause**: NIC offloading (checksum computed by hardware)

**Solution**:
```bash
# Disable offloading
sudo ethtool -K eth0 tx off rx off
```

---

## APPENDIX B: Useful Resources

### RFCs (Protocol Specifications)
- RFC 791: Internet Protocol (IPv4)
- RFC 793: Transmission Control Protocol (TCP)
- RFC 768: User Datagram Protocol (UDP)
- RFC 792: Internet Control Message Protocol (ICMP)
- RFC 2616: Hypertext Transfer Protocol (HTTP/1.1)

### Tools
- Wireshark: https://www.wireshark.org/
- tcpdump: https://www.tcpdump.org/
- libpcap: https://github.com/the-tcpdump-group/libpcap
- iperf3: https://software.es.net/iperf/
- hping3: http://www.hping.org/

### Go Libraries (for reference, not dependencies)
- google/gopacket: https://github.com/google/gopacket
- golang.org/x/net/bpf: BPF filter compiler

### Learning Resources
- Beej's Guide to Network Programming
- TCP/IP Illustrated (Stevens)
- The Linux Programming Interface (Kerrisk)

---

## FINAL NOTES

**Remember**:
1. **Comment everything** - Assume you're explaining to a junior dev
2. **Test incrementally** - Don't write 1000 lines before testing
3. **Commit often** - Small, atomic commits with clear messages
4. **Profile early** - Don't guess performance, measure it
5. **Ask for help** - Stuck >1 hour? Search, ask, move on

**This is a marathon, not a sprint**. Take breaks, celebrate small wins, and remember why you're building this: to demonstrate deep technical expertise that 95% of backend developers don't have.

**You've got this! 🚀**

---

**Document Version**: 1.0
**Last Updated**: 2024-04-26
**Status**: Ready for Implementation
```

---

**This plan is comprehensive, detailed, and production-ready. Follow it step-by-step, track your progress, and you'll have an impressive project that will make your resume stand out!** 🎯