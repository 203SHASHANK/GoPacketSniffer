# GoPacketSniffer

> High-performance network packet analyzer built from scratch in Go - no libpcap dependency.

[![CI](https://github.com/203SHASHANK/GoPacketSniffer/actions/workflows/ci.yml/badge.svg)](https://github.com/203SHASHANK/GoPacketSniffer/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/203SHASHANK/GoPacketSniffer)](https://goreportcard.com/report/github.com/203SHASHANK/GoPacketSniffer)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## Overview

GoPacketSniffer captures live network traffic from any Linux network interface
using raw `AF_PACKET` sockets, decodes packets layer-by-layer
(Ethernet → IPv4 → TCP/UDP/ICMP → HTTP), and displays real-time statistics
in a colorized terminal dashboard - all without external C libraries.

It is a systems programming project covering:
- Raw socket programming and kernel interaction
- Binary protocol parsing straight from the RFC header layouts
- A concurrent capture pipeline with clean shutdown
- Allocation reduction with `sync.Pool`, plus a lock-free SPSC ring buffer

---

## Features

| Feature | Details |
|---|---|
| Protocol support | Ethernet, IPv4, TCP, UDP, ICMP, HTTP/1.x |
| Live dashboard | Protocol distribution, bandwidth, top talkers, TCP flows |
| BPF filtering | Kernel-level pre-filter (`tcp`, `udp`, `icmp`, `tcp port N`, `udp port N`, `host A.B.C.D`) |
| PCAP export | Wireshark-compatible `.pcap` files |
| Verbose mode | Per-packet decoded output with timestamps |
| Docker | Single-command containerized deployment |
| Zero C deps | Pure Go - no libpcap, no cgo |

---

## Quick Start

### Prerequisites

- Go 1.25+
- Linux (Ubuntu 20.04+ recommended)
- Root privileges or `CAP_NET_RAW` + `CAP_NET_ADMIN`

### Build & Run

```bash
git clone https://github.com/203SHASHANK/GoPacketSniffer
cd GoPacketSniffer
make build

# Live dashboard
sudo ./bin/gopacketsniffer -i eth0

# Verbose per-packet output
sudo ./bin/gopacketsniffer -i eth0 -v

# BPF filter - only HTTP traffic
sudo ./bin/gopacketsniffer -i eth0 -f "tcp port 80"

# Save to PCAP file
sudo ./bin/gopacketsniffer -i eth0 -w capture.pcap
```

### Docker

```bash
# Build and run
docker build -t gopacketsniffer .
docker run --rm --network host --cap-add=NET_RAW --cap-add=NET_ADMIN \
  gopacketsniffer -i eth0

# Or with docker-compose
docker-compose up
```

---

## CLI Reference

```
Usage: gopacketsniffer -i <interface> [options]

Flags:
  -i  string   Network interface to capture on (required)
  -v           Verbose: print each decoded packet instead of the dashboard
  -f  string   Capture filter (e.g. "tcp port 443")
  -w  string   Also write packets to a .pcap file
  -version     Print the version and exit
```

### Filter Expressions

| Expression | Effect |
|---|---|
| `tcp` | TCP packets only |
| `udp` | UDP packets only |
| `icmp` | ICMP packets only |
| `tcp port 80` | TCP on port 80 (src or dst) |
| `udp port 53` | UDP on port 53 (DNS) |
| `host 10.0.0.1` | IPv4 packets to or from that address |

Filters are compiled to classic BPF and run in the kernel. They match IPv4
only, read the ports at the offset given by the IP header length, and skip
non-first IP fragments for port filters. Anything else is rejected with an
error rather than silently capturing everything.

---

## Dashboard Output

```
┌────────────────────────────────────────────────────────────────────────────────┐
│  GoPacketSniffer v1.0.0                         Live Network Traffic Analysis  │
├────────────────────────────────────────────────────────────────────────────────┤
│  Interface: eth0             Uptime: 00:02:15                                  │
│  Captured: 45234 packets | 23.5 MB    Dropped: 12 (0.0%)                       │
├────────────────────────────────────────────────────────────────────────────────┤
│  PROTOCOL DISTRIBUTION                                                         │
│  TCP       32156 pkts ( 71.1%) |   18.2 MB  ██████████████░░░░░░               │
│  UDP        8945 pkts ( 19.8%) |    3.8 MB  ███░░░░░░░░░░░░░░░░░               │
│  ICMP       3133 pkts (  6.9%) |    1.0 MB  █░░░░░░░░░░░░░░░░░░░               │
│  Other      1000 pkts (  2.2%) |  512.0 KB  ░░░░░░░░░░░░░░░░░░░░               │
├────────────────────────────────────────────────────────────────────────────────┤
│  BANDWIDTH                                                                     │
│  Current: 2.3 Mbps    Peak: 5.1 Mbps @ 14:23:15                                │
├────────────────────────────────────────────────────────────────────────────────┤
│  TOP TALKERS (by bytes sent)                                                   │
│   1. 192.168.1.100      12.5 MB  ( 53.2%)                                      │
│   2. 172.217.164.46      8.3 MB  ( 35.3%)                                      │
├────────────────────────────────────────────────────────────────────────────────┤
│  HTTP TRAFFIC                                                                  │
│  Requests: 234  |  Responses  2xx: 180  4xx: 45  5xx: 9                        │
├────────────────────────────────────────────────────────────────────────────────┤
│  Active TCP flows: 42                                                          │
└────────────────────────────────────────────────────────────────────────────────┘
  [Ctrl+C to stop]
```

Verbose mode (`-v`) prints one line per packet instead:

```
19:05:41.998617 TCP   10.0.0.5:41488 -> 93.184.216.34:80 [SYN]
19:05:41.998688 TCP   93.184.216.34:80 -> 10.0.0.5:41488 [SYN,ACK]
19:05:41.998735 TCP   10.0.0.5:41488 -> 93.184.216.34:80 [ACK,PSH] HTTP GET example.com/
19:05:42.002009 TCP   93.184.216.34:80 -> 10.0.0.5:41488 [ACK,PSH] HTTP 200 OK
19:05:42.120344 UDP   10.0.0.5:53124 -> 8.8.8.8:53
19:05:42.300112 ICMP  10.0.0.5 -> 8.8.8.8 (EchoRequest)
```

---

## Architecture

```
Network Card
     │  (raw Ethernet frames)
     ▼
AF_PACKET socket  ←── BPF filter (kernel, pre-userspace)
     │
     ▼
CaptureLoop goroutine
     │  Frame{Data, Timestamp}
     ▼
frames channel (buffered, 4096; overflow is counted as dropped)
     │
     ▼
Parse worker goroutine
  ├── ParseEthernet → ParseIPv4 → ParseTCP/UDP/ICMP
  ├── ParseHTTP (TCP payload, best-effort)
  ├── sync.Pool (PacketInfo reuse)
  └── pcap.Writer (optional, -w flag)
     │
     ▼
Statistics engine (mutex-protected)
  ├── Protocol counters
  ├── Bandwidth (bits/s per refresh interval)
  ├── Top talkers (IP → bytes)
  ├── HTTP counters
  └── FlowTracker (5-tuple → state, idle expiry)
     │
     ▼
Display goroutine (1s ticker)
  └── Terminal dashboard (ANSI colors, progress bars)
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for full design details.

---

## Performance

Benchmarked on Intel i5-1235U @ 3.30GHz, 16 GB RAM, Linux 6.x:

| Metric | Value |
|---|---|
| Ethernet parse | 41 ns/op |
| IPv4 parse | 44 ns/op |
| TCP parse | 76 ns/op |
| Full decode (pooled) | 335 ns/op |
| Ring buffer op | 17 ns/op (0 allocs) |
| Packet loss @ 1 Gbps | < 0.1% |

See [BENCHMARKS.md](BENCHMARKS.md) for methodology and comparison vs tcpdump.

---

## Project Structure

```
GoPacketSniffer/
├── cmd/gopacketsniffer/main.go     # Entry point, CLI, goroutine orchestration
├── internal/
│   ├── capture/                    # Raw socket, promiscuous mode, BPF, ring buffer
│   ├── parser/                     # Ethernet, IPv4, TCP, UDP, ICMP, HTTP decoders
│   ├── stats/                      # Statistics engine, top talkers, flow tracker
│   ├── display/                    # Terminal dashboard, ANSI colors
│   ├── pcap/                       # PCAP file writer
│   └── models/                     # Shared PacketInfo struct
├── test/testdata/                  # Raw packet byte fixtures
├── examples/                       # Usage shell scripts
├── scripts/                        # Test traffic generator
├── Dockerfile
├── docker-compose.yml
└── Makefile
```

---

## Development

```bash
make test       # run all tests with race detector
make bench      # run benchmarks
make cover      # generate HTML coverage report
make lint       # run golangci-lint
make docker     # build Docker image
```

---

## Common Issues

**Permission denied**
```bash
# Option 1
sudo ./bin/gopacketsniffer -i eth0

# Option 2 - grant capabilities without sudo
sudo setcap cap_net_raw,cap_net_admin=eip ./bin/gopacketsniffer
./bin/gopacketsniffer -i eth0
```

**No such device**
```bash
ip link show          # list available interfaces
```

**Dropped counter keeps climbing**
Frames are arriving faster than they can be decoded. Narrow the capture with
a filter (`-f "tcp port 443"`) so the kernel discards the rest.

**No HTTP statistics**
Only plaintext HTTP/1.x is recognised. HTTPS and HTTP/2 payloads are
encrypted or binary and show up as plain TCP.

---

## License

MIT - see [LICENSE](LICENSE)

---

## Author

Built to demonstrate systems-level Go programming: raw sockets, binary protocol
parsing, lock-free data structures, and high-throughput concurrent pipelines.
