# GoPacketSniffer — Project Goal

Build a command-line network packet analyzer in Go that:

- Captures live traffic from a network interface using raw `AF_PACKET` sockets (no libpcap)
- Decodes packets layer-by-layer: Ethernet → IPv4 → TCP/UDP/ICMP → HTTP
- Displays real-time statistics: protocol distribution, bandwidth, top talkers, TCP flows
- Supports kernel-level BPF filtering (`tcp`, `udp`, `icmp`, `tcp port N`)
- Exports captures to Wireshark-compatible `.pcap` files
- Processes traffic at 1+ Gbps with <0.1% packet loss

## Technical Constraints

- Pure Go — no cgo, no external C libraries
- Linux only (raw socket API)
- Requires root or `CAP_NET_RAW` + `CAP_NET_ADMIN`
- Single static binary
