# Benchmarks

## Environment

| | |
|---|---|
| CPU | Intel Core i5-1235U @ 3.30 GHz (10 cores) |
| RAM | 16 GB DDR4 |
| OS | Ubuntu 22.04, Linux 6.5 |
| Go | 1.25 |
| NIC | 1 Gbps Ethernet |

---

## Parser Microbenchmarks

Run with: `make bench`

```
BenchmarkParseEthernet-12        41157750     41 ns/op    80 B/op   1 allocs/op
BenchmarkParseIPv4-12            32006406     44 ns/op   112 B/op   1 allocs/op
BenchmarkParseTCP-12             13752972     76 ns/op    85 B/op   2 allocs/op
BenchmarkDecodePacket-12          2839195    428 ns/op   528 B/op   9 allocs/op
BenchmarkDecodePacketPool-12      3817147    335 ns/op   352 B/op   8 allocs/op
BenchmarkRingBuffer-12           64655238     17 ns/op     0 B/op   0 allocs/op
```

**Key observations:**
- Individual parsers are well under the 100 ns/packet target.
- `sync.Pool` reduces full-decode cost by **22%** (428 → 335 ns) and
  allocated bytes by **33%** (528 → 352 bytes).
- Ring buffer operates at **17 ns with zero allocations** - suitable for
  lock-free inter-goroutine packet passing.

---

## Throughput Estimate

At 335 ns per full decode on a single core:

```
1 / 335ns ≈ 2,985,000 packets/sec theoretical maximum (single core)
```

With a typical 1 Gbps link carrying 1500-byte frames:

```
1,000,000,000 bits/sec ÷ (1500 × 8 bits) ≈ 83,333 packets/sec
```

That leaves roughly **35× headroom** over a saturated 1 Gbps link of
full-size frames on a single parse worker. This is an estimate from the
decode cost alone: it ignores the `recvfrom` syscall and copy per frame, and
small packets raise the packet rate considerably (1 Gbps of 64-byte frames is
about 1.49M packets/sec). The dashboard's `Dropped` counter shows the actual
loss on a given machine.

---

## Memory Profile

At steady state capturing 1 Gbps traffic for 60 seconds:

| Component | Memory |
|---|---|
| frames channel buffer (4096 × 1500 B) | ~6 MB |
| sync.Pool (PacketInfo cache) | ~1 MB |
| Statistics maps | ~2 MB |
| Flow tracker (10k flows) | ~5 MB |
| **Total** | **~14 MB** |

Well within the 500 MB target.

---

## Comparison vs tcpdump

Both tools tested capturing on loopback while `iperf3` generates traffic.

| Metric | GoPacketSniffer | tcpdump |
|---|---|---|
| Capture rate (pps) | ~2.9M (theoretical) | ~1.5M |
| CPU @ 100k pps | ~8% | ~12% |
| Memory | ~14 MB | ~8 MB |
| Packet loss @ 1 Gbps | < 0.1% | < 0.1% |
| HTTP parsing | Yes | No |
| Flow tracking | Yes | No |
| Live dashboard | Yes | No |
| PCAP export | Yes | Yes |
| BPF filtering | Subset | Full |

---

## Reproducing Results

```bash
# Parser benchmarks
make bench

# Generate load while the sniffer runs on loopback
sudo ./bin/gopacketsniffer -i lo &
iperf3 -s &
iperf3 -c 127.0.0.1 -t 30 -b 1G
```

The binary does not expose a pprof endpoint. To take a CPU profile during a
live capture, temporarily add one as described in
[COMMANDS.md](COMMANDS.md#12-profiling-advanced).
