# GoPacketSniffer — Command Reference

A complete guide to every command you'll use while building, running, and
testing GoPacketSniffer. Each section explains what the command does and
exactly when to use it.

---

## 1. Find Your Network Interface

Before running the sniffer you need to know which interface to capture on.

```bash
ip link show
```
Lists every network interface on your machine with its state (UP/DOWN).
Run this first if you're unsure which interface name to use.

```bash
ip route get 8.8.8.8
```
Shows which interface your outgoing traffic actually uses right now.
The `dev` field in the output is the interface name to pass to `-i`.
**Use this to pick the right interface before starting a capture.**

```bash
ip addr show wlp0s20f3
```
Shows the IP address assigned to a specific interface.
Replace `wlp0s20f3` with your interface name.

---

## 2. Build

```bash
make build
```
Compiles the Go source into `bin/gopacketsniffer`.
Run this after any code change before running the binary.
Equivalent to:
```bash
go build -ldflags="-w -s -X main.version=dev" -o bin/gopacketsniffer ./cmd/gopacketsniffer
```

```bash
go build ./...
```
Compiles every package in the project without producing a binary.
Use this to quickly check that the code compiles after edits.

---

## 3. Run

```bash
make run IFACE=wlp0s20f3
```
Builds and runs the sniffer on your WiFi interface with the live dashboard.
**Use this for normal day-to-day capture.**

```bash
make run IFACE=enp0s31f6
```
Same but on your wired Ethernet interface.
Use when you are plugged into a network cable.

```bash
make run IFACE=wlp0s20f3 ARGS='-v'
```
Verbose mode — prints one decoded line per packet instead of the dashboard.
**Use this when you want to see individual packets scroll by in real time.**

```bash
make run IFACE=wlp0s20f3 ARGS='-f "tcp port 80"'
```
Attaches a BPF filter so the kernel only passes HTTP (port 80) packets.
**Use this to focus on a specific protocol or port and reduce noise.**

```bash
make run IFACE=wlp0s20f3 ARGS='-f "tcp port 443"'
```
Capture only HTTPS traffic (port 443).

```bash
make run IFACE=wlp0s20f3 ARGS='-f "udp port 53"'
```
Capture only DNS queries and responses (UDP port 53).
**Use this to see every domain your machine looks up.**

```bash
make run IFACE=wlp0s20f3 ARGS='-f "icmp"'
```
Capture only ICMP packets (ping traffic).

```bash
make run IFACE=wlp0s20f3 ARGS='-w capture.pcap'
```
Saves every captured packet to `capture.pcap` in Wireshark format.
**Use this when you want to analyse traffic offline later.**

```bash
make run IFACE=wlp0s20f3 ARGS='-f "tcp port 443" -w https.pcap -v'
```
Combines filter + save + verbose — all three flags at once.

### Running directly with sudo (without make)

```bash
sudo ./bin/gopacketsniffer -i wlp0s20f3
sudo ./bin/gopacketsniffer -i wlp0s20f3 -v
sudo ./bin/gopacketsniffer -i wlp0s20f3 -f "tcp port 80"
sudo ./bin/gopacketsniffer -i wlp0s20f3 -w capture.pcap
```

### Grant capabilities so you don't need sudo every time

```bash
sudo setcap cap_net_raw,cap_net_admin=eip ./bin/gopacketsniffer
./bin/gopacketsniffer -i wlp0s20f3
```
Sets Linux capabilities on the binary so it can open raw sockets without
being run as root. **Use this if you find typing sudo annoying.**
Note: you must re-run setcap after every `make build`.

---

## 4. Test

```bash
make test
```
Runs the full test suite with the race detector enabled.
**Run this after every code change to catch bugs and data races.**
Equivalent to:
```bash
go test -v -race ./...
```

```bash
go test ./internal/parser/
```
Runs only the parser package tests. Faster when you're working on parsers.

```bash
go test -run TestParseTCP ./internal/parser/
```
Runs a single named test. Replace `TestParseTCP` with any test function name.
**Use this to debug a specific failing test.**

```bash
go test -v -race ./internal/stats/
```
Runs stats tests with verbose output and race detection.
The `-v` flag prints each test name and PASS/FAIL as it runs.

---

## 5. Benchmarks

```bash
make bench
```
Runs all benchmark functions across every internal package.
**Use this to measure parser performance after optimisation attempts.**
Equivalent to:
```bash
go test -bench=. -benchmem ./internal/...
```

```bash
go test -bench=BenchmarkDecodePacket -benchmem ./internal/parser/
```
Runs a single named benchmark.
`-benchmem` adds columns for bytes allocated and number of allocations per op.

```bash
go test -bench=. -benchmem -count=5 ./internal/parser/
```
Runs each benchmark 5 times for more stable results.
**Use this when comparing before/after an optimisation.**

---

## 6. Coverage

```bash
make cover
```
Runs tests, generates `coverage.out`, then opens `coverage.html` in your
browser showing which lines are covered.
**Use this to find untested code paths.**

```bash
go test -cover ./internal/...
```
Prints a quick coverage percentage per package without generating HTML.
Use this for a fast coverage check from the terminal.

```bash
go tool cover -func=coverage.out | grep -v "100.0%"
```
Lists every function that is not at 100% coverage.
**Use this to find exactly which functions need more tests.**

---

## 7. Code Quality

```bash
go vet ./...
```
Runs Go's built-in static analyser. Catches common mistakes like incorrect
format strings, unreachable code, and misuse of sync primitives.
**Run this before every commit.**

```bash
gofmt -l .
```
Lists files that are not correctly formatted.
If this prints anything, run:
```bash
gofmt -w .
```
to auto-format them.

```bash
make lint
```
Runs `golangci-lint` with the project's `.golangci.yml` config.
Checks for errcheck, staticcheck, unused variables, misspellings, and more.
Requires golangci-lint to be installed:
```bash
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
```

---

## 8. Generate Test Traffic

While the sniffer is running in one terminal, open a second terminal and run:

```bash
bash scripts/test_traffic.sh
```
Sends HTTP, HTTPS, ICMP, and DNS traffic so you can see the sniffer working.

```bash
curl http://example.com
```
Generates one HTTP GET request. You'll see it appear in the HTTP stats.

```bash
ping -c 4 8.8.8.8
```
Sends 4 ICMP echo requests to Google's DNS server.
You'll see ICMP packets appear in the protocol distribution.

```bash
nslookup google.com
```
Sends a DNS query over UDP port 53.

---

## 9. PCAP / Wireshark

```bash
sudo ./bin/gopacketsniffer -i wlp0s20f3 -w capture.pcap
```
Captures traffic and saves it to `capture.pcap`.

```bash
wireshark capture.pcap
```
Opens the saved capture in Wireshark for deep inspection.
Install Wireshark with: `sudo apt install wireshark`

```bash
tcpdump -r capture.pcap
```
Reads and prints the capture file from the terminal without Wireshark.

---

## 10. Docker

```bash
make docker
```
Builds the Docker image tagged `gopacketsniffer:dev`.
**Use this to test the containerised deployment.**

```bash
make docker-run IFACE=wlp0s20f3
```
Runs the Docker image with host networking and the required capabilities.
Equivalent to:
```bash
docker run --rm --network host \
  --cap-add=NET_RAW --cap-add=NET_ADMIN \
  gopacketsniffer:dev -i wlp0s20f3
```

```bash
docker-compose up
```
Starts the sniffer container using `docker-compose.yml`.

```bash
docker-compose --profile test up
```
Starts both the sniffer and the traffic-generator container.
**Use this to test the Docker setup end-to-end without needing a browser.**

---

## 11. Git

```bash
git init
git add .
git commit -m "feat: GoPacketSniffer v1.0.0"
```
Initialises the repo and makes the first commit.

```bash
git tag v1.0.0
git push origin main --tags
```
Tags the release and pushes it. The CI pipeline will run automatically.

---

## 12. Profiling (Advanced)

Add this import to `main.go` temporarily:
```go
import _ "net/http/pprof"
```
And start the pprof server:
```go
go http.ListenAndServe(":6060", nil)
```

Then while the sniffer is running under load:

```bash
go tool pprof http://localhost:6060/debug/pprof/profile?seconds=30
```
Captures a 30-second CPU profile. Shows which functions consume the most CPU.
**Use this to find bottlenecks before optimising.**

```bash
go tool pprof http://localhost:6060/debug/pprof/heap
```
Captures a heap profile. Shows which code is allocating the most memory.

```bash
go tool pprof -http=:8080 cpu.prof
```
Opens an interactive flame graph in your browser from a saved profile file.

---

## Quick Reference Card

| Goal | Command |
|---|---|
| Find your interface | `ip route get 8.8.8.8` |
| Build | `make build` |
| Run dashboard | `make run IFACE=wlp0s20f3` |
| Run verbose | `make run IFACE=wlp0s20f3 ARGS='-v'` |
| Filter HTTP | `make run IFACE=wlp0s20f3 ARGS='-f "tcp port 80"'` |
| Save to pcap | `make run IFACE=wlp0s20f3 ARGS='-w out.pcap'` |
| Run all tests | `make test` |
| Run benchmarks | `make bench` |
| Check coverage | `make cover` |
| Lint | `make lint` |
| Build Docker | `make docker` |
| Generate traffic | `bash scripts/test_traffic.sh` |
