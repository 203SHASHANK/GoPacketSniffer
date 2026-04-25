#!/usr/bin/env bash
# Capture only HTTP traffic (TCP port 80) in verbose mode
set -euo pipefail

IFACE=${1:-eth0}
sudo ./bin/gopacketsniffer -i "$IFACE" -f "tcp port 80" -v
