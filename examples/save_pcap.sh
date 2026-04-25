#!/usr/bin/env bash
# Capture all traffic and save to a timestamped .pcap file
set -euo pipefail

IFACE=${1:-eth0}
OUTFILE="captures/capture_$(date +%Y%m%d_%H%M%S).pcap"

mkdir -p captures
echo "Saving to $OUTFILE — press Ctrl+C to stop"
sudo ./bin/gopacketsniffer -i "$IFACE" -w "$OUTFILE"
echo "Saved: $OUTFILE"
