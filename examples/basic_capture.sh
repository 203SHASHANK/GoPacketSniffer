#!/usr/bin/env bash
# Basic capture on the default interface
set -euo pipefail

IFACE=${1:-eth0}
sudo ./bin/gopacketsniffer -i "$IFACE"
