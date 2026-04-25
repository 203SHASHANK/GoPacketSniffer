#!/usr/bin/env bash
# Generate a mix of test traffic to exercise the sniffer.
# Run this in a second terminal while gopacketsniffer is running.
set -euo pipefail

echo "Generating test traffic..."

# HTTP
curl -s http://example.com > /dev/null && echo "HTTP GET done"

# HTTPS (TCP handshake visible, payload encrypted)
curl -s https://example.com > /dev/null && echo "HTTPS GET done"

# ICMP
ping -c 4 8.8.8.8 && echo "ICMP ping done"

# DNS (UDP port 53)
nslookup google.com > /dev/null && echo "DNS query done"

echo "Done."
