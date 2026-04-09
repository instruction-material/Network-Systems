#!/usr/bin/env bash
set -euo pipefail

interface="${1:-eth0}"
host_filter="${2:-127.0.0.1}"
port_filter="${3:-80}"
packet_limit="${4:-20}"

echo "Running focused HTTP capture"
echo "Interface: $interface"
echo "Host filter: $host_filter"
echo "Port filter: $port_filter"
echo "Packet limit: $packet_limit"
echo

sudo tcpdump \
	-i "$interface" \
	-nn \
	-c "$packet_limit" \
	"host $host_filter and tcp port $port_filter"
