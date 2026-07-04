#!/usr/bin/env bash
set -euo pipefail

#################
#   CONSTANTS   #
#################
readonly DEFAULT_INTERFACE="eth0"
readonly DEFAULT_HOST_FILTER="127.0.0.1"
readonly DEFAULT_PORT_FILTER="80"
readonly DEFAULT_PACKET_LIMIT="20"

#################
#   MAIN CODE   #
#################
# Read optional capture settings from the command line
interface="${1:-$DEFAULT_INTERFACE}"
host_filter="${2:-$DEFAULT_HOST_FILTER}"
port_filter="${3:-$DEFAULT_PORT_FILTER}"
packet_limit="${4:-$DEFAULT_PACKET_LIMIT}"

# Show the exact capture settings before tcpdump starts
echo "Running focused HTTP capture"
echo "Interface: $interface"
echo "Host filter: $host_filter"
echo "Port filter: $port_filter"
echo "Packet limit: $packet_limit"
echo

# Capture matching HTTP traffic using a focused tcpdump filter
sudo tcpdump \
	-i "$interface" \
	-nn \
	-c "$packet_limit" \
	"host $host_filter and tcp port $port_filter"
