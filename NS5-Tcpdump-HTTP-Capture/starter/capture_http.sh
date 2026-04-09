#!/usr/bin/env bash
set -euo pipefail

interface="${1:-eth0}"
host_filter="${2:-127.0.0.1}"
port_filter="${3:-80}"

echo "Starter capture command:"
echo "sudo tcpdump -i $interface host $host_filter and tcp port $port_filter"
echo
echo "TODO:"
echo "- add -nn so names do not hide raw evidence"
echo "- limit the capture to a small packet count"
echo "- explain which packets show the request and which show the response"
