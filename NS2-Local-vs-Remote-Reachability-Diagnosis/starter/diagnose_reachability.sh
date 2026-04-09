#!/usr/bin/env bash
set -euo pipefail

host="${1:-127.0.0.1}"
port="${2:-8080}"

echo "Checking local listener state for port $port"
ss -ltn "( sport = :$port )" || true
echo
echo "Checking localhost probe"
curl --max-time 3 -I "http://127.0.0.1:$port" || true
echo
echo "Checking remote-style probe to $host:$port"
nc -vz "$host" "$port" || true
echo
echo "TODO:"
echo "- inspect ip addr and ip route"
echo "- inspect firewall policy"
echo "- classify the failure as timeout, refusal, or reset"
