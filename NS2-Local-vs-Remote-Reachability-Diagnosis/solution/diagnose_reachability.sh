#!/usr/bin/env bash
set -euo pipefail

host="${1:-127.0.0.1}"
port="${2:-8080}"
scheme="${3:-http}"

probe_url="${scheme}://${host}:${port}"

check_command() {
	if ! command -v "$1" >/dev/null 2>&1; then
		echo "missing required command: $1" >&2
		exit 1
	fi
}

for required in ss ip curl nc; do
	check_command "$required"
done

echo "== listener state =="
ss -ltnp "( sport = :$port )" || true
echo

echo "== interface summary =="
ip addr show
echo

echo "== route summary =="
ip route show
echo

echo "== localhost probe =="
curl --max-time 3 -I "http://127.0.0.1:$port" || true
echo

echo "== remote-style probe to $probe_url =="
curl --max-time 3 -I "$probe_url" || true
echo

echo "== raw TCP probe =="
nc -vz "$host" "$port" || true
echo

echo "== interpretation checklist =="
echo "- timeout: likely path, firewall, or no-return traffic problem"
echo "- refusal: destination reachable but nothing is listening there"
echo "- reset: TCP conversation started and was actively closed"
echo "- if localhost works but remote host fails, compare bind address, route, and firewall state before editing the app"
