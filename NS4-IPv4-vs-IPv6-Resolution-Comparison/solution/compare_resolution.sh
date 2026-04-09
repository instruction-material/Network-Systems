#!/usr/bin/env bash
set -euo pipefail

hostname="${1:-example.com}"

require_command() {
	if ! command -v "$1" >/dev/null 2>&1; then
		echo "missing required command: $1" >&2
		exit 1
	fi
}

for required in dig host; do
	require_command "$required"
done

echo "== dig A =="
dig +short A "$hostname"
echo

echo "== dig AAAA =="
dig +short AAAA "$hostname"
echo

echo "== host summary =="
host "$hostname" || true
echo

echo "== interpretation checklist =="
echo "- If only A records appear, the service is effectively IPv4-only from DNS."
echo "- If both A and AAAA appear, the client may choose either family depending on resolver and stack behavior."
echo "- If DNS answers look correct but only one family fails, inspect binding, routes, and firewall policy for that family."
