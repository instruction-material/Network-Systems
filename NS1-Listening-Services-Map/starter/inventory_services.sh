#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo 'usage: bash inventory_services.sh [PORT]' >&2
    exit 2
}
[[ $# -le 1 ]] || usage
port="${1:-}"
if [[ -n "$port" ]]; then
    [[ "$port" =~ ^[0-9]{1,5}$ ]] || usage
    port=$((10#$port))
    ((port >= 1 && port <= 65535)) || usage
fi
[[ $(uname -s) == Linux ]] || { echo 'This exercise requires Linux.' >&2; exit 2; }
for tool in timeout ss lsof readlink; do
    command -v "$tool" >/dev/null || { echo "missing required command: $tool" >&2; exit 2; }
done
probe() {
    local label="$1" status=0
    shift
    printf '\n== %s ==\n' "$label"
    printf 'command:'
    printf ' %q' "$@"
    printf '\n'
    timeout --signal=TERM --kill-after=1s 5s "$@" || status=$?
    printf '\ncommand status: %s\n' "$status"
}
socket_filter=()
if [[ -n "$port" ]]; then
    socket_filter=("sport = :$port")
fi
printf '# Listening services evidence\n'
printf 'Read-only view on this machine for this account; selected port: %s\n' "${port:-all}"
probe 'Current network namespace' readlink /proc/self/ns/net

# TASK-BEGIN inventory-sections
probe 'TCP listener view' ss -ltn "${socket_filter[@]}"
echo 'TODO: compare UDP and visible process ownership; preserve raw statuses.'
# TASK-END inventory-sections

cat <<'REVIEW'

## Review the inventory
An empty selection can produce lsof status 1; inspect its stderr and the ss view
before distinguishing an empty view from an error or limited permission.
Missing owner text does not prove that no process owns a socket.
Classify each observed service as expected, internal-only or review-needed and
record the evidence supporting the choice. UDP UNCONN is not TCP LISTEN.
A local socket inventory does not prove another machine can reach the service.
The script changed no service, route, interface or firewall configuration.
REVIEW
