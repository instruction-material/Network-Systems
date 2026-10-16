#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "usage: bash diagnose_reachability.sh [HOST [PORT [http|https]]]" >&2
    exit 2
}
[[ $# -le 3 ]] || usage
host="${1:-127.0.0.1}"
port="${2:-8080}"
scheme="${3:-http}"
[[ "$host" =~ ^[[:alnum:]_:.][-[:alnum:]_.:]*$ ]] || usage
[[ "$port" =~ ^[0-9]{1,5}$ ]] || usage
port=$((10#$port))
((port >= 1 && port <= 65535)) || usage
[[ "$scheme" == http || "$scheme" == https ]] || usage
[[ $(uname -s) == Linux ]] || { echo 'This exercise requires Linux.' >&2; exit 2; }
for tool in timeout ss curl nc ip; do
    command -v "$tool" >/dev/null || { echo "missing required command: $tool" >&2; exit 2; }
done

# A failed diagnostic is evidence. Retain its status and continue the checklist.
# The outer deadline also bounds resolver stalls and the TCP diagnostic.
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
authority="$host"
local_authority=127.0.0.1
if [[ "$host" == *:* ]]; then
    authority="[$host]"
    local_authority='[::1]'
fi
printf 'Read-only diagnostics from this machine. A target probe here is not a second-machine test.\n'
printf 'Target: %s://%s:%s/\n' "$scheme" "$authority" "$port"
probe 'TCP listener state on this machine' ss -ltnp "sport = :$port"

# TASK-BEGIN route-evidence
probe 'Interface summary on this machine' ip -brief address
probe 'IPv4 routes on this machine' ip -4 route show
probe 'IPv6 routes on this machine' ip -6 route show
# TASK-END route-evidence

probe 'Loopback HTTP observation on this machine' curl --noproxy '*' --connect-timeout 2 --max-time 3 --silent --show-error --head "$scheme://$local_authority:$port/"
probe 'Target HTTP observation from this machine' curl --noproxy '*' --connect-timeout 2 --max-time 3 --silent --show-error --head "$scheme://$authority:$port/"
probe 'Target TCP observation from this machine' nc -vz -w 3 "$host" "$port"

cat <<'NOTES'

Review the command statuses and raw errors before drawing conclusions.
A TCP connection can succeed while an HTTP or TLS exchange fails.
A timeout alone does not locate a firewall or routing fault; a refusal can also
come from a rejecting policy. A reset does not establish application readiness.
Compare binding, addresses, routes and authorized firewall observations, then
repeat from a separate authorized machine before claiming remote reachability.
No service, route, interface, firewall rule or resolver configuration was changed.
NOTES
