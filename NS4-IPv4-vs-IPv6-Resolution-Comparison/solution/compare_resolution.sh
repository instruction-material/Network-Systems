#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo 'usage: bash compare_resolution.sh [NAME [DNS_SERVER [DNS_PORT]]]' >&2
    exit 2
}
[[ $# -le 3 ]] || usage
query_name="${1:-example.com}"
resolver_address="${2:-}"
resolver_port="${3:-53}"
[[ "$query_name" =~ ^[[:alnum:]_][-[:alnum:]_.]*$ ]] || usage
[[ -z "$resolver_address" || "$resolver_address" =~ ^[[:alnum:]_:][-[:alnum:]_.:]*$ ]] || usage
[[ "$resolver_port" =~ ^[0-9]{1,5}$ ]] || usage
resolver_port=$((10#$resolver_port))
((resolver_port >= 1 && resolver_port <= 65535)) || usage
[[ $# -lt 3 || -n "$resolver_address" ]] || usage
[[ $(uname -s) == Linux ]] || { echo 'This exercise requires Linux.' >&2; exit 2; }
for tool in timeout dig getent; do
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
resolver_args=()
if [[ -n "$resolver_address" ]]; then
    resolver_args=("@$resolver_address")
fi
printf '# DNS and system name-service observations\n'
printf 'Question name: %s\nDNS server: %s; DNS port: %s\n' "$query_name" "${resolver_address:-configured DNS resolver}" "$resolver_port"
printf 'The selected server applies only to dig. getent uses this system NSS configuration.\n'
probe 'DNS A response' dig +time=2 +tries=1 "${resolver_args[@]}" -p "$resolver_port" "$query_name" A
probe 'DNS AAAA response' dig +time=2 +tries=1 "${resolver_args[@]}" -p "$resolver_port" "$query_name" AAAA

# TASK-BEGIN system-lookup
probe 'System NSS address view' getent ahosts "$query_name"
# TASK-END system-lookup

cat <<'REVIEW'

## Interpret the two lookup paths
Read the DNS response status, answer types, TTL and responding server as well
as the command status. NOERROR with no AAAA answer is not a failed command.
An absent AAAA answer does not prove that a service or machine is IPv4-only.
A CNAME is an alias record; follow the actual typed address answers separately.
System NSS can use local hosts data and address-family policy as well as DNS;
getent does not automatically use the explicit dig server or its port.
No application connection, IPv6 data path or preferred client family was tested.
No hosts, resolver, name-service, route or firewall configuration was changed.
REVIEW
