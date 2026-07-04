#!/usr/bin/env bash
set -euo pipefail

#################
#   CONSTANTS   #
#################
readonly DEFAULT_HOST="127.0.0.1"
readonly DEFAULT_PORT="8080"
readonly DEFAULT_SCHEME="http"
readonly CURL_TIMEOUT_SECONDS="3"
readonly -a REQUIRED_COMMANDS=(ss ip curl nc)

#################
#   FUNCTIONS   #
#################
# Require one command before the diagnosis tries to use it
check_command() {
	# Stop early when a required diagnostic command is missing
	if ! command -v "$1" >/dev/null 2>&1; then
		echo "missing required command: $1" >&2
		exit 1
	fi
}

#################
#   MAIN CODE   #
#################
# Read optional target settings from the command line
host="${1:-$DEFAULT_HOST}"
port="${2:-$DEFAULT_PORT}"
scheme="${3:-$DEFAULT_SCHEME}"
probe_url="${scheme}://${host}:${port}"

# Verify every command needed for the diagnosis
for required_command in "${REQUIRED_COMMANDS[@]}"; do
	check_command "$required_command"
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
curl --max-time "$CURL_TIMEOUT_SECONDS" -I "http://127.0.0.1:$port" || true
echo

echo "== remote-style probe to $probe_url =="
curl --max-time "$CURL_TIMEOUT_SECONDS" -I "$probe_url" || true
echo

echo "== raw TCP probe =="
nc -vz "$host" "$port" || true
echo

echo "== interpretation checklist =="
echo "- timeout: likely path, firewall, or no-return traffic problem"
echo "- refusal: destination reachable but nothing is listening there"
echo "- reset: TCP conversation started and was actively closed"
echo "- if localhost works but remote host fails, compare bind address, route, and firewall state before editing the app"
