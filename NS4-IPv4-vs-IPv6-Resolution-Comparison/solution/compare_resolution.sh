#!/usr/bin/env bash
set -euo pipefail

#################
#   CONSTANTS   #
#################
readonly DEFAULT_HOSTNAME="example.com"
readonly IPV4_RECORD_TYPE="A"
readonly IPV6_RECORD_TYPE="AAAA"
readonly -a REQUIRED_COMMANDS=(dig host)

#################
#   FUNCTIONS   #
#################
# Require one command before the comparison tries to use it
require_command() {
	# Stop early when a required DNS command is missing
	if ! command -v "$1" >/dev/null 2>&1; then
		echo "missing required command: $1" >&2
		exit 1
	fi
}

#################
#   MAIN CODE   #
#################
# Read the optional hostname from the command line
hostname="${1:-$DEFAULT_HOSTNAME}"

# Verify every command needed for the DNS comparison
for required_command in "${REQUIRED_COMMANDS[@]}"; do
	require_command "$required_command"
done

echo "== dig A =="
dig +short "$IPV4_RECORD_TYPE" "$hostname"
echo

echo "== dig AAAA =="
dig +short "$IPV6_RECORD_TYPE" "$hostname"
echo

echo "== host summary =="
host "$hostname" || true
echo

echo "== interpretation checklist =="
echo "- If only A records appear, the service is effectively IPv4-only from DNS."
echo "- If both A and AAAA appear, the client may choose either family depending on resolver and stack behavior."
echo "- If DNS answers look correct but only one family fails, inspect binding, routes, and firewall policy for that family."
