#!/usr/bin/env bash
set -euo pipefail

#################
#   CONSTANTS   #
#################
readonly DEFAULT_OUTPUT_FILE="listening-services-report.md"
readonly -a REQUIRED_COMMANDS=(ss lsof)

#################
#   FUNCTIONS   #
#################
# Require one command before the report tries to use it
require_command() {
	# Stop early when a required diagnostic command is missing
	if ! command -v "$1" >/dev/null 2>&1; then
		echo "missing required command: $1" >&2
		exit 1
	fi
}

#################
#   MAIN CODE   #
#################
# Read the optional report path from the command line
output_file="${1:-$DEFAULT_OUTPUT_FILE}"

# Verify every command needed for the inventory
for required_command in "${REQUIRED_COMMANDS[@]}"; do
	require_command "$required_command"
done

# Build the listener report with command output and review prompts
{
	echo "# Listening Services Report"
	echo
	echo "Generated: $(date -u)"
	echo
	echo "## TCP listeners with process mapping"
	ss -ltnp
	echo
	echo "## UDP listeners with process mapping"
	ss -lunp
	echo
	echo "## Open internet sockets from lsof"
	lsof -nP -iTCP -sTCP:LISTEN
	echo
	echo "## Review checklist"
	echo "- Which listeners are expected for this host role?"
	echo "- Which listeners should be limited by firewall policy?"
	echo "- Which listeners require a remote test before claiming they are reachable?"
} >"$output_file"

echo "Wrote solution report to $output_file"
