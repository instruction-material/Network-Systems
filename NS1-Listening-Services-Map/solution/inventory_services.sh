#!/usr/bin/env bash
set -euo pipefail

output_file="${1:-listening-services-report.md}"

require_command() {
	if ! command -v "$1" >/dev/null 2>&1; then
		echo "missing required command: $1" >&2
		exit 1
	fi
}

require_command ss
require_command lsof

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
