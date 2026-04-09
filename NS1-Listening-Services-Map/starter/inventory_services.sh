#!/usr/bin/env bash
set -euo pipefail

output_file="${1:-listening-services-report.md}"

{
	echo "# Listening Services Report"
	echo
	echo "Generated: $(date -u)"
	echo
	echo "## TCP listeners"
	ss -ltn
	echo
	echo "## TODO"
	echo "- add process and user ownership"
	echo "- add UDP listeners"
	echo "- classify which services are expected"
} >"$output_file"

echo "Wrote starter report to $output_file"
