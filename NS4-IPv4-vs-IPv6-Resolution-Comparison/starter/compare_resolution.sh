#!/usr/bin/env bash
set -euo pipefail

hostname="${1:-example.com}"

echo "A records for $hostname"
dig +short A "$hostname"
echo
echo "AAAA records for $hostname"
dig +short AAAA "$hostname"
echo
echo "TODO:"
echo "- compare resolver tools"
echo "- explain which family a client might try first"
echo "- note what a missing AAAA answer implies"
