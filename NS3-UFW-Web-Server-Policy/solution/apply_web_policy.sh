#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
	echo "Run this script as root so UFW changes can be applied." >&2
	exit 1
fi

echo "Applying safe web-server rollout policy"
ufw allow OpenSSH
ufw allow 80/tcp
ufw allow 443/tcp
ufw logging on
ufw --force enable
echo
echo "Current numbered rules:"
ufw status numbered
echo
echo "Verification checklist:"
echo "- confirm SSH still works from another terminal"
echo "- confirm HTTP or HTTPS answers from another host"
echo "- confirm unused ports still show refusal or timeout"
