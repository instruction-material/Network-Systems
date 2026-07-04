#!/usr/bin/env bash
set -euo pipefail

#################
#   CONSTANTS   #
#################
readonly ROOT_USER_ID="0"
readonly SSH_SERVICE_NAME="OpenSSH"
readonly HTTP_PORT_RULE="80/tcp"
readonly HTTPS_PORT_RULE="443/tcp"

#################
#   MAIN CODE   #
#################
# Require root because firewall changes affect host connectivity
if [[ "${EUID:-$(id -u)}" -ne "$ROOT_USER_ID" ]]; then
	echo "Run this script as root so UFW changes can be applied." >&2
	exit 1
fi

echo "Applying safe web-server rollout policy"
ufw allow "$SSH_SERVICE_NAME"
ufw allow "$HTTP_PORT_RULE"
ufw allow "$HTTPS_PORT_RULE"
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
