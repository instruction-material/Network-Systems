#!/usr/bin/env bash
set -euo pipefail

echo "Starter rollout order:"
echo "1. allow OpenSSH"
echo "2. allow 80/tcp"
echo "3. enable ufw"
echo
echo "Suggested commands:"
echo "sudo ufw allow OpenSSH"
echo "sudo ufw allow 80/tcp"
echo "sudo ufw enable"
echo
echo "TODO:"
echo "- add numbered-rule checks"
echo "- add logging review"
echo "- decide whether HTTPS is also required"
