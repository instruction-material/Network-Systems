#!/usr/bin/env bash
set -euo pipefail

# Bound the packet count and select port 8080; -nn is part of the supplied apparatus.
# The supplied apparatus separately owns and bounds the traffic and capture.
printf '%s\n' '{"packetLimit":64,"filterPort":true}'
