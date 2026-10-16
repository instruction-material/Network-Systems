#!/usr/bin/env bash
set -euo pipefail

# Record predictions before completing the count and port-filter choices.
# packetLimit: an integer from 1 through 64 selects -c; 0 omits that option.
# filterPort: true selects only the owned service on port 8080; false includes both ports.
# The apparatus always provides -nn and a separate wall-clock deadline.
printf '%s\n' '{"packetLimit":0,"filterPort":false}'
