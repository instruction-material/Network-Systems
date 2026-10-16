#!/usr/bin/env bash
set -euo pipefail
stage="${1:?expected forwarding, snat, dnat, or filter}"
router="${2:?expected the owned router namespace}"
case "$stage" in
  forwarding)
    # TODO: enable IPv4 forwarding only inside "$router" with ip netns exec.
    : "$router"
    ;;
  snat)
    # TODO: translate the client subnet source to 10.20.0.1 for the server service.
    : "$router"
    ;;
  dnat)
    # TODO: map 10.10.0.1:18080 on rl0 to 10.20.0.2:8080.
    : "$router"
    ;;
  filter)
    # Unit12 TODO: allow only new client-to-server requests originally addressed
    # to 10.10.0.1:18080, plus established replies; drop other forwarded traffic.
    # Match conntrack's ORIGINAL destination because DNAT runs before FORWARD.
    : "$router"
    ;;
  *) printf 'Unknown stage: %s\n' "$stage" >&2; exit 2 ;;
esac
