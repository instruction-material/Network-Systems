#!/usr/bin/env bash
set -euo pipefail
stage="${1:?expected forwarding, snat, or dnat}"
router="${2:?expected the owned router namespace}"
case "$stage" in
  forwarding)
    ip netns exec "$router" sysctl -qw net.ipv4.ip_forward=1
    ;;
  snat)
    ip netns exec "$router" iptables -t nat -A POSTROUTING \
      -s 10.10.0.0/24 -d 10.20.0.2/32 -p tcp --dport 8080 \
      -o rr0 -j SNAT --to-source 10.20.0.1
    ;;
  dnat)
    ip netns exec "$router" iptables -t nat -A PREROUTING \
      -i rl0 -d 10.10.0.1/32 -p tcp --dport 18080 \
      -j DNAT --to-destination 10.20.0.2:8080
    ;;
  *) printf 'Unknown stage: %s\n' "$stage" >&2; exit 2 ;;
esac
