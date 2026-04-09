#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
	echo "Run this lab as root because network namespaces and forwarding are required." >&2
	exit 1
fi

for namespace in clientns routerns serverns; do
	ip netns del "$namespace" 2>/dev/null || true
done

ip netns add clientns
ip netns add routerns
ip netns add serverns

ip link add veth-client type veth peer name veth-router-left
ip link add veth-server type veth peer name veth-router-right

ip link set veth-client netns clientns
ip link set veth-router-left netns routerns
ip link set veth-server netns serverns
ip link set veth-router-right netns routerns

ip -n clientns addr add 10.10.0.2/24 dev veth-client
ip -n clientns link set veth-client up
ip -n clientns link set lo up
ip -n clientns route add default via 10.10.0.1

ip -n serverns addr add 10.20.0.2/24 dev veth-server
ip -n serverns link set veth-server up
ip -n serverns link set lo up
ip -n serverns route add default via 10.20.0.1

ip -n routerns addr add 10.10.0.1/24 dev veth-router-left
ip -n routerns addr add 10.20.0.1/24 dev veth-router-right
ip -n routerns link set veth-router-left up
ip -n routerns link set veth-router-right up
ip -n routerns link set lo up

ip netns exec routerns sysctl -w net.ipv4.ip_forward=1

echo "Topology created."
echo
echo "Suggested verification commands:"
echo "sudo ip netns exec clientns ping -c 2 10.10.0.1"
echo "sudo ip netns exec clientns ping -c 2 10.20.0.2"
echo "sudo ip netns exec clientns ip route"
echo "sudo ip netns exec serverns ip route"
