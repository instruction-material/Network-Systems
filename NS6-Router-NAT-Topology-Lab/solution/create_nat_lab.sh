#!/usr/bin/env bash
set -euo pipefail

#################
#   CONSTANTS   #
#################
readonly ROOT_USER_ID="0"
readonly CLIENT_NAMESPACE="clientns"
readonly ROUTER_NAMESPACE="routerns"
readonly SERVER_NAMESPACE="serverns"
readonly CLIENT_VETH="veth-client"
readonly ROUTER_LEFT_VETH="veth-router-left"
readonly SERVER_VETH="veth-server"
readonly ROUTER_RIGHT_VETH="veth-router-right"
readonly CLIENT_ADDRESS="10.10.0.2/24"
readonly CLIENT_GATEWAY="10.10.0.1"
readonly SERVER_ADDRESS="10.20.0.2/24"
readonly SERVER_GATEWAY="10.20.0.1"
readonly ROUTER_LEFT_ADDRESS="10.10.0.1/24"
readonly ROUTER_RIGHT_ADDRESS="10.20.0.1/24"
readonly -a NETWORK_NAMESPACES=("$CLIENT_NAMESPACE" "$ROUTER_NAMESPACE" "$SERVER_NAMESPACE")

#################
#   MAIN CODE   #
#################
# Require root because network namespaces and forwarding affect the host
if [[ "${EUID:-$(id -u)}" -ne "$ROOT_USER_ID" ]]; then
	echo "Run this lab as root because network namespaces and forwarding are required." >&2
	exit 1
fi

# Remove any previous lab namespaces so the setup is repeatable
for namespace in "${NETWORK_NAMESPACES[@]}"; do
	ip netns del "$namespace" 2>/dev/null || true
done

# Create the three namespaces used by the topology
ip netns add "$CLIENT_NAMESPACE"
ip netns add "$ROUTER_NAMESPACE"
ip netns add "$SERVER_NAMESPACE"

# Create the veth pairs that connect client-router and server-router sides
ip link add "$CLIENT_VETH" type veth peer name "$ROUTER_LEFT_VETH"
ip link add "$SERVER_VETH" type veth peer name "$ROUTER_RIGHT_VETH"

# Move each veth endpoint into its assigned namespace
ip link set "$CLIENT_VETH" netns "$CLIENT_NAMESPACE"
ip link set "$ROUTER_LEFT_VETH" netns "$ROUTER_NAMESPACE"
ip link set "$SERVER_VETH" netns "$SERVER_NAMESPACE"
ip link set "$ROUTER_RIGHT_VETH" netns "$ROUTER_NAMESPACE"

# Configure the client namespace interface and default route
ip -n "$CLIENT_NAMESPACE" addr add "$CLIENT_ADDRESS" dev "$CLIENT_VETH"
ip -n "$CLIENT_NAMESPACE" link set "$CLIENT_VETH" up
ip -n "$CLIENT_NAMESPACE" link set lo up
ip -n "$CLIENT_NAMESPACE" route add default via "$CLIENT_GATEWAY"

# Configure the server namespace interface and default route
ip -n "$SERVER_NAMESPACE" addr add "$SERVER_ADDRESS" dev "$SERVER_VETH"
ip -n "$SERVER_NAMESPACE" link set "$SERVER_VETH" up
ip -n "$SERVER_NAMESPACE" link set lo up
ip -n "$SERVER_NAMESPACE" route add default via "$SERVER_GATEWAY"

# Configure the router namespace interfaces
ip -n "$ROUTER_NAMESPACE" addr add "$ROUTER_LEFT_ADDRESS" dev "$ROUTER_LEFT_VETH"
ip -n "$ROUTER_NAMESPACE" addr add "$ROUTER_RIGHT_ADDRESS" dev "$ROUTER_RIGHT_VETH"
ip -n "$ROUTER_NAMESPACE" link set "$ROUTER_LEFT_VETH" up
ip -n "$ROUTER_NAMESPACE" link set "$ROUTER_RIGHT_VETH" up
ip -n "$ROUTER_NAMESPACE" link set lo up

# Enable forwarding inside the router namespace
ip netns exec "$ROUTER_NAMESPACE" sysctl -w net.ipv4.ip_forward=1

echo "Topology created."
echo
echo "Suggested verification commands:"
echo "sudo ip netns exec clientns ping -c 2 10.10.0.1"
echo "sudo ip netns exec clientns ping -c 2 10.20.0.2"
echo "sudo ip netns exec clientns ip route"
echo "sudo ip netns exec serverns ip route"
