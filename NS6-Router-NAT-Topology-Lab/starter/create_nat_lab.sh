#!/usr/bin/env bash
set -euo pipefail

echo "Starter namespace plan:"
echo "- create client, router, and server namespaces"
echo "- connect them with two veth pairs"
echo "- assign 10.10.0.0/24 and 10.20.0.0/24"
echo "- enable forwarding on the router namespace"
echo
echo "Suggested commands:"
echo "sudo ip netns add clientns"
echo "sudo ip netns add routerns"
echo "sudo ip netns add serverns"
echo
echo "TODO:"
echo "- add addresses and routes"
echo "- add forwarding"
echo "- decide what should be reachable across the router"
