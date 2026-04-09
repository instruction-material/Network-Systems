# NS6 Router NAT Topology Lab

Simulate a routed environment with isolated segments and controlled exposure.

## Goals

- build a tiny routed topology with Linux network namespaces
- inspect addresses, routes, forwarding, and selective exposure
- explain which host is acting as the router and what it is forwarding

## Starter Expectations

- finish the forwarding and validation steps
- explain the route tables in each namespace
- decide which service should be reachable and why

## Solution Highlights

- builds a disposable client, router, and server namespace topology
- enables forwarding and a simple edge path
- provides clear follow-up verification commands
