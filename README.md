# Network Systems

This folder is structured as the future
`instruction-material/Network-Systems` repository.

The materials follow the main project sequence used by the site course:

1. `NS1-Listening-Services-Map`
2. `NS2-Local-vs-Remote-Reachability-Diagnosis`
3. `NS3-UFW-Web-Server-Policy`
4. `NS4-IPv4-vs-IPv6-Resolution-Comparison`
5. `NS5-Tcpdump-HTTP-Capture`
6. `NS6-Router-NAT-Topology-Lab`

Each project contains:

- `starter/` with a guided scaffold and TODO-style follow-up work
- `solution/` with a fuller reference workflow
- `README.md` describing the networking goal and the evidence students should
  collect

## Tooling

Preferred IDE:

- `VS Code`

Expected local toolchain:

- a real Linux shell or VM
- `ssh`
- `curl`
- `dig`
- `ip`
- `ss`
- `ufw`
- `tcpdump`

## Local Validation Workflow

These scripts are written for Linux networking labs. In this environment they
were validated with shell syntax checks:

1. `find . -name '*.sh' -print0 | xargs -0 bash -n`

Runtime execution should happen on a Linux host, VM, WSL instance, or disposable
cloud system where `ip`, `ss`, `ufw`, and packet capture tools are available.

## Teaching Notes

- every lab should end with a short explanation of what the evidence proved
- repeat failure signatures: timeout, refusal, reset, bad DNS, wrong route
- keep one running glossary for ports, protocols, layers, and common tools
