# NS4 IPv4 vs IPv6 Resolution Comparison

Compare A and AAAA resolution for the same hostname and explain likely client
behavior.

## Goals

- inspect both IPv4 and IPv6 answers
- compare multiple resolver views
- connect DNS answers to likely client connection behavior

## Starter Expectations

- add clearer IPv6 interpretation notes
- explain what changes when only one address family resolves
- note how local overrides such as `/etc/hosts` would change the result

## Solution Highlights

- collects A and AAAA answers cleanly
- prints both raw resolver output and simplified summaries
- turns dual-stack resolution into a short diagnostic explanation
