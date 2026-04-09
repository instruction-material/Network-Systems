# NS1 Listening Services Map

Inventory the listening network services on a Linux host.

## Goals

- map TCP and UDP listeners to real processes
- separate expected services from unknown exposure
- explain the difference between a local listener and proven remote reachability

## Starter Expectations

- extend the inventory to cover UDP and clearer process output
- group findings into expected, internal-only, and review-needed services
- explain what extra external test would still be needed

## Solution Highlights

- collects TCP and UDP listeners
- ties listeners back to process evidence
- writes a readable markdown service map
