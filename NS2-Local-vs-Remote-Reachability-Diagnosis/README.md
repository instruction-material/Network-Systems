# NS2 Local vs Remote Reachability Diagnosis

Diagnose a service that works locally but fails from another machine.

## Goals

- compare localhost success to remote reachability
- separate listener, route, and firewall evidence
- classify failures as timeout, refusal, or reset

## Starter Expectations

- add route and firewall inspection to the checklist
- record the first observed failure signature before changing config
- explain why local success alone is not enough

## Solution Highlights

- checks service state, host addressing, route state, and a remote probe path
- prompts students to classify the failure before they fix it
- produces a structured troubleshooting record instead of ad hoc notes
