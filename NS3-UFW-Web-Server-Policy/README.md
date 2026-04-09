# NS3 UFW Web Server Policy

Apply a safe UFW policy for a web server while preserving administration
access.

## Goals

- allow only the intended public service ports
- keep SSH access safe during rollout
- verify host policy with numbered rules and remote tests

## Starter Expectations

- add numbered-rule verification and logging checks
- explain why SSH is allowed before the web rule rollout
- confirm what should stay closed after the policy is applied

## Solution Highlights

- applies a cautious UFW rollout order
- uses a small application profile plus explicit verification
- reinforces that firewall changes are operational changes with recovery steps
