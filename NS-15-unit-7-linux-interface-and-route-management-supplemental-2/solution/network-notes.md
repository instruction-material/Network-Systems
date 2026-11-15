# Routing transfer: diagnose an SNAT source match

## Context and boundary

Record the owned VM, UID, host and namespace identities, tool versions, command and purpose.

## Predict before observing

The supplied route and forwarding work, but the SNAT rule selects a different client subnet. Predict which HTTP requests still succeed and which peer address the server reports. Keep the first report, then correct only the source-prefix match in the snat case of lab-rules.sh. Explain why a successful routed request does not demonstrate that translation matched.

## First observation

Retain the unmodified first report, raw outputs and actual endpoint/process identities. Identify the first unsupported or differing claim.

## Single change and comparison

Keep the exact setting/rule change, new report and an explanation tied to actual observations. Preserve all other supplied code.

## Recovery and limits

Record child reaping, namespace/remaining-interface evidence, unchanged outer configuration and a conclusion that remains unsupported.

## Reference reasoning

The actual client is 10.10.0.2/24. Matching its 10.10.0.0/24 source range makes the selected requests leave rr0 with source 10.20.0.1. The routed request before SNAT still reports 10.10.0.2. A result for this one owned client does not establish behavior for every address in the subnet.

This is configuration reasoning. Fill in current run tokens, process IDs, observations and cleanup from a fresh run.
