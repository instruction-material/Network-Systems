# Routing extension: locate a translated destination-port fault

## Context and boundary

Record the owned VM, UID, host and namespace identities, tool versions, command and purpose.

## Predict before observing

Direct routing and SNAT work. The public-side mapping selects a server port without the owned HTTP listener. Predict the first differing stage, retain the mapped-request failure, then correct only the destination port in the dnat case of lab-rules.sh. Reconcile the requested router endpoint with the actual server listener.

## First observation

Retain the unmodified first report, raw outputs and actual endpoint/process identities. Identify the first unsupported or differing claim.

## Single change and comparison

Keep the exact setting/rule change, new report and an explanation tied to actual observations. Preserve all other supplied code.

## Recovery and limits

Record child reaping, namespace/remaining-interface evidence, unchanged outer configuration and a conclusion that remains unsupported.

## Reference reasoning

The requested router endpoint remains 10.10.0.1:18080, while the owned listener is 10.20.0.2:8080. Changing the DNAT destination port to 8080 restores the mapped request. The later mapping removal still breaks a fresh mapped request while a direct request continues to work.

This is configuration reasoning. Fill in current run tokens, process IDs, observations and cleanup from a fresh run.
