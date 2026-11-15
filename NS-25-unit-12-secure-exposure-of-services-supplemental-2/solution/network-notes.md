# Exposure transfer: close a direct-path bypass

## Context and boundary

Record the owned VM, UID, host and namespace identities, tool versions, command and purpose.

## Predict before observing

The router already supplies working forwarding, SNAT and DNAT. Its new-connection policy matches the translated server endpoint without restricting the original published endpoint. Predict both the mapped and direct requests. Retain the direct-path exposure, then restore only the original-destination and original-port match in the filter case of lab-rules.sh.

## First observation

Retain the unmodified first report, raw outputs and actual endpoint/process identities. Identify the first unsupported or differing claim.

## Single change and comparison

Keep the exact setting/rule change, new report and an explanation tied to actual observations. Preserve all other supplied code.

## Recovery and limits

Record child reaping, namespace/remaining-interface evidence, unchanged outer configuration and a conclusion that remains unsupported.

## Reference reasoning

Both routes arrive at FORWARD with translated destination 10.20.0.2:8080. Requiring the original destination 10.10.0.1 and port 18080 keeps the mapped entry usable and denies a fresh direct request. The final direct request after private-filter removal proves that the policy comparison did not depend on stopping the listener.

This is configuration reasoning. Fill in current run tokens, process IDs, observations and cleanup from a fresh run.
