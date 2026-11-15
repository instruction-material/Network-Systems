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
