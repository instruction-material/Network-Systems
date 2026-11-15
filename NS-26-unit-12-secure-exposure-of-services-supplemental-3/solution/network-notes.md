# Exposure extension: match the destination after translation

## Context and boundary

Record the owned VM, UID, host and namespace identities, tool versions, command and purpose.

## Predict before observing

The original published tuple is selected, but the new-connection rule compares the packet destination port with the public-side port after DNAT has already changed it. Predict why both baselines work while the legitimate published request fails under this policy. Correct only the packet destination-port match in the filter case of lab-rules.sh.

## First observation

Retain the unmodified first report, raw outputs and actual endpoint/process identities. Identify the first unsupported or differing claim.

## Single change and comparison

Keep the exact setting/rule change, new report and an explanation tied to actual observations. Preserve all other supplied code.

## Recovery and limits

Record child reaping, namespace/remaining-interface evidence, unchanged outer configuration and a conclusion that remains unsupported.

## Reference reasoning

The packet reaching FORWARD uses destination port 8080. The connection's original destination-port match separately names 18080. Keeping these two observations distinct allows the published path without allowing a direct bypass. Both the pre-policy baseline and the restored direct request remain part of the explanation.

This is configuration reasoning. Fill in current run tokens, process IDs, observations and cleanup from a fresh run.
