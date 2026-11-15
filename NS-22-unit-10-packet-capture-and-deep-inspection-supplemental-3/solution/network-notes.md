# Capture extension: separate the selected service from nearby traffic

## Context and boundary

Record the owned VM, UID, host and namespace identities, tool versions, command and purpose.

## Predict before observing

The capture is bounded, but its expression includes traffic to a second owned loopback listener. Predict the target and noise conversations before reading the packets. Preserve the broad first capture, then change only filterPort in capture-options.sh. Compare default and --reverse request order with fresh reports so a successful selection cannot depend on which request happened first.

## First observation

Retain the unmodified first report, raw outputs and actual endpoint/process identities. Identify the first unsupported or differing claim.

## Single change and comparison

Keep the exact setting/rule change, new report and an explanation tied to actual observations. Preserve all other supplied code.

## Recovery and limits

Record child reaping, namespace/remaining-interface evidence, unchanged outer configuration and a conclusion that remains unsupported.

## Reference reasoning

The selected service is TCP 8080; the nearby owned noise listener is TCP 8081. Enabling the destination-or-source port selection keeps the target conversation and excludes the other service in either request order. A port filter selects packets; it does not establish that the application outcome was useful or that every packet on another interface was observed.

This is configuration reasoning. Fill in current run tokens, process IDs, observations and cleanup from a fresh run.
