# Capture transfer: retain enough evidence for an HTTP claim

## Context and boundary

Record the owned VM, UID, host and namespace identities, tool versions, command and purpose.

## Predict before observing

The filter already selects the owned HTTP service, but the two-packet ceiling ends capture before the HTTP exchange is retained. Predict the capture independently of the application's successful responses. Preserve the short first capture, then change only packetLimit in capture-options.sh to a positive value at most 64 that retains the complete target evidence. The reference uses 64; also compare a fresh run with 32.

## First observation

Retain the unmodified first report, raw outputs and actual endpoint/process identities. Identify the first unsupported or differing claim.

## Single change and comparison

Keep the exact setting/rule change, new report and an explanation tied to actual observations. Preserve all other supplied code.

## Recovery and limits

Record child reaping, namespace/remaining-interface evidence, unchanged outer configuration and a conclusion that remains unsupported.

## Reference reasoning

A two-packet capture can stop at connection establishment even when the HTTP request later succeeds. A complete HTTP claim needs the retained request, response and run identity, not only SYN traffic. Raising the ceiling preserves the selection filter and lets the owned exchange be captured. The apparatus still owns a separate wall-clock and cleanup bound.

This is configuration reasoning. Fill in current run tokens, process IDs, observations and cleanup from a fresh run.
