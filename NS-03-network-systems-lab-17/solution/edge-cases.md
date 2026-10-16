# Boundary and recovery cases

## Preserve cause before changing configuration

Retain the original run with both intentional faults. A wrong destination
prefix can prevent the IPv4 request before any application exchange occurs.
The working IPv6 resolver transport can still return an A record. Explain why
that answer does not establish IPv4 connectivity. Correct only the route and
record how the first failure moves to the proxy/upstream boundary.

## Distinguish a proxy reply from an application reply

Capture the configured upstream port, actual loopback listener, HTTP 502 and
the later application response. Check the expected body and per-run token.
Then compare the application's 404 with a failed connection. State which
process generated each response and which request actually reached it.

## Prove the denial control exists

Use recorded listener/process evidence for both TCP 8088 sockets before
interpreting failed client probes as policy evidence. Compare the declared
client/port rules with actual IPv4 and IPv6 results. Explain why a loopback-only
backend and an externally denied listening control demonstrate different
boundaries. IPv6 control traffic has a separate role from the allowed service.

## Changed inputs and bounded observation

Predict the alternate client links, name and proxy port. Compare actual DNS
resource data with the destinations subsequently used by the clients. Keep
the original packet bytes with the textual decoder, then explain what the
capture filter, packet limit, plaintext fixture and run deadline omit.

## Failure and interruption cleanup

Retain nonzero, prerequisite-failure and interrupted attempts separately from
a completed case. Confirm the actual worker end records, empty owned namespace
list and unchanged calling-host configuration. No persistent host firewall,
resolver, default route or service change is a recovery step for this fixture.
Use a new output folder for every attempt so earlier evidence is preserved.
