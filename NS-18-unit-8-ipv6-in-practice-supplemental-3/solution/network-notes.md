# IPv6 observation notebook

## Machine, account and prediction

Record the actual host, UID, namespace, tools and run command. Predict the IPv4
and IPv6 outcome in each binding mode before observing either response.

## Actual IPv6 path and family comparison

Keep the raw address, route and neighbor records. Match readyLine, /proc UID,
ss PID/address/port, the selected curl command, response token and child request.
Explain the held non-listening IPv4 control. Distinguish the paired sockets.
Record worker reaping and the final PID-based socket comparison.

## Prefix and scope reasoning

Calculate the requested prefix table independently. Record address count,
normalized prefix, membership and offsets. Explain loopback, link-local zone
identity and why documentation-prefix arithmetic does not establish a live path.

## Supplied cases, separately labeled

For Case A, trace DNS, route, neighbor and service interface evidence. Name the
earliest unsupported boundary and the next approved observation.
For Case B, distinguish IPv4 policy, IPv6 policy, packet counters and HTTP.
For Case C, identify missing zone/interface information and distinguish Router
Advertisement information, address configuration and a selected default route.

## Limits and review

Separate actual measurements from supplied model records. Keep unexpected
results and the evidence that could disprove the explanation. Do not claim
active Neighbor Discovery, Router Advertisement, DHCPv6 or firewall observations
from the loopback run. The optional analysis is not notebook completion.

## Reference interpretation of the supplied records

This is a worked interpretation of the constructed cases, not a measured report.
Insert actual host, port, token and command evidence from a separate reference
run rather than copying invented values into a personal notebook.

Case A has a successful DNS answer and an on-link route but no usable neighbor
for the AAAA destination. The supplied service inventory lacks that intended
address. Compare the authorized configuration plan with actual assignment before
choosing a DNS correction or interface repair. The later supplied successful
request is evidence for that modeled correction, not an action by this program.

Case B supplies an IPv6 listener and a reachable neighbor, plus an IPv6 DROP
counter increase. Its policy evidence differs from the IPv4 ACCEPT evidence.
Counters locate matched packets; the later fresh HTTP 200 separately establishes
the modeled application result after the approved IPv6 policy change.

Case C lacks the outgoing interface for a link-local next hop. A numeric value
alone cannot select between the two links. A Router Advertisement's prefix and
router information have separate effects, and a DHCPv6 lease alone establishes
neither the chosen default router nor application reachability.
