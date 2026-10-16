# Router and NAT observations

Before running, predict the gateway used by a client request for 10.20.0.2 and
the server's return path. Explain why forwarding is separate from those routes.

| Stage | Predicted result and peer | Measured result and peer | Supporting rule/route |
| --- | --- | --- | --- |
| forwarding-off | | | |
| routed | | | |
| snat | | | |
| dnat | | | |
| mapping-removed | | | |
| direct-after-removal | | | |

Explain why the DNAT request also undergoes SNAT. Identify what changed after
removing the mapping and what remained. Why is NAT unnecessary for basic routing
between these two private networks? Which observations would still be needed
before claiming a restrictive firewall policy or public Internet reachability?

Record the run token, output filename, completion status, cleanup evidence and
whether the original host state was unchanged. Leave measured fields blank until
they are supported by an actual run.

## Unit12 Secure Exposure continuation

Continue the Unit7 attempt with `--exposure-policy`. Before adding the fourth
case, predict which original and translated endpoint fields FORWARD will see.
Explain why an allow rule using only the translated server port is insufficient.

| Stage | Prediction | Actual fresh request and peer | Policy/rule counters |
| --- | --- | --- | --- |
| policy-baseline-direct | | | |
| policy-baseline-mapped | | | |
| policy-mapped-allowed | | | |
| policy-direct-blocked | | | |
| policy-direct-restored | | | |

Record the exact original-destination NEW rule, the established/related rule,
the FORWARD policy, and their measured counters. Explain which change restored
direct access and how the response token ties the observations to the same live
server. Keep routes/NAT evidence beside the filter evidence.

Does the test cover existing connections, IPv6, router-local services, other
clients or public Internet access? State the limits and the additional evidence
each broader claim would require. Record cleanup and host configuration checks
for this run as well as for the earlier Unit7 run.
