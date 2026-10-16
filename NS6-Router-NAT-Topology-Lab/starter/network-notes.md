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
