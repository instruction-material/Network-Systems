# Service Exposure Transfer Practice worked notebook

## Keep binding and probe families distinct

A server's local socket snapshot and a client's request answer different
questions. Record both the originating namespace and the destination family
before combining them.

**Worked binding:** baseline.backendBind4 is loopback. backendBind6 is
not_listed in the supplied socket snapshot. This states what that snapshot
shows; a new or different listener requires a fresh observation. The actual
directUpstream command targets the external IPv6 server address on port 9000,
so directBackend.family is the number 6 and its result is request_failed.

That one IPv6 failure is not an IPv4 client test of the IPv4 loopback backend,
and it does not isolate a firewall cause by itself. To investigate a live
version, compare a server-local IPv4 loopback request, an owned IPv4 peer
request, the actual binding and the corresponding policy. Preserve each
origin/family rather than collapsing them into "port open" or "port closed."

**Worked transfer:** alternate changes the front port to 8087 and name to
amber.capstone.test. Its two application answers remain intended_application;
backendBind4 remains loopback and directBackend.family remains 6.
Inspect the command arguments instead of assuming the default port or name.

**Worked mixed result:** route-gap.application4 is request_failed,
application6 is intended_application and firstBoundary is ipv4_route.
Use the failed IPv4 lookup and excluded .2 address to explain the difference.
An IPv6 success supplies an IPv6 result.


## Evidence locations and conclusion

The record IDs above name complete captured command/result objects in observations.json. Read original argv, family, exit code and response identity together. Preserve the actual .2 destination when comparing the /31 route. The baseline and changed records are different historical attempts with different run markers; compare each body with its own marker.

## Next measurement and scope

Choose the proposed follow-up named above and state the originating node, endpoint, family and expected observation. The supplied record answers remain bounded to their named clients and time. No VPN, BGP, wireless, cloud or public-ingress execution is inferred from this assessment. A live rerun retains its capstone receipt, original failure and cleanup evidence.
