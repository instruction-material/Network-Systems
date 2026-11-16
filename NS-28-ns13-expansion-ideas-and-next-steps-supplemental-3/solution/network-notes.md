# Next Steps Extension Practice worked notebook

## Audit the scope of an advanced networking claim

A working private application path supports a local reachability conclusion.
Advanced claims need the measurements belonging to that additional boundary.

**Worked local claim:** baseline.application4 and application6 are
intended_application. That supports the recorded client's two private paths.
vpnTunnel, bgpPolicy, wirelessSecurity and cloudSecurityGroup are
not_established: the supplied measurements concern a wired namespace topology,
its static routes and host filtering. They include no tunnel exchange, BGP
peer/announcement, radio authentication or provider security-group observation.

**Worked counterexample:** open-control.control4 and control6 are
control_response. The recorded client now reaches the deliberately admitted
control at 8088. otherClients and internetExposure remain not_established.
One successful source does not establish the behavior of every source or a
path through a public edge.

Choose two claims: one supported by a specific command/result and one requiring
a new measurement. For the latter, draw the extra component and identify the
evidence it would produce in an approved later lab. A tunnel comparison can
identify inner/outer traffic and route selection; a BGP comparison needs a
routing-peer/announcement view; wireless needs radio/authentication evidence;
cloud policy needs its provider-side boundary and a measured request path.

Conceptual reading: [IPsec architecture](https://www.rfc-editor.org/rfc/rfc4301),
[BGP-4](https://www.rfc-editor.org/rfc/rfc4271) and
[NIST WLAN guidance](https://csrc.nist.gov/pubs/sp/800/153/final).


## Evidence locations and conclusion

The record IDs above name complete captured command/result objects in observations.json. Read original argv, family, exit code and response identity together. Preserve the actual .2 destination when comparing the /31 route. The baseline and changed records are different historical attempts with different run markers; compare each body with its own marker.

## Next measurement and scope

Choose the proposed follow-up named above and state the originating node, endpoint, family and expected observation. The supplied record answers remain bounded to their named clients and time. No VPN, BGP, wireless, cloud or public-ingress execution is inferred from this assessment. A live rerun retains its capstone receipt, original failure and cleanup evidence.
