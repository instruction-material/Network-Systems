# Expansion Ideas and Next Steps worked notebook

## Choose a specialization from a measured baseline

VPN and tunneling add an encapsulated path, so a useful next question is which
traffic selects it and how the inner and outer paths differ. BGP exchanges
reachability and policy between routing peers; one host's static route lookup
provides a foundation rather than a BGP-session observation. Wireless study
adds radio, access-point and authentication considerations to the familiar
address/route/service path. Cloud study adds provider routing and policy
boundaries around the host-level evidence.

Choose one learning goal and draw the extra boundary it would introduce.
For example, "Which destinations would use a tunnel?" needs an existing
working ordinary path, then separate tunnel/interface/route and inner/outer
observations in an approved later lab. This archive establishes the baseline
and plans that next measurement.

**Worked baseline:** baseline has matching A/AAAA answers, successful route
lookups and the intended application response through both families. The
listening control fails from the declared client. Set its readiness to
ready_for_conceptual_extension. The captured topology has no VPN tunnel or
BGP session measurement, so vpnTunnel and bgpPolicy remain not_established.

**Worked prerequisite failure:** route-gap still answers DNS and serves the
application over IPv6, while its IPv4 route-get fails. 198.18.32.0/31 contains
.0 and .1, leaving server .2 outside the prefix. Set readiness to
repair_baseline_first and firstBoundary to ipv4_route. Correct that baseline
before using an advanced extension to explain its symptoms.

**Worked responding failure:** wrong-upstream has a route and HTTP 200, but
the body identifies owned-denial-control rather than the intended application.
Its firstBoundary is application_identity and readiness is
repair_baseline_first. Compare the baseline and choose one next-topic question
with the additional evidence it would require.

Conceptual reading: [IPsec architecture](https://www.rfc-editor.org/rfc/rfc4301),
[BGP-4](https://www.rfc-editor.org/rfc/rfc4271) and
[NIST WLAN guidance](https://csrc.nist.gov/pubs/sp/800/153/final).


## Evidence locations and conclusion

The record IDs above name complete captured command/result objects in observations.json. Read original argv, family, exit code and response identity together. Preserve the actual .2 destination when comparing the /31 route. The baseline and changed records are different historical attempts with different run markers; compare each body with its own marker.

## Next measurement and scope

Choose the proposed follow-up named above and state the originating node, endpoint, family and expected observation. The supplied record answers remain bounded to their named clients and time. No VPN, BGP, wireless, cloud or public-ingress execution is inferred from this assessment. A live rerun retains its capstone receipt, original failure and cleanup evidence.
