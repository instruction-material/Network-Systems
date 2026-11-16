# Service Exposure Studio worked notebook

## Trace the service boundary

Draw client -> router -> server proxy -> loopback backend. Add each observed
address, family and port to that diagram. A reverse proxy can admit a front
request while the application itself remains bound to loopback.

**Worked intended path:** baseline.application4 and application6 are
intended_application. The client requests the recorded server's front port,
and the body identifies owned-operations-capstone with the matching run marker
and /health path. The server listener snapshot makes backendBind4 loopback.
internetExposure remains not_established because the observed client is inside
the owned private topology.

**Worked wrong responder:** wrong-upstream returns 200 through the front port
in both families, but the body names owned-denial-control. Both application
answers are wrong_application and firstBoundary is application_identity.
The faulty upstream is 8088; the intended application is at 127.0.0.1:9000.
A working transport and responding front proxy can therefore coexist with the
wrong application result.

Annotate the diagram with one observation supporting each edge. State what
additional external witness and edge-policy observations a public-exposure
claim would require. The separate extension challenge on this saved attempt
adds a before/after prediction for the wrong-upstream correction; preserve the
original record and compare its body with the baseline.


## Evidence locations and conclusion

The record IDs above name complete captured command/result objects in observations.json. Read original argv, family, exit code and response identity together. Preserve the actual .2 destination when comparing the /31 route. The baseline and changed records are different historical attempts with different run markers; compare each body with its own marker.

## Next measurement and scope

Choose the proposed follow-up named above and state the originating node, endpoint, family and expected observation. The supplied record answers remain bounded to their named clients and time. No VPN, BGP, wireless, cloud or public-ingress execution is inferred from this assessment. A live rerun retains its capstone receipt, original failure and cleanup evidence.
