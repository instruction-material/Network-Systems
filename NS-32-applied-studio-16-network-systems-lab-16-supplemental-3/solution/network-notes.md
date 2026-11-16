# Service Exposure Extension Practice worked notebook

## Compare a measured policy change

Read the baseline and open-control listener, route and rule snapshots before
using the request outcomes as a before/after comparison. Both captures retain
a real control listener at 8088 and a working application through the proxy.

**Worked baseline:** control4 and control6 are request_failed, while
application4 is intended_application. The captured rules admit the declared
client's front-proxy traffic and leave new control traffic outside that
admission. Read the recorded timeout beside the viable route and listener.

**Worked changed boundary:** open-control adds admission for that client's
8088 traffic. control4 and control6 become control_response; application4
stays intended_application. The response identifies the control application,
which is the intended responder for the separate 8088 probe. The same control
identity behind a request for the front application would be a different result.

otherClients and internetExposure remain not_established. The pair supports
the changed rule and observed client in this private topology; it has no
measurement of another client or a public ingress path. Record the exact
family-specific admission rules, retain the baseline as the rollback
comparison, and identify the next source/path measurement needed for a wider
claim. The analysis route changes no rules; live work uses the capstone's
owned isolated context and retains its cleanup receipt.


## Evidence locations and conclusion

The record IDs above name complete captured command/result objects in observations.json. Read original argv, family, exit code and response identity together. Preserve the actual .2 destination when comparing the /31 route. The baseline and changed records are different historical attempts with different run markers; compare each body with its own marker.

## Next measurement and scope

Choose the proposed follow-up named above and state the originating node, endpoint, family and expected observation. The supplied record answers remain bounded to their named clients and time. No VPN, BGP, wireless, cloud or public-ingress execution is inferred from this assessment. A live rerun retains its capstone receipt, original failure and cleanup evidence.
