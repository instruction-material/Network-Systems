# Next Steps Transfer Practice worked notebook

## Transfer the diagnostic ladder

Carry one baseline through DNS, the selected family route, the intended
endpoint and application identity, then the exposure control. A successful
earlier step supplies context for the next one. Keep each address family
separate when the results disagree.

**Worked route gap:** baseline.firstBoundary is none. In route-gap, the A
answer is matching_answer, route4 is failed, application6 is
intended_application and firstBoundary is ipv4_route. The exact next lookup
is the recorded equivalent of ip -n ncap-client -4 route get 198.18.32.2.
Read the failed lookup beside the configured /31 and the server .2 address.
A valid lookup for the adjacent router .1 would answer a different question.

**Worked identity gap:** wrong-upstream.route4 is selected, so replacing the
working route does not address this observation. Its application4 is
wrong_application: curl exits zero and HTTP returns 200, yet the response body
names the control application. firstBoundary is application_identity.
Compare the configured upstream 8088 with the reference 9000 and preserve the
original response before changing it.

Write two next-measurement plans, one for each failure. Include source namespace,
destination, protocol/port, expected result and the observation that would
change the conclusion. Explain why a generic "network down" diagnosis loses
the useful difference between these two records.


## Evidence locations and conclusion

The record IDs above name complete captured command/result objects in observations.json. Read original argv, family, exit code and response identity together. Preserve the actual .2 destination when comparing the /31 route. The baseline and changed records are different historical attempts with different run markers; compare each body with its own marker.

## Next measurement and scope

Choose the proposed follow-up named above and state the originating node, endpoint, family and expected observation. The supplied record answers remain bounded to their named clients and time. No VPN, BGP, wireless, cloud or public-ingress execution is inferred from this assessment. A live rerun retains its capstone receipt, original failure and cleanup evidence.
