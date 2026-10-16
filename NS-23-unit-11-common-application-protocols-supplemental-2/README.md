# Conditional Requests and Explicit Redirects

Network Systems, Unit 11: Common Application Protocols.

A protocol specifies how peers interpret messages. A port identifies one part
of a transport endpoint; its number alone does not prove which application
answered. An observed TCP connection, HTTP response, trusted TLS identity and
successful application operation answer different questions. This lab supplies
one real HTTP service to make those distinctions inspectable.

Use Python 3.10 or newer, curl and ss in an external Linux terminal under an
ordinary account. No root account is needed. The program binds only 127.0.0.1
on a newly allocated port. It does not query a public host or change interfaces,
routes, firewall rules, resolver files, credentials or existing services. Keep
main.py, application_lab.py, network-notes.md and application-cases.md together.
The root README.md is this complete guide; the role README.md identifies the
selected role. Run from starter/ for an attempt or solution/ for a separate
reference. Both roles collect the same real observations. Python programming is
optional; only analyze(evidence) is incomplete in the starter.

An HTTP request combines a method, target, version and fields. The service replies
with a status, fields and, when appropriate, content. Read actual bytes before
interpreting them. Content-Type describes the representation; Content-Length
counts octets. A HEAD reply has metadata without transferred representation
content. The record includes base64 for exact binary bytes, because decoding
arbitrary content as text can destroy evidence. The laboratory deliberately
closes each connection, allowing its raw client to retain bytes through EOF.
It is a small HTTP/1.1 experiment, not a general HTTP parser or production server.

The report keeps the issuing namespace, ordinary UID, owned child PID, loopback
address and allocated port. Match the ss listener row to that PID and compare
the unique response token with the worker's request log. Client local/peer
addresses and server local/peer addresses should agree in opposite directions.
The two curl requests corroborate the raw client using another implementation.
A separate socket holds a different loopback port without listening while curl
attempts a connection. Its refusal supplies a controlled comparison without a
successful HTTP response. A general timeout or refusal elsewhere would need
additional authorized evidence before assigning a cause.

## Optional transfer: validators and an explicit second request

This task extends the core protocol comparison by changing request conditions.
Run `python3 main.py`. Predict all six request outcomes before opening the
result. The initial GET /state returns a representation and an ETag validator.
The next request sends that exact validator in If-None-Match. This service
returns HTTP 304 without representation content. Keep the earlier bytes beside
the validating result: an empty 304 is not an empty replacement representation.
The helper records exchanges; it does not install a browser cache or persist a
cache entry. The retention table in the notebook is the explicit reasoning work.

A third GET sends a different, stale validator. Compare the returned status,
ETag and bytes with the initial representation. Explain why that condition did
not justify reusing an unvalidated local copy. The HEAD request then compares
metadata and transferred content independently of the conditional request.
Do not infer that a HEAD response has transferred the representation merely
because its Content-Length describes a positive number of octets.

The fifth exchange requests /redirect and receives HTTP 307 plus a relative
Location. The helper deliberately does not automatically follow that response.
Its sixth request explicitly addresses /state with GET, so both the redirect
and the destination result remain visible. Retain the method and target of
each exchange. This run demonstrates GET and a separately issued GET; it does
not test every redirect method rule, browser history or a cross-origin policy.

Repeat `python3 main.py --changed --message "Transfer observation"` as a fresh
run. The service is recreated, and its representation, validator and response
token belong to that new run. Explain why an ETag from the old run is not a
universal resource identity. The stale-validator request already gives a real
changed-condition comparison within each run. No proxy or shared cache is
started, and no cache lifetime or freshness clock is measured here.

## Evidence and a bounded interpretation

Fill network-notes.md with a six-row exchange table. Add the retained initial
body's SHA-256, the actual 304 byte count, the validator sent on each request,
the stale result, the redirect target and the explicitly requested destination.
Keep actual timing as observation timestamps, not a claim of benchmark speed.
Match every response to the current token and owned listener. The corroborating
curl requests and held-port refusal remain transport/application controls.
Check the final owned PID cleanup before ending the run.

Read the supplied DNS, TLS and SSH cases separately. Identify which extra
evidence each would need before a conditional HTTP request could even be made.
Their fictional observations are not part of the local request log. Distinguish
a negative DNS answer from a DNS transport failure, a TLS identity error from
an HTTP status, and SSH account authentication from host-key trust.

For independent work, write predictions before reading each response and
explain a result that would falsify the proposed reuse decision. For a paced
walkthrough, compare one conditional request at a time, then the two explicit
redirect exchanges. The task is complete when the retained representation,
conditions and observed outcomes support the explanation, including its limits.

Optional Python practice: implement analyze(evidence) to report the validator,
conditional status and transferred byte count, retained-body digest, stale
status, redirect status and Location, and equality of the final/initial body.
The separate reference implements this summary; networking interpretation and
the notebook remain the task even when no Python is written.

## Protocol reference

For HTTP terminology and the method/status rules, consult
[RFC 9110: HTTP Semantics](https://www.rfc-editor.org/rfc/rfc9110.html),
especially sections 8.6, 9.3.2, 13.1.2, 15.4.5, 15.4.8, 15.5.6 and 15.6.4.
The observations and service behavior described above are specific to this lab.
