# Application Responses and Transport Boundaries

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

## Required protocol observations

Run `python3 main.py` and retain its JSON as a new observation record. Predict the
five method/path outcomes first: GET /state, HEAD /state, GET /missing, POST /state
and GET /unavailable. The first reply transfers a JSON representation containing
the run's token, message and server identity. Compare its byte count with the
advertised length. The HEAD reply describes that representation while the raw
connection transfers no content. An empty HEAD body is expected behavior.

The missing resource produces HTTP 404. The unsupported method produces HTTP
405 with Allow naming GET and HEAD. The planned local unavailability produces
HTTP 503 with a Retry-After value. These are actual application messages from
the owned service. They establish that an HTTP exchange occurred, even when
the requested operation did not succeed. The held-port curl refusal has no
HTTP status line; keep that transport observation in a different table column.

Repeat with `python3 main.py --changed --message "Second observation"`.
Predict which facts should change: the message and suggested retry delay do;
the per-run token and allocated endpoint may also change. The distinction
between HEAD content and GET content, the missing path and allowed methods
remain. Compare independent runs using their own identities, not one remembered
port. A 503 Retry-After suggestion does not show that the service later recovered.
The script does not wait and automatically retry that unavailable route.

## Connect this evidence to other application protocols

DNS can provide an address answer, a negative name answer or a protocol-level
error. A successful DNS answer still does not demonstrate this HTTP service.
Use the earlier name-resolution exercise for actual DNS/NSS observations.
HTTPS adds TLS: a certificate trust or name failure may prevent HTTP from being
reached. SSH involves server host identity and account authentication; a
successful TCP connection alone establishes neither. Read the three explicitly
constructed cases in application-cases.md and name the earliest unsupported
boundary. They are reasoning exercises, not packets captured by this program.

## Deliverable and review

Complete network-notes.md with predictions, the two actual runs, response bytes,
transport comparison, issuing host/namespace, method, target, token, endpoint,
owner, observed status and cleanup. Preserve unexpected results with their raw
errors and identify the next authorized observation that would distinguish two
plausible explanations. Finish with the supplied-case comparisons and one
limit on each conclusion. Verify serverReaped and the PID's absence from the
final listener query. For paced review, pause after the prediction, each
request/response pair, the refusal comparison and the closing diagnosis.

Optional Python practice: implement analyze(evidence) to summarize the five
observed statuses, actual HEAD byte count, allowed methods and whether the
refusal produced an HTTP response. Work from the collected records. Keep the
reference separate and compare only after completing an attempt.

## Protocol reference

For HTTP terminology and the method/status rules, consult
[RFC 9110: HTTP Semantics](https://www.rfc-editor.org/rfc/rfc9110.html),
especially sections 8.6, 9.3.2, 13.1.2, 15.4.5, 15.4.8, 15.5.6 and 15.6.4.
The observations and service behavior described above are specific to this lab.
