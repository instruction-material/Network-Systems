# Response Policy, Binary Content and Request Authority

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

## Optional extension: response policy and representation boundaries

This task extends the core distinction between a connection and a useful
application response. Run `python3 main.py` and predict five outcomes:
GET /unavailable, GET /missing, POST /state, GET /binary and GET /state with a
different Host field. Identify the request, peer and service owner before
classifying any failure or successful result.

The first response is a real planned HTTP 503 with Retry-After. The next is
HTTP 404 for a missing resource, and the third is HTTP 405 with allowed methods.
All three exchanges reach the owned HTTP application. Their different status
classes and fields support different client decisions. They do not authorize
unlimited retries or imply that changing a route, port or firewall will fix
an application decision. A Retry-After value is a suggestion retained from the
response; this program neither sleeps for that interval nor demonstrates that
the unavailable resource recovers afterward.

The /binary resource transfers four exact octets with application/octet-stream.
Inspect its base64 and decoded byte values before trying to display it as text.
Compare the byte count with Content-Length. Distinguish an intact nontext
representation from a decoding problem or a truncated network response. Do
not silently replace undecodable bytes and then call the altered string exact
evidence. The surrounding JSON report preserves the octets through base64.

The final request still connects directly to the numeric 127.0.0.1 endpoint,
but sends Host: representation.invalid. No DNS query for that name is made.
This intentionally simple service accepts the request and returns its current
identity token. Compare the peer, port, PID and token with earlier exchanges.
This shows what this local service did with a changed application field. It
does not prove that a production virtual host, reverse proxy, TLS SNI check or
name-based authorization rule would accept the same request.

## Changed case and client decision table

Repeat `python3 main.py --changed --message "Extension observation"`. Compare
the Retry-After value and JSON message using the new run's token and endpoint.
Keep the raw service decisions, exact binary octets and changed Host behavior
separate. Construct a decision table that names what is observed, what the
client can safely infer, the next authorized check and a stopping condition.
Include the held-port curl refusal, where there is no HTTP message to classify.

Read application-cases.md as supplied reasoning material. Its DNS negative
answer, TLS trust failure and SSH host-key/authentication cases concern distinct
protocol boundaries. Name the missing evidence before proposing a correction.
The local script does not query DNS, establish TLS, authenticate SSH or measure
an Internet service. A protocol name or conventional port does not establish
which peer answered or whether an authenticated operation succeeded.

Complete network-notes.md with the prediction/result table, exact binary
representation, response fields, actual connection identities, the changed run,
constructed-case reasoning and cleanup. Retain contrary evidence and explain
which conclusion it limits. Check serverReaped and the owned PID's absence
from the final listener result. In a paced review, stop after each boundary
before comparing the proposed client decisions.

Optional Python practice: implement analyze(evidence) to summarize the first
three status classes, retry suggestion, binary octets and whether the changed
Host request kept the same actual peer and response token. Compare with the
separate reference after completing the observation and reasoning work.

## Protocol reference

For HTTP terminology and the method/status rules, consult
[RFC 9110: HTTP Semantics](https://www.rfc-editor.org/rfc/rfc9110.html),
especially sections 8.6, 9.3.2, 13.1.2, 15.4.5, 15.4.8, 15.5.6 and 15.6.4.
The observations and service behavior described above are specific to this lab.
