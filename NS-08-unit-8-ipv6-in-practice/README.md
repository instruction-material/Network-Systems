# Required Project: Trace IPv6 Independently

Explain one actual IPv6 application path without treating IPv4 success as a
substitute. Run the IPv6-only and paired loopback cases, reconcile address scope,
the selected route, owner identity and response, then complete the three supplied
on-link and policy cases. Reuse the earlier DNS/NSS evidence and label its scope.
The operations notebook is a continuation of this core attempt.

For ::1/128, only ::1 is a member; :: and ::2 are outside. This is a numeric
membership fact, separate from the actual lo interface and application endpoint.
Predict the controlled IPv4 refusal before the IPv6-only run. After the paired
run, explain how two different family endpoints can have the same numeric port.
Change --message and repeat, retaining the fresh owner and token. Keep an
unavailable family or missing command as an explicit failed prerequisite.

Completion is an actual IPv6 HTTP response with matching owner and request,
the controlled family comparison, cleanup, a correct scope table and a complete
path diagnosis for each supplied case. No Python edit is required. If choosing
the optional analysis function, summarize the IPv6 endpoint, successful response
families and actual namespace; do not infer Internet reachability.

## Environment and saved work

Prerequisites are the addressing, separate DNS/NSS and route-reading units.
Use the same owned Linux lab and an ordinary account. Python 3.10 or newer,
iproute2 (ip and ss) and curl are required. On an Ubuntu lab that the account
administers, package preparation is `sudo apt-get install python3 iproute2 curl`.
Only package preparation uses elevation. Run main.py without sudo.

Save and export the selected role in the site IDE. Extract its ZIP and enter
`starter/` for the attempt or `solution/` for the separate reference. The browser
edits and saves the files; the Linux terminal runs the actual observations.
Keep main.py, ipv6_lab.py, network-notes.md, ipv6-practice-case.md and README.md
together. The untouched attempt already runs. Its analysis: null field marks
the optional Python extension; it does not indicate a failed networking lab.

Confirm `uname -s`, `hostname`, `id`, `pwd` and `python3 --version` in that terminal.
Use a new report name for each run; Bash `set -C` prevents accidental truncation
by a later `>` redirection. The program itself writes its report to stdout.
An unavailable IPv6 stack, missing tool or failed owned experiment produces a
nonzero status with an error, not a substitute IPv4 success. Keep the error and
use the explicitly labeled supplied cases where a working lab is unavailable.

## Observe an actual family-specific path

Run `python3 main.py --binding v6-only` and retain the complete JSON. The program
queries the current IPv6 addresses, the route to ::1 and the existing neighbor
table. It starts one bounded owned child, bound only to loopback. The child
sets and reads IPV6_V6ONLY=1 before listening on ::1 at an OS-selected high port.
The same child exclusively binds 127.0.0.1 at the same numeric port as a control.
In v6-only mode that IPv4 socket deliberately does not listen. This prevents
the comparison from sending application data to an unrelated IPv4 listener.

The parent retains actual ss output and /proc owner UID fields, then issues
the IPv4 comparison first while the control is still held. Its curl status 7
records a refused connection in the controlled lab. A separate explicit IPv6
request to `http://[::1]:PORT/ipv6-lab` receives the owned HTTP 200 response.
Brackets separate the IPv6 literal from the URL port. They are URL syntax,
not part of the address. The response token, family, bound address, numeric
port, message and path identify this run. Match them to the child PID and its
actual request and peer records. An application response is stronger evidence
than a DNS answer or a row in a socket table.

Repeat with `--binding paired`. Both distinct sockets now listen, one on ::1
and one on 127.0.0.1 at the same numeric port within that run. Both HTTP requests
return the owned token, with different address families. This demonstrates
two explicit loopback listeners, not one wildcard dual-stack socket or an
IPv4-mapped-address experiment. Fresh runs can choose different numeric ports;
do not attribute a later process to an earlier port number.

The child closes its sockets and exits; the parent reaps it. Compare the final
ss output with the original PID and endpoints. A port number alone is not an
owner identity. Timeouts bound commands and the owned worker, and error cleanup
stops only that child's process group. No interface, route, name-service file,
firewall rule or system IPv6 setting is changed.

## Scope, prefixes and configuration

IPv6 addresses have 128 bits. ::1 is loopback and stays within this node;
127.0.0.1 is an IPv4 endpoint with a different address family. A link-local
address in fe80::/10 belongs to a particular link, so retain its actual
interface or zone identity. A global-unicast-looking address is not evidence
of an available route or successful Internet application. The 2001:db8::/32
prefix used in the calculation and supplied cases is reserved for documentation.

The prefixTable is arithmetic, not a measurement or address assignment. A /126
contains four numeric addresses, a /127 two and a /128 one. Membership says
nothing by itself about interface configuration, address selection, an owned
service or usability of every address. IPv6 has no broadcast address. Keep the
calculated prefix table separate from actual ip, ss and HTTP observations.

Router Advertisements can provide prefix and router information. On-link,
autonomous-configuration and router-lifetime information have different roles.
SLAAC can use advertised information to form an address, while DHCPv6 can supply
addresses or other configuration. A lease alone does not establish the default
router, chosen source address or application path. Inspect those observations
separately. Existing neighbor rows are a passive snapshot; an empty table is
not evidence that Neighbor Discovery is broken. Loopback does not exercise
on-link Neighbor Discovery, Router Advertisements or DHCPv6.

## Complete the whole diagnostic explanation

Keep the issuing host, account, namespace, tool versions, predictions, commands,
raw outputs and cleanup in network-notes.md. Reuse the earlier DNS/NSS unit's
actual A, AAAA and system-lookup evidence. A returned AAAA value does not prove
the address is configured, reachable or selected by a later client.

Read all three cases in ipv6-practice-case.md. They supply the on-link neighbor,
family-policy and configuration reasoning that the loopback run cannot measure.
Label those constructed records separately from actual results. Trace each
family through address scope, selected route, neighbor where relevant, lookup,
listener, policy and application response. Locate the first unsupported step
and name the further authorized observation that could disprove the diagnosis.
IPv4 success cannot stand in for missing IPv6 evidence. Do not infer an IPv6
firewall allowance from an IPv4 rule or perform privileged changes for this lab.

For independent work, make each prediction before its comparison and keep any
mismatch with its explanation. In a guided review, pause at address scope,
route, owner identity, the refused family, the paired response and cleanup;
then trace the supplied cases one boundary at a time. The core networking work
is command interpretation and the complete notebook. Python programming is an
optional extension in analyze(evidence); the supplied apparatus stays unchanged.
The reference is a separate attempt and does not overwrite saved work.

## Primary references

- [Python socket interface](https://docs.python.org/3.10/library/socket.html)
- [Linux IPv6 sockets](https://man7.org/linux/man-pages/man7/ipv6.7.html)
- [IPv6 addressing architecture](https://www.rfc-editor.org/rfc/rfc4291.html)
- [Neighbor Discovery and Router Advertisements](https://www.rfc-editor.org/rfc/rfc4861.html)
- [Stateless address autoconfiguration](https://www.rfc-editor.org/rfc/rfc4862.html)
- [Documentation prefix](https://www.rfc-editor.org/rfc/rfc3849.html)
