# Network Systems

The course follows Linux Systems and develops evidence-based explanations of
service reachability, transport, addressing, routing, DNS, firewall policy and
packet inspection. Project folders remain aligned with the catalog identities
in COURSE_SOURCE_MANIFEST.md.

## Required foundations

- NS-04-ns0-setup-and-tooling: establish the selected Linux environment, inspect
  its loopback route and live listener, and observe one actual local HTTP request.
- NS-05-unit-1-the-network-stack-in-plain-english: reconstruct a real TCP stream,
  distinguish transport EOF from line completion, and observe empty and truncated
  UDP datagrams through actual Linux sockets.

Each has a complete guide and self-contained starter/reference roles. Begin with
the starter; its instrumentation runs before the analysis TODO is completed.
The required work uses native commands, observations and the notebook; Python
programming is not a prerequisite. The analysis TODO is supplemental code practice.
The notebook continues the same core attempt. The completed test profile means
that optional analysis code was supplied; it does not certify completion of the
networking explanation.

## Source acceptance and remaining audit

Run ./verify-course-source.sh for repository inventory checks. For actual native
acceptance of the two foundations, as an ordinary Linux user with the documented
tools, run:

    python3 test/verify_foundations.py --proof output/network-foundations.json

The native workflow retains raw observations and process lifecycles for untouched
starter, completed starter and reference roles. Its 48 cases include 33 real owned
network experiments and fifteen invalid-input refusals. A passing presence check is
not a substitute for those native observations.

The remaining 25 generic optional starter/reference pairs remain under content
audit. Acceptance of the replaced packs does not certify those other contexts. The six earlier shell projects below are
preserved and have separate goals and tooling requirements:

1. NS1-Listening-Services-Map
2. NS2-Local-vs-Remote-Reachability-Diagnosis
3. NS3-UFW-Web-Server-Policy
4. NS4-IPv4-vs-IPv6-Resolution-Comparison
5. NS5-Tcpdump-HTTP-Capture
6. NS6-Router-NAT-Topology-Lab

Use the individual guide before any route, firewall or packet-capture operation.
The two introductory packs use only their own loopback sockets and do not
reconfigure the lab. They require a Linux VM, WSL or another owned Linux lab;
the browser workspace is an editor and export path for this native work.

## Addresses and Naming

The required Unit 2 pack observes an actual local endpoint and operating-system name lookup. Its two supplemental packs transfer prefix boundary reasoning to /31 and /32 and compare address families. Each has a complete guide, working instrumentation, an evidence notebook and an optional analysis function.

Run python3 test/verify_naming.py --proof output/network-addressing.json as an ordinary Linux user for native acceptance. Source-only checking uses --source-only and never marks native acceptance. The native gate records 45 real owned HTTP experiments and 45 pre-experiment input refusals.


## Optional application record and queue investigations

The Unit 1 transfer pack
`NS-03-unit-1-the-network-stack-in-plain-english-supplemental-2` investigates
length-prefixed application records across partial TCP reads. The separate
extension pack
`NS-04-unit-1-the-network-stack-in-plain-english-supplemental-3` investigates a
UDP diagnostic that consumes a queued datagram and a peeking correction. Each
includes a complete guide, a case configuration, evidence notebook and named
reasoning cases. The apparatus is prewritten; programming is optional.

These optional activities keep their own attempts and do not replace the
required Unit 1 transport project. Starter and reference apparatus match;
`case.json` is the only completion difference. Successful runtime checks do not
complete either notebook. In an ordinary Linux account with Python 3.10+ and
strace, run the native gate with:

    python3 test/verify_transport_optional.py --proof output/network-transport-optional.json

The gate retains real socket observations, raw syscall traces, process records,
source hashes, unfinished attempts, controlled regressions and input refusals.
