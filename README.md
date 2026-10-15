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
The notebook is a continuation of that core attempt. The reference explains the
same contract without pretending to grade the learner's written explanation.

## Source acceptance and remaining audit

Run ./verify-course-source.sh for repository inventory checks. For actual native
acceptance of the two foundations, as an ordinary Linux user with the documented
tools, run:

    python3 test/verify_foundations.py --proof output/network-foundations.json

The native workflow retains raw observations and process lifecycles for untouched
starter, completed starter and reference roles. Its 48 cases include 33 real owned
network experiments and fifteen invalid-input refusals. A passing presence check is
not a substitute for those native observations.

The other 42 generic Python starter/reference pairs remain under content audit;
this change does not certify them. The six earlier shell projects below are
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
