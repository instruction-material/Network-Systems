# Service Exposure Studio

Explain the complete path from client through proxy to the intended loopback application.

## Prepare and run

This optional archive follows the required addressing, route, listener, diagnostic
and exposure units. Its supplied-record route uses five actual isolated Linux
captures. Python 3.10 or later is the supplied checking tool; the networking task
is to interpret observations, complete an assessment and explain the evidence.
Use the same cases independently or pause with an instructor at each evidence
boundary.

Open the starter in the site IDE, retain the reference as a separate attempt,
and keep the imported files together. Save assessment.json and network-notes.md,
reopen the same assignment to confirm those edits, then export the complete ZIP.
From the exported project folder, run the selected role:

    cd starter
    python3 main.py

The reference uses the parallel solution folder. Exit 1 means an assessment is
incomplete or disagrees with the observations; exit 2 means an input file is
invalid; exit 0 means the factual fields agree. The report always leaves
reasoning and notebook review open. Local analysis creates no network resources.
Complete the null answer fields using the vocabulary and worked comparisons
below. Explanations belong in network-notes.md; keep the documented answer keys.

## Input inventory and topology

- main.py selects this exercise; archive_lab.py reads and checks the data.
- observations.json contains the exact recorded inside.json text, original
  command arguments, outputs, exit codes, timestamps and capture provenance.
- assessment.json is the editable factual assessment. network-notes.md records
  the question, predictions, cited fields, explanation and next measurement.
- edge-cases.md supplies further comparisons. SOURCES.md identifies each
  original capture and its hash.

The client is 198.18.31.2 and 2001:db8:31::2. A router connects it to the server
at 198.18.32.2 and 2001:db8:32::2. The default name is blue.capstone.test. The
resolver listens at server port 15353; the front proxy listens at TCP 8080; the
intended application binds IPv4 loopback 127.0.0.1:9000. An owned control listens
at TCP 8088. The default policy admits the declared client's proxy and resolver
traffic and denies its control traffic. The alternate capture changes the name
to amber.capstone.test and the proxy port to 8087.

Read these fields in each record's raw object:

| Field | What it measures |
| --- | --- |
| dns.A / dns.AAAA | Actual lookup command and returned family-specific answer |
| routeGet4 / routeGet6 | Route selected for that family's server address |
| listeners | Server-namespace socket snapshot, including address and port |
| policy4 / policy6 | The recorded family-specific filtering rules |
| http4 / http6 | Client request arguments, curl exit, HTTP status and response body |
| denied4 / denied6 | Client requests to the listening control on port 8088 |
| directUpstream | One client request to the external IPv6 address on port 9000 |
| case | The configured IPv4 service prefix and proxy upstream port |

Display a readable observation field directly from either role folder:

    python3 main.py --show route-gap --field routeGet4
    python3 main.py --show wrong-upstream --field http4
    python3 main.py --show baseline --field listeners
    python3 main.py --show open-control --field policy4

Omit --field to show that entire named record. This decodes the preserved raw
text without requiring a separate JSON editor or Python code.

The top-level completed flag is the older lab's overall verdict. Derive this
exercise's answers from the observations instead. A record describes one
originating namespace, endpoint, family and time; further claims need further
measurements. The original run markers are ephemeral response identifiers from
an already closed isolated lab.

## Record set

| Record | Comparison |
| --- | --- |
| baseline | Working dual-stack application path; control requests fail |
| alternate | Working path using a different name and front proxy port |
| route-gap | A /31 service route excludes server .2; IPv6 still works |
| wrong-upstream | Front proxy reaches the control application at upstream 8088 |
| open-control | The same control becomes reachable after an admission-rule change |

A 200 response establishes an HTTP response, then the requested endpoint,
application identity, run marker and path identify what answered. A listening
socket alone establishes the local binding snapshot. A failed request alone
does not identify a firewall cause: inspect the route, actual listener and
matching policy as separate evidence.

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

## Collect a fresh owned-lab comparison

The complete [capstone source and guide](https://github.com/instruction-material/Network-Systems/tree/f37b558cfe75c7e6348a4689e1c06284da1f2812/NS-03-network-systems-lab-17) provide the optional live
Linux route. Use an owned disposable Linux VM with root privileges and network
and mount namespaces. On an administered Debian/Ubuntu practice VM, install
the tools once:

    sudo apt-get update
    sudo apt-get install python3 git iproute2 iptables util-linux curl dnsutils tcpdump dnsmasq-base

Check out the pinned source in a new working directory:

    git clone https://github.com/instruction-material/Network-Systems.git network-practice
    cd network-practice
    git checkout f37b558cfe75c7e6348a4689e1c06284da1f2812
    cd NS-03-network-systems-lab-17/solution
    sudo python3 main.py --output ./fresh-observation

Choose a new output path for each attempt. The capstone creates an outer private
network/mount context and its own client/router/server namespaces, collects the
results and removes its workers and namespaces. Retain receipt.json, inside.json
and capture.pcap. The receipt compares the calling host's routes, links and rules
before and after. A missing tool or refused namespace is a prerequisite issue.

From the exported archive role folder, inspect that new inside.json:

    python3 main.py --inspect /absolute/path/to/fresh-observation/inside.json

This summarizes a supplied file and reports no new network execution. The
assessment route continues to refer to its five named source records; put the
fresh comparison and its provenance in the notebook. Repeat with the alternate
capstone option described in its guide, or with a separately copied learner
case.json using /31 versus /30 or upstream 8088 versus 9000. Preserve the
failed observation before correcting that one field. The open-control source
record comes from the capstone verifier's controlled rule regression; its exact
rule and request output are already supplied here.

## Finish and review

An independent review writes the prediction before checking the reference.
A guided review pauses after the topology, the first conflicting observation,
the bounded conclusion and the next measurement. Cite record IDs and exact
command/result fields in the notebook. Explain one alternative cause and the
evidence that would distinguish it. Reopen/export the saved role and rerun its
command. The green factual report confirms the assessed fields; explanation,
topology and scope notes remain part of review.
