# Trace a Destination Address and Port Mapping

Network Systems, Unit 3.

This Unit 3 task observes mechanisms before the later command-editing work.
The supplied apparatus creates the network and collects actual kernel and HTTP
records. The required work is prediction, observation and explanation in the
notebook. Python programming is optional. Unit 7 later edits forwarding and NAT
commands in the NS6 lab; Unit 12 continues that saved NS6 attempt with a measured
restrictive policy. Those are configuration and exposure tasks with different
deliverables, rather than another copy of this introductory observation task.

## Environment, files and scope

Use a disposable Linux VM with root access, Python 3.10 or newer and kernel network
and mount namespaces. The commands require iproute2 (ip, bridge and ss), iptables,
util-linux (unshare and mount), sysctl and curl. Package preparation belongs to
the VM's administration. On an owned Ubuntu VM, the relevant packages are
python3, iproute2, iptables, util-linux, procps and curl. Preparation on that
owned VM is:

```sh
sudo apt-get update
sudo apt-get install -y python3 iproute2 iptables util-linux procps curl
```

The lab itself needs no Internet connection. Run it with sudo after checking the files and purpose.

Save and export the selected role in the site IDE, extract its files and enter
starter/ for the attempt or solution/ for the separate reference. Keep main.py,
link_routing_lab.py, network-notes.md and edge-cases.md together. README.md is
the complete guide. Both roles already collect the observations; only the
starter's optional analyze(evidence) summary is incomplete. The website edits,
saves and exports this project. The disposable Linux terminal runs the actual
kernel experiment; it cannot run inside the browser or on macOS.

The apparatus enters new network and mount namespaces and mounts a private /run
before creating three named namespaces. Its interfaces and namespace registry
belong to that run. It uses fixed private IPv4 subnets, a new response token and
an owned HTTP worker. It never connects the network to an outside interface or
flushes a host firewall. It compares outer links, routes, named namespaces,
forwarding and firewall configuration before and after, retaining raw counters
while normalizing only changing firewall comments and chain counters for that
comparison. A mismatch or unavailable isolation stops the run with an error.

Record hostname, uname -s, id, python3 --version, command and namespace identities
beside the result. Use `sudo python3 main.py` for the default run. To retain a
new report from an ordinary shell without truncating an earlier one, use
`(set -C; sudo python3 main.py > first-observation.json)`. Read its error status
before interpreting the report. Do not change host security settings to force
an unsupported VM/container to accept namespace operations.

## Actual identities and limits

Each successful response carries the current token, PID, UID, actual server
endpoint and actual peer endpoint. Match it to the owned listener and worker
log. Curl also retains its numeric local and peer endpoints and raw HTTP bytes.
Translation can make those socket views differ; keep both instead of guessing.
Every comparison uses a new curl process and TCP connection. A general timeout
alone does not locate a fault; this lab also records a deliberate change,
kernel state, successful readiness and a restoration comparison.

The private worker stops and is reaped, its listener is checked, and the named
namespaces and links are removed before the report returns. Verify hostUnchanged
and the cleanup records. A program run does not complete the notebook's
reasoning. Public Internet connectivity, IPv6, an ISP, physical switch hardware,
DNS and a restrictive filtering policy are not measured by this program.

## Optional extension: destination mapping and the two socket views

This task begins with routed links: client 10.31.0.2/24, middle gateway
addresses 10.31.0.1 and 10.32.0.1, and server 10.32.0.2/24. Both endpoints have
their corresponding gateway and middle IP forwarding is enabled. The first
request directly addresses server port 8080 and succeeds with the original
client address visible to the server. The next applies narrowly matched SNAT;
the server then sees middle address 10.32.0.1. Preserve the actual source port
too, without assuming every translation always preserves it.

A destination rule maps client-side middle endpoint 10.31.0.1:18080 to the
server's 10.32.0.2:8080. Compare the requested endpoint and curl's peer view
with the server's actual local endpoint. Match the same run token and owned
worker. The service did not start listening on port 18080 inside its namespace;
the router changed a destination address and port before routing the connection.
That mapped request also matches the earlier source-translation rule, explaining
the peer visible at the server. Connection tracking supports the reverse
translations for replies; this program observes their successful result rather
than dumping the entire connection-tracking table.

The apparatus removes only its owned middle PREROUTING mappings, then makes a
new request to the mapped endpoint. That request no longer yields an HTTP
response. A final new direct request to the server still succeeds with SNAT.
Use this comparison to distinguish removal of the destination mapping from a
dead service, lost route, disabled forwarding or removal of all NAT. The exact
kernel rules and socket identities remain necessary evidence.

Repeat `sudo python3 main.py --alternate --service-port 8087 --mapped-port 18087`.
Predict both translated endpoints using the new prefixes and ports. The server
listens at 10.42.0.2:8087; the mapped entry is 10.41.0.1:18087. Read actual
records instead of reusing a token or port from the earlier run. Existing
tracked connections can outlive a rule change; the apparatus deliberately
starts a new curl process/TCP connection for each comparison.

These translations do not prove an Internet-facing service or a restrictive
firewall. The namespace has no connection to an outside interface, and no
filtering policy is installed in this exercise. The Unit 12 continuation of
the later NS6 configuration project measures a separate restrictive policy.
Keep that purpose distinct from this early mechanism observation.

Complete network-notes.md with the five-stage table, both endpoint views,
translation matches, the fresh failed mapped request, the successful direct
retest and cleanup. Label edge-cases.md as constructed Internet-edge reasoning.
For independent review, predict each translation before opening its result.
For paced review, pause at source translation, destination translation and
mapping removal before drawing the next conclusion.

Optional Python practice summarizes the requested mapped endpoint, observed
server endpoint, pre/post-SNAT peer addresses, whether the removed mapping
yielded HTTP and whether the direct path remains usable. Compare with the
separate reference after completing the observation and explanation.

## Further protocol detail

[Linux Ethernet bridging](https://www.kernel.org/doc/html/latest/networking/bridge.html)
and the [bridge command reference](https://man7.org/linux/man-pages/man8/bridge.8.html)
describe the bridge and FDB. This guide and its retained commands define the
scope of the actual exercise; it does not cover VLANs, STP convergence or every
switch/router feature.
