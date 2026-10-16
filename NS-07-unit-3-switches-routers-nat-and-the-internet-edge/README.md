# Observe a Bridge, a Router and Source Translation

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

## Required observation: bridge, route and source translation

The client begins at 10.31.0.2/24 and the server at 10.31.0.3/24. Each is joined
by a virtual Ethernet pair to one port of br0 in the middle namespace. The peers
share an IP prefix and a bridged link. No default gateway is needed between
these peers. The middle namespace has IP forwarding disabled, yet the first
HTTP request succeeds. Read the two bridge ports, STP setting and forwarding
database (FDB). Match learned peer MAC addresses to the actual client/server
interface addresses. Forwarding an Ethernet frame inside the bridge is a
different operation from forwarding an IP packet between routed interfaces.

Predict the effect of taking the server-side bridge port down. The next request
has no HTTP response. The apparatus restores that port and makes a successful
fresh request. Compare the controlled link state and retained FDB rather than
treating the failed request alone as proof of a particular layer's defect.

The apparatus then removes its bridge and gives the server 10.32.0.2/24.
The middle interfaces become 10.31.0.1/24 and 10.32.0.1/24. Client and server
receive their respective middle address as a default gateway. These are now
different links and prefixes. The first cross-prefix request fails while
middle IP forwarding is zero. Enabling that setting permits a fresh request;
the server sees the original client address 10.31.0.2. Read the client route
lookup, both return routes and neighbor entries along with the application
record. The router routes these connected prefixes without needing NAT.

Finally, a narrowly matched source-translation rule changes the source address
seen by the server to 10.32.0.1. Match the actual reply and kernel NAT rule.
The client still requests 10.32.0.2 on the same service port. NAT changed a
connection view; it was not what made basic routing work and does not itself
establish a restrictive security policy.

Repeat `sudo python3 main.py --alternate --service-port 8087 --mapped-port 18087`.
The private prefixes become 10.41.0.0/24 and 10.42.0.0/24, and the server's
port changes. Predict the corresponding gateway, on-link and translated-peer
values. Use that run's token and process identities, and retain contrary results.

Complete network-notes.md with all six predicted and actual stages, the two
topologies, learned MAC/port matches, local-versus-gateway route decisions,
untranslated and translated endpoint views, restoration evidence and cleanup.
Read edge-cases.md as explicitly constructed Internet-edge reasoning. For
independent review, explain each boundary before reading its outcome. In a paced
walkthrough, pause between the bridge, routing and translation mechanisms.

Optional Python practice: summarize whether the bridge works with middle IP
forwarding off, whether its restoration succeeds, whether the routed-off stage
has an HTTP response, and the actual peer before and after source translation.
Keep the reference separate from the saved attempt.

## Further protocol detail

[Linux Ethernet bridging](https://www.kernel.org/doc/html/latest/networking/bridge.html)
and the [bridge command reference](https://man7.org/linux/man-pages/man8/bridge.8.html)
describe the bridge and FDB. This guide and its retained commands define the
scope of the actual exercise; it does not cover VLANs, STP convergence or every
switch/router feature.
