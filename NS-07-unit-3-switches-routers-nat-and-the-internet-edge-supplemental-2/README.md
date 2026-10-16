# Diagnose the Outbound Gateway and Return Route

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

## Optional transfer: gateway and return-path diagnosis

The client is 10.31.0.2/24 with gateway 10.31.0.1. The server is 10.32.0.2/24
with gateway 10.32.0.1. The middle namespace owns those gateway addresses on
separate interfaces and enables IP forwarding. There is no bridge and no NAT
rule in this task. Read the initial routes and successful application response
before interpreting either controlled failure.

The apparatus removes the client's default route. The selected server is not
in the client's connected /24, and the route lookup now fails. The attempted
HTTP connection supplies no application response. The server and middle routes
remain recorded separately. Restoring the same client gateway is followed by
a successful new request. Keep the absent/default route and its restoration
beside the client tool's exact exit status and stderr.

The next change removes the server's default route, while leaving the restored
client route and middle forwarding in place. The client's next request has no
HTTP response. Inspect the server's route lookup toward the client and the
connected prefix it still owns. Restoring its gateway permits another fresh
request. Explain why a usable outbound route on one endpoint is insufficient
evidence for a complete TCP/application conversation. Do not infer that this
particular failure can always be diagnosed from a timeout at one endpoint.

Compare both failures with the live service readiness, route inventories,
controlled changes and successful restoration requests. A neighbor entry does
not replace the route decision, and a route entry does not establish that an
application answered. The program makes no packet capture and therefore does
not claim to show a failed handshake's exact packet sequence. Its commands and
successful application records bound the supported conclusion.

Repeat `sudo python3 main.py --alternate --service-port 8087 --mapped-port 18087`.
Use the changed 10.41.0.0/24 and 10.42.0.0/24 prefixes and service port when
writing predictions. The mapped-port option remains unused by this task; there
is no destination mapping merely because a port value appears in the run
configuration. Retain each run's actual token, worker and socket identities.

Complete network-notes.md with a five-stage prediction/result table. Name which
endpoint's route changed, the other state that remained recorded, the failed
route lookup, raw connection result and successful retest. Include one
alternative explanation that the connection result alone would not exclude.
Use edge-cases.md only as constructed reasoning about an outside path. Verify
worker reaping, namespace/link cleanup and the outer host comparison.

For independent practice, write the missing evidence before comparing results.
For paced review, discuss the client-side failure and restoration before the
server-side pair. Optional Python practice summarizes the absent client/server
defaults, actual failed stage names and the peer in the final restored response.
The untouched attempt collects all observations without that summary.

## Further protocol detail

[Linux Ethernet bridging](https://www.kernel.org/doc/html/latest/networking/bridge.html)
and the [bridge command reference](https://man7.org/linux/man-pages/man8/bridge.8.html)
describe the bridge and FDB. This guide and its retained commands define the
scope of the actual exercise; it does not cover VLANs, STP convergence or every
switch/router feature.
