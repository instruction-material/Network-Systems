# NS6 Router, NAT and Port Mapping Lab

Build a real, disposable Linux network with a client, a router and a server.
Observe a routed HTTP request, source address translation (SNAT), and a destination
address and port mapping (DNAT). Explain each change using the actual server's
response and the router's kernel rules.

This is a required Linux command and observation project. The supplied Python
apparatus creates the topology, makes requests and records evidence. Writing
Python is not a prerequisite. In a classroom, partners can alternate driver and
observer after each stage. In an individual lesson, make the same predictions
before comparing the evidence with an instructor.

## Environment and files

Use a disposable Linux VM with root access and network namespaces enabled, such
as Ubuntu 24.04. This kernel lab cannot run in the website's Python IDE, on macOS,
or in containers that prohibit network and mount namespaces. Download all files
from one role folder together. Keep `create_nat_lab.sh`, `lab_runtime.py`,
`lab-rules.sh`, `network-notes.md` and this README in that folder.

On the disposable VM, install the standard tools if they are missing:

```sh
sudo apt-get update
sudo apt-get install -y python3 iproute2 iptables util-linux curl
```

The lab itself needs no Internet access and uses only Python's standard library.
The root launcher refuses other operating systems and missing tools before
changing the network. Root privileges are needed for the isolated kernel setup.

## Read the topology

| Namespace | Interface | Address | Default gateway |
| --- | --- | --- | --- |
| Client | c0 | 10.10.0.2/24 | 10.10.0.1 |
| Router, client side | rl0 | 10.10.0.1/24 | none |
| Router, server side | rr0 | 10.20.0.1/24 | none |
| Server | s0 | 10.20.0.2/24 | 10.20.0.1 |

A virtual Ethernet pair joins c0 to rl0; another joins rr0 to s0. Each `/24`
contains its own directly connected subnet. A request for the other subnet goes
to the client's default gateway. The router knows both connected routes. The
server's default route provides the return path. IP forwarding controls whether
the router transfers packets between its interfaces. Its own interface addresses
are reachable independently of whether forwarding is enabled.

The server listens on TCP port 8080. The router's client-side port 18080 is the
entry point for the DNAT exercise. TCP ports identify services; subnet prefixes
identify address ranges. Changing a port is different from changing a route.

Both networks use private addresses. Correct routes and forwarding already let
them communicate. NAT is not required here for basic routing. It is added so its
effect can be measured. This lab does not represent a public Internet connection.

## Complete and run the starter

First fill the predictions in `network-notes.md`. Run the untouched starter:

```sh
sudo bash create_nat_lab.sh --output starter-observations.json
```

It creates the apparatus and records blocked requests, then reports `Incomplete
starter`. A successful apparatus run does not mean the exercises are complete.
An isolation, command or cleanup error instead stops with a nonzero exit status.

For Unit7, edit the first three cases in `lab-rules.sh`. The apparatus passes the current
owned router namespace as `$router`. Prefix every kernel command with
`ip netns exec "$router"` so it runs in that namespace.

1. **Forwarding:** use `sysctl -qw` to set `net.ipv4.ip_forward=1` inside the
   router. This enables the already configured route between the subnets.
2. **SNAT:** add a rule with `iptables -t nat -A POSTROUTING`. Match source
   `10.10.0.0/24`, destination `10.20.0.2/32`, TCP destination port `8080`, and
   outgoing interface `rr0`. Choose target `SNAT` with `--to-source 10.20.0.1`.
   The relevant match flags are `-s`, `-d`, `-p tcp`, `--dport`, and `-o`.
3. **DNAT:** add a rule with `iptables -t nat -A PREROUTING`. Match incoming
   interface `rl0` (`-i`), destination `10.10.0.1/32`, and TCP destination port
   `18080`. Choose target `DNAT` with `--to-destination 10.20.0.2:8080`.

Use `-j` to select each target. Run again with a new output filename. Fresh
namespaces ensure a previous run cannot supply missing rules. The reference
folder contains the completed rules and the identical apparatus.

```sh
sudo bash create_nat_lab.sh --output completed-observations.json
python3 -m json.tool completed-observations.json
```

## Interpret the measured stages

The JSON report contains the actual addresses, routes, `iptables-save` output,
forwarding setting, HTTP response bodies and failed curl exit statuses. Each
response includes a random run token, the peer address seen by the server, its
own address and port, and the requested path. These are live observations, not
simulated packet traces or prefilled expected results.

| Stage | Client request | Expected completed behavior |
| --- | --- | --- |
| forwarding-off | 10.20.0.2:8080 | fails; router forwarding is zero |
| routed | 10.20.0.2:8080 | succeeds; server sees peer 10.10.0.2 |
| snat | 10.20.0.2:8080 | succeeds; server sees peer 10.20.0.1 |
| dnat | 10.10.0.1:18080 | succeeds at server 10.20.0.2:8080; peer is 10.20.0.1 |
| mapping-removed | 10.10.0.1:18080 | a fresh request fails after removing the mapping |
| direct-after-removal | 10.20.0.2:8080 | still succeeds with SNAT |

SNAT runs after routing chooses an outgoing interface. DNAT runs before that
choice, so the translated destination is routed toward the server. Connection
tracking reverses translations on replies. The apparatus makes fresh TCP
connections for each observation because existing tracked connections can retain
earlier mappings. It removes only the owned router's PREROUTING mappings before
the last two requests.

The DNAT request also matches the earlier SNAT rule after destination translation.
That explains its observed peer address. Removing DNAT does not remove routes,
forwarding or SNAT. The final direct request distinguishes removal of one mapping
from loss of the entire network. The default six-stage run installs no filtering
policy. Complete the additional Unit12 procedure below to measure an actual
restrictive forwarding policy.

## Cleanup and troubleshooting

Each run enters new network and mount namespaces before creating resources. A
private `/run` contains only that run's namespace registry. Interface names fit
Linux's 15-byte limit. The apparatus never preemptively deletes a host namespace.
It stops and reaps its owned HTTP process, removes its owned namespaces, and
compares the original host's interfaces, routes, forwarding and firewall rules
before and after. The raw firewall snapshots retain packet counters; the
configuration comparison ignores only timestamp comments and advancing chain
counters, while preserving chain names, policies, all rules and their order.
Normal completion, reported errors and Ctrl-C use the cleanup
path. Output evidence remains available after the disposable network is removed.

`Operation not permitted` from `unshare` means the VM/container policy does not
allow this lab. Use the required disposable VM. Do not weaken a host's security
settings to force it to run. A report that says `Incomplete starter` means compare
the first differing stage with its forwarding value and rule output. A timeout
alone does not identify a route or NAT defect; use the successful server-local
readiness probe and later observations as additional evidence.

## Unit7 evidence

Keep your edited rules, predictions and actual JSON report. Explain the two
default gateways, the difference between routing and forwarding, the exact peer
address change caused by SNAT, and why the forwarded port stops working while
the direct request still succeeds. Identify the limit of each conclusion.

## Unit12: restrict exposure and verify the boundary

Continue the same saved project and notebook. This is the Secure Exposure
capstone pass, not a second router setup project. The Unit7 apparatus and three
completed routing/translation cases remain useful. The fourth `filter` case is
required for this pass. Do not replace a working attempt with the reference.

The policy permits new client requests to the published router endpoint
`10.10.0.1:18080`, translated to the server at `10.20.0.2:8080`. It drops other
new forwarded requests, including a fresh request directly to that same server
service. Established and related forwarded traffic remains allowed. This is an
IPv4 FORWARD policy inside the disposable router; it does not filter the router's
own INPUT or OUTPUT traffic or revoke an already established connection.

Before editing, predict why a rule allowing all traffic to server port 8080 would
fail to enforce this policy. Both the direct request and a DNAT request have the
same destination by the time they reach FORWARD. Connection tracking retains
the original destination and port before translation, so those fields distinguish
the published endpoint from a bypass of the mapping.

The option definitions are in the
[Netfilter conntrack reference](https://ipset.netfilter.org/iptables-extensions.man.html).
The explanations and commands below supply the information needed for this lab.

In the `filter` case, prefix each command with `ip netns exec "$router"`:

1. Set the FORWARD chain's default policy to DROP with
   `iptables -P FORWARD DROP`. This affects only the owned router.
2. Append an ACCEPT rule for `-m conntrack --ctstate ESTABLISHED,RELATED`.
   This permits the rest of an accepted connection and its return packets.
3. Append an ACCEPT rule for new client requests. Match `-i rl0 -o rr0`,
   source `10.10.0.0/24`, translated destination `10.20.0.2/32`, and
   `-p tcp --dport 8080`. Add `-m conntrack --ctstate NEW --ctdir ORIGINAL`,
   `--ctorigdst 10.10.0.1` and `--ctorigdstport 18080`. Use `-A FORWARD` to
   append each rule and `-j ACCEPT` for the target. Keep the general established
   rule separate from this narrower rule for new connections.

Run this pass from the extracted role folder:

```sh
sudo bash create_nat_lab.sh --exposure-policy --output exposure-observations.json
python3 -m json.tool exposure-observations.json
```

The apparatus first runs the six routing/NAT stages, then restores the DNAT
mapping and adds these five observations. Every row makes a fresh TCP connection
and uses the same live, owned HTTP server. The run token identifies its responses.

| Additional stage | Fresh client request | Expected completed behavior |
| --- | --- | --- |
| policy-baseline-direct | 10.20.0.2:8080 | succeeds before restriction |
| policy-baseline-mapped | 10.10.0.1:18080 | succeeds before restriction |
| policy-mapped-allowed | 10.10.0.1:18080 | succeeds while FORWARD defaults to DROP |
| policy-direct-blocked | 10.20.0.2:8080 | fails under the restrictive policy |
| policy-direct-restored | 10.20.0.2:8080 | succeeds after removing only the FORWARD filter |

Inspect `filterRules`, `policyBeforeInterruption` and `policyCounters` in the
report. They retain actual `iptables-save -c -t filter` output. The DROP policy
counter must increase, the original-endpoint NEW rule must accept packets, and
the ESTABLISHED rule must accept later/return packets. A timeout without these
observations does not establish which device or rule blocked the request.

The final stage flushes only the owned router's FORWARD rules and restores its
ACCEPT policy. Routes, forwarding, DNAT, SNAT and the server stay in place.
Successful direct access after this change distinguishes filtering from a dead
service or broken route. The reference's complete report requires both the
traffic results and nonzero kernel policy/rule counters. Completing the three
Unit7 cases while leaving `filter` blank must still report `Incomplete starter`
for this pass, even though the server is reachable.

Record the before/after policy, counters, original and translated endpoints, and
the fresh direct/mapped results in the notebook. Explain the rule that matches
the first packet and the rule that admits replies. State why preexisting tracked
connections, router-local services, IPv6, other clients and public Internet
reachability need separate tests before making broader security claims.

For an instructor walkthrough, pause at each baseline, after applying the policy,
and after removal. Partners can alternate who predicts the rule match and who
finds the corresponding kernel evidence. Keep the edited rules, both reports,
reasoning and cleanup evidence together as completion evidence.
