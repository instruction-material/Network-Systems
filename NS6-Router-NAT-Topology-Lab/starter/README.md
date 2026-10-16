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

Edit only the three cases in `lab-rules.sh`. The apparatus passes the current
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
from loss of the entire network. No filtering policy is installed here: this is a
translation and reachability experiment, not proof of a firewall or access policy.

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

## Required evidence and extension

Keep your edited rules, predictions and actual JSON report. Explain the two
default gateways, the difference between routing and forwarding, the exact peer
address change caused by SNAT, and why the forwarded port stops working while
the direct request still succeeds. Identify the limit of each conclusion.

An optional extension is to design a restrictive forwarding policy on paper:
which direction and TCP port should it allow, and what return traffic would need
to pass? State the additional kernel rules and measurements needed to test that
policy. Do not describe it as an implemented firewall experiment.
