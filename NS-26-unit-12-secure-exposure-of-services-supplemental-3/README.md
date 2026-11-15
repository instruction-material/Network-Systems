# Exposure extension: match the destination after translation

The original published tuple is selected, but the new-connection rule compares the packet destination port with the public-side port after DNAT has already changed it. Predict why both baselines work while the legitimate published request fails under this policy. Correct only the packet destination-port match in the filter case of lab-rules.sh.

This is a separate optional investigation after the core project. Keep its saved attempt and reference separate from the core notebook.

## Environment and files

Use a disposable Linux VM with root access and network namespaces enabled, such
as Ubuntu 24.04. This kernel lab cannot run in the website's Python IDE, on macOS,
or in containers that prohibit network and mount namespaces. Read the shared README.md in the exported root, then enter the selected starter or solution directory. Keep create_nat_lab.sh, lab_runtime.py, lab-rules.sh and network-notes.md together in that role directory. The shared guide remains one level above it.

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

## Predict, run and correct the selected case

The original published tuple is selected, but the new-connection rule compares the packet destination port with the public-side port after DNAT has already changed it. Predict why both baselines work while the legitimate published request fails under this policy. Correct only the packet destination-port match in the filter case of lab-rules.sh.

Change only the selected case in lab-rules.sh. The supplied forwarding, other translation cases and apparatus remain unchanged. Use the diagram and saved rules to justify the correction.

```sh
sudo bash create_nat_lab.sh --exposure-policy --output first-observations.json
sudo bash create_nat_lab.sh --exposure-policy --output corrected-observations.json
```

Use the second command only after the correction. Each report filename must be new; every run creates fresh namespaces and does not inherit a prior run's rules.

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

## Observe the exposure pass

Run with --exposure-policy. The first six routing/translation observations must still work. The next direct and mapped baselines prove both paths work before filtering. Compare policy-mapped-allowed and policy-direct-blocked as actual request outcomes; these stage names describe the intended tests and do not guarantee success.

The selected policy belongs to the owned router's FORWARD chain. Its default is DROP, with a separate ESTABLISHED,RELATED allowance and a narrower NEW/ORIGINAL allowance. Inspect the actual saved rules, original tuple, translated destination and counters rather than inferring the policy from its label. These observations concern fresh connections. They do not revoke an already established session or measure the router's own INPUT/OUTPUT policy.

The final policy-direct-restored observation follows removal of only this private filter; routes and NAT remain. Reconcile the restored response with the same owned service and run token. Counted drops support a rule-path observation; they are not retained system-log messages.

Reference for the named match fields: [Netfilter conntrack options](https://ipset.netfilter.org/iptables-extensions.man.html).
## Evidence, recovery and review

Record the owned VM, console/snapshot, hostname, UID, tool versions, namespace identities and exact issuing command. Keep the prediction, first report, edited lab-rules.sh and corrected report together. Match every successful response token, server/peer address and port to the corresponding route and kernel-rule view. An incomplete task still retains a report; a zero launcher status alone does not establish task completion.

Each run creates fresh private network and mount namespaces and a private namespace registry. The supplied apparatus stops and reaps its owned HTTP worker, removes its namespaces and compares the measured outer interfaces, routes, forwarding and firewall configuration. Existing report filenames are refused. Preserve the actual cleanup fields and raw errors. Only the supplied owned experiment is in scope.

For independent study, explain the first differing stage before comparing the reference. In a guided review, pause at topology, prediction, first failure, correction and recovery. The reference explains the supplied configuration; fill in current observations from an actual run. Python programming is optional; the task is the rule choice, Linux evidence and explanation.

This is IPv4 routing/translation in a disposable local topology. It does not establish public Internet exposure, IPv6 forwarding, SSH authentication or TLS. The HTTP service supplies a run identity rather than a production application.
