# Course Source Manifest

Canonical source repository: `Network-Systems`

## Mapped Catalog Courses

- `network-systems`: Network Systems

## Verification Gate

- Run `./verify-course-source.sh` from this repository root before treating the source pack as ready.
- The verification gate checks for this manifest, the source backlog ledger, source-like files, removed Replit metadata, and any repo-specific readiness files.
- Project-specific unit tests or build commands should still be run inside individual project folders when a project includes its own test harness.

## Active Catalog Targets

| Folder |
| --- |
| `NS-01-network-systems-lab-15` |
| `NS-01-ns0-setup-and-tooling-supplemental-2` |
| `NS-02-network-systems-lab-16` |
| `NS-02-ns0-setup-and-tooling-supplemental-3` |
| `NS-03-network-systems-lab-17` |
| `NS-03-unit-1-the-network-stack-in-plain-english-supplemental-2` |
| `NS-04-ns0-setup-and-tooling` |
| `NS-04-unit-1-the-network-stack-in-plain-english-supplemental-3` |
| `NS-05-unit-1-the-network-stack-in-plain-english` |
| `NS-05-unit-2-addresses-and-naming-supplemental-2` |
| `NS-06-unit-2-addresses-and-naming` |
| `NS-06-unit-2-addresses-and-naming-supplemental-3` |
| `NS-07-unit-3-switches-routers-nat-and-the-internet-edge` |
| `NS-07-unit-3-switches-routers-nat-and-the-internet-edge-supplemental-2` |
| `NS-08-unit-3-switches-routers-nat-and-the-internet-edge-supplemental-3` |
| `NS-08-unit-8-ipv6-in-practice` |
| `NS-09-unit-11-common-application-protocols` |
| `NS-09-unit-4-ports-and-listening-services-supplemental-2` |
| `NS-10-ns13-expansion-ideas-and-next-steps` |
| `NS-10-unit-4-ports-and-listening-services-supplemental-3` |
| `NS-11-unit-5-dns-and-name-resolution-supplemental-2` |
| `NS-12-unit-5-dns-and-name-resolution-supplemental-3` |
| `NS-13-unit-6-core-diagnostics-supplemental-2` |
| `NS-14-unit-6-core-diagnostics-supplemental-3` |
| `NS-15-unit-7-linux-interface-and-route-management-supplemental-2` |
| `NS-16-unit-7-linux-interface-and-route-management-supplemental-3` |
| `NS-17-unit-8-ipv6-in-practice-supplemental-2` |
| `NS-18-unit-8-ipv6-in-practice-supplemental-3` |
| `NS-19-unit-9-firewalls-and-host-policy-supplemental-2` |
| `NS-20-unit-9-firewalls-and-host-policy-supplemental-3` |
| `NS-21-unit-10-packet-capture-and-deep-inspection-supplemental-2` |
| `NS-22-unit-10-packet-capture-and-deep-inspection-supplemental-3` |
| `NS-23-unit-11-common-application-protocols-supplemental-2` |
| `NS-24-unit-11-common-application-protocols-supplemental-3` |
| `NS-25-unit-12-secure-exposure-of-services-supplemental-2` |
| `NS-26-unit-12-secure-exposure-of-services-supplemental-3` |
| `NS-27-ns13-expansion-ideas-and-next-steps-supplemental-2` |
| `NS-28-ns13-expansion-ideas-and-next-steps-supplemental-3` |
| `NS-29-applied-studio-15-network-systems-lab-15-supplemental-2` |
| `NS-30-applied-studio-15-network-systems-lab-15-supplemental-3` |
| `NS-31-applied-studio-16-network-systems-lab-16-supplemental-2` |
| `NS-32-applied-studio-16-network-systems-lab-16-supplemental-3` |
| `NS-33-applied-studio-17-network-systems-lab-17-supplemental-2` |
| `NS-34-applied-studio-17-network-systems-lab-17-supplemental-3` |
| `NS1-Listening-Services-Map` |
| `NS2-Local-vs-Remote-Reachability-Diagnosis` |
| `NS3-UFW-Web-Server-Policy` |
| `NS4-IPv4-vs-IPv6-Resolution-Comparison` |
| `NS5-Tcpdump-HTTP-Capture` |
| `NS6-Router-NAT-Topology-Lab` |

## Source Inventory

- Top-level course folders: 50
- Active linked folders: 50
- Ledgered inactive/support folders: 2
- Source-like files: 290

## Scoped Native Acceptance

The workflow in `.github/workflows/native-network.yml` exercises two introductory
foundations and three addressing/naming packs as an ordinary Linux user. Separate
root-only gates exercise the owned NS6 router/NAT topology, NS5 HTTP capture and
NS3 UFW policy in disposable Linux namespaces. The UFW gate checks actual fresh
allow/deny requests, a nondefault management marker, prior-rule preservation,
private policy rollback and interruption cleanup. Inspect the exact revision's
retained native evidence; a source-only result is not native acceptance.

The NS2 reachability gate also uses owned ordinary-user HTTP services, IPv4/IPv6
literals, changed ports, refusal, application deadlines and a controlled hung
command. It distinguishes TCP connection from application response and does not
claim a second-machine path or inspect privileged firewall policy.

The NS1 listener gate observes owned TCP and UDP sockets, visible process
ownership, filtered and broader views, empty selections and process cleanup
without sending service probes. Its command helper is the unchanged NS2 verifier.

The NS4 resolution gate observes an owned unprivileged DNS server and separate
system NSS lookups. It retains typed records, negative DNS answers, transport
failures and resolver cleanup without changing system name-service files. DNS
answer families do not certify application reachability.

Three IPv6 packs now supply an ordinary-account IPv6-only/paired endpoint
experiment, independent /126-/127-/128 calculations and explicit supplied
neighbor/policy/configuration reasoning. The native gate covers the actual
loopback observations and optional analyses; it does not certify active Neighbor
Discovery, Router Advertisement, DHCPv6, firewall policy or notebook completion.

The workflow has scoped native gates for NS1-NS6 and these IPv6 packs. The 30
remaining generic Python pairs are not certified by these gates. `test/` and `.github/workflows/` are
validation support, not additional learner assignments.

Three application-protocol packs supply actual HTTP requests/responses, independent conditional-request and response-policy tasks, exact binary bytes, an owned held-port refusal and complete source guides. Their ordinary-user native gate retains raw wire bytes, curl corroboration, process identity and cleanup. Supplied DNS/TLS/SSH cases are constructed; notebook completion is not inferred.

Three Unit3 observation packs now distinguish a real Linux bridge, routed gateway/return paths, SNAT and destination/port mapping in owned network/mount namespaces. Complete guides keep this introductory observation purpose distinct from later NS6 command editing and Unit12 policy work. Native acceptance retains actual MAC/FDB, routes, raw HTTP, endpoint views, host comparisons and cleanup; it does not infer notebook completion or Internet reachability.

## Routed operations capstone

`NS-03-network-systems-lab-17` replaces the generic port-string normalizer with
an owned Linux dual-stack client/router/server fixture. The starter has two
configuration faults; the reference and an independent completed attempt must
pass the actual DNS, route, proxy, policy, packet and cleanup contracts.
The separate `native-capstone` CI job retains four completed profiles, the two
unfinished profiles, a route-only intermediate correction, three controlled
regressions and a live interruption/isolation check. All prior native cohorts
remain required. `network-notes.md` and `edge-cases.md` need actual observations;
code success does not establish their completion. Source/native acceptance and
site import integration are separate gates.

## Optional setup context and argument investigations

The NS0 transfer pack now diagnoses actual command selection and child working
directory independently. Its separate extension compares direct argv with real
quoted/unquoted Bash expansion. Both use ordinary-user owned fixtures, complete
guides, case configuration and evidence notebooks. The reference and independent
completed source differ from the starter only in case.json. Native verification
retains actual execve/chdir traces, twelve role/fixture profiles, a one-field
correction, refusal cases and controlled regressions. All previous Linux and
capstone cohorts remain required. Runtime success does not infer notebook
completion; site import integration is a separate gate.
