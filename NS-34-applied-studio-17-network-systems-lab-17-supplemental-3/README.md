# Operations Capstone Extension Practice: Identify a responding backend

This separate optional practice follows the required routed capstone. A proxy
can connect and return HTTP 200 from an owned application that is the wrong
backend for the task. Diagnose that service-identity mismatch while preserving
working routes, resolver answers and least-exposure policy.

## Prepare the isolated Linux lab

Use an owned Linux VM with root access and network/mount namespace support.
The source workspace edits, saves and exports files; run the exported project
in that Linux VM. Python is supplied apparatus; the task is network diagnosis,
case configuration and an evidence-based explanation.

On an administered Debian/Ubuntu practice VM, prepare the tools once:

    sudo apt-get update
    sudo apt-get install python3 iproute2 iptables util-linux curl dnsutils tcpdump dnsmasq-base

Record distribution, kernel and tool versions. A missing command or refused
namespace is a prerequisite failure, separate from the intended case fault.
Each role contains main.py, capstone_lab.py, case.json, network-notes.md and
edge-cases.md. Keep them together and read this shared README.md. The learner
and reference workspaces keep separate source, notebooks and output folders.

The fixture creates an outer private network and mount context, private /run
and three owned client/router/server namespaces. Its IPv4 endpoints use the
reserved 198.18.0.0/15 range; IPv6 uses 2001:db8::/32. Its fictional names end
in .capstone.test. Host resolver files and persistent services are unchanged.
The fixture removes its own namespaces/workers and compares the calling
host's routes, links and firewall configuration before and after each run.

## Locate the endpoints

| Endpoint | Default value | Role |
| --- | --- | --- |
| Client and next hop | 198.18.31.2/30; 198.18.31.1 | Request source and directly connected router |
| Server link | 198.18.32.0/30 | Router .1; server .2 |
| Client IPv6 and next hop | 2001:db8:31::2/64; ::1 | Separate IPv6 routed path |
| Server IPv6 | 2001:db8:32::2/64 | Resolver/proxy destination |
| Resolver | server UDP 15353 | Owned A/AAAA answers |
| Public proxy | server TCP 8080 | Forwards to a loopback application |
| Intended backend | 127.0.0.1:9000 | Correct application identity |
| Denial control | server TCP 8088 | Owned listening control, denied directly to the client |

The server has a return route through its router. The router forwards both
families. The server permits the declared client to query the resolver and
contact the proxy, allows loopback/established replies and required IPv6
control traffic, and drops other new client traffic. The backend binds only
to loopback. A denied probe needs a viable route and an actual listener before
it supports a policy interpretation.

The resolver answers blue.capstone.test. Queries over IPv6 can return an IPv4
A answer even when the later IPv4 route fails. Keep resolver transport, record
type and application destination separate.

## Predict the identity, not only the status

case.json initially contains the correct server route 198.18.32.0/30 and sets
proxy_upstream_port to the owned control listener 8088. The intended backend
is 127.0.0.1:9000. The control is deliberately reachable from server loopback,
even though direct client access to its external socket is denied.

From the extracted learner directory:

    sudo python3 main.py --output ./identity-first

The unfinished case exits 1 with completed=false, while both proxy requests
can return HTTP 200. Read each response body and service.log's proxyTarget.
The wrong response has fixture = owned-denial-control. Its token belongs to the
same owned experiment, so a matching token alone is insufficient. The required
body identifies owned-operations-capstone, the run's token and /health.

Check the recorded route selection, A/AAAA answers, actual listening endpoints
and policy first. Successful routing and TCP narrow the diagnosis; they do not
identify which responding application generated the proxy body. The proxy
header identifies the intermediate proxy, and does not certify its backend.
The recorded target distinguishes 8088 from the intended loopback port 9000.

Change only proxy_upstream_port to 9000. Retain the route and every earlier
output. Run:

    sudo python3 main.py --output ./identity-corrected

Reconcile service.log, the 127.0.0.1:9000 listener, the correct fixture label and
per-run token over both families, /health 200 and /missing 404. Check the two
direct control probes and direct backend probe remain denied. Compare
completed=true and exit 0 with the earlier false case; HTTP 200 alone is not
the completion criterion.

Explain why the proxy can reach the control over loopback while a direct client
probe fails the server policy. The control remains a separate owned service;
broadening its exposure is not a correction. Keep raw bodies, configurations,
commands, packet evidence and the actual cleanup records for both states.
Compare the reference only after an independent endpoint/identity diagnosis.

## Repeat with changed endpoints

    sudo python3 main.py --alternate --output ./alternate-observation

The alternate case changes the client link to 198.18.41.0/30 and
2001:db8:41::/64, the name to amber.capstone.test and the proxy port to 8087.
The server link, intended backend 9000 and control 8088 stay fixed. Predict the
changed source addresses, client next hop, policy rows, name and packet ports
before comparing the new run. Use its own token and exact source case.

Keep receipt.json, inside.json, commands.json, parent-commands.json,
case-used.json, service/DNS/capture logs, response bodies and capture.pcap.
The report records commands after the owned topology has been removed.
Re-run into a fresh folder for another observation; those names are not a
persistent environment to probe after completion. The bounded capture observes
the server interface, proxy TCP and resolver UDP. It supports only that run's
plaintext exchanges, not encrypted payload visibility or general reliability.

## Cleanup, interruption and review

Confirm allWorkersReaped, an empty remainingNamespaces list, distinct private
network/mount identities and receipt.json's actual before/after comparison.
A successful HTTP request does not establish cleanup. Preserve failures and
interrupted attempts separately. The fixture has a 35-second outer run bound,
supervised commands and worker cleanup. Use Ctrl-C to cancel an owned running
attempt; keep its nonzero cancellation and recovery evidence.

For an optional interruption observation, run:

    sudo python3 main.py --hold-after-ready 15 --output ./interruption-observation

In a second terminal check for interruption-observation/ready.json. Once it
exists, press Ctrl-C in the first terminal during the hold. If the hold ended,
retain that ordinary result and use a new output folder for the next attempt.
Compare actual reaping and host restoration with a normal completed run.
Namespace or firewall support may be restricted by the VM/container. Preserve a
prerequisite error and stop that attempt instead of changing host protections.

Complete network-notes.md and the named edge cases with actual predictions,
commands, failed and corrected observations, one rejected alternative, the
first failing boundary and a limitation. Independent work records the diagnosis
before consulting the reference. A guided walkthrough pauses at the first
route result, application body and recovery check, using the same evidence.
A passing configuration does not fill the notebook or complete the explanation.
