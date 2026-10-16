# Routed Operations Capstone

This investigation joins addressing, routing, name resolution, listeners, application responses, least-exposure policy, packet interpretation and recovery in one owned client-router-server topology. The supplied Python program maintains the fixture. The capstone work is to predict its behavior, diagnose two independent configuration faults, correct the case and preserve an evidence-based operations runbook. A successful automated run is one part of completion; the explanation and cleanup evidence are also required.

The starter deliberately contains a wrong IPv4 destination prefix and a wrong loopback upstream port in `case.json`. Both defects are visible through real Linux behavior. Keep the first observation before editing. The reference uses the same fixture with a completed configuration. Keep the attempts separate so the first failure, intermediate correction and final explanation remain available.

## Native target and scope

Use an owned Linux VM or lab with root access and support for network and mount namespaces. On macOS use a Linux VM; on Windows use a Linux environment that supports these namespace and firewall operations. The browser workspace edits, saves and exports the source. This native experiment runs after downloading and extracting the complete selected role.

The program creates an outer private network/mount context, a private `/run`, and three temporary network namespaces. It changes routes, forwarding and firewall rules inside that context, then removes the workers and namespaces. It checks the calling host's link, route and firewall configuration before and after. Preserve the raw comparison and the actual namespace identities. Root access alone does not establish that isolation succeeded.

Every endpoint belongs to the fixture: IPv4 uses the reserved `198.18.0.0/15` range; IPv6 uses `2001:db8::/32`; names end in `.capstone.test`. The experiment requires no public domain, certificate, router configuration, cloud credential or third-party target. It supplies an explicit local resolver address and port instead of changing the system resolver configuration.

On a Debian/Ubuntu lab, the administrator can prepare the tools with:

```sh
sudo apt-get update
sudo apt-get install python3 iproute2 iptables util-linux curl dnsutils tcpdump dnsmasq-base
```

Record the exact distribution, kernel and tool versions. Namespace creation, IPv6 or firewall support can be unavailable in restricted containers. A prerequisite failure is not evidence of a diagnosed network case. Read its error and stop that attempt; retain it separately from the two intentional case faults.

## Read the topology before running it

| Node | IPv4 link | IPv6 link | Purpose |
| --- | --- | --- | --- |
| Client | `198.18.31.2/30` | `2001:db8:31::2/64` | Requests the owned service |
| Router, client side | `198.18.31.1/30` | `2001:db8:31::1/64` | Client's next hop |
| Router, server side | `198.18.32.1/30` | `2001:db8:32::1/64` | Server's next hop |
| Server | `198.18.32.2/30` | `2001:db8:32::2/64` | Resolver and reverse proxy |

The client and server occupy different links. Each needs a route to the other side through its directly connected router address. The router has both connected prefixes and enables forwarding for both families. A route chooses the next hop; a successful route lookup alone does not prove that a listener, policy or application request will succeed. The return route is a separate requirement.

The server's application binds to `127.0.0.1:9000`. A dual-stack proxy listens on the lab server's port `8080` and makes a new connection to that loopback application. The IPv6-facing proxy can therefore use an IPv4 loopback upstream. This is an application boundary, rather than evidence of a direct IPv6 application listener.

The explicit resolver supplies A and AAAA records for `blue.capstone.test` over unicast UDP port `15353`. Its A answer selects the IPv4 destination; its AAAA answer selects the IPv6 destination. Record which resolver transport was used separately from the record type requested. An A answer obtained over IPv6 does not establish that the returned IPv4 address is reachable.

The server policy permits the declared client to query UDP `15353` and reach the proxy's TCP `8080`. It permits loopback traffic, established replies and the IPv6 control traffic needed by the topology. It drops other new client traffic. A separate process listens on TCP `8088` as a denial control: record both that listener and the failed client connection. The backend port `9000` remains loopback-only. Explain each allowed tuple and the reason for each denial instead of treating all listening ports as intended services.

## Preserve the first observation

From the extracted selected role, use a fresh output directory for each attempt:

```sh
cd starter
sudo python3 main.py --output ./first-observation
```

The unfinished case exits nonzero. Keep `receipt.json`, `inside.json`, `commands.json`, `parent-commands.json`, the service/DNS/capture logs, response bodies and `capture.pcap`. The output folder must not already exist, protecting an earlier attempt from accidental replacement. The program prints the actual output directory and lab exit status.

Read the recorded commands and outputs after the run. The namespaces and listeners have already been removed. These are observations from that run, rather than commands aimed at a still-running environment. Re-run the fixture into a new folder when another observation is needed.

For each family, write an evidence ladder: address, route and next hop; successful name query; listener and policy; connection; HTTP status and body; cleanup. Identify the first failed boundary before proposing a change. Retain the actual command, relevant output, interpretation and one limit for each step.

## Diagnose two different layers

The starter IPv4 route points to a different reserved subnet. Inspect the recorded route table and `routeGet4`; compare the requested destination with the route's prefix and next hop. A missing route is earlier evidence than a failed HTTP request. The IPv6 path remains separately configured. Use its DNS and proxy observations to avoid assigning every symptom to the name service.

The proxy's upstream port is the second defect. A proxy-generated HTTP `502` shows that a connection reached the proxy and that its attempt to contact the configured upstream failed. Compare its configured port, the actual loopback listener and the service log. Keep this application-boundary diagnosis separate from the IPv4 route failure.

Change only the route in `case.json`, then run again into `route-corrected`. Record which failures disappear and which remain. Correct the upstream port only after predicting the next result, then run into `both-corrected`. Preserve the two edited values and the reasons for them. The reference can be consulted after the local diagnosis; run it in its separate role and a new output folder.

The completed case must resolve both record types, reach the correct owned response over both families, receive an application `404` for `/missing`, deny the two TCP `8088` probes and deny direct access to the backend. Check the response body and the actual per-run token as well as status `200`. A successful status alone can come from the wrong process or response.

## Interpret the bounded capture

The capture records only the owned service interface, selected proxy port and resolver UDP port. It stops at a packet limit and is also supervised by a run deadline. Retain the PCAP alongside its recorded textual decoding. Name the source/destination addresses, transport ports, request/response direction and the observations supporting a handshake or reply.

Compare IPv4 and IPv6 evidence rather than inferring one from the other. Separate a DNS answer from the later connection and an HTTP response from an application success. This fixture uses plaintext HTTP, making headers and small bodies observable. The same visibility cannot be assumed for an encrypted payload. A finite capture also cannot establish general performance, reliability or internet reachability.

## Repeat, recover and explain

```sh
sudo python3 main.py --alternate --output ./alternate-observation
```

The changed case uses the client-side `198.18.41.0/30` and `2001:db8:41::/64` links, the name `amber.capstone.test` and proxy port `8087`. The server-side prefix and backend port stay the same. Predict the affected routes, policy addresses, DNS name and packet endpoints before comparing actual results. Explain what this variation tests and which assumptions it leaves unchanged.

For every attempt, check `allWorkersReaped`, the empty remaining namespace list, and the parent's actual before/after configuration comparison. These checks are distinct from an application response. The fixture also supports a bounded ready hold for interruption verification; this is a native validation control, not a persistent service or deployment mode. Preserve interruption and failure evidence with its cleanup result.

Complete `network-notes.md` and `edge-cases.md` with the boundary card, topology, versions, predictions, first failures, intermediate correction, final retests, policy matrix, packet interpretation and recovery. Name one remaining limitation. Independent work and a paced walkthrough use the same saved evidence. A walkthrough can pause at scope, each route, resolver transport, listener ownership, each first failure, corrected retest and final cleanup. Optional transfer/extension work follows this completed capstone and keeps its own attempt.

Native namespace behavior is described in the [Linux `unshare` manual](https://man7.org/linux/man-pages/man1/unshare.1.html). Keep the fixture's actual version and recorded behavior beside that reference.
