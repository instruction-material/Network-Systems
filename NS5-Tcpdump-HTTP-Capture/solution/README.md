# NS5 HTTP packet capture in an owned Linux lab

This project captures and explains one selected HTTP conversation. It uses a
new Linux network namespace, its own loopback interface and two temporary
HTTP listeners. The selected service uses port 8080; a second owned service
uses port 8081 to make an overly broad filter observable. No request or
capture is made against an external host, the VM's external interface or a
production service.

The core deliverable is the capture configuration and an evidence notebook.
Python implements the supplied apparatus and can be read as optional code
study. Editing that apparatus is not required to complete the networking
exercise. The reference configuration is separate from the starter attempt.

## Environment and execution

Use a disposable Linux VM with console access. The lab requires Python 3.10
or later, `bash`, `ip`, `unshare`, `sysctl`, `iptables-save` and `tcpdump`.
On an Ubuntu VM, the relevant packages are `python3`, `iproute2`, `iptables`,
`util-linux` and `tcpdump`. Root is required to create the isolated namespace
and capture its packets. The launcher refuses macOS, non-root execution and
direct capture in the original network namespace before opening any lab
listener. It does not install dependencies.

Edit and save the selected role's configuration and notebook. Copy that role
folder into the disposable VM. In the copied role directory, run:

```sh
sudo bash capture_http.sh --output /tmp/ns5-first-observations.json
sudo bash capture_http.sh --reverse --output /tmp/ns5-reversed-observations.json
```

Each output path must be new and have an existing parent directory. An
existing report, file or symlink is refused. A JSON report retains the
original pcap bytes as base64 with a SHA-256 digest, decoded packet lines,
actual HTTP requests, process records and cleanup observations. Thus the
evidence remains available after the temporary lab directory disappears.
The exit status reports whether the apparatus finished. Check the separate
`complete` field before treating the capture settings as completed work.

## The interface, endpoints and handshake

A capture sees packets on the selected interface in its current namespace.
A request to 127.0.0.1 uses that namespace's loopback interface, `lo`.
Capturing `eth0` would not establish what happened to the same loopback
request. The selected request goes from a kernel-assigned client source
port to 127.0.0.1:8080. Its reply reverses the endpoint roles; the service's
source port is 8080 and the destination is the client's ephemeral port.

Locate the SYN and the reverse-direction SYN/ACK. They establish the
transport conversation, not HTTP success. Locate the actual `GET` line,
the `HTTP/1.1 200` status and the body containing this run's token. The
report's HTTP client records provide the actual local and peer endpoints.
Compare those endpoints with the captured IPv4/TCP headers rather than
inferring ports from a service label. A TCP ACK may acknowledge received
bytes without carrying application data. Several packets may therefore be
needed to explain one request and response.

## Configure the capture

The editable `capture-options.sh` emits two settings as JSON. Select a
`packetLimit` from 1 through 64 for `-c`, and enable `filterPort` to restrict
the capture to the selected service on port 8080.
The reference uses 64 as its upper packet limit. The starter deliberately
leaves these choices incomplete so its capture also exposes the independent
conversation on port 8081 and its analysis reports `complete: false`.

The capture uses `-p` so it does not request promiscuous interface mode,
even inside this isolated loopback lab.

The supplied capture and readback commands already use `-nn` to keep
address and port display numeric. Inspect the recorded command and decoded
endpoints. A name-display option does not change the raw IPv4 or TCP headers.
The apparatus uses full snapshots and flushes each saved packet. Its filter
already restricts the protocol and owned loopback address; the port choice
narrows that filter further.

`-c` stops capture after a selected number of matching packets. It does not
promise that this many packets will arrive. A small limit can stop before
the HTTP response; a large limit can wait for traffic that never arrives.
The apparatus therefore also waits for actual listener and capture readiness,
uses bounded requests, stops and reaps the capture after the owned traffic,
and bounds the entire isolated run. The reference can finish with fewer
than 64 packets. No fixed sleep is used as a substitute for capture readiness.

The capture and readback retain the namespace's root identity with `-Z root`
so they can use the run's private directory. This occurs only after the
namespace guard. The host's interfaces, routes, forwarding setting and
firewall configuration are compared before and after the experiment.

## Observe, change and review

Before execution, complete the predictions in `network-notes.md`. After
execution, enter the actual client/service ports, flags, request and response
evidence, filter membership and cleanup results. Keep the settings used for
each report. Repeat with `--reverse`, which requests the selected service
before the noise service. Flow membership should follow the filter even
when traffic order changes. Do not interpret packet count differences alone
as a change in application behavior.

The captured HTTP bytes are plaintext in this deliberately local experiment.
TLS would change which application content an ordinary packet capture can
read. This lab does not claim that a successful HTTP request proves TLS,
Internet reachability or a firewall policy. No private third-party traffic
or credentials are part of the experiment.

For independent study, explain each prediction against the retained bytes
and decoded command output before consulting the reference. For a paced
walkthrough, review endpoints, handshake, HTTP evidence, filter contrast and
cleanup in that order. The work is complete when the two settings are
implemented, both traffic orders support the explanation, the flow on port 8081 is
excluded, selected request/response bytes are present, and both subprocesses
are reaped with the host network configuration unchanged.

## Command reference

- [Ubuntu tcpdump manual](https://manpages.ubuntu.com/manpages/noble/man8/tcpdump.8.html)
- [Linux network namespaces](https://man7.org/linux/man-pages/man7/network_namespaces.7.html)

The report is measured lab evidence, not an automatic evaluation of the
notebook's explanation.
