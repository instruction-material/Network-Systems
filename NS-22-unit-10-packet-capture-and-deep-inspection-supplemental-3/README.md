# Capture extension: separate the selected service from nearby traffic

The capture is bounded, but its expression includes traffic to a second owned loopback listener. Predict the target and noise conversations before reading the packets. Preserve the broad first capture, then change only filterPort in capture-options.sh. Compare default and --reverse request order with fresh reports so a successful selection cannot depend on which request happened first.

This optional attempt and its reference are separate from the core capture project.

## Owned environment and files

Use an owned disposable Ubuntu 24.04 Linux VM with console access, a snapshot, root access, Python 3.10+, iproute2, iptables, util-linux and tcpdump. The package preparation is sudo apt-get install python3 iproute2 iptables util-linux tcpdump. The browser edits and exports files; the real capture runs in that VM. Python programming is optional.

Keep capture_http.sh, capture_runtime.py, capture-options.sh, network-notes.md and README.md together for the selected role. Use the starter first. Each launch creates its own network namespace, brings up only its loopback interface and owns two small HTTP listeners. The original network namespace is refused before capture. The measured host configuration is compared before and after; the owned listeners and capture process are reaped.

## Traffic and packet evidence

The selected listener is 127.0.0.1:8080; the other owned listener is 127.0.0.1:8081. The program makes three fresh HTTP requests with a random run token. Default order is noise, target, noise; --reverse selects target, noise, noise. Record the actual local/peer endpoints, process identity and request order.

capture-options.sh prints the two JSON settings packetLimit and filterPort. The supplied program accepts an integer packetLimit from 0 through 64 and a Boolean filterPort. A positive limit supplies tcpdump's -c ceiling; zero omits that ceiling. The program separately bounds its own capture lifetime and owned traffic. A zero packet setting therefore still has apparatus cleanup, but does not satisfy this task's explicit packet-count bound.

The capture uses the owned loopback interface, numeric addresses/ports and a full packet snapshot. It records the actual invocation and stderr, PCAP bytes as pcapBase64, their SHA256, decoded frames and separately observed application request/response bytes. Preserve all these fields. To inspect the retained capture independently, use the following supplied commands. The new PCAP filename must not already exist; no Python programming is required.

```sh
python3 -c "import base64,json,sys; data=json.load(open(sys.argv[1])); open(sys.argv[2],'xb').write(base64.b64decode(data['lab']['pcapBase64']))" first-capture.json first-capture.pcap
tcpdump -nn -tt -r first-capture.pcap
```

A TCP handshake, an HTTP status and an application response identity answer different questions. Explain which bytes are present and which are absent. The count of captured packets does not by itself establish a complete HTTP request or response. A port selection describes this owned interface and time interval; it does not demonstrate Internet traffic, TLS or another machine's capture.

## Explain and recover

Use network-notes.md for context, predictions, the first capture, the single changed setting, comparison and limits. Retain the first unsuccessful report. A complete reference configuration still needs an actual run and explanation; its notebook supplies reasoning without invented observations.

Confirm workerReaped, captureReaped, remainingLinks and hostUnchanged, and retain any actual error. Existing reports, symlink outputs and missing output parents are refused. For independent review, account for every prediction mismatch before opening the reference. A guided walkthrough can pause at request order, handshake, HTTP bytes, selection and cleanup.

[Ubuntu tcpdump manual](https://manpages.ubuntu.com/manpages/noble/man8/tcpdump.8.html) supplies the command-option reference.

## Run the investigation

```sh
sudo bash capture_http.sh --output first-capture.json
sudo bash capture_http.sh --output corrected-capture.json
sudo bash capture_http.sh --reverse --output reverse-capture.json
```

Use corrected-capture.json only after changing the selected setting. Keep each earlier report and its raw PCAP data.
