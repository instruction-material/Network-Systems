# DNS resolution extension: distinguish a name answer from a missing resolver

Compare a real NXDOMAIN answer from the owned resolver with a failed DNS transport after that exact resolver is stopped. Preserve the same question, selected server and port. Correct the classification in case.json and explain why no DNS response cannot establish the question name's existence.

## Linux environment and owned resolver

Use an ordinary account in the selected Linux lab, with Python 3.10 or newer, dig and dnsmasq. In an Ubuntu lab that the account administers, package preparation is `sudo apt-get install python3 dnsutils dnsmasq-base`. The experiment itself runs without sudo.

In a dedicated terminal start this foreground fixture. It binds only loopback on an unprivileged port, reads no hosts/resolver configuration and forwards no queries. If port 1053 is occupied, select another unused port above 1024 in both this command and --port. Keep the actual port and process identity in the notebook.

```sh
dnsmasq --no-daemon --conf-file=/dev/null --no-hosts --no-resolv --log-queries --log-facility=- --listen-address=127.0.0.1 --bind-interfaces --port=1053 --local=/course.test/ --host-record=dual.course.test,127.0.0.8,::1 --host-record=v4.course.test,127.0.0.9 --cname=alias.course.test,dual.course.test
```

Keep this terminal visible. Ctrl-C stops this specific foreground fixture when the task requests it. It supplies DNS observations only. System NSS, service connection, actual IPv6 forwarding and an Internet DNS service are separate questions.

## Files, prediction and first run

Keep main.py, dns_probe.py, case.json, network-notes.md and README.md together. The program already performs the real queries. The required work is configuration and the evidence notebook; Python programming is optional.

From the exported starter directory:

```sh
python3 main.py --port 1053 --phase live --output first-observation.json
```

The JSON retains raw dig stdout/stderr, actual argv and child PID, command status, DNS status, typed records, current UID and namespace. A no-data answer remains separate from NXDOMAIN, a DNS error response and a transport failure. Each child has a four-second deadline and is reaped. A report filename must be new; earlier reports are preserved. Exit 78 identifies an unmet configured goal, not an absent report.

## Investigation

While the resolver is alive, run with --phase live and retain the NXDOMAIN report. Stop only that foreground resolver with Ctrl-C. Run again with --phase stopped and a new report filename. The starter's negative_name claim fails and exits 78; retain its actual dig statuses and errors. Change stoppedClaim to transport_failure and repeat. Restart the owned resolver and retain a fresh live report to distinguish restoration from a rewritten result.

For the stopped phase use the same command with `--phase stopped` and a new output filename after stopping the owned resolver. That phase belongs only to the extension project.

## Evidence and comparison

Complete network-notes.md with context/tool versions, predictions, first observations, the one-field correction, all raw reports, a comparison and one unsupported inference. Read the reference case and its worked interpretation after the independent attempt. The reference needs the same real fixture; it does not invent a currently running resolver or fill a measured notebook.

In a guided walkthrough, pause after predicting each answer, after observing the response status and after the changed case. Keep this optional project's saved attempt separate from the core DNS project and from the other optional investigation.

## Fixed fixture answer key

The live missing.course.test questions receive a DNS message whose status is NXDOMAIN. After the owned resolver stops, dig normally exits 9 with no responding DNS message; this is transport_failure. A deadline is also a transport failure with the timeout recorded. Neither event proves that the name exists, nor that it is absent. The source accepts DNS negative answers separately from tool failures and DNS server error statuses.

The answer key describes this explicitly supplied fixture. Record fresh observed ports, PIDs, errors and DNS data before comparing them. A passing program does not supply the explanatory notebook.

References: [dnsmasq options](https://thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html), [DNS message and record formats](https://www.rfc-editor.org/rfc/rfc1035.html).
