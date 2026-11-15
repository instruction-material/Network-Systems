# Diagnostic Trace Extension Practice: Distinguish an accepted TCP connection from an HTTP response

This optional diagnostic investigation uses owned IPv4 loopback services. It
collects real Linux commands and response evidence before one configuration
change. Prerequisites: the core diagnostics project, basic Linux commands and
reading addresses, ports and HTTP headers. Python programming is optional.

## Prepare the owned experiment

Use an ordinary account in an owned Linux practice VM or WSL environment, with
Python 3.10 or newer, Bash, GNU timeout, iproute2, curl and OpenBSD netcat.
On an Ubuntu lab that you administer, install the missing tools once:

    sudo apt-get update
    sudo apt-get install python3 iproute2 curl netcat-openbsd coreutils

Run the experiment as the ordinary account. It refuses root. It chooses its own
ephemeral ports, binds only 127.0.0.1 and 127.0.0.2, and reserves the comparison
endpoints so that it cannot accidentally probe a reused service. Netcat's
numeric mode and curl's explicit proxy bypass keep these observations local.
It reads interface/route information and changes no network configuration.
No second machine, DNS service, credentials or public endpoint is involved.

Import the starter into its own saved attempt. Review consent, save and export
the ZIP, extract it, and enter its starter directory in the Linux terminal.
Keep the separate reference workspace for comparison. The site IDE edits and
saves these files; the Linux terminal runs the supplied commands.

## Configuration choices

| Field | Choices |
| --- | --- |
| targetAddress | owned: 127.0.0.1; reserved: 127.0.0.2 |
| targetPort | owned: live HTTP port; reserved: bound non-listening port |
| scheme | http or https |
| responseMode | http: reply immediately; silent: read without replying |
| httpStatus | 200 or 500 for the owned HTTP reply |

The report gives the actual fresh ports. Correct only the field named by the
evidence for this assignment; retain the other choices.

## Read the evidence ladder

The supplied service accepts connections and reads HEAD requests but deliberately withholds a response. Curl has a two-second connection deadline and a three-second total deadline; netcat checks the TCP connection only. Use the actual listener, request log and command statuses to distinguish the application wait from a missing listener.

The collector runs seven sections in this order: TCP listeners, interface
summary, IPv4 routes, IPv6 routes, loopback HTTP, selected-target HTTP and
selected-target TCP. Each section preserves its arguments, output and exit
status and continues after a failed probe. Curl uses two-second connection and
three-second total deadlines; every command also has a five-second outer
deadline. An empty listener table can be a successful command with no matching
listener. Local route output describes this host; it does not prove delivery.

## Predict, observe, correct, repeat

1. Read `case.json` and write predictions in `network-notes.md` for the
   listener, loopback HTTP, selected-target HTTP, TCP result and HTTP status.
   Name the issuing machine and separate observed failure from proposed cause.
2. Run `python3 main.py --report first-observation.json`. Read all seven
   retained sections, `selectedTarget`, `ready`, `control` and `worker`.
   A normal collection exits 0 even when `complete` is false. A command failure
   inside the report remains evidence. Setup, invalid input or interruption
   errors exit 2 and preserve the report when collection has started.
3. Identify the first failing layer and cite its exact arguments, status and
   output. Reject two plausible alternatives with evidence. A permission-hidden
   process name does not establish that no process owns the listener.
4. Change only `responseMode` from `silent` to `http`. Repeat with a fresh report and verify the same kind of owned service now sends HTTP headers.
5. Run `python3 main.py --report corrected-observation.json`, then
   `python3 main.py --alternate --report changed-case.json`. The alternate
   run allocates fresh endpoints/token and changes header order; it does not
   provide a memorized port or token. Compare the actual values in each report.
6. Check `hostUnchanged`, `sourceUnchanged`, the stopped/reaped worker,
   `socketClosed`, `allReservationsClosed` and `temporaryWorkspaceRemoved`.
   Preserve failures and corrections together; reports refuse overwriting an
   existing filename. Ctrl-C stops the owned collector and worker.

## Expected observations and explanation

Both HTTP observations reach their finite deadline, commonly curl 28, while the TCP check succeeds. The independent one-second HTTP control also records a timeout and retains any bytes actually received. That controlled application silence does not identify a firewall or Internet path failure.

The `control` is an additional plain-HTTP HEAD exchange directly to the owned
live service, using a one-second receive deadline. Its hex fields retain the
actual sent and received bytes. It does not use the selected wrong address,
wrong port or HTTPS scheme. In the silence case it also times out. Decode the
received header bytes with this read-only command, replacing the report name:

    python3 -c 'import json; d=json.load(open("first-observation.json")); print(bytes.fromhex(d["control"]["receivedHex"]).decode("iso-8859-1"))'

The reference sets the same five documented choices to a live owned address,
live owned port, plain HTTP, an immediate response and HTTP 200. It supplies a
comparison pattern; it cannot supply the token, ports, statuses and reasoning
from an independent run. No output here measures a second-machine path,
privileged firewall policy, Internet routing or a completed notebook.

## Independent record and guided pauses

An independent record contains the prediction, exact failed evidence, first
failing layer, two rejected alternatives, one changed field, repeated evidence
and cleanup. Explain why TCP, command status and HTTP status answer different
questions. The archived studio connects that record into a complete incident
narrative; the separate transfer and extension change the failure signature.

For a guided walkthrough, pause after the prediction, after the first failed
section, before the proposed correction and after recovery. At each pause,
state which next observation would disprove the current explanation. Keep
the matching saved starter attempt for notes and open the reference separately.

References: [curl command manual](https://curl.se/docs/manpage.html),
[curl error codes](https://curl.se/libcurl/c/libcurl-errors.html) and
[OpenBSD netcat](https://man.openbsd.org/nc).
