# NS0: Establish the Linux Lab and Observe One HTTP Request

The required project establishes where commands run, which tools are available,
and what a local service observation actually proves. Prerequisite: comfortable
Linux navigation, command execution and reading output. The deliverable is a
verified Linux environment and an evidence notebook from that lab. The working
Python instrumentation is supplied; programming it is supplemental practice.
This replaces the unrelated port-list exercise previously present in this folder.

## Working environment

Use an ordinary user account in the Linux environment selected for this course.
Python 3.10 or newer and these command-line tools are required: `ip`, `ss`,
`curl`, `ssh`, `dig`, and `traceroute`. On an Ubuntu lab that you administer,
install missing tools with:

    sudo apt-get update
    sudo apt-get install python3 iproute2 curl openssh-client dnsutils traceroute

Package installation is environment preparation. The experiment itself runs
without sudo and refuses a root account. It changes no routes, firewall rules,
DNS configuration, services, or files outside its own project. It starts a child
process on an operating-system-selected port bound to `127.0.0.1`, performs
bounded local exchanges, then closes its sockets and reaps that child.

On macOS, use VS Code Remote SSH to an owned Linux lab or a Linux VM. On Windows,
open the folder through VS Code's WSL support and use its Linux terminal. In
that terminal check `uname -s`, `hostname`, `pwd`, and `python3 --version`.
`uname -s` must say Linux. A VS Code window alone does not establish where its
terminal or Python interpreter runs. For Remote SSH, select the intended owned
host and open its folder before repeating these commands. No SSH login or
remote machine is created by this pack. Never copy credentials into the notes.

Keep the same terminal and Linux network namespace for the experiment. A
container, WSL instance, VM and desktop host can each have a different loopback
interface. Here `127.0.0.1` names the current namespace, not a different host.

## Files and iteration

Start in `starter/` and run `python3 main.py`. The working instrumentation in
`network_lab.py` performs the experiment even while the analysis is unfinished.
The JSON includes raw command output, actual endpoint and process identities,
transport observations, and `analysis: null`. For the required lab, leave the code unchanged and record the explanation and
command evidence in `network-notes.md`. An optional Python extension completes
the marked `analyze(evidence)` function in `main.py`; keep the instrumentation
unchanged if choosing that extension. Python programming is not a prerequisite.

The required project develops networking interpretation through the observed
commands and notebook. The Python dictionary contract below is supplemental code
practice. A returned dictionary does not grade the required explanation. Keep the first run before editing, predict a changed case,
then run it and compare the observation with the prediction. The `solution/`
folder provides one reference after an independent attempt or an agreed
instructor checkpoint. It does not replace the commands and observations.

The JSON is printed to standard output; redirect it to a new local file if a
record is useful, for example `python3 main.py > first-run.json`. Re-running the
program chooses fresh ports. Refer to the endpoints printed by that run rather
than copying example port numbers. Do not edit an earlier saved attempt merely
to make it match a newer source pack.

If a tool is missing, the program names it before creating its child. Install
that tool in the selected Linux lab and retry. A permission error during socket
creation can mean the lab's execution policy forbids it; use an ordinary Linux
VM or owned lab that permits loopback sockets. A timeout is an observation to
investigate, not proof of a remote firewall problem. The worker and commands
have finite deadlines, and the parent cleans up its owned worker on failure.

## Independent and instructor use

Work through environment checks, prediction, untouched starter, changed cases,
and explanation in that order. If choosing the Python extension, implement its
analysis function afterward and repeat the changed cases. In a paced session pause after the
prediction and after the first raw evidence, before consulting the reference.
The operations notebook continues this same core project and should retain its
observations; it is not a second independent programming assignment. Additional
transfer and extension projects have their own goals and are outside this pack.

## Read the path before running it

An application asks a socket to communicate. An IPv4 socket has an address and
port; a TCP listening socket accepts connection requests for its bound endpoint.
The route lookup selects where traffic to an address goes. This experiment uses
a numeric loopback address, so it needs neither external DNS nor a remote host.
HTTP supplies a request path and a response body over that local TCP connection.

`ip -j address show dev lo` reports loopback interface addresses as JSON.
`ip -j route get 127.0.0.1` asks the kernel how it would route to the local
address. The expected device on an ordinary Linux lab is `lo`; read the actual
`dev` field. `ss -H -ltnp` lists TCP listening sockets without a header, with
numeric endpoints and process information available to the current user. The
script records this while its HTTP server is alive, before issuing a request.

The owned HTTP worker returns a JSON object containing the selected message and
the request path. `curl` requests `/lab`, bypasses environment proxy settings for
this owned loopback experiment, rejects HTTP errors, and has a five-second
transfer deadline. The worker records the path it actually received. The parent
waits for the worker to finish, then records the TCP listener table again.

The tool inventory records paths for SSH, DNS and path-diagnostic clients as well
as the clients used in this experiment. Finding `ssh`, `dig` or `traceroute`
proves that a file was found on PATH. It does not prove remote login permission,
DNS correctness, or a complete route to another host. Verify remote access using
only the owned Linux host selected during setup and its normal connection method.

## Optional Python analysis extension

The required lab uses the observations and notebook. For supplemental code
practice, return a dictionary with these exact fields:

- `linux`: whether the recorded platform equals `linux`.
- `availableTools`: the sorted keys of the recorded tool inventory.
- `routeInterface`: the `dev` of the first recorded route result.
- `ownedListenerObserved`: whether a single recorded listener row contains both
  the exact `127.0.0.1:<actual port>` token and the worker's `pid=<actual pid>,`.
- `responseMatches`: whether the response equals the actual selected message
  and `/lab` path, with no additional fields.
- `scope`: the string `same Linux network namespace`.

Use the recorded evidence, rather than substituting fixed hostnames, ports,
process IDs, or a hardcoded true value. In `network-notes.md`, connect platform,
hostname, working folder and namespace to the terminal selected in VS Code.
Match the kernel route, the live listener PID, the curl URL and the response.
Explain why the listener later disappears.

## Change and explain

Run `python3 main.py --message 'Second local observation'`. The selected message
and HTTP body must change; the PID and port may change too. The interface can
remain `lo`. Compare before and after listener output using the new worker PID.
No part of this local success establishes a publicly exposed service. Write the
additional evidence needed for a second machine: its address, name resolution
if a hostname is used, a path to that address, a reachable listening endpoint,
and the relevant host and network policy. Those later diagnostics belong to the
following units, rather than being inferred from loopback success.

Core completion: all required tools are located in the intended Linux
environment, the notebook explains the actual route, listener and HTTP evidence
from two runs, and no worker is left running. If choosing the Python extension,
its analysis must also agree with those same recorded observations.

References: [ip-address](https://man7.org/linux/man-pages/man8/ip-address.8.html),
[ip-route](https://man7.org/linux/man-pages/man8/ip-route.8.html),
[ss](https://man7.org/linux/man-pages/man8/ss.8.html), and
[curl options](https://curl.se/docs/manpage.html).
