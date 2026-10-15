# Unit 1: Follow Bytes Through TCP and UDP Sockets

The required project connects applications, sockets, ports and transport behavior
to real Linux observations. Prerequisite: the NS0 environment and local request
project. The deliverable is a layer-by-layer evidence notebook
from actual command and socket observations. The supplied instrumentation runs
unchanged; Python analysis code is supplemental practice. This replaces the unrelated port-list exercise previously in this folder.

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

## Layers and the experiment

An application defines the meaning and boundaries of a message. A socket exposes
an operating-system communication interface. Its transport protocol uses ports
to select an endpoint on an addressed host. IP supplies network-layer addressing
and forwarding; an interface handles delivery on the chosen link. Ethernet
frames belong to an Ethernet link. The local `lo` path used here has no external
Ethernet hop. A socket observation alone is not a packet capture.

TCP provides an ordered byte stream and signals receive EOF when its peer has
finished sending and all received data has been consumed. A send call does not
define a message boundary for the receiver. UDP delivers datagrams with separate
boundaries; a valid datagram can contain zero payload bytes. Receiving zero bytes
from that datagram is different from TCP EOF. A UDP receive buffer that is too
small can discard the rest of that datagram; another receive does not return its
remaining suffix. These are observed below using actual Linux sockets.

The owned worker announces separate TCP and UDP loopback endpoints. The parent
records each live listener with `ss`. For TCP it sends only the first two bytes,
waits for a one-byte acknowledgement from the worker, then sends the rest. This
gate makes an incomplete first observation real without depending on sleep or
assuming a particular packet split. The worker logs each nonempty `recv` result,
observes EOF after the client half-closes, and echoes the complete observed byte
stream. The number of reads after the gate can vary. Hexadecimal preserves exact
bytes, including a UTF-8 character split across reads.

For UDP the client sends an empty datagram and then the message as a second
datagram, waiting for each echo. The worker uses `recvmsg`, records the actual
sender endpoint and the kernel's `MSG_TRUNC` flag, then echoes only received bytes.
The final observations are emitted after both listening sockets close. The
parent reaps the worker and records TCP and UDP listener tables again.

## Optional Python analysis extension

The required lab uses the observations and notebook. For supplemental code
practice, return these exact fields from the recorded worker evidence:

- `tcpBytes`: byte length after concatenating and hex-decoding `tcpReadsHex`.
- `tcpReadCalls`: number of nonempty recorded TCP reads.
- `tcpCompleteLine`: whether the reconstructed stream ends in byte `0a` (newline).
- `tcpEofObserved`: the worker's recorded EOF observation.
- `udpDatagramLengths`: byte lengths decoded from the two datagram records.
- `udpTruncated`: the two recorded truncation booleans, in order.
- `emptyUdpIsDatagram`: whether the first recorded datagram has empty payload.
- `scope`: the string `same Linux network namespace`.

Do not treat the first TCP read as the entire message. Do not turn the empty UDP
record into a disconnected peer. A newline is this application's chosen frame
terminator; TCP does not add it. `tcpCompleteLine` must become false for the
unterminated case, even though the transport still reaches EOF normally.

## Predict three changed cases

1. `python3 main.py --message 'Different transport message'`: reconstruct the
   exact selected UTF-8 bytes plus newline. Verify both client endpoints match
   the corresponding worker peer/sender records. Count bytes rather than letters.
2. `python3 main.py --message 'abcdef' --udp-buffer 3`: the second UDP observation
   is three bytes, its truncation flag is true, and its echo is `abc`. TCP still
   transfers the whole line. The lost UDP suffix is not a later datagram.
3. `python3 main.py --message 'abcdef' --without-newline`: TCP reaches EOF with
   six bytes, while the application-level line is incomplete. The first UDP
   datagram remains valid and empty in every case.

In the notebook draw application -> socket -> transport/port -> IP address ->
interface for one NS0 HTTP request, and reverse the path at the receiving process.
Label the observed PID, local and peer endpoints, and route. If the destination
were a different machine, add routing and the actual link between interfaces;
do not insert a router or Ethernet hop into this observed loopback exchange.
An HTTP request has application framing beyond TCP. SSH also has its own protocol
and authentication over TCP. This pack sends its stated simple byte protocol; it
does not claim to implement HTTP framing, SSH authentication, reliability tests,
packet capture, internet reachability, or actual packet loss.

Core completion: raw observations and a notebook covering all four cases,
distinguishing transport EOF from message completion and empty datagrams, exact
byte evidence, matching kernel listener identities, and a reaped worker with
closed sockets. If choosing the Python extension, its returned fields must agree
with those same observations.

References: [Python socket API](https://docs.python.org/3/library/socket.html),
[Linux TCP](https://man7.org/linux/man-pages/man7/tcp.7.html), and
[Linux UDP](https://man7.org/linux/man-pages/man7/udp.7.html).
