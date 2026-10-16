# Optional transfer: reconstruct application records

This optional Network Stack activity follows the required transport observation
project. The required project traces a request and compares TCP with UDP. This
transfer asks a different question: how can one application recover several
records when a TCP read returns only part of a record?

The deliverable is a saved case configuration and an evidence notebook. The
supplied Python is instrumentation; programming is optional. The reference
configuration also needs its own observations and explanation.

## Environment and files

Use an ordinary non-root account in an owned Linux environment with Python 3.10
or newer. Check `uname -s`, `hostname`, `pwd`, and `python3 --version` in the
terminal that will run the project. The application refuses other environments.
On macOS select an owned Linux lab through Remote SSH or use a Linux VM. On
Windows use the Linux terminal in WSL. An editor window does not identify the
terminal's execution host. No remote connection is created by this project.

Both roles contain `main.py`, `transport_lab.py`, `case.json`, `network-notes.md`,
and `edge-cases.md`. The shared README explains the investigation. Start with
`starter/`. Keep its supplied instrumentation unchanged for this activity.

The experiment creates a listener and client on `127.0.0.1` using a port chosen
by the operating system, exchanges only its own data, closes its sockets and
joins its owned worker thread. It changes no routes, firewall, DNS settings, or
system services. Loopback belongs to the current Linux network namespace, so
the reported endpoint cannot be used to infer reachability from another host.

## Distinguish the units

A socket exposes transport operations to an application. TCP provides an
ordered byte stream; it does not add application record boundaries. A successful
read can return fewer bytes than the application needs. An IP packet, a TCP
segment, a send call, a receive call, a Unicode character, and an application
record are different units. The socket observations here do not reveal packet
boundaries. See the primary [Linux TCP manual](https://man7.org/linux/man-pages/man7/tcp.7.html)
and [TCP specification](https://www.rfc-editor.org/rfc/rfc9293.html).

This application's record format is four bytes containing an unsigned payload
length in network byte order, followed by that many UTF-8 bytes. The length
counts encoded bytes, rather than the number of displayed characters. Two
records follow one another without an extra separator. The format belongs to
this application; TCP does not invent or interpret it.

The apparatus deliberately sends the first byte of the first length prefix,
waits until the client has read it, and then sends the remainder. This gate
makes the partial observation reproducible without predicting network packet
segmentation or relying on a sleep. The first read asks for two bytes and gets
the one byte currently available. Later read sizes can vary.

For this bounded trial the apparatus drains the stream to EOF and records all
raw reads. The selected application decoder receives either just the first
read or the reconstructed stream. A real application can decode complete
length-prefixed records incrementally; it does not need to wait for a
connection to close. EOF here ends the finite trial. EOF by itself does not
prove that every intended application record was complete.

## Predict, observe, correct

1. Read `case.json` and predict what the selected decoder can learn from a
   one-byte input. Sketch the first four-byte length field before running.
2. In `starter/`, run `python3 main.py --report tcp-first.json`. The report name
   must be new. Exit status 78 means the observed application result does not
   meet the goal; the report still contains the transport observations.
3. Compare `firstReadHex`, the concatenation of `readCalls[*].dataHex`, and
   `wireHex`. The transport can deliver the complete stream even while the
   selected application decoder receives an incomplete prefix. Identify which
   part failed using the report's actual fields.
4. Change only the `framing` setting in `case.json` to select length-prefix
   reconstruction. Keep the first report. Run
   `python3 main.py --report tcp-corrected.json` and explain why each decoded
   record now has a boundary.
5. Predict the alternate message count and the effect of its UTF-8 payload,
   then run `python3 main.py --alternate --report tcp-alternate.json`.
   Compare payload byte lengths with visible character counts. Use that run's
   endpoint, process, thread, and actual read evidence.

Exit status zero checks the apparatus's application contract. It does not
complete `network-notes.md`. Keep predictions, observed command/report names,
the configuration change, a byte-level explanation, and one limitation there.
Use `edge-cases.md` to explain how a decoder handles a partial length,
a partial payload, or an invalid advertised size. Those reasoning cases are
not claims that this trial sent malformed input.

## Inspect and troubleshoot

For an optional syscall view, install `strace` in the selected Linux lab and
run a fresh trial, for example:

    strace -f -yy -s 4096 -e trace=network,close -o tcp-syscalls.txt python3 main.py --report tcp-traced.json

Match file descriptors, loopback endpoints and thread IDs to the report.
`sendall` is a Python operation that can produce one or more kernel sends;
do not assume one Python call equals one packet. The
[Python socket documentation](https://docs.python.org/3.10/library/socket.html)
explains the API, and [recv(2)](https://man7.org/linux/man-pages/man2/recv.2.html)
documents the Linux receive behavior.

An existing report path is refused so evidence is not replaced. Invalid case
keys or values are refused before the sockets are created. A socket-policy
error or an owned-peer timeout is a local lab failure to inspect, not evidence
of a remote firewall or DNS problem. The finite socket deadlines and cleanup
checks bound each trial. If a run fails, keep its report and command before
trying a new filename in a suitable owned Linux environment.

## Independent and paced checkpoints

Independently, complete the prediction, baseline, correction, alternate and
explanation before consulting `solution/`. In a paced session pause after the
first one-byte observation and ask which layer knows where a record ends.
Resume with the same case and notebook rather than starting another required
project. The separate UDP extension has a different deliverable and its own
attempt.
