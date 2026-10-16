# Optional extension: observe a datagram without consuming it

This optional Network Stack extension follows the required transport project.
The required project compares stream and datagram observations. This extension
investigates a diagnostic that changes the receive queue it is trying to
inspect. Preserve complete application datagrams while observing the prefix
of the next queued datagram.

The deliverable is a case configuration, a queue-state explanation, and an
evidence notebook. The prewritten apparatus runs unchanged. Programming is
optional. A working reference configuration is a comparison after an
independent attempt, not a completed explanation.

## Environment and scope

Use an ordinary non-root account in an owned Linux environment with Python 3.10
or newer. In the same terminal check `uname -s`, `hostname`, `pwd`, and
`python3 --version`. On macOS use an owned Linux lab through Remote SSH or a
Linux VM. On Windows use the Linux terminal in WSL. The apparatus creates no
remote login and refuses unsupported or root execution.

The two roles contain `main.py`, `transport_lab.py`, `case.json`,
`network-notes.md`, and `edge-cases.md`, with one shared README. Work in
`starter/` first. The only completion edit for this investigation is the
documented setting in `case.json`; leave the source apparatus unchanged.

The sender and receiver bind to operating-system-selected ports on
`127.0.0.1`. They exchange only this trial's datagrams in the current Linux
network namespace and close all their sockets afterward. The experiment
changes no routes, firewall, DNS configuration, or services. This controlled
local queue does not establish internet UDP reliability or remote reachability.

## Read the queue model

UDP preserves datagram boundaries. A consuming receive removes the next
datagram from this socket's queue. If the provided buffer is too short, Linux
can return only its prefix and mark truncation; the next consuming receive
does not supply the missing suffix. See the primary
[Linux UDP manual](https://man7.org/linux/man-pages/man7/udp.7.html).

The `MSG_PEEK` receive flag lets an application inspect queued data while
leaving it available for a later consuming receive. A short peek can still
report truncation of that observation. The original datagram remains queued;
a later sufficiently large consuming receive can obtain it. This is the
documented [Linux receive interface](https://man7.org/linux/man-pages/man2/recv.2.html),
exposed by [Python's socket API](https://docs.python.org/3.10/library/socket.html).

The apparatus sends two named datagrams, then performs a four-byte diagnostic
receive before the application consumer runs. The consumer uses a large
enough buffer and attempts one receive for each sent datagram. The starter
diagnostic consumes the first datagram, so the consumer starts with the second
and its last bounded receive times out. That missing consumer record is not
evidence of network loss: the earlier diagnostic already received its prefix.

The corrected diagnostic peeks. Its prefix observation is still truncated,
but the consumer subsequently receives both complete datagrams in order.
Distinguish the diagnostic's requested flags, the kernel's returned flags,
the bytes observed by each reader, and the state of the owned receive queue.

## Predict and retain the first trial

Draw this initial queue using the message names in the supplied case:

    [first complete datagram] [second complete datagram]

Predict the queue after a four-byte diagnostic read and after each subsequent
application receive. A receive buffer limits the returned payload; it does
not convert one datagram into a sequence of application messages.

From `starter/` run:

    python3 main.py --report udp-first.json

Choose a new report filename for every attempt. Exit status 78 means the
observed application records do not meet the goal. Retain this report; it is
the evidence needed to explain the failure.

Inspect `probe.dataHex`, `probe.requestedFlags`, `probe.returnedFlags`,
`probe.truncated`, `consumerReads`, and `applicationRecords`. Match the actual
sender and receiver endpoints. The report's event list also includes the
bounded receive timeout, process ID and actual native thread IDs. Do not
replace the observations with an expected transcript.

## Correct one boundary and transfer the reasoning

Change only `probe_behavior` in `case.json` to select a peeking diagnostic.
Before running, predict both the short diagnostic result and the complete
consumer results. Then run:

    python3 main.py --report udp-peek.json

The diagnostic can remain truncated while the application contract succeeds.
Explain how the two facts can both be true, using the requested receive flag
and subsequent complete payload. A different failure would require different
evidence; changing a label in the notebook does not change the queue.

Next predict the alternate trial, which sends three different datagrams, and
run:

    python3 main.py --alternate --report udp-alternate.json

Compare the new payload bytes and message count with the same queue model.
Describe why a diagnostic that consumed just one message would still be
incorrect even if later messages were received successfully.

Exit status zero checks this bounded apparatus's application contract. It
does not fill the notebook or demonstrate a remote service's availability.
Record predictions, commands, report names, the configuration change, the
actual kernel flag evidence, and the remaining scope limitation in
`network-notes.md`. Use `edge-cases.md` for the reasoning cases.

## Optional syscall evidence and recovery

If `strace` is installed in the selected Linux lab, retain a separate trial:

    strace -f -yy -s 4096 -e trace=network,close -o udp-syscalls.txt python3 main.py --report udp-traced.json

Find the probe's `recvmsg` request and distinguish its requested `MSG_PEEK`
flag from the returned truncation flag. Match subsequent consuming receives
to the original payload bytes and owned socket endpoints. A syscall trace is
evidence about these application/kernel calls, not a packet capture or a
measurement of a remote path.

Existing report filenames and invalid configuration are refused. A local
socket restriction or timeout during a failed trial needs its actual report;
it does not by itself identify a firewall, route or DNS fault. Socket deadlines
and explicit cleanup bound the owned experiment. Preserve failed evidence,
correct the local environment or selected case, and choose a fresh report
filename for recovery.

## Independent and paced checkpoints

Independently, finish the queue prediction, consuming baseline, peeking
correction, alternate trial and explanation before consulting `solution/`.
In a paced session pause after the first diagnostic observation and ask which
operation removed the message. Resume the same optional attempt and notebook.
The TCP transfer has its own question about application record boundaries;
neither optional activity replaces the required transport project.
