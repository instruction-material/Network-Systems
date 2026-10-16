# One listener with two process owners

This optional extension activity builds on Unit 4's passive service map.
Observe one TCP listener held by a parent and an owned child, then distinguish
the number of sockets from the number of processes holding descriptors.
The required listening-services project remains a separate attempt. The
apparatus is supplied; Python programming is optional.

## Follow the open socket

A file descriptor is a process-local handle. A child can inherit a descriptor
that refers to the same open socket as its parent's descriptor. Two visible
process owners therefore need not represent two listeners. Within this lab's
observation interval, compare the network namespace and socket inode alongside
the transport, local endpoint and visible PID/descriptor pairs.

The supplied parent binds 127.0.0.1 on an operating-system-selected port,
listens and explicitly passes that descriptor to its own child. Both processes
hold the same socket. The parent records `ss` and `/proc` evidence, then closes
its own descriptor. The child still holds the listener and accepts one local
token exchange. When the child closes and exits, that listener disappears.
Any TCP TIME-WAIT rows describe connection state rather than a listening socket;
their presence or absence is not the criterion for listener cleanup.

Socket inodes and PID values can be reused after objects exit. They are evidence
for this bounded observation, not durable identities for an unrelated later
inventory. A successful local reply does not establish remote reachability.

## Environment and files

Use an ordinary account in an owned Linux VM, WSL or Linux lab with Python 3.10+
and iproute2's `ss`. No root access, service-manager changes or firewall changes
are needed. The browser workspace edits and exports the files. Run the native
experiment in the Linux environment.

- `main.py` selects this investigation.
- `listener_lab.py` supplies the parent, child and socket observations.
- `case.json` selects a grouping rule and declares the local request token.
- `network-notes.md` records predictions and evidence.
- `edge-cases.md` separates descriptor, process, socket and reachability claims.
- `../README.md` contains this complete guide.

## Observe and group

From the learner directory, run:

```sh
python3 --version
ss --version
python3 main.py --report listener-first.json
```

The untouched case executes the apparatus and exits 2 with `unfinished`.
Read the report before editing the optional analysis choice. Compare the parent
and child PID, descriptor, namespace and inode. In `beforeParentClose`, identify
one listening row with both owners. In `afterParentClose`, identify the same
socket with only the child owner. Then reconcile the child's received token,
the client's reply and the final inventory after the child exits.

Set `group_by` in `case.json` to `pid` or `netns_inode`. The question is how to
count the one shared listening socket from its two observed descriptor owners.
Run with a new output filename:

```sh
python3 main.py --report listener-grouped.json
```

Exit 0 means the choice groups the observed owners into one socket. Exit 1 means
revise the choice or inspect an execution error. Exit 64 means the environment,
case or output path was refused before creating the experiment. The notebook
still needs the underlying evidence and explanation after a passing choice.

Change the token to `inherited-listener-second` and repeat with a fresh report.
Record the changed received bytes. Compare the reference case after documenting
an independent grouping choice; the apparatus is identical in both roles and
only the completed case differs. Save, reopen and export the workspace when
preserving the changed case and notebook.

## Limits and troubleshooting

The script creates only its own loopback sockets and one child. Each child has
a bounded readiness/action interval, the parent reaps it, and interruption
closes the parent's socket and terminates a still-running owned child. No
background service is left behind. Do not stop unrelated processes to change
the inventory. A familiar port or process name does not identify an application.

If the two owners cannot be observed, preserve the error and inspect whether
the lab restricts `/proc` or process visibility. Do not infer a second socket
from a second PID alone. Use a fresh report filename and a token of 1–48 ASCII
letters, digits, underscores or hyphens. Unknown fields and strategies are
refused. Interpret listener cleanup using the recorded inode and listening
view, even if other TCP rows remain.

References: [Linux fork descriptors](https://man7.org/linux/man-pages/man2/fork.2.html),
[Python 3.10 pass_fds](https://docs.python.org/3.10/library/subprocess.html)
and [ss options](https://man7.org/linux/man-pages/man8/ss.8.html).
