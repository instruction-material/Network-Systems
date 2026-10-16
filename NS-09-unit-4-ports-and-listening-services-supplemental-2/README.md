# Connected UDP sockets and inventory filters

This optional transfer activity extends Unit 4's service map. Compare two views
of one owned UDP socket before and after setting its default peer. Keep the
required listening-services project and its notebook as a separate attempt.
The supplied apparatus performs the experiment; Python programming is optional.

## Read the socket table

A UDP socket can bind a local address and port without selecting one peer.
Linux commonly displays that socket as UNCONN. UDP connect selects the default
destination and limits incoming datagrams to that peer. It does not perform a
TCP handshake or establish that an application will reply.

`ss -lunpe` selects listening UDP sockets. `ss -aunpe` includes connected UDP
sockets as well. After a default peer is set, the owned socket can disappear
from the first view while remaining in the second. Retain the transport,
network namespace, local address, port, peer and socket inode when comparing
observations. An empty filtered view does not prove that a socket was closed.

The experiment binds two sockets to 127.0.0.1 and operating-system-selected
ports. It records both inventories before connect and again after connect,
before sending any application bytes. It then sends a declared token and
receives a reply from its owned peer. Those final bytes establish one local
exchange. They do not establish reachability from another machine.

## Environment and files

Use an ordinary account in an owned Linux VM, WSL or Linux lab with Python 3.10+
and `ss` from iproute2. No root access or network reconfiguration is needed.
The browser workspace edits, saves and exports these files; run the experiment
in the Linux environment. Open the learner role first.

- `main.py` selects this investigation.
- `listener_lab.py` contains the supplied socket and command apparatus.
- `case.json` contains the token and optional inventory analysis choice.
- `network-notes.md` records predictions, observations and limits.
- `edge-cases.md` contains named reasoning cases.
- `../README.md` contains this complete guide.

## Observe, select and explain

From the exported learner directory, run:

```sh
python3 --version
ss --version
python3 main.py --report udp-first.json
```

The untouched learner case runs the complete experiment and exits 2 with
`unfinished`. Read `udp-first.json` before changing the case. Its raw command
records preserve arguments, output, stderr, status, timestamps and child PIDs.
Compare the same inode in both views before and after connect. Record the
default peer and the received token/reply bytes in the notebook.

Change `inventory_view` in `case.json` from `TODO` to either `listening` or
`all`. The question is which inventory retains this connected UDP socket.
Use a fresh report name for every run:

```sh
python3 main.py --report udp-selected.json
```

Exit 0 means the selected view contains the observed connected socket. Exit 1
means revise the inventory choice or inspect an execution error. Exit 64 means
the environment, case or output path was refused before the experiment.
A passing choice does not complete the notebook. Explain the state change,
the limits of connect and the additional application evidence separately.

Change the ASCII token to `udp-second-observation` and repeat with a new report.
Verify that actual received bytes change. After completion, the final all-socket
view no longer contains the owned inode. Other sockets or port reuse belong to
different observations. No background listener remains from this script.

## Review and troubleshoot

Compare the reference case after making and explaining an inventory choice.
Its apparatus matches the learner files; only the completed case differs.
Each role has its own report and notebook. Finish the named reasoning cases,
then save and reopen the workspace and export its files for the native run.

If `ss` is unavailable, install iproute2 through the lab's normal setup or use
an already provisioned owned Linux lab. A missing process column can reflect
permissions or namespace boundaries. This experiment requires its own visible
socket inode; preserve an error rather than inventing a successful inventory.
Use a fresh report filename if a previous report or a symlink already occupies
the requested path. Keep the token to 1–48 ASCII letters, digits, underscores or
hyphens. Unknown fields and strategies are refused. Ctrl-C closes the owned
sockets and stops an active owned command.

References: [Linux connect](https://man7.org/linux/man-pages/man2/connect.2.html)
and [ss options](https://man7.org/linux/man-pages/man8/ss.8.html).
