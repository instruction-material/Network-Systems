# Local and second-machine reachability diagnosis

This exercise separates a listening socket, an established TCP connection and a
usable application exchange. These observations answer different questions. A
loopback request reaches this machine; changing its destination address while
running the command here still does not test a second machine's network path.
The script collects bounded read-only observations and preserves failed command
statuses so that a refused connection does not hide the remaining evidence.

## Prepare the experiment

Use an owned Linux practice machine and an HTTP service or course lab that is
already authorized for testing. Install Bash, GNU coreutils (`timeout`),
iproute2 (`ss` and `ip`), curl and OpenBSD netcat (`nc`). Do not point the
exercise at an unrelated service. No root access or configuration edit is
required to run the supplied script. Process names may be hidden when this
account cannot inspect the listener's owner; missing process text does not
mean no process exists.

Open the selected role in the site IDE, review the import choice, save the
files and download the ZIP. Extract it, open a terminal and enter the selected role folder: `starter/` for
the learner attempt or `solution/` for the reference.
The IDE is the editor and saved notebook; these Linux commands execute in the
external Linux environment. Keep each report under a fresh filename so that
earlier observations remain available. The reference belongs to a separate
workspace and must not overwrite the learner attempt.

## Predict, observe and compare

1. Write the service owner, expected bind address, application scheme and port
   in `network-notes.md`. Predict the local listener, loopback HTTP, destination
   HTTP and raw TCP outcomes. Record which machine issues every command.
2. Run `bash diagnose_reachability.sh 127.0.0.1 8080 http` for an owned service
   on that endpoint. Replace the host and port with the actual authorized
   target. Each command prints its exact arguments, raw output and exit status.
   Curl uses a two-second connection deadline and three-second total deadline;
   every command also has a five-second outer deadline and bounded termination.
3. Complete the starter's route-evidence block with `probe` calls for
   `ip -brief address`, `ip -4 route show` and `ip -6 route show`. These show
   this machine's configuration. They do not prove that packets reached the
   destination. Bash programming is a small optional extension; collecting
   and explaining equivalent manual command observations meets the core goal.
4. Compare the bind address and destination with the actual HTTP headers and
   raw TCP status. Stop only the owned practice service, repeat, and restore
   it. A refused endpoint, an HTTP error response and an application that
   accepts TCP but sends no HTTP headers are different observations. A curl
   status of zero does not certify a useful HTTP status or a healthy page.
5. If a second owned machine is available, run the same target command there
   and label that report with its source machine. Without this comparison,
   leave remote reachability explicitly unmeasured. IPv6 literals are entered
   without brackets, for example `::1`; the script brackets them in URLs.
   Use `https` only for an actual TLS service. Both local and target HTTP
   observations use the selected scheme.

## Interpret limits before changing anything

An immediate refusal is compatible with an absent listener or an active reject.
A timeout can reflect filtering, loss, a missing return path or an application
deadline. A reset means the connection was actively closed; it is not proof of
a healthy application. Curl output, netcat output and listening socket state
must be read together. DNS, proxy settings and IPv4/IPv6 selection can add other
differences. The script bypasses environment HTTP proxies to make these direct
endpoint observations explicit.

The script does not read privileged firewall policy and never changes it. On an
owned practice VM, obtain an authorized read-only policy report separately if
needed, recording the command, account and time. If permission is unavailable,
record that evidence gap. Never infer a specific firewall rule merely from a
failed probe. Form one explanation supported by the evidence before proposing
one small change and a recovery plan. Do not disable a firewall to make a
request succeed.

## Independent work and a paced walkthrough

For independent work, keep the prediction beside the command, status, actual
output and revised explanation. Include a changed-port comparison, an absent
service case, the selected scheme and any missing second-machine observation.
Confirm any service stopped for the experiment has been restored. A complete
notebook distinguishes observed facts from proposed causes and lists what
would disprove its explanation.

For a guided walkthrough, pause after the topology sketch, after the first
failed command, after the route comparison and before a proposed change. At
each pause explain what the current evidence can and cannot establish. Reopen
the matching saved attempt for the notebook instead of creating another copy.
The reference demonstrates a bounded collection pattern; its output still
requires interpretation for the particular host.

Command references: [curl manual](https://curl.se/docs/manpage.html),
[OpenBSD netcat manual](https://man.openbsd.org/nc), and
[GNU timeout manual](https://www.gnu.org/software/coreutils/manual/html_node/timeout-invocation.html).
