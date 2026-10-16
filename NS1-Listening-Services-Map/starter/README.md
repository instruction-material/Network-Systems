# Listening services and ownership evidence

A service map connects a local socket to a transport, bind address, port and
visible process owner. It also separates what the inventory actually shows from
the role assigned to a service. A socket can be expected for one machine and
unexpected for another; the reference script cannot infer that policy from a
port number. The required work is a reasoned inventory and notebook. Extending
the small Bash collection block is optional programming practice.

## Prepare an owned Linux observation

Use an owned Linux practice environment with Bash, GNU coreutils (`timeout`),
iproute2 (`ss`) and `lsof`. No root access or configuration change is required
to inspect this account's available view. Process details for other accounts
can be hidden. Record the issuing machine, account, time and network namespace;
containers or separate namespaces can have different socket tables.

Review the selected role, save it and download the ZIP from the integrated
workspace. Extract it and enter the selected role folder in the external Linux terminal:
`starter/` for the learner attempt or `solution/` for the reference.
Keep `network-notes.md` beside the script. The browser edits and saves these
files; the actual kernel inventory runs on Linux. Preserve each report under
a fresh name. The script writes to standard output and never opens or
overwrites a report file itself. The optional numeric port filter is shown in the usage line.

## Predict and collect the socket evidence

1. Start with an already authorized owned service. If a controlled example is
   needed, run `python3 -m http.server 8080 --bind 127.0.0.1` in one practice
   terminal. This is supplied apparatus, not a Python programming assignment.
   An optional UDP comparison uses OpenBSD netcat in another terminal:
   `nc -u -l 127.0.0.1 8080`. TCP and UDP can use the same numeric port because
   the transport is part of the endpoint identity. Keep these terminals open
   until the comparison is complete; use another port if it is already owned
   by an unrelated service.
2. Predict which transport, address and process appear. Run
   `bash inventory_services.sh 8080`, then run without an argument to see the
   account's broader view. The starter records the namespace and TCP bind
   addresses. Every command prints its exact arguments, raw output and status
   and has a five-second outer deadline with bounded termination.
3. Compare the reference collection or complete only the starter's named
   inventory-sections block. Use `ss -ltnp` for TCP ownership, `ss -lunp` for
   UDP and `lsof -nP -iTCP:8080 -sTCP:LISTEN` plus `lsof -nP -iUDP:8080` for
   visible file-descriptor ownership. Repeat equivalent manual commands if
   choosing the command-observation path instead of the Bash extension.
4. Stop only the owned TCP and UDP examples with Ctrl-C and repeat the filtered
   inventory. A successful `ss` query can contain no matching rows. `lsof` can
   return status 1 for an empty selection. Keep its raw stderr and the other
   observations: a nonzero status alone does not establish why a row is absent.
   The script retains that status and continues to the review section.

## Read the fields and their limits

TCP LISTEN describes a passive socket waiting for connections. A UDP socket
often appears as UNCONN because it has no fixed peer; that state does not mean
the UDP service is broken. For each row retain the transport, local address,
local port, state, visible PID and process name. Do not infer the application
solely from a familiar port number. Match a known owned PID to its actual
socket row before assigning a service label.

Loopback binding limits the local destination address. Wildcard IPv4 or IPv6
binding describes the local socket's scope but does not by itself prove an
external path, policy allowance or application response. An IPv6 wildcard also
does not establish whether IPv4-mapped connections are accepted; that depends
on the socket and operating-system configuration. A separate authorized
request is needed to test a particular remote path. This exercise performs
passive inventory and sends no service probe.

Process names and file descriptors can be unavailable to this account. An
empty owner column is an evidence gap, not an unowned socket. The `ss` socket
view and `lsof` process view need not expose identical rows under different
permissions or namespaces. Record those limits rather than elevating privilege
or changing policy to make the output match.

## Classify, explain and review

Classify each relevant row as expected for the stated host role, internal-only
or review-needed. Support the choice with the actual owner, bind scope and
service purpose. Keep unknown services in the review-needed group until the
identity is established. Add one diagram showing the issuing machine and
where an additional authorized request would originate. Explain which facts
that request could establish beyond this passive inventory.

For independent work, preserve the prediction, filtered and broader reports,
the stopped-service comparison and a short explanation for every classification.
Confirm only the owned examples were stopped and note whether any practice
service needs restoration. For a guided walkthrough, pause after the first
TCP row, after comparing UDP, after an empty selection and before assigning
policy labels. Reopen the same saved core attempt for its notebook; keep the
reference separate. A complete review identifies both the observed socket
facts and the reachability or ownership questions that remain unanswered.
