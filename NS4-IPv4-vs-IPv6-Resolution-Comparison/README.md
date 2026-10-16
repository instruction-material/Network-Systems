# DNS records, address families and system name service

This comparison keeps three questions separate: which DNS records a selected
resolver returned, which addresses the operating system supplied through its
name-service path (the Linux Name Service Switch, or NSS), and whether an application can connect to one of those
addresses. The supplied script observes the first two questions. It does not
test an application connection, choose a client's preferred family or prove an
IPv6 data path. An absent AAAA answer is evidence about this DNS view and
question, not proof that a service or machine is IPv4-only.

## Prepare the lookup paths

Use an owned Linux practice environment with Bash, GNU coreutils (`timeout`),
BIND's `dig` and libc's `getent`. Running the supplied comparison requires an
ordinary account. Review and save the selected role, download its ZIP and
enter the selected role folder (`starter/` for the learner attempt or
`solution/` for the reference) in the external Linux terminal. The browser saves the scripts
and `network-notes.md`; the actual system commands execute on Linux. Keep each
comparison under a fresh report name. The reference belongs to a separate
workspace and does not replace the learner attempt.

Run `bash compare_resolution.sh example.com` to query the configured DNS
resolver, or supply an authorized server and port explicitly. The optional
server applies only to `dig`. It does not redirect `getent`, change
`/etc/resolv.conf`, replace `/etc/hosts` or alter `/etc/nsswitch.conf`.
Each command prints its exact arguments, raw response and exit status. DNS
requests have a two-second response wait and one attempt; every command also
has a five-second outer deadline with bounded termination.

## Use an optional controlled DNS example

If the lab provides dnsmasq (often packaged as `dnsmasq-base`), an ordinary
account can start this isolated example on an unused high port. The example
uses no system hosts file, upstream resolver or default configuration. Keep
the terminal open and stop this owned process with Ctrl-C after the comparison.
Choose another high port if 1053 is already in use; do not stop an unrelated
service or edit the system resolver to make the example work.

```sh
dnsmasq --no-daemon --conf-file=/dev/null \
  --listen-address=127.0.0.1 --bind-interfaces --port=1053 \
  --no-hosts --no-resolv --log-facility=- \
  --local=/course.test/ --local=/localhost/ \
  --host-record=dual.course.test,127.0.0.8,::1 \
  --host-record=v4.course.test,127.0.0.9 \
  --cname=alias.course.test,dual.course.test
```

In a second terminal, run
`bash compare_resolution.sh dual.course.test 127.0.0.1 1053`.
Repeat with `v4.course.test`, `alias.course.test`, `missing.course.test` and
`localhost`. This DNS server is reached over IPv4 loopback. An AAAA answer
containing `::1` describes returned data; it does not turn that DNS exchange
into an IPv6 connection test.

## Predict and read the actual answers

1. Predict the A and AAAA record sets and response status before each query.
   Preserve the question name, record type, explicit server, port and time.
   Read the DNS header status separately from the shell command status.
2. Read each answer as name, TTL, class, record type and value. An A value is
   an IPv4 address and an AAAA value is an IPv6 address. IN identifies the Internet DNS class. The DNS TTL advertises a cache lifetime in seconds; it is separate from an IP packet's hop limit. A CNAME names an alias
   target, not an address. The alias case can contain both CNAME and typed
   address records; do not treat every answer line as an IP address.
3. Compare the dual-address name with the A-only name. A successful NOERROR
   response with no AAAA answer is a type-specific absence, often called
   NODATA. NXDOMAIN instead reports that the queried name is absent from this
   resolver's view. A command can exit successfully after receiving either
   DNS response, so an empty short-answer listing alone loses useful context.
4. Stop only the owned resolver and repeat the explicit-server query. Retain
   the raw transport error and nonzero status, and confirm the remaining
   comparison still prints. A missing DNS response is a different observation
   from a received negative DNS answer. Restore the example only if another
   comparison is needed.

## Compare the separate system lookup

The starter leaves a named system-lookup block. Complete it with
`probe 'System NSS address view' getent ahosts "$query_name"`, or run the
equivalent manual command and keep its status and raw output. Bash programming
is optional; the lookup observations and their explanation are the core work.
The reference includes that bounded call.

Compare `localhost` through the explicitly selected empty DNS view and through
the actual system lookup. NSS commonly supplies localhost from local hosts
data, while this controlled DNS server has no matching record. Record what
this machine actually returns rather than assuming the results must match.
For the fictional course names, the selected DNS example and the system's
configured lookup path can legitimately disagree. Family filtering, local
overrides, caches and name-service policy can affect the application-facing
result. None establishes the client's eventual connection order or success.

Different DNS client tools can still consult the same configured resolver;
that alone is not a comparison of independent resolver views. To compare
resolvers, repeat the same named question against another authorized server
and label both sources and times. DNS view differences or caching can explain
different answers. Leave that comparison unmeasured if a second resolver is
unavailable. Never replace system configuration merely to force agreement.

## Independent work and paced review

For independent work, keep each prediction beside the full response, typed
answer set, command status and separate NSS observation. Explain the dual,
A-only, alias, negative-name and stopped-resolver cases. State which further
authorized application test would be needed before claiming reachability.
Confirm the owned resolver was stopped and no system name-service files were
edited. A complete notebook distinguishes DNS facts, system lookup facts and
unmeasured application behavior.

For a guided walkthrough, pause after predicting each record set, after a
negative response, after the localhost contrast and before choosing a next
test. Reopen the matching saved core attempt for its notebook. Use the
[dnsmasq option reference](https://thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html)
for the optional fixture; all interpretation steps needed for the comparison
are included here.
