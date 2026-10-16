# NS3: Build, Observe and Roll Back an Owned UFW Policy

This project measures how a host firewall changes fresh connections to a
running service. Complete two UFW rule choices, compare actual client
requests with kernel rules and counters, and verify restoration of the
prior configuration. The operations notebook records this same project.
Python programming is optional; the supplied apparatus stays unchanged.

## Environment and boundary

Use an owned disposable Linux VM with console access and a snapshot. This
experiment requires root, Linux network and mount namespaces, Python 3.10+,
UFW, iproute2, iptables, util-linux and curl. On Ubuntu the packages are
`python3 ufw iproute2 iptables util-linux curl`. The native acceptance gate
uses Ubuntu 24.04. Record the distribution, kernel and `ufw --version` when
repeating the experiment in another supported Linux environment.

Extract the ZIP, read this guide, and enter its `starter` directory. The
six imported files are this README plus `starter/network-notes.md`,
`starter/apply_web_policy.sh`, `starter/policy-rules.sh`,
`starter/web-stack.profile` and `starter/firewall_runtime.py`. The reference
uses the corresponding `solution` directory. The site workspace edits and
saves these files; execute the real policy experiment in the Linux VM.

The launcher first records the outer host's network and UFW configuration.
It then enters new network and mount namespaces. All UFW changes use private
configuration at `/etc/ufw` and `/etc/default/ufw`; the named client registry also
belongs to that run. The original namespaces are refused before mutation.
Calling `policy-rules.sh` directly is refused unless the owned namespace
and private configuration markers are present. No command in this pack
requires changing a real server's policy or its SSH connection.

## Trace the experiment

The owned client is `10.77.0.1`; the owned service endpoint is `10.77.0.2`.
A veth pair connects them directly. This is an IPv4 endpoint policy exercise,
so traffic is checked by the service host's INPUT rules. A routed topology
would use FORWARD rules instead and needs a separate forwarding analysis.
UFW's private IPv6 setting is disabled for this controlled comparison;
the outer IPv6 configuration is retained. These results do not establish
an IPv6 policy, Internet reachability or a production deployment.

Three listeners remain running during the policy comparison:

| Purpose | TCP port | Required policy outcome |
| --- | --- | --- |
| Owned management marker | 2222 by default | Allow a fresh connection |
| Local HTTP web service | 8080 | Allow a fresh connection |
| Unrequested local service | 9090 | Deny a fresh connection |

The management marker returns a small HTTP identity; it is not an SSH daemon
and does not test SSH authentication. Its nondefault port makes the distinction
between an administration requirement and an assumed service name visible.
An OpenSSH application profile commonly names a different port; allowing that
profile alone does not prove that the selected management port remains usable.

Before activation, all three listeners answer from the client. The private
configuration already contains a harmless retained rule for 65530/tcp and
UFW is inactive. That prior rule must survive policy application and the
original private configuration must return after rollback. This is a measured
starting state, not permission to reset an existing real host's firewall.

## Complete the two rule choices

The apparatus supplies default-deny incoming, default-allow outgoing,
logging at the low level and controlled activation. In `policy-rules.sh`,
replace only `TODO_MANAGEMENT` and `TODO_WEB` with the corresponding rules.
The management case runs before activation and receives `MANAGEMENT_PORT`.
Use that supplied value rather than hardcoding 22 or 2222. The web case names
the `Course Web` application profile defined by `web-stack.profile`.

UFW accepts a numeric rule such as `ufw allow 7999/tcp` and an application
rule such as `ufw allow "Example Application"`. A profile's name is only a
label: its `ports=` field determines the selected protocol and destination.
Inspect the supplied profile before choosing the rule. Here it selects only
8080/tcp. Opening 443 or 8443 without an actual HTTPS requirement and a TLS
service would add exposure without proving HTTPS works.

Do not add a reset, flush, policy enable or cleanup command to the two cases.
Those operations belong to the supplied owned apparatus, which preserves the
existing private rule. The untouched starter still runs and records the
consequences of its missing allowances; it reports an incomplete result.

## Run and reconcile the evidence

From the selected role directory, use a new filename for each report:

```sh
sudo bash apply_web_policy.sh --output policy-observations.json
sudo bash apply_web_policy.sh --management-port 22022 --output changed-port.json
sudo bash apply_web_policy.sh --reverse --output reverse-order.json
```

Predict the results in `network-notes.md` before the first run. Each run owns
its temporary services and has a wall-clock bound. It removes its namespaces
and processes on normal completion, a handled failure or an interruption.
Existing reports, symlink outputs and missing output directories are refused.

Read the actual JSON fields rather than treating `complete` as the explanation:

1. `baselineRequests` proves all three services and the client path work
   before activation. Responses identify the run token, service PID,
   destination and peer endpoints. Each curl invocation opens a fresh connection.
2. `activeBeforeProbe` records UFW's numbered and verbose views and the actual
   kernel rules. Numbered output lists managed rules, not every rule or default.
3. `policyRequests` separates management, web and unrequested traffic. In a
   completed attempt, the first two return matching identities and the third
   fails. `activeAfterProbe.listeners` confirms that the failed request did not
   merely target a stopped service. Compare actual INPUT and logging-rule
   counters with these outcomes. A logging-rule counter is evidence of that
   rule being traversed; it is not a retained journal entry. This experiment
   does not read or alter the outer host's system logs.
4. `rollback` compares the saved private configuration and kernel rules with
   the restored state. Its fresh requests must reach all three original
   listeners before those listeners stop. `cleanup` records process reaping
   and namespace removal. `hostBefore`, `hostAfter` and `hostUnchanged` cover
   the measured outer configuration independently of private rollback.

Keep the original report beside the changed-port and reverse-order reports.
Explain a failure using the listener, route, rule and request evidence. A
successful old connection does not prove that a new management connection is
allowed. A timeout alone does not distinguish a firewall drop from a broken
path, which is why the baseline, active listener and restored-request checks
are all part of the experiment.

## Independent study and paced review

Work through the topology, prior state, two allowances, active observations
and rollback in that order. An independent review checks every prediction
against the reports and records a reason for each mismatch. A guided
walkthrough can pause after the topology sketch, after the two rule choices,
after the three fresh requests and after restoration. The same notebook and
saved attempt support both routes. Compare the reference after the initial
attempt; the reference remains a separate role.

Optional code study can trace the namespace guards, private mounts, request
identity or interruption cleanup in `firewall_runtime.py`. These are supplied
apparatus rather than another required Python assignment. Extending to TLS,
IPv6, a routed firewall or a real SSH daemon needs its own owned targets and
verification; the current result does not imply those extensions succeeded.

## References

- [UFW command, remote-management and application-profile manual](https://manpages.ubuntu.com/manpages/noble/man8/ufw.8.html)
- [UFW framework and configuration files](https://manpages.ubuntu.com/manpages/noble/man8/ufw-framework.8.html)
