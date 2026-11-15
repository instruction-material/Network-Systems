# Firewall policy transfer: preserve a changed management port

The starter permits the original management marker on TCP 2222. Predict why its default run can pass while the same policy loses a fresh connection after --management-port changes to 22022. Change only the management allowance to use the supplied MANAGEMENT_PORT. Keep both first reports and verify the web allowance, denied unrequested service and rollback independently.


## Predict before activation

Sketch the client and service endpoints. Name the required web and management
ports and explain why the unrequested listener remains closed. Explain why
an OpenSSH profile is not proof that the selected nondefault management port
is allowed. Record the initial inactive state and the retained 65530/tcp rule.

## Observe the three fresh requests

Keep the report filename and exact rule choices. For each service, record the
baseline response, active-policy response or failure, peer and destination,
run token and service PID. Compare the numbered UFW view, kernel INPUT default,
allow rules and counters. Verify that the blocked listener remains running.
Distinguish a logging-rule counter from a retained system log message.

## Change and review

Repeat with --management-port 22022 and with --reverse. Compare predictions with the fresh requests rather
than an already-established connection. Explain any mismatch before changing
another rule. Keep the prior reports and settings for independent or guided
review of topology, policy, observations and recovery.

## Verify recovery

Record whether the prior private configuration, retained rule and kernel policy
returned. Reconcile all three restored responses before process shutdown.
Record worker reaping, namespace removal and the measured outer host comparison.
Explain why these IPv4 HTTP observations do not establish SSH authentication,
IPv6 filtering, HTTPS or Internet reachability. Python code study is optional.

## Reference interpretation

Using the selected MANAGEMENT_PORT keeps the rule aligned with both actual listener cases. A default-port success cannot establish the changed-port result. This explains the supplied configuration; fill in actual report identities, observed requests and recovery from a fresh run.
