# Resolution comparison notebook

## Scope and predictions

Record issuing machine, question name, record type, selected resolver and port,
time, and expected A/AAAA sets. Label the system NSS path separately.

## Actual DNS and NSS evidence

Keep exact commands, raw output and statuses. Separate DNS header status from
shell command status. Record each answer's type, TTL and value; a CNAME is a
name, not an IP address. Keep the actual responding server alongside the data.

## Changed cases

Compare dual records, A-only/NODATA, an alias, NXDOMAIN and the stopped owned
resolver. Compare the controlled localhost DNS view with actual system NSS.
Explain any unavailable path or permission/configuration limit explicitly.

## Interpretation and cleanup

State which lookup path each fact describes and which application or IPv6 path
remains untested. Confirm the owned resolver stopped and system name-service
files were not edited. Propose one further authorized discriminating test.
