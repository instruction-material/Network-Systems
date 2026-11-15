# Evidence notebook

Project: DNS resolution extension: distinguish a name answer from a missing resolver

## Context

Record the Linux host, UID, namespace, Python/dig/dnsmasq versions, owned resolver port and issuing terminal.

## Predictions

Predict each query's command status, DNS status, answer types and supported inference before running it.

## Actual observations

Retain new report filenames, raw output/errors, questions, server/port, types and exact returned records. Keep every failed and corrected observation.

## Change and explanation

Record the one-field change, compare fresh observations and explain the DNS boundary using the actual evidence.

## Cleanup and limits

Stop the owned foreground resolver, retain its actual exit and name one conclusion the observations do not establish.

## Worked fixture interpretation

The live missing.course.test questions receive a DNS message whose status is NXDOMAIN. After the owned resolver stops, dig normally exits 9 with no responding DNS message; this is transport_failure. A deadline is also a transport failure with the timeout recorded. Neither event proves that the name exists, nor that it is absent. The source accepts DNS negative answers separately from tool failures and DNS server error statuses.

This is an answer for the fixed supplied DNS fixture, not a completed record of this run. Fill the actual context and raw results above.
