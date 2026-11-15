# Evidence notebook

Project: DNS resolution transfer: follow the typed alias answers

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

alias.course.test has CNAME dual.course.test plus A 127.0.0.8 or AAAA ::1 in the respective question. dual.course.test supplies the address data directly, so it does not meet the alias goal. v4.course.test supplies an A answer and a successful NOERROR response with no AAAA data. missing.course.test has NXDOMAIN. These are the owned fixture's configured DNS data, not measurements of an Internet service.

This is an answer for the fixed supplied DNS fixture, not a completed record of this run. Fill the actual context and raw results above.
