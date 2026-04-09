# NS5 Tcpdump HTTP Capture

Capture and analyze one HTTP request at the packet level.

## Goals

- use a narrow packet capture filter
- identify source port, destination port, and response packets
- explain what stayed visible before TLS

## Starter Expectations

- tighten the capture filter to one host or one port
- explain why `-nn` is useful
- identify the packet sequence that represents the response

## Solution Highlights

- uses a constrained capture filter and packet limit
- reinforces safe capture habits
- focuses students on one visible request instead of noisy output
