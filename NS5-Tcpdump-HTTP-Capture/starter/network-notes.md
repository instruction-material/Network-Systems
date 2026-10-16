# HTTP capture observations

## Predict before running

Identify the capture interface and namespace. Explain why a loopback request
cannot be diagnosed by capturing the VM's external interface. Explain why the recorded
`-nn` keeps endpoints numeric, why a packet count needs an independent deadline, and
which of the two owned service ports belongs in the filter.

## Capture and interpret

| Observation | Prediction | Actual packet or command evidence | Explanation |
| --- | --- | --- | --- |
| Client source port and selected service port | | | |
| Initial SYN and reverse-direction SYN/ACK | | | |
| HTTP request line and response status | | | |
| Response body and per-run token | | | |
| Presence or absence of the independent flow on port 8081 | | | |
| Numeric address and port display | | | |
| Packet count and wall-clock cleanup | | | |

## Change, compare and review

Run the same settings with `--reverse`. Compare membership in the selected
flow with packet ordering. Explain which application bytes are visible in
this plaintext HTTP experiment and why this is not evidence about TLS
plaintext visibility. Keep the original report, the changed report and the
settings used for each. Account for both worker processes and the temporary
namespace after each run. Complete the two capture settings and explain
the actual evidence independently or during a paced review.
