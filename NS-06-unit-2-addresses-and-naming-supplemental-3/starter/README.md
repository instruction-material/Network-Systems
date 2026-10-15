# Optional Extension: Address Families, Lookup and Reachability

Choose this after the required Addresses and Naming project. Compare the
operating-system lookup view with the actual bound endpoint and a second
address family. This experiment does not configure or query an authoritative
DNS server, so it cannot diagnose public DNS or DNS caching.

Run the default localhost lookup, then repeat with --lookup 127.0.0.1. Save the
getent output and getaddrinfo results separately; their family filters differ.
Compare each with the IPv4 worker endpoint and the recorded ::1 probe. If the
IPv6 result is unexpected, identify its actual observation and possible owner
rather than forcing a preferred explanation.

For the separate IPv6 example, 2001:db8::/126 contains four addresses, :: through
::3. ::4 is outside, and 127.0.0.1 is a different family. IPv6 has no directed
broadcast address. The report's firstAddress/lastAddress fields are numeric
boundaries, not claims about general host assignability or network operation.

Success means a name-versus-literal/family decision table, actual local request
and cleanup evidence, and a justified IPv6 membership table. Distinguish a
lookup result, an IPv6 connection observation and ownership of the IPv4 server.
The optional analysis returns query, resolvedFamilies, selectedEndpoint,
ipv6Probe, workerClosedItsSockets and dnsOnlyObservation (false).

## Environment and files

Prerequisite: the two required foundation labs and a working ordinary Linux
account. Use the same Linux VM, WSL instance or owned remote lab for every
command. In its terminal, check uname -s, hostname, id, pwd and python3 --version.
Python 3.10 or newer and ip, ss, curl, getent, ssh, dig and traceroute are required.
On an Ubuntu lab that you administer, the preparation command is:

    sudo apt-get install python3 iproute2 curl libc-bin openssh-client dnsutils traceroute

Only package preparation uses elevated privileges. Run this project without
sudo. It changes no interfaces, routes, firewall rules, DNS settings or hosts
files. All actual connections target loopback in the selected Linux network
namespace. A container's loopback and the desktop host's loopback are distinct.
No production server or remote service is required.

Start in starter/ and run python3 main.py. The supplied instrumentation already
works; analysis: null is the untouched optional Python extension, not a failed
network experiment. Required work is prediction, reading actual command output,
an address table and network-notes.md. No Python editing is needed for the core
networking deliverable. Save the complete JSON output to a newly named file:

    python3 main.py > first-run.json

The JSON records the commands, their real outputs, actual listener endpoint and
PID, hostname lookup results, HTTP response and owned child cleanup. The helper
starts a temporary HTTP server bound only to 127.0.0.1 on an OS-selected port.
The parent observes it and makes one bounded request. The child closes its
socket and exits. The parent reaps it even on failure. Do not reuse a printed
port after the run; each repetition creates a new owned endpoint.

## Names, addresses, prefixes and ports

A name is a label. The system resolver chooses addresses according to its NSS
configuration, which may include a hosts file and DNS. The getent ahostsv4
command requests the IPv4 system view; getaddrinfo can report both address
families. localhost is local context. A successful localhost lookup is not
evidence that public DNS, a remote resolver or internet routing works.

An IP address identifies a network-layer endpoint. A prefix selects a block of
addresses; it does not identify a listening application. An application endpoint
also needs a transport and port. Here the actual service is IPv4 TCP,
127.0.0.1 and the port in ready.http.port. Its IPv6 counterpart is a different
endpoint even when the numeric port is equal.

Read the ip JSON for interface lo, its address families and prefix lengths.
Read the route lookup's dev field and compare it with the loopback interface.
The ss output names the listening address, port and process. Match all three
to the owned worker, then inspect the HTTP path and message. A loopback result
establishes this local path only. It does not establish remote reachability.

The IPv6 probe attempts a connection to ::1 at the same numeric port before
the IPv4 request and sends no application data. Record its actual error or
connection result. If it connects, inspect the listener and owner; do not assign
another IPv6 service to the IPv4 worker. An unsupported family, a refused
connection and a successful connection are different observations. None alone
identifies a DNS or firewall fault.

## Address calculations

Keep a separate table for the network example. For 192.0.2.64/26, six host bits
remain, so the block has 64 addresses, from .64 through .127. In an ordinary
IPv4 subnet, .64 is the network identifier and .127 is the directed broadcast;
.65 through .126 are ordinary host-address positions. .63 and .128 lie outside
that block. Binary prefix comparison establishes membership; a familiar-looking
first three octets alone is insufficient.

The examples use IPv4 documentation blocks and 2001:db8::/32 for IPv6
documentation. The program never assigns those example addresses or sends
packets to them. Mathematical membership is separate from routing, assignment,
firewall policy and whether a service is listening. A changed --network value
changes the calculation task, not the Linux interface configuration.

Do not equate non-private with reachable. RFC1918's IPv4 private blocks are
10.0.0.0/8, 172.16.0.0/12 and 192.168.0.0/16. Documentation addresses are a
different category. IPv6 has loopback, link-local and global-scope address
categories; a global-looking address alone does not establish internet routing.
Inspect the selected environment's actual addresses and route evidence before
making an operational claim. No address classification requires a port list.

## Run, compare, explain

1. Predict the lookup addresses, worker address family and prefix boundary rows.
2. Run the untouched starter. Record Linux namespace, worker PID and endpoint,
   actual getent/resolver results, route device, HTTP response and cleanup.
3. Complete the address table by hand, with a reason for each membership result.
4. Run the changed case named in this project's brief. Keep both outputs.
5. Explain one expected result, one boundary and one limit of the evidence.
6. Save and reopen the notebook and source; export all role files and README.md.

An independent session follows this sequence. A paced walkthrough pauses after
the prediction and first raw output before consulting solution/. The operations
notebook continues the core project. Transfer and extension packs are optional
choices with their own saved attempts, not additional required core assignments.

If a tool is missing or localhost has no 127.0.0.1 IPv4 mapping, fix the selected
lab environment and retry. A bounded socket or command failure is not proof of
a remote network problem. Keep its diagnostic instead of inventing an output.
Stop with Ctrl-C if needed; do not kill unrelated services or change global
network settings to force the example to pass.

## Optional Python analysis

Complete only analyze(evidence) in main.py after the networking explanation
works. The supplied naming_lab.network_rows function parses literal addresses and performs
bounded membership calculations without enumerating a subnet. A /0 example
therefore does not allocate billions of host records. A network entered with
host bits, such as 192.0.2.65/26, is normalized to 192.0.2.64/26 and reports
hostBitsMasked: true. A bare address is a single-address prefix.

The reference function derives the specified fields from the same evidence. Its
notebook supplies reasoning examples, not fabricated terminal observations.
Keep actual output and the explanation separate. Completing the Python
dictionary does not grade the required networking explanation.

## Primary references

- [Python 3.10 address parsing and membership](https://docs.python.org/3.10/library/ipaddress.html)
- [RFC1918 private addressing](https://www.rfc-editor.org/rfc/rfc1918.html)
- [RFC5737 IPv4 documentation blocks](https://www.rfc-editor.org/rfc/rfc5737.html)
- [RFC3849 IPv6 documentation block](https://www.rfc-editor.org/rfc/rfc3849.html)
