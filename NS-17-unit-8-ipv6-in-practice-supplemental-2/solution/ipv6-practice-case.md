# Supplied IPv6 diagnostic cases

These are constructed practice records for reasoning, not output collected by
the Python program or a record of a completed personal lab. Documentation
addresses identify the modeled topology only. Do not probe these addresses.
Complete the predictions and diagnoses in network-notes.md before comparing
the separate reference interpretation.

## Case A: an address answer with no usable on-link endpoint

The modeled reader has lab0 at 192.0.2.10/24 and 2001:db8:8::10/64.
The modeled service has 192.0.2.20/24 and link-local fe80::20 on lab0.
Its current interface inventory has no 2001:db8:8::20 address. A separately
recorded configuration plan names that address as the intended service address.

| Observation | Supplied record |
| --- | --- |
| Selected DNS question | service.course.test, A then AAAA, resolver 192.0.2.53 |
| DNS response | NOERROR; A 192.0.2.20; AAAA 2001:db8:8::20; TTL 60 |
| Reader IPv6 route lookup | 2001:db8:8::20 dev lab0 src 2001:db8:8::10 |
| Reader IPv6 neighbor entry | 2001:db8:8::20 dev lab0 FAILED |
| IPv4 application request | HTTP 200 from 192.0.2.20:8080 |
| IPv6 application request | Connection timeout to [2001:db8:8::20]:8080 |
| Later supplied comparison | After the intended address is configured in the modeled lab, the neighbor becomes REACHABLE and a fresh IPv6 request returns HTTP 200 |

Explain what the DNS, route, neighbor and interface records each establish.
Identify the earliest unsupported step in the IPv6 path. Explain why IPv4
success and a valid AAAA answer do not establish IPv6 application reachability.
State the further approved configuration evidence needed before choosing
between correcting a DNS record and configuring an intended service address.
The later comparison belongs to this supplied case; it is not a change made
by the ordinary-account loopback program.

## Case B: a separate family policy

Now both intended service addresses are configured. The modeled reader's
IPv6 neighbor is REACHABLE. The service socket inventory shows an owned IPv6
TCP listener at [2001:db8:8::20]:8080 and an IPv4 listener at 192.0.2.20:8080.

| Observation | Supplied record |
| --- | --- |
| Fresh IPv4 request | HTTP 200 |
| Fresh IPv6 request | Times out before an HTTP response |
| IPv4 input policy | TCP destination port 8080 ACCEPT; counter increases by 3 |
| IPv6 input policy | TCP destination port 8080 DROP; counter increases by 3 |
| Later supplied comparison | An approved IPv6 policy change is followed by a fresh HTTP 200 over IPv6 |

Locate the policy boundary using the separate-family evidence. Explain why a
live listener does not prove policy allowance, why the IPv4 rule is insufficient
evidence about IPv6, and why a packet counter is not an application response.
The program reads or changes no firewall policy. This modeled comparison must
be labeled separately from the actual loopback observations.

## Case C: scope and address configuration

The modeled reader has two interfaces, lab0 and lab1. A link-local next hop is
written as fe80::1 with no interface recorded. The same numeric address can
exist independently on the two links. State the missing interface identity and
why an unqualified link-local value is insufficient to select the intended
neighbor. A link-local address cannot identify an endpoint on a different link
through an ordinary router.

A supplied Router Advertisement on lab0 names an on-link prefix, permits
autonomous address configuration and advertises a nonzero router lifetime.
The address and default-route observations are still separate checks. A second
record says only that a DHCPv6 lease exists. Explain why that record alone does
not establish the selected IPv6 default router or the successful application
path. No Router Advertisement, DHCPv6 or Neighbor Discovery exchange is sent
or captured by the loopback program.
