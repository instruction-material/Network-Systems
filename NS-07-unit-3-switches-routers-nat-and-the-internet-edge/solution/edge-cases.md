# Constructed Internet-edge comparisons

These supplied records are fictional reasoning cases. They are not live packets
from the private namespace lab. Documentation addresses below are labels, not
targets to contact.

## A: on-link forwarding and a routed next hop

Two modeled peers share 192.0.2.0/24 and one bridged link. A third peer is
198.51.100.20/24 on another routed interface. Explain which destination needs a
gateway from 192.0.2.10/24, which MAC identifies the next hop on each link and
why an IP prefix alone does not create a cable, bridge or usable router.
Separate the modeled diagram from the actual MAC/FDB records in the program.

## B: an extra upstream translation

A modeled home router has private client-side addresses and an upstream
100.64.0.10 address. An outside record names 203.0.113.8 as a public endpoint.
A local destination mapping is present, but no successful outside request is
supplied. Explain why the local mapping alone does not prove control over the
upstream translation, routability of the advertised endpoint or a working
remote application path. Name the next authorized evidence and its scope.

## C: mapping and policy are different

Two modeled routers have the same routes and destination mapping. One permits
the relevant new forwarded connection; the other drops it under a separate
filtering policy. Explain why a NAT rule does not establish policy allowance.
State the additional rule/counter and actual application evidence needed before
assigning a cause. This program changes no restrictive filter and measures no
ISP, external client, public DNS, IPv6 or physical switch.
