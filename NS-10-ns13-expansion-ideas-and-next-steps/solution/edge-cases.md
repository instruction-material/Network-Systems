# Further checks

- An A answer or an IPv6 success alone leaves the IPv4 application path unverified.
- HTTP 200 needs the requested endpoint, expected application identity, matching run marker and path.
- A failed request to a port without an observed listener cannot isolate a policy effect.
- An IPv4 loopback listener and one IPv6 client probe measure different boundaries.
- A successful recorded client says nothing about unmeasured clients, the public internet or an advanced protocol.
- Missing observations remain unknown. Compare the alternate recorded port and name without assuming the default values.
