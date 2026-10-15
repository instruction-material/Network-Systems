"""Address arithmetic, NSS resolution and owned native Linux observations."""
import ipaddress
import json
import socket

from network_lab import command, environment, require_linux, validate, with_worker


def parse_inputs(network, candidates):
    if len(network) > 128 or len(candidates) > 4096:
        raise ValueError("Use one short network and at most 32 candidate addresses.")
    interface = ipaddress.ip_interface(network)
    values = candidates.split(",")
    if not 1 <= len(values) <= 32 or any(not item.strip() for item in values):
        raise ValueError("Use 1 to 32 comma-separated address literals.")
    addresses = [ipaddress.ip_address(item.strip()) for item in values]
    return interface, addresses


def network_rows(network, candidates):
    interface, addresses = parse_inputs(network, candidates)
    subnet = interface.network
    rows = []
    for address in addresses:
        inside = address.version == subnet.version and address in subnet
        rows.append({
            "address": str(address),
            "version": address.version,
            "inNetwork": inside,
            "firstAddress": inside and address == subnet.network_address,
            "lastAddress": inside and address == subnet.broadcast_address,
            "ordinaryIpv4Host": (
                inside and (
                    subnet.prefixlen >= 31
                    or address not in (
                        subnet.network_address, subnet.broadcast_address,
                    )
                )
            ) if subnet.version == address.version == 4 else None,
        })
    return {
        "enteredNetwork": network,
        "network": str(subnet),
        "version": subnet.version,
        "prefixLength": subnet.prefixlen,
        "addressCount": subnet.num_addresses,
        "hostBitsMasked": interface.ip != subnet.network_address,
        "rows": rows,
        "scope": "address calculation only; no addresses or routes were changed",
    }


def addressing(message, network, candidates, lookup):
    # Refuse malformed inputs before starting any owned service.
    parse_inputs(network, candidates)
    validate(message, 256)
    if lookup not in ("localhost", "127.0.0.1"):
        raise ValueError("Compare localhost with the literal 127.0.0.1 only.")
    require_linux()
    evidence = {
        "kind": "addressing",
        "message": message,
        "environment": environment(),
        "commands": [],
        "networkInput": network,
        "candidateInput": candidates,
        "resolverQuery": lookup,
        "resolverScope": "operating-system NSS lookup; not a DNS-only experiment",
    }
    tools = evidence["environment"]["tools"]
    commands = evidence["commands"]
    evidence["loopback"] = json.loads(command(
        [tools["ip"], "-j", "address", "show", "dev", "lo"], commands,
    ))
    evidence["route"] = json.loads(command(
        [tools["ip"], "-j", "route", "get", "127.0.0.1"], commands,
    ))
    evidence["getent"] = command(
        [tools["getent"], "ahostsv4", lookup], commands,
    )

    def observe(ready):
        port = ready["http"]["port"]
        answers = socket.getaddrinfo(lookup, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        evidence["resolverAnswers"] = [
            {"family": family, "address": address[0], "port": address[1]}
            for family, _kind, _protocol, _canon, address in answers
        ]
        ipv4 = [row["address"] for row in evidence["resolverAnswers"]
                if row["family"] == socket.AF_INET]
        if not ipv4 or any(address != "127.0.0.1" for address in ipv4):
            raise ValueError("The selected lab must resolve localhost to 127.0.0.1.")
        evidence["listenersDuring"] = command(
            [tools["ss"], "-H", "-ltnp"], commands,
        )
        # A same-number IPv6 endpoint is a different endpoint. Never send it data.
        probe = {"address": "::1", "port": port, "dataSent": False}
        try:
            with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                code = sock.connect_ex(("::1", port))
                probe.update(supported=True, errno=code, connected=code == 0)
        except OSError as error:
            probe.update(supported=False, errno=error.errno, connected=False)
        evidence["ipv6Probe"] = probe
        evidence["httpResponse"] = json.loads(command([
            tools["curl"], "--noproxy", "*", "--ipv4", "--silent",
            "--show-error", "--fail", "--max-time", "5",
            f"http://{lookup}:{port}/lab",
        ], commands))

    with_worker("setup", {"message": message}, observe, evidence)
    evidence["listenersAfter"] = command(
        [tools["ss"], "-H", "-ltnp"], commands,
    )
    return evidence
