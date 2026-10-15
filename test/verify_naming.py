"""Verify exact addressing packs, optional analyses and real ordinary-user Linux runs."""
import argparse
import ast
import contextlib
import datetime
import hashlib
import importlib.util
import ipaddress
import json
import os
import signal
import subprocess
import sys
import tempfile
from pathlib import Path

PACKS = {
    "NS-06-unit-2-addresses-and-naming": "core",
    "NS-05-unit-2-addresses-and-naming-supplemental-2": "transfer",
    "NS-06-unit-2-addresses-and-naming-supplemental-3": "extension",
}
FILES = ("main.py", "network_lab.py", "naming_lab.py", "network-notes.md", "README.md")


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def complete(source, reference):
    def bounds(text):
        node = next(n for n in ast.parse(text).body
                    if isinstance(n, ast.FunctionDef) and n.name == "analyze")
        return node.lineno - 1, node.end_lineno

    start, end = bounds(source)
    ref_start, ref_end = bounds(reference)
    lines = source.splitlines(keepends=True)
    lines[start:end] = reference.splitlines(keepends=True)[ref_start:ref_end]
    return "".join(lines)


def run(args, cwd, records):
    started = now()
    process = subprocess.Popen(
        args, cwd=cwd, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
    )
    cleanup = "exited and reaped"
    try:
        stdout, stderr = process.communicate(timeout=45)
    except BaseException:
        cleanup = "terminated owned process group"
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGTERM)
        try:
            process.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate(timeout=3)
        raise
    finally:
        records.append({
            "task": "network-addressing-native-acceptance", "parentPid": os.getpid(),
            "cwd": str(cwd), "command": args, "pid": process.pid,
            "startTime": started, "endTime": now(), "exitCode": process.returncode,
            "timeoutSeconds": 45, "childProcessGroupCleanup": cleanup,
        })
    return process.returncode, stdout.decode(), stderr.decode()


def independent_network(evidence):
    interface = ipaddress.ip_interface(evidence["networkInput"])
    network = interface.network
    rows = []
    for raw in evidence["candidateInput"].split(","):
        address = ipaddress.ip_address(raw.strip())
        inside = network.version == address.version and address in network
        rows.append({
            "address": str(address), "version": address.version,
            "inNetwork": inside,
            "firstAddress": inside and address == network[0],
            "lastAddress": inside and address == network[-1],
            "ordinaryIpv4Host": (
                inside and (network.prefixlen >= 31 or address not in (network[0], network[-1]))
            ) if network.version == address.version == 4 else None,
        })
    return {
        "enteredNetwork": evidence["networkInput"], "network": str(network),
        "version": network.version, "prefixLength": network.prefixlen,
        "addressCount": network.num_addresses,
        "hostBitsMasked": interface.ip != network[0], "rows": rows,
        "scope": "address calculation only; no addresses or routes were changed",
    }


def check_observation(evidence, kind, profile):
    assert evidence["environment"]["platform"] == "linux"
    assert evidence["environment"]["uid"] != 0
    assert evidence["environment"]["networkNamespace"].startswith("net:[")
    assert evidence["resolverScope"] == "operating-system NSS lookup; not a DNS-only experiment"
    assert evidence["resolverQuery"] == ("127.0.0.1" if profile == "literal" else "localhost")
    assert evidence["route"][0]["dev"] == "lo"
    assert evidence["loopback"][0]["ifname"] == "lo"
    assert any(ipaddress.ip_address(line.split()[0]) == ipaddress.ip_address("127.0.0.1")
               for line in evidence["getent"].splitlines())
    ready, worker = evidence["ready"], evidence["workerResult"]
    assert ready["http"]["address"] == "127.0.0.1"
    assert 1024 <= ready["http"]["port"] <= 65535
    identity = f"127.0.0.1:{ready['http']['port']}"
    pid = f"pid={ready['pid']},"
    assert any(identity in line.split() and pid in line
               for line in evidence["listenersDuring"].splitlines())
    assert not any(identity in line.split() and pid in line
                   for line in evidence["listenersAfter"].splitlines())
    assert evidence["httpResponse"] == {"message": evidence["message"], "path": "/lab"}
    assert worker["requests"] == ["/lab"] and worker["socketsClosed"]
    assert ready["pid"] == worker["pid"] == evidence["workerProcess"]["pid"]
    assert evidence["workerProcess"]["exitCode"] == 0 and evidence["workerProcess"]["reaped"]
    assert evidence["ipv6Probe"]["address"] == "::1"
    assert evidence["ipv6Probe"]["port"] == ready["http"]["port"]
    assert evidence["ipv6Probe"]["dataSent"] is False
    assert len(evidence["commands"]) == 6
    for row in [*evidence["commands"], evidence["workerProcess"]]:
        assert row["exitCode"] == 0 and row["pid"] > 0
        assert row["parentPid"] == evidence["environment"]["pid"]
        assert row["cwd"] == evidence["environment"]["cwd"]
        assert row["startTime"] <= row["endTime"] and row["timeoutSeconds"] == 8
    expected_network = independent_network(evidence)
    return {
        "core": {
            "resolvedIpv4": ["127.0.0.1"],
            "endpoint": {**ready["http"], "transport": "TCP"},
            "httpMatches": True, "network": expected_network,
        },
        "transfer": expected_network,
        "extension": {
            "query": evidence["resolverQuery"],
            "resolvedFamilies": sorted({row["family"] for row in evidence["resolverAnswers"]}),
            "selectedEndpoint": ready["http"], "ipv6Probe": evidence["ipv6Probe"],
            "workerClosedItsSockets": True, "dnsOnlyObservation": False,
        },
    }[kind]


def verify(root, source_only, proof):
    hashes = {}
    for pack in PACKS:
        guide = (root / pack / "README.md").read_bytes()
        for role in ("starter", "solution"):
            for name in FILES:
                path = root / pack / role / name
                raw = path.read_bytes()
                hashes[str(path.relative_to(root))] = hashlib.sha256(raw).hexdigest()
                if name.endswith(".py"):
                    ast.parse(raw, filename=str(path), feature_version=(3, 10))
                if name == "README.md":
                    assert raw == guide
        hashes[f"{pack}/README.md"] = hashlib.sha256(guide).hexdigest()
    # Known fixed tables supplement the independent per-run calculation oracle.
    sys.path.insert(0, str(root / next(iter(PACKS)) / "starter"))
    path = root / next(iter(PACKS)) / "starter/naming_lab.py"
    spec = importlib.util.spec_from_file_location("naming_source", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    tables = [
        ("192.0.2.64/26", "192.0.2.63,192.0.2.64,192.0.2.65,192.0.2.126,192.0.2.127,192.0.2.128",
         [False, True, True, True, True, False]),
        ("192.0.2.0/31", "192.0.2.0,192.0.2.1,192.0.2.2", [True, True, False]),
        ("192.0.2.1/32", "192.0.2.0,192.0.2.1,192.0.2.2", [False, True, False]),
        ("2001:db8::/126", "2001:db8::,2001:db8::1,2001:db8::3,2001:db8::4,127.0.0.1",
         [True, True, True, False, False]),
        ("0.0.0.0/0", "0.0.0.0,255.255.255.255,127.0.0.1", [True, True, True]),
    ]
    for network, addresses, expected in tables:
        actual = module.network_rows(network, addresses)
        assert [row["inNetwork"] for row in actual["rows"]] == expected
    records, observations, refusals = [], [], []
    profiles = [
        ("default", []),
        ("masked", ["--network", "192.0.2.65/26"]),
        ("single", ["--network", "192.0.2.1/32", "--candidates", "192.0.2.0,192.0.2.1,192.0.2.2"]),
        ("ipv6", ["--network", "2001:db8::/126", "--candidates", "2001:db8::,2001:db8::3,2001:db8::4"]),
        ("literal", ["--lookup", "127.0.0.1"]),
    ]
    result = {
        "mode": "source-only" if source_only else "ordinary-linux-native",
        "nativeAccepted": False, "hashes": hashes, "knownTables": len(tables),
        "processes": records, "observations": observations, "refusals": refusals,
    }
    try:
        if source_only:
            return result
        assert sys.platform == "linux" and os.geteuid() != 0
        with tempfile.TemporaryDirectory(prefix="network-addressing-native-") as temp:
            for pack, kind in PACKS.items():
                for role in ("untouched-starter", "completed-starter", "reference"):
                    source_role = "solution" if role == "reference" else "starter"
                    work = Path(temp) / pack / role
                    work.mkdir(parents=True)
                    for name in FILES:
                        (work / name).write_bytes((root / pack / source_role / name).read_bytes())
                    if role == "completed-starter":
                        (work / "main.py").write_text(complete(
                            (work / "main.py").read_text(),
                            (root / pack / "solution/main.py").read_text(),
                        ))
                    for profile, options in profiles:
                        code, out, err = run([sys.executable, "main.py", *options], work, records)
                        assert code == 0 and not err, (pack, role, profile, code, err)
                        evidence = json.loads(out)
                        expected = check_observation(evidence, kind, profile)
                        assert evidence["analysis"] == (None if role == "untouched-starter" else expected)
                        observations.append({"pack": pack, "role": role, "profile": profile,
                                             "evidence": evidence})
                    for options in (["--network", "bad"], ["--candidates", ""],
                                    ["--lookup", "elsewhere.invalid"], ["--message", "x"],
                                    ["--candidates", ",".join(["::1"] * 33)]):
                        code, out, err = run([sys.executable, "main.py", *options], work, records)
                        assert code == 2 and not out and err
                        refusals.append({"pack": pack, "role": role, "arguments": options,
                                         "code": code, "diagnostic": err})
        assert len(observations) == 45 and len(refusals) == 45
        result["nativeAccepted"] = True
        return result
    finally:
        proof.parent.mkdir(parents=True, exist_ok=True)
        proof.write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-only", action="store_true")
    parser.add_argument("--proof", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    result = verify(root, args.source_only, args.proof)
    print(json.dumps({"nativeAccepted": result["nativeAccepted"], "mode": result["mode"],
                      "observations": len(result["observations"]),
                      "refusals": len(result["refusals"])}))
