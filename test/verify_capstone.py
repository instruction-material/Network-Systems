"""Independently check real capstone attempts, packet bytes and cleanup."""
import argparse
import contextlib
import datetime
import hashlib
import ipaddress
import json
import os
import re
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACK = "NS-03-network-systems-lab-17"
REQUIRED = {"main.py", "capstone_lab.py", "case.json", "network-notes.md", "edge-cases.md"}
CORRECT = {"ipv4_service_route": "198.18.32.0/30", "proxy_upstream_port": 9000}
PROCESSES = []
RETAINED = None
PROCESS_LOG = None


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def hashes(root):
    return {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(root.rglob("*")) if path.is_file()}


def run(argv, cwd, interrupted_output=None):
    argv = [str(value) for value in argv]
    started = now()
    environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    child = subprocess.Popen(argv, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True, env=environment)
    runtime = None
    out = err = b""
    cleanup = "owned project process group exited"
    try:
        if interrupted_output:
            limit = time.monotonic() + 12
            ready_path = interrupted_output / "ready.json"
            while not ready_path.exists():
                assert child.poll() is None, "Project exited before interruption checkpoint"
                assert time.monotonic() < limit, "Ready checkpoint was not reached"
                time.sleep(0.04)
            ready = json.loads(ready_path.read_text())
            physical_net = os.readlink("/proc/self/ns/net")
            physical_mount = os.readlink("/proc/self/ns/mnt")
            inside_pid = ready["pid"]
            actual_net = os.readlink(f"/proc/{inside_pid}/ns/net")
            actual_mount = os.readlink(f"/proc/{inside_pid}/ns/mnt")
            assert actual_net == ready["identities"]["network"] != physical_net
            assert actual_mount == ready["identities"]["mount"] != physical_mount
            workers = []
            for worker in ready["workers"]:
                pid = worker["pid"]
                observed = {"pid": pid, "processGroup": os.getpgid(pid),
                            "network": os.readlink(f"/proc/{pid}/ns/net"),
                            "mount": os.readlink(f"/proc/{pid}/ns/mnt")}
                assert observed["processGroup"] == inside_pid
                assert observed["network"] not in {physical_net, actual_net}
                assert observed["mount"] != physical_mount
                workers.append(observed)
            assert len(workers) == 3
            runtime = {"insidePid": inside_pid, "insideNetwork": actual_net, "insideMount": actual_mount,
                       "physicalNetwork": physical_net, "physicalMount": physical_mount, "workers": workers}
            child.send_signal(signal.SIGINT)
        out, err = child.communicate(timeout=50)
    except BaseException:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(child.pid, signal.SIGTERM)
        try:
            out, err = child.communicate(timeout=8)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(child.pid, signal.SIGKILL)
            out, err = child.communicate(timeout=3)
        cleanup = "owned project process group terminated and reaped"
        raise
    finally:
        result = {"parentTaskId": "network-capstone-native-source", "cwd": str(cwd), "command": argv,
                  "pid": child.pid, "parentPid": os.getpid(), "startTime": started, "endTime": now(),
                  "exitCode": child.returncode, "timeoutSeconds": 50, "childProcessGroupCleanup": cleanup,
                  "stdout": out.decode(errors="replace"), "stderr": err.decode(errors="replace")}
        PROCESSES.append(result)
        if PROCESS_LOG is not None:
            with PROCESS_LOG.open("a") as stream:
                stream.write(json.dumps(result) + "\n")
        if RETAINED is not None and "--output" in argv:
            output = Path(argv[argv.index("--output") + 1])
            if output.is_dir():
                shutil.copytree(output, RETAINED / output.name)
    return result, runtime


def dns_name(raw, offset, visited=None):
    visited = set() if visited is None else visited
    assert offset not in visited and len(visited) < 20
    visited.add(offset)
    parts = []
    while True:
        assert offset < len(raw)
        length = raw[offset]
        if length & 0xc0 == 0xc0:
            assert offset + 1 < len(raw)
            pointer = ((length & 0x3f) << 8) | raw[offset + 1]
            name, _end = dns_name(raw, pointer, visited)
            parts.append(name)
            return ".".join(parts), offset + 2
        assert length < 64
        offset += 1
        if not length:
            return ".".join(parts), offset
        assert offset + length <= len(raw)
        parts.append(raw[offset:offset + length].decode("ascii"))
        offset += length


def packet_observations(path):
    raw = path.read_bytes()
    assert len(raw) > 24
    formats = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">",
               b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">"}
    endian = formats[raw[:4]]
    major, minor, _zone, _sigfigs, snaplen, link = struct.unpack_from(endian + "HHIIII", raw, 4)
    assert (major, minor, link) == (2, 4, 1) and snaplen >= 1500
    offset = 24
    packets, answers, http_statuses, request_hosts, response_tokens = [], [], [], [], []
    while offset < len(raw):
        assert offset + 16 <= len(raw)
        _seconds, _subseconds, length, original = struct.unpack_from(endian + "IIII", raw, offset)
        offset += 16
        assert 14 <= length <= original and length <= snaplen and offset + length <= len(raw)
        frame = raw[offset:offset + length]
        offset += length
        ethertype = struct.unpack_from("!H", frame, 12)[0]
        if ethertype == 0x0800:
            header = frame[14:]
            ihl = (header[0] & 15) * 4
            total = struct.unpack_from("!H", header, 2)[0]
            assert header[0] >> 4 == 4 and ihl >= 20 and ihl <= total <= len(header)
            assert struct.unpack_from("!H", header, 6)[0] & 0x3fff == 0
            family, protocol = 4, header[9]
            source, destination = str(ipaddress.ip_address(header[12:16])), str(ipaddress.ip_address(header[16:20]))
            payload = header[ihl:total]
        else:
            assert ethertype == 0x86dd
            header = frame[14:]
            size = struct.unpack_from("!H", header, 4)[0]
            assert header[0] >> 4 == 6 and len(header) >= 40 + size
            family, protocol = 6, header[6]
            source, destination = str(ipaddress.ip_address(header[8:24])), str(ipaddress.ip_address(header[24:40]))
            payload = header[40:40 + size]
        assert protocol in {6, 17}
        assert len(payload) >= (20 if protocol == 6 else 8)
        source_port, destination_port = struct.unpack_from("!HH", payload)
        row = {"family": family, "source": source, "destination": destination,
               "sourcePort": source_port, "destinationPort": destination_port, "protocol": protocol,
               "frameSha256": hashlib.sha256(frame).hexdigest()}
        if protocol == 6:
            data_offset = (payload[12] >> 4) * 4
            assert 20 <= data_offset <= len(payload)
            row["flags"] = payload[13]
            data = payload[data_offset:]
            status = re.search(rb"HTTP/1\.[01] (\d{3}) ", data)
            if status:
                http_statuses.append({"family": family, "status": int(status[1]), "source": source})
            host = re.search(rb"\bHost: ([^\r\n]+)", data, re.IGNORECASE)
            if host:
                request_hosts.append(host[1].decode("ascii"))
            token = re.search(rb'"token"\s*:\s*"([0-9a-f]{20})"', data)
            if token:
                response_tokens.append({"family": family, "token": token[1].decode("ascii")})
        else:
            udp_length = struct.unpack_from("!H", payload, 4)[0]
            assert 8 <= udp_length <= len(payload)
            data = payload[8:udp_length]
            if source_port == 15353:
                _transaction, flags, questions, answer_count, _authority, _additional = struct.unpack_from("!HHHHHH", data)
                assert flags & 0x8000 and questions == 1
                question, cursor = dns_name(data, 12)
                cursor += 4
                for _answer in range(answer_count):
                    owner, cursor = dns_name(data, cursor)
                    kind, rrclass, _ttl, size = struct.unpack_from("!HHIH", data, cursor)
                    cursor += 10
                    assert cursor + size <= len(data)
                    if kind in {1, 28}:
                        assert rrclass == 1 and size == (4 if kind == 1 else 16)
                        answers.append({"transportFamily": family, "question": question, "owner": owner,
                                        "type": kind, "address": str(ipaddress.ip_address(data[cursor:cursor + size]))})
                    cursor += size
        packets.append(row)
    assert offset == len(raw) and 1 <= len(packets) <= 160
    return {"sha256": hashlib.sha256(raw).hexdigest(), "packets": packets, "answers": answers, "httpStatuses": http_statuses, "requestHosts": request_hosts, "responseTokens": response_tokens}


def cleanup_evidence(output):
    parent = json.loads((output / "receipt.json").read_text())
    lab = json.loads((output / "inside.json").read_text())
    assert parent["hostUnchanged"] and parent["before"] == parent["after"]
    assert lab["allWorkersReaped"] and lab["remainingNamespaces"] == ""
    assert lab["identities"]["network"] != lab["identities"]["parentNetwork"]
    assert lab["identities"]["mount"] != lab["identities"]["parentMount"]
    for worker in lab["workers"]:
        assert isinstance(worker["exitCode"], int) and worker["endTime"] >= worker["startTime"]
        assert not Path("/proc/" + str(worker["pid"])).exists()
    assert len(lab["workers"]) == 3
    commands = json.loads((output / "commands.json").read_text())
    for record in commands + json.loads((output / "parent-commands.json").read_text()):
        assert record["parentTaskId"] and record["command"] and record["pid"] > 0 and record["cwd"]
        assert 0 < record["timeoutSeconds"] <= 8 and record["endTime"] >= record["startTime"]
        assert isinstance(record["exitCode"], int) and record["childProcessGroupCleanup"]
    return parent, lab, commands


def completed_evidence(output, alternate):
    parent, lab, commands = cleanup_evidence(output)
    assert parent["exitCode"] == 0 and not parent["cancelled"] and not lab["interrupted"] and lab["completed"]
    client_net = 41 if alternate else 31
    c4, c6 = f"198.18.{client_net}.2", f"2001:db8:{client_net}::2"
    s4, s6, port = "198.18.32.2", "2001:db8:32::2", 8087 if alternate else 8080
    name = ("amber" if alternate else "blue") + ".capstone.test"
    assert lab["token"] == hashlib.sha256((name + str(output)).encode()).hexdigest()[:20]
    assert (lab["client4"], lab["client6"], lab["server4"], lab["server6"], lab["publicPort"], lab["name"]) == (c4, c6, s4, s6, port, name)
    for owner, expected4, expected6 in [("ncap-client", [c4], [c6]), ("ncap-router", [f"198.18.{client_net}.1", "198.18.32.1"], [f"2001:db8:{client_net}::1", "2001:db8:32::1"]), ("ncap-server", [s4], [s6])]:
        for family, wanted in [("ipv4", expected4), ("ipv6", expected6)]:
            observed = [entry["local"] for interface in json.loads(lab["addresses"][owner][family]["stdout"]) for entry in interface.get("addr_info", [])]
            assert set(wanted) <= set(observed)
    assert "net.ipv4.ip_forward = 1" in lab["forwarding"]["stdout"] and "net.ipv6.conf.all.forwarding = 1" in lab["forwarding"]["stdout"]
    assert lab["routeGet4"]["exitCode"] == lab["routeGet6"]["exitCode"] == 0
    assert c4 in lab["routeGet4"]["stdout"] and c6 in lab["routeGet6"]["stdout"]
    listeners = [line.split()[4] for line in lab["listeners"]["stdout"].splitlines() if len(line.split()) >= 6]
    assert [address for address in listeners if address.endswith(":9000")] == ["127.0.0.1:9000"]
    assert len([address for address in listeners if address.endswith(":8088")]) == 2
    assert len([address for address in listeners if address.endswith(":" + str(port))]) == 2
    for family, client in [(4, c4), (6, c6)]:
        policy = lab["policy" + str(family)]["stdout"]
        assert "-P INPUT DROP" in policy and client in policy and "--dport " + str(port) in policy
        assert "--dport 15353" in policy and "--dport 8088" not in policy
    assert lab["dns"]["A"]["stdout"].strip() == lab["dns4"]["stdout"].strip() == s4
    assert lab["dns"]["AAAA"]["stdout"].strip() == s6
    assert lab["resolvedDestinations"] == {"A": s4, "AAAA": s6}
    for key, address in [("http4", s4), ("http6", s6)]:
        result = lab[key]
        assert result["command"]["exitCode"] == 0 and result["status"] == "200"
        assert address in result["command"]["command"][-1]
        assert json.loads(result["body"]) == {"fixture": "owned-operations-capstone", "token": lab["token"], "path": "/health"}
        assert (output / (key + ".body")).read_text() == result["body"]
    assert lab["missingPath"]["status"] == "404" and json.loads(lab["missingPath"]["body"])["path"] == "/missing"
    assert (output / "missing.body").read_text() == lab["missingPath"]["body"]
    for key in ["denied4", "denied6", "directUpstream"]:
        assert lab[key]["status"] == "000" and lab[key]["command"]["exitCode"] != 0 and not lab[key]["body"]
    packet = packet_observations(output / "capture.pcap")
    assert {(a["type"], a["address"]) for a in packet["answers"] if a["owner"] == a["question"] == name} >= {(1, s4), (28, s6)}
    assert all(a["transportFamily"] in {4, 6} and a["question"] == name for a in packet["answers"])
    assert {(h["family"], h["status"]) for h in packet["httpStatuses"]} >= {(4, 200), (6, 200), (6, 404)}
    assert name in packet["requestHosts"]
    assert {(row["family"], row["token"]) for row in packet["responseTokens"]} >= {(4, lab["token"]), (6, lab["token"])}
    assert {(row["family"], row["destination"], row["destinationPort"]) for row in packet["packets"] if row["protocol"] == 6 and row["flags"] & 2} >= {(4, s4, port), (6, s6, port)}
    return {"alternate": alternate, "packetEvidence": packet, "commandRecords": len(commands),
            "actualHTTPResponses": 3, "actualDeniedConnections": 3, "case": lab["case"],
            "hostUnchanged": True, "learnerNotebookCompletionInferred": False}


def main():
    global RETAINED, PROCESS_LOG
    parser = argparse.ArgumentParser()
    parser.add_argument("--proof", type=Path, required=True)
    args = parser.parse_args()
    pack = ROOT / PACK
    before = hashes(pack)
    for role in ["starter", "solution"]:
        assert REQUIRED <= {path.name for path in (pack / role).iterdir() if path.is_file()}
    assert (pack / "starter/capstone_lab.py").read_bytes() == (pack / "solution/capstone_lab.py").read_bytes()
    assert json.loads((pack / "solution/case.json").read_text()) == CORRECT
    assert json.loads((pack / "starter/case.json").read_text()) == {"ipv4_service_route": "198.18.99.0/30", "proxy_upstream_port": 9001}
    args.proof.parent.mkdir(parents=True, exist_ok=True)
    retained = args.proof.parent / "capstone-observations"
    retained.mkdir(exist_ok=False)
    RETAINED = retained
    PROCESS_LOG = args.proof.with_suffix(".processes.jsonl")
    accepted, unfinished, regressions, interruptions, refusals = [], [], [], [], []
    completed_hashes = {}
    with tempfile.TemporaryDirectory(prefix="network-capstone-contracts-") as temporary:
        work = Path(temporary)
        completed = work / "completed"
        shutil.copytree(pack / "starter", completed)
        (completed / "case.json").write_bytes((pack / "solution/case.json").read_bytes())
        starter_hashes, completed_hashes = hashes(pack / "starter"), hashes(completed)
        assert {name for name in starter_hashes if starter_hashes[name] != completed_hashes[name]} == {"case.json"}
        for entry, extra in [("_inside", [str(pack / "solution/case.json"), str(work / "refused-inside"), "0", "0"]), ("_serve", ["8080", "9000", "owned-token"])]:
            result, _runtime = run([sys.executable, pack / "solution/capstone_lab.py", entry, *extra], pack / "solution")
            assert result["exitCode"] != 0 and "Internal lab entry requires distinct owned network and mount namespaces" in result["stderr"]
            refusals.append({"kind": entry, "result": result, "refusedBeforeTopologyOrListeners": True})
        for kind, bad in [("public-route", dict(CORRECT, ipv4_service_route="8.8.8.0/24")), ("boolean-port", dict(CORRECT, proxy_upstream_port=True))]:
            folder = work / kind
            shutil.copytree(pack / "solution", folder)
            (folder / "case.json").write_text(json.dumps(bad) + "\n")
            output = work / (kind + "-refused-output")
            result, _runtime = run([sys.executable, folder / "main.py", "--output", output], folder)
            assert result["exitCode"] == 2 and not output.exists()
            refusals.append({"kind": kind, "result": result, "refusedBeforeOutputOrTopology": True})
        for role, folder in [("starter", pack / "starter"), ("solution", pack / "solution"), ("completed", completed)]:
            for alternate in [False, True]:
                label = role + ("-alternate" if alternate else "-default")
                output = work / label
                argv = [sys.executable, folder / "main.py", "--output", output] + (["--alternate"] if alternate else [])
                result, _runtime = run(argv, folder)
                if role == "starter":
                    parent, lab, _commands = cleanup_evidence(output)
                    assert result["exitCode"] == parent["exitCode"] == 1 and not lab["completed"]
                    assert lab["routeGet4"]["exitCode"] != 0 and lab["http4"]["status"] == "000"
                    assert lab["dns"]["A"]["stdout"].strip() == "198.18.32.2"
                    assert lab["http6"]["status"] == lab["missingPath"]["status"] == "502"
                    unfinished.append({"role": role, "alternate": alternate, "result": result, "firstIPv4Failure": "route", "firstIPv6Failure": "proxy-upstream"})
                else:
                    assert result["exitCode"] == 0, result
                    accepted.append(dict(completed_evidence(output, alternate), role=role, result=result))
        partial = work / "route-only"
        shutil.copytree(pack / "starter", partial)
        (partial / "case.json").write_text(json.dumps(dict(CORRECT, proxy_upstream_port=9001)) + "\n")
        output = work / "route-only-output"
        result, _runtime = run([sys.executable, partial / "main.py", "--output", output], partial)
        parent, lab, _commands = cleanup_evidence(output)
        assert result["exitCode"] == 1 and lab["routeGet4"]["exitCode"] == 0
        assert lab["dns4"]["stdout"].strip() == "198.18.32.2" and lab["http4"]["status"] == lab["http6"]["status"] == "502"
        partial_evidence = {"result": result, "routeCorrectedIndependently": True, "remainingFailure": "proxy-upstream"}
        helper = (pack / "solution/capstone_lab.py").read_text()
        changes = {
            "public-upstream": ('(("127.0.0.1", 9000), Application)', '(("0.0.0.0", 9000), Application)'),
            "open-denial-control": ('[("udp", 15353), ("tcp", port)]', '[("udp", 15353), ("tcp", port), ("tcp", 8088)]'),
            "wrong-aaaa-answer": ('"--address=/" + name + "/" + s6', '"--address=/" + name + "/2001:db8:32::99"'),
        }
        for kind, (old, new) in changes.items():
            assert helper.count(old) == 1, kind
            folder = work / kind
            shutil.copytree(pack / "solution", folder)
            (folder / "capstone_lab.py").write_text(helper.replace(old, new))
            output = work / (kind + "-output")
            result, _runtime = run([sys.executable, folder / "main.py", "--output", output], folder)
            _parent, lab, _commands = cleanup_evidence(output)
            assert result["exitCode"] == 1
            try:
                completed_evidence(output, False)
            except AssertionError:
                rejected = True
            else:
                rejected = False
            assert rejected
            if kind == "public-upstream":
                assert "0.0.0.0:9000" in lab["listeners"]["stdout"] and lab["http4"]["status"] == "200"
            elif kind == "open-denial-control":
                assert lab["denied4"]["status"] == lab["denied6"]["status"] == "200"
            else:
                assert lab["dns"]["AAAA"]["stdout"].strip() == "2001:db8:32::99"
                assert lab["resolvedDestinations"]["AAAA"] == "2001:db8:32::99" and lab["http6"]["status"] == "000"
            regressions.append({"kind": kind, "result": result, "independentlyRejected": rejected})
        output = work / "interrupted-output"
        result, runtime = run([sys.executable, pack / "solution/main.py", "--hold-after-ready", "15", "--output", output], pack / "solution", interrupted_output=output)
        parent, lab, _commands = cleanup_evidence(output)
        assert result["exitCode"] == 130 and parent["cancelled"] and lab["interrupted"]
        assert runtime and all(not Path("/proc/" + str(row["pid"])).exists() for row in runtime["workers"])
        interruptions.append({"result": result, "actualLiveIsolation": runtime, "allWorkersReaped": True})
        assert hashes(completed) == completed_hashes
    assert before == hashes(pack) and not Path(temporary).exists()
    proof = {"event": "verified-network-operations-capstone", "acceptedProfiles": accepted,
             "unfinishedProfilesRejected": unfinished, "routeOnlyCorrection": partial_evidence,
             "controlledRegressions": regressions, "interruptions": interruptions,
             "refusals": refusals,
             "sourceFileHashes": before, "completedSourceFileHashes": completed_hashes,
             "independentCompletionOnly": "case.json", "sourceUnchanged": True,
             "temporaryBuildCleanup": True, "notebookCompletionNotInferred": True,
             "evidenceFiles": hashes(retained)}
    write = json.dumps(proof, indent=2) + "\n"
    args.proof.write_text(write)
    args.proof.with_suffix(".processes.jsonl").write_text("".join(json.dumps(row) + "\n" for row in PROCESSES))
    print(json.dumps({"acceptedProfiles": len(accepted), "unfinishedProfilesRejected": len(unfinished),
                      "controlledRegressionsRejected": len(regressions), "actualInterruptions": len(interruptions),
                      "retainedAttempts": len(list(retained.iterdir())), "sourceUnchanged": True,
                      "nativeCases": "actual dual-stack routing, DNS, HTTP, policy and PCAP observations"}))


if __name__ == "__main__":
    main()
