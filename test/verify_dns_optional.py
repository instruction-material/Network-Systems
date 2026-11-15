"""Verify actual optional DNS role runs against independent DNS wire evidence."""
from __future__ import annotations
import argparse
import ast
import base64
import datetime
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
PACKS = ["NS-11-unit-5-dns-and-name-resolution-supplemental-2",
         "NS-12-unit-5-dns-and-name-resolution-supplemental-3"]
def stamp():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()
def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
def name_at(data, offset, seen=None):
    seen = set() if seen is None else seen
    labels = []
    next_offset = None
    while True:
        if offset >= len(data) or offset in seen:
            raise ValueError("invalid compressed DNS name")
        seen.add(offset)
        length = data[offset]
        offset += 1
        if length & 0xc0 == 0xc0:
            if offset >= len(data):
                raise ValueError("incomplete DNS pointer")
            target = ((length & 0x3f) << 8) | data[offset]
            tail, _ = name_at(data, target, seen)
            labels.append(tail.rstrip("."))
            next_offset = offset + 1
            break
        if length & 0xc0 or length > 63 or offset + length > len(data):
            raise ValueError("invalid DNS label")
        if not length:
            next_offset = offset
            break
        labels.append(data[offset:offset + length].decode("ascii").lower())
        offset += length
    return ".".join(labels) + ".", next_offset

def decode_dns(data):
    if len(data) < 12:
        raise ValueError("short DNS packet")
    ident, flags, qd, an, _, _ = struct.unpack("!6H", data[:12])
    if qd != 1 or an > 30:
        raise ValueError("outside the owned single-question fixture")
    question, pos = name_at(data, 12)
    if not question.endswith(".course.test."):
        raise ValueError("outside fixture names")
    kind, klass = struct.unpack("!HH", data[pos:pos + 4])
    if klass != 1 or kind not in [1, 28]:
        raise ValueError("outside fixture types")
    pos += 4
    records = []
    for _ in range(an):
        owner, pos = name_at(data, pos)
        rrtype, rrclass, ttl, size = struct.unpack("!HHIH", data[pos:pos + 10])
        pos += 10
        value = data[pos:pos + size]
        if rrclass != 1 or len(value) != size:
            raise ValueError("invalid fixture record")
        if rrtype == 1:
            value = str(ipaddress.IPv4Address(value))
        elif rrtype == 28:
            value = str(ipaddress.IPv6Address(value))
        elif rrtype == 5:
            value, _ = name_at(data, pos)
        else:
            raise ValueError("unexpected fixture answer type")
        records.append({"owner": owner, "ttl": ttl,
                        "type": {1: "A", 28: "AAAA", 5: "CNAME"}[rrtype], "data": value})
        pos += size
    return {"id": ident, "question": question.rstrip("."),
            "type": {1: "A", 28: "AAAA"}[kind], "response": bool(flags & 0x8000),
            "rcode": flags & 15, "records": records,
            "wireBase64": base64.b64encode(data).decode(),
            "wireSHA256": hashlib.sha256(data).hexdigest()}

def trace_packets(path):
    packets = []
    for line in path.read_text().splitlines():
        if not any(call in line for call in ["sendto(", "recvfrom(", "sendmsg(",
                                             "recvmsg(", "sendmmsg(", "recvmmsg("]):
            continue
        for encoded in re.findall(r'"((?:\\x[0-9a-f]{2})+)"', line):
            raw = bytes.fromhex(encoded.replace("\\x", ""))
            try:
                packets.append(decode_dns(raw))
            except (ValueError, UnicodeError, struct.error):
                continue
    return packets

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--proof", type=Path, required=True)
    args = parser.parse_args()
    output = args.proof.parent / "dns-optional-raw"
    output.mkdir(parents=True, exist_ok=False)
    proof = {"at": stamp(), "accepted": False, "profiles": [], "processes": [],
             "independentWireComparisons": 0, "reports": [], "sourceFiles": {}}
    for pack in PACKS:
        for path in sorted((ROOT / pack).rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts:
                proof["sourceFiles"][str(path.relative_to(ROOT))] = digest(path)

    def command(argv, cwd, label, timeout=12):
        started = stamp()
        process = subprocess.Popen(argv, cwd=cwd, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, start_new_session=True,
                                   env={**os.environ, "LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1"})
        cleanup = "owned process group exited and was reaped"
        try:
            out, err = process.communicate(timeout=timeout)
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.communicate(timeout=1)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate()
            cleanup = "owned process group terminated and reaped"
            raise
        finally:
            proof["processes"].append({"parentTask": "optional-dns-native",
                                      "parentPID": os.getpid(), "pid": process.pid,
                                      "cwd": str(cwd), "command": argv, "startedAt": started,
                                      "endedAt": stamp(), "exitCode": process.returncode,
                                      "timeoutSeconds": timeout, "cleanup": cleanup})
        (output / (label + ".stdout")).write_bytes(out)
        (output / (label + ".stderr")).write_bytes(err)
        return process.returncode, out, err

    def run_role(folder, label, phase, port, expected):
        report = output / (label + ".json")
        trace = output / (label + ".strace")
        argv = ["strace", "-f", "-qq", "-s", "4096", "-xx", "-e", "trace=process,network",
                "-o", str(trace), sys.executable, "main.py", "--port", str(port),
                "--phase", phase, "--output", str(report)]
        code, _, err = command(argv, folder, label)
        assert code == expected, (label, code, err.decode())
        data = json.loads(report.read_text())
        assert data["context"]["uid"] == os.geteuid() and len(data["observations"]) == 2
        assert data["notebookCompletionInferred"] is False
        packets = trace_packets(trace)
        comparisons = 0
        for row in data["observations"]:
            question = [p for p in packets if not p["response"] and
                        p["question"] == row["question"] and p["type"] == row["type"]]
            assert question, (label, "missing actual query", row["type"])
            assert row["process"]["pid"] > 0 and row["process"]["timeoutSeconds"] == 4
            responses = [p for p in packets if p["response"] and
                         p["question"] == row["question"] and p["type"] == row["type"]]
            if phase == "live":
                assert responses, (label, "missing actual response", row["type"])
                assert any(p["records"] == row["records"] and
                           {0: "NOERROR", 3: "NXDOMAIN"}.get(p["rcode"]) == row["dnsStatus"]
                           for p in responses), (label, "wire/report mismatch")
                comparisons += 1
            else:
                assert not responses and row["classification"] == "transport_failure"
                assert row["process"]["exitCode"] == 9
        proof["independentWireComparisons"] += comparisons
        proof["reports"].append({"label": label, "report": str(report), "trace": str(trace),
                                 "wirePackets": packets, "reportSHA256": digest(report)})
        proof["profiles"].append({"label": label, "phase": phase, "exitCode": code,
                                  "goalMet": data["goalMet"]})
        return data

    resolver = None
    reserve = None
    logs = None
    temporary = None
    try:
        assert sys.platform == "linux" and os.geteuid() != 0
        for tool in ["dnsmasq", "dig", "strace"]:
            assert shutil.which(tool), tool
        temporary = tempfile.TemporaryDirectory(prefix="network-optional-dns-")
        sandbox = Path(temporary.name)
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()
        argv = ["dnsmasq", "--no-daemon", "--conf-file=/dev/null", "--no-hosts", "--no-resolv",
                "--log-queries", "--log-facility=-", "--listen-address=127.0.0.1",
                "--bind-interfaces", "--port=" + str(port), "--local=/course.test/",
                "--host-record=dual.course.test,127.0.0.8,::1",
                "--host-record=v4.course.test,127.0.0.9",
                "--cname=alias.course.test,dual.course.test"]
        logs = (output / "owned-resolver.log").open("wb")
        started = stamp()
        resolver = subprocess.Popen(argv, stdout=logs, stderr=logs, start_new_session=True)
        time.sleep(0.3)
        assert resolver.poll() is None
        identity = Path("/proc/" + str(resolver.pid) + "/status").read_text()
        assert int(re.search(r"^Uid:\s+(\d+)", identity, re.M).group(1)) == os.geteuid()
        proof["resolver"] = {"pid": resolver.pid, "uid": os.geteuid(), "port": port,
                             "command": argv, "startedAt": started}
        for role, expected in [("starter", 78), ("solution", 0)]:
            run_role(ROOT / PACKS[0] / role, "alias-" + role, "live", port, expected)
        corrected = sandbox / "alias-corrected"
        shutil.copytree(ROOT / PACKS[0] / "starter", corrected)
        original_runtime = digest(corrected / "dns_probe.py")
        (corrected / "case.json").write_text(json.dumps({"question": "alias.course.test"}))
        run_role(corrected, "alias-one-field-correction", "live", port, 0)
        assert digest(corrected / "dns_probe.py") == original_runtime
        (corrected / "case.json").write_text(json.dumps({"question": "dual.course.test"}))
        run_role(corrected, "alias-direct-name-control", "live", port, 78)
        for role in ["starter", "solution"]:
            run_role(ROOT / PACKS[1] / role, "negative-" + role, "live", port, 0)
        resolver.terminate()
        resolver.wait(timeout=3)
        proof["resolver"].update(endedAt=stamp(), exitCode=resolver.returncode,
                                  reaped=True, pidAbsent=not Path("/proc/" + str(resolver.pid)).exists())
        assert proof["resolver"]["pidAbsent"]
        # Own the old UDP port without responding, preventing another resolver from racing the test.
        reserve = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        reserve.bind(("127.0.0.1", port))
        proof["stoppedPortBoundary"] = "Original resolver reaped; inspector reserves UDP port and sends no DNS response"
        for role, expected in [("starter", 78), ("solution", 0)]:
            run_role(ROOT / PACKS[1] / role, "stopped-" + role, "stopped", port, expected)
        corrected2 = sandbox / "transport-corrected"
        shutil.copytree(ROOT / PACKS[1] / "starter", corrected2)
        (corrected2 / "case.json").write_text(json.dumps({"stoppedClaim": "transport_failure"}))
        run_role(corrected2, "transport-one-field-correction", "stopped", port, 0)

        original = (output / "alias-solution.json").read_bytes()
        argv = [sys.executable, "main.py", "--port", str(port), "--output",
                str(output / "alias-solution.json")]
        code, _, _ = command(argv, ROOT / PACKS[0] / "solution", "existing-report-refusal")
        assert code == 2 and (output / "alias-solution.json").read_bytes() == original
        for option in ["1024", "65536"]:
            report = output / ("invalid-" + option + ".json")
            code, _, _ = command([sys.executable, "main.py", "--port", option, "--output",
                                   str(report)], ROOT / PACKS[0] / "solution",
                                  "invalid-port-" + option)
            assert code == 2 and not report.exists()

        # Interrupt a confirmed live dig child, then verify its actual process was reaped.
        folder = ROOT / PACKS[1] / "solution"
        stdout = (output / "interrupted.stdout").open("wb")
        stderr = (output / "interrupted.stderr").open("wb")
        child = subprocess.Popen([sys.executable, "main.py", "--port", str(port),
                                  "--phase", "stopped", "--output",
                                  str(output / "interrupted.json")],
                                 cwd=folder, stdout=stdout, stderr=stderr,
                                 start_new_session=True)
        started = stamp()
        dig_pid = None
        try:
            deadline = time.monotonic() + 3
            children_path = Path("/proc/" + str(child.pid) + "/task/" + str(child.pid) + "/children")
            while time.monotonic() < deadline:
                children = children_path.read_text().split() if children_path.exists() else []
                if children:
                    dig_pid = int(children[0])
                    break
                time.sleep(0.01)
            assert dig_pid and Path("/proc/" + str(dig_pid) + "/comm").read_text().strip() == "dig"
            child.terminate()
            assert child.wait(timeout=4) == 2
            assert not Path("/proc/" + str(dig_pid)).exists()
            proof["actualInterruption"] = {"parentPID": child.pid, "digPID": dig_pid,
                                           "liveChildConfirmed": True, "childReaped": True,
                                           "startedAt": started, "endedAt": stamp(),
                                           "timeoutSeconds": 4, "exitCode": child.returncode}
        finally:
            for pid in [dig_pid, child.pid]:
                if pid and Path("/proc/" + str(pid)).exists():
                    try:
                        os.killpg(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
            child.wait(timeout=2)
            stdout.close()
            stderr.close()
        assert proof["independentWireComparisons"] == 12
        assert len(proof["profiles"]) == 9
        proof["accepted"] = True
    finally:
        if resolver is not None and resolver.poll() is None:
            os.killpg(resolver.pid, signal.SIGTERM)
            resolver.wait(timeout=3)
        if reserve:
            reserve.close()
        if logs:
            logs.close()
        if temporary:
            temporary.cleanup()
        proof["endedAt"] = stamp()
        args.proof.parent.mkdir(parents=True, exist_ok=True)
        args.proof.write_text(json.dumps(proof, indent=2) + "\n")
    print(json.dumps({"accepted": proof["accepted"], "profiles": len(proof["profiles"]),
                      "independentWireComparisons": proof["independentWireComparisons"]}))
if __name__ == "__main__":
    main()
