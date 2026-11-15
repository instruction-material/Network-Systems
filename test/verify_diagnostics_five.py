"""Inspect actual owned diagnostics and retain syscall and raw response evidence."""
import argparse
import base64
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
CASES = json.loads((ROOT / "test/network_diagnostics_five_cases.json").read_text())
LABELS = ["TCP listener state on this machine", "Interface summary on this machine",
          "IPv4 routes on this machine", "IPv6 routes on this machine",
          "Loopback HTTP observation on this machine", "Target HTTP observation from this machine",
          "Target TCP observation from this machine"]


def now():
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def source_checks(exported=False):
    hashes = {}
    for definition in CASES["definitions"]:
        pack = ROOT / definition["pack"]
        assert definition["title"] in (pack / "README.md").read_text()
        for role in ["starter", "solution"]:
            folder = pack / role
            assert "normalize_ports" not in (folder / "main.py").read_text()
            assert digest((folder / "main.py").read_bytes()) == CASES["launcherSHA256"]
            assert digest((folder / "diagnostics_lab.py").read_bytes()) == CASES["runtimeSHA256"]
            assert digest((folder / "diagnose_reachability.sh").read_bytes()) == CASES["collectorSHA256"]
            assert json.loads((folder / "case.json").read_text()) == definition["starterCase" if role == "starter" else "referenceCase"]
            for name in definition["roleFiles"] + ([] if exported else ["README.md"]):
                hashes[definition["pack"] + "/" + role + "/" + name] = digest((folder / name).read_bytes())
        hashes[definition["pack"] + "/README.md"] = digest((pack / "README.md").read_bytes())
    assert len(hashes) == (55 if exported else 65)
    return hashes


def command(argv, cwd, records, ready=None, cancellation=None):
    child = subprocess.Popen([str(x) for x in argv], cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             start_new_session=True, env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
    start = now()
    stdout, stderr = b"", b""
    cleanup = "process and owned children completed"
    live = None
    try:
        if ready:
            deadline = time.monotonic() + 8
            while not ready.exists() and child.poll() is None and time.monotonic() < deadline:
                time.sleep(0.02)
            assert ready.exists(), "live owned worker never became ready"
            data = json.loads(ready.read_text())
            with socket.create_connection((data["host"], data["servicePort"]), timeout=1) as client:
                client.sendall(b"HEAD / HTTP/1.1\r\nHost: live-owned.invalid\r\nConnection: close\r\n\r\n")
                wire = bytearray()
                while b"\r\n\r\n" not in wire:
                    block = client.recv(1024)
                    assert block
                    wire.extend(block)
            assert b"200 OK" in wire and data["token"].encode() in wire
            live = {"ready": data, "wireHex": bytes(wire).hex(), "workerConfirmedLive": True}
            assert os.getpgid(data["controllerPid"]) == child.pid
            os.kill(data["controllerPid"], signal.SIGTERM)
        stdout, stderr = child.communicate(timeout=35)
    except BaseException:
        cleanup = "owned validation process group terminated and reaped"
        with contextlib.suppress(ProcessLookupError):
            os.killpg(child.pid, signal.SIGTERM)
        try:
            stdout, stderr = child.communicate(timeout=7)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(child.pid, signal.SIGKILL)
            stdout, stderr = child.communicate(timeout=3)
        raise
    finally:
        row = {"command": [str(x) for x in argv], "cwd": str(cwd), "pid": child.pid,
               "parentPid": os.getpid(), "startTime": start, "endTime": now(),
               "exitCode": child.returncode, "timeoutSeconds": 35,
               "childProcessGroupCleanup": cleanup, "stdout": stdout.decode(), "stderr": stderr.decode()}
        if live:
            row["liveInterruption"] = live
        records.append(row)
    return row


def stable(raw, reference):
    addresses = []
    for link in raw["addresses"]:
        value = {key: link.get(key) for key in ["ifindex", "ifname", "mtu", "operstate", "flags"]}
        value["addr_info"] = [{key: row.get(key) for key in ["family", "local", "prefixlen", "scope", "label"]}
                              for row in link.get("addr_info", [])]
        addresses.append(value)
    routes = [{key: row.get(key) for key in ["dst", "gateway", "dev", "protocol", "scope", "prefsrc",
                                            "metric", "type", "table", "pref"]} for row in raw["routes"]]
    return {**{key: reference[key] for key in ["uid", "cwd", "networkNamespace"]},
            "addresses": addresses, "routes": routes}


def check_report(data, definition, corrected, mode="normal"):
    assert data["startedAt"] <= data["endedAt"]
    assert data["hostUnchanged"] and data["hostBefore"] == data["hostAfter"]
    assert data["hostBefore"] == stable(data["rawHostBefore"], data["hostBefore"])
    assert data["hostAfter"] == stable(data["rawHostAfter"], data["hostBefore"])
    assert data["hostBefore"]["uid"] > 0 and data["sourceUnchanged"]
    assert data["notebookCompletionInferred"] is False and data["temporaryWorkspaceRemoved"]
    ready, worker = data["ready"], data["worker"]
    process = data["workerProcess"]
    assert ready["pid"] == worker["pid"] == process["pid"] and process["exitCode"] == 0
    assert ready["uid"] == worker["uid"] == data["hostBefore"]["uid"]
    assert ready["networkNamespace"] == worker["networkNamespace"] == data["hostBefore"]["networkNamespace"]
    assert ready["host"] == "127.0.0.1" and ready["reservedAddress"] == "127.0.0.2"
    assert ready["servicePort"] != ready["reservedPort"]
    assert worker["socketClosed"] and worker["allReservationsClosed"] and worker["stopped"]
    try:
        os.kill(worker["pid"], 0)
    except ProcessLookupError:
        pass
    else:
        raise AssertionError("owned worker remains live")
    for row in data["commands"] + [process]:
        assert row["exitCode"] is not None and row["pid"] > 0 and row["parentPid"] > 0
        assert row["startTime"] <= row["endTime"] and row["timeoutSeconds"] > 0
    if mode != "normal":
        assert not data["complete"]
        expected = "lab interrupted; owned processes are being closed" if mode == "hold" else "intentional failure after owned listener setup"
        assert data["error"] == expected
        assert "diagnostic" not in data
        return
    assert "error" not in data and "cleanupError" not in data
    case = definition["referenceCase" if corrected else "starterCase"]
    assert data["case"] == ready["case"] == worker["case"] == case
    target_host = ready["host"] if case["targetAddress"] == "owned" else ready["reservedAddress"]
    target_port = ready["servicePort"] if case["targetPort"] == "owned" else ready["reservedPort"]
    assert data["selectedTarget"] == {"address": target_host, "port": target_port, "scheme": case["scheme"]}
    result = data["diagnostic"]
    assert result["exitCode"] == 0
    parts = re.split(r"^== (.+) ==\n", result["stdout"], flags=re.M)
    independent = {}
    for i in range(1, len(parts), 2):
        values = re.findall(r"^command status: (\d+)$", parts[i + 1], re.M)
        assert len(values) == 1
        independent[parts[i]] = int(values[0])
        assert data["sections"][parts[i]] == {"exitCode": int(values[0]), "raw": parts[i + 1]}
    assert list(independent) == LABELS
    expected = dict.fromkeys(LABELS, 0)
    kind = definition["kind"]
    if not corrected:
        if kind in ["protocol", "deadline", "port"]:
            expected[LABELS[4]] = expected[LABELS[5]] = {"protocol": 35, "deadline": 28, "port": 7}[kind]
        elif kind == "address":
            expected[LABELS[5]] = 7
        if kind in ["port", "address"]:
            expected[LABELS[6]] = 1
    assert independent == expected, (kind, corrected, independent)
    assert "not a second-machine test" in result["stdout"]
    assert "Target: " + case["scheme"] + "://" + target_host + ":" + str(target_port) + "/" in result["stdout"]
    assert "command: nc -nvz -w 3 " + target_host + " " + str(target_port) in result["stdout"]
    wire = bytes.fromhex(data["control"]["receivedHex"])
    assert bytes.fromhex(data["control"]["requestHex"]) == b"HEAD / HTTP/1.1\r\nHost: owned-lab.invalid\r\nConnection: close\r\n\r\n"
    assert data["control"]["peer"] == [ready["host"], ready["servicePort"]]
    assert data["control"]["socketClosed"]
    if case["responseMode"] == "silent":
        assert data["control"]["timedOut"] and not wire
    else:
        assert not data["control"]["timedOut"] and wire.startswith(b"HTTP/1.1 " + str(case["httpStatus"]).encode() + b" ")
        assert b"X-Owned-Diagnostics: " + ready["token"].encode() + b"\r\n" in wire and wire.endswith(b"\r\n\r\n")
    http = data["sections"][LABELS[5]]["raw"]
    statuses = re.findall(r"^HTTP/\S+ (\d{3})\b", http, re.M)
    status = int(statuses[-1]) if statuses else None
    assert data["targetHTTPStatus"] == status
    assert data["targetTokenObserved"] == ("X-Owned-Diagnostics: " + ready["token"] in http)
    actual_complete = independent[LABELS[5]] == independent[LABELS[6]] == 0 and status == 200 and data["targetTokenObserved"]
    assert data["complete"] is actual_complete is corrected
    expected_requests = 3 if corrected or kind in ["deadline", "status"] else 2 if kind == "address" else 1
    assert len(worker["requests"]) == expected_requests, (kind, worker["requests"])
    for row in worker["requests"]:
        assert row["method"] == "HEAD" and row["path"] == "/" and row["peer"][0] == "127.0.0.1"
        assert base64.b64decode(row["requestLineBase64"], validate=True).startswith(b"HEAD / HTTP/1.1\r\n")
    if kind == "protocol" and not corrected:
        assert len(worker["protocolErrors"]) == 2
        assert all(base64.b64decode(row["requestLineBase64"], validate=True).startswith(bytes([22]))
                   and row["status"] == 400 for row in worker["protocolErrors"])
    else:
        assert not worker["protocolErrors"]


def check_trace(text, data=None, no_network=False):
    assert text and ("exited with" in text or "killed by" in text)
    if no_network:
        assert 'socket(AF_INET' not in text and 'bind(' not in text and 'connect(' not in text
        return
    assert 'bind(' in text and 'listen(' in text and 'connect(' in text
    addresses = re.findall(r'connect\([^\n]*sin_addr=inet_addr\("([^"]+)"\)', text)
    assert addresses and set(addresses) <= {"127.0.0.1", "127.0.0.2"}, addresses
    assert 'sin_port=htons(53)' not in text
    if data:
        assert 'htons(' + str(data["ready"]["servicePort"]) + ')' in text


def run_profile(folder, definition, corrected, alternate, mode, raw, processes, profile):
    report_path = raw / (profile + ".json")
    trace_path = raw / (profile + ".syscalls.txt")
    ready = raw / (profile + ".ready.json") if mode == "hold" else None
    argv = ["strace", "-f", "-yy", "-s", "4096", "-e", "trace=network,close,process",
            "-o", trace_path, sys.executable, "-B", folder / "main.py", "--report", report_path,
            "--test-mode", mode]
    if alternate:
        argv.append("--alternate")
    if ready:
        argv += ["--ready-file", ready]
    result = command(argv, folder, processes, ready)
    assert result["exitCode"] == (0 if mode == "normal" else 2), result
    data = json.loads(report_path.read_text())
    check_report(data, definition, corrected, mode)
    check_trace(trace_path.read_text(), data)
    return {"profile": profile, "pack": definition["pack"], "kind": definition["kind"],
            "corrected": corrected, "alternate": alternate, "mode": mode, "result": result,
            "report": report_path.name, "reportSHA256": digest(report_path.read_bytes()),
            "trace": trace_path.name, "traceSHA256": digest(trace_path.read_bytes()), "evidence": data}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proof", type=Path, required=True)
    parser.add_argument("--source-only", action="store_true")
    parser.add_argument("--exported-source", action="store_true")
    args = parser.parse_args()
    proof = {"at": now(), "accepted": False, "runs": [], "processes": [], "refusals": []}
    args.proof = args.proof.resolve()
    args.proof.parent.mkdir(parents=True, exist_ok=True)
    raw = args.proof.parent / "diagnostics-five-raw"
    try:
        proof["sourceFiles"] = source_checks(args.exported_source)
        if args.source_only:
            proof.update(sourceOnlyVerified=True, nativeAccepted=False)
            return
        raw.mkdir(exist_ok=False)
        assert sys.platform == "linux" and os.getuid() > 0 and shutil.which("strace")
        with tempfile.TemporaryDirectory(prefix="diagnostics-five-independent-") as temporary:
            temporary = Path(temporary)
            for definition in CASES["definitions"]:
                original = ROOT / definition["pack"]
                completed = temporary / (definition["kind"] + " completed quoted")
                shutil.copytree(original / "starter", completed)
                (completed / "case.json").write_bytes((original / "solution/case.json").read_bytes())
                for role, folder in [("starter", original / "starter"), ("solution", original / "solution"), ("completed", completed)]:
                    for alternate in [False, True]:
                        profile = definition["kind"] + "-" + role + ("-alternate" if alternate else "-default")
                        proof["runs"].append(run_profile(folder, definition, role != "starter", alternate,
                                                         "normal", raw, proof["processes"], profile))
            definition = CASES["definitions"][0]
            folder = ROOT / definition["pack"] / "solution"
            for mode in ["failure", "hold"]:
                proof["runs"].append(run_profile(folder, definition, True, False, mode, raw,
                                                 proof["processes"], "owned-" + mode))
            invalid = temporary / "invalid-case.json"
            for label, payload in [("unknown", {"unknown": "choice"}), ("wrong-type", {**definition["referenceCase"], "httpStatus": True})]:
                invalid.write_text(json.dumps(payload))
                report = raw / (label + ".json")
                trace = raw / (label + ".syscalls.txt")
                result = command(["strace", "-f", "-s", "4096", "-e", "trace=network,close,process", "-o", trace,
                                  sys.executable, "-B", folder / "main.py", "--case", invalid, "--report", report],
                                 folder, proof["processes"])
                assert result["exitCode"] == 2 and not report.exists()
                check_trace(trace.read_text(), no_network=True)
                proof["refusals"].append({"kind": label, "result": result, "trace": trace.name})
            report = raw / "preserved-report.json";report.write_text("retained original\n")
            trace = raw / "preserved-report.syscalls.txt"
            result = command(["strace", "-f", "-s", "4096", "-e", "trace=network,close,process", "-o", trace,
                              sys.executable, "-B", folder / "main.py", "--report", report], folder, proof["processes"])
            assert result["exitCode"] == 2 and report.read_text() == "retained original\n"
            check_trace(trace.read_text(), no_network=True)
            proof["refusals"].append({"kind": "preserved-report", "result": result, "trace": trace.name})
        assert proof["sourceFiles"] == source_checks(args.exported_source)
        assert len(proof["runs"]) == 32 and len(proof["refusals"]) == 3
        proof.update(accepted=True, actualProfiles=32, normalRoleProfiles=30, liveInterruptedWorkerVerified=True,
                     allOwnedProcessesAndSocketsClosed=True, allFailedRawObservationsRetained=True,
                     allSourcesUnchanged=True, temporaryValidationTreeRemoved=not temporary.exists())
    finally:
        proof["endedAt"] = now()
        args.proof.write_text(json.dumps(proof, indent=2) + "\n")
    print(json.dumps({key: value for key, value in proof.items() if key not in ["sourceFiles", "runs", "processes", "refusals"]}))


if __name__ == "__main__":
    main()
