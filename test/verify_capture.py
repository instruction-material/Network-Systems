"""Check actual owned HTTP packet bytes, selection and cleanup on Linux."""
import argparse
import ast
import base64
import contextlib
import datetime
import hashlib
import json
import os
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

PACK = "NS5-Tcpdump-HTTP-Capture"
FILES = ("capture_http.sh", "capture-options.sh", "capture_runtime.py", "network-notes.md", "README.md")


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def run(argv, ledger, ready=None):
    started = now()
    process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               start_new_session=True)
    cleanup = "exited and reaped"
    try:
        if ready:
            deadline = time.monotonic() + 8
            while not ready.exists() and process.poll() is None and time.monotonic() < deadline:
                time.sleep(0.03)
            assert ready.exists(), "capture never reached actual readiness"
            process.send_signal(signal.SIGTERM)
        stdout, stderr = process.communicate(timeout=35)
    except BaseException:
        cleanup = "terminated and reaped owned process group"
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGTERM)
        try:
            process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate(timeout=3)
        raise
    finally:
        ledger.append({"task": "NS5-native-capture-acceptance", "cwd": str(Path.cwd()),
                       "command": argv, "parentPid": os.getpid(), "pid": process.pid,
                       "startTime": started, "endTime": now(), "exitCode": process.returncode,
                       "timeoutSeconds": 35, "childProcessGroupCleanup": cleanup})
    return process.returncode, stdout.decode(), stderr.decode()


def wire_packets(raw):
    assert len(raw) >= 24
    byte_order = "<" if raw[:4] in (bytes.fromhex("d4c3b2a1"), bytes.fromhex("4d3cb2a1")) else ">"
    assert raw[:4] in [bytes.fromhex(x) for x in ("d4c3b2a1", "a1b2c3d4", "4d3cb2a1", "a1b23c4d")]
    assert struct.unpack(byte_order + "I", raw[20:24])[0] == 1
    frames = []
    cursor = 24
    while cursor < len(raw):
        stamp, fraction, length, original = struct.unpack_from(byte_order + "4I", raw, cursor)
        cursor += 16
        frame = raw[cursor:cursor + length]
        assert len(frame) == length <= original <= 65536
        cursor += length
        assert frame[12:14] == bytes.fromhex("0800")
        ip = frame[14:]
        assert ip[0] >> 4 == 4 and ip[9] == 6
        ip_length = struct.unpack_from("!H", ip, 2)[0]
        assert len(ip) >= ip_length
        segment = ip[4 * (ip[0] & 15):ip_length]
        sport, dport, seq, ack = struct.unpack_from("!HHII", segment)
        header_length = (segment[12] >> 4) * 4
        assert 20 <= header_length <= len(segment)
        frames.append({"seconds": stamp, "fraction": fraction,
                       "source": socket.inet_ntoa(ip[12:16]), "destination": socket.inet_ntoa(ip[16:20]),
                       "sourcePort": sport, "destinationPort": dport, "sequence": seq,
                       "acknowledgement": ack, "flags": segment[13],
                       "payloadBase64": base64.b64encode(segment[header_length:]).decode()})
    assert cursor == len(raw)
    return frames


def check_run(data, complete, mode, reverse):
    assert data["hostUnchanged"] and data["hostBefore"] == data["hostAfter"]
    lab = data["lab"]
    assert lab["networkNamespace"] != data["hostBefore"]["networkNamespace"]
    assert lab["workerReady"]["networkNamespace"] == lab["networkNamespace"]
    assert lab["workerReady"]["token"] == data["token"] and lab["workerReady"]["ports"] == [8080, 8081]
    assert lab["cleanup"]["workerReaped"] and lab["cleanup"]["captureReaped"]
    assert [row["ifname"] for row in lab["cleanup"]["remainingLinks"]] == ["lo"]
    for child in (lab["worker"], lab["capture"]):
        assert child["reaped"] and child["pid"] > 0 and child["exitCode"] is not None
        try:
            os.kill(child["pid"], 0)
        except ProcessLookupError:
            pass
        else:
            raise AssertionError("an owned capture or HTTP worker remains alive")
    for row in data["commands"] + lab["commands"]:
        assert row["pid"] > 0 and row["parentPid"] > 0 and row["exitCode"] is not None
        assert row["endTime"] >= row["startTime"] and row["timeoutSeconds"] in (5, 20)
    raw = base64.b64decode(lab["pcapBase64"], validate=True)
    assert hashlib.sha256(raw).hexdigest() == lab["pcapSha256"]
    frames = wire_packets(raw)
    assert frames == lab["packets"]
    assert all(row["source"] == row["destination"] == "127.0.0.1" for row in frames)
    captured = re.search(r"(\d+) packets captured", lab["capture"]["stderr"])
    assert captured and int(captured[1]) == len(frames)
    capture = next(row for row in lab["commands"] if row["pid"] == lab["capture"]["pid"])
    argv = capture["command"]
    assert argv[:2] == ["tcpdump", "--immediate-mode"] and argv[argv.index("-i") + 1] == "lo"
    assert argv[-1] == "tcp and host 127.0.0.1" + (" and port 8080" if complete else "")
    assert "-nn" in argv and (("-c" in argv) is complete)
    if complete:
        assert argv[argv.index("-c") + 1] == "64"
    if mode == "hold":
        assert not lab["requests"] and not data["complete"] and "signal" in lab["error"]
        return len(frames), 0
    assert len(lab["requests"]) == 3
    assert [row["peer"][1] for row in lab["requests"]] == ([8080, 8081, 8081] if reverse else [8081, 8080, 8081])
    target = next(row for row in lab["requests"] if row["peer"][1] == 8080)
    source_port = target["local"][1]
    assert source_port > 1023 and target["local"][0] == target["peer"][0] == "127.0.0.1"
    for row in lab["requests"]:
        assert row["networkNamespace"] == lab["networkNamespace"]
        assert row["body"] == {"token": data["token"], "pid": lab["worker"]["pid"],
                               "port": row["peer"][1], "path": "/capture/" + data["token"]}
        assert base64.b64decode(row["requestBase64"], validate=True).startswith(b"GET /capture/" + data["token"].encode() + b" HTTP/1.1\r\n")
        assert base64.b64decode(row["responseBase64"], validate=True).startswith(b"HTTP/1.1 200 ")
    selected = [row for row in frames if {row["sourcePort"], row["destinationPort"]} == {source_port, 8080}]
    assert selected and any(row["sourcePort"] == source_port and row["flags"] & 0x12 == 2 for row in selected)
    assert any(row["sourcePort"] == 8080 and row["flags"] & 0x12 == 0x12 for row in selected)
    requests = b"".join(base64.b64decode(row["payloadBase64"]) for row in selected if row["destinationPort"] == 8080)
    replies = b"".join(base64.b64decode(row["payloadBase64"]) for row in selected if row["sourcePort"] == 8080)
    assert base64.b64decode(target["requestBase64"]) in requests
    assert b"HTTP/1.1 200 " in replies and data["token"].encode() in replies
    has_noise = any(8081 in (row["sourcePort"], row["destinationPort"]) for row in frames)
    assert has_noise is not complete
    if complete:
        assert "127.0.0.1.8080" in lab["decoded"]["stdout"] and "127.0.0.1.8081" not in lab["decoded"]["stdout"]
    assert data["complete"] is (complete and mode == "normal")
    if mode == "failure":
        assert "controlled failure" in lab["error"]
    else:
        assert "error" not in data and "error" not in lab
    return len(frames), 3


def verify(root, proof, source_only):
    result = {"nativeAccepted": False, "mode": "source-only" if source_only else "owned-linux-packet-capture",
              "sourceHashes": {}, "processes": [], "runs": [], "refusals": []}
    ledger = result["processes"]
    pack = root / PACK
    try:
        for role in ("starter", "solution"):
            for name in FILES:
                path = pack / role / name
                raw = path.read_bytes()
                result["sourceHashes"][str(path.relative_to(root))] = hashlib.sha256(raw).hexdigest()
                assert b"\r" not in raw
                if name.endswith(".py"):
                    ast.parse(raw, filename=str(path), feature_version=(3, 10))
                if name.endswith(".sh"):
                    assert run(["bash", "-n", str(path)], ledger)[0] == 0
                if name != "capture-options.sh":
                    assert raw == (pack / "starter" / name).read_bytes()
        assert (pack / "README.md").read_bytes() == (pack / "starter/README.md").read_bytes()
        result["sourceHashes"][PACK + "/README.md"] = hashlib.sha256((pack / "README.md").read_bytes()).hexdigest()
        if source_only:
            return result
        assert sys.platform == "linux" and os.geteuid() == 0
        frames = requests = 0
        with tempfile.TemporaryDirectory(prefix="ns5-native-check-") as temp:
            for profile, source_role, complete in (("untouched-starter", "starter", False),
                                                   ("completed-starter", "starter", True),
                                                   ("reference", "solution", True)):
                for reverse in (False, True):
                    name = profile + ("-reversed" if reverse else "")
                    work = Path(temp) / (name + " quoted workspace")
                    shutil.copytree(pack / source_role, work)
                    if profile == "completed-starter":
                        shutil.copyfile(pack / "solution/capture-options.sh", work / "capture-options.sh")
                    output = work / "observations.json"
                    argv = ["bash", str(work / "capture_http.sh"), "--output", str(output)] + (["--reverse"] if reverse else [])
                    status, stdout, stderr = run(argv, ledger)
                    assert status == 0, (stdout, stderr, output.read_text() if output.exists() else "no report")
                    data = json.loads(output.read_text())
                    result["runs"].append({"profile": name, "status": status, "stdout": stdout, "stderr": stderr, "evidence": data})
                    observed, sent = check_run(data, complete, "normal", reverse)
                    frames += observed
                    requests += sent
            for mode in ("failure", "hold"):
                work = Path(temp) / (mode + " quoted workspace")
                shutil.copytree(pack / "solution", work)
                output, ready = work / "observations.json", work / "ready"
                argv = ["bash", str(work / "capture_http.sh"), "--output", str(output), "--test-mode", mode]
                if mode == "hold":
                    argv += ["--ready-file", str(ready)]
                status, stdout, stderr = run(argv, ledger, ready if mode == "hold" else None)
                assert status != 0 and output.exists(), (stdout, stderr)
                data = json.loads(output.read_text())
                result["runs"].append({"profile": mode, "status": status, "stdout": stdout, "stderr": stderr, "evidence": data})
                observed, sent = check_run(data, True, mode, False)
                frames += observed
                requests += sent
            sentinel = Path(temp) / "outside"
            sentinel.write_text("outside content remains unchanged\n")
            link = Path(temp) / "output-symlink"
            link.symlink_to(sentinel)
            for name, argv in (
                    ("existing output", ["bash", str(pack / "solution/capture_http.sh"), "--output", str(sentinel)]),
                    ("symlink output", ["bash", str(pack / "solution/capture_http.sh"), "--output", str(link)]),
                    ("missing output parent", ["bash", str(pack / "solution/capture_http.sh"), "--output", str(Path(temp) / "missing/report.json")]),
                    ("direct internal host capture", [sys.executable, str(pack / "solution/capture_runtime.py"), "--inside", "--origin", os.readlink("/proc/self/ns/net")])):
                status, stdout, stderr = run(argv, ledger)
                assert status == 2 and not stdout and stderr
                assert sentinel.read_text() == "outside content remains unchanged\n" and link.is_symlink()
                result["refusals"].append({"case": name, "status": status, "stdout": stdout, "stderr": stderr})
        assert requests == 21 and len(result["runs"]) == 8 and len(result["refusals"]) == 4
        for name, digest in result["sourceHashes"].items():
            assert hashlib.sha256((root / name).read_bytes()).hexdigest() == digest
        result.update(nativeAccepted=True, actualCapturedPackets=frames, actualHttpRequests=requests,
                      captureProfiles=8, actualCaptureProcesses=8, actualHttpWorkers=8,
                      reversedTrafficProfiles=3, controlledFailureAndCancellationCleaned=True,
                      hostNetworkConfigurationPreserved=True, sourceUnchanged=True)
    except BaseException as error:
        result["error"] = str(error)
        raise
    finally:
        proof.parent.mkdir(parents=True, exist_ok=True)
        proof.write_text(json.dumps(result, indent=2) + "\n")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--proof", type=Path, required=True)
    parser.add_argument("--source-only", action="store_true")
    args = parser.parse_args()
    accepted = verify(args.root, args.proof, args.source_only)
    print(json.dumps({"nativeAccepted": accepted["nativeAccepted"], "sourceFiles": len(accepted["sourceHashes"]),
                      "captureProfiles": accepted.get("captureProfiles", 0), "actualHttpRequests": accepted.get("actualHttpRequests", 0)}))
