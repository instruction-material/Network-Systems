"""Verify two optional transport investigations and retain actual socket traces."""
import argparse
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
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKS = {"tcp": "NS-03-unit-1-the-network-stack-in-plain-english-supplemental-2",
         "udp": "NS-04-unit-1-the-network-stack-in-plain-english-supplemental-3"}
LOG = []


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()  # noqa: UP017


def hashes(root):
    return {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(root.rglob("*")) if path.is_file()}


def command(argv, cwd):
    argv = [str(value) for value in argv]
    started = now()
    child = subprocess.Popen(argv, cwd=cwd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             start_new_session=True, env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
    cleanup = "process exited"
    try:
        stdout, stderr = child.communicate(timeout=30)
    except BaseException:
        cleanup = "owned process group terminated and reaped"
        with contextlib.suppress(ProcessLookupError):
            os.killpg(child.pid, signal.SIGTERM)
        try:
            child.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(child.pid, signal.SIGKILL)
            child.communicate(timeout=3)
        raise
    finally:
        record = {"parentTaskId": "network-transport-native-validation", "command": argv,
                  "cwd": str(cwd), "pid": child.pid, "startTime": started, "endTime": now(),
                  "exitCode": child.returncode, "timeoutSeconds": 30,
                  "childProcessGroupCleanup": cleanup}
        LOG.append(record)
    return dict(record, stdout=stdout, stderr=stderr)


def check_report(report, trace, folder, mode, alternate, expected_complete, mutant):
    assert report["mode"] == mode and report["alternate"] == alternate
    assert report["sourceUnchanged"] and report["parentUnchanged"]
    assert report["parentBefore"] == report["parentAfter"] and report["parentBefore"]["uid"] > 0
    assert report["allSocketsClosed"] and report["allThreadsJoined"] and report["notebookCompletionNotInferred"]
    assert report["sourceFileHashes"] == {path.name: digest for path, digest in ((folder / name, value) for name, value in hashes(folder).items())}
    assert report["case"] == json.loads((folder / "case.json").read_text())
    assert report["caseFileSha256"] == hashlib.sha256((folder / "case.json").read_bytes()).hexdigest()
    assert report["completed"] == expected_complete and report["exitCode"] == (0 if expected_complete else 78)
    assert report["startedAt"] <= report["endedAt"] and 0 <= report["elapsedSeconds"] < 20
    pid = report["parentBefore"]["pid"]
    assert re.search(r"^" + str(pid) + r"\s+recvmsg\(", trace, re.MULTILINE)
    assert "socket(AF_INET, " in trace and "127.0.0.1" in trace and "close(" in trace
    observation = report["observation"]
    assert observation["completed"] == expected_complete
    closes = [row["fd"] for row in report["events"] if row["operation"] == "close"]
    created = [row["fd"] for row in report["events"] if row["operation"] in {"socket", "accept"}]
    assert sorted(closes) == sorted(created) and len(set(created)) == len(created)
    if mode == "tcp":
        messages = ["changed first record", "lamp \u2713", "third record"] if alternate else ["north route", "lamp \u2713"]
        wire = b"".join(struct.pack("!I", len(value.encode())) + value.encode() for value in messages)
        assert observation["messages"] == messages and observation["wireHex"] == wire.hex()
        assert observation["payloadByteLengths"] == [len(value.encode()) for value in messages]
        assert observation["firstReadHex"] == "00" and observation["eofObserved"]
        assert b"".join(bytes.fromhex(row["dataHex"]) for row in observation["readCalls"]) == wire
        assert observation["readCalls"][0]["requestedBytes"] == 2
        assert observation["applicationInputHex"] == (wire.hex() if expected_complete else "00")
        assert observation["applicationRecords"] == (messages if expected_complete else [])
        assert observation["applicationError"] == (None if expected_complete else "incomplete-length-prefix")
        assert "SOCK_STREAM" in trace and "shutdown(" in trace and "MSG_PEEK" not in trace
        assert re.search(r"^" + str(observation["serverThreadId"]) + r"\s+(accept|sendto|shutdown)\(", trace, re.MULTILINE)
    else:
        messages = ["changed first datagram", "second changed", "third changed"] if alternate else ["first datagram", "second datagram"]
        assert observation["messages"] == messages and observation["sentHex"] == [value.encode().hex() for value in messages]
        assert observation["probe"]["dataHex"] == messages[0].encode()[:4].hex()
        assert observation["probe"]["truncated"] and observation["probe"]["returnedFlags"] & socket.MSG_TRUNC
        assert observation["probe"]["requestedFlags"] == (socket.MSG_PEEK if expected_complete else 0)
        assert observation["applicationRecords"] == (messages if expected_complete else messages[1:])
        assert [bytes.fromhex(row["dataHex"]).decode() for row in observation["consumerReads"]] == observation["applicationRecords"]
        assert sum(row["operation"] == "receive-timeout" for row in report["events"]) == (0 if expected_complete else 1)
        assert "SOCK_DGRAM" in trace and ("MSG_PEEK" in trace) == expected_complete
        assert all(row["peer"] == observation["senderEndpoint"] for row in observation["consumerReads"])
    if mutant:
        assert not expected_complete


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proof", type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != "linux" or os.getuid() == 0:
        parser.error("Native validation requires an ordinary Linux account")
    assert shutil.which("strace")
    proof = args.proof.resolve()
    proof.parent.mkdir(parents=True, exist_ok=True)
    retained = proof.parent / "transport-observations"
    retained.mkdir(exist_ok=False)
    before = {mode: hashes(ROOT / pack) for mode, pack in PACKS.items()}
    accepted, unfinished, regressions, refusals = [], [], [], []
    try:
        with tempfile.TemporaryDirectory(prefix="network-transport-contracts-") as temporary:
            work = Path(temporary)
            for mode, pack in PACKS.items():
                root = ROOT / pack
                assert len(before[mode]) == 11
                assert {name for name in hashes(root / "starter") if hashes(root / "starter")[name] != hashes(root / "solution")[name]} == {"case.json"}
                completed = work / (mode + "-completed")
                shutil.copytree(root / "starter", completed)
                (completed / "case.json").write_bytes((root / "solution/case.json").read_bytes())
                for role, folder in [("starter", root / "starter"), ("solution", root / "solution"), ("completed", completed)]:
                    for alternate in [False, True]:
                        stem = mode + "-" + role + ("-alternate" if alternate else "-default")
                        report_path, trace_path = retained / (stem + ".json"), retained / (stem + ".syscalls.txt")
                        result = command(["strace", "-f", "-yy", "-xx", "-s", "4096", "-e", "trace=network,close", "-o", trace_path,
                                          sys.executable, folder / "main.py", "--report", report_path, *(["--alternate"] if alternate else [])], folder)
                        expected = role != "starter"
                        assert result["exitCode"] == (0 if expected else 78), result
                        report = json.loads(report_path.read_text())
                        check_report(report, trace_path.read_text(), folder, mode, alternate, expected, False)
                        row = {"mode": mode, "role": role, "alternate": alternate,
                               "report": report_path.name, "trace": trace_path.name, "result": result}
                        (accepted if expected else unfinished).append(row)
                mutant = work / (mode + "-mutant")
                shutil.copytree(root / "solution", mutant)
                helper = mutant / "transport_lab.py"
                text = helper.read_text()
                old = 'application_input = bytes.fromhex(first["dataHex"]) if case["framing"] == "single-read" else observed' if mode == "tcp" else 'flags = socket.MSG_PEEK if case["probe_behavior"] == "peek" else 0'
                new = 'application_input = bytes.fromhex(first["dataHex"])' if mode == "tcp" else 'flags = 0'
                assert text.count(old) == 1
                helper.write_text(text.replace(old, new))
                report_path, trace_path = retained / (mode + "-regression.json"), retained / (mode + "-regression.syscalls.txt")
                result = command(["strace", "-f", "-yy", "-xx", "-s", "4096", "-e", "trace=network,close", "-o", trace_path,
                                  sys.executable, mutant / "main.py", "--report", report_path], mutant)
                assert result["exitCode"] == 78
                check_report(json.loads(report_path.read_text()), trace_path.read_text(), mutant, mode, False, False, True)
                regressions.append({"mode": mode, "report": report_path.name, "trace": trace_path.name, "result": result, "rejected": True})
                invalid = work / (mode + "-invalid-case.json")
                invalid.write_text('{"unknown": "setting"}\n')
                for kind in ["invalid-case", "existing-output"]:
                    target = work / (mode + "-" + kind + "-report.json")
                    if kind == "existing-output":
                        target.write_text("retained original\n")
                    trace = retained / (mode + "-" + kind + ".syscalls.txt")
                    result = command(["strace", "-f", "-yy", "-xx", "-s", "4096", "-e", "trace=network,close", "-o", trace,
                                      sys.executable, root / "starter/main.py", "--report", target,
                                      *(["--case", invalid] if kind == "invalid-case" else [])], root / "starter")
                    assert result["exitCode"] == 2 and "socket(AF_INET" not in trace.read_text()
                    if kind == "existing-output":
                        assert target.read_text() == "retained original\n"
                    else:
                        assert not target.exists()
                        assert invalid.read_text() == '{"unknown": "setting"}\n'
                    refusals.append({"mode": mode, "kind": kind, "trace": trace.name, "result": result})
        assert not Path(temporary).exists()
        assert before == {mode: hashes(ROOT / pack) for mode, pack in PACKS.items()}
        proof.write_text(json.dumps({"event": "verified-network-transport-optional", "sourceFileHashes": before,
                                     "sourceUnchanged": True, "temporaryBuildCleanup": True,
                                     "notebookCompletionNotInferred": True, "independentCompletionOnly": "case.json",
                                     "acceptedProfiles": accepted, "unfinishedProfilesRejected": unfinished,
                                     "controlledRegressions": regressions, "refusals": refusals,
                                     "retainedFiles": hashes(retained)}, indent=2) + "\n")
    finally:
        proof.with_suffix(".processes.jsonl").write_text("".join(json.dumps(row) + "\n" for row in LOG))
    assert (len(accepted), len(unfinished), len(regressions), len(refusals), len(LOG)) == (8, 4, 2, 4, 18)
    print(json.dumps({"accepted": True, "proof": str(proof), "nativeLaunches": len(LOG)}))


if __name__ == "__main__":
    main()
