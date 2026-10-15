"""Run untouched, completed and reference packs against actual Linux sockets."""
import argparse
import ast
import datetime
import hashlib
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

PACKS = {
    "NS-04-ns0-setup-and-tooling": "setup",
    "NS-05-unit-1-the-network-stack-in-plain-english": "transport",
}


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def hashes(root):
    result = {}
    for pack in PACKS:
        paths = [root / pack / "README.md"]
        for role in ("starter", "solution"):
            paths.extend((root / pack / role).iterdir())
        for path in paths:
            if path.is_file():
                result[str(path.relative_to(root))] = hashlib.sha256(
                    path.read_bytes()
                ).hexdigest()
    return result


def function_range(source):
    tree = ast.parse(source)
    node = next(n for n in tree.body
                if isinstance(n, ast.FunctionDef) and n.name == "analyze")
    return node.lineno - 1, node.end_lineno


def complete(starter, solution):
    first, last = function_range(starter)
    reference_first, reference_last = function_range(solution)
    lines, reference = starter.splitlines(keepends=True), solution.splitlines(keepends=True)
    assert "TODO:" in "".join(lines[first:last])
    return "".join(lines[:first] + reference[reference_first:reference_last] + lines[last:])


def visible(table, port, pid):
    target = f"127.0.0.1:{port}"
    return any(target in row.split() and f"pid={pid}," in row
               for row in table.splitlines())


def verify(report, kind, message, udp_buffer=256, newline=True):
    env, ready, child = report["environment"], report["ready"], report["workerProcess"]
    worker = report["workerResult"]
    assert env["platform"] == "linux" and env["uid"] == os.geteuid() > 0
    assert env["networkNamespace"] == os.readlink("/proc/self/ns/net")
    assert set(env["tools"]) == {"ip", "ss", "curl", "ssh", "dig", "traceroute"}
    assert all(Path(path).is_file() for path in env["tools"].values())
    assert env["pid"] > 0 and child["pid"] == ready["pid"] == worker["pid"] > 0
    assert child["exitCode"] == 0 and child["reaped"]
    assert child["cleanup"] == "exited and reaped"
    assert not Path(f"/proc/{child['pid']}").exists()
    assert child["startTime"] <= child["endTime"]
    assert worker["socketsClosed"] and 0 <= worker["elapsedSeconds"] < 40
    assert report["kind"] == kind and report["message"] == message
    commands = report["commands"]
    assert all(row["exitCode"] == 0 and row["cleanup"] == "exited and reaped"
               and row["startTime"] <= row["endTime"] and row["pid"] > 0
               and row["timeoutSeconds"] == 8 for row in commands)
    for name in (("http",) if kind == "setup" else ("tcp", "udp")):
        assert ready[name]["address"] == "127.0.0.1"
        assert 1 <= ready[name]["port"] <= 65535
    if kind == "setup":
        port = ready["http"]["port"]
        assert len(commands) == 5
        assert report["route"][0]["dev"] == "lo"
        assert report["loopback"][0]["ifname"] == "lo"
        assert any(row["local"] == "127.0.0.1"
                   for row in report["loopback"][0]["addr_info"])
        assert visible(report["listenersDuring"], port, child["pid"])
        assert not visible(report["listenersAfter"], port, child["pid"])
        assert worker["requests"] == ["/lab"]
        assert report["httpResponse"] == {"message": message, "path": "/lab"}
        assert commands[0]["command"] == [env["tools"]["ip"], "-j", "address", "show", "dev", "lo"]
        assert commands[1]["command"] == [env["tools"]["ip"], "-j", "route", "get", "127.0.0.1"]
        assert json.loads(commands[0]["stdout"]) == report["loopback"]
        assert json.loads(commands[1]["stdout"]) == report["route"]
        assert commands[2]["stdout"] == report["listenersDuring"]
        assert commands[3]["command"][-1] == f"http://127.0.0.1:{port}/lab"
        assert "--noproxy" in commands[3]["command"] and "--fail" in commands[3]["command"]
        assert json.loads(commands[3]["stdout"]) == report["httpResponse"]
        assert commands[4]["stdout"] == report["listenersAfter"]
        expected = {
            "linux": True, "availableTools": sorted(env["tools"]),
            "routeInterface": "lo", "ownedListenerObserved": True,
            "responseMatches": True, "scope": "same Linux network namespace",
        }
    else:
        assert len(commands) == 4
        for protocol in ("tcp", "udp"):
            assert visible(report[protocol + "ListenersDuring"], ready[protocol]["port"], child["pid"])
            assert not visible(report[protocol + "ListenersAfter"], ready[protocol]["port"], child["pid"])
            assert report[protocol + "Client"]["address"] == "127.0.0.1"
        data = message.encode("utf-8")
        wire = data + (b"\n" if newline else b"")
        reads = [bytes.fromhex(chunk) for chunk in worker["tcpReadsHex"]]
        assert len(reads) >= (2 if len(wire) > 2 else 1)
        assert all(0 < len(chunk) <= 256 for chunk in reads)
        assert b"".join(reads) == wire
        assert b"".join(bytes.fromhex(c) for c in report["tcpEchoChunksHex"]) == wire
        prefix = b""
        for chunk in reads:
            prefix += chunk
            if len(prefix) >= 2:
                break
        assert prefix == wire[:2]
        assert worker["tcpPeer"] == report["tcpClient"]
        assert worker["tcpEofObserved"]
        datagrams = worker["datagrams"]
        assert len(datagrams) == 2
        assert [bytes.fromhex(row["dataHex"]) for row in datagrams] == [b"", data[:udp_buffer]]
        assert report["udpEchoesHex"] == ["", data[:udp_buffer].hex()]
        assert all(row["sender"] == report["udpClient"] for row in datagrams)
        truncated = [False, len(data) > udp_buffer]
        assert [row["truncated"] for row in datagrams] == truncated
        assert [bool(row["flags"] & socket.MSG_TRUNC) for row in datagrams] == truncated
        assert all(row["flags"] in (0, socket.MSG_TRUNC) for row in datagrams)
        for index, label in enumerate(("tcpListenersDuring", "udpListenersDuring",
                                       "tcpListenersAfter", "udpListenersAfter")):
            assert commands[index]["stdout"] == report[label]
            assert commands[index]["command"] == [
                env["tools"]["ss"], "-H", "-ltnp" if label.startswith("tcp") else "-lunp"
            ]
        expected = {
            "tcpBytes": len(wire), "tcpReadCalls": len(reads),
            "tcpCompleteLine": newline, "tcpEofObserved": True,
            "udpDatagramLengths": [0, min(len(data), udp_buffer)],
            "udpTruncated": truncated, "emptyUdpIsDatagram": True,
            "scope": "same Linux network namespace",
        }
    return expected


def run(args, cwd, records, process_log):
    started = now()
    process = subprocess.Popen(
        args, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        start_new_session=True, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )
    entry = {"parentTask": "network-foundations-source-validation",
             "parentPid": os.getpid(), "cwd": str(cwd), "command": args,
             "pid": process.pid, "startTime": started, "timeoutSeconds": 60}
    with process_log.open("a") as out:
        out.write(json.dumps({**entry, "event": "start"}) + "\n")
    cleanup = "exited and reaped"
    try:
        stdout, stderr = process.communicate(timeout=60)
    finally:
        if process.poll() is None:
            cleanup = "owned process group terminated"
            os.killpg(process.pid, signal.SIGTERM)
            try:
                stdout, stderr = process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                stdout, stderr = process.communicate()
        with process_log.open("a") as out:
            out.write(json.dumps({**entry, "event": "end", "endTime": now(),
                                 "exitCode": process.returncode, "cleanup": cleanup}) + "\n")
    row = {**entry, "endTime": now(), "status": process.returncode,
           "stdout": stdout.decode(), "stderr": stderr.decode(), "cleanup": cleanup}
    records.append(row)
    return row


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--proof", type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != "linux" or os.geteuid() == 0:
        parser.error("Native acceptance requires an ordinary Linux user.")
    root = Path(__file__).resolve().parents[1]
    args.proof.parent.mkdir(parents=True, exist_ok=True)
    stem = args.proof.with_suffix("")
    process_log = Path(str(stem) + ".processes.jsonl")
    assert not process_log.exists()
    initial = hashes(root)
    assert len(initial) == 18
    records, profiles = [], []
    proof = {"nativePassed": False, "platform": sys.platform, "uid": os.geteuid(),
             "sourceHashes": initial, "profiles": profiles,
             "learnerExplanationCompletionInferred": False, "error": None}
    try:
        with tempfile.TemporaryDirectory(prefix="network foundation ' quoted ") as temporary:
            outside = Path(temporary) / "outside.txt"
            outside.write_text("Preserved outside observation.\n")
            for index, (pack, kind) in enumerate(PACKS.items()):
                for role in ("starter", "completed", "solution"):
                    dest = Path(temporary) / f"{index} {role} quoted role"
                    shutil.copytree(root / pack / ("starter" if role == "completed" else role), dest)
                    if role == "completed":
                        file = dest / "main.py"
                        file.write_text(complete(file.read_text(),
                                                 (root / pack / "solution/main.py").read_text()))
                    cases = [
                        ("default", [], "First local observation" if kind == "setup" else "First transport observation", 256, True, 0),
                        ("quoted Unicode", ["--message", "Quoted ' café Δ message"], "Quoted ' café Δ message", 256, True, 0),
                    ]
                    cases.extend([
                        ("minimum message", ["--message", "ab"], "ab", 256, True, 0),
                        ("maximum UTF8 bytes", ["--message", "λ" * 64], "λ" * 64, 256, True, 0),
                    ] if kind == "setup" else [])
                    if kind == "transport":
                        cases.extend([
                            ("truncated UDP", ["--message", "abcdef", "--udp-buffer", "3"], "abcdef", 3, True, 0),
                            ("incomplete line", ["--message", "abcdef", "--without-newline"], "abcdef", 256, False, 0),
                            ("minimum EOF", ["--message", "ab", "--without-newline"], "ab", 256, False, 0),
                            ("maximum UTF8 bytes", ["--message", "λ" * 64], "λ" * 64, 256, True, 0),
                            ("UTF8 truncated byte", ["--message", "λé", "--udp-buffer", "1"], "λé", 1, True, 0),
                            ("invalid buffer", ["--udp-buffer", "0"], "", 0, True, 2),
                            ("oversized buffer", ["--udp-buffer", "257"], "", 257, True, 2),
                            ("oversized message", ["--message", "λ" * 65], "λ" * 65, 256, True, 2),
                        ])
                    else:
                        cases.extend([
                            ("invalid message", ["--message", "x"], "x", 256, True, 2),
                            ("oversized message", ["--message", "λ" * 65], "λ" * 65, 256, True, 2),
                        ])
                    for label, options, message, buffer, newline, status in cases:
                        row = run([sys.executable, str(dest / "main.py"), *options],
                                  dest, records, process_log)
                        row.update(pack=pack, profile=role, case=label)
                        assert row["status"] == status and row["cleanup"] == "exited and reaped"
                        if status:
                            assert not row["stdout"] and row["stderr"]
                            continue
                        assert not row["stderr"]
                        report = json.loads(row["stdout"])
                        assert row["startTime"] <= report["workerProcess"]["startTime"]
                        assert report["workerProcess"]["endTime"] <= row["endTime"]
                        expected = verify(report, kind, message, buffer, newline)
                        assert report["analysis"] == (None if role == "starter" else expected)
                        row["independentExpectedAnalysis"] = expected
                    assert outside.read_text() == "Preserved outside observation.\n"
                    profiles.append({"pack": pack, "profile": role, "cases": len(cases),
                                     "passed": True, "outsidePreserved": True,
                                     "learnerExplanationCompletionInferred": False})
        assert hashes(root) == initial
        assert len(records) == 48 and len(profiles) == 6
        proof.update(nativePassed=True, sourceUnchanged=True, actualCases=len(records),
                     nativeExchanges=sum(row["status"] == 0 for row in records),
                     rejectedInputs=sum(row["status"] != 0 for row in records))
    except BaseException as error:
        proof["error"] = repr(error)
        raise
    finally:
        args.proof.write_text(json.dumps(proof, indent=2) + "\n")
        Path(str(stem) + ".observations.json").write_text(json.dumps(records, indent=2) + "\n")
    print(json.dumps({k: proof[k] for k in (
        "nativePassed", "actualCases", "nativeExchanges", "rejectedInputs", "sourceUnchanged"
    )}))


if __name__ == "__main__":
    main()

