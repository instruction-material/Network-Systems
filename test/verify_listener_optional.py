"""Retain native socket, process, filter and cleanup evidence for optional Unit4."""
import argparse
import ast
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

PACKS = {
    "udp": "NS-09-unit-4-ports-and-listening-services-supplemental-2",
    "tcp": "NS-10-unit-4-ports-and-listening-services-supplemental-3",
}


def rows(raw, owned):
    inode = owned["socket"].removeprefix("socket:[").removesuffix("]")
    return [line for line in raw.splitlines()
            if re.search(r"\bino:" + re.escape(inode) + r"\b", line)]


def reconcile(mode, report, trace):
    observed = report["observations"]
    token = report["config"]["token"].encode()
    assert report["process"]["ownedSocketsClosed"]
    assert not Path("/proc/" + str(report["process"]["pid"])).exists()
    commands = report["commands"]
    ss_commands = [x for x in commands if Path(x["command"][0]).name == "ss"]
    assert len(ss_commands) == 6
    assert all(x["exitCode"] == 0 and x["endTime"] >= x["startTime"]
               and x["timeoutSeconds"] == 4 for x in ss_commands)
    assert len(re.findall(r"socket\(AF_INET,", trace)) == 2
    assert re.search(r'bind\(.*sin_addr=inet_addr\("127\.0\.0\.1"\)', trace)
    assert '"' + token.decode() + '"' in trace
    assert '"reply:' + token.decode() + '"' in trace
    assert len(re.findall(r"execve\(\"[^\"]*/ss\"", trace)) == 6
    assert re.search(r"close\(\d+<(?:UDP|TCP):.*\)\s+= 0", trace)
    if mode == "udp":
        owned = observed["endpoint"]["identity"]
        before, after, closed = [observed[k] for k in
                                ("beforeConnect", "afterConnectBeforeSend", "afterClose")]
        assert rows(before["listening"], owned) and rows(before["all"], owned)
        assert not rows(after["listening"], owned) and rows(after["all"], owned)
        assert not rows(closed["all"], owned)
        assert observed["exchange"]["peerReceivedHex"] == token.hex()
        assert observed["exchange"]["replyReceivedHex"] == (b"reply:" + token).hex()
        assert observed["exchange"]["sender"] == observed["endpoint"]["local"]
        assert "SOCK_DGRAM" in trace
        assert re.search(r"connect\(.*127\.0\.0\.1.*\)\s+= 0", trace)
        assert "listen(" not in trace and "accept(" not in trace and "accept4(" not in trace
    else:
        parent, child = observed["parent"], observed["child"]
        assert (parent["namespace"], parent["socket"]) == (child["namespace"], child["socket"])
        assert parent["pid"] != child["pid"]
        before = rows(observed["beforeParentClose"]["listening"], parent)
        after = rows(observed["afterParentClose"]["listening"], parent)
        assert len(before) == len(after) == 1
        assert all(f"pid={x['pid']}," in before[0] for x in (parent, child))
        assert f"pid={parent['pid']}," not in after[0]
        assert f"pid={child['pid']}," in after[0]
        assert not rows(observed["afterChildExit"]["listening"], parent)
        assert observed["workerExchange"]["receivedHex"] == token.hex()
        assert observed["replyReceivedHex"] == (b"reply:" + token).hex()
        assert observed["workerExitCode"] == 0
        assert not Path("/proc/" + str(observed["workerPid"])).exists()
        assert any(x["pid"] == observed["workerPid"] and x["exitCode"] == 0
                   and x["cleanup"] == "normal worker exit and reap" for x in commands)
        assert re.search(r"listen\(.*\)\s+= 0", trace)
        assert re.search(r"accept4?\(.*\)\s+= \d+<TCP:", trace)
        assert re.search(r"wait4\(" + str(child["pid"]) + r",.*WEXITSTATUS\(s\) == 0", trace)


def execute(args, cwd, stdout_path, stderr_path):
    started = time.time()
    process = subprocess.Popen(args, cwd=cwd, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, start_new_session=True)
    cleanup = "not needed"
    try:
        stdout, stderr = process.communicate(timeout=45)
    except BaseException:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        stdout, stderr = process.communicate()
        cleanup = "owned process group killed and reaped"
        raise
    finally:
        record = {"parentTask": "network-optional-listener-native-ci",
                  "cwd": str(cwd), "command": args, "pid": process.pid,
                  "parentPid": os.getpid(), "startTime": started,
                  "endTime": time.time(), "exitCode": process.returncode,
                  "timeoutSeconds": 45, "childProcessGroupCleanup": cleanup}
        stdout_path.with_suffix(".process.json").write_text(json.dumps(record, indent=2) + "\n")
    stdout_path.write_bytes(stdout)
    stderr_path.write_bytes(stderr)
    return process.returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proof", type=Path, required=True)
    parser.add_argument("--source-only", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    files = {}
    for mode, pack in PACKS.items():
        for path in sorted((root / pack).rglob("*")):
            if not path.is_file() or "__pycache__" in path.parts:
                continue
            raw = path.read_bytes()
            files[str(path.relative_to(root))] = hashlib.sha256(raw).hexdigest()
            if path.suffix == ".py":
                ast.parse(raw, feature_version=(3, 10))
        for name in ("main.py", "listener_lab.py", "network-notes.md", "edge-cases.md"):
            assert (root / pack / "starter" / name).read_bytes() == (root / pack / "solution" / name).read_bytes()
        assert len(list((root / pack).glob("starter/*"))) == 5
    assert len(files) == 22
    proof = {"sourceFiles": files, "nativeExecuted": False, "cases": []}
    args.proof.parent.mkdir(parents=True, exist_ok=True)
    if args.source_only:
        args.proof.write_text(json.dumps(proof, indent=2) + "\n")
        print("Source structure checked; native acceptance was not executed")
        return
    assert sys.platform == "linux" and os.geteuid() != 0
    assert shutil.which("strace") and shutil.which("ss")
    work = args.proof.parent / "listener-optional-raw"
    work.mkdir(exist_ok=False)
    for mode, pack in PACKS.items():
        key = "inventory_view" if mode == "udp" else "group_by"
        correct = "all" if mode == "udp" else "netns_inode"
        wrong = "listening" if mode == "udp" else "pid"
        cases = [("untouched", "starter", None, 2),
                 ("reference", "solution", None, 0),
                 ("completed", "starter", {key: correct}, 0),
                 ("wrong-strategy", "solution", {key: wrong}, 1),
                 ("changed-token", "solution", {"token": "alternate_" + mode}, 0),
                 ("bad-token", "solution", {"token": []}, 64),
                 ("bad-strategy", "solution", {key: "unknown"}, 64),
                 ("unknown-target", "solution", {"host": "192.0.2.1"}, 64),
                 ("existing-output", "solution", None, 64)]
        for label, role, edits, expected in cases:
            case_dir = work / (mode + "-" + label)
            shutil.copytree(root / pack / role, case_dir)
            config_path = case_dir / "case.json"
            config = json.loads(config_path.read_text())
            config.update(edits or {})
            config_path.write_text(json.dumps(config) + "\n")
            report_path = case_dir / "report.json"
            if label == "existing-output":
                report_path.write_text("preserved-output\n")
            trace_path = case_dir / "strace.txt"
            argv = [shutil.which("strace"), "-f", "-yy", "-s", "256", "-o", str(trace_path.resolve()),
                    "-e", "trace=%network,%process,close,read,write,readlink",
                    sys.executable, "-B", "main.py", "--report", "report.json"]
            actual = execute(argv, case_dir, case_dir / "stdout.txt", case_dir / "stderr.txt")
            assert actual == expected, (mode, label, actual, (case_dir / "stderr.txt").read_text())
            trace = trace_path.read_text()
            if expected == 64:
                assert "socket(AF_INET," not in trace
                if label == "existing-output":
                    assert report_path.read_text() == "preserved-output\n"
                else:
                    assert not report_path.exists()
                report = None
            else:
                report = json.loads(report_path.read_text())
                assert report["analysis"] == {0: "passed", 1: "revise", 2: "unfinished"}[expected]
                reconcile(mode, report, trace)
            proof["cases"].append({"mode": mode, "label": label, "role": role,
                                   "exitCode": actual, "report": str(report_path.relative_to(args.proof.parent)) if report else None,
                                   "rawTrace": str(trace_path.relative_to(args.proof.parent)),
                                   "traceSha256": hashlib.sha256(trace_path.read_bytes()).hexdigest()})
    proof.update(nativeExecuted=True, nativeExperiments=10, inputRefusals=8,
                 unfinishedAttempts=2, controlledWrongChoices=2,
                 socketAndProcessCleanupReconciled=True)
    assert len(proof["cases"]) == 18
    args.proof.write_text(json.dumps(proof, indent=2) + "\n")
    print(json.dumps({k:v for k,v in proof.items() if k != "sourceFiles"}))


if __name__ == "__main__":
    main()
