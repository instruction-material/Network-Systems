"""Verify real Linux forwarding/NAT and cleanup without trusting completion flags."""
import argparse
import ast
import contextlib
import datetime
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

PACK = "NS6-Router-NAT-Topology-Lab"
FILES = ("README.md", "create_nat_lab.sh", "lab_runtime.py", "lab-rules.sh", "network-notes.md")


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def run(args, records, ready=None):
    started = now()
    process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               start_new_session=True)
    cleanup = "exited and reaped"
    try:
        if ready:
            deadline = time.monotonic() + 15
            while not ready.is_file() and time.monotonic() < deadline and process.poll() is None:
                time.sleep(0.05)
            assert ready.is_file(), "interruption case never reached a live owned HTTP worker"
            process.send_signal(signal.SIGTERM)
        stdout, stderr = process.communicate(timeout=75)
    except BaseException:
        cleanup = "terminated and reaped owned process group"
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGTERM)
        try:
            process.communicate(timeout=12)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate(timeout=3)
        raise
    finally:
        records.append({"task": "NS6-native-acceptance", "parentPid": os.getpid(),
                        "cwd": str(Path.cwd()), "command": args, "pid": process.pid,
                        "startTime": started, "endTime": now(), "exitCode": process.returncode,
                        "timeoutSeconds": 75, "childProcessGroupCleanup": cleanup})
    return process.returncode, stdout.decode(), stderr.decode()


def host_state(records):
    values = {}
    for name, args in (("links", ["ip", "-j", "link", "show"]),
                       ("routes", ["ip", "-j", "route", "show", "table", "all"]),
                       ("named", ["ip", "netns", "list"]),
                       ("forwarding", ["sysctl", "-n", "net.ipv4.ip_forward"]),
                       ("firewall", ["iptables-save"])):
        code, stdout, stderr = run(args, records)
        assert code == 0, stderr
        values[name] = "\n".join(line for line in stdout.splitlines() if not line.startswith("#"))
    values["networkNamespace"] = os.readlink("/proc/self/ns/net")
    values["mountNamespace"] = os.readlink("/proc/self/ns/mnt")
    return values


def check_cleanup(data):
    assert data["hostBefore"] == data["hostAfter"] and data["hostUnchanged"] is True
    lab = data["lab"]
    assert lab["networkNamespace"] != data["hostBefore"]["networkNamespace"]
    assert lab["mountNamespace"] != data["hostBefore"]["mountNamespace"]
    assert lab["cleanup"]["workerReaped"] is True
    assert lab["cleanup"]["namespacesRemoved"] is True
    assert lab["cleanup"]["remainingNamespaces"] == ""
    assert [row["ifname"] for row in lab["cleanup"]["remainingLinks"]] == ["lo"]
    assert lab["worker"]["reaped"] and lab["worker"]["exitCode"] is not None
    try:
        os.kill(lab["worker"]["pid"], 0)
    except ProcessLookupError:
        pass
    else:
        raise AssertionError("owned HTTP worker PID still exists after return")
    for row in [*data["commands"], *lab["commands"]]:
        assert row["pid"] > 0 and row["parentPid"] > 0
        assert row["startTime"] <= row["endTime"] and row["exitCode"] is not None
    names = lab["names"]
    for role, interface, address, gateway in (("client", "c0", "10.10.0.2", "10.10.0.1"),
                                               ("server", "s0", "10.20.0.2", "10.20.0.1")):
        topology = lab["topology"][names[role]]
        assert any(row.get("dst") == "default" and row.get("gateway") == gateway
                   for row in topology["routes"])
        link = next(row for row in topology["addresses"] if row["ifname"] == interface)
        assert any(row.get("local") == address and row["prefixlen"] == 24 for row in link["addr_info"])
    for topology in lab["topology"].values():
        assert all(len(row["ifname"].encode()) <= 15 for row in topology["addresses"])


def check_flows(data, completed):
    rows = data["lab"]["observations"]
    assert [row["stage"] for row in rows] == ["forwarding-off", "routed", "snat", "dnat",
                                              "mapping-removed", "direct-after-removal"]
    expected_peers = [None, "10.10.0.2", "10.20.0.1", "10.20.0.1", None, "10.20.0.1"]
    if not completed:
        expected_peers = [None] * 6
    for row, peer in zip(rows, expected_peers):
        response = row["response"]
        assert row["forwarding"] == ("1" if completed and row["stage"] != "forwarding-off" else "0")
        if peer is None:
            assert response["exitCode"] != 0 and response["body"] is None
        else:
            assert response["exitCode"] == 0
            assert response["body"] == {"token": data["token"], "peer": peer,
                                         "server": "10.20.0.2", "port": 8080, "path": "/lab"}
    if completed:
        assert "-j SNAT --to-source 10.20.0.1" in rows[2]["natRules"]
        assert "-j DNAT --to-destination 10.20.0.2:8080" in rows[3]["natRules"]
        assert "--dport 18080" in rows[3]["natRules"]
        assert "-j DNAT" not in rows[4]["natRules"]
        assert "-j SNAT" in rows[4]["natRules"]
    else:
        assert all("-j SNAT" not in row["natRules"] and "-j DNAT" not in row["natRules"] for row in rows)
    assert data["lab"]["complete"] is completed


def verify(root, proof, source_only):
    records = []
    result = {"mode": "source-only" if source_only else "isolated-linux-kernel",
              "nativeAccepted": False, "hashes": {}, "processes": records, "runs": []}
    try:
        pack = root / PACK
        for role in ("starter", "solution"):
            for name in FILES:
                path = pack / role / name
                raw = path.read_bytes()
                result["hashes"][str(path.relative_to(root))] = hashlib.sha256(raw).hexdigest()
                assert b"\r" not in raw, path
                if name.endswith(".py"):
                    ast.parse(raw, filename=str(path), feature_version=(3, 10))
                if name.endswith(".sh"):
                    assert run(["bash", "-n", str(path)], records)[0] == 0
                if name in ("README.md", "lab_runtime.py", "create_nat_lab.sh", "network-notes.md"):
                    assert raw == (pack / "starter" / name).read_bytes()
        guide = pack / "README.md"
        assert guide.read_bytes() == (pack / "starter/README.md").read_bytes()
        result["hashes"][str(guide.relative_to(root))] = hashlib.sha256(guide.read_bytes()).hexdigest()
        if source_only:
            return result
        assert sys.platform == "linux" and os.geteuid() == 0
        host_before = host_state(records)
        with tempfile.TemporaryDirectory(prefix="ns6-native-check-") as temp:
            for profile, source_role, completed, mode in (
                    ("untouched-starter", "starter", False, "normal"),
                    ("completed-starter", "starter", True, "normal"),
                    ("reference", "solution", True, "normal"),
                    ("intentional-failure", "solution", True, "failure"),
                    ("cancel-live-worker", "solution", True, "cancellation")):
                work = Path(temp) / profile
                shutil.copytree(pack / source_role, work)
                if profile == "completed-starter":
                    # Only the three exercise cases differ; keep the starter apparatus.
                    shutil.copyfile(pack / "solution/lab-rules.sh", work / "lab-rules.sh")
                output, ready = work / "observations.json", work / "ready.txt"
                args = ["bash", str(work / "create_nat_lab.sh"), "--output", str(output),
                        "--test-mode", mode, "--ready-file", str(ready)]
                code, stdout, stderr = run(args, records, ready if mode == "cancellation" else None)
                data = json.loads(output.read_text())
                check_cleanup(data)
                assert host_state(records) == host_before
                if mode == "normal":
                    assert code == 0, (stdout, stderr)
                    check_flows(data, completed)
                else:
                    assert code != 0 and "error" in data["lab"]
                    assert not data["lab"]["complete"]
                result["runs"].append({"profile": profile, "exitCode": code,
                                        "stdout": stdout, "stderr": stderr, "evidence": data})
        # Direct internal entry must refuse the host before any mounting or changes.
        code, _, stderr = run([sys.executable, str(pack / "solution/lab_runtime.py"),
                               "--inside", os.readlink("/proc/self/ns/net")], records)
        assert code == 2 and "refusing to alter the original" in stderr
        assert host_state(records) == host_before
        result["hostUnchanged"] = True
        result["nativeAccepted"] = True
        return result
    finally:
        proof.parent.mkdir(parents=True, exist_ok=True)
        proof.write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-only", action="store_true")
    parser.add_argument("--proof", type=Path, required=True)
    options = parser.parse_args()
    print(json.dumps({key: value for key, value in verify(
        Path(__file__).resolve().parents[1], options.proof, options.source_only).items()
        if key in ("mode", "nativeAccepted", "hostUnchanged")}))
