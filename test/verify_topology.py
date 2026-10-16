"""Verify real Linux forwarding/NAT and cleanup without trusting completion flags."""
import argparse
import ast
import contextlib
import datetime
import hashlib
import importlib.util
import json
import os
import re
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
        values[name] = "\n".join(re.sub(r"^(:\S+ \S+) \[\d+:\d+\]$", r"\1", line)
                                for line in stdout.splitlines() if not line.startswith("#"))
    values["networkNamespace"] = os.readlink("/proc/self/ns/net")
    values["mountNamespace"] = os.readlink("/proc/self/ns/mnt")
    return values


def check_cleanup(data):
    differences = {key: {"before": value, "after": data["hostAfter"][key]}
                   for key, value in data["hostBefore"].items()
                   if key != "firewallRaw" and value != data["hostAfter"][key]}
    assert not differences and data["hostUnchanged"] is True, differences
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


def check_flows(data, completed, policy_complete=False, interrupted=False):
    rows = data["lab"]["observations"]
    exposure = data["lab"]["exposurePolicyRequested"]
    stages = ["forwarding-off", "routed", "snat", "dnat", "mapping-removed", "direct-after-removal"]
    if exposure:
        stages += ["policy-baseline-direct", "policy-baseline-mapped"]
        if not interrupted:
            stages += ["policy-mapped-allowed", "policy-direct-blocked", "policy-direct-restored"]
    assert [row["stage"] for row in rows] == stages
    expected_peers = [None, "10.10.0.2", "10.20.0.1", "10.20.0.1", None, "10.20.0.1"]
    if exposure:
        expected_peers += ["10.20.0.1", "10.20.0.1"]
        if not interrupted:
            expected_peers += ["10.20.0.1", None if policy_complete else "10.20.0.1", "10.20.0.1"]
    if not completed:
        expected_peers = [None] * len(stages)
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
    assert data["lab"]["baseComplete"] is completed
    if exposure:
        if policy_complete:
            assert re.search(r"^:FORWARD DROP \[\d+:\d+\]$", data["lab"]["policyBeforeInterruption"], re.MULTILINE)
            for fragment in ("--ctstate NEW", "--ctorigdst 10.10.0.1", "--ctorigdstport 18080", "--ctdir ORIGINAL"):
                assert fragment in data["lab"]["policyBeforeInterruption"]
        if not interrupted:
            current = rows[9]["filterRules"]
            policy = re.search(r"^:FORWARD (\S+) \[(\d+):\d+\]$", current, re.MULTILINE)
            assert policy
            accepts = [(int(count), rule) for count, rule in re.findall(r"^\[(\d+):\d+\] (-A FORWARD .*)$", current, re.MULTILINE)
                       if "-j ACCEPT" in rule]
            new_count = sum(count for count, rule in accepts if "--ctstate NEW" in rule
                            and "--ctorigdstport 18080" in rule)
            reply_count = sum(count for count, rule in accepts if "ESTABLISHED" in rule)
            assert data["lab"]["policyCounters"] == {
                "policy": policy[1], "dropped": int(policy[2]) if policy[1] == "DROP" else 0,
                "newMappedAccepted": new_count, "establishedAccepted": reply_count,
            }
            if policy_complete:
                assert policy[1] == "DROP" and int(policy[2]) > 0 and new_count > 0 and reply_count > 0
            else:
                assert policy[1] == "ACCEPT" and new_count == reply_count == 0
            assert re.search(r"^:FORWARD ACCEPT \[\d+:\d+\]$", rows[10]["filterRules"], re.MULTILINE)
            assert "-A FORWARD" not in rows[10]["filterRules"]
            if completed:
                assert all("-j SNAT" in row["natRules"] and "-j DNAT" in row["natRules"] for row in rows[6:])
    expected_completion = completed and (not exposure or policy_complete) and not interrupted
    assert data["lab"]["complete"] is expected_completion


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
        spec = importlib.util.spec_from_file_location("ns6_runtime", pack / "starter/lab_runtime.py")
        module = importlib.util.module_from_spec(spec)
        sys.dont_write_bytecode = True
        spec.loader.exec_module(module)
        raw = "# Generated at one time\n*filter\n:OUTPUT ACCEPT [12:430]\n-A OUTPUT -p tcp --dport 8080 -j ACCEPT\nCOMMIT\n"
        canonical = module.firewall_configuration(raw)
        assert canonical == module.firewall_configuration(raw.replace("[12:430]", "[15:900]"))
        assert canonical != module.firewall_configuration(raw.replace("OUTPUT ACCEPT", "OUTPUT DROP"))
        assert canonical != module.firewall_configuration(raw.replace("8080", "18080"))
        assert canonical != module.firewall_configuration(raw.replace(":OUTPUT", ":INPUT"))
        result["firewallComparisonRegressionCases"] = 4
        if source_only:
            return result
        assert sys.platform == "linux" and os.geteuid() == 0
        host_before = host_state(records)
        with tempfile.TemporaryDirectory(prefix="ns6-native-check-") as temp:
            for profile, source_role, completed, policy, exposure, mode in (
                    ("untouched-starter", "starter", False, False, False, "normal"),
                    ("completed-starter", "starter", True, False, False, "normal"),
                    ("reference", "solution", True, False, False, "normal"),
                    ("intentional-failure", "solution", True, False, False, "failure"),
                    ("cancel-live-worker", "solution", True, False, False, "cancellation"),
                    ("policy-untouched-starter", "starter", False, False, True, "normal"),
                    ("policy-completed-starter", "starter", True, True, True, "normal"),
                    ("policy-reference", "solution", True, True, True, "normal"),
                    ("policy-incomplete-starter", "starter", True, False, True, "normal"),
                    ("policy-intentional-failure", "solution", True, True, True, "failure"),
                    ("policy-cancel-live-worker", "solution", True, True, True, "cancellation")):
                work = Path(temp) / profile
                shutil.copytree(pack / source_role, work)
                if profile in ("completed-starter", "policy-completed-starter"):
                    # Only exercise cases differ; keep the starter apparatus.
                    shutil.copyfile(pack / "solution/lab-rules.sh", work / "lab-rules.sh")
                elif profile == "policy-incomplete-starter":
                    starter = (work / "lab-rules.sh").read_text()
                    reference = (pack / "solution/lab-rules.sh").read_text()
                    for stage in ("forwarding", "snat", "dnat"):
                        pattern = re.compile(r"^  " + stage + r"\)\n.*?^    ;;", re.MULTILINE | re.DOTALL)
                        replacement = pattern.search(reference).group()
                        starter = pattern.sub(lambda _match, value=replacement: value, starter)
                    (work / "lab-rules.sh").write_text(starter)
                output, ready = work / "observations.json", work / "ready.txt"
                args = ["bash", str(work / "create_nat_lab.sh"), "--output", str(output),
                        "--test-mode", mode, "--ready-file", str(ready)]
                if exposure:
                    args.append("--exposure-policy")
                code, stdout, stderr = run(args, records, ready if mode == "cancellation" else None)
                data = json.loads(output.read_text())
                result["runs"].append({"profile": profile, "exitCode": code,
                                        "stdout": stdout, "stderr": stderr, "evidence": data})
                check_cleanup(data)
                assert host_state(records) == host_before
                if mode == "normal":
                    assert code == 0, (stdout, stderr)
                    check_flows(data, completed, policy)
                else:
                    assert code != 0 and "error" in data["lab"]
                    assert not data["lab"]["complete"]
                    if exposure:
                        check_flows(data, completed, policy, interrupted=True)
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
