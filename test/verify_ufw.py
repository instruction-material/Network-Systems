"""Verify source or actual owned UFW policy outcomes, rollback and interruption."""
import argparse
import ast
import contextlib
import datetime
import hashlib
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

PACK = "NS3-UFW-Web-Server-Policy"
ROLE_FILES = ("README.md", "network-notes.md", "apply_web_policy.sh", "policy-rules.sh", "web-stack.profile", "firewall_runtime.py")


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def write_proof(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n")


def run(argv, records, ready=None):
    started = now()
    process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    cleanup = "exited and reaped"
    try:
        if ready:
            deadline = time.monotonic() + 30
            while not ready.exists() and process.poll() is None and time.monotonic() < deadline:
                time.sleep(0.04)
            assert ready.exists(), "owned policy never reached real readiness"
            assert json.loads(ready.read_text())["activeOwnedPolicy"]
            process.send_signal(signal.SIGTERM)
        stdout, stderr = process.communicate(timeout=95)
    except BaseException:
        cleanup = "terminated and reaped owned process group"
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGTERM)
        try:
            process.communicate(timeout=22)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate(timeout=3)
        raise
    finally:
        records.append({"task": "NS3-native-policy-acceptance", "command": argv, "cwd": str(Path.cwd()),
                        "parentPid": os.getpid(), "pid": process.pid, "startTime": started,
                        "endTime": now(), "exitCode": process.returncode, "timeoutSeconds": 95,
                        "childProcessGroupCleanup": cleanup})
    return process.returncode, stdout.decode(), stderr.decode()


def source_checks(root):
    hashes = {}
    for relative in ["README.md"] + [role + "/" + name for role in ("starter", "solution") for name in ROLE_FILES]:
        path = root / PACK / relative
        raw = path.read_bytes()
        assert b"\r" not in raw, relative
        hashes[relative] = hashlib.sha256(raw).hexdigest()
        if path.suffix == ".py":
            ast.parse(raw, feature_version=(3, 10))
    for name in ("apply_web_policy.sh", "firewall_runtime.py", "web-stack.profile"):
        assert (root / PACK / "starter" / name).read_bytes() == (root / PACK / "solution" / name).read_bytes()
    solution = (root / PACK / "solution/policy-rules.sh").read_text()
    starter = (root / PACK / "starter/policy-rules.sh").read_text()
    assert 'ufw allow "${MANAGEMENT_PORT}/tcp"' in solution and 'ufw allow "Course Web"' in solution
    assert "TODO_MANAGEMENT" in starter and "TODO_WEB" in starter and "TODO_" not in solution
    assert "refusing" in solution and "/proc/1/ns/net" in solution and "/proc/1/ns/mnt" in solution
    for role in ("starter", "solution"):
        wrapper = (root / PACK / role / "apply_web_policy.sh").read_text()
        assert 'exec python3 "$here/firewall_runtime.py" "$@"' in wrapper
        assert "ufw allow" not in wrapper and "ufw --force enable" not in wrapper
    guide = (root / PACK / "README.md").read_text()
    assert all(phrase in guide for phrase in ("console access", "--management-port 22022", "rollback", "IPv4", "not an SSH daemon", "Python programming is optional"))
    return hashes


def normalized_rules(raw):
    return "\n".join(re.sub(r"\[\d+:\d+\]", "[COUNTERS]", line)
                     for line in raw.splitlines() if not line.startswith("#"))


def check_body(row, token, pid):
    assert row["response"]["exitCode"] == 0
    body = json.loads(row["response"]["stdout"])
    assert body == row["body"]
    assert body["token"] == token and body["pid"] == pid and body["path"] == "/policy/" + token
    assert body["server"] == ["10.77.0.2", row["port"]] and body["client"][0] == "10.77.0.1"
    assert 1024 <= body["client"][1] <= 65535 and body["service"] == row["service"]


def check_case(case):
    report = case["report"]
    assert report["hostUnchanged"] and report["hostBefore"] == report["hostAfter"]
    lab = report["lab"]
    assert lab["networkNamespace"] != report["hostBefore"]["networkNamespace"]
    assert lab["mountNamespace"] != report["hostBefore"]["mountNamespace"]
    assert lab["privateConfigurationVerified"]
    assert lab["workerReady"]["pid"] == lab["worker"]["pid"] and lab["workerReady"]["networkNamespace"] == lab["networkNamespace"]
    assert lab["workerReady"]["listeners"] == [["10.77.0.2", lab["managementPort"]], ["10.77.0.2", 8080], ["10.77.0.2", 9090]]
    assert all(lab["cleanup"][name] for name in ("workerReaped", "namespaceRemoved", "policyRestored"))
    assert lab["worker"]["reaped"] and lab["worker"]["exitCode"] is not None
    assert not lab["cleanup"]["remainingNamespaces"].strip()
    assert [link["ifname"] for link in lab["cleanup"]["remainingLinks"]] == ["lo"]
    rollback = lab["rollback"]
    assert rollback["beforeConfiguration"] == rollback["afterConfiguration"] == lab["priorPolicy"]["configuration"]
    assert rollback["configurationRestored"] and rollback["kernelRestored"] and rollback["allThreeServicesRestored"]
    assert normalized_rules(rollback["beforeKernel"]) == normalized_rules(rollback["afterKernel"])
    assert rollback["addedRules"] == lab["priorPolicy"]["addedRules"] and "65530/tcp" in rollback["addedRules"]
    assert "inactive" in rollback["status"] and "inactive" in lab["priorPolicy"]["status"]
    for stage in ("baselineRequests", "rollbackRequests"):
        assert set(lab[stage]) == {"management-marker", "web", "unrequested"}
        for row in lab[stage].values():
            check_body(row, report["token"], lab["worker"]["pid"])
    assert "Status: active" in lab["activeBeforeProbe"]["verbose"]
    assert "65530/tcp" in lab["activeBeforeProbe"]["numbered"]
    if case["mode"] != "normal":
        assert case["exitCode"] != 0 and report.get("error") and not report["complete"] and not lab["complete"]
        assert "error" in lab
        if case["mode"] == "hold":
            assert "signal 15" in lab["error"] and "signal 15" in report["error"]
        else:
            assert "intentional failure" in lab["error"]
        return
    assert case["exitCode"] == 0 and "error" not in report and "error" not in lab
    assert report["complete"] is case["expectedComplete"] and lab["complete"] is case["expectedComplete"]
    assert lab["reverse"] is case["reverse"] and lab["managementPort"] == case["managementPort"]
    expected = {"web": case["name"] != "untouched-starter", "management-marker": case["expectedComplete"], "unrequested": False}
    for name, allowed in expected.items():
        row = lab["policyRequests"][name]
        if allowed:
            check_body(row, report["token"], lab["worker"]["pid"])
        else:
            assert row["response"]["exitCode"] != 0 and row["body"] is None
    kernel = lab["activeAfterProbe"]["kernel"]
    policy = re.search(r"^:INPUT DROP \[(\d+):\d+\]$", kernel, re.MULTILINE)
    assert policy and int(policy[1]) > 0
    logging_hits = sum(int(match[1]) for match in re.finditer(r'^\[(\d+):\d+\] -A ufw-after-logging-input .* -j LOG\b', kernel, re.MULTILINE))
    assert logging_hits > 0
    assert "--dport 65530" in kernel and lab["priorRulePreserved"]
    assert str(lab["worker"]["pid"]) in lab["activeAfterProbe"]["listeners"]
    for port in (lab["managementPort"], 8080, 9090):
        assert f"10.77.0.2:{port}" in lab["activeAfterProbe"]["listeners"]
    if case["expectedComplete"]:
        assert f"--dport {case['managementPort']}" in kernel and "--dport 8080" in kernel
    if case["name"] == "wrong-management-port":
        assert "--dport 22" in kernel and f"--dport {case['managementPort']}" not in kernel
    assert len(lab["observations"]) == 9
    assert [row["service"] for row in lab["observations"][:3]] == (["unrequested", "web", "management-marker"] if case["reverse"] else ["management-marker", "web", "unrequested"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-only", action="store_true")
    parser.add_argument("--proof", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    proof = {"pack": PACK, "sourceHashes": source_checks(root), "nativeAccepted": False, "cases": [], "commands": [], "refusals": []}
    write_proof(args.proof, proof)
    if args.source_only:
        print(json.dumps({"sourceFiles": len(proof["sourceHashes"]), "sourceOnlyPassed": True, "nativeAccepted": False}))
        return
    assert sys.platform == "linux" and os.geteuid() == 0
    with tempfile.TemporaryDirectory(prefix="ns3-native-") as temporary:
        directory = Path(temporary)
        starter = root / PACK / "starter"
        reference = root / PACK / "solution"
        completed = directory / "completed"
        shutil.copytree(starter, completed)
        source = (completed / "policy-rules.sh").read_text()
        source = source.replace(": # TODO_MANAGEMENT", 'ufw allow "${MANAGEMENT_PORT}/tcp"').replace(": # TODO_WEB", 'ufw allow "Course Web"')
        assert "TODO_" not in source
        (completed / "policy-rules.sh").write_text(source)
        wrong = directory / "wrong-management"
        shutil.copytree(reference, wrong)
        (wrong / "policy-rules.sh").write_text((wrong / "policy-rules.sh").read_text().replace('"${MANAGEMENT_PORT}/tcp"', '"22/tcp"'))
        scenarios = [("untouched-starter", starter, False, 2222, False, "normal"),
                     ("completed-starter", completed, True, 2222, False, "normal"),
                     ("reference", reference, True, 2222, False, "normal"),
                     ("changed-management-port", reference, True, 22022, False, "normal"),
                     ("reverse-order", reference, True, 2222, True, "normal"),
                     ("wrong-management-port", wrong, False, 2222, False, "normal"),
                     ("failure", reference, False, 2222, False, "failure"),
                     ("cancellation", reference, False, 2222, False, "hold")]
        for name, folder, complete, port, reverse, mode in scenarios:
            output, ready = directory / (name + ".json"), directory / (name + "-ready.json")
            command = ["bash", str(folder / "apply_web_policy.sh"), "--output", str(output), "--management-port", str(port), "--test-mode", mode]
            if reverse:
                command.append("--reverse")
            if mode == "hold":
                command += ["--ready-file", str(ready)]
            code, stdout, stderr = run(command, proof["commands"], ready if mode == "hold" else None)
            case = {"name": name, "expectedComplete": complete, "managementPort": port, "reverse": reverse,
                    "mode": mode, "exitCode": code, "stdout": stdout, "stderr": stderr,
                    "report": json.loads(output.read_text()) if output.exists() else None}
            proof["cases"].append(case)
            write_proof(args.proof, proof)
            assert case["report"] is not None, (name, stdout, stderr)
            check_case(case)
        output = directory / "existing.json"
        output.write_text("keep the existing observation\n")
        link = directory / "linked.json"
        link.symlink_to(output)
        refusals = [("existing-report", ["bash", str(reference / "apply_web_policy.sh"), "--output", str(output)]),
                    ("symlink-report", ["bash", str(reference / "apply_web_policy.sh"), "--output", str(link)]),
                    ("missing-parent", ["bash", str(reference / "apply_web_policy.sh"), "--output", str(directory / "missing/report.json")]),
                    ("default-management-port", ["bash", str(reference / "apply_web_policy.sh"), "--output", str(directory / "refused.json"), "--management-port", "22"]),
                    ("direct-policy-script", ["bash", str(reference / "policy-rules.sh"), "management"]),
                    ("original-namespace", [sys.executable, str(reference / "firewall_runtime.py"), "--inside", "--origin", os.readlink("/proc/self/ns/net"), "--original-mount", os.readlink("/proc/self/ns/mnt")])]
        for name, command in refusals:
            code, stdout, stderr = run(command, proof["commands"])
            proof["refusals"].append({"name": name, "exitCode": code, "stdout": stdout, "stderr": stderr})
            write_proof(args.proof, proof)
            assert code != 0
        assert output.read_text() == "keep the existing observation\n" and link.is_symlink()
        assert sum(len(case["report"]["lab"]["observations"]) for case in proof["cases"]) == 66
        assert sum(row["body"] is not None for case in proof["cases"] for row in case["report"]["lab"]["observations"]) == 57
        proof.update(nativeAccepted=True, profiles=8, actualObservations=sum(len(case["report"]["lab"]["observations"]) for case in proof["cases"]),
                     successfulHTTPRequests=sum(row["body"] is not None for case in proof["cases"] for row in case["report"]["lab"]["observations"]),
                     reapedServices=8, actualPolicyRollbacks=8, refusalsVerified=6)
        write_proof(args.proof, proof)
        print(json.dumps({key: value for key, value in proof.items() if key not in ("cases", "commands", "sourceHashes", "refusals")}))


if __name__ == "__main__":
    main()
