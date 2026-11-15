"""Measure actual optional firewall corrections in owned private namespaces."""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile

from verify_ufw import check_body, normalized_rules, now, run, write_proof

ROOT = Path(__file__).resolve().parents[1]
PACKS = ["NS-19-unit-9-firewalls-and-host-policy-supplemental-2",
         "NS-20-unit-9-firewalls-and-host-policy-supplemental-3"]
ROLE_FILES = ["README.md", "network-notes.md", "apply_web_policy.sh",
              "policy-rules.sh", "web-stack.profile", "firewall_runtime.py"]

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def source_checks():
    base = ROOT / "NS3-UFW-Web-Server-Policy/solution"
    hashes = {}
    for index, pack in enumerate(PACKS):
        folder = ROOT / pack
        for name in ["README.md"] + [role + "/" + name for role in ["starter", "solution"]
                                      for name in ROLE_FILES]:
            path = folder / name
            hashes[pack + "/" + name] = digest(path)
            if path.suffix == ".py":
                ast.parse(path.read_text(), feature_version=(3, 10))
        for role in ["starter", "solution"]:
            assert not (folder / role / "main.py").exists()
            for name in ["firewall_runtime.py", "apply_web_policy.sh"]:
                assert (folder / role / name).read_bytes() == (base / name).read_bytes()
            policy = (base / "policy-rules.sh").read_text()
            if role == "starter" and index == 0:
                policy = policy.replace('ufw allow "${MANAGEMENT_PORT}/tcp"', 'ufw allow "2222/tcp"')
            assert (folder / role / "policy-rules.sh").read_text() == policy
            profile = (base / "web-stack.profile").read_text()
            if role == "starter" and index == 1:
                profile = profile.replace("ports=8080/tcp", "ports=8080,9090/tcp")
            assert (folder / role / "web-stack.profile").read_text() == profile
        guide = (folder / "README.md").read_text()
        assert all(word in guide for word in ["console access", "--management-port 22022",
                                             "rollback", "IPv4", "Python programming is optional"])
    return hashes

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
    expected = case["expectedReachability"]
    for name, allowed in expected.items():
        row = lab["policyRequests"][name]
        if allowed:
            check_body(row, report["token"], lab["worker"]["pid"])
        else:
            assert row["response"]["exitCode"] != 0 and row["body"] is None
    kernel = lab["activeAfterProbe"]["kernel"]
    policy = re.search(r"^:INPUT DROP \[(\d+):\d+\]$", kernel, re.MULTILINE)
    assert policy
    if not all(expected.values()):
        assert int(policy[1]) > 0
    logging_hits = sum(int(match[1]) for match in re.finditer(r'^\[(\d+):\d+\] -A ufw-after-logging-input .* -j LOG\b', kernel, re.MULTILINE))
    if not all(expected.values()):
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
    args.proof = args.proof.resolve()
    raw = args.proof.parent / "ufw-optional-raw"
    raw.mkdir(parents=True, exist_ok=False)
    proof = {"at": now(), "nativeAccepted": False, "sourceFiles": source_checks(),
             "cases": [], "commands": [], "refusals": []}
    write_proof(args.proof, proof)
    if args.source_only:
        print(json.dumps({"sourceChecks": True, "sourceFiles": len(proof["sourceFiles"]),
                          "nativeAccepted": False}))
        return
    assert sys.platform == "linux" and os.geteuid() == 0
    try:
        with tempfile.TemporaryDirectory(prefix="network-optional-ufw-") as temporary:
            directory = Path(temporary)
            corrected_port = directory / "corrected-port"
            corrected_profile = directory / "corrected-profile"
            wrong_protocol = directory / "wrong-protocol"
            shutil.copytree(ROOT / PACKS[0] / "starter", corrected_port)
            shutil.copytree(ROOT / PACKS[1] / "starter", corrected_profile)
            shutil.copytree(ROOT / PACKS[1] / "solution", wrong_protocol)
            runtime_hashes = [digest(folder / "firewall_runtime.py")
                              for folder in [corrected_port, corrected_profile, wrong_protocol]]
            policy = corrected_port / "policy-rules.sh"
            policy.write_text(policy.read_text().replace('ufw allow "2222/tcp"',
                              'ufw allow "${MANAGEMENT_PORT}/tcp"'))
            profile = corrected_profile / "web-stack.profile"
            profile.write_text(profile.read_text().replace("ports=8080,9090/tcp", "ports=8080/tcp"))
            profile = wrong_protocol / "web-stack.profile"
            profile.write_text(profile.read_text().replace("ports=8080/tcp", "ports=8080/udp"))
            assert [digest(folder / "firewall_runtime.py")
                    for folder in [corrected_port, corrected_profile, wrong_protocol]] == runtime_hashes
            p = ROOT / PACKS[0]
            e = ROOT / PACKS[1]
            scenarios = [
                ("port-starter-default-control", p / "starter", True, 2222, False, "normal", [True, True, False]),
                ("port-starter-changed", p / "starter", False, 22022, False, "normal", [False, True, False]),
                ("port-reference-changed", p / "solution", True, 22022, False, "normal", [True, True, False]),
                ("port-corrected-default", corrected_port, True, 2222, False, "normal", [True, True, False]),
                ("port-corrected-changed-reverse", corrected_port, True, 22022, True, "normal", [True, True, False]),
                ("profile-starter-exposes-unrequested", e / "starter", False, 2222, False, "normal", [True, True, True]),
                ("profile-reference-changed", e / "solution", True, 22022, False, "normal", [True, True, False]),
                ("profile-corrected-reverse", corrected_profile, True, 2222, True, "normal", [True, True, False]),
                ("profile-wrong-protocol-control", wrong_protocol, False, 2222, False, "normal", [True, False, False]),
                ("port-reference-failure", p / "solution", False, 22022, False, "failure", None),
                ("profile-reference-cancellation", e / "solution", False, 2222, False, "hold", None),
            ]
            for name, folder, complete, port, reverse, mode, allowed in scenarios:
                output, ready = raw / (name + ".json"), raw / (name + "-ready.json")
                argv = ["bash", str(folder / "apply_web_policy.sh"), "--output", str(output),
                        "--management-port", str(port), "--test-mode", mode]
                if reverse:
                    argv.append("--reverse")
                if mode == "hold":
                    argv += ["--ready-file", str(ready)]
                code, stdout, stderr = run(argv, proof["commands"], ready if mode == "hold" else None)
                (raw / (name + ".stdout")).write_text(stdout)
                (raw / (name + ".stderr")).write_text(stderr)
                case = {"name": name, "expectedComplete": complete, "managementPort": port,
                        "reverse": reverse, "mode": mode, "exitCode": code,
                        "expectedReachability": dict(zip(["management-marker", "web", "unrequested"], allowed))
                                                if allowed is not None else None,
                        "report": json.loads(output.read_text()) if output.exists() else None,
                        "rawReport": str(output), "rawSHA256": digest(output) if output.exists() else None}
                proof["cases"].append(case)
                write_proof(args.proof, proof)
                assert case["report"] is not None, (name, stdout, stderr)
                check_case(case)
                if name == "port-starter-changed":
                    kernel = case["report"]["lab"]["activeAfterProbe"]["kernel"]
                    assert "--dport 2222" in kernel and "--dport 22022" not in kernel
                if name == "profile-starter-exposes-unrequested":
                    kernel = case["report"]["lab"]["activeAfterProbe"]["kernel"]
                    assert re.search(r"(?:--dports 8080,9090|--dport 9090)", kernel)
            reference = e / "solution"
            kept = directory / "kept.json"
            kept.write_text("Keep the earlier observation.\n")
            refusals = [
                ("existing-report", ["bash", str(reference / "apply_web_policy.sh"), "--output", str(kept)]),
                ("direct-policy", ["bash", str(reference / "policy-rules.sh"), "management"]),
                ("original-namespace", [sys.executable, str(reference / "firewall_runtime.py"), "--inside",
                 "--origin", os.readlink("/proc/self/ns/net"), "--original-mount", os.readlink("/proc/self/ns/mnt")])]
            for name, argv in refusals:
                code, stdout, stderr = run(argv, proof["commands"])
                proof["refusals"].append({"name": name, "exitCode": code, "stdout": stdout, "stderr": stderr})
                assert code != 0
            assert kept.read_text() == "Keep the earlier observation.\n"
            assert source_checks() == proof["sourceFiles"]
            proof.update(nativeAccepted=True, actualProfiles=len(proof["cases"]),
                         actualObservations=sum(len(c["report"]["lab"]["observations"]) for c in proof["cases"]),
                         successfulHTTPRequests=sum(row["body"] is not None for c in proof["cases"]
                           for row in c["report"]["lab"]["observations"]),
                         oneFileCorrections=2, incorrectDefaultSuccessDemonstrated=True,
                         actualOverexposureDemonstrated=True, wrongProtocolRejected=True,
                         actualPolicyRollbacks=len(proof["cases"]), hostUnchangedInAllProfiles=True,
                         isolationGuardsUnchanged=True, allRoleRuntimesMatchCore=True, sharedHostComparisonFix=True)
    finally:
        proof["endedAt"] = now()
        write_proof(args.proof, proof)
    print(json.dumps({k: v for k, v in proof.items() if k not in ["sourceFiles", "cases", "commands", "refusals"]}))

if __name__ == "__main__":
    main()
