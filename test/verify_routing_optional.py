"""Check actual routed peers, mappings and exposure before accepting a task."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile

from kernel_optional_source import CASES, ROOT, digest, source_checks
from verify_topology import check_cleanup, check_flows, now, run

BASE_STAGES = ["forwarding-off", "routed", "snat", "dnat", "mapping-removed", "direct-after-removal"]
POLICY_STAGES = ["policy-baseline-direct", "policy-baseline-mapped", "policy-mapped-allowed",
                 "policy-direct-blocked", "policy-direct-restored"]
BASE_PEERS = [None, "10.10.0.2", "10.20.0.1", "10.20.0.1", None, "10.20.0.1"]
STARTER_PEERS = {
    "snat-source": [None, "10.10.0.2", "10.10.0.2", "10.10.0.2", None, "10.10.0.2"],
    "dnat-port": [None, "10.10.0.2", "10.20.0.1", None, None, "10.20.0.1"],
    "exposure-bypass": BASE_PEERS + ["10.20.0.1"] * 5,
    "exposure-port": BASE_PEERS + ["10.20.0.1", "10.20.0.1", None, None, "10.20.0.1"],
}


def check_observations(data, kind, corrected, mode):
    check_cleanup(data)
    lab = data["lab"]
    exposure = kind.startswith("exposure-")
    assert lab["exposurePolicyRequested"] is exposure
    assert lab["worker"]["reaped"]
    rows = lab["observations"]
    if mode != "normal":
        assert lab.get("error") and lab["complete"] is False
        if mode == "cancellation":
            assert lab["error"] == data.get("error") == "lab interrupted; cleaning up owned resources"
            check_flows(data, True, policy_complete=True, interrupted=True)
            assert [r["stage"] for r in rows] == BASE_STAGES + POLICY_STAGES[:2]
            assert re.search(r"^:FORWARD DROP \[\d+:\d+\]$", lab["policyBeforeInterruption"], re.M)
        else:
            assert lab["error"] == "intentional failure after owned topology setup"
        return
    assert "error" not in lab and "error" not in data
    stages = BASE_STAGES + (POLICY_STAGES if exposure else [])
    peers = (BASE_PEERS + (["10.20.0.1", "10.20.0.1", "10.20.0.1", None, "10.20.0.1"]
             if exposure else [])) if corrected else STARTER_PEERS[kind]
    assert [row["stage"] for row in rows] == stages
    for row, peer in zip(rows, peers):
        response = row["response"]
        assert row["forwarding"] == ("0" if row["stage"] == "forwarding-off" else "1")
        if peer is None:
            assert response["exitCode"] != 0 and response["body"] is None
        else:
            assert response["exitCode"] == 0
            expected = {"token": data["token"], "peer": peer, "server": "10.20.0.2", "port": 8080, "path": "/lab"}
            assert response["body"] == json.loads(response["stdout"]) == expected
    assert lab["baseComplete"] is (corrected or exposure)
    assert lab["complete"] is corrected
    translated, mapped = rows[2]["natRules"], rows[3]["natRules"]
    if kind == "snat-source":
        source = "10.10.0.0/24" if corrected else "10.99.0.0/24"
        assert "-s " + source in translated
    assert "-j SNAT --to-source 10.20.0.1" in translated
    port = 8081 if kind == "dnat-port" and not corrected else 8080
    assert "-j DNAT --to-destination 10.20.0.2:" + str(port) in mapped
    assert "-j DNAT" not in rows[4]["natRules"] and "-j SNAT" in rows[4]["natRules"]
    if exposure:
        rules = rows[9]["filterRules"]
        policy = re.search(r"^:FORWARD DROP \[(\d+):\d+\]$", rules, re.M)
        assert policy and "--ctstate NEW" in rules and "--ctdir ORIGINAL" in rules
        assert "--ctstate RELATED,ESTABLISHED" in rules or "--ctstate ESTABLISHED,RELATED" in rules
        if kind == "exposure-bypass" and not corrected:
            assert "--ctorigdstport" not in rules
        else:
            assert "--ctorigdst 10.10.0.1" in rules and "--ctorigdstport 18080" in rules
        new_rules = [line for line in rules.splitlines() if "-A FORWARD" in line and "--ctstate NEW" in line]
        assert len(new_rules) == 1
        assert "--dport " + ("18080" if kind == "exposure-port" and not corrected else "8080") in new_rules[0]
        if corrected:
            assert int(policy[1]) > 0 and lab["policyCounters"]["newMappedAccepted"] > 0
            assert lab["policyCounters"]["establishedAccepted"] > 0
        assert re.search(r"^:FORWARD ACCEPT \[\d+:\d+\]$", rows[-1]["filterRules"], re.M)
        assert "-A FORWARD" not in rows[-1]["filterRules"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proof", type=Path, required=True)
    parser.add_argument("--source-only", action="store_true")
    parser.add_argument("--exported-source", action="store_true")
    args = parser.parse_args()
    args.proof = args.proof.resolve()
    raw = args.proof.parent / "routing-optional-raw"
    raw.mkdir(parents=True, exist_ok=False)
    proof = {"at": now(), "nativeAccepted": False, "processes": [], "runs": []}
    try:
        proof["sourceFiles"] = source_checks("routing", run, proof["processes"], args.exported_source)
        if args.source_only:
            return
        assert sys.platform == "linux" and os.geteuid() == 0
        with tempfile.TemporaryDirectory(prefix="network-routing-optional-") as temporary:
            root = Path(temporary)
            for definition in CASES["routing"]:
                pack, kind = definition["pack"], definition["kind"]
                for variant in ["starter", "solution", "corrected"]:
                    work = root / (kind + "-" + variant + " quoted workspace")
                    shutil.copytree(ROOT / pack / ("starter" if variant == "corrected" else variant), work)
                    if variant == "corrected":
                        original = (work / "lab-rules.sh").read_text()
                        reference = (ROOT / pack / "solution/lab-rules.sh").read_text()
                        pattern = re.compile(r"^  " + definition["stage"] + r"\)\n.*?^    ;;", re.M | re.S)
                        old_case, new_case = pattern.search(original), pattern.search(reference)
                        assert old_case and new_case
                        fixed = original[:old_case.start()] + new_case.group() + original[old_case.end():]
                        assert len(original.splitlines()) == len(fixed.splitlines())
                        assert sum(a != b for a, b in zip(original.splitlines(), fixed.splitlines())) == 1
                        (work / "lab-rules.sh").write_text(fixed)
                    assert digest(work / "lab_runtime.py") == CASES["qualifiedApparatus"]["routing"]["lab_runtime.py"]
                    label = kind + "-" + variant
                    observe(work, label, kind, variant != "starter", "normal", definition["exposure"], raw, proof)
            for kind, mode in [("snat-source", "failure"), ("exposure-port", "cancellation")]:
                definition = next(r for r in CASES["routing"] if r["kind"] == kind)
                work = ROOT / definition["pack"] / "solution"
                observe(work, kind + "-" + mode, kind, True, mode, definition["exposure"], raw, proof)
        assert source_checks("routing", run, proof["processes"], args.exported_source) == proof["sourceFiles"]
        proof.update(nativeAccepted=True, actualProfiles=len(proof["runs"]), oneFileCorrections=4,
                     observedHTTPRequests=sum(len(r["evidence"]["lab"]["observations"]) for r in proof["runs"]),
                     actualHostAndNamespaceCleanupVerified=True, unchangedQualifiedApparatus=True)
    finally:
        proof["endedAt"] = now()
        args.proof.parent.mkdir(parents=True, exist_ok=True)
        args.proof.write_text(json.dumps(proof, indent=2) + "\n")
    print(json.dumps({k: v for k, v in proof.items() if k not in ["sourceFiles", "processes", "runs"]}))


def observe(work, label, kind, corrected, mode, exposure, raw, proof):
    report, ready = raw / (label + ".json"), raw / (label + "-ready.txt")
    argv = ["bash", str(work / "create_nat_lab.sh"), "--output", str(report),
            "--test-mode", mode, "--ready-file", str(ready)]
    if exposure:
        argv.append("--exposure-policy")
    code, stdout, stderr = run(argv, proof["processes"], ready if mode == "cancellation" else None)
    (raw / (label + ".stdout")).write_text(stdout)
    (raw / (label + ".stderr")).write_text(stderr)
    assert code == (0 if mode == "normal" else 1), (label, code, stderr)
    data = json.loads(report.read_text())
    proof["runs"].append({"profile": label, "kind": kind, "corrected": corrected, "mode": mode,
                          "exitCode": code, "rawReport": str(report), "rawSHA256": digest(report), "evidence": data})
    check_observations(data, kind, corrected, mode)


if __name__ == "__main__":
    main()
