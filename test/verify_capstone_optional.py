"""Verify two optional routed capstone tasks with actual kernel and response evidence."""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import shutil
import sys
import tempfile
import verify_capstone as v

ROOT = Path(__file__).resolve().parents[1]
CASES = json.loads((ROOT / "test/network_capstone_optional_cases.json").read_text())

def source_checks(exported=False):
    hashes = {}
    for definition in CASES["definitions"]:
        pack = ROOT / definition["pack"]
        assert definition["title"] in (pack / "README.md").read_text()
        for role in ["starter", "solution"]:
            folder = pack / role
            assert set(CASES["roleFiles"]) == {p.name for p in folder.iterdir() if p.is_file()}
            assert hashlib.sha256((folder / "capstone_lab.py").read_bytes()).hexdigest() == CASES["runtimeSHA256"]
            assert hashlib.sha256((folder / "main.py").read_bytes()).hexdigest() == CASES["launcherSHA256"]
            expected = definition["starterCase"] if role == "starter" else CASES["correctCase"]
            assert json.loads((folder / "case.json").read_text()) == expected
        hashes.update({definition["pack"] + "/" + k: val for k, val in v.hashes(pack).items()})
    assert len(hashes) == 22
    if not exported:
        for role in ["starter", "solution"]:
            assert hashlib.sha256((ROOT / v.PACK / role / "capstone_lab.py").read_bytes()).hexdigest() == CASES["runtimeSHA256"]
    return hashes

def inspect_unfinished(output, kind):
    parent, lab, commands = v.cleanup_evidence(output)
    assert parent["exitCode"] == 1 and not parent["cancelled"] and not lab["completed"] and not lab["interrupted"]
    if kind == "prefix":
        prefix = ipaddress.ip_network(lab["case"]["ipv4_service_route"])
        assert str(prefix) == "198.18.32.0/31"
        assert ipaddress.ip_address("198.18.32.1") in prefix
        assert ipaddress.ip_address(lab["server4"]) not in prefix
        assert lab["routeGet4"]["exitCode"] != 0 and lab["http4"]["status"] == "000"
        assert lab["routeGetServerRouter4"]["exitCode"] == 0
        assert "198.18.32.1 via " in lab["routeGetServerRouter4"]["stdout"]
        assert lab["dns"]["A"]["stdout"].strip() == "198.18.32.2"
        assert lab["http6"]["status"] == "200"
        assert json.loads(lab["http6"]["body"])["fixture"] == "owned-operations-capstone"
        first = "IPv4 route-prefix coverage"
    else:
        assert lab["case"]["proxy_upstream_port"] == 8088
        assert lab["routeGet4"]["exitCode"] == lab["routeGet6"]["exitCode"] == 0
        ready = [json.loads(line) for line in (output / "service.log").read_text().splitlines() if line.startswith("{")]
        assert len(ready) == 1 and ready[0]["proxyTarget"] == 8088
        for key in ["http4", "http6"]:
            result = lab[key]
            assert result["command"]["exitCode"] == 0 and result["status"] == "200"
            assert json.loads(result["body"]) == {"fixture": "owned-denial-control", "token": lab["token"], "path": "/health"}
        assert lab["missingPath"]["status"] == "404"
        first = "intended responding application identity"
    packet = v.packet_observations(output / "capture.pcap")
    assert {(a["type"], a["address"]) for a in packet["answers"]} >= {(1, "198.18.32.2"), (28, "2001:db8:32::2")}
    return {"firstFailingBoundary": first, "case": lab["case"], "packetEvidence": packet,
            "hostUnchanged": True, "commandRecords": len(commands), "notebookCompletionInferred": False}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--proof", type=Path, required=True)
    parser.add_argument("--source-only", action="store_true")
    parser.add_argument("--exported", action="store_true")
    args = parser.parse_args()
    source = source_checks(args.exported)
    args.proof.parent.mkdir(parents=True, exist_ok=True)
    if args.source_only:
        args.proof.write_text(json.dumps({"sourceFileHashes": source, "sourceOnly": True, "nativeAcceptance": False}, indent=2) + "\n")
        print(json.dumps({"sourceFiles": len(source), "nativeAcceptance": False}))
        return
    retained = args.proof.parent / "capstone-optional-observations"
    retained.mkdir(exist_ok=False)
    v.RETAINED = retained
    v.PROCESS_LOG = args.proof.with_suffix(".processes.jsonl")
    profiles = []
    with tempfile.TemporaryDirectory(prefix="owned-capstone-optional-") as temp:
        work = Path(temp)
        for definition in CASES["definitions"]:
            pack = ROOT / definition["pack"]
            corrected = work / (definition["kind"] + "-corrected-source")
            shutil.copytree(pack / "starter", corrected)
            (corrected / "case.json").write_bytes((pack / "solution/case.json").read_bytes())
            original, complete = v.hashes(pack / "starter"), v.hashes(corrected)
            assert {k for k in original if original[k] != complete[k]} == {"case.json"}
            for role, folder in [("starter", pack / "starter"), ("solution", pack / "solution"), ("corrected", corrected)]:
                for alternate in [False, True]:
                    label = definition["kind"] + "-" + role + ("-alternate" if alternate else "-default")
                    output = work / label
                    argv = [sys.executable, folder / "main.py", "--output", output] + (["--alternate"] if alternate else [])
                    result, _ = v.run(argv, folder)
                    if role == "starter":
                        assert result["exitCode"] == 1, result
                        evidence = inspect_unfinished(output, definition["kind"])
                    else:
                        assert result["exitCode"] == 0, result
                        evidence = v.completed_evidence(output, alternate)
                    profiles.append({"pack": definition["pack"], "kind": definition["kind"], "role": role,
                                     "alternate": alternate, "process": result, "evidence": evidence})
            assert complete == v.hashes(corrected)
        # A cloned success body cannot hide the wrong selected backend endpoint.
        alias = work / "control-identity-alias"
        shutil.copytree(ROOT / CASES["definitions"][1]["pack"] / "starter", alias)
        helper = (alias / "capstone_lab.py").read_bytes()
        old = b'fixture_identity = "owned-denial-control"'
        assert helper.count(old) == 1
        (alias / "capstone_lab.py").write_bytes(helper.replace(old, b'fixture_identity = "owned-operations-capstone"'))
        output = work / "aliased-control-output"
        result, _ = v.run([sys.executable, alias / "main.py", "--output", output], alias)
        parent, lab, _ = v.cleanup_evidence(output)
        assert result["exitCode"] == 1 and not lab["completed"]
        assert all(lab[key]["status"] == "200" and json.loads(lab[key]["body"])["fixture"] == "owned-operations-capstone" for key in ["http4", "http6"])
        try:
            v.completed_evidence(output, False)
        except AssertionError:
            rejected = True
        else:
            rejected = False
        assert rejected
        regression = {"process": result, "sameIdentityAndTokenStillRejectedForWrongEndpoint": True,
                      "case": lab["case"], "hostUnchanged": parent["hostUnchanged"]}
        output = work / "live-interruption"
        folder = ROOT / CASES["definitions"][0]["pack"] / "solution"
        result, runtime = v.run([sys.executable, folder / "main.py", "--hold-after-ready", "15", "--output", output],
                                folder, interrupted_output=output)
        parent, lab, _ = v.cleanup_evidence(output)
        assert result["exitCode"] == 130 and parent["cancelled"] and lab["interrupted"]
        assert runtime and all(not Path("/proc/" + str(row["pid"])).exists() for row in runtime["workers"])
        interruption = {"process": result, "liveNamespacesAndWorkers": runtime, "allWorkersReaped": True}
    assert source == source_checks(args.exported)
    assert not Path(temp).exists()
    proof = {"event": "verified-capstone-optional-source", "sourceFileHashes": source,
             "profiles": profiles, "actualProfiles": 14, "controlledIdentityAlias": regression,
             "liveInterruption": interruption, "independentCompletionChangesOnlyCase": True,
             "sourceUnchanged": True, "temporaryBuildCleanup": True,
             "notebookCompletionInferred": False, "evidenceFiles": v.hashes(retained)}
    args.proof.write_text(json.dumps(proof, indent=2) + "\n")
    print(json.dumps({"sourceFiles": len(source), "profiles": 12, "aliasRegressions": 1, "liveInterruptions": 1}))

if __name__ == "__main__":
    main()
