"""Reproduce or reject the owned proxy-target identity counterexample."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import verify_capstone as v

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--proof", type=Path, required=True)
    parser.add_argument("--expect-wrong-accepted", action="store_true",
                        help="Historical baseline reproduction only, never fixed-source acceptance")
    args = parser.parse_args()
    proof = args.proof.resolve()
    proof.parent.mkdir(parents=True, exist_ok=True)
    retained = proof.parent / "proxy-identity-observations"
    retained.mkdir(exist_ok=False)
    v.RETAINED = retained
    v.PROCESS_LOG = proof.with_suffix(".processes.jsonl")
    source = v.ROOT / v.PACK / "solution"
    before = v.hashes(source)
    rows = []
    with tempfile.TemporaryDirectory(prefix="owned-capstone-proxy-identity-") as temp:
        work = Path(temp)
        for port in [9000, 8088]:
            folder = work / ("source-" + str(port))
            shutil.copytree(source, folder)
            (folder / "case.json").write_text(json.dumps(dict(v.CORRECT, proxy_upstream_port=port)) + "\n")
            for alternate in [False, True]:
                label = str(port) + ("-alternate" if alternate else "-default")
                output, trace = work / label, work / (label + ".strace")
                argv = ["strace", "-f", "-e", "trace=connect", "-s", "256", "-o", trace,
                        sys.executable, folder / "main.py", "--output", output]
                if alternate:
                    argv.append("--alternate")
                result, _ = v.run(argv, folder)
                parent, lab, commands = v.cleanup_evidence(output)
                text = trace.read_text()
                actual_upstream_connects = [line for line in text.splitlines()
                    if "connect(" in line and "AF_INET," in line
                    and "sin_port=htons(" + str(port) + ")" in line
                    and 'sin_addr=inet_addr("127.0.0.1")' in line]
                assert len(actual_upstream_connects) >= 3, actual_upstream_connects
                service = [json.loads(line) for line in (output / "service.log").read_text().splitlines()
                           if line.startswith("{")]
                assert len(service) == 1 and service[0]["proxyTarget"] == port
                independently_accepted = False
                try:
                    v.completed_evidence(output, alternate)
                except AssertionError:
                    pass
                else:
                    independently_accepted = True
                wanted = port == 9000 or args.expect_wrong_accepted
                assert independently_accepted == wanted
                assert bool(lab["completed"]) == wanted
                assert result["exitCode"] == parent["exitCode"] == (0 if wanted else 1)
                for family in ["http4", "http6"]:
                    assert lab[family]["command"]["exitCode"] == 0 and lab[family]["status"] == "200"
                    body = json.loads(lab[family]["body"])
                    assert body["token"] == lab["token"] and body["path"] == "/health"
                    if wanted:
                        assert body["fixture"] == "owned-operations-capstone"
                    else:
                        assert body["fixture"] == "owned-denial-control"
                if not wanted:
                    assert lab["missingPath"]["status"] == "404"
                saved = retained / (label + ".strace")
                saved.write_bytes(trace.read_bytes())
                rows.append({"port": port, "alternate": alternate, "process": result,
                             "actualLoopbackUpstreamConnects": actual_upstream_connects,
                             "traceSHA256": hashlib.sha256(trace.read_bytes()).hexdigest(),
                             "completed": lab["completed"],
                             "independentCompletedVerifierAccepts": independently_accepted,
                             "case": lab["case"], "rawPacketEvidence": v.packet_observations(output / "capture.pcap"),
                             "hostUnchanged": parent["hostUnchanged"], "allWorkersReaped": lab["allWorkersReaped"]})
    assert before == v.hashes(source)
    proof.write_text(json.dumps({"event": "capstone-proxy-identity-baseline" if args.expect_wrong_accepted else "capstone-proxy-identity-fixed",
                                "sourceFileHashes": before, "profiles": rows,
                                "historicalBugReproduced": args.expect_wrong_accepted,
                                "wrongTargetRejected": not args.expect_wrong_accepted,
                                "isFixedSourceAcceptance": not args.expect_wrong_accepted,
                                "evidenceFiles": v.hashes(retained)}, indent=2) + "\n")
    print(json.dumps({"profiles": len(rows), "historicalBugReproduced": args.expect_wrong_accepted,
                      "wrongTargetRejected": not args.expect_wrong_accepted}))

if __name__ == "__main__":
    main()
