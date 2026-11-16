"""Independent bounded-analysis and actual CLI checks for the six archive tasks."""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFINITIONS = json.loads((ROOT / "test/network_archive_six_cases.json").read_text())["definitions"]
PROCESSES = []
PROCESS_LOG = None


def run(argv, cwd):
    start = time.time()
    child = subprocess.Popen([str(x) for x in argv], cwd=cwd, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, start_new_session=True,
                             env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
    cleanup = "owned process group completed"
    out = err = b""
    if PROCESS_LOG:
        with PROCESS_LOG.open("a") as log:
            log.write(json.dumps({"event": "start", "parentTaskId": os.environ.get("CLASSES_FAMILY_TASK_ID", "network-archive-six"), "pid": child.pid, "parentPid": os.getpid(), "cwd": str(cwd), "command": [str(x) for x in argv], "startUnix": start, "timeoutSeconds": 10}) + "\n")
    try:
        out, err = child.communicate(timeout=10)
    except BaseException:
        cleanup = "owned process group terminated and reaped"
        if child.poll() is None:
            os.killpg(child.pid, signal.SIGTERM)
            try:
                out, err = child.communicate(timeout=2)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                out, err = child.communicate()
        raise
    finally:
        record = {"parentTaskId": os.environ.get("CLASSES_FAMILY_TASK_ID", "network-archive-six"),
                          "parentPid": os.getpid(), "pid": child.pid, "cwd": str(cwd),
                          "command": [str(x) for x in argv], "startUnix": start,
                          "endUnix": time.time(), "exitCode": child.returncode,
                          "timeoutSeconds": 10, "childProcessGroupCleanup": cleanup,
                          "stdout": out.decode(errors="replace"), "stderr": err.decode(errors="replace")}
        PROCESSES.append(record)
        if PROCESS_LOG:
            with PROCESS_LOG.open("a") as log:
                log.write(json.dumps(dict(record, event="end")) + "\n")
    assert not err, err.decode()
    return child.returncode, json.loads(out)


def load(folder):
    spec = importlib.util.spec_from_file_location("archive_analysis", folder / "archive_lab.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify():
    runtime = None
    files = {}
    cli = []
    controls = []
    with tempfile.TemporaryDirectory(prefix="network-archive-six-") as temp:
        temporary = Path(temp)
        for definition in DEFINITIONS:
            pack = ROOT / definition["pack"]
            for role in ["starter", "solution"]:
                folder = pack / role
                assert set(definition["roleFiles"]) == {p.name for p in folder.iterdir() if p.is_file()}
                assert "normalize_ports" not in (folder / "main.py").read_text()
                module = load(folder)
                records = module.load_records(folder / "observations.json")
                assert set(records) == {"baseline", "alternate", "route-gap", "wrong-upstream", "open-control"}
                source = (folder / "archive_lab.py").read_bytes()
                if runtime is None:
                    runtime = source
                assert source == runtime
                for name in definition["roleFiles"]:
                    files[definition["pack"] + "/" + role + "/" + name] = hashlib.sha256((folder / name).read_bytes()).hexdigest()
                # These expectations are derived from the independently retained
                # kernel/request records, not the apparatus's generated solution.
                base = module.facts(records["baseline"])
                assert base["application4"] == base["application6"] == "intended_application"
                assert base["control4"] == base["control6"] == "request_failed"
                assert base["backendBind4"] == "loopback" and base["backendBind6"] == "not_listed"
                assert base["directBackend"] == {"family": 6, "result": "request_failed"}
                assert base["readiness"] == "ready_for_conceptual_extension"
                for field in ["internetExposure", "vpnTunnel", "bgpPolicy", "wirelessSecurity", "cloudSecurityGroup", "otherClients"]:
                    assert base[field] == "not_established"
                gap = module.facts(records["route-gap"])
                assert gap["dns4"] == "matching_answer" and gap["route4"] == "failed"
                assert gap["application4"] == "request_failed" and gap["application6"] == "intended_application"
                assert gap["firstBoundary"] == "ipv4_route" and gap["readiness"] == "repair_baseline_first"
                wrong = module.facts(records["wrong-upstream"])
                assert wrong["route4"] == "selected"
                assert wrong["application4"] == wrong["application6"] == "wrong_application"
                assert wrong["firstBoundary"] == "application_identity"
                opened = module.facts(records["open-control"])
                assert opened["control4"] == opened["control6"] == "control_response"
                assert opened["application4"] == "intended_application" and opened["firstBoundary"] == "exposure_control"
                alternate = module.facts(records["alternate"])
                assert alternate["application4"] == alternate["application6"] == "intended_application"
                # Held negative controls: a convincing body at the wrong endpoint,
                # a non-listening denial control and incomplete observations.
                value = copy.deepcopy(records["baseline"])
                value["http4"]["command"]["command"][-1] = "http://198.18.32.2:8088/health"
                assert module.request_state(value, 4) == "wrong_endpoint"
                value = copy.deepcopy(records["baseline"])
                value["denied4"]["command"]["command"][-1] = "http://198.18.32.2:65534/health"
                assert module.request_state(value, 4, control=True) == "wrong_endpoint"
                assert module.first_boundary(value) == "exposure_control"
                value = copy.deepcopy(records["baseline"])
                value["listeners"]["stdout"] = "\n".join(line for line in value["listeners"]["stdout"].splitlines() if ":8088" not in line)
                assert module.first_boundary(value) == "collect_control_listener"
                assert module.readiness(value) == "collect_missing_evidence"
                value = copy.deepcopy(records["baseline"])
                del value["routeGet6"]
                assert module.first_boundary(value) == "collect_route"
                value = copy.deepcopy(records["baseline"])
                value["http4"]["status"] = "500"
                assert module.request_state(value, 4) == "unexpected_http_status"
                value = copy.deepcopy(records["baseline"])
                value["http4"]["command"]["exitCode"] = False
                assert module.request_state(value, 4) == "not_observed"
                value = copy.deepcopy(records["baseline"])
                value["completed"] = False
                assert module.facts(value) == base
                controls.append({"pack": definition["pack"], "role": role, "controls": ["baseline", "alternate", "route-gap", "wrong-upstream", "open-control", "correct-body-wrong-target", "non-listening-probe-target", "missing-control-listener", "missing-family-route", "HTTP500-is-a-response", "invalid-exit-is-unknown", "overall-verdict-not-trusted"]})

                status, report = run([sys.executable, folder / "main.py"], folder)
                assert status == (1 if role == "starter" else 0)
                assert report["objectiveChecksPassed"] is (role == "solution")
                assert report["liveNetworkRun"] is False and report["notebookCompletionInferred"] is False
                # Reading preserved input and inspecting separately collected
                # data are actual supported command paths.
                status, shown = run([sys.executable, folder / "main.py", "--show", "route-gap", "--field", "routeGet4"], folder)
                assert status == 0 and shown == records["route-gap"]["routeGet4"]
                observed = temporary / (definition["task"] + "-" + role + "-inside.json")
                observed.write_text(json.dumps(records["alternate"]))
                status, inspected = run([sys.executable, folder / "main.py", "--inspect", observed], folder)
                assert status == 0 and inspected["facts"]["application4"] == "intended_application"
                cli.append({"pack": definition["pack"], "role": role, "defaultExit": 1 if role == "starter" else 0,
                            "readableRawFieldChecked": True, "independentInsideFileChecked": True})
            files[definition["pack"] + "/README.md"] = hashlib.sha256((pack / "README.md").read_bytes()).hexdigest()
            # The reference fills only the assessment and its worked notebook.
            for name in definition["roleFiles"]:
                if name not in ["assessment.json", "network-notes.md"]:
                    assert (pack / "starter" / name).read_bytes() == (pack / "solution" / name).read_bytes()
            assert all(token in (pack / "README.md").read_text() for token in [
                "## Prepare and run", "--show", "--inspect", "198.18.32.2",
                "## Finish and review", "network-notes.md", "SOURCES.md"])
    for name, expected in files.items():
        assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == expected
    return {"acceptedWithinStatedScope": True, "sourcePairs": len(DEFINITIONS),
            "sourceFileHashes": files, "actualCLIProfiles": cli,
            "actualCLICommands": len(PROCESSES), "independentAnalysisControlGroups": sum(len(row["controls"]) for row in controls),
            "independentControls": controls,
            "sourceUnchanged": True, "recordedInputKind": "actual-isolated-linux-captures",
            "freshKernelExecutionClaimed": False, "notebookCompletionInferred": False,
            "processes": PROCESSES, "fullCourseSignoff": False, "fullGoalComplete": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--proof", required=True, type=Path)
    args = parser.parse_args()
    args.proof.parent.mkdir(parents=True, exist_ok=True)
    PROCESS_LOG = args.proof.with_suffix(".processes.jsonl")
    try:
        result = verify()
    except BaseException:
        args.proof.write_text(json.dumps({"acceptedWithinStatedScope": False, "processes": PROCESSES}, indent=2) + "\n")
        raise
    args.proof.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: v for k, v in result.items() if k not in ["sourceFileHashes", "processes", "actualCLIProfiles", "independentControls"]}))
