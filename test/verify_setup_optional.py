"""Independently verify actual command selection, cwd and argv with Linux strace."""
import argparse
import ast
import contextlib
import datetime
import hashlib
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKS = {
    "context": "NS-01-ns0-setup-and-tooling-supplemental-2",
    "arguments": "NS-02-ns0-setup-and-tooling-supplemental-3"
}
CORRECT = {"context": {"first_tool": "beta", "work_area": "second"},
           "arguments": {"quote_arguments": True}}
PROCESS_LOG = []
REQUIRED = {"main.py", "setup_lab.py", "case.json", "network-notes.md", "edge-cases.md"}


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()  # noqa: UP017


def hashes(folder):
    return {str(p.relative_to(folder)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(folder.rglob("*")) if p.is_file()}


def command(argv, cwd):
    argv = [str(x) for x in argv]
    started = now()
    child = subprocess.Popen(argv, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             text=True, start_new_session=True,
                             env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
    cleanup = "process exited"
    try:
        stdout, stderr = child.communicate(timeout=90)
    except BaseException:
        cleanup = "owned verifier process group terminated and reaped"
        with contextlib.suppress(ProcessLookupError):
            os.killpg(child.pid, signal.SIGTERM)
        try:
            child.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(child.pid, signal.SIGKILL)
            child.communicate(timeout=3)
        raise
    finally:
        row = {"parentTaskId": "network-setup-native-validation", "command": argv,
               "cwd": str(cwd), "pid": child.pid, "startTime": started, "endTime": now(),
               "exitCode": child.returncode, "timeoutSeconds": 90,
               "childProcessGroupCleanup": cleanup}
        PROCESS_LOG.append(row)
    return dict(row, stdout=stdout, stderr=stderr)


def parse_trace(path):
    rows = []
    raw = path.read_text()
    for line in raw.splitlines():
        match = re.match(r"^(\d+)\s+(execve|chdir)\((.*)\)\s+=\s+(.+)$", line)
        if not match:
            assert "unfinished" not in line and "resumed>" not in line, line
            continue
        pid, operation, fields, status = match.groups()
        tokens = [json.loads('"' + value + '"')
                  for value in re.findall(r'"((?:\\.|[^"\\])*)"', fields)]
        assert tokens, line
        rows.append({"pid": int(pid), "operation": operation, "tokens": tokens,
                     "success": status == "0", "status": status, "raw": line})
    assert rows and any(row["operation"] == "execve" and row["success"] for row in rows)
    return rows


def worker_source(folder):
    module = ast.parse((folder / "setup_lab.py").read_text())
    node = next(node for node in module.body if isinstance(node, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == "WORKER" for t in node.targets))
    return ast.literal_eval(node.value)


def validate(folder, mode, report, trace, alternate, expected_complete):
    payload = json.loads(report.read_text())
    assert payload["event"] == "owned-setup-" + mode and payload["mode"] == mode
    assert payload["alternate"] == alternate
    assert payload["case"] == json.loads((folder / "case.json").read_text())
    expected_source = {name: hashlib.sha256((folder / name).read_bytes()).hexdigest()
                       for name in REQUIRED}
    assert payload["sourceFileHashes"] == expected_source
    assert payload["sourceUnchanged"] and payload["temporaryBuildCleanup"]
    assert payload["allExecutedTargetsReaped"] and payload["notebookCompletionNotInferred"]
    before = payload["parentBefore"]
    assert payload["parentUnchanged"] and before == payload["parentAfter"]
    assert before["uid"] == os.getuid() != 0
    assert before["hostname"] == os.uname().nodename
    assert before["cwd"] == str(folder)
    assert before["networkNamespace"] == os.readlink("/proc/self/ns/net")
    assert before["mountNamespace"] == os.readlink("/proc/self/ns/mnt")
    root = Path(payload["temporaryRoot"])
    assert root.name.startswith("owned-setup-space-") and not root.exists()
    worker = root / "owned worker.py"
    tool = "course-context-alt" if alternate else "course-context"
    assert payload["tool"] == tool
    observation = payload["observation"]
    assert observation["configuredMatchesGoal"] == expected_complete
    assert observation["areas"] == {"first": str(root / "north work"), "second": str(root / "south work")}
    assert payload["fixtureFiles"]["owned worker.py"] == worker_source(folder)
    assert set(payload["fixtureFiles"]) == {"owned worker.py", "alpha bin/" + tool, "beta bin/" + tool}
    for tag in ["alpha", "beta"]:
        expected = "#!/bin/sh\nexec " + shlex.quote(payload["pythonExecutable"]) + " -I " + shlex.quote(str(worker)) + " " + tag + ' "$@"\n'
        assert payload["fixtureFiles"][tag + " bin/" + tool] == expected
    events = parse_trace(trace)
    records = observation["stages"]
    assert [row["stage"] for row in records] == (
        ["path-alpha", "path-beta", "cwd-second", "missing-path", "absolute-without-path", "configured"]
        if mode == "context" else
        ["direct-arguments", "shell-quoted", "shell-unquoted", "configured"])
    successful = []
    selected_events = []
    desired = ["changed three words", "*.data", "owned; note"] if alternate else ["two words", "*.txt", "left; right"]
    glob_names = ["amber.data", "blue.data"] if alternate else ["one.txt", "two.txt"]
    split_arguments = desired[0].split() + glob_names + desired[2].split()
    if mode == "arguments":
        assert observation["desiredArguments"] == desired and observation["globFiles"] == glob_names
    for row in records:
        stage = row["stage"]
        assert row["parentTaskId"] == "network-setup-optional" and row["timeoutSeconds"] == 5
        assert row["startTime"] <= row["endTime"]
        if stage == "missing-path":
            assert row["state"] == "launch-error" and row["errno"] == 2
            assert row["exception"] == "FileNotFoundError" and row["pid"] is None
            assert row["exitCode"] is None and row["which"] is None
            assert not row["stdout"]
            failed = [e for e in events if e["operation"] == "execve" and e["tokens"][0] == tool and "ENOENT" in e["status"]]
            assert len(failed) == 1
            assert any(e["pid"] == failed[0]["pid"] and e["operation"] == "chdir"
                       and e["tokens"] == [str(root / "south work")] and e["success"] for e in events)
            assert not any(e["pid"] == failed[0]["pid"] and e["operation"] == "execve"
                           and e["success"] for e in events)
            continue
        assert row["state"] == "executed" and row["exitCode"] == 0 and not row["stderr"]
        assert row["childProcessGroupCleanup"] == "process exited and reaped"
        actual = json.loads(row["stdout"])
        assert actual == row["actual"] and len(row["stdout"].splitlines()) == 1
        assert actual["pid"] == row["pid"] > 0 and actual["parentPid"] == payload["parentPid"]
        assert actual["uid"] == before["uid"]
        assert actual["hostname"] == before["hostname"]
        assert actual["networkNamespace"] == before["networkNamespace"]
        assert actual["mountNamespace"] == before["mountNamespace"]
        assert actual["executable"] == payload["pythonExecutable"] and actual["script"] == str(worker)
        assert not Path("/proc/" + str(actual["pid"])).exists()
        if mode == "context":
            expected_tag = "alpha" if stage in {"path-alpha", "absolute-without-path"} else "beta"
            area = "first" if stage in {"path-alpha", "path-beta"} else "second"
            if stage == "configured":
                expected_tag, area = payload["case"]["first_tool"], payload["case"]["work_area"]
            arguments = ["owned observation"]
            if stage == "absolute-without-path":
                assert row["which"] is None and row["absoluteInvocation"] and row["childPATH"] == ""
            else:
                assert row["which"] == str(root / (expected_tag + " bin") / tool)
                assert not row["absoluteInvocation"]
        else:
            expected_tag, area = "alpha", "first"
            quoted = stage in {"direct-arguments", "shell-quoted"} or (
                stage == "configured" and payload["case"]["quote_arguments"])
            arguments = desired if quoted else split_arguments
            assert row["matchesDesiredArguments"] == quoted
            if stage != "direct-arguments":
                assert row["command"][:3] == [observation["bashExecutable"], "--noprofile", "--norc"]
                assert row["command"][3] == "-c"
                assert any(e["pid"] == row["pid"] and e["operation"] == "execve"
                           and e["tokens"][0] == observation["bashExecutable"] and e["success"] for e in events)
        expected_cwd = str(root / ("north work" if area == "first" else "south work"))
        assert actual["tag"] == expected_tag and actual["cwd"] == row["cwd"] == expected_cwd
        assert actual["arguments"] == arguments
        selected = str(root / (expected_tag + " bin") / tool)
        own = [e for e in events if e["pid"] == row["pid"]]
        chosen = [e for e in own if e["operation"] == "execve" and e["tokens"][0] == selected and e["success"]]
        assert len(chosen) == 1
        assert any(e["operation"] == "chdir" and e["tokens"] == [expected_cwd] and e["success"] for e in own)
        native_worker = [e for e in own if e["operation"] == "execve"
                         and e["tokens"][0] == payload["pythonExecutable"] and e["success"]]
        assert len(native_worker) == 1
        # First token is the execve path, followed by the actual argv array.
        assert native_worker[0]["tokens"][1:] == [payload["pythonExecutable"], "-I", str(worker), expected_tag, *arguments]
        selected_events.append(chosen[0])
        successful.append(row["pid"])
    assert len(successful) == len(set(successful)) == (5 if mode == "context" else 4)
    allowed = {str(ROOT / "test/verify_setup_optional.py"), payload["pythonExecutable"],
               str(root / "alpha bin" / tool), str(root / "beta bin" / tool)}
    if mode == "arguments":
        allowed.add(observation["bashExecutable"])
    # The program must not execute an extra command through expanded semicolons.
    assert all(event["tokens"][0] in allowed for event in events
               if event["operation"] == "execve" and event["success"])
    return {"mode": mode, "alternate": alternate, "configuredMatchesGoal": expected_complete,
            "report": report.name, "reportSha256": hashlib.sha256(report.read_bytes()).hexdigest(),
            "trace": trace.name, "traceSha256": hashlib.sha256(trace.read_bytes()).hexdigest(),
            "actualExecutedTargets": len(successful), "actualExecEvents": len([x for x in events if x["operation"] == "execve"]),
            "matchedNativeWorkerExecs": len(successful), "actualCwdAndUidChecked": True,
            "onlyOwnedTargetsExecuted": True, "cleanupIndependentlyChecked": True}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--proof", type=Path, required=True)
    args = parser.parse_args()
    args.proof = args.proof.resolve()
    assert sys.platform == "linux" and os.getuid() != 0 and shutil.which("strace")
    args.proof.parent.mkdir(parents=True, exist_ok=True)
    retained = args.proof.parent / "setup-observations"
    retained.mkdir(exist_ok=False)
    before = {mode: hashes(ROOT / pack) for mode, pack in PACKS.items()}
    accepted, unfinished, refusals, regressions, intermediate = [], [], [], [], []
    with tempfile.TemporaryDirectory(prefix="setup-optional-contracts-") as temporary:
        work = Path(temporary)
        for mode, pack_name in PACKS.items():
            pack = ROOT / pack_name
            assert REQUIRED <= {path.name for path in (pack / "starter").iterdir()}
            assert REQUIRED <= {path.name for path in (pack / "solution").iterdir()}
            assert (pack / "starter/setup_lab.py").read_bytes() == (pack / "solution/setup_lab.py").read_bytes()
            assert json.loads((pack / "solution/case.json").read_text()) == CORRECT[mode]
            completed = work / (mode + "-completed")
            shutil.copytree(pack / "starter", completed)
            (completed / "case.json").write_bytes((pack / "solution/case.json").read_bytes())
            initial = hashes(pack / "starter")
            assert {name for name, value in hashes(completed).items() if value != initial[name]} == {"case.json"}
            for role, folder in [("starter", pack / "starter"), ("solution", pack / "solution"), ("completed", completed)]:
                for alternate in [False, True]:
                    name = mode + "-" + role + ("-alternate" if alternate else "-default")
                    report, trace = retained / (name + ".json"), retained / (name + ".execve.txt")
                    argv = ["strace", "-f", "-qq", "-s", "4096", "-e", "trace=execve,chdir",
                            "-o", trace, "--", sys.executable, folder / "main.py"]
                    if alternate:
                        argv.append("--alternate")
                    argv.extend(["--output", report])
                    result = command(argv, folder)
                    complete = role != "starter"
                    assert result["exitCode"] == (0 if complete else 78), result
                    row = validate(folder, mode, report, trace, alternate, complete)
                    row.update(role=role, result=result)
                    (accepted if complete else unfinished).append(row)
                    if role == "solution" and not alternate:
                        repeated = command([sys.executable, folder / "main.py", "--output", report], folder)
                        assert repeated["exitCode"] == 2 and "new output filename" in repeated["stderr"]
                        refusals.append({"mode": mode, "kind": "existing-output", "result": repeated})
            if mode == "context":
                partial = work / "context-tool-corrected"
                shutil.copytree(pack / "starter", partial)
                (partial / "case.json").write_text(json.dumps({"first_tool": "beta", "work_area": "first"}) + "\n")
                report, trace = retained / "context-tool-corrected.json", retained / "context-tool-corrected.execve.txt"
                result = command(["strace", "-f", "-qq", "-s", "4096", "-e", "trace=execve,chdir",
                                  "-o", trace, "--", sys.executable, partial / "main.py", "--output", report], partial)
                assert result["exitCode"] == 78
                row = validate(partial, mode, report, trace, False, False)
                row["result"] = result
                intermediate.append(row)
            invalid = work / (mode + "-invalid")
            shutil.copytree(pack / "solution", invalid)
            (invalid / "case.json").write_text(json.dumps({"first_tool": [], "work_area": "second"} if mode == "context" else {"quote_arguments": "true"}) + "\n")
            output = retained / (mode + "-refused.json")
            result = command([sys.executable, invalid / "main.py", "--output", output], invalid)
            assert result["exitCode"] == 2 and not output.exists()
            refusals.append({"mode": mode, "kind": "invalid-config", "result": result})
            mutant = work / (mode + "-regression")
            shutil.copytree(pack / "solution", mutant)
            helper = mutant / "setup_lab.py"
            text = helper.read_text()
            old = 'env["PATH"] = os.pathsep.join(str(directories[tag]) for tag in order)' if mode == "context" else 'fields = [\'"$COURSE_WORDS"\', \'"$COURSE_PATTERN"\', \'"$COURSE_LITERAL"\'] if quoted else'
            new = 'env["PATH"] = os.pathsep.join(str(directories[tag]) for tag in reversed(order))' if mode == "context" else 'fields = ["$COURSE_WORDS", "$COURSE_PATTERN", "$COURSE_LITERAL"] if quoted else'
            assert text.count(old) == 1
            helper.write_text(text.replace(old, new))
            output, trace = retained / (mode + "-regression.json"), retained / (mode + "-regression.execve.txt")
            result = command(["strace", "-f", "-qq", "-s", "4096", "-e", "trace=execve,chdir",
                              "-o", trace, "--", sys.executable, mutant / "main.py", "--output", output], mutant)
            rejected = result["exitCode"] != 0
            if not rejected:
                try:
                    validate(mutant, mode, output, trace, False, True)
                except AssertionError:
                    rejected = True
            assert rejected, mode
            regressions.append({"mode": mode, "rejected": True, "result": result,
                                "trace": trace.name, "traceSha256": hashlib.sha256(trace.read_bytes()).hexdigest()})
        assert before == {mode: hashes(ROOT / pack) for mode, pack in PACKS.items()}
    proof = {"event": "verified-network-setup-optional", "sourceFileHashes": before,
             "acceptedProfiles": accepted, "unfinishedProfilesRejected": unfinished,
             "refusals": refusals, "controlledRegressions": regressions,
             "oneFieldCorrection": intermediate,
             "sourceUnchanged": True, "temporaryBuildCleanup": not Path(temporary).exists(),
             "independentCompletionOnly": "case.json", "notebookCompletionNotInferred": True,
             "retainedFiles": hashes(retained), "straceVersion": command(["strace", "--version"], ROOT)}
    assert len(accepted) == 8 and len(unfinished) == 4 and len(refusals) == 4 and len(regressions) == 2
    args.proof.write_text(json.dumps(proof, indent=2) + "\n")
    args.proof.with_suffix(".processes.jsonl").write_text("".join(json.dumps(row) + "\n" for row in PROCESS_LOG))
    assert len(intermediate) == 1
    targets = sum(row["actualExecutedTargets"] for row in accepted + unfinished + intermediate)
    assert targets == 59
    print(json.dumps({"acceptedProfiles": 8, "unfinishedRejected": 4, "refusals": 4,
                      "controlledRegressions": 2, "actualMatchedTargetExecs": targets,
                      "sourceUnchanged": True, "notebookCompletionNotInferred": True}))


if __name__ == "__main__":
    main()
