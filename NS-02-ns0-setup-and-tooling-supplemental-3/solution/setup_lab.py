"""Run owned command-context and argument-boundary experiments on Linux."""
import argparse
import contextlib
import datetime
import hashlib
import json
import os
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

WORKER = r'''import json
import os
import sys
from pathlib import Path
print(json.dumps({
    "tag": sys.argv[1], "arguments": sys.argv[2:],
    "pid": os.getpid(), "parentPid": os.getppid(),
    "uid": os.getuid(), "cwd": os.getcwd(), "hostname": os.uname().nodename,
    "executable": sys.executable,
    "script": str(Path(__file__).resolve()),
    "networkNamespace": os.readlink("/proc/self/ns/net"),
    "mountNamespace": os.readlink("/proc/self/ns/mnt")
}, sort_keys=True))
'''


class Interrupted(Exception):
    pass


def now():
    # Python 3.10 remains a supported learner interpreter.
    return datetime.datetime.now(datetime.timezone.utc).isoformat()  # noqa: UP017


def interrupt(_signum, _frame):
    raise Interrupted("Owned experiment interrupted")


def snapshot():
    return {
        "cwd": os.getcwd(), "uid": os.getuid(), "hostname": os.uname().nodename,
        "pathSha256": hashlib.sha256(os.environ.get("PATH", "").encode()).hexdigest(),
        "networkNamespace": os.readlink("/proc/self/ns/net"),
        "mountNamespace": os.readlink("/proc/self/ns/mnt")
    }


def source_hashes(folder):
    return {name: hashlib.sha256((folder / name).read_bytes()).hexdigest()
            for name in ["main.py", "setup_lab.py", "case.json", "network-notes.md", "edge-cases.md"]}


def run(argv, cwd, environment, stage):
    started = now()
    record = {"stage": stage, "command": [str(x) for x in argv], "cwd": str(cwd),
              "childPATH": environment["PATH"], "startTime": started,
              "parentTaskId": "network-setup-optional", "timeoutSeconds": 5}
    try:
        child = subprocess.Popen(argv, cwd=cwd, env=environment,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 text=True, start_new_session=True)
    except FileNotFoundError as error:
        # Popen may fork before exec fails. No target execution or PID is invented.
        record.update(state="launch-error", pid=None, errno=error.errno,
                      exception=type(error).__name__, stdout="", stderr=str(error),
                      exitCode=None, endTime=now(),
                      childProcessGroupCleanup="Popen handled the exec failure")
        return record
    cleanup = "process exited and reaped"
    try:
        stdout, stderr = child.communicate(timeout=5)
    except BaseException:
        cleanup = "owned child process group terminated and reaped"
        with contextlib.suppress(ProcessLookupError):
            os.killpg(child.pid, signal.SIGTERM)
        try:
            child.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(child.pid, signal.SIGKILL)
            child.communicate(timeout=2)
        raise
    finally:
        record.update(pid=child.pid, endTime=now(), exitCode=child.returncode,
                      childProcessGroupCleanup=cleanup)
    record.update(state="executed", stdout=stdout, stderr=stderr)
    assert child.returncode == 0 and not stderr, "Owned worker did not complete normally"
    actual = json.loads(stdout)
    assert actual["pid"] == child.pid
    record["actual"] = actual
    return record


def launchers(root, tool):
    worker = root / "owned worker.py"
    worker.write_text(WORKER)
    directories = {}
    fixture_files = {"owned worker.py": WORKER}
    for tag in ["alpha", "beta"]:
        directory = root / (tag + " bin")
        directory.mkdir()
        text = "#!/bin/sh\nexec " + shlex.quote(sys.executable) + " -I " + shlex.quote(str(worker)) + " " + tag + ' "$@"\n'
        target = directory / tool
        target.write_text(text)
        target.chmod(0o755)
        directories[tag] = directory
        fixture_files[str(target.relative_to(root))] = text
    areas = {}
    for key, label in [("first", "north work"), ("second", "south work")]:
        folder = root / label
        folder.mkdir()
        areas[key] = folder
    return directories, areas, worker, fixture_files


def environment_for(directories, order):
    env = {"LANG": "C", "LC_ALL": "C"}
    env["PATH"] = os.pathsep.join(str(directories[tag]) for tag in order)
    return env


def context_observation(root, directories, areas, tool, case):
    records = []
    choices = [
        ("path-alpha", ["alpha", "beta"], "first", False),
        ("path-beta", ["beta", "alpha"], "first", False),
        ("cwd-second", ["beta", "alpha"], "second", False),
        ("missing-path", [], "second", False),
        ("absolute-without-path", [], "second", True),
        ("configured", [case["first_tool"], "alpha" if case["first_tool"] == "beta" else "beta"],
         case["work_area"], False)
    ]
    for stage, order, area, absolute in choices:
        env = environment_for(directories, order)
        selected = shutil.which(tool, path=env["PATH"])
        argv = [str(directories["alpha"] / tool) if absolute else tool, "owned observation"]
        record = run(argv, areas[area], env, stage)
        record["which"] = selected
        record["absoluteInvocation"] = absolute
        records.append(record)
    configured = records[-1]["actual"]
    complete = configured["tag"] == "beta" and configured["cwd"] == str(areas["second"])
    return {"stages": records, "configuredMatchesGoal": complete,
            "goal": {"tag": "beta", "workArea": "second"},
            "root": str(root), "areas": {k: str(v) for k, v in areas.items()}}


def argument_observation(directories, areas, tool, case, alternate):
    desired = ["changed three words", "*.data", "owned; note"] if alternate else ["two words", "*.txt", "left; right"]
    names = ["amber.data", "blue.data"] if alternate else ["one.txt", "two.txt"]
    for name in names:
        (areas["first"] / name).write_text("Owned argument fixture\n")
    env = environment_for(directories, ["alpha", "beta"])
    env.update(COURSE_WORDS=desired[0], COURSE_PATTERN=desired[1], COURSE_LITERAL=desired[2])
    bash = str(Path("/bin/bash").resolve())
    assert Path(bash).is_file() and os.access(bash, os.X_OK)
    records = []
    for stage, quoted in [("direct-arguments", None), ("shell-quoted", True),
                          ("shell-unquoted", False), ("configured", case["quote_arguments"])]:
        if quoted is None:
            argv = [tool, *desired]
        else:
            fields = ['"$COURSE_WORDS"', '"$COURSE_PATTERN"', '"$COURSE_LITERAL"'] if quoted else ["$COURSE_WORDS", "$COURSE_PATTERN", "$COURSE_LITERAL"]
            argv = [bash, "--noprofile", "--norc", "-c", "exec " + shlex.quote(tool) + " " + " ".join(fields)]
        record = run(argv, areas["first"], env, stage)
        record["matchesDesiredArguments"] = record["actual"]["arguments"] == desired
        records.append(record)
    return {"stages": records, "desiredArguments": desired,
            "globFiles": names, "configuredMatchesGoal": records[-1]["matchesDesiredArguments"],
            "areas": {k: str(v) for k, v in areas.items()},
            "bashExecutable": bash,
            "shellCodeIsFixedAndEnvironmentValuesAreNotReparsed": True}


def main(mode, folder):
    parser = argparse.ArgumentParser(description="Observe owned command context or shell argument boundaries")
    parser.add_argument("--alternate", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if sys.platform != "linux" or os.geteuid() == 0:
        parser.error("Use an ordinary non-root account in a Linux lab")
    if not Path("/proc/self/ns/net").exists() or not Path("/proc/self/ns/mnt").exists():
        parser.error("Linux process namespace identities are required")
    try:
        case = json.loads((folder / "case.json").read_text())
    except (OSError, ValueError):
        parser.error("case.json must be a readable valid JSON configuration")
    if not isinstance(case, dict):
        parser.error("case.json must contain a JSON object")
    if mode == "context":
        if set(case) != {"first_tool", "work_area"} or type(case["first_tool"]) is not str or type(case["work_area"]) is not str or case["first_tool"] not in {"alpha", "beta"} or case["work_area"] not in {"first", "second"}:
            parser.error("The context case accepts only the declared tool and work-area labels")
    elif mode == "arguments":
        if set(case) != {"quote_arguments"} or type(case["quote_arguments"]) is not bool:
            parser.error("quote_arguments must be a JSON boolean")
    else:
        parser.error("Unknown owned setup experiment")
    output = (args.output or folder / ("setup-observation-" + str(time.time_ns()) + ".json")).resolve()
    if output.exists() or not output.parent.is_dir():
        parser.error("Select a new output filename in an existing directory")
    before = snapshot()
    source_before = source_hashes(folder)
    handlers = {kind: signal.signal(kind, interrupt) for kind in [signal.SIGINT, signal.SIGTERM, signal.SIGALRM]}
    signal.alarm(40)
    try:
        with tempfile.TemporaryDirectory(prefix="owned-setup-space-") as temporary:
            root = Path(temporary)
            tool = "course-context-alt" if args.alternate else "course-context"
            directories, areas, worker, fixture_files = launchers(root, tool)
            if mode == "context":
                observation = context_observation(root, directories, areas, tool, case)
            else:
                observation = argument_observation(directories, areas, tool, case, args.alternate)
            for record in observation["stages"]:
                if record["state"] == "executed":
                    actual = record["actual"]
                    assert actual["uid"] == before["uid"]
                    assert actual["networkNamespace"] == before["networkNamespace"]
                    assert actual["mountNamespace"] == before["mountNamespace"]
                    assert actual["script"] == str(worker)
                    assert not Path("/proc/" + str(actual["pid"])).exists()
            payload = {
                "event": "owned-setup-" + mode, "mode": mode, "case": case,
                "alternate": args.alternate, "parentPid": os.getpid(),
                "parentBefore": before, "observation": observation,
                "fixtureFiles": fixture_files, "tool": tool,
                "sourceFileHashes": source_before,
                "pythonVersion": sys.version, "pythonExecutable": sys.executable
            }
        payload.update(parentAfter=snapshot(), parentUnchanged=before == snapshot(),
                       temporaryRoot=temporary, temporaryBuildCleanup=not Path(temporary).exists(),
                       sourceUnchanged=source_before == source_hashes(folder),
                       allExecutedTargetsReaped=True, notebookCompletionNotInferred=True)
        assert payload["parentUnchanged"] and payload["temporaryBuildCleanup"] and payload["sourceUnchanged"]
        with output.open("x", encoding="utf8") as stream:
            json.dump(payload, stream, indent=2)
            stream.write("\n")
        print(json.dumps({"output": str(output), "configuredMatchesGoal": observation["configuredMatchesGoal"],
                          "temporaryBuildCleanup": True, "parentUnchanged": True}))
        return 0 if observation["configuredMatchesGoal"] else 78
    finally:
        signal.alarm(0)
        for kind, handler in handlers.items():
            signal.signal(kind, handler)
