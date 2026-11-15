"""Collect real typed DNS answers from the owned loopback resolver."""
from __future__ import annotations
import argparse
import datetime
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import sys
import time

NAMES = {"dual.course.test", "v4.course.test", "alias.course.test", "missing.course.test"}

def stamp():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def parse_result(stdout, returncode, timed_out=False):
    header = re.search(r"\bstatus:\s*([A-Z0-9]+)\s*,", stdout)
    status = header.group(1) if header else None
    records = []
    for line in stdout.splitlines():
        fields = line.split()
        if len(fields) >= 5 and not line.startswith(";") and fields[2] == "IN":
            records.append({"owner": fields[0].lower(), "ttl": int(fields[1]),
                            "type": fields[3], "data": " ".join(fields[4:])})
    if timed_out or returncode == 9:
        classification = "transport_failure"
    elif returncode != 0:
        classification = "tool_failure"
    elif status == "NXDOMAIN":
        classification = "negative_name"
    elif status == "NOERROR":
        classification = "answer" if records else "no_data"
    elif status:
        classification = "dns_error"
    else:
        classification = "unrecognized_result"
    return {"dnsStatus": status, "records": records, "classification": classification}

def query(name, record_type, port):
    argv = ["dig", "+time=1", "+tries=1", "+noall", "+comments", "+answer",
            "@127.0.0.1", "-p", str(port), name, record_type]
    start = stamp()
    proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            start_new_session=True,
                            env={"PATH": os.environ.get("PATH", ""), "LC_ALL": "C"})
    timed_out = False
    cleanup = "owned child exited and was reaped"
    try:
        stdout, stderr = proc.communicate(timeout=4)
    except BaseException as error:
        timed_out = isinstance(error, subprocess.TimeoutExpired)
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            stdout, stderr = proc.communicate(timeout=1)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            stdout, stderr = proc.communicate()
        cleanup = "owned process group stopped and reaped"
        if not timed_out:
            raise
    out = stdout.decode("utf-8", errors="replace")
    return {"question": name, "type": record_type, "server": "127.0.0.1",
            "port": port, "stdout": out, "stderr": stderr.decode("utf-8", errors="replace"),
            "process": {"parentTask": "network-optional-dns", "parentPID": os.getpid(),
                        "pid": proc.pid, "cwd": str(Path.cwd()), "command": argv,
                        "startedAt": start, "endedAt": stamp(), "exitCode": proc.returncode,
                        "timeoutSeconds": 4, "timedOut": timed_out, "cleanup": cleanup},
            **parse_result(out, proc.returncode, timed_out)}

def validate_case(project, case):
    if not isinstance(case, dict):
        raise ValueError("case.json must contain an object")
    if project == "alias-transfer":
        if set(case) != {"question"} or (not isinstance(case["question"], str) or case["question"] not in NAMES):
            raise ValueError("question must select one of the four supplied course.test names")
    elif project == "negative-vs-transport":
        if set(case) != {"stoppedClaim"} or (not isinstance(case["stoppedClaim"], str) or case["stoppedClaim"] not in {
                "negative_name", "transport_failure"}):
            raise ValueError("stoppedClaim must be negative_name or transport_failure")
    else:
        raise ValueError("unknown project")

def main(project, case_path):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=1053, help="Owned loopback DNS port")
    parser.add_argument("--phase", choices=["live", "stopped"], default="live")
    parser.add_argument("--output", type=Path, required=True, help="A new report filename")
    args = parser.parse_args()
    try:
        if sys.platform != "linux" or os.geteuid() == 0:
            raise ValueError("Use an ordinary user in the selected Linux lab")
        if not shutil.which("dig"):
            raise ValueError("Install dnsutils in the selected Linux lab")
        if not 1024 < args.port <= 65535:
            raise ValueError("Use an owned loopback port from 1025 through 65535")
        if project == "alias-transfer" and args.phase != "live":
            raise ValueError("The alias investigation uses the live phase")
        def cancelled(signum, frame):
            raise InterruptedError("DNS collection interrupted; any new report is incomplete")
        signal.signal(signal.SIGTERM, cancelled)
        case = json.loads(case_path.read_text())
        validate_case(project, case)
        # Reserve the new file before launching a diagnostic; earlier evidence stays intact.
        with args.output.open("x", encoding="utf-8") as destination:
            names = [case["question"]] if project == "alias-transfer" else ["missing.course.test"]
            observations = [query(name, kind, args.port) for name in names for kind in ["A", "AAAA"]]
            if project == "alias-transfer":
                target = "dual.course.test."
                goal = all(row["dnsStatus"] == "NOERROR" for row in observations)
                goal = goal and all(any(r["type"] == "CNAME" and r["data"].lower() == target
                                        for r in row["records"]) for row in observations)
                expected = {"A": "127.0.0.8", "AAAA": "::1"}
                goal = goal and all(any(r["owner"] == target and r["type"] == row["type"]
                                        and r["data"] == expected[row["type"]]
                                        for r in row["records"]) for row in observations)
            else:
                expected = "negative_name" if args.phase == "live" else case["stoppedClaim"]
                goal = all(row["classification"] == expected for row in observations)
                if args.phase == "stopped":
                    goal = goal and expected == "transport_failure"
            report = {"project": project, "phase": args.phase, "case": case,
                      "context": {"host": socket.gethostname(), "uid": os.geteuid(),
                                  "pid": os.getpid(), "cwd": str(Path.cwd()),
                                  "networkNamespace": os.readlink("/proc/self/ns/net")},
                      "at": stamp(), "observations": observations, "goalMet": bool(goal),
                      "scope": "Actual DNS queries to the selected owned loopback resolver; no application connection or system NSS lookup",
                      "notebookCompletionInferred": False}
            json.dump(report, destination, indent=2)
            destination.write("\n")
        print(json.dumps({"report": str(args.output), "goalMet": bool(goal)}))
        return 0 if goal else 78
    except (ValueError, OSError, json.JSONDecodeError) as error:
        print(str(error), file=sys.stderr)
        return 2
