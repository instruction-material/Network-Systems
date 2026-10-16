"""Reconcile real HTTP wire bytes, source roles, optional analyses and cleanup."""
import argparse
import base64
import contextlib
import datetime
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from verify_naming import complete

sys.dont_write_bytecode = True
PACKS = {
    "NS-09-unit-11-common-application-protocols": "core",
    "NS-23-unit-11-common-application-protocols-supplemental-2": "transfer",
    "NS-24-unit-11-common-application-protocols-supplemental-3": "extension",
}
FILES = ("main.py", "application_lab.py", "network-notes.md", "application-cases.md", "README.md")
PLANS = {
    "core": [("GET", "/state", 200), ("HEAD", "/state", 200), ("GET", "/missing", 404),
             ("POST", "/state", 405), ("GET", "/unavailable", 503)],
    "transfer": [("GET", "/state", 200), ("GET", "/state", 304), ("GET", "/state", 200),
                 ("HEAD", "/state", 200), ("GET", "/redirect", 307), ("GET", "/state", 200)],
    "extension": [("GET", "/unavailable", 503), ("GET", "/missing", 404),
                  ("POST", "/state", 405), ("GET", "/binary", 200), ("GET", "/state", 200)],
}
COMPLETIONS = {
    "core": '''def analyze(e):
    from base64 import b64decode
    return dict(observedStatuses=list(map(lambda x: x['status'], e['exchanges'])),
                headTransferredBytes=len(b64decode(e['exchanges'][1]['bodyBase64'])),
                allowedMethods=e['exchanges'][3]['headers']['allow'].replace(',', '').split(),
                refusalProducedHTTP=e['curlRefusal']['stdout'][:5] == 'HTTP/')
''',
    "transfer": '''def analyze(e):
    from base64 import b64decode
    from hashlib import sha256
    r = e['exchanges']
    result = dict(validator=r[0]['headers']['etag'], validatingStatus=r[1]['status'],
                  conditionalTransferredBytes=len(b64decode(r[1]['bodyBase64'])),
                  retainedRepresentationSha256=sha256(b64decode(r[0]['bodyBase64'])).hexdigest())
    result.update(staleValidatorStatus=r[2]['status'], redirectStatus=r[4]['status'],
                  redirectTarget=r[4]['headers']['location'], finalBodyMatchesFirst=r[5]['bodyBase64'] == r[0]['bodyBase64'])
    return result
''',
    "extension": '''def analyze(e):
    from base64 import b64decode
    r = e['exchanges']
    same = r[4]['requestHeaders']['Host'] == 'representation.invalid'
    same = same and r[4]['peer'] == r[3]['peer']
    same = same and r[4]['headers']['x-lab-token'] == e['ready']['token']
    return dict(statusClasses=[int(str(x['status'])[0]) for x in r[:3]],
                retryAfterSeconds=int(r[0]['headers']['retry-after']),
                binaryOctets=[x for x in b64decode(r[3]['bodyBase64'])], hostHeaderChangedOnly=same)
''',
}


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def decode(text):
    return base64.b64decode(text, validate=True)


def run(argv, cwd, records, env=None):
    started = now()
    child = subprocess.Popen(argv, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1", **(env or {})}, start_new_session=True)
    cleanup = "exited and reaped"
    try:
        out, err = child.communicate(timeout=45)
    except BaseException:
        cleanup = "owned process group stopped and reaped"
        with contextlib.suppress(ProcessLookupError):
            os.killpg(child.pid, signal.SIGTERM)
        try:
            child.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL)
            child.communicate(timeout=3)
        raise
    finally:
        records.append({"parentTask": "network-application-native", "parentPid": os.getpid(),
                        "cwd": str(cwd), "command": argv, "pid": child.pid,
                        "startTime": started, "endTime": now(), "exitCode": child.returncode,
                        "timeoutSeconds": 45, "childProcessGroupCleanup": cleanup})
    records[-1].update(stdout=out.decode(), stderr=err.decode())
    return child.returncode, out.decode(), err.decode()


def headers(raw):
    head, body = raw.split(b"\r\n\r\n", 1)
    lines = head.decode("ascii").split("\r\n")
    fields = {key.lower(): value.strip() for key, value in
              (line.split(":", 1) for line in lines[1:])}
    return int(lines[0].split()[1]), fields, body


def expected_analysis(e, kind):
    if kind == "core":
        return {"observedStatuses": [200, 200, 404, 405, 503], "headTransferredBytes": 0,
                "allowedMethods": ["GET", "HEAD"], "refusalProducedHTTP": False}
    if kind == "transfer":
        return {"validator": e["exchanges"][0]["headers"]["etag"], "validatingStatus": 304,
                "conditionalTransferredBytes": 0,
                "retainedRepresentationSha256": sha(decode(e["exchanges"][0]["bodyBase64"])),
                "staleValidatorStatus": 200, "redirectStatus": 307, "redirectTarget": "/state",
                "finalBodyMatchesFirst": True}
    return {"statusClasses": [5, 4, 4], "retryAfterSeconds": 2 if e["changed"] else 1,
            "binaryOctets": [0, 1, 255, 254], "hostHeaderChangedOnly": True}


def check(e, kind):
    assert e["kind"] == kind and not e.get("error")
    env, ready, worker, proc = e["environment"], e["ready"], e["workerResult"], e["serverProcess"]
    uid, pid, port, token = env["uid"], ready["pid"], ready["port"], ready["token"]
    assert uid > 0 and env["platform"] == "linux" and env["networkNamespace"].startswith("net:[")
    assert ready == json.loads(e["readyLine"])["ready"] == worker["worker"]
    assert uid == ready["uid"] and pid == proc["pid"] and ready["address"] == "127.0.0.1"
    assert 1024 <= port <= 65535 and len(token) == 32 and e["workerProcUidFields"] == [str(uid)] * 4
    assert e["serverReaped"] and proc["exitCode"] == 0 and not proc["stderr"]
    assert proc["timeoutSeconds"] == 45 and proc["readinessDeadlineSeconds"] == proc["stopDeadlineSeconds"] == 3
    assert proc["childProcessGroupCleanup"] == "owned service stopped and reaped"
    assert proc["command"][1] == "-u" and proc["command"][3:] == ["--serve", token, e["message"], str(e["retrySeconds"])]
    owner = "pid=" + str(pid) + ","
    assert any(owner in line and "127.0.0.1:" + str(port) in line for line in e["listenersDuring"].splitlines())
    assert owner not in e["listenersAfter"]
    assert not e["configuredSystemState"] and not e["dnsMeasured"] and not e["tlsMeasured"] and not e["sshMeasured"]
    assert e["suppliedCasesAreConstructed"] and not e["learnerWorksheetCompletionInferred"]
    assert e["refusalControl"]["heldWithoutListen"] and e["refusalControl"]["heldDuringProbe"]
    assert e["refusalControl"]["port"] != port
    representation = {"token": token, "message": e["message"], "pid": pid, "uid": uid,
                      "address": "127.0.0.1", "port": port}
    encoded_representation = json.dumps(representation, sort_keys=True).encode() + b"\n"
    tag = '"' + sha(encoded_representation) + '"'
    rows = e["exchanges"]
    assert len(rows) == len(PLANS[kind]) and len(worker["requests"]) == len(rows) + 2
    for i, (row, expected) in enumerate(zip(rows, PLANS[kind])):
        method, path, status = expected
        assert (row["method"], row["path"], row["status"]) == expected
        request, response = decode(row["requestBase64"]), decode(row["responseBase64"])
        actual_status, fields, body = headers(response)
        assert actual_status == status and fields == row["headers"] and body == decode(row["bodyBase64"])
        assert row["version"] == "HTTP/1.1" and row["readToEOF"]
        assert row["deadlineSeconds"] == 3 and row["responseLimitBytes"] == 65536
        assert request.startswith((method + " " + path + " HTTP/1.1\r\n").encode()) and request.endswith(b"\r\n\r\n")
        assert fields["x-lab-token"] == token and fields["connection"] == "close"
        assert row["peer"] == ["127.0.0.1", port] and row["local"][0] == "127.0.0.1"
        assert 1024 <= row["local"][1] <= 65535
        observed = worker["requests"][i]
        assert observed["local"] == row["peer"] and observed["peer"] == row["local"]
        assert observed["requestLine"] == method + " " + path + " HTTP/1.1\r\n"
        assert observed["requestHeaders"] == row["requestHeaders"]
        assert observed["status"] == status and observed["bodyBase64"] == row["bodyBase64"]
        assert proc["startTime"] <= row["startTime"] <= observed["at"] <= row["endTime"] <= proc["endTime"]
        host = "representation.invalid" if kind == "extension" and i == 4 else "127.0.0.1:" + str(port)
        assert row["requestHeaders"]["Host"] == host and ("Host: " + host + "\r\n").encode() in request
        if method == "HEAD":
            assert not body and int(fields["content-length"]) == len(encoded_representation)
        elif status == 304:
            assert not body and "content-length" not in fields
        else:
            assert len(body) == int(fields["content-length"])
            if path == "/binary":
                assert body == b"\x00\x01\xff\xfe" and fields["content-type"] == "application/octet-stream"
            elif path == "/state" and status == 200:
                assert body == encoded_representation
            else:
                assert json.loads(body)["token"] == token
        if path == "/state" and method != "POST":
            assert fields["etag"] == tag and observed["etag"] == tag and fields["cache-control"] == "no-cache"
        if status == 405:
            assert fields["allow"] == "GET, HEAD"
        if status == 503:
            assert fields["retry-after"] == str(2 if e["changed"] else 1)
        if status == 307:
            assert fields["location"] == "/state"
    if kind == "transfer":
        assert rows[1]["requestHeaders"]["If-None-Match"] == tag
        assert rows[2]["requestHeaders"]["If-None-Match"] != tag
    assert [r["method"] for r in worker["requests"][-2:]] == ["GET", "HEAD"]
    for key, method in [("curlGet", "GET"), ("curlHead", "HEAD")]:
        c = e[key]
        assert c["exitCode"] == 0 and not c["stderr"]
        status, fields, body = headers(c["stdout"].encode())
        assert status == 200 and fields["etag"] == tag and fields["x-lab-token"] == token
        assert body == (b"" if method == "HEAD" else encoded_representation)
        assert "--noproxy" in c["command"] and "*" in c["command"] and "--http1.1" in c["command"]
        assert c["command"][-1] == "http://127.0.0.1:" + str(port) + "/state"
    refused = e["curlRefusal"]
    assert refused["exitCode"] == 7 and refused["stdout"] == "" and refused["stderr"]
    assert refused["command"][-1] == "http://127.0.0.1:" + str(e["refusalControl"]["port"]) + "/state"
    assert len(e["commands"]) == 5
    assert all(c["parentPid"] == env["parentPid"] and c["timeoutSeconds"] == 4 and
               c["childProcessGroupCleanup"] == "exited and reaped" for c in e["commands"])
    assert e["commands"][0]["stdout"] == e["listenersDuring"] and e["commands"][-1]["stdout"] == e["listenersAfter"]
    assert proc["endTime"] <= e["commands"][-1]["startTime"]
    return len(worker["requests"])


def interrupt(folder, signum, records):
    argv = [sys.executable, "main.py", "--hold-ms", "2000"]
    started = now()
    child = subprocess.Popen(argv, cwd=folder, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}, start_new_session=True)
    worker = None
    try:
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            children = Path("/proc/" + str(child.pid) + "/task/" + str(child.pid) + "/children")
            for text in children.read_text().split() if children.exists() else []:
                cmd = Path("/proc/" + text + "/cmdline")
                if cmd.exists() and b"--serve\0" in cmd.read_bytes():
                    worker = int(text)
            if worker:
                time.sleep(0.1)
                break
            time.sleep(0.01)
        assert worker and child.poll() is None
        child.send_signal(signum)
        out, err = child.communicate(timeout=8)
        assert child.returncode == 128 + signum and not err
        e = json.loads(out)
        assert e["interruptedStatus"] == 128 + signum and e["serverReaped"]
        assert e["serverProcess"]["pid"] == worker and e["serverProcess"]["exitCode"] == 0
        assert not e.get("exchanges") and not e["workerResult"]["requests"]
        assert "pid=" + str(worker) + "," not in e["listenersAfter"]
        assert not Path("/proc/" + str(worker)).exists()
        return e
    finally:
        if child.poll() is None:
            os.killpg(child.pid, signal.SIGTERM)
            try:
                child.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.communicate(timeout=3)
        records.append({"parentTask": "network-application-native-interruption", "parentPid": os.getpid(),
                        "cwd": str(folder), "command": argv, "pid": child.pid,
                        "startTime": started, "endTime": now(), "exitCode": child.returncode,
                        "timeoutSeconds": 8, "signalSent": signum,
                        "childProcessGroupCleanup": "parent exited; owned worker reaping checked"})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--proof", type=Path, required=True)
    args = parser.parse_args()
    assert sys.platform == "linux" and os.geteuid() > 0
    root = Path(__file__).resolve().parents[1]
    source_names = [pack + "/README.md" for pack in PACKS]
    source_names += [pack + "/" + role + "/" + name for pack in PACKS for role in ("starter", "solution") for name in FILES]
    source_names += ["test/verify_applications.py", ".github/workflows/native-network.yml", "COURSE_SOURCE_MANIFEST.md", "SOURCE_BACKLOG.md"]
    sources = {name: {"sha256": sha((root / name).read_bytes()), "contentBase64": base64.b64encode((root / name).read_bytes()).decode()} for name in source_names}
    args.proof.parent.mkdir(parents=True, exist_ok=True)
    proof = {"nativePassed": False, "platform": sys.platform, "uid": os.geteuid(),
             "sourceFiles": sources, "profiles": [], "interruptions": [], "refusals": [],
             "outerProcesses": [], "dnsTLSAndSSHMeasured": False, "learnerWorksheetCompletionInferred": False}
    try:
        with tempfile.TemporaryDirectory(prefix="application-protocol ") as temporary:
            for pack, kind in PACKS.items():
                for profile in ("starter", "completed", "reference"):
                    for changed in (False, True):
                        role = "solution" if profile == "reference" else "starter"
                        folder = Path(temporary) / (kind + " ' " + profile + " " + str(changed))
                        shutil.copytree(root / pack / role, folder)
                        if profile == "completed":
                            (folder / "main.py").write_text(complete((folder / "main.py").read_text(), COMPLETIONS[kind]))
                        message = "Changed café observation" if changed else "Owned application observation"
                        argv = [sys.executable, "main.py", "--message", message, *(["--changed"] if changed else [])]
                        status, out, err = run(argv, folder, proof["outerProcesses"])
                        name = kind + "-" + profile + "-" + str(int(changed)) + ".json"
                        (args.proof.parent / name).write_text(out)
                        assert status == 0 and not err, (pack, profile, status, err, out[-1500:])
                        e = json.loads(out)
                        count = check(e, kind)
                        assert e["message"] == message and e["changed"] == changed
                        assert e["analysis"] == (None if profile == "starter" else expected_analysis(e, kind))
                        proof["profiles"].append({"pack": pack, "kind": kind, "profile": profile, "changed": changed,
                                                  "evidence": name, "sha256": sha(out.encode()), "actualHTTPResponses": count,
                                                  "executedMain": (folder / "main.py").read_text(),
                                                  "roleFileHashes": {n: sha((folder / n).read_bytes()) for n in FILES}})
                folder = Path(temporary) / (kind + " ' refusals")
                shutil.copytree(root / pack / "starter", folder)
                for tail in (["--hold-ms", "-1"], ["--hold-ms", "2001"], ["--message", ""],
                             ["--message", "x" * 161], ["--message", "bad\nmessage"], ["--unknown"]):
                    status, out, err = run([sys.executable, "main.py", *tail], folder, proof["outerProcesses"])
                    assert status == 2 and err
                    assert not out or "serverProcess" not in json.loads(out)
                    proof["refusals"].append({"pack": pack, "arguments": tail, "status": status})
            folder = Path(temporary) / "interruption"
            shutil.copytree(root / next(iter(PACKS)) / "starter", folder)
            for signum in (signal.SIGINT, signal.SIGTERM):
                e = interrupt(folder, signum, proof["outerProcesses"])
                name = "interrupted-" + str(signum) + ".json"
                data = json.dumps(e, indent=2) + "\n"
                (args.proof.parent / name).write_text(data)
                proof["interruptions"].append({"signal": signum, "evidence": name, "sha256": sha(data.encode())})
        assert len(proof["profiles"]) == 18 and len(proof["refusals"]) == 18 and len(proof["interruptions"]) == 2
        assert all(sha((root / name).read_bytes()) == source["sha256"] for name, source in sources.items())
        proof.update(nativePassed=True, sourceUnchanged=True, sourceFileCopies=37,
                     actualHTTPResponses=sum(row["actualHTTPResponses"] for row in proof["profiles"]),
                     rawHTTPExchanges=96, controlledTCPRefusals=18, actualWorkerReaps=20,
                     outerLifecycles=len(proof["outerProcesses"]), independentCompletedAndReferenceAnalyses=12)
    except BaseException as error:
        proof["error"] = type(error).__name__ + ": " + str(error)
        raise
    finally:
        args.proof.write_text(json.dumps(proof, indent=2) + "\n")
    print(json.dumps({key: value for key, value in proof.items() if key not in ("sourceFiles", "profiles", "outerProcesses")}))


if __name__ == "__main__":
    main()
