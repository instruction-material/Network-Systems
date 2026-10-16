"""Observe bounded HTTP exchanges with an owned ordinary-user loopback service."""
import base64
import contextlib
import datetime
import hashlib
import json
import os
import select
import shutil
import signal
import socket
import subprocess
import sys
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def encoded(raw):
    return base64.b64encode(raw).decode("ascii")


def command(argv, evidence):
    started = now()
    child = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             start_new_session=True)
    cleanup = "exited and reaped"
    try:
        out, err = child.communicate(timeout=4)
    except BaseException:
        cleanup = "owned process group stopped and reaped"
        with contextlib.suppress(ProcessLookupError):
            os.killpg(child.pid, signal.SIGTERM)
        try:
            child.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL)
            child.communicate(timeout=2)
        raise
    finally:
        evidence["commands"].append({
            "parentTask": "application-protocol-observation", "parentPid": os.getpid(),
            "cwd": os.getcwd(), "command": argv, "pid": child.pid,
            "startTime": started, "endTime": now(), "exitCode": child.returncode,
            "timeoutSeconds": 4, "childProcessGroupCleanup": cleanup,
        })
    record = evidence["commands"][-1]
    record.update(stdout=out.decode("utf-8"), stderr=err.decode("utf-8"))
    return record


def serve(token, message, retry):
    requests = []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "OwnedApplicationLab/1"
        sys_version = ""

        def log_message(self, _format, *_args):
            pass

        def do_GET(self):
            self.respond()

        def do_HEAD(self):
            self.respond()

        def do_POST(self):
            self.respond()

        def respond(self):
            data = {"token": token, "message": message, "pid": os.getpid(),
                    "uid": os.geteuid(), "address": "127.0.0.1",
                    "port": self.server.server_port}
            representation = json.dumps(data, sort_keys=True).encode() + b"\n"
            etag = '"' + hashlib.sha256(representation).hexdigest() + '"'
            status = 200
            fields = {"Content-Type": "application/json; charset=utf-8"}
            body = representation
            if self.command == "POST":
                status, fields["Allow"] = 405, "GET, HEAD"
                body = json.dumps({"token": token, "error": "method not allowed"}).encode() + b"\n"
            elif self.path == "/state":
                fields["ETag"] = etag
                fields["Cache-Control"] = "no-cache"
                if self.headers.get("If-None-Match") == etag:
                    status, body = 304, b""
            elif self.path == "/redirect":
                status, fields["Location"] = 307, "/state"
                body = json.dumps({"token": token, "next": "/state"}).encode() + b"\n"
            elif self.path == "/unavailable":
                status, fields["Retry-After"] = 503, str(retry)
                body = json.dumps({"token": token, "error": "planned local unavailability"}).encode() + b"\n"
            elif self.path == "/binary":
                fields["Content-Type"], body = "application/octet-stream", b"\x00\x01\xff\xfe"
            else:
                status = 404
                body = json.dumps({"token": token, "error": "resource not found"}).encode() + b"\n"
            self.send_response(status)
            self.send_header("Connection", "close")
            self.send_header("X-Lab-Token", token)
            for key, value in fields.items():
                self.send_header(key, value)
            # A 304 has no content. Omit Content-Length rather than advertising
            # a length that differs from the selected 200 representation.
            if status != 304:
                self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            actual_body = b"" if self.command == "HEAD" else body
            self.wfile.write(actual_body)
            self.wfile.flush()
            requests.append({
                "at": now(), "method": self.command, "path": self.path,
                "requestLine": self.raw_requestline.decode("ascii"),
                "requestHeaders": dict(self.headers), "status": status,
                "bodyBase64": encoded(actual_body), "etag": fields.get("ETag"),
                "local": list(self.connection.getsockname()),
                "peer": list(self.connection.getpeername()),
            })

    def stop(_signum, _frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGALRM, stop)
    signal.alarm(45)
    server = HTTPServer(("127.0.0.1", 0), Handler)
    server.timeout = 2
    ready = {"pid": os.getpid(), "uid": os.geteuid(), "address": "127.0.0.1",
             "port": server.server_port, "token": token}
    print(json.dumps({"ready": ready}), flush=True)
    try:
        server.serve_forever(poll_interval=0.05)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        print(json.dumps({"worker": ready, "requests": requests}), flush=True)
    return 0


def read_ready(child):
    readable, _, _ = select.select([child.stdout], [], [], 3)
    if not readable:
        raise TimeoutError("owned HTTP service did not announce readiness")
    raw = child.stdout.readline()
    if not raw or len(raw) > 2048:
        raise ValueError("invalid HTTP service readiness")
    return raw.decode("ascii"), json.loads(raw)["ready"]


def exchange(port, method, path, extra=None, host=None):
    host = host or "127.0.0.1:" + str(port)
    fields = {"Host": host, "Connection": "close", **(extra or {})}
    if method == "POST":
        fields["Content-Length"] = "0"
    request = (method + " " + path + " HTTP/1.1\r\n" +
               "".join(key + ": " + value + "\r\n" for key, value in fields.items()) +
               "\r\n").encode("ascii")
    started = now()
    deadline = time.monotonic() + 3
    chunks, size = [], 0
    with socket.create_connection(("127.0.0.1", port), timeout=2) as client:
        local, peer = list(client.getsockname()), list(client.getpeername())
        client.sendall(request)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("HTTP response exceeded its overall deadline")
            client.settimeout(min(2, remaining))
            chunk = client.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > 65536:
                raise ValueError("HTTP response exceeded its size boundary")
    raw = b"".join(chunks)
    header, body = raw.split(b"\r\n\r\n", 1)
    lines = header.decode("ascii").split("\r\n")
    version, status, reason = lines[0].split(" ", 2)
    headers = {}
    for line in lines[1:]:
        key, value = line.split(":", 1)
        key = key.lower()
        if key in headers:
            raise ValueError("unexpected repeated response header")
        headers[key] = value.strip()
    return {"method": method, "path": path, "requestHeaders": fields,
            "requestBase64": encoded(request), "responseBase64": encoded(raw),
            "version": version, "status": int(status), "reason": reason,
            "headers": headers, "bodyBase64": encoded(body),
            "local": local, "peer": peer, "startTime": started, "endTime": now(),
            "readToEOF": True, "deadlineSeconds": 3, "responseLimitBytes": 65536}


def observe(kind, message, changed, hold_ms, evidence):
    if sys.platform != "linux" or os.geteuid() == 0:
        raise ValueError("use an ordinary account in an external Linux terminal")
    if kind not in ("core", "transfer", "extension"):
        raise ValueError("unknown application-protocol task")
    if not message or len(message.encode()) > 160 or any(ord(c) < 32 for c in message):
        raise ValueError("message must contain 1 to 160 printable UTF-8 bytes")
    if not 0 <= hold_ms <= 2000:
        raise ValueError("hold milliseconds must be between 0 and 2000")
    curl, ss = shutil.which("curl"), shutil.which("ss")
    if not curl or not ss:
        raise ValueError("curl and ss are required")
    retry = 2 if changed else 1
    evidence.update(kind=kind, environment={"platform": sys.platform, "uid": os.geteuid(),
                    "parentPid": os.getpid(), "networkNamespace": os.readlink("/proc/self/ns/net")},
                    message=message, changed=changed, retrySeconds=retry,
                    commands=[], exchanges=[], configuredSystemState=False,
                    dnsMeasured=False, tlsMeasured=False, sshMeasured=False,
                    suppliedCasesAreConstructed=True, learnerWorksheetCompletionInferred=False)
    token = uuid.uuid4().hex
    argv = [sys.executable, "-u", str(Path(__file__).resolve()), "--serve", token, message, str(retry)]
    started = now()
    child = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    proc = {"parentTask": "application-protocol-observation", "parentPid": os.getpid(),
            "cwd": os.getcwd(), "command": argv, "pid": child.pid, "startTime": started,
            "timeoutSeconds": 45, "readinessDeadlineSeconds": 3,
            "stopDeadlineSeconds": 3, "childProcessGroupCleanup": "pending"}
    evidence["serverProcess"] = proc
    control = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    port = None
    try:
        control.bind(("127.0.0.1", 0))
        evidence["refusalControl"] = {"address": "127.0.0.1", "port": control.getsockname()[1],
                                      "heldWithoutListen": True}
        raw, ready = read_ready(child)
        evidence.update(readyLine=raw, ready=ready)
        if ready["pid"] != child.pid or ready["uid"] != os.geteuid() or ready["token"] != token:
            raise ValueError("service identity mismatch")
        port = ready["port"]
        evidence["workerProcUidFields"] = next(line.split()[1:] for line in
            Path("/proc/" + str(child.pid) + "/status").read_text().splitlines() if line.startswith("Uid:"))
        evidence["listenersDuring"] = command([ss, "-H", "-ltnp", "sport = :" + str(port)], evidence)["stdout"]
        time.sleep(hold_ms / 1000)
        plans = {
            "core": [("GET", "/state"), ("HEAD", "/state"), ("GET", "/missing"),
                     ("POST", "/state"), ("GET", "/unavailable")],
            "transfer": [("GET", "/state"), ("GET", "/state"), ("GET", "/state"),
                         ("HEAD", "/state"), ("GET", "/redirect"), ("GET", "/state")],
            "extension": [("GET", "/unavailable"), ("GET", "/missing"),
                          ("POST", "/state"), ("GET", "/binary"), ("GET", "/state")],
        }
        for i, (method, path) in enumerate(plans[kind]):
            extra = None
            if kind == "transfer" and i in (1, 2):
                extra = {"If-None-Match": evidence["exchanges"][0]["headers"]["etag"] if i == 1 else '"stale-version"'}
            host = "representation.invalid" if kind == "extension" and i == 4 else None
            evidence["exchanges"].append(exchange(port, method, path, extra, host))
        common = [curl, "--noproxy", "*", "--http1.1", "--silent", "--show-error",
                  "--include", "--connect-timeout", "1", "--max-time", "2"]
        evidence["curlGet"] = command([*common, "http://127.0.0.1:" + str(port) + "/state"], evidence)
        evidence["curlHead"] = command([*common, "--head", "http://127.0.0.1:" + str(port) + "/state"], evidence)
        evidence["curlRefusal"] = command([*common, "http://127.0.0.1:" + str(control.getsockname()[1]) + "/state"], evidence)
        evidence["refusalControl"]["heldDuringProbe"] = True
    finally:
        control.close()
        if child.poll() is None:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(child.pid, signal.SIGTERM)
        cleanup = "owned service stopped and reaped"
        try:
            out, err = child.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL)
            out, err = child.communicate(timeout=2)
            cleanup = "owned service killed after deadline and reaped"
        proc.update(endTime=now(), exitCode=child.returncode, childProcessGroupCleanup=cleanup,
                    stdout=out.decode("ascii"), stderr=err.decode("utf-8"))
        evidence["serverReaped"] = child.poll() is not None
        for line in out.splitlines():
            message_record = json.loads(line)
            if "ready" in message_record and "ready" not in evidence:
                evidence.update(readyLine=line.decode("ascii") + "\n", ready=message_record["ready"])
                port = evidence["ready"]["port"]
            if "worker" in message_record:
                evidence["workerResult"] = message_record
        if port is not None:
            evidence["listenersAfter"] = command([ss, "-H", "-ltnp", "sport = :" + str(port)], evidence)["stdout"]


if __name__ == "__main__":
    if len(sys.argv) != 5 or sys.argv[1] != "--serve" or os.geteuid() == 0:
        raise SystemExit(2)
    raise SystemExit(serve(sys.argv[2], sys.argv[3], int(sys.argv[4])))
