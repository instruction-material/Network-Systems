"""Owned loopback diagnostics; source commands remain visible in the report."""
import argparse
import base64
import contextlib
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = Path(__file__).resolve().parent
FIELDS = {"targetAddress": {"owned", "reserved"}, "targetPort": {"owned", "reserved"},
          "scheme": {"http", "https"}, "responseMode": {"http", "silent"},
          "httpStatus": {200, 500}}


class LabInterrupted(Exception):
    pass


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def write_new(path, data):
    with path.open("x") as output:
        json.dump(data, output, indent=2)
        output.write("\n")


def read_case(path):
    if path.stat().st_size > 4096:
        raise ValueError("case.json is too large")
    value = json.loads(path.read_text())
    if not isinstance(value, dict) or set(value) != set(FIELDS):
        raise ValueError("case.json must contain exactly the five documented choices")
    for key, allowed in FIELDS.items():
        expected = int if key == "httpStatus" else str
        if type(value[key]) is not expected or value[key] not in allowed:
            raise ValueError("invalid choice: " + key)
    return value


def terminate(child):
    if child.poll() is None:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(child.pid, signal.SIGTERM)
        try:
            child.wait(timeout=4)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(child.pid, signal.SIGKILL)
            child.wait(timeout=3)


def command(argv, records, timeout=25):
    started = now()
    child = subprocess.Popen(argv, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             start_new_session=True, env=dict(os.environ, LC_ALL="C"))
    cleanup = "completed and reaped"
    stdout, stderr = b"", b""
    try:
        stdout, stderr = child.communicate(timeout=timeout)
    except BaseException:
        cleanup = "owned command process group terminated and reaped"
        terminate(child)
        stdout, stderr = child.communicate(timeout=3)
        raise
    finally:
        record = {"command": [str(x) for x in argv], "cwd": str(ROOT),
                  "parentPid": os.getpid(), "pid": child.pid, "startTime": started,
                  "endTime": now(), "exitCode": child.returncode, "timeoutSeconds": timeout,
                  "childProcessGroupCleanup": cleanup,
                  "stdout": stdout.decode(errors="replace"), "stderr": stderr.decode(errors="replace")}
        records.append(record)
    return record


def host_snapshot(records):
    raw = {}
    for name, argv in [("addresses", ["ip", "-j", "address", "show"]),
                       ("routes", ["ip", "-j", "route", "show", "table", "all"])]:
        row = command(argv, records)
        if row["exitCode"] != 0:
            raise RuntimeError("read-only host snapshot failed: " + name)
        raw[name] = json.loads(row["stdout"])
    addresses = []
    for link in raw["addresses"]:
        stable = {k: link.get(k) for k in ["ifindex", "ifname", "mtu", "operstate", "flags"]}
        stable["addr_info"] = [{k: address.get(k) for k in ["family", "local", "prefixlen", "scope", "label"]}
                               for address in link.get("addr_info", [])]
        addresses.append(stable)
    routes = [{k: route.get(k) for k in ["dst", "gateway", "dev", "protocol", "scope",
                                        "prefsrc", "metric", "type", "table", "pref"]}
              for route in raw["routes"]]
    return {"uid": os.getuid(), "cwd": os.getcwd(),
            "networkNamespace": os.readlink("/proc/self/ns/net"),
            "addresses": addresses, "routes": routes}, raw


def worker(directory, specification):
    directory = Path(directory)
    spec = json.loads(Path(specification).read_text())
    stopped = threading.Event()
    lock = threading.Lock()
    requests, errors = [], []
    token = uuid.uuid4().hex

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def handle_one_request(self):
            # Reject a TLS handshake on this intentionally plain HTTP fixture
            # without depending on random newline bytes inside ClientHello.
            first = self.connection.recv(1, socket.MSG_PEEK)
            if first == bytes([22]):
                raw = self.connection.recv(4096)
                with lock:
                    errors.append({"status": 400, "requestLineBase64": base64.b64encode(raw).decode()})
                self.connection.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                self.close_connection = True
                return
            return super().handle_one_request()

        def do_HEAD(self):
            with lock:
                requests.append({"method": "HEAD", "path": self.path, "peer": list(self.client_address),
                                 "requestLineBase64": base64.b64encode(self.raw_requestline).decode(),
                                 "at": now()})
            if spec["case"]["responseMode"] == "silent":
                stopped.wait(12)
                return
            self.send_response(spec["case"]["httpStatus"])
            headers = [("X-Owned-Diagnostics", token), ("Content-Length", "0"),
                       ("Connection", "close")]
            if spec["alternate"]:
                headers.reverse()
            for key, value in headers:
                self.send_header(key, value)
            self.end_headers()

        def send_error(self, code, message=None, explain=None):
            with lock:
                errors.append({"status": code,
                               "requestLineBase64": base64.b64encode(self.raw_requestline).decode()})
            return super().send_error(code, message, explain)

        def log_message(self, *_):
            pass

    class Server(ThreadingHTTPServer):
        daemon_threads = False
        block_on_close = True

    reservations = []
    server = None
    try:
        # Hold both refused endpoints ourselves, so the exercise cannot probe a
        # coincidentally reused service. No interface address is installed.
        for attempt in range(20):
            server = Server(("127.0.0.1", 0), Handler)
            other = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                other.bind(("127.0.0.2", server.server_port))
            except OSError:
                other.close()
                server.server_close()
                server = None
                continue
            reservations.append(other)
            break
        if server is None:
            raise RuntimeError("cannot reserve the owned loopback comparison")
        held = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        held.bind(("127.0.0.1", 0))
        reservations.append(held)
        server.timeout = 0.1
        ready = {"pid": os.getpid(), "uid": os.getuid(), "token": token,
                 "host": "127.0.0.1", "servicePort": server.server_port,
                 "reservedAddress": "127.0.0.2", "reservedPort": held.getsockname()[1],
                 "networkNamespace": os.readlink("/proc/self/ns/net"),
                 "case": spec["case"], "alternate": spec["alternate"]}
        write_new(directory / "ready.json", ready)

        def stop(*_):
            stopped.set()

        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        deadline = time.monotonic() + 40
        while not stopped.is_set() and time.monotonic() < deadline:
            server.handle_request()
        stopped.set()
    finally:
        stopped.set()
        if server is not None:
            server.server_close()
        for reservation in reservations:
            reservation.close()
        if "ready" in locals():
            write_new(directory / "worker.json", dict(ready, requests=requests, protocolErrors=errors,
                      socketClosed=server.socket.fileno() == -1,
                      allReservationsClosed=all(sock.fileno() == -1 for sock in reservations),
                      stopped=True))


def sections(stdout):
    found = {}
    chunks = re.split(r"^== (.+) ==\n", stdout, flags=re.M)
    for index in range(1, len(chunks), 2):
        body = chunks[index + 1]
        statuses = re.findall(r"^command status: (\d+)$", body, flags=re.M)
        if len(statuses) != 1:
            raise RuntimeError("incomplete diagnostic section")
        found[chunks[index]] = {"exitCode": int(statuses[0]), "raw": body}
    if len(found) != 7:
        raise RuntimeError("the seven diagnostic sections were not retained")
    return found


def wire_control(ready):
    request = b"HEAD / HTTP/1.1\r\nHost: owned-lab.invalid\r\nConnection: close\r\n\r\n"
    received = bytearray()
    timed_out = False
    started = now()
    with socket.create_connection((ready["host"], ready["servicePort"]), timeout=1) as client:
        local, peer = list(client.getsockname()), list(client.getpeername())
        client.sendall(request)
        try:
            while b"\r\n\r\n" not in received and len(received) < 16384:
                chunk = client.recv(1024)
                if not chunk:
                    break
                received.extend(chunk)
        except socket.timeout:
            timed_out = True
    return {"requestHex": request.hex(), "receivedHex": bytes(received).hex(),
            "timedOut": timed_out, "local": local, "peer": peer, "socketClosed": client.fileno() == -1,
            "startTime": started, "endTime": now()}


def run(args):
    if sys.platform != "linux" or os.getuid() == 0:
        raise ValueError("Run as an ordinary user in the owned Linux lab")
    for name in ["bash", "timeout", "ss", "curl", "nc", "ip"]:
        if shutil.which(name) is None:
            raise ValueError("missing required command: " + name)
    case_file = args.case.resolve() if args.case else ROOT / "case.json"
    case = read_case(case_file)
    report_path = args.report.resolve()
    source_names = ["main.py", "diagnostics_lab.py", "diagnose_reachability.sh"]
    before = {name: digest((ROOT / name).read_bytes()) for name in source_names}
    case_bytes = case_file.read_bytes()
    # Reserve the exact fresh destination before creating a worker or socket.
    with report_path.open("x") as destination:
        report = {"startedAt": now(), "complete": False, "case": case, "caseFileSHA256": digest(case_bytes),
                  "alternate": args.alternate, "sourceFiles": before, "commands": [],
                  "notebookCompletionInferred": False, "testMode": args.test_mode}
        worker_child = None
        previous_handlers = {}
        def interrupted(*_):
            raise LabInterrupted("lab interrupted; owned processes are being closed")
        for sig in [signal.SIGINT, signal.SIGTERM]:
            previous_handlers[sig] = signal.signal(sig, interrupted)
        error = None
        try:
            stable_before, raw_before = host_snapshot(report["commands"])
            report.update(hostBefore=stable_before, rawHostBefore=raw_before)
            with tempfile.TemporaryDirectory(prefix="diagnostics owned quoted ") as temporary:
                work = Path(temporary)
                write_new(work / "specification.json", {"case": case, "alternate": args.alternate})
                log = (work / "worker.log").open("wb")
                argv = [sys.executable, "-B", str(ROOT / "diagnostics_lab.py"), "--worker", str(work),
                        "--specification", str(work / "specification.json")]
                worker_started = now()
                worker_child = subprocess.Popen(argv, cwd=work, stdout=log, stderr=log, start_new_session=True)
                try:
                    deadline = time.monotonic() + 5
                    while not (work / "ready.json").exists() and worker_child.poll() is None and time.monotonic() < deadline:
                        time.sleep(0.02)
                    if not (work / "ready.json").exists():
                        raise RuntimeError("owned worker did not become ready: " + (work / "worker.log").read_text())
                    ready = json.loads((work / "ready.json").read_text())
                    if ready["pid"] != worker_child.pid or ready["uid"] != os.getuid():
                        raise RuntimeError("owned worker identity mismatch")
                    report["ready"] = ready
                    if args.ready_file:
                        write_new(args.ready_file, dict(ready, controllerPid=os.getpid()))
                    if args.test_mode == "failure":
                        raise RuntimeError("intentional failure after owned listener setup")
                    if args.test_mode == "hold":
                        while True:
                            time.sleep(0.1)
                    address = ready["host"] if case["targetAddress"] == "owned" else ready["reservedAddress"]
                    port = ready["servicePort"] if case["targetPort"] == "owned" else ready["reservedPort"]
                    result = command(["bash", str(ROOT / "diagnose_reachability.sh"), address, str(port), case["scheme"]],
                                     report["commands"])
                    report.update(selectedTarget={"address": address, "port": port, "scheme": case["scheme"]},
                                  diagnostic=result, sections=sections(result["stdout"]),
                                  control=wire_control(ready))
                    if result["exitCode"] != 0:
                        raise RuntimeError("diagnostic collector failed")
                    target = report["sections"]["Target HTTP observation from this machine"]
                    transport = report["sections"]["Target TCP observation from this machine"]
                    matches = re.findall(r"^HTTP/\S+ (\d{3})\b", target["raw"], re.M)
                    observed_status = int(matches[-1]) if matches else None
                    observed_token = "X-Owned-Diagnostics: " + ready["token"] in target["raw"]
                    report["targetHTTPStatus"] = observed_status
                    report["targetTokenObserved"] = observed_token
                    report["complete"] = target["exitCode"] == transport["exitCode"] == 0 and observed_status == 200 and observed_token
                finally:
                    terminate(worker_child)
                    log.close()
                    report["workerProcess"] = {"command": argv, "cwd": str(work), "parentPid": os.getpid(),
                        "pid": worker_child.pid, "startTime": worker_started, "endTime": now(),
                        "exitCode": worker_child.returncode, "timeoutSeconds": 40,
                        "childProcessGroupCleanup": "owned worker and request threads closed and reaped"}
                    if (work / "worker.json").exists():
                        report["worker"] = json.loads((work / "worker.json").read_text())
                    report["workerLog"] = (work / "worker.log").read_text()
            report["temporaryWorkspaceRemoved"] = not work.exists()
        except BaseException as exception:
            report["complete"] = False
            report["error"] = str(exception)
            error = exception
        finally:
            # Further signals cannot interrupt restoration and evidence retention.
            for sig in previous_handlers:
                signal.signal(sig, signal.SIG_IGN)
            try:
                if worker_child is not None:
                    terminate(worker_child)
                if "work" in locals():
                    report["temporaryWorkspaceRemoved"] = not work.exists()
                if "hostBefore" in report:
                    stable_after, raw_after = host_snapshot(report["commands"])
                    report.update(hostAfter=stable_after, rawHostAfter=raw_after,
                                  hostUnchanged=stable_after == report["hostBefore"])
                    if not report["hostUnchanged"]:
                        raise RuntimeError("host configuration changed during the experiment")
                after = {name: digest((ROOT / name).read_bytes()) for name in source_names}
                report["sourceUnchanged"] = after == before and case_file.read_bytes() == case_bytes
                if not report["sourceUnchanged"]:
                    raise RuntimeError("project source changed during the experiment")
            except BaseException as exception:
                report["complete"] = False
                report["cleanupError"] = str(exception)
                error = error or exception
            finally:
                for sig, handler in previous_handlers.items():
                    signal.signal(sig, handler)
                report["endedAt"] = now()
                json.dump(report, destination, indent=2)
                destination.write("\n")
        if error is not None:
            raise error
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, default=Path("diagnostic-report.json"))
    parser.add_argument("--case", type=Path)
    parser.add_argument("--alternate", action="store_true")
    parser.add_argument("--test-mode", choices=["normal", "failure", "hold"], default="normal")
    parser.add_argument("--ready-file", type=Path)
    parser.add_argument("--worker", type=Path)
    parser.add_argument("--specification", type=Path)
    args = parser.parse_args()
    if args.worker:
        worker(args.worker, args.specification)
        return 0
    try:
        report = run(args)
    except (Exception, KeyboardInterrupt) as error:
        print(str(error), file=sys.stderr)
        return 2
    print(json.dumps({"report": str(args.report), "complete": report["complete"],
                      "targetHTTPStatus": report["targetHTTPStatus"], "notebookCompletionInferred": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
