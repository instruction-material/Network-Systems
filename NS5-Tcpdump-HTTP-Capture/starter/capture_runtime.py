"""Capture only owned HTTP traffic in a disposable Linux network namespace."""
import argparse
import base64
import contextlib
import datetime
import hashlib
import http.server
import json
import os
import selectors
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def command(argv, records, timeout=5, check=True):
    started = now()
    process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               start_new_session=True)
    cleanup = "exited and reaped"
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except BaseException:
        cleanup = "terminated and reaped owned process group"
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGTERM)
        try:
            process.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate(timeout=3)
        raise
    finally:
        records.append({"command": argv, "cwd": str(Path.cwd()), "parentPid": os.getpid(),
                        "pid": process.pid, "startTime": started, "endTime": now(),
                        "exitCode": process.returncode, "timeoutSeconds": timeout,
                        "childProcessGroupCleanup": cleanup})
    result = {"exitCode": process.returncode, "stdout": stdout.decode(), "stderr": stderr.decode()}
    if check and process.returncode:
        raise RuntimeError(f"command failed: {argv[0]}: {result['stderr'].strip()}")
    return result


def firewall_configuration(text):
    import re
    return "\n".join(re.sub(r" \[\d+:\d+\]$", "", line)
                     for line in text.splitlines() if not line.startswith("#"))


def host_state(records):
    return {"networkNamespace": os.readlink("/proc/self/ns/net"),
            "links": command(["ip", "-j", "link", "show"], records)["stdout"],
            "routes": command(["ip", "-j", "route", "show", "table", "all"], records)["stdout"],
            "firewall": firewall_configuration(command(["iptables-save"], records)["stdout"]),
            "forwarding": command(["sysctl", "-n", "net.ipv4.ip_forward"], records)["stdout"]}


def require_owned_namespace(original):
    if not original or os.readlink("/proc/self/ns/net") in (original, os.readlink("/proc/1/ns/net")):
        raise RuntimeError("refusing to capture or open lab sockets in the original network namespace")


def publish_ready(path, content):
    temporary = path.with_name(path.name + ".pending")
    descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(descriptor, "w") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        # This marker is in the run's private TemporaryDirectory.
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def serve(args):
    require_owned_namespace(args.origin)

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            body = json.dumps({"token": args.serve, "port": self.server.server_port,
                               "pid": os.getpid(), "path": self.path}, sort_keys=True).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            self.close_connection = True

        def log_message(self, *_args):
            pass

    servers = [http.server.HTTPServer(("127.0.0.1", port), Handler) for port in (8080, 8081)]
    for server in servers:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    publish_ready(Path(args.worker_ready), json.dumps({"pid": os.getpid(), "token": args.serve,
                  "ports": [server.server_port for server in servers],
                  "networkNamespace": os.readlink("/proc/self/ns/net")}) + "\n")
    while True:
        time.sleep(1)


def request(args):
    require_owned_namespace(args.origin)
    wire = (f"GET /capture/{args.token} HTTP/1.1\r\nHost: owned-lab.invalid\r\n"
            "Connection: close\r\n\r\n").encode()
    with socket.create_connection(("127.0.0.1", args.request), timeout=2) as client:
        client.settimeout(2)
        local, peer = client.getsockname(), client.getpeername()
        client.sendall(wire)
        chunks = []
        while block := client.recv(4096):
            chunks.append(block)
            if sum(map(len, chunks)) > 65536:
                raise RuntimeError("owned response exceeded its size limit")
    response = b"".join(chunks)
    headers, body = response.split(b"\r\n\r\n", 1)
    assert headers.startswith(b"HTTP/1.1 200 ")
    data = json.loads(body)
    assert data["token"] == args.token and data["port"] == args.request
    print(json.dumps({"local": local, "peer": peer, "requestBase64": base64.b64encode(wire).decode(),
                      "responseBase64": base64.b64encode(response).decode(), "body": data,
                      "networkNamespace": os.readlink("/proc/self/ns/net")}))


def packets(raw):
    if len(raw) < 24:
        raise RuntimeError("capture does not contain a complete pcap header")
    magic = raw[:4]
    endian = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    if magic not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
        raise RuntimeError("unsupported pcap format")
    assert struct.unpack(endian + "I", raw[20:24])[0] == 1, "expected Linux loopback Ethernet framing"
    rows = []
    offset = 24
    while offset < len(raw):
        assert len(raw) - offset >= 16
        seconds, fraction, captured, original = struct.unpack(endian + "IIII", raw[offset:offset + 16])
        offset += 16
        assert 14 <= captured <= original <= 65536 and offset + captured <= len(raw)
        frame = raw[offset:offset + captured]
        offset += captured
        assert frame[12:14] == b"\x08\x00", "expected the owned IPv4 TCP flow"
        ip = frame[14:]
        ihl = (ip[0] & 15) * 4
        assert ip[0] >> 4 == 4 and ihl >= 20 and ip[9] == 6
        total = struct.unpack(">H", ip[2:4])[0]
        assert total <= len(ip) and not struct.unpack(">H", ip[6:8])[0] & 0x3fff
        tcp = ip[ihl:total]
        assert len(tcp) >= 20
        source, destination, sequence, acknowledgement = struct.unpack(">HHII", tcp[:12])
        header = (tcp[12] >> 4) * 4
        assert 20 <= header <= len(tcp)
        rows.append({"seconds": seconds, "fraction": fraction,
                     "source": socket.inet_ntoa(ip[12:16]), "destination": socket.inet_ntoa(ip[16:20]),
                     "sourcePort": source, "destinationPort": destination, "sequence": sequence,
                     "acknowledgement": acknowledgement, "flags": tcp[13],
                     "payloadBase64": base64.b64encode(tcp[header:]).decode()})
    return rows


def finish(process, argv, started, records, initial=b"", interrupt=False):
    if process.poll() is None:
        process.send_signal(signal.SIGINT if interrupt else signal.SIGTERM)
    cleanup = "exited and reaped"
    try:
        _stdout, stderr = process.communicate(timeout=3)
    except subprocess.TimeoutExpired:
        cleanup = "killed and reaped owned process group"
        os.killpg(process.pid, signal.SIGKILL)
        _stdout, stderr = process.communicate(timeout=3)
    records.append({"command": argv, "cwd": str(Path.cwd()), "parentPid": os.getpid(),
                    "pid": process.pid, "startTime": started, "endTime": now(),
                    "exitCode": process.returncode, "timeoutSeconds": 20,
                    "childProcessGroupCleanup": cleanup})
    return {"pid": process.pid, "exitCode": process.returncode, "reaped": True,
            "stderr": (initial + (stderr or b"")).decode()}


def inside(args):
    require_owned_namespace(args.origin)
    lab = {"networkNamespace": os.readlink("/proc/self/ns/net"), "commands": [], "requests": [],
           "complete": False, "cleanup": {"workerReaped": False, "captureReaped": False}}
    records = lab["commands"]
    capture = worker = None
    capture_initial = b""
    with tempfile.TemporaryDirectory(prefix="ns5-capture-owned-") as temp:
        ready, pcap = Path(temp) / "worker.json", Path(temp) / "capture.pcap"
        try:
            command(["ip", "link", "set", "lo", "up"], records)
            lab["tcpdumpVersion"] = command(["tcpdump", "--version"], records)
            settings = json.loads(command(["bash", str(Path(__file__).with_name("capture-options.sh"))], records)["stdout"])
            assert set(settings) == {"packetLimit", "filterPort"}
            assert type(settings["filterPort"]) is bool
            assert type(settings["packetLimit"]) is int and 0 <= settings["packetLimit"] <= 64
            lab["settings"] = settings
            worker_argv = [sys.executable, str(Path(__file__).resolve()), "--serve", args.token,
                           "--origin", args.origin, "--worker-ready", str(ready)]
            worker_started = now()
            worker = subprocess.Popen(worker_argv, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                      start_new_session=True)
            deadline = time.monotonic() + 3
            while not ready.exists() and worker.poll() is None and time.monotonic() < deadline:
                time.sleep(0.02)
            assert ready.exists(), "owned HTTP listeners did not become ready"
            lab["workerReady"] = json.loads(ready.read_text())
            assert lab["workerReady"]["pid"] == worker.pid and lab["workerReady"]["token"] == args.token
            assert lab["workerReady"]["networkNamespace"] == lab["networkNamespace"]
            expression = "tcp and host 127.0.0.1" + (" and port 8080" if settings["filterPort"] else "")
            capture_argv = ["tcpdump", "--immediate-mode", "-Z", "root", "-U", "-s", "0", "-i", "lo",
                            "-nn", "-w", str(pcap)]
            if settings["packetLimit"]:
                capture_argv += ["-c", str(settings["packetLimit"])]
            capture_argv.append(expression)
            capture_started = now()
            capture = subprocess.Popen(capture_argv, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                       start_new_session=True)
            with selectors.DefaultSelector() as selector:
                selector.register(capture.stderr, selectors.EVENT_READ)
                deadline = time.monotonic() + 3
                while b"listening on lo" not in capture_initial:
                    assert time.monotonic() < deadline and capture.poll() is None, "owned capture did not become ready"
                    if selector.select(0.1):
                        capture_initial += os.read(capture.stderr.fileno(), 4096)
            lab["captureFilter"] = expression
            if args.ready_file:
                with open(args.ready_file, "x", encoding="utf8") as marker:
                    marker.write(args.token + "\n")
            if args.test_mode == "hold":
                time.sleep(5)
                raise RuntimeError("controlled hold reached its bounded deadline")
            for port in ([8080, 8081, 8081] if args.reverse else [8081, 8080, 8081]):
                row = command([sys.executable, str(Path(__file__).resolve()), "--request", str(port),
                               "--origin", args.origin, "--token", args.token], records)
                lab["requests"].append(json.loads(row["stdout"]))
            time.sleep(0.15)
            if args.test_mode == "failure":
                raise RuntimeError("controlled failure after owned HTTP traffic")
        except (RuntimeError, OSError, AssertionError, ValueError, KeyError,
                TypeError, struct.error, subprocess.TimeoutExpired, KeyboardInterrupt) as error:
            lab["error"] = str(error)
        finally:
            if capture:
                lab["capture"] = finish(capture, capture_argv, capture_started, records, capture_initial, True)
                lab["cleanup"]["captureReaped"] = True
            if worker:
                lab["worker"] = finish(worker, worker_argv, worker_started, records)
                lab["cleanup"]["workerReaped"] = True
            if pcap.exists() and pcap.stat().st_size >= 24:
                raw = pcap.read_bytes()
                assert len(raw) <= 4 * 1024 * 1024
                lab["pcapBase64"] = base64.b64encode(raw).decode()
                lab["pcapSha256"] = hashlib.sha256(raw).hexdigest()
                lab["packets"] = packets(raw)
                decode = command(["tcpdump", "-Z", "root", "-nn", "-tt", "-r", str(pcap)], records)
                lab["decoded"] = decode
                target = [row for row in lab["packets"] if 8080 in (row["sourcePort"], row["destinationPort"])]
                noise = [row for row in lab["packets"] if 8081 in (row["sourcePort"], row["destinationPort"])]
                request_visible = any(b"GET /capture/" + args.token.encode() in base64.b64decode(row["payloadBase64"]) for row in target if row["destinationPort"] == 8080)
                response_visible = any(b"HTTP/1.1 200 " in base64.b64decode(row["payloadBase64"]) for row in target if row["sourcePort"] == 8080)
                body_visible = any(args.token.encode() in base64.b64decode(row["payloadBase64"]) for row in target if row["sourcePort"] == 8080)
                flags = [row["flags"] for row in target]
                lab["analysis"] = {"targetPackets": len(target), "noisePackets": len(noise),
                                   "requestVisible": request_visible, "responseVisible": response_visible,
                                   "responseTokenVisible": body_visible,
                                   "synObserved": any(flag & 0x12 == 0x02 for flag in flags),
                                   "synAckObserved": any(flag & 0x12 == 0x12 for flag in flags)}
                lab["complete"] = (not lab.get("error") and settings["packetLimit"] > 0
                                   and settings["filterPort"] and not noise and request_visible and response_visible
                                   and body_visible and lab["analysis"]["synObserved"] and lab["analysis"]["synAckObserved"])
            lab["cleanup"]["remainingLinks"] = json.loads(command(["ip", "-j", "link", "show"], records)["stdout"])
            Path(args.inner_output).write_text(json.dumps(lab, indent=2) + "\n")
    return 2 if lab.get("error") else 0


def outer(args):
    if sys.platform != "linux" or os.geteuid() != 0:
        raise RuntimeError("Use a disposable Linux VM and sudo; no capture or network changes were made.")
    for tool in ("ip", "iptables-save", "sysctl", "unshare", "tcpdump", "bash"):
        if not shutil.which(tool):
            raise RuntimeError(f"required Linux lab tool is missing: {tool}")
    output = Path(args.output)
    if output.exists() or output.is_symlink() or not output.parent.is_dir():
        raise RuntimeError("the observation output must be a new file in an existing directory")
    result = {"token": uuid.uuid4().hex, "commands": [], "complete": False}
    records = result["commands"]
    result["hostBefore"] = host_state(records)
    with tempfile.TemporaryDirectory(prefix="ns5-outer-owned-") as temp:
        inside_output = Path(temp) / "inside.json"
        argv = ["unshare", "--net", sys.executable, str(Path(__file__).resolve()),
                "--inside", "--origin", result["hostBefore"]["networkNamespace"],
                "--token", result["token"], "--inner-output", str(inside_output),
                "--test-mode", args.test_mode]
        if args.reverse:
            argv.append("--reverse")
        if args.ready_file:
            argv += ["--ready-file", args.ready_file]
        try:
            run = command(argv, records, timeout=20, check=False)
            if run["exitCode"]:
                result["error"] = run["stderr"] or "owned capture lab did not complete"
        except (RuntimeError, OSError, AssertionError, ValueError, KeyError,
                TypeError, struct.error, subprocess.TimeoutExpired, KeyboardInterrupt) as error:
            result["error"] = str(error)
        finally:
            if inside_output.exists():
                result["lab"] = json.loads(inside_output.read_text())
                result["complete"] = bool(result["lab"]["complete"]) and "error" not in result
            result["hostAfter"] = host_state(records)
            result["hostUnchanged"] = result["hostBefore"] == result["hostAfter"]
            if not result["hostUnchanged"]:
                result["error"] = "host network configuration changed during the experiment"
                result["complete"] = False
            with output.open("x", encoding="utf8") as stream:
                json.dump(result, stream, indent=2)
                stream.write("\n")
    print(json.dumps({"output": str(output), "complete": result["complete"], "hostUnchanged": result["hostUnchanged"]}))
    return 2 if result.get("error") else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="capture-observations.json", help="New JSON report including the actual pcap and decoded packets.")
    parser.add_argument("--reverse", action="store_true", help="Request the selected service before the independent noise service.")
    parser.add_argument("--inside", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--origin", help=argparse.SUPPRESS)
    parser.add_argument("--token", help=argparse.SUPPRESS)
    parser.add_argument("--inner-output", help=argparse.SUPPRESS)
    parser.add_argument("--worker-ready", help=argparse.SUPPRESS)
    parser.add_argument("--ready-file", help=argparse.SUPPRESS)
    parser.add_argument("--serve", help=argparse.SUPPRESS)
    parser.add_argument("--request", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--test-mode", choices=("normal", "failure", "hold"), default="normal", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.serve:
        serve(args)
        return 0
    if args.request:
        request(args)
        return 0

    def interrupted(signum, _frame):
        raise RuntimeError(f"interrupted by signal {signum}")

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    return inside(args) if args.inside else outer(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, AssertionError, ValueError, OSError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(2)
