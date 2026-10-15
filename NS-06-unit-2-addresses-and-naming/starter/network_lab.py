"""Owned Linux socket instrumentation reused by the addressing labs."""
import contextlib
import datetime
import http.server
import json
import os
import platform
import selectors
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

TOOLS = ("ip", "ss", "curl", "ssh", "dig", "traceroute", "getent")


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def require_linux():
    if sys.platform != "linux" or os.geteuid() == 0:
        raise ValueError("Run as an ordinary user in the chosen Linux lab.")


def validate(message, udp_buffer):
    size = len(message.encode("utf-8"))
    if not 2 <= size <= 128 or "\n" in message or "\r" in message:
        raise ValueError("Use one message of 2 to 128 UTF-8 bytes, without newlines.")
    if not 1 <= udp_buffer <= 256:
        raise ValueError("The UDP receive buffer must be between 1 and 256 bytes.")


def command(args, observations):
    started = now()
    process = subprocess.Popen(
        args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        start_new_session=True,
    )
    cleanup = "exited and reaped"
    try:
        stdout, stderr = process.communicate(timeout=8)
    except BaseException:
        cleanup = "owned process group terminated"
        if process.poll() is None:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGTERM)
        try:
            stdout, stderr = process.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            stdout, stderr = process.communicate()
        raise
    finally:
        observations.append({
            "command": args, "pid": process.pid, "startTime": started,
            "parentPid": os.getpid(), "task": "network-addressing-lab",
            "cwd": str(Path.cwd()),
            "endTime": now(), "exitCode": process.returncode,
            "timeoutSeconds": 8, "cleanup": cleanup,
        })
    row = observations[-1]
    row.update(stdout=stdout.decode("utf-8"), stderr=stderr.decode("utf-8"))
    if process.returncode:
        raise ValueError(f"Command failed: {args[0]}: {row['stderr']}")
    return row["stdout"]


def endpoint(address):
    return {"address": address[0], "port": address[1]}


def read_ready(process):
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        if not selector.select(8):
            raise TimeoutError("Owned worker did not announce its endpoints.")
    line = process.stdout.readline(4096)
    if not line.endswith(b"\n"):
        raise ValueError("Incomplete owned worker announcement.")
    return json.loads(line)


def with_worker(kind, config, operate, evidence):
    args = [sys.executable, str(Path(__file__).resolve()), "--worker", kind,
            json.dumps(config, ensure_ascii=True)]
    started = now()
    process = subprocess.Popen(
        args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        start_new_session=True, bufsize=0,
    )
    cleanup = "exited and reaped"
    try:
        ready = read_ready(process)
        if ready["pid"] != process.pid:
            raise ValueError("Worker identity did not match the spawned child.")
        evidence["ready"] = ready
        operate(ready)
        stdout, stderr = process.communicate(timeout=8)
        if process.returncode or stderr:
            raise ValueError(f"Owned worker failed: {stderr.decode('utf-8')}")
        evidence["workerResult"] = json.loads(stdout)
    finally:
        if process.poll() is None:
            cleanup = "owned process group terminated"
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
        for pipe in (process.stdout, process.stderr):
            pipe.close()
        evidence["workerProcess"] = {
            "command": args, "pid": process.pid, "startTime": started,
            "parentPid": os.getpid(), "task": "network-addressing-lab",
            "cwd": str(Path.cwd()),
            "endTime": now(), "exitCode": process.returncode,
            "timeoutSeconds": 8, "cleanup": cleanup,
            "reaped": process.poll() is not None,
        }


def environment():
    tools = {name: shutil.which(name) for name in TOOLS}
    missing = [name for name, path in tools.items() if path is None]
    if missing:
        raise ValueError("Install the lab tools first: " + ", ".join(missing))
    return {
        "platform": sys.platform, "kernel": platform.release(),
        "hostname": socket.gethostname(), "uid": os.geteuid(),
        "pid": os.getpid(), "cwd": str(Path.cwd()),
        "networkNamespace": os.readlink("/proc/self/ns/net"), "tools": tools,
    }


def setup(message):
    require_linux()
    validate(message, 256)
    result = {"kind": "setup", "message": message,
              "environment": environment(), "commands": []}
    commands = result["commands"]
    tools = result["environment"]["tools"]
    result["loopback"] = json.loads(command(
        [tools["ip"], "-j", "address", "show", "dev", "lo"], commands,
    ))
    result["route"] = json.loads(command(
        [tools["ip"], "-j", "route", "get", "127.0.0.1"], commands,
    ))

    def operate(ready):
        result["listenersDuring"] = command(
            [tools["ss"], "-H", "-ltnp"], commands,
        )
        url = f"http://127.0.0.1:{ready['http']['port']}/lab"
        raw = command([
            tools["curl"], "--noproxy", "*", "--silent", "--show-error",
            "--fail", "--max-time", "5", url,
        ], commands)
        result["httpResponse"] = json.loads(raw)

    with_worker("setup", {"message": message}, operate, result)
    result["listenersAfter"] = command([tools["ss"], "-H", "-ltnp"], commands)
    return result


def transport(message, udp_buffer=256, newline=True):
    require_linux()
    validate(message, udp_buffer)
    result = {"kind": "transport", "message": message,
              "udpBuffer": udp_buffer, "newline": newline,
              "environment": environment(), "commands": []}
    tools = result["environment"]["tools"]
    wire = message.encode("utf-8") + (b"\n" if newline else b"")

    def operate(ready):
        result["tcpListenersDuring"] = command(
            [tools["ss"], "-H", "-ltnp"], result["commands"],
        )
        result["udpListenersDuring"] = command(
            [tools["ss"], "-H", "-lunp"], result["commands"],
        )
        with socket.create_connection(
            ("127.0.0.1", ready["tcp"]["port"]), timeout=5,
        ) as client:
            result["tcpClient"] = endpoint(client.getsockname())
            client.sendall(wire[:2])
            if client.recv(1) != b"K":
                raise ValueError("The first TCP fragment was not acknowledged.")
            client.sendall(wire[2:])
            client.shutdown(socket.SHUT_WR)
            chunks = []
            while True:
                chunk = client.recv(256)
                if not chunk:
                    break
                chunks.append(chunk.hex())
            result["tcpEchoChunksHex"] = chunks
        echoes = []
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(5)
            client.connect(("127.0.0.1", ready["udp"]["port"]))
            result["udpClient"] = endpoint(client.getsockname())
            for datagram in (b"", message.encode("utf-8")):
                client.send(datagram)
                data = client.recv(256)
                echoes.append(data.hex())
        result["udpEchoesHex"] = echoes

    with_worker("transport", {"udpBuffer": udp_buffer}, operate, result)
    result["tcpListenersAfter"] = command(
        [tools["ss"], "-H", "-ltnp"], result["commands"],
    )
    result["udpListenersAfter"] = command(
        [tools["ss"], "-H", "-lunp"], result["commands"],
    )
    return result


def setup_worker(config):
    captured = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(5)

        def do_GET(self):
            captured.append(self.path)
            body = json.dumps(
                {"message": config["message"], "path": self.path},
                ensure_ascii=False,
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format, *_args):
            pass

    with http.server.HTTPServer(("127.0.0.1", 0), Handler) as server:
        server.timeout = 20
        print(json.dumps({"pid": os.getpid(), "http": endpoint(server.server_address)}),
              flush=True)
        server.handle_request()
    return {"pid": os.getpid(), "requests": captured, "socketsClosed": True}


def transport_worker(config):
    tcp_reads, datagrams = [], []
    with contextlib.ExitStack() as stack:
        tcp = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        udp = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
        for sock in (tcp, udp):
            sock.bind(("127.0.0.1", 0))
            sock.settimeout(20)
        tcp.listen(1)
        print(json.dumps({"pid": os.getpid(), "tcp": endpoint(tcp.getsockname()),
                          "udp": endpoint(udp.getsockname())}), flush=True)
        connection, peer = tcp.accept()
        with connection:
            connection.settimeout(5)
            first = b""
            while len(first) < 2:
                chunk = connection.recv(2 - len(first))
                if not chunk:
                    raise ValueError("EOF before the first two bytes.")
                tcp_reads.append(chunk.hex())
                first += chunk
            connection.sendall(b"K")
            while True:
                chunk = connection.recv(256)
                if not chunk:
                    break
                tcp_reads.append(chunk.hex())
            connection.sendall(b"".join(bytes.fromhex(row) for row in tcp_reads))
        for _ in range(2):
            data, ancillary, flags, sender = udp.recvmsg(config["udpBuffer"])
            if ancillary:
                raise ValueError("Unexpected ancillary data.")
            datagrams.append({"dataHex": data.hex(), "flags": flags,
                              "truncated": bool(flags & socket.MSG_TRUNC),
                              "sender": endpoint(sender)})
            udp.sendto(data, sender)
    return {"pid": os.getpid(), "tcpReadsHex": tcp_reads, "tcpPeer": endpoint(peer),
            "tcpEofObserved": True, "datagrams": datagrams, "socketsClosed": True}


if __name__ == "__main__":
    try:
        require_linux()
        if len(sys.argv) != 4 or sys.argv[1] != "--worker":
            raise ValueError("Run main.py; this file supplies its owned worker.")
        kind, config = sys.argv[2], json.loads(sys.argv[3])
        worker = {"setup": setup_worker, "transport": transport_worker}[kind]
        started = time.monotonic()
        report = worker(config)
        report["elapsedSeconds"] = time.monotonic() - started
        print(json.dumps(report, ensure_ascii=True), flush=True)
    except (OSError, ValueError, KeyError, TimeoutError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(2)

