"""Observe owned Linux socket inventories; supplied apparatus, optional analysis."""
import argparse
import datetime
import json
import os
import re
import select
import shutil
import signal
import socket
import subprocess
import sys
from pathlib import Path


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def interrupted(signum, frame):
    raise InterruptedError("Owned socket investigation interrupted")


def identity(fd, pid=None):
    pid = os.getpid() if pid is None else pid
    return {"pid": pid, "fd": fd,
            "socket": os.readlink(f"/proc/{pid}/fd/{fd}"),
            "namespace": os.readlink(f"/proc/{pid}/ns/net")}


def command(args, records):
    started = now()
    process = subprocess.Popen(args, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, start_new_session=True)
    cleanup = "not needed"
    try:
        stdout, stderr = process.communicate(timeout=4)
    except BaseException:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.communicate()
        cleanup = "owned process group killed and reaped"
        raise
    finally:
        records.append({"command": args, "cwd": str(Path.cwd()),
                        "pid": process.pid, "parentPid": os.getpid(),
                        "startTime": started, "endTime": now(),
                        "exitCode": process.returncode, "timeoutSeconds": 4,
                        "cleanup": cleanup})
    records[-1].update(stdout=stdout.decode(), stderr=stderr.decode())
    if process.returncode:
        raise RuntimeError("ss failed; retain its raw command record")
    return stdout.decode()


def inventory(protocol, port, records):
    views = {}
    for view, flags in (("listening", "-Hnl"), ("all", "-Hna")):
        views[view] = command([shutil.which("ss"), flags + protocol + "pe",
                               "sport = :" + str(port)], records)
    return views


def socket_rows(raw, socket_identity):
    inode = socket_identity["socket"][8:-1]
    return [line for line in raw.splitlines()
            if re.search(r"\bino:" + re.escape(inode) + r"\b", line)]


def udp_case(config, records):
    token = config["token"].encode("ascii")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer, \
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        peer.settimeout(3)
        client.settimeout(3)
        peer.bind(("127.0.0.1", 0))
        client.bind(("127.0.0.1", 0))
        owned = identity(client.fileno())
        local = client.getsockname()
        peer_address = peer.getsockname()
        before = inventory("u", local[1], records)
        client.connect(peer_address)
        after = inventory("u", local[1], records)
        sent = client.send(token)
        received, sender = peer.recvfrom(128)
        replied = peer.sendto(b"reply:" + received, sender)
        reply = client.recv(128)
        endpoint = {"local": local, "peer": client.getpeername(),
                    "type": "SOCK_DGRAM", "identity": owned}
    closed = inventory("u", local[1], records)
    facts = {"endpoint": endpoint, "beforeConnect": before,
             "afterConnectBeforeSend": after, "afterClose": closed,
             "exchange": {"sentBytes": sent, "peerReceivedHex": received.hex(),
                          "sender": sender, "replySentBytes": replied,
                          "replyReceivedHex": reply.hex()}}
    assert socket_rows(before["listening"], owned)
    assert socket_rows(before["all"], owned)
    assert not socket_rows(after["listening"], owned)
    assert socket_rows(after["all"], owned)
    assert not socket_rows(closed["all"], owned)
    assert received == token and reply == b"reply:" + token
    selected = config["inventory_view"]
    return facts, (None if selected == "TODO" else
                   bool(socket_rows(after[selected], owned)))


def read_line(stream, timeout=4):
    if not select.select([stream], [], [], timeout)[0]:
        raise TimeoutError("Owned worker did not report readiness")
    line = stream.readline()
    if not line:
        raise RuntimeError("Owned worker closed its readiness pipe")
    return json.loads(line)


def owned_listener_worker(fd, token):
    with socket.socket(fileno=int(fd)) as listener:
        listener.settimeout(4)
        assert listener.family == socket.AF_INET
        assert listener.type == socket.SOCK_STREAM
        assert listener.getsockname()[0] == "127.0.0.1"
        print(json.dumps({"ready": identity(listener.fileno())}), flush=True)
        if not select.select([sys.stdin], [], [], 20)[0]:
            raise TimeoutError("Owned worker did not receive its bounded action")
        if sys.stdin.readline() != "accept\n":
            raise ValueError("Unknown owned-worker action")
        with listener.accept()[0] as accepted:
            accepted.settimeout(4)
            received = b""
            while len(received) < len(token):
                part = accepted.recv(len(token) - len(received))
                if not part:
                    raise RuntimeError("Owned client closed an incomplete request")
                received += part
            if received != token.encode("ascii"):
                raise ValueError("Owned request did not match its declared token")
            accepted.sendall(b"reply:" + received)
            result = {"receivedHex": received.hex(),
                      "peer": accepted.getpeername(),
                      "local": accepted.getsockname()}
    print(json.dumps(result), flush=True)


def tcp_case(config, records):
    token = config["token"].encode("ascii")
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    worker = None
    started = now()
    cleanup = "normal worker exit and reap"
    try:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        local = listener.getsockname()
        parent = identity(listener.fileno())
        args = [sys.executable, str(Path(__file__).resolve()),
                "--owned-listener-worker", str(listener.fileno()), config["token"]]
        worker = subprocess.Popen(args, stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  pass_fds=(listener.fileno(),), text=True,
                                  start_new_session=True)
        ready = read_line(worker.stdout)["ready"]
        assert ready == identity(ready["fd"], worker.pid)
        assert ready["socket"] == parent["socket"]
        assert ready["namespace"] == parent["namespace"]
        before = inventory("t", local[1], records)
        listener.close()
        after_parent = inventory("t", local[1], records)
        worker.stdin.write("accept\n")
        worker.stdin.flush()
        with socket.create_connection(local, timeout=3) as client:
            client.settimeout(3)
            client.sendall(token)
            reply = b""
            while True:
                part = client.recv(128)
                if not part:
                    break
                reply += part
        stdout, stderr = worker.communicate(timeout=5)
        assert worker.returncode == 0, stderr
        result = json.loads(stdout)
        assert result["receivedHex"] == token.hex()
        assert reply == b"reply:" + token
        closed = inventory("t", local[1], records)
        before_rows = socket_rows(before["listening"], parent)
        parent_closed_rows = socket_rows(after_parent["listening"], parent)
        assert len(before_rows) == len(parent_closed_rows) == 1
        assert f"pid={parent['pid']}," in before_rows[0]
        assert f"pid={worker.pid}," in before_rows[0]
        assert f"pid={parent['pid']}," not in parent_closed_rows[0]
        assert f"pid={worker.pid}," in parent_closed_rows[0]
        assert not socket_rows(closed["listening"], parent)
        facts = {"local": local, "parent": parent, "child": ready,
                 "beforeParentClose": before, "afterParentClose": after_parent,
                 "afterChildExit": closed, "workerExchange": result,
                 "replyReceivedHex": reply.hex(), "workerPid": worker.pid,
                 "workerExitCode": worker.returncode}
        selected = config["group_by"]
        keys = ([item["pid"] for item in (parent, ready)] if selected == "pid"
                else [(item["namespace"], item["socket"])
                      for item in (parent, ready)])
        count = len(set(keys))
        return facts, (None if selected == "TODO" else count == 1)
    finally:
        listener.close()
        if worker is not None:
            if worker.poll() is None:
                cleanup = "owned worker process group killed and reaped"
                try:
                    os.killpg(worker.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            worker.communicate(timeout=3)
            records.append({"command": args, "cwd": str(Path.cwd()),
                            "pid": worker.pid, "parentPid": os.getpid(),
                            "startTime": started, "endTime": now(),
                            "exitCode": worker.returncode, "timeoutSeconds": 30,
                            "cleanup": cleanup})


def load_config(mode, path):
    raw = path.read_bytes()
    if len(raw) > 4096:
        raise ValueError("case.json must fit within 4096 bytes")
    config = json.loads(raw)
    key = "inventory_view" if mode == "udp" else "group_by"
    choices = {"TODO", "listening", "all"} if mode == "udp" else {"TODO", "pid", "netns_inode"}
    if not isinstance(config, dict) or set(config) != {key, "token"}:
        raise ValueError("Keep only the documented strategy and token fields")
    if config[key] not in choices:
        raise ValueError("Unknown inventory strategy")
    token = config["token"]
    if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,48}", token):
        raise ValueError("Use a token of 1 to 48 ASCII letters, digits, underscores or hyphens")
    return config


def run(mode):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", type=Path, default=Path(__file__).with_name("case.json"))
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    records = []
    try:
        config = load_config(mode, args.case)
        if (sys.platform != "linux" or sys.version_info < (3, 10)
                or os.geteuid() == 0 or shutil.which("ss") is None):
            raise ValueError("Use an ordinary Linux account with Python3.10+ and ss")
        if os.path.lexists(args.report) or not args.report.parent.is_dir():
            raise ValueError("Use a fresh report filename in an existing directory")
    except (OSError, TypeError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 64
    started = now()
    signals = (signal.SIGINT, signal.SIGTERM, signal.SIGALRM)
    previous = {item: signal.getsignal(item) for item in signals}
    for item in signals:
        signal.signal(item, interrupted)
    previous_timer = signal.setitimer(signal.ITIMER_REAL, 30)
    try:
        facts, passed = (udp_case if mode == "udp" else tcp_case)(config, records)
        outcome = "unfinished" if passed is None else "passed" if passed else "revise"
        with args.report.open("x") as out:
            json.dump({"mode": mode, "config": config, "observations": facts,
                       "analysis": outcome, "commands": records,
                       "process": {"pid": os.getpid(), "parentPid": os.getppid(),
                                   "cwd": str(Path.cwd()), "startTime": started,
                                   "endTime": now(), "timeoutSeconds": 30,
                                   "ownedSocketsClosed": True}}, out, indent=2)
            out.write("\n")
        print(outcome + ": " + str(args.report))
        return 2 if passed is None else 0 if passed else 1
    except (OSError, ValueError, RuntimeError, AssertionError, subprocess.SubprocessError) as error:
        print(type(error).__name__ + ": " + str(error), file=sys.stderr)
        return 1
    finally:
        signal.setitimer(signal.ITIMER_REAL, *previous_timer)
        for item, handler in previous.items():
            signal.signal(item, handler)


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--owned-listener-worker":
        owned_listener_worker(sys.argv[2], sys.argv[3])
    else:
        raise SystemExit("Use main.py --report a-fresh-file.json")
