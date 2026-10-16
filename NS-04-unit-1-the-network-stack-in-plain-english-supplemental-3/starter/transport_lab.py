"""Owned Linux loopback observations for two optional transport investigations."""
import argparse
import datetime
import hashlib
import json
import os
import socket
import struct
import sys
import threading
import time
from pathlib import Path


def stamp():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()  # noqa: UP017


def source_hashes():
    root = Path(__file__).resolve().parent
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
            for name in ["main.py", "transport_lab.py", "case.json", "network-notes.md", "edge-cases.md"]}


def identity():
    return {"pid": os.getpid(), "uid": os.getuid(), "hostname": socket.gethostname(),
            "cwd": str(Path.cwd()), "networkNamespace": os.readlink("/proc/self/ns/net"),
            "mountNamespace": os.readlink("/proc/self/ns/mnt")}


class Experiment:
    def __init__(self):
        self.sockets = []
        self.threads = []
        self.events = []

    def record(self, operation, **fields):
        self.events.append({"operation": operation, "pid": os.getpid(),
                            "threadId": threading.get_native_id(), "at": stamp(), **fields})

    def new_socket(self, kind):
        sock = socket.socket(socket.AF_INET, kind)
        sock.settimeout(3)
        self.sockets.append(sock)
        self.record("socket", fd=sock.fileno(), family="AF_INET", kind=int(kind))
        return sock

    def receive(self, sock, count, actor, flags=0):
        fd = sock.fileno()
        started = stamp()
        try:
            data, ancillary, returned, peer = sock.recvmsg(count, 0, flags)
        except TimeoutError:
            self.record("receive-timeout", actor=actor, fd=fd, requestedBytes=count,
                        requestedFlags=flags, startedAt=started)
            return None
        assert ancillary == []
        row = {"actor": actor, "fd": fd, "requestedBytes": count,
               "requestedFlags": flags, "returnedFlags": returned,
               "truncated": bool(returned & socket.MSG_TRUNC),
               "dataHex": data.hex(), "peer": peer, "startedAt": started}
        self.record("recvmsg", **row)
        return row

    def send(self, sock, data, actor, peer=None):
        fd = sock.fileno()
        if peer is None:
            sock.sendall(data)
            self.record("sendall", actor=actor, fd=fd, dataHex=data.hex())
        else:
            sent = sock.sendto(data, peer)
            assert sent == len(data)
            self.record("sendto", actor=actor, fd=fd, dataHex=data.hex(), bytesSent=sent, peer=peer)

    def close(self):
        for sock in self.sockets:
            fd = sock.fileno()
            if fd >= 0:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                sock.close()
                self.record("close", fd=fd)
        for thread in self.threads:
            thread.join(timeout=5)
        assert all(sock.fileno() == -1 for sock in self.sockets)
        assert all(not thread.is_alive() for thread in self.threads)


def tcp_framing(experiment, case, alternate):
    messages = ["changed first record", "lamp \u2713", "third record"] if alternate else ["north route", "lamp \u2713"]
    payloads = [message.encode("utf8") for message in messages]
    wire = b"".join(struct.pack("!I", len(data)) + data for data in payloads)
    server = experiment.new_socket(socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    endpoint = server.getsockname()
    experiment.record("listen", fd=server.fileno(), local=endpoint)
    first_sent, first_read = threading.Event(), threading.Event()
    errors = []

    def peer():
        try:
            accepted, remote = server.accept()
            accepted.settimeout(3)
            experiment.sockets.append(accepted)
            experiment.record("accept", fd=accepted.fileno(), local=accepted.getsockname(), peer=remote)
            experiment.send(accepted, wire[:1], "server-header-fragment")
            first_sent.set()
            assert first_read.wait(timeout=3), "Client did not acknowledge its first read"
            experiment.send(accepted, wire[1:], "server-remainder")
            accepted.shutdown(socket.SHUT_WR)
            experiment.record("shutdown-write", fd=accepted.fileno())
        except (OSError, ValueError, AssertionError, struct.error) as error:
            errors.append(type(error).__name__ + ": " + str(error))
            first_sent.set()

    thread = threading.Thread(target=peer, name="owned-loopback-framing-peer")
    experiment.threads.append(thread)
    thread.start()
    client = experiment.new_socket(socket.SOCK_STREAM)
    client.connect(endpoint)
    experiment.record("connect", fd=client.fileno(), local=client.getsockname(), peer=client.getpeername())
    assert first_sent.wait(timeout=3), "Owned peer did not send its first fragment"
    first = experiment.receive(client, 2, "client-first-read")
    assert first is not None and bytes.fromhex(first["dataHex"]) == wire[:1]
    first_read.set()
    reads = [first]
    while True:
        row = experiment.receive(client, 3 if alternate else 2, "client-remaining-read")
        assert row is not None, "Owned stream read timed out"
        reads.append(row)
        if row["dataHex"] == "":
            break
    thread.join(timeout=5)
    assert not thread.is_alive() and not errors, errors
    observed = b"".join(bytes.fromhex(row["dataHex"]) for row in reads)
    assert observed == wire
    application_input = bytes.fromhex(first["dataHex"]) if case["framing"] == "single-read" else observed
    decoded, offset, error = [], 0, None
    while offset < len(application_input):
        if len(application_input) - offset < 4:
            error = "incomplete-length-prefix"
            break
        size = struct.unpack("!I", application_input[offset:offset + 4])[0]
        offset += 4
        if not 1 <= size <= 128:
            error = "invalid-record-length"
            break
        if len(application_input) - offset < size:
            error = "incomplete-record-body"
            break
        decoded.append(application_input[offset:offset + size].decode("utf8"))
        offset += size
    return {"messages": messages, "payloadByteLengths": [len(data) for data in payloads],
            "wireHex": wire.hex(), "firstReadHex": first["dataHex"], "readCalls": reads,
            "applicationInputHex": application_input.hex(), "applicationRecords": decoded,
            "applicationError": error, "eofObserved": reads[-1]["dataHex"] == "",
            "serverEndpoint": endpoint, "serverThreadId": thread.native_id,
            "completed": error is None and decoded == messages,
            "claimScope": "Application framing over one owned IPv4 loopback TCP stream; no packet boundaries inferred"}


def udp_probe(experiment, case, alternate):
    messages = ["changed first datagram", "second changed", "third changed"] if alternate else ["first datagram", "second datagram"]
    payloads = [message.encode("utf8") for message in messages]
    receiver = experiment.new_socket(socket.SOCK_DGRAM)
    sender = experiment.new_socket(socket.SOCK_DGRAM)
    receiver.bind(("127.0.0.1", 0))
    sender.bind(("127.0.0.1", 0))
    destination, origin = receiver.getsockname(), sender.getsockname()
    experiment.record("bind", actor="receiver", fd=receiver.fileno(), local=destination)
    experiment.record("bind", actor="sender", fd=sender.fileno(), local=origin)
    for payload in payloads:
        experiment.send(sender, payload, "owned-sender", destination)
    flags = socket.MSG_PEEK if case["probe_behavior"] == "peek" else 0
    probe = experiment.receive(receiver, 4, "diagnostic-probe", flags)
    assert probe is not None and probe["peer"] == origin
    assert probe["dataHex"] == payloads[0][:4].hex() and probe["truncated"]
    receiver.settimeout(0.15)
    consumed = []
    for _ in payloads:
        row = experiment.receive(receiver, 256, "application-consumer")
        if row is not None:
            assert row["peer"] == origin and not row["truncated"]
            consumed.append(row)
    records = [bytes.fromhex(row["dataHex"]).decode("utf8") for row in consumed]
    return {"messages": messages, "sentHex": [data.hex() for data in payloads],
            "receiverEndpoint": destination, "senderEndpoint": origin,
            "probe": probe, "consumerReads": consumed, "applicationRecords": records,
            "completed": records == messages,
            "claimScope": "One owned IPv4 loopback UDP queue and its consuming or peeking application calls; no remote loss inferred"}


def run(mode):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", type=Path, default=Path(__file__).with_name("case.json"))
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--alternate", action="store_true")
    args = parser.parse_args()
    if sys.platform != "linux" or sys.version_info < (3, 10) or os.getuid() == 0:
        parser.error("Use Python 3.10+ as an ordinary non-root user in an owned Linux environment")
    try:
        case_bytes = args.case.read_bytes()
        case = json.loads(case_bytes)
        expected = {"framing"} if mode == "tcp" else {"probe_behavior"}
        allowed = {"single-read", "length-prefix"} if mode == "tcp" else {"consume", "peek"}
        if not isinstance(case, dict) or set(case) != expected or not all(isinstance(value, str) and value in allowed for value in case.values()):
            raise ValueError("Case must contain only the selected investigation's documented setting")
        before, hashes, started = identity(), source_hashes(), stamp()
        out = args.report.open("x")
    except (OSError, ValueError) as error:
        parser.error(str(error))
    experiment = Experiment()
    report = {"event": "owned-transport-investigation", "mode": mode, "case": case,
              "casePath": str(args.case.resolve()), "caseFileSha256": hashlib.sha256(case_bytes).hexdigest(),
              "alternate": args.alternate, "parentBefore": before, "sourceFileHashes": hashes,
              "startedAt": started, "notebookCompletionNotInferred": True,
              "command": [sys.executable, *sys.argv], "completed": False}
    outcome = 2
    started_clock = time.monotonic()
    try:
        observation = tcp_framing(experiment, case, args.alternate) if mode == "tcp" else udp_probe(experiment, case, args.alternate)
        report.update(observation=observation, completed=observation["completed"])
        outcome = 0 if report["completed"] else 78
    except (KeyboardInterrupt, OSError, ValueError, AssertionError, struct.error) as error:
        report["error"] = type(error).__name__ + ": " + str(error)
        outcome = 130 if isinstance(error, KeyboardInterrupt) else 2
    finally:
        experiment.close()
        report.update(events=experiment.events, parentAfter=identity(),
                      allSocketsClosed=True, allThreadsJoined=True,
                      sourceUnchanged=source_hashes() == hashes,
                      endedAt=stamp(), elapsedSeconds=time.monotonic() - started_clock)
        report["parentUnchanged"] = before == report["parentAfter"]
        report["exitCode"] = outcome
        with out:
            json.dump(report, out, indent=2)
            out.write("\n")
    assert report["parentUnchanged"] and report["sourceUnchanged"]
    print(json.dumps({"report": str(args.report), "mode": mode, "completed": report["completed"],
                      "exitCode": outcome, "notebookCompletionNotInferred": True}))
    return outcome
