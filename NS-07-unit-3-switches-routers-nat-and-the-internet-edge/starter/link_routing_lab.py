"""Observe a bridge, routing and translation inside owned Linux namespaces."""
import argparse
import contextlib
import datetime
import http.server
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


class LabInterrupted(Exception):
    def __init__(self, number):
        super().__init__("interrupted; cleaning up the owned topology")
        self.number = number


def interrupted(number, _frame):
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    raise LabInterrupted(number)


def stop(process):
    if process.poll() is None:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=3)


def command(argv, records, check=True, timeout=8):
    started = now()
    process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    cleanup = "exited and reaped"
    out = err = b""
    try:
        out, err = process.communicate(timeout=timeout)
    except BaseException:
        cleanup = "owned process group stopped and reaped"
        stop(process)
        raise
    finally:
        records.append({"parentTask": "unit3-owned-link-routing", "parentPid": os.getpid(),
                        "cwd": str(Path.cwd()), "command": argv, "pid": process.pid,
                        "startTime": started, "endTime": now(), "exitCode": process.returncode,
                        "timeoutSeconds": timeout, "childProcessGroupCleanup": cleanup,
                        "stdout": out.decode(), "stderr": err.decode()})
    result = {"exitCode": process.returncode, "stdout": out.decode(), "stderr": err.decode(), "commandPid": process.pid}
    if check and process.returncode:
        raise RuntimeError("command failed: " + repr(argv) + ": " + result["stderr"])
    return result


def firewall_configuration(raw):
    return "\n".join(re.sub(r"^(:\S+ \S+) \[\d+:\d+\]$", r"\1", line)
                     for line in raw.splitlines() if not line.startswith("#"))


def host_snapshot(records):
    raw = command(["iptables-save"], records)["stdout"]
    return {"networkNamespace": os.readlink("/proc/self/ns/net"),
            "mountNamespace": os.readlink("/proc/self/ns/mnt"),
            "links": command(["ip", "-j", "link", "show"], records)["stdout"],
            "routes": command(["ip", "-j", "route", "show", "table", "all"], records)["stdout"],
            "namespaces": command(["ip", "netns", "list"], records)["stdout"],
            "forwarding": command(["sysctl", "-n", "net.ipv4.ip_forward"], records)["stdout"],
            "firewallRaw": raw, "firewall": firewall_configuration(raw)}


def require_isolation(original_network, original_mount):
    if not original_network or not original_mount:
        raise RuntimeError("original namespace identities are required")
    network, mount = os.readlink("/proc/self/ns/net"), os.readlink("/proc/self/ns/mnt")
    if network in (original_network, os.readlink("/proc/1/ns/net")):
        raise RuntimeError("refusing to alter or serve in the original network namespace")
    if mount in (original_mount, os.readlink("/proc/1/ns/mnt")):
        raise RuntimeError("refusing to alter or serve in the original mount namespace")
    return network, mount


def serve(args):
    require_isolation(args.original_network, args.original_mount)
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    signal.signal(signal.SIGALRM, signal.SIG_DFL)
    signal.alarm(60)

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = {"token": args.token, "pid": os.getpid(), "uid": os.geteuid(),
                    "peer": list(self.connection.getpeername()),
                    "local": list(self.connection.getsockname()), "path": self.path}
            raw = json.dumps(body).encode() + b"\n"
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            self.wfile.flush()
            print(json.dumps({"at": now(), "requestLine": self.raw_requestline.decode("ascii"),
                              "headers": dict(self.headers), "response": body}), flush=True)

        def log_message(self, _format, *_args):
            pass

    with http.server.HTTPServer(("0.0.0.0", args.service_port), Handler) as server:
        server.serve_forever(poll_interval=0.05)


def inside(args):
    network, mount = require_isolation(args.original_network, args.original_mount)
    records, owned, worker = [], [], None
    result = {"networkNamespace": network, "mountNamespace": mount,
              "commands": records, "observations": [], "cleanup": {},
              "learnerNotebookCompletionInferred": False}
    prefix = "ns3-" + args.token[:8]
    client, middle, server = [prefix + "-" + suffix for suffix in ("c", "m", "s")]
    left = "10.41.0" if args.alternate else "10.31.0"
    right = "10.42.0" if args.alternate else "10.32.0"
    result["names"] = {"client": client, "middle": middle, "server": server}
    result["addresses"] = {"client": left + ".2", "bridgeServer": left + ".3",
                           "clientGateway": left + ".1", "server": right + ".2", "serverGateway": right + ".1"}
    address = result["addresses"]

    def run(*parts, check=True):
        return command(list(parts), records, check=check)

    def ns(name, *parts, check=True):
        return run("ip", "netns", "exec", name, *parts, check=check)

    def probe(namespace, host, port):
        r = ns(namespace, "curl", "--noproxy", "*", "--silent", "--show-error", "--include",
               "--connect-timeout", "1", "--max-time", "1", "--write-out",
               "\nCURL_PEER=%{remote_ip}:%{remote_port};CURL_LOCAL=%{local_ip}:%{local_port}\n", "http://" + host + ":" + str(port) + "/edge", check=False)
        wire, peer = r["stdout"].rsplit("\nCURL_PEER=", 1) if "\nCURL_PEER=" in r["stdout"] else (r["stdout"], "")
        observed_peer, _, observed_local = peer.strip().partition(";CURL_LOCAL=")
        r.update(wire=wire, clientObservedPeer=observed_peer, clientObservedLocal=observed_local, body=None)
        if r["exitCode"] == 0:
            header, body = wire.split("\r\n\r\n", 1)
            if header.splitlines()[0].split()[1] != "200":
                raise RuntimeError("unexpected owned HTTP response")
            r["body"] = json.loads(body)
        return r

    def state():
        return {"addresses": {name: json.loads(run("ip", "-n", name, "-j", "addr", "show")["stdout"]) for name in owned},
                "routes": {name: json.loads(run("ip", "-n", name, "-j", "route", "show")["stdout"]) for name in owned},
                "neighbors": {name: json.loads(run("ip", "-n", name, "-j", "neigh", "show")["stdout"]) for name in owned},
                "forwarding": ns(middle, "sysctl", "-n", "net.ipv4.ip_forward")["stdout"].strip(),
                "natRules": ns(middle, "iptables-save", "-t", "nat")["stdout"]}

    def observe(stage, target, port=None, bridged=False):
        row = {"stage": stage, "target": target, "port": port or args.service_port,
               "response": probe(client, target, port or args.service_port), "state": state()}
        if bridged:
            row["bridgeFDB"] = json.loads(ns(middle, "bridge", "-j", "fdb", "show", "br", "br0")["stdout"])
            row["bridgeLinks"] = json.loads(run("ip", "-n", middle, "-j", "link", "show", "master", "br0")["stdout"])
            row["bridgeInterface"] = json.loads(run("ip", "-n", middle, "-d", "-j", "link", "show", "dev", "br0")["stdout"])
        row["clientRouteLookup"] = run("ip", "-n", client, "-j", "route", "get", target, check=False)
        row["serverReturnLookup"] = run("ip", "-n", server, "-j", "route", "get", address["client"], check=False)
        result["observations"].append(row)

    def route_topology(from_bridge=False):
        if from_bridge:
            for interface in ("ml0", "mr0"):
                run("ip", "-n", middle, "link", "set", interface, "nomaster")
            run("ip", "-n", middle, "link", "del", "br0")
            run("ip", "-n", server, "addr", "flush", "dev", "s0")
        for name, interface, value in ((middle, "ml0", address["clientGateway"]),
                                       (middle, "mr0", address["serverGateway"]),
                                       (server, "s0", address["server"])):
            run("ip", "-n", name, "addr", "add", value + "/24", "dev", interface)
        run("ip", "-n", client, "route", "add", "default", "via", address["clientGateway"])
        run("ip", "-n", server, "route", "add", "default", "via", address["serverGateway"])

    def snat():
        ns(middle, "iptables", "-t", "nat", "-A", "POSTROUTING", "-s", left + ".0/24",
           "-d", address["server"] + "/32", "-o", "mr0", "-p", "tcp", "--dport", str(args.service_port),
           "-j", "SNAT", "--to-source", address["serverGateway"])

    try:
        run("mount", "--make-rprivate", "/")
        run("mount", "-t", "tmpfs", "-o", "mode=755,nosuid,nodev", "ns3-owned-run", "/run")
        Path("/run/netns").mkdir()
        if run("ip", "netns", "list")["stdout"].strip():
            raise RuntimeError("private namespace registry was not empty")
        for name in (client, middle, server):
            run("ip", "netns", "add", name)
            owned.append(name)
            run("ip", "-n", name, "link", "set", "lo", "up")
        for a, b, a_ns in (("c0", "ml0", client), ("s0", "mr0", server)):
            run("ip", "link", "add", a, "type", "veth", "peer", "name", b)
            run("ip", "link", "set", a, "netns", a_ns)
            run("ip", "link", "set", b, "netns", middle)
            run("ip", "-n", a_ns, "link", "set", a, "up")
            run("ip", "-n", middle, "link", "set", b, "up")
        run("ip", "-n", client, "addr", "add", address["client"] + "/24", "dev", "c0")
        ns(middle, "sysctl", "-qw", "net.ipv4.ip_forward=0")
        if args.kind == "core":
            run("ip", "-n", middle, "link", "add", "br0", "type", "bridge", "stp_state", "0")
            for interface in ("ml0", "mr0"):
                run("ip", "-n", middle, "link", "set", interface, "master", "br0")
            run("ip", "-n", middle, "link", "set", "br0", "up")
            run("ip", "-n", server, "addr", "add", address["bridgeServer"] + "/24", "dev", "s0")
        else:
            route_topology()
        worker_argv = ["ip", "netns", "exec", server, sys.executable, "-u", str(Path(__file__).resolve()),
                       "--serve", "--token", args.token, "--service-port", str(args.service_port),
                       "--original-network", args.original_network, "--original-mount", args.original_mount]
        started = now()
        worker = subprocess.Popen(worker_argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        result["worker"] = {"pid": worker.pid, "parentPid": os.getpid(), "cwd": str(Path.cwd()),
                            "command": worker_argv, "startTime": started, "timeoutSeconds": 60}
        for _ in range(20):
            ready = probe(server, "127.0.0.1", args.service_port)
            if ready["body"]:
                result["readiness"] = ready
                break
            if worker.poll() is not None:
                raise RuntimeError("owned service exited before readiness")
            time.sleep(0.05)
        else:
            raise RuntimeError("owned service did not become ready")
        result["workerProcUidFields"] = next(line.split()[1:] for line in
            Path("/proc/" + str(worker.pid) + "/status").read_text().splitlines() if line.startswith("Uid:"))
        result["workerNetworkNamespace"] = os.readlink("/proc/" + str(worker.pid) + "/ns/net")
        result["listenerDuring"] = ns(server, "ss", "-H", "-ltnp", "sport = :" + str(args.service_port))["stdout"]
        if "pid=" + str(worker.pid) + "," not in result["listenerDuring"]:
            raise RuntimeError("owned listener identity was not visible")
        marker = Path(args.inner_output).with_name("ready.json")
        temporary_marker = marker.with_suffix(".private")
        temporary_marker.write_text(json.dumps({"token": args.token, "workerPid": worker.pid,
                                                "port": args.service_port, "networkNamespace": result["workerNetworkNamespace"]}))
        os.chmod(temporary_marker, 0o600)
        os.replace(temporary_marker, marker)
        if args.fail_after_ready:
            raise RuntimeError("controlled failure after owned topology readiness")
        time.sleep(args.hold_ms / 1000)
        if args.kind == "core":
            observe("bridge-forwarding-off", address["bridgeServer"], bridged=True)
            run("ip", "-n", middle, "link", "set", "mr0", "down")
            observe("bridge-port-down", address["bridgeServer"], bridged=True)
            run("ip", "-n", middle, "link", "set", "mr0", "up")
            observe("bridge-restored", address["bridgeServer"], bridged=True)
            route_topology(from_bridge=True)
            observe("router-forwarding-off", address["server"])
            ns(middle, "sysctl", "-qw", "net.ipv4.ip_forward=1")
            observe("routed", address["server"])
            snat()
            observe("snat", address["server"])
        elif args.kind == "transfer":
            ns(middle, "sysctl", "-qw", "net.ipv4.ip_forward=1")
            observe("route-ready", address["server"])
            run("ip", "-n", client, "route", "del", "default")
            observe("client-gateway-missing", address["server"])
            run("ip", "-n", client, "route", "add", "default", "via", address["clientGateway"])
            observe("client-gateway-restored", address["server"])
            run("ip", "-n", server, "route", "del", "default")
            observe("return-route-missing", address["server"])
            run("ip", "-n", server, "route", "add", "default", "via", address["serverGateway"])
            observe("return-route-restored", address["server"])
        else:
            ns(middle, "sysctl", "-qw", "net.ipv4.ip_forward=1")
            observe("routed", address["server"])
            snat()
            observe("snat", address["server"])
            ns(middle, "iptables", "-t", "nat", "-A", "PREROUTING", "-i", "ml0",
               "-d", address["clientGateway"] + "/32", "-p", "tcp", "--dport", str(args.mapped_port),
               "-j", "DNAT", "--to-destination", address["server"] + ":" + str(args.service_port))
            observe("mapped", address["clientGateway"], args.mapped_port)
            ns(middle, "iptables", "-t", "nat", "-F", "PREROUTING")
            observe("mapping-removed", address["clientGateway"], args.mapped_port)
            observe("direct-after-removal", address["server"])
        result["observationsCollected"] = True
    except (RuntimeError, LabInterrupted, subprocess.TimeoutExpired, ValueError) as error:
        result["error"] = str(error)
        if isinstance(error, LabInterrupted):
            result["interruptedSignal"] = error.number
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        if worker:
            stop(worker)
            out, err = worker.communicate(timeout=2)
            result["worker"].update(endTime=now(), exitCode=worker.returncode,
                                     childProcessGroupCleanup="owned HTTP worker stopped and reaped",
                                     stdout=out.decode(), stderr=err.decode(), reaped=worker.poll() is not None)
            result["workerRequests"] = [json.loads(line) for line in out.splitlines()]
            result["cleanup"]["workerReaped"] = worker.poll() is not None
            result["listenerAfter"] = ns(server, "ss", "-H", "-ltnp", "sport = :" + str(args.service_port), check=False)["stdout"]
        for name in reversed(owned):
            run("ip", "netns", "del", name, check=False)
        remaining = run("ip", "netns", "list")["stdout"]
        links = json.loads(run("ip", "-j", "link", "show")["stdout"])
        result["cleanup"].update(remainingNamespaces=remaining, remainingLinks=links,
                                 namespacesRemoved=not remaining.strip(),
                                 onlyLoopbackRemains=[row["ifname"] for row in links] == ["lo"])
        fd = os.open(args.inner_output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as stream:
            stream.write(json.dumps(result, indent=2) + "\n")
    return 1 if result.get("error") else 0


def observe(kind, alternate, service_port, mapped_port, hold_ms, fail_after_ready, evidence):
    if sys.platform != "linux" or os.geteuid() != 0:
        raise ValueError("use sudo in a disposable Linux VM for the isolated kernel lab")
    if kind not in ("core", "transfer", "extension") or not 0 <= hold_ms <= 2000:
        raise ValueError("invalid observation task or hold deadline")
    if not 1024 <= service_port <= 65535 or not 1024 <= mapped_port <= 65535 or service_port == mapped_port:
        raise ValueError("use distinct unprivileged service and mapped ports")
    for tool in ("ip", "bridge", "unshare", "mount", "sysctl", "iptables", "iptables-save", "curl", "ss"):
        if not shutil.which(tool):
            raise ValueError("missing Linux prerequisite: " + tool)
    records = []
    before = host_snapshot(records)
    evidence.update(kind=kind, alternate=alternate, servicePort=service_port, mappedPort=mapped_port,
                    environment={"platform": sys.platform, "uid": os.geteuid(), "pid": os.getpid(), "cwd": str(Path.cwd())},
                    token=uuid.uuid4().hex, hostBefore=before, commands=records,
                    learnerNotebookCompletionInferred=False, publicInternetMeasured=False)
    with tempfile.TemporaryDirectory(prefix="ns3-owned-") as temporary:
        output = str(Path(temporary) / "inner.json")
        argv = ["unshare", "--mount", "--net", sys.executable, str(Path(__file__).resolve()),
                "--inside", "--original-network", before["networkNamespace"],
                "--original-mount", before["mountNamespace"], "--kind", kind,
                "--token", evidence["token"], "--inner-output", output,
                "--service-port", str(service_port), "--mapped-port", str(mapped_port), "--hold-ms", str(hold_ms)]
        if alternate:
            argv.append("--alternate")
        if fail_after_ready:
            argv.append("--fail-after-ready")
        try:
            evidence["isolatedProcess"] = command(argv, records, check=False, timeout=60)
        except (LabInterrupted, subprocess.TimeoutExpired) as error:
            evidence["error"] = str(error)
            if isinstance(error, LabInterrupted):
                evidence["interruptedSignal"] = error.number
        finally:
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            signal.signal(signal.SIGINT, signal.SIG_IGN)
            if Path(output).is_file():
                evidence["lab"] = json.loads(Path(output).read_text())
            evidence["hostAfter"] = host_snapshot(records)
            evidence["hostUnchanged"] = all(value == evidence["hostAfter"][key] for key, value in before.items() if key != "firewallRaw")
    if not evidence["hostUnchanged"]:
        raise RuntimeError("outer host configuration comparison changed")
    if not evidence.get("lab") and evidence.get("isolatedProcess", {}).get("exitCode"):
        raise RuntimeError("Linux isolation prerequisite failed: " + evidence["isolatedProcess"]["stderr"])
    if evidence.get("error") or evidence.get("lab", {}).get("error"):
        number = evidence.get("interruptedSignal") or evidence.get("lab", {}).get("interruptedSignal")
        if number:
            raise LabInterrupted(number)
        raise RuntimeError(evidence.get("error") or evidence["lab"]["error"])
    if not evidence.get("lab", {}).get("cleanup", {}).get("namespacesRemoved"):
        raise RuntimeError("owned namespace cleanup was not confirmed")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--inside", action="store_true")
    parser.add_argument("--serve", action="store_true")
    parser.add_argument("--kind", choices=("core", "transfer", "extension"))
    parser.add_argument("--original-network")
    parser.add_argument("--original-mount")
    parser.add_argument("--token")
    parser.add_argument("--inner-output")
    parser.add_argument("--alternate", action="store_true")
    parser.add_argument("--service-port", type=int, default=8080)
    parser.add_argument("--mapped-port", type=int, default=18080)
    parser.add_argument("--hold-ms", type=int, default=0)
    parser.add_argument("--fail-after-ready", action="store_true")
    args = parser.parse_args()
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    if sys.platform != "linux" or os.geteuid() != 0 or not args.token or not re.fullmatch("[0-9a-f]{32}", args.token):
        raise RuntimeError("private Linux worker invocation required")
    if args.serve:
        serve(args)
        return 0
    if not args.inside or not args.inner_output:
        raise RuntimeError("private isolated worker invocation required")
    output = Path(args.inner_output)
    parent = output.parent.lstat()
    if (args.kind not in ("core", "transfer", "extension") or output.name != "inner.json"
            or not output.parent.name.startswith("ns3-owned-") or parent.st_uid != 0
            or parent.st_mode & 0o077 or output.exists() or output.is_symlink()
            or not 1024 <= args.service_port <= 65535 or not 1024 <= args.mapped_port <= 65535
            or args.service_port == args.mapped_port or not 0 <= args.hold_ms <= 2000):
        raise RuntimeError("invalid private worker arguments")
    return inside(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, LabInterrupted) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(2)
