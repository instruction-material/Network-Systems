"""Run the prewritten NS6 apparatus; edit lab-rules.sh for the three exercises."""
import argparse
import contextlib
import datetime
import http.server
import json
import os
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


def interrupted(_number, _frame):
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    raise InterruptedError("lab interrupted; cleaning up owned resources")


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


def command(args, records, check=True, timeout=8):
    started = now()
    process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               start_new_session=True)
    cleanup = "exited and reaped"
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except BaseException:
        cleanup = "terminated and reaped owned process group"
        stop(process)
        raise
    finally:
        records.append({"task": "NS6-owned-topology", "parentPid": os.getpid(),
                        "cwd": str(Path.cwd()), "command": args, "pid": process.pid,
                        "startTime": started, "endTime": now(),
                        "exitCode": process.returncode, "timeoutSeconds": timeout,
                        "childProcessGroupCleanup": cleanup})
    result = {"exitCode": process.returncode, "stdout": stdout.decode(),
              "stderr": stderr.decode()}
    if check and process.returncode:
        raise RuntimeError(f"command failed: {args}: {result['stderr']}")
    return result


def snapshot(records):
    firewall = command(["iptables-save"], records)["stdout"]
    return {"networkNamespace": os.readlink("/proc/self/ns/net"),
            "mountNamespace": os.readlink("/proc/self/ns/mnt"),
            "links": command(["ip", "-j", "link", "show"], records)["stdout"],
            "routes": command(["ip", "-j", "route", "show", "table", "all"], records)["stdout"],
            "namespaces": command(["ip", "netns", "list"], records)["stdout"],
            "forwarding": command(["sysctl", "-n", "net.ipv4.ip_forward"], records)["stdout"],
            "firewall": "\n".join(line for line in firewall.splitlines()
                                    if not line.startswith("#"))}


def serve(token):
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            payload = json.dumps({"token": token, "peer": self.client_address[0],
                                  "server": self.connection.getsockname()[0],
                                  "port": self.connection.getsockname()[1],
                                  "path": self.path}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, _format, *_args):
            pass

    with http.server.HTTPServer(("10.20.0.2", 8080), Handler) as server:
        server.serve_forever()


def inside(args):
    records, owned, worker = [], [], None
    result = {"commands": records, "observations": [], "complete": False,
              "cleanup": {"workerReaped": False, "namespacesRemoved": False}}
    current = os.readlink("/proc/self/ns/net")
    if current in (args.inside, os.readlink("/proc/1/ns/net")):
        raise RuntimeError("refusing to alter the original network namespace")
    mount_namespace = os.readlink("/proc/self/ns/mnt")
    if mount_namespace in (args.original_mount, os.readlink("/proc/1/ns/mnt")):
        raise RuntimeError("refusing to alter the original mount namespace")
    result["networkNamespace"] = current
    result["mountNamespace"] = mount_namespace
    names = [f"ns6-{args.token[:8]}-{suffix}" for suffix in ("c", "r", "s")]
    client, router, server = names

    def run(*parts, check=True):
        return command(list(parts), records, check=check)

    def probe(namespace, host, port):
        response = run("ip", "netns", "exec", namespace, "curl", "--noproxy", "*",
                       "--silent", "--show-error", "--fail", "--connect-timeout", "1",
                       "--max-time", "2", f"http://{host}:{port}/lab", check=False)
        response["body"] = json.loads(response["stdout"]) if response["exitCode"] == 0 else None
        return response

    def observe(stage, host="10.20.0.2", port=8080):
        row = {"stage": stage, "request": {"host": host, "port": port},
               "response": probe(client, host, port),
               "forwarding": run("ip", "netns", "exec", router, "sysctl", "-n",
                                 "net.ipv4.ip_forward")["stdout"].strip(),
               "natRules": run("ip", "netns", "exec", router, "iptables-save", "-t", "nat")["stdout"]}
        result["observations"].append(row)
        return row["response"]["body"]

    def apply(stage):
        run("bash", str(Path(__file__).with_name("lab-rules.sh")), stage, router)

    try:
        # Mount propagation and the named-netns registry belong to this run only.
        run("mount", "--make-rprivate", "/")
        run("mount", "-t", "tmpfs", "-o", "mode=755,nosuid,nodev", "ns6-owned-run", "/run")
        Path("/run/netns").mkdir()
        assert not run("ip", "netns", "list")["stdout"].strip()
        for name in names:
            run("ip", "netns", "add", name)
            owned.append(name)
            run("ip", "-n", name, "link", "set", "lo", "up")
        for left, right, left_ns, right_ns in (("c0", "rl0", client, router),
                                               ("s0", "rr0", server, router)):
            run("ip", "link", "add", left, "type", "veth", "peer", "name", right)
            run("ip", "link", "set", left, "netns", left_ns)
            run("ip", "link", "set", right, "netns", right_ns)
        for namespace, interface, address in ((client, "c0", "10.10.0.2/24"),
                                               (router, "rl0", "10.10.0.1/24"),
                                               (router, "rr0", "10.20.0.1/24"),
                                               (server, "s0", "10.20.0.2/24")):
            run("ip", "-n", namespace, "addr", "add", address, "dev", interface)
            run("ip", "-n", namespace, "link", "set", interface, "up")
        for namespace, gateway in ((client, "10.10.0.1"), (server, "10.20.0.1")):
            run("ip", "-n", namespace, "route", "add", "default", "via", gateway)
        run("ip", "netns", "exec", router, "sysctl", "-qw", "net.ipv4.ip_forward=0")
        result["topology"] = {name: {
            "addresses": json.loads(run("ip", "-n", name, "-j", "addr", "show")["stdout"]),
            "routes": json.loads(run("ip", "-n", name, "-j", "route", "show")["stdout"]),
        } for name in names}
        result["names"] = {"client": client, "router": router, "server": server}
        started = now()
        worker = subprocess.Popen(["ip", "netns", "exec", server, sys.executable,
                                   str(Path(__file__).resolve()), "--serve", args.token],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                  start_new_session=True)
        result["worker"] = {"pid": worker.pid, "parentPid": os.getpid(),
                            "startTime": started, "cwd": str(Path.cwd())}
        for _ in range(30):
            if probe(server, "10.20.0.2", 8080)["body"]:
                break
            if worker.poll() is not None:
                raise RuntimeError("owned HTTP service failed to start")
            time.sleep(0.1)
        else:
            raise RuntimeError("owned HTTP service readiness deadline exceeded")
        if args.ready_file:
            Path(args.ready_file).write_text("setup and service ready\n")
        if args.test_mode == "failure":
            raise RuntimeError("intentional failure after owned topology setup")
        if args.test_mode == "cancellation":
            signal.pause()
            raise RuntimeError("unexpected wakeup")
        blocked = observe("forwarding-off")
        apply("forwarding")
        routed = observe("routed")
        apply("snat")
        translated = observe("snat")
        apply("dnat")
        mapped = observe("dnat", "10.10.0.1", 18080)
        run("ip", "netns", "exec", router, "iptables", "-t", "nat", "-F", "PREROUTING")
        removed = observe("mapping-removed", "10.10.0.1", 18080)
        direct = observe("direct-after-removal")
        def expected(body, peer):
            return body == {"token": args.token, "peer": peer,
                            "server": "10.20.0.2", "port": 8080, "path": "/lab"}
        result["complete"] = (blocked is None and expected(routed, "10.10.0.2")
                              and expected(translated, "10.20.0.1")
                              and expected(mapped, "10.20.0.1") and removed is None
                              and expected(direct, "10.20.0.1"))
    except (RuntimeError, InterruptedError, subprocess.TimeoutExpired, AssertionError) as error:
        result["error"] = str(error)
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        if worker:
            stop(worker)
            result["worker"].update({"endTime": now(), "exitCode": worker.returncode,
                                     "reaped": worker.poll() is not None})
            result["cleanup"]["workerReaped"] = worker.poll() is not None
        else:
            result["cleanup"]["workerReaped"] = True
        for name in reversed(owned):
            run("ip", "netns", "del", name, check=False)
        if owned:
            result["cleanup"]["remainingNamespaces"] = run("ip", "netns", "list")["stdout"]
            result["cleanup"]["namespacesRemoved"] = not result["cleanup"]["remainingNamespaces"].strip()
        result["cleanup"]["remainingLinks"] = json.loads(run("ip", "-j", "link", "show")["stdout"])
        Path(args.output).write_text(json.dumps(result, indent=2) + "\n")
    return 1 if "error" in result else 0


def outside(args):
    if sys.platform != "linux" or os.geteuid() != 0:
        raise RuntimeError("Use a disposable Linux VM and sudo; no lab changes were made.")
    for tool in ("ip", "unshare", "mount", "sysctl", "iptables", "iptables-save", "curl", "bash"):
        if not shutil.which(tool):
            raise RuntimeError(f"required Linux tool is missing: {tool}")
    records = []
    before = snapshot(records)
    result = {"token": uuid.uuid4().hex, "hostBefore": before, "commands": records}
    with tempfile.TemporaryDirectory(prefix="ns6-owned-") as temp:
        inner_output = str(Path(temp) / "inner.json")
        parts = ["unshare", "--mount", "--net",
                 sys.executable, str(Path(__file__).resolve()), "--inside", before["networkNamespace"],
                 "--original-mount", before["mountNamespace"],
                 "--token", result["token"], "--output", inner_output,
                 "--test-mode", args.test_mode]
        if args.ready_file:
            parts.extend(["--ready-file", args.ready_file])
        try:
            result["isolatedProcess"] = command(parts, records, check=False, timeout=60)
        except (InterruptedError, subprocess.TimeoutExpired) as error:
            result["error"] = str(error)
        finally:
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            signal.signal(signal.SIGINT, signal.SIG_IGN)
            if Path(inner_output).is_file():
                result["lab"] = json.loads(Path(inner_output).read_text())
            result["hostAfter"] = snapshot(records)
            result["hostUnchanged"] = before == result["hostAfter"]
            output = Path(args.output).resolve()
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(json.dumps(result, indent=2) + "\n")
    if not result["hostUnchanged"] or "error" in result or "error" in result.get("lab", {}):
        print(f"Lab stopped; inspect {output}", file=sys.stderr)
        return 1
    if not result.get("lab", {}).get("cleanup", {}).get("namespacesRemoved"):
        print(f"Isolation or cleanup failed; inspect {output}", file=sys.stderr)
        return 1
    print(f"{'Complete' if result['lab']['complete'] else 'Incomplete starter'}; observations: {output}")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="network-observations.json")
    parser.add_argument("--inside", help=argparse.SUPPRESS)
    parser.add_argument("--original-mount", help=argparse.SUPPRESS)
    parser.add_argument("--token", help=argparse.SUPPRESS)
    parser.add_argument("--serve", help=argparse.SUPPRESS)
    parser.add_argument("--test-mode", choices=("normal", "failure", "cancellation"),
                        default="normal", help=argparse.SUPPRESS)
    parser.add_argument("--ready-file", help=argparse.SUPPRESS)
    args = parser.parse_args()
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    if args.serve:
        serve(args.serve)
        return 0
    return inside(args) if args.inside else outside(args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except RuntimeError as failure:
        print(str(failure), file=sys.stderr)
        sys.exit(2)
