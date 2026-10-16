"""Measure a real UFW policy only inside an owned network and mount namespace."""
import argparse
import contextlib
import datetime
import hashlib
import http.server
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def stop(process, grace=4):
    if process.poll() is None:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=grace)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=3)


def command(argv, records, timeout=8, check=True, env=None, input_text=None, grace=4):
    started = now()
    process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
                               start_new_session=True, env=env)
    cleanup = "exited and reaped"
    stdout = stderr = b""
    try:
        stdout, stderr = process.communicate(input_text.encode() if input_text is not None else None,
                                             timeout=timeout)
    except BaseException:
        cleanup = "terminated and reaped owned process group"
        stop(process, grace)
        stdout, stderr = process.communicate(timeout=3)
        raise
    finally:
        records.append({"task": "NS3-owned-UFW", "command": argv,
                        "cwd": str(Path.cwd()), "parentPid": os.getpid(), "pid": process.pid,
                        "startTime": started, "endTime": now(), "exitCode": process.returncode,
                        "timeoutSeconds": timeout, "childProcessGroupCleanup": cleanup,
                        "stdout": stdout.decode(errors="replace"), "stderr": stderr.decode(errors="replace")})
    result = {"exitCode": process.returncode, "stdout": stdout.decode(), "stderr": stderr.decode()}
    if check and process.returncode:
        raise RuntimeError(f"command failed: {argv[0]}: {result['stderr'].strip()}")
    return result


def firewall_configuration(raw):
    return "\n".join(re.sub(r"\[\d+:\d+\]", "[COUNTERS]", line)
                     for line in raw.splitlines() if not line.startswith("#"))


def tree_hashes(root):
    result = {}
    for file in sorted(root.rglob("*")):
        name = str(file.relative_to(root))
        if file.is_symlink():
            result[name] = "symlink:" + os.readlink(file)
        elif file.is_file():
            result[name] = hashlib.sha256(file.read_bytes()).hexdigest()
    return result


def configuration_hashes():
    return {"etcUfw": tree_hashes(Path("/etc/ufw")),
            "defaultUfw": hashlib.sha256(Path("/etc/default/ufw").read_bytes()).hexdigest()}


def host_state(records):
    return {"networkNamespace": os.readlink("/proc/self/ns/net"),
            "mountNamespace": os.readlink("/proc/self/ns/mnt"),
            "links": command(["ip", "-j", "link", "show"], records)["stdout"],
            "addresses": command(["ip", "-j", "addr", "show"], records)["stdout"],
            "routes": command(["ip", "-j", "route", "show", "table", "all"], records)["stdout"],
            "ipv6Routes": command(["ip", "-6", "-j", "route", "show", "table", "all"], records)["stdout"],
            "firewall": firewall_configuration(command(["iptables-save"], records)["stdout"]),
            "ipv6Firewall": firewall_configuration(command(["ip6tables-save"], records)["stdout"]),
            "forwarding": command(["sysctl", "-n", "net.ipv4.ip_forward"], records)["stdout"],
            "configuration": configuration_hashes()}


def require_owned(args):
    if sys.platform != "linux" or os.geteuid() != 0:
        raise RuntimeError("Use an owned disposable Linux VM with console access and sudo.")
    if not args.origin or os.readlink("/proc/self/ns/net") in (args.origin, os.readlink("/proc/1/ns/net")):
        raise RuntimeError("refusing to change the original network namespace")
    if not args.original_mount or os.readlink("/proc/self/ns/mnt") in (args.original_mount, os.readlink("/proc/1/ns/mnt")):
        raise RuntimeError("refusing to change the original mount namespace")


def publish_ready(path, content):
    pending = path.with_name(path.name + ".pending")
    descriptor = os.open(pending, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(descriptor, "w") as stream:
            json.dump(content, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(pending, path)
    finally:
        pending.unlink(missing_ok=True)


def serve(args):
    require_owned(args)
    servers = []

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            body = json.dumps({"token": args.token, "pid": os.getpid(), "path": self.path,
                               "client": list(self.client_address),
                               "server": list(self.connection.getsockname()),
                               "service": self.server.lab_service}, sort_keys=True).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Type", "application/json")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            self.close_connection = True

        def log_message(self, _format, *_args):
            pass

    try:
        for service, port in (("management-marker", args.management_port), ("web", 8080), ("unrequested", 9090)):
            server = http.server.ThreadingHTTPServer(("10.77.0.2", port), Handler)
            server.daemon_threads = True
            server.lab_service = service
            servers.append(server)
            threading.Thread(target=server.serve_forever, daemon=True).start()
        publish_ready(Path(args.worker_ready), {"pid": os.getpid(), "networkNamespace": os.readlink("/proc/self/ns/net"),
                                               "listeners": [["10.77.0.2", server.server_port] for server in servers]})
        signal.pause()
    finally:
        for server in servers:
            server.server_close()


def restore_directory(saved, target):
    for file in target.iterdir():
        if file.is_dir() and not file.is_symlink():
            shutil.rmtree(file)
        else:
            file.unlink()
    for file in saved.iterdir():
        destination = target / file.name
        if file.is_dir():
            shutil.copytree(file, destination, symlinks=True)
        else:
            shutil.copy2(file, destination, follow_symlinks=False)


def inside(args):
    require_owned(args)
    result = {"commands": [], "observations": [], "complete": False,
              "networkNamespace": os.readlink("/proc/self/ns/net"),
              "mountNamespace": os.readlink("/proc/self/ns/mnt"),
              "managementPort": args.management_port, "reverse": args.reverse,
              "cleanup": {"workerReaped": False, "namespaceRemoved": False, "policyRestored": False}}
    records = result["commands"]
    client = "ns3-" + args.token[:10] + "-client"
    worker = None
    created = False
    baseline = None
    private = None
    worker_started = None

    def run(*argv, **options):
        return command(list(argv), records, **options)

    def probe(stage, service, port):
        response = run("ip", "netns", "exec", client, "curl", "--noproxy", "*", "--silent", "--show-error",
                       "--fail", "--connect-timeout", "1", "--max-time", "1",
                       f"http://10.77.0.2:{port}/policy/{args.token}", check=False)
        row = {"stage": stage, "service": service, "port": port, "response": response,
               "body": json.loads(response["stdout"]) if response["exitCode"] == 0 else None}
        result["observations"].append(row)
        return row

    services = [("management-marker", args.management_port), ("web", 8080), ("unrequested", 9090)]
    if args.reverse:
        services.reverse()

    def probes(stage):
        return {service: probe(stage, service, port) for service, port in services}

    def valid(row):
        body = row["body"]
        return bool(body and body["token"] == args.token and body["pid"] == worker.pid
                    and body["client"][0] == "10.77.0.1" and body["server"] == ["10.77.0.2", row["port"]]
                    and body["path"] == "/policy/" + args.token and body["service"] == row["service"])

    def rollback():
        if baseline is None or result["cleanup"]["policyRestored"]:
            return
        run("ufw", "--force", "disable")
        restore_directory(private / "before-config", private / "config")
        shutil.copy2(private / "before-default", private / "defaults/ufw")
        run("iptables-restore", input_text=baseline["kernel"])
        after_kernel = run("iptables-save")["stdout"]
        after_config = configuration_hashes()
        result["rollback"] = {"beforeConfiguration": baseline["configuration"], "afterConfiguration": after_config,
                              "beforeKernel": baseline["kernel"], "afterKernel": after_kernel,
                              "status": run("ufw", "status", "verbose")["stdout"],
                              "addedRules": run("ufw", "show", "added")["stdout"],
                              "configurationRestored": after_config == baseline["configuration"],
                              "kernelRestored": firewall_configuration(after_kernel) == firewall_configuration(baseline["kernel"])}
        result["cleanup"]["policyRestored"] = result["rollback"]["configurationRestored"] and result["rollback"]["kernelRestored"]
        result["rollbackRequests"] = probes("rollback")
        result["rollback"]["allThreeServicesRestored"] = all(valid(row) for row in result["rollbackRequests"].values())

    with tempfile.TemporaryDirectory(prefix="ns3-private-") as temporary:
        private = Path(temporary)
        try:
            run("mount", "--make-rprivate", "/")
            run("mount", "-t", "tmpfs", "-o", "mode=755,nosuid,nodev", "ns3-owned-run", "/run")
            Path("/run/netns").mkdir()
            assert not run("ip", "netns", "list")["stdout"].strip()
            shutil.copytree("/etc/ufw", private / "config", symlinks=True)
            (private / "defaults").mkdir()
            (private / "defaults/ufw").write_text('IPV6=no\nDEFAULT_INPUT_POLICY="DROP"\nDEFAULT_OUTPUT_POLICY="ACCEPT"\nDEFAULT_FORWARD_POLICY="DROP"\nDEFAULT_APPLICATION_POLICY="SKIP"\nMANAGE_BUILTINS=no\nIPT_SYSCTL=/etc/ufw/sysctl.conf\nIPT_MODULES=""\n')
            run("mount", "--bind", str(private / "config"), "/etc/ufw")
            run("mount", "--bind", str(private / "defaults"), "/etc/default")
            result["privateConfigurationVerified"] = (os.path.samestat(os.stat("/etc/ufw"), (private / "config").stat())
                                                       and os.path.samestat(os.stat("/etc/default"), (private / "defaults").stat()))
            assert result["privateConfigurationVerified"]
            Path("/etc/ufw/sysctl.conf").write_text("# This owned endpoint experiment requires no sysctl changes.\n")
            run("ufw", "--force", "reset")
            Path("/etc/ufw/.course-owned-run").write_text(args.token)
            shutil.copy2(Path(__file__).with_name("web-stack.profile"), "/etc/ufw/applications.d/course-web")
            run("ufw", "allow", "65530/tcp", "comment", "owned prior rule")
            before_added = run("ufw", "show", "added")["stdout"]
            assert "65530/tcp" in before_added
            baseline = {"configuration": configuration_hashes(), "kernel": run("iptables-save")["stdout"],
                        "addedRules": before_added, "status": run("ufw", "status", "verbose")["stdout"]}
            result["priorPolicy"] = baseline
            shutil.copytree(private / "config", private / "before-config", symlinks=True)
            shutil.copy2(private / "defaults/ufw", private / "before-default")
            run("ip", "link", "set", "lo", "up")
            run("ip", "netns", "add", client)
            created = True
            run("ip", "-n", client, "link", "set", "lo", "up")
            run("ip", "link", "add", "s0", "type", "veth", "peer", "name", "c0")
            run("ip", "link", "set", "c0", "netns", client)
            run("ip", "addr", "add", "10.77.0.2/24", "dev", "s0")
            run("ip", "link", "set", "s0", "up")
            run("ip", "-n", client, "addr", "add", "10.77.0.1/24", "dev", "c0")
            run("ip", "-n", client, "link", "set", "c0", "up")
            result["clientNamespace"] = client
            result["topology"] = {"server": json.loads(run("ip", "-j", "addr", "show")["stdout"]),
                                  "client": json.loads(run("ip", "-n", client, "-j", "addr", "show")["stdout"])}
            ready = private / "worker-ready.json"
            worker_argv = [sys.executable, str(Path(__file__).resolve()), "--serve", "--token", args.token,
                           "--origin", args.origin, "--original-mount", args.original_mount,
                           "--management-port", str(args.management_port), "--worker-ready", str(ready)]
            worker_started = now()
            worker = subprocess.Popen(worker_argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
            result["worker"] = {"command": worker_argv, "pid": worker.pid, "parentPid": os.getpid(),
                                "cwd": str(Path.cwd()), "startTime": worker_started, "timeoutSeconds": 75}
            deadline = time.monotonic() + 5
            while not ready.exists() and time.monotonic() < deadline and worker.poll() is None:
                time.sleep(0.03)
            assert ready.exists(), "owned service readiness deadline exceeded"
            result["workerReady"] = json.loads(ready.read_text())
            result["baselineRequests"] = probes("baseline")
            assert all(valid(row) for row in result["baselineRequests"].values()), "baseline must prove all services and the peer path"
            run("ufw", "default", "deny", "incoming")
            run("ufw", "default", "allow", "outgoing")
            environment = dict(os.environ, COURSE_ORIGINAL_NETNS=args.origin, COURSE_ORIGINAL_MNTNS=args.original_mount,
                               COURSE_LAB_TOKEN=args.token, MANAGEMENT_PORT=str(args.management_port))
            for stage in ("management", "web"):
                run("bash", str(Path(__file__).with_name("policy-rules.sh")), stage, env=environment)
            run("ufw", "logging", "low")
            run("ufw", "--force", "enable")
            result["activeBeforeProbe"] = {"numbered": run("ufw", "status", "numbered")["stdout"],
                                           "verbose": run("ufw", "status", "verbose")["stdout"],
                                           "added": run("ufw", "show", "added")["stdout"],
                                           "kernel": run("iptables-save", "-c")["stdout"]}
            if args.ready_file:
                publish_ready(Path(args.ready_file), {"activeOwnedPolicy": True, "networkNamespace": result["networkNamespace"]})
            if args.test_mode == "failure":
                raise RuntimeError("intentional failure after the owned policy became active")
            if args.test_mode == "hold":
                signal.pause()
                raise RuntimeError("unexpected hold wakeup")
            result["policyRequests"] = probes("policy")
            result["activeAfterProbe"] = {"numbered": run("ufw", "status", "numbered")["stdout"],
                                          "kernel": run("iptables-save", "-c")["stdout"],
                                          "listeners": run("ss", "-ltnp")["stdout"]}
            responses = result["policyRequests"]
            result["policyOutcomeCorrect"] = (valid(responses["management-marker"]) and valid(responses["web"])
                                               and responses["unrequested"]["body"] is None)
            result["priorRulePreserved"] = "--dport 65530" in result["activeAfterProbe"]["kernel"]
            rollback()
            result["complete"] = (result["policyOutcomeCorrect"] and result["priorRulePreserved"]
                                  and result["cleanup"]["policyRestored"] and result["rollback"]["allThreeServicesRestored"])
        except (RuntimeError, AssertionError, OSError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
            result["error"] = str(error)
            result["complete"] = False
        finally:
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            signal.signal(signal.SIGINT, signal.SIG_IGN)
            try:
                rollback()
            except (RuntimeError, AssertionError, OSError, ValueError, subprocess.TimeoutExpired) as error:
                result["rollbackError"] = str(error)
                result["complete"] = False
            if worker:
                stop(worker)
                result["worker"].update(endTime=now(), exitCode=worker.returncode,
                                         reaped=worker.poll() is not None, childProcessGroupCleanup="terminated and reaped owned service")
                result["cleanup"]["workerReaped"] = worker.poll() is not None
            else:
                result["cleanup"]["workerReaped"] = True
            if created:
                run("ip", "netns", "del", client, check=False)
            result["cleanup"]["remainingNamespaces"] = run("ip", "netns", "list")["stdout"]
            result["cleanup"]["namespaceRemoved"] = not result["cleanup"]["remainingNamespaces"].strip()
            result["cleanup"]["remainingLinks"] = json.loads(run("ip", "-j", "link", "show")["stdout"])
            Path(args.inner_output).write_text(json.dumps(result, indent=2) + "\n")
    return 2 if result.get("error") or result.get("rollbackError") else 0


def outer(args):
    if sys.platform != "linux" or os.geteuid() != 0:
        raise RuntimeError("Use an owned disposable Linux VM with console access and sudo; no policy changes were made.")
    for tool in ("ufw", "ip", "unshare", "mount", "iptables-save", "iptables-restore", "ip6tables-save", "sysctl", "ss", "curl", "bash"):
        if not shutil.which(tool):
            raise RuntimeError(f"required Linux lab tool is missing: {tool}")
    output = Path(args.output)
    if output.exists() or output.is_symlink() or not output.parent.is_dir():
        raise RuntimeError("the report must be a new file in an existing directory")
    if args.management_port in (22, 8080, 9090) or not 1024 <= args.management_port <= 65529:
        raise RuntimeError("choose a distinct nondefault management marker port from 1024 through 65529")
    result = {"commands": [], "token": uuid.uuid4().hex, "complete": False}
    records = result["commands"]
    result["hostBefore"] = host_state(records)
    with tempfile.TemporaryDirectory(prefix="ns3-outer-") as temporary:
        inner_output = Path(temporary) / "inner.json"
        argv = ["unshare", "--mount", "--net", sys.executable, str(Path(__file__).resolve()),
                "--inside", "--origin", result["hostBefore"]["networkNamespace"],
                "--original-mount", result["hostBefore"]["mountNamespace"], "--token", result["token"],
                "--inner-output", str(inner_output), "--management-port", str(args.management_port), "--test-mode", args.test_mode]
        if args.reverse:
            argv.append("--reverse")
        if args.ready_file:
            argv += ["--ready-file", args.ready_file]
        try:
            outcome = command(argv, records, timeout=75, check=False, grace=18)
            if outcome["exitCode"]:
                result["error"] = outcome["stderr"] or "owned UFW experiment did not complete"
        except (RuntimeError, OSError, ValueError, AssertionError, subprocess.TimeoutExpired) as error:
            result["error"] = str(error)
        finally:
            if inner_output.exists():
                result["lab"] = json.loads(inner_output.read_text())
                result["complete"] = bool(result["lab"]["complete"]) and "error" not in result
            result["hostAfter"] = host_state(records)
            result["hostUnchanged"] = result["hostBefore"] == result["hostAfter"]
            if not result["hostUnchanged"]:
                result["error"] = "outer host configuration changed"
                result["complete"] = False
            with output.open("x", encoding="utf8") as stream:
                json.dump(result, stream, indent=2)
                stream.write("\n")
    print(json.dumps({"output": str(output), "complete": result["complete"], "hostUnchanged": result["hostUnchanged"]}))
    return 2 if result.get("error") else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="policy-observations.json", help="A new JSON report filename.")
    parser.add_argument("--management-port", type=int, default=2222, help="Owned management marker, not an SSH daemon.")
    parser.add_argument("--reverse", action="store_true", help="Reverse fresh request order.")
    parser.add_argument("--inside", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--origin", help=argparse.SUPPRESS)
    parser.add_argument("--original-mount", help=argparse.SUPPRESS)
    parser.add_argument("--token", help=argparse.SUPPRESS)
    parser.add_argument("--inner-output", help=argparse.SUPPRESS)
    parser.add_argument("--serve", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--worker-ready", help=argparse.SUPPRESS)
    parser.add_argument("--ready-file", help=argparse.SUPPRESS)
    parser.add_argument("--test-mode", choices=("normal", "failure", "hold"), default="normal", help=argparse.SUPPRESS)
    args = parser.parse_args()

    def interrupted(signum, _frame):
        raise RuntimeError(f"interrupted by signal {signum}")

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    if args.serve:
        serve(args)
        return 0
    return inside(args) if args.inside else outer(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, AssertionError, ValueError, OSError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(2)
