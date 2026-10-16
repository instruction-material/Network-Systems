"""Observe a routed operations case in disposable Linux namespaces."""
import argparse
import contextlib
import datetime
import hashlib
import http.client
import http.server
import ipaddress
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

COMMANDS = []
WORKERS = []


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


class Interrupted(Exception):
    pass


def interrupted(_number, _frame):
    raise Interrupted()


def command(argv, timeout=8, check=True):
    argv = [str(value) for value in argv]
    started = now()
    child = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out = err = b""
    cleanup = "child exited in the supervised lab process group"
    try:
        out, err = child.communicate(timeout=timeout)
    except BaseException:
        child.kill()
        out, err = child.communicate(timeout=2)
        cleanup = "owned command killed and reaped; enclosing lab group remains supervised"
        raise
    finally:
        result = {"parentTaskId": "network-operations-capstone", "cwd": str(Path.cwd()),
                  "command": argv, "pid": child.pid, "parentPid": os.getpid(),
                  "processGroup": os.getpgrp(), "startTime": started, "endTime": now(),
                  "exitCode": child.returncode, "timeoutSeconds": timeout,
                  "childProcessGroupCleanup": cleanup, "stdout": out.decode(errors="replace"),
                  "stderr": err.decode(errors="replace")}
        COMMANDS.append(result)
    if check and result["exitCode"] != 0:
        raise RuntimeError(json.dumps(result))
    return result


def write_json(path, value):
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n")
    os.replace(temporary, path)


def require_isolation():
    parent_net = os.environ.get("CAPSTONE_PARENT_NET")
    parent_mount = os.environ.get("CAPSTONE_PARENT_MOUNT")
    current = [os.readlink("/proc/self/ns/net"), os.readlink("/proc/self/ns/mnt")]
    if not parent_net or not parent_mount or current[0] in {parent_net, os.readlink("/proc/1/ns/net")} or current[1] in {parent_mount, os.readlink("/proc/1/ns/mnt")}:
        raise RuntimeError("Internal lab entry requires distinct owned network and mount namespaces")
    return {"network": current[0], "mount": current[1], "parentNetwork": parent_net, "parentMount": parent_mount}


def host_snapshot():
    result = {}
    for label, argv in [
        ("links", ["ip", "-j", "link", "show"]),
        ("ipv4Routes", ["ip", "-4", "-j", "route", "show", "table", "all"]),
        ("ipv6Routes", ["ip", "-6", "-j", "route", "show", "table", "all"]),
        ("ipv4Policy", ["iptables-save"]), ("ipv6Policy", ["ip6tables-save"]),
    ]:
        text = command(argv)["stdout"]
        if label.endswith("Policy"):
            text = "\n".join(re.sub(r"\[\d+:\d+\]", "[counter]", line) for line in text.splitlines() if not line.startswith("#"))
        elif label.endswith("Routes"):
            rows = json.loads(text)
            for row in rows:
                for volatile in ["expires", "used", "cache", "error"]:
                    row.pop(volatile, None)
            text = json.dumps(rows, sort_keys=True)
        result[label] = text
    return result


def worker(argv, output, name):
    path = output / (name + ".log")
    stream = path.open("wb")
    child = subprocess.Popen([str(value) for value in argv], stdout=stream, stderr=subprocess.STDOUT)
    descriptor = {"parentTaskId": "network-operations-capstone", "cwd": str(Path.cwd()),
                  "command": [str(value) for value in argv], "pid": child.pid,
                  "parentPid": os.getpid(), "processGroup": os.getpgrp(),
                  "startTime": now(), "timeoutSeconds": 35, "log": path.name}
    WORKERS.append((child, stream, descriptor))
    return child, path


def stop_workers():
    for child, stream, descriptor in reversed(WORKERS):
        if child.poll() is None:
            child.send_signal(signal.SIGINT if descriptor["log"] == "capture.log" else signal.SIGTERM)
        try:
            child.wait(timeout=3)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=2)
        stream.close()
        descriptor.update(endTime=now(), exitCode=child.returncode,
                          childProcessGroupCleanup="owned worker reaped in enclosing supervised lab group")
    return [descriptor for _child, _stream, descriptor in WORKERS]


class IPv6Server(http.server.ThreadingHTTPServer):
    address_family = socket.AF_INET6

    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        super().server_bind()


def serve(public_port, upstream_port, token):
    require_isolation()

    class Application(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            status = 200 if self.path == "/health" else 404
            data = json.dumps({"fixture": "owned-operations-capstone", "token": token, "path": self.path}).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, _format, *_arguments):
            return

    class Proxy(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            upstream = http.client.HTTPConnection("127.0.0.1", upstream_port, timeout=1)
            try:
                upstream.request("GET", self.path, headers={"Host": "owned-upstream.capstone.test"})
                response = upstream.getresponse()
                status, data = response.status, response.read()
            except OSError:
                status, data = 502, b'{"error":"owned upstream connection failed"}'
            finally:
                upstream.close()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("X-Capstone-Proxy", "owned-loopback-upstream")
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, _format, *_arguments):
            return

    servers = [http.server.ThreadingHTTPServer(("127.0.0.1", 9000), Application),
               http.server.ThreadingHTTPServer(("0.0.0.0", public_port), Proxy),
               IPv6Server(("::", public_port), Proxy),
               http.server.ThreadingHTTPServer(("0.0.0.0", 8088), Application),
               IPv6Server(("::", 8088), Application)]
    for server in servers:
        server.daemon_threads = True
        threading.Thread(target=server.serve_forever, daemon=True).start()
    print(json.dumps({"event": "listeners-ready", "pid": os.getpid(), "publicPort": public_port,
                      "upstream": "127.0.0.1:9000", "proxyTarget": upstream_port}), flush=True)
    while True:
        time.sleep(0.2)


def inside(case_file, output, alternate, hold):
    signal.signal(signal.SIGINT, interrupted)
    signal.signal(signal.SIGTERM, interrupted)
    case = json.loads(case_file.read_text())
    identities = require_isolation()
    client_net = 41 if alternate else 31
    c4, r4, s4, g4 = f"198.18.{client_net}.2", f"198.18.{client_net}.1", "198.18.32.2", "198.18.32.1"
    c6, r6, s6, g6 = f"2001:db8:{client_net}::2", f"2001:db8:{client_net}::1", "2001:db8:32::2", "2001:db8:32::1"
    port = 8087 if alternate else 8080
    name = ("amber" if alternate else "blue") + ".capstone.test"
    token = hashlib.sha256((name + str(output)).encode()).hexdigest()[:20]
    namespaces = ["ncap-client", "ncap-router", "ncap-server"]
    report = {"event": "operations-capstone", "alternate": alternate, "identities": identities,
              "case": case, "client4": c4, "client6": c6, "server4": s4, "server6": s6,
              "publicPort": port, "name": name, "token": token, "completed": False, "interrupted": False}
    created = []
    result_code = 1

    def ns(name, *argv, check=True, timeout=8):
        return command(["ip", "netns", "exec", name, *argv], check=check, timeout=timeout)

    def http(label, address, target_port, path="/health"):
        if address is None:
            return {"command": None, "status": "unresolved", "body": ""}
        payload = output / (label + ".body")
        host = "[" + address + "]" if ":" in address else address
        result = ns(namespaces[0], "curl", "--noproxy", "*", "-g", "--silent", "--show-error", "--max-time", "1", "--header", "Host: " + name, "--output", str(payload), "--write-out", "%{http_code}", "http://" + host + ":" + str(target_port) + path, check=False, timeout=3)
        return {"command": result, "status": result["stdout"].strip(),
                "body": payload.read_text() if payload.exists() else ""}

    try:
        command(["mount", "--make-rprivate", "/"])
        command(["mount", "-t", "tmpfs", "-o", "mode=0755", "capstone-run", "/run"])
        Path("/run/netns").mkdir()
        for name_space in namespaces:
            command(["ip", "netns", "add", name_space])
            created.append(name_space)
            command(["ip", "-n", name_space, "link", "set", "lo", "up"])
        for left, right, left_ns, right_ns in [("c-r", "r-c", namespaces[0], namespaces[1]), ("r-s", "s-r", namespaces[1], namespaces[2])]:
            command(["ip", "link", "add", left, "type", "veth", "peer", "name", right])
            command(["ip", "link", "set", left, "netns", left_ns])
            command(["ip", "link", "set", right, "netns", right_ns])
            for interface, owner in [(left, left_ns), (right, right_ns)]:
                command(["ip", "-n", owner, "link", "set", interface, "up"])
        for owner, interface, ipv4, ipv6 in [(namespaces[0], "c-r", c4, c6), (namespaces[1], "r-c", r4, r6), (namespaces[1], "r-s", g4, g6), (namespaces[2], "s-r", s4, s6)]:
            command(["ip", "-n", owner, "address", "add", ipv4 + "/30", "dev", interface])
            command(["ip", "-n", owner, "-6", "address", "add", ipv6 + "/64", "dev", interface, "nodad"])
        ns(namespaces[1], "sysctl", "-q", "-w", "net.ipv4.ip_forward=1", "net.ipv6.conf.all.forwarding=1")
        command(["ip", "-n", namespaces[0], "route", "add", case["ipv4_service_route"], "via", r4])
        command(["ip", "-n", namespaces[2], "route", "add", f"198.18.{client_net}.0/30", "via", g4])
        command(["ip", "-n", namespaces[0], "-6", "route", "add", "2001:db8:32::/64", "via", r6])
        command(["ip", "-n", namespaces[2], "-6", "route", "add", f"2001:db8:{client_net}::/64", "via", g6])
        for tool, client in [("iptables", c4), ("ip6tables", c6)]:
            ns(namespaces[2], tool, "-P", "INPUT", "DROP")
            ns(namespaces[2], tool, "-A", "INPUT", "-i", "lo", "-j", "ACCEPT")
            ns(namespaces[2], tool, "-A", "INPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT")
            if tool == "ip6tables":
                ns(namespaces[2], tool, "-A", "INPUT", "-p", "ipv6-icmp", "-j", "ACCEPT")
            for protocol, allowed in [("udp", 15353), ("tcp", port)]:
                ns(namespaces[2], tool, "-A", "INPUT", "-s", client, "-p", protocol, "--dport", str(allowed), "-j", "ACCEPT")
        dns_argv = ["ip", "netns", "exec", namespaces[2], "dnsmasq", "--no-daemon", "--conf-file=/dev/null", "--no-hosts", "--no-resolv", "--no-poll", "--cache-size=0", "--user=root", "--bind-interfaces", "--port=15353", "--listen-address=" + s4, "--listen-address=" + s6, "--address=/" + name + "/" + s4, "--address=/" + name + "/" + s6, "--pid-file=" + str(output / "dnsmasq.pid"), "--log-queries"]
        worker(dns_argv, output, "dns")
        service, service_log = worker(["ip", "netns", "exec", namespaces[2], sys.executable, str(Path(__file__).resolve()), "_serve", str(port), str(case["proxy_upstream_port"]), token], output, "service")
        limit = time.monotonic() + 4
        while b'"event": "listeners-ready"' not in service_log.read_bytes():
            if service.poll() is not None or time.monotonic() >= limit:
                raise RuntimeError("Owned service did not create its listeners")
            time.sleep(0.03)
        limit = time.monotonic() + 4
        while True:
            ready_dns = ns(namespaces[0], "dig", "@" + s6, "-p", "15353", name, "A", "+short", "+time=1", "+tries=1", check=False)
            if ready_dns["stdout"].strip() == s4:
                break
            if time.monotonic() >= limit:
                raise RuntimeError("Owned fictional-name resolver did not answer")
        capture, capture_log = worker(["ip", "netns", "exec", namespaces[2], "tcpdump", "-i", "s-r", "-s", "0", "-n", "-U", "-c", "160", "-w", str(output / "capture.pcap"), "tcp port " + str(port) + " or udp port 15353"], output, "capture")
        limit = time.monotonic() + 3
        while b"listening on" not in capture_log.read_bytes():
            if capture.poll() is not None or time.monotonic() >= limit:
                raise RuntimeError("Owned bounded capture did not start")
            time.sleep(0.03)
        write_json(output / "ready.json", {"event": "topology-ready", "pid": os.getpid(), "namespaces": namespaces,
                   "workers": [{"pid": child.pid, "command": descriptor["command"]} for child, _stream, descriptor in WORKERS],
                   "identities": identities})
        if hold:
            time.sleep(hold)
        report["addresses"] = {owner: {family: command(["ip", "-n", owner, flag, "-j", "address", "show"]) for family, flag in [("ipv4", "-4"), ("ipv6", "-6")]} for owner in namespaces}
        report["forwarding"] = ns(namespaces[1], "sysctl", "net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding")
        report["routes4"] = command(["ip", "-n", namespaces[0], "-4", "route", "show"])
        report["routes6"] = command(["ip", "-n", namespaces[0], "-6", "route", "show"])
        report["routeGet4"] = command(["ip", "-n", namespaces[0], "-4", "route", "get", s4], check=False)
        report["routeGet6"] = command(["ip", "-n", namespaces[0], "-6", "route", "get", s6], check=False)
        report["listeners"] = ns(namespaces[2], "ss", "-H", "-lntup")
        report["policy4"] = ns(namespaces[2], "iptables", "-S")
        report["policy6"] = ns(namespaces[2], "ip6tables", "-S")
        report["dns"] = {}
        for record_type in ["A", "AAAA"]:
            result = ns(namespaces[0], "dig", "@" + s6, "-p", "15353", name, record_type, "+short", "+time=1", "+tries=1", check=False)
            report["dns"][record_type] = result
        report["dns4"] = ns(namespaces[0], "dig", "@" + s4, "-p", "15353", name, "A", "+short", "+time=1", "+tries=1", check=False)
        resolved = {}
        for record_type, version, boundary in [("A", 4, "198.18.0.0/15"), ("AAAA", 6, "2001:db8::/32")]:
            try:
                address = ipaddress.ip_address(report["dns"][record_type]["stdout"].strip())
                resolved[record_type] = str(address) if address.version == version and address in ipaddress.ip_network(boundary) else None
            except ValueError:
                resolved[record_type] = None
        report["resolvedDestinations"] = resolved
        report["http4"] = http("http4", resolved["A"], port)
        report["http6"] = http("http6", resolved["AAAA"], port)
        report["missingPath"] = http("missing", resolved["AAAA"], port, "/missing")
        report["denied4"] = http("denied4", s4, 8088)
        report["denied6"] = http("denied6", s6, 8088)
        report["directUpstream"] = http("direct-upstream", s6, 9000)
        expected = [report["dns"]["A"]["stdout"].strip() == s4,
                    report["dns"]["AAAA"]["stdout"].strip() == str(ipaddress.ip_address(s6)),
                    report["dns4"]["stdout"].strip() == s4,
                    report["http4"]["status"] == report["http6"]["status"] == "200",
                    report["missingPath"]["status"] == "404",
                    all(report[key]["status"] == "000" and report[key]["command"]["exitCode"] != 0 for key in ["denied4", "denied6", "directUpstream"])]
        upstream_listeners = [line.split()[4] for line in report["listeners"]["stdout"].splitlines() if len(line.split()) >= 6 and line.split()[4].endswith(":9000")]
        expected.append(upstream_listeners == ["127.0.0.1:9000"])
        for family in ["http4", "http6"]:
            try:
                body = json.loads(report[family]["body"])
            except json.JSONDecodeError:
                body = {}
            expected.append(body == {"fixture": "owned-operations-capstone", "token": token, "path": "/health"})
        report["completed"] = all(expected)
        result_code = 0 if report["completed"] else 1
    except Interrupted:
        report["interrupted"] = True
        result_code = 130
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        report["workers"] = stop_workers()
        for namespace in reversed(created):
            command(["ip", "netns", "delete", namespace], check=False)
        report["remainingNamespaces"] = command(["ip", "netns", "list"])["stdout"].strip()
        report["allWorkersReaped"] = all(child.poll() is not None for child, _stream, _descriptor in WORKERS)
        if (output / "capture.pcap").exists():
            report["packetRead"] = command(["tcpdump", "-n", "-r", str(output / "capture.pcap")], check=False)
        write_json(output / "inside.json", report)
        write_json(output / "commands.json", COMMANDS)
    return result_code if report["allWorkersReaped"] and not report["remainingNamespaces"] else 70


def main(case_file):
    parser = argparse.ArgumentParser(description="Build, diagnose and remove an owned routed operations case")
    parser.add_argument("--alternate", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--hold-after-ready", type=float, default=0)
    args = parser.parse_args()
    if sys.platform != "linux" or os.geteuid() != 0:
        parser.error("Use sudo in an owned Linux lab with namespace support")
    tools = ["ip", "unshare", "mount", "sysctl", "iptables", "ip6tables", "iptables-save", "ip6tables-save", "dnsmasq", "dig", "tcpdump", "curl", "ss"]
    missing = [tool for tool in tools if not shutil.which(tool)]
    if missing:
        parser.error("Missing native lab tools: " + ", ".join(missing))
    if not 0 <= args.hold_after_ready <= 30:
        parser.error("The ready hold must be between zero and thirty seconds")
    case = json.loads(case_file.read_text())
    if set(case) != {"ipv4_service_route", "proxy_upstream_port"}:
        parser.error("case.json must contain only the route and owned proxy port")
    route = ipaddress.ip_network(case["ipv4_service_route"], strict=True)
    if route.version != 4 or not route.subnet_of(ipaddress.ip_network("198.18.0.0/15")):
        parser.error("The case route must stay in the reserved owned fixture range")
    if type(case["proxy_upstream_port"]) is not int or not 1024 <= case["proxy_upstream_port"] <= 65535:
        parser.error("The owned proxy port must be an integer in 1024..65535")
    output = (args.output or Path.cwd() / ("capstone-observation-" + str(time.time_ns()))).resolve()
    output.mkdir(exist_ok=False)
    write_json(output / "case-used.json", case)
    environment = dict(os.environ)
    environment["CAPSTONE_PARENT_NET"] = os.readlink("/proc/self/ns/net")
    environment["CAPSTONE_PARENT_MOUNT"] = os.readlink("/proc/self/ns/mnt")
    versions = {"python": sys.version, "kernel": list(os.uname())}
    for label, argv in [("ip", ["ip", "-V"]), ("iptables", ["iptables", "--version"]), ("dnsmasq", ["dnsmasq", "--version"]), ("dig", ["dig", "-v"]), ("tcpdump", ["tcpdump", "--version"]), ("curl", ["curl", "--version"])]:
        versions[label] = command(argv)
    before = host_snapshot()
    started = now()
    child = subprocess.Popen(["unshare", "--mount", "--net", sys.executable, str(Path(__file__).resolve()), "_inside", str(case_file.resolve()), str(output), "1" if args.alternate else "0", str(args.hold_after_ready)], env=environment, start_new_session=True)
    signal.signal(signal.SIGINT, interrupted)
    signal.signal(signal.SIGTERM, interrupted)
    cancelled = False
    try:
        child.wait(timeout=35)
    except (Interrupted, subprocess.TimeoutExpired):
        cancelled = True
        with contextlib.suppress(ProcessLookupError):
            os.killpg(child.pid, signal.SIGTERM)
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(child.pid, signal.SIGKILL)
            child.wait(timeout=2)
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        after = host_snapshot()
        receipt = {"event": "operations-capstone-parent", "parentTaskId": "network-operations-capstone",
                   "cwd": str(Path.cwd()), "command": child.args, "pid": child.pid, "parentPid": os.getpid(),
                   "startTime": started, "endTime": now(), "exitCode": child.returncode, "timeoutSeconds": 35,
                   "childProcessGroupCleanup": "owned lab process group exited or was terminated and reaped",
                   "before": before, "after": after, "hostUnchanged": before == after,
                   "versions": versions,
                   "cancelled": cancelled, "sourceCaseSha256": hashlib.sha256(case_file.read_bytes()).hexdigest()}
        write_json(output / "receipt.json", receipt)
        write_json(output / "parent-commands.json", COMMANDS)
    print(json.dumps({"output": str(output), "labExit": child.returncode, "hostUnchanged": before == after, "cancelled": cancelled}))
    return 130 if cancelled else (child.returncode if before == after else 70)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "_serve":
        serve(int(sys.argv[2]), int(sys.argv[3]), sys.argv[4])
    elif len(sys.argv) > 1 and sys.argv[1] == "_inside":
        raise SystemExit(inside(Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4] == "1", float(sys.argv[5])))
    else:
        raise SystemExit("Run the role's main.py; internal entries require an owned namespace")
