"""Reconcile real bridge, route, translation, process and restoration evidence."""
import argparse
import ast
import contextlib
import hashlib
import ipaddress
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from verify_naming import complete

sys.dont_write_bytecode = True
PACKS = {
    "NS-07-unit-3-switches-routers-nat-and-the-internet-edge": "core",
    "NS-07-unit-3-switches-routers-nat-and-the-internet-edge-supplemental-2": "transfer",
    "NS-08-unit-3-switches-routers-nat-and-the-internet-edge-supplemental-3": "extension",
}
FILES = ("main.py", "link_routing_lab.py", "network-notes.md", "edge-cases.md", "README.md")
PLANS = {
    "core": [("bridge-forwarding-off", True), ("bridge-port-down", False), ("bridge-restored", True),
             ("router-forwarding-off", False), ("routed", True), ("snat", True)],
    "transfer": [("route-ready", True), ("client-gateway-missing", False), ("client-gateway-restored", True),
                 ("return-route-missing", False), ("return-route-restored", True)],
    "extension": [("routed", True), ("snat", True), ("mapped", True), ("mapping-removed", False), ("direct-after-removal", True)],
}
COMPLETIONS = {
    "core": '''def analyze(e):
    rows = e['lab']['observations']
    first, _, restored, off, routed, translated = rows
    return dict(bridgeWorksWithIPForwardingOff=first['response']['exitCode'] == 0 and first['state']['forwarding'] == '0',
                bridgeRestoreSucceeded=restored['response']['exitCode'] == 0,
                routerOffHasHTTP=off['response']['body'] is not None,
                routedPeer=routed['response']['body']['peer'][0], translatedPeer=translated['response']['body']['peer'][0])
''',
    "transfer": '''def analyze(e):
    rows = e['lab']['observations']
    client, server = e['lab']['names']['client'], e['lab']['names']['server']
    return dict(clientDefaultAbsent=all(r.get('dst') != 'default' for r in rows[1]['state']['routes'][client]),
                returnDefaultAbsent=all(r.get('dst') != 'default' for r in rows[3]['state']['routes'][server]),
                failedStages=[r['stage'] for r in rows if r['response']['exitCode']],
                restoredPeer=rows[-1]['response']['body']['peer'][0])
''',
    "extension": '''def analyze(e):
    rows = e['lab']['observations']
    return dict(requestedMappedEndpoint=[rows[2]['target'], rows[2]['port']],
                observedServerEndpoint=rows[2]['response']['body']['local'],
                peerBeforeSNAT=rows[0]['response']['body']['peer'][0], peerAfterSNAT=rows[1]['response']['body']['peer'][0],
                removedMappingHasHTTP=rows[3]['response']['body'] is not None, directStillWorks=rows[4]['response']['exitCode'] == 0)
''',
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def run(argv, cwd, records):
    started = time.time()
    child = subprocess.Popen(argv, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}, start_new_session=True)
    cleanup = "exited and reaped"
    out = err = b""
    try:
        out, err = child.communicate(timeout=90)
    except BaseException:
        cleanup = "owned process group stopped and reaped"
        with contextlib.suppress(ProcessLookupError):
            os.killpg(child.pid, signal.SIGTERM)
        try:
            child.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL)
            child.communicate(timeout=3)
        raise
    finally:
        records.append({"parentTask": "unit3-native-verification", "parentPid": os.getpid(), "cwd": str(cwd),
                        "command": argv, "pid": child.pid, "startTime": started, "endTime": time.time(),
                        "exitCode": child.returncode, "timeoutSeconds": 90, "childProcessGroupCleanup": cleanup,
                        "stdout": out.decode(), "stderr": err.decode()})
    return child.returncode, out.decode(), err.decode()


def global_state(cwd, records):
    result = {}
    for label, argv in [("links", ["ip", "-j", "link", "show"]), ("routes", ["ip", "-j", "route", "show", "table", "all"]),
                        ("names", ["ip", "netns", "list"]), ("forwarding", ["sysctl", "-n", "net.ipv4.ip_forward"]),
                        ("firewall", ["iptables-save"])]:
        code, out, err = run(argv, cwd, records)
        assert code == 0 and not err
        if label == "firewall":
            out = "\n".join(re.sub(r"^(:\S+ \S+) \[\d+:\d+\]$", r"\1", line) for line in out.splitlines() if not line.startswith("#"))
        result[label] = out
    result.update(networkNamespace=os.readlink("/proc/self/ns/net"), mountNamespace=os.readlink("/proc/self/ns/mnt"))
    return result


def check_cleanup(e):
    assert e["launcherUID"] == e["environment"]["uid"] == 0
    assert e["environment"]["platform"] == "linux" and not e["publicInternetMeasured"]
    assert not e["learnerNotebookCompletionInferred"] and not e["lab"]["learnerNotebookCompletionInferred"]
    assert e["hostUnchanged"] and all(v == e["hostAfter"][k] for k, v in e["hostBefore"].items() if k != "firewallRaw")
    lab, worker = e["lab"], e["lab"]["worker"]
    assert lab["networkNamespace"] != e["hostBefore"]["networkNamespace"]
    assert lab["mountNamespace"] != e["hostBefore"]["mountNamespace"]
    assert lab["workerNetworkNamespace"] not in (lab["networkNamespace"], e["hostBefore"]["networkNamespace"])
    assert lab["workerProcUidFields"] == ["0"] * 4
    owner = "pid=" + str(worker["pid"]) + ","
    assert owner in lab["listenerDuring"] and owner not in lab["listenerAfter"]
    assert worker["reaped"] and worker["exitCode"] == -signal.SIGTERM and not worker["stderr"]
    assert worker["childProcessGroupCleanup"] == "owned HTTP worker stopped and reaped" and worker["timeoutSeconds"] == 60
    assert lab["cleanup"]["workerReaped"] and lab["cleanup"]["namespacesRemoved"] and lab["cleanup"]["onlyLoopbackRemains"]
    assert lab["cleanup"]["remainingNamespaces"] == "" and [r["ifname"] for r in lab["cleanup"]["remainingLinks"]] == ["lo"]
    assert not Path("/proc/" + str(worker["pid"])).exists()
    assert [json.loads(line) for line in worker["stdout"].splitlines()] == lab["workerRequests"]
    ready = lab["readiness"]["body"]
    assert ready["token"] == e["token"] and ready["pid"] == worker["pid"] and ready["uid"] == 0
    assert ready["local"] == ["127.0.0.1", e["servicePort"]] and ready["peer"][0] == "127.0.0.1"
    assert lab["workerRequests"][0]["response"] == ready
    assert len(e["commands"]) == 11
    for record in [*e["commands"], *lab["commands"]]:
        assert record["startTime"] <= record["endTime"] and record["exitCode"] is not None
        assert record["parentPid"] > 0 and record["pid"] > 0 and record["timeoutSeconds"] in (8, 60)
    return len(lab["workerRequests"])


def rule_tokens(raw, chain, target):
    rows = [shlex.split(line) for line in raw.splitlines() if line.startswith("-A " + chain + " ")]
    rows = [row for row in rows if "-j" in row and row[row.index("-j") + 1] == target]
    assert len(rows) == 1
    return rows[0]


def check(e, kind):
    count = check_cleanup(e)
    assert not e.get("error") and e["lab"]["observationsCollected"] and e["kind"] == kind
    lab, addresses = e["lab"], e["lab"]["addresses"]
    left, right = ("10.41.0", "10.42.0") if e["alternate"] else ("10.31.0", "10.32.0")
    assert addresses == {"client": left + ".2", "bridgeServer": left + ".3", "clientGateway": left + ".1", "server": right + ".2", "serverGateway": right + ".1"}
    client, middle, server = [lab["names"][name] for name in ("client", "middle", "server")]
    rows = lab["observations"]
    assert [(row["stage"], row["response"]["exitCode"] == 0) for row in rows] == PLANS[kind]
    expected_success = 4 if kind != "transfer" else 3
    assert count == expected_success + 1
    body_records = lab["workerRequests"][1:]
    body_index = 0
    for i, row in enumerate(rows):
        r, state = row["response"], row["state"]
        bridged = row["stage"].startswith("bridge-")
        translated = kind == "extension" and i > 0 or kind == "core" and row["stage"] == "snat"
        target = addresses["bridgeServer"] if bridged else addresses["clientGateway"] if row["stage"] in ("mapped", "mapping-removed") else addresses["server"]
        port = e["mappedPort"] if row["stage"] in ("mapped", "mapping-removed") else e["servicePort"]
        assert row["target"] == target and row["port"] == port
        assert state["forwarding"] == ("0" if bridged or row["stage"] == "router-forwarding-off" else "1")
        command = next(x for x in lab["commands"] if x["pid"] == r["commandPid"])
        assert command["stdout"] == r["stdout"] and command["stderr"] == r["stderr"] and command["exitCode"] == r["exitCode"]
        assert command["command"][:4] == ["ip", "netns", "exec", client]
        assert command["command"][-1] == "http://" + target + ":" + str(port) + "/edge"
        assert "--noproxy" in command["command"] and "*" in command["command"]
        if r["exitCode"] == 0:
            head, raw_body = r["wire"].split("\r\n\r\n", 1)
            assert head.splitlines()[0].split()[1] == "200"
            headers = dict(line.split(": ", 1) for line in head.split("\r\n")[1:])
            assert int(headers["Content-Length"]) == len(raw_body.encode())
            body = json.loads(raw_body)
            assert body == r["body"] == body_records[body_index]["response"]
            assert body["token"] == e["token"] and body["pid"] == lab["worker"]["pid"] and body["uid"] == 0 and body["path"] == "/edge"
            assert body["peer"][0] == (addresses["serverGateway"] if translated else addresses["client"])
            assert body["local"] == [addresses["bridgeServer"] if bridged else addresses["server"], e["servicePort"]]
            assert r["clientObservedPeer"] == target + ":" + str(port)
            assert r["clientObservedLocal"].startswith(addresses["client"] + ":")
            if not translated:
                assert r["clientObservedLocal"] == body["peer"][0] + ":" + str(body["peer"][1])
            assert body_records[body_index]["requestLine"] == "GET /edge HTTP/1.1\r\n"
            body_index += 1
        else:
            assert r["body"] is None and r["stderr"] and not r["wire"]
        if translated:
            tokens = rule_tokens(state["natRules"], "POSTROUTING", "SNAT")
            assert tokens[tokens.index("--to-source") + 1] == addresses["serverGateway"]
            assert tokens[tokens.index("--dport") + 1] == str(e["servicePort"])
            assert ipaddress.ip_network(tokens[tokens.index("-s") + 1]) == ipaddress.ip_network(left + ".0/24")
        else:
            assert "-j SNAT" not in state["natRules"]
        if row["stage"] == "mapped":
            tokens = rule_tokens(state["natRules"], "PREROUTING", "DNAT")
            assert tokens[tokens.index("--to-destination") + 1] == addresses["server"] + ":" + str(e["servicePort"])
            assert tokens[tokens.index("--dport") + 1] == str(e["mappedPort"])
        else:
            assert "-j DNAT" not in state["natRules"]
        if not bridged:
            assert not any(link["ifname"] == "br0" for link in state["addresses"][middle])
            for interface, value in [("ml0", addresses["clientGateway"]), ("mr0", addresses["serverGateway"])]:
                link = next(link for link in state["addresses"][middle] if link["ifname"] == interface)
                assert any(info.get("local") == value and info.get("prefixlen") == 24 for info in link["addr_info"])
        if bridged:
            assert not any(r.get("dst") == "default" for r in state["routes"][client])
            assert {r["ifname"] for r in row["bridgeLinks"]} == {"ml0", "mr0"}
            assert ("UP" in next(r for r in row["bridgeLinks"] if r["ifname"] == "mr0")["flags"]) == (row["stage"] != "bridge-port-down")
            bridge = row["bridgeInterface"][0]
            assert bridge["ifname"] == "br0" and bridge["linkinfo"]["info_kind"] == "bridge" and bridge["linkinfo"]["info_data"]["stp_state"] == 0
            if r["exitCode"] == 0:
                for namespace, interface, port_name in [(client, "c0", "ml0"), (server, "s0", "mr0")]:
                    mac = next(link["address"] for link in state["addresses"][namespace] if link["ifname"] == interface)
                    assert any(entry["mac"] == mac and entry.get("ifname", entry.get("dev")) == port_name for entry in row["bridgeFDB"])
        if row["stage"] == "client-gateway-missing":
            assert not any(r.get("dst") == "default" for r in state["routes"][client]) and row["clientRouteLookup"]["exitCode"] != 0
        if row["stage"] == "return-route-missing":
            assert not any(r.get("dst") == "default" for r in state["routes"][server]) and row["serverReturnLookup"]["exitCode"] != 0
    assert body_index == len(body_records) == expected_success
    return count


def expected_analysis(e, kind):
    a = e["lab"]["addresses"]
    if kind == "core":
        return {"bridgeWorksWithIPForwardingOff": True, "bridgeRestoreSucceeded": True, "routerOffHasHTTP": False,
                "routedPeer": a["client"], "translatedPeer": a["serverGateway"]}
    if kind == "transfer":
        return {"clientDefaultAbsent": True, "returnDefaultAbsent": True,
                "failedStages": ["client-gateway-missing", "return-route-missing"], "restoredPeer": a["client"]}
    return {"requestedMappedEndpoint": [a["clientGateway"], e["mappedPort"]], "observedServerEndpoint": [a["server"], e["servicePort"]],
            "peerBeforeSNAT": a["client"], "peerAfterSNAT": a["serverGateway"], "removedMappingHasHTTP": False, "directStillWorks": True}


def descendants(pid):
    result, pending = [], [pid]
    while pending:
        current = pending.pop()
        path = Path("/proc/" + str(current) + "/task/" + str(current) + "/children")
        try:
            children = [int(p) for p in path.read_text().split()]
        except FileNotFoundError:
            continue
        result.extend(children)
        pending.extend(children)
    return result


def interrupt(folder, signum, records):
    argv = [sys.executable, "main.py", "--hold-ms", "2000"]
    started = time.time()
    child = subprocess.Popen(argv, cwd=folder, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}, start_new_session=True)
    marker = None
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and child.poll() is None:
            for pid in descendants(child.pid):
                cmdline = Path("/proc/" + str(pid) + "/cmdline")
                try:
                    parts = cmdline.read_bytes().decode().split("\0")
                except FileNotFoundError:
                    continue
                if "--inside" in parts and "--inner-output" in parts:
                    path = Path(parts[parts.index("--inner-output") + 1]).with_name("ready.json")
                    try:
                        marker = json.loads(path.read_text())
                    except FileNotFoundError:
                        continue
            if marker:
                break
            time.sleep(0.02)
        assert marker and child.poll() is None
        code, out, err = run(["nsenter", "--target", str(marker["workerPid"]), "--net", "ss", "-H", "-ltnp", "sport = :" + str(marker["port"])], folder, records)
        assert code == 0 and not err and "pid=" + str(marker["workerPid"]) + "," in out
        child.send_signal(signum)
        out, err = child.communicate(timeout=20)
        assert child.returncode == 128 + signum and not err
        e = json.loads(out)
        assert e["interruptedStatus"] == 128 + signum and e["token"] == marker["token"]
        assert not e["lab"]["observations"] and check_cleanup(e) == 1
        return e
    finally:
        if child.poll() is None:
            os.killpg(child.pid, signal.SIGTERM)
            try:
                child.communicate(timeout=15)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.communicate(timeout=3)
        records.append({"parentTask": "unit3-native-interruption", "parentPid": os.getpid(), "cwd": str(folder),
                        "command": argv, "pid": child.pid, "startTime": started, "endTime": time.time(),
                        "exitCode": child.returncode, "timeoutSeconds": 20, "signalSent": signum,
                        "childProcessGroupCleanup": "owned hierarchy cleanup and reaping checked"})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--proof", type=Path, required=True)
    args = parser.parse_args()
    assert sys.platform == "linux" and os.geteuid() == 0
    root = Path(__file__).resolve().parents[1]
    names = [p + "/README.md" for p in PACKS]
    names += [p + "/" + role + "/" + n for p in PACKS for role in ("starter", "solution") for n in FILES]
    names += ["test/verify_link_routing.py", ".github/workflows/native-network.yml", "COURSE_SOURCE_MANIFEST.md", "SOURCE_BACKLOG.md"]
    sources = {name: {"content": (root / name).read_text(), "sha256": sha((root / name).read_bytes())} for name in names}
    args.proof.parent.mkdir(parents=True, exist_ok=True)
    proof = {"nativePassed": False, "sourceFiles": sources, "profiles": [], "controlledFailures": [], "interruptions": [],
             "refusals": [], "nonrootRefusals": [], "guardRefusals": [], "processes": [], "platform": sys.platform, "uid": os.geteuid(),
             "learnerNotebookCompletionInferred": False, "publicInternetMeasured": False}
    before = global_state(root, proof["processes"])
    try:
        with tempfile.TemporaryDirectory(prefix="unit3-native ") as temporary:
            temporary = Path(temporary)
            temporary.chmod(0o755)
            for pack, kind in PACKS.items():
                for role in ("starter", "completed", "reference"):
                    for alternate in (False, True):
                        selected = "solution" if role == "reference" else "starter"
                        folder = temporary / (kind + " ' " + role + " " + str(alternate))
                        shutil.copytree(root / pack / selected, folder)
                        if role == "completed":
                            original = (folder / "main.py").read_text()
                            changed = complete(original, COMPLETIONS[kind])
                            def unchanged_body(text):
                                tree = ast.parse(text)
                                tree.body = [node for node in tree.body if not isinstance(node, ast.FunctionDef) or node.name != "analyze"]
                                return ast.dump(tree, include_attributes=False)
                            assert unchanged_body(original) == unchanged_body(changed)
                            (folder / "main.py").write_text(changed)
                        tail = ["--alternate", "--service-port", "8087", "--mapped-port", "18087"] if alternate else []
                        status, out, err = run([sys.executable, "main.py", *tail], folder, proof["processes"])
                        name = kind + "-" + role + "-" + str(int(alternate)) + ".json"
                        (args.proof.parent / name).write_text(out)
                        assert status == 0 and not err, (kind, role, status, err, out[-1600:])
                        e = json.loads(out)
                        count = check(e, kind)
                        assert e["alternate"] == alternate and (e["servicePort"], e["mappedPort"]) == ((8087, 18087) if alternate else (8080, 18080))
                        assert e["analysis"] == (None if role == "starter" else expected_analysis(e, kind))
                        proof["profiles"].append({"pack": pack, "kind": kind, "role": role, "alternate": alternate,
                                                  "evidence": name, "sha256": sha(out.encode()), "actualHTTPResponses": count,
                                                  "executedMain": (folder / "main.py").read_text(),
                                                  "roleFileHashes": {n: sha((folder / n).read_bytes()) for n in FILES}})
                folder = temporary / (kind + " refusals")
                shutil.copytree(root / pack / "starter", folder)
                for tail in (["--service-port", "80"], ["--service-port", "65536"], ["--mapped-port", "80"],
                             ["--service-port", "8080", "--mapped-port", "8080"], ["--hold-ms", "-1"], ["--hold-ms", "2001"], ["--unknown"]):
                    status, out, err = run([sys.executable, "main.py", *tail], folder, proof["processes"])
                    assert status == 2 and err and (not out or "hostBefore" not in json.loads(out))
                    proof["refusals"].append({"pack": pack, "arguments": tail, "status": status})
                status, out, err = run(["setpriv", "--reuid=65534", "--regid=65534", "--clear-groups", sys.executable, "main.py"], folder, proof["processes"])
                assert status == 2 and err and json.loads(out)["launcherUID"] == 65534 and "hostBefore" not in json.loads(out)
                proof["nonrootRefusals"].append({"pack": pack, "status": status, "actualUID": 65534})
                status, out, err = run([sys.executable, "main.py", "--fail-after-ready"], folder, proof["processes"])
                assert status == 2 and "controlled failure" in err
                e = json.loads(out)
                assert "controlled failure" in e["error"] and not e["lab"]["observations"] and check_cleanup(e) == 1
                name = kind + "-controlled-failure.json"
                (args.proof.parent / name).write_text(out)
                proof["controlledFailures"].append({"pack": pack, "evidence": name, "sha256": sha(out.encode())})
            folder = temporary / "interruption"
            shutil.copytree(root / next(iter(PACKS)) / "starter", folder)
            for signum in (signal.SIGINT, signal.SIGTERM):
                e = interrupt(folder, signum, proof["processes"])
                name = "interrupted-" + str(signum) + ".json"
                raw = json.dumps(e, indent=2) + "\n"
                (args.proof.parent / name).write_text(raw)
                proof["interruptions"].append({"signal": signum, "evidence": name, "sha256": sha(raw.encode())})
            helper = str(folder / "link_routing_lab.py")
            original = ["--original-network", before["networkNamespace"], "--original-mount", before["mountNamespace"], "--token", "a" * 32]
            for flag in ("--serve", "--inside"):
                tail = [flag, *original]
                if flag == "--inside":
                    private = temporary / "ns3-owned-guard"
                    private.mkdir(mode=0o700)
                    tail += ["--kind", "core", "--inner-output", str(private / "inner.json")]
                status, out, err = run([sys.executable, helper, *tail], folder, proof["processes"])
                assert status == 2 and "original network namespace" in err and not out
                proof["guardRefusals"].append({"flag": flag, "status": status})
        after = global_state(root, proof["processes"])
        assert before == after and all(sha((root / name).read_bytes()) == record["sha256"] for name, record in sources.items())
        assert len(proof["profiles"]) == 18 and len(proof["refusals"]) == 21 and len(proof["nonrootRefusals"]) == 3
        assert len(proof["controlledFailures"]) == 3 and len(proof["interruptions"]) == len(proof["guardRefusals"]) == 2
        proof.update(nativePassed=True, sourceUnchanged=True, sourceFileCopies=37, hostBefore=before, hostAfter=after,
                     actualPrimaryAttempts=96, actualPrimaryHTTPResponses=66, normalHTTPResponsesIncludingReadiness=84,
                     actualAllHTTPResponsesIncludingReadiness=89, actualWorkerReaps=23,
                     independentCompletedAndReferenceAnalyses=12)
    except BaseException as error:
        proof["error"] = type(error).__name__ + ": " + str(error)
        raise
    finally:
        args.proof.write_text(json.dumps(proof, indent=2) + "\n")
    print(json.dumps({k: v for k, v in proof.items() if k not in ("sourceFiles", "profiles", "processes", "hostBefore", "hostAfter")}))


if __name__ == "__main__":
    main()
