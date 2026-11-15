"""Verify capture choices against retained packet bytes and actual HTTP traffic."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile

from kernel_optional_source import CASES, ROOT, digest, source_checks
from verify_capture import now, run, wire_packets


def stream_bytes(frames, source_port):
    selected = [row for row in frames if row["sourcePort"] == source_port]
    payloads = [row for row in selected if base64.b64decode(row["payloadBase64"])]
    if not payloads:
        return b""
    syn = next((row for row in selected if row["flags"] & 2), None)
    origin = (syn["sequence"] + 1) & 0xffffffff if syn else payloads[0]["sequence"]
    values = {}
    for row in payloads:
        offset = (row["sequence"] - origin) & 0xffffffff
        data = base64.b64decode(row["payloadBase64"], validate=True)
        assert offset + len(data) <= 65536
        for index, byte in enumerate(data, offset):
            assert index not in values or values[index] == byte
            values[index] = byte
    assert set(values) == set(range(max(values) + 1)), "gap in the retained owned TCP stream"
    return bytes(values[index] for index in range(len(values)))


def check_observations(data, settings, complete, mode, reverse):
    assert data["hostUnchanged"] and data["hostBefore"] == data["hostAfter"]
    lab = data["lab"]
    assert lab["networkNamespace"] != data["hostBefore"]["networkNamespace"]
    assert lab["workerReady"]["networkNamespace"] == lab["networkNamespace"]
    assert lab["workerReady"]["ports"] == [8080, 8081]
    assert lab["workerReady"]["pid"] == lab["worker"]["pid"]
    assert lab["workerReady"]["token"] == data["token"]
    assert lab["settings"] == settings
    for name in ["worker", "capture"]:
        assert lab["cleanup"][name + "Reaped"] and lab[name]["reaped"]
        assert lab[name]["exitCode"] is not None
        try:
            os.kill(lab[name]["pid"], 0)
        except ProcessLookupError:
            pass
        else:
            raise AssertionError("owned child remains alive")
    assert [row["ifname"] for row in lab["cleanup"]["remainingLinks"]] == ["lo"]
    for row in data["commands"] + lab["commands"]:
        assert row["pid"] > 0 and row["parentPid"] > 0 and row["exitCode"] is not None
        assert row["startTime"] <= row["endTime"]
    raw = base64.b64decode(lab["pcapBase64"], validate=True)
    assert hashlib.sha256(raw).hexdigest() == lab["pcapSha256"]
    frames = wire_packets(raw)
    assert frames == lab["packets"]
    assert all(row["source"] == row["destination"] == "127.0.0.1" for row in frames)
    captured = re.search(r"(\d+) packets captured", lab["capture"]["stderr"])
    assert captured and int(captured[1]) == len(frames)
    invocation = next(row for row in lab["commands"] if row["pid"] == lab["capture"]["pid"])["command"]
    assert invocation[:2] == ["tcpdump", "--immediate-mode"] and invocation[invocation.index("-i") + 1] == "lo"
    assert "-p" in invocation and "-nn" in invocation and "-U" in invocation
    assert invocation[-1] == "tcp and host 127.0.0.1" + (" and port 8080" if settings["filterPort"] else "")
    assert ("-c" in invocation) is bool(settings["packetLimit"])
    if settings["packetLimit"]:
        assert invocation[invocation.index("-c") + 1] == str(settings["packetLimit"])
        assert len(frames) <= settings["packetLimit"]
    assert data["complete"] is complete and lab["complete"] is complete
    if mode == "hold":
        assert not lab["requests"] and lab.get("error") and "signal" in lab["error"]
        return frames, 0
    requests = lab["requests"]
    assert len(requests) == 3
    assert [row["peer"][1] for row in requests] == ([8080, 8081, 8081] if reverse else [8081, 8080, 8081])
    for row in requests:
        assert row["networkNamespace"] == lab["networkNamespace"]
        assert row["body"] == {"token": data["token"], "pid": lab["worker"]["pid"],
                               "port": row["peer"][1], "path": "/capture/" + data["token"]}
        assert base64.b64decode(row["requestBase64"], validate=True).startswith(
            b"GET /capture/" + data["token"].encode() + b" HTTP/1.1\r\n")
        assert base64.b64decode(row["responseBase64"], validate=True).startswith(b"HTTP/1.1 200 ")
    target_request = next(row for row in requests if row["peer"][1] == 8080)
    source_port = target_request["local"][1]
    target = [row for row in frames if 8080 in (row["sourcePort"], row["destinationPort"])]
    noise = [row for row in frames if 8081 in (row["sourcePort"], row["destinationPort"])]
    chosen = [row for row in target if {row["sourcePort"], row["destinationPort"]} == {source_port, 8080}]
    assert chosen
    request_bytes, response_bytes = stream_bytes(chosen, source_port), stream_bytes(chosen, 8080)
    request_visible = b"GET /capture/" + data["token"].encode() in request_bytes
    response_visible = b"HTTP/1.1 200 " in response_bytes
    token_visible = data["token"].encode() in response_bytes
    analysis = {"targetPackets": len(target), "noisePackets": len(noise),
                "requestVisible": request_visible, "responseVisible": response_visible,
                "responseTokenVisible": token_visible,
                "synObserved": any(row["flags"] & 0x12 == 2 for row in target),
                "synAckObserved": any(row["flags"] & 0x12 == 0x12 for row in target)}
    assert analysis == lab["analysis"]
    if settings["filterPort"]:
        assert not noise
    else:
        assert noise, "the broad filter must actually retain the owned second service"
    if settings["packetLimit"] == 2:
        assert len(frames) == 2 and not request_visible and not response_visible and not token_visible
    else:
        assert base64.b64decode(target_request["requestBase64"]) == request_bytes
        assert base64.b64decode(target_request["responseBase64"]) == response_bytes
        assert request_visible and response_visible and token_visible
    independently_complete = (mode == "normal" and settings["packetLimit"] > 0 and settings["filterPort"]
                              and not noise and request_visible and response_visible and token_visible
                              and analysis["synObserved"] and analysis["synAckObserved"])
    assert independently_complete is complete
    if mode == "failure":
        assert "controlled failure" in lab["error"]
    else:
        assert "error" not in data and "error" not in lab
    return frames, 3


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proof", type=Path, required=True)
    parser.add_argument("--source-only", action="store_true")
    parser.add_argument("--exported-source", action="store_true")
    args = parser.parse_args()
    args.proof = args.proof.resolve()
    raw = args.proof.parent / "capture-optional-raw"
    raw.mkdir(parents=True, exist_ok=False)
    proof = {"at": now(), "nativeAccepted": False, "sourceFiles": {}, "processes": [], "runs": []}
    try:
        proof["sourceFiles"] = source_checks("capture", run, proof["processes"], args.exported_source)
        if args.source_only:
            return
        assert sys.platform == "linux" and os.geteuid() == 0
        with tempfile.TemporaryDirectory(prefix="network-capture-optional-") as temporary:
            scenarios = [(0, "starter", None, False, "normal"), (0, "solution", None, False, "normal"),
                         (0, "corrected", {"packetLimit": 64, "filterPort": True}, True, "normal"),
                         (0, "alternate-bound", {"packetLimit": 32, "filterPort": True}, False, "normal"),
                         (0, "zero-bound-control", {"packetLimit": 0, "filterPort": True}, False, "normal"),
                         (1, "starter", None, False, "normal"), (1, "solution", None, True, "normal"),
                         (1, "corrected", {"packetLimit": 64, "filterPort": True}, False, "normal"),
                         (1, "broad-reverse-control", {"packetLimit": 64, "filterPort": False}, True, "normal"),
                         (0, "failure", None, False, "failure"), (1, "hold", None, False, "hold")]
            for index, variant, changed, reverse, mode in scenarios:
                definition = CASES["capture"][index]
                role = variant if variant in ["starter", "solution"] else "solution" if mode != "normal" else "starter"
                label = definition["kind"] + "-" + variant
                work = Path(temporary) / (label + " quoted workspace")
                shutil.copytree(ROOT / definition["pack"] / role, work)
                if changed is not None:
                    path = work / "capture-options.sh"
                    text = path.read_text()
                    old = definition["referenceSettings"] if role == "solution" else definition["starterSettings"]
                    assert text.count(json.dumps(old, separators=(",", ":"))) == 1
                    path.write_text(text.replace(json.dumps(old, separators=(",", ":")),
                                                json.dumps(changed, separators=(",", ":")), 1))
                settings = changed or definition["starterSettings" if role == "starter" else "referenceSettings"]
                assert digest(work / "capture_runtime.py") == CASES["qualifiedApparatus"]["capture"]["capture_runtime.py"]
                report, ready = raw / (label + ".json"), raw / (label + "-ready.txt")
                argv = ["bash", str(work / "capture_http.sh"), "--output", str(report), "--test-mode", mode]
                if reverse:
                    argv.append("--reverse")
                if mode == "hold":
                    argv += ["--ready-file", str(ready)]
                code, stdout, stderr = run(argv, proof["processes"], ready if mode == "hold" else None)
                (raw / (label + ".stdout")).write_text(stdout)
                (raw / (label + ".stderr")).write_text(stderr)
                assert code == (0 if mode == "normal" else 2), (label, code, stderr)
                data = json.loads(report.read_text())
                complete = mode == "normal" and settings["filterPort"] and settings["packetLimit"] >= 32
                row = {"profile": label, "settings": settings, "mode": mode, "reverse": reverse,
                       "exitCode": code, "rawReport": str(report), "rawSHA256": digest(report), "evidence": data}
                proof["runs"].append(row)
                frames, requests = check_observations(data, settings, complete, mode, reverse)
                pcap = base64.b64decode(data["lab"]["pcapBase64"], validate=True)
                (raw / (label + ".pcap")).write_bytes(pcap)
                row.update(independentFrames=frames, actualRequests=requests)
        assert source_checks("capture", run, proof["processes"], args.exported_source) == proof["sourceFiles"]
        proof.update(nativeAccepted=True, actualProfiles=len(proof["runs"]), oneSettingCorrections=2,
                     independentPackets=sum(len(r["independentFrames"]) for r in proof["runs"]),
                     actualHTTPRequests=sum(r["actualRequests"] for r in proof["runs"]),
                     actualInsufficientCaptureVerified=True, actualNoiseAndOrderControlsVerified=True,
                     unchangedQualifiedApparatus=True)
    finally:
        proof["endedAt"] = now()
        args.proof.parent.mkdir(parents=True, exist_ok=True)
        args.proof.write_text(json.dumps(proof, indent=2) + "\n")
    print(json.dumps({k: v for k, v in proof.items() if k not in ["sourceFiles", "processes", "runs"]}))


if __name__ == "__main__":
    main()
