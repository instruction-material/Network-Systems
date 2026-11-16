"""Read supplied network observations and check bounded factual assessments.

This program performs local JSON analysis. It creates no sockets, services,
routes or firewall rules. SOURCES.md records the supplied capture provenance.
"""
import argparse
import hashlib
import ipaddress
import json
import sys
from pathlib import Path
from urllib.parse import urlsplit

MAX_BYTES = 2 * 1024 * 1024


def read_json(path):
    raw = Path(path).read_bytes()
    if len(raw) > MAX_BYTES:
        raise ValueError("Input exceeds the two-megabyte limit")
    return json.loads(raw)


def load_records(path):
    bundle = read_json(path)
    if bundle.get("schemaVersion") != 1 or bundle.get("kind") != "recorded-isolated-linux-lab":
        raise ValueError("Expected the documented recorded-observation bundle")
    records = {}
    for name, record in bundle["records"].items():
        raw = record["raw"].encode("utf-8")
        if hashlib.sha256(raw).hexdigest() != record["origin"]["entrySHA256"]:
            raise ValueError("Recorded input hash changed: " + name)
        records[name] = json.loads(raw)
    return records


def succeeded(command):
    return isinstance(command, dict) and type(command.get("exitCode")) is int and command["exitCode"] == 0


def request_state(observation, family, control=False):
    key = ("denied" if control else "http") + str(family)
    response = observation.get(key)
    if not isinstance(response, dict) or not isinstance(response.get("command"), dict):
        return "not_observed"
    command = response["command"]
    arguments = command.get("command", [])
    if not arguments:
        return "not_observed"
    endpoint = urlsplit(arguments[-1])
    expected_address = observation.get("server" + str(family))
    port = 8088 if control else observation.get("publicPort")
    if (endpoint.scheme != "http" or endpoint.hostname != expected_address
            or endpoint.port != port or endpoint.path != "/health"):
        return "wrong_endpoint"
    if type(command.get("exitCode")) is not int:
        return "not_observed"
    if not succeeded(command):
        return "request_failed"
    if response.get("status") != "200":
        return "unexpected_http_status"
    try:
        body = json.loads(response.get("body", ""))
    except (ValueError, TypeError):
        return "wrong_application"
    fixture = "owned-denial-control" if control else "owned-operations-capstone"
    if not isinstance(body, dict) or body != {
            "fixture": fixture, "token": observation.get("token"), "path": "/health"}:
        return "wrong_application"
    return "control_response" if control else "intended_application"


def binding(observation, family, port):
    command = observation.get("listeners")
    if not succeeded(command):
        return "not_observed"
    addresses = []
    for line in command.get("stdout", "").splitlines():
        columns = line.split()
        if len(columns) < 6 or columns[0] != "tcp" or columns[1] != "LISTEN":
            continue
        endpoint = columns[4]
        address, separator, value = endpoint.rpartition(":")
        if not separator or value != str(port):
            continue
        try:
            parsed = ipaddress.ip_address(address.strip("[]"))
        except ValueError:
            continue
        if parsed.version == family:
            addresses.append(parsed)
    if not addresses:
        return "not_listed"
    return "loopback" if all(a.is_loopback for a in addresses) else "interface_or_wildcard"


def command_observed_failure(command):
    return isinstance(command, dict) and type(command.get("exitCode")) is int and command["exitCode"] != 0


def route_state(observation, family):
    command = observation.get("routeGet" + str(family))
    if not isinstance(command, dict):
        return "not_observed"
    if not succeeded(command):
        return "failed" if command_observed_failure(command) else "not_observed"
    if family == 4:
        prefix = observation.get("case", {}).get("ipv4_service_route")
        if not prefix:
            return "not_observed"
        if ipaddress.ip_address(observation["server4"]) not in ipaddress.ip_network(prefix):
            return "prefix_excludes_server"
    # The selected route-get command must actually ask for this endpoint.
    arguments = command.get("command", [])
    if "get" not in arguments or observation.get("server" + str(family)) not in arguments:
        return "not_observed"
    return "selected"


def dns_state(observation, family):
    key = "A" if family == 4 else "AAAA"
    command = observation.get("dns", {}).get(key)
    if not isinstance(command, dict):
        return "not_observed"
    if not succeeded(command):
        return "failed" if command_observed_failure(command) else "not_observed"
    answers = command.get("stdout", "").split()
    return "matching_answer" if observation.get("server" + str(family)) in answers else "different_answer"


def first_boundary(observation):
    for family in [4, 6]:
        value = dns_state(observation, family)
        if value != "matching_answer":
            return "collect_dns" if value == "not_observed" else "dns"
    for family in [4, 6]:
        value = route_state(observation, family)
        if value != "selected":
            return "collect_route" if value == "not_observed" else "ipv" + str(family) + "_route"
    for family in [4, 6]:
        value = request_state(observation, family)
        if value != "intended_application":
            return "collect_application" if value == "not_observed" else "application_identity" if value in ["wrong_application", "wrong_endpoint"] else "application_request"
    for family in [4, 6]:
        if binding(observation, family, 8088) not in ["interface_or_wildcard", "loopback"]:
            return "collect_control_listener"
        value = request_state(observation, family, control=True)
        if value != "request_failed":
            return "collect_exposure" if value == "not_observed" else "exposure_control"
    return "none"


def readiness(observation):
    boundary = first_boundary(observation)
    if boundary == "none":
        return "ready_for_conceptual_extension"
    return "collect_missing_evidence" if boundary.startswith("collect_") else "repair_baseline_first"


def direct_backend(observation):
    response = observation.get("directUpstream")
    if not isinstance(response, dict) or not isinstance(response.get("command"), dict):
        return {"family": "not_observed", "result": "not_observed"}
    command = response["command"]
    arguments = command.get("command", [])
    if not arguments:
        return {"family": "not_observed", "result": "not_observed"}
    endpoint = urlsplit(arguments[-1])
    try:
        family = ipaddress.ip_address(endpoint.hostname).version
    except ValueError:
        return {"family": "not_observed", "result": "not_observed"}
    if endpoint.scheme != "http" or endpoint.path != "/health" or endpoint.hostname != observation.get("server" + str(family)) or endpoint.port != 9000:
        return {"family": family, "result": "wrong_endpoint"}
    if type(command.get("exitCode")) is not int:
        return {"family": family, "result": "not_observed"}
    status = str(response.get("status", ""))
    replied = succeeded(command) and status.isdecimal() and 100 <= int(status) <= 599
    return {"family": family, "result": "http_response" if replied else "request_failed"}


def facts(observation):
    if observation.get("event") != "operations-capstone":
        raise ValueError("Expected a capstone inside.json observation")
    if ipaddress.ip_address(observation["server4"]).version != 4 or ipaddress.ip_address(observation["server6"]).version != 6:
        raise ValueError("The declared server addresses must retain their families")
    return {
        "dns4": dns_state(observation, 4), "dns6": dns_state(observation, 6),
        "route4": route_state(observation, 4), "route6": route_state(observation, 6),
        "application4": request_state(observation, 4), "application6": request_state(observation, 6),
        "control4": request_state(observation, 4, control=True),
        "control6": request_state(observation, 6, control=True),
        "backendBind4": binding(observation, 4, 9000),
        "backendBind6": binding(observation, 6, 9000),
        "directBackend": direct_backend(observation),
        "firstBoundary": first_boundary(observation),
        "readiness": readiness(observation),
        # These measurements are absent from the supplied isolated topology.
        "internetExposure": "not_established", "vpnTunnel": "not_established",
        "bgpPolicy": "not_established", "wirelessSecurity": "not_established",
        "cloudSecurityGroup": "not_established", "otherClients": "not_established",
    }


TASK_FIELDS = {
    "expansion-plan": {
        "baseline": ["readiness", "vpnTunnel", "bgpPolicy"],
        "route-gap": ["readiness", "firstBoundary"],
        "wrong-upstream": ["readiness", "firstBoundary"],
    },
    "expansion-transfer": {
        "baseline": ["firstBoundary"],
        "route-gap": ["dns4", "route4", "application6", "firstBoundary"],
        "wrong-upstream": ["route4", "application4", "firstBoundary"],
    },
    "expansion-claims": {
        "baseline": ["application4", "application6", "vpnTunnel", "bgpPolicy", "wirelessSecurity", "cloudSecurityGroup"],
        "open-control": ["control4", "control6", "otherClients", "internetExposure"],
    },
    "exposure-core": {
        "baseline": ["application4", "application6", "backendBind4", "internetExposure"],
        "wrong-upstream": ["application4", "application6", "firstBoundary"],
    },
    "exposure-families": {
        "baseline": ["backendBind4", "backendBind6", "directBackend.family", "directBackend.result"],
        "alternate": ["application4", "application6", "backendBind4", "directBackend.family"],
        "route-gap": ["application4", "application6", "firstBoundary"],
    },
    "exposure-policy": {
        "baseline": ["control4", "control6", "application4"],
        "open-control": ["control4", "control6", "application4", "otherClients", "internetExposure"],
    },
}


def expected_answers(task, records):
    if task not in TASK_FIELDS:
        raise ValueError("Unknown archive task")
    result = {}
    for name, fields in TASK_FIELDS[task].items():
        values = facts(records[name])
        for field in fields:
            value = values
            for part in field.split("."):
                value = value[part]
            result[name + "." + field] = value
    return result


def main(task):
    parser = argparse.ArgumentParser(description="Check an assessment of recorded network evidence")
    parser.add_argument("--observations", default="observations.json")
    parser.add_argument("--assessment", default="assessment.json")
    parser.add_argument("--inspect", metavar="INSIDE_JSON", help="Summarize a separately collected capstone inside.json")
    parser.add_argument("--show", metavar="RECORD", help="Display a named recorded observation")
    parser.add_argument("--field", metavar="PATH", help="Select a dotted field for --show, such as dns.A or http4")
    args = parser.parse_args()
    try:
        if args.inspect:
            print(json.dumps({"kind": "provided-file-analysis", "liveNetworkRun": False,
                              "facts": facts(read_json(args.inspect))}, indent=2))
            return 0
        records = load_records(args.observations)
        if args.show:
            selected = records[args.show]
            if args.field:
                for part in args.field.split("."):
                    selected = selected[part]
            print(json.dumps(selected, indent=2))
            return 0
        if args.field:
            raise ValueError("--field accompanies --show")
        assessment = read_json(args.assessment)
        if assessment.get("task") != task or not isinstance(assessment.get("answers"), dict):
            raise ValueError("Assessment task or answers do not match this exercise")
        expected = expected_answers(task, records)
        answers = assessment["answers"]
        if set(answers) != set(expected):
            raise ValueError("Keep every documented answer field; put explanations in network-notes.md")
        checks = [{"field": key, "accepted": type(answers[key]) is type(value) and answers[key] == value}
                  for key, value in expected.items()]
        accepted = all(item["accepted"] for item in checks)
        print(json.dumps({"task": task, "objectiveChecksPassed": accepted, "checks": checks,
                          "evidenceRoute": "recorded-isolated-linux-lab", "liveNetworkRun": False,
                          "notebookCompletionInferred": False, "notebookReviewRequired": True,
                          "scope": "These checks compare factual answers with the supplied observations. Record reasoning, evidence locations and the next measurement in network-notes.md."}, indent=2))
        return 0 if accepted else 1
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(json.dumps({"task": task, "inputError": str(error), "objectiveChecksPassed": False}))
        return 2


if __name__ == "__main__":
    sys.exit("Run main.py for the selected exercise")
