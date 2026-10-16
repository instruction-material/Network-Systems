"""Observe an isolated Linux kernel path; Python summaries are optional."""
import argparse
import json
import os
import signal
import sys

import link_routing_lab


def analyze(evidence):
    rows = {row["stage"]: row for row in evidence["lab"]["observations"]}
    bridge = rows["bridge-forwarding-off"]
    return {"bridgeWorksWithIPForwardingOff": bridge["state"]["forwarding"] == "0" and bridge["response"]["exitCode"] == 0,
            "bridgeRestoreSucceeded": rows["bridge-restored"]["response"]["exitCode"] == 0,
            "routerOffHasHTTP": rows["router-forwarding-off"]["response"]["body"] is not None,
            "routedPeer": rows["routed"]["response"]["body"]["peer"][0],
            "translatedPeer": rows["snat"]["response"]["body"]["peer"][0]}


def main():
    signal.signal(signal.SIGTERM, link_routing_lab.interrupted)
    signal.signal(signal.SIGINT, link_routing_lab.interrupted)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--alternate", action="store_true")
    parser.add_argument("--service-port", type=int, default=8080)
    parser.add_argument("--mapped-port", type=int, default=18080)
    parser.add_argument("--hold-ms", type=int, default=0, help=argparse.SUPPRESS)
    parser.add_argument("--fail-after-ready", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    evidence = {"launcherUID": os.geteuid()}
    status = 0
    try:
        link_routing_lab.observe('core', args.alternate, args.service_port, args.mapped_port,
                                 args.hold_ms, args.fail_after_ready, evidence)
        evidence["analysis"] = analyze(evidence)
    except link_routing_lab.LabInterrupted as error:
        evidence["interruptedStatus"] = 128 + error.number
        status = 128 + error.number
    except (ValueError, RuntimeError, OSError, TimeoutError) as error:
        evidence["error"] = str(error)
        print(str(error), file=sys.stderr)
        status = 2
    print(json.dumps(evidence, indent=2))
    return status


if __name__ == "__main__":
    raise SystemExit(main())
