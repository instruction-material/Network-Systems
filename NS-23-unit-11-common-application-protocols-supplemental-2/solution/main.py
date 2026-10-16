"""Collect actual local HTTP evidence; Python analysis is optional."""
import argparse
import base64
import hashlib
import json
import signal
import sys

import application_lab


def analyze(evidence):
    first, conditional, stale, _head, redirect, followed = evidence["exchanges"]
    retained = base64.b64decode(first["bodyBase64"])
    return {"validator": first["headers"]["etag"],
            "validatingStatus": conditional["status"],
            "conditionalTransferredBytes": len(base64.b64decode(conditional["bodyBase64"])),
            "retainedRepresentationSha256": hashlib.sha256(retained).hexdigest(),
            "staleValidatorStatus": stale["status"],
            "redirectStatus": redirect["status"], "redirectTarget": redirect["headers"]["location"],
            "finalBodyMatchesFirst": followed["bodyBase64"] == first["bodyBase64"]}


def interrupted(signum, _frame):
    raise SystemExit(128 + signum)


def main():
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--message", default="Owned application observation")
    parser.add_argument("--changed", action="store_true")
    parser.add_argument("--hold-ms", type=int, default=0)
    args = parser.parse_args()
    evidence = {}
    status = 0
    try:
        application_lab.observe('transfer', args.message, args.changed, args.hold_ms, evidence)
        evidence["analysis"] = analyze(evidence)
    except SystemExit as error:
        status = int(error.code)
        evidence["interruptedStatus"] = status
    except (OSError, ValueError, TimeoutError) as error:
        status = 2
        evidence["error"] = str(error)
        print(str(error), file=sys.stderr)
    print(json.dumps(evidence, ensure_ascii=True, indent=2))
    return status


if __name__ == "__main__":
    raise SystemExit(main())
