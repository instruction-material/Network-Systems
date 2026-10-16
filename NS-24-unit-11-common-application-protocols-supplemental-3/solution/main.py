"""Collect actual local HTTP evidence; Python analysis is optional."""
import argparse
import base64
import json
import signal
import sys

import application_lab


def analyze(evidence):
    unavailable, missing, method, binary, authority = evidence["exchanges"]
    return {"statusClasses": [row["status"] // 100 for row in (unavailable, missing, method)],
            "retryAfterSeconds": int(unavailable["headers"]["retry-after"]),
            "binaryOctets": list(base64.b64decode(binary["bodyBase64"])),
            "hostHeaderChangedOnly": authority["requestHeaders"]["Host"] == "representation.invalid"
                and authority["peer"] == binary["peer"]
                and authority["headers"]["x-lab-token"] == evidence["ready"]["token"]}


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
        application_lab.observe('extension', args.message, args.changed, args.hold_ms, evidence)
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
