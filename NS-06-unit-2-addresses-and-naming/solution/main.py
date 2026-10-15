"""Observe the lab without coding; analyze the evidence as an optional extension."""
import argparse
import json
import signal
import sys

import naming_lab


def analyze(evidence):
    endpoint = evidence["ready"]["http"]
    return {
        "resolvedIpv4": sorted({
            row["address"] for row in evidence["resolverAnswers"]
            if row["family"] == 2
        }),
        "endpoint": {"address": endpoint["address"], "port": endpoint["port"],
                     "transport": "TCP"},
        "httpMatches": evidence["httpResponse"] == {
            "message": evidence["message"], "path": "/lab",
        },
        "network": naming_lab.network_rows(
            evidence["networkInput"], evidence["candidateInput"],
        ),
    }


def interrupted(signum, _frame):
    raise SystemExit(128 + signum)


def main():
    signal.signal(signal.SIGTERM, interrupted)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--message", default="Owned addressing observation")
    parser.add_argument("--lookup", choices=("localhost", "127.0.0.1"), default="localhost")
    parser.add_argument("--network", default='192.0.2.64/26')
    parser.add_argument("--candidates", default='192.0.2.63,192.0.2.64,192.0.2.65,192.0.2.126,192.0.2.127,192.0.2.128')
    args = parser.parse_args()
    try:
        evidence = naming_lab.addressing(args.message, args.network, args.candidates, args.lookup)
        evidence["analysis"] = analyze(evidence)
        print(json.dumps(evidence, ensure_ascii=True, indent=2))
    except (OSError, ValueError, TimeoutError) as error:
        print(str(error), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
