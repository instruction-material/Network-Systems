"""Observe the lab without coding; analyze the evidence as an optional extension."""
import argparse
import json
import signal
import sys

import naming_lab


def analyze(evidence):
    return {
        "query": evidence["resolverQuery"],
        "resolvedFamilies": sorted({
            row["family"] for row in evidence["resolverAnswers"]
        }),
        "selectedEndpoint": evidence["ready"]["http"],
        "ipv6Probe": evidence["ipv6Probe"],
        "workerClosedItsSockets": evidence["workerResult"]["socketsClosed"],
        "dnsOnlyObservation": False,
    }


def interrupted(signum, _frame):
    raise SystemExit(128 + signum)


def main():
    signal.signal(signal.SIGTERM, interrupted)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--message", default="Owned addressing observation")
    parser.add_argument("--lookup", choices=("localhost", "127.0.0.1"), default="localhost")
    parser.add_argument("--network", default='2001:db8::/126')
    parser.add_argument("--candidates", default='2001:db8::,2001:db8::1,2001:db8::3,2001:db8::4,127.0.0.1')
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
