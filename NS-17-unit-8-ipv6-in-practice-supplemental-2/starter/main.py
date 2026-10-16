"""Collect the actual IPv6 lab without requiring Python implementation."""
import argparse
import json
import signal
import sys

import ipv6_lab


def analyze(evidence):
    """Optional Python extension; complete the networking notebook independently."""
    return


def interrupted(signum, _frame):
    raise SystemExit(128 + signum)


def main():
    signal.signal(signal.SIGTERM, interrupted)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binding", choices=("v6-only", "paired"), default='v6-only')
    parser.add_argument("--message", default="Owned IPv6 observation")
    parser.add_argument("--prefix", default='2001:db8::/126')
    parser.add_argument("--candidates", default='2001:db8::,2001:db8::1,2001:db8::3,2001:db8::4')
    args = parser.parse_args()
    evidence = {}
    try:
        ipv6_lab.observe(args.message, args.binding, args.prefix, args.candidates, evidence)
        evidence["analysis"] = analyze(evidence)
    except (OSError, ValueError, TimeoutError) as error:
        print(json.dumps({"error": str(error), "evidence": evidence}, ensure_ascii=True, indent=2))
        print(str(error), file=sys.stderr)
        return 2
    print(json.dumps(evidence, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
