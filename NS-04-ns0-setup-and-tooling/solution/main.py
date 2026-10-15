"""Run the owned experiment, then interpret its recorded evidence."""
import argparse
import json
import signal
import sys

from network_lab import setup


def analyze(evidence):
    ready = evidence["ready"]
    target = f"127.0.0.1:{ready['http']['port']}"
    pid = f"pid={ready['pid']},"
    return {
        "linux": evidence["environment"]["platform"] == "linux",
        "availableTools": sorted(evidence["environment"]["tools"]),
        "routeInterface": evidence["route"][0]["dev"],
        "ownedListenerObserved": any(
            target in line.split() and pid in line
            for line in evidence["listenersDuring"].splitlines()
        ),
        "responseMatches": evidence["httpResponse"] == {
            "message": evidence["message"], "path": "/lab"
        },
        "scope": "same Linux network namespace",
    }


def interrupted(signum, _frame):
    raise SystemExit(128 + signum)


def main():
    signal.signal(signal.SIGTERM, interrupted)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--message", default="First local observation")
    args = parser.parse_args()
    try:
        evidence = setup(args.message)
        evidence["analysis"] = analyze(evidence)
        print(json.dumps(evidence, ensure_ascii=True, indent=2))
    except (OSError, ValueError, TimeoutError) as error:
        print(str(error), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
