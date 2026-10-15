"""Run the owned experiment, then interpret its recorded evidence."""
import argparse
import json
import signal
import sys

from network_lab import transport


def analyze(evidence):
    # TODO: derive each documented analysis field from the actual evidence.
    return None


def interrupted(signum, _frame):
    raise SystemExit(128 + signum)


def main():
    signal.signal(signal.SIGTERM, interrupted)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--message", default="First transport observation")
    parser.add_argument("--udp-buffer", type=int, default=256)
    parser.add_argument("--without-newline", action="store_true")
    args = parser.parse_args()
    try:
        evidence = transport(args.message, args.udp_buffer, not args.without_newline)
        evidence["analysis"] = analyze(evidence)
        print(json.dumps(evidence, ensure_ascii=True, indent=2))
    except (OSError, ValueError, TimeoutError) as error:
        print(str(error), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
