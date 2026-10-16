from pathlib import Path

from capstone_lab import main

if __name__ == "__main__":
    raise SystemExit(main(Path(__file__).with_name("case.json")))
