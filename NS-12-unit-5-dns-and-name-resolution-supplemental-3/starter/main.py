from pathlib import Path
from dns_probe import main

if __name__ == "__main__":
    raise SystemExit(main('negative-vs-transport', Path(__file__).with_name("case.json")))
