from pathlib import Path

from setup_lab import main

if __name__ == "__main__":
    raise SystemExit(main("context", Path(__file__).resolve().parent))
