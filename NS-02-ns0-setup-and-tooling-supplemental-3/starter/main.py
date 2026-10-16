from pathlib import Path

from setup_lab import main

if __name__ == "__main__":
    raise SystemExit(main("arguments", Path(__file__).resolve().parent))
