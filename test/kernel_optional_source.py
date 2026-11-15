"""Inventory standalone optional kernel labs against the qualified apparatus."""
import ast
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CASES = json.loads((ROOT / "test/network_kernel_optional_cases.json").read_text())


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_checks(family, run, records, exported=False):
    definitions = CASES[family]
    assert len(definitions) == (4 if family == "routing" else 2)
    hashes = {}
    for definition in definitions:
        pack = ROOT / definition["pack"]
        assert definition["title"] in (pack / "README.md").read_text()
        names = ["README.md"]
        for role in ["starter", "solution"]:
            assert not (pack / role / "main.py").exists()
            role_files = definition["roleFiles"] + ([] if exported else ["README.md"])
            names += [role + "/" + name for name in role_files]
            assert digest(pack / role / definition["taskFile"]) == definition["choiceHashes"][role]
            for name, expected in CASES["qualifiedApparatus"][family].items():
                assert digest(pack / role / name) == expected
        for name in names:
            path = pack / name
            hashes[definition["pack"] + "/" + name] = digest(path)
            if path.suffix == ".py":
                ast.parse(path.read_text(), feature_version=(3, 10))
            elif path.suffix == ".sh":
                code, _, error = run(["bash", "-n", str(path)], records)
                assert code == 0, error
    return hashes
