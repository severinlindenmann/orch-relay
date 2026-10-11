"""MANIFEST.json must match the HTTP fixture directory exactly (stale-manifest guard)."""

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/http_fixtures"
sys.path.insert(0, str(FIXTURES))
import manifest as M

MANIFEST = json.loads((FIXTURES / "MANIFEST.json").read_text())


def test_manifest_shape():
    assert set(MANIFEST) == {"revision", "files", "aggregate"}
    assert isinstance(MANIFEST["revision"], int) and MANIFEST["revision"] >= 1
    assert "MANIFEST.json" not in MANIFEST["files"]


def test_manifest_is_not_stale():
    actual = {
        p.name: hashlib.sha256(p.read_bytes()).hexdigest()
        for p in FIXTURES.iterdir()
        if p.is_file() and p.name != "MANIFEST.json"
    }
    files = MANIFEST["files"]
    hint = "run `uv run python tests/http_fixtures/manifest.py --write` and bump revision"
    assert sorted(set(actual) - set(files)) == [], f"added: {hint}"
    assert sorted(set(files) - set(actual)) == [], f"removed: {hint}"
    assert [n for n in actual if actual[n] != files[n]] == [], f"changed: {hint}"


def test_manifest_aggregate():
    lines = "".join(f"{n}\t{h}\n" for n, h in sorted(MANIFEST["files"].items()))
    assert MANIFEST["aggregate"] == hashlib.sha256(lines.encode()).hexdigest()
    assert M.aggregate(MANIFEST["files"]) == MANIFEST["aggregate"]


def test_manifest_file_is_canonical():
    assert (FIXTURES / "MANIFEST.json").read_text() == M.render(MANIFEST)
