"""Generate or verify MANIFEST.json for the HTTP fixture corpus.

uv run python tests/http_fixtures/manifest.py --write
uv run python tests/http_fixtures/manifest.py --check
"""

import hashlib
import json
import sys
from pathlib import Path

DIR = Path(__file__).resolve().parent
MANIFEST = DIR / "MANIFEST.json"


def file_hashes() -> dict[str, str]:
    return {
        p.name: hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(DIR.iterdir())
        if p.is_file() and p.name != MANIFEST.name
    }


def aggregate(files: dict[str, str]) -> str:
    lines = "".join(f"{n}\t{files[n]}\n" for n in sorted(files))
    return hashlib.sha256(lines.encode()).hexdigest()


def build(revision: int) -> dict:
    files = file_hashes()
    return {"revision": revision, "files": files, "aggregate": aggregate(files)}


def render(manifest: dict) -> str:
    return json.dumps(manifest, sort_keys=True, indent=2) + "\n"


def main(argv: list[str]) -> int:
    if len(argv) != 1 or argv[0] not in ("--write", "--check"):
        print(__doc__)
        return 2
    current = json.loads(MANIFEST.read_text()) if MANIFEST.exists() else None
    if argv[0] == "--write":
        MANIFEST.write_text(render(build(current["revision"] if current else 1)))
        print(f"wrote {MANIFEST}")
        return 0
    if current is None:
        print("MANIFEST.json missing")
        return 1
    if render(build(current["revision"])) != MANIFEST.read_text():
        print("MANIFEST.json is stale: bump `revision` and run --write")
        return 1
    print("manifest ok")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
