"""The vendored hub vectors must be the hub's file byte for byte (scripts/sync-hub-vectors.sh writes SOURCE)."""

import hashlib
import pathlib

D = pathlib.Path(__file__).parent / "vectors" / "hub"


def test_source_checksum_matches_vendored_file():
    src = dict(line.split(": ", 1) for line in (D / "SOURCE").read_text().splitlines() if line)
    assert src["hub_repo"] == "orch-hub"
    assert len(src["hub_commit"]) == 40
    assert (
        hashlib.sha256((D / "vectors_hub.json").read_bytes()).hexdigest()
        == src["vectors_hub_sha256"]
    )
