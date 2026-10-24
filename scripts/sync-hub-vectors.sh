#!/usr/bin/env bash
# Refresh the vendored hub contract vectors tests/vectors/hub/vectors_hub.json from an orch-hub ref (V3-D8), byte for byte,
# and write tests/vectors/hub/SOURCE (hub_repo, hub_commit, vectors_hub_sha256). Land it as a PR that changes nothing else;
# tests/test_hub_vectors_source.py checks SOURCE against the file.
# Usage: scripts/sync-hub-vectors.sh [ref] (default origin/develop); ORCH_HUB_DIR overrides the clone path.
set -euo pipefail
ref="${1:-origin/develop}"
hub="${ORCH_HUB_DIR:-$HOME/orch-dev/orch-hub}"
dest="$(cd "$(dirname "${BASH_SOURCE[0]}")/../tests/vectors/hub" && pwd)"
git -C "$hub" fetch -q
sha="$(git -C "$hub" rev-parse "$ref^{commit}")"
tmp="$(mktemp "$dest/.sync.XXXXXX")"
trap 'rm -f "$tmp"' EXIT
git -C "$hub" show "$sha:vectors/vectors_hub.json" > "$tmp"
digest="$(python3 -c 'import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$tmp")"
mv "$tmp" "$dest/vectors_hub.json"
printf 'hub_repo: orch-hub\nhub_commit: %s\nvectors_hub_sha256: %s\n' "$sha" "$digest" > "$dest/SOURCE"
echo "synced tests/vectors/hub from orch-hub $sha"
