#!/usr/bin/env bash
# shellcheck disable=SC2029
# Deploy orch-relay to the dev VPS (ssh alias "orch-dev", user "deploy").
# Run from the dev machine: infra/dev/deploy.sh
set -euo pipefail

HOST="${ORCH_DEPLOY_HOST:-orch-dev}"
BASE=/opt/orch
KEEP=5

cd "$(dirname "${BASH_SOURCE[0]}")/../.."

sha="$(git rev-parse --short HEAD)"
rm -rf dist
uv build --wheel
wheel="$(ls dist/orch_relay-*.whl)"
wheel_name="$(basename "$wheel")"
version="$(printf '%s' "$wheel_name" | cut -d- -f2)"
release="relay-${version}-${sha}"
rdir="${BASE}/releases/${release}"
echo "deploying ${release}"

ssh "$HOST" "mkdir -p '${rdir}' '${BASE}/relay'"
rsync -a "$wheel" "${HOST}:${rdir}/${wheel_name}"

# Build the venv (system python: nothing may point into /home, units use ProtectHome),
# switch the symlink atomically, prune old releases.
ssh "$HOST" bash -s -- "$rdir" "$wheel_name" "$BASE" "$KEEP" <<'REMOTE'
set -euo pipefail
rdir="$1"; wheel_name="$2"; base="$3"; keep="$4"
if [ ! -x "$rdir/venv/bin/orch-relay" ]; then
    rm -rf "$rdir/venv"
    uv venv --python /usr/bin/python3.14 "$rdir/venv"
    uv pip install --python "$rdir/venv/bin/python" "$rdir/$wheel_name"
fi
mkdir -p "$rdir/bin"
ln -sfn "$rdir/venv/bin/orch-relay" "$rdir/bin/orch-relay"
ln -sfn "$rdir" "$base/relay/.current.new"
mv -T "$base/relay/.current.new" "$base/relay/current"
cur="$(readlink "$base/relay/current")"
# shellcheck disable=SC2012
ls -1dt "$base"/releases/relay-* | tail -n +"$((keep + 1))" | while read -r old; do
    [ "$old" = "$cur" ] || rm -rf "$old"
done
REMOTE

for unit in orch-relay orch-relay-int; do
    ssh "$HOST" sudo orch-unit enable "$unit"
    ssh "$HOST" sudo orch-unit restart "$unit"
done

fail=0
for port in 8101 8102; do
    ok=0
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        if out="$(ssh "$HOST" curl -fsS "http://127.0.0.1:${port}/healthz" 2>/dev/null)"; then
            echo "${port}: ${out}"
            ok=1
            break
        fi
        sleep 1
    done
    [ "$ok" = 1 ] || { echo "health check failed on :${port}" >&2; fail=1; }
done
exit "$fail"
