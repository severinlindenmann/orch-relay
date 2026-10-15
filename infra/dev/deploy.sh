#!/usr/bin/env bash
# shellcheck disable=SC2029
# Deploy orch-relay to the dev VPS (ssh alias "orch-dev", user "deploy").
# Run from the dev machine: infra/dev/deploy.sh
# Refuses a dirty git tree unless ORCH_DEPLOY_ALLOW_DIRTY=1 (release is then named ...-dirty-<hash>).
# Migrations run at `orch-relay serve` startup; a bad one fails the health check and rolls back.
set -euo pipefail

HOST="${ORCH_DEPLOY_HOST:-orch-dev}"
BASE=/opt/orch
KEEP=5

cd "$(dirname "${BASH_SOURCE[0]}")/../.."

sha="$(git rev-parse --short HEAD)"
dirty=""
if [ -n "$(git status --porcelain --untracked-files=all)" ]; then
    if [ "${ORCH_DEPLOY_ALLOW_DIRTY:-}" != 1 ]; then
        echo "working tree is dirty; commit or set ORCH_DEPLOY_ALLOW_DIRTY=1" >&2
        exit 1
    fi
    dirty=1
fi

rm -rf dist
uv build --wheel
wheel="$(ls dist/orch_relay-*.whl)"
wheel_name="$(basename "$wheel")"
version="$(printf '%s' "$wheel_name" | cut -d- -f2)"
wheel_sha="$(shasum -a 256 "$wheel" | cut -d' ' -f1)"
if [ -n "$dirty" ]; then
    release="relay-${version}-dirty-${wheel_sha:0:8}"
else
    release="relay-${version}-${sha}"
fi
rdir="${BASE}/releases/${release}"
echo "deploying ${release}"

ssh "$HOST" "mkdir -p '${rdir}' '${BASE}/relay'"
rsync -a "$wheel" "${HOST}:${rdir}/${wheel_name}"

# Everything below runs on the VPS under a deploy lock.
ssh "$HOST" bash -s -- "$rdir" "$wheel_name" "$wheel_sha" "$version" "$BASE" "$KEEP" <<'REMOTE'
set -euo pipefail
rdir="$1"; wheel_name="$2"; wheel_sha="$3"; version="$4"; base="$5"; keep="$6"
units="orch-relay orch-relay-int"
ports="8101 8102"

exec 9>"$base/.deploy.lock"
flock -n 9 || { echo "another deploy is running" >&2; exit 1; }

# The venv is built in place (venvs are not relocatable); the stamp is written last, so an
# interrupted install is never mistaken for a finished one, and a changed wheel is reinstalled.
if [ "$(cat "$rdir/.wheel.sha256" 2>/dev/null || true)" != "$wheel_sha" ] \
        || [ ! -x "$rdir/venv/bin/orch-relay" ]; then
    py="$(command -v python3.14 || command -v python3)"
    rm -rf "$rdir/venv" "$rdir/.wheel.sha256"
    uv venv --python "$py" "$rdir/venv"
    uv pip install --python "$rdir/venv/bin/python" "$rdir/$wheel_name"
    printf '%s' "$wheel_sha" > "$rdir/.wheel.sha256"
fi
mkdir -p "$rdir/bin"
ln -sfn "$rdir/venv/bin/orch-relay" "$rdir/bin/orch-relay"
touch "$rdir"

switch() {
    ln -sfn "$1" "$base/relay/.current.new"
    mv -T "$base/relay/.current.new" "$base/relay/current"
}
restart_all() {
    local rc=0 u
    for u in $units; do
        sudo orch-unit enable "$u" || rc=1
        sudo orch-unit restart "$u" || rc=1
    done
    return "$rc"
}
check_all() {
    local rc=0 p out i ok
    for p in $ports; do
        ok=0
        for i in 1 2 3 4 5 6 7 8 9 10; do
            if out="$(curl -fsS "http://127.0.0.1:${p}/healthz" 2>/dev/null)" \
                    && printf '%s' "$out" | grep -q "\"version\":\"${version}\""; then
                echo "${p}: ${out}"
                ok=1
                break
            fi
            sleep 1
        done
        [ "$ok" = 1 ] || { echo "health check failed on :${p} (want version ${version})" >&2; rc=1; }
    done
    return "$rc"
}

prev="$(readlink "$base/relay/current" || true)"
switch "$rdir"
if restart_all && check_all; then
    :
else
    echo "deploy failed" >&2
    for u in $units; do sudo orch-unit logs "$u" 50 || true; done
    if [ -n "$prev" ] && [ "$prev" != "$rdir" ]; then
        echo "rolling back to $prev" >&2
        switch "$prev"
        restart_all || true
    fi
    exit 1
fi

# shellcheck disable=SC2012
ls -1dt "$base"/releases/relay-* | tail -n +"$((keep + 1))" | while read -r old; do
    [ "$old" = "$rdir" ] || [ "$old" = "$prev" ] || rm -rf "$old"
done
REMOTE
