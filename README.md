# orch-relay

Directory, relay, drop and push service for orch v2. Wire protocol: `docs/protocol-v2.md`
(reference implementation in `ref/`, vectors in `tests/vectors_v2.json`).

## Develop

```sh
uv sync
uv run pytest -q -m "not slow"     # tests
uv run pytest tests/test_health.py -x -q   # targeted
uv run ruff check                  # lint
shellcheck infra/dev/deploy.sh
```

## Run locally

```sh
export ORCH_RELAY_DATA=./data      # DB: $ORCH_RELAY_DATA/relay.sqlite3 (SQLite, WAL)
uv run orch-relay migrate          # apply pending migrations (serve also does this at startup)
uv run orch-relay serve --host 127.0.0.1 --port 8101
curl http://127.0.0.1:8101/healthz # {"ok":true,"version":"...","instance":"public"}
```

Environment: `ORCH_RELAY_DATA` (data dir), `ORCH_RELAY_PORT` (default port),
`ORCH_RELAY_INSTANCE` (name reported by `/healthz`; default `public`, `int` on port 8102).
Several instances can run side by side with different data dirs and ports.

Migrations are numbered `.sql` files in `src/orch_relay/migrations/`, tracked in `schema_migrations`.

## Deploy (dev VPS)

```sh
infra/dev/deploy.sh
```

Builds the wheel, installs it into `/opt/orch/releases/relay-<version>-<sha>/venv` over `ssh orch-dev`,
switches `/opt/orch/relay/current`, restarts `orch-relay` (:8101) and `orch-relay-int` (:8102)
and health-checks both. Safe to re-run; the last 5 releases are kept. Public hostnames are
`*.dev.severin.io` / `*.orch.severin.io`.
