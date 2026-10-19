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
`ORCH_RELAY_INSTANCE` (name reported by `/healthz`; default `public`; the int unit sets `int`).
Several instances can run side by side with different data dirs and ports.

Migrations run at `serve` startup (a bad migration shows up as a failed deploy health check, which rolls back). They are numbered `.sql` files in `src/orch_relay/migrations/`, tracked in `schema_migrations`.

## Deploy (dev VPS)

```sh
infra/dev/deploy.sh
```

Builds the wheel, installs it into `/opt/orch/releases/relay-<version>-<sha>/venv` over `ssh orch-dev`,
switches `/opt/orch/relay/current`, restarts `orch-relay` (:8101) and `orch-relay-int` (:8102)
and health-checks both. Safe to re-run; the last 5 releases are kept. Public hostnames are
`*.dev.severin.io` / `*.orch.severin.io`.

## G1 directory

Set `ORCH_RELAY_ORIGIN` to the public origin clients sign for (default
`http://localhost:8101`). It is independent of the request Host header. Set
`ORCH_RELAY_TRUSTED_PROXY` to a single trusted proxy IP when behind Caddy; otherwise
forwarded addresses are ignored. The server uses the last X-Forwarded-For hop from
that proxy, maps IPv4-mapped IPv6 to IPv4, and groups IPv6 clients by /64. Uvicorn
proxy rewriting is disabled so this check sees the actual peer.

```sh
uv run orch-relay invite create --ttl 7d
uv run pytest tests/test_auth.py -x -q
```

The admin command prints a new invite once; distribute that output privately.
Only its SHA-256 hash is stored. There is no public invite-management endpoint.
The invite, first certificate, and proof of device-key possession are committed
atomically by `POST /v2/accounts`.

Run one worker per database. SQLite uses WAL and `synchronous=FULL`; all database
work runs in the thread pool. Directory records, token hashes, invite-use digests,
and accepted recovery request digests survive restart. Challenges and rate windows
are process-local, per P3-D15. Clients obtain fresh challenges after a restart.
Directory JSON bodies are capped at 16 KiB (64 KiB for accounts and cards), checked
before parsing; oversized input returns 413. Devices may hold eight live tokens.

G1 implements §19.1. Membership publication, holder acquisition, bridge and pairing
routes remain the G2/G3 groups. Shared tables and integration rules are documented
in [directory integration](docs/directory-integration.md).

## Push (P3-D40)

`POST /v2/push/register`, `/v2/push/unregister` and the host's `POST /v2/workspaces/{ws}/push` (protocol §19.10, design
§14.3 and §14.7) exist only when push is configured; otherwise they answer 404 `not_found`. Configuration is
`ORCH_RELAY_APNS_TEAM_ID`, `ORCH_RELAY_APNS_TOPIC`, `ORCH_RELAY_PUSH_TOKEN_KEY_FILE` (32 random bytes, mode 0600) and,
per environment, `ORCH_RELAY_APNS_{SANDBOX,PRODUCTION}_KEY_ID` and `..._KEY_FILE` (the `.p8`, mode 0600). All or nothing: a
partial set makes `serve` exit 2. Tokens are stored sealed; the key and the secret are never in the database. Delivery
is best effort over one HTTP/2 connection per environment (`httpx[http2]`). Tests use a throwaway P-256 key, a fake
transport and a local h2 server; no test reaches Apple (`tests/conftest.py`). The deploy steps are in
[dev-deploy-plan](docs/dev-deploy-plan.md) (R8).

## License

Licensed under the PolyForm Noncommercial License 1.0.0. Commercial use requires a separate license from the author. See [LICENSE](LICENSE).
