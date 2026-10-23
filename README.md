# orch-relay

Hub accounts, hub channels and hub phone push for orch V3 (the relay serves hubs only; no per-workspace routes).
Contract: orch-hub `docs/protocol.md` §10.8; shared encodings in `tests/vectors_v2.json`.

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

## Push (D77)

The relay serves hubs only (V3-D36; D68, D69, D76, D77): hub accounts (`/v2/hubs`), the hub's push targets, push sends and
channel mailboxes (`/v2/hubs/{hub}/...`, signed by the hub's `HK_op`) and the phone's own channel mailbox read. There is
no per-workspace route. `GET /v2/relay-info` and `GET /healthz` are public. The hub push routes exist only when push is
configured; otherwise they answer 404 `not_found` (the channel purge excepted). Configuration is
`ORCH_RELAY_APNS_TEAM_ID`, `ORCH_RELAY_APNS_TOPIC`, `ORCH_RELAY_PUSH_TOKEN_KEY_FILE` (32 random bytes, mode 0600) and,
per environment, `ORCH_RELAY_APNS_{SANDBOX,PRODUCTION}_KEY_ID` and `..._KEY_FILE` (the `.p8`, mode 0600). All or nothing: a
partial set makes `serve` exit 2. Tokens are stored sealed; the key and the secret are never in the database. Delivery
is best effort over one HTTP/2 connection per environment (`httpx[http2]`). Tests use a throwaway P-256 key, a fake
transport and a local h2 server; no test reaches Apple (`tests/conftest.py`). Set `ORCH_RELAY_TRUSTED_PROXY` to a single
trusted proxy IP when behind Caddy; otherwise forwarded addresses are ignored (the last X-Forwarded-For hop, IPv6 by /64).
Run one worker per database (SQLite, WAL, `synchronous=FULL`; database work runs in the thread pool). The deploy steps are in
[dev-deploy-plan](docs/dev-deploy-plan.md).

## License

Licensed under the PolyForm Noncommercial License 1.0.0. Commercial use requires a separate license from the author. See [LICENSE](LICENSE).

## A phone reads its channel mailbox (E5, orch-core#864)

`GET /v2/hub-channels/{hub}/{ch}/mailbox` (list), `GET`/`DELETE` `.../mailbox/{id}`: signed by the channel key, with the
hub's `hub.channel_cert` in `Orch-Channel-Cert` (contract §10.8.4; checks in the contract's order, each `Orch-Channel-*`
header exactly once). The hub's signed `DELETE /v2/hubs/{hub}/mailbox/{ch}` (§10.8.1) also records the channel as revoked
for that hub, permanently (`hub_revoked_channels`), and the channel is refused with `403 channel_revoked` from then on
(only to the holder of the key: the check follows the signature). Reads are limited to 600 held nonces per channel in the
240 s window (`429 quota_exceeded`). Not yet in the signed bytes: the relay's own origin (L2B-10, awaiting the contract).
`uv run pytest tests/test_hub_channel*.py -x -q`.
