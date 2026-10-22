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

## Cut-over to a hub (E3, orch-core#896)

A workspace keeps its direct (per-workspace) relay path until it is cut over to a hub; nothing changes for it before
that. The switch is one row per workspace (`workspace_cutover`, migration 0024): `pending` (the workspace named a
registered hub; lapses after 24 h unconfirmed) then `cut_over`. Contract: orch-hub `docs/protocol.md` §10.8.3.

ONE gate, `cutover.guard`, driven by one policy table (`cutover.CLASS`/`NAMES`). After `cut_over` EVERY per-workspace
direct route answers 403 `cut_over` (`drain_until_ms`, `drained`): bridge and pairing POSTs, hooks, Drop, cert requests,
checkpoints, card, membership, push register and push send. The allow-list is the mailbox reads (bridge GET, pair GET,
host hold/poll) until the drain window ends (`ORCH_RELAY_CUTOVER_DRAIN_S`, default 7 days), push unregistration and the
cut-over routes. At the end of the drain the bridge mailbox, replay records, push registrations, hooks and cert
requests are purged and the Drop sweep releases the workspace's objects, usage and blob files. Note the bridge
mailbox itself lives 60 s, so in practice the drain holds little beyond push registrations and Drop data. An anonymous
pairing request is answered as for an unknown workspace. `tests/test_cutover_gate.py` lists every registered route and
fails for one that is neither gated nor on the allow-list.

The workspace's own session (WSK, with the holder fence, 409 `fenced`) does `PUT`/`GET`/`DELETE`
`/v2/workspaces/{ws}/cutover` (`PUT {v:2, hub_id, state:"pending"|"cut_over"}`; `pending` over `cut_over` is 403
`cut_over`; `DELETE` reverses and only the workspace can). The hub (§10.8 signed) does `PUT {v:2, state:"cut_over"}`/`GET`
`/v2/hubs/{hub}/workspaces/{ws}/cutover` and can only confirm `pending` -> `cut_over` for a workspace that named exactly
that hub (otherwise `other_hub`); a hub `DELETE` is always 403 `not_allowed`. `uv run pytest tests/test_cutover*.py -x -q`.

## Webhook doorbells (#81)

`POST /h/<id>` answers 204 with no body for every id and state, reads no body and stores only the first ring time of a
registered hook (`H(id)`, `hooks` table). The workspace host registers, revokes and fetches hooks with its W session
(`/v2/workspaces/{ws}/hooks[/revoke|/fetch]`; protocol §19.11). `uv run pytest tests/test_hooks.py -x -q`; the
known/unknown timing test is `slow`.

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
