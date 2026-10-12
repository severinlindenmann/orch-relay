PLAN ONLY: nothing here may be executed without explicit approval from the coordinator (orch-d6)

# Dev relay deployment plan: orch-relay `develop` to relay.dev.severin.io

Written 2026-10-12 19:38 CEST against orch-relay `develop` at `601cd91` (PR #59 merged). It covers the
public instance `orch-relay.service` (127.0.0.1:8101, https://relay.dev.severin.io) and the internal instance
`orch-relay-int.service` (127.0.0.1:8102, https://relay-internal.dev.severin.io). Scope: orch-mobile can test
against the real relay in phase 2. This document is a plan. Nothing in it has been run, applied or verified on the
VPS. Every step that changes the VPS needs explicit approval from orch-d6 first.

Conventions:

- `ROOT$` means a root shell on the VPS (the owner, or whoever orch-d6 names). `deploy$` means the `deploy` user,
  whose sudo is limited to `/usr/local/sbin/orch-unit`. `laptop$` means the dev machine (`~/orch-dev`).
- **UNKNOWN: to verify read-only on the VPS** marks a fact that the local sources could not establish. Each one is
  listed again in §9.
- `TS` is one timestamp for the whole run, set on the VPS from `date` (for example `TS=$(date +%Y%m%d-%H%M%S)`).

Facts already established by read-only inspection of the VPS (12 Oct; not re-verified here):

- 1961 MB RAM, no swap, 2 vCPU, 38 GB disk (3.1 GB used), up 4 days.
- Both relay instances run the OLD skeleton: `/healthz` only, instance `public` and `int`, about 64 MB RSS each.
- Caddy is the stock 2.11.7 build (no rate-limit plugin). Neither relay unit has a memory limit or proxy
  environment. `ulimit -n` is 1024.
- The databases live under `/srv/orch-relay/data`. Releases are under `/opt/orch/relay/current`, a symlink to a
  release dir; deploys go through `bin/relay-deploy`.

Sources: `docs/p3-relay-design.md` §10 (gates, ever-device recovery design, pre-public checklist 1–8),
`docs/protocol-v2.md` §19, `docs/p3-checkpoint-capacity.md`, `src/orch_relay/` (`app.py`, `cli.py`, `db.py`,
`directory.py`, `checkpoints.py`, `migrations/`), `infra/dev/deploy.sh`, `~/orch-dev/bin/relay-deploy`,
`~/orch-dev/vps/provision.sh`, the dev-kit draft PR #27 (branch `feat/relay-limits`, worktree
`~/orch-dev/.worktrees/dk-limits`, head `48bf7b5`), the P3-D36 branch `feat/p3-limits-reserve` (worktree
`~/orch-dev/.worktrees/relay-limits`, head `3e345cf`, local and not pushed), `~/orch-dev/e2e/`,
`~/orch-dev/orch-mobile/docs/{gaps,plug-in,host-api-v0}.md`, `OrchKit/Tests/OrchTestVectors/PROVENANCE.md`,
and `~/orch-dev/state/p3-relay-plan.md`.

---

## 1. Goal, and what "ready for mobile testing" means

**Goal.** Replace the skeleton on both dev instances with orch-relay `develop` (G0 to G4, P3-D30 to P3-D35,
plus P3-D36 if it has merged by then), on fresh databases, with memory limits and the proxy settings in place. A
real phone (TestFlight build) and a real host can then run the phase-2 flows against `https://relay.dev.severin.io`.

**Ready for mobile testing** means all of the following hold:

1. **The new build is live on both instances.** Do not rely on `/healthz` alone. It returns
   `{"ok": true, "version": "0.1.0", "instance": "public"|"int"}` (`src/orch_relay/app.py`), and `version` is the
   wheel version `0.1.0`. That version does not change between commits and may equal the skeleton's (**ANSWERED (12 Oct 2026, read-only ssh/local): U3: both instances answer `{"ok":true,"version":"0.1.0","instance":"public"|"int"}`, so `version` is identical to the new build and proves nothing**). The build counts as confirmed only when all three
   of these hold:
   - `readlink /opt/orch/relay/current` names `/opt/orch/releases/relay-0.1.0-<sha>`, where `<sha>` is the
     deployed commit (`infra/dev/deploy.sh` names releases `relay-${version}-${short sha}`).
   - `schema_migrations` on each database lists `0001_init` … `0015_account_caps` (and
     `0016_account_workspace_override` if P3-D36 is included). No `0008` exists; it is reserved.
   - `POST /v2/session/challenge` with body `{}` answers 200 `{challenge, expires_ms}`. The skeleton has no `/v2`
     routes and would answer 404.

   Follow-up (code, not in this plan): put the git sha in `/healthz` so that one request can tell builds apart.
2. **The routes the phone exercises answer per protocol-v2 §19.** These are the device-side routes in the mobile
   vendored fixture set (`OrchKit/Tests/OrchTestVectors/http_fixtures/`):
   - §19.1 sessions and directory: `POST /v2/session/challenge`, `POST /v2/session/login`, `POST /v2/session/logout`,
     `POST /v2/accounts`, `PUT|GET /v2/devices/{d}`, `POST /v2/revocations`, `GET /v2/devices/{d}/revocation`,
     `GET /v2/persons/{p}/revocations`, `GET /v2/workspaces/{ws}/card`.
   - §19.2 members and epochs: `GET /v2/workspaces/{ws}/members`, `GET .../grants`, `GET .../card-key`.
   - §19.3 pairing and bridge: `POST|GET /v2/workspaces/{ws}/pair/{offer}/{rid}` (device role),
     `POST|GET /v2/workspaces/{ws}/bridge/{rid}` (device role), and the `cert_pending` queues
     (`/v2/persons/{p}/cert-requests`, `/v2/cert-requests/{id}`, `.../challenge`, `.../rejection`) for a primary
     device.
   - §19.8 device reads (`GET .../checkpoint`, `GET .../transitions`, `GET .../proof`), only if the phase-2 phone
     runs the checkpoint sync walk. **ANSWERED (12 Oct 2026, read-only ssh/local): U12: the phone code has no real relay transport at all in this build (no `URLSession`; `PairingScreen` says "The relay isn't connected in this build") and no checkpoint walk outside the fake host, so §19.8 device reads are not exercised by the TestFlight build.** The mobile vendored set has
     no checkpoint fixtures.
   - The host routes (`host/hold`, `host/poll`, `membership`, `card` PUT, `card-keys`, `genesis`, `staging/*`,
     `checkpoint` PUT, `baselines`, `unpublished*`) are exercised by the host (orch-core), not by the phone. Mobile
     testing still needs a real host that uses them (see §8, R7).
   - **Not testable on this deploy:** push registration and deregistration. There is no wire route (orch-mobile
     `docs/gaps.md` row 16; `FakeRelay` answers 404), and the relay has no APNs or Web Push code (no `APNS`/`VAPID`
     reads in `src/orch_relay`). The `apple-app-site-association` route is not served either (orch-relay issues
     #11/#24; gaps row 6).
3. **The fixtures are pinned to the deployed commit.** The relay's `tests/http_fixtures/MANIFEST.json` at
   `601cd91` is **revision 11**, aggregate `8da79c77340347fec895513980113df5f7671990b769880d50c378d47b80c6ec`.
   P3-D36 (`3e345cf`) does not touch `tests/http_fixtures/`, so the revision stays 11 if it merges unchanged
   (re-check after the merge).
   orch-mobile currently vendors the fixtures from relay commit `386a6cb` (`PROVENANCE.md`). That copy predates
   `MANIFEST.json` and differs in at least `accounts`, `bridge_host_post`, `cert_*`, `host_poll`, `members`,
   `membership`, `pair_*` and `revocation_get`. Before testing starts, orch-mobile must re-vendor `vectors_v2.json`
   and `http_fixtures/` from the **deployed** commit, record it in `PROVENANCE.md`, and verify the manifest
   (`uv run python tests/http_fixtures/manifest.py --check` on the relay side; the mobile CI equivalent per
   protocol-v2 §19.6).
4. **The e2e and smoke checks pass** (details in §5 step F):
   - `laptop$ ORCH_RELAY_URL=https://relay.dev.severin.io e2e/run.sh hello` from `~/orch-dev` checks both instances
     over HTTPS.
   - The stateless fixture smoke subset (§5 F3) passes against both instances.
   - A manual end-to-end flow passes: invite → account → device → host pairs the phone → bridge request answered.
   - The remote e2e scenarios that design §10 names (`directory-basic`, `rotate-epoch`, `bridge-device`,
     `pair-device`, `revoke-device`, `checkpoint-rollback`, `restore-walk`) **do not exist**.
     `~/orch-dev/e2e/scenarios/` holds only `hello` and stubs (`pair-phone` exits "not implemented until P3").
     `tests/e2e/test_vertical_slice.py` runs in process (`TestClient`, seeded state, fixed clock) and cannot target
     a URL. A remote harness is G5 work. Until it exists, "e2e" on the deployed relay means `hello`, the smoke
     subset and the manual flow.
5. **The soak passes:** 24 h with no OOM kill, no unit restart, no proxy warning in the journal, and
   `MemoryPeak` well under `MemoryMax` (§5 step G).

---

## 2. Preconditions

The dev relay is invite-only: accounts need a CLI-made invite (P3-D3). The pre-public gates in design §10 are
therefore "acceptable on the invite-only dev relay". But this VPS has **1961 MB and no swap**, and the routes are
reachable from the internet. So the memory and abuse items still matter here, because the failure mode is the
kernel OOM killer picking `sshd`, Caddy or the other relay instance.

| # | Item | Required before the dev deploy? | Owner | Status (12 Oct) |
|---|---|---|---|---|
| P1 | **ORCH_RELAY_ORIGIN** per instance (`https://relay.dev.severin.io`, `https://relay-internal.dev.severin.io`). New finding: the default is `http://localhost:8101` (`directory.py` `install`), and login signatures bind the origin (`P.auth_bytes(self.origin, …)`, protocol §19.4 "origin is the instance's configured origin"), so without it **every login fails** | **Yes** | stream D (values) / owner (applies) | Not in `provision.sh` or dev-kit PR #27; added by §4.3 of this plan |
| P2 | **Proxy env** `ORCH_RELAY_BEHIND_PROXY=1`, `ORCH_RELAY_TRUSTED_PROXY=127.0.0.1` (checklist 7, P3-D35 N4). Without it every client has Caddy's address, so all anonymous pairing shares 4 concurrent polls and one set of address windows relay-wide. Phone pairing tests would hit 429 | **Yes** | dev kit (PR #27) | In PR #27 (unit `Environment=`); not applied |
| P3 | **Unit memory limits** `MemoryMax=900M` (public) / `450M` (int), `TasksMax=256`, `LimitNOFILE=4096`, no `MemoryHigh` (PR #27 round 2). Without them an overrun kills a random process | **Yes** | dev kit (PR #27) | Draft; Opus review "safe to apply after fixes", fixes in `48bf7b5`; Opus delta of `48bf7b5` running (automated flag: possible ordering cycle in `orch-limits.service`, `Before=network-pre.target` without `DefaultDependencies=no`) |
| P4 | **Hard maximum publication size** (new relay item: refuse a publication above a configured heads limit). With `PUBLISH_WIDTH=1`, `Gate.fits()` admits any single publication when nothing else runs (`checkpoints.py` `Gate.fits`: `self.active == 0 or …`), so the heads cap does not bound a full 64 MiB set: ~1.2 GB phase A plus ~250 MB baseline per instance, above both `MemoryMax` values | **Yes: the code item, or the interim env cap in §4.3** (`ORCH_RELAY_GLOBAL_STAGE_BYTES`, which bounds every staged set and so every publication's new heads) | stream D (relay code) | Not started (tracked by orch-d6 after P3-D36); interim cap is env-only and needs no code |
| P5 | **nftables per-IP limits** on 443 (checklist 7; PR #27: table `inet orch_limits`, 100 concurrent / 60 new per s, burst 120, IPv6 per /64; Caddy `request_body max_size 8MB`). This is the only bound on unauthenticated 401 floods and on the P3-D32 residuals (exact certificate receipt replays, unused-invite account requests) | **Yes**, after `nft -c` passes on a throwaway Ubuntu 26.04 VM (the real VPS OS) and the Opus delta of `48bf7b5` passes. Fallback only if orch-d6 accepts it in writing: deploy with the Caddy body cap and memory limits and no nft table, as a known DoS exposure of a dev box | dev kit (PR #27); owner applies | Draft; `nft -c` **not yet run** |
| P6 | **Disk fits the storage caps** (checklist 2). The defaults allow 32 × 1.17 GB ≈ 37.5 GB per account, about the whole 38 GB disk | **Yes** (env only, §4.3) | stream D | Values proposed in §4.3 |
| P7 | **P3-D36 limits PR**: staging refill 600/min weighted by body size (checklist 8), node-quota restore reserve (checklist 3), audited per-account workspace-cap override (checklist 4, migration 0016, CLI `orch-relay account-cap`) | **No.** Preferred if merged by deploy time (one deploy, one wipe), but migration 0016 is additive and can follow later without a wipe. If deploying **without** it, set `ORCH_RELAY_THROTTLE_STAGING=27777/600` (checklist 8's interim). If deploying **with** it, do **not** set that variable: P3-D36 changes the staging burst and weights tokens by size, and the old override would undo that | stream D | Implemented locally (6 commits, `3e345cf`), not pushed, no PR; Opus review pending |
| P8 | **Ever-device way out** (checklist 5: offline compaction, audited override; orch-d6 ruling 12 Oct) | No. Invite-only testers; a workspace at 4,096 ever-devices is unreachable in dev; migration (d) is the exit | stream D | Ruled, not implemented |
| P9 | **PoP / device self-signature** on certificates and evidence (orch-52, F1 format change) | No. It hardens against squatting by registered users; invite-only dev | orch-52 | Scheduled with G1 as a P3 F1 item |
| P10 | **429 detail for permanent quotas** (checklist 6, `quota: "nodes"` and so on) | No. Dev caps are far above test use; a host retry loop on a permanent cap is bounded by the refused-heads budget | orch-52 to rule | Open |
| P11 | **Host-side items**: per-person device cap; no unchanged retry after membership 429 `quota_exceeded` (orch-core) | No (pre-public list per orch-52) | orch-52 | Scheduled pre-public |
| P12 | Pre-public gates G1, G3, G4 and blocker 4 (P3-D32 to P3-D35) | Already in `develop` | stream D | Merged (#56–#59) |
| P13 | **Mobile fixture re-pin** to the deployed commit (§1.3) | **Yes**, for the testing to mean anything, not for the deploy itself | orch-f1 / orch-mobile | Mobile on `386a6cb` (pre-MANIFEST) |
| P14 | **Database audit queries** from the P3-D30 implementer report ("4 SQL to run before any deploy") | No, if the databases are wiped (§3). Yes, if orch-d6 chooses to keep them | stream D | Moot under the wipe recommendation |
| P15 | **Coordinator approval** of this plan and of each step in §5 | **Yes** | orch-d6 | Pending |

Notes on the table:

- P1 and P2 are mechanical but load-bearing. P1 is missing from every artifact so far. P2 is in PR #27 only.
- `ORCH_RELAY_PUBLISH_WIDTH=1` and `ORCH_RELAY_PUBLISH_HEADS=300000` from PR #27 stay as defence in depth. They do
  not replace P4 (see the PR #27 README, "Honest peak").

---

## 3. Data and migrations

### 3.1 How the runner behaves (`src/orch_relay/db.py` `migrate`)

- **Discovery and order.** Every `*.sql` in the package's `migrations/` is applied in lexicographic order of the
  file stem (`0001_init` … `0015_account_caps`, plus `0016_account_workspace_override` with P3-D36). Gaps are
  allowed: `0008` is reserved for the pairing binding and absent. Caveat: if a `0008_*` is added later, a database
  that already has `0009`–`0015` applies it **after** them, while a fresh database applies it in sequence. The
  author must make it order-independent, or the fresh and upgraded schemas can differ.
- **Atomic per file.** Each file runs in its own `BEGIN IMMEDIATE` … `COMMIT`. The statements are split with
  `sqlite3.complete_statement`, never `executescript`, so there is no implicit COMMIT. The `schema_migrations` row is
  inserted in the same transaction. Files must not contain `BEGIN`/`COMMIT`.
- **Idempotent.** The applied set (`schema_migrations.version`) is re-read inside each transaction, so a second
  runner or a restart skips applied files (`tests/test_migrations.py`: `test_migrate_is_idempotent`,
  `test_concurrent_migrate_same_fresh_db`).
- **On failure.** The failing file is rolled back (`test_failed_migration_rolls_back`) and the exception propagates.
  Files before it stay committed. At `serve` startup the migration runs in the FastAPI lifespan
  (`app.py`). A failure aborts startup, uvicorn exits, systemd restarts the unit every 2 s
  (`Restart=on-failure`, `RestartSec=2`), and `deploy.sh`'s health check fails and flips the symlink back. The
  database then holds the migrations before the failed one, and the old code runs on top of them (§6.2).
- **When it runs.** Migrations apply at `orch-relay serve` startup. `orch-relay migrate` applies them and exits.
  Both read `ORCH_RELAY_DATA` (database file `relay.sqlite3`).
- **Forward-only.** There are no down migrations. 0012 deletes rows (evidence-only device rows); 0010, 0011, 0014
  and 0015 rekey or backfill. The only rollback is restoring a pre-deploy copy.

### 3.2 An existing skeleton database compared with a fresh one

- The skeleton was deployed from `246f3f3` or close to it. **ANSWERED (12 Oct 2026, read-only ssh/local): U2: not quite. `current` points to `/opt/orch/releases/relay-0.1.0-661302a` (commit `661302a`, "CI: pin python 3.14 ...", after the skeleton). Four release dirs exist: `relay-0.1.0-9aa1731`, `-110cded`, `-661302a`, `-dirty-f6539008`. All carry only the code of the skeleton era, 0001_init (the dirty one additionally has a `0002_bad.sql`, a leftover of a rollback test).** Its only migration is `0001_init` (the `meta` table), and
  `0001_init.sql` has never changed since (`git log` shows one commit). An existing skeleton database should
  therefore list only `0001_init` (**U4: NOT OBTAINABLE read-only: the data dirs `/srv/orch-relay` and `/srv/orch-relay-int` are `root:<service user> 0750`, so `deploy` cannot list them, and the live database was deliberately not opened. The running release `661302a` ships only `0001_init.sql`, so the database can hold nothing newer. The operator must check, as root with the unit stopped or on a copy,** with
  `sqlite3 -readonly /srv/orch-relay/data/relay.sqlite3 'SELECT version, applied_at FROM schema_migrations'`, and the
  same for the int database). On that database the new code would apply `0002` … `0015` (+`0016`) in order at
  startup.
- On a fresh database, every migration from `0001` applies at first startup.
- **Recommendation: wipe and re-initialise both dev databases.** Reasons:
  - Nothing real lives there: the skeleton served `/healthz` only.
  - Protocol-v2 §7.2 (line ~701) and `docs/members-integration.md` require relay databases from before G2b to be
    wiped. Protocol-v2 line ~2367 says queued requests from before G3b are `malformed` ("wipe dev databases with
    queued requests").
  - A fresh database makes every later migration test start from a known point and makes the P3-D30 audit
    queries unnecessary.
  - Only the int database location is uncertain. `provision.sh` puts it at `/srv/orch-relay-int/data`, while the
    read-only facts list only `/srv/orch-relay/data`. **ANSWERED (12 Oct 2026, read-only ssh/local): U5: the units set `ORCH_RELAY_DATA=/srv/orch-relay/data` (public) and `/srv/orch-relay-int/data` (int), `ReadWritePaths=/srv/orch-relay` and `/srv/orch-relay-int`, so the int database is under `/srv/orch-relay-int/data`. Both parents exist (`root:orch-relay 750`, `root:orch-relay-int 750`); the `data` dirs themselves are not listable by `deploy`, so file names and sizes are NOT OBTAINABLE read-only (operator: `sudo ls -la /srv/orch-relay*/data`).**
- **Backup before the wipe** (§5 step B). With the unit stopped, **move** the data dir to a root-only timestamped
  backup and recreate it empty with the original owner and mode. The move is atomic and is itself the backup.
  Keep the backups outside `/srv/<svc>/data`: `orch-dev-reset` wipes the data dirs.
- **Do not use `orch-dev-reset` / `bin/reset --vps` for this wipe.** It also wipes `/srv/orch-publish/*`,
  `/srv/orch-host-ws2/state` and `/srv/agent-ws2/work` (`provision.sh` `TARGETS`), which is broader than needed.

---

## 4. Build and release

### 4.1 How a release is produced (`infra/dev/deploy.sh`, called by `~/orch-dev/bin/relay-deploy [ref]`)

1. Locally: `relay-deploy <ref>` makes a temporary detached worktree of `<ref>` and runs `infra/dev/deploy.sh`,
   which refuses a dirty tree unless `ORCH_DEPLOY_ALLOW_DIRTY=1`. It runs `uv build --wheel` and names the release
   `relay-<version>-<short sha>` (for example `relay-0.1.0-601cd91`).
2. It runs `ssh orch-dev mkdir -p /opt/orch/releases/<release> /opt/orch/relay` and rsyncs the wheel there.
   (Note: the releases live in `/opt/orch/releases/`, not under `/opt/orch/relay/`.)
3. On the VPS, under `flock /opt/orch/.deploy.lock`:
   - It creates `uv venv --python $(command -v python3.14 || command -v python3) <rdir>/venv` and runs
     `uv pip install` of the wheel, then writes the stamp `<rdir>/.wheel.sha256` last.
   - It sets `<rdir>/bin/orch-relay` → `venv/bin/orch-relay`.
   - It flips the symlink atomically: `ln -sfn <rdir> /opt/orch/relay/.current.new && mv -T … /opt/orch/relay/current`.
   - It runs `sudo orch-unit enable` + `restart` for **both** `orch-relay` and `orch-relay-int`.
   - It checks health: `curl http://127.0.0.1:{8101,8102}/healthz` must contain `"version":"0.1.0"`, 10 tries,
     1 s apart.
   - If that fails, it prints the last 50 log lines per unit, flips back to the previous target and restarts both.
     Otherwise it prunes to the 5 newest `relay-*` release dirs (keeping the current and the previous).
4. **ANSWERED (12 Oct 2026, read-only ssh/local): U1, U9:**
   - the venv uses `/usr/bin/python3.14`, CPython 3.14.4 (`pyvenv.cfg`: `home = /usr/bin`, `version_info = 3.14.4`); `/usr/bin/python3` is on the box too;
   - `uv` 0.12.23 is at `/usr/local/bin/uv`, on the deploy user's PATH;
   - the Ubuntu release is 26.04 LTS (kernel 7.0.0-14, x86_64), not 24.04.

**Limitations of the deploy script for this plan:**

- It always restarts both instances together. There is no "internal first" mode, so §5 step C stages the int
  instance by hand.
- Its health check cannot tell the new build from the skeleton (§1.1). The extra checks in §5 are mandatory.
- Its automatic rollback restores the code but not the database (§6).

### 4.2 Unit changes (dev-kit PR #27, `vps/provision.sh`)

PR #27 changes both units, plus a new unit, the nft table and the Caddyfile:

- Both relay units get `MemoryMax=900M` (public) / `450M` (int), `TasksMax=256`, `LimitNOFILE=4096`, no
  `MemoryHigh`, and
  `Environment=ORCH_RELAY_BEHIND_PROXY=1 ORCH_RELAY_TRUSTED_PROXY=127.0.0.1 ORCH_RELAY_PUBLISH_WIDTH=1 ORCH_RELAY_PUBLISH_HEADS=300000`.
- A new `orch-limits.service`, enabled and started by `provision.sh`, loads `/etc/nftables.d/orch-limits.nft`
  (table `inet orch_limits`).
- The Caddyfile gains `request_body { max_size 8MB }` on `relay.` and `relay-internal.`.

Points to know before running `provision.sh` for these changes:

- **It is a whole-host run.** It runs `apt-get install`, rewrites the units and helper scripts, rewrites the
  Caddyfile and reloads Caddy if it changed, and enables and starts `orch-limits`. It does **not** restart relay
  units (only `daemon-reload`), so the unit changes take effect at the deploy restart in step C/D.
- It takes `<domain> <vapid-subject-email>`. Use **the same email as the first run**, or the Caddyfile global
  `email` and `VAPID_SUBJECT` change too. **ANSWERED (12 Oct 2026, read-only ssh/local): U7: the Caddyfile global block has `email agent@severin.io`.** Check that value against what the run will pass.
- **It overwrites `/etc/orch/relay.env` and `/etc/orch/relay-int.env`** with only the three `VAPID_*` lines
  (`vapid()` uses `write_if_changed`). Any `ORCH_RELAY_*` line added to those files is silently removed by the next
  provision run. The PR #27 README advice ("or the `ORCH_RELAY_*` variables in `/etc/orch/relay.env`") is therefore
  unsafe. Feed this back to PR #27. This plan puts relay settings in a separate file instead (§4.3).
- How `provision.sh` gets onto the VPS: **ANSWERED (12 Oct 2026, read-only ssh/local): U14: there is no kit checkout visible to `deploy` (`/opt` holds only `orch`; `~deploy` holds only `.cache`, `.ssh`; `/root` and `/home/ubuntu` are unreadable). An installed copy exists: `/usr/local/sbin/orch-dev-provision` (root 0750, written by `provision.sh` itself, last modified 11 Oct 01:39 UTC, so the script was rerun then), plus `/usr/local/sbin/orch-dev-reset` and `orch-unit`. The earlier copy to the host was therefore a one-off copy by an admin. The reviewed head still has to be copied over (scp to the admin user) and its sha256 compared with the installed copy.** Use exactly the reviewed commit (`48bf7b5` or its successor after the delta
  review) and record its sha256 in the run log.

### 4.3 Relay settings (environment), from the code

All of these are read once at start-up. The list is complete for `develop` `601cd91`, plus P3-D36:

| Variable | Read in | Default | Dev value (public / int) | Why |
|---|---|---|---|---|
| `ORCH_RELAY_DATA` | `app.py` | `./data` | unit sets `/srv/orch-relay/data` / `/srv/orch-relay-int/data` | unchanged |
| `ORCH_RELAY_PORT` | `cli.py` | 8101 | unit: 8101 / 8102 | unchanged |
| `ORCH_RELAY_INSTANCE` | `app.py` | `public` | unset / unit sets `int` | unchanged |
| `ORCH_RELAY_ORIGIN` | `directory.py` | `http://localhost:8101` | `https://relay.dev.severin.io` / `https://relay-internal.dev.severin.io` | **P1**: login binds the origin; it must also equal the cards' `relay_url` (§7.1 form, no trailing slash) |
| `ORCH_RELAY_TRUSTED_PROXY` | `directory.py` | unset | `127.0.0.1` (PR #27 unit) | P2: one trusted hop, last XFF entry only |
| `ORCH_RELAY_BEHIND_PROXY` | `directory.py` | unset | `1` (PR #27 unit) | P2: start-up warning if the proxy setting is missing |
| `ORCH_RELAY_PUBLISH_WIDTH` | `checkpoints.py` | 2 | `1` (PR #27 unit) | checklist 1 |
| `ORCH_RELAY_PUBLISH_HEADS` | `checkpoints.py` | 1,500,000 | `300000` (PR #27 unit) | checklist 1 (only matters for width > 1) |
| `ORCH_RELAY_GLOBAL_STAGE_BYTES` | `checkpoints.py` | 4 GiB | `16777216` (16 MiB) / `4194304` (4 MiB) | **P4 interim**, see below |
| `ORCH_RELAY_ACCOUNT_STAGE_BYTES` | `checkpoints.py` | 512 MiB | leave the default (the global cap is lower) | — |
| `ORCH_RELAY_WORKSPACE_NODES` | `checkpoints.py` | 4,000,000 | `500000` / `100000` | P6, disk |
| `ORCH_RELAY_WORKSPACE_NODES_RESERVE` | `checkpoints.py` (P3-D36 only) | 5 % of the node quota | leave the default | — |
| `ORCH_RELAY_ACCOUNT_WORKSPACES` | `directory.py` | 32 | `8` / `4` | P6, disk |
| `ORCH_RELAY_ACCOUNT_EVIDENCE` | `checkpoints.py` | 50,000 | leave the default (~75 MB per account worst case) | — |
| `ORCH_RELAY_THROTTLE_<CLASS>` (`SESSION`, `PERSON`, `WORKSPACE`, `PAGE_SESSION`, `PAGE_PERSON`, `PAGE_WORKSPACE`, `STAGING`, `HOST_ANSWER`; value `burst/per-minute`) | `directory.py` `throttle_settings` | `THROTTLES` | only `ORCH_RELAY_THROTTLE_STAGING=27777/600`, and only if P3-D36 is **not** in the release (P7) | checklist 8 interim |
| `ORCH_RELAY_THROTTLE_TABLE` | `directory.py` | 16,384 | leave the default (≤ ~61 MB if all 8 classes fill; dev will not) | — |
| `ORCH_RELAY_ADMIN_BUSY_MS` | `cli.py` (P3-D36 `account-cap`) | 5000 | operator shell only | — |
| `VAPID_SUBJECT`, `VAPID_PRIVATE_KEY_FILE`, `VAPID_PUBLIC_KEY_FILE` | **not read by the relay** | — | leave as `provision.sh` writes them | push is not implemented (TODO(P4) in `provision.sh`) |
| APNs key (`/srv/orch-relay/apns/`) | **not read by the relay** | — | not needed for this deploy | see R8 |

**P4 interim cap (`ORCH_RELAY_GLOBAL_STAGE_BYTES`).** The ceiling counts every live staged byte relay-wide (503
`overloaded` above it, `charge_stage`). No staged set can exceed it, so a publication's new heads are bounded by
`cap / 74 B`. Figures from design §10 checklist 1 (measured on macOS, CPython 3.14; **U10 NOT OBTAINABLE read-only (VPS Python is CPython 3.14.4, same minor as the measurement; the benchmark must still be run)** with `tests/bench_publication_lockhold.py`): ~1.3 KB of phase A memory per new node, and a baseline of
~150–250 MB plus up to 48 pooled read connections (~2 MB each) plus in-flight bodies. Allow ~350 MB for the
baseline:

- **Public (MemoryMax 900M):** 16 MiB → ≤ ~226,700 heads → ~295 MB phase A → ~650 MB peak, leaving ~250 MB of
  margin.
- **Int (MemoryMax 450M):** 4 MiB (one full page) → ≤ ~56,700 heads → ~75 MB → ~425 MB peak. This is tight. The
  int instance is not needed for mobile testing, so orch-d6 may instead run it with checkpoint publication unused.
- **Honest load still fits.** A 5,000-ticket workspace stages ~20,000 heads (~1.5 MB of pages plus a ~0.85 MB
  manifest, `docs/p3-checkpoint-capacity.md`).
- **Effect.** A workspace with more history than the cap cannot make its first publication (503). That is
  acceptable for dev and lifted by resizing (R1) or by P4's code.
- Remove the interim cap only when P4 ships and the hard limit is set below `MemoryMax`.

**Disk (P6).** Checklist 2: `accounts × ACCOUNT_WORKSPACES × WORKSPACE_NODES × 293 B`.

- Public: 10 invited accounts × 8 × 500,000 × 293 B ≈ 11.7 GB.
- Int: 10 × 4 × 100,000 × 293 B ≈ 1.2 GB.
- Add 2 × the staging ceilings and the WAL, and the total stays under ~15 GB of the ~35 GB free. The number of
  invited accounts is orch-d6's call; scale the values if it is larger.

**Where to put them.** Use a drop-in that adds a second `EnvironmentFile` that `provision.sh` never writes. It wins
over the unit's `Environment=` and survives provision runs:

```
ROOT$ install -d -m 0755 /etc/systemd/system/orch-relay.service.d /etc/systemd/system/orch-relay-int.service.d
ROOT$ printf '[Service]\nEnvironmentFile=/etc/orch/relay.local.env\n' > /etc/systemd/system/orch-relay.service.d/local-env.conf
ROOT$ printf '[Service]\nEnvironmentFile=/etc/orch/relay-int.local.env\n' > /etc/systemd/system/orch-relay-int.service.d/local-env.conf
ROOT$ install -m 0640 -o root -g orch-relay /dev/stdin /etc/orch/relay.local.env <<'EOF'
ORCH_RELAY_ORIGIN=https://relay.dev.severin.io
ORCH_RELAY_GLOBAL_STAGE_BYTES=16777216
ORCH_RELAY_WORKSPACE_NODES=500000
ORCH_RELAY_ACCOUNT_WORKSPACES=8
EOF
ROOT$ install -m 0640 -o root -g orch-relay-int /dev/stdin /etc/orch/relay-int.local.env <<'EOF'
ORCH_RELAY_ORIGIN=https://relay-internal.dev.severin.io
ORCH_RELAY_GLOBAL_STAGE_BYTES=4194304
ORCH_RELAY_WORKSPACE_NODES=100000
ORCH_RELAY_ACCOUNT_WORKSPACES=4
EOF
ROOT$ systemctl daemon-reload
```

- Add `ORCH_RELAY_THROTTLE_STAGING=27777/600` to both files only if the release lacks P3-D36.
- systemd reads `EnvironmentFile=` as root before dropping privileges, so the mode could be 0600. 0640 with the
  service group matches `/etc/orch/*.env` practice; nothing in these files is secret.
- The drop-in has no effect until the next restart (step C/D).

Alternatively, if orch-d6 prefers everything in the dev kit, PR #27 gets an `ORCH_RELAY_ORIGIN` line per unit and
these values become `PROVISION_RELAY_*` knobs. That needs another PR round and review.

---

## 5. Order of operations

General rules for every step:

- orch-d6 approves the step before it runs.
- A second root SSH session stays open for the whole run.
- Each step is logged in `~/orch-dev/state/p3-relay-plan.md`, with times taken from `date`.
- No broad kills (`orch-unit` and `systemctl` on the named units only).
- Each step lists its rollback, and a failed check stops the run there.

### Step 0: Read-only pre-flight (no changes)

```
ROOT$ TS=$(date +%Y%m%d-%H%M%S); echo "$TS"
ROOT$ free -m; df -h /; uptime; systemctl --version | head -1
ROOT$ systemctl show orch-relay orch-relay-int -p ActiveState -p MemoryCurrent -p MemoryMax -p NRestarts -p FragmentPath -p DropInPaths
ROOT$ readlink /opt/orch/relay/current; ls -1dt /opt/orch/releases/relay-*
ROOT$ ls -la /srv/orch-relay/data /srv/orch-relay-int/data
ROOT$ sqlite3 -readonly /srv/orch-relay/data/relay.sqlite3 'SELECT version, applied_at FROM schema_migrations'
ROOT$ sqlite3 -readonly /srv/orch-relay-int/data/relay.sqlite3 'SELECT version, applied_at FROM schema_migrations'
ROOT$ cat /etc/orch/relay.env /etc/orch/relay-int.env; grep -n email /etc/caddy/Caddyfile
ROOT$ curl -fsS http://127.0.0.1:8101/healthz; curl -fsS http://127.0.0.1:8102/healthz
ROOT$ nft --version; nft list tables; ufw status verbose | head -20
ROOT$ systemctl list-units 'orch-*' --all --no-pager; systemctl status caddy --no-pager | head -5
ROOT$ command -v python3.14 python3 uv; python3 --version
```

- Resolves UNKNOWNs U1–U9 and U16 (§9).
- **Go only if** the read-only facts still hold, nothing unexpected is running, and the RAM, disk and Ubuntu values
  match what §4.3 assumes.
- `MemoryPeak` needs systemd ≥ 255 (**ANSWERED (12 Oct 2026, read-only ssh/local): U9: systemd 259 (259.5-0ubuntu3.4), nftables 1.1.6; `MemoryPeak` works and already reports ~50 MB per relay unit**). If it is missing, use
  `MemoryCurrent` sampling and the cgroup's `memory.peak`.

### Step A: Off-host validation of the nft ruleset (laptop or a throwaway VM; nothing on the VPS)

```
laptop$ (throwaway Ubuntu 26.04 VM (local, cloud-init))  apt-get install -y nftables
        nft -c -f orch-limits.nft        # or, without root: unshare -rn nft -c -f orch-limits.nft
```

- `orch-limits.nft` is the exact `nft_rules` text from the reviewed PR #27 head with its default values
  substituted, plus an empty `orch-limits-allow.nft`.
- Also confirm that the Opus delta of `48bf7b5` passed, and that the ordering-cycle flag is fixed
  (`DefaultDependencies=no` or a different `Before=`).
- Rollback: none needed.

### Step B: Backup and wipe of both relay databases (VPS)

```
ROOT$ systemctl stop orch-relay-int orch-relay
ROOT$ install -d -m 0700 -o root -g root /var/backups/orch-relay/$TS
ROOT$ mv /srv/orch-relay/data     /var/backups/orch-relay/$TS/orch-relay-data
ROOT$ mv /srv/orch-relay-int/data /var/backups/orch-relay/$TS/orch-relay-int-data
ROOT$ install -d -m 0750 -o orch-relay     -g orch-relay     /srv/orch-relay/data
ROOT$ install -d -m 0750 -o orch-relay-int -g orch-relay-int /srv/orch-relay-int/data
ROOT$ ls -la /var/backups/orch-relay/$TS/*; sha256sum /var/backups/orch-relay/$TS/*/relay.sqlite3*
```

- The units stay stopped until step C/D. The skeleton serves nothing anyone depends on, so the downtime is
  harmless. `relay.dev.severin.io` answers 502 meanwhile.
- If orch-d6 wants the skeleton up during A–C, copy with `sqlite3 <db> ".backup '<dest>'"` instead of moving, and
  wipe right before step C.
- Rollback:
  ```
  ROOT$ systemctl stop orch-relay orch-relay-int
  ROOT$ rm -rf /srv/orch-relay/data /srv/orch-relay-int/data
  ROOT$ mv /var/backups/orch-relay/$TS/orch-relay-data /srv/orch-relay/data
  ROOT$ mv /var/backups/orch-relay/$TS/orch-relay-int-data /srv/orch-relay-int/data
  ROOT$ systemctl start orch-relay orch-relay-int
  ```

### Step (a): nftables per-IP limits, only if P5 is approved

- Run as part of step (b)'s provision run: `provision.sh` installs and starts `orch-limits` itself after its own
  `nft -c`.
- Before it:
  ```
  ROOT$ nft list ruleset > /root/pre-limits-$TS.nft
  ROOT$ cp -a /etc/caddy/Caddyfile /root/Caddyfile-$TS
  ```
- After it, check that SSH and HTTPS still work:
  ```
  ROOT$ systemctl is-active orch-limits; nft list table inet orch_limits
  ```
  Open a **new** SSH login from a third terminal, and run
  `laptop$ curl -sSI https://relay.dev.severin.io/healthz` (a 502 is expected while the relay is stopped; what
  matters is that TLS and Caddy answer).
- Rollback:
  ```
  ROOT$ systemctl disable --now orch-limits     # runs: nft delete table inet orch_limits
  ```
  or `nft delete table inet orch_limits` directly. **Never** enable `nftables.service`: its `flush ruleset` would
  wipe ufw's rules.

### Step (b): Unit limits, proxy env and relay settings

1. Run the reviewed PR #27 `provision.sh` with the original arguments:
   `ROOT$ ./provision.sh dev.severin.io <same email as before>`.
2. Write the §4.3 drop-ins and `*.local.env` files, then `systemctl daemon-reload`.
3. Check the result:
   ```
   ROOT$ systemctl show orch-relay orch-relay-int -p MemoryMax -p TasksMax -p LimitNOFILE -p Environment -p EnvironmentFiles -p DropInPaths
   ROOT$ caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
   ```
   Expect `MemoryMax=943718400` / `471859200`, `LimitNOFILE=4096`, the proxy variables, and both env files.

Rollback:

- Units: restore the pre-PR unit files. The previous kit commit's `provision.sh` rewrites them; or, quicker, add a
  drop-in `[Service]` with `MemoryMax=infinity`, `TasksMax=infinity`, `LimitNOFILE=1024`. Then
  `systemctl daemon-reload`.
- Relay settings: `rm /etc/systemd/system/orch-relay{,-int}.service.d/local-env.conf /etc/orch/relay{,-int}.local.env`,
  then `systemctl daemon-reload`.
- Caddyfile: `cp /root/Caddyfile-$TS /etc/caddy/Caddyfile && caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile && systemctl reload caddy`.
- Nothing restarts the relays in this step, so a rollback here never touches a running relay.

### Step (c): New release on the INTERNAL instance first (8102), then smoke tests

`deploy.sh` cannot deploy one instance alone (§4.1). The int instance therefore runs the new release from a staged
directory through a temporary drop-in, while the public instance stays stopped from step B (or on the skeleton, if
the copy variant was chosen).

1. Build the wheel locally from the approved commit (`<sha>`: `601cd91`, or the P3-D36 merge commit). Use the same
   steps as `infra/dev/deploy.sh` without deploying:
   ```
   laptop$ git -C ~/orch-dev/orch-relay worktree add --detach /tmp/relay-stage <sha>
   laptop$ cd /tmp/relay-stage && uv build --wheel
   laptop$ ssh orch-dev "mkdir -p /opt/orch/releases/relay-0.1.0-<sha>-stage"
   laptop$ rsync -a dist/orch_relay-0.1.0-py3-none-any.whl orch-dev:/opt/orch/releases/relay-0.1.0-<sha>-stage/
   ```
   The `-stage` suffix keeps it apart from the dir `deploy.sh` will build, so `deploy.sh` never rebuilds a venv the
   int instance is running from.
2. Build the venv on the VPS (`deploy$`), mirroring the script:
   ```
   deploy$ R=/opt/orch/releases/relay-0.1.0-<sha>-stage
   deploy$ uv venv --python "$(command -v python3.14 || command -v python3)" $R/venv
   deploy$ uv pip install --python $R/venv/bin/python $R/orch_relay-0.1.0-py3-none-any.whl
   ```
3. Point the int instance at the staged release (`ROOT$`):
   ```
   ROOT$ printf '[Service]\nExecStart=\nExecStart=/opt/orch/releases/relay-0.1.0-<sha>-stage/venv/bin/orch-relay serve --host 127.0.0.1 --port 8102\n' > /etc/systemd/system/orch-relay-int.service.d/stage.conf
   ROOT$ systemctl daemon-reload && systemctl start orch-relay-int
   ```
4. Smoke-test the int instance (the commands are in step F):
   - healthz;
   - `schema_migrations` lists `0001`…`0015` (+`0016`);
   - the challenge route answers 200;
   - the F3 subset passes through `https://relay-internal.dev.severin.io`;
   - the journal shows no proxy warning;
   - `systemctl show orch-relay-int -p MemoryCurrent` is reasonable;
   - the environment check (F5) shows the int origin.

Rollback:

```
ROOT$ systemctl stop orch-relay-int
ROOT$ rm /etc/systemd/system/orch-relay-int.service.d/stage.conf
ROOT$ systemctl daemon-reload
```

Then restore the int database from step B's backup if the skeleton must run again (§6.2). The skeleton code at
`/opt/orch/relay/current` is untouched by this step.

### Step (d): Public instance, through the normal deploy path

1. Remove the int staging drop-in and run the canonical deploy, which builds `/opt/orch/releases/relay-0.1.0-<sha>`,
   flips `current` and restarts **both** units from it:
   ```
   ROOT$ rm /etc/systemd/system/orch-relay-int.service.d/stage.conf && systemctl daemon-reload
   laptop$ ~/orch-dev/bin/relay-deploy <sha>
   ```
   The int database was already migrated in (c); its migrations are a no-op now.
2. Confirm the build: the three checks in §1.1, on both ports.
3. Remove the stage dir afterwards (`deploy$ rm -rf /opt/orch/releases/relay-0.1.0-<sha>-stage`), or let the
   five-release pruning remove it.

Rollback:

- `deploy.sh` rolls back by itself if a health check fails. Its check passes on any `0.1.0`, so a manual rollback
  can still be needed (§6.1).
- Database: §6.2.

### Step (e): Caddy

- Unchanged except for the `request_body max_size 8MB` from PR #27, applied in step (b) only if PR #27 is applied.
- The relay's largest accepted body is a 4 MiB staging page (`checkpoints.PAGE_CAP`); the final checkpoint request
  is ≤ 2,686,976 bytes.
- Caddy 2.11's `reverse_proxy` sets `X-Forwarded-For` from the real peer, and the relay trusts only the last hop
  from `127.0.0.1` (PR #27 review: not exploitable externally).
- Rollback: restore `/root/Caddyfile-$TS` (step b).

### Step (f): Verification

**F1. Build and schema:** the three §1.1 checks, on both ports.

**F2. Health over HTTPS:**

```
laptop$ cd ~/orch-dev && ORCH_RELAY_URL=https://relay.dev.severin.io e2e/run.sh hello
```

This checks `ok:true` plus instance `public` and `int` via `relay.` and `relay-internal.`.

**F3. Fixture replay subset (stateless cases that hold on a fresh database).** Send the exact request from the
fixture and compare the status and the JSON field set. Values that depend on the fixture's seeded state or clock
(challenge bytes, `expires_ms`) only need the right shape. Run against both instances:

| Fixture case | Expected |
|---|---|
| `session_challenge.json` `success` (POST `{}`) | 200 `{challenge, expires_ms}` |
| `session_challenge.json` `refusal_400_malformed` (query `unexpected=1`) | 400 `{"error":"malformed"}` |
| `session_challenge.json` `refusal_413_too_large` (`body_recipe`) | 413 `{"error":"too_large"}` |
| `members.json` `refusal_401_unauthenticated` (no `Authorization`) | 401 `{"error":"unauthenticated"}` |
| `revocation_get.json` `refusal_404_not_found` (fresh database: no pairs) | 404 `{"error":"not_found"}` |
| `session_logout.json`, unknown token | 200 `{}` (protocol §19.6) |
| a body of more than 8 MB to any relay route (only with the PR #27 Caddyfile) | 413 from Caddy, never reaching the relay |

There is no ready script for this. A small `httpx` loop over the fixture JSON is a G5 task, and the cases can be
sent by hand with `curl` meanwhile. Stateful success cases (login, membership, bridge) need seeded state and are
covered by the manual flow in F6.

**F4. Memory and stability:**

```
ROOT$ systemctl show orch-relay orch-relay-int -p MemoryCurrent -p MemoryPeak -p MemoryMax -p NRestarts -p ActiveEnterTimestamp
ROOT$ journalctl -k --since "-1h" | grep -iE 'out of memory|oom-kill|killed process'
ROOT$ free -m
```

**F5. Settings actually in effect, and no proxy warning:**

```
ROOT$ tr '\0' '\n' < /proc/$(systemctl show -p MainPID --value orch-relay)/environ | grep ^ORCH_RELAY_
ROOT$ journalctl -u orch-relay -u orch-relay-int --since "-1h" | grep -E 'TRUSTED_PROXY is unset|Trusted proxy sent no X-Forwarded-For|Traceback'
```

The `grep` must find nothing.

**F6. Manual end-to-end flow (the phase-2 entry test):**

1. Create an invite:
   ```
   ROOT$ sudo -u orch-relay env ORCH_RELAY_DATA=/srv/orch-relay/data /opt/orch/relay/current/bin/orch-relay invite create --ttl 2d
   ```
   The invite is printed once. Hand it over out of band, never commit it.
2. A host (orch-core, P3 bridge client) creates the workspace and card, holds, and pairs the phone.
3. The phone joins, then sends one bridge request and gets the answer.
4. The host revokes a test device, and the phone sees 403 `revoked` on login.

Whether a P3-capable host exists for this (orch-core bridge client, or `orch-host-ws2` on the VPS): **ANSWERED (12 Oct 2026, read-only ssh/local): U11: no host exists on the VPS: `orch-host-ws2`, `orch-publish-api` and `orch-app@` are installed but `disabled` and `inactive`. A host-side bridge client on the dev laptop is not visible read-only (state/coordination.md of 11 Oct: "P3 core-side host bridge client waits for A"); NOT OBTAINABLE read-only: ask orch-52 whether it exists now.**

**F7. Load sanity (optional, orch-d6 to decide):**

- Stage and publish one 5,000-ticket checkpoint from a host. It must pass under the 16 MiB cap.
- Read `MemoryPeak` afterwards. It should be ≤ ~500 MB. This replaces the macOS 1.3 KB/node figure with a
  measured one (U10).

### Step (g): Soak, 24 h before mobile starts

Watch at +1 h, +6 h and +24 h:

- `NRestarts` stays 0 on both units, with no OOM line in `journalctl -k`.
- `MemoryPeak` < 70 % of `MemoryMax`, and `free -m` `available` > 300 MB.
- The journal has no `Traceback`, proxy warning or `sqlite3` error.
- Database size: `du -sh /srv/orch-relay*/data`, including the WAL. `relay.sqlite3-wal` should stay below a few
  hundred MB; check that it is truncated after idle periods.
- `df -h /` stays ≥ 20 GB free.
- `nft list table inet orch_limits` counters, if (a) was applied. Hits from the testers' addresses mean that
  address belongs in `orch-limits-allow.nft`.
- `curl -fsS https://relay.dev.severin.io/healthz` at each check.
- Caddy 5xx and 429 rates, if Caddy access logs exist. **ANSWERED (12 Oct 2026, read-only ssh/local): U8: Caddy has no `log` directive and `/var/log/caddy` is empty, so there are no access logs; the 5xx/429 watch must use relay journal lines or add a `log` block**: the
  provisioned Caddyfile has no `log` directive.

**Stop the soak and roll back if** any OOM kill or unexpected restart occurs, if `MemoryPeak` > 85 % of
`MemoryMax`, or if the free disk shrinks faster than 1 GB/h.

---

## 6. Rollback

### 6.1 Code (symlink flip back)

```
deploy$ readlink /opt/orch/relay/current                         # note the new target
deploy$ ln -sfn /opt/orch/releases/<previous> /opt/orch/relay/.current.new && mv -T /opt/orch/relay/.current.new /opt/orch/relay/current
deploy$ sudo orch-unit restart orch-relay-int; sudo orch-unit restart orch-relay
```

- `<previous>` is the skeleton release recorded in step 0. `deploy.sh` keeps it while it is the `prev` of the latest
  deploy. After a second deploy it may be pruned, so record its name in step 0, and orch-d6 may ask to copy it
  aside.
- The skeleton applies only `0001_init` and ignores the other tables, so it **runs** on a migrated database. To get
  back the exact pre-deploy state, also restore the backup (§6.2).
- A rollback from one new release to an older new release on a database that a newer migration has touched is
  **not supported**. Restore the backup taken before that migration.

### 6.2 Database (restore the pre-deploy backup)

Migrations are forward-only. A rollback means restoring the step-B backup, and **every write since the deploy is
lost** (accounts, devices, workspaces, pairing state, checkpoints). Testers must re-pair after it.

```
ROOT$ systemctl stop orch-relay orch-relay-int
ROOT$ mv /srv/orch-relay/data     /var/backups/orch-relay/$TS/failed-orch-relay-data          # keep for diagnosis
ROOT$ mv /srv/orch-relay-int/data /var/backups/orch-relay/$TS/failed-orch-relay-int-data
ROOT$ cp -a /var/backups/orch-relay/$TS/orch-relay-data     /srv/orch-relay/data
ROOT$ cp -a /var/backups/orch-relay/$TS/orch-relay-int-data /srv/orch-relay-int/data
ROOT$ systemctl start orch-relay orch-relay-int        # after the §6.1 code flip
```

`cp -a` keeps the owners (`orch-relay`, `orch-relay-int`) and the 0750 mode. Copy rather than move, so the backup
survives a second attempt.

### 6.3 Units and drop-ins

- Remove `/etc/systemd/system/orch-relay{,-int}.service.d/{local-env,stage}.conf`.
- For the PR #27 unit lines, either re-run the previous kit commit's `provision.sh` or add a `MemoryMax=infinity` /
  `TasksMax=infinity` / `LimitNOFILE=1024` drop-in.
- Then `systemctl daemon-reload` and restart the two relay units.

### 6.4 nftables

`systemctl disable --now orch-limits`, which runs `nft delete table inet orch_limits`, or the `nft delete table`
command directly. `/root/pre-limits-$TS.nft` is the reference for the previous ruleset. Do not `nft -f` it
blindly: it contains ufw's tables, which ufw manages.

### 6.5 Caddyfile

```
ROOT$ cp /root/Caddyfile-$TS /etc/caddy/Caddyfile
ROOT$ caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
ROOT$ systemctl reload caddy
```

The certificates in `/var/lib/caddy` are never touched, which matters for the Let's Encrypt duplicate limit.

### 6.6 What cannot be rolled back

- **Applied migrations.** Restore the backup instead (§6.2); writes after the backup are lost.
- **Invites, accounts and pairings handed to testers.** They live only in the database, so a restore invalidates
  them, and phones must re-pair. Mobile keychain state (device keys) survives on the phone. Whether the phone
  recovers cleanly from a relay that "forgot" it (login 401 or 404, re-registration of the same device id): **NOT OBTAINABLE read-only (U12): the build has no relay client, so ask orch-f1 for the planned behaviour**.
- **Throttle buckets and in-memory windows.** They reset on every restart (accepted, P3-D35).

---

## 7. Risks and open questions for orch-d6 and the owner

Ordered by impact:

- **R1. Memory on a 1961 MB VPS with no swap.** One full 64 MiB publication needs ~1.45 GB per instance, above
  both `MemoryMax` values, and the heads cap does not bound a single publication (P4).
  - Mitigation for this deploy: `MemoryMax` plus the interim `ORCH_RELAY_GLOBAL_STAGE_BYTES` (§4.3). The per-node
    figure is from macOS and unmeasured on the VPS (U10).
  - **Decision for the owner: resize to 4 GB** (the README planned 4 GB; design §10 checklist 1 gives width 1 and
    heads 900,000 per instance at 4 GB), or keep 2 GB with the interim cap until P4 ships. Adding 2 GB of swap is a
    stopgap only (§10 checklist 1).
- **R2. Missing `ORCH_RELAY_ORIGIN`.** Every login fails, so the deploy "works" (healthz green) but nothing can
  authenticate. Also, `provision.sh` overwrites `/etc/orch/relay*.env`, so settings placed there vanish on the next
  provision run. Mitigation: §4.3 drop-ins and `*.local.env`. Feed this back to PR #27 (its README suggests
  `relay.env`).
- **R3. False-positive deploy check.** `/healthz` reports `0.1.0` for any commit, and probably for the skeleton too.
  Mitigation: the §1.1 three-way check. Follow-up: put the sha in `/healthz`.
- **R4. Forward-only migrations, and both instances restarted at once.** `deploy.sh` has no per-instance mode, and
  its auto-rollback leaves the migrated schema in place. Mitigations:
  - the step-B backup;
  - the manual int-first staging (step c);
  - a fresh database, so the migrations run on an empty schema.

  Optional follow-up for the dev kit: an `ORCH_DEPLOY_UNITS` knob in `deploy.sh`.
- **R5. nftables on the only VPS.** The rules leave port 22 alone, but the syntax has not been through `nft -c`, the
  automated flag (ordering cycle) is open, and the rules fail open with no alert.
  - Mitigations: step A, the second SSH session, `/root/pre-limits-$TS.nft`, and never `nftables.service`.
  - Many phones behind one carrier NAT address share the 100-connection and 60-per-second caps.
  - Testers' fixed addresses can go into the allow file.
- **R6. Contract drift between phone and relay.** Mobile vendors fixtures from `386a6cb` (pre-MANIFEST). The
  relay's corpus is at revision 11. Phase-2 results are meaningless until mobile re-pins to the deployed commit
  (P13). Every later relay deploy that bumps the revision must be announced to orch-f1 with the new sha and revision.
- **R7. No remote e2e harness and no confirmed real host.** The design §10 scenarios do not exist (§1.4), and
  whether a P3-capable orch-core host is available is unknown (U11). Without a host the phone cannot pair, so the
  deploy alone does not unblock mobile.
- **R8. APNs and push.** The relay has no push code and no push-registration route (gap 16), so APNs keys on the VPS
  are **not** needed for this deploy, and push cannot be tested against the real relay in phase 2.
  - HANDOVER and `e2e/CHECKLIST.md` expect the `.p8` in `/srv/orch-relay/apns/` at mode 0600. `provision.sh`
    comments say root-owned with mode 0640 and group `orch-relay`. Reconcile this before P4 push work.
  - Open for orch-d6: when is push registration designed (protocol amendment plus relay)?
- **R9. Mobile pins the relay URL.** The vectors and fixtures use `relay_url = https://relay.dev.severin.io`, and the
  phone requires the signed card's `relay_url` to be byte-equal to the reviewed origin. The relay's
  `ORCH_RELAY_ORIGIN` and the host's card must therefore carry exactly that string; a trailing slash breaks it.
  - Open: does the TestFlight build let a tester choose the relay (paste or QR origin review), or does it pin
    `relay.dev`? (**ANSWERED (12 Oct 2026, read-only ssh/local): U15: the TestFlight build can NOT reach any relay yet (no real transport, "relay isn't connected in this build"; Demo mode only). Once connected, decisions D-3 and gaps 5/6 say pairing uses a pasted link or QR that carries the relay origin, shown before joining; the associated-domains file lists `relay.dev.severin.io` only**)
  - The internal instance (`relay-internal.`) is only reachable if the build accepts that origin.
- **R10. TestFlight expectations.** Phase 2 needs a TestFlight build with the HTTPS `RequestSender` (orch-mobile
  `docs/plug-in.md` §A: "The HTTPS sender is not implemented"). Its build date and the commit it pins are orch-f1's.
  Do not schedule the soak's end as "mobile starts" until that build exists.
- **R11. Disk and abuse by invited users.** The §4.3 values bound storage to ~15 GB for 10 accounts. Raising the
  number of invited accounts requires recomputing them (checklist 2).
- **R12. Database write availability.** One relay process per database, and all writes take one lock; the gate and
  mutex are per event loop (P3-D33, P3-D34 F6). Never run two processes on one database: no second `serve`, and no
  `orch-relay migrate` while the unit runs. P3-D36's `account-cap set` is safe while the relay runs; it waits up to
  5 s for the lock.

**Who runs what (proposal for orch-d6 to confirm):**

- orch-d6 approves the plan and then each step.
- The **owner** (root on the VPS) runs steps 0, B, (a), (b), the root parts of (c) and the rollbacks.
- **stream D (orch-4e)**:
  - runs the laptop parts, `relay-deploy` (as `deploy`) and the F1–F5 checks;
  - logs every step in `p3-relay-plan.md`;
  - prepares the F3 smoke script.
- **orch-f1** re-pins mobile, then starts phase-2 tests only after the soak passes and orch-d6 says go.
- **orch-52** confirms the host side (U11).

---

## 8. Go / no-go checklist (one page)

All boxes must be ticked, and orch-d6 must say "go", before step B. Before (c), (d) and the start of mobile
testing, orch-d6 says "go" again.

**Approvals**

- [ ] orch-d6 approved this plan (and recorded which release commit: `601cd91` or the P3-D36 merge)
- [ ] orch-d6 decided on 2 GB with the interim cap, or a resize to 4 GB first (R1)
- [ ] orch-d6 decided whether nftables goes in now (P5), or accepted the fallback in writing

**Preconditions**

- [ ] P1 `ORCH_RELAY_ORIGIN` values agreed (`https://relay.dev.severin.io`, `https://relay-internal.dev.severin.io`)
- [ ] P2/P3 PR #27: Opus delta of the head passed, the ordering-cycle flag resolved, head sha recorded
- [ ] P5 `nft -c -f orch-limits.nft` passed on a throwaway Ubuntu 26.04 (step A), if nft is in scope
- [ ] P4 interim `ORCH_RELAY_GLOBAL_STAGE_BYTES` values agreed (16 MiB public, 4 MiB int), or P4 code merged
- [ ] P6 disk values agreed for the number of invited accounts
- [ ] P7 release includes P3-D36, or `ORCH_RELAY_THROTTLE_STAGING=27777/600` is in both env files (never both)
- [ ] Release commit CI green on `develop` (`gh pr checks` / Actions), full suite and ruff

**Pre-flight (step 0)**

- [ ] Pre-flight run; U1–U9 and U16 resolved; nothing unexpected running
- [ ] Skeleton release name recorded (for §6.1)
- [ ] Second root SSH session open; provision email confirmed equal to the first run

**Backup (step B)**

- [ ] Both data dirs moved to `/var/backups/orch-relay/$TS/` and recreated empty with the right owner and mode
- [ ] sha256 of the backed-up `relay.sqlite3*` files recorded

**After (b)**

- [ ] `MemoryMax`, `LimitNOFILE`, proxy env and `*.local.env` visible in `systemctl show`
- [ ] `caddy validate` OK

**After (c), int instance**

- [ ] `schema_migrations` complete
- [ ] `/v2/session/challenge` answers 200
- [ ] F3 subset passes
- [ ] No proxy warning
- [ ] Origin correct

**After (d), public instance**

- [ ] `current` → `relay-0.1.0-<sha>`
- [ ] F1–F5 pass on both instances
- [ ] `e2e/run.sh hello` passes

**Before mobile starts**

- [ ] F6 manual flow passes (needs a host: U11)
- [ ] 24 h soak passed: `NRestarts` 0, no OOM, `MemoryPeak` < 70 % of `MemoryMax`, disk fine
- [ ] Mobile re-vendored the fixtures and vectors at the deployed commit; MANIFEST revision (11 at `601cd91`) and
  aggregate recorded in `PROVENANCE.md`
- [ ] TestFlight build with the HTTPS sender available (R10)
- [ ] orch-d6 "go" for mobile phase-2 testing

**No-go triggers (any one stops the run and starts the rollback of the current step):**

- the pre-flight differs from the facts;
- `nft -c` fails;
- the new SSH login fails after (a);
- a migration error appears in the journal;
- the challenge route answers 404 after a deploy;
- an OOM kill or unit restart happens;
- a proxy warning appears;
- `MemoryPeak` > 85 % of `MemoryMax`.

---

## 9. UNKNOWN list (answered 12 Oct 2026 by a read-only check; open items marked)

| # | Unknown | How to verify (read-only) |
|---|---|---|
| U1 | Python that `deploy.sh` uses on the VPS (`python3.14` or `python3`, version ≥ 3.11), and `uv` on the deploy user's PATH | `command -v python3.14 python3 uv; python3 --version` **ANSWERED (12 Oct 2026, read-only ssh/local): python3.14 = /usr/bin/python3.14 (CPython 3.14.4); uv 0.12.23 at /usr/local/bin/uv** |
| U2 | The skeleton's release name and commit (expected near `246f3f3`) | `readlink /opt/orch/relay/current; ls /opt/orch/releases` **ANSWERED (12 Oct 2026, read-only ssh/local): current = relay-0.1.0-661302a; also -9aa1731, -110cded, -dirty-f6539008 (naming relay-<version>-<sha>, dirty = wheel hash)** |
| U3 | The skeleton's `/healthz` body (does it carry `version: 0.1.0`?) | `curl -fsS http://127.0.0.1:8101/healthz` **ANSWERED (12 Oct 2026, read-only ssh/local): {"ok":true,"version":"0.1.0","instance":"public"} and ..."int"}; version equals the new build's** |
| U4 | `schema_migrations` of both existing databases (expected `0001_init` only) | `sqlite3 -readonly … 'SELECT * FROM schema_migrations'` **NOT OBTAINABLE read-only: data dirs are root:svc 0750; running release ships only 0001_init; operator checks as root** |
| U5 | Where the int database lives (`/srv/orch-relay-int/data` per `provision.sh`, while the given facts name only `/srv/orch-relay/data`) | `ls -la /srv/orch-relay*/data` **ANSWERED (12 Oct 2026, read-only ssh/local): int data = /srv/orch-relay-int/data (unit Environment); dir contents not listable by deploy** |
| U6 | Current `/etc/orch/relay.env` and `relay-int.env` contents (expected `VAPID_*` only) | `cat` **ANSWERED (12 Oct 2026, read-only ssh/local): names only: VAPID_SUBJECT, VAPID_PRIVATE_KEY_FILE, VAPID_PUBLIC_KEY_FILE in both files (150 and 158 bytes, mode 644 root:root, so they hold paths and an address, not key bytes); no ORCH_RELAY_* lines** |
| U7 | The email of the first provision run (Caddyfile global `email`) | `grep -n email /etc/caddy/Caddyfile` **ANSWERED (12 Oct 2026, read-only ssh/local): email agent@severin.io** |
| U8 | Whether Caddy access logs exist (for the 5xx/429 watch) | `grep -n log /etc/caddy/Caddyfile; ls /var/log/caddy` **ANSWERED (12 Oct 2026, read-only ssh/local): no access logs (no log directive, /var/log/caddy empty)** |
| U9 | Ubuntu release, nft and systemd versions (`MemoryPeak` needs systemd ≥ 255) | `lsb_release -ds; nft --version; systemctl --version` **ANSWERED (12 Oct 2026, read-only ssh/local): Ubuntu 26.04 LTS, nftables 1.1.6, systemd 259 (MemoryPeak OK)** |
| U10 | Phase A memory per node on the VPS Python (1.3 KB measured on macOS, CPython 3.14) | F7, or `tests/bench_publication_lockhold.py` on a VPS-like machine **NOT OBTAINABLE read-only (VPS CPython is 3.14.4; run the benchmark / F7)** |
| U11 | Whether a P3-capable orch-core host (bridge client) exists for pairing tests, and whether `orch-host-ws2` is enabled | ask orch-52; `systemctl is-enabled orch-host-ws2` **ANSWERED (12 Oct 2026, read-only ssh/local): no host on the VPS (orch-host-ws2, orch-publish-api, orch-app@ disabled and inactive); a local bridge client: ask orch-52** |
| U12 | Whether the phase-2 phone runs the checkpoint sync walk (§19.8 reads), and how it recovers after a relay restore | ask orch-f1 **ANSWERED (12 Oct 2026, read-only ssh/local): build has no relay transport and no checkpoint walk outside the fake host; restore recovery: ask orch-f1** |
| U13 | The remote e2e scenarios named in design §10 (they do not exist; who builds the G5 harness, and when) | orch-d6 / stream D **ANSWERED (12 Oct 2026, read-only ssh/local): design §10 G5 row (line 1137) names: P3 exit run, rotation race, restart during the outbox, a real-phone adapter; no remote harness or script exists in orch-relay/e2e or orch-relay/infra; owner and date still open** |
| U14 | How `provision.sh` reaches the VPS (a kit checkout there, or scp of the reviewed head) | `ls -la /root /opt` for a kit checkout **ANSWERED (12 Oct 2026, read-only ssh/local): no kit checkout; installed copy /usr/local/sbin/orch-dev-provision (root 0750, 11 Oct 01:39 UTC); reviewed head must be copied by an admin** |
| U15 | Whether the TestFlight build allows choosing the relay origin (paste/QR) or pins `relay.dev` | ask orch-f1 **ANSWERED (12 Oct 2026, read-only ssh/local): not yet: build has no relay transport (Demo only); later via pasted link or QR carrying the origin** |
| U16 | Other services running on the VPS and their memory (orch-publish, `orch-app@`, host, agent) | `systemctl list-units 'orch-*'; systemctl show … -p MemoryCurrent` **ANSWERED (12 Oct 2026, read-only ssh/local): only caddy (15 MB), orch-relay (49 MB), orch-relay-int (50 MB) run; orch-host-ws2, orch-publish-api, orch-app@ disabled** |

---

## 10. Findings of the read-only check (12 Oct 2026)

Done with read-only ssh as `deploy` plus local repo reads. Nothing was written on the VPS, the live databases were
not opened, and no env file contents were read (variable names only).

What changes the plan:

- **The VPS is not a skeleton at `246f3f3`.** `current` is `relay-0.1.0-661302a`. The release naming is
  `relay-<wheel version>-<short sha>`, or `relay-<version>-dirty-<wheel sha8>` for a dirty tree. Four releases are
  kept (`KEEP=5`). The dirty release carries a `0002_bad.sql` from a failed-migration rollback test; the pruning
  will drop it. Only `0001_init` exists in the running code, so the database is at `0001_init` at most.
- **`/healthz` cannot prove a deploy**: `version` is `0.1.0` in the old and new builds. Keep the stronger checks
  of §3.
- **Toolchain is fine**: Ubuntu 26.04 LTS, Python 3.14.4 at `/usr/bin/python3.14`, `uv` 0.12.23, systemd 259,
  nftables 1.1.6. HANDOVER's "24.04" is wrong for this host.
- **Data dirs are invisible to `deploy`** (`/srv/orch-relay` and `/srv/orch-relay-int` are `root:svc 0750`). The
  backup and wipe steps (§5) need root via the installed helpers, and the int database path comes from the unit
  `Environment`, `/srv/orch-relay-int/data`. U4 stays with the operator.
- **Env files**: `/etc/orch/relay.env` and `relay-int.env` hold exactly three names, `VAPID_SUBJECT`,
  `VAPID_PRIVATE_KEY_FILE`, `VAPID_PUBLIC_KEY_FILE`, mode 0644 root:root (150 and 158 bytes: paths, not key
  material). No `ORCH_RELAY_*` setting is there, so §4.3's separate settings file is still needed, and a
  provision run would overwrite these two files.
- **Caddy**: global `email agent@severin.io`; vhosts `relay.dev`, `relay-internal.dev`, `pub.dev` (to 8103) and
  `apps.dev` (to 8104), all `*.severin.io`. The last two have no running backend (units disabled), so they answer
  502. No `log` directive and an empty `/var/log/caddy`: there are no access logs for the 5xx/429 watch.
- **Memory**: 1961 MB total, 529 MB used, 1432 MB available, no swap, 35 GB disk free. Each relay is ~50 MB
  (peak ~51 MB), Caddy ~15 MB. That leaves room, but the §4.3 cap sizing (~350 MB per instance) still has to be
  validated by the benchmark (U10).
- **Provisioning**: `/usr/local/sbin/orch-dev-provision`, `orch-dev-reset` and `orch-unit` are installed, so
  `provision.sh` was already run (the installed copy was refreshed 11 Oct 01:39 UTC). No kit checkout is visible.
- **`deploy` cannot read the journal** (not in `adm` or `systemd-journal`), so log checks go through
  `sudo orch-unit logs <unit> [lines]`.
- **No host exists for pairing tests**: `orch-host-ws2`, `orch-publish-api` and `orch-app@` are `disabled`. The
  TestFlight build has no relay client yet (Demo mode only), so F6 (phone against the dev relay) cannot run
  until a build with a real transport exists. This is the largest surprise for the phone-side plan.

Still open (NOT OBTAINABLE read-only): U4 (database `schema_migrations`), U5 file listing, U10 (benchmark on the
VPS), U11 local bridge-client status (orch-52), U12 restore-recovery behaviour (orch-f1), U13 owner and date of the
G5 remote harness.

## 11. Decision of 12 Oct 2026 and cleanup list

**Decision (orch-d6): this plan is merged as documentation only. No dev deploy yet.** With no real relay client in the phone build (Demo mode only) and no P3 bridge client in orch-core, nothing could use the relay. The deploy waits until one of them exists, and then still needs orch-d6's explicit approval. The throwaway VM for the nft and systemd checks must be Ubuntu 26.04, the real VPS OS (the local VM is installed by the owner).

**Cleanup list (found by the read-only check; no action now):**
- The `-dirty` release on the VPS contains a leftover `0002_bad.sql` from a rollback test. Remove that release directory (or never point `current` at it) before any deploy, so a stray migration file cannot be applied.
- Caddy serves `pub.dev` and `apps.dev` with no running backend (ports 8103/8104): they answer 502. Remove the vhosts or start the services; outside this plan.
- Four releases sit under `/opt/orch/relay`; prune old ones after the deploy settles.
- `/healthz` reports version `0.1.0` for every build; a build identifier in the health body would make the post-deploy check meaningful.
