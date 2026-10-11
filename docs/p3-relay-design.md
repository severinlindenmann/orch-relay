# P3 relay design: directory, bridge v2, members and epochs, checkpoints

Status: **draft for the Codex challenge**, 11 Oct 2026 (stream D, orch-4e). This document decides and maps; the wire
contract stays [`protocol-v2.md`](protocol-v2.md) plus `tests/vectors_v2.json`. Every decision below that changes the
wire is carried into protocol-v2 by implementation group G0 (§10) before any code is written (contract first).

Inputs: orch-core spec `orch-v2.md` (§4, §5, §6.1, §6.2, §13 P3 row, D1–D62), ticket format F1
(`orch-v2-ticket-format.md` §5.3, §5.5, §5.10, §5.11), protocol-v2 (all), the relay skeleton (`src/orch_relay`), issues
orch-relay #5, #6, #7, #8, #11, #12, #24, #31, and orch-mobile `docs/gaps.md` (Slice 1 additions) with the FakeRelay
(`OrchKit/Sources/OrchFakeHost/FakeRelay.swift`) and `docs/host-api-v0.md` §1, §3.

Naming: **P3-Dn** is a decision taken here; **§n** is this document; **proto §n** is protocol-v2; **F1 §n** is the
ticket format; **spec §n / Dn** is `orch-v2.md`.

## 1. Scope and non-goals

P3 delivers, in orch-relay:

- **Directory** (spec §6.1): accounts by invite, device certificates, revocations, cards, sessions (device-key and
  WSK challenge login).
- **Members and epochs** (spec §5.4, proto §7.2–7.3): member lists, WK grants, card-key wraps, rotation (including the
  abandon path), the relay side of revocation (#12 relay half).
- **Bridge v2** (spec §6.2, proto §8): per-device request mailboxes, host and device long polling, response chunks,
  the relay's replay store, the pairing transport (#11 relay half) and the `cert_pending` queues (proto §8.4).
- **Signed checkpoints** (F1 §5.10): the relay as a checkpoint receiver, including the restore↔chain binding (#31).
- **Protocol change #24** (D39–D41, D45/D46 fold-in) and the #31 relay-model items.
- The **HTTP contract the host's bridge client** (orch-core, stream A, P3 core side) builds on (§9).

Exit (spec §13 P3): a device ↔ workspace over the dev relay with epoch rotation and checkpoints tested (§11 Q4 on
"desktop browser").

Non-goals (later phases): push and APNs registration (P4, #13), the pairing fallback page and
`/.well-known/apple-app-site-association` (P4, #11), Drop of any kind (P4 basics #25, P6), ws→ws mailboxes (P6, #20;
the table is not even created in P3), orch-publish (P5), scoped agent enrolment (P6, #18), second accounts' invite
flows and colleague UIs (P8, #21), the internal relay installer (#22). Type scope and the WebAuthn replacement stay out
(mobile D-5).

## 2. Components and data model

One FastAPI process per instance (`orch-relay`, `orch-relay-int`, ports 8101/8102), SQLite in WAL mode, migrations by
the existing runner. Shipped code never imports `ref/` (proto header): G1 adds `src/orch_relay/proto/` (strict JSON,
`cj`, b64u, suite-2 verify, signed-object and card/list/grant/revocation checks, ORB2 header parsing, F1 event
envelope for `restore`), tested against the same vectors as `ref/`. `cryptography` moves from the dev group to runtime
dependencies.

**P3-D15 (one worker).** Each instance runs one uvicorn worker. Long-poll wakeups, challenge stores and rate windows
live in process memory; everything that must survive a restart (deploys restart often) is in SQLite.

Modules and tables (`*` = primary key). Times are integer ms of the relay clock unless named otherwise.

**directory** (`src/orch_relay/directory/`)

| Table | Columns | Notes |
|---|---|---|
| `invites` | `code_hash*`, `created_ms`, `expires_ms`, `used_ms`, `used_by` | SHA-256 of the code; single use (P3-D3) |
| `accounts` | `person_id*`, `pk_pub`, `created_ms` | one per person (spec D5) |
| `devices` | `device_id*`, `person_id`, `cert` (signed JSON), `dk_sig_pub`, `dk_kx_pub`, `scopes_max`, `expires_ms`, `stored_ms` | proto §6.1; `label_sealed` stays opaque |
| `revocations` | `device_id*`, `person_id`, `record`, `revoked_ms`, `received_ms`, `cursor` (autoincrement) | proto §6.2; permanent; `cursor` drives the host feed |
| `workspaces` | `workspace_id*`, `owner_person_id`, `wsk_pub`, `delegation`, `card`, `card_seq`, `wxk_version`, `client_hosted`, `updated_ms` | proto §7.1; only the cleartext and the opaque sealed part |
| `card_key_wraps` | `(workspace_id, device_id, card_seq)*`, `sealed` | host-api v0 §3, proto §5.3 purpose `card` |
| `sessions` | `token_hash*`, `kind`, `subject_id`, `expires_ms` | proto §12.2; SHA-256 of the bearer token |

**members** (`src/orch_relay/members/`)

| Table | Columns | Notes |
|---|---|---|
| `member_lists` | `(workspace_id, list_seq)*`, `epoch`, `list`, `accepted_ms` | proto §7.2; the highest `list_seq` is current |
| `members` | `(workspace_id, device_id)*`, `person_id`, `scopes` | the current list, exploded for joins |
| `ever_members` | `(workspace_id, device_id)*`, `first_list_seq` | every device ever listed; used by §6 rule R4 |
| `epochs` | `workspace_id*`, `current_epoch`, `retired_through` | P3-D7 watermark |
| `wk_grants` | `(workspace_id, device_id, epoch)*`, `grant` | spec §6.1 calls this `memberships` |

**bridge** (`src/orch_relay/bridge/`)

| Table | Columns | Notes |
|---|---|---|
| `bridge_msgs` | `n*`, `workspace_id`, `device_id`, `rid`, `kind` (`req`, `resp`, `pair_req`, `pair_resp`), `offer_id`, `idx`, `flags`, `envelope`, `digest`, `received_ms`, `expires_ms`, `taken_ms` | sealed bodies, 60 s from receipt (proto §8.9), never extended by polls |
| `rid_seen` | `(workspace_id, device_id, rid)*`, `digest`, `expires_ms` | relay replay store, 900 s (P3-D9) |
| `cert_requests` | `request_id*`, `workspace_id`, `person_id`, `primary_device_id`, `request`, `expires_ms`, `state`, `challenge`, `cert_device_id`, `rejection`, `gc_ms` | proto §8.4 queues (P3-D11) |

**checkpoints** (`src/orch_relay/checkpoints/`)

| Table | Columns | Notes |
|---|---|---|
| `checkpoint_held` | `workspace_id*`, `genesis`, `n`, `checkpoint`, `at`, `accepted_ms` | the held H (F1 §5.10) |
| `checkpoint_history` | `(workspace_id, n)*`, `checkpoint`, `accepted_ms` | last 16, audit only |
| `restores` | `restore_id*`, `workspace_id`, `log`, `from_seq`, `line`, `bundle_n`, `accepted_ms` | applied ids (#31 b) and the bundles served to devices; permanent |

Not stored anywhere: `WK`, `CK`, pairing secrets, names, labels in clear, bridge plaintext. The #6 acceptance test greps
the database after a full flow for the fixture's names and descriptions.

## 3. HTTP API

**P3-D1 (routes).** All routes start with `/v2`. Bodies reuse the shapes the phone's FakeRelay already speaks
(host-api v0 §1, §3) **without the `host_api` field** and without the `Orch-Host-API` header, which stay the phone's
host-view adapter versioning. Errors are proto §14's `{"error": code, …}`. JSON is proto §2.3 strict; unknown fields,
duplicate keys and bad encodings are 400 `malformed`. `Retry-After` is integer delta-seconds (gaps Slice 1). orch-mobile
changes its route prefix and drops `host_api` on relay routes only (stream C, small).

Auth column: **none**; **D** device session; **W** workspace session (subject = that workspace); **D(m)** device session
of a current, unrevoked member of `{ws}` (proto §8.9); **D(p)** device session of the same person.

### 3.1 Directory and sessions

| Method, path | Auth | Request → response | Idempotency, limits | Refusals | Proto |
|---|---|---|---|---|---|
| `POST /v2/session/challenge` | none | `{}` → `{challenge, expires_ms}` | 60 s, single use; ≤ 16 outstanding and 60/min per client address (P3-D17) | 429 `rate_limited` | §12.2 |
| `POST /v2/session/login` | none | `{challenge, kind: "device"\|"workspace", id, sig}` → `{token, expires_ms}` | challenge consumed on every attempt; session 15 min, no refresh | 400 `malformed`; 401 `unknown_challenge`, `expired`, `bad_signature`; 403 `revoked`; 400 `cert_expired`, `cert_invalid` | §12.2, §4 below |
| `POST /v2/session/logout` | D or W | `{}` → `{}` | idempotent | 401 `unauthenticated` | new |
| `POST /v2/accounts` | none | `{invite, pk_pub, device_cert}` → `{person_id}` | invite single use, 7 days; same body after success → 200 | 400 `malformed`, `cert_invalid`; 403 `not_eligible` (invite unknown, used, expired: one code, no oracle); 409 `account_exists` | spec §6.1 (P3-D3) |
| `PUT /v2/devices/{device}` | D(p) or W (card owner = cert person, or person in its list) | `{cert}` → `{device_id}` | same cert → 200; another cert for a stored id → 409 `cert_conflict` | 400 `cert_invalid`, `cert_expired`; 403 `revoked`, `other_person` | §6.1, §8.3 step 6.1, §8.4 step 6 |
| `GET /v2/devices/{device}` | D(p), or W whose list or owner covers the person | → `{cert}` | | 403 `not_eligible`; 404 `not_found` | §6.1 |
| `POST /v2/revocations` | D(p) | `{record}` → `{device_id}` | same record → 200; effects in §5.3 | 400 `malformed`; 401 `bad_signature`; 403 `other_person` | §6.2 (P3-D5) |
| `GET /v2/devices/{device}/revocation` | none | → `{record}` | 60/min per address, windows pruned | 404 `not_found`; 429 | §6.2, gaps 24 |
| `GET /v2/persons/{person}/revocations?after=<cursor>` | D(p), or W whose list or owner covers the person | → `{revocations: [record], cursor}` | at most 256 per page | 403 `not_eligible` | §6.2 "directory poll" |
| `PUT /v2/workspaces/{ws}/card` | none for the first card; W after (P3-D4) | `{card}` → `{card_seq}` | same card → 200; update rules of proto §7.1 | 400 `malformed`, `wrong_suite`, `delegation_mismatch`; 401 `bad_signature`; 403 `other_person` (no account for the owner); 409 `other_workspace`, `wsk_changed`, `delegation_changed`, `stale_card`, `wxk_changed_without_version`, `bad_wxk_version` | §7.1 |
| `GET /v2/workspaces/{ws}/card` | D(m) or W | → `{card}` | | 403 `not_eligible`; 404 | §7.1, host-api §3 |

**P3-D3 (accounts).** Accounts come only from single-use invite codes made by the relay admin CLI
(`orch-relay invite create --ttl 7d`, printed once, stored hashed). The first device certificate is the proof of
possession of `PK` (it is `PK`-signed under `sig_device_cert`), so no new label is needed. The "first-run owner" of
spec §6.1 is the admin who runs the CLI; the relay has no pages (D54). The e2e harness runs the CLI over SSH.

**P3-D4 (first card without a session).** A workspace session needs a known card, so the first `PUT card` takes no
session. It is self-authenticating (the account's `PK` signs the delegation, `WSK` signs the card) and rate-limited per
address and per workspace. Every later card needs the workspace session.

**P3-D5 (revocations).** Posting needs a device session of the same person (the primary, or a recovered device, D50).
The authority is still the `PK` signature alone; the session only bounds abuse. Reading one record takes no session
(owner's decision, gaps 24).

### 3.2 Members and epochs

| Method, path | Auth | Request → response | Idempotency, limits | Refusals | Proto |
|---|---|---|---|---|---|
| `PUT /v2/workspaces/{ws}/grants` | W | `{grants: [wk_grant]}` → `{stored: n}` | per `(device, epoch)`: same bytes → no-op; other bytes → 409 `grant_conflict`; ≤ 1024 per call | 401 `bad_signature`; 403 `revoked`, `other_person`, `cert_expired`; 409 `retired_epoch`, `bad_epoch` | §7.3 |
| `PUT /v2/workspaces/{ws}/members` | W | `{member_list}` → `{list_seq, epoch}` | same list → 200 | 401 `bad_signature`; 403 `revoked`, `other_person`, `scope_exceeded`; 409 `other_workspace`, `stale_list`, `bad_epoch`, `rotation_required`, `missing_grant`, `retired_epoch` | §7.2 |
| `POST /v2/workspaces/{ws}/rotation-abandon` | W | `{abandon}` → `{retired_through}` | repeat at the watermark → 200 | 401 `bad_signature`; 409 `bad_epoch` | new (P3-D7) |
| `PUT /v2/workspaces/{ws}/card-keys` | W | `{card_seq, wraps: [{device_id, sealed}]}` → `{stored: n}` | same → no-op; `card_seq` must be the current card's | 403 `revoked`, `other_person`; 409 `stale_card` | §5.3, host-api §3 |
| `GET /v2/workspaces/{ws}/grants[?epoch=e]` | D(m) | → `{grants: [wk_grant]}` (own device only, ascending epoch) | | 403 `not_eligible`, `revoked`; 404 | §7.3, host-api §3 |
| `GET /v2/workspaces/{ws}/members` | D(m) or W | → `{member_list}` | | 403; 404 | §7.2, host-api §3 |
| `GET /v2/workspaces/{ws}/card-key?card_seq=N` | D(m) | → `{workspace_id, device_id, card_seq, sealed}` | | 403; 404 | host-api §3 |

Write-time re-check (gaps Slice 1): a grant or card-key wrap is accepted only if, in the same transaction as the
write, the session is live, the card is current, the device certificate is stored, belongs to the card owner or to a
person of the current list (P3-D6), is unexpired now and not revoked, and the epoch is not retired. Membership is not
required at upload (grants come before the list, proto §7.2).

**P3-D6 (member list with persons, D39).** Each member entry becomes `{device_id, person_id, scopes}`, and the list
gains `persons: [person_id]` (sorted, unique, the persons whose devices may appear). Check 8 becomes: the certificate's
`person_id` is the card owner **or** is in `persons`; `other_person` otherwise. `persons` is the host's WSK-signed
statement; the relay cannot replay the workspace log's `member.added`. That is acceptable: a WSK holder can leak `WK`
anyway, and readers of the log still replay authorization (F1 §5.11). In P3 every list has one person in practice.

**P3-D7 (rotation abandon, adopted from orch-mobile).** A host that uploaded grants for `e+1` and lost `WK_{e+1}`
before publishing the list posts a WSK-signed `{"o": {v, suite, kind: "rotation_abandon", workspace_id, epoch}, sig}`
(label `orch/v2/sig/rotation-abandon|`, new in proto §3). The relay accepts `epoch == max(current list epoch,
retired_through)` or that plus 1, raises `retired_through`, and deletes that epoch's grants. Lists and grants never
reuse a retired epoch; check 6 becomes "the previous epoch + 1, or `retired_through` + 1 after an abandon". This
matches the FakeRelay's amendment (gaps "Slice 2a rotation amendment"); its local label changes to the protocol one.

### 3.3 Bridge, pairing and the `cert_pending` queues

| Method, path | Auth | Request → response | Idempotency, limits | Refusals | Proto |
|---|---|---|---|---|---|
| `POST /v2/workspaces/{ws}/bridge/{rid}` (device) | D(m) | raw ORB2, direction 1 → 202 `{}` | ≤ 1 MiB whole envelope; P3-D9 replay store; ≤ 128 live mailboxes per device per workspace, ≤ 20 posts/s per session | 400 `malformed`, `wrong_suite`; 403 `not_for_this_device`, `not_eligible`, `revoked`; 409 `rid_conflict`, `stale_epoch` (`epoch`); 429 `quota_exceeded`, `rate_limited` | §8.1, §8.9 |
| `GET /v2/workspaces/{ws}/bridge/{rid}?after=i&wait=s` (device) | D(m), own mailbox | → `{chunks: [{id, idx, last, stream, envelope}]}` | non-consuming; `wait` 0–25 s; ≤ 6 concurrent polls and 10/s per session | 403; 401 `unauthenticated` | §8.8, host-api §1 |
| `GET /v2/workspaces/{ws}/host/poll?wait=s&holder=h[&take_over=1]` | W | → `{requests: [{route: "bridge"\|"pair", device, rid, offer, envelope}], notices: {revocations_cursor, cert_requests: [{request_id, state}], rotation_due}, lease_s: 40}` | consuming (`taken_ms`), ≤ 16 requests per poll; one holder per workspace, lease 40 s (TIX v1) | 409 `holder_conflict`; 401 | §8.6 input, P3-D10 |
| `POST /v2/workspaces/{ws}/bridge/{rid}` (host) | W | raw ORB2, direction 2 → 202 `{}` | ≤ 256 KiB whole chunk; duplicate digest → no-op; ≤ 8 MiB undelivered per workspace | 400; 403 `not_eligible`, `revoked` (header device left or was revoked); 429 | §8.1, §8.9 |
| `POST /v2/workspaces/{ws}/pair/{offer}/{rid}` | none (device) / W (host answer) | raw epoch-0 ORB2 → 202 `{}` | ≤ 64 KiB; 60/min per workspace and per address; route = header ws/stream/rid | 400; 401 `unknown_workspace`; 429 | §8.3, §8.9, host-api §3 |
| `GET /v2/workspaces/{ws}/pair/{offer}/{rid}?after=i&wait=s` | none | → `{chunks: […]}` | 120/min per address | 429 | §8.3 |
| `POST /v2/persons/{person}/cert-requests` | W (card owner = person) | `{request}` (WSK-signed) → `{request_id}` | same → 200; one open per workspace (relay mirrors the primary's rule) | 401 `bad_signature`; 403 `other_person`, `not_for_this_device`; 409 `request_open`, `replayed` | §8.4 step 1 |
| `GET /v2/persons/{person}/cert-requests?wait=s` | D(p), addressee only | → `{requests: [request]}` | open requests only | 403 | §8.4 step 2 |
| `POST /v2/cert-requests/{request_id}/challenge` | D(p), addressee | `{challenge}` (PK-signed) → `{}` | one per request; same bytes → 200 | 401 `bad_signature`; 409 `replayed`; 410 `expired` | §8.4 step 3 |
| `POST /v2/cert-requests/{request_id}/rejection` | D(p), addressee | `{rejection}` (PK-signed) → `{}` | idempotent | 401; 409 `already_signed` | new (P3-D11) |
| `GET /v2/cert-requests/{request_id}` | W (requester) | → `{state: "open"\|"challenged"\|"signed"\|"rejected"\|"expired", challenge, cert, rejection}` | kept until expiry + 60 s | 404 | §8.4 steps 4, 6 |

**P3-D8 (epoch at the relay).** A device request whose header epoch is not the current list epoch is refused with
409 `stale_epoch {"epoch": current}`. This is an unsigned hint: the device refetches the list and its grant (both
signed) and resends as a new request; it never raises its epoch from the hint (gaps Slice 2a). The host's sealed
`stale_epoch` (proto §8.5) stays for the race where the list moves between the relay's check and the host's read. This
meets #7's "wrong-epoch envelopes are rejected" and keeps old-epoch traffic off the host.

**P3-D9 (relay replay store).** The relay never checks `seq` or `ts_ms`: the host answers those with sealed refusals the
device can verify (proto §8.6, §15), and a relay drop would stop the clock-offset rule. The relay keeps
`(ws, device, rid) → digest` for 900 s (proto §15's rid record time). The same bytes again are re-queued (the host
answers from its rid store; mobile U8 re-sends byte for byte); other bytes under a seen rid are 409 `rid_conflict`.

**P3-D10 (host poll).** One multiplexed, consuming host long poll carries bridge and pairing requests plus notices
(new revocations for its persons, changes of its cert requests, `rotation_due`). One holder per workspace with a 40 s
lease, as in TIX v1, so a second copy of a workspace cannot silently take its requests (`take_over=1` forces it and is
logged). Every wake slice (2 s) re-checks the session, revocation and membership, so nothing is handed to a device or
host that lost its right while waiting.

**P3-D11 (cert queues and rejection).** The three proto §8.4 queues get the routes above (gaps 22, Slice 2b). The
relay verifies the request against the card's `WSK`, the challenge and the rejection against the account's `PK`, and
serves the challenge only to the requesting host. A rejection is a new signed kind
`cert_rejection {v, suite, kind, request_id, workspace_id, person_id}` under `orch/v2/sig/cert-rejection|`, so nobody
who merely learns a request id can cancel a pairing. The phone still sees only `rejected` through the host.

**P3-D16 (scopes).** The relay enforces membership on the bridge, not route scopes: the op and its scope are sealed
(proto §8.6 step 11 is the host's). The typing lease has no relay part.

### 3.4 Checkpoints

| Method, path | Auth | Request → response | Idempotency, limits | Refusals | Proto |
|---|---|---|---|---|---|
| `PUT /v2/workspaces/{ws}/checkpoint` | W | `{checkpoint}` or `{checkpoint, restore: {line, cert}}` → `{result: "accepted"\|"ignored", n}` | same checkpoint → `accepted`; ≤ 1 MiB, ≤ 10 000 tickets (§11 Q7) | 400 `malformed`, `wrong_suite`; 401 `bad_signature`; 409 `chain_diverged`, `genesis_mismatch`, `restore_invalid`, `restore_not_owner`, `restore_reused`, `restore_stale`, `restore_missing_revocation` (`devices`) | new §7.6 (§6) |
| `GET /v2/workspaces/{ws}/checkpoint[?since_n=k]` | D(m) or W | → `{checkpoint, restores: [{line, cert, checkpoint}]}` (bundles with `n > k`, ascending) | | 403; 404 | new §7.6 |

**P3-D12.** The relay accepts and stores **workspace** checkpoints only; a workspace checkpoint already names every
ticket's `{seq, head}`. `ticket_checkpoint` objects are not published to the relay in P3.

### 3.5 HTTP refusal codes added to proto §14

401 `unauthenticated`; 403 `not_eligible`, `not_for_this_device` (already listed for Drop and cert requests, now also
for the routes above); 404 `not_found`; 409 `account_exists`, `cert_conflict`, `grant_conflict`, `retired_epoch`,
`rid_conflict`, `stale_epoch` (`epoch`, unsigned hint), `holder_conflict`, `request_open`, `replayed`,
`already_signed`, `chain_diverged`, `genesis_mismatch`, `restore_invalid`, `restore_not_owner`, `restore_reused`,
`restore_stale` (`server_ms`), `restore_missing_revocation` (`devices`); 410 `expired`; 429 `rate_limited`,
`quota_exceeded` (both with `Retry-After`).

## 4. Auth and sessions

- **Login** is proto §12.2 unchanged: `sig` over `"orch/v2/sig/relay-auth|" || suite || lp16(origin) || challenge ||
  kind || id`, with `origin` the instance's configured origin (`ORCH_RELAY_ORIGIN`, e.g.
  `https://relay.dev.severin.io`), never one the client names. Check order: challenge known (removed whatever follows)
  → unexpired → `kind` → signature.
- **Keys.** `device`: `dk_sig_pub` of the stored certificate. `workspace`: `wsk_pub` of the stored card.
- **Unknown identity.** An unknown `id` (or a kind without a stored key) verifies against a fixed dummy P-256 key, so
  the timing matches, answers the same 401 `bad_signature` and still consumes the challenge (gaps Slice 1).
- **Revoked devices get no session** (owner's decision): 403 `revoked`, answered **only after the signature verified**,
  so strangers cannot probe revocation state. An expired certificate is 400 `cert_expired`. The device then reads its
  record on the session-less route and verifies it against its pinned `PK` before wiping (host-api §3).
- **P3-D2 (session scope).** One bearer token per login, valid 15 minutes, no refresh (log in again). A device token
  is scoped to the relay; each route authorizes against the workspace's **current** list and the revocation table at
  request time (gaps 23). A workspace token is scoped to its workspace. Tokens are stored as SHA-256 hashes; agents
  never see them (spec §5.5).
- **P3-D17 (caps).** Challenges: at most 16 outstanding and 60 issued per minute per client address; a global ceiling
  of 65 536 sheds the oldest, never the new request. Rate windows are pruned on every request. The client address is
  the peer address, or Caddy's `X-Forwarded-For` only when the peer is the configured proxy.
- **Revocation ends sessions at once** (§5.3), and every long poll re-checks within 2 s.

## 5. Members and epochs

### 5.1 How lists and grants reach the relay and the devices

1. The host rotates (spec §5.4, proto §7.2 host rules): at startup and daily for the 90-day age, on a revocation it
   learns of (host poll notice, revocation feed, bridge op `revocation`), on `member_remove`, on `orch keys rotate`.
2. It generates `WK_{e+1}`, `PUT grants` for every remaining device, then `PUT members` with `epoch = e+1`. The relay
   checks proto §7.2 (with P3-D6 and P3-D7) and refuses a list whose grants are missing (`missing_grant`). A crash
   between 2 and 3 with the key lost → `rotation-abandon`, then a fresh `e+2`.
3. On acceptance the relay deletes the departed devices' request mailboxes, queued responses, grants and card-key wraps
   (and, from P4, push registrations).
4. Devices fetch `members` and `grants` at connect and on a `stale_epoch` (relay hint or host refusal). A device moves
   its current epoch only to an epoch confirmed by a verified list (proto §7.3, gaps Slice 2a). Offline devices pick up
   their grant at the next connect (spec §5.4).
5. New devices (D26) get grants from the current epoch on; the relay never serves a grant older than the device's
   first list (`ever_members.first_list_seq` → epoch).

### 5.2 What the relay sees

It sees routing ids (workspace, device and person ids), each member's scopes, the epoch and `list_seq` numbers and when
they change, the card's cleartext (`wsk_pub`, `wxk_pub`, `wxk_version`, `owner_person_id`, `relay_url`,
`client_hosted`), and sealed grants and card-key wraps as opaque bytes. It never sees `WK_e`, `CK`, names, labels or
descriptions. It cannot forge a grant (WSK-signed, proto §7.3), a list (WSK-signed) or a card (delegation + WSK). It
can withhold or delay them; devices never move backwards (proto §7.3, §18 R6).

### 5.3 The relay side of revocation (#12, proto §6.2)

On `POST /v2/revocations` (or a revocation inside an accepted restore, §6.3 R4), in one transaction: verify against the
account's `PK` and the stored certificate's person; store it permanently; delete the device's sessions, request
mailboxes and queued responses, grants and card-key wraps in every workspace; refuse it on every route. It is not
deleted from member lists (they are WSK-signed); the relay refuses it anyway, refuses any later list naming it
(`revoked`), and sets `rotation_due` for each workspace whose current list names it. `rotation_due` is shown to the
host in the host poll until a list with a higher epoch is accepted; e2e asserts that the host rotated before sealing
anything new. There is no un-revoke (proto §6.2).

## 6. Signed checkpoints on the relay

### 6.1 What the host publishes, what the relay keeps

The host publishes its workspace checkpoint (F1 §5.10) after each burst of appends (debounced, at most one per 5 s), at
startup and daily. The relay verifies `{o, sig}` under the card's `wsk_pub` with the `sig/checkpoint|` label and the
exact field set, pins `genesis` on the first checkpoint (trust on first use; devices pin it at pairing, F1 §5.11), and
then judges each new checkpoint against its held H by F1 §5.10's receiver rules (accepted, ignored, `chain_diverged`),
which the F1 `checkpoint.json` vectors already pin. It keeps H with the relay time it accepted it (`accepted_ms`).

### 6.2 How receivers use it

- **The host** fetches H at startup and compares H's heads with its logs. H ahead of the logs with heads the logs do
  not contain, or a head at a shared `seq` that differs, is `chain.diverged`: the host refuses appends until an owner
  `restore`. This closes F1 §5.10's "what P1 can't detect" (history and local checkpoints both replaced).
- **Devices** fetch `checkpoint?since_n=` with their held n, apply the same receiver rules and the restore rules of §6.3
  with their own clock, persist the highest accepted H per workspace, and raise an alarm on `chain.diverged`.
- **The relay cannot** forge or lower a checkpoint (WSK), only withhold or serve an older one, which receivers ignore.

### 6.3 Restores and the binding to the chain

**The problem (#31 d).** F1 §5.10 lets a lower checkpoint through when it comes with a restore
`{id, log, from_seq, abandoned}`. Those fields are metadata; anyone holding `WSK` can sign any checkpoint. So a WSK
holder could pair an old, genuine owner-signed restore with a forged checkpoint and roll a receiver back without the
owner, for example behind a revocation or a decision.

**Options considered.**

| Option | Binds | Cost | Verdict |
|---|---|---|---|
| A. The offered log's entry must be exactly `from_seq + 1`, with `head = head(restore line)` | the post-restore state to the owner-signed event | the host publishes one checkpoint at exactly the restore, and the restore line is sent in full | **taken** (R1) |
| B. Checkpoints commit to the last restore per log (`{id, seq}` in each log entry) | later checkpoints to the restore history | F1 checkpoint shape change, core and vector change; the WSK holder signs the commitment too | not now; fallback if R2 is overturned |
| C. Freshness: the restore must be signed after the receiver accepted the H it abandons | old restores to their time | relies on the owner's clock in the ULID `id` | **taken** (R2) |
| D. Relay holds the logs and checks the chain | everything | the relay would read ticket content | rejected (spec §4) |

**P3-D13 (restore rules R0–R4; the relay, and devices with their own clock).** A restore is offered as `{line, cert}` next to a
checkpoint C (higher `n` than H). It is looked at only when F1 §5.10 says a restore is needed (the log drops below H,
or reaches H's `seq` with another head). Then, in this order:

- **R0 shape (#31 a, g).** `line` is a strictly parsed F1 event of type `restore` with the exact envelope and payload
  field set (F1 §5.1, §5.4.1): person actor, `sig`, `auth` and `roster_v` present (and on no other kind), `v = 2`,
  `hash_v = 1`, `ws_seq` present exactly for a ticket log. → `restore_invalid`.
- **R1 owner and chain (#31 a, d).** `host_sig` verifies under `wsk_pub` (`sig/host-event|`); `sig` verifies under the
  `dk_sig_pub` of `cert` (`sig/ws-event|` or `sig/ticket-event|`, F1 §5.3); `cert` is a stored, unexpired, unrevoked
  certificate of the **card owner** with `operate`, and `actor.device` is its id (→ `restore_not_owner`).
  `line.seq == from_seq + 1`, `line.prev == payload.head`, and C's entry for that log is **exactly**
  `{seq: from_seq + 1, head: head(line)}`. Every other log in C keeps its seq and heads per F1 (no drop, no other head
  at a shared seq). F1's other conditions hold: `from_seq < H.seq <= abandoned.seq`, equal heads when equal seqs. →
  `restore_invalid` or `chain_diverged`.
- **R2 freshness (#31 c, d).** `ulid_ms(payload id) >= H.accepted_ms − 300 s` and `<= now + 300 s`, and
  `line.at > H.o.at`. → `restore_stale` (with `server_ms`).
- **R3 single use (#31 b).** The id is not in `restores`. Every restore id the relay accepts, or sees inside any line
  it is given, is recorded permanently. → `restore_reused`.
- **R4 revocations (#31 e, f).** The restore payload (F1 change from stream A, owner decision 11 Oct) carries the
  revocations; each verifies under its person's account `PK`. The set must include every revocation the relay holds
  for a device in `ever_members` of this workspace. → `restore_missing_revocation` with the missing device ids.
  Revocations in the payload that the relay lacked are ingested as in §5.3.

On acceptance H is replaced by C, the id is recorded, and `{line, cert, checkpoint: C}` is kept as a bundle and served
by `GET checkpoint?since_n=` so devices that missed C can check the binding themselves. Later growth past
`from_seq + 1` is ordinary checkpoint growth.

**Why this closes the attack.** R1 pins the post-restore state to the owner's own statement (`payload.head`, signed
under the owner's device key); the WSK holder can re-wrap the line but cannot change where it attaches. R2 refuses a
restore signed before the receiver accepted the checkpoint it would abandon: an old genuine restore predates every
checkpoint of the regrown chain after it, so every receiver that holds such a checkpoint refuses it. This also covers
#31's "open (low)" items: a receiver that joined later, or whose H already sits on the regrown chain, accepted that H
after the old restore was signed. What remains: a receiver offline since before the restore can be served the
genuine restore bundle and nothing newer; that is withholding (accepted, spec §4), not forgery, and lands on a state
the owner signed. A legitimate restore signed before the relay accepted a newer checkpoint is refused; the owner signs
again (rare, fails closed).

**Requirement map (#31).**

| # | Requirement | Mechanism |
|---|---|---|
| a | verify the full owner-signed restore event | R0 + R1 (line, `host_sig`, `sig`, owner certificate with `operate`) |
| b | mark every restore id seen | R3, permanent `restores` table, ids from every line received |
| c | `restore.at > H.at` | R2 second clause (cheap; `at` is host-chosen) |
| d | tie the restore to the chain | R1 exact entry at `from_seq + 1` + R2 freshness against `accepted_ms` |
| e | never capture a restore without its revocations | by construction once revocations are inside the restore payload (stream A's F1 change); until then the host publishes the restore checkpoint only after the re-appends, under the store lock (§9) |
| f | own set of PK-signed revocations; refuse a restore lacking any | R4 against `revocations` ∩ `ever_members` |
| g | field set per actor kind | R0 strict envelope; vector added in G0 |

R2 relies on the restore `id` being a ULID whose time part is the signer's clock at signing (orch-core `new_ulid` does
this). G0 adds one line to F1 §5.1 saying so for `restore` (text only, no code change in core).

## 7. Protocol change #24 (and the #31 relay model)

Wording outline of the protocol-v2 amendment (G0, one PR, Opus security review):

| Section | Change |
|---|---|
| header, §1, §17/§18 | Suite 2 (P-256) is the only deployment suite (D46); suite 1 vectors stay as test-only. "PWA", "service worker", "Web Push" become the native app, the notification service extension and APNs (text only; push details stay P4). R2 and R5 closed by D45/D46. |
| §3 | New rows: `sig_rotation_abandon` `orch/v2/sig/rotation-abandon\|` (WSK), `sig_cert_rejection` `orch/v2/sig/cert-rejection\|` (PK). Prefix-free test extended. |
| §7.2 | Member entries `{device_id, person_id, scopes}` and `persons`; check 8 per D39 (P3-D6); check 6 with `retired_through` (P3-D7); state which rules bind the relay (publication) and which bind devices (snapshots, gaps Slice 0). |
| §7.6 (new) | Checkpoints and restores on the relay: §6 of this document (receiver rules by reference to F1 §5.10, the restore bundle, R0–R4). |
| §8.3 | Link `orch://pair?relay=…#v2…` and `https://<relay>/pair#…` (host-api v0 §3; `/app/pair` accepted as alias); passkey registration (step 6.4) removed (native, D45). |
| §8.4 | Queue routes; `cert_rejection` (P3-D11). |
| §8.7 | WebAuthn ops marked not used by native clients; their replacement (a detached `dk_sig` action signature with F1 `auth`) is deferred with Type (mobile D-5). |
| §8.9 | P3-D8 relay epoch hint, P3-D9 replay store, P3-D10 host poll, P3-D16; envelope limits count the whole envelope. |
| §12.2 | P3-D2 session scope; revoked devices get no session (403 after the signature); dummy-key verification; per-address caps. |
| §13 | Phone decisions: the host records a verified §13 decision verbatim as F1 `evidence` under a new event contract (core P3); a `decision_id` is single-use forever, across restores (§9). |
| §14 | §3.5 codes. |
| §19 (new) | Relay HTTP API: §3 tables of this document. |

#24's original checklist, item by item: check 8 (D39) → P3-D6. Ticket-event signature context (D40) → already in §3
from the F1 sync (`sig_ticket_event`, `sig_ws_event`, `sig_host_event`, `sig_checkpoint`; the issue's
`…|<workspace_id>|<uid>` form and `list_seq` were superseded by F1's `cj({contract, suite, workspace_id, log, event})`
and `roster_v`); only §13's evidence note is new. Checkpoints and restore → §7.6. Restricted tickets sealed to listed
persons' devices → **P3-D14: deferred to P8**: in P3 every member device belongs to the owner, mailboxes are per device,
and the host already refuses `not_visible`. Session grants → F1 `grant.issued` (not a protocol object). `presence` →
F1 `auth` (D64, D66). D45/D46 fold-in → header, §1, §8.3, §8.7 rows above.

#31 relay-model items → §4 (no session for revoked, session-less record, per-address caps, pruned windows, dummy key),
§5.3 (whole footprint), §2/§3.3 (retention by time, whole-envelope limits), §3.2 (write-time re-check), §3 P3-D1
(`Retry-After` delta-seconds). Per-workspace push replay is phone-side (P4). The #31 text items (refusal-order
differences, Drop chain identity, relay URL host rules, `-0`, byte-wise comparison, §2.5 Unicode) go into the same G0
PR because they touch the same sections; Drop chain identity is recorded for P4.

**Vectors to add (G0, both `ref/` and `tests/vectors_v2.json`, suite 2):**

- `member_lists` v2: a second person's device accepted when in `persons`, refused (`other_person`) when not; a person
  in `persons` with a revoked device; retired-epoch reuse refused; a jump to `retired_through + 1` accepted.
- `rotation_abandon`: valid, wrong key, epoch too far, idempotent repeat.
- `cert_rejection`: valid, signed by WSK instead of PK, other request id.
- `relay_auth` additions: revoked device after a valid signature (403), unknown id against the dummy key (401, challenge
  consumed), expired certificate.
- `checkpoints` (new section): the F1 `checkpoint.json` offers replayed through the relay rules, plus restore bundles:
  valid workspace restore; valid ticket restore; **old genuine restore + forged checkpoint** (`restore_stale`); offered
  seq above `from_seq + 1` (`restore_invalid`); head not `head(line)`; `line.prev` not `payload.head`; signed by a
  decide-only device; by another person's device (`restore_not_owner`); by a revoked device; reused id; `at` not after
  H; a missing revocation (`restore_missing_revocation`); `sig`/`auth`/`roster_v` on the wrong actor kind (#31 g); a
  ticket restore that lowers the workspace log.
- `bridge.relay_cases` (new): header device ≠ session, non-member, epoch hint, rid conflict, identical re-send
  re-queued, whole-envelope size limits.

## 8. Threat model delta for P3

| Attacker | Can | Cannot, because |
|---|---|---|
| **Relay operator or compromised relay** (honest-but-curious for confidentiality, untrusted for integrity, spec §4) | See routing ids, scopes, epochs, timing, sizes; see checkpoints (ticket uids, which carry creation times, seqs, heads, `at`) and restore lines (abandoned decision ids, revocations, the `reason` text, §11 Q2); drop, delay, replay, withhold; serve stale lists, cards, checkpoints | Read `WK`, bridge or card plaintext (sealed); forge grants, lists, cards, checkpoints, restores (WSK, PK and device signatures); roll a device back (monotonic epochs, `card_seq`, checkpoint n/seq on devices); seal its own `WK` to a device (grants are signed). New accepted leak: checkpoint metadata (activity per ticket). |
| **WSK holder** (stolen key; client-hosted machine admin, D29; P1-era agents) | Sign any card, list, grant, checkpoint; add a foreign person to `persons`; inflate checkpoints (checkpoint-only receivers accept forks grown past H, F1 limit) | Lower a chain at the relay or a device without a fresh owner-signed restore (R1 + R2); replay an old restore (R2, R3); drop a revocation through a restore (R4); get a session as a revoked device; change `wsk_pub` or the delegation (proto §7.1). Inflation is caught by the honest host comparing H with its logs (§6.2). |
| **Member device** (or a stolen unlocked phone, D49) | Act within its scopes until removed or revoked; read current-epoch content | Act after revocation (no session, mailboxes deleted, refused on every route, host rotates); read content sealed after rotation; queue for another device (header device = session, proto §8.9); cancel another pairing (P3-D11). |
| **Revoked device** | Read its own revocation record | Log in, poll, post, fetch grants, learn new epochs. |
| **Network attacker** (TLS assumed) | Observe timing; probe routes | Get sessions (single-use challenges bound to the relay origin); learn whether an id exists or is revoked (dummy key, revoked only after a valid signature); exhaust login for others (per-address caps). |

## 9. The interface between the host and the relay

The host's bridge client lives in orch-core (`orch serve`, stream A; P3 core side). It holds the workspace session;
agents never see it (spec §5.5). The contract is §3; this is what the host calls, in which order, and what it owes.

| Host does | Calls | Owes |
|---|---|---|
| Start | `session/challenge`, `session/login` (kind `workspace`); first run: `PUT card` | re-login on 401 and before 15 min; one host process per workspace (holder lease) |
| Learn revocations | `GET persons/{p}/revocations?after=` at startup and on a host-poll notice; bridge op `revocation` | rotate before sealing anything new (proto §6.2) |
| Rotate | `PUT grants` → `PUT members`; on a lost key `rotation-abandon` | order grants → list; seal nothing under the new epoch before the list is accepted, nothing new under the old one after |
| Card changes (WXK every 90 days) | `PUT card`, `PUT card-keys` | `card_seq` strictly rising; CK wraps only for certified devices |
| Serve devices | `GET host/poll` loop; `POST bridge/{rid}` per chunk | proto §8.6 order; persist the seq window and rid store atomically (gaps Slice 2a) |
| Pair | host poll `route: "pair"`; `POST pair/{offer}/{rid}`; `POST persons/{p}/cert-requests`, `GET cert-requests/{id}`; `PUT devices/{d}` | proto §8.3–8.4; no grant before a valid certificate |
| Checkpoints | `PUT checkpoint` (debounced), `GET checkpoint` at startup | compare H with the logs (§6.2) |
| Restore | sync revocations, build the restore, have the owner sign, append, `PUT checkpoint` with `restore: {line, cert}` and the log entry at exactly `from_seq + 1` | the restore checkpoint is published before any later checkpoint; under the store lock (#31 e) |
| Decisions | none at the relay | keep every admitted `decision_id` (and person-event id) in host state outside the logs, so a restore never re-enables one (#31 comment, proto §13) |

The relay offers the host nothing unsolicited: everything reaches the host through the host poll or its own fetches.
Stream A agrees or amends this table once its socket contract is published; disagreements go into the G0 PR.

## 10. Implementation groups

Each group is one PR into `develop` (Codex implements, Opus security-reviews every group: all touch auth, keys or the
protocol), merged after T2 green. Contract first: G0 lands before any code group.

| Group | Content | T0 (per task) | T1 | T2 extra | Depends |
|---|---|---|---|---|---|
| **G0 contract** | protocol-v2 amendment (§7), `ref/` and vectors (§7 list), F1 text line for R2 (orch-core, tiny PR) | `uv run pytest tests/test_vectors.py -x -q` | `uv run pytest -q -m "not slow"` + ruff | orch-mobile and orch-core vector runs on the new file | A's restore-payload PR (for R4 vectors) |
| **G1 directory** | `proto/` module, accounts and invites CLI, devices, revocations (§5.3 without member effects), sessions and auth (§4), cards | `uv run pytest tests/test_auth.py -x -q`, `tests/test_directory.py -k <case>` | `uv run pytest -q -m "not slow" tests/test_auth.py tests/test_directory.py tests/test_proto*.py` | `e2e/run.sh directory-basic`; grep test for names | G0 |
| **G2 members** | lists, grants, card-key wraps, rotation-abandon, revocation footprint and `rotation_due` | `uv run pytest tests/test_members.py -x -q` | members + directory tests | `e2e/run.sh rotate-epoch` (in-process host stub) | G1 |
| **G3 bridge** | mailboxes, device POST/poll with `wait`, host poll with lease, responses, replay store, pairing routes, cert queues, limits, TTL pruning | `uv run pytest tests/test_bridge_v2.py -x -q` (`-k replay`, `-k pair`) | bridge + members tests | `e2e/run.sh bridge-device`, `pair-device`, `revoke-device` | G2 |
| **G4 checkpoints** | receiver rules, restore bundle R0–R4, GET with `since_n` | `uv run pytest tests/test_checkpoints.py -x -q` | checkpoints + F1 vector tests | `e2e/run.sh checkpoint-rollback` | G2 (parallel with G3: disjoint files) |
| **G5 deploy and e2e** | Python device client (test support), deploy to the dev relay, the P3 exit run with orch-core's bridge client | per scenario `e2e/run.sh <name>` | | full P3 exit scenario | G3, G4, stream A's bridge client |

Order: G0 → G1 → G2 → (G3 ∥ G4) → G5. Vectors first within every group: each task's first commit is its failing
vector or targeted test.

## 11. Open questions

| # | Question | Recommendation |
|---|---|---|
| Q1 | Stream A's restore payload: every revocation the host holds for the workspace's devices, or only those the kept chain lacks? | **Every one.** Only the full set lets the relay check R4 without reading the log. Cross-stream request to orch-52 before A's PR merges. |
| Q2 | The restore `reason` is free text the relay (and every device) reads. | Make it a closed list in A's restore PR (`backup_restored`, `force_push`, `other`); until then the host UI says the reason is visible to the relay. |
| Q3 | Co-owners (D39) and mandates (D62, which the owner extended to restores) cannot sign restores the relay accepts under R1. | P3 accepts restores only from the card owner's devices. A mandate's key is host-held, so accepting it would hand restore power back to the WSK holder; a mandate restore stays local until the owner signs. Tell orch-fa and orch-52; revisit co-owners in P8 with roles in the list. |
| Q4 | Spec §13's exit says "desktop browser", but D54 (no relay pages) and D45 (native app) remove the browser client of #8. | Run the exit with a Python suite-2 device client in the e2e harness; close #8 as superseded. |
| Q5 | Should the host also publish `ticket_checkpoint` objects? | No (P3-D12); add later only if a device needs per-ticket checkpoints without the workspace one. |
| Q6 | Option B (checkpoints commit to the last restore per log) as defence in depth? | Not now; take it if the Codex challenge rejects R2's reliance on the signer's clock. |
| Q7 | Workspace checkpoints grow with the ticket count and are sent whole. | Cap at 1 MiB and 10 000 tickets in P3; design a delta form when a real workspace approaches it. |
| Q8 | The relay pins `genesis` on first use. | Accept: binding it to the card adds nothing (both WSK-signed), and the delegation predates the genesis. Devices pin from pairing; a mismatch alarms. |
| Q9 | The relay's 409 `stale_epoch` hint (P3-D8) is new to the phone's FakeRelay. | Keep; orch-mobile treats it like any unsigned relay error: refetch list and grants, never trust it. |
| Q10 | Should the relay refuse response chunks at the pre-rotation epoch once `rotation_due` is old? | No: a revoked device has no session and cannot fetch them; the host's rotation duty plus the e2e check suffice. Revisit if a relay-compromise-plus-revoked-key scenario is in scope. |
