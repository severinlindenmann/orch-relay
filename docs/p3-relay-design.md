# P3 relay design: directory, bridge v2, members and epochs, checkpoints

Status: **revision 2**, 11 Oct 2026 (stream D, orch-4e), after the Codex challenge; the challenge log is §12. This
document decides and maps. The wire contract stays [`protocol-v2.md`](protocol-v2.md) plus `tests/vectors_v2.json`.
Every decision below that changes the wire goes into protocol-v2 in group G0 (§10), with shared vectors and HTTP
fixtures, before any code is written (contract first).

Inputs:

- orch-core spec `orch-v2.md`: §4, §5, §6.1, §6.2, the §13 P3 row, D1–D62.
- Ticket format F1 (`orch-v2-ticket-format.md`): §5.3, §5.5, §5.10, §5.11.
- protocol-v2 in full, and the relay skeleton.
- orch-relay issues #5, #6, #7, #8, #11, #12, #24 and #31.
- orch-mobile `docs/gaps.md` (Slice 1 additions), its FakeRelay and `docs/host-api-v0.md` §1 and §3.
- Stream A's decisions of 11 Oct on the restore payload (Q1–Q3, see §6.4).

Naming:

- **P3-Dn** is a decision taken here.
- **§n** is this document, **proto §n** is protocol-v2, **F1 §n** is the ticket format, **spec §n / Dn** is
  `orch-v2.md`.
- **Cn** is a Codex challenge finding (§12).

## 1. Scope and non-goals

P3 delivers, in orch-relay:

- **Directory** (spec §6.1): accounts by invite, device certificates, revocations, cards and sessions (device-key and
  WSK challenge login).
- **Members and epochs** (spec §5.4, proto §7.2–7.3): atomic membership publication (the member list, its WK grants
  and its card-key wraps), and the relay side of revocation (the relay half of #12).
- **Bridge v2** (spec §6.2, proto §8):
  - per-device request mailboxes and response chunks;
  - a durable host cursor with fencing;
  - the relay's replay store;
  - the pairing transport (the relay half of #11);
  - the `cert_pending` queues (proto §8.4).
- **Signed checkpoints** (F1 §5.10): an owner-signed genesis pin, and restores as owner-signed transitions with a
  served transition history. This fixes the restore↔chain binding of #31.
- **Protocol change #24** (D39–D41, with the D45/D46 fold-in) and the relay-model items of #31.
- The **HTTP contract the host's bridge client** builds on (§9). That client is orch-core, stream A, on the P3 core
  side.

**Exit criterion.** Spec §13 asks for "desktop browser ↔ workspace over the dev relay, with epoch rotation and
checkpoints tested". This becomes: a Python suite-2 device client ↔ workspace host over the dev relay, plus one native
orch-mobile adapter smoke run, with rotation, revocation and a restore walk tested. That is a spec amendment (Q4).

**Non-goals (later phases):**

- push and APNs registration (P4, #13);
- the pairing fallback page and `/.well-known/apple-app-site-association` (P4, #11);
- Drop (P4 basics #25, P6);
- ws→ws mailboxes (P6, #20; no table in P3);
- orch-publish (P5);
- scoped agent enrolment (P6, #18);
- invite flows for colleagues (P8, #21);
- the internal relay installer (#22);
- Type scope and the WebAuthn replacement (mobile D-5).

**Deferred convenience (C2).** No audit history of checkpoints, and no relay-side listing beyond what clients need.
The first group that runs code ends with a real vertical slice: device ↔ relay ↔ host stub (§10, G3).

## 2. Components and data model

**Process.** One FastAPI process per instance (`orch-relay`, `orch-relay-int`), SQLite in WAL mode, migrations by the
existing runner. Shipped code never imports `ref/`. Group G1 adds `src/orch_relay/proto/`, which holds:

- strict JSON, `cj` and b64u;
- suite-2 verification;
- the signed-object, card, list, grant and revocation checks;
- ORB2 header parsing;
- the F1 event envelope for `restore`.

It is tested against the same vectors as `ref/`. `cryptography` becomes a runtime dependency.

**P3-D15 (one worker, durable, off the loop; C1).** Each instance runs one uvicorn worker:

- Long-poll wakeups, challenges and rate windows live in memory.
- Everything else is in SQLite with `synchronous=FULL`, so commits survive a power loss. G3 measures the bridge's write
  cost; if needed, only the `bridge_msgs` writes move to a second database file with `NORMAL`.
- All SQLite work runs in the thread pool, never on the event loop.
- Restart recovery: rebuild wakeups from the tables; outstanding challenges are dropped (clients ask again); holder
  generations, cursors, the replay store, revocations and transitions are durable.

Tables (`*` marks the primary key; times are integer ms of the relay clock):

**directory**

| Table | Columns | Notes |
|---|---|---|
| `invites` | `code_hash*`, `expires_ms`, `used_ms`, `used_by`, `request_digest` | single use; `request_digest` makes the exact retry idempotent (P3-D3) |
| `accounts` | `person_id*`, `pk_pub`, `created_ms` | one per person |
| `devices` | `device_id*`, `person_id`, `cert`, `dk_sig_pub`, `dk_kx_pub`, `scopes_max`, `expires_ms` | proto §6.1; `label_sealed` stays opaque |
| `revocations` | `device_id*`, `person_id`, `record`, `reason`, `received_ms`, `cursor` | permanent; a stronger reason replaces a weaker one (compromised > lost/retired, §6.3 R4) |
| `workspaces` | `workspace_id*`, `owner_person_id`, `wsk_pub`, `delegation`, `card`, `card_seq`, `wxk_version`, `client_hosted` | proto §7.1, cleartext and the opaque sealed part |
| `card_key_wraps` | `(workspace_id, device_id, card_seq)*`, `sealed` | proto §5.3, purpose `card` |
| `sessions` | `token_hash*`, `kind`, `subject_id`, `expires_ms` | proto §12.2 |

**members**

| Table | Columns | Notes |
|---|---|---|
| `member_lists` | `(workspace_id, list_seq)*`, `epoch`, `list` | the highest `list_seq` is current |
| `members` | `(workspace_id, device_id)*`, `person_id`, `scopes` | the current list, exploded |
| `ever_devices` | `(workspace_id, device_id)*`, `first_epoch` | every device ever listed, or named in a restore's revocation entries |
| `ever_persons` | `(workspace_id, person_id)*` | the card owner and every person ever in `persons` |
| `wk_grants` | `(workspace_id, device_id, epoch)*`, `grant` | spec §6.1 calls this `memberships` |

**bridge**

| Table | Columns | Notes |
|---|---|---|
| `bridge_msgs` | `n*`, `workspace_id`, `device_id`, `rid`, `kind` (`req`, `resp`, `pair_req`, `pair_resp`), `offer_id`, `idx`, `flags`, `epoch`, `envelope`, `digest`, `received_ms`, `expires_ms` | sealed bodies, 60 s from their own receipt (proto §8.9), never extended |
| `rid_seen` | `(workspace_id, device_id, rid)*`, `req_digest`, `req_epoch`, `first_ms`, `requeues`, `last_requeue_ms`, `chunk_digests` | replay store, 900 s from the first receipt (P3-D9) |
| `holders` | `workspace_id*`, `gen`, `lease_until_ms`, `cursor` | fencing and the host's acknowledged cursor (P3-D10) |
| `cert_requests` | `request_id*`, `workspace_id`, `person_id`, `primary_device_id`, `request`, `expires_ms`, `state`, `challenge`, `cert_device_id`, `rejection` | the transactional state machine (P3-D11) |

**checkpoints**

| Table | Columns | Notes |
|---|---|---|
| `genesis_pins` | `workspace_id*`, `pin`, `cert` | owner-device-signed (P3-D18) |
| `checkpoint_store` | `(workspace_id, n)*`, `checkpoint`, `bytes` | the current H and every checkpoint a transition references |
| `checkpoint_held` | `workspace_id*`, `n`, `accepted_ms` | points into `checkpoint_store` |
| `log_heads` | `(workspace_id, log, seq)*`, `head`, `acc` | the heads of each log's current chain; cut back to `from_seq` on a restore; they serve ancestry proofs (P3-D19) |
| `transitions` | `restore_id*`, `workspace_id`, `log`, `source_n` (null for a bootstrap), `target_n`, `bundle` | permanent, ordered by `target_n`; the bundle holds the line, the certificate, `authz`, `abandoned_heads` and `acc_from` (§6.3) |

Never stored: `WK`, `CK`, pairing secrets, names, labels in clear, bridge plaintext. A test greps the database after a
full flow for the fixture's names, descriptions and restore `note` text.

## 3. HTTP API

**P3-D1 (routes and fixtures; C3).**

- All routes start with `/v2`.
- Bodies reuse the FakeRelay's shapes (host-api v0 §1 and §3), without `host_api` and without the `Orch-Host-API`
  header.
- Errors use proto §14's form, `{"error": code, …}`. JSON is strict per proto §2.3. `Retry-After` is integer
  delta-seconds.
- This is more than a prefix change for the phone. G0 therefore publishes request/response fixtures
  (`tests/fixtures/relay_http/*.json`, one per row below, including refusals) that the relay tests, the phone's
  adapter and its FakeRelay all consume.

Common semantics:

- **Cursors** are opaque decimal integers, exclusive (`after`), and strictly increasing per stream.
- **Pagination** returns at most `limit` items (the default and maximum are listed per route) and at most 4 MiB, plus
  `next` (null at the end).
- **Long polls** take `wait` from 0 to 25 s.

The **Auth** column uses these codes:

| Code | Meaning |
|---|---|
| none | no session |
| D | device session |
| W(g) | workspace session that holds the current holder generation `g` (header `Orch-Holder: g`, P3-D10) |
| W | workspace session, any generation (read routes) |
| D(m) | device session of a current, unrevoked member of `{ws}` with an unexpired certificate, checked in the same transaction as the read or write |
| D(p) | device session of the same person |

### 3.1 Directory and sessions

| Method, path | Auth | Request → response | Idempotency, limits | Refusals | Proto |
|---|---|---|---|---|---|
| `POST /v2/session/challenge` | none | `{}` → `{challenge, expires_ms}` | 60 s, single use; per address ≤ 16 outstanding and 60/min; global ≤ 65 536 outstanding, excess **refused** (P3-D17) | 429 `rate_limited` | §12.2 |
| `POST /v2/session/login` | none | `{challenge, kind, id, sig}` → `{token, expires_ms}` | challenge consumed on every attempt; 15 min; concurrent tokens allowed | 400 `malformed`, `cert_expired`, `cert_invalid`; 401 `unknown_challenge`, `expired`, `bad_signature`; 403 `revoked` | §12.2, §4 |
| `POST /v2/session/logout` | D or W | `{}` → `{}` | idempotent; safe to retry with an expired token (200) | — | new |
| `POST /v2/accounts` | none | `{invite, pk_pub, device_cert, challenge, sig}` → `{person_id}` | `sig` is the new device's login signature over a fresh challenge; the exact same request → 200 (by digest) | 400 `malformed`, `cert_invalid`; 401 `bad_signature`, `unknown_challenge`; 403 `not_eligible` (one code for unknown, used or expired); 409 `account_exists` | spec §6.1 (P3-D3) |
| `PUT /v2/devices/{device}` | none | `{cert}` → `{device_id}` | self-authenticating under the account `PK`; per address 30/h, per person 64/day; same cert → 200 | 400 `cert_invalid`, `cert_expired`; 403 `revoked`, `other_person` (no account); 409 `cert_conflict` | §6.1, §8.3, §8.4 (P3-D5) |
| `GET /v2/devices/{device}` | D(p), or W whose `ever_persons` contains the person | → `{cert}` | | 403 `not_eligible`; 404 `not_found` | §6.1 |
| `POST /v2/revocations` | none | `{record}` → `{device_id}` | authority is `PK`; per address 10/min, per person 32/day; same record → 200 | 400 `malformed`; 401 `bad_signature`; 403 `other_person` | §6.2 (P3-D5) |
| `GET /v2/devices/{device}/revocation` | none | → `{record}` | per address 60/min | 404; 429 | §6.2, gaps 24 |
| `GET /v2/persons/{person}/revocations?after=&limit=` | D(p), or W whose `ever_persons` contains the person | → `{revocations, next}` | limit ≤ 256 | 403 | §6.2 |
| `PUT /v2/workspaces/{ws}/card` | none for the first card; W(g) after | `{card}` → `{card_seq}` | first card: per address 10/h, per owner account 10/h, first writer wins in one transaction; same card → 200 | proto §7.1 codes: 400 `malformed`, `wrong_suite`, `delegation_mismatch`; 401 `bad_signature`; 403 `other_person`; 409 `other_workspace`, `wsk_changed`, `delegation_changed`, `stale_card`, `wxk_changed_without_version`, `bad_wxk_version` | §7.1 (P3-D4) |
| `GET /v2/workspaces/{ws}/card` | D(m) or W | → `{card}` | | 403; 404 | §7.1 |

**P3-D3 (accounts; C5).** Accounts come only from single-use invite codes made by the admin CLI
(`orch-relay invite create --ttl 7d`, stored hashed). The request carries the first device certificate (`PK`-signed)
and a fresh login signature by that device over a relay challenge. That proves the applicant holds the device key now.
Invite use and the request digest commit in one transaction. A replay of a captured certificate without the device key
fails. Registering someone's `pk_pub` would need their device key, and an account alone grants nothing.

**P3-D4 (first card; C5).** The first card takes no session: a workspace login needs a card. It is
self-authenticating (the account `PK` signs the delegation, `WSK` signs the card). The first writer wins in one
transaction. Quotas are per owner account and per address, not per attacker-chosen workspace id. A captured genuine
card that wins first publication is the genuine card; the host then logs in with the same `WSK` and moves `card_seq`
on.

**P3-D5 (PK-only recovery; C6).**

- Revocations and device certificates are accepted without a session. Each is authorized by its `PK` signature
  alone, under strict per-address and per-person quotas.
- So a person who kept only the recovery code, and so `PK` (D50), can bootstrap: upload a new device certificate, log
  in with it, and revoke the lost device.
- The public record route reveals whether a known device id is revoked. §8 states this; login adds no further oracle.

### 3.2 Members and epochs

| Method, path | Auth | Request → response | Idempotency, limits | Refusals | Proto |
|---|---|---|---|---|---|
| `PUT /v2/workspaces/{ws}/membership` | W(g) | `{member_list, grants: [wk_grant], card_key_wraps?: {card_seq, wraps}}` → `{list_seq, epoch}` | one transaction; the exact same body → 200; ≤ 1024 members, ≤ 2 MiB | 401 `bad_signature`; 403 `revoked`, `other_person`, `scope_exceeded`, `cert_expired`; 409 `other_workspace`, `stale_list`, `bad_epoch`, `rotation_required`, `missing_grant`, `grant_conflict`, `stale_card`, `fenced` | §7.2, §7.3 (P3-D7) |
| `PUT /v2/workspaces/{ws}/card-keys` | W(g) | `{card_seq, wraps: [{device_id, sealed}]}` → `{stored}` | only devices of the current list; same → no-op | 403; 409 `stale_card`, `fenced` | §5.3 |
| `GET /v2/workspaces/{ws}/grants[?epoch=e]` | D(m) | → `{grants}` (own device, ascending, from `first_epoch` on) | | 403; 404 | §7.3 |
| `GET /v2/workspaces/{ws}/members` | D(m) or W | → `{member_list}` | | 403; 404 | §7.2 |
| `GET /v2/workspaces/{ws}/card-key?card_seq=N` | D(m) | → `{workspace_id, device_id, card_seq, sealed}` | | 403; 404 | host-api §3 |

**P3-D7 (atomic membership publication; replaces the rotation-abandon proposal; C8, C9).** A list, all grants for its
epoch and optionally the card-key wraps for new devices are published in **one request and one transaction**:

1. Every proto §7.2 check, with check 8 per P3-D6 and check 9 against the grants in the same body.
2. The write-time re-check of each grant's and wrap's device certificate: stored, owned by the card owner or by a person
   in **this list's** `persons`, unexpired now, not revoked.
3. The write.

Consequences:

- **No staging deadlock for a new person (C8).** That person's grants are judged against the list that adds them.
- **No partial rotation state at the relay (C9).** A host that loses `WK_{e+1}` before the commit generates a new one;
  nothing was published.
- **The host persists `WK_{e+1}` durably before sending.** If the response is lost, it resends the exact body
  (idempotent).
- **If a committed key is lost anyway** (disk loss), the host rotates again to `e+2` at once. Committed grants are
  never deleted until a later list replaces them.
- **The rotation-abandon route and label of orch-mobile's FakeRelay amendment are dropped.** Phones already accept
  forward epoch jumps.
- **`grant_conflict`.** Other bytes for an already-committed `(device, epoch)` are refused.

**P3-D6 (persons, D39; C8).** Each member entry is `{device_id, person_id, scopes}`, and the list carries
`persons: [person_id]` (sorted, unique). Check 8: the certificate's person is the card owner **or** in `persons`
(`other_person` otherwise).

The guarantee is narrower than F1:

- `persons` is the host's WSK-signed statement. It does not establish F1 roles; readers of the workspace log still
  replay `member.added` and roles.
- A WSK holder could add a foreign person. Such a holder can leak `WK` anyway.

In P3, lists have one person in practice.

### 3.3 Bridge, pairing and the `cert_pending` queues

| Method, path | Auth | Request → response | Idempotency, limits | Refusals | Proto |
|---|---|---|---|---|---|
| `POST /v2/workspaces/{ws}/bridge/{rid}` (device) | D(m) | raw ORB2, direction 1 → 202 `{}` | ≤ 1 MiB whole envelope; P3-D9 coalescing; budgets of P3-D17 | 400 `malformed`, `wrong_suite`; 403 `not_for_this_device`, `not_eligible`, `revoked`; 409 `rid_conflict`, `stale_epoch` (`epoch`); 429 | §8.1, §8.9 |
| `GET /v2/workspaces/{ws}/bridge/{rid}?after=i&wait=s` (device) | D(m), own mailbox | → `{chunks: [{id, idx, last, stream, envelope}]}` | non-consuming | 401; 403 | §8.8 |
| `POST /v2/workspaces/{ws}/host/hold` | W | `{take_over: bool}` → `{gen, lease_s: 40, cursor}` | a new `gen` when the lease is expired or `take_over` is set; otherwise 409 | 409 `holder_conflict` | P3-D10 |
| `GET /v2/workspaces/{ws}/host/poll?after=n&wait=s` | W(g) | → `{items: [{n, route, device, rid, offer, envelope}], notices: {revocations_cursor, cert_requests, rotation_due}, next}` | non-consuming; `after` acknowledges everything up to it (stored as `holders.cursor`); renews the lease; ≤ 16 items or 4 MiB | 409 `fenced`; 401 | P3-D10 |
| `POST /v2/workspaces/{ws}/bridge/{rid}` (host) | W(g) | raw ORB2, direction 2 → 202 `{}` | ≤ 256 KiB whole chunk; same `(device, rid, idx)` and bytes → no-op; other bytes → 409; epoch rule P3-D22 | 400; 403 `not_eligible`, `revoked`; 409 `chunk_conflict`, `stale_epoch`, `fenced`; 429 | §8.1, §8.5, §8.9 |
| `POST /v2/workspaces/{ws}/pair/{offer}/{rid}` | none (device), W(g) (host answer) | raw epoch-0 ORB2 → 202 | ≤ 64 KiB; per workspace and per address 60/min; global 6 000/min | 400; 401 `unknown_workspace`; 429 | §8.3, §8.9 |
| `GET /v2/workspaces/{ws}/pair/{offer}/{rid}?after=i&wait=s` | none | → `{chunks}` | per address 120/min; global 12 000/min | 429 | §8.3 |
| `POST /v2/persons/{person}/cert-requests` | W(g), card owner = person | `{request}` → `{request_id}` | ≤ 1 open per workspace, ≤ 64 open per person; same → 200 | 401 `bad_signature`; 403 `other_person`, `not_for_this_device`; 409 `request_open`, `replayed` | §8.4 step 1 |
| `GET /v2/persons/{person}/cert-requests?wait=s` | D(p), addressee only | → `{requests}` | open only | 403 | §8.4 step 2 |
| `POST /v2/cert-requests/{id}/challenge` | D(p), addressee | `{challenge}` → `{}` | `open` → `challenged` only; same bytes → 200; another challenge → 409 | 401; 409 `replayed`; 410 `expired` | §8.4 step 3 |
| `POST /v2/cert-requests/{id}/rejection` | D(p), addressee | `{rejection}` → `{}` | `open` or `challenged` → `rejected`; repeat → 200 | 401; 409 `already_signed`; 410 | new (P3-D11) |
| `GET /v2/cert-requests/{id}` | W, the requester | → `{state, challenge, cert, rejection}` | kept until expiry + 60 s | 404 | §8.4 |

**P3-D8 (epoch at the relay; C10).** A device request for a **new** rid, whose header epoch is not the current list
epoch, is refused with 409 `stale_epoch {"epoch": current}`. This is an unsigned hint. The device:

- refetches the list and its grants (both signed);
- never raises its epoch from the hint;
- refetches at most 3 times per minute, then backs off 20, 40 and 60 s.

An **identical resend** of a known rid (P3-D9) skips the epoch check, so the host can answer from its rid store with the
stored bytes. The relay's order is: session and membership → shape → replay store → epoch.

**P3-D9 (replay store and coalescing; C11).** The relay keeps `(ws, device, rid)` for 900 s from the **first** receipt,
never extended:

- **Same bytes:**
  - If an undelivered copy exists (its `n` is above the holder's acknowledged cursor), the resend is coalesced: 202,
    nothing new queued.
  - Otherwise it is queued again, at most once per 10 s and at most 8 times per rid. Further resends get 202 and are
    dropped. A new copy lives 60 s from its own receipt.
- **Other bytes:** 409 `rid_conflict`.

The relay never checks `seq` or `ts_ms`: the host's sealed refusals do that. The host's durable rid store stays the only
exactly-once authority.

**P3-D10 (durable host cursor and fencing; C12).** This replaces the consuming poll:

- **Hold.** The host first takes a holder generation `gen` (`host/hold`). A new generation needs an expired lease or
  `take_over`.
- **Fencing.** Every host write carries `Orch-Holder: gen`: response chunks, pair answers, membership, card, card keys,
  cert requests and checkpoints. A stale generation is 409 `fenced`, so an old host process that wakes up after a
  takeover cannot interleave writes.
- **Delivery.** The poll is non-consuming: items have a strictly increasing `n` and stay until their 60 s expiry. The
  host passes `after` = the highest `n` it has durably processed (recorded in its rid store). A lost HTTP response is
  harmless: the next poll returns the same items, which is at-least-once delivery.
- **Authorization at handoff.** The relay filters each item against membership and revocation in the same transaction
  that reads it. Devices' response polls do the same.
- **Limit.** Fencing protects an honest host from its own stale twin. It does not protect against a WSK holder, who
  can always take over (§8).

**P3-D11 (cert queues; C13).** One transactional state machine per request:

- **States:** `open` → `challenged` → `signed`; `rejected` from `open` or `challenged`; `expired` from any non-terminal
  state at `expires_ms`.
- **Validation.** The relay verifies the request under the card's `WSK`, and the challenge and the rejection under
  the account's `PK`.
- **No replacement.** It refuses to replace a challenge.
- **When the request becomes `signed`.** Only when a certificate is stored (`PUT devices`) whose `dk_sig_pub`,
  `dk_kx_pub`, `device_id` and person equal the challenge's. Scopes are inside the sealed inner request, so the host
  checks them, not the relay.
- **Rejection** is a new signed kind, `cert_rejection {v, suite, kind, request_id, workspace_id, person_id}`, under
  `orch/v2/sig/cert-rejection|`.
- **FakeRelay change.** The primary must now use a device session; its session-less submission in the FakeRelay
  changes.

**P3-D16 (scopes).** On the bridge the relay enforces membership only. Ops and scopes are sealed. The typing lease has
no relay part.

**P3-D22 (old-epoch responses; C19, Q10).** Defence in depth. A response chunk's epoch must equal its request's
(`rid_seen.req_epoch`). Once the list epoch has moved past that epoch, the relay accepts a chunk at the old epoch only
if it is a `REFUSAL` chunk, or if it is byte-identical to a chunk already accepted for that rid (a stored replay;
`chunk_digests`, 900 s). Everything else is 409 `stale_epoch`. This matches the host's duty in proto §8.5. It cannot
constrain a compromised relay.

### 3.4 Checkpoints and transitions

| Method, path | Auth | Request → response | Idempotency, limits | Refusals | Proto |
|---|---|---|---|---|---|
| `PUT /v2/workspaces/{ws}/genesis` | W(g) | `{pin, cert}` → `{}` | once; the same pin → 200 | 401 `bad_signature`; 403 `restore_not_owner`; 409 `genesis_mismatch` | new §7.6 (P3-D18) |
| `PUT /v2/workspaces/{ws}/checkpoint` | W(g) | `{checkpoint, appended}` or `{checkpoint: T, appended, restore: {line, cert, authz, abandoned_heads, acc_from}}` → `{result: "accepted"\|"ignored", n}` | same → `accepted`; ≤ 2 MiB measured as the `cj` bytes of the body (P3-D20) | 400 `malformed`, `wrong_suite`, `too_large`; 401 `bad_signature`; 409 `no_genesis`, `chain_diverged`, `restore_invalid`, `restore_not_owner`, `restore_source_mismatch`, `restore_reused`, `restore_missing_revocation` (`devices`), `fenced` | new §7.6 |
| `GET /v2/workspaces/{ws}/checkpoint[?n=k]` | D(m) or W | → `{genesis: {pin, cert}, checkpoint, transitions_head}` | the held H, or a stored checkpoint `k` (a pairing baseline or a bundle source); `transitions_head` is the highest `target_n` | 403; 404 | new §7.6 |
| `GET /v2/workspaces/{ws}/transitions?after_n=k&to_n=E&limit=` | D(m) or W | → `{transitions: [bundle], next}` | ascending, `k < target_n ≤ E`; bound to the endpoint `E`; limit ≤ 16, ≤ 8 MiB | 403; 409 `chain_diverged` (`E` not held or referenced) | new §7.6 (§6.4) |
| `GET /v2/workspaces/{ws}/heads?log=L&after_seq=s&to_n=E&limit=` | D(m) or W | → `{heads: [head], next}` | the heads of `L` from `s+1` up to its seq in checkpoint `E`; limit ≤ 65 536 | 403; 404 | new §7.6 (P3-D19) |

**P3-D12.** The relay stores **workspace** checkpoints only. `ticket_checkpoint` objects are not published to it.

### 3.5 HTTP refusal codes added to proto §14

| Status | Codes |
|---|---|
| 400 | `too_large` |
| 401 | `unauthenticated` |
| 403 | `not_eligible`, `not_for_this_device` (also for the routes here) |
| 404 | `not_found` |
| 409 | `account_exists`, `cert_conflict`, `grant_conflict`, `rid_conflict`, `chunk_conflict`, `stale_epoch` (`epoch`, unsigned hint), `holder_conflict`, `fenced`, `request_open`, `replayed`, `already_signed`, `no_genesis`, `genesis_mismatch`, `chain_diverged`, `restore_invalid`, `restore_not_owner`, `restore_source_mismatch`, `restore_reused`, `restore_missing_revocation` (`devices`) |
| 410 | `expired` |
| 429 | `rate_limited`, `quota_exceeded` (both with `Retry-After`) |
| 503 | `overloaded` (global budget, with `Retry-After`) |

## 4. Auth and sessions

**Login** is proto §12.2 unchanged:

- The signed bytes are `"orch/v2/sig/relay-auth|" || suite || lp16(origin) || challenge || kind || id`.
- `origin` is the instance's configured origin (`ORCH_RELAY_ORIGIN`), never one the client names.
- Check order: the challenge is known (and removed whatever follows), unexpired, a valid `kind`, then the signature.

**Unknown ids** are verified against a fixed dummy P-256 key: same timing, the same 401 `bad_signature`, and the
challenge is consumed.

**Revoked devices get no session** (the owner's decision):

- The answer is 403 `revoked`, and only after the signature verifies.
- An expired certificate gets 400 `cert_expired`.
- The device reads its record session-less and verifies it under its pinned `PK` before wiping.

**P3-D2 (sessions; C4).**

- **Lifetime.** Bearer tokens last 15 minutes, with no refresh. A new login never invalidates other live tokens:
  clients reauthenticate single-flight and may overlap tokens.
- **Every route re-checks** expiry, revocation and certificate expiry against the database at request time. Long polls
  re-check immediately before handing over data, not only every few seconds.
- **Scope.** A device token is scoped to the relay; each workspace route authorizes against the current list. A
  workspace token is scoped to its workspace.
- **Tokens are stored as SHA-256 hashes.** That protects a database dump. It does not make a stolen bearer useless:
  a stolen token works until it expires or the device is revoked (§8).
- Agents never see tokens (spec §5.5).

**P3-D17 (budgets; C7).** All limits are refusals, never evictions of existing state:

- **Challenges:** 16 outstanding and 60 per minute per address. The global ceiling of 65 536 outstanding is a refusal
  (429), never the eviction of other clients' challenges.
- **Per device, across all its sessions:** ≤ 128 live request mailboxes per workspace, 20 posts/s, 6 concurrent long
  polls, ≤ 8 MiB of queued requests.
- **Per workspace:** ≤ 1 024 queued requests, ≤ 16 MiB queued requests, ≤ 16 MiB undelivered responses.
- **Global:** ≤ 256 MiB of queued bodies and ≤ 4 096 concurrent long polls (503 `overloaded`).
- **Client addresses.**
  - The peer address is used, or Caddy's `X-Forwarded-For` only when the peer is the configured proxy.
  - Addresses are canonicalized: IPv4-mapped IPv6 becomes IPv4, and IPv6 is grouped by /64.
  - Window keys expire 2 minutes after their last hit and are pruned on every request.

## 5. Members and epochs

### 5.1 Flow

1. **When the host rotates** (spec §5.4, proto §7.2):
   - at startup and daily, for the 90-day age;
   - on a revocation it learns of (a host-poll notice, the revocation feed, or the bridge op `revocation`);
   - on `member_remove` and on `orch keys rotate`;
   - and immediately when it holds no key for the current list epoch (P3-D7).
2. **How it rotates.** It generates and durably stores `WK_{e+1}`, then sends one `PUT membership` with the list and
   every grant.
3. **The rotation gate is the host's and is durable** (gaps Slice 2a). From the moment the host learns of a revocation
   or removal, it seals nothing new until the new list is committed.
4. **On commit,** the relay deletes the departed devices' mailboxes, queued responses, grants and card-key wraps (and
   push registrations, from P4).
5. **Devices** fetch `members` and `grants` at connect and on a `stale_epoch` (the relay hint or the host's refusal).
   They move their epoch only to one confirmed by a verified list.
6. **New devices (D26)** get grants from their `first_epoch` on.

### 5.2 What the relay sees

**It sees:**

- routing ids: workspace, device and person ids;
- scopes, epoch and `list_seq` values and when they change;
- the card's cleartext;
- sealed grants and card-key wraps, as opaque bytes.

**It never sees** `WK`, `CK`, names or labels.

**It cannot forge** grants, lists or cards. It can withhold or delay them. Devices never move backwards (proto §7.3,
§18 R6).

### 5.3 The relay side of revocation (#12, proto §6.2)

On a verified revocation, from the route or from a restore's entries, the relay does the following in one transaction:

- it stores the revocation, or upgrades the stored reason (compromised over lost/retired);
- it deletes the device's sessions, request mailboxes, queued responses, grants and card-key wraps in every workspace;
- it refuses the device on every route;
- it sets `rotation_due` for each workspace whose current list names the device.

The host sees `rotation_due` in its poll until a higher epoch is committed. There is no un-revoke.

## 6. Signed checkpoints on the relay

### 6.1 Genesis pin, log accumulators and publication

**P3-D18 (owner-signed genesis pin; C18).** TOFU is replaced. When the owner links a workspace to a relay, an owner
device (with `operate`, of the card's owner person) signs:

```
{"o": {"v": 2, "suite": 2, "kind": "genesis_pin", "workspace_id", "wsk_pub", "genesis"},
 "sig": Sign(dk_sig, "orch/v2/sig/genesis-pin|" || cj(o))}
```

- **Why a pin object.** The relay never reads `workspace.created`, which carries the owner's name and the prefix
  (spec §4). The pin gives the same binding: an owner device signs `{workspace_id, wsk_pub, genesis}`.
- **Relay.** It verifies the pin under a stored owner certificate and the card's `wsk_pub`. It refuses checkpoints
  before a pin (`no_genesis`) and checkpoints with another genesis (`genesis_mismatch`).
- **Devices** verify the pin independently, under the owner `PK` pinned from the pairing link.

**P3-D19 (log accumulators: verified append-only ancestry without logs; source challenge 7).** Heights cannot prove
ancestry. A relay that withholds a restore can serve a later checkpoint whose heights exceed what a device holds, and a
height test accepts it, even when the device held heads of the abandoned branch. The fix is a per-log accumulator in
each workspace checkpoint entry:

```
entry = {"seq", "head", "acc"}
acc_0 = 32 zero bytes
acc_k = SHA-256("orch/v2/log-acc|" || acc_{k-1} || raw(head_k))     acc = "sha256:" + lowercase hex
```

`acc_k` commits to the ordered list of heads 1…k of the log's current chain. After a restore, the chain continues from
`acc_{from_seq}`. Ancestry from a held entry `(s, acc_s)` to an offered entry `(t, acc_t)` is proved by the heads
`s+1 … t`: folding them onto `acc_s` must give `acc_t`, and the last one must be the offered `head`.

What it proves:

- The offered checkpoint extends exactly the head list the held checkpoint committed to.
- The relay's history cannot be faked by withholding or splicing while the host (`WSK`) is honest. The signed `acc`
  values pin every list.

What it does not prove:

- That the heads form a valid event chain. Only the event bytes prove that.
- Anything against a WSK holder, who can sign any `acc`. That stays F1's limit for checkpoint-only receivers.

This is a checkpoint-shape change in F1: part 2 of the proposal in §6.4. If stream A rejects it, the fallback is
heights only, and §8 then states that a withholding relay can hide a transition from a device that held abandoned
heads.

**Publication.** The host publishes `{checkpoint, appended: {log: [head, …]}}`:

- `appended` holds the heads of each log that grew since the relay's held H.
- The relay checks that each fold reproduces the new `acc`, and that logs absent from `appended` are unchanged. So the
  relay itself enforces append-only growth, not only F1's height rules.
- It stores the heads per log in `log_heads`. These serve ancestry proofs to devices.

Publication runs through the host's outbox (§9): after each burst of appends (at most one per 5 s), at startup and
daily.

**P3-D20 (capacity; C18).** A checkpoint body is at most 2 MiB of `cj` bytes. Measured: one ticket entry with `acc` is
about 200 bytes, so this is about 10 000 tickets. The host computes the size of the next checkpoint before it appends
`ticket.created`, and refuses above 1.8 MiB (`checkpoint.capacity`, F1/core). An append can therefore never make the
state unpublishable. `appended` is paged per request (at most 4 MiB of heads); a long-offline host publishes in
several steps, each one a valid checkpoint.

### 6.2 How receivers use it

**The host** fetches the relay's H with its workspace session at startup and compares it with its logs. If H's heads
or accumulators are not those of its logs at the same seqs, that is `chain.diverged`, and the host refuses appends
until an owner restore. This catches F1 §5.10's "what P1 can't detect". The host accepts the relay's H as its held
checkpoint by the receiver rules, so its held H is always a checkpoint the relay has accepted or one it has written
itself (§6.4 (1)).

**Devices** accept checkpoints only from the relay. The host never shows a device a checkpoint before the relay
accepted it.

- **Bootstrap baseline (source challenge 6).** A newly paired device does not start empty. The host's `approved`
  pairing answer (WSK-signed, proto §8.3) carries the host's held checkpoint `{n, hash}`. The device fetches that
  checkpoint from the relay and verifies it (the signature, the genesis pin, the hash). That becomes its baseline,
  marked `initialized_at = n`. A device that is not yet initialized refuses every restore with `source: null` unless
  the relay holds nothing at all and the pairing answer said "none". The empty-relay case covers only a workspace that
  has never published. A relay that falsely claims emptiness is caught by the pairing baseline.
- **Synchronisation, bound to an endpoint (source challenge 8).**
  1. `GET checkpoint` gives the endpoint E (its `n` and hash).
  2. `GET transitions?after_n=held.n&to_n=E.n` pages the transitions with `held.n < target_n ≤ E.n`.
  3. `GET heads?log=…&after_seq=…&to_n=…` pages the head lists the walk needs, as they stand in the chain up to that
     checkpoint.
  4. The device runs the walk of §6.4 (3) and ends at E, or reports `sync.incomplete` and keeps its held H.

  Pages are bound to `to_n`, so a relay cannot shift the endpoint between pages. Gaps in `n` are normal, because
  continuity is proved by the accumulators, not by consecutive numbers. Missing evidence means an incomplete sync and
  a retry. It does not mean re-pairing, which would throw away the rollback protection.
- **`chain.diverged`** (a proved non-ancestry) raises an alarm on the device.

**The relay** cannot forge or lower a checkpoint, and cannot splice histories while the host is honest. It can only
withhold, which leaves devices with an incomplete sync, not on a wrong state.

**Delimited guarantee (C15).** Checkpoint-only receivers verify signatures, accumulator ancestry, the exact restore
binding and the bundle's authorization evidence (§6.3). They do not replay F1 authorization:

- not event validity;
- not historical roles beyond §6.3's evidence;
- not `based_on`.

Hosts holding the logs do all of these.

### 6.3 Restores as owner-signed transitions

**The problem (#31 d, C14).** Revision 1's R2 relied on the restore id's ULID time and on `line.at`. Neither holds:
F1 §5.3 does not sign `at`, and ULIDs are not trusted timestamps. **The fix:** the owner signs the transition's
baseline. The person-signed restore payload carries `source: {n, hash}`, the workspace checkpoint C it abandons. This
is decided by stream A; §6.4 has the details.

**P3-D13 (restore rules at the relay).** A restore arrives as `{line, cert, authz, abandoned_heads}` beside a target
checkpoint T. The relay checks R0 to R5 **atomically**: compare, validate, persist the bundle, advance H. Of two
restores signed against the same C, one wins; the other needs a newly signed `source`. An exact retry returns the prior
result.

| Rule | Check | Refusal |
|---|---|---|
| **R0 shape (#31 a, g)** | `line` is a strictly parsed F1 `restore` event in stream A's payload shape (no interim fallback). Exact envelope and payload field sets. Person actor; `sig`, `auth` and `roster_v` present (and on no other kind). `v = 2`, `hash_v = 1`. `ws_seq` present exactly for a ticket log. | `restore_invalid` |
| **R1 signature** | `host_sig` verifies under `wsk_pub`. `sig` verifies under `cert.dk_sig_pub` with the context `{workspace_id, log}` (F1 §5.3). `actor.device == "d_" + cert.device_id`. | `restore_invalid` |
| **R1 authorization evidence (source challenge 10)** | `authz` = `{delegation, member_list}`. The delegation is the card's (PK-signed, it names `owner_person_id`), and `actor.id == "p_" + owner_person_id`. The certificate is signed by that person's `PK` and its scopes include `operate`. `member_list` is a WSK-signed list of this workspace, no newer than the relay's current one; the signer's device is in it with `operate`, as evidence that the device was introduced to the workspace and not removed. **Present authority** at the relay: the certificate is unexpired now and not revoked, counting the revocations staged from this payload. | `restore_not_owner` |
| **R2 source (#31 d)** | `source` equals the relay's held H (`n` and `h_checkpoint(H.o)`, lowercase). `null` only in the relay's uninitialized state (no held checkpoint), where T becomes the first. | `restore_source_mismatch` |
| **R3 binding (#31 d)** | `line.seq == from_seq + 1` and `line.prev == payload.head`. `abandoned_heads` are C's heads of the restored log above `from_seq`, with `acc_from`. Folding them from `acc_from` gives C's `acc`, and T's entry is exactly `{from_seq + 1, head(line), fold(acc_from, head(line))}`. Every other log of T is append-only growth of C (proved by `appended`); every log of C stays present (a ticket restore keeps every existing ticket entry); `T.n > C.n`. A ticket restore also has `ws_seq ≤ T.workspace_log.seq`. | `restore_invalid`, `chain_diverged` |
| **R4 revocations (#31 e, f; stream A's B1)** | A workspace restore carries **every** host-held revocation of the workspace; a ticket restore carries `[]`. Each entry `{revocation, device_cert, pk_pub}` verifies, and `pk_pub` is the stored account key of its person. All evidence is validated before any effect. Every revocation the relay holds for a device in `ever_devices` must appear with the same or a stronger reason. | `restore_missing_revocation` (`devices`), `restore_invalid` |
| **R5 single use (#31 b, C16)** | The id is not among the applied transitions. Only applied ids are recorded, never ids from refused offers, so nobody can poison the set. | `restore_reused` |

**On acceptance:** the staged revocations are applied (strongest reason kept, §5.3), their devices join
`ever_devices`, `log_heads` of the restored log is cut back to `from_seq` and extended by `head(line)`, H becomes T, and
the bundle is stored.

**Limits of the authorization evidence.** It is what a checkpoint-only party can verify:

- The owner is the delegation's owner person. F1 owner roles beyond that (co-owners) come in P8 with a signed roster.
- Membership in the WSK-signed list stands in for F1's device introduction and removal. A WSK holder could list a
  removed device, but still needs that owner device's signature.

The host replays full F1 authorization at `from_seq` (stream A).

**Requirement map (#31).**

| # | Requirement | Mechanism |
|---|---|---|
| a | verify the full owner-signed restore event | R0, R1 (signature and authorization evidence) |
| b | mark every restore id seen | R5: applied ids only, permanent; exact retries idempotent |
| c | `restore.at > H.at` | **dropped**: `at` is host-chosen and unsigned (C14). R2 replaces it. |
| d | tie the restore to the chain | R2 (owner-signed source = held H, atomic) + R3 (exact accumulator entry) + endpoint-bound walk with accumulator ancestry |
| e | never capture a restore without its revocations | revocations inside the payload (stream A); host outbox (§9) |
| f | own revocation set; refuse a restore lacking any | R4, transactional, strongest reason |
| g | field set per actor kind | R0; vector in G0 |

### 6.4 Stream A's source binding, and proposal part 2

**Decided by stream A** (core restore PR; recorded here as fixed input):

- `source` is `{n, hash}` or `null`. `hash` is `"sha256:"` + lowercase hex of
  `SHA-256("orch/v2/checkpoint-hash|" || cj(C.o))` (new label `h_checkpoint`).
- C is a schema-valid, WSK-signed workspace checkpoint of the pinned workspace and genesis, with `source.n == C.o.n`.
- `abandoned` still names the highest known checkpoint entry above `from_seq`, C's included; `source` is only the
  baseline. Equal-height conflicting heads are refused.
- `null` is accepted only by a receiver in an uninitialized state.
- Workspace and ticket restores both bind the workspace checkpoint. A ticket restore keeps every existing ticket entry.
- The owner's authority is checked at `from_seq` against the pre-event replay state.
- The P1/P2 host uses its last locally accepted workspace checkpoint as `source`, under the append lock (`null` only
  before any exists). It accepts a restore only if `source == held H`, atomically, and persists transitions locally for
  publication in P3.
- Revocations: B1 (Q1 below).

**Proposal part 2 to stream A (new; needs core agreement before G0):**

1. **Accumulator in checkpoint entries.** Add `acc` to every `{seq, head}` entry of a workspace checkpoint (and of a
   ticket checkpoint), computed as in P3-D19, with the new label `h_log_acc` (`orch/v2/log-acc|`). Receivers that hold
   logs check `acc` against their logs; checkpoint-only receivers use it for ancestry. Vectors: the fold, a restore
   continuing from `acc_from`, a spliced list refused.
2. **Bootstrap baseline at pairing.** The `approved` pairing answer carries the host's held checkpoint reference
   `{n, hash}` or `null` (proto §8.3; host side).
3. **Locally persisted transitions keep their evidence** (the line, the certificate, the delegation, the member list in
   force, and C's abandoned heads with `acc_from`), so the P3 bridge client can publish them as bundles.

**Answers to stream A's three questions, as revised after the source challenge:**

**(1) The source when the owner's client holds no checkpoint.** The source is not the owner device's to choose: it is
the host's held H under the append lock (stream A's rule). In P3 the host's held H includes the relay's H, fetched with
its workspace session and accepted under the receiver rules. Before signing, the owner's client:

- fetches the relay's H itself, over its own authenticated device session (a second channel, independent of the
  host);
- compares the relay's H with the host's `source` and with any checkpoint the client holds;
- shows the result: "matches the relay", "differs from the relay: n=…", or "relay unreachable: freshness unknown".

None of this proves that H is the latest (source challenge 3). The relay's R2 is the arbiter: a stale source gets
`restore_source_mismatch`, and the owner signs again. **Flushing the outbox is not a prerequisite** (source challenge
4). A rolled-back host's queued checkpoints are exactly what the relay refuses. Instead:

- Queued checkpoints of the host's own chain are published in order before the restore entry.
- If the relay refuses them as diverged, the host holds two incompatible checkpoints. It shows the conflict, takes
  the relay's H as `source` (the one that must be abandoned for propagation), and drops its unpublished ones.

**(2) Ticket-log and workspace-log restores.** Both bind the workspace checkpoint, with the exact accumulator entry on
the restored log (R3):

- A **workspace restore** carries every revocation, and no ticket entry drops.
- A **ticket restore** keeps every existing ticket entry, carries `[]`, has `ws_seq ≤ T.workspace_log.seq`, and the
  host enforces F1 §5.5 order and §5.11 authorization.

**(3) Receivers that missed intermediate restores.** The relay stores:

- every applied transition, permanently, as a bundle `{restore_id, log, source C, line, cert, authz, abandoned_heads,
  acc_from, target T}`, ordered by `T.n`;
- every checkpoint a bundle references;
- `log_heads` per log, so that it can serve ancestry proofs.

The walk, bound to the endpoint E:

```
held = baseline                              # bootstrap (6.2) or the last synced H
for each bundle B in transitions(held.n < target_n <= E.n), ascending:
    prove ancestry held -> B.source by accumulators (heads served for B.source)  else sync.incomplete or chain.diverged
    verify B (R0, R1 historically, R3, R4 internal consistency, R5)
    held = B.target
prove ancestry held -> E by accumulators                                         else sync.incomplete or chain.diverged
held = E
```

- **`source: null` bundles** appear only as the first transition of a workspace. An initialized device skips history
  below its baseline and never applies them.
- **Historical verification is recomputed by each device from the bundle** (source challenge 10), never trusted from
  the relay. Deterministic validity uses bundle content only:
  - the certificate is valid at `line.at`, F1's event position (`at` is host-chosen, which is F1's own position
    semantics);
  - the signer is not revoked by an entry in the bundle's own revocation set;
  - the `authz` checks pass.

  Expiry today is not required. Device-local knowledge, such as a `compromised` revocation of the signer learned
  later, raises a separate alarm and does not change validity. All runtimes thereby share the same history semantics.
- **Catching-up devices keep their durable revocation knowledge and tombstones** (source challenge 9). A restore can
  never resurrect a device they know to be revoked: they keep refusing it whatever the bundle says.

## 7. Protocol change #24 (and the #31 relay model)

Outline of the protocol-v2 amendment (G0, one PR, Opus security review):

| Section | Change |
|---|---|
| header, §1, §17, §18 | Suite 2 is the only deployment suite (D46); suite-1 vectors stay as test-only. PWA, service worker and Web Push become the native app, the NSE and APNs (text only). R2 and R5 are closed by D45/D46. |
| §3 | New rows: `sig_cert_rejection` `orch/v2/sig/cert-rejection\|` (PK); `sig_genesis_pin` `orch/v2/sig/genesis-pin\|` (`dk_sig`); `h_checkpoint` `orch/v2/checkpoint-hash\|`; `h_log_acc` `orch/v2/log-acc\|`. The prefix-free test is extended. |
| §7.2 | Member entries `{device_id, person_id, scopes}` plus `persons`; check 8 per D39 (P3-D6); atomic publication with grants (P3-D7); which rules bind the relay (publication) and which bind devices (snapshots). |
| §7.6 (new) | Genesis pin, accumulator entries, checkpoints with `appended`, restores as transitions with evidence, the endpoint-bound transition and head history (§6). |
| §8.3 (bootstrap) | The `approved` answer carries the baseline checkpoint reference `{n, hash}` or `null`. |
| §8.3 | Links `orch://pair?relay=…#v2…` and `https://<relay>/pair#…` (`/app/pair` accepted as an alias); passkey registration removed (D45). |
| §8.4 | Queue routes and the state machine; `cert_rejection` (P3-D11). |
| §8.7 | WebAuthn ops are not used by native clients; their replacement is deferred with Type (mobile D-5). |
| §8.9 | P3-D8, P3-D9, P3-D10, P3-D16, P3-D22; envelope limits cover the whole envelope. |
| §12.2 | P3-D2; revoked devices get no session; dummy-key verification; P3-D17. |
| §13 | The host records a verified decision verbatim as F1 `evidence` (core P3). A `decision_id` and every admitted person-event id are single-use forever, across restores (§9). |
| §14 | The codes in §3.5. |
| §19 (new) | Relay HTTP API: the §3 tables, plus the fixtures. |

**#24 item by item:**

- **Check 8 (D39)** → P3-D6.
- **Ticket-event signature context (D40)** → already in §3 from the F1 sync (`cj({contract, suite, workspace_id, log,
  event})` and `roster_v` replaced the issue's form). Only the §13 evidence note is new.
- **Checkpoints and restore** → §7.6.
- **Restricted tickets** → **P3-D14: deferred to P8.** In P3 every member device belongs to the owner, and the host
  refuses `not_visible`. In P8 the checkpoints also expose restricted tickets' uids to every member (C19), which must
  be solved then.
- **Session grants** → F1 `grant.issued`.
- **`presence`** → F1 `auth`.
- **D45/D46** → the rows above.

**#31 relay-model items** are covered in §4, §5.3, §3.3 and P3-D1. The #31 text items go into the same G0 PR: refusal
order, relay URL host rules, `-0`, byte-wise comparison, §2.5 Unicode. Drop chain identity is recorded for P4.

**Vectors and fixtures (G0, adversarial first; C20):**

- **`member_lists` v2:**
  - a second person accepted when in `persons`, refused when not;
  - a new person's grants in the same publication (C8);
  - missing grant, grant conflict, a revoked device.
- **`cert_queue`:** every state transition, signing after a rejection, a second challenge, a certificate for other keys,
  expiry races.
- **`relay_auth` additions:** revoked after a valid signature, unknown id against the dummy key, expired certificate,
  concurrent tokens.
- **`genesis_pin`:** valid; signed by a non-owner; by a decide-only device; another `wsk_pub`.
- **`checkpoints` and `transitions`:**
  - the F1 offers through the relay rules;
  - a valid workspace restore and a valid ticket restore;
  - **an old genuine restore offered after the chain regrew** (`restore_source_mismatch`);
  - **a withheld restore followed by a checkpoint with higher heights** (the accumulator walk detects it; the height
    test would not);
  - two concurrent restores against the same source (one wins);
  - a spliced head list refused; the accumulator fold; a restore continuing from `acc_from`;
  - a bootstrap: a `null` source against an uninitialized receiver (accepted) and against an initialized one
    (refused); a pairing baseline that disagrees with the relay;
  - pagination bound to an endpoint while the relay advances;
  - `authz` evidence: a signer not in the member list, a list of another workspace, a delegation of another person;
  - B1 entries: retained same-reason entries, an upgrade, a weaker reason, a ticket restore with entries;
  - P1-to-P3 publication of a locally persisted transition;
  - a source with a forged hash;
  - `source: null` against a held H;
  - T not exactly `from_seq + 1`; `line.prev` ≠ `payload.head`; a WSK-rewritten `at` (no effect);
  - signers: a non-owner, a decide-only device, a revoked device, a device revoked inside the payload;
  - revocations: a missing one, a weaker reason, a stronger reason (upgrade);
  - a reused id, an exact retry, an id from a refused offer (not recorded);
  - `sig`/`auth`/`roster_v` on the wrong actor kind;
  - a ticket restore that lowers the workspace log;
  - a **two-transition walk** for a receiver that missed both;
  - a receiver between source and target (diverged);
  - a historical bundle whose signer was later revoked `lost` (valid) or `compromised` (alarm, validity unchanged);
    a certificate expired today but valid at `line.at` (valid).
- **`bridge.relay_cases`:**
  - header device ≠ session; a non-member;
  - the epoch hint; an identical resend after rotation (skips the hint);
  - rid conflict; coalescing; the requeue cap;
  - fencing; cursor redelivery after a lost response;
  - chunk conflict; old-epoch data chunk refused, refusal chunk accepted;
  - whole-envelope limits.
- **HTTP fixtures** for every route, consumed by orch-mobile's adapter and its FakeRelay.

## 8. Threat model delta for P3

### Relay operator or compromised relay

Spec §4 treats the relay as honest-but-curious for confidentiality and untrusted for integrity.

**It can:**

- see routing ids, scopes, epochs, timing and sizes;
- see checkpoints: ticket uids (with their creation times), seqs, heads and `at`;
- see transitions: abandoned decision ids, revocation entries, the closed `reason`, the optional `note` (the host UI
  says the note is visible to the relay);
- drop, delay, replay or withhold anything, and serve stale objects;
- **with the old `WK` of a revoked device, decrypt traffic sealed under that epoch until the host rotates.**

**It cannot:**

- read `WK` or plaintext;
- forge grants, lists, cards, checkpoints, genesis pins or transitions;
- roll a device back (monotonic epochs, `card_seq`, checkpoint heights and transitions);
- seal its own `WK` to a device.

**Defence:** the host's durable rotation gate (§5.1), plus P3-D22 at an honest relay.

### WSK holder

This means a stolen key, a client-hosted admin (D29), or a host-held mandate key's process (Q3).

**It can:**

- sign any card, list, grant or checkpoint;
- add a foreign person to `persons`;
- inflate checkpoints and grow forks (F1 limit);
- take over the holder;
- deny service.

**It cannot:**

- lower a chain at the relay or a device without a fresh owner-signed transition naming the current H (R2, R3);
- (with an honest host) let a withholding relay splice histories: accumulators pin every head list (P3-D19);
- replay an old restore (R2, R5);
- drop or weaken a revocation through a restore (R4);
- forge the genesis pin;
- get a session for a revoked device.

Inflation is caught by the honest host holding the logs (§6.2).

### Member device, or a stolen unlocked phone (D49)

**It can:** act within its scopes until it is removed or revoked.

**It cannot:**

- act after revocation;
- read content sealed after the rotation;
- queue for another device (proto §8.9);
- cancel another pairing (P3-D11).

### Revoked device

**It can:** read its own record.

**It cannot:** log in, poll, post, or fetch grants and epochs **through the relay**. Its old keys still open what was
sealed before the rotation.

### Network attacker (TLS assumed)

**It can:**

- see timing;
- learn whether a device id **it already knows** is revoked, through the public record route;
- spend its own address's budgets.

**It cannot:**

- get sessions;
- learn whether an id exists through login;
- exhaust login for others (refusal budgets, not evictions).

### Owner device compromise

Out of scope as before. It can sign transitions and genesis pins. The owner revokes it with `PK`, and the revocation
reaches the relay without a session (P3-D5).

## 9. The interface between the host and the relay

The bridge client lives in orch-core (`orch serve`, stream A). Agents never see its tokens.

**P3-D21 (host outbox; C20).** The host never holds the store lock across networking:

- Under the lock, together with an append, it durably writes an outbox entry: the exact checkpoint (and, for a restore,
  the line and certificate).
- After releasing the lock, a publisher sends outbox entries in order, retries with backoff, and deletes an entry only
  after a 200.
- A restore's outbox entry is the next one after the source it names. Normal checkpoints queued behind it wait.
- Admitted `decision_id`s and person-event ids are committed to host state in the same transaction as their admission
  (tombstones that survive a restore).

| Host does | Calls | Owes |
|---|---|---|
| Start | `session/login` (kind `workspace`); `host/hold`; first run: `PUT card`, `PUT genesis` (an owner device signs the pin, one human step at relay link) | reauthenticate single-flight; carry `Orch-Holder` on every write; on `fenced` stop writing and re-hold only by explicit takeover |
| Learn revocations | `GET persons/{p}/revocations?after=` at startup and on a notice; bridge op `revocation` | raise the rotation gate at once (durable) |
| Rotate | `PUT membership` (list + grants + new devices' card-key wraps) | persist `WK_{e+1}` before sending; resend the exact body on a lost response; rotate again if the committed key is lost |
| Card change (WXK every 90 days) | `PUT card`, `PUT card-keys` | `card_seq` strictly rising |
| Serve devices | `GET host/poll?after=` loop; `POST bridge/{rid}` per chunk | advance `after` only to `n`s recorded in its rid store; seq window and rid store committed atomically; nothing sealed under an old epoch after the gate is up |
| Pair | poll items `route: "pair"`; `POST pair/…`; cert requests and their state; `PUT devices` | proto §8.3–8.4; no grant before a valid certificate; the `approved` answer carries the baseline `{n, hash}` (§6.2) |
| Checkpoints | outbox → `PUT checkpoint` with `appended` heads; `GET checkpoint` at startup | compare H with the logs (§6.2); show devices only relay-accepted checkpoints; refuse `ticket.created` near capacity (P3-D20) |
| Restore | take the held H as `source` under the append lock (relay H accepted at startup or later); the owner's client cross-checks with the relay itself and shows the result (§6.4 (1)); append and persist the transition bundle with its evidence; publish through the outbox | do not require an outbox flush; on a diverged refusal of its own queued checkpoints, show the conflict and take the relay's H; fetch revocations first, so R4 cannot refuse a signed restore; on `restore_source_mismatch` the owner signs again |

## 10. Implementation groups

Each group is one PR into `develop`: Codex implements, Opus security-reviews every group, merged after T2. G0 comes
first.

| Group | Content | T0 | T1 | T2 extra | Depends |
|---|---|---|---|---|---|
| **G0 contract** | protocol-v2 amendment (§7); `ref/`, vectors and HTTP fixtures; F1 text for `source` (stream A's PR) | `uv run pytest tests/test_vectors.py -x -q` | `uv run pytest -q -m "not slow"` + ruff | orch-mobile and orch-core run the new vectors and fixtures | stream A's restore-payload PR |
| **G1 directory** | `proto/`; accounts, invites, devices, revocations, sessions, auth, cards; durability settings | `uv run pytest tests/test_auth.py -x -q` | auth + directory + proto tests | `e2e/run.sh directory-basic`; name grep | G0 |
| **G2 members** | atomic membership, card-key wraps, revocation footprint, `rotation_due` | `uv run pytest tests/test_members.py -x -q` | members + directory | `e2e/run.sh rotate-epoch` (host stub) | G1 |
| **G3 bridge + vertical slice** | mailboxes, hold/poll/fencing, coalescing, P3-D22, pairing, cert queues, budgets | `uv run pytest tests/test_bridge_v2.py -x -q` (`-k replay`, `-k fence`, `-k pair`) | bridge + members | **vertical slice**: Python device client ↔ dev relay ↔ host stub (`bridge-device`, `pair-device`, `revoke-device`); lost-response and restart cases | G2 |
| **G4 checkpoints** | genesis pin, accumulators and `appended`, checkpoints, transitions R0–R5 with evidence, heads and transitions routes bound to an endpoint, capacity | `uv run pytest tests/test_checkpoints.py -x -q` | checkpoints + F1 vectors | `e2e/run.sh checkpoint-rollback`, `restore-walk` | G2 (parallel with G3) |
| **G5 integration** | orch-core bridge client against the dev relay; one native orch-mobile adapter smoke run | per scenario | | P3 exit run, rotation race, restart during the outbox, a real-phone adapter | G3, G4, stream A |

Order: G0 → G1 → G2 → (G3 ∥ G4) → G5. In every task the first commit is its failing vector or targeted test.

## 11. Open questions

| # | Question | Recommendation |
|---|---|---|
| Q1 | Restore revocation set | **Decided by stream A**: every revocation for any device ever seen, the strongest reason per device, entries `{revocation, device_cert, pk_pub}`. R4 follows it. |
| Q2 | `reason` text | **Decided by stream A**: closed `rollback`, `diverged`, `broken`, `other`, plus an optional `note` ≤ 280 bytes. The relay sees the note (§8); the host UI says so. |
| Q3 | Co-owners and mandates as restore signers | **Decided: owner devices only** (P3-D23). This is a documented restriction of D62: a host-held mandate key would give restore power back to the WSK holder, so a mandate may not sign a restore that leaves the host. Co-owners come in P8 with independently authorized roles. |
| Q4 | Exit criterion "desktop browser" | A Python harness plus one native smoke run. Amend spec §13 formally; close #8 as superseded. |
| Q5 | Ticket checkpoints at the relay | No (P3-D12). |
| Q6 | Option B (checkpoints commit to the last restore) | Not needed: the owner-signed source, the accumulators and the endpoint-bound walk cover it. B alone is WSK-forgeable. |
| Q11 | Accumulators (P3-D19) are an F1 checkpoint-shape change | Ask stream A to take them (proposal part 2, §6.4). The fallback is heights only, with the limit stated in §8. |
| Q7 | Checkpoint growth | P3-D20 limits; deltas only with a commitment scheme. |
| Q8 | Genesis | P3-D18 owner-device pin; devices verify it under the pinned `PK`. |
| Q9 | The `stale_epoch` hint in orch-mobile | Keep, bounded (P3-D8). The FakeRelay is amended, and drops rotation-abandon (P3-D7). |
| Q10 | Relay epoch checks on responses | Yes, as defence in depth (P3-D22). |

## 12. Challenge log (Codex, 11 Oct)

**Accepted and changed:**

| Finding | Change |
|---|---|
| C1 | `synchronous=FULL`, thread pool, restart recovery (P3-D15) |
| C2 | Audit history dropped; vertical slice in G3 |
| C3 | Fixtures, cursor, pagination and chunk-conflict rules (P3-D1, §3) |
| C4 | Overlapping tokens, checks before handoff, stolen-bearer note (P3-D2) |
| C5 | Device signature over an invite challenge; quotas per owner (P3-D3, P3-D4) |
| C6 | Session-less, quota-bound revocation and certificate upload; enumeration wording fixed (P3-D5, §8) |
| C7 | Refusals instead of evictions; device, workspace and global budgets; canonical addresses (P3-D17) |
| C8 | Atomic membership publication (P3-D7); narrower `persons` guarantee stated (P3-D6) |
| C9 | No retirement of committed epochs; rotation-abandon removed (P3-D7) |
| C10 | Bounded hint refetch; resend order (P3-D8) |
| C11 | Coalescing, 900 s from first receipt, requeue cap (P3-D9) |
| C12 | Durable cursor plus fencing generation; authorization at handoff (P3-D10) |
| C13 | Cert-request state machine bound to the challenged keys (P3-D11) |
| C14 | R2 replaced by the owner-signed source and the transition history (§6.3, §6.4) |
| C15 | Guarantee delimited; no interim fallback (§6.2, R0) |
| C16 | Only applied ids recorded; transactional R4 with stronger-reason semantics; coverage = `ever_devices` including payload devices |
| C17 | Offline convergence by the endpoint-bound accumulator walk; historical validity recomputed from the bundle (§6.4 (3)) |
| C18 | Owner-signed genesis pin; measured limits; capacity failure (P3-D18, P3-D20) |
| C19 | Relay plus old `WK` stated; rotation gate; P3-D22; uids to members noted for P8 |
| C20 | Host outbox, tombstones at admission (P3-D21); adversarial vectors; G5 crash and race coverage |

**Source challenge** (restore-rev/source-challenge.md; points 1, 2, 5, 9 and the core half of 6, 7 and 10 were
decided by stream A and are fixed input in §6.4). The relay- and receiver-side points:

| Point | Change |
|---|---|
| 3. The owner client cannot establish H's freshness | Agreed. The owner client fetches the relay's H over its own session and **discloses** matches, conflicts and unknown freshness; it claims nothing about latestness. The relay's atomic R2 is the arbiter (§6.4 (1)). |
| 4. Flushing must not be a prerequisite | Agreed. Queued checkpoints go first in order; a diverged refusal is shown as a conflict, and the relay's H becomes the source (§6.4 (1)). |
| 6. `null` needs an explicit bootstrap state | Agreed. An uninitialized state at the relay; at devices, a pairing baseline from the host's `approved` answer, cross-checked with the relay. `null` bundles only ever come first (§6.2, §6.4 (3)). |
| 7. Growth must be verified ancestry, not heights | Agreed. A per-log accumulator in checkpoints (P3-D19). The relay enforces it on publication and serves head lists; devices verify ancestry. Limit: it holds against a withholding relay with an honest host, not against a WSK holder (stated). This needs the F1 shape change (Q11). |
| 8. Bind pagination to an endpoint | Agreed. `to_n=E` on transitions and heads; gaps in `n` are allowed because the accumulators prove continuity. Missing evidence is `sync.incomplete`, not re-pairing (§6.2). |
| 10. Authorization evidence; recheck historical validity | Agreed. Bundles carry `authz` (the delegation and the member list in force). Devices recompute validity from the bundle at `line.at` and the bundle's own revocation set; device-local knowledge raises alarms without changing validity (§6.3, §6.4 (3)). |

**Disagreements and deviations** (for the Opus tie-break):

1. **C18, how the genesis is co-signed.** The relay gets a separate owner-device-signed `genesis_pin` object, not the
   `workspace.created` event, because that event carries the owner's name and the prefix, which are sealed (spec §4).
   The binding is equivalent.
2. **Source challenge 10, owner evidence at checkpoint-only receivers.** Full F1 authorization at `from_seq` cannot be
   replayed without the logs. The relay and devices accept as owner evidence: the delegation's owner person, a
   `PK`-signed certificate with `operate`, and the device's membership in a WSK-signed member list. This is weaker
   than the host's replay (a WSK holder could list a removed device that still holds a valid owner key). I argue it is
   the most that can be verified without logs. A signed roster with roles is the P8 answer.
3. **C16, receivers' revocation sets.** Devices keep their durable revocation knowledge and refuse revoked devices
   whatever a bundle says. They do not demand retroactive R4 completeness from historical bundles, because a revocation
   learned later would otherwise invalidate every older bundle. Completeness is judged by the relay at acceptance.
4. **Historical position time.** Validity at `line.at` uses F1's host-chosen position. A WSK holder could choose an
   `at` inside a certificate's validity window. It would still need that owner device's signature on a restore naming
   the current source, so I accept this rather than invent a signer clock (stream A's ULID rule forbids that).
5. **C12, delivery mechanism.** I chose the durable cursor of Codex's two options. This is not a disagreement.
6. **C5, fresh `PK` possession at account creation.** Not required. Fresh device possession is required, and an
   account holding someone's `pk_pub` grants nothing without their device keys.
