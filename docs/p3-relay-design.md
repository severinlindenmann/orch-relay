# P3 relay design: directory, bridge v2, members and epochs, checkpoints

Status: **revision 3**, 11 Oct 2026 (stream D, orch-4e), after two Codex challenges and the Opus tie-break; challenge log §12, decision index §13. This
document decides and maps. §14 (P3-D39 Drop, P3-D40 push; 15 Oct 2026, draft for review) is designed ahead of
R3. The wire contract stays [`protocol-v2.md`](protocol-v2.md) plus `tests/vectors_v2.json`.
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

(G0a review 1) G0a review amendments in `protocol-v2.md` §19 are normative over
the original route and budget summaries below. They include directory filtering, body caps,
canonical retries, requeue status, quotas, and implementation limits.

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

- push and APNs registration (P4, #13); **designed ahead in §14 (P3-D40)**;
- the pairing fallback page and `/.well-known/apple-app-site-association` (P4, #11);
- Drop (P4 basics #25, P6); **P4 basics designed ahead in §14 (P3-D39)**, the P6 rest stays out (§14.8);
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
| `ever_devices` | `(workspace_id, device_id)*`, `first_epoch` | grows only from verified evidence: listed devices, verified revocation entries, verified bundle certificates |
| `rotation_due` | `(workspace_id, device_id)*`, `revocation_cursor`, `epoch` | durable obligation; cleared only by a committed higher-epoch list that excludes the device, serialized with revocation intake (§5.3) |
| `ever_devices` | `(workspace_id, device_id)*` | devices ever in an accepted member list (G0a review 1) |
| `ever_persons` | `(workspace_id, person_id)*` | persons with a certificate-bound member device in an accepted list (G0a review 1; protocol §19.1) |
| `wk_grants` | `(workspace_id, device_id, epoch)*`, `grant` | spec §6.1 calls this `memberships` |

**bridge**

| Table | Columns | Notes |
|---|---|---|
| `bridge_msgs` | `n*`, `workspace_id`, `device_id`, `rid`, `kind` (`req`, `resp`, `pair_req`, `pair_resp`), `offer_id`, `idx`, `flags`, `epoch`, `envelope`, `digest`, `received_ms`, `expires_ms` | sealed bodies, 60 s from their own receipt (proto §8.9), never extended |
| `rid_seen` | `(workspace_id, device_id, rid)*`, `req_digest`, `req_epoch`, `first_ms`, `requeues`, `last_requeue_ms`, `keep_until_ms` | replay store: 900 s from the first receipt, extended only to outlive every dependent queued message (P3-D9); ≤ 4 096 records per device |
| `rid_chunks` | `(workspace_id, device_id, rid, idx)*`, `digest`, `flags`, `restores` | chunk identity for conflicts and stored replays, same lifetime as its `rid_seen` row; ≤ 64 chunks per rid; `restores` counts re-stores of expired identical bytes (≤ 8, P3-D27) |
| `holders` | `workspace_id*`, `gen`, `lease_until_ms`, `cursor`, `poll_token` | fencing, the contiguous acknowledged cursor and the one live poll (P3-D10) |
| `cert_requests` | `request_id*`, `workspace_id`, `person_id`, `primary_device_id`, `request`, `expires_ms`, `state`, `challenge`, `cert_device_id`, `rejection` | the transactional state machine (P3-D11) |

**checkpoints**

| Table | Columns | Notes |
|---|---|---|
| `genesis_pins` | `workspace_id*`, `pin`, `cert` | owner-device-signed (P3-D18) |
| `checkpoint_store` | `(workspace_id, hash)*`, `n`, `checkpoint`, `bytes`, `superseded_ms`, `pinned` | addressed by `h_checkpoint`; kept 24 h after supersession, permanently when a transition references it or it is a pairing baseline still in use (§6.2) |
| `checkpoint_held` | `workspace_id*`, `hash`, `accepted_ms` | points into `checkpoint_store` |
| `log_nodes` | `(workspace_id, log, acc)*`, `seq`, `head`, `prev_acc` | immutable and branch-agnostic, never cut back; abandoned suffixes stay; a proof for any stored checkpoint walks `prev_acc` back from its entry's `acc` (P3-D19); storage O(history) |
| `staging` | `(workspace_id, source_hash, target_hash, page)*`, `kind`, `body`, `expires_ms` | paged evidence before an atomic commit, 1 h (P3-D20) |
| `transitions` | `restore_id*`, `workspace_id`, `log`, `source_hash` (null for a bootstrap), `target_hash`, `target_n`, `bundle` | permanent, ordered by `target_n`; the bundle holds the full signed restore line, the certificate and `authz = {delegation}` (P3-D24); proof material lives in `log_nodes` |

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

- **Position cursors** (`after`, `after_n`, `after_seq`) are decimal integers, exclusive, and strictly increasing per
  stream. **Checkpoint references** (`to`, `hash`) are `h_checkpoint` values. `next` is an opaque string that the
  client passes back unchanged.
- **Pagination** returns at most `limit` items (the default and maximum are listed per route) and **at most 4 MiB per
  response on every route**, plus `next` (null at the end).
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
| `POST /v2/accounts` | none | `{invite, pk_pub, device_cert, challenge, sig}` → `{person_id}` | `sig` is the new device's login signature over a fresh challenge; the exact same request → 200 (by digest) | 400 `malformed`, `cert_invalid`; 401 `bad_signature`, `unknown_challenge`; 403 `not_eligible` (one code for unknown, used or expired), `revoked` (P3-D30 registration refusal); 409 `account_exists` | spec §6.1 (P3-D3) |
| `PUT /v2/devices/{device}` | none | `{cert}` → `{device_id}` | self-authenticating under the account `PK`; per address 30/h; per person 64/day, charged only after the signature verifies; an exact retry is free | 400 `cert_invalid`, `cert_expired`; 403 `revoked`, `other_person` (no account); 409 `cert_conflict` | §6.1, §8.3, §8.4 (P3-D5) |
| `GET /v2/devices/{device}` | D(p), or W whose `ever_persons` contains the person | → `{cert}` | | 403 `not_eligible`; 404 `not_found` | §6.1 |
| `POST /v2/revocations` | none | `{record}` → `{device_id}` | authority is `PK`; per address 10/min; per person 32/day, charged only after the signature verifies, with 8/day reserved for revocations of devices not yet revoked; an exact retry is free | 400 `malformed`; 401 `bad_signature`; 403 `other_person` | §6.2 (P3-D5) |
| `GET /v2/devices/{device}/revocation?after=&limit=` | none | → `{pairs: [{person_id, reason, revocation, provenance}], next}`, registered person first, then chain before feed by cursor (P3-D30) | per address 60/min; limit ≤ 32 | 400; 404; 429 | §6.2, gaps 24 |
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
- **Quota denial (challenge 2, finding 10).** Person quotas are charged only after the signature verifies, exact retries
  are free, windows are kept for their full duration (hour, day), never idle-pruned, and a reserved share stays
  available for revocations, so invalid or replayed submissions cannot block a recovery.

### 3.2 Members and epochs

| Method, path | Auth | Request → response | Idempotency, limits | Refusals | Proto |
|---|---|---|---|---|---|
| `PUT /v2/workspaces/{ws}/membership` | W(g) | `{member_list, grants: [wk_grant], card_key_wraps?: {card_seq, wraps}}` → `{list_seq, epoch}` | one transaction; the exact same body → 200; ≤ 1024 members, ≤ 2 MiB | 401 `bad_signature`; 403 `revoked`, `other_person`, `scope_exceeded`, `cert_expired`; 409 `other_workspace`, `stale_list`, `bad_epoch`, `rotation_required`, `wk_commit_changed`, `missing_grant`, `grant_conflict`, `stale_card`, `wrap_conflict`, `fenced` | §7.2, §7.3 (P3-D7, P3-D26) |
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
- **No partial rotation state at the relay (C9).** A refused publication leaves nothing at an honest relay, but the
  host never relies on that (P3-D26): the body was exposed, so its `list_seq` and any new epoch are **burned**, and
  the next key is generated at the next unused epoch. **The host never reseals a refused epoch**, and never creates a
  second key for an epoch number.
- **The host persists `WK_E` durably before sending.** If the response is lost, it resends the exact body
  (idempotent). A container-only refusal (`stale_card`, `wrap_conflict`) resends the same signed list and grants
  with corrected wraps; nothing is burned.
- **If a committed key is lost anyway** (disk loss), it is host-state loss (proto §7.2 H7): the host jumps `LHW` and
  `EHW` by 1024 above the relay's verified list and rotates at once. Committed grants are never deleted until a later
  list replaces them.
- **The rotation-abandon route and label of orch-mobile's FakeRelay amendment are dropped.** Phones already accept
  forward epoch jumps.
- **`grant_conflict`.** Other bytes for an already-committed `(device, epoch)` are refused.
- **Retries (challenge 2, finding 11).** An exact-body retry of a committed publication returns its result before any
  freshness check. The host persists the sealed grants it sent and resends the same bytes, never reseals, so a retry
  never hits `grant_conflict`.

**P3-D26 (one `WK` per epoch, ever; burned epochs; `wk_commit`; G2b, F1 Q10).** The signed list carries the required
`wk_commit = b64u(H("orch/v2/wk-commit|" || workspace_id || u32(epoch) || WK_epoch))`. Relay rules (proto §7.2):

- `epoch` is a u32 (`1 … 2^32−1`); a missing or ill-formed `wk_commit` is 400 `malformed`;
- the first list takes any epoch `1 … 2^16` and any `list_seq ≥ 1` (this replaces the `(1, 1)` pin, which would
  deadlock a workspace whose first publication was refused);
- a later list takes `prev ≤ epoch ≤ prev + 2^16` (`bad_epoch`): **epochs may skip, never fall**;
- a removal needs `epoch > prev` (`rotation_required`);
- the same epoch needs the same `wk_commit` (409 `wk_commit_changed`, new);
- `grant_conflict` and every other rule are unchanged.

The relay cannot open grants, so it checks only presence, ranges and same-epoch consistency. Devices check each grant
against `wk_commit` before sealing (no fallback to an older epoch) and, where they hold a list for that epoch, before
reading (proto §7.3 D1–D6).

Host rules H1–H8 are in proto §7.2 and orch-core host §11 (#382). In short: durable high-water marks `LHW`/`EHW` and
holder sets, write-ahead before the first send, exact-bytes resends for transient outcomes, burning on every content or
divergence refusal, the holder rule, one list per `list_seq`, a 1024 jump after host-state loss, and alarms.
**Liveness limit:** the rotation target is `min(EHW + 1, committed + 2^16)` and the clamp wins; when `EHW + 1`
exceeds `committed + 2^16` the host cannot rotate without a second key for a burned epoch, so it alarms, keeps the
gate up and the workspace is frozen until an operator intervenes (about 65,000 burns, or about 63 H7 jumps with no
commit in between). The relay checks list rules before grants, so a re-sealed same-epoch key gets
`wk_commit_changed`; there is no legacy-row exception (wipe pre-G2b dev databases). The
alarm definition is orch-52's wider one: **content and divergence refusals** count, **the count resets on a 2xx**,
3 consecutive ones raise the alarm with exponential backoff up to 5 minutes, and **a rotation uncommitted for 10
minutes** alarms whatever the cause. A **burned key never seals anything**: under it the host only answers the §8.5
`stale_epoch`, and it serves no `drop_rewrap` (a device re-wraps its own Drop objects at the current epoch instead).

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
| `POST /v2/workspaces/{ws}/host/hold` | W | `{gen: int \| null, take_over: bool}` → `{gen, lease_s: 40, cursor}` | `gen` = the current generation: renews the lease, same `gen`; `gen: null`: a new generation when the lease is expired or `take_over` is set, otherwise 409; a stale `gen` → 409 `fenced` | 409 `holder_conflict`, `fenced` | P3-D10 |
| `GET /v2/workspaces/{ws}/host/poll?after=n&wait=s` | W(g) | → `{items: [{n, route, device, rid, offer, envelope}], notices: {revocations_cursor, cert_requests, rotation_due, unpublished}, next}` | non-consuming; `after` acknowledges everything up to it (stored as `holders.cursor`); renews the lease; ≤ 16 items or 4 MiB | 409 `fenced`; 401 | P3-D10 |
| `POST /v2/workspaces/{ws}/bridge/{rid}` (host) | W(g) | raw ORB2, direction 2 → 202 `{}` | ≤ 256 KiB whole chunk; same `(device, rid, idx)` and bytes → no-op while a copy is live, stored again after it expired within P3-D27's bounds; other bytes → 409; epoch rule P3-D22 | 400; 403 `not_eligible`, `revoked`; 409 `chunk_conflict`, `stale_epoch`, `fenced`, `retry_exhausted`; 410 `expired`; 429 | §8.1, §8.5, §8.9 |
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

**P3-D9 (replay store and coalescing; C11).** The relay keeps `(ws, device, rid)` for 900 s from the **first** receipt.
A resend never extends this; the only exception is that the record lives on until every dependent queued message has
expired (`keep_until_ms`, §2):

- **Same bytes:**
  - If an undelivered copy exists (its `n` is above the holder's acknowledged cursor), the resend is coalesced: 202,
    nothing new queued.
  - Otherwise it is queued again, at most once per 10 s and at most 8 times per rid. After that cap the relay answers
    409 `retry_exhausted`, so a device never takes a 202 for a delivery promise (challenge 2, finding 9). A new copy
    lives 60 s from its own receipt, and the `rid_seen` and `rid_chunks` rows are kept until every dependent message
    has expired, so conflict detection never ends before them. Records and chunk digests are bounded per device
    (P3-D17).
- **Other bytes:** 409 `rid_conflict`.

The relay never checks `seq` or `ts_ms`: the host's sealed refusals do that. The host's durable rid store stays the only
exactly-once authority.

**P3-D10 (durable host cursor and fencing; C12).** This replaces the consuming poll:

- **Hold.** The host first takes a holder generation `gen` (`host/hold`). A new generation needs an expired lease or
  an explicit `take_over` (no silent automatic takeover). The lease is 40 s; the host renews it every 15 s, by a poll or
  by `host/hold` with `gen` set to its current generation.
- **One live poll per generation.** A new poll cancels the previous one of the same `gen`.
- **Compare-and-set (challenge 2, finding 8).** Every cursor move and every host write is a compare-and-set on
  `(gen, lease unexpired)`, re-checked after a long-poll wakeup before data is handed over.
- **Fencing.** Every host write carries `Orch-Holder: gen`: response chunks, pair answers, membership, card, card keys,
  cert requests and checkpoints. A stale generation is 409 `fenced`, so an old host process that wakes up after a
  takeover cannot interleave writes.
- **Delivery.** The poll is non-consuming: items have a strictly increasing `n` and stay until their 60 s expiry. The
  host passes `after` = the end of the **contiguous prefix** of items it has durably completed (recorded in its rid
  store), never the highest `n` seen; the relay moves the cursor only forward. A lost HTTP response is harmless: the
  next poll returns the same items. Delivery is **at-least-once within the 60 s retention**; later, the device's
  resend is the recovery.
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
- **Rejection** is a new signed kind, `cert_rejection {v, suite, kind, request_id, workspace_id, person_id, offer_id,
  attempt, device_id, dk_hash, expires_ms}` (the fields after `person_id` since P3-D28), under
  `orch/v2/sig/cert-rejection|`.
- **FakeRelay change.** The primary must now use a device session; its session-less submission in the FakeRelay
  changes.

**P3-D28 (pairing attempt binding; G3b; F1 Q6–Q9).** F1 found that the PK-signed challenge and rejection were not
bound to the pairing attempt, and two security challenges (Opus, Codex) agreed on the fix:

- **Attempt.** The device draws a nonce `attempt` per pairing attempt and sends it in the pair request; a resumed
  attempt keeps it, a new one draws a new one. An uncertified phone MUST use fresh device keys per attempt and
  remembers its earlier attempts' device ids for at least 10 minutes. The host cannot know either before the
  attempt starts.
- **Binding.** The sealed cert-request inner carries `attempt`; the request also carries `offer_id`, `attempt`,
  `device_id` and `dk_hash` (both keys) in clear, and the primary checks them against the inner. The challenge adds
  `offer_id` and `attempt`; the rejection adds `offer_id`, `attempt`, `device_id`, `dk_hash` and the request's
  `expires_ms`. Plain `offer_id`: it is in the pair path, a hash adds nothing.
- **Relay.** Before storing, the relay requires a posted challenge or rejection to name the stored request's clear
  binding (403 `not_for_this_device`) and a rejection to carry the request's expiry. Defence in depth only.
- **Phone order.** Keys and device are checked before the attempt and the offer, also when no challenge was seen,
  so a host-chosen `offer_id` cannot turn the `not_my_key` alarm into a silent drop. An own earlier attempt's
  object is dropped without alarm (`stale_attempt`) only when both its `device_id` and `dk_hash` match an earlier
  attempt the phone persisted before sending that attempt's pair request; an expired foreign object is dropped
  without alarm; any other foreign object raises the alarm (round 2).
- **`rejected`.** Two exact forms (short, or with `pk_pub` and the PK-signed rejection). "Denied by the owner" is
  shown only when everything verifies; it names the pinned owner, never the host's `primary_label`. Anything else
  is an unattributed refusal; a rejection for a foreign device raises the alarm.
- **Join anchor (Q6).** `approved` carries `list_seq` and `card_seq` beside `epoch` and G0b's `baseline`; the phone
  persists them as a floor across join retries and requires its first list and card at or above it, with its own
  entry present (`not_a_member` otherwise, no retry) and at exactly the approved scopes when the list is at the
  anchor's `list_seq`. The host fills the anchor from relay-accepted objects only (burned G2b numbers would stall
  the join).
- **Q9.** A host pair answer without a held generation is 409 `fenced`, as intended (P3-D10).
- **Residual.** A hostile host can still refuse (short form, timeout); a hostile relay can drop answers; a
  compromised primary can sign anything. Withholding newer lists after the floor stays possible (§5.2).

**P3-D16 (scopes).** On the bridge the relay enforces membership only. Ops and scopes are sealed. The typing lease has
no relay part.

**P3-D22 (old-epoch responses; C19, Q10; challenge 2, finding 13).** A defence against honest-host mistakes, not a
confidentiality boundary against a malicious host (the relay sees a flag, not the sealed refusal). A response chunk's
epoch must equal its request's (`rid_seen.req_epoch`), and the chunk must answer a known request (rid). Once the list
epoch has moved past that epoch, the relay accepts an old-epoch chunk only if it has the `LAST | REFUSAL` shape, or if it
is byte-identical to a chunk already accepted for that rid (a stored replay, `rid_chunks`). Everything else is 409
`stale_epoch`. The device validates the refusal itself (proto §8.8). Replaying stored bytes never extends a live
chunk's TTL, and an expired old-epoch data chunk is never stored again (P3-D27). This cannot constrain a compromised
relay.

**P3-D27 (bounded exact-bytes re-store; Q11, two challenge rounds).** v1 replays a finished answer re-sealed with a
fresh salt, which can never pass `chunk_conflict`, so in v2 a lost answer older than 60 s could not be recovered.
Shrinking the resend window to 60 s fails on routine iOS suspension. Instead:

- **Host.** A replay re-posts the **exact** chunk bytes already posted. The host persists each response envelope's
  bytes with the rid record before the first POST (uncertain POST outcomes included). While an op runs, a resend
  gets no interim `already_done {unknown}` (it would take idx 0). Proto §8.6 step 5.
- **Relay.** An identical chunk for a known `(device, rid, idx)` with no unexpired queued copy is stored again with
  a fresh 60 s TTL, only if all hold:
  - fencing, target eligibility (current member, not revoked) and `chunk_conflict` pass first, as for a new chunk;
  - the chunk is at the current list epoch, or has the `LAST | REFUSAL` shape (old-epoch data stays expired: the
    at-rest minimisation behind P3-D22's "no resurrection");
  - now is before `rid_seen.first_ms + 900 s`, an immutable deadline (never the extended `keep_until_ms`);
    otherwise 410 `expired`;
  - the chunk has been restored fewer than 8 times (`rid_chunks.restores`, durable across restarts); otherwise 409
    `retry_exhausted`;
  - the host-post rate and response storage budgets admit it (it is charged; a live duplicate stays a free no-op).
  The epoch rule is checked before the deadline (old-epoch data past it is a 202 no-op), and the cap before the
  rate and budgets (a capped chunk spends nothing). Removing or revoking a device sets its chunks' `restores` to
  the cap (rows and digests stay, so `chunk_conflict` still holds): a re-added device gets nothing restored.
  The copy expires at `min(now + 60 s, keep_until_ms)` and `keep_until_ms` never moves, so chunks restored in turn
  cannot keep a rid alive. Pairing answers are never restored.
- **Device.** A replay keeps its original `ts_ms`: the phone's last automatic resend starts by about 240 s after the
  first send (best-effort: clock offset and host delay also count; outside the window the device ends `uncertain`). A replayed `stale_timestamp` carries the original `host_ms`, so the offset is computed against the
  first send's device time (proto §8.8).
- **Not a security boundary.** A hostile relay could always replay bytes it once held; this bounds an honest
  relay's storage and lifetime only. Vectors: `p3.restore`; fixture `bridge_host_post` cases
  `expired_identical_chunk_restored` and `refusal_409_retry_exhausted`.

### 3.4 Checkpoints and transitions

Checkpoints are addressed by `hash` = `h_checkpoint(o)` (lowercase), with `n` alongside.

| Method, path | Auth | Request → response | Idempotency, limits | Refusals | Proto |
|---|---|---|---|---|---|
| `PUT /v2/workspaces/{ws}/genesis` | W(g) | `{pin, cert}` → `{}` | once; the same pin → 200; never replaced (§6.1) | 401 `bad_signature`; 409 `genesis_mismatch`, `restore_not_owner` | new §7.6 (P3-D18) |
| `PUT /v2/workspaces/{ws}/staging/{source_hash}/{target_hash}/pages/{i}` | W(g) | `{kind: "appended"\|"abandoned"\|"retained", log, after_seq, from_acc, heads: [head], digest}` → `{}` | page ≤ 4 MiB; the same page → 200, other bytes → 409; set expires after 1 h; per workspace ≤ 2 open sets and ≤ 64 MiB staged | 400; 409 `fenced`, `staging_conflict`; 429 `quota_exceeded` | new §7.6 (P3-D20) |
| `PUT /v2/workspaces/{ws}/staging/{source_hash}/{target_hash}/manifest` | W(g) | `{pages: [{i, kind, log, after_seq, count, digest}]}` → `{complete: bool, missing: [i]}` | the terminal marker; immutable once put; pages ordered by `(kind, log, after_seq)` with contiguous ranges | 400; 409 `staging_conflict`, `fenced` | new §7.6 (P3-D20) |
| `POST /v2/workspaces/{ws}/baselines` | W(g) | `{hash, offer_id}` → `{until_ms}` | pins a pairing baseline for 7 days; ≤ 16 per workspace; same → 200 | 404; 409 `fenced`; 429 | new §7.6 (§6.2) |
| `DELETE /v2/workspaces/{ws}/baselines/{hash}` | W(g), or D(m) after its initialization | → `{}` | releases the pin early; idempotent | — | new §7.6 (§6.2) |
| `PUT /v2/workspaces/{ws}/checkpoint` | W(g) | `{checkpoint, source_hash}` or `{checkpoint: T, source_hash, restore: {line, cert, authz, log}}` → `{result: "accepted"\|"ignored", n, hash}` | final commit over a complete staged set (manifest present, every page present with its digest), atomic, preflighted; same → `accepted`; checkpoint ≤ 2 MiB `cj`, line ≤ F1's line limit, **whole request ≤ 2 MiB + F1's line limit + 64 KiB** (certificate, delegation, framing) (P3-D20) | 400 `malformed`, `wrong_suite`, `too_large`; 401 `bad_signature`; 409 `no_genesis`, `chain_diverged`, `checkpoint_time`, `staging_incomplete`, `restore_invalid`, `restore_not_owner`, `restore_source_mismatch`, `restore_reused`, `restore_missing_revocation` (`devices`), `fenced` | new §7.6 |
| `GET /v2/workspaces/{ws}/checkpoint[?hash=h]` | D(m) or W | → `{genesis: {pin, cert}, checkpoint, transitions_head}` | the held H, or a stored checkpoint `h` (a pairing baseline or a bundle source) | 403; 404; 410 `checkpoint_gone` | new §7.6 |
| `GET /v2/workspaces/{ws}/transitions?after_n=k&to=E&limit=` | D(m) or W | → `{transitions: [bundle], next}` | ascending `target_n` with `k < target_n ≤ E.n`, where `k` is the device's held `n` (a position cursor, so an expired held checkpoint is no problem: continuity is proved from the device's own copy); limit ≤ 16, ≤ 4 MiB | 403; 410 `checkpoint_gone` (only `E`) | new §7.6 (§6.4) |
| `GET /v2/workspaces/{ws}/proof?log=L&from=acc&to=E&limit=` | D(m) or W | → `{heads: [head], next}` | the heads of `L` between the node `acc` and `L`'s entry in checkpoint `E`, walked over `log_nodes`; limit ≤ 65 536 | 403; 404; 410 `checkpoint_gone` | new §7.6 (P3-D19) |

**P3-D12.** The relay stores **workspace** checkpoints only. `ticket_checkpoint` objects are not published to it.

### 3.5 HTTP refusal codes added to proto §14

| Status | Codes |
|---|---|
| 400 | `too_large` |
| 401 | `unauthenticated` |
| 403 | `not_eligible`, `not_for_this_device` (also for the routes here) |
| 404 | `not_found` |
| 409 | `account_exists`, `cert_conflict`, `grant_conflict`, `wk_commit_changed` (P3-D26), `rid_conflict`, `retry_exhausted`, `chunk_conflict`, `checkpoint_time`, `staging_incomplete`, `staging_conflict`, `stale_epoch` (`epoch`, unsigned hint), `holder_conflict`, `fenced`, `request_open`, `replayed`, `already_signed`, `no_genesis`, `genesis_mismatch`, `chain_diverged`, `restore_invalid`, `restore_not_owner`, `restore_source_mismatch`, `restore_reused`, `restore_missing_revocation` (`devices`) |
| 410 | `expired`, `checkpoint_gone` |
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
- **Anonymous pair long polls (G3 review 2/3):** ≤ 4 concurrent per canonical client address, ≤ 32 per
  IPv4 /24, ≤ 32 per IPv6 /56 and ≤ 64 per IPv6 /48 (429 `quota_exceeded`), and ≤ 512 in total, a
  separate share of the 4 096 (503 `overloaded`). At most 16 pair polls wait on one
  `(ws, offer, rid)` (429 `quota_exceeded`).
- **Authorization first (G3 review 3):** every bridge, pair, holder and certificate request is
  authenticated, authorized and fenced by a read-only check before it takes the directory lock, a
  write transaction, a rate window, a poll slot or a wakeup; only anonymous pairing is admitted
  without a session, and it is charged only to its own windows. Refusal codes match the
  transaction's, with one deliberate exception: a non-device session posting a cert challenge or
  rejection gets 403 `not_eligible` before the request lookup, even for an unknown request id
  (never 404), so it learns nothing about request ids. Host pair answers use separate
  pairing windows with the same caps, and host response chunks are rate-limited per (workspace,
  target device), never against the device's own 20 posts/s.
- **Waiting long polls** hold no lock, transaction or worker thread. Commits that insert or change
  rows wake only the affected polls (new requests → that workspace's host; responses → that rid;
  revocation, logout, certificate store → that device's polls and the hosts of its workspaces;
  membership → that workspace). Each poll also re-checks at its session/certificate expiry and on a
  jittered 5–7 s tick, using a read-only check on the event loop; only a ready or refused check
  re-runs the full fenced transaction. At the deadline host polls rebuild their response with the
  transaction; device, pair and cert polls re-check on the event loop and answer empty unless ready
  or refused. Waits of 5 s or more end up to 10 % (≤ 1 s) early, so polls admitted together do not
  time out together. Identical resends and replays wake nobody.
- **Host poll notices** make a poll ready only when they differ from the notices last delivered to
  the current holder generation (a new generation receives them once); a past revocation alone does
  not keep a host poll from waiting.
- **Pre-public-deploy gate (G3 review D4): done (P3-D32).** `Directory.handle` took the global
  `Directory.lock`, opened a fresh connection and ran `BEGIN IMMEDIATE` before authenticating or
  validating anything (about 1 ms of lock time per unauthenticated request; ~750 bad-token
  requests/s from one client saturated the lock that bridge transactions share). Now every
  directory route authorizes first in a read-only pre-check outside the lock, the relay reuses
  connections from a bounded pool (no per-thread connections), `rate(..., charge=False)` is
  side-effect-free, and
  `tests/test_directory_preauth.py` pins that refusals take no lock or write transaction. Anonymous
  pair requests check their pairing windows before the first bridge transaction.
  *Infra TODO (defence in depth, not code):* a Caddy per-IP `rate_limit` or connection cap in front
  of the relay, before any public deploy and on the dev relay now.
- **Client addresses.**
  - The peer address is used, or Caddy's `X-Forwarded-For` only when the peer is the configured proxy.
  - Addresses are canonicalized: IPv4-mapped IPv6 becomes IPv4, and IPv6 is grouped by /64.
  - Windows are kept for their full duration (minute, hour, day) and pruned only after it ends; per-person windows
    are charged only after a signature verifies (§3.1 P3-D5).
- **Per device:** at most 4 096 `rid_seen` records and 64 chunk digests per rid.

## 5. Members and epochs

### 5.1 Flow

1. **When the host rotates** (spec §5.4, proto §7.2):
   - at startup and daily, for the 90-day age;
   - on a revocation it learns of (a host-poll notice, the revocation feed, or the bridge op `revocation`);
   - on `member_remove` and on `orch keys rotate`;
   - and immediately when it holds no key for the current list epoch (P3-D7).
2. **How it rotates.** It generates and durably stores `WK_E` at the next unused epoch (`EHW + 1`; epochs may skip),
   then sends one `PUT membership` with the list (carrying `wk_commit` for `WK_E`) and every grant. A content or
   divergence refusal burns that epoch and `list_seq`; the next attempt uses a fresh key at a higher epoch
   (P3-D26).
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

On a verified revocation, from the route or from a restore's entries, the relay does the following in one transaction
(the cutoff steps only for the device's registry pair, P3-D30):

- it stores the revocation, or upgrades the stored reason (compromised over lost/retired);
- it deletes the device's sessions, request mailboxes, queued responses, grants and card-key wraps in every workspace;
- it refuses the device on every route;
- it sets `rotation_due` for each workspace whose current list names the device.

`rotation_due` is durable: one row per obligating device, with the revocation's cursor and epoch. It is cleared only by
a committed list with a higher epoch that excludes the device, in a transaction serialized with revocation intake, so a
newer obligation is never cleared by an older publication. The host sees it in its poll until then. There is no
un-revoke.

## 6. Signed checkpoints on the relay

### 6.1 Genesis pin, log accumulators and publication

**P3-D18 (owner-signed genesis pin; C18).** TOFU is replaced. When the owner links a workspace to a relay, an owner
device (with `operate`, of the card's owner person) signs:

```
{"o": {"v": 2, "suite": 2, "kind": "genesis_pin", "workspace_id", "wsk_pub", "genesis"},
 "sig": Sign(dk_sig, "orch/v2/sig/genesis-pin|" || cj(o))}
```

- **Why a pin object.** The relay never reads `workspace.created`, which carries the owner's name and the prefix
  (spec §4). The pin attests the genesis; it does not prove the genesis is valid. Hosts holding the log check that.
- **First acceptance at the relay.** The relay checks the certificate's eligibility only when it first accepts the
  pin: unexpired by the relay clock, not revoked, `operate`, of the owner person. It also checks that `wsk_pub` is the
  card's. It refuses checkpoints before a pin (`no_genesis`) and checkpoints with another genesis
  (`genesis_mismatch`).
- **Later.** Devices verify the pin historically, under the owner `PK` pinned from the pairing link. An established pin
  is **never replaced** because its certificate later expires or is revoked. A revoked pin certificate raises an alarm
  and leaves the pin as it is.

**P3-D19 (log accumulators; decided with stream A).** Each workspace checkpoint entry is `{seq, head, acc}`:

```
acc_0 = 32 zero bytes
acc_k = SHA-256("orch/v2/log-acc|" || acc_{k-1} || raw32(head_k))
acc   = "sha256:" + lowercase hex
```

- Both inputs are exactly 32 decoded bytes, never their text forms. `seq` is not in the preimage.
- The new label is `h_log_acc`.
- An extension from `s` to `t` needs exactly `t − s` heads, the last one equal to the offered entry's `head`, folding
  to its signed `acc`. An equal `seq` needs the identical `head` and `acc`. Every existing entry is kept.

**What the accumulator guarantees** (stream A's wording): it **cannot conceal abandonment of the receiver's committed
prefix**, given an honest host and a withholding relay. It does not prove event validity, latestness, or that every
restore is disclosed: a restore after the receiver's held prefix can itself be an ordinary extension of that prefix. A
WSK holder can fabricate accumulators; that stays F1's limit for checkpoint-only receivers. A missing or malformed proof
means the sync is incomplete. It is not, by itself, proof of equivocation.

**Storage (challenge 2, finding 2).** The relay keeps the immutable, branch-agnostic table
`log_nodes(workspace, log, acc) → (seq, head, prev_acc)`:

- Every head the relay ever verified goes in, and nothing is cut back on a restore: abandoned suffixes stay.
- A proof for any stored checkpoint walks `prev_acc` back from that checkpoint's entry `acc`. Proof pages are keyed by
  the checkpoint hash.
- Storage is O(history); fold cost is O(heads).
- At the host, `acc` is maintained incrementally on append and replay. Unloaded entries are copied forward unchanged
  and validated when their log loads (stream A).

**Publication (P3-D20, decided by the tie-break).** Object limits and request limits are separate:

- A checkpoint is at most 2 MiB of `cj` bytes. Host admission refuses `ticket.created` above 1.8 MiB
  (`checkpoint.capacity`).
- A restore line is limited by F1's line limit. Stream A measures the full signed line; revocations are never
  truncated.

Evidence goes up in pages:

- The heads appended since the relay's held H (`appended`, per log from C's entry onwards), and for a restore C's
  abandoned suffix (`abandoned`, from `from_seq`) and the retained-prefix proof (`retained`, from a node `(s, acc_s)` the
  relay holds up to `from_seq`), go up in pages of at most 4 MiB into a staging set bound to `(source hash, T hash)`.
  A `retained` page is omitted when the relay's `log_nodes` already hold that path.
- A **manifest** is the terminal marker. It lists every page with `kind`, `log`, `after_seq`, `count` and a digest,
  ordered by `(kind, log, after_seq)` with contiguous ranges. The set is complete when the manifest and every listed
  page are present with matching digests.
- A set expires after 1 h. Per workspace, at most 2 open sets and 64 MiB of staged pages are allowed (`quota_exceeded`).
- A final small `PUT checkpoint` commits atomically over the staged pages and preflights everything first: every fold,
  R0–R5, sizes. Missing pages are `staging_incomplete`. Nothing is half-accepted.
- Capacity is advertised only as G0 measures it. Until then the stated capacity is **about 5 000 tickets**. G0 also
  measures fold time and `log_nodes` growth. With `acc`, one entry is about 200 bytes and one published head is about
  74 bytes of JSON.

Publication runs through the host's outbox (§9): after each burst of appends (at most one per 5 s), at startup and
daily.

**P3-D25 (position time, decided by the tie-break).** Every published checkpoint has `o.at ≥` the held H's `o.at`, and
`o.at ≤ relay clock + 300 s`. Otherwise it is 409 `checkpoint_time`. Restores get the anchors of R3a (§6.3). The host
clamps its writer: `o.at = max(clock, last checkpoint o.at)`. For a restore append it uses
`at = max(clock, source C.o.at, last at in the merged order)` (stream A).

### 6.2 How receivers use it

**The host** fetches the relay's H with its workspace session at startup and compares H's heads and accumulators with
its logs at the same seqs. A mismatch is `chain.diverged`, and the host refuses appends until an owner restore. It
accepts the relay's H as its held checkpoint only after full verification.

**Devices** accept checkpoints only from the relay. The host never shows a device a checkpoint the relay has not
accepted.

- **Bootstrap baseline (stream A's decision).** The authenticated `approved` pairing answer carries the host's
  **exact** held workspace checkpoint reference `{n, hash}`, or `null` only when none exists. The relay keeps that
  checkpoint retrievable: the host registers it with `POST baselines` when it sends `approved`. The pin lasts 7 days and is
released early by the device after its initialization, or by the host when the pairing ends. The device stays "initializing"
  until it has fetched it (`GET checkpoint?hash=`) and verified the signature, the workspace, the genesis pin and the
  hash. A baseline is never downgraded. A relay's report of emptiness can never override a non-null reference. A device
  that cannot fetch its baseline within 24 h asks the host over the bridge for its current reference, under the same
  no-downgrade rule. A `null` baseline is accepted only when the relay holds no checkpoint either; that device is
  uninitialized and its first checkpoint is the relay's first.
- **Synchronisation, bound to an immutable endpoint (challenge 2, finding 3).**
  1. `GET checkpoint` gives the endpoint E (its hash and `n`).
  2. `GET transitions?after_n=<held n>&to=E` and `GET proof?…&to=E` page the transitions and the proofs.
  3. The device runs the walk of §6.4 (3), normative in protocol-v2 §19.8 "Device synchronisation". It advances its held H **only after complete verification**. A partially
     fetched sync changes nothing.

  Rules for the endpoint:

  - The relay keeps every superseded checkpoint for 24 h after supersession, and permanently when a transition
    references it.
  - If E has expired mid-sync, the relay answers 410 `checkpoint_gone`, and the device restarts the walk with a new E,
    keeping its held H.
  - Mixed pages fail the final fold against the signed `acc`.
  - Missing evidence means `sync.incomplete` and a retry. It never means re-pairing, which would throw away the
    rollback protection.
- **`chain.diverged`**, a proved non-extension, raises an alarm on the device.

**The relay** cannot forge or lower a checkpoint. With an honest host it cannot conceal abandonment of a device's
committed prefix. It can withhold, which leaves devices with an incomplete sync, not on a wrong state.

**Delimited guarantee (C15).** Checkpoint-only receivers verify signatures, accumulator extensions, the exact restore
binding and the P3 owner-device policy (P3-D24). They do not replay F1 authorization (event validity, roles, device
introduction and removal at `from_seq`, `based_on`). Hosts holding the logs do.

### 6.3 Restores as owner-signed transitions

**The problem (#31 d, C14).** Revision 1 relied on the restore id's ULID time and on `line.at`. Neither holds: F1 §5.3
does not sign `at`, and ULIDs are not trusted timestamps. **The fix**, decided with stream A: the person-signed restore
payload carries `source: {n, hash}`, the workspace checkpoint C it abandons.

**P3-D13 (restore rules at the relay).** A restore arrives as `{line, cert, authz, log}` (`log` required since the G0b review) in the final `PUT checkpoint`, beside
a target T, with the staged pages bound to `(source hash, T hash)`. The relay checks the rules below **atomically**:
compare, validate, persist the bundle, advance H. Of two restores signed against the same C, one wins; the other needs a
newly signed `source`. An exact retry returns the prior result.

| Rule | Check | Refusal |
|---|---|---|
| **R0 shape (#31 a, g)** | `line` is a strictly parsed F1 `restore` event in stream A's payload shape (no interim fallback). Exact envelope and payload field sets. Person actor; `sig`, `auth` and `roster_v` present (and on no other kind). `v = 2`, `hash_v = 1`. `ws_seq` present exactly for a ticket log. | `restore_invalid` |
| **R1 signature** | `host_sig` verifies under `wsk_pub`. `sig` verifies under `cert.dk_sig_pub` with the context `{workspace_id, log}` (F1 §5.3). | `restore_invalid` |
| **R1 authorization (P3 owner-device policy, P3-D24)** | `authz` = `{delegation}`: the card's PK-signed delegation. `actor.id == "p_" + delegation.o.owner_person_id`. `cert` is signed by that person's `PK` (`person_id(pk_pub) == cert.o.person_id`), its `scopes_max` is a level list containing `operate`, it has no `drop:` scope, and `actor.device == "d_" + cert.o.device_id`. **Present authority at the relay only:** the certificate is unexpired by the relay clock and not revoked (counting the revocations staged from this payload), and the device is in the relay's **current** member list with `operate`. This relay-local check is never bundle evidence, and devices do not repeat it. | `restore_not_owner` |
| **R2 source (#31 d)** | `source` equals the relay's held H (`n` and `h_checkpoint(H.o)`, lowercase). `source: null` follows the bootstrap rules below. | `restore_source_mismatch` |
| **R3 binding (#31 d; challenge 2, finding 1)** | `line.seq == from_seq + 1`, `line.prev == payload.head`. **Retained prefix:** the proof shows that `from_seq` ends at the owner-signed `payload.head`. If `from_seq < C.seq`: exactly `from_seq − s` heads fold from a stored node `(s, acc_s)` of C's branch, the last one is `payload.head`, and that gives `acc_from`; C's abandoned suffix (exactly `C.seq − from_seq` heads, staged) folds from `acc_from` to C's entry `acc`. If `from_seq ≥ C.seq`: a forward proof from C's entry to `from_seq`, the last head `payload.head`. **Zero-length proofs:** when `from_seq == s` (or `from_seq == C.seq`), there are no heads; the endpoint entry itself must have `head == payload.head`, and `acc_from` is its `acc` directly. `from_seq ≥ 1` always. T's entry for the log is exactly `{from_seq + 1, head(line), fold(acc_from, head(line))}`. Every other log of T is an exact extension of C's (staged `appended` heads, exact counts; equal seq means identical head and `acc`; unchanged logs byte-equal). Every log of C stays present (a ticket restore keeps every existing ticket entry). `T.n > C.n`. A ticket restore has `ws_seq ≤ T.workspace_log.seq`. The signed `abandoned` names the highest known entry above `from_seq`, C's included (stream A); the relay checks that it is at least C's entry when C's seq exceeds `from_seq`, and refuses an equal-height conflicting head. | `restore_invalid`, `chain_diverged` |
| **R3a position time (P3-D25)** | `C.o.at ≤ line.at ≤ T.o.at`; `T.o.at ≥ H.o.at`; `T.o.at ≤ relay clock + 300 s`. The same `at` rules apply to every published checkpoint (non-decreasing, not more than 300 s ahead of the relay clock). | `restore_invalid`; plain publication: `checkpoint_time` (409) |
| **R4 revocations (#31 e, f; stream A's B1; challenge 2, finding 12)** | A workspace restore carries **every** host-held revocation of the workspace; a ticket restore carries `[]`. Each entry `{revocation, device_cert, pk_pub}` is verified first, with `pk_pub` self-certifying as in F1 (the certificate's `person_id` is `H(pk_pub)`), so persons the relay never stored are accepted (G0b review 5). All evidence is validated before any effect. The relay then compares **by `(device_id, reason strength)`**: every revocation it holds for a device in `ever_devices` must appear with the same or a stronger reason (compromised > lost = retired). Byte identity with the chain's earliest revocation stays a host/F1 rule: the relay never holds the chain and would refuse honest restores. | `restore_missing_revocation` (`devices`), `restore_invalid` |
| **R5 single use (#31 b, C16)** | The id is not among the applied transitions. Only applied ids are recorded, never ids from refused offers, so nobody can poison the set. | `restore_reused` |

**Bootstrap (`source: null`; challenge 2, finding 4).** This is accepted only while the relay holds no checkpoint for
the workspace. It runs R0, R1, R4 and R5. T becomes the first checkpoint. There is no R2 comparison and no R3 fold
against a C; T's restored log must hold exactly `{from_seq + 1, head(line)}` with a full proof from `acc_0`. Of R3a,
`line.at ≤ T.o.at` and the relay's future ceiling `T.o.at ≤ relay clock + 300 s` apply. Devices never apply a `null` bundle once initialized.

**On acceptance**, in one transaction:

- the staged revocations are applied (strongest reason kept, §5.3);
- `ever_devices` grows from the verified entries and the verified bundle certificate;
- every verified head enters `log_nodes`;
- H becomes T;
- the bundle `{restore_id, log, source hash, line, cert, authz, target hash}` is stored, and C and T are pinned.

**P3-D24, the P3 owner-device policy** (an agreed deviation from F1 §5.11 for checkpoint-only receivers). Hosts that
hold the logs replay full F1 authorization at `from_seq`: membership, owner role, device introduction and removal,
scopes, revocation and roster. The relay and devices cannot replay this without the logs. In P3 they accept a restore
when the owner person of the card's delegation signed it from a PK-certified, operate-scoped device that isn't revoked.

- **What it guarantees:** a restore cannot leave the host without the signature of a device the owner's `PK` certified
  for operate, on this exact transition and source.
- **What it does not guarantee:** that the device was introduced into this workspace and not removed at `from_seq`, or
  that the person still held the F1 owner role there. Example: an owner device removed from this workspace
  (`device.removed`) but not revoked can still sign a restore that a WSK holder publishes. This needs WSK plus the
  owner's own still-trusted device, and revocation closes it.
- **The relay's current-list check** catches honest-host mistakes only, because a WSK holder signs lists.
- **Why no member list or roster commitment as evidence:** every restore arrives under a WSK session with a WSK-signed T
  and `host_sig`, so WSK-signed evidence adds nothing against a WSK holder. A malicious relay cannot create bundles.
- **P8** replaces this with an owner-signed roster with roles. The roster is committed in checkpoints and verified by
  checkpoint-only receivers.

**Requirement map (#31).**

| # | Requirement | Mechanism |
|---|---|---|
| a | verify the full owner-signed restore event | R0, R1 (signature and the P3-D24 policy) |
| b | mark every restore id seen | R5: applied ids only, permanent; exact retries idempotent |
| c | `restore.at > H.at` | replaced by R3a (P3-D25): `C.o.at ≤ line.at ≤ T.o.at`, with non-decreasing checkpoint `at` |
| d | tie the restore to the chain | R2 (owner-signed source = held H, atomic), R3 (retained prefix to `payload.head`, exact accumulator entry), and the endpoint-bound walk |
| e | never capture a restore without its revocations | revocations inside the payload (stream A); host outbox with the full evidence (§9) |
| f | own revocation set; refuse a restore lacking any | R4, by device and reason strength, transactional |
| g | field set per actor kind | R0; vector in G0 |

### 6.4 Stream A's decisions, and what each side does

**Decided by stream A** (core restore PR; one breaking change for checkpoints and restore). This is fixed input:

- **`source`** is `{n, hash}` or `null`. `hash` is `"sha256:"` + lowercase hex of
  `SHA-256("orch/v2/checkpoint-hash|" || cj(C.o))` (label `h_checkpoint`). C is a schema-valid, WSK-signed workspace
  checkpoint of the pinned workspace and genesis, with `source.n == C.o.n`.
- **`abandoned`** names the highest known entry above `from_seq`, C's included. Equal-height conflicting heads are
  refused. `null` is accepted only by an uninitialized receiver.
- **Both log kinds** bind the workspace checkpoint. A ticket restore keeps every existing ticket entry. The host checks
  owner authority at `from_seq` by replay.
- **The P1/P2 host** takes its last locally accepted workspace checkpoint as `source`, under the append lock. It
  accepts a restore only if `source == held H`, atomically.
- **Accumulators** are as in P3-D19, with the guarantee wording above.
- **Pairing `approved`** carries the exact held checkpoint reference, never downgraded (§6.2).
- **Persisted transitions** atomically keep C, T, the full signed restore, the certificate and the delegation (the
  authorization evidence at the pre-event state), plus the branch and proof material. Crash recovery keeps pending
  transitions. **No member list, and P1 never fabricates relay objects.**
- **Revocations** are B1. Reasons are closed (`rollback`, `diverged`, `broken`, `other`), with an optional `note`.

**Stream A must also** (from the tie-break):

1. Amend decided.md's Q4 line to: "Hosts check owner at `from_seq` by replay. Relays and checkpoint-only devices apply
   P3-D24 (the card's owner person, a PK-certified operate device, not revoked) until P8's signed roster."
2. Apply the host clamps of P3-D25. Optionally, mirror the receiver rule in F1 §5.10: a higher `n` with a lower `o.at`
   is refused.

**(1) The source when the owner's client holds no checkpoint.** The source is the host's held H under the append lock.
In P3 that includes the relay's H, which the host accepted after full verification. Before signing, the owner's client
fetches the relay's H over its own device session, compares it with the host's `source` and with anything it holds,
and **discloses** the result: "matches the relay", "differs: n=…", or "relay unreachable: freshness unknown". This
proves nothing about latestness. The relay's atomic R2 is the arbiter: a stale source gets `restore_source_mismatch`,
and the owner signs again. **Flushing the outbox is not a prerequisite.** The host publishes queued checkpoints of its
own chain in order. If the relay refuses them as diverged, the host shows the conflict, takes the relay's H as
`source`, and drops its unpublished ones.

**(2) Ticket-log and workspace-log restores.** Both bind the workspace checkpoint, with the retained-prefix proof and the
exact accumulator entry on the restored log (R3).

- A **workspace restore** carries every revocation, and no ticket entry drops.
- A **ticket restore** keeps every existing ticket entry, carries `[]`, and has `ws_seq ≤ T.workspace_log.seq`. The
  host enforces F1 §5.5 order and §5.11 authorization.

**(3) Receivers that missed intermediate restores.** The relay stores:

- every applied transition, permanently, ordered by `target_n`, with C and T pinned;
- every verified head in `log_nodes`, never cut back.

The device's walk, bound to an immutable endpoint E (§6.2):

```
H    = the durable held checkpoint (baseline or last commit); unchanged until the final commit
work = H                                    # working state, also for zero transitions
for each bundle B in transitions(after_n = H.n, to = E), ascending target_n:
    fetch B.source by hash; verify its signature, workspace, genesis pin, h_checkpoint and o.at >= work.o.at
    prove the exact extension work -> B.source by accumulators          (else sync.incomplete / chain.diverged)
    check B.source == the extended work (R2-equivalent)
    verify B: R0, R1 signature, R1 P3-D24 signer checks, R3 (retained prefix to payload.head, exact entries,
              every log present), R3a, R4 internal consistency, R5 against its own applied ids
    fetch B.target by hash; verify its signature, workspace, genesis pin, h_checkpoint and o.at
    work = B.target                                                      # advance the working state
fetch E; verify its signature, workspace, genesis pin, h_checkpoint and o.at >= work.o.at (P3-D25)
prove the exact extension work -> E
commit atomically: H = E, record the restore ids, apply the bundles' revocations,
                   keep local tombstones                                 (on any failure H stays unchanged)
```

- **Historical validity is recomputed by each device from bundle content.** The certificate must be valid at
  `line.at` (F1's event position: unexpired against `at`). **Position-time anchors (P3-D25):**
  `B.source.o.at ≤ line.at ≤ B.target.o.at` (skipped for a `source: null` bundle, where only `line.at ≤ target.o.at`
  applies). Every checkpoint a receiver accepts has `o.at ≥` the held H's `o.at`. The signer must not be revoked by an
  entry in the bundle's own revocation set, and the R1 P3-D24 signer checks must pass. Expiry today is not required.
- **Device-local knowledge (amended after the G0b security review, finding 1).** "Later" means later in the device's
  own order: a `compromised` revocation of the signer first learned after the device judged that transition (from a
  higher-n bundle of the same walk, or after commit) raises an alarm without changing validity. A revocation the
  device already holds when it judges a transition, from before the sync or from a lower-n bundle of the walk,
  refuses it whatever the reason or `revoked_ms`, as F1's receiver does. The host-chosen `line.at` never decides it:
  otherwise a WSK holder with a stolen, already revoked owner device and a malicious relay could roll every device
  back with only an alarm. Round 2 (re-review N3/N4): a device keeps chain-learned and out-of-band revocations
  apart. Both refuse a signer; only chain-learned ones are demanded as restore evidence. It records the signer of
  every applied transition, so the compromised-history alarm is the same however the syncs were split.
  Round 3: a device also binds carried evidence for every device it knows as active (pairing member list,
  applied signers) or locally revoked (orch-52 #377), and a local `compromised` revocation alarms when learned.
  At the relay, device→person comes from the live global device registry (or a verified restore signer), not a
  snapshot. Round 4: a held revocation is never discarded; self-certified evidence registers the device globally in
  the same transaction, so the first accepted binding wins at the relay and on devices alike (reverted in round 6). The
  failed-publication budget is 16 per holder generation and 48 per workspace-hour: takeovers stay unlimited
  (P3-D10), so the workspace ceiling, not a takeover limit, bounds a WSK holder taking over from itself.
  Round 5 (orch-core #387, F1 §5.10 at e9a26d95, decision rows 149–151): the chain-learned/out-of-band split is now
  F1's, and the relay follows F1. A held revocation refuses a signer only when it names its device and person;
  chain-learned ones carry provenance (target checkpoint, restore event id, seq, head, accumulator node) and are
  monotonic; reasons are tracked per collection; an accepted workspace restore missing a local revocation (or
  carrying it weaker) gives `revocation.unpublished`, forwarded for devices the workspace knows and kept pending
  otherwise, until an accepted restore carries it; a failed walk keeps the evidence it verified as local and alarms
  only for committed signers. A hash-only withheld suffix can hide a committed revocation (accepted limit). The relay
  server's R4 must use per-workspace chain-learned revocations in G4, not the global table (protocol-v2 §19.8
  transport detail 6 (c)).
  Round 6 (orch-core #397, F1 §5.10 at 8a07c5ab, decision row 152, the row-151 fix): every revocation is retained
  and matched per `(device_id, person_id)`. The round-4 first-come rule is gone at the relay and on devices: restore
  evidence never registers its device, held revocations (chain pairs, the global set, a device's local evidence)
  never bind a carried entry's identity (only associations do: registry, verified signers, a device's
  `known_devices`), a restore may carry two persons' pairs for one device id, completeness and `unpublished` are per
  pair, and devices have no `contested` store. Held out-of-band evidence on devices is capped per person (members
  included, the card owner exempt), per device and in total, membership read at eviction time.
- **Devices keep their durable revocation knowledge and tombstones.** A restore can never resurrect a device they know
  to be revoked. Bundle absence does not prove historical non-revocation, and no retroactive completeness is demanded.

## 7. Protocol change #24 (and the #31 relay model)

Outline of the protocol-v2 amendment (G0, one PR, Opus security review):

| Section | Change |
|---|---|
| header, §1, §17, §18 | Suite 2 is the only deployment suite (D46); suite-1 vectors stay as test-only. PWA, service worker and Web Push become the native app, the NSE and APNs (text only). R2 and R5 are closed by D45/D46. |
| §3 | New rows: `sig_cert_rejection` `orch/v2/sig/cert-rejection\|` (PK); `sig_genesis_pin` `orch/v2/sig/genesis-pin\|` (`dk_sig`); `h_checkpoint` `orch/v2/checkpoint-hash\|`; `h_log_acc` `orch/v2/log-acc\|`. The prefix-free test is extended. |
| §7.2 | Member entries `{device_id, person_id, scopes}` plus `persons`; check 8 per D39 (P3-D6); atomic publication with grants (P3-D7); which rules bind the relay (publication) and which bind devices (snapshots). |
| §7.6 (new) | Genesis pin, accumulator entries, staged publication (pages and manifest), restores as transitions with evidence, baselines, the endpoint-bound transition and proof history (§6). |
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
- **`genesis_pin`:** valid; signed by a non-owner; by a decide-only device; another `wsk_pub`; an established pin whose
  certificate later expires or is revoked (kept; alarm on revocation).
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
  - P3-D24 policy: `restore_owner_policy_removed_device_accepted_at_checkpoint_receiver` (documents the limit; the
    host refuses the same restore at replay), `restore_signer_not_in_current_list_refused_at_relay`,
    `restore_cert_other_person_refused`, `restore_cert_decide_only_refused`, a delegation of another person;
  - P3-D25 position time: `restore_at_rewritten_within_window_accepted` (documents host control),
    `restore_at_before_source_at_refused`, `restore_at_after_target_at_refused`, `checkpoint_at_regression_refused`
    (at the relay and at a device), `checkpoint_at_future_refused_at_relay`,
    `restore_expired_cert_signs_against_fresh_source_refused` (refused by the device even when a colluding relay
    serves it);
  - accumulator boundaries: the retained prefix not ending at `payload.head`; a wrong head count; equal seq with
    another head or `acc`; a changed unchanged log; `from_seq ≥ C.seq` with a forward proof; text instead of raw
    32-byte inputs;
  - historical proofs from `log_nodes` for a source on an abandoned branch; mixed pages failing the final fold;
  - an endpoint expiring mid-sync (`checkpoint_gone`, restart with a held H unchanged); a pairing baseline fetched by
    hash; a baseline downgrade refused; relay emptiness against a non-null baseline;
  - staging: a missing page (`staging_incomplete`), pages bound to another `(source, T)`, expiry;
  - bootstrap validation of a `null` bundle without R2/R3;
  - R4 by device and strength: lost against retired (equal), compromised against lost (stronger), a weaker reason;
  - B1 entries: retained same-reason entries, an upgrade, a weaker reason, a ticket restore with entries;
  - P1-to-P3 publication of a locally persisted transition;
  - a source with a forged hash;
  - `source: null` against a held H;
  - T not exactly `from_seq + 1`; `line.prev` ≠ `payload.head`;
  - signers: a non-owner, a decide-only device, a revoked device, a device revoked inside the payload;
  - revocations: a missing one, a weaker reason, a stronger reason (upgrade);
  - a reused id, an exact retry, an id from a refused offer (not recorded);
  - `sig`/`auth`/`roster_v` on the wrong actor kind;
  - a ticket restore that lowers the workspace log;
  - a **two-transition walk** for a receiver that missed both;
  - a receiver between source and target (diverged);
  - a historical bundle whose signer the receiver already knows revoked, any reason (refused), and one whose signer
    is revoked `compromised` only by a later bundle of the walk (alarm, validity unchanged);
    a certificate expired today but valid at `line.at` (valid).
- **`bridge.relay_cases`:**
  - header device ≠ session; a non-member;
  - the epoch hint; an identical resend after rotation (skips the hint);
  - rid conflict; coalescing; the requeue cap answering `retry_exhausted`; rid metadata outliving its last copy;
  - fencing; a second poll cancelling the first; a cursor that never skips an unfinished lower item; a write after
    lease expiry refused; redelivery after a lost response;
  - chunk conflict; old-epoch data chunk refused; a `LAST | REFUSAL` chunk for a known rid accepted, for an unknown rid
    refused; a stored replay not extending its TTL;
  - recovery quotas: invalid signatures not charging the person, an exact retry free, the reserved revocation share;
  - durable `rotation_due` surviving a restart, cleared only by a higher-epoch list that excludes the device;
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
- **with the old `WK` of a revoked device, decrypt traffic sealed under that epoch until the sending device learns of
  the rotation.** The host's gate stops its own sealing under the old epoch at once, but the relay can delay a
  phone's view of the new list (withholding), and the phone keeps sealing under the epoch it knows until then. A
  burned epoch (P3-D26) gives the same exposure, no more: the excluded device was a member at the previous epoch.

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
- publish a restore signed by an owner device that was removed from (not revoked in) the workspace (P3-D24);
- choose the position `at` of a restore within `[C.o.at, T.o.at]`. Certificate expiry at checkpoint-only devices is
  evaluated at that host-chosen position (F1 §5.3, §5.11). At the relay, present authority (unexpired by the relay
  clock) also applies. Together with a colluding relay, it can therefore get a device to accept a restore signed by an
  **expired but unrevoked** device key, if the device's held checkpoint is older than the expiry, or if the holder
  froze checkpoint `at` from before the expiry onwards. Expiry bounds honest use; **revocation is the only boundary
  against a stolen key**, and is what the owner must use for a lost or retired device (P3-D25);
- take over the holder;
- deny service.

**It cannot:**

- lower a chain at the relay or a device without a fresh owner-signed transition naming the current H (R2, R3);
- (with an honest host) let a withholding relay conceal the abandonment of a device's committed prefix (P3-D19);
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
sealed before the rotation, and what a device that has not yet learned of the rotation seals under the old epoch
(withholding, above).

### Network attacker (TLS assumed)

**It can:**

- see timing;
- learn whether a device id **it already knows** is revoked, through the public record route;
- spend its own address's budgets.

**It cannot:**

- get sessions;
- learn whether an id exists through login;
- evict other clients' challenges (refusals, not evictions).

A global challenge saturation by a distributed attacker remains possible (P3-D17); it denies logins, it does not
break any.

### Owner device compromise

Out of scope as before. It can sign transitions and genesis pins. The owner revokes it with `PK`, and the revocation
reaches the relay without a session (P3-D5).

## 9. The interface between the host and the relay

The bridge client lives in orch-core (`orch serve`, stream A). Agents never see its tokens.

**P3-D21 (host outbox; C20).** The host never holds the store lock across networking:

- Under the lock, together with an append, it durably writes an outbox entry: the exact checkpoint, and for a restore
  the full evidence set of stream A (C, T, the full signed restore, the certificate, the delegation) plus the proof
  material (C's abandoned suffix from durable branch history, verified against C).
- After releasing the lock, a publisher sends outbox entries in order, retries with backoff, and deletes an entry only
  after a 200.
- A restore's outbox entry is the next one after the source it names. Normal checkpoints queued behind it wait.
- Admitted `decision_id`s and person-event ids are committed to host state in the same transaction as their admission
  (tombstones that survive a restore).

| Host does | Calls | Owes |
|---|---|---|
| Start | `session/login` (kind `workspace`); `host/hold`; first run: `PUT card`, `PUT genesis` (an owner device signs the pin, one human step at relay link) | reauthenticate single-flight; carry `Orch-Holder` on every write; on `fenced` stop writing and re-hold only by explicit takeover |
| Learn revocations | `GET persons/{p}/revocations?after=` at startup and on a notice; bridge op `revocation` | raise the rotation gate at once (durable) |
| Rotate | `PUT membership` (list with `wk_commit` + grants + new devices' card-key wraps) | persist `WK_E` (at `EHW + 1`) before sending; resend the exact body on a lost response; on a content or divergence refusal burn the epoch and `list_seq`, never reseal it, and never seal anything under the burned key; rotate again (H7) if the committed key is lost; alarm per P3-D26 |
| Card change (WXK every 90 days) | `PUT card`, `PUT card-keys` | `card_seq` strictly rising |
| Serve devices | `GET host/poll?after=` loop; `POST bridge/{rid}` per chunk | advance `after` only to `n`s recorded in its rid store; seq window and rid store committed atomically; nothing sealed under an old epoch after the gate is up |
| Pair | poll items `route: "pair"`; `POST pair/…`; cert requests and their state; `PUT devices`; `POST baselines` with `approved` | proto §8.3–8.4; no grant before a valid certificate; the `approved` answer carries the baseline `{n, hash}` (§6.2) |
| Checkpoints | outbox → staged pages and manifest, then the final `PUT checkpoint`; `GET checkpoint` at startup | compare H with the logs (§6.2); show devices only relay-accepted checkpoints; refuse `ticket.created` near capacity (P3-D20) |
| Restore | take the held H as `source` under the append lock (relay H accepted at startup or later); the owner's client cross-checks with the relay itself and shows the result (§6.4 (1)); append and persist the transition with stream A's evidence set (C, T, the full signed restore, the certificate, the delegation) and the proof material; publish through the outbox: staged pages, then the final commit | do not require an outbox flush; on a diverged refusal of its own queued checkpoints, show the conflict and take the relay's H; fetch revocations first, so R4 cannot refuse a signed restore; on `restore_source_mismatch` the owner signs again |

## 10. Implementation groups

Each group is one PR into `develop`: Codex implements, Opus security-reviews every group, merged after T2. G0 comes
first.

| Group | Content | T0 | T1 | T2 extra | Depends |
|---|---|---|---|---|---|
| **G0 contract** | protocol-v2 amendment (§7); `ref/`, vectors and HTTP fixtures; F1 text for `source` (stream A's PR) | `uv run pytest tests/test_vectors.py -x -q` | `uv run pytest -q -m "not slow"` + ruff | orch-mobile and orch-core run the new vectors and fixtures | stream A's restore-payload PR |
| **G1 directory** | `proto/`; accounts, invites, devices, revocations, sessions, auth, cards; durability settings | `uv run pytest tests/test_auth.py -x -q` | auth + directory + proto tests | `e2e/run.sh directory-basic`; name grep | G0 |
| **G2 members** | atomic membership, card-key wraps, revocation footprint, `rotation_due` | `uv run pytest tests/test_members.py -x -q` | members + directory | `e2e/run.sh rotate-epoch` (host stub) | G1 |
| **G3 bridge + vertical slice** | mailboxes, hold/poll/fencing, coalescing, P3-D22, pairing, cert queues, budgets | `uv run pytest tests/test_bridge_v2.py -x -q` (`-k replay`, `-k fence`, `-k pair`) | bridge + members | **vertical slice**: Python device client ↔ dev relay ↔ host stub (`bridge-device`, `pair-device`, `revoke-device`); lost-response and restart cases | G2 |
| **G4 checkpoints** | genesis pin, accumulators and `log_nodes`, staging and the atomic commit, checkpoints with P3-D25, transitions R0–R5 with the P3-D24 policy, hash-addressed proof and transition routes, retention and `checkpoint_gone`, measured capacity | `uv run pytest tests/test_checkpoints.py -x -q` | checkpoints + F1 vectors | `e2e/run.sh checkpoint-rollback`, `restore-walk` | G2 (parallel with G3) |
| **G5 integration** | orch-core bridge client against the dev relay; one native orch-mobile adapter smoke run | per scenario | | P3 exit run, rotation race, restart during the outbox, a real-phone adapter | G3, G4, stream A |

Order: G0 → G1 → G2 → (G3 ∥ G4) → G5. In every task the first commit is its failing vector or targeted test.

**G4 preconditions from the G0b security review** (protocol-v2 §19.8 transport detail 6):

- *Proof reads (finding 4).* `GET proof` must cost O(limit) per page (per-branch node index, skip pointers or a
  memoised ordered acc list per `(E, log)`), or charge walk steps to the §19.6 budgets with a stated bound.
- *Cross-workspace isolation (finding 7).* Add a second workspace's token and fixtures: B's sessions on A's routes
  (403 `not_eligible`), A's checkpoint/proof/staging/baseline hashes under B (404, or a no-op DELETE), and vector
  bindings for transitions 404, baseline 404/410, staging 429 and checkpoint `too_large`/`wrong_suite`.
- *Global staging ceiling (finding 11).* Enforce the deployment-wide staged-bytes cap (503 `overloaded`).
- *Revocations at the relay server (orch-core #387; protocol-v2 §19.8 transport detail 6 (c)).* R4 completeness over
  the revocations accepted in this workspace's own restores, kept with provenance and never removed; a global
  (§19.5) revocation a restore omits or carries weaker is accepted with `revocation.unpublished`; R1 unchanged.

**G4 as built** (`src/orch_relay/checkpoints.py`, migration `0009_checkpoints.sql`; 0008 is reserved for the
pairing binding). Same check order as `ref/checkpoints.py`; `tests/test_checkpoint_vectors.py` replays every
`checkpoints` and `checkpoints_g4` vector against the production app (device walks run the reference
`sync_walk` against the production GET routes), and `tests/test_directory_fixtures.py` replays every checkpoint
HTTP fixture.

- *Authorization first.* Writes authorize (session, workspace, `Orch-Holder` fence) read-only before the
  directory lock and again inside the transaction; reads authorize and read in one read-only snapshot, without
  the lock. Retention (`checkpoint_gone`) is evaluated at read time.
- *Atomicity and the budget.* The publication runs in a savepoint; any refusal rolls it back, then records one
  `checkpoint_failures` row (except 429) in the same transaction. Exact retries are served from
  `checkpoint_receipts` before the budget check.
- *Proof index* (precondition a): skip pointers in `log_nodes`, hashes stored as raw 32 bytes.
- *Staging.* Manifest descriptors are rows (`checkpoint_staging_slots`), so a page PUT touches one page and one
  slot; the security review found that re-reading the set made n small pages cost O(n²).
- **P3-D29 (evidence-only persons).** Self-certified R4 evidence for a person without an account stores an
  account row marked in `evidence_persons`, because the device and its revocation must be stored (§19.8 R4)
  and both reference `accounts`. Such a person registers no device, owns no card and joins no list
  (`other_person`) until it redeems an invite, which turns the row into its account (its evidence device rows are
  deleted, P3-D30 round 2); revocation intake for it still works. Found by the G4 security review: without the mark, the row was a full account without an invite.
- **P3-D30 (per-pair device cutoff, chain-learned registration refusal; orch-52 rulings 1 to 4).** Protocol §19.5
  states the rules; the decisions taken in implementing them:
  - *Cutoff per registry pair.* `device_status` (sessions, login, stored-certificate retries, the bridge),
    `members.certificate` and `PUT /v2/devices/{device}` of a registered device check the pair
    `(device_id, devices.person_id)`; the person never comes from the request.
  - *Registration refusal.* A new registration (`PUT` without a registry row, every `POST /v2/accounts`) is 403
    `revoked` on any `checkpoint_revocations` row of the id (any workspace, any person) or on a revocation of the
    new pair itself. A global row of another person alone never refuses it, so a squatted id registers and logs in.
    Migration 0011 adds the `checkpoint_revocations(device_id, person_id)` index for this lookup.
  - *`revoke()`* always stores the pair. It deletes sessions, prunes queues, grants and wraps, and sets
    `rotation_due` only when the record's person is the registry person. A revocation of an unregistered id cuts
    nothing off, because no session, queue, grant, wrap or member row can exist without a registry row. If the id
    registers later, the stored pair applies to the registry person through the same per-pair checks.
  - *Bridge notice cursor.* `revocations_cursor` counts only registry pairs of ever-devices, excluding P3-D29
    evidence-only persons (the same filter as `unpublished` eligibility). Another person's pair cuts nothing off and
    obliges no rotation, so it must not wake the host.
  - *Revocation list.* `GET /v2/devices/{device}/revocation` returns `{pairs: [{person_id, reason, revocation,
    provenance}]}` built by joins, with no new column. `registry` marks an association: the registry row, excluding
    evidence-only persons. `chain` marks a pair that a `checkpoint_revocations` row holds; `feed` marks one that only
    the global table holds. Round 2 (review S1): paginated like the §19.5 feed, `?after=&limit=` with at most 32 per
    page and `{pairs, next}`, where `next` is opaque and passed back as `after`. The order is the registered person
    first, then `chain` before `feed`, then by cursor. `person_id` order would let an attacker mint ids that push
    genuine pairs off page 1. Intake is not capped. No client decision may rest on this route.
  - *Deviation from ruling 3, needs orch-52 confirmation.* Ruling 3 included `device_cert` and `pk_pub` where the
    relay holds them. The security review of this change found that this discloses, on an unauthenticated route,
    the registry certificate, which `GET /v2/devices/{device}` gates (scopes, `dk_kx_pub`, expiry, sealed label).
    It also discloses the account key, and the evidence that another workspace's restore carried, which is otherwise
    readable only through that workspace's routes. Both fields are therefore omitted. The response is the public
    signed records plus the label. As a result, a consumer cannot verify a non-registry pair from this route alone.
    That needs an authorized route (P3-D31, or a gated variant).
    A `chain` label is not authentication: any workspace host can carry a self-certified pair.
  - *Exact account retry.* The exact same `POST /v2/accounts` body is answered 200 from the invite digest even after
    the device was revoked. It writes nothing and grants nothing.
  - *Evidence-only device rows (round 2, review R1).* An evidence-only person's pre-0010 device rows were created by
    restores and so are no association. Redeeming an invite used to turn them into associations even when the person
    redeemed with another device. Such an association could contradict another workspace's chain pair for the id
    and strand that workspace. `account()` now deletes them, with their sessions and queues, before the person stops
    being evidence-only, and migration 0012 does the same once.
    We deleted the rows instead of marking each device, because deletion is the safer choice:
    - It needs no new column. Every reader (`association()`, the list, the bridge cursor, `GET /v2/devices`) is left
      unchanged, and none of them can forget a marker.
    - Nothing references such a row: its pair is revoked, and members, grants and wraps need a usable account.
    - Each such device stays cut off: its revocations are kept, and its chain pair refuses re-registration.
  - *Pinned by:*
    - the `P3_D30_*` checkpoint vectors: both routes, through `register_device` with `route`; registry person vs
      request person; the account route always a new registration;
    - the `revocation_get` fixtures `every_pair_*`, including pages;
    - production tests in `tests/test_directory.py` and `tests/test_migrations.py`.
  - *Separate.* The retrieval route for `unpublished_refs` is P3-D31 (below).
- **P3-D31 (retrieval of unpublished revocation evidence; orch-52 decision point 7, approved with answers (a) to
  (d)).** Protocol §19.5 "P3-D31" is normative; this is the decision record.
  - *Routes.* `GET /v2/workspaces/{ws}/unpublished?cursor=&limit=` → `{items, cursor, more}` and
    `POST /v2/workspaces/{ws}/unpublished/ack` with `{cursor}` → `{acked}`, both W(g); host-poll `notices.unpublished`.
  - *Derived view, not a queue* (orch-52 (a)). An item exists while the global §19.5 table holds `(d, p)`, `d` is a
    G2 ever-device, `p` its registry person (evidence-only persons excluded) and the workspace chain holds the pair
    weaker or not at all. No intake hook, fan-out, eviction or rebuild: response loss, host restart and relay
    restart all recover by re-reading. Items keep `provenance.digest = sha256(cj(revocation))` (equal to the ref's),
    stable for identical evidence, so the host dedupes by `(device_id, person_id, provenance.digest)`.
  - *Retention* (orch-52 (b)): indefinite, until an accepted workspace restore carries the pair at equal or greater
    strength. The optional advisory ack field `published: [{device_id, person_id, event_id}]` is **not**
    implemented: the high-water mark already silences the notice, the event ids are unverifiable at the relay, and
    the field would add a table and a refusal surface for no change in what the route serves. An ack body with any
    other field is 400 `malformed`; the field can be added later as a new optional member. Until the relay
    announces it, a host MUST NOT send `published` (the field set is exact, so it is refused today).
  - *Budgets* (orch-52 (c)): ≤ 64 items and ≤ 256 KiB of `cj(response)` per page (the first item always);
    fetch 120/min and 2 000/h, ack 30/min per workspace, charged only after W(g); ≤ 4 096 ever-devices per
    workspace (membership 429 `quota_exceeded`). The quota is permanent (ever-devices never shrink): a host MUST
    NOT retry a membership publication refused with it unchanged. One item is at most about 66 KiB (a registry
    certificate registered through `POST /v2/accounts` is bounded by that route's 64 KiB body cap, not the 16 KiB
    `PUT /v2/devices` cap), well under the 256 KiB page bound.
  - *Ack* (orch-52 (d)): no per-item acknowledgement; a monotonic per-workspace high-water mark (migration 0013
    `unpublished_acks`) that drives the notice only. Not publication; never hides an item.
  - *Positions:* `b64u(cj({v: 1, ws, c}))`, bound to the workspace (another workspace's is 400 `malformed`), not to
    the generation; behind is a legal re-serve, ahead of the relay's state is 409 `cursor_ahead` (new code).
  - *Authorization first, no oracle:* 401, then 403 `not_eligible` (never 404/410), then 409 `fenced`, read-only
    before any lock, write or window; a fetch is one `query_only` snapshot.
  - *Publication hints (U10):* `unpublished_refs` are exactly the view's items after the restore minus the signer's
    device (the `holder is None` branch is removed, F1: no association keeps evidence pending), so every ref is
    served; `checkpoint_unpublished` is no longer written. Safe: nothing ever read that table, the view holds every
    ref (refs ⊆ items in the same transaction), and the receipt still replays the stored refs. The table is kept (no
    destructive migration); a later cleanup may drop it.
  - *Host obligations (MUST, P3 bridge):* re-read from the start at every takeover, after `cursor_ahead` and daily;
    verify every item independently under its person key with a matching certificate; check its own association;
    store durably before acking; publish only as F1 §5.3 permits (protocol §19.5).
  - *Deviations from the approved design text, by existing convention:* the ever-device quota answers 429
    `quota_exceeded` (§19.6: storage caps are 429), not 409; the ack's 1 KiB cap and unknown query parameters are
    refused at the transport before authorization, uncharged, as on every §19.8 route.
  - *Pinned by:* the `unpublished` vector group (23 cases, reference and production), the `unpublished_get`,
    `unpublished_ack`, `host_poll` (`unpublished_notice*`) and `checkpoint_put` (`restore_with_unpublished_refs`)
    fixtures, and `tests/test_unpublished.py` (lock and window spies, snapshot, page cost, wakeups, hints, quota).
- **P3-D32 (directory routes authorize first; G3 re-review D4, pre-public-deploy gate).** Protocol §19.4
  "Authorization first" is normative; this is the decision record.
  - *Mechanism.* `Directory.handle` runs the request's own steps (recovery address window, body, dispatch) as a
    pre-check on a pooled `query_only` WAL connection (`busy_timeout=0`), outside `Directory.lock`, up to the
    route's authorization point (`Directory.authorized`). A refusal there is the answer: same code, same order,
    same body, from the same code path. Otherwise the transaction (the lock, the shared write connection,
    `BEGIN IMMEDIATE`) re-runs every check, so correctness never rests on the pre-check (TOCTOU); any
    `sqlite3.Error` in the pre-check falls back to the transaction alone.
  - *Authorization point per route.* Device/workspace session reads (`members`, `grants`, `card-key`, feed,
    `GET /devices/{d}`, `GET /card`): after authentication and access (404 `not_found` stays where it was, after
    authentication). W(g) writes (`membership`, `card-keys`, `PUT /card` of a stored workspace): after fencing.
    PK-signed and anonymous routes: login after the session quota; accounts after `account_exists`; recovery
    (`POST /revocations`, `PUT /devices/{d}`) and the first card after their signature checks and their
    `charge=False` window checks, before any charge or write.
  - *Answered without the lock* (read-only, no row changes): `POST /session/challenge` (no database state), a logout
    whose token has no stored session (200 `{}` as before), an exact revocation receipt replay, and the public
    `GET /devices/{d}/revocation` read.
  - *In-memory state* (challenges, rate windows) sits under a small budget mutex, taken alone by pre-checks and
    inside `Directory.lock` by transactions; `rate(charge=False)` has no side effects. Steps with in-memory effects
    happen once per request: a login consumes its challenge in the pre-check (one guess per challenge, as before)
    and the transaction reuses it; an account request whose invite is unused (or expired for under a minute)
    proceeds before consuming, so a concurrent identical retry still sees the replay, while one on a used or
    long-expired invite (invites are never deleted) is refused in the pre-check, its challenge consumed (round 2,
    review F2); the recovery address window (charged before authentication
    by design) is checked in the pre-check and charged there only if the pre-check refuses, otherwise by the
    transaction after re-reading the receipt (a concurrent identical retry stays free).
  - *Connections (round 2, review F1).* anyio retires idle worker threads after 10 s and starts new ones, so
    per-thread connections (Directory's, and the Bridge's on develop) were never closed: bursts of refused requests
    leaked them until shutdown. `db.Connections` owns every connection instead: one write connection shared by
    Directory, Bridge and checkpoints and used only under `Directory.lock` (guarded by a debug `assert`), and a pool of at most 48
    `query_only` read connections borrowed per use and returned in a `finally` that ends the snapshot ("read" with
    `busy_timeout=0`, "query" waiting); a borrow beyond the pool gets a temporary closed on return. Thread churn
    test (idle timeout 0.05 s, 9 bursts): 21 → 161 open connections before; after, never more than the 24-wide burst + 2 (the pool grows lazily to the peak concurrency, then stays flat).
  - *Bridge.* Anonymous and host pair requests check their pairing windows (`charge=False`) before the first
    transaction, after admission, i.e. in the transaction's order.
  - *Measured* (`uv run python tests/bench_directory_preauth.py`, in process, idle laptop): a refused directory
    request 0.95–1.3 ms with ~1 ms holding `Directory.lock` → 13–19 µs with no lock; authenticated `GET members`
    850–1 600/s → 17 700–18 400/s (connection reuse). Under a paced 750/s bad-token flood: bridge transactions
    15 100/s → 29 200/s (idle ~32 000/s), `GET members` 741/s → 16 900/s; at 3 000/s the old relay served only
    ~1 500 flood requests/s and bridge transactions fell to 97/s, now 3 000/s served and 19 300/s.
  - *Residual (unthrottled paths to the lock, listed in the §10 gates).* (1) `POST /v2/accounts` on an unused
    invite (or one expired for under a minute): needs a live invite code; once redeemed or expired the invite is
    refused in the pre-check. (2) Exact certificate receipt replays (`PUT /v2/devices/{d}` with the bytes of an
    accepted request): no window, any address, about 35 µs under the lock each; the body is `cj({cert})`, and
    certificates are readable by members and hosts, so the bytes are not secret. (3) Accepted no-op recoveries:
    each needs a valid `PK` signature and is behind the per-address recovery window. Unpaced in-process floods also
    compete for the GIL. The per-IP limit belongs in Caddy (infra TODO).
  - *Pinned by* `tests/test_directory_preauth.py`: every route class refused without lock or write connection and
    with only the windows charged by design, the same bytes, windows and challenge state from the transaction alone
    (also for every G1/G2 HTTP fixture), TOCTOU, the `sqlite3.Error` fallback, the consumed challenge handed over,
    concurrent identical account retries, used and expired invites, the bounded pool under worker-thread churn,
    lock order (budget never held while taking the lock); `test_rate_check_without_charge_has_no_side_effects`;
    `test_full_pair_windows_refuse_without_lock_or_transaction`.
- **P3-D33 (final publication outside the global write lock; the G1 pre-public-deploy gate).**
  Protocol §19.8 "Publication cost" states the observable rules; this is the decision record.
  - *Phase A, outside the lock.* After the read-only authorization and the stateless pre-checks
    (review G2), the publication runs in full on one pooled `query` WAL snapshot: it re-authorizes,
    then runs `Relay.publish` in the reference order, with every fold, skip pointer and R0–R5 check
    (H, genesis, the staged set, the restore evidence and owner policy, the budget). Nothing is
    written: new `log_nodes` rows are collected in fold order and restore effects are skipped. The
    staged pages are read with the manifest and parsed one at a time when folded. After that only
    immutable nodes are read, so the snapshot is renewed every `A_SNAPSHOT_HEADS` (20,000) folded
    heads (round 2, F3). The output (`Memo`) is every fold's
    result or refusal, the pages' `(after_seq, from_acc)`, the manifest, the new rows, the heads
    folded, and whether phase A reached the commit point.
  - *The fingerprint is the fold key.* A fold is recorded under `(log, key, start seq, start acc)`,
    where `key` is the page's manifest digest (which binds the page's bytes, P3-D20) or the restore
    line's head. A stored node is a function of its acc alone (immutable, hash-addressed,
    branch-agnostic), so a recorded fold is what a live fold would return whenever phase C asks
    for the same key from the same start. Every other input is re-read live in phase C rather
    than compared: the holder fence, the receipt, the budget, H and `source_hash`, genesis, the
    staged set (presence, expiry, completeness and the manifest bytes), the WSK (the stateless
    pre-check is redone if the card's WSK differs), the owner, membership, delegation, revocation,
    association and coverage checks, `restore_reused`, the clock. This is stronger than comparing
    a precondition hash: phase C's answer is by construction the reference's answer on live
    state at phase C's time.
  - *Phase B, short chunks.* If phase A reached the commit point, its new rows are inserted
    `NODE_CHUNK` (20,000) per transaction, each a short `BEGIN IMMEDIATE` under the lock that
    re-authorizes first (a takeover stops phase B and answers 409 `fenced`, uncharged), sorts the
    chunk by key and uses `INSERT OR IGNORE`. Safe because nothing references the nodes until
    phase C commits; a crash or a refusal after any chunk leaves only orphans, and a retry finds
    them stored.
  - *Phase C, a short commit.* The publication under the lock in its savepoint, as before, with
    phase A's folds: no head is folded and no staged page is read (pinned by counting both under
    the lock). A fold phase A did not reach, or for a page whose digest it did not see (a set
    re-staged under the same key), is done live, but only up to `LIVE_FOLD_LIMIT` (5,000) heads of
    fold or page parse per round (round 2, F1). Beyond that, or when phase C would commit an
    acceptance on recorded folds whose nodes phase B did not insert, or when phase A hit an
    `sqlite3.Error` or a page that disagrees with its descriptor, the round rolls back, releases
    the lock and restarts from phase A, which does the work outside the lock. After
    `PUBLISH_ROUNDS` (3) rounds the answer is 503 `overloaded` with `Retry-After`, never charged.
    There is no fully locked fallback any more. Exact retries and unparsable bodies skip phases A and B (as
    today); `ignored` publications pass through phase A (no fold) and are answered by phase C.
  - *Concurrency and lock order.* A publication waits on a per-workspace `asyncio.Lock`, then on
    first-come-first-served admission, both on the event loop (`Gate`): a waiting publication pins
    no worker thread, so reads and `/healthz` keep their threads. Admission allows at most
    `ORCH_RELAY_PUBLISH_WIDTH` (default 2) publications whose reserved heads together stay under
    `ORCH_RELAY_PUBLISH_HEADS` (default 1.5 million, about 2 GB of phase A memory at ~1.3 KB per new
    node; round 2, F4); a publication above the cap runs alone. The reservation is estimated from
    the staged set's bytes (74 B per head); phase A stops at the manifest and re-enters the gate
    with the real count if the estimate was short. Order: workspace mutex → admission →
    `Directory.lock` → `Directory.budget`. Phase A returns its pooled read connection before phase
    B takes the lock, and nothing borrows a pooled connection while holding the lock in a way that
    waits (the write connection is the lock's). Same-workspace publications serialize through
    phases A–C; two publications from one H give exactly one acceptance even without the mutex,
    because phase C re-reads H (pinned by an interleaved A1 A2 B1 C1 B2 C2 test).
  - *Budget by work.* Every refusal records the heads its rounds folded (phase A's of every round and
    any live ones) in `checkpoint_refused_heads` (migration 0014): a charged refusal in its own
    transaction, any other (`fenced` after a takeover, 429, 503, a refusal in phase B) right after
    the answer, without a failure row (round 2, F2: a self-takeover no longer makes phase A free). The existing budget check (after the exact
    retry, before any work, 429 `quota_exceeded`, uncharged) also refuses once a workspace's rolling
    hour holds `REFUSED_HEADS` = 2 x (64 MiB / 74 B) ≈ 1.81 million refused heads, so refused fold
    work is bounded by about three full staging sets per workspace-hour instead of 48. A refusal
    before the staged set is folded records no heads. We kept the staged set on refusals (the
    other option): deleting it would be a new effect of a refusal and change the vectors'
    retry semantics.
  - *Orphan accounting.* `checkpoint_node_usage` (migration 0014, backfilled from `log_nodes`)
    counts every stored node per workspace (phase B and the live path) and, separately, the nodes
    phase B inserted for a publication phase C did not commit. Orphans are verified heads: phase
    B runs only when phase A matched every log's proof to the WSK-signed checkpoint. The counter
    is the input for the G4 per-workspace storage quota; a crash between B and C is counted in
    `nodes`, not in `orphaned`. `orphaned` is cumulative: it never decreases, also when a later
    publication commits on those nodes, so the G4 quota must use `nodes`. The accounting after the
    answer is best effort: a database error there is logged and never replaces the answer (F6).
  - *Measured* (`uv run python tests/bench_publication_lockhold.py`, in process, one run each before
    and after): an accepted 200,000-head append held `Directory.lock` 3.18 s in one hold, now at
    most 0.22 s per hold (10 chunks plus the commit, 1.6 s in total, other writers interleave);
    wall 3.19 s → 2.81 s; peak RSS 408 → 484 MB (phase A keeps its new rows until phase B). A
    refused 10,000-ticket x 2-page first publication held it 0.40 s, now 0.066 s (wall 0.57 s →
    0.60 s). A full 64 MiB set (~900,000 heads) needs about 45 chunks of ~0.2 s each.
  - *Round 2 (Opus review of PR #57, "pass with required changes").*
    - F1: a WSK holder could force the fully locked path, doubled: phase A refuses before any fold
      (`at` just past now+5 min, the last page uploaded between A and C, an owner-policy change),
      then phase C folded the set under the lock and re-ran it live. Review PoC: 40,000 folds under
      the lock for 20,000 heads (estimated ~40 s for a full set). Now: the bounded phase C and the
      restarts above; the same PoCs fold 0 heads under the lock (longest hold 0.08 s).
    - F2: a self-takeover during phase A made its work uncharged and repeatable (PoC: 4 rounds,
      0 heads recorded). Now every refusal records the work.
    - F3: WAL starvation from overlapping long phase A snapshots: renewed every 20,000 heads (a
      `wal_checkpoint(TRUNCATE)` completes while phase A runs, tested). A single fold (at most one
      4 MiB page, ~56,000 heads, well under a second) still runs on one snapshot.
    - F4: memory roughly doubles with two big publications in flight: the gate by heads and the
      environment knobs above.
    - F6: post-answer accounting is best effort; `orphaned` is cumulative.
  - *Round 2 delta check (Opus, "pass with required changes (small)").*
    - N1: the admission queue mishandled cancellation. A waiter cancelled in the same loop step
      as another publication's leave was admitted by `wake()`: `set_result` raised in the leaving
      request (a committed publication answered 500), the slot leaked for good, and the cancelled
      waiter then failed to remove itself. Now `wake()` skips done futures, and a cancelled waiter
      removes itself only if it is still queued, then wakes the queue. This was latent: nothing
      cancels publication handlers today. Pinned by three cancellation tests: cancelled while
      queued (behind another waiter), cancelled in the same step as a leave, and cancelled after
      admission but before running. In each, the gate ends empty and still admits.
    - N2: restart rounds did not count earlier rounds of the same request against the
      refused-heads budget, which is recorded only after the answer (PoC: 3 sets recorded against
      a one-set budget). Now each round's budget check, in phase A and phase C, adds the heads
      carried from earlier rounds. One request folds at most the remaining budget plus one set,
      and a round past the budget answers 429 `quota_exceeded`, uncharged, with the work
      recorded.
    - Pins: phase C's live heads on a restart are recorded; phase A reads no staged page after it
      renews its snapshot. The preload mutant is equivalent here because the pages are read in
      bulk at the first access, which is also before the first renewal.
    - F7: pins for membership removed between A and C, an unused page re-staged between A and C,
      and the mutex taken before admission.
  - *Residual.*
    - Phase A still materialises every new node of the publication. The fold cache needs them for
      skip pointers, and nodes must not be stored before their log's proof matches the signed
      checkpoint. So peak memory per publication is unchanged in kind (~1.2 GB for a full set);
      the gate bounds the total. Compact row packing is a possible follow-up.
    - The per-workspace waiters are not capped (each holds its request body, at most 2.6 MiB);
      they were not capped before either (they waited on the lock in worker threads).
    - F5: no per-account fairness. An account with k workspaces (G3: 10 new ones per hour) can keep
      both admission slots busy with accepted publications, and each of its workspaces has its own
      refused-heads budget, so refused work per account scales with its workspaces. Only
      publications wait; logins, the bridge and reads do not. Bounded since P3-D34 (at most 32
      workspaces per account); not closed (see G3 in the gates).
    - Phase C still parses a changed manifest (at most 4 MiB) and checks completeness under the
      lock when the set was re-staged between A and C, as before P3-D33.
  - *Pinned by* `tests/test_publication_phases.py`: no fold and no staged page read under the lock
    and one hold per chunk; lock order; the gate (mutex, width, cleanup, used by the route);
    same-workspace serialization and the interleaved race on H; takeover before phase C and inside
    phase B; staging deleted or re-staged between A and C; signer revoked, chain pair added,
    delegation changed and WSK changed between A and C; a refusal after folds answered on phase A's
    nodes; idempotent phase B; crashes between and inside phase B; the commit-on-unstored-folds
    guard; the refused-heads budget; `/healthz`, login and a bridge host poll served while a
    publication is paused in phase A or between phase B chunks; round 2: restarts for the clock,
    staging and owner-policy triggers with no fold under the lock, 503 after the rounds, an
    `sqlite3.Error` in phase A retried, work recorded on self-takeovers and across restart rounds,
    the renewed snapshot, the gate by heads, the reweigh, the environment knobs, the best-effort
    accounting. Every checkpoint vector and HTTP fixture passes unchanged through the phased path.
- **P3-D34 (per-account and per-workspace caps; the G3 and G4 pre-public-deploy gates).** Protocol §19.8
  "Storage caps (P3-D34)" states the observable rules; this is the decision record. Every cap answers 429
  `quota_exceeded` (no new code), is checked after authorization (401, 403 `not_eligible`, 409 `fenced` come
  first), is read and enforced inside the write transaction that would exceed it (so it is exact under
  concurrency, like the global ceiling), and is configurable by environment (read once at start-up).
  - *Staged bytes per owner person* (G3; `ORCH_RELAY_ACCOUNT_STAGE_BYTES`, default 512 MiB = 4 GiB / 8). The sum
    of live staged bytes (pages and manifests of unexpired sets) over every workspace the owner person of this
    workspace owns, checked where the per-workspace 64 MiB quota and the 4 GiB ceiling are checked (page and
    manifest PUTs, in `charge_stage`): workspace quota, then this cap (429), then the ceiling (503 `overloaded`),
    so an account that is over its own cap hears so before it hears about everyone else. Uncharged, like every
    staging refusal (staging has no failure budget). A delegated (client-hosted) WSK holder of one of the
    owner's workspaces can spend the owner's whole 512 MiB, delaying the owner's other workspaces' staging for
    up to an hour (set expiry); this is within the trust the owner delegated (review F6). Nothing is stored per account: the sum is computed from the
    live rows (index `workspace_owner`, migration 0015), so expiry, deletion, the sweep and a committed
    publication (which deletes its set) release the bytes with no bookkeeping that could drift. One account
    now fills at most 512 MiB, eight full workspace quotas; eight accounts are needed to fill the ceiling.
  - *Workspaces per account* (G3; `ORCH_RELAY_ACCOUNT_WORKSPACES`, default 32), at the first card: a person that
    already owns 32 workspaces gets 429 `quota_exceeded`. Workspaces are never deleted, so "live" is every
    workspace the person owns, and the cap is a lifetime cap until a workspace deletion route exists; the
    operator could raise it only globally (one environment variable for every account; the audited per-account
    override came with P3-D36). Migration to a new workspace, the documented exit for the node quota, the ever-device cap and a wrong
    genesis pin, burns a slot each time (review F2; pre-public item in the checklist below). Judgement: the staging cap alone closes the G3 staging attack, but without a bound on
    workspaces every per-workspace cap (the node quota, staging slots, the refused-heads budget, the admission
    gate's fairness, F5) multiplies by an unbounded count (10 new workspaces per hour). The card route is the
    only place workspaces are created and already runs per-owner checks, so the cap belongs there. It is a
    read-only check, placed after the card and delegation signature checks and the side-effect-free
    (`charge=False`) creation windows and before `authorized()`, so the P3-D32 pre-check refuses it without
    `Directory.lock` and a refused card charges no creation window.
  - *Stored nodes per workspace* (G4; `ORCH_RELAY_WORKSPACE_NODES`, default 4,000,000 ≈ 1.17 GB at 293 B per
    node, about 4.4 full 64 MiB staging sets). The quota is on `checkpoint_node_usage.nodes`, which includes
    orphans (never on `orphaned`, which is cumulative). Checked at the commit point of the publication, after
    every fold and R0–R5 check: in phase A on its snapshot (stored nodes plus the new nodes it collected), so a
    publication over the quota never reaches phase B and inserts nothing; and again in phase C live (stored
    nodes, excluding nodes phase C inserted itself in this transaction, plus those inserted live and the new nodes
    of reused phase A folds that phase B did not store). A publication that adds no new node (a retry over
    orphans, a checkpoint whose nodes are all stored) is never refused by it. The refusal is uncharged like every
    429 (no `checkpoint_failures` row), and its fold work is recorded as refused heads (`settle`), so repeating
    it spends the P3-D33 refused-heads budget (about two full sets per workspace-hour) and then stops at the
    budget check before any fold. Charging a failure row instead would let the quota consume the 16/48 refusal
    slots that protect the holder generations, for a condition the host cannot fix by retrying. Exactness: the
    nodes of a workspace are written only by that workspace's publications, which the per-workspace mutex
    serializes through phases A to C, so phase A's check is exact; phase C re-checks it anyway. This assumes one
    relay process per database, as P3-D33 does (the mutex and the gate are per event loop): with several
    processes phase C still refuses, but phase B could leave up to one set's nodes as orphans above the quota
    (review F6).
    Earlier refusal (before the folds) is not possible without a lower bound of the new nodes: a publication
    whose nodes are all stored must pass at any usage.
  - *Receipts and tombstones* (G4). `checkpoint_receipts` keeps the newest 256 rows per workspace and
    `checkpoint_gone` the newest 4,096 (rowid order, evicted after an insert; neither is referenced by another
    table). Safe: the newest receipt is always the held checkpoint's (only an acceptance writes one), and a host
    retries only its last unanswered publication, so an evicted receipt is one with at least 256 later
    acceptances; its exact retry is then judged live (an append is `ignored`, a restore
    `restore_source_mismatch`), never wrongly accepted, because a checkpoint hash includes `n` and `n` only
    grows. An evicted tombstone turns a 410 `checkpoint_gone` into a 404 `not_found` for an endpoint that was
    superseded more than 24 hours and at least 4,096 purges ago; both are refusals, a device restarts its walk
    (410) or reports `sync_incomplete` (404) and never accepts anything from either, and a gone hash cannot be
    re-accepted (lower `n`). Charging differs by kind (review F6): an evicted append retry is `ignored`
    (uncharged), an evicted restore retry is refused `restore_source_mismatch` and charged one failure row (no
    heads); both need 256 later acceptances first.
  - *Self-certified restore evidence per owner person* (`ORCH_RELAY_ACCOUNT_EVIDENCE`, default 50,000 pairs,
    table `account_evidence_pairs`, migration 0015). A restore entry is counted when its device has no
    association (self-certified, orch-core #397) and the global §19.5 table does not hold its `(device_id,
    person_id)` pair yet, i.e. exactly the entries that add a global `revocations` row. Checked after R4
    coverage and before any fold, in phase A (so phase B never runs) and live in phase C; charged to the
    workspace's owner person (the restore signer's person, by `owner_policy`) only when the restore commits.
    It cannot be used to block a victim: re-carrying a pair the table already holds (all of a workspace's chain
    pairs, which R4 makes a victim carry, are in it, since every accepted restore writes them globally, and the
    table never loses a pair) costs nothing and is never refused, and a victim's restores are charged to the
    victim's own account only, which an attacker cannot spend (only the owner device signs a restore line, so
    only the owner chooses its evidence). A reason upgrade of an existing pair is not new. Associated devices'
    entries are not counted (their key is bound by the registry; bounded by registrations). Size: an entry is
    about 1 KB (`cj`), so about 500 per 512 KiB line; 50,000 pairs is about 100 such restores and about 75 MB of
    global and chain rows per account, far above honest use (an owner revoking its own unknown devices).
    Migration 0015 backfills the count from each owner's chain pairs of unassociated devices (approximate: a
    pair carried in several owners' workspaces counts for each).
  - *Permanent quotas look transient (review F5).* The node quota, the workspace cap and the evidence quota answer
    the same 429 `quota_exceeded` with `Retry-After: 1` as the transient budgets (the refusal and refused-heads
    windows), so a host cannot tell them apart from one answer. Each retry of a publication over the node quota
    costs a full phase A (folds and up to ~1.2 GB peak memory for a full set) until the workspace's refused-heads
    budget is spent; then retries stop at the budget check before any fold. Follow-up for orch-52 to rule on, not
    implemented: an error detail such as `{"error": "quota_exceeded", "quota": "nodes"}` (no new code; values
    `nodes`, `workspaces`, `evidence`, `account_staging`) and/or a longer `Retry-After` for the permanent caps.
  - *Not modelled in `ref/checkpoints.py`:* like the 4 GiB ceiling, these are deployment limits, not protocol
    state; no vector or fixture reaches them at the defaults, so no vector or fixture changed.
  - *Pinned by* `tests/test_caps.py` (each cap refused over it, honest use exactly at it accepted,
    authorization before it, the workspace cap in the pre-check without the lock, the staging cap exact under 12
    concurrent PUTs, release on expiry and deletion, ceiling order, node quota in phase A with no phase B and in
    phase C, orphans counted, no-new-node publications never refused, live inserts counted once, concurrent
    publications, receipt and tombstone eviction keeping the newest, evidence counted only for new pairs and per
    owner, the phase C live re-check, the 0015 backfill, the environment knobs). Targeted mutation (one at a time
    on a scratch copy): 21 of 21 killed. Review of PR #58 (F4): a second owner's workspaces do not count, eviction
    never crosses workspaces, associated evidence is not counted (review mutants O2, O12, O4 now killed).
- *Measured* (`uv run python tests/bench_checkpoint_capacity.py`, `docs/p3-checkpoint-capacity.md`).
- **P3-D35 (session token buckets on authenticated requests, O(1) poll admission, proxy warning; pre-public-deploy
  blocker 4).** Protocol §19.4 (P3-D17 budgets) and §19.6 state the observable rules; this is the decision record.
  Closes G3 re-review N1 (no per-session bucket on bridge routes: authenticated `wait=0` polls and identical
  resends were unlimited write transactions), N3 (`admit()` summed the poll table) and N4 (no warning when
  `ORCH_RELAY_TRUSTED_PROXY` is unset behind Caddy), and the G4 / P3-D33 review note that authenticated reads and
  refusals were not rate-limited.
  - *What is charged* (as of round 2, below). Every request that carries a valid session on a directory (§19.1,
    §19.2, §19.5), bridge (§19.3, certificate queues included) or checkpoint (§19.8, unpublished included) route is
    charged to exactly one bucket class. *Read* (everything not listed next): the session's bucket, keyed by the
    device for a device session and by the token for a W session, plus the person's bucket (device sessions) or the
    workspace's (W sessions, which are not capped in number). *Page* (proof and transition pages): the page buckets
    of the same identities, weighted by the work returned. *Staging* (staging page and manifest PUTs): one bucket
    per workspace. *Host answer* (a W session's ORB2 response or pair answer): one bucket per (workspace, target
    device). Long polls are charged once per request (their wake-up re-checks are bounded by the admission slots
    and the 5–7 s tick), so authenticated `wait=0` polls, polls that return at once and identical resends are
    bounded per device.
  - *When: after authentication, before anything else.* The charge comes after the read-only authentication of
    P3-D32 / G3 review 3 and before `Directory.lock`, a write transaction, a poll slot, a waiter or the checkpoint
    snapshot read. A request with no valid session (no, a malformed, an unknown, an expired token, a revoked or
    expired device) charges no bucket and creates no table entry, so an attacker without the token can never burn
    an honest session's bucket, and a flood of distinct bad tokens costs no memory. A valid session's refusals
    after authentication (403 `not_eligible`, 409 `fenced`, 404, 400 `malformed`) are charged the same: the holder
    of a token only burns its own buckets. An empty bucket answers 429 `rate_limited` with `Retry-After` (whole
    seconds to the next token) in place of whatever the request would have answered; no new code, no shape change.
  - *Defaults* (burst, refill per minute; `ORCH_RELAY_THROTTLE_<NAME>="burst/per-minute"`): session 600, 600
    (10/s); person 1,200, 1,200; workspace 1,200, 1,200; page-session 5,914, 600; page-person and page-workspace
    11,828, 1,200; staging 28,801, 600 (10/s), weighted by body size (P3-D36; was 27,777, 3,000 unweighted);
    host-answer 1,200, 1,200. The arithmetic, round 2:
    - *Read.* Honest hosts and phones long-poll (`wait` up to 25 s) or poll at most every few seconds (≤ 0.5/s),
      and a directory sync reads the card, members, grants, a card key and a few certificates: 600 of burst and
      10/s per device are 20x above an honest client's peak. A person with 2 devices at full rate fits its 1,200.
      What it bounds: one device at 10 lock-taking directory requests per second (about 0.1 % of the lock at the
      measured ~60 µs each).
    - *Page.* A device without H walks one full proof per grown log (ref `sync_walk`, protocol §19.8 device
      synchronisation step 5). A full 64 MiB set (`STAGE_CAP / 74` = 906,876 heads) is 17 pages of at most
      `PROOF_PAGE_HEADS` = 56,678 heads; at one token per started 1,000 heads that is 16 x 57 + 1 = 913 tokens.
      A 5,000-ticket workspace has 5,001 logs, each at least one page: 5,001 more. So the page burst is 5,914
      and a first sync of that workspace (or of a full single-log set) completes at once without a 429. The refill
      of 10 tokens/s bounds sustained bandwidth to 10,000 heads/s (~740 kB/s) per device; a flood of full pages
      gets 104 pages, then one every 5.7 s. The first token is taken before the read; the rest of a page's weight
      after it, as debt (the level may go below zero, so the next request waits for it). *Limit of the
      no-429 claim (delta review S2):* a new device proves every log from its start, so the cost grows with the
      workspace's whole history, not with one staging set. It holds while the history is at most about 907,000
      heads (one full set) across at most 5,001 logs; beyond, the walk waits about
      (heads / 1,000 + logs - 5,914) / 10 seconds in all (2.5 million heads over 5,001 logs: about 158 s), obeying
      `Retry-After`. Deployments with long histories raise `ORCH_RELAY_THROTTLE_PAGE_SESSION`.
    - *Staging.* A manifest is at most `PAGE_CAP`, and its smallest canonical descriptor is 150 bytes plus a
      comma, so one staging set has at most 27,776 pages; the burst is that plus the manifest, so the largest
      honest set (and a 5,001-page one) uploads without a 429 and never touches the host's session. Staging PUTs
      take the lock, so they stay bounded per workspace: 50/s after the burst (a full set again after ~9 min).
      Superseded by P3-D36: one token per started 64 KiB of body, burst 28,801, refill 600/min.
    - *Host answer.* A member posts at most 20 requests/s (`bridge-post`) and 10/s on its device bucket; the host's
      answers to it are charged to (workspace, that device) at 1,200 burst and 20/s, the rate of the existing
      `bridge-host-post` window. A member therefore spends only the host's answers to itself; the host's polls,
      `hold` and answers to other members keep their buckets. The key is never the poster's free choice (security
      review of round 2: keying by the envelope's target alone let a W session name a fresh device per post, each
      a fresh bucket and a lock-taking refused transaction, and flood the table): a bridge response uses
      (workspace, target) only when the target has a live request on that rid (`rid_seen` without an offer,
      written only by an eligible member's own post), so the keys are bounded by the members' requests; anything
      else is charged to the host's read buckets. All pair answers of a workspace share the key
      (workspace, "pair"). The check is one indexed read on a pooled snapshot before the transaction, which
      re-checks everything.
  - *Store.* In memory (`Directory.buckets`), under the budget mutex like the rate windows (P3-D32): all buckets of
    a request are checked without side effects, then charged. Levels are integers in 1/60,000 of a token, so
    counts are exact under an injected clock; a clock that goes back adds nothing. Each key class (session,
    person, workspace, the three page classes, staging, host-answer) has its own bounded table
    (`ORCH_RELAY_THROTTLE_TABLE`, default 16,384 entries per class, about 470 B each: ~7.6 MB per full class, ~61 MB
    if all 8 were full), so keys of one class never evict another's. Beyond the bound the entry evicted is, among
    the 64 least recently charged, the first that has refilled completely (lossless: a missing entry is a full
    bucket), else the one closest to full; a depleted bucket is not reset by a flood of fresh identities while
    fuller ones remain (security review of round 2). Reset on restart (accepted, like every window). No migration.
  - *N3.* `Bridge.polls` keeps running totals (all polls, and per key kind: pair, device, workspace) updated on
    every table write (admit, release, also direct writes), so `admit()` is O(1). Pinned at zero after a
    timeout, an exception in the transaction, a replaced host poll and a cancelled request.
  - *N4.* `Directory.client_address` logs one WARNING per process when a request carries `X-Forwarded-For` while
    `ORCH_RELAY_TRUSTED_PROXY` is unset, and start-up logs one when `ORCH_RELAY_BEHIND_PROXY` is set without it.
    The relay still starts (a direct deployment may receive client-sent `X-Forwarded-For`, which it ignores).
  - *Unauthenticated reads (item 4).* The public revocation-pair read had only its per-address window (60/min);
    it now also has a per-IPv6-/56 window (960/min), as challenges and pairing. Challenges, pairing, recovery
    and the first card already had per-address windows; `/healthz` is static. 401 refusals of authenticated routes
    are deliberately not charged per address: they take no lock (~15 µs, P3-D32), and a per-address 401 budget
    would let an attacker behind the same address (or every client, with N4's misconfiguration) turn honest
    clients' 401 into 429 and delay their re-login. The Caddy per-IP limit covers them.
  - *Refusals.* A refusal after authentication always takes one token of the session's read class, whatever the
    route, so a refused staging PUT or host answer for a workspace the session may not write never spends that
    workspace's staging bucket or that target's answer bucket.
  - *Not charged.* The sqlite3.Error fallbacks of the bridge, directory and checkpoint pre-checks (the
    transaction authorizes alone; rare: WAL readers do not wait). Request bodies (up to 4 MiB) are read before
    the charge, so bandwidth is bounded by the proxy, not the bucket.
  - *Pinned by* `tests/test_throttle.py`: every authenticated GET family fires at the limit and not below with
    `Retry-After`; requests without a valid session charge nothing and create no entry; a session's refusals charge
    only its own bucket, other sessions of the same device and the host unaffected; W sessions share the workspace
    bucket and device sessions do not; resends charged; a throttled request takes no lock and no slot; anonymous
    pairing charges no bucket; the page buckets; checkpoint writes charged only after authorization; the bucket
    (exact counts, no side effects on a check, refill cap, clock going back, Retry-After, bounded LRU, a table
    bounded under many valid sessions); the revocation-read /56 window; the N4 warnings (once; not with a proxy;
    at start-up); the environment knobs; the N3 counters (no table scan in `admit()`, direct writes, timeout,
    exception, replaced poll, cancel, both ceilings). Load tests and benchmarks that flood one session on purpose
    lift the buckets (`directory_support.unthrottled`). Round 1 targeted mutation (one at a time on a scratch copy):
    36 of 36 killed (removed, charged before authentication, shared or wrong key, and refusals uncharged for
    each of the directory, bridge, checkpoint read, checkpoint write, unpublished and page throttles; the bucket's
    check, eviction, refill cap, clock, Retry-After and environment; the revocation-read /56 window; the N3
    counters, scans and pair share; the N4 warnings). The first run left one survivor (the pair share compared
    with the total), killed by an added test.
  - *Round 2 (Opus review of PR #59).* F1: the round 1 page arithmetic counted only the single-log case ("a few
    dozen pages", and 16 instead of 17); the reference walk makes one proof per grown log, so a phone's first sync
    of a 5,000-ticket workspace needed 5,001 pages (about 40 minutes and 2,373 refusals at 256 / 2/s), and staging
    those 5,001 pages held the host's own session at zero for about 7 minutes. Now proof and transition pages
    charge only the page buckets, weighted by heads, with the burst above; staging has its own per-workspace
    bucket. F2: the session key was the token, so a logout and a login gave a fresh bucket (60 tokens from a burst
    of 3 in the review's probe); a device session is now keyed by its device, plus a per-person bucket. F3: host
    answers were charged to the host's session and workspace, so one member sending requests at its own limit
    could push the host into 429 for everyone; they now charge (workspace, target device). F5: tests for one global
    workspace bucket, Retry-After with partial and non-integer refill, the revocation read checking both windows
    before charging, and a clock going back. *Pinned by* `tests/test_throttle.py` round 2: a logout and login loop
    gets one burst; a person's devices share the person bucket; workspaces have separate buckets; proof pages are
    weighted (debt, Retry-After over it); the default page burst serves a 5,001-log first sync under a full set at
    one instant and a flood of full pages gets exactly 104; staging charges only its own bucket, per workspace, and
    its default burst serves a full manifest; host answers spend only the requesting member's bucket, refused
    answers and answers with no request on the rid (also a pairing request's rid) the host's read buckets and mint
    no key; the bucket tables keep a depleted bucket under a same-class flood and never evict across classes.
    Mutation (one at a time on a scratch copy, on the final code):
    62 mutants, 61 killed and 1 equivalent (skipping the early return of a fully refilled eviction candidate:
    it has the highest fill anyway). They cover round 1 re-targeted (removed, before authentication, refusals
    uncharged, shared keys, the bucket, N3, N4), the review's survivors O2, O5, O6, O10 and O15, weighting and
    debt, the page and staging classes and burst sizes, device and person keys, host-answer keys (on the session,
    shared, unvalidated, any offer, refusals on the target) and eviction (plain LRU, emptiest first, one table,
    scan of 1, clock going back). Survivors on the way (staging and answer keys shared, a pairing rid accepted,
    eviction under a clock going back) were killed by added tests.

- **P3-D36 (pre-public limits: staging weighted by size, node-quota restore reserve, per-account workspaces
  override).** Closes pre-public-deploy checklist items 8 (delta review S1), 3 (P3-D34 review F1) and 4 (review
  F2). Protocol §19.4 (the staging bucket) and §19.8 (storage caps) state the observable rules.
  - *Staging weighted by body size, refill 600/min* (`directory.STAGING_BURST`, `staging_tokens`). Before, every
    staging PUT took one token of a 27,777 burst refilled at 3,000/min (50/s) per workspace; each PUT takes the
    global write lock, and an identical 4 MiB re-PUT reads and compares 4 MiB under it, so one account (32
    workspaces) sustained ~1,600 such writes/s (~6.4 GB/s of compares under the lock). Now a PUT costs one token
    per started 64 KiB of its body (`STAGE_TOKEN_BYTES`), at least one, charged after authorization from the
    length of the body the transport read. *Burst.* A set is at most `MANIFEST_PAGES` = 27,776 pages plus its
    manifest and at most `STAGE_CAP` = 64 MiB in all (manifest included); a piece of `s` bytes costs
    `1 + floor((s - 1) / 64 KiB)`, and the extra terms sum to at most `floor(64 MiB / 64 KiB)` = 1,024, so no
    honest set costs more than 27,777 + 1,024 = **28,801**, the burst: it uploads with no 429 at one instant
    (pinned with an injected clock). Worked: 5,001 one-head pages (~300 B each) plus their ~0.9 MB manifest =
    5,001 + 14 = 5,015 tokens; a full 64 MiB set in 4 MiB pages = 15 x 64 + 64 + 1 = 1,025 tokens; the largest
    set by count (27,776 small pages and a 4 MiB manifest) = 27,840. Weighting is safe for honest sets because
    the burst carries the byte allowance; small pages pay what they paid before. *Refill: 600/min (10 tokens/s,
    640 KiB/s per workspace).* A full burst comes back in 28,801 / 600 ≈ 48 min. Judgement: acceptable, because
    only the pathological largest-by-count set drains it: a repeated full 64 MiB checkpoint in 4 MiB pages costs
    1,025 tokens (back in ~1.7 min), a repeated 5,001-page set 5,015 (~8.4 min), and an incremental checkpoint a
    handful; and the burst is not one set's worth but holds five 5,001-page sets or 28 full 4 MiB-page sets back
    to back. A host that stages beyond it is paced by `Retry-After` (10 small pages/s), never failed.
    1,200/min was not needed. What it bounds: per
    workspace 10 tiny lock-taking writes/s or one 4 MiB re-PUT per 6.4 s (a flood of 4 MiB re-PUTs gets 450,
    then one per 6.4 s; a flood of tiny PUTs 28,801, then 10/s); per account (32 workspaces) 320 writes/s or
    20 MiB/s of compares, down from ~1,600/s and ~6.4 GB/s. Residual: the per-account burst is still 32 x 28,801
    tiny lock-taking writes (~0.9 million) once per ~48 min; a per-account staging bucket would bound it if
    invites open (not done: it needs sizing against honest accounts that stage several workspaces at once).
  - *Node-quota restore reserve* (`Caps.reserve`, `ORCH_RELAY_WORKSPACE_NODES_RESERVE`; unset: 5 % of the
    configured quota, **200,000** of the default 4,000,000). An ordinary publication (any final publication
    without a verified owner-signed restore) is refused 429 `quota_exceeded` once stored + new nodes would
    exceed `quota - reserve`; an owner-signed restore may fill up to the full quota. The flag is the restore
    that `restore()` verified (owner policy, signatures, R0–R5) before the commit point, so a WSK holder cannot
    claim it; `node_quota()` is the same call at phase A's commit point and in phase C, so both use it, and the
    refusal keeps the P3-D34 treatment (uncharged, fold work recorded as refused heads; phase A inserts
    nothing, phase C rolls back). *Why it holds against a hostile fill:* phase B inserts only after phase A
    passed the ordinary limit, and one workspace's phases are serialized, so accepted publications and orphans
    of refused ones (the hostile holder's two ways to store nodes) never take stored nodes above
    `quota - reserve` (pinned). *A restore's node cost* (from `publish`/`restore`): its line head (1) plus every
    head of its staged set that is not stored yet: retained pages of a branch the relay does not hold and
    appended pages of other logs (abandoned pages re-prove the stored branch: 0). So 1 node for the recovery
    case (roll back to a stored prefix, no other log growing), at most `STAGE_CAP / 74 + 1` = 906,877 for a
    restore that carries a full set of new history. 200,000 fits 200,000 minimal restores, or, e.g., four that
    each carry 50,000 new heads; a restore that must carry more new history than the reserve has left is
    refused like an ordinary publication (sizing it for one full set would take 23 % of every workspace's
    quota). Remaining: after a hostile fill, ordinary appends stay refused (nodes are never pruned), so the
    restore's role is to abandon the hostile branch so devices follow the owner's chain; the owner then migrates
    (one slot, see the override below). Validated at start-up: `0 <= reserve <= quota`.
  - *Per-account override of the workspaces cap* (migration 0016). `account_workspace_override(person_id
    PRIMARY KEY, cap 1..10,000 (CHECK), set_by, set_at_ms, note)` and the append-only
    `account_workspace_override_audit(seq, person_id, old_cap, new_cap, set_by, set_at_ms, note)` (triggers
    refuse UPDATE, DELETE and an insert naming an existing `seq`, which closes REPLACE: round 2), written together in one `BEGIN IMMEDIATE` by the operator command
    `orch-relay account-cap set <person_id> <cap> --by <operator> [--note ...]` (JSON on stdout); `account-cap
    show <person_id>` (owned workspaces, effective cap, override) and `account-cap audit [<person_id>]` (one
    JSON row per line, oldest first) only read. No HTTP route: there is no remote admin surface. The person must
    have an account; the cap must be an integer 1..10,000 (`MAX_ACCOUNT_WORKSPACES`; 10,000 x the default node
    quota is far beyond any disk, so it is a typo guard); `--by` 1..128 and `--note` up to 1,024 characters, no
    control characters. A lower override is allowed (it refuses new first cards, deletes nothing). *Locking:*
    the command opens its own connection and takes SQLite's write lock with `BEGIN IMMEDIATE`, with the relay
    running or stopped; while the relay holds the lock (each of its write transactions is short: a node chunk
    ~0.2 s, a commit) the command waits up to `ORCH_RELAY_ADMIN_BUSY_MS` (default 5,000 ms), else exits 1 with
    nothing written ("database busy"; retry); bad input exits 2 with nothing written. It never migrates
    (a relay may be serving the database): migration 0016 must be applied (`orch-relay migrate` or a relay
    start), else it exits 2. *Operations (round 2):* run it as the relay's user, `sudo -u orch-relay env
    ORCH_RELAY_DATA=<the unit's data directory> orch-relay account-cap ...`; it opens the database with
    `mode=rw` (a wrong or unset `ORCH_RELAY_DATA` gets exit 2 "no database", never a new empty database), and
    refuses (exit 2) unless the effective user owns both the database file and its directory, since SQLite may
    create `-wal`/`-shm` files there that a killed command would leave owned by another user, after which the
    relay fails with "readonly database". The relay caches nothing: the next first card's check reads the
    row (`Directory.workspace_cap`, one primary-key read on the caller's connection), in the read-only P3-D32
    pre-check (so an over-cap card is still refused without `Directory.lock`) and again in the transaction
    under the lock (exact under concurrency, as P3-D34). An account without a row keeps the global
    `ORCH_RELAY_ACCOUNT_WORKSPACES`. Not done: a workspace deletion or archival route (slots stay lifetime).
  - *Round 2 (Opus review of PR #61: pass with required changes).* F1: the audit's DELETE trigger does not
    fire for the delete inside `REPLACE` / `INSERT OR REPLACE` (`recursive_triggers` is off), so a row naming an
    existing `seq` silently overwrote an audit row; 0016 (applied nowhere yet, so edited in place) gains a
    `BEFORE INSERT ... WHEN EXISTS (... seq = NEW.seq)` trigger. F2: the account-cap commands opened the
    database through `db.connect`, which makes the directory and creates the file; they now use
    `db.connect_existing` (`mode=rw`) and the ownership check above. `invite create` gets the ownership check
    for an existing database; it still creates a missing one (a fresh deployment's first invite relies on it;
    a wrong `ORCH_RELAY_DATA` there still makes a stray database: left open). F3 (pre-existing): stopping the
    relay while a maintenance sweep waited in `BEGIN IMMEDIATE` on another process's lock crashed it (SIGSEGV):
    the lifespan's `cancel()` returns at once while the anyio worker thread keeps running, and `Bridge.close()`
    closed the shared write connection under its statement. `Bridge.close()` now closes the pool under
    `Directory.lock` (both sweeps hold it for their whole run), and both maintenance loops log a
    `sqlite3.Error` and continue (one busy sweep used to end the loop for the process's life and make the
    lifespan's `await task` re-raise and skip `close()`). Data were never at risk (the transaction had not
    begun). F4: test gap only; the staging weight is the bytes the transport read, never the declared
    `Content-Length` (a chunked body now pins it). F5 (noted, accepted): a restore publication's reserve
    covers the whole publication, including appended pages of other logs in the same restore, not only the
    restore line; that needs an owner-signed, single-use restore line bound to the held checkpoint plus the
    WSK signature, so a delegated host cannot use it, while a compromised owner device can burn the reserve
    (it can do far worse). *Pinned by* `tests/test_account_cap.py` (both REPLACE forms and an explicit
    existing `seq` refused, fresh rows allowed; a missing database and its directory never created; another
    user's file or directory refused, also by `invite create` and the CLI with exit 2; `mode=rw` never
    creates), `tests/test_shutdown.py` (the app in a subprocess shut down while its sweep waits on another
    connection's lock exits 0, asserted by exit code; a busy sweep keeps both loops running) and
    `tests/test_throttle.py` (a chunked staging body charged by the bytes read). Mutation, one at a time on a
    scratch copy: 13 of 13 killed (the REPLACE trigger; `mode=rwc`; no existence check; no owner check; file
    or directory owner only; the account-cap and invite owner checks skipped; the CLI's invite error; close
    without the lock; either loop dying on a busy sweep; the declared length charged), two of them (`rwc`,
    directory owner only) after added tests.
  - *Still open:* checklist item 5 (the ever-device way out: offline compaction and the audited per-workspace
    ever-device override, orch-d6 ruling) and item 6 (429 detail for permanent quotas).
  - *Pinned by* `tests/test_throttle.py` (the defaults and their arithmetic; an honest 5,001-page set, a full
    64 MiB set and the largest set by count with no 429 at one instant; tiny and 4 MiB floods cut off at exact
    counts with exact refill; the HTTP route's weighting by body size, a 429 charging nothing),
    `tests/test_caps.py` (ordinary publications refused at `quota - reserve` in phase A and re-checked in phase
    C, uncharged with refused heads; a hostile fill by orphans stops at `quota - reserve`; a restore accepted
    into the reserve, also after a fill and through phase C, refused at the full quota; the environment knob,
    its 5 % default and its validation) and `tests/test_account_cap.py` (the override raises or lowers the cap
    for one account only, read in the lock-free pre-check and re-read in the transaction; override and audit
    written atomically, the audit append-only; bad caps and inputs refused, also by the schema; a busy database
    writes nothing; the CLI's set, show, audit, bad input and busy exit).
    Targeted mutation (one at a time on a scratch copy): 36 of 36 killed (staging: unweighted, size not passed,
    floor instead of ceiling, no minimum token, refill 3,000 or 1,200, burst without the byte allowance, a
    128 KiB token; reserve: ignored, applied to restores too, restores unlimited, the restore flag in phase A
    only or phase C only, a strict comparison, the environment ignored, no upper-bound check, the default from
    the default quota, a doubled reserve; override: ignored, of any account, only under the lock, no audit row,
    audit in its own transaction, no upper, lower or type bound, no account check, old cap lost, control
    characters, audit deletable or updatable, no schema CHECK, busy exit 0, `show` and `audit` filters, no
    schema check).

- **P3-D37 (a hard maximum publication size; owner decision, no VPS resize).** Protocol §19.6 and §19.8 state
  the observable rule. *Why:* the dev VPS has 1,961 MB of RAM and no swap. Phase A holds every new node of a
  publication (about 1.3 KB of peak process memory each, measured on macOS), and the gate (`Gate.fits`) admits a
  publication above `ORCH_RELAY_PUBLISH_HEADS` when nothing else runs, so the gate never bounded one
  publication: a full 64 MiB set (906,876 heads) needs about 1.2–1.45 GB in phase A, above either relay unit's
  `MemoryMax` (public 900M, internal 450M in the dev-kit PR #27 draft), and the unit is OOM-killed.
  - *The limit.* `ORCH_RELAY_MAX_PUBLICATION_BYTES` (`Caps.max_publication`, default `MAX_PUBLICATION` =
    **16 MiB**) bounds the staged bytes of one set, measured exactly as `checkpoint_staging.bytes` (the manifest
    plus every page, the bytes the P3-D20 quotas charge). Validated at start-up: a decimal integer in
    `1..STAGE_CAP` (64 MiB), else the app does not start (`ValueError`). It is a per-set bound below the
    per-workspace 64 MiB quota (two sets), the per-account 512 MiB and the 4 GiB deployment ceiling, which are
    unchanged.
  - *Where it is checked.* (1) Staging, 413 `too_large`, after authorization and the existing staging checks
    (identical retries stay free no-ops, conflicts stay `staging_conflict`) and **before** the transient staging
    quotas (429/503), so a host never retries a set that can never fit. A page PUT: the set's staged bytes plus
    this page (running total). A manifest PUT, before any page is uploaded: the set's staged bytes, plus the
    manifest, plus 74 bytes per head of every listed page not staged yet. That is a lower bound of the whole
    set (a page of n heads is at least 74 n bytes: 73 JSON bytes per head plus separators and its framing), so
    a manifest whose set cannot fit is refused at once and an honest set is never refused early; the pages
    then meet the running total. (2) The final publication, 400 `too_large` (the route's existing `too_large`
    status, P3-D20), right after `staging_incomplete` and before `load_stage`: no staged page is read and no
    head is folded, in phase A and again in phase C (defence in depth: a set staged under an older, larger
    maximum, or a restart with a lowered one). Charged like the route's other `too_large` (one failure row,
    zero refused heads: it did no fold work); its set reserves no heads in the gate (`weigh` is 0).
    (3) The gate: unset, `ORCH_RELAY_PUBLISH_HEADS` is now `max // 74` (226,719 by default; was 1,500,000), the
    heads the maximum implies, so one maximal publication always fits alone and the publications in flight on
    one instance never reserve more than one maximal set together (small ones still run two wide). An operator
    may set the heads cap lower than the maximum implies (a maximal set then runs alone) or higher (two maximal
    sets may then run at once: count `max(heads cap, max // 74) x 1.3 KB` in the memory budget).
  - *Code decision: `too_large`, never 429.* The limit is permanent for that set: the same bytes can never be
    accepted, whatever the host waits, so a 429 `quota_exceeded` with `Retry-After` (transient by §19.6) would
    make hosts retry forever, and the P3-D34 permanent quotas are already flagged as looking transient (checklist
    item 6). `too_large` is the existing permanent size refusal; each route keeps its one `too_large` status
    (413 on the staging routes, §19.6; 400 on the final publication, P3-D20), so no new code or status. A host
    that gets it on a request within the request cap knows it is the set.
  - *Cleanup: the staged set is kept.* A refusal writes nothing (the module rule: "a refused write leaves the
    database unchanged"); pages staged before the refusal stay until the set's one-hour expiry, and they never
    exceed the maximum (each accepted PUT stayed within it). Deleting the set would make every refused PUT a
    write under the lock and gain nothing: the set's bytes are bounded and
    expire, and its slot (two live sets per workspace) frees within the hour. A final publication refused as `too_large` also keeps its set,
    like every publication refusal (P3-D33).
  - *Restores* use the same maximum: a restore's staged set (abandoned, retained and appended pages) goes
    through the same routes and the same publication check. **Limitation:** a restore must stage its whole
    abandoned suffix (from `from_seq` up to the source's height) plus any retained branch and other logs' growth
    in one set, and cannot be split, so a restore whose set exceeds the maximum (about 226,000 heads at 16 MiB,
    56,000 at the 4 MiB recommended for the internal instance) cannot be published. Before P3-D37 the same
    limit existed at the 64 MiB quota (~906,000 heads). A WSK holder can grow the hostile suffix past it with
    several publications (each within the maximum), and then the owner's roll-back past that suffix is
    impossible; the exit is migration to a new workspace (as for the node quota). Ordinary growth is not
    limited the same way: a host can publish a long backlog as several checkpoints with intermediate `n`, each
    within the maximum (a host change, see below). A larger limit for restores alone was not taken: staging
    cannot tell a restore set from another before the final request, and phase A's memory for abandoned pages
    is not measured. Follow-up: the streaming verify below, which removes the reason for the limit.
  - *Constants not changed.* The staging bucket's burst (28,801, P3-D36) is derived from the 64 MiB quota; with
    a smaller maximum every honest set costs fewer tokens, so the burst still uploads any honest set with no
    429 (it only becomes generous). `REFUSED_HEADS` (about two 64 MiB sets of fold work per workspace-hour) is a
    CPU budget; a refused publication now folds at most one maximal set (eight fit the budget). The node-quota
    reserve is unchanged (a restore now adds at most `max // 74 + 1` new nodes, 226,720 by default). No schema
    change.
  - *Memory arithmetic (the defaults and the per-instance recommendation).* Assumptions: 1.3 KB per new node
    in phase A as measured on macOS arm64 (CPython 3.14); **the figure on the VPS's Python is not measured**
    (run `tests/bench_publication_lockhold.py` there), so add a 25 % margin; a head is 74 bytes on the wire;
    a ~250 MB baseline per instance (Python, SQLite, read-pool page caches, throttle tables, in-flight bodies);
    systemd's `900M`/`450M` are MiB (943.7 MB / 471.9 MB). Public, **16 MiB**: 16,777,216 / 74 = 226,719
    heads x 1.3 KB = 295 MB, +25 % = 368 MB, + 250 MB = **~618 MB < 944 MB** (`900M`; 34 % headroom).
    Internal (`450M` = 471.9 MB): 8 MiB = 113,359 heads, 147 MB, +25 % 184 MB, + 250 = 434 MB, 8 % headroom:
    too tight (the baseline alone ranges 150–250 MB plus up to 61 MB of throttle tables); 6 MiB = 85,019 heads,
    111 MB, 138 MB, **388 MB** (18 %); 4 MiB = 56,679 heads, 74 MB, 92 MB, **342 MB** (28 %). Recommended:
    **4 MiB on the internal instance** (keeps the checklist's 25 % headroom; it still carries a 5,000-ticket first
    publication with 4 heads per log, 5,001 pages of 542 B and an 854,055-byte manifest = 3.56 MB of
    4.19 MB), 6 MiB only once `MemoryPeak` on the VPS shows a baseline of 200 MB or less.
    The VPS with one maximal publication in flight per instance: 618 + 342 + Caddy ~100 + OS ~250 = **~1,310 MB
    of 1,961 MB** (67 %, under the 75 % rule); even both units at their `MemoryMax` (944 + 472 MB) plus 350 MB
    is 1,766 MB, and an overrun kills the relay unit, not another process.
  - *Long-term follow-up: streaming verify* (P3-D33 residual). Phase A materialises every new node (dicts and
    tuples, ~1.3 KB each) and every staged page body until phase B. Either pack rows compactly (raw 32-byte
    `acc`, `head`, `prev_acc` and the seq in arrays: ~110 B of payload, roughly 250–300 B per node with
    container overhead, 4–5x less: a 64 MiB set ~250 MB) or stream them to a temporary table in `NODE_CHUNK`
    chunks that phase B copies (memory O(chunk): 20,000 rows ~26 MB plus one 4 MiB page, independent of the set).
    With that, the maximum can return to the 64 MiB quota and restores of large histories become possible again.
  - *Host side (orch-52).* A host must treat 413 `too_large` on a staging PUT and 400 `too_large` on a final
    publication within the request cap as permanent for that set: do not retry it unchanged; split ordinary
    growth into several checkpoints, and surface an oversized restore to the owner (migration). The maximum is
    a deployment value; since P3-D38 the relay advertises it as `max_publication_bytes` in `GET /v2/relay-info`
    (unauthenticated, an operator statement).
  - *Pinned by* `tests/test_max_publication.py`: each place refuses at max + 1 and accepts at max exactly (page
    running total, manifest implied size with and without staged pages, final publication in phase A and in
    phase C), the manifest refusal stores nothing (no set, no page), the page refusal keeps the set's pages at or
    under the maximum and identical retries free, the refusal precedes the 429 byte quotas (the two-live-sets 429 of a new set comes first) and follows
    authorization (401, 409 `fenced`), the publication refusal reads no page, folds nothing, reserves nothing in
    the gate, records one failure and no refused heads and keeps the set; a restore refused and accepted at the
    boundary, its staging refused too; the environment, its default, the derived heads cap and its validation
    (0, -1, non-decimal, empty, above 64 MiB). Honest flows unchanged: every vector and fixture byte-identical;
    one unit test that lowers the 64 MiB quota below the default maximum now reads its caps first.
    Mutation, one at a time on a scratch copy: 18 of 18 killed (each check removed; the manifest's missing
    pages ignored or counted at 73 bytes; `<` instead of `<=` in staging and at the publication; the
    environment ignored; a 64 MiB default; no upper or lower validation; the heads cap not derived; an
    oversized set reserved in the gate; a retryable 429; the publication check after `load_stage`, in phase A
    only, or with 413; the page check after the byte quotas).

- **P3-D38 (H12d relay scope: the reader-version handshake; orch-core orch-v2-host §9, PR #440, decided by
  orch-52, authorised by orch-d6).** The relay's part of H12d is three things; everything else (the gate, reader
  records, `rd` checks) is the host's.
  - *`GET /v2/relay-info`* (protocol §19.1) → exactly `{"v": 1, "reader": N, "max_publication_bytes": M}`.
    `N` is `relay_info.RELAY_READER_LEVEL`, a **code constant (1), never a setting**, so an operator cannot
    misreport it; the module refuses to import if `N ≥ 1` and `AUTH_KINDS` lacks `convenience`. `M` is
    `Caps.max_publication` (`ORCH_RELAY_MAX_PUBLICATION_BYTES`, P3-D37), read per request. Unauthenticated (no
    session is read, no bucket is created), the same answer for every caller, no workspace, person or device
    data; `Cache-Control: no-store` on every answer (no cached level after a deploy); any query parameter is
    400 `malformed`; GET only (other methods get the framework's 405, as on every route). Throttled like the
    public revocation-pair read: its own windows, 60/min per canonical address and 960/min per IPv6 /56, both
    checked before either is charged (protocol §19.4), so it can never spend the revocation read's windows. No
    database access. An old relay answers 404, which the host reads as level 0. **It is an honest-operator
    statement, authenticated only by TLS to the stored origin, never a security control**: a hostile relay can
    claim level 1; its worst case is a refused restore publication, which the host alarms (orch-v2-host §9.8,
    11A.9) and which stays held, blocking every later publication of that workspace until the operator resolves it
    (availability only, review F2).
  - *`AUTH_KINDS` gains `convenience`* (`src/orch_relay/checkpoints.py` and `ref/checkpoints.py`, now one named
    tuple in each): a parse-only change of the R0 restore-line check; every unknown kind stays refused, never
    mapped to a known one. That is what level 1 means.
  - *Vectors and protocol text* for the host and phone, with no relay code: the `reader_decl` label
    (`orch/v2/sig/reader-decl|`), the declaration checks, the pair-request meta v2 (`reader_decl`, §8.3) and
    `rd` in the request meta (§8.6). The relay never sees sealed meta, so neither needs a relay change.
  - ***Rollout order (binding).*** The deployed relay MUST carry `convenience` in `AUTH_KINDS` (this decision)
    **before any convenience-signed restore line can be published to it**: an older relay refuses such a
    restore as `restore_invalid`, and since publications are one ordered chain (11A.5) the held restore blocks
    every later publication of that workspace. Order: (1) this relay deployed (`relay-info` answers level 1);
    (2) orch-core adds the convenience cases to the F1 checkpoint vectors and `reader_kat_1`, the relay vendors
    them; (3) only then may a relay-linked workspace switch convenience signing on (the host checks `relay-info`
    at link and every login). dev-deploy-plan §2 P16.
  - *Core-owned, not done here.* The F1 checkpoint/restore vectors have no `convenience` case yet (the
    vendored `tests/vectors/f1/*` are untouched); the relay-owned `checkpoints` vectors carry a signed
    convenience restore (accepted) and an unknown-kind restore (`restore_invalid`) meanwhile. `reader_kat_1` and
    its digest are core's (F1 §11.5): the `reader_decl` vectors carry core's real level-1 `log` and `view`
    digests (H12d-1, orch-core PR #463; provisional until H12d-2), copied by the generator; the old stand-ins and
    the `depends_on_core` marker are gone.
  - *Capacity and operations.* No schema change, no migration, no new setting. The route costs two in-memory
    windows per address (the existing window table, pruned at the window's end) and no database read; hosts
    call it at link and at each login (every 15 minutes at most per linked host), far below 60/min. The operator
    checks a deploy with `curl -s https://<relay>/v2/relay-info` (expect `"reader":1` and the configured
    maximum).
  - *Pinned by* `tests/test_relay_info.py` (shape, constant level, settings that cannot change it, the maximum
    following the setting and its default, no auth and the same answer for any caller or state, no buckets,
    query refusal, methods as on other GET routes, deterministic address and /56 windows under the frozen clock,
    windows separate from the revocation read), `tests/test_auth_kinds.py`, `tests/test_reader_vectors.py`, the
    HTTP fixture `relay_info.json` replayed in production, and the new checkpoint vector cases. Every existing
    vector and fixture is byte-identical (the vector diff is additions only). Mutation, one at a time on a
    scratch copy: 17 of 17 killed (the level changed or read from the environment, the maximum not following the
    setting, the throttle, the /56 window or the check-before-charge removed, `convenience` removed from the
    relay or the reference (and with the import guard), an auth-dependent answer, no `no-store`, a query
    accepted, and in the reference: no bind or device check, an inexact pair meta, no 2 KiB cap, KAT checked
    above the host's level).

- *Round 2 (Opus review of PR #51).* R1: staged descriptors are grouped by `(kind, log)` once per
  publication; a refused 10,000-ticket x 2-page first publication held the lock 12.7 s (9.4 s in the
  review), now 1.1 s. G2: parsing and every check that needs no database state run after the read-only
  authorization and before the lock; the precomputed refusal is raised in the transaction at its reference
  position, so codes and charging are unchanged (lock hold of a 4 MiB bad-digest page 77 ms → 0.2 ms, of an
  exact retry of a 1.8 MB publication 66 ms → 0.2 ms). L1: failure rows stop at the budget. L2: the
  signer's revocation lookup fails closed. L3: `checkpoint_bound` is dropped (restore signers are current
  list members, members are registered devices, devices are never deleted).

- *Workspace revocations (round 2, F1 #387 / orch-52, provisional).* `checkpoint_revocations` holds this
  workspace's chain pairs `(device, person)`; completeness, carried-evidence binding and the provisional
  `unpublished` result fields follow protocol-v2 §19.8 transport detail 8. Out-of-band (global) revocations
  are hints, never refusals.

- *Round 3 (Opus re-check).* N1: `unpublished` also reports a stronger global revocation of a chain pair the
  restore carries only at chain strength. N2: the unpublished lookup reads only the devices this workspace
  knows (500,000 unrelated global rows: 0.80 s scan before, 64 µs after). N3: test pins (multi-page logs,
  full-strength carriage, chain scoping, precomputed refusal after the budget). N4: an exact retry is found in a
  read snapshot before the lock and skips validation (10k-ticket retry 0.55–0.70 s → 0.06 s wall). N5: on the
  `sqlite3.Error` fallback nothing is parsed before the transaction authorizes.

**Pre-public-deploy gates.** Acceptable on the invite-only dev relay; each must be closed before any
public deployment.

- **G1: publication work inside the global write lock. Closed for honest load and bounded against a WSK
  holder as of P3-D33 round 2** (the round-2 delta check passed the re-check of F1 and F2; its N1
  gate-cancellation fix and N2 per-request budget fix are in; F3 to F5 residuals are listed in P3-D33). A full 64 MiB / ~900,000-head
  publication held `directory.lock` (shared by every write: logins, bridge, membership, recovery) for
  21.4 s with peak RSS about 836 MB, and a refusal at the end of the fold cost the same; refused
  publications repeated 48 times per workspace-hour without re-staging, and blocked writes pinned the
  worker threads, so reads and `/healthz` stalled too. Now: no fold under the lock (at most 5,000 heads of
  live work per round when state changed between phases, then a restart), holds of one 20,000-row chunk
  (~0.2 s) or the commit, waits on the event loop, a refused-heads budget charged on every refusal, and
  orphan accounting. The recommended design, as implemented with the deviations P3-D33 records (the
  fingerprint is the fold key plus live re-reads; the semaphore covers phases A to C):
  - *Phase A, outside the lock:* parse and verify on a WAL read snapshot (H, genesis, the staged set, every
    fold, skip pointers against the snapshot's nodes, R0–R5), under a per-workspace mutex and a global
    semaphore of about 2. Output: the new node rows and a precondition fingerprint (H's hash, the staging
    key, the evidence and policy inputs).
  - *Phase B:* insert the nodes in chunks of 20–50k rows, each a short `BEGIN IMMEDIATE`, releasing the lock
    between chunks. Safe because nodes are immutable, hash-addressed and branch-agnostic, and nothing
    references them yet; orphans after a phase C refusal are verified WSK-signed heads (count them in G4).
  - *Phase C, a short commit under the lock:* re-authorize and fence, re-check receipt and budget, require H
    unchanged and the staging set present, re-run the O(evidence) owner, membership, revocation, binding and
    coverage checks live, then write checkpoint, head, receipt, transition and evidence and delete the set.
  - *Budget by work:* a per-workspace budget of refused heads per hour, or delete the staged set on every
    charged refusal after it was loaded. A per-publication head cap alone does not work: a first publication
    needs a full proof from acc_0.
- **G3: one account can fill the global staging ceiling. Closed by P3-D34.** 4 GiB was 64 full workspaces and
  one account creates 10 per hour, so it could keep every other workspace at 503. Now each owner person stages at
  most 512 MiB across its workspaces (429), and owns at most 32 workspaces (429 at the first card). Remaining:
  F5 (per-account fairness in the admission gate) is bounded by the 32 workspaces but not closed: one account
  can still keep both admission slots busy with accepted publications of its own workspaces, delaying other
  accounts' publications (not logins, the bridge or reads) by about (k/2) x 13 s for k busy workspaces.
- **G4: storage amplification. Closed by P3-D34 for nodes, receipts, tombstones and self-certified evidence.**
  An accepted 64 MiB publication adds ~900k nodes (~264 MB at 293 B/node), repeatable every ~25 s per workspace.
  Now: at most 4,000,000 stored nodes per workspace (orphans included; ~1.17 GB, about 4.4 full sets), checked
  before phase B inserts (429); `checkpoint_receipts` (256) and `checkpoint_gone` (4,096) keep the newest rows
  per workspace; at most 50,000 new self-certified global revocation pairs per owner person (429).
  `checkpoint_unpublished` no longer grows and the per-workspace ever-device quota (4 096) is in place (P3-D31).
  Remaining, listed honestly:
  - *Per-account storage.* The node quota is per workspace, so one account can store up to 32 x 1.17 GB ≈
    37.5 GB (about an hour of accepted full publications across its workspaces, plus the uploads). Invite-only
    accounts bound who can; the deploy check (2) below sizes the knobs to the disk. A per-account node budget
    (the sum of `checkpoint_node_usage.nodes` over the owner's workspaces, checked like the workspace quota) is
    the follow-up if invites are opened.
  - *A workspace at its node quota cannot append any more*: nodes are never pruned (history is O(history)
    storage by design, P3-D19). At ~1,000 events a day 4,000,000 nodes is about 11 years; a workspace that
    reaches it migrates to a new workspace (as for a wrong genesis pin). Node pruning below a permanent anchor is
    not designed.
  - *The node quota also blocked owner-signed restores (review F1). Closed by P3-D36* (a reserve of the quota,
    200,000 nodes by default, that only owner-signed restores may use). The record of the problem: every restore
    adds at least one new node (its line head), so a workspace at the quota can never be restored. A hostile or
    compromised WSK holder can fill 4,000,000 nodes in minutes (about five accepted full sets, or refused
    publications whose orphans count too); the owner then cannot use a restore to abandon that host's branch,
    gets a permanent 429 that looks like the transient budget (P3-D34, "Permanent quotas look transient"), and
    the only exit, migrating, burns one of the account's 32 lifetime workspace slots. Before a public deploy:
    a small restore reserve or a per-workspace operator override of the node quota. P3-D36 implements the
    reserve inside the quota (ordinary publications stop at `quota - reserve`).
  - *Restore-referenced checkpoints and transitions are permanent* (P3-D13/D19): each accepted restore keeps a
    checkpoint of up to 2 MiB and a bundle of up to ~0.6 MiB. Owner-gated (only an owner device signs a
    restore) and each restore is a full accepted publication; not capped yet. A per-workspace bound on
    transitions needs a protocol decision (devices walk them; they cannot simply be evicted).
  - *`checkpoint_revocations`* grows with chain pairs: self-certified ones are bounded by the per-account evidence
    cap, associated ones by device registrations. Restores x known devices otherwise (owner-gated).
- **P3-D31 ever-device quota: the way out (ruled by orch-d6, not implemented).** See "Ever-device quota:
  recovery design" below. The host-side per-person device cap is on orch-52's pre-public-deploy list (host/core
  scope; not phase 1 or 2, since the relay is not publicly deployed).
- **Unthrottled authenticated work (blocker 4). Closed by P3-D35** for request counts: every authenticated
  request (directory, bridge, checkpoint) takes a token of its session's bucket after authentication, refusals
  included, plus a page token for proof and transition pages; N1, N3 and N4 of the G3 re-review are closed.
  Remaining, listed honestly:
  - *Cost is weighted only for pages.* Proof and transition pages are weighted by heads and staging PUTs have
    their own bucket (round 2), but a genesis or baseline refusal and an `ignored` lower-n publication (full
    stateless validation, uncharged by the failure budget; exact retries skip it since round 3) take one read
    token like a GET. The publication gate (P3-D33) bounds their phase A work, not their parsing.
  - *The Caddy per-IP limit is still an infra TODO* (provisioning in the dev-kit `vps/`, not this repo): it is
    the only bound on unauthenticated 401 floods (deliberately not charged per address, P3-D35), on the
    sqlite3.Error fallbacks and on traffic spread over many valid sessions. Deploy checklist item 7.
  - *Per-workspace sharing.* A W session's workspace bucket and the workspace's staging bucket are shared by every
    W session of the workspace, so a delegated WSK holder can spend them and delay the owner's host sessions of
    that workspace (within the delegated trust, as P3-D34's staging cap). W sessions themselves are keyed by token,
    so a WSK holder that logs in again gets a fresh session bucket, but never a fresh workspace bucket. The
    page-workspace bucket and its debt are shared the same way (delta review S3): a delegated host that walks
    proofs can make the primary host's proof reads wait (each full page costs 57 tokens, about 3 s of its 20/s
    refill; minutes for a long walk). Acceptable: only key holders can.
  - *Pair answers* of a workspace share one host-answer key: anonymous pair requests (60/min per workspace)
    can delay the host's pair answers for that workspace, never its bridge answers, polls or `hold`.
  - *Buckets reset on restart*, and an identity whose depleted bucket is evicted comes back full; this needs 64
    least recently charged entries of its class that are all depleted and a full class table (16,384 live
    identities of that class).
- **P3-D32 residual: exact certificate receipt replays (P3-D32 review F3).** A byte-identical `PUT /v2/devices/{d}`
  of an accepted certificate takes no window and no challenge from any address and runs the P3-D30 status
  re-check and `complete()` under `Directory.lock` (about 35 µs each). The status re-check must stay (it is the
  per-pair cutoff). Fix options before a public deploy: answer the replay from the pre-check when `device_status`
  passes on the snapshot and `complete()` would change no row (no challenged request of the person matches), or
  charge a generous per-address replay window. Until then the Caddy per-IP limit covers it. Also listed there:
  requests on an unused invite (needs a live invite code) reach the lock before the challenge is checked.

**Ever-device quota: recovery design (P3-D31 follow-up; for orch-52 / orch-d6 to rule on; not implemented).**

*Problem.* A workspace may list at most 4,096 ever-devices (G2 `ever_devices`: every device ever in an accepted
member list; P3-D31, 429 `quota_exceeded` on the membership publication). The set never shrinks, so a workspace
that reaches the cap can never list a new device. One member that registers fresh device ids and gets them listed
(or a host that lists them) can burn the budget. The host-side per-person device cap (host/core scope) prevents
the burning; this note is about the relay-side way out for a workspace already at the cap.

*What `ever_devices` protects (why rows cannot simply be dropped).* The relay reads it in seven places:
1. R4 completeness (`coverage`): every chain pair of a known device must be carried by each workspace restore,
   at the same or a stronger reason. Dropping a device whose pair is in the chain lets a later restore omit that
   revocation, and devices that initialize from the chain afterwards never learn it: the rollback R4 exists to
   stop.
2. The P3-D31 unpublished view: a global (§19.5) revocation of an ever-device that the chain lacks (or holds
   weaker) is served to the host until it publishes it. Dropping the device silently ends that obligation.
3. The host's access to the §19.5 feed (`person_access`, feed filtered to the workspace's ever-devices) and to
   the device's certificate (`GET /v2/devices/{d}` for a W session).
4. The bridge notice cursor and the wake keys of a revocation intake (a revocation of an ever-device wakes the
   host).
5. Grant retrieval of past epochs for a former member (`wk_grants` joined with `ever_devices`).
6. `ever_persons` / person access for the host.
7. The cap itself (`members.py`, the new-device check of a membership publication): a retired id that is listed
   again counts as new, which is correct; its `first_epoch` restarts, so grants are served only from the
   re-listing epoch on, the same loss as (5).
So "revoked former members stay covered" is (1) and (2), and the host learning about a later revocation is (3)
and (4). Any compaction must keep all four for every device that is, or may later become, revoked.

*Options.*
- (a) **Operator-run offline compaction of never-revoked former devices**, with re-admission. An admin CLI
  command (`orch-relay compact-ever-devices <ws>`, relay stopped or under the write lock) moves a device from
  `ever_devices` to a new `retired_ever_devices(workspace_id, device_id, first_epoch, retired_ms)` only if ALL
  hold: not a current member; no revocation pair for the id in the global table (any person) and none in any
  workspace's chain (`checkpoint_revocations`); not in `checkpoint_ever_devices` of the workspace (never restore
  evidence or a restore signer) and never the signer of an accepted transition or genesis pin; not listed for at
  least 30 days (its grant retrieval and pending certificate flows are over). And one intake rule: a later
  revocation of a retired id (any route: `POST /v2/revocations`, restore evidence) re-inserts it into
  `ever_devices` in the same transaction, bypassing the 4,096 check (the check only refuses new list
  additions). Security: (1) and (2) are untouched for every device that has a pair, because such devices are
  never compacted, and a device that gets a pair later is back before the revocation commits, so (3), (4) and
  the unpublished item see it exactly as before; the only loss is (5), old grants of a device that left more than
  30 days ago, and (6) for persons with no remaining ever-device (the host then cannot read that person's feed,
  which holds no pair for the retired ids anyway). Residual (corrected after review F3): a member who burned ids can revoke them afterwards and push the
  count back over the cap. This is not slow: the burned ids are registered devices of the member's own person
  (associated pairs), which the per-account evidence quota does not count, and one restore line carries about
  500 entries, so a member who owns any workspace re-revokes 4,096 ids in about 9 restores within minutes
  (`POST /v2/revocations`, 32 per person per day, binds only a member who owns no workspace). Against an
  adversarial member, (a) is therefore defeated quickly; it helps against honest churn and against members who
  own no workspace. (b) is the practical fallback and (d) the guaranteed exit, and the host-side cap is what
  actually prevents the burning.
  Implementation note (later): the re-admission rule must live inside `Directory.revoke` (directory.py), where
  every revocation path ends (`POST /v2/revocations`, the device PUT recovery and restore evidence through
  `apply_evidence`), re-inserting the id for every workspace that retired it with its original `first_epoch`
  from `retired_ever_devices`; that covers "any route" by construction.
- (b) **Per-workspace operator override of the cap** (admin CLI, a `ever_device_limits(workspace_id, limit)`
  row). Drops nothing, so it is safe for revoked burned ids too; the cost is that the unpublished page and the
  coverage query grow linearly with the set (the reason for the cap). The fallback when (a) cannot compact
  enough because the burned ids are revoked, which an adversarial member achieves in minutes (residual above).
- (c) **Owner-signed retirement or a replacement list that resets ever status.** Rejected: a retirement signed by
  an owner device moves the decision to the signer that R4 exists to constrain. A compromised owner device with
  the WSK could retire a revoked device and then publish a restore that omits its revocation; restricting it to
  never-revoked devices makes it (a) with a weaker trigger (no operator review) and still needs the re-admission
  rule.
- (d) **Migrate to a new workspace.** Always available, no relay change: new genesis, devices pair again, the
  old workspace stays (and counts against the 32-workspace account cap). The guaranteed way out today.
- Rejected outright: compacting *revoked* devices, even those "not referenced by chain pairs": a revoked device
  whose pair is only in the global feed is exactly an unpublished item (2), and one whose pair is in the chain is
  exactly what (1) covers.

*Recommendation.* (a) for honest churn, (b) as the practical fallback (against an adversarial member who owns a
workspace (a) is defeated in minutes), (d) the guaranteed exit (it burns a workspace slot); reject (c).

*Ruling (orch-d6, 2026-10-12).*
1. The 30-day grace stands. Compaction is **offline only** in the first version (an operator command with the
   relay stopped, or in maintenance mode), so it cannot race live revocations. The re-insert-on-revoke rule in
   `Directory.revoke` is kept anyway, as defence in depth.
2. The per-workspace operator override (b) is the fallback. It is audited (who, when, old and new cap) and
   documented. Migrating (d) stays the guaranteed exit.
3. The host-side per-person device cap is scheduled by orch-52 on the pre-public-deploy list (not phase 1 or 2,
   since the relay is not deployed).
Still open: whether hosts must be told of a compaction (a `notices` field or nothing: the retired devices hold no
pair, so no host decision depends on them). Host side (orch-core): the per-person device cap, and the host's
handling of 429 `quota_exceeded` on a membership publication (do not retry unchanged; surface it to the owner).

**Pre-public-deploy checklist (operator, per VPS).**

1. **Memory fits the publication gate and the maximum publication size (P3-D37).** Phase A holds every new
   node of a publication, about 1.3 KB of peak process memory per node (measured on macOS; not yet on the VPS's
   Python: add 25 %), so a full 64 MiB staging set (~906,876 heads) needs about 1.2–1.45 GB. Since P3-D37 one
   set is at most `ORCH_RELAY_MAX_PUBLICATION_BYTES` (default 16 MiB = 226,719 heads), refused as `too_large`
   before any fold, and the gate's `ORCH_RELAY_PUBLISH_HEADS` defaults to the heads that maximum implies
   (`max // 74`), so the publications in flight on one instance (at most `ORCH_RELAY_PUBLISH_WIDTH`, default 2)
   reserve at most one maximal set together. Per relay instance:
   `peak ≈ max(HEADS_CAP, MAX // 74) x 1.3 KB x 1.25 + baseline`, where the baseline is the Python process and
   SQLite (about 150–250 MB measured, plus up to 48 pooled read connections' page caches, ~2 MB each by default,
   up to ~61 MB of throttle tables (item 7), and in-flight request bodies: staging pages up to 4 MiB, waiting
   publications up to 2.6 MiB each). The VPS needs `Σ instances (peak) + other services (Caddy, orch-publish,
   hosts and agents on the box, the OS: about 0.35–0.8 GB) ≤ 75 % of RAM` (25 % headroom), and each instance's
   peak must stay under its unit's `MemoryMax` (systemd `M` = MiB). `provision.sh` defines two relay instances
   (`orch-relay` and `orch-relay-int`), each with its own gate. Recommended settings (in `/etc/orch/relay.env`
   and `/etc/orch/relay-int.env`, the units' `EnvironmentFile`; the dev-kit units and README take these values):
   - **2 GB VPS (the dev VPS: 1,961 MB, no swap; units `MemoryMax=900M` public, `450M` internal).** Public:
     `ORCH_RELAY_MAX_PUBLICATION_BYTES=16777216` (the default; 226,719 heads, 295 MB, +25 % 368 MB, + 250 MB
     = ~618 MB of 944 MB). Internal: `ORCH_RELAY_MAX_PUBLICATION_BYTES=4194304` (4 MiB; 56,679 heads, 74 MB,
     +25 % 92 MB, + 250 MB = ~342 MB of 472 MB, 28 % headroom; 8 MiB would be ~434 MB, 8 % headroom: too tight;
     6 MiB ~388 MB only once `MemoryPeak` shows a baseline of 200 MB or less). Leave `ORCH_RELAY_PUBLISH_HEADS`
     and the width unset. In all: 618 + 342 + Caddy ~100 + OS ~250 ≈ 1,310 MB of 1,961 MB (67 %).
   - 4 GB VPS: public 32 MiB (453,438 heads, ~0.99 GB), internal 16 MiB (~0.62 GB); `MemoryMax` about 1.2G and
     800M.
   - 8 GB VPS: 64 MiB, the staging quota, on both (906,876 heads, ~1.72 GB each, ~4.2 GB with the rest).
   How to read it: on the VPS `free -m` (`total` and `available`), `systemctl show orch-relay -p MemoryCurrent
   -p MemoryPeak` (and the same for `orch-relay-int`) after a large publication, and the bench
   (`uv run python tests/bench_publication_lockhold.py`) for the per-node figure on the deployed Python. A
   `MemoryMax=` in the units makes an overrun kill (and restart) the relay instead of a random process.
   Limitation: a restore whose staged set exceeds the maximum cannot be published (P3-D37). The follow-up (the
   streaming verify, P3-D33 residual) is to stop materialising every new node in phase A, either packing rows
   compactly (raw 32-byte fields in arrays instead of dicts and tuples, roughly 4–5x less: ~250 MB for a 64 MiB
   set) or streaming them to a temporary table in `NODE_CHUNK` chunks that phase B copies (O(chunk): ~26 MB plus
   one page, whatever the set); then the maximum can return to 64 MiB. Not implemented.
2. **Disk fits the storage caps.** Worst case is `accounts x ORCH_RELAY_ACCOUNT_WORKSPACES x
   ORCH_RELAY_WORKSPACE_NODES x 293 B` of nodes (an account with a P3-D36 override counts with its own cap) (defaults: 32 x 1.17 GB ≈ 37.5 GB per account) plus the 4 GiB
   staging ceiling plus the WAL and the self-certified evidence (≤ ~75 MB per account). Lower the workspace node
   quota or the workspaces per account for the invited accounts and the disk (example: 10 accounts on 40 GB with
   10 GB headroom and the 4 GiB staging: 10 x 32 x N x 293 B ≤ 26 GB gives N ≈ 270,000 nodes).
3. **Node-quota restore reserve (review F1). Done (P3-D36).** Ordinary publications stop at `quota - reserve`;
   owner-signed restores may use the reserve. Operator: keep `ORCH_RELAY_WORKSPACE_NODES_RESERVE` unset (5 % of
   `ORCH_RELAY_WORKSPACE_NODES`) unless restores must carry more new history.
4. **Per-account override of the 32-workspace lifetime cap (review F2). Done (P3-D36).** `orch-relay
   account-cap set <person_id> <cap> --by <operator> [--note ...]` (audited, 1..10,000; `show`, `audit`). A
   workspace deletion or archival route is still not designed; each migration still burns a slot unless the
   operator raises that account's cap.
5. **Ever-device way out (orch-d6 ruling above; code).** The offline compaction command, the audited
   per-workspace ever-device override, and (orch-52, host side) the per-person device cap.
6. **429 detail for permanent quotas (follow-up for orch-52 to rule on).** `quota: "nodes"` and the like, or a
   longer `Retry-After`, so hosts stop retrying permanent caps (P3-D34, "Permanent quotas look transient").
7. **Reverse proxy and per-IP limit (P3-D35, N4; infra).** Behind Caddy set `ORCH_RELAY_TRUSTED_PROXY` to the
   proxy's IP address (and `ORCH_RELAY_BEHIND_PROXY=1`, so a missing proxy setting warns at start-up): without it
   every client has the proxy's address, so all anonymous pairing shares 4 concurrent polls and one set of
   address windows relay-wide (the relay logs one WARNING on the first `X-Forwarded-For`). Add a per-client-IP
   request rate limit in Caddy (infra TODO in the dev-kit `vps/` provisioning; not in this repo): it is the only
   bound on unauthenticated 401 floods, on request bandwidth (bodies are read before the buckets) and on load
   spread over many valid identities. The buckets (`ORCH_RELAY_THROTTLE_*`, P3-D35) need no change for honest load
   up to a 5,000-ticket workspace and a full staging set; a deployment expecting larger first syncs raises
   `ORCH_RELAY_THROTTLE_PAGE_SESSION` (one token per 1,000 heads plus one per log). Their tables add up to ~61 MB
   per instance (all 8 key classes full) to the memory baseline of item 1.
8. **Staging refill (delta review S1). Done (P3-D36).** One token per started 64 KiB of body, burst 28,801,
   refill 600/min per workspace (`ORCH_RELAY_THROTTLE_STAGING=28801/600`): any honest set uploads with no 429,
   and one account sustains at most 320 lock-taking staging writes/s (20 MiB/s of compares), down from ~1,600/s.

## 11. Open questions

| # | Question | Recommendation |
|---|---|---|
| Q1 | Restore revocation set | **Decided by stream A**: every revocation for any device ever seen, the strongest reason per device, entries `{revocation, device_cert, pk_pub}`. R4 follows it. |
| Q2 | `reason` text | **Decided by stream A**: closed `rollback`, `diverged`, `broken`, `other`, plus an optional `note` ≤ 280 bytes. The relay sees the note (§8); the host UI says so. |
| Q3 | Co-owners and mandates as restore signers | **Decided: owner devices only** (P3-D23). This is a documented restriction of D62: a host-held mandate key would give restore power back to the WSK holder, so a mandate may not sign a restore that leaves the host. Co-owners come in P8 with independently authorized roles. |
| Q4 | Exit criterion "desktop browser" | A Python harness plus one native smoke run. Amend spec §13 formally; close #8 as superseded. |
| Q5 | Ticket checkpoints at the relay | No (P3-D12). |
| Q6 | Option B (checkpoints commit to the last restore) | Not needed: the owner-signed source, the accumulators and the endpoint-bound walk cover it. B alone is WSK-forgeable. |
| Q11 | Accumulators (P3-D19) are an F1 checkpoint-shape change | **Decided by stream A**: taken, with 32-byte inputs and the guarantee wording of §6.1. There is no heights-only fallback. |
| Q7 | Checkpoint growth | **Decided (P3-D20)**: object vs request limits, staged pages, atomic commit; about 5 000 tickets until G0 measures. Deltas only with a commitment scheme. |
| Q8 | Genesis | P3-D18 owner-device pin; devices verify it under the pinned `PK`. |
| Q9 | The `stale_epoch` hint in orch-mobile | Keep, bounded (P3-D8). The FakeRelay is amended, and drops rotation-abandon (P3-D7). |
| Q10 | Relay epoch checks on responses | Yes, as defence in depth (P3-D22). |
| Q12 | Drop and push (P3-D39, P3-D40) | Open: the host questions Q-H1 to Q-H6 and the phone questions Q-F1 to Q-F9 in §14.9, each with a recommended answer. |

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

**Source challenge** (restore-rev/source-challenge.md; its core points were decided by stream A, fixed input in
§6.4). The relay- and receiver-side points:

| Point | Change |
|---|---|
| S3. The owner client cannot establish H's freshness | Agreed. It discloses matches, conflicts and unknown freshness; the relay's atomic R2 is the arbiter (§6.4 (1)). |
| S4. Flushing must not be a prerequisite | Agreed (§6.4 (1)). |
| S6. `null` needs an explicit bootstrap state | Agreed. Separate bootstrap validation (§6.3), plus the exact pairing baseline (§6.2). |
| S7. Growth must be verified ancestry | Agreed. Accumulators, **decided by stream A as P3-D19**. |
| S8. Bind pagination to an endpoint | Agreed. Hash-addressed endpoints with retention (§6.2). |
| S10. Authorization evidence; historical validity | **Decided by tie-break: P3-D24** (a named, narrower P3 owner-device policy, not a resolution of S10), and historical validity recomputed from the bundle with the **P3-D25** anchors. |

**Challenge 2** (codex-p3-challenge2-out.md, on commit `049cf9a`; rulings from the Opus tie-break, p3-tiebreak.md):

| Finding | Status in revision 3 |
|---|---|
| 1. Accumulator boundary | Fixed: the retained prefix proven to `payload.head`, exact counts, equal-seq identity, unchanged logs byte-equal, the forward proof when `from_seq ≥ C.seq`; the WSK limit kept (R3, §6.1). |
| 2. Historical proof serving | **Decided (tie-break):** immutable `log_nodes` keyed by `acc`, never cut back; pages keyed by checkpoint hash; advance only after the final fold (§2, §6.1). |
| 3. Disappearing endpoint | **Decided (tie-break):** hash-addressed endpoints, 24 h retention (permanent if referenced), 410 `checkpoint_gone`, restart with the held H; baseline refresh over the bridge (§3.4, §6.2). |
| 4. Incomplete transition cases | Fixed: separate bootstrap validation, the `abandoned` rule, the walker's own checks listed, the outbox carries the full evidence (§6.3, §6.4, §9). |
| 5. Stale authorization evidence | **Decided (tie-break): P3-D24.** The member list is dropped from bundles; there is a relay-only current-list check; non-guarantees are stated. |
| 6. Historical validity and `line.at` | **Decided (tie-break): P3-D25.** A documented host-chosen position with the anchors `C.at ≤ line.at ≤ T.at`, non-decreasing checkpoint `at`, at most 300 s into the future. The claim that a rewritten `at` has no effect is withdrawn. |
| 7. Incompatible limits | **Decided (tie-break): P3-D20.** Object vs request limits, paged staging bound to `(source hash, T hash)`, an atomic preflighted final PUT, about 5 000 tickets until G0 measures. |
| 8. Cursor and fence races | Fixed: one poll per generation, a contiguous completed prefix, compare-and-set on `(gen, lease)`, renewal every 15 s, at-least-once within 60 s (P3-D10). |
| 9. Retry lifecycle | Fixed: 409 `retry_exhausted`, metadata outliving dependent messages, per-device bounds (P3-D9, P3-D17). |
| 10. Recovery quota denial | Fixed: charge after verification, free exact retries, full-duration windows, reserved revocation share. The "cannot exhaust login" claim is replaced by the stated saturation limit (§3.1, §4, §8). |
| 11. Durable rotation | Fixed: a durable `rotation_due` with cursor and epoch, cleared only by an excluding higher-epoch list under serialization; exact-body retry precedence; no reseal (§2, §3.2, §5.3). |
| 12. B1 evidence | **Decided (tie-break):** the relay compares by `(device_id, reason strength)`, with lost = retired; byte identity stays a host rule; `ever_devices` grows only from verified evidence; devices keep tombstones and commit atomically (R4, §6.4). |
| 13. Refusal exception | Fixed: bound to a known rid with the `LAST \| REFUSAL` shape, validated by the client, described as an honest-host defence; no TTL extension (P3-D22). |
| Genesis-pin verdict | Fixed: eligibility checked at first acceptance, historical verification later, an established pin never replaced, alarm on revocation (P3-D18). |

**Disagreements: status after the tie-break**

1. **Genesis pin vs the genesis event.** Codex accepted the separate privacy-preserving attestation. Closed.
2. **Owner evidence without logs.** **Decided by tie-break: P3-D24, an agreed narrower policy.**
3. **Revocation completeness on old bundles.** Codex agreed: no retroactive completeness, and local denials are kept.
   Closed.
4. **Historical position time.** **Decided by tie-break: P3-D25.** A documented host-chosen position with the
   source/target anchors. The claim that rewriting has no effect is withdrawn.
5. **Delivery mechanism.** The durable cursor; Codex's fixes for it adopted (finding 8). Closed.
6. **Fresh `PK` possession at account creation.** Not required (P3-D3); not contested again. Closed.

No open disagreements remain.

**Check 3** (codex-p3-check3-out.md, on revision 3): 7 of 13 resolved. The consistency gaps are closed in the final
pass:

- zero-length proofs use direct entry equality (R3);
- baselines get a pin registration and release route, and transitions page by the held `n`, so an expired held hash
  never blocks a lookup (§3.4, §6.2);
- the receiver walk has an explicit working state, with target verification and the durable H kept until the commit
  (§6.4);
- a bootstrap keeps the relay's future ceiling (§6.3);
- staging gets a manifest, a `retained` page kind, a storage quota and a total request limit (§3.4, §6.1);
- §3 has one 4 MiB response cap and two named cursor types;
- `host/hold` renews with the current generation (§3.3);
- replay-record lifetime is worded with its single exception (P3-D9);
- §9 publishes through staging.

No new decisions.

## 13. Decision index

| Id | Decision | Section |
|---|---|---|
| P3-D1 | `/v2` routes, FakeRelay shapes without `host_api`, shared HTTP fixtures | §3 |
| P3-D2 | Sessions: 15 min bearer tokens, concurrent, checked per route; scoped per relay or workspace | §4 |
| P3-D3 | Accounts by single-use invite plus a fresh device signature | §3.1 |
| P3-D4 | The first card without a session, first writer wins, per-owner quotas | §3.1 |
| P3-D5 | PK-only recovery: session-less revocations and certificates, quota-protected | §3.1 |
| P3-D6 | Member list with `person_id` and `persons` (D39); narrower guarantee | §3.2 |
| P3-D7 | Atomic membership publication; no rotation-abandon; no reseal on retry | §3.2 |
| P3-D8 | Unsigned 409 `stale_epoch` hint for new rids; bounded refetch | §3.3 |
| P3-D9 | Replay store, coalescing, `retry_exhausted` | §3.3 |
| P3-D10 | Durable host cursor (contiguous prefix), one poll per generation, CAS fencing | §3.3 |
| P3-D11 | Cert-request state machine; signed `cert_rejection` | §3.3 |
| P3-D12 | The relay stores workspace checkpoints only | §3.4 |
| P3-D13 | Restore rules R0–R5 with R3a, atomic; bootstrap validation | §6.3 |
| P3-D14 | Restricted-ticket inner seal deferred to P8 | §7 |
| P3-D15 | One worker, `synchronous=FULL`, SQLite off the event loop | §2 |
| P3-D16 | Relay enforces membership, not bridge scopes | §3.3 |
| P3-D17 | Budgets as refusals; full-duration windows; per-device record bounds | §4 |
| P3-D18 | Owner-device genesis pin; eligibility at first acceptance; never replaced | §6.1 |
| P3-D19 | Log accumulators (stream A) and immutable `log_nodes` | §6.1 |
| P3-D20 | Object vs request limits, staged pages, atomic commit, measured capacity | §6.1 |
| P3-D21 | Host outbox with the full evidence; no lock across networking | §9 |
| P3-D22 | Old-epoch response chunks: refusals for known rids or stored replays only | §3.3 |
| P3-D23 | Restores from owner devices only (a restriction of D62) | §11 Q3 |
| P3-D24 | P3 owner-device policy for checkpoint-only receivers (tie-break) | §6.3 |
| P3-D25 | Position time: documented limit, anchors, non-decreasing checkpoint `at` (tie-break) | §6.1, §6.3 |
| P3-D26 | One `WK` per epoch, ever; refused publications burn their epoch and `list_seq`; `wk_commit` and `wk_commit_changed` (G2b) | §3.2 |
| P3-D27 | Bounded exact-bytes re-store of expired response chunks (current epoch or refusal, immutable deadline, ≤ 8 per chunk, budgets) | §3.3 |
| P3-D28 | Pairing attempt binding: device `attempt` nonce, fresh keys per attempt, bound challenge and rejection, two `rejected` forms, `approved` join anchor (G3b) | §3.3 |
| P3-D29 | Evidence-only person rows for self-certified restore evidence; no account powers until an invite (G4) | §10 |
| P3-D30 | Per-pair device cutoff under the registry person; new registration refused on any chain-learned revocation; per-pair `GET /revocation` list; registry-pair notice cursor (orch-52 rulings 1 to 4) | §10, proto §19.5 |
| P3-D31 | Retrieval of unpublished revocation evidence: derived per-workspace view, W(g) `GET`/`POST ack`, `notices.unpublished`, refs as hints, 4 096 ever-devices per workspace (orch-52 decision point 7) | §10, proto §19.5 |
| P3-D32 | Directory routes authorize first: read-only pre-check outside `Directory.lock`, bounded shared connection pool, side-effect-free window checks (G3 re-review D4) | §4, §10, proto §19.4 |
| P3-D33 | Final publication outside the global write lock: phase A on renewed read snapshots (folds keyed by page digest and start), phase B node chunks, phase C live re-run and commit with bounded live work and restarts (503 after 3 rounds); per-workspace mutex and admission by width and heads on the event loop; refused-heads budget on every refusal; orphan accounting (G1 gate) | §10, proto §19.8 |
| P3-D34 | Per-account and per-workspace caps (429 `quota_exceeded`): 512 MiB staged per owner person, 32 workspaces per account, 4,000,000 stored nodes per workspace before phase B, newest 256 receipts and 4,096 tombstones per workspace, 50,000 new self-certified evidence pairs per owner person; ever-device recovery design (G3, G4 gates) | §10, proto §19.8 |
| P3-D35 | Token buckets on every authenticated directory, bridge and checkpoint request, charged after authentication (refusals to the read class): read buckets per device (or W token) and person (or workspace), page buckets weighted by heads, a staging bucket per workspace, host answers per (workspace, target device); bounded LRU table; O(1) poll admission counters (N3); proxy misconfiguration warning (N4); revocation-read /56 window (blocker 4; round 2: review F1-F3) | §10, proto §19.4, §19.6 |
| P3-D36 | Pre-public limits: staging weighted by body size (one token per started 64 KiB, burst 28,801, refill 600/min); a node-quota reserve (5 %, 200,000 nodes) only owner-signed restores may use; an audited per-account override of the workspaces cap (migration 0016, `orch-relay account-cap`, no HTTP route) (checklist items 3, 4, 8) | §10, proto §19.4, §19.8 |
| P3-D37 | A hard maximum publication size (`ORCH_RELAY_MAX_PUBLICATION_BYTES`, default 16 MiB, 1..64 MiB): `too_large` at the staging manifest (implied size, before any page) and pages (413, running total) and at the final publication before any fold (400, phase A and C); restores alike; the publication heads cap defaults to the heads it implies (checklist item 1) | §10, proto §19.6, §19.8 |
| P3-D38 | H12d relay scope: `GET /v2/relay-info` (`reader` a code constant, 1; `max_publication_bytes`; unauthenticated, per-address throttled, `no-store`, an honest-operator statement), `AUTH_KINDS` += `convenience` (deploy before any convenience restore), the `reader_decl`/pair meta v2/`rd` vectors and protocol text | §10, proto §8.3, §8.6, §19.1, §19.4, §19.8 |
| P3-D39 | Drop at the relay (P4 basics, D39a1/D39a2/D39b): `/v2` routes; one streamed `ODU2` upload frame (head ≤ 512 KiB, exact `Content-Length`) checked before any blob byte is read, early answers drained; descriptor ≤ 96 KiB, `meta` ≤ 64 KiB + 16; tombstone check, then exact retry, before the CAS; `wk` wraps at the current epoch (409 `stale_epoch`; rewrap the same `DEK`); `wxk` and `recipients` within the own workspace (cross-workspace is P6); per-caller wrap filtering; unclaimed inbox files visible to the host and their author only (amendment A2), blob after the claim; list by change position and a host `drop` notice; byte-cut pages and bounded read slots; 26 MiB blobs; blob and head quotas per device, workspace, account and global with reservations; slot caps per device, person and workspace with minimum rates; 7-day files, documents without expiry and a host retire of files and documents (amendment A1: an `expect_version`/`expect_head` precondition, the fence re-checked inside the transaction, idempotent only within the tombstone window), 30-day tombstones listed with a `state` (`live`, `pruned`, `expired`, `retired`; every state change raises `n` and the host notice) and a `tombstone_until_ms`, a full reconciliation after a gap beyond the retention, pruned old document blobs, batched sweeps; claims and host re-wraps (`wrap_conflict`); the Caddy body-cap exception before deploy; migration 0017 | §14.2, proto §19.9 |
| P3-D40 | Push at the relay: per-(device, workspace, env, topic) APNs registrations with sealed tokens; same-person token move; host send route W(g) with targets, current-epoch outer, priority and TTL; generic `aps` text plus `o`, no collapse id or badge; in-memory best-effort queue, dedup LRU, budgets per device and workspace; APNs answer handling (410 deletes, 403 backoff); a per-environment key mapping (today the owner's one both-gateway key `TD27F9Z9V7`) and the token secret as files of the public instance's user (optionally `LoadCredentialEncrypted`), never in the database, logs or git; 404 when disabled; migration 0018 | §14.3, §14.7, proto §19.10 |

## 14. Drop and push, designed ahead of R3 (P3-D39, P3-D40)

Status: **design for review**, 15 Oct 2026 (stream D). Docs only: no code, no migration, no deployment, no
network call. Revision 2 (15 Oct) folds in the Opus design review (SOUND WITH CHANGES: H1, H2, M1–M7, L1–L14),
orch-f1's phone-side review (R1–R6), orch-52's host-side review (relay-side items) and orch-d6's correction on
the existing APNs key. Revision 3 (15 Oct) folds in the Opus delta review of revision 2 (PASS WITH REQUIRED
CHANGES: N1–N5, L-a to L-j) and orch-f1's check (S1–S3); the finding ids are cited where each lands. A Codex challenge is pending; the owner
questions of §14.9 are **open**.

**Amendment record** (changes after the merged design, before D39a1's code):

| # | Date | Change | Agreed by |
|---|---|---|---|
| A1 | 15 Oct 2026 | The host retire covers **files** as well as documents (a file's bytes, wraps and usage released in the retire transaction); list entries carry `object_id`, `version` and a `state` (`live`, `pruned`, `expired`, `retired`); expired and retired objects stay listed as tombstones for the 30-day window, and every state change raises the change position. With orch-52's changes: (0) the holder generation and lease are re-checked inside the mutation transaction of every fenced Drop write and at the push queue admission, with a takeover-versus-retire race test; (1) retire requires `{expect_version, expect_head}`, checked atomically (409 `version_conflict`, object untouched; the same retry against the tombstone 200); (2) entries carry `tombstone_until_ms`, a gap longer than the 30-day retention forces a full reconciliation, every state change raises the host `drop` notice, an expiry reaches incremental lists after the sweep (~10 minutes); (3) a retire is never replayed after the window, a 404 then proves nothing and the host reconciles; (4) visibility: the 403/404 existence oracle stated precisely, restricted tickets are the host's job (device wraps and device-only `recipients`, filtered host listings), R-D10. Opus delta of this amendment (PASS WITH REQUIRED CHANGES, retire races sound): R1 the `PUT` answers 403 to a device outside a device-only audience before any 410, exact retry or CAS; R2 an explicit `drop_objects.audience` (`space`, `inbox`, `devices`), audience rows never pruned by membership changes, `recipients: []` 400; R3 a 60 s minimum file lifetime, audience rows deleted at expiry and kept (workspace-charged) only on retired tombstones, charge scopes stated, Q-H6 corrected; lows L1–L7 (push re-check off the event loop, 404 inside the retire transaction, canonical `expect_head`, `state` in the 409 body, a 29-day retry and reconciliation margin, the estimate restated, the 403 rationale); Opus delta 2: the list row's relist bound, the expired device-only file's 410-then-403 after the sweep (author included) with fixtures, a host MUST for re-added devices, the retire charge kept on the workspace with a host bound, the request `now` for the 60 s floor, the on-time-sweep assumption (P3-D39 items 1, 3, 4, 5, 6, 7, 8, 9; P3-D40 item 4; §14.4; §14.5; §14.6; §14.9; proto §19.9) | orch-fa (dashboard): host-mediated retire is enough, and the list state is exactly what the dashboard needs; orch-d6 rulings (no device delete in P4, host-mediated only); orch-52 15 Oct 2026: agreed with changes 0-4 (host-only retire for files, fenced by `Orch-Holder`, bounded idempotency in the tombstone window); to be checked by orch-f1 (phone list parser) |
| A2 | 15 Oct 2026 (revisions 2–6 the same day) | (1) **Decide-class uploads**: a device `PUT` is authorized by `operate`, **or** by `decide` for exactly one shape: a new `file` (version 1, `If-Match: 0`) with `recipients: "inbox"` and the usual inbox wraps; decided on the current member list and re-checked in the commit; a separate decide-class budget (50 creations and 64 MiB per device and workspace per UTC day, JUDGEMENT CALL) on top of the per-device shares; 403 `not_eligible` for any other shape from a decide-only device, at the existing scope step (no new oracle); the host-side claim rule (a person's own uploads claimed without a gesture, someone else's only after a terminal hand-off). (2) **W-session list walks**: `direction: "all"` (W sessions only; a device asking for it 403 `not_eligible`); a relay-wide `generation` in every list page (regenerated when the Drop dataset is restored or replaced) with 409 `generation_changed` for a stale one; a bounded high-watermark `until` returned by a walk's first page and passed by its following pages, which are cut at it. **Revision 2** (Opus delta PASS WITH REQUIRED CHANGES, R1–R4, L1–L5; orch-f1's check; orch-52's Q-H9): the budget charged at admission (refunded only before the first blob byte; failed streams charged their received bytes and a creation) with a conditional update, one decide-class upload slot per device, the real ingress bound (the upload bucket, R-D12) instead of the wrong "1.9 GiB a day", the UTC day of the request's `now`, the commit-time authority winning, the 429's `Retry-After` to 00:00 UTC as a MUST; the threat model corrected (a stolen phone's uploads are its owner's own and released by the gestureless claim; Q-H9's current-member-device condition, "Shared from your phone" list, R-D13); **unclaimed inbox objects visible only to the W session and their author device** (orch-f1 (d)1, confirmed; reverses A1's rule that members list them); the `generation` detected structurally (no `drop_generation` in backup copies, a high-water file outside the database checked before the start-up sweep, held in memory; R-D11 narrowed); client guidance and rollout. **Revision 3** (Opus delta 2, PASS WITH REQUIRED CHANGES: RA–RC, L-1 to L-7; orch-52 and orch-fa): the high-water file moved to a state directory outside the data directory (dev-deploy-plan step B, §6.2 and the reset tool move the whole data directory; D40c replaces them), written at most every 60 s with the committed counter, R-D11 restated; the budget charged by an upsert with a best-effort give-back on the error path; steps 2, 6, 9 and 11 aligned; `claimed_ms` and `expires_ms` in list entries (JUDGEMENT CALL) and "Shared from your phone" a host-side record until `claimed_ms + 7 d`; multi-person release, the revocation timing, the per-workspace scaling of the stored bound and the phone's disconnect backoff stated; estimate +0.5 (D39a2) and +0.5 (D40c). **Revision 4** (Opus delta 3: RD–RG): the upsert everywhere; the state directory fail-closed (an existing, writable directory outside the data directory, the start write required, periodic failures logged and retried, the temporary file in the state directory, one `flock`ed file per instance); the start check and writer independent of the Drop switch, and no `n`-assigning sweep while the check fails; `claimed_ms` owned by D39a2 alone, named-column inserts, no `REPLACE`. **Revision 5** (Opus delta 4: RH, RI, L-i to L-n; orch-f1 wording pins): the failed state check's two rules (no Drop route with Drop on; no `n`-assigning sweep when `n > 0`) and the process staying up; the `flock` on a separate `drop-hwm.lock` taken by `serve` only, with a 30 s retry; the no-replace trigger's reach; every page echoing `generation` and `until`; the exact 403 and 409 bodies; the author's descriptor read-back. **Revision 6** (Opus delta 5: RJ; lows L-o to L-q): this change-log cell, the start order, the 403 wording, the estimate sentence. The rest of A1 is unchanged (P3-D39 items 1, 3, 4, 6, 7, 8, 13, 14; §14.4; §14.5; §14.6; §14.9 Q-H8, Q-H9, Q-F5, Q-F11; proto §19.9) | orch-52 (host) 15 Oct 2026 on the design points, including Q-H9 and the window; orch-f1 (phone) on the phone points: the inbox visibility change (d)1, its (c)/(d) inputs for revision 3 and the wording pins of revision 5 (its check that the strict list parser accepts `claimed_ms` and `expires_ms` is pending); orch-fa (dashboard) checked revision 2; final confirmations by orch-52 and orch-fa pending. Opus deltas: revision 1 and revision 2 PASS WITH REQUIRED CHANGES (applied in revisions 2 and 3); revision 3 PASS WITH REQUIRED CHANGES (RD–RG and lows, applied in revision 4); revision 4 PASS WITH REQUIRED CHANGES (RH, RI and lows, applied in revision 5); revision 5 PASS WITH REQUIRED CHANGES (RJ only, applied in revision 6; no further delta needed) |

Owner decisions (via orch-d6, 14 and 15 Oct): the end-to-end target includes **both** Drop and push; this design
goes ahead of R3; the relay uses the owner's existing APNs key (Key ID `TD27F9Z9V7`, created by the owner on 8 Oct,
already on the VPS; orch-d6 correction, 15 Oct) as a VPS secret that is never printed, logged or committed. Any
new key is created by hand by the owner (or the Apple team's admin): the App Store Connect API cannot create
APNs keys (§14.7).

Inputs: proto §9 (push payloads), §10 (Drop content, wraps, descriptors, claims, documents), §13 (decisions),
§17/§18, §19 (routes and budgets); spec §6.3 and §6.4, D43, D47, D48; orch-mobile `FakeRelay.swift`
(`dropRoute`, `rewrapSource`, `putRewrap`), `docs/host-api-v0.md` §3 "Push registration" and §4, `docs/gaps.md`
rows 7, 10–19 and the Slice 5 notes (F4, F6, the residual rotation race), and the NSE's `PushProcessor`
(`userInfo["o"]`, 3,072-byte outer cap); orch-core `orch-v2.md` §6.3/§6.4 (the host documents do not yet describe
Drop or push sending: §14.9 asks orch-52); `docs/p3-checkpoint-capacity.md` and `docs/dev-deploy-plan.md` (1,961
MB RAM, no swap, 38 GB disk with ~35 GB free, R8).

This section moves two items out of §1's non-goals: "push and APNs registration (P4, #13)" and "Drop (P4 basics
#25)". Drop's P6 rest (personal and shared spaces, scoped agents, leases, links) stays a non-goal (§14.8).
The wire contract is protocol-v2 §19.9 (Drop) and §19.10 (push); this section decides and explains.

### 14.1 Scope

**Drop, P4 basics (D43).** Workspace spaces only (`space_kind: "workspace"`), member ↔ **own** workspace only: a
member device sends a file or a document version to its workspace; the host sends one to its member devices;
members read them. Every `wxk` wrap and every workspace id in `recipients` names the object's own workspace
(Opus M1; owner question 1). Claims (§10.5) and host re-wraps (`drop_rewrap`, §7.5) are in, because the phone's
inbox and rewrap paths already use them (D39b); in P4 an `inbox` object is a `file` claimed by its own workspace
(M7). Out: cross-workspace addressing (ws→ws mailboxes and foreign inbox claims, P6 #20), personal and shared
spaces (no `SK` grants exist), `drop:` scoped agents (P6, D15), the advisory lease (`POST /drop/{id}/lease`),
public and upload links, recall, byte ranges. The only delete is the host's retire of a file or a document
(item 5, amendment A1); a device has no delete route in P4 and asks its host instead.

**Push, P4 (spec §6.3, D47, D48).** Per-(device, workspace) APNs registrations; a host-originated send route; the
relay's fan-out to registered tokens through APNs with the `.p8` auth key; token lifecycle. Delivery is best
effort. No Web Push or VAPID: `provision.sh`'s `VAPID_*` remnants are dropped (§14.7).

### 14.2 P3-D39: Drop routes at the relay

**P3-D39 (Drop transport, storage and limits).** Protocol §19.9 states the observable rules. The decision record:

1. **Routes, all under `/v2`** (P3-D1). The phone's FakeRelay spells the write and claim routes without the prefix
   (§10.5/§10.6 spelling); orch-f1 has agreed to move them.

   | Route | Auth | Purpose |
   |---|---|---|
   | `PUT /v2/drop/{o}/versions` | D(m) with `operate`, or with `decide` for a new `inbox` file (item 13, amendment A2), or W(g) of the space | write version `current + 1` (one framed, streamed body) |
   | `POST /v2/drop/list` | D(m) with `look`, or W (`direction: "all"`: W only, item 14, amendment A2) | the newest version of each visible object, by change position |
   | `GET /v2/drop/{o}/descriptors?after=&limit=` | as list | the signed descriptor chain, in pages (fixes the phone's F4 amplification) |
   | `GET /v2/drop/{o}/versions/{v}/descriptor` | as list | one signed descriptor, `ETag` |
   | `GET /v2/drop/{o}/versions/{v}/wraps` | as list | the wraps the caller can use, and `claimed_by` |
   | `GET /v2/drop/{o}/versions/{v}/blob` | as list | the ORD2 ciphertext, streamed |
   | `PUT /v2/drop/{o}/versions/{v}/wraps` | W(g) | the host's `drop_rewrap` wrap under its current `WK_e` (D39b) |
   | `POST /v2/drop/{o}/claim` | W(g) | §10.5 claim-once, unchanged (D39b) |
   | `POST /v2/drop/{o}/retire` | W(g) of the space | tombstone a `file` or a `document` at once if its head is still the expected one, releasing its bytes (item 5, Opus M5, amendment A1; D39a2) |

   The host's writes are fenced (`Orch-Holder`) like every other W write (P3-D10). **The fence holds inside the
   mutation, not only at admission (amendment A1, orch-52 change 0).** Every fenced Drop write (`PUT` versions,
   `PUT .../wraps`, claim, retire) checks the fence twice: at admission, before any slot, bucket or body read
   (so a stale host spends nothing), and again **inside the write transaction that mutates**, against the live
   `holders` row (`gen` equal to `Orch-Holder` and `lease_until_ms` > the transaction's `now`), before any row
   changes; a failure there is 409 `fenced` with nothing changed (an upload's temp or renamed file is unlinked as
   for any failure before the commit). `host/hold` writes the `holders` row in its own write transaction under
   the same directory lock, so a takeover and a fenced Drop write are serialized: either the write commits under
   the old generation before the takeover, or it sees the new generation and changes nothing. A long upload
   (up to 10 minutes) whose lease lapsed or was taken over during the blob transfer therefore fails at the
   commit, not silently. The push send route applies the same rule to its queue admission (§14.3 item 4).
   Drop routes refuse `drop:` scoped devices with 403 `not_eligible` until P6.

2. **One streamed upload body, not JSON with a base64 blob (JUDGEMENT CALL; changes the phone's packaging).**
   The FakeRelay's `PUT` takes `{"descriptor", "wraps", "blob": b64u}` up to 36 MiB of JSON. Parsing that holds the
   raw body, the decoded string and the blob at once: about 100 MB per 25 MiB upload in CPython, against a public
   unit with `MemoryMax=900M` of which the publication gate already reserves ~618 MB (§10 checklist 1). The relay
   instead reads a frame:

   ```
   body = "ODU2" || u32be(head_len) || head || blob        u32be: 4 bytes, unsigned, big-endian
   head = cj({"descriptor": <signed drop_object>, "wraps": [<wrap record>, ...]})      exactly these two fields
   ```

   `head_len ≤ 512 KiB` (Opus L9: realistic P4 heads are under 300 KB); `blob` is exactly `content_len` bytes (the
   ORD2 ciphertext of §10.2), and the body ends there. The request MUST carry `Content-Length` equal to
   `8 + head_len + content_len` (no chunked bodies; Opus M3). The relay authenticates and authorizes on the
   headers alone, reads and checks the head (signature, CAS, wraps, quota reservation) **before it reads a single
   blob byte**, and answers a refusal (or the exact-retry 200) at once. It then streams the blob in 64 KiB reads
   into a temporary file, hashing as it goes, and never holds more than the head plus one buffer. The phone keeps
   the frame bytes in its `drop_uploads` row exactly as it keeps the JSON body today, and resends them byte for
   byte (from the app, never the share extension, which only stages up to 25 MiB).

   **Early answers must reach the phone (Opus M3, orch-f1 R3).** An answer sent before the body is read travels
   URLSession → Caddy (HTTP/2) → uvicorn (HTTP/1.1). If the relay closes with unread upload bytes, the kernel can
   answer them with a TCP RST that destroys the response; the phone then sees `disconnected` and resends a 409
   `stale_epoch` or 429 forever. So after an early answer the relay shuts down its write side, **drains** the
   rest of the declared body without hashing or storing it, then closes. The drain is bounded on its own (Opus
   N1):
   - only answers given **after** an upload slot is held drain (refusals at steps 3–9 and the exact-retry 200).
     Refusals at steps 1–2 (transport, session, principal, fence, buckets, slots) close at once, after reading at
     most 64 KiB or 1 s; a 413 for a declared length never drains. These are not resend-forever cases, and an
     unauthenticated client gets no drain;
   - the upload slot and the head buffer are released as soon as the answer is sent; the drain counts in its own
     pool (32 relay-wide, 2 per device). When the pool is full the relay closes without draining;
   - a drain ends at 5 s idle or 30 s in all (at most the declared remainder), and the relay then closes. The
     answer may then be lost; the phone's read-back covers that.

   A client may close its side once it has an early answer. Before resending a stored frame after any lost
   answer, the phone reads back `GET /v2/drop/{o}/versions/{v}/descriptor` (orch-f1 R5, Opus L-d):

   | Read-back | Meaning | Phone action |
   |---|---|---|
   | 200, its own descriptor | stored | done |
   | 200, another descriptor | the version was taken | `version_conflict` handling (fresh `DEK`, next version) |
   | 404 | the slot is empty | resend the stored frame |
   | 410 | the object is gone | use a new object id |
   | 403 | no longer eligible | stop, show it |

   The resend loop has a bounded backoff and attempt cap. A link below ~46 KiB/s (27.8 MB in 10 minutes) cannot
   finish a maximal upload; the phone shows "link too slow" instead of resending forever. A non-JSON 413 (from a
   proxy) is treated as `too_large`, and a 400 for an `expires_ms` beyond the window (a phone clock more than 5
   minutes ahead, Opus L-j) is shown, not retried.

   D39a1 adds a real-socket test (an early 409 and an early 200 with an unread 26 MiB body, asserting the client
   receives the JSON; a drain that stalls past 5 s; a full drain pool) and an end-to-end test through a real Caddy
   (HTTP/2) with the same cases.

   Rejected alternatives for the packaging: two requests (blob first, then descriptor) need a staging table, its
   GC and its quota, and authorize the blob before its descriptor; `multipart/form-data` needs a streaming parser
   with its own limits and gives nothing the frame lacks.

3. **Check order of the `PUT`** (each refusal stops; nothing is stored before step 11):
   1. transport: no `Content-Length` (a chunked body) → 400 `malformed`; a declared `Content-Length` above
      `8 + 512 KiB + max_blob` → 413 `too_large`, before anything else (P3-D17 "caps apply to streamed bytes as
      well as declared Content-Length");
   2. session (401), principal (403 `not_eligible` for a `drop:` device or a non-member; a device needs
      `operate` or, since amendment A2, `decide` in at least one workspace before it gets a slot, and a device
      with `operate` in no workspace gets **one** upload slot, item 13), for a W session the
      fence at admission (`Orch-Holder` current and the lease unexpired, else 409 `fenced`, P3-D10; Opus N4;
      re-checked in step 11), buckets (P3-D35
      read class, then the upload bucket), then an upload slot (item 8: 429 `quota_exceeded` per device, person or
      workspace; 503 `overloaded` relay-wide);
   3. `If-Match` (428 `precondition_required`, §10.6);
   4. the frame's magic and `head_len` (400 `malformed`; 413 above 512 KiB), the head read and parsed strictly;
   5. the descriptor → 400 `malformed` unless: the §10.4 field set and suite; `cj(descriptor)` ≤ 96 KiB and the
      decoded `meta` ≤ 64 KiB + 16 bytes (the phone's `Drop.maxMetaBytes`; Opus H1); `object_id` equals the path;
      `space_kind` is `workspace`; `object_kind`; `recipients` is `"inbox"` (only with `object_kind: "file"`, M7)
      or a sorted unique list of 1 to 1 024 ids, each either `space_id` or a current member device of it (M1;
      an empty list `[]` is 400, amendment A1: it would be an audience nobody but the W session can see, which
      no client needs); the expiry rules of item 5; and `Content-Length = 8 + head_len + content_len` (M3). An `expires_ms` at or
      before `now` is 410 `expired` (a resent body that has expired; orch-f1 R4). The author: `author_kind`/
      `author_id` must be the session's principal (a device session writes `author_kind: "device"` with its own
      id, a W session `"workspace"` with its own id) → 403 `not_eligible`; the signature under the registry
      `dk_sig_pub` or the card's `wsk_pub` → 401 `bad_signature`; the space: the principal may write to
      `space_id` (a current member with `operate`, a current member with `decide` whose request has the
      decide-class shape of item 13, or that workspace's W(g)) → 403 `not_eligible` (amendment A2: a
      decide-only device with any other shape gets this same answer at this same step);
   6. the object's state: an object id that exists in another space is 403 `not_eligible` (never its `current`);
      for a device session, an object whose stored audience excludes the device (`audience = 'devices'` and no
      `drop_audience` row for it, §14.5; live or tombstoned) is 403 `not_eligible` as well (amendment A1, Opus
      delta R1), and so is another author's unclaimed `inbox` object (amendment A2), so a member outside a
      restricted audience or an inbox's author learns no state, version, kind or claim through a `PUT` either; then an expired or tombstoned object (item 5) is 410 `expired`. Both precede the exact retry
      (Opus L1) and the CAS, so a retry never answers 200 for an object that is gone and the 410, the
      `version_conflict` `current`, the file-above-version-1 400 and the claimed 403 reach only callers that
      may see the object. The newest version's device author is in its audience (item 4) until the expiry
      sweep deletes the audience rows of an expired device-only file (item 5), so a lost 201 is recoverable by
      its author while the file lives; after that sweep every device, the author included, gets 403 on reads
      and `PUT` (no new oracle: the id was already known to exist), and only the W session still sees the
      tombstone;
   7. an **exact retry**: if version `version` is stored and its descriptor's `cj(o)` equals this one's, answer
      200 `{version}` at once (no blob read, no CAS; the stored wraps stay). This precedes the CAS, as for
      membership (P3-D7 "Retries"), so a lost 201 never turns into a 409 for the phone to reconcile;
   8. the CAS of §10.6 against a read snapshot: `If-Match == current`, `parent == current`,
      `version == current + 1`, `parent_hash` = the hash of the current head, and for `current > 0` the same
      `object_kind`, `space_id` and `space_kind` as the head; a `file` takes only version 1, with `expires_ms ≥
      now + 60 s` (item 5's floor; 400 `malformed`; `now` here is the request's `now`, below); a claimed object
      takes no new version (403 `not_eligible`; M7). Otherwise 409 `version_conflict` with `current`;
   9. the wraps (item 4) → 400 `malformed`, 409 `stale_epoch` (`epoch`), 409 `bad_wxk_version` or (pending owner
      question 6) 409 `rotation_required`; then, for an upload authorized by `decide` alone, the **charge** of
      the decide-class budget (an upsert, kept unless the request is refused before its first blob byte; item
      13, amendment A2) → 429 `rate_limited`; then the quota reservation of
      the blob bytes and the head bytes (item 8) → 429 `quota_exceeded` or 503 `overloaded`;
   10. the blob: streamed to `drop/tmp/<random>` (mode 0600), at most `content_len` bytes; its first 40 bytes
       must be an ORD2 header with this descriptor's suite, `object_id` and `version`, and `content_len` must be
       consistent with the header's chunk size (Opus L10: no arbitrary non-ORD2 storage); a short or long body is
       400 `malformed`, `H(blob) ≠ content_hash` is 400 `malformed`; the file is `fsync`ed and renamed to a
       unique final path `drop/blobs/<o>/<v>.<rand>` (recorded in the row) and the directory `fsync`ed, all
       **before** the directory lock (Opus L8: no `fsync` under the global write lock);
   11. the commit, under the directory lock in one write transaction: for a W session re-check the fence on the
       live `holders` row first (409 `fenced`, item 1; a takeover during the transfer), then re-run 5's
       eligibility (for a device: its live `members` row, so a `decide` or `operate` removed during the
       transfer is 403 here with nothing stored; amendment A2), 6, 8 and 9 on live state (a concurrent writer gets 409 `version_conflict`), insert the rows (§14.5), charge the usage
       (the decide-class budget was charged at step 9; the commit charges it only when the device held
       `operate` at admission and is decide-only now, item 13),
       commit; 201 `{version}` with `ETag: "<version>"`. A failure before the commit unlinks the file; a crash
       leaves an orphan file that the start-up sweep deletes (a row never points to a missing file because the
       file lands first). The reservation is released when the commit returns (Opus R2: a 201, 200 or refusal
       frees it at once) and in `finally` on every other exit, also on `ClientDisconnect` and cancellation.

   The relay never checks `content_hash` against anything but the bytes it received, never opens metadata, and
   never checks `dek_commit` (it has no `DEK`). Readers do all three (§10.4).

4. **Wrap checks at the relay** (defence in depth; readers rely on `content_hash` and `dek_commit`, not on these).
   Each wrap record has the §10.3 field set with `object_id` and `version` of this descriptor, a `wrap` of at most
   512 B with the §5.3 suite framing (as P3-D7 checks grants; Opus L9), at most 1 024 records (the 512 KiB head
   bounds them further), unique `(target_kind, target_id, key_version)`:
   - `wk`: `target_id` = the space's workspace, `key_version` = that workspace's **current list epoch**, else 409
     `stale_epoch` with `{"epoch": current}` (the unsigned hint of P3-D8). The phone refetches the signed list
     and grants, bounded, and **rewraps the same `DEK`** under `WK_{e+1}`, keeping the blob and the signed
     descriptor (the descriptor does not bind the wraps), so the exact-retry identity holds and 26 MiB is not
     re-encrypted; a fresh `DEK` and reseal follow only a `version_conflict` (Opus M6; Q-F4). This closes the
     phone's "residual rotation race" (gaps.md Slice 5) **for removals**, which publish a new epoch. It does not
     close it for a revoked device while the workspace's `rotation_due` row is open: the epoch is unchanged
     until the host rotates, so an upload lands under the `WK_e` that the revoked device holds. The relay
     already refuses that device a session, so this matters only against a hostile relay (R-D7). Recommended,
     pending owner question 6: refuse `wk` wraps with 409 `rotation_required` while the workspace has an open
     `rotation_due` row. It is cheap (one indexed lookup on the existing `rotation_due` table, re-run in the
     commit) but blocks uploads until the host rotates; if the owner declines, R-D7 stays documented. The 409
     body is `{"error": "rotation_required", "epoch": <current>}`; the client retries after the host's rotation.
     For a **non-inbox** object a device author MUST include one `wk` wrap (the member-writer wrap of §10.3); a W
     author MAY omit it only when the object is addressed to devices only;
   - `wxk`: `target_id` MUST be `space_id` (400 `malformed` otherwise: cross-workspace targets are P6, Opus M1),
     `key_version` = the card's current `wxk_version`, else 409 `bad_wxk_version`: the client refreshes the card
     and rewraps the same `DEK` under the current `WXK`, as for `stale_epoch` (no reseal; orch-f1 S3);
   - `device`: `target_id` is a current member of the space's workspace (or the author) with an unrevoked,
     unexpired certificate, else 403 `not_eligible`; `key_version` is 0 (a device wrap has no key version);
   - `sk`: 400 `malformed` until shared spaces exist (P6).

   **Inbox wraps (Opus N2, orch-f1 S1).** An `inbox` object (device- or W-authored) carries exactly one `wxk`
   wrap to its space and, optionally, its author device's own `device` wrap, and **no** `wk` wrap (400
   `malformed` otherwise). Before the claim only the host (through `WXK`) and the author can open it; other
   members can open nothing, and since amendment A2 they do not see it either (item 6). At the claim the host adds its `wk` wrap (§7.5, `PUT .../wraps`), which makes the
   item readable to the members, as intended in P4. P8 note: a device author of restricted content needs the
   same `wk`-free rule.

   **Restricted content (orch-52 Q-H4; amendment A1, orch-52 change 4).** Relay membership and `recipients` are
   not ticket authorization. The relay does not know tickets or their visibility; what it enforces is only
   membership (`look`/`operate`) and the newest version's `recipients`: a device-only list hides the object,
   its tombstone and its list entry from every other member device (403 on reads and on a `PUT`, step 6; no
   list entry). That device-only list **is** the restricted audience. The relay stores it explicitly (Opus delta
   R2): `drop_objects.audience` is `'space'` (`recipients` contains `space_id`), `'inbox'` or `'devices'` (a
   device-only list), and visibility is keyed on that column, never on whether `drop_audience` rows exist. For
   `'devices'` the rows are the listed devices plus the newest version's device author (so an author never
   locks itself out). The rows change only when a new version's commit replaces them, and are deleted with the
   object row or at an expiry tombstoning (item 5); **membership removal and revocation never delete or prune
   them**. A removed or revoked device that is still listed sees nothing, because the membership check comes
   first; if a removed device is added back to the workspace, it sees the object again, as the host chose it.
   No other relay mechanism is added. Everything else is the host's job (a host MUST, now, before P8):
   - an object about a restricted ticket is addressed with `device` wraps only, for exactly the devices allowed
     to see the ticket (no `wk` wrap, which every member device can open; no `inbox`, whose claim adds a `wk`
     wrap), and `recipients` = those devices; the W-author rule above allows exactly that;
   - the host decides which wraps and recipients exist and re-checks visibility on every later version, re-wrap
     and claim it writes; when the allowed audience shrinks it writes no new wrap for the removed devices (wraps
     already fetched cannot be recalled, as for removals);
   - a host that adds a device id back to the workspace MUST NOT assume that device is blind to restricted
     objects it was listed for before: audience rows survive membership changes (by design, item 4), so the
     re-added device can again list and read their descriptors and metadata; it holds no wrap the host did not
     write for it, so it cannot open content it lost access to, and the host re-wraps nothing for it unless
     the ticket allows (Opus delta 2, L-a);
   - the host filters what it passes on by ticket visibility: a W session's list returns every object of the
     workspace in every state, so any listing, object id or tombstone the host relays to devices (bridge
     answers, the dashboard) is filtered by the ticket's audience, and a restricted object's id is never put
     into content that a wider audience reads.
   What the relay cannot do: stop a member device inside a restricted audience from writing a next document
   version with a wider `recipients` and a `wk` wrap (documents are collaborative; readers apply the author
   rule, and orch-52 restricts its host to `file` objects, so restricted content should be files); and hide an
   object's existence from a member that knows its id (the 403/404 existence oracle of item 6). Both stay
   residuals (R-D10).

   `recipients` is `"inbox"` or a sorted unique list of 1 to 1 024 ids (§10.4), each `space_id` or a current
   member device of it (step 5). Every object is therefore visible only within its own workspace (in P4 a claim
   is by that same workspace), so no per-object access table is needed (§14.5).

5. **Expiry, retention and the document lifecycle (JUDGEMENT CALL on the numbers; Opus M5, owner question 3).**
   A `file` MUST carry `expires_ms` with `now < expires_ms ≤ now + 7 d + 300 s` (`ORCH_RELAY_DROP_MAX_TTL_MS`,
   default 604,800,000; the FakeRelay's rule, plus 300 s for clock skew, orch-f1 R4); `expires_ms ≤ now` is 410
   `expired` (a resent body that has expired), above the window 400 `malformed`. **Minimum lifetime (amendment
   A1, Opus delta R3):** a new file with `expires_ms < now + 60 s` is 400 `malformed`, `now` being the request's
   clock reading taken once at its start and reused when the commit re-runs step 8, so a slow upload that met
   the floor at admission is not refused for it at the commit (the commit's `expires_ms ≤ now` check, 410,
   uses the transaction's own `now`; Opus delta 2, L-c), so no member can churn
   files that expire at once. The floor is checked with the CAS (step 8), after the exact retry, so a retry of
   a stored file close to its expiry still answers 200. A `document` version MUST carry
   `expires_ms: null` in P4 (400 otherwise): with a settable expiry any `operate` member could write a version
   expiring in 1 ms and let the sweeper destroy the whole history. When `now ≥ expires_ms` a file is unreadable at
   once (reads 410 `expired`; a list shows it as `expired`, item 7), a sweeper deletes its blob and wraps within
   10 minutes, releases the usage, sets `tombstone_kind = 'expired'` and `tombstone_ms = expires_ms` (not the
   sweep time, so the listed `tombstone_until_ms` of item 7 is the same before and after the sweep), deletes its
   `drop_audience` rows (a device-only expired tombstone stays `audience = 'devices'` with no rows, so it is
   then visible to the W session only; its audience devices hold `expires_ms` and drop the file at that time;
   Opus delta R3) and assigns
   it a new change position, and
   a **tombstone** (the `drop_objects` row with `tombstone_ms`) is kept 30 days, so a reused id is 410 rather
   than a fresh version 1 that a reader holding the old head would read as a rollback. Superseded document
   versions keep their descriptors (readers check the chain from version 1) but their **blobs** are pruned when
   they are neither among the newest 8 versions nor younger than 30 days; pruning releases the blob bytes (the
   head bytes stay charged), and a pruned blob reads 410 `expired`. A document has at most 1 024 versions (the
   phone's chain cap); the 1 025th is 429 `quota_exceeded`.
   **Retire** (`POST /v2/drop/{o}/retire`, W(g) of the object's space, fenced like every W write, body
   `{"expect_version": <int ≥ 1>, "expect_head": "<b64u>"}` → `{"state": "retired" | "expired"}`): the host
   tombstones a `file` or a `document` at once, **if its head is still the one the host decided about**
   (orch-52 change 1). `expect_version` is the newest version the host saw and `expect_head` that version's
   head hash, `H("orch/v2/drop-parent|" || cj(o))` (the value the next version's `parent_hash` would carry,
   stored as `parent_hash_next` and copied to `drop_objects.head_hash`, §14.5). Both fields are **required**
   for files and documents (every P4 object); a body without them, or with any other field, is 400
   `malformed`. Encodings (Opus delta L3): `expect_version` is a JSON integer ≥ 1 (not a boolean, float or
   string); `expect_head` is canonical unpadded b64u (§1) of exactly 32 bytes, i.e. 43 characters that decode
   to 32 bytes and re-encode to the same text, else 400; the relay compares the decoded bytes with the stored
   hash. Check order: the W session, its fence at admission (409 `fenced`) and buckets; the body (400);
   object absent → 404; another space → 403 `not_eligible`; then, **in one write transaction**:
   1. the fence again on the live `holders` row (409 `fenced`, nothing changed; item 1, orch-52 change 0), so
      a retire admitted just before a takeover cannot commit after it; then the object row again: a row the
      tombstone sweep deleted after the pre-check is 404 (Opus delta L2);
   2. the precondition against the live row: if `current ≠ expect_version` or `head_hash ≠ expect_head`, 409
      `version_conflict` with `{"current": <current>, "state": <the entry state>}` and the object untouched
      (a member's version committed after the host's decision is never taken along by the retire);
   3. if the object is already a tombstone (retired, or a file at or past `expires_ms`, swept or not) and the
      precondition matched: 200 with its stored state, nothing changed and no new `n` (the bounded idempotent
      retry, below);
   4. otherwise the relay sets `tombstone_ms = now` and `tombstone_kind = 'retired'` and assigns a new change
      position `n` (item 7). A device-only object keeps its `drop_audience` rows on the retired tombstone (its
      audience still sees the `retired` entry); they move from the author device's head share to the
      workspace's head bytes only, until the row is deleted (§14.5). Only the host creates retired tombstones.
   Every read is then 410 `expired` and the list shows the object with `state: "retired"` until its tombstone
   ends (30 days, then 404 and no entry; a `PUT` of the id is 410 meanwhile, as for an expired file).
   JUDGEMENT CALL (`expect_version` and `expect_head` both): a file always has version 1, so a version alone
   protects nothing for files and cannot tell an id reused after the tombstone window; the head hash binds the
   exact version the host decided about, and the version keeps the 409 readable (`current`, the existing
   `version_conflict` code and body of the `PUT`, not a new code). The alternatives (an `If-Match` header as on
   the `PUT`, or the version only) were rejected for those reasons.
   - A **document** keeps the batched release: the sweeper frees its blobs, wraps and head bytes (item 12; up to
     1 024 versions cannot be deleted under one write lock). Its document count drops at once.
   - A **file** (amendment A1) has one version and at most 1 024 wraps, within item 12's per-transaction row
     bound, so the retire transaction itself deletes its version and wraps and releases its blob bytes, head
     bytes and live-version count from every usage scope (workspace, account, the author's device share); the
     blob file is unlinked after the commit (a crash in between leaves an orphan that the start-up sweep deletes,
     §14.5). A claimed or unclaimed `inbox` file, and a file a member device authored, are retired the same way.
   - **Idempotent, bounded by the tombstone window:** a retry with the same `expect_version` and `expect_head`
     against the tombstone answers 200 with its stored state and changes nothing (no new `n`); a file whose
     `expires_ms` has passed is already `expired` (200 `{"state": "expired"}`, the sweeper frees it as
     before), so expiry and retire never race into two tombstones. The tombstone keeps `current` and
     `head_hash`, so the precondition is checked the same way on it.
   - **Never replay a retire after the window (orch-52 change 3).** The idempotency lasts only while the
     tombstone lives (until its `tombstone_until_ms`, item 7). After that the row is gone and the id may be
     reused as a fresh version 1 (R-D5), so a 404 proves nothing (neither that the retire happened nor that the
     object expired), and a match of the reused id is unlikely only because of `expect_head`. Host contract: a
     retire whose answer was lost is retried only within **29 days** of the earlier of its first attempt and,
     for a file, its `expires_ms` (a retire that committed did so after the first attempt, and an expiry
     tombstone starts at `expires_ms`, so either tombstone outlives the bound; the day of margin covers the
     host's clock against the relay's; a tombstone the host has listed gives the exact end,
     `tombstone_until_ms`); after that the host
     **does not replay it** but reconciles: it relists the workspace in full and decides again from what is
     there (a live object with another head is a new object; absence means gone).
   This is the only way out of the per-document and per-workspace document caps, so no workspace can reach a
   permanent 429: the host retires a full or abandoned document after copying what it keeps into a new object.
   It also frees a file's quota before its 7 days end (Q-H6). **Only the host deletes:** devices have no retire
   or delete route in P4, not even for their own uploads; a member that wants an item gone asks its host (a
   host op over the bridge, orch-52), which decides and retires (orch-d6 ruling, amendment A1). A removed
   device's uploads stay until the host acts or they expire. The tombstone window (30 days) and the sweeps are
   unchanged.

6. **Reads.** A W session reads the objects of its workspace (the space, or the claimer, §10.5). A device
   session reads an object when it is a current member with `look` of the object's workspace and `recipients`
   does not exclude the device (a device-only list without it), **and**, for an unclaimed `inbox` object, the
   device is its author. **Unclaimed `inbox` objects are visible only to the W session and their author
   device** (amendment A2, orch-f1 (d)1, confirmed 15 Oct 2026; this **reverses** A1's rule, from orch-f1's
   earlier R1, that member devices list unclaimed inbox objects and read their descriptors): the inbox is the
   phone-to-host path, the host claims a phone's own uploads itself (item 13), and a phone that asks the host
   to release someone else's content gets the host answer `drop.handoff_required`, so no phone needs to list
   another author's unclaimed item. The author sees its own upload in `sending` (Opus L14), with its
   descriptor (the read-back of item 2 works for it) and its own `device` wrap; only `GET .../blob` stays 403
   `not_eligible` until the claim, for the
   author too. Other member devices get no list entry, and 403 on every read and on a `PUT` (step 6), live or
   tombstoned, exactly as for a device outside a device-only audience, with the same code and body as every
   other 403 `not_eligible` (`{"error": "not_eligible"}`, no extra key; orch-f1 wording pin); once the object is claimed (its
   `claimed_by` set) it is visible to every `look` member, and the claim's new `n` brings it into their
   incremental lists; a member that already held the id sees its 403 turn into 200 at the claim (it learns
   the claim, which the object is now theirs to see). The visibility filter, in SQL terms: `audience = 'space' OR (audience = 'inbox' AND
   (claimed_by IS NOT NULL OR head_author_id = :device)) OR (audience = 'devices' AND EXISTS (SELECT 1 FROM
   drop_audience ...))`. What this removes: before A2 other members learned an unclaimed item's routing
   metadata (author device id, `created_ms`, `expires_ms`, `content_len`, its existence); now they learn
   nothing about it unless they know its id (then the 403 of the existence oracle below), and a hostile phone's
   inbox spam reaches only the host. **Answer order (orch-f1 R5, Opus L-b)**, so a caller that may not
   see an object learns its existence and nothing more (not its workspace, kind, version, state or recipients):
   1. object absent → 404;
   2. object not visible to the caller (another workspace, `recipients` excluding the device, or another
      author's unclaimed `inbox` object, amendment A2) → 403 for every version and state, tombstones included;
   3. expired, retired or tombstoned → 410;
   4. version absent → 404 (the phone's pre-`PUT` read-back treats it as "slot empty").
   **This is an existence oracle, not "no leak" (amendment A1, orch-52 change 4).** Any authenticated caller
   that knows or guesses an object id tells 403 (the id exists, live or as a tombstone, and is hidden from it)
   from 404 (no such id, or its tombstone has ended), and the `PUT` answers the same way: step 6 gives 403 for
   another space's id and, for a device, for an object whose audience excludes it, before any 410, exact
   retry, CAS or claim answer (Opus delta R1). That holds **across workspaces** and **within one**: a member
   device outside a device-only `recipients` list (a restricted audience, item 4) that learns a restricted
   object's id gets 403, not 404, on every read and `PUT`, so it learns that something it may not see exists,
   and later that it is gone (403 turns into 404 when the tombstone ends). That is all it learns: no list entry,
   descriptor, wrap or blob, and no state, version, kind or claim status (the reads stop at step 2 of the order
   above, the `PUT` at step 6). Accepted (R-D10): ids are 128-bit random, so guessing is infeasible and the
   oracle answers only for ids a caller already learned elsewhere; the host keeps restricted ids out of content
   a wider audience reads (item 4). JUDGEMENT CALL, 403 rather than 404 for "not visible" (Opus delta L7): a
   404 would close the oracle within a workspace only if every route lied the same way, but the `PUT` cannot:
   it must refuse a write to an existing id it hides (a 404 there would invite a version 1 under that id, which
   the CAS then refuses with its own answer), and 403 on reads alone next to a 403 on `PUT` would just move the
   oracle. One rule across workspaces and within one (403 = exists and hidden) is simpler to test and to reason
   about; it also keeps the phone's pre-`PUT` read-back meaning of 404 ("slot empty", orch-f1 R5). `GET .../blob` streams the file with `Content-Length: content_len`,
   `Content-Type: application/octet-stream`, `ETag: "<v>"`, `Cache-Control: no-store`, in 64 KiB reads, never
   buffered; no `Range` in P4. `GET .../wraps` and the list return only the wraps the caller can use: a **W
   session** gets the `wk` and `wxk` wraps of its workspace; a **device** gets the `wk` wraps of its workspace and
   its own `device` wraps, **never** `wxk` (Opus N2; JUDGEMENT CALL:
   the FakeRelay returns every wrap; filtering bounds an entry to a few KiB and stops one member enumerating the
   others' device wraps). `claimed_by` is present in every list entry and wraps answer (null when unclaimed).

7. **List, change positions and page bounds.** `POST /v2/drop/list` with `{workspace_id, direction, after?,
   limit?, generation?, until?}` (D(m) with `look` in `workspace_id`, or W of `workspace_id`) → `{objects: [{n, object_id, version,
   state, tombstone_until_ms, descriptor, wraps, claimed_by, claimed_ms, expires_ms}], next, generation, until}` (`generation`, `until`,
   `claimed_ms` and `expires_ms`: amendment A2, items 14 and below). `direction` is `received` (author ≠ caller) or `sending`
   (author = caller), judged by the newest version's author, or, for a W session only, `all` (item 14). Each visible
   object appears once, with its newest version, at its **change position** `n`: a relay-wide counter assigned by
   every version commit, wrap change, claim and **state change** of the object (the §19.5 cursor pattern), so a
   client that keeps `after` sees only what changed. Pages ascend by `n`; `next` is the last entry's `n`, or null
   when there is nothing more up to the walk's `until` (orch-f1 S2; amendment A2, item 14).

   **Entry state (amendment A1).** `state` is one of:

   | `state` | Meaning | `descriptor` | `wraps` | Raises `n` |
   |---|---|---|---|---|
   | `live` | the entry's version and its blob are readable | the newest version's | the caller's usable wraps | (by the version, wrap or claim) |
   | `pruned` | the object is live but the entry's version has no blob (a pruned blob, descriptor kept; reads of that blob are 410) | kept | `[]` (pruning deletes the version's wraps, item 10) | yes, when the listed version is pruned |
   | `expired` | a file at or past `expires_ms`: a tombstone | `null` | `[]` | yes, by the expiry sweep (≤ 10 minutes after `expires_ms`) |
   | `retired` | retired by the host (item 5): a tombstone | `null` | `[]` | yes, in the retire transaction |

   A superseded document version whose blob is pruned is never the listed version (the newest 8 always keep
   their blobs), so in P4 `pruned` appears on an entry only after a database restore without its blob files
   (item 12, the start-up sweep), which assigns the new `n`; superseded pruning shows only as 410 on that
   version's blob and in the descriptor chain, and raises no `n`. `object_id` and `version` are given in every
   entry because a tombstone has no descriptor (the relay keeps only the `drop_objects` row, §14.5). An
   `expired` entry may appear before the sweep has run (the state is computed against `now` at read time), but
   only a list that happens to reach the object's old position sees it; a client therefore also treats a file
   as expired at its descriptor's `expires_ms` on its own (Opus delta L5); the sweep's `n`, **up to about 10
   minutes after `expires_ms`**, is what makes it reach every incremental list that may see the tombstone and
   the host notice (a device-only file's audience devices lose its entry at the sweep instead, item 5), so an
   incremental client learns of an expiry up to ~10 minutes late (a read is 410 at once).

   **Tombstone end and full reconciliation (orch-52 change 2).** Every entry carries `tombstone_until_ms`: null
   on `live` and `pruned` entries, and on a tombstone the end of its retention, `tombstone_ms + 30 d` (for
   `expired`, `expires_ms + 30 d` both before and after the sweep, item 5). A tombstone is listed until then;
   its row is then deleted, which raises no `n` (there is no entry left to carry it), so a client drops a
   tombstone it holds at `tombstone_until_ms` on its own, and a full relist simply omits it. Consequently a
   client **MUST do a full reconciliation** (list from the start, `after` omitted, and replace its whole set
   for the workspace: anything it holds that the full list lacks is gone; since amendment A2 a walk bounded by
   `until` concludes "gone" only after its follow-up walk, item 14) when the gap since its last complete
   incremental list is longer than the retention less the sweep period (30 days minus 10 minutes; 29 days is
   recommended, for clock margin; measured by the client from that list's start; the bound assumes the expiry
   sweep runs on time, every 10 minutes, so clients use 29 days, which also covers a late sweep of up to a
   day; Opus delta 2, L-d),
   because a state change in the gap may have been followed by the end of its tombstone, which no `after`
   list shows. A host also reconciles in full after a state restore, at takeover and before deciding about a
   retire it did not complete (item 5).

   **Every state change reaches the host notice.** `retired` (the retire transaction), `expired` (the expiry
   sweep) and `pruned` (the start-up sweep) each assign a new `n`, so each raises the workspace's newest change
   position and thus the host's `drop` notice (§14.9 Q-H1), like a version, wrap or claim. The end of a
   tombstone does not: the notice is the newest `n` among the workspace's remaining rows, so when the newest-`n` row is a
   tombstone that ends, the notice value can drop; a host treats only a value above its stored position as
   news and never moves its position back.

   **Who sees which entry.** Unchanged from item 6, and the same for tombstones: a **W session** sees every object
   of its workspace in every state. A **device** sees an entry when it is a current member with `look` and the
   object's audience includes it (`audience` `'space'`, `'inbox'` when claimed or authored by the device
   (amendment A2), or `'devices'` with a `drop_audience` row for it); a device excluded from a device-only list sees no entry for it in any state, tombstones included (the
   read answer order's 403). Exception (Opus delta R3): an expired device-only tombstone has no audience rows
   after the sweep, so only the W session lists it; a retired one keeps them. Unclaimed `inbox` files, and their
   tombstones, are listed only for the W session and their author device (amendment A2, item 6); claimed ones
   for every `look` member.

   **Why incremental lists see state changes (JUDGEMENT CALL).** The alternative was to state that `after` lists
   never see a retire or an expiry and that clients relist in full. The existing design already raises `n` on a
   retire (§19.9's route table, the `n` column of §14.5, the "positions moving on ... a retire" test), and the
   host learns of changes only through the `drop` notice and `after` lists, so a state change that raised no `n`
   would be invisible to the host and the dashboard until a full relist. Raising `n` keeps one rule (every change
   moves the object to the end) and costs one counter update per sweep batch row. orch-f1's phone relists in full
   and is unaffected; the dashboard and the host can list incrementally. Example entries (values shortened):

   ```json
   {"n": 4182, "object_id": "9f2c…", "version": 3, "state": "live", "tombstone_until_ms": null,
    "descriptor": {"o": {"kind": "drop_object", "object_id": "9f2c…", "version": 3, "…": "…"}, "sig": "…"},
    "wraps": [{"target_kind": "wk", "target_id": "5a1e…", "key_version": 7, "…": "…"}], "claimed_by": null,
    "claimed_ms": null, "expires_ms": null}
   {"n": 4190, "object_id": "c07d…", "version": 1, "state": "retired", "tombstone_until_ms": 1763208000000,
    "descriptor": null, "wraps": [], "claimed_by": "5a1e…", "claimed_ms": 1760600000000,
    "expires_ms": 1761200000000}
   ```

   **`claimed_ms` and `expires_ms` (amendment A2 revision 3; orch-52 and orch-fa, 15 Oct 2026; JUDGEMENT
   CALL).** Every entry also carries `claimed_ms`: the relay's clock at the claim's commit, set once with
   `claimed_by` and never changed (a trigger refuses any update of a non-null value, §14.5), null while
   unclaimed and for every non-inbox object; and `expires_ms`: the object's `drop_objects.expires_ms` (the
   head descriptor's, null for a document), given on tombstones too, where the descriptor is null. Both stay
   in the entry until the tombstone's row is deleted (`tombstone_until_ms`). Why: the host's "Shared from your
   phone" record (item 13, Q-H9) and its restore or takeover reconciliation can then take the claim time and
   the file's end from the relay, the source of truth, instead of its own clock; the alternative (the host
   alone records them) loses them with the host's state. Cost: one integer column and two entry fields;
   `claimed_ms` tells a device that sees the entry no more than the claim's `n` already does.

   The relay-wide counter tells a host roughly how much Drop activity
   other tenants have (Opus L7): accepted (R-D8). The host learns of new objects through a new host-poll notice
   `drop` (the newest change position of the workspace; §14.9 Q-H1), then lists `after` its stored position.
   `GET /v2/drop/{o}/descriptors?after=&limit=` pages the chain (`limit` ≤ 256, default 256): the phone's
   1 024-version walk becomes a few requests instead of 1 024.
   **Every page is cut by bytes as well as by count (Opus H1):** a list page stops before 2 MiB of JSON and a
   descriptor page before 1 MiB, always returning at least one entry (one entry is at most ~100 KiB: the 96 KiB
   descriptor plus the caller's few wraps), with `next` set as usual. Default and maximum list `limit` 64. The
   list's **request** body is capped at 16 KiB (the JSON-route cap); its **response** page at 2 MiB (orch-52 nit
   7: the earlier "4 MiB" is replaced by 2 MiB, and a host's 4 MiB read cap covers it).
   **Read concurrency (Opus N3):** at most 8 list or descriptor-page reads in flight relay-wide (503
   `overloaded`, `Retry-After: 1`), 4 per person and 2 per device (429 `quota_exceeded`, `"quota": "slot"`). The
   read slot is held until the whole body has been handed to the socket (a backpressure-aware send with the
   30 s idle limit), not only until it is serialized. **Pages are spliced from the stored `cj` text, never
   parsed and re-dumped** (normative; Opus L-a), and the byte cut uses the stored `descriptor_len` (§14.5).
   Peak: 8 × 2 MiB × ~3 ≈ 48 MiB, in the peak-RSS bench.

8. **Quotas, slots, buckets, disk and memory (arithmetic).**
   - **Per object:** blob ≤ `ORCH_RELAY_DROP_MAX_BLOB_BYTES`, default 26 MiB = 27,262,976 bytes (1..256 MiB). The
     phone's 25 MiB plaintext cap gives 40 + 26,214,400 + 25 × 16 = 26,214,840 bytes of ORD2 at 1 MiB chunks, which
     fits. A whole request is at most 8 + 524,288 + 27,262,976 = 27,787,272 bytes.
   - **Blob bytes:** per workspace 512 MiB and 4 096 live versions (a live version is one whose blob is
     `stored`); per owner account (all its workspaces) 1 GiB; per device per workspace 256 MiB authored (so one
     `operate` member cannot fill its workspace); global `ORCH_RELAY_DROP_GLOBAL_BYTES`, default 4 GiB public,
     1 GiB recommended for the internal instance.
   - **Head bytes (separate; Opus M4, L5):** descriptors and every stored wrap, including host re-wraps and claim
     wraps, charged to the workspace: per workspace 32 MiB, global `ORCH_RELAY_DROP_GLOBAL_HEAD_BYTES` 512 MiB
     public, 128 MiB internal. Heads live in SQLite, so this cap is what bounds the database, its WAL and
     `VACUUM` space; blobs live in files. Per workspace at most 256 documents that are not tombstoned.
     **Audience rows (amendment A1, Opus delta R3)** are head bytes at 65 B each: while the object is live they
     count against the workspace, the author device's head share and the global head ceiling, like its
     descriptor; an expiry deletes them (item 5); a retire moves them off the author's share, so a retired
     device-only tombstone holds at most M × 65 B (M the listed devices, ≤ the workspace's member devices) of
     workspace and global head bytes until its row is deleted 30 days later. Only the host creates retired
     tombstones, so no member can pin head bytes that way; the host's own retires of restricted objects cost
     it up to M × 65 B each for 30 days (≈ 1.3 KB at M = 20), which it cannot free early. JUDGEMENT CALL (Opus
     delta 2, L-b): the charge stays on the workspace (as above) rather than moving back to the author's share,
     because only the host's decision creates it, so a host rule bounds it with no new relay counter: the host
     SHOULD let a member's restricted file expire rather than retire it in bulk, and keeps its retired
     restricted tombstones' rows within 1 MiB of the workspace head bytes (about 800 retires at M = 20).
   - **Per-member shares (Opus N5).** Every workspace-wide counter also has a per-(device, workspace) share, so
     one `operate` member cannot lock the workspace's Drop: blob bytes 256 MiB, head bytes 8 MiB, live versions
     1 024, documents 64, version-1 creations 250 per day. The workspace totals stay. The 1 024-version cap of a
     single document has no share (any member may fill a shared document; the host retires it).
   - Exceeding a workspace, account or device cap is 429 `quota_exceeded`; a global ceiling is 503 `overloaded`
     (P3-D17 convention).
   - **`Retry-After` (orch-52 item 7).** Every Drop 429 and 503 carries `Retry-After` (integer seconds, ≥ 1). For
     429 `rate_limited`, a slot cap and 503 `overloaded` it is the time until a token or slot frees, or the next
     expiry sweep (≤ 600 s) for a global ceiling: these are transient. A **stored-bytes** 429 `quota_exceeded`
     also carries `Retry-After: 600` (the sweep period) for uniformity, but is **not** transient: its body names
     the cap, `{"error": "quota_exceeded", "quota": "drop_ws" | "drop_head_ws" | "drop_account" |
     "drop_versions" | "drop_documents" | "drop_device" | "drop_device_head" | "drop_device_versions" |
     "drop_device_documents" | "drop_doc_versions"}`, and it stays until expiry, pruning, a retire or (for
     head bytes held by a retired device-only tombstone's audience rows) the end of that tombstone frees
     usage (Q-H6). A slot cap's 429 carries `"quota": "slot"` and is transient. Usage is reserved in memory at
     step 9 and charged in the commit, so concurrent uploads cannot overshoot; a crash drops reservations and the
     temp files with them.
   - **Slots (Opus M2).** Uploads: 16 relay-wide (503 `overloaded`), and 2 per device, 3 per person and 4 per
     workspace (429 `quota_exceeded`). Downloads: 32 relay-wide (503), 4 per device and 8 per person (429). Both
     directions: an idle timeout of 30 s between body reads or writes, a **minimum average rate of 64 KiB/s**
     after the head (a 26 MiB body may take about 7 minutes), and a maximum duration of 10 minutes; a breach
     closes the connection and frees the slot and the reservation. One person (any number of devices) therefore
     holds at most 3 of 16 upload slots.
   - **Disk.** Drop's worst case is the blob ceilings (public 4 GiB + internal 1 GiB = 5.37 GB), the head
     ceilings in SQLite counted twice for WAL and `VACUUM` with ~1.3× page and index overhead (≈ 1.75 GB),
     in-flight temp files (16 × 27.8 MB per instance, both instances ≈ 0.89 GB) and tombstones (≤ ~100 B each,
     uncharged, plus a retired device-only tombstone's charged audience rows, within the head ceilings):
     ≈ 8 GB (Opus delta: 7.5–7.9 GB). With the dev-deploy-plan §4.3 checkpoint bound of ~15 GB and ~35 GB free,
     the worst case leaves ~12 GB free; the plan's "≥ 20 GB free" soak criterion is about real usage and
     still holds for the invited users (files live ≤ 7 days). A larger ceiling needs the disk recomputed (§10
     checklist 2 gains a Drop line).
   - **Memory.** Per upload: the head (≤ 512 KiB of bytes, but ~2–3 MB of CPython objects while 1 024 wrap
     records are parsed and verified; Opus L-a) plus a 64 KiB buffer; per download 64 KiB. Peak ≈ 16 × 3 MB +
     32 × 64 KiB ≈ 50 MB for transfers, ≈ 48 MiB for Drop JSON reads (item 7, spliced), ≈ 45 MB for the push
     queue and its dedup LRU (P3-D40 item 6): ~145 MB on top of the ~618 MB public peak of §10 checklist 1,
     ~765 MB of the 944 MB `MemoryMax` (~19 % headroom; parse-then-dump pages would push this to ~800 MB, which
     is why splicing is normative). The bench decides. The 618 MB includes a 250 MB baseline where U9 measured ~50 MB per unit,
     so the real headroom is larger. No blob is ever held in memory.
   - **Event loop (Opus L8).** Drop gets its own async endpoint (the existing one buffers the whole body and runs
     `Directory.handle` on the shared 40-token threadpool): file writes, hashing and `fsync` run off the event
     loop through a dedicated limiter (16 tokens), so transfers cannot starve the JSON routes.
   - **Buckets (P3-D35 form, in memory, overrides `burst/per-minute`).** Upload: one token per started MiB of
     body, per device burst 64 and 32/min (`ORCH_RELAY_THROTTLE_DROP_UP`), per workspace burst 256 and 128/min
     (a 5-attachment, 25 MiB compose costs about 27 tokens: no 429). Download: one token per started MiB served,
     taken before the read for `content_len`, per device burst 256 and 256/min, per person twice that
     (`ORCH_RELAY_THROTTLE_DROP_DOWN`, and `..._DROP_DOWN_PERSON` for the person's: 512 and 512/min; likewise `..._DROP_UP_WORKSPACE`). Metadata routes take one read-class token as today.
   - **Rate of new objects:** at most 1 000 version-1 creations per workspace per day and 250 per device in it
     (429 `rate_limited`), which bounds tombstones to ~30 000 per workspace (~3 MB of uncharged rows; the
     60-second minimum file lifetime of item 5 stops instant-expiry churn, and expired tombstones keep no
     audience rows).
   - **Decide-class budget and slot (amendment A2, item 13):** an upload authorized by `decide` alone also
     spends a per-(device, workspace) budget of 50 creations and 64 MiB of `content_len` per UTC day, charged
     at admission and kept for failed streams (429 `rate_limited`, `Retry-After` to 00:00 UTC), and holds the
     device's single decide-class upload slot, on top of every cap above.

9. **Claims and host re-wraps (D39b).** `POST /v2/drop/{o}/claim` is §10.5 verbatim (one transaction, the
   five-step order, idempotent, `claimed_by` to the loser), with relay details: the W session's fence and
   authorization are checked before anything else (Opus N4) and the fence again inside the claim's and the
   re-wrap's write transaction (item 1); the object must be an `inbox`
   `file` and unexpired (403 `not_eligible` otherwise, as the FakeRelay does); in P4 the claimer is the object's
   own workspace (M1); the claim's change position is new, so lists show it; a claimed object takes no new
   version (M7). `PUT /v2/drop/{o}/versions/{v}/wraps` with `{wraps: [wrap]}` (exactly one record) stores the
   host's current-epoch `wk` wrap for its own workspace: the object version must be addressed to the workspace
   (its space, claimed by it if `inbox`; an unclaimed inbox is 403 `not_eligible`, the FakeRelay's
   `rewrapSource`), the wrap `target_kind` `wk`, `target_id` the workspace and `key_version` its current epoch
   (409 `stale_epoch` otherwise). An identical record is a 200 no-op; other bytes for the same
   `(target, key_version)` are 409 `wrap_conflict` (as G0a review 10 for card-key wraps: the host persists the
   wrap before sending and resends the same bytes, never reseals). The 409 `wrap_conflict` body carries what a
   host that lost its local copy needs to recognize its own earlier wrap (orch-52 Q-H5): `{"error":
   "wrap_conflict", "wrap": <the stored record>, "dek_commit": <the version descriptor's>}`; the host opens the
   stored wrap with its `WK_e`, checks `dek_commit`, and treats a match as success. The body is produced only
   after the auth, fence and addressing checks, and the caller is already authorized for that version's wraps,
   so nothing new is disclosed (Opus L-h). If the stored wrap does **not** match `dek_commit` (a bad wrap from a
   hostile writer), the slot stays occupied and cannot be replaced: the host treats the version as unreadable
   through `wk`, logs it, and readers fall back to other wraps. The FakeRelay replaces silently; this
   tightens it. Re-wraps are charged to the workspace's head bytes (L5).

10. **Revocation and removal (Opus L-f).** The device-wrap deletion is bounded only by the head caps (~130 k
    rows per workspace), so it does not run inside the revocation or publication transaction: that transaction
    only records the device as gone (the read filter already excludes non-members, so its `device` wraps are
    unreachable at once), and a batched sweep (item 12) then deletes the `drop_wraps` rows with
    `target_kind = 'device'` and `target_id` = the device, in every workspace on revocation and in the workspace
    on removal. Pruning a version's blob also deletes that version's wraps (useless without the blob), which
    frees head bytes and keeps this sweep small. Objects a removed or revoked device authored stay (their
    signatures stay valid; readers apply their own author rule, gaps.md Slice 5). The device's usage share is
    released only by expiry, pruning or retire.

11. **What the relay sees and stores.** Routing ids, object ids, space, kind, version, author id, recipients
    (ids), sizes, expiries, timing, claims, and the opaque ciphertext of blobs, metadata and wraps. Never a
    `DEK`, `WK`, `WXK`, file name, MIME type or plaintext. The §2 "never stored" grep test extends to an uploaded
    fixture's name, MIME type and content.

12. **Sweeps and backups (Opus M4; owner question 4).** The expiry, tombstone, pruning and device-wrap
    sweeps work in batches of at most 4 096 **deleted rows, cascaded `drop_wraps` rows included**, per write
    transaction (Opus L-e: never a 1 024 × 1 024 cascade under the global write lock; one document's tombstone
    sweep is split across transactions and reads answer 410 throughout), unlink files only after the batch commits, and log and skip an object whose sweep fails (for example a
    usage underflow against `CHECK bytes >= 0`), so one bad row never wedges the sweeper. **Backups:** the
    database backup carries every descriptor and wrap; `<data>/drop/` is **excluded** from backups and from the
    reset runbook's moves by default (recommended; owner question 4), because files live at most 7 days and
    pruned document blobs are already "gone" to readers. A database restored without its blob files is
    consistent: the start-up sweep marks each `stored` row whose file is missing as `pruned` and releases its
    blob bytes. If the owner wants Drop blobs backed up, the runbook copies `data/drop/` after the database and
    counts twice its size on disk.

13. **Decide-class uploads (amendment A2; agreed with orch-52, 15 Oct 2026; revision 2 after the Opus delta
    R1–R3 and orch-f1's check).** Phones hold `look` and `decide` only (core 11A.15.6, the N1 scope ceiling: a
    phone never holds `operate`), so under steps 2 and 5 a phone's inbox upload would be 403. **Authority of a
    device `PUT`:** `operate` in `space_id`, **or** `decide` in `space_id` with the **decide-class shape**:
    `object_kind: "file"`, `recipients: "inbox"`, `version: 1` (`parent: 0`, `parent_hash: null`) and
    `If-Match: 0`, i.e. a new object id. Item 4's inbox wraps apply unchanged: exactly one `wxk` wrap to the
    space and optionally the author device's own `device` wrap, never `wk`. Not allowed to a device without
    `operate`: a second version (a file takes none anyway), any `document`, an object addressed to the space
    or device-only (a `recipients` list), and, as for every device, the W-only routes (`PUT .../wraps`, claim,
    retire). W sessions are unaffected.
    - **The current member list.** Scopes are a prefix of `["look", "decide", "operate", "type"]`, so `operate`
      implies `decide`; "decide-only" (or "decide alone") means `decide` without `operate` in `space_id`. The
      scope is read from the live `members` row for `(space_id, device)` (a revoked device has no session,
      step 2), and step 11 re-runs it inside the write transaction like the other eligibility checks, so a
      device whose `decide` is removed, or that is removed or revoked, during the transfer gets 403
      `not_eligible` at the commit with nothing stored.
    - **Place in the check order.** Step 2 (before any slot) admits a device with `operate` or `decide` in at
      least one workspace (D39a1's review F8 check widens); a device with `operate` in no workspace gets at most
      **one** upload slot there. The shape check sits in step 5, where the session's write scope for
      `space_id` is checked (after the session, principal, fence and workspace scope, long before the quota
      reservation): a decide-only device whose request lacks the decide-class shape gets **403
      `not_eligible`**, the code and step a device without write scope gets today. It depends only on the
      request and the caller's own scopes, never on stored object state, and comes before step 6, so it adds
      **no oracle**: an id of another space, outside a device-only audience or of another author's unclaimed
      inbox object (item 6) still answers 403 at step 6, an own-workspace id the caller sees answers what an
      `operate` member would get (410 for a tombstone, the exact-retry 200, or the CAS's 409
      `version_conflict` with `current`). "A new object id" therefore needs no extra check: `If-Match: 0` and
      the CAS enforce it. The exact retry (step 7) precedes the budget, so a phone's resend after a lost 201
      answers 200 and spends nothing.
    - **Epoch and rotation answers (orch-f1 (d)2).** A decide-class upload carries no `wk` wrap, so it never
      gets 409 `stale_epoch`; its `wxk` wrap gets 409 `bad_wxk_version` when the card moved (item 4). The
      `rotation_required` refusal (owner question 6, if adopted) refuses `wk` wraps only, so it never applies
      to a `wk`-less inbox upload; where it applies, it is checked in step 9 before the budget.
    - **One decide-class slot (Opus delta R1).** An upload authorized by `decide` alone holds a decide-class
      slot: **at most one per device**, besides the device's 2, the person's 3, the workspace's 4 and the 16
      relay-wide upload slots, which it also counts against. Step 2 gives a device with `operate` in no
      workspace one slot; a device with `operate` elsewhere that turns out at step 5 to be decide-only for
      `space_id` while another decide-class upload of it is in flight gets 429 `quota_exceeded` (`"quota":
      "slot"`, transient), before any blob byte. So a stolen phone holds at most 1 of a workspace's 4 upload
      slots.
    - **Budget (JUDGEMENT CALL on the numbers; Opus delta R1, R3).** An upload authorized by `decide` alone
      also spends a per-(device, workspace) **decide-class budget: 50 creations and 64 MiB (67,108,864 bytes)
      per UTC day**, on top of item 8's per-device shares and workspace, account and global caps, which apply
      as to any device.
      - *Charged at admission, refunded almost never.* In step 9 (after the wraps and any `rotation_required`
        check, before the quota reservation) the relay **charges** 1 creation and the declared `content_len`
        in one short write transaction on the persisted `drop_decide_budget` row, as an **upsert**, so the
        first upload of a UTC day (no row yet) is charged like any other (Opus delta 2, RB):

        ```sql
        INSERT INTO drop_decide_budget (workspace_id, device_id, day, creations, bytes)
        VALUES (:ws, :device, :day, 1, :len)
        ON CONFLICT (workspace_id, device_id, day) DO UPDATE
          SET creations = creations + 1, bytes = bytes + excluded.bytes
          WHERE creations + 1 <= 50 AND bytes + excluded.bytes <= 67108864;
        ```

        `:len` ≤ 67,108,864 always (a blob is at most 26 MiB), so the insert branch never exceeds the cap.
        The upsert is refused when `changes()` is 0 after it (the conflict branch's `WHERE` failed) → 429. Under
        the directory's single writer, two concurrent `PUT`s therefore cannot both take the last creation or
        the last bytes, and a crash or restart never refills the budget. The charge is **refunded only** when
        the request is refused before the relay reads its first blob byte (the quota reservation's 429 or 503
        right after the charge) and for the lost commit race (the commit finds the identical version already
        stored and answers 200, the exact retry of step 7 at the commit: the whole charge is given back; D39a2
        part 3, review L3), and never arises for an exact retry that step 7 answers before any charge. Every other outcome keeps the charge: a commit keeps all of it; a stream that fails after
        its first blob byte (a disconnect, an idle or rate breach, a short, long or non-ORD2 body, a wrong
        `content_hash`, a 403 at the commit, a relay error such as 503) is charged 1 creation and the bytes
        actually received. The give-back of the unreceived bytes (`content_len` − received, and for a refusal
        before the first blob byte the whole charge) is a **separate small write transaction on the error
        path** (`finally`, shielded from cancellation), best effort: if it is lost (a crash, an
        `OperationalError`, the process killed), the full `content_len` stays charged, so a skipped give-back
        over-charges and never under-charges. JUDGEMENT CALL: no refund for relay-side failures either, so no client-chosen
        failure can pass as one; a phone loses at most one upload's budget per relay fault.
      - *The day.* `day = floor(now_ms / 86,400,000)` of the request's `now`, read once at its start (A1's
        `now`, item 5). The charge, the shortfall give-back and the refund all go to that day's row, also when
        the commit falls after midnight UTC. The day boundary allows up to twice the budget within minutes
        around midnight (accepted).
      - *Authority changing during the transfer (Opus delta R3).* The commit's re-check on the live row
        decides: **the commit-time authority wins** for eligibility. If the device was decide-only at
        admission (charged) and holds `operate` at the commit, the charge stays (no refund). If it held
        `operate` at admission (no charge) and is decide-only at the commit, the commit transaction applies the
        same upsert for 1 creation and `content_len` (a plain `UPDATE` would refuse the day's first upload;
        `changes() = 0` → 429); if it is refused, the commit is 429
        `rate_limited` with nothing stored and no charge (the stream was admitted under `operate`). The
        per-device shares and the workspace, account and global quotas are charged as for every upload either
        way, so no path stores bytes uncharged.
      - *The refusal (orch-52, orch-f1 (c)1).* `{"error": "rate_limited", "quota": "drop_decide_creations" |
        "drop_decide_bytes"}` with 429. It **MUST** carry `Retry-After` = the integer seconds from the relay's
        `now` to the next 00:00 UTC by the relay's clock, at least 1 and at most 86,400; the phone derives
        "tomorrow" from it, not from its own clock, and sends no decide-class `PUT` before then. It is a step-9
        answer after an upload slot is held, so it takes the early-answer path of item 2 (the bounded drain;
        the connection may close; the phone treats a disconnect as an unknown outcome and reads back). A read-back
        404 followed by a resend that again ends in a closed connection costs bucket tokens and a drain each
        time, so the phone backs off exponentially after two consecutive disconnects on a decide-class upload
        and stops at its attempt cap (item 2; Opus delta 2, L-6).
      - *Arithmetic, and what the budget bounds (Opus delta R1: the revision-1 "~1.9 GiB a day of ingress" was
        wrong).* The budget bounds the bytes the relay **reads into a blob file, hashes and stores** for a
        decide-only device, failed streams included: at most 64 MiB a day per (device, workspace). 64 MiB is
        about 2.5 maximal files (26,214,840 bytes each), so for large files the byte limit trips before the
        50-count (orch-f1 (d)3); it is also about 20 photos of ~3 MB. Stored: files live at most 7 days + 300 s,
        so at most 7 × 64 MiB = 448 MiB, which the 256 MiB device blob share already caps, at most 350 live
        inbox files (7 × 50) and about 1 850 tombstones (~185 KB of uncharged rows). Head bytes: realistic inbox
        heads are 1–3 KB; the worst case (a 96 KiB descriptor and two 512 B wraps) is ~97 KiB × 50 ≈ 4.7 MiB a
        day, within the 8 MiB device head share. The budget is per (device, workspace), so a phone that is a
        decide-only member of W workspaces can store and hash W × 64 MiB a day; relay-wide the bound is 64 MiB
        × the number of (decide-only device, workspace) memberships, a day (Opus delta 2, L-4). With ~10
        invited accounts and ~3 phones each in one workspace, that is 30 × 64 MiB ≈ 1.9 GiB a day of
        decide-class blobs (the revision-1 number, a stored-bytes bound, not an ingress bound); every phone in
        two workspaces doubles it. The global ceilings (4 GiB blobs) still cap what is stored at once. **Network ingress** is bounded by the buckets and slots,
        not by the budget: every request takes upload-bucket tokens for its declared body at admission (32
        MiB/min per device, 128 MiB/min per workspace), and a refused request's drain reads at most its
        declared remainder within 30 s from the drain pool (2 per device, 32 relay-wide). A stolen phone that
        keeps sending budget-refused bodies can thus make the relay **receive** up to the device bucket,
        32 MiB/min ≈ 45 GiB a day, almost all of it drained and discarded without hashing or storing, while
        holding at most one upload slot and at most two drains; per workspace the bucket caps it at 128 MiB/min
        (≈ 180 GiB a day), relay-wide the drain pool, the 16 upload slots and the VPS link. That is the
        capacity any device with `operate` already had before A2, now reachable by a decide-only device:
        **accepted as an availability residual until the device is revoked** (R-D12). Disk (item 8, ~8 GB) and
        memory (~765 MB of 944 MB) worst cases are unchanged, because the global ceilings, the account cap and
        the upload slots are unchanged and a decide-only device holds fewer slots.
      - *Alternative (orch-f1 (d)3), not taken:* 128 MiB a day (about 4.9 maximal files) doubles the stored and
        hashed bound to ≈ 3.75 GiB a day relay-wide (30 × 128 MiB) and to 7 × 128 MiB = 896 MiB of possible
        live bytes per device, still capped by the 256 MiB share; network ingress is unchanged (bucket-bound).
        Chosen: 64 MiB, because the phone's composer stages at most 25 MiB per file and the owner's phones
        upload photos and documents, not videos, in P4; the number is a configuration default and can rise
        without a protocol change.
      Why a separate budget: the phone is the device most likely to be stolen unlocked (D49), and `decide`
      is a smaller grant than `operate`; with only the operate shares a stolen phone could post 250 inbox items
      a day into its host's triage.
    - **Who sees a decide-class upload (orch-f1 (d)1, confirmed 15 Oct; reverses A1's "members see an
      unclaimed inbox item's routing metadata", item 6).** Before the claim an inbox object is visible only to
      the W session and to its author device (`sending`); other member devices get no list entry and 403 on
      reads and `PUT` (item 6). After the host's claim it follows the claimed visibility (every `look` member,
      with the `wk` wrap the host adds, item 4).
    - **Host-side claim rule (orch-52; recorded here, enforced by the host, not the relay; Q-H9, agreed).** The
      relay's claim is by the workspace (item 9, M1); "the person the claim is for" is the person on whose
      behalf the host releases the object to the workspace's members. The host claims an inbox object
      **without an extra gesture** only when (1) the object's verified author device (the descriptor's
      signature under that device's `dk_sig_pub`) is a **current member device of that person** at claim
      time, with `decide` present and not revoked, re-checked under the host's store lock in the same step as
      the claim, and (2) the claim is for that person's own device-authored upload. Releasing **someone
      else's** upload, or an upload whose author device has since been revoked or removed, needs a terminal
      hand-off (a phone asking for it gets the host answer `drop.handoff_required`, orch-52 §11A.16). In a
      workspace with several people this means any member's own phone upload is released without a gesture to
      every member, the host's owner included (Opus delta 2, L-1). **"Shared from your phone" is host-side**
      (orch-52, cc orch-fa, decided 15 Oct): at each gestureless claim the host persists its own record (item,
      author device, `claimed_ms`) and shows it on the dashboard and in `orch status` until `shared_until_ms =
      claimed_ms + 7 d`, independent of the file: once the file is gone (its `expires_ms` passed, or retired)
      the record stays with the state `expired` or `retired` and the retire action is hidden. Who sees that
      list is the host's matter; relay-side, the only fact is that before the claim the object is visible
      to the W session and its author device only, so the person's other devices do not see it (visibility is
      per author **device**, item 6). The relay promises nothing beyond its list: an entry carries `claimed_by`,
      `claimed_ms` and `expires_ms` (item 7) until its tombstone is deleted (30 days after it began), and after
      that the host's own record is the only source. Retiring one's own upload stays a single unsigned action.
      No activity window: a stolen unlocked phone can already answer questions with `decide`, so this upload
      risk is comparable, and bounded by the budget.
    - **Pinned by** (D39a2): a decide-only device's new inbox file 201 with one `wxk` and its own `device` wrap;
      403 `not_eligible` at step 5 for a decide-only device's `document`, `space` list, device-only list, file
      at version 2, `If-Match: 1`, with nothing charged; the same answer for those shapes on an id of another
      space (no extra information); a decide-only device's `If-Match: 0` on its own existing file 409
      `version_conflict`, on another author's unclaimed inbox id 403, on a tombstone it sees 410, and its exact
      retry 200 after the budget is spent; a `wk` wrap on its inbox file 400; no `stale_epoch` and no
      `rotation_required` for a `wk`-less inbox upload, `bad_wxk_version` for an old `wxk`; `decide` removed
      during the transfer: 403 at the commit, no row, the file unlinked, 1 creation and the received bytes
      charged; a disconnect after half the blob: 1 creation and the received bytes charged, the rest given
      back; the give-back lost (the process killed on the error path): the full `content_len` stays charged; a
      refusal at the quota reservation right after the charge: refunded; the first upload of a UTC day (no
      row yet) charged by the upsert's insert branch, and a refused upsert detected by `changes() = 0`; the 51st creation and a
      `content_len` over the remaining bytes 429 `rate_limited` with the `quota` field and `Retry-After` the
      seconds to 00:00 UTC (≥ 1, ≤ 86,400; at 23:59:59.500 UTC it is 1); two concurrent `PUT`s for the last
      creation (one admitted, one 429); an upload admitted at 23:59 UTC and committed after midnight charged to
      the first day; `operate` removed but `decide` kept during the transfer (charged at the commit, or 429 at
      the commit when the budget is spent) and the reverse (the charge kept); a second concurrent decide-class
      upload of one device 429 `slot`; an `operate` device's inbox upload not charged to the decide budget;
      the budget surviving a restart; the pre-slot admission of a decide-only device and the refusal of a
      `look`-only device before any slot. Fixture cases in `drop_put.json` (§14.6) and a `drop.relay_put`
      vector step "decide-only inbox file, then a decide-only document" (201, then 403).

14. **W-session list walks: `direction: "all"`, `generation` and `until` (amendment A2; agreed with orch-52,
    15 Oct 2026).** The host keeps one position per workspace and needs every object, whoever wrote it, in one
    walk that ends and is consistent against concurrent changes.
    - **`direction: "all"`**: every object of the workspace that the caller sees, both authors (for a W
      session, every object in every state, item 7). **W sessions only.** A device session that asks for
      `all` gets **403 `not_eligible`** (JUDGEMENT CALL: an authority refusal, not a syntax one, since the
      same body is valid from a W session; it mirrors the `PUT`'s "author ≠ session" 403, and depends only
      on the caller's kind, so it reveals nothing about any object). Devices keep `received` and `sending`
      unchanged, and W sessions may still use them.
    - **`generation`**: a random id of 16 bytes, written as 32 lower-case hex characters, in the relay's
      `meta` table (key `drop_generation`). Every list page carries it, for every caller and direction (it is
      relay-wide and tells nothing about a workspace beyond "the Drop dataset was replaced"). The relay reads
      it **once at start**, after the check below, and serves it from memory (Opus delta L1): a row changed or
      deleted while the relay runs takes effect only at the next start, and no page is ever served without
      one. It changes **only** when the Drop dataset is restored or replaced, detected structurally rather than
      by an operator step (Opus delta R4; the "fix a security class structurally" rule):
      1. **A high-water mark outside the data directory (the primary mechanism; Opus delta 2, RA).** Today's
         procedures move or copy the **whole** data directory: dev-deploy-plan step B backs up by `mv
         /srv/orch-relay/data /var/backups/...` (and creates an empty one), its §6.2 rollback restores by `cp -a`
         of that directory (the deploy-day runbook's step 2 `mv` and R2 `cp -a` likewise), and the reset tool
         wipes it in place (`find ... -delete`). A file inside it would be rolled back with the
         database, so the high-water file lives in a **sibling state directory that no backup, restore,
         rollback or reset touches**: `ORCH_RELAY_STATE`, deployed as `/srv/orch-relay/state/` and
         `/srv/orch-relay-int/state/`, one per instance (each instance has its own file, so the two never
         share one; a sibling of `data/` like `apns/`, but owned `<svc>:<svc>` with mode 0700 on both
         instances, where `apns/` is `root:orch-relay` 0750 and public only). `provision.sh` always creates it
         and the units always set `ORCH_RELAY_STATE` (the parents are `root:<svc> 0750`, so the service cannot
         create it; the reset helper's comment names `*/state` as never touched and keeps it out of its
         targets; D40c). Only `serve` (never an admin or CLI command) takes an exclusive `flock` on a
         **separate, never-renamed lock file** `drop-hwm.lock` in the state directory (opened with
         `O_CREAT`, held for the process lifetime; a lock on `drop-hwm.json` itself would be lost at its
         first atomic `rename`, which replaces the inode; Opus delta 4, RI). On contention it retries for up
         to 30 s (a restart overlap) and then counts as a failed state check. **Start order:** the state check
         (directory, `realpath`, writability), then the lock, then the start check of the `generation` and the
         start write of `drop-hwm.json`, and only then the Drop routes and the `n`-assigning sweeps; a failed
         check lasts until the next start (no retry while the process runs), so a misconfiguration that
         points two instances at one state directory cannot cause a regeneration storm.
         **Fail closed (Opus delta 3, RE).** At start the relay accepts `ORCH_RELAY_STATE` only if, after
         `realpath`, it is an **existing directory writable by the service** that is neither
         `ORCH_RELAY_DATA` nor inside it, **and** the post-check high-water write succeeds; otherwise the
         state check has failed (below). A **failed periodic or shutdown write never blocks or fails a Drop
         commit**: it is logged at ERROR and retried at the next tick, so a persistent failure is visible,
         not silent. The temporary file is created **in the state directory itself**, never in `/tmp`
         (`PrivateTmp`), so the `rename` is atomic on one filesystem.
         **Independent of the Drop switch (Opus delta 3 RF, delta 4 RH).** The start check and the writer
         run whenever `ORCH_RELAY_STATE` is set, whether `ORCH_RELAY_DROP` is on or off. A failed state check
         (unset, invalid, unwritable, locked, or the start write failed), logged at ERROR, has two separate
         consequences: (a) with `ORCH_RELAY_DROP=1` it **always** means no Drop route (they answer 404 as
         absent), whatever `drop_counter.n` is; (b) with Drop on or off, when `drop_counter.n > 0`, it means
         **no code that assigns a change position** runs (no start-up pruning renumbering, no expiry, tombstone
         or pruning sweep), so a restore made while Drop is off (the kill-switch) cannot be renumbered past a
         client's position before the check passes again. With Drop off and `drop_counter.n = 0` nothing
         changes. Either way the process still starts and serves every non-Drop route (no exit, so no crash
         loop under `Restart=on-failure`). The file `drop-hwm.json` holds
         `{"generation": <hex>, "n": <committed drop_counter.n>}`, read from the database (never an in-memory
         next position, so a crash cannot leave a value that was never committed; Opus delta 2, L-5) and
         written by a temporary file, `fsync`, `rename` and a directory `fsync`: at every start (after the
         check), **at most every 60 s while the counter changes**, and at a clean shutdown.
      2. **Backups never carry the row (defence in depth).** A backup made by `sqlite3 .backup` has the
         `drop_generation` row deleted **in the backup copy** before it is stored, so a restore of such a copy
         starts without the row even onto a fresh host whose state directory is empty. D40c replaces
         dev-deploy-plan step B's `mv` and §6.2's `cp -a` of the whole data directory with this (and keeps the
         state directory out of every move), with a test that restores a step-B backup and a §6.2 rollback and
         gets 409 on a stale `generation`.
      3. **The start check**, before the start-up sweep (whose pruning of missing blob files assigns new `n`
         and could otherwise carry the counter past a client's stored position before the first request): the
         relay regenerates the row (a fresh random id, in the same transaction as the check) when the row is
         missing, when the high-water file is missing or unreadable, when its `generation` differs from the
         row's, or when its `n` is above `drop_counter.n` (the counter went back: a restore, a rollback or a
         reset to an empty database, whichever procedure did it). JUDGEMENT CALL: a missing high-water file
         regenerates too (one extra full relist for each host at D39a2's first start, on a new host or after a
         lost state directory, never a missed change).
      A plain restart or deploy keeps it. Regenerating at every start was rejected: every deploy would force
      every host into a full relist. A request's `generation`, when present, that differs from the relay's
      answers **409 `generation_changed`**, exactly `{"error": "generation_changed"}` with no other key (the
      wraps and claim answers gain no new keys either; orch-f1 wording pin); the client then relists from
      the start (no `after`, `until` or `generation`), replaces its whole set for the workspace and stores the
      new `generation`. `generation` is **required** (400 `malformed` without it) whenever `until` is present,
      and with `direction: "all"` whenever `after` is present; otherwise optional, so `received`/`sending`
      clients written before A2 keep working; devices SHOULD send it on every list with `after` (Opus delta
      L2), because the counter check below alone misses a restore whose start-up pruning outran the gap.
      `generation` is an **unauthenticated hint**: a hostile relay can change or keep it at will (§14.4), so a
      client lets it reset only its list walk, never its chain heads, anti-rollback state, uploads or re-wraps.
    - **`until`**, the walk's bounded high-watermark. A request **without** `until` starts a walk: the relay
      reads `drop_counter.n` (the relay-wide position, which never goes back within one generation) in the
      same read snapshot as the page, returns it as `until`, and the page holds the visible entries with
      `after < n ≤ until`. Positions are assigned in the committing write transaction under the directory lock,
      so every `n ≤ until` is committed and in that snapshot. A request **with** `until` continues that walk:
      the entries with `after < n ≤ until`, the same `until` echoed. `after > until` is 400 `malformed`. An
      `after` or `until` **above the relay's current counter** cannot happen within one generation, so it
      answers 409 `generation_changed` as well, whether or not `generation` was sent (JUDGEMENT CALL, the
      P3-D31 `cursor_ahead` pattern): a second line of defence behind the start check above, for a restore
      it could not see (a whole-disk snapshot that rolled the state directory back with the database, or
      changes in the last ≤ 60 s before an unclean stop that a rollback then removed), as
      long as the client lists before the counter passes its stored position. `next` is the last entry's `n`, or null when no visible entry with `n` in (that `n`, `until`]
      remains; null ends the walk. `generation` and `until` are echoed on **every** page of a walk, the last
      page (`next` null) included, and a non-null `next` is always above the request's `after` and at most
      `until` (orch-f1 wording pin). After a complete walk the client stores **`(generation, until)`**, not the
      last entry's `n`, and its next walk starts with `after = until`. `until` reveals no more than an entry's
      `n` already does (R-D8).
    - **Concurrent changes.** An object that changes during a walk (a version, wrap, claim, retire, expiry
      sweep or start-up pruning) gets a new `n > until`: it leaves the walk's range and is in the next walk
      from `until`. So a walk ends (it never chases a moving object), lists no object twice, and misses only
      objects that changed during it, all of which are above `until`. Consequence for A1's full
      reconciliation: a client that infers "gone" from a full walk runs the follow-up walk from `until` at once
      and treats as gone only an object absent from both; an object that changed during both walks shows up in
      a later one, so a "gone" inference stays reversible (the client re-adds any object a later walk lists)
      and the host takes no irreversible action on absence alone.
    - **The A1 state field.** Every state change raises `n` (item 7), so a retire, an expiry sweep or a
      pruning during a walk lands above `until` and the next walk shows it. An `expired` state computed at read
      time may appear on an entry at `n ≤ until` before the sweep, and the sweep's later `n` shows it again
      (idempotent for the client). A tombstone that ends during a walk is simply absent (its deletion raises no
      `n`; the client drops it at `tombstone_until_ms`, item 7). `tombstone_until_ms`, `descriptor: null` and
      `wraps: []` on tombstones are unchanged.
    - **Bounds** as item 7: `limit` ≤ 64 (default 64), the 2 MiB byte cut with at least one entry, the 16 KiB
      request cap, the read slots and buckets. `all` costs no more per page than `received`; the walk is
      bounded by the workspace's rows at or below `until`.
    - **Check order:** the existing session (401), principal (403 for a `drop:` device), bucket, body (400
      `malformed`: fields and types, an unknown `direction`, a `generation` that is not 32 lower-case hex
      characters, `until` without `generation`, `all` with `after` but without `generation`, `after >
      until`) and workspace eligibility (403 `not_eligible`: not a `look` member, a device asking for `all`)
      checks, then the read slot; then, in the read snapshot, `generation` and `after`/`until` against the
      counter (409 `generation_changed`). The generation check follows authorization, though it reveals
      nothing that a page would not.
    - **Notice interplay (host rule, orch-52).** A `drop` notice value below the host's stored position (a
      tombstone that ended, item 7, or a relay restore that took the counter back) makes the host list
      incrementally with its stored `generation` at once; after a restore that answers 409
      `generation_changed` (a new `generation`, or `after` above the counter) and the host relists in full. The host also sends its `generation` on every incremental list.
    - **Client guidance (orch-f1's phone, 15 Oct; normative for the phone, advice for other device clients).**
      The phone lists in full walks only. It pins `generation` and `until` from page 1 and sends both on pages
      2 and later, and drops the walk if either changes. A 409 `generation_changed` restarts the walk at most
      twice per refresh; after that the list shows as "outdated" and nothing is purged. The phone purges
      local entries only after a complete walk of both directions (`received` and `sending`) finished under
      the same `generation`. A missing object purges only the local cache; a reappearing object is
      re-verified (signature, chain, anti-rollback) like a new one. A `generation` change resets only the list
      walk (chain heads, anti-rollback state, pending uploads and re-wraps are unchanged: the field is an
      unauthenticated hint). Confirmed uploads lost in a relay restore are never re-sent automatically.
    - **Rollout (Opus delta L2).** D39a1's list parser is strict and refuses `generation` and `until` in a
      request (400 `malformed`), so clients send them only to a relay running D39a2. That holds now because
      Drop is off by default until D39a2 (§14.9 deploy gate); a client that meets a 400 for these fields
      falls back to a walk without them. The response fields are new keys that the phone's parser accepts
      from D39a2 on (Q-F11).
    - **Example** (W session, values shortened):

      ```json
      {"workspace_id": "5a1e…", "direction": "all", "after": 4100, "generation": "3f9a0c…"}
      {"objects": [{"n": 4182, "object_id": "9f2c…", "version": 3, "state": "live", "…": "…"}],
       "next": 4182, "generation": "3f9a0c…", "until": 4231}
      {"workspace_id": "5a1e…", "direction": "all", "after": 4182, "until": 4231, "generation": "3f9a0c…"}
      {"objects": [{"n": 4190, "object_id": "c07d…", "version": 1, "state": "retired", "…": "…"}],
       "next": null, "generation": "3f9a0c…", "until": 4231}
      ```

      The host stores `("3f9a0c…", 4231)`. After a database restore its next list answers 409
      `{"error": "generation_changed"}`, and it relists from the start.
    - **Pinned by** (D39a2): `generation` in every page for both session kinds; stable across a restart,
      regenerated at start when the meta row is missing, when `drop-hwm.json` is missing or names another
      `generation`, and when its `n` is above the counter; dev-deploy-plan step B (a moved data directory and an
      empty new one) and a §6.2 `cp -a` rollback each regenerating (the state directory untouched); the
      high-water `n` written within 60 s of a commit and at shutdown, always a committed value; Drop refused at
      start with `ORCH_RELAY_STATE` unset, missing, unwritable, equal to or inside `ORCH_RELAY_DATA` (after
      `realpath`), or locked by another process, and when the start write fails; a second `serve` on the same
      state directory **after** the first's start write (and so after a `rename` of `drop-hwm.json`) still
      finds `drop-hwm.lock` held and fails its check after the 30 s retry, while the first keeps serving;
      with Drop on and `drop_counter.n = 0`, a failed check still serves no Drop route; non-Drop routes
      served after any failed check; a failing periodic write
      (read-only state directory) logged at ERROR and retried while commits go on; no sweep assigning `n`
      while the state check failed and `drop_counter.n > 0`, also with Drop off; the check and writer running
      with Drop off when `ORCH_RELAY_STATE` is set; the check before the start-up sweep (a backup
      restored without `data/drop/` whose pruning renumbers past the host's stored position still answers
      the host's next list 409); a backup copy without the `drop_generation` row (D40c's backup test); a row
      deleted while running changes nothing until the next start; 409
      `generation_changed` for a stale `generation` on an `after` list and on a continued walk; 400 for
      `until` without `generation`, `all` with `after` without it, and `after > until`; 409 for `after` or
      `until` above the counter with the current `generation` (a restore the start check could not see); 403 `not_eligible` for a device asking for `all`; `all` returning both authors' objects in every
      state; a walk under concurrent writes (a version, a retire and an expiry sweep committed between pages:
      none listed above `until`, each in the follow-up walk, no entry twice, `next` null at `until`); a walk
      cut by bytes and by count at the same `until`; the stored `(generation, until)` incremental walk; a
      tombstone ending mid-walk; a device's `received` without another author's unclaimed inbox object, with it
      once claimed, and the author's own unclaimed upload in its `sending` (item 6). Fixture cases in
      `drop_list.json` (§14.6) and a `drop.relay_list_walk` vector.

**Pinned by (D39a1, D39a2, D39b).** HTTP fixtures (§14.6), the `drop` vector sections, and tests for: every
refusal in the check order with nothing stored; a stale host `PUT` fenced before any slot; the drain bounds
(no drain before a slot, 5 s idle and 30 s total, the drain pool, the upload slot freed at the answer); inbox
wraps (`wk` refused on an inbox, no `wxk` returned to a device); the read answer order (404, 403, 410, 404); the
read slot held until the body is sent and the per-person read cap; per-device shares; the tombstone check before the exact retry; the exact retry
before the CAS; the `Content-Length` frame check; the descriptor and `meta` caps; foreign `wxk` and `recipients`
refused; two concurrent writers of version N+1 (one 201, one 409, one blob file on disk); a killed upload
mid-blob (no row, the temp file swept, the reservation released); a crash after the rename (orphan swept at
start-up, no row without its file); quota reservation under concurrency; slot caps per device, person and
workspace and the minimum rate on both directions; the `stale_epoch` wrap after a rotation and the same-`DEK`
rewrap retry; expiry, tombstone and pruned-blob reads (410); retire of a document and of a file (amendment
A1: a file's usage rows, version count and per-device share back to their earlier values in the retire
transaction, its blob file unlinked after the commit, a crash between commit and unlink swept at start-up, a
member-authored file and a claimed and an unclaimed inbox file retired by the host, every read 410 at once, a
`PUT` of the id 410, idempotent 200 with the stored state for a retired and for an expired object, no new `n` on
the repeat, 403 for another space, 409 `fenced` before anything else, no device route; orch-52 changes 0, 1
and 3: 400 without `expect_version` or `expect_head`, 409 `version_conflict` with `current` and nothing
changed when a member's version 2 of a document committed after the host read version 1 and when the head
hash differs at the same version, the same retry against the tombstone 200, a retry with another head against
the tombstone 409, a reused id after the tombstone window 409 for the old head); the **takeover-versus-retire
race** (a retire admitted under generation `g`, a `host/hold` takeover committed before its write transaction:
409 `fenced`, the object live and its `n` unchanged; the reverse order: the retire commits and the new holder
sees the tombstone), and the same race for a host `PUT` (a takeover during the blob transfer: 409 `fenced` at
the commit, no row, the file unlinked), a claim, a re-wrap and a push send (nothing queued); list `state` per
entry (`live`, `pruned` after a restore without blob files, `expired` before and after the sweep, `retired`) with
`descriptor` null and `wraps` empty on tombstones, `tombstone_until_ms` null on live entries and `tombstone_ms
+ 30 d` on tombstones (`expires_ms + 30 d` for an expiry, unchanged by the sweep), `n` and the host `drop`
notice raised by the retire, the expiry sweep and the start-up pruning so an `after` list sees each, a
tombstone hidden from a device outside a device-only audience (403 on its reads, 404 once the tombstone ends),
a tombstone gone from the list after 30 days without a new `n`; Opus delta R1–R3 and lows: a `PUT` by a member
device outside a device-only audience 403 for a live, an expired and a retired object and for a matching exact
retry, before any 410, `version_conflict` or file-version 400, while the author device (always in the audience)
gets its exact-retry 200; `audience` `'devices'` with every listed device removed or revoked still hidden from
the other members (rows untouched by removal and revocation); `recipients: []` 400; a new file expiring in under
60 s 400 and an exact retry 59 s before expiry 200; an expired device-only tombstone without audience rows after
the sweep (listed to the W session only), a retired one keeping them, the head-byte charges per scope (author
share while live, workspace only after a retire, released at the row's deletion); a retire whose row the
tombstone sweep deletes between pre-check and transaction 404; `expect_head` padded, 31 or 33 bytes and
non-canonical 400, `expect_version` `true` or `1.0` 400; byte-cut pages; wrap filtering per caller;
an unclaimed inbox listed with its descriptor for its author but a 403 blob, and hidden (no entry, 403 reads) from other member devices until the claim (amendment A2); 404 (not 403) for an absent version; list
positions moving on a new version, a wrap, a claim and a retire; revocation pruning device wraps; batched sweeps
and a failing row skipped; a restore without `data/drop/`; early answers with an unread body over a real socket
and through Caddy (item 2); peak RSS of 16 concurrent 26 MiB uploads plus 8 concurrent maximal descriptor pages
(a bench, as P3-D33's); amendment A2: the decide-class upload and list-walk tests of items 13 and 14.

### 14.3 P3-D40: push registration and APNs sending

**P3-D40 (push at the relay).** Protocol §19.10 states the observable rules. The decision record:

1. **Registration** (`POST /v2/push/register`, D(m)): `{workspace_id, registration_id, env, topic, token}` →
   `{registration_id, registered: true}`, the host-api v0 shape. `env` is `sandbox` or `production` (`demo`
   never reaches a real relay: 400 `malformed`); `topic` MUST equal the configured topic (the app's bundle ID,
   `io.severin.orch`), else 400 `malformed`; `token` is b64u of 32 to 100 bytes (Apple's tokens are 32 bytes
   today and may grow). One registration per `(device, workspace, env, topic)`: a new `registration_id` for the
   tuple retires the old one in the same transaction. The same id and body is 200 and refreshes `last_seen_ms`
   (free of rate windows, as exact retries are in P3-D5); the same id with another body, or an id that belongs
   to another device, is 409 `registration_conflict` (new code; the id lookup matches `device_id` too, so device
   B replaying A's exact body cannot refresh A's row, Opus L2). A `drop:` scoped device is 403 `not_eligible`.
   An `env` without a configured key on this relay is 400 `malformed`. A token held by **another device of the same person** moves: that
   device's registrations with this token are deleted (a phone reset gives new device keys but keeps its token;
   without the move the old identity's pushes would reach the new one as generic text). Another person's
   registrations of the same token are not touched (JUDGEMENT CALL: a token is secret to Apple, the app and the
   relay, and a move across persons would let anyone holding a token cancel a victim's pushes).
2. **Unregister** (`POST /v2/push/unregister`, D, membership not required, so a removed but not revoked device
   can clean up after Leave): `{workspace_id, registration_id}` (an id, or `null` for every registration of the
   device in that workspace) → `{registration_id, registered: false}`, idempotent, also for an absent id. Another
   device's id is 403 `not_for_this_device`.
3. **Lifecycle.** A registration ends on unregister; on device revocation and on removal from the workspace's list
   (`prune_device` already deletes from a table named `push_subscriptions` when it exists, by `device_id` and
   `workspace_id`: the new table takes that name and those columns); on an APNs `410 Unregistered` (rows with that
   token whose `last_seen_ms` is not after Apple's timestamp), `400 BadDeviceToken` (that token in that `env`) or
   `400 DeviceTokenNotForTopic`; when the certificate expires (skipped at send, deleted by the daily sweep); and
   when not refreshed for 60 days (the app re-registers at every launch with the same body, which is free).
4. **The host's send route** (`POST /v2/workspaces/{ws}/push`, W(g), **fenced** like every W write: a missing or
   stale `Orch-Holder` or an expired lease is 409 `fenced`, P3-D10, and nothing is queued; orch-52 nit 7). Auth
   and the fence are checked **before** any bucket, dedup-LRU or queue effect, so a stale holder cannot spend the
   live holder's budget or poison the LRU (Opus N4); retire, re-wrap and claim follow the same rule. The fence
   is checked **again at the effect** (amendment A1, orch-52 change 0): just before the all-or-nothing queue
   admission the route re-reads the live `holders` row under the directory lock that `host/hold` takes (a read,
   no write transaction; the queue is in memory). That lock is a `threading.RLock` the sweeps hold for whole
   batches, so the re-check and the enqueue run in the worker threadpool, never on the event loop (Opus delta
   L1), so a takeover between admission and enqueue queues nothing
   and answers 409 `fenced`, as the fenced Drop writes do inside their transactions (P3-D39 item 1):
   `{targets: [device_id], outer: {v, ws, epoch, c}, priority: "high" | "normal", ttl_s}` → `{accepted}`.
   - `outer` is §9's outer object, sealed under `K_push(e)` with the `WSK` signature inside; the relay checks only
     its exact field set, `v = 2`, `ws` = the path, `c` canonical b64u, `|cj(outer)| ≤ 3,072` (else 400
     `malformed`), and `epoch` = the workspace's current list epoch (else 409 `stale_epoch` with `epoch`: the host
     never seals under an old epoch after its gate, §7.2).
   - `targets`: 1 to 1 024 sorted unique device ids. Each target that is a current member with an unrevoked,
     unexpired certificate is accepted; others are skipped without an error (a removal race is normal). The host
     MUST target only devices that may see what the label says (a restricted ticket's question goes only to its
     viewers, P8): the relay cannot tell. `accepted` is the number of accepted targets, **not** the number of
     registrations, so a host does not learn which of its devices have push on.
   - `priority` maps to `apns-priority` 10 or 5; `ttl_s` (0..86,400) to `apns-expiration`: 0 is APNs' "once,
     then drop", otherwise `now_s + ttl_s`. The NSE drops anything older than 24 h anyway (§9 step 6).
   - **Idempotency.** The relay remembers `(ws, H(cj(outer)), device)` for 24 h in memory (an LRU of at most
     65,536 entries keyed by a 32-byte digest of the triple in a bounded `OrderedDict`; ~20–30 MB with CPython
     object overhead, Opus L6): an exact retry sends nothing to a device that already got it. A restart forgets,
     so a retry right after a restart can duplicate, which the NSE drops as a replay and shows as generic text
     (A12). The host MUST persist the outer bytes before sending and resend them unchanged (never reseal: a new
     `c` is a new push).
   - Body cap 64 KiB (1 024 × 35 + 3,072 + framing).
5. **APNs request**, one per accepted target's registration, over HTTP/2 to `api.push.apple.com` (production) or
   `api.sandbox.push.apple.com` (sandbox), `POST /3/device/<hex token>`:
   - headers `authorization: bearer <JWT>`, `apns-topic: <topic>`, `apns-push-type: alert`,
     `apns-priority`, `apns-expiration`; **no `apns-collapse-id`** (the id is sealed; mobile D-4: the NSE replaces
     by `(ws, id)` locally) and no `apns-id` from the host;
   - body, exactly `{"aps":{"alert":{"title":"orch","body":"New activity in orch"},"mutable-content":1},"o":cj(outer)}`
     with `o` a JSON **string** holding `cj(outer)` (the NSE reads `userInfo["o"]` as a string). No `badge`, `sound`,
     `thread-id`, `category` or other key: the visible fallback is the relay's constant generic text, the same
     words the NSE shows on any drop (A12), so a relay never carries content in clear. Size: `cj(outer)` ≤ 3,072
     plus 12 escaped quotes plus 91 bytes of wrapper = at most 3,175 bytes, under APNs' 4,096 (921 bytes spare);
   - the JWT is ES256 with header `{alg: "ES256", kid: <key id mapped to that env>}` and claims
     `{iss: <team id>, iat}`, signed with the key mapped to the registration's `env` (§14.7: a per-environment
     mapping; today both environments map to the one key `TD27F9Z9V7`), cached **per key** (a provider JWT does
     not bind the environment, so one key mapped to both gateways uses one JWT; Opus L-g) and renewed every 40 minutes (Apple refuses tokens older than an hour and
     throttles renewals more often than every 20 minutes).
6. **Sender.** An in-memory queue per instance (JUDGEMENT CALL: best effort, no durable outbox): at most 4 096
   queued sends (each ≤ ~3.3 KB, ≤ ~13.5 MB), 1 024 per workspace and 2 048 per owner account (so one account's
   workspaces cannot fill the queue; Opus L6); a send request whose sends do not all fit is 503 `overloaded` with
   `Retry-After` and queues nothing (the host retries after `Retry-After`; never a permanent failure). One HTTP/2 connection per enabled `env`, at most 16
   concurrent streams; a send waiting longer than `min(ttl_s, 600 s)` is dropped. APNs answers:

   | APNs answer | Relay action |
   |---|---|
   | 200 | done |
   | 410 `Unregistered` | delete the registrations with that token whose `last_seen_ms` ≤ Apple's timestamp |
   | 400 `BadDeviceToken`, `DeviceTokenNotForTopic` | delete that registration |
   | 403 `ExpiredProviderToken`, `InvalidProviderToken` | renew the JWT once and retry once; then log `apns_auth` (no token, no key material) and pause that `env` for a backoff of at least 20 minutes (Apple's renewal floor), doubling up to 2 h, then renew and retry (Opus L3: a transient 403 never disables push until a restart) |
   | 400 `TopicDisallowed`, `BadTopic` | configuration error: log, pause that `env` with the same backoff |
   | 429 `TooManyRequests` (per device) | drop the send |
   | 413 `PayloadTooLarge` | a relay bug: log and drop |
   | 500, 503, connection errors | retry at most twice with backoff while within the send's deadline |

   Logs carry the registration id's first 8 hex digits and the reason, never a token, payload, JWT or key byte.
7. **Abuse bounds** (in-memory buckets, P3-D35 form; overrides `ORCH_RELAY_THROTTLE_PUSH_*`):
   - per (workspace, target device): burst 20, refill 2/min (120/h): an agent asking 30 questions in a minute
     notifies 20; the rest are skipped for that device (still `accepted`; the phone reconciles on open);
   - per target device across all workspaces: burst 60, refill 6/min (a person in many workspaces);
   - per workspace send requests: burst 120, refill 20/min (429 `rate_limited` for the request);
   - global: at most 50 APNs sends per second per instance (the queue absorbs bursts; then 503);
   - registrations: per device 30 state-changing registrations per hour (429 `rate_limited`), at most 2 per
     (device, workspace) by construction and 128 per device in all (429 `quota_exceeded`).
   The budgets **ignore `priority`**: a `high` and a `normal` push cost the same, and over budget either is
   skipped. Hosts merge repeated pushes per ticket and keep their own, stricter budget (orch-52 Q-H2, H13a).
   A WSK holder can therefore notify its own members at most ~2/min per device in steady state; a member device
   cannot send at all (no route for a D session); nobody can target a non-member.
8. **Token privacy at rest (JUDGEMENT CALL).** The relay must hold tokens in clear to send, but its database is
   backed up and copied. It stores `token_sealed = AES-256-GCM(K_tok, nonce(12, random), token, aad =
   "orch-relay/push-token|" || registration_id)` and `token_mac = HMAC-SHA-256(K_mac, token)` (for the
   same-person move and the 410 deletion), with `K_tok`, `K_mac` derived by HKDF from a 32-byte instance secret
   `push-token.key` held like the APNs key (§14.7) and never backed up with the database. A database dump alone
   then reveals no token; losing the secret loses the registrations only (delete them; apps re-register at their
   next launch).
9. **Disabled push.** A relay without APNs configuration (team id, topic, token secret, and at least one
   environment's key id and key file) answers 404 `not_found` on all three push routes, as a relay without
   a route does (the H12d convention); the phone treats that as "push unavailable on this relay". The relay
   refuses to start when the configuration is partial (an environment with a key id but no key, or the reverse;
   a key without the token secret), so a misconfiguration is loud. An environment that is not configured is
   400 `malformed` at registration (item 1).

**Pinned by (D40a, D40b).** HTTP fixtures (§14.6), and tests for: registration idempotency, retirement per tuple,
conflict, another device's id (409), a `drop:` device refused, same-person move, cross-person non-move;
unregister of null, absent and another device's id; pruning on revocation and removal; the stale sweep; the send
route's checks and `accepted` count; 409 `stale_epoch`; the exact-retry LRU; queue admission all-or-nothing and
the per-account queue cap; every row of the APNs table against a fake APNs transport (a scripted HTTP/2-shaped
fake that verifies the JWT under the public half of the key mapped to that environment, the path, the headers and the exact
body bytes), including the 403 backoff and its recovery; one JWT cache per key, shared by both environments
when one key is mapped to both; token sealing (no token bytes in the database file, a grep test); no token, JWT or key in logs (a log-capture test); refusal to start on partial
configuration.

### 14.4 Threat model delta

**Hostile relay (or one with a stolen database).** It can withhold, delay or reorder Drop versions and pushes;
serve an older version as the newest (readers persist the highest version and head hash and refuse a lower one,
§10.6); refuse uploads; send generic notifications to any registered token (the NSE shows generic text for every
dropped payload, A12, and cannot suppress a notification); link a phone's workspaces through its token (it can
already through the device id, R4); see sizes, timing, recipients and claims. It **cannot** forge or alter a
version (the author's signature over `content_hash`, `dek_commit` and `parent_hash`), substitute a blob or a wrap
(hash and commitment), fork a document unnoticed (the chain), read content or labels, forge a push (the `WSK`
signature inside `K_push`), or replay a push as new (the NSE's per-`(ws, id)` `ts_ms` rule and 24 h window; a
replay shows generic text at most). It cannot tell a host which devices have push on beyond what it already
knows from its own tables.

**Hostile host (a `WSK` holder).** It can notify its own members within the budgets, with any label it signs
(it is the workspace authority), upload within its account's quota, claim its own workspace's inbox objects,
re-wrap objects of its own space, and retire any file or document in its own space, including a member's
upload before the others have read it (amendment A1; it is the workspace authority, R-D9). It cannot target a non-member, learn a device's
token or whether it registered, read or address another workspace's objects (P4 has no cross-workspace
addressing), or exceed its account's stored bytes (1 GiB) or its per-device notification budget.

**Stale host process (after a takeover; amendment A1, orch-52 changes 0 and 1).** An old host process that
still holds a generation's session cannot write once a takeover has committed: the fence is re-checked inside
every fenced Drop write transaction and at the push queue admission (P3-D39 item 1), so a retire, `PUT`,
claim, re-wrap or push admitted before the takeover and reaching its effect after it is 409 `fenced` with
nothing changed. A retire also cannot take along a version committed after the host's decision (the
`expect_version`/`expect_head` precondition, item 5), and after the tombstone window a lost retire is not
replayed but reconciled (item 5).

**Hostile member device with `operate` (a laptop or another `operate` device, stolen or compromised; a phone
never holds `operate`, so a stolen phone is the decide-only case below, Opus delta L3).** It can upload within its 256 MiB share
and the workspace caps, and write the next version of a document of its workspace (the model: documents are
collaborative; readers apply the author rule). It cannot delete anything: P4 has no device delete or retire
route, not even for its own uploads (deletes are host-mediated: the device asks its host, which decides;
amendment A1), so it cannot destroy a document's history or another member's file (documents carry no expiry in
P4 and only the host retires), address other workspaces (M1), hold more than 3 upload slots for its
person, or force a large read (descriptors ≤ 96 KiB, byte-cut pages, bounded read slots; Opus H1). It cannot
send pushes, read other workspaces' objects, see other members' device wraps (filtered), or register a token for
a workspace it is not a member of. Outside a restricted (device-only) audience it gets no entry, descriptor,
wrap or blob, but if it knows an object's id it learns that the object exists and, later, that it is gone (the
403/404 existence oracle, P3-D39 item 6, R-D10); inside such an audience it can write a document's next
version with a wider audience (item 4; restricted content should be files). It can register a
victim's token if it learns it (it cannot from the relay); the victim then receives generic text for this
device's workspaces, bounded by P3-D40 item 7's budgets.

**Hostile decide-only device (a compromised or stolen phone, D49; amendment A2, revision 2).** Without
`operate` it can write only new `inbox` files (P3-D39 item 13). It cannot write a document, a second version, a
`space`-addressed or device-only object, re-wrap, claim or retire. Its bounds:
- **stored and hashed bytes**: the decide-class budget, 50 files and 64 MiB per workspace per UTC day, charged
  at admission and kept for failed and aborted streams, inside its device shares (256 MiB stored, 8 MiB head);
- **slots**: one decide-class upload slot (so at most 1 of a workspace's 4) and at most 2 drains;
- **network ingress**: only the upload bucket (32 MiB/min ≈ 45 GiB a day per device, 128 MiB/min per
  workspace), mostly drained and discarded once the budget is spent: the same capacity an `operate` device
  had before A2, accepted until the device is revoked (R-D12).
**Visibility (orch-f1 (d)1).** Before a claim its uploads are visible only to the host (the W session) and to
itself: other member devices get no list entry and no descriptor, so its spam reaches only the host's inbox
and leaks no routing metadata to the other members (this replaces A1's rule that members list unclaimed inbox
items; Opus delta L4 is moot for unclaimed items). The step-5 refusal for any other shape depends only on the
request and the caller's scopes, so it adds no existence oracle (P3-D39 item 13).
**Release through the host's own-claim rule (Opus delta R2; orch-52 Q-H9, agreed).** A stolen phone's uploads
are its owner's **own** uploads, so the host claims them **without a gesture**, which adds the `wk` wrap and
makes them readable, attributed to the victim, by every member. The host rule contains only what it can: a
gestureless claim requires the inbox object's verified author device to be a **current member device of the
person the claim is for** (decide present, not revoked) at claim time, re-checked under the host's store lock
in the same step as the claim, and the claim to be for that person's own device-authored upload; releasing
another person's upload, or one whose author device has since been revoked or removed, needs a terminal
hand-off. In a workspace with several people, any member's own phone upload is thus released to every member
without a gesture (Opus delta 2, L-1). The host records every gestureless own-claim (item, device,
`claimed_ms`) and shows it under "Shared from your phone" on the dashboard and in `orch status` until
`claimed_ms + 7 d`, also after the file is gone (host-side, Q-H9), and retiring one's own upload is a single
unsigned action. **Revoking the phone before the claim blocks the release**, but the host claims within its
poll or notice latency, so in practice the block helps only for uploads the host has not yet processed (for
example while the host was offline; Opus delta 2, L-2); anything released before is visible and removable at
once (what members already downloaded stays read, spec §6.4). No activity window is added: a
stolen unlocked phone can already answer questions with `decide`, so the upload risk is comparable to what
`decide` already allows, bounded by the budget (residual R-D13).

**List walks (amendment A2).** `direction: "all"` is W-only (a device gets 403), so it widens nothing for
devices. `generation` and `until` tell a caller only that the Drop dataset was replaced and the relay-wide
position, which every entry's `n` already shows (R-D8). `generation` is unauthenticated: a hostile relay
could keep it across a restore and serve positions that go back, or change it to force full relists
(availability only, bounded by item 7's pages); it can already withhold changes (above), so this adds nothing
to that model, and clients let it reset only their list walk (P3-D39 item 14). An honest relay detects a
restore structurally (a high-water file in a state directory outside the data directory; backup copies carry
no `generation`),
before its start-up pruning can move the counter past a client's position (R-D11).

**Revoked or removed device.** Its registrations and device wraps are deleted in the revocation or publication
transaction; it gets no session. What it downloaded before stays readable to it (a claim or revocation does not
take back what was read; spec §6.4).

**Stolen APNs key.** The thief can send arbitrary visible notifications, including ones **without**
`mutable-content` that skip the NSE (gaps.md row 19), to any token it knows. Tokens come only from the relay's
database, where they are sealed (D40 item 8), so the key alone is not enough. Response: revoke the key in the
Apple developer account (immediate), place the replacement (§14.7), restart. The app treats every notification's
`userInfo` as a lookup key, never an instruction, and re-verifies on tap (NSE comment; U10). The existing key is
team-scoped (owner's note), so a stolen copy also reaches the owner's other apps' tokens, if the thief has them;
a later replacement by topic-specific, per-environment keys (§14.7) would narrow this (owner question 2).

**Apple (APNs).** Sees each token, the topic, timing, priority, the outer object (a random workspace id, an
epoch and ciphertext) and the generic text. It cannot read labels, but it can read their length (R-D6). New accepted leak: the workspace id and epoch
reach Apple (the NSE needs `ws` to pick keys without trial decryption).

**Network attacker.** TLS to the relay and to APNs; the upload frame adds nothing new. A slow uploader or
downloader holds a slot: the per-device, per-person and per-workspace slot caps of P3-D39 item 8, plus an idle
timeout of 30 s, a minimum average rate of 64 KiB/s and a 10-minute maximum in both directions (else the relay
closes and frees the slot and the reservation). Caddy's per-IP limits (§10 checklist 7) remain the bound on
unauthenticated floods.

**Residuals.**

- R-D1. Generic-text spam to a registered phone by a hostile relay or the holder of the APNs key and the tokens:
  unavoidable on iOS (the NSE cannot suppress), bounded only by the operator's honesty.
- R-D2. Push is best effort: a restart loses queued sends and the dedup memory (a duplicate shows generic text).
- R-D3. Global Drop ceiling saturation (4 GiB) by the invited accounts together denies uploads until files
  expire (≤ 7 days), as the staging ceiling did before P3-D34; the per-account cap (1 GiB) bounds one account
  (the numbers against ~10 invited accounts are owner question 4).
- R-D4. The relay learns recipients, sizes and claim outcomes, as spec §4 accepts.
- R-D5. Old document blobs are pruned (item 5): a reader that never downloaded version 3 cannot get it later;
  the chain stays verifiable. A host retire removes a file or a document for everyone. After its 30-day tombstone an id
  can be reused as version 1, for files and retired documents alike; a reader that persisted its highest version
  sees that as a rollback error (Opus L-i).
- R-D6. §9 has no padding, so the push ciphertext's length reveals the label's length to the byte, and often the
  kind (`drop.new`, `question` and `question.closed` differ), to the relay and to Apple; the target set shows the
  relay which devices a push is for, and in P8 which devices see a restricted ticket (Opus L11, orch-52 Q-H4).
  A padding field would be a sealed-format change, out of scope here. *Recommended host mitigation* (no format
  change): the host pads the **label** to a fixed 80 code points with spaces that the NSE trims; until then the
  length leak is accepted.
- R-D7. While a revocation's `rotation_due` is open, uploads land under the `WK_e` the revoked device holds
  (P3-D39 item 4); only a hostile relay could serve them to it. Closed if the owner adopts the
  `rotation_required` refusal (owner question 6).
- R-D8. The relay-wide change position `n` tells a host roughly how much Drop activity other tenants have
  (Opus L7). Accepted for P4; per-workspace positions would remove it.
- R-D9. The host can retire any object of its workspace, so a member's upload can vanish before other members
  read it, and a member cannot remove its own upload without the host (amendment A1). Accepted: the host is the
  workspace authority, and a hostile host could already withhold its `wk` wrap or never claim an inbox item.
  A tombstone tells the devices that saw the object whether it expired or was retired.
- R-D10. Relay membership and `recipients` are not ticket authorization (amendment A1, orch-52 change 4). The
  relay does not know which ticket an object belongs to or who may see it; it enforces membership and the
  newest version's device-only `recipients` list, which the host chooses (P3-D39 item 4). Restricted tickets
  therefore rest on the host: `device` wraps and `recipients` only for the allowed devices, no `wk` wrap, and
  its own listings and bridge answers filtered by ticket visibility. Residual at the relay: the 403/404
  existence oracle (P3-D39 item 6: a member outside the audience that knows an id learns that the object
  exists and when it is gone, never its content, metadata, state, version, kind or claim, on reads or on a
  `PUT`, P3-D39 step 6), and a member inside a restricted document's
  audience can widen the next version's audience (files avoid it). Accepted for P4; a relay-side ticket
  audience would need the relay to learn ticket ids, which spec §4 avoids.
- R-D11. The `generation` is regenerated at start whenever the database's counter is below the high-water `n`
  kept in a state directory outside the data directory, or the file is missing or names another
  `generation`, or the row is missing (backup copies drop it), all checked before the start-up sweep (P3-D39
  item 14; Opus delta R4, delta 2 RA). That covers dev-deploy-plan step B, its §6.2 rollback and the reset
  tool (`mv` and `cp -a` of the whole data directory; the reset tool wipes it in place), and any restore of a
  backup copy. What remains: (a) a
  whole-disk snapshot restore that rolls the state directory back with the database; (b) changes committed
  in the last ≤ 60 s before an unclean stop (not yet in the high-water file) that a rollback then removes.
  In both, a client whose stored position is above the counter gets 409 `generation_changed` on its next list
  (the host's notice rule makes it list at once) unless the start-up pruning or new writes carry the counter
  past that position first; then the changes in between are missed until its next full relist (at most 29
  days apart, item 7). Until D40c ships (state directory, backup step), Drop stays off (§14.9 deploy gate).
- R-D12. Network ingress of a decide-only device is bounded by the upload bucket (32 MiB/min ≈ 45 GiB a day),
  not by the decide-class budget, which bounds only the bytes read into blob files (P3-D39 item 13). Drained
  bytes are discarded without hashing or storing. Accepted as an availability residual until the device is
  revoked, as it was for `operate` devices before A2.
- R-D13. A stolen **unlocked** phone can push content within the decide-class budget until it is revoked;
  the host claims it without a gesture (it is its owner's own upload), which makes it readable to every
  member; each such claim is visible ("Shared from your phone", `orch status`) and removable at once, and a
  revocation before the claim blocks it, which in practice helps only for uploads the host has not yet
  processed, since the host claims within its poll latency (orch-52 Q-H9).

**D39a2 part 1, Opus review round 2 (15 Oct 2026).** A device's workspace upload bucket is charged inside step 5 as soon as
the device is eligible to write to the workspace (not earlier: a device must not drain a workspace it may not write
to), so steps 6 to 9 refusals, the creations 429, the exact-retry 200 and part 2's budget 429 all spend it (R-D12's
per-workspace bound holds), never refunded; ineligible and unauthenticated requests stay cheap under their own
throttles. The reservation is released when the commit returns, before the answer is sent. With Drop on, the relay
refuses to start when a Drop bucket's burst is below the tokens of a maximal body (it names the env var and the
numbers); an upload whose cost exceeds a burst anyway is 413 `too_large`, a download's cost is clamped to the burst. The
creations 429's `Retry-After` and the charged day both come from the request's `now`. `drop_objects.object_id` is
immutable (a trigger: `UPDATE OR REPLACE` could otherwise reset `claimed_ms`). The global-cap variables are parsed only
with Drop on. Runbook: once 0019 is applied, rolling the code back to a pre-D39a2 build breaks the Drop `PUT` (its
positional insert has 15 values for 16 columns) when Drop is on; with Drop off nothing breaks.

**D39a2 part 1 decisions (owner, via orch-d6, 15 Oct 2026).** When several caps apply at once, the refusal names
the author's own share first, then the workspace, the account and the global ceiling (503, no `quota` key). Admission
charges the head bytes gross (the audience rows a new document version releases are not netted off); the commit
charges them exactly. A device's workspace upload bucket is charged at step 5, once the device is eligible to write in the
workspace the head names (Opus R1: every later refusal, an exact retry and a creations 429 spend it; an ineligible
request does not), a W session's at admission. The daily version-1 creation counters answer 429 `rate_limited` with `quota: "drop_creations"` and
`Retry-After` to 00:00 UTC; their day rows are swept with the budget's (D39a2 part 2). `ORCH_RELAY_DROP_NOTICE` works
only with `ORCH_RELAY_DROP=1`. D39a2's `n`-assigning sweepers run only when `ORCH_RELAY_DROP=1` (the state-check gate
arrives with the list walks).

**D39a2 part 2 decisions (implementation, 16 Oct 2026; `drop_life.py`).** One sweep cycle every 600 s, only with
`ORCH_RELAY_DROP=1` (with Drop off no sweeper task exists, `Life.run` returns at once and the start-up sweep stops
after cleaning `tmp/`, so nothing assigns a position; PR 4 puts the state-check gate in front of the same entry
points). Phases, each in transactions of at most 4 096 deleted rows (versions, cascaded wraps, audience rows; one
object always completes): expiry (`expires_ms <= now`: `expired` tombstone with `tombstone_ms = expires_ms`, a
file's version, wraps and usage released, audience rows deleted, new `n`), release of a retired document's versions,
end of tombstones (`tombstone_ms + 30 d <= now` and no version left; no `n`; a retired device-only tombstone's
audience rows give back their workspace and global head bytes), document blob pruning (version `<= current - 8`
and `received_ms + 30 d <= now`; no `n`), `device` wraps of devices that are no longer members of the object's
workspace or have a revocation (head bytes released from the workspace, global and the version author's share),
and the two daily tables (rows older than the previous UTC day: the previous day stays for a slow upload that
began before midnight). A failing object is rolled back to its savepoint, logged and skipped for the cycle. Retire
is as the amendment A1 text above; the retire of a document counts it out at once (the creator's document share
too) and leaves its versions to the sweeper. `rotation_required` is adopted: a `wk` wrap is refused with 409 and the
current epoch while any `rotation_due` row of the workspace exists (after `stale_epoch`, in the commit again); an
exact retry (step 7) and `wk`-less uploads are unaffected. N3: an error after the blob's rename removes the blob. A device counts as revoked only by its registered person's pair (`directory.revoked_sql`, P3-D30): a stranger's self-certified pair never removes its wraps (one helper for every access decision, pinned by a structural test). The sweeper loop logs and survives any exception; a cycle in which any object failed counts as failed (one summary line with the first traceback, the first at once, then at most one per 300 s). The structural guard over `revocations` is static: it scans the relay's SQL string literals and migrations against an exact allowlist, and does not see SQL assembled at run time. Notes: each sweep's candidate scan runs inside the global write lock (about 0.35 s for 300 000 device wraps; acceptable at P4 scale, drive it from `drop_wraps_target` if that changes); the sweeps use the wall clock like the reads; a device removed and re-added before the sweep ran gets its old device wraps back, after it they are gone (the host's MUST for re-added devices); the `rotation_required` body carries `epoch` on a Drop `PUT` only (the membership route's has none); PR 4's state check must land before Drop is switched on.

**D39a2 part 3 decisions (implementation, 16 Oct 2026; `drop.py`, `drop_quota.py`).** The decide-class authority is decided in step 5
from the request alone (`Drop.decide_shape`: `file`, `inbox`, version 1, `If-Match: 0`) and the live `members` row, before any object
state is read, and again in the commit's transaction (`eligibility` returns the class; the commit-time class wins). Step 2 admits a
device holding `operate` or `decide` anywhere; one holding `operate` nowhere takes the `("decide", device)` slot key at admission (cap 1),
one that is decide-only only for this workspace takes it at step 5 (429 `slot`, before the charge and any blob byte). The budget is
charged in step 9 after the workspace slot and immediately before the reservation, by `charge_budget` (the item 13 upsert in its own
write transaction under `Directory.lock`; the refused upsert names `drop_decide_creations` or `drop_decide_bytes` by reading the row,
`Retry-After` from the request's `now`); a lowered cap that a request cannot fit even on an empty day is refused before the insert
branch. The give-back runs in `finally`, shielded, in its own transaction (`give_back`, errors logged, never raised): a refusal at the
reservation or an exact retry that won the commit gives back the whole charge; every other end keeps one creation and the blob bytes the
stream read (`Body.blob_in`) and gives back the unread rest, so a stream that never delivered a byte still costs its creation. A
commit-time `operate` to `decide` change charges the budget by the same upsert inside the commit (429 `rate_limited` with nothing stored
and no charge). The visibility rule is one function (`Drop.visible`) for reads and `PUT`, and one SQL clause for the list, applied in the
`WHERE` before the page `LIMIT`. List entries carry `claimed_ms` and `expires_ms` from `drop_objects`.

### 14.5 Migration plan (0017, 0018, D39a2's)

Conventions as before: numbered `.sql` files run by `db.migrate`, integer ms of the relay clock, ids as lower-case
hex, signed objects stored as received `cj`. 0008 stays reserved.

**0017_drop.sql** (D39a1; D39b adds no table; its `claimed_ms` column is D39a2's, below):

```sql
CREATE TABLE drop_objects (
    object_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,            -- space_id (space_kind 'workspace' only in P4)
    owner_person_id TEXT NOT NULL,         -- the space's card owner: the account quota
    object_kind TEXT NOT NULL CHECK (object_kind IN ('file', 'document')),
    current INTEGER NOT NULL CHECK (current >= 1),
    inbox INTEGER NOT NULL CHECK (inbox IN (0, 1)),
    claimed_by TEXT,                        -- §10.5; NULL until claimed
    expires_ms INTEGER,                     -- the head's; NULL for a document without expiry
    tombstone_ms INTEGER,                   -- set when retired (now) or expired (= expires_ms); row deleted 30 d later
    tombstone_kind TEXT CHECK (tombstone_kind IN ('expired', 'retired')),  -- the list state (A1)
    head_author_id TEXT NOT NULL,           -- the newest version's author: `direction` without a descriptor (A1)
    head_hash TEXT NOT NULL,                -- the newest version's parent_hash_next: retire's expect_head, kept on the tombstone (A1)
    audience TEXT NOT NULL CHECK (audience IN ('space', 'inbox', 'devices')),  -- the newest version's recipients kind (A1, R2)
    n INTEGER NOT NULL,                     -- latest change position (version, wrap, claim, state change)
    created_ms INTEGER NOT NULL,
    CHECK ((tombstone_ms IS NULL) = (tombstone_kind IS NULL))
);
-- The device-only `recipients` list of the newest version (audience = 'devices'), one row per listed
-- device plus the newest version's device author (A1): the list, read and PUT step 6 filters use it
-- without parsing descriptors. Visibility is keyed on drop_objects.audience, never on whether rows
-- exist: 'devices' with no row for a device hides the object from it. Rows exist only for 'devices';
-- a new version's commit replaces them; membership removal and revocation never touch them; an expiry
-- tombstoning deletes them; a retired tombstone keeps them until the object row is deleted. Charged as
-- head bytes at 65 B each (P3-D39 item 8: workspace, global and, while live, the author device's share);
-- at most the workspace's member devices per object. The relay knows nothing of tickets.
CREATE TABLE drop_audience (
    object_id TEXT NOT NULL REFERENCES drop_objects(object_id) ON DELETE CASCADE,
    device_id TEXT NOT NULL,
    PRIMARY KEY (object_id, device_id)
);
-- The list scan: in P4 an object is visible only within its own workspace (P3-D39 item 4),
-- so no per-object access table is needed (Opus M1).
CREATE INDEX drop_objects_scan ON drop_objects(workspace_id, n);
CREATE INDEX drop_objects_expiry ON drop_objects(expires_ms)
    WHERE expires_ms IS NOT NULL AND tombstone_ms IS NULL;
CREATE INDEX drop_objects_tombstone ON drop_objects(tombstone_ms) WHERE tombstone_ms IS NOT NULL;

CREATE TABLE drop_versions (
    object_id TEXT NOT NULL REFERENCES drop_objects(object_id) ON DELETE CASCADE,
    version INTEGER NOT NULL CHECK (version >= 1),
    author_kind TEXT NOT NULL CHECK (author_kind IN ('device', 'workspace')),
    author_id TEXT NOT NULL,
    descriptor TEXT NOT NULL,               -- the signed drop_object, cj
    parent_hash_next TEXT NOT NULL,         -- b64u H("orch/v2/drop-parent|" || cj(o)): the next version's parent_hash
    content_hash TEXT NOT NULL,
    content_len INTEGER NOT NULL,
    head_len INTEGER NOT NULL,
    descriptor_len INTEGER NOT NULL,        -- bytes of descriptor: the page byte cut without parsing
    blob TEXT NOT NULL CHECK (blob IN ('stored', 'pruned')),
    blob_path TEXT,                         -- '<o>/<v>.<rand>' under drop/blobs; NULL once pruned
    received_ms INTEGER NOT NULL,
    PRIMARY KEY (object_id, version)
);
CREATE INDEX drop_versions_author ON drop_versions(author_id);

CREATE TABLE drop_wraps (
    object_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    target_kind TEXT NOT NULL CHECK (target_kind IN ('wk', 'wxk', 'device')),
    target_id TEXT NOT NULL,
    key_version INTEGER NOT NULL,
    record TEXT NOT NULL,                   -- the wrap record, cj
    PRIMARY KEY (object_id, version, target_kind, target_id, key_version),
    FOREIGN KEY (object_id, version) REFERENCES drop_versions(object_id, version) ON DELETE CASCADE
);
CREATE INDEX drop_wraps_target ON drop_wraps(target_kind, target_id);

-- Charged usage; scope 'workspace' | 'account' | 'device' (key "ws:device") | 'global' (id '').
-- Blob bytes and head bytes are separate quotas (Opus M4); head_bytes includes every stored wrap (L5).
CREATE TABLE drop_usage (
    scope TEXT NOT NULL,
    id TEXT NOT NULL,
    blob_bytes INTEGER NOT NULL CHECK (blob_bytes >= 0),
    head_bytes INTEGER NOT NULL CHECK (head_bytes >= 0),
    versions INTEGER NOT NULL CHECK (versions >= 0),       -- live versions (blob stored)
    documents INTEGER NOT NULL CHECK (documents >= 0),     -- documents not tombstoned
    PRIMARY KEY (scope, id)
);

-- Descriptors are immutable once stored (the 0016 audit-table pattern): no UPDATE of the signed
-- columns, and no REPLACE (which deletes without a DELETE trigger) over an existing version.
CREATE TRIGGER drop_versions_immutable
BEFORE UPDATE OF object_id, version, author_kind, author_id, descriptor, parent_hash_next,
                 content_hash, content_len, head_len, received_ms ON drop_versions
BEGIN SELECT RAISE(ABORT, 'drop_versions is immutable'); END;
CREATE TRIGGER drop_versions_no_replace
BEFORE INSERT ON drop_versions
WHEN EXISTS (SELECT 1 FROM drop_versions WHERE object_id = NEW.object_id AND version = NEW.version)
BEGIN SELECT RAISE(ABORT, 'drop_versions is immutable'); END;
```

Deletion happens in the sweeps, in batches bounded as P3-D39 item 12 says, and in a file's retire transaction
(one version and at most 1 024 wraps, within that bound; amendment A1): at tombstoning (expiry or retire) the
object's versions and wraps are deleted and their bytes released, keeping only the `drop_objects` row (with
`tombstone_kind`, `audience`, `current` and `head_hash`, uncharged; on a retired device-only tombstone also its
`drop_audience` rows, charged to the workspace; an expiry deletes them), which the sweeper deletes 30 days later,
releasing the audience rows' head bytes; every tombstoning assigns a new `n`; blob pruning sets `blob` → `'pruned'` and
`blob_path` → NULL (the only columns that may change). `wrap_conflict` and the claim's "delete every other wrap"
are ordinary deletes on `drop_wraps`. Files live in `<data>/drop/blobs/<o>/<v>.<rand>` and `<data>/drop/tmp/`,
directories 0700, files 0600, on the database's filesystem so `rename` is atomic; files are unlinked after the
batch commits. The start-up sweep (before serving) deletes `tmp/*`, blob files without a `stored` row, and marks
a `stored` row whose file is missing as `pruned` with an error log, releasing its blob bytes and, when that row
is the object's newest version, assigning the object a new `n` (its list `state` becomes `pruned`); this also
makes a database restored without `data/drop/` consistent.

**D39a2's migration (amendment A2; `0019_drop_a2.sql`, or the next free number when D39a2 lands; 0018 stays
D40a's).** `db.migrate` applies files by their version set, so the order in which D39a2 and D40a land does not
matter:

```sql
-- The decide-class budget (P3-D39 item 13): one row per (workspace, device, UTC day of the request's
-- `now`), charged at admission (step 9) by the upsert of P3-D39 item 13 (INSERT ... ON CONFLICT DO UPDATE
-- ... WHERE; changes() = 0 means refused) for uploads authorized by `decide` alone,
-- refunded only for a refusal before the first blob byte, reduced to the received bytes for a failed
-- stream; persisted so a restart does not refill it.
-- The periodic sweep deletes rows older than the previous day. D39a2 may keep its other daily
-- creation counters (item 8) in a table of the same shape.
CREATE TABLE drop_decide_budget (
    workspace_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    day INTEGER NOT NULL,                   -- floor(now_ms / 86400000)
    creations INTEGER NOT NULL CHECK (creations >= 0),
    bytes INTEGER NOT NULL CHECK (bytes >= 0),
    PRIMARY KEY (workspace_id, device_id, day)
);
```

The caps (50, 64 MiB) live in the upsert's `WHERE`, not in CHECKs, so they can be configured. The
list `generation` (P3-D39 item 14) needs no schema: it is the row `meta(key = 'drop_generation', value = 32
lower-case hex)` in 0001's `meta` table, written by the start check (before the start-up sweep) when it is
missing or when the high-water file shows a restore, and read once into memory. Outside the data directory:
`$ORCH_RELAY_STATE/drop-hwm.json` (`{generation, n}` with the committed counter, mode 0600, written atomically
with `fsync` at start, at most every 60 s while the counter changes and at shutdown), in
`/srv/orch-relay/state/` and `/srv/orch-relay-int/state/` (created by `provision.sh`, untouched by every
backup, restore, rollback and reset). The backup procedure (D40c, replacing dev-deploy-plan step B's `mv` and
§6.2's `cp -a` of the whole data directory, and the deploy-day runbook's step 2 and R2) deletes the `drop_generation` row in the **backup copy**, so no
backup carries it; its test restores a backup and a rollback and checks that the first start answers a stale
`generation` with 409. The claim time (P3-D39 item 7, amendment A2 revision 3):

```sql
ALTER TABLE drop_objects ADD COLUMN claimed_ms INTEGER;  -- set with claimed_by at the claim; NULL until then
CREATE TRIGGER drop_objects_claimed_ms_immutable
BEFORE UPDATE OF claimed_ms ON drop_objects
WHEN OLD.claimed_ms IS NOT NULL AND NEW.claimed_ms IS NOT OLD.claimed_ms
BEGIN SELECT RAISE(ABORT, 'claimed_ms is immutable'); END;
```

D39b's claim transaction sets `claimed_ms` with `claimed_by` (relay clock, the transaction's `now`); if D39b
lands before D39a2 it still adds no migration: **D39a2 alone owns the column and the trigger** (one owner, no
"duplicate column"), and D39b's claim sets `claimed_ms` only once the column exists (D39b and D39a2 merge
serialized, the later one rebased onto the earlier). Because of the new column, D39a2 changes D39a1's
positional `INSERT INTO drop_objects VALUES (...)` into an insert with **named columns**, and `drop_objects`
is never written by `INSERT OR REPLACE` or `REPLACE` (which would delete the row and reset `claimed_ms`
without firing the update trigger); D39a2 adds a `drop_objects_no_replace` trigger like `drop_versions`'s
(`BEFORE INSERT ... WHEN EXISTS (... object_id = NEW.object_id)`). It also forbids `INSERT ... ON CONFLICT` and
`INSERT OR IGNORE` on `drop_objects` (a future idempotent insert checks existence first; a duplicate insert
fails with the trigger's message, still an `IntegrityError`); the decide-class budget's upsert is on the
other table, `drop_decide_budget`, which has no such trigger (Opus delta 4, L-i). The
migration itself inserts nothing, so a database restored by any route regenerates the same way.
`drop_counter` (0017) is unchanged and remains the source of `n` and `until`.

**0018_push.sql** (D40a):

```sql
CREATE TABLE push_subscriptions (           -- the name prune_device already handles
    registration_id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    env TEXT NOT NULL CHECK (env IN ('sandbox', 'production')),
    topic TEXT NOT NULL,
    token_sealed BLOB NOT NULL,
    token_mac TEXT NOT NULL,
    body_digest TEXT NOT NULL,              -- sha256 of the canonical register body: exact-retry identity
    created_ms INTEGER NOT NULL,
    last_seen_ms INTEGER NOT NULL,
    UNIQUE (device_id, workspace_id, env, topic)
);
CREATE INDEX push_subscriptions_send ON push_subscriptions(workspace_id, device_id);
CREATE INDEX push_subscriptions_token ON push_subscriptions(token_mac);
CREATE INDEX push_subscriptions_stale ON push_subscriptions(last_seen_ms);
```

No audit table: registrations are not evidence. No push send is stored.

### 14.6 Fixtures and vectors

HTTP fixtures (`tests/http_fixtures/`, MANIFEST revision bumped, one file per route role as §19.6):
`drop_put.json` (201; 200 exact retry; 428 missing and malformed `If-Match`; 409 `version_conflict` with
`current`; 409 `stale_epoch`; 409 `bad_wxk_version`; 409 `fenced` for a stale host; 400 a `wk` wrap on an
inbox object; 429 for each per-device share (`quota` names it); 403 `not_eligible` for a `drop:` device, for another
space, for a claimed object and (amendment A1, Opus delta R1) for a member device outside a device-only audience,
live and tombstoned; 400 for `recipients: []` and for a new file expiring in under 60 s; an expired device-only
file's `PUT` by its author 410 before the sweep and 403 after it; 401 `bad_signature`; 400 bad frame, missing `Content-Length`, a `Content-Length`
that does not match the frame, short blob, wrong hash, a non-ORD2 blob header, a descriptor or `meta` over its
cap, a foreign `wxk` target or `recipients` id, a document with an expiry, an `inbox` document; 410 tombstoned
id, and a tombstoned id resent as an exact retry; 410 an expired `expires_ms`; 413 head and declared length; 429
`quota_exceeded`; 503 `overloaded`; amendment A2: 201 for a decide-only device's new inbox file, 403
`not_eligible` for its document, `space`-addressed file and version 2, 403 for its `If-Match: 0` on another
author's unclaimed inbox id, 429 `rate_limited` with `quota` `drop_decide_creations` and `drop_decide_bytes` and
`Retry-After` the seconds to 00:00 UTC, 429 `slot` for a second concurrent decide-class upload), with the frame given as hex; `drop_list.json` (positions, `direction`, wrap
filtering for a device and a W session, an unclaimed inbox listed for its author device and absent from another member device's `received` until the claim (amendment A2), `claimed_by` in every entry,
`next` and null at the end, ascending `n`, the byte cut, no `wxk` wrap returned to a device; amendment A2
revision 3: `claimed_ms` (null, then set; the "set" case needs D39b's claim and stays DEFERRED until D39b, or
uses direct database setup in D39a2) and `expires_ms` (a file's, null for a document, kept on a
tombstone) in every entry; amendment A2:
`generation` and `until` in every page, a two-page `all` walk of a W session ending at `until`, 409
`generation_changed` for a stale `generation` and for `after` above the counter, 400 for `until` without
`generation`, 403 `not_eligible` for a device asking for `all` with a body otherwise valid (no `after`, so the
missing `generation` cannot answer 400 first; Opus delta L5); amendment A1:
`object_id`, `version` and `state` in every entry, a `pruned` entry, an `expired` and a `retired` tombstone with
`descriptor` null and `wraps` empty, `tombstone_until_ms` null on live entries and set on tombstones, an
`after` list that sees a retire, a device outside a device-only audience without the tombstone);
`drop_descriptors.json` (the byte-cut page); `drop_descriptor_get.json` (with `ETag`; 404
for an absent version, 403 for a foreign object in any state, 410 before a version's 404; an expired device-only
file read by its audience device 410 before the sweep and 403 after it, by the W session 410 after it); `drop_wraps_get.json`; `drop_blob_get.json` (headers, 403 unclaimed inbox for its author, 403 for another member device, 410 pruned);
`drop_wraps_put.json`; `drop_claim.json` (won, idempotent, lost with `claimed_by`, not inbox; the following list entry's `claimed_ms`
unchanged by the idempotent retry, amendment A2);
`drop_retire.json` (200 `{state: "retired"}` for a document and for a file with a matching `expect_version`
and `expect_head`, idempotent 200 for a retired and for an expired object with the stored state, 409
`version_conflict` with `current` and `state` for a stale version and for a stale head (object untouched), 400
`malformed` without the precondition and for a non-canonical `expect_head`, 403 `not_eligible` for another space, 404, 409 `fenced`); `host_poll.json` (the `drop` notice);
`push_register.json` (200, idempotent refresh, 409 `registration_conflict` for another body and for another
device's id, 400 env/topic/token and an unconfigured env, 403 `not_eligible` and a `drop:` device, 404 when
disabled); `push_unregister.json`; `push_send.json` (200 `accepted`, skipped non-member, 409 `stale_epoch`, 400
oversized outer, 503 queue full); `apns_request.json` (the exact outbound request for a fixed outer, key id,
team id and `iat`, for each environment's mapping, with the JWT's signing input; the signature itself is not fixed because
ES256 is randomized).

Beyond fixtures, D39a1 adds the **real-socket** early-answer test and the **Caddy (HTTP/2)** end-to-end test of
P3-D39 item 2 (an early 409 and an early 200 with an unread 26 MiB body reach the client intact).

Vectors (`tests/vectors_v2.json`, relay-owned sections): `drop.upload_frame` (encodings, big-endian `head_len`,
a head at the cap, a blob one byte short and long); `drop.relay_put` (a chain of PUT steps against one state:
create with `If-Match: 0`, the next version, a stale writer, a fork attempt with another `parent_hash`, a
file's version 2, an exact retry after the head moved, a `wk` wrap at an old epoch and the same-`DEK` rewrap
that follows, "tombstoned then retry", "inbox document refused", and amendment A1's "retired file then
retry" and "retired file then version 1 under the same id", both 410); `drop.relay_retire` (amendment A1,
orch-52 changes 0, 1 and 3: steps against one state: a retire with the matching head, its retry (200, no new
`n`), a retire after a member's newer version (409 `version_conflict`, untouched), a retire whose generation
was taken over between admission and commit (409 `fenced`, untouched), and a retire of a reused id with the
old head after the window (409)); amendment A2: `drop.relay_put` gains "decide-only inbox file, then a
decide-only document" (201, then 403) and `drop.relay_list_walk` (a W walk under one `until` with a version, a
retire and an expiry committed between pages: the follow-up walk from `until` lists exactly those three, no
entry twice; then a regenerated `generation`: 409); `push.apns_envelope` (outer → APNs body bytes,
the 3,072-byte edge giving 3,175 bytes). The existing `drop` and `push` sections (descriptors, claims, chains,
NSE cases) are unchanged and are what the phone and host already run.

### 14.7 Secret handling for the APNs key (owner decision)

**The key that exists (owner's note via orch-d6, 15 Oct).** The owner created an APNs auth key on 8 Oct: Key ID
`TD27F9Z9V7`, **team-scoped** (all topics), valid for **sandbox and production in one key** (an older-style
key). It is already on the VPS at `/srv/orch-relay/apns/AuthKey_TD27F9Z9V7.p8`, owner `orch-relay:orch-relay`,
mode 0600. Only the Key ID and that path convention may appear in documents; no agent reads, prints, copies or
references the file's contents, on the VPS or on the laptop. *Taken from the owner's note, not verified here*:
that this one key serves both gateways and is team-scoped. D40b's first sandbox send in tests/dev re-verifies the
sandbox half; the production gateway is verified only at the first production-gateway send (a TestFlight build),
at deploy time. Each check runs once against Apple's token-auth answer (a 403 `InvalidProviderToken` or `TopicDisallowed` would contradict it).

**Configuration is a per-environment mapping** `env → (key id, key file or credential)`, so it works with:
- **one key for both gateways** (the default today): `sandbox` and `production` both map to `TD27F9Z9V7` and the
  same file;
- **two environment-specific keys** later: orch-f1 notes that **new** APNs keys are created for one environment
  each and may be topic-specific, so a replacement or a production deployment may map each `env` to its own key.

The relay signs a send with the key mapped to the registration's `env` and keeps **one JWT cache per (key,
environment)**. The topic is `io.severin.orch`.

**Open facts for any new key (owner question 2).** The App Store Connect API has no resource for APNs auth keys
(it covers bundle IDs, certificates, devices and profiles); keys are made by hand under Certificates,
Identifiers & Profiles → Keys, and the `.p8` downloads **once**. Apple has historically limited a team to **two**
APNs keys, so a new key might mean revoking one the owner's other apps use. These are unverified (no network
here); the owner checks the portal before planning a new key. Creating a key is a **human step** by the owner
(or the Apple team's admin); agents receive only key ids and the team id (not secret).

- **Which instance holds it.** The two relay instances run as separate users (`orch-relay` for the public
  instance, `orch-relay-int` for the internal one; Opus L4 makes this an invariant). Only the **public**
  instance sends push and reads the key; the internal instance gets no push configuration, so its push routes
  answer 404 (P3-D40 item 9). The runbook checks that `sudo -u orch-relay-int cat <the configured key path>
  >/dev/null` fails with permission denied (the check never prints the file). The path is
  `/srv/orch-relay/apns/AuthKey_TD27F9Z9V7.p8` by default, and
  `/run/credentials/orch-relay.service/apns-TD27F9Z9V7` after the optional `systemd-creds` step (Opus L-g:
  after `shred` the old path no longer exists, so checking it would pass trivially).
- **Default credential handling: keep the existing file.** The relay reads the mapped file at start-up and
  refuses one that is group- or world-accessible or owned by another uid than the service user, except a file
  under `$CREDENTIALS_DIRECTORY`, whose owner and mode systemd sets (accepted as is; a test pins both cases,
  Opus L-g). The token
  secret `push-token.key` (32 bytes from `/dev/urandom`, made on the VPS by root, never copied off it) sits
  beside it with the same owner and mode. This settles dev-deploy-plan R8's 0600 vs 0640 question: 0600, owned
  by `orch-relay`; `provision.sh`'s root-owned 0640 comment and its `VAPID_*` lines go (D40c).
- **Optional at deploy time: `systemd-creds` (`LoadCredentialEncrypted=`).** Exact steps, as root on the VPS
  (Ubuntu 26.04, systemd 259, dev-deploy-plan U9), for the key and likewise for `push-token`:
  1. `install -d -m 0700 -o root -g root /etc/credstore.encrypted`;
  2. `systemd-creds encrypt --name=apns-TD27F9Z9V7 /srv/orch-relay/apns/AuthKey_TD27F9Z9V7.p8
     /etc/credstore.encrypted/apns-TD27F9Z9V7` (a future key can instead be piped over ssh into
     `systemd-creds encrypt --name=<name> - <out>` so its plaintext never lands on the VPS disk);
  3. a drop-in for the public unit (as dev-deploy-plan §4.3's `local-env.conf`, never written by `provision.sh`)
     with `LoadCredentialEncrypted=apns-TD27F9Z9V7` and `LoadCredentialEncrypted=push-token`, and the mapping
     pointing at `$CREDENTIALS_DIRECTORY/apns-TD27F9Z9V7`;
  4. restart, confirm a sandbox test push, then `shred -u` the plaintext files.
  **Honest bound:** without a TPM, `systemd-creds` encrypts with the host key in
  `/var/lib/systemd/credential.secret`, so this protects against copies of `/etc`, backups and provider snapshots
  that lack that file, **not** against root on the host. The plain 0600 file protects against other users only.
- **Configuration (not secret)** in `/etc/orch/relay.local.env`: `ORCH_RELAY_APNS_TEAM_ID`,
  `ORCH_RELAY_APNS_TOPIC=io.severin.orch`, and per environment `ORCH_RELAY_APNS_SANDBOX_KEY_ID`,
  `ORCH_RELAY_APNS_SANDBOX_KEY_FILE`, `ORCH_RELAY_APNS_PRODUCTION_KEY_ID`, `ORCH_RELAY_APNS_PRODUCTION_KEY_FILE`
  (today both ids `TD27F9Z9V7` and both files the one path), plus `ORCH_RELAY_PUSH_TOKEN_KEY_FILE`. An
  environment is enabled when both its key id and its file are set (P3-D40 item 9).
- **Never in the database, logs or errors.** Each key is parsed once into a `cryptography` private-key object;
  load errors are reported as `apns key unreadable (<env>)` without path contents; JWTs are never logged; a test
  captures logs through a full send and greps for the test key's, JWTs' and token's bytes. The key is never
  committed, pasted into an issue, chat or transcript, or uploaded.
- **Production deployment** (D48 move to `*.orch.severin.io`) gets its own placement on the same layout and
  fresh registrations (production data starts empty).
- **Rotation.** The owner creates the new key (one environment each, per orch-f1), places it beside the old one,
  switches that environment's mapping, restarts the unit (queued sends are lost: best effort), confirms a test
  push, then revokes the old key in the portal (only once no environment maps to it) and deletes its file.
  Compromise: revoke first (pushes stop until the new key is in place). `push-token.key` is never rotated in
  place: rotating it means deleting every registration (apps re-register).

### 14.8 Out of scope (public launch hardening and P6)

Cross-workspace Drop addressing (ws→ws mailboxes, foreign `wxk` and inbox claims, P6 #20); personal and shared
spaces and `SK` grants; `drop:` scoped agents; leases; public and upload links; recall (beyond the host's
retire of files and documents); a device delete or self-retire route; byte ranges and resumable uploads; cross-relay addressing; a durable push outbox and delivery
receipts; multiple instances sharing APNs connections; an HSM or KMS for the APNs key; hot key reload;
per-account Drop quota overrides (as P3-D36's workspaces override); malware or content scanning (impossible on
ciphertext); abuse reporting and takedown; metrics and alerting on APNs failures; localized generic push text
(English only in P4, owner question 5); padding of §9's ciphertext (R-D6); Caddy bandwidth limits for uploads
(§10 checklist 7 grows a Drop line before a public deploy).

**Not out of scope: the Caddy body cap (Opus H2).** The dev deploy's Caddyfile (dev-kit PR #27,
dev-deploy-plan P5 and §4.2) sets `request_body max_size 8MB`, which Caddy reads as **8,000,000 bytes**, on
`relay.` and `relay-internal.`. Every Drop upload above that would get Caddy's own 413, not the relay's JSON. So
the Caddy exception must be deployed **before D39 ships** to any deployed relay: a matcher scoped to
`PUT /v2/drop/*/versions` with `max_size` 27,852,808 bytes: the relay's whole-body maximum of 27,787,272 bytes
(8 + 512 KiB + 26 MiB) plus 64 KiB, so an over-cap declared length reaches the relay and gets its JSON 413
rather than Caddy's (Opus L-c; recomputed if `ORCH_RELAY_DROP_MAX_BLOB_BYTES` changes), the 8 MB cap everywhere else, and Caddy read and idle timeouts above
the slowest upload the relay allows (10 minutes, P3-D39 item 8). D40c carries it; dev-deploy-plan P5 records it.

### 14.9 Implementation breakdown and questions

**PRs** (each lands its protocol text, fixtures and vectors first, then code; Opus security review each; never
merged before its review and green CI). Efforts are implementer days (re-estimated after the Opus review):

| PR | Content | Effort | Depends |
|---|---|---|---|
| D39a1 | Drop write and read, storage: migration 0017, the dedicated async endpoint and file limiter, the frame parser and streamed upload (temp file, hash, `fsync`, unique rename outside the lock), the check order with the fence, exact retry, CAS, wrap, inbox-wrap and recipients checks, the bounded early-answer drain and its pool, list with positions, spliced pages and byte cuts, read slots held until sent, the host `drop` notice, descriptor, descriptor-page and blob GET (streamed), read concurrency bound, slots and minimum rates, the start-up sweep, the real-socket and Caddy early-answer tests; the explicit `PLANNED` route list in `tests/test_http_fixtures.py` (Opus L13), emptied as routes land; **amendment A1:** the list entry shape with `object_id`, `version` and `state` from the start (`live`, `pruned` from the start-up sweep with its new `n`, `expired` computed at read time, tombstone entries with `descriptor` null, `tombstone_until_ms`), the `tombstone_kind`, `head_author_id`, `head_hash` and `audience` columns and the `drop_audience` table in 0017; orch-52 change 0: the fence re-checked inside the `PUT` commit and its takeover-during-transfer test; Opus delta R1–R3: the `PUT` step 6 audience 403, non-empty `recipients`, the 60 s file floor, audience rows charged to the author's head share | 4.5–5 + 0.75 review | this design |
| D39a2 | Drop limits and lifecycle: blob and head quotas with per-device shares, document count, reservations, buckets, the expiry, tombstone, pruning and device-wrap sweepers (batched by deleted rows; the expiry sweep assigns the new `n`), retire for documents **and files** (amendment A1: a file's version, wraps and usage released in the retire transaction, the unlink after commit, `{state}` answers, idempotency against expiry), the `retired` list state; orch-52 changes 0–3: the retire's in-transaction fence and `expect_version`/`expect_head` precondition (409 `version_conflict`), the bounded idempotent retry, the takeover-versus-retire race tests and the `drop.relay_retire` vectors, `tombstone_ms = expires_ms` on expiry, the notice tests per state change, audience rows deleted at an expiry and kept (moved to the workspace charge) on a retire; the `rotation_required` refusal if the owner adopts it, the peak-RSS bench (uploads plus descriptor pages); **amendment A2:** decide-class uploads (the widened step-2 admission, the step-5 shape check, the commit re-check, the decide-class budget with its table and day sweep; +0.5), and the W-session list walks (`direction: "all"`, the `generation` meta row and start-up insertion, `until`, 409 `generation_changed` including `after` above the counter; +0.5), their fixtures and the `drop.relay_put` and `drop.relay_list_walk` vectors; A2 revision 2: the budget charged at admission with its conditional update and failed-stream charges, the decide-class slot, the inbox visibility filter on lists, reads and `PUT` step 6, the `generation` start check with `drop-hwm.json` (+0.5); A2 revision 3: the budget upsert and the error-path give-back, `ORCH_RELAY_STATE` and the 60 s high-water writer, `claimed_ms` and `expires_ms` in list entries, and +0.25 for the tight revision-2 estimate (Opus delta 2, L-7) (+0.5) | 5.25–5.75 + 1 | D39a1 |
| D39b | Claims and host re-wraps: `POST claim` (§10.5 transaction), `PUT .../wraps` (`wrap_conflict`), the round trip with `test_round_trip_drop_claim` | 2 + 0.5 | D39a1 |
| D40a | Push register and unregister: migration 0018, token sealing with the token secret, device-bound ids, same-person move, pruning on revocation and removal, the stale sweep, the disabled-push 404, the partial-configuration refusal | 1.5 + 0.5 | this design |
| D40b | The host send route and APNs delivery: checks, budgets, the dedup LRU, the in-memory queue and its per-account cap, the HTTP/2 client (a new runtime dependency: `httpx[http2]`, pinned), ES256 JWT cached per key, the per-environment key mapping, the answer table with the 403 backoff, credential loading, the fake APNs transport, log hygiene tests, the end-to-end test | 3.5–4 + 1 | D40a |
| D40c | Operations (infra session, outside this repo's code): the Caddy body-size exception and timeouts for the Drop upload path (§14.8; deployed before D39 ships), the push configuration on the public unit only (the existing key file, optionally `LoadCredentialEncrypted`), the separate-users credential check, `provision.sh` without VAPID and its 0640 comment, the runbook for key placement and rotation and for `data/drop/` in backups and resets, dev-deploy-plan R8 and P5; amendment A2: the state directories `/srv/orch-relay{,-int}/state/` created by `provision.sh` before (in the same run) the units set `ORCH_RELAY_STATE`, dev-deploy-plan step B's `mv` and §6.2's `cp -a` (and the deploy-day runbook's step 2 `mv` and R2 `cp -a`) of the whole data directory replaced by `sqlite3 .backup` with the `drop_generation` row deleted in the copy (the state directory never moved), with a restore and rollback test | ~1.5 | D40b (the Caddy part before any D39 deploy) |

**Deploy gate (Opus review of PR #72, F1).** D39a1 ships its routes behind `ORCH_RELAY_DROP=1`, default off (every Drop route answers 404 as absent): without D39a2's quotas, reservations, upload bucket, expiry sweep and retire, any `operate` member could fill the database and the disk. Migration 0017 and the start-up sweep run either way (from D39a2 on, subject to item 14's state check: no `n`-assigning pruning while it fails and `drop_counter.n > 0`). D39a2 removes the requirement or keeps the switch as a kill-switch; no relay serves Drop before D39a2 lands. The same review added to D39a1: a total deadline for the frame and head (30 s) and for the whole transfer (10 minutes, from the upload slot), account (`person`) slot caps for W sessions, the descriptor-page cut chosen from `descriptor_len` before any descriptor is read, a start-up sweep that never loads descriptors, 503 `overloaded` on a disk error, a non-member device refused before any slot, and a drained 413 for an oversized head.

**D39a2 notes from the Opus delta review of PR #72 (round 3).** Fixed in D39a1: a cancelled or unknown commit outcome keeps the landed blob (the start-up sweep deletes a file no `stored` row names; N1); a SQLite `OperationalError` at the commit answers 503 `overloaded` with `Retry-After` (N2); `members(device_id)` is indexed in 0017 (N4); `descriptor_len` is CHECKed against the descriptor in 0017. For D39a2 to settle: (N3) an EIO on the directory `fsync` after the rename answers 503 but leaves the renamed blob (up to 26 MiB) until the next start-up sweep: D39a2's periodic sweep (or an unlink in that path) removes it; (N5) a host session's slots count against its account owner, so the owner's own devices share the person caps (3 uploads, 4 reads, 8 downloads) with all of that account's hosts: D39a2 decides whether hosts get a separate account key with its own caps; (nits) `ORCH_RELAY_DROP_NOTICE` works while `ORCH_RELAY_DROP` is off (it then reports objects only a past enabled run stored; D39a2 may tie it to the Drop switch); an error while closing the temporary file turns a 400 into a 503.

The **smallest end-to-end slice** is D39a1 + D39a2 + D40a + D40b + D40c (**~19.5–21 days** with reviews,
the table's sum; ~11 in revision 1, ~14–15 in revision 2, ~15.5–17 in revision 3, ~16.75–18.25 after amendment
A1; amendment A1 with orch-52's changes 0–4 and the Opus delta's R1–R3 is already in the D39a1 and D39a2 rows,
not added again; amendment A2 adds 2 implementer days and 0.25 review day to D39a2 (revisions 2 to 6; revision 4's no-replace trigger,
named-column insert, fail-closed checks and Drop-off sweep gating and revision 5's lock file fit in revision 3's +0.5 implementer
days, which already include 0.25 day for the tight revision-2 estimate; revision 6 is text only) and 0.5 day to D40c (the state directories and the backup and rollback procedure); D39b's and
D40b's in-transaction fence re-checks and D39b's setting of `claimed_ms` fit their existing estimates):
a Python harness with a device (suite 2, the ref client) uploading a file to its workspace, the host stub
seeing the `drop` notice, listing and downloading it, uploading a reply, and sending `drop.new` through the fake
APNs transport, whose captured body the ref NSE logic (`push` vectors' receiver) opens and verifies. D39b
follows before the phone's inbox demo runs against the real relay.

**Questions for the owner (open; the owner has not answered; recommended defaults in italics, used by D39/D40
unless the owner decides otherwise):**

1. Cross-workspace Drop addressing (`wxk` to other workspaces, foreign inbox claims; Opus M1): in P4 or later?
   *Defer to P6*: `wxk` targets and workspace ids in `recipients` must equal the object's own workspace. If
   wanted in P4: at most 4 foreign targets per object, a per-source-workspace daily cap, and list access only for
   workspaces with a wrap.
2. APNs key facts (§14.7): the existing key `TD27F9Z9V7` is, per the owner's note, team-scoped and valid for
   both gateways; *use it for both environments now and re-verify once with a sandbox send in D40b*. For any
   **new** key: the possible two-key team limit (which could force revoking a key the owner's other apps use)
   and per-environment, topic-specific keys. *Confirm in the portal before planning a new key*; the owner (or
   the team admin) creates it by hand.
3. Document expiry and lifecycle (Opus M5): *P4 documents carry `expires_ms: null` only*, with the host's
   retire route as the way out of the per-document (1 024 versions) and per-workspace (256 documents) caps, so
   no workspace reaches a permanent 429. Alternative: a version-cap policy instead of retire.
4. Drop ceilings and backups: 4 GiB global and 1 GiB per account against ~10 invited accounts (R-D3), and are
   Drop blobs in backups? *Keep the numbers; back up the database (descriptors, wraps); exclude `data/drop/`
   by default, stated in the runbook* (P3-D39 item 12).
5. Generic push text "orch" / "New activity in orch": *English only for P4* (a `loc-key` later is cosmetic).
6. Refuse Drop uploads while a revocation's `rotation_due` is open (Opus M6)? *Refuse with 409
   `rotation_required`, because it is cheap* (one indexed lookup on the existing table), accepting that uploads
   wait for the host's rotation; if the owner declines, R-D7 stays documented.

**Questions for orch-52 (host side), with recommended answers:**

- **Q-H1.** Add `drop` to the host poll's exact `notices` set (the newest Drop change position of the workspace,
  0 if none)? *Recommend yes*; the host lists `after` its durable position. **Rollout order (Opus L12):**
  §19.6 defines `notices` as an exact key set, so hosts must accept the `drop` key **before** the relay ships
  it; D39a1 emits it only once orch-52 confirms a host release that tolerates it. The device visibility filter
  applies on top.
- **Q-H2.** Push sending: the host targets explicit devices, persists the outer before sending, resends identical
  bytes on a lost response, never seals under an old epoch (409 `stale_epoch` → refetch, reseal, which gives a
  new `c` and so a new push: expected), and never sends `join` (the phone does not show it, gap 13). After a
  host state restore the push planner applies the 11A.4 start fence (events before `meta.start_ms` without a push
  row are never pushed; pushes older than their `ttl_s` are deleted unsent), because the relay's dedup memory
  does not survive a restart and the NSE shows replays as generic text (orch-52 item 6).
  *Recommend* `question` and `question.closed` at `high` with `ttl_s` 86,400; `ticket.update` at `normal` with
  3,600; `drop.new` at `high` with 86,400.
- **Q-H3.** `ts_ms` per `(ws, id)` strictly increasing even within one millisecond (gap 17): *recommend*
  `max(now, last + 1)` as FakeHost does.
- **Q-H4.** Restricted tickets: the host filters targets by visibility, because the label is readable by every
  `K_push` holder it reaches, and addresses Drop objects about them with `device` wraps only (P3-D39 item 4).
  The relay cannot tell and enforces nothing here. *Recommend* making this a host MUST now, before P8. orch-52
  agrees and adds the seal gate (seal a `wk` wrap or a push only at the committed epoch with the rotation gate
  down) and label padding (R-D6). Amendment A1 (orch-52 change 4) makes the split explicit: the relay enforces
  membership and the device-only `recipients` list only, keeps the documented 403/404 existence oracle, and
  the host also filters its own listings and bridge answers by ticket visibility (P3-D39 items 4 and 6,
  R-D10).
- **Q-H5.** Host Drop writes: a `PUT` with `author_kind: "workspace"`, W(g)-fenced like every write; a
  `drop_rewrap` persists its wrap before the `PUT .../wraps` (409 `wrap_conflict` otherwise); documents are
  retired, never expired. *Recommend yes.* orch-52 agrees and persists the whole `ODU2` frame before the first
  `PUT`; a `wrap_conflict` after lost host state is resolved with the stored wrap and `dek_commit` in the 409
  body (P3-D39 item 9). The relay lets a W author write document versions; orch-52 restricts its host to
  `file` objects until a merge rule exists.
- **Q-H6.** Handling 429 `quota_exceeded` on Drop (per device, workspace, account): permanent until expiry,
  pruning or a retire (head bytes held by a retired device-only tombstone's audience rows only when that
  tombstone ends, 30 days after the retire; P3-D39 item 8); the host shows it, never retries unchanged in a loop (as the P3-D34 permanent quotas).
  The body's `quota` field names the cap (P3-D39 item 8). 503 `overloaded`, 429 `rate_limited` and a slot
  429 are retryable after `Retry-After`, never permanent.
- **Q-H7 (amendment A1; orch-52, 15 Oct 2026: agreed with changes 0-4).** Host-only retire of files and
  documents, fenced by `Orch-Holder` (re-checked inside the relay's write transaction, P3-D39 item 1). The host
  sends `{expect_version, expect_head}` of the head it decided about and treats 409 `version_conflict` as "look
  again" (the object is untouched); it retries a retire with a lost answer only within **29 days** of the
  earlier of its first attempt and, for a file, its `expires_ms` (a day of margin for the host's clock against
  the relay's `tombstone_ms`; Opus delta L5), and otherwise reconciles by a full relist, never replaying it (a
  404 after the window proves nothing); it reconciles in full after a listing gap longer than 29 days, a state
  restore or a takeover; it counts a `drop` notice as news only above its stored position (P3-D39 items 5 and
  7). *Agreed.*
- **Q-H8 (amendment A2; orch-52, 15 Oct 2026: agreed).** (1) Phones upload inbox files with `decide` alone
  (P3-D39 item 13); the host's claim rule is Q-H9; it treats a decide-class 429 `rate_limited` as transient
  (`Retry-After` to 00:00 UTC). (2) The host lists with `direction: "all"`,
  stores `(generation, until)` after each complete walk, passes `until` and `generation` on every following
  page, relists in full on 409 `generation_changed`, confirms a full walk's absences with the follow-up walk
  from `until` and takes no irreversible action on absence alone, and lists at once when its `drop` notice
  falls below its stored position (P3-D39 item 14). *Agreed.*
- **Q-H9 (amendment A2 revisions 2 and 3, after the Opus delta R2 and delta 2; orch-52, 15 Oct 2026: agreed
  host-side rule; the window decided by orch-52, cc orch-fa).**
  The host claims an inbox object **without a gesture** only when (1) its verified author device is a
  **current member device of the person the claim is for** (`decide` present, not revoked) at claim time,
  re-checked under the host store lock in the same step as the claim, and (2) the claim is for that person's
  own device-authored upload; "the person the claim is for" is the person on whose behalf the host releases
  the object to the workspace (the relay's claimer is the workspace, P3-D39 item 9). Every other release
  (another person's upload, or one whose author device has since been revoked or removed) needs a terminal
  hand-off (`drop.handoff_required` to a phone that asks). In a workspace with several people, any member's
  own phone upload is so released to every member. **"Shared from your phone" is host-side:** at each
  gestureless claim the host persists its own record (item, author device, `claimed_ms`) and shows it on the
  dashboard and in `orch status` until `shared_until_ms = claimed_ms + 7 d`, independent of the file; once the
  file is gone (`expires_ms` passed, or retired) the record stays with the state `expired` or `retired` and
  the retire action is hidden. The relay promises nothing about listing the entry after its tombstone is
  deleted: its list entries carry `claimed_by`, `claimed_ms` and `expires_ms` (P3-D39 item 7) until then, and
  after that the host's own record is the only source. Retiring one's own upload stays a single unsigned
  action. No activity window. A revocation before the claim blocks it, which helps in practice only for
  uploads the host has not yet processed. Residual R-D13: a stolen unlocked phone can
  push content within the budget until revoked; the host claims it without a gesture; it is visible and
  removable at once. *Agreed (host-side; the relay enforces nothing here).*

orch-52's review (15 Oct, SOUND WITH CHANGES) also lists host-side work recorded in orch-core, not here: R6's
typed `BridgeKeys` methods (`seal_push`, `wrap_dek_wk`, `open_wrap_wk`), the H13a push planner and outbox, the
H13b Drop client, the H13c core carriage, and about 11 core days for the host end of the slice.

**Questions for orch-f1 (phone side).** orch-f1 agreed Q-F1 to Q-F7 and Q-F9 (15 Oct) and supplied Q-F8;
its blocker R1 (inbox visibility) and its R3–R6 are folded in above; its blocker R2 (new keys are one
environment each) is met by the per-environment key mapping, which today maps both environments to the owner's
existing both-gateway key (orch-d6 correction, 15 Oct).

- **Q-F1.** Move every Drop route under `/v2` (the write and claim too). *Agreed.*
- **Q-F2.** Replace the JSON upload body with the `ODU2` frame (P3-D39 item 2), keeping the stored-bytes,
  resend-unchanged discipline, with an exact `Content-Length` and a descriptor read-back before any resend
  (Opus M3; the read-back outcomes table and the bounded resend loop of P3-D39 item 2, Opus L-d). *Agreed*; uploads run in the app, the share extension only stages.
- **Q-F3.** `If-Match: 0` creates version 1 (`current = 0` for an absent object): adopted, with a protocol
  clarification in §19.9 rather than a §10.6 change. The relay also emits `ETag: "<v>"` and accepts `If-Match`
  as the bare decimal or that quoted form. *Agreed.*
- **Q-F4.** Handle 409 `stale_epoch` on a Drop `PUT` with the existing `EpochRefetchLimiter`, then **rewrap the
  same `DEK`** under the new epoch and resend the same blob and descriptor in a new frame; reseal with a fresh
  `DEK` only after `version_conflict` (Opus M6; changed from "reseal after a read-back"). *Agreed in principle;
  the rewrap detail is new in revision 2.* 409 `bad_wxk_version` is handled the same way: refresh the card and
  rewrap the same `DEK` (orch-f1 S3). A 409 `rotation_required` (owner question 6) is retried after the host's
  rotation, through the same limiter.
- **Q-F5.** Wraps are filtered per caller, the list is paged by position (`after`, `next`) and cut by bytes,
  and the descriptor page route replaces 1 024 single fetches (F4); unclaimed inbox objects are listed with
  their descriptors, only the blob waits for the claim (amendment A2: to their author device and the W
  session only; Q-F11). A phone's inbox upload carries a `wxk` wrap and
  optionally its own `device` wrap, never `wk` (Opus N2, orch-f1 S1); a device never receives `wxk` wraps.
  *Agreed* (the inbox wrap rule is new in revision 3).
- **Q-F6.** Push registration: `env` only `sandbox` or `production` (and configured) at a real relay; token b64u
  of 32..100 bytes; `topic` exactly `io.severin.orch`; re-register at every launch (refreshes; 60 days
  unrefreshed deletes); `registration_id` bound to the device (another device's is 409); `drop:` devices are
  refused; 404 means push is off on that relay. *Agreed.*
- **Q-F7.** The APNs body (P3-D40 item 5): generic `aps.alert` "orch" / "New activity in orch",
  `mutable-content: 1`, `o` a string of at most 3,072 bytes holding exactly `{v, ws, epoch, c}`, no badge,
  sound, thread or collapse id (the NSE replaces by entity key). *Agreed.*
- **Q-F8.** Keys and transfer: §14.7. The owner's existing key `TD27F9Z9V7` serves both environments through
  the per-environment mapping; orch-f1's facts (keys made by hand in the portal, new keys one environment each,
  topic-specific) shape the mapping and any future key, and its `systemd-creds` pipe is the optional
  deploy-time step. *Adopted with the owner's correction.*
- **Q-F9.** Pruned old document versions answer 410 `expired` on the blob, tombstoned or retired ids 410 on
  every read, and 410 on a `PUT` means "use a new object id": the phone treats 410 as final, never as a fork.
  *Agreed.*
- **Q-F10 (amendment A1, to be checked by orch-f1).** List entries gain `object_id`, `version` and `state`
  (`live`, `pruned`, `expired`, `retired`); tombstones (`expired`, `retired`) stay listed for 30 days with
  `descriptor: null` and `wraps: []`, so the parser must accept a null descriptor and key entries by
  `object_id`. The phone relists in full, so it needs no `after` handling; it shows a retired item as removed by
  the host. A file's retire is host-mediated: the phone has no delete route and asks its host (orch-52's host
  op). After orch-52's changes every entry also carries `tombstone_until_ms` (null unless a tombstone), which
  the parser accepts and may ignore; a client that does list incrementally reconciles in full after a gap
  longer than 29 days (P3-D39 item 7).
- **Q-F11 (amendment A2, to be checked by orch-f1).** (1) A phone with `look` and `decide` may `PUT` a new
  `file` with `recipients: "inbox"`, `If-Match: 0`, one `wxk` wrap and optionally its own `device` wrap; any
  other shape is 403 `not_eligible`, shown, not retried; a 429 `rate_limited` with `quota`
  `drop_decide_creations` or `drop_decide_bytes` carries `Retry-After` = the seconds to 00:00 UTC by the
  relay's clock (1 to 86,400), from which the phone derives "tomorrow" and sends no decide-class `PUT` before
  then; the budget is charged at admission, so a failed or aborted stream still costs a creation and its
  received bytes; one decide-class upload at a time (a second is 429 `slot`); no `stale_epoch` for a
  `wk`-less inbox upload (`bad_wxk_version` applies); a budget 429 can arrive as a closed connection (early
  answer, read back as unknown). (2) Every list page gains `generation` and `until`, which the parser accepts;
  the phone follows the client guidance of P3-D39 item 14 (full walks, `generation` and `until` pinned from
  page 1, at most two restarts on 409 `generation_changed` before "outdated", purge only after both
  directions completed under one `generation`, `generation` an unauthenticated hint, no automatic resend of
  confirmed uploads after a restore), sends `generation` on every list with `after`, and sends the new
  request fields only to a relay running D39a2 (D39a1 refuses them); `direction: "all"` is 403 for a device.
  The phone backs off exponentially after two consecutive closed connections on a decide-class upload and
  stops at its attempt cap (each resend costs bucket tokens and a drain). Every list entry also carries
  `claimed_ms` and `expires_ms` (revision 3; may be ignored). (3) **Confirmed by orch-f1, 15 Oct:** a device's lists no longer show another author's unclaimed inbox
  object (it is 403 by id); the phone's own unclaimed uploads stay in its `sending`, and claimed objects are
  visible as before; the phone's claim flow does not list others' unclaimed items (P3-D39 items 6 and 13).

**FakeRelay versus the protocol (conflicts and proposals):**

| FakeRelay today | Protocol and this design | Proposal |
|---|---|---|
| `PUT /drop/{o}/versions`, `POST /drop/{o}/claim` without `/v2` | P3-D1: everything under `/v2` | move (agreed) |
| JSON `{descriptor, wraps, blob: b64u}`, 36 MiB | streamed `ODU2` frame, exact `Content-Length` | change the packaging (Q-F2) |
| 201 only; a lost 201 then a stale `If-Match` is 409 | exact retry is 200 before the CAS; descriptor read-back before resend | adopt; keep the read-back reconciliation |
| `wk` wraps at any epoch | `wk` at the current epoch, else 409 `stale_epoch`; rewrap the same `DEK` | adopt (closes the race for removals) |
| `wxk` to any workspace | `wxk` and `recipients` within the object's own workspace (P4) | adopt (owner question 1) |
| documents may expire | documents carry no expiry; the host retires | adopt (owner question 3) |
| no retire; list entries have no state, gone objects vanish | the host retires files and documents (with an `expect_version`/`expect_head` precondition); entries carry `object_id`, `version`, `state`, `tombstone_until_ms`, tombstones listed 30 days | adopt (amendment A1, Q-F10, Q-H7) |
| all wraps returned on list and wraps GET | the caller's usable wraps only | adopt (Q-F5) |
| no pagination on list | `after`/`next` by change position, byte-cut pages | adopt |
| host rewrap in process, silent replace | `PUT .../wraps`, `wrap_conflict` on other bytes | adopt |
| global 1 024 versions / 100 MiB | per device, workspace, account and global caps, separate head bytes | adopt the numbers in the fake's limits |
| expired objects vanish (404) | 410 `expired` for 30 days, then 404; absent versions 404 | adopt |
| no ETag | `ETag: "<v>"` on PUT and descriptor GET | adopt (informational) |
| push routes answer 404 | §19.10 routes | implement |

**Sealed formats.** No defect found in §9's or §10's sealed or signed formats; none is changed (§9's missing
padding is residual R-D6). Text-only amendments made with this design: §9 now points to §19.10 for delivery
(the "Web Push payload" and "service worker" wording stays as gaps.md row 7's open protocol amendment), and
§10.5/§10.6 point to §19.9 for the `/v2` paths and the upload packaging.
