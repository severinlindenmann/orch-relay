# P3 relay design: directory, bridge v2, members and epochs, checkpoints

Status: **revision 3**, 11 Oct 2026 (stream D, orch-4e), after two Codex challenges and the Opus tie-break; challenge log §12, decision index §13. This
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
| `POST /v2/accounts` | none | `{invite, pk_pub, device_cert, challenge, sig}` → `{person_id}` | `sig` is the new device's login signature over a fresh challenge; the exact same request → 200 (by digest) | 400 `malformed`, `cert_invalid`; 401 `bad_signature`, `unknown_challenge`; 403 `not_eligible` (one code for unknown, used or expired); 409 `account_exists` | spec §6.1 (P3-D3) |
| `PUT /v2/devices/{device}` | none | `{cert}` → `{device_id}` | self-authenticating under the account `PK`; per address 30/h; per person 64/day, charged only after the signature verifies; an exact retry is free | 400 `cert_invalid`, `cert_expired`; 403 `revoked`, `other_person` (no account); 409 `cert_conflict` | §6.1, §8.3, §8.4 (P3-D5) |
| `GET /v2/devices/{device}` | D(p), or W whose `ever_persons` contains the person | → `{cert}` | | 403 `not_eligible`; 404 `not_found` | §6.1 |
| `POST /v2/revocations` | none | `{record}` → `{device_id}` | authority is `PK`; per address 10/min; per person 32/day, charged only after the signature verifies, with 8/day reserved for revocations of devices not yet revoked; an exact retry is free | 400 `malformed`; 401 `bad_signature`; 403 `other_person` | §6.2 (P3-D5) |
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
| `GET /v2/workspaces/{ws}/host/poll?after=n&wait=s` | W(g) | → `{items: [{n, route, device, rid, offer, envelope}], notices: {revocations_cursor, cert_requests, rotation_due}, next}` | non-consuming; `after` acknowledges everything up to it (stored as `holders.cursor`); renews the lease; ≤ 16 items or 4 MiB | 409 `fenced`; 401 | P3-D10 |
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
- **Pre-public-deploy gate (G3 review D4, open):** `Directory.handle` still takes the global
  `Directory.lock`, opens a fresh connection and runs `BEGIN IMMEDIATE` before authenticating or
  validating anything (about 1.3 ms of lock time per unauthenticated request; ~750 bad-token
  requests/s from one client saturate the lock that bridge transactions share). Before any public
  deploy: reuse per-thread connections in `Directory`, add a read-only pre-check outside the lock
  for authenticated directory routes and `rate(..., charge=False)` pre-checks for unauthenticated
  ones, and add a no-lock test for directory routes like the bridge's. The dev relay needs a Caddy
  per-IP rate limit (or connection cap) meanwhile. Anonymous pair requests to an existing workspace
  likewise reach the lock before their pairing windows refuse them.
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

On a verified revocation, from the route or from a restore's entries, the relay does the following in one transaction:

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
  the same transaction, so the first accepted binding wins at the relay and on devices alike. The
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
  (`other_person`) until it redeems an invite, which turns the row into its account; revocation intake for it
  still works. Found by the G4 security review: without the mark, the row was a full account without an invite.
- *Measured* (`uv run python tests/bench_checkpoint_capacity.py`, `docs/p3-checkpoint-capacity.md`).

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

- **G1: publication work inside the global write lock.** A full 64 MiB / ~900,000-head publication holds
  `directory.lock` (shared by every write: logins, bridge, membership, recovery) for 21.4 s with peak RSS
  about 836 MB, and a refusal at the end of the fold costs the same; refused publications repeat 48 times
  per workspace-hour without re-staging, and blocked writes pin the worker threads, so reads and `/healthz`
  stall too. Recommended phased design:
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
- **G3: one account can fill the global staging ceiling.** 4 GiB is 64 full workspaces; one account creates
  10 per hour and keeps every other workspace at 503. Needs a per-account (owner-person) staging cap or a
  limit on live workspaces per account.
- **G4: storage amplification.** An accepted 64 MiB publication adds ~900k nodes (~264 MB at 293 B/node),
  about 4x the staged bytes, repeatable every ~25 s per workspace; `checkpoint_receipts` and
  `checkpoint_gone` are never purged and restore-referenced checkpoints are permanent. `checkpoint_revocations`
  and `checkpoint_unpublished` grow with restores x known devices (owner-gated). Self-certified restore evidence
  adds an account, a device and a global revocation per entry, and any account holder can cause it from their
  own workspace (hundreds of entries per 512 KiB line); this is what made the round-2 unpublished scan
  (review N2, now a per-device lookup) a cost for every workspace. Needs a per-workspace storage quota (429)
  and a quota on self-certified evidence per account. The `unpublished` retrieval or poll route (orch-52
  decision point 7) does not exist yet; it is a gate before the #397 host side relies on `unpublished`.
- **Unthrottled authenticated work.** Reads (up to 56,680 heads per proof page), staging, genesis and
  baseline refusals, and `ignored` lower-n publications (full stateless validation, uncharged; exact retries
  skip it since round 3) are not rate-limited; with the G3 review's `Directory.handle` finding (directory routes
  take the lock before authenticating, D4) these are the same gate.

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
