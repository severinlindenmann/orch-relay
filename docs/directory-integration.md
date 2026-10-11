# G1 integration for G2/G3

`app.state.directory` owns the process lock, challenge store, full-duration fixed
rate windows, configured origin, and clock. The CLI explicitly uses one worker;
multiple workers sharing a database are unsupported. `ORCH_RELAY_TRUSTED_PROXY`
is one IP address, not a CIDR or an arbitrary proxy chain.

Run blocking database operations through `run_in_threadpool`. Use `db.connect`
(with `sqlite3.Row`) and `BEGIN IMMEDIATE`, then perform authorization and mutation
in the same transaction. Acquire `directory.lock` before the transaction if using
the shared ephemeral state. Never wait for a long poll while holding this lock or
a database transaction. G3 can call `directory.assert_can_wait()` before waiting
to assert that the current thread does not own the lock. At handoff open a fresh
transaction and reauthorize.

Shared authorization methods:

- `authenticate(con, headers, now)` checks token expiry, device revocation and
  certificate expiry, returning kind, subject_id, and device person/scopes.
- `person_access(con, session, person)` implements D(p) or workspace ever_persons.
- `workspace_access(con, session, ws, write=False)` implements D(m) or W. Use
  `write=True` for W-only writes.
- `fence(con, headers, ws, now)` checks the current holder generation and lease.
- `Refusal` carries the wire code, HTTP status and optional Retry-After.
- `rate(purpose, identity, duration_ms, cap, now, charge=True)` supports shared
  refusal windows. Check multiple budgets with charge=False before charging.
  Keep distinct operation names and never evict live windows to admit new ones.

Migration 0002 owns the directory tables and shared authorization tables:
`members`, `member_lists`, `ever_devices`, `ever_persons`, `wk_grants`,
`card_key_wraps`, `rotation_due`, and `holders`. Subsequent migrations should
extend these, not recreate them. Signed objects are canonical UTF-8 JSON BLOBs;
public keys and sealed wraps are canonical b64u text; ids are lowercase hex.
`token_hash()` hashes decoded random token bytes (SHA-256); opaque noncanonical
strings are hashed as UTF-8 for lookup and cannot match generated tokens.

G2 must publish members, lists, grants and wraps atomically, grow ever_persons and
ever_devices, and clear rotation_due only on a higher-epoch publication excluding
the obligated device. Only accepted membership publications add historical authority;
first-card publication adds neither set. Read authorization also checks for a historical
device bound to the person, so legacy card-only history rows grant no access and
remain untouched in storage. Each listed person must have a certificate-bound
member device in that list (403 `other_person` otherwise). W device reads require both
sets, and W feeds filter by ever_devices before pagination. Card reads remain D(m) or W.
G1 does not treat ownership alone as device workspace membership.

G3 must implement holder acquisition/renewal and bridge/cert-request routes.
`holders` already has gen, lease_until_ms, cursor and poll_token; card writes
consume that authority. Add highest-delivered position and other fields as needed.
G3 must complete a pending certificate request within the device-upload transaction,
after the certificate is verified, including the already-stored-certificate path.
Add this at every successful `Directory.recovery` certificate exit, including canonical
and exact retries, with the
queue's key/person/expiry checks; queue behavior is deliberately not simulated here.

`Directory.revoke(con, record, now)` expects previously verified PK evidence and
an active write transaction. It preserves the strongest reason, advances the feed
cursor on a new revocation/upgrade, deletes device sessions, grants and wraps, and
sets durable rotation_due for each current membership. It also deletes matching
`bridge_msgs` (both directions), `sk_grants`, and `push_subscriptions` if those
later-group tables exist, using their `device_id` columns. G3 must wake affected
pollers after commit; every handoff still rechecks authorization. Replay metadata
must retain its contractual lifetime. G4 can reuse this operation after validating
all restore evidence, inside the restore transaction.

Bridge mailbox, queued-byte, posts-per-second and concurrent-poll limits are G3's
responsibility (§19.4). G1 implements challenge, certificate, revocation and first
card limits and eight live tokens per device (429 `quota_exceeded`, Retry-After until
the earliest expiry, consumed challenge, no eviction). Challenges also enforce /56 IPv6
limits of 256 outstanding and 960/min alongside /64 limits.

`check_response_budget(device_bytes, workspace_bytes, incoming_bytes)` is the G3
capacity hook: 2 MiB per device across sessions within 16 MiB per workspace. Call it
inside the queue transaction with persisted undelivered totals before insertion.
Release capacity on delivery, expiry or revocation; never evict to admit an overflow.
G3 owns queue accounting and retry timing. Card-key routes belong to G2, which must
apply atomic `wrap_conflict` for differing sealed bytes at the same device/card sequence.

G1 JSON body caps are 16 KiB except accounts and card writes (64 KiB). Both declared
and streamed sizes are checked before parsing/authentication, returning 413 `too_large`.
Production dummy verification keys are random per Directory instance; only the public
half is retained, and verification success never authorizes a missing subject.

Contract interpretations and fixture repairs:

- Subsequent card writes, including identical cards, require W(g), per §19.6.
  After authorization, the same signed cleartext/sealed hash is idempotent even
  when the card ECDSA signature uses the other valid s representation.
- The full canonical signed delegation is immutable (§7.1); the reference helper
  compares only its `o`. HTTP enforces the stricter normative rule. Existing card
  vectors agree with both. A changed delegation signature alone is refused.
- Recovery address windows charge every submission before parsing or signature
  verification (30/hour certificates, 10/minute revocations). Exact accepted HTTP
  retries are recognized by their persisted digest and remain free, including at
  a full address budget; certificate retries still check revocation and expiry.
  Accepted canonical retries and weaker revocations also persist a receipt so
  subsequent byte-identical retries remain free.
  Person quotas charge only verified state changes. Canonical retries and weaker
  revocations are free for person quotas. Certificates compare `cj(o)` after
  verification and preserve the original stored certificate. First-card owner
  quota is checked and charged only after both signatures verify.
- Fixed UTC-aligned minute/hour/day windows match the P3 quota vectors. Live
  windows are never pruned before expiry. Challenges and all rate windows reset on
  restart (P3-D15 accepted limit), including daily person recovery quotas and the
  reserved revocation-share counter. A restart therefore grants fresh budgets.
- Revocation feeds serve the current strongest record per device. Upgrades get a
  new cursor. `next` is opaque b64u of the person, original after, and last cursor;
  pass it with the original after value. Authorization is checked on each page.
- Four original HTTP refusal examples had impossible success artifacts: account
  cert_invalid, upload cert_expired, card delegation_mismatch and card
  bad_signature. Their requests now use the matching negative vectors, and the
  generator and fixture-validation tests assert those refusals. Statuses and
  response shapes are unchanged. Downstream fixture copies must take this update.
