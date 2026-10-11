# G3 bridge integration for G4/G5

`app.state.bridge` implements protocol §19.3, §19.4 and §19.6. It shares
`Directory.lock` and `BEGIN IMMEDIATE` with G1/G2. Blocking SQLite work runs in
the thread pool. Long polls release both the transaction and lock between checks,
rechecking authorization, membership, holder lease and poll identity at handoff.
The application still requires one worker, as documented by G1.

Migration `0004_bridge` adds `rid_seen`, `rid_chunks`, `bridge_msgs`,
`request_mailboxes`, `queue_totals`, `holder_delivery` and `cert_requests`.
G4 should allocate migration 0005 or later when merging the parallel work.
The existing five-column `holders` layout is unchanged. `holder_delivery` records
the highest position actually handed to the current holder. Takeover resets this
position to the acknowledged cursor; the acknowledged cursor never rewinds.

`bridge_msgs` exposes `workspace_id` and `device_id` for G1/G2 pruning. Its SQL
triggers maintain retained body bytes, undelivered bytes and undelivered counts.
Acknowledgement releases request capacity; device delivery releases response
capacity. Bodies remain available for non-consuming retry until their original
60-second expiry and still count against global retained-byte capacity. Expiry,
revocation and departure release capacity by deleting rows. Never delete
`rid_seen` or `rid_chunks` during membership pruning: replay evidence must survive.

Requests coalesce while a live unacknowledged copy exists. A requeue creates a
new 60-second copy, at least ten seconds after the last receipt/requeue, up to
eight requeues. First receipt fixes the 900-second replay lifetime; only a later
dependent message can extend its keep-until time. Identical response retries do
not recreate or refresh bodies. Chunk conflicts precede the old-epoch exception.

Holder acquisition/renewal and all G3 host writes use the existing Directory
fence. Host polls are non-consuming and capped at 16 items and 4 MiB of encoded
JSON, with an opaque `next` continuation that does not acknowledge. Notices expose
relevant revocation position, certificate results and durable rotation obligations.
A replaced same-generation poll returns empty success; a fenced poll returns 409.
Long-poll checks wake at most every 50 ms, including after directory revocation or
membership commits. A lifespan task sweeps expired queue bodies once per second;
all transactional reads enforce the exact expiry boundary independently.

`cert_queue.complete(con, cert, now)` is invoked at every successful
`Directory.recovery` certificate exit: new upload, stored canonical repeat and
exact recovery receipt. It completes only a live challenged request with matching
person, device, signing key and key-exchange key. Terminal requests cannot be
revived by an upload. A directory upload may legitimately store a certificate
without completing any request. Challenges and rejections require the requested
addressee's device session and a valid person-key signature; canonical-object
re-signatures are idempotent without overwriting the original signed object.

There is no separate primary-device designation in the G1 account schema. The
signed request names the addressee; admission verifies its certificate/person,
and challenge/rejection gates enforce that exact device. The abstract vector's
`primary` context is represented by the available addressee certificate in tests.

The shared HTTP corpus had two impossible `quota_exceeded` examples: workspace
host polls and anonymous pair polls have no normative per-principal concurrent
limit. Those examples were removed from the generator and regenerated fixtures.
Both routes retain the global 4096-poll cap; devices retain six polls across all
their sessions. Other fixture requests and responses are unchanged. All 147 G3
examples now run through the application without later-group skips.

G5 can run `uv run pytest tests/e2e -q` independently. The suite-2 device and host
stub exchange signed, encrypted envelopes; compare the pairing code; publish
membership and a WK grant; authenticate and retrieve/decrypt the grant; exchange
bridge traffic; resend after a lost acceptance; restart with a queued request;
and revoke the device. The stub uses an already certified device and is not a
complete host implementation. First-time certificate challenge/rejection and
completion are covered separately by HTTP, boundary and vector tests.

The 101 G3 vector adapters cover request replay, chunks, hold, poll, handoff,
certificate requests/transitions/rejections, envelope shape and whole-envelope
sizes. Production code does not import the reference implementation. Test-client
crypto uses the suite-2 reference primitives. Slow tests use TestClient threads
for poll replacement, takeover and revocation wakeups; no live socket is required.
