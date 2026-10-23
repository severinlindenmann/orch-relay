-- The relay's one schema (V3-D36; D76, D77). Hub accounts, the hub's push targets and channel mailboxes, and the replay
-- stores of signed hub requests and channel reads. Public data and ciphertext only: no secret is ever stored here
-- (push tokens are sealed under the instance secret, which lives outside the database).
-- A database from any other schema is refused at start (db.init_schema): delete it.

-- Relay accounts of kind `hub` (orch-relay E1, orch-hub contract H0 §4-§5). One row per hub, keyed by
-- hub_id = H(label || suite || hk_root_pub)[0:16]; the card is stored as its canonical JSON (cj), the
-- fields the relay compares are kept as columns. Public data only: no secret is ever stored here.
CREATE TABLE hub_accounts (
    hub_id TEXT PRIMARY KEY CHECK (length(hub_id) = 32),
    hk_root_pub TEXT NOT NULL,
    op_cert_id TEXT NOT NULL CHECK (length(op_cert_id) = 32),
    op_seq INTEGER NOT NULL CHECK (op_seq >= 1),
    expires_ms INTEGER NOT NULL,
    card_seq INTEGER NOT NULL CHECK (card_seq >= 1),
    dev INTEGER NOT NULL CHECK (dev IN (0, 1)),
    card TEXT NOT NULL,
    registered_ms INTEGER NOT NULL,
    updated_ms INTEGER NOT NULL
);
-- Root-signed op-cert revocations (permanent: a row is never updated or deleted). A revocation may
-- arrive before the hub registers; it is kept so that a card under that op cert is refused.
CREATE TABLE hub_op_revoked (
    hub_id TEXT NOT NULL CHECK (length(hub_id) = 32),
    cert_id TEXT NOT NULL CHECK (length(cert_id) = 32),
    revoked_ms INTEGER NOT NULL,
    recorded_ms INTEGER NOT NULL,
    PRIMARY KEY (hub_id, cert_id)
);

-- Nonces of hub -> relay requests (contract §10.8 step 6). A replay inside the 240 s retention window must not repeat
-- a state change, so the nonce is recorded in the same transaction that authenticates the request. Rows older than the
-- window are pruned on use. ts_ms is the request's own (signed) timestamp. Public data only.
CREATE TABLE hub_request_nonces (
    hub_id TEXT NOT NULL CHECK (length(hub_id) = 32),
    nonce TEXT NOT NULL CHECK (length(nonce) = 32),
    ts_ms INTEGER NOT NULL,
    PRIMARY KEY (hub_id, nonce)
) WITHOUT ROWID;
CREATE INDEX hub_request_nonces_ts ON hub_request_nonces (ts_ms);

-- E2 hub-phone (orch-hub contract §10.8.1): one APNs target per (hub, channel) and the hub's channel mailboxes.
-- The token is sealed (AES-256-GCM under K_tok, bound to the sealing id
-- "hub:<hub_id>:<channel_id>"; HMAC under K_mac for lookups); it is never returned. Mailbox messages are sealed
-- ciphertext the relay cannot read. Public ids and ciphertext only.
CREATE TABLE hub_push_targets (
    hub_id TEXT NOT NULL CHECK (length(hub_id) = 32),
    channel_id TEXT NOT NULL CHECK (length(channel_id) = 32),
    env TEXT NOT NULL CHECK (env IN ('sandbox', 'production')),
    topic TEXT NOT NULL,
    token_sealed BLOB NOT NULL,
    token_mac BLOB NOT NULL,
    created_ms INTEGER NOT NULL,
    updated_ms INTEGER NOT NULL,
    PRIMARY KEY (hub_id, channel_id)
) WITHOUT ROWID;
CREATE INDEX hub_push_targets_token ON hub_push_targets (token_mac);

CREATE TABLE hub_mailbox (
    hub_id TEXT NOT NULL CHECK (length(hub_id) = 32),
    channel_id TEXT NOT NULL CHECK (length(channel_id) = 32),
    msg_id TEXT NOT NULL CHECK (length(msg_id) = 32),
    c BLOB NOT NULL,
    expires_ms INTEGER NOT NULL,
    created_ms INTEGER NOT NULL,
    PRIMARY KEY (hub_id, channel_id, msg_id)
) WITHOUT ROWID;
CREATE INDEX hub_mailbox_expiry ON hub_mailbox (expires_ms);

-- E5 phone mailbox (orch-hub contract §10.8.1 purge, §10.8.4 channel read). Public ids only.
-- hub_revoked_channels: the channel ids a hub revoked, recorded by the hub's signed `DELETE .../mailbox/{ch}` and kept
-- permanently (a revoked channel id never comes back). hub_channel_nonces: the replay store of channel-signed reads
-- (240 s window), per (hub, channel).
CREATE TABLE hub_revoked_channels (
    hub_id TEXT NOT NULL CHECK (length(hub_id) = 32),
    channel_id TEXT NOT NULL CHECK (length(channel_id) = 32),
    revoked_ms INTEGER NOT NULL,
    PRIMARY KEY (hub_id, channel_id)
) WITHOUT ROWID;

CREATE TABLE hub_channel_nonces (
    hub_id TEXT NOT NULL CHECK (length(hub_id) = 32),
    channel_id TEXT NOT NULL CHECK (length(channel_id) = 32),
    nonce TEXT NOT NULL CHECK (length(nonce) = 32),
    ts_ms INTEGER NOT NULL,
    PRIMARY KEY (hub_id, channel_id, nonce)
) WITHOUT ROWID;
CREATE INDEX hub_channel_nonces_ts ON hub_channel_nonces (ts_ms);
