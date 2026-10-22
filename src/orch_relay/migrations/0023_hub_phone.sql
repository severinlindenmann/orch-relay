-- E2 hub-phone (orch-hub contract §10.8.1): one APNs target per (hub, channel) and the hub's channel mailboxes.
-- The token is sealed exactly as push_subscriptions (AES-256-GCM under K_tok, bound to the sealing id
-- "hub:<hub_id>:<channel_id>"; HMAC under K_mac for lookups); it is never returned. Mailbox messages are sealed
-- ciphertext the relay cannot read. Public ids and ciphertext only.
CREATE TABLE IF NOT EXISTS hub_push_targets (
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
CREATE INDEX IF NOT EXISTS hub_push_targets_token ON hub_push_targets (token_mac);

CREATE TABLE IF NOT EXISTS hub_mailbox (
    hub_id TEXT NOT NULL CHECK (length(hub_id) = 32),
    channel_id TEXT NOT NULL CHECK (length(channel_id) = 32),
    msg_id TEXT NOT NULL CHECK (length(msg_id) = 32),
    c BLOB NOT NULL,
    expires_ms INTEGER NOT NULL,
    created_ms INTEGER NOT NULL,
    PRIMARY KEY (hub_id, channel_id, msg_id)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS hub_mailbox_expiry ON hub_mailbox (expires_ms);
