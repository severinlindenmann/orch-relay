-- P3-D40a push registrations (protocol §19.10, P3 design §14.3). The APNs token is never stored in
-- clear: token_sealed = AES-256-GCM(K_tok, nonce(12) || ciphertext||tag, aad = "orch-relay/push-token|"
-- || registration_id) and token_mac = HMAC-SHA-256(K_mac, token), both keys derived from the instance
-- secret push-token.key, which is never in the database or its backups (P3 design §14.7).
-- `prune_device` (members.py) already deletes from this table by device_id and workspace_id.
CREATE TABLE push_subscriptions (
    registration_id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    env TEXT NOT NULL CHECK (env IN ('sandbox', 'production')),
    topic TEXT NOT NULL,
    token_sealed BLOB NOT NULL,
    token_mac BLOB NOT NULL,
    created_ms INTEGER NOT NULL,
    last_seen_ms INTEGER NOT NULL,
    UNIQUE (device_id, workspace_id, env, topic)
);
CREATE INDEX push_subscriptions_workspace ON push_subscriptions(workspace_id, device_id);
CREATE INDEX push_subscriptions_token ON push_subscriptions(token_mac);
CREATE INDEX push_subscriptions_seen ON push_subscriptions(last_seen_ms);
