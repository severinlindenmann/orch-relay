-- E5 phone mailbox (orch-hub contract §10.8.1 purge, §10.8.4 channel read). Public ids only.
-- hub_revoked_channels: the channel ids a hub revoked, recorded by the hub's signed `DELETE .../mailbox/{ch}` and kept
-- permanently (a revoked channel id never comes back). hub_channel_nonces: the replay store of channel-signed reads
-- (240 s window), per (hub, channel).
CREATE TABLE IF NOT EXISTS hub_revoked_channels (
    hub_id TEXT NOT NULL CHECK (length(hub_id) = 32),
    channel_id TEXT NOT NULL CHECK (length(channel_id) = 32),
    revoked_ms INTEGER NOT NULL,
    PRIMARY KEY (hub_id, channel_id)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS hub_channel_nonces (
    hub_id TEXT NOT NULL CHECK (length(hub_id) = 32),
    channel_id TEXT NOT NULL CHECK (length(channel_id) = 32),
    nonce TEXT NOT NULL CHECK (length(nonce) = 32),
    ts_ms INTEGER NOT NULL,
    PRIMARY KEY (hub_id, channel_id, nonce)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS hub_channel_nonces_ts ON hub_channel_nonces (ts_ms);
