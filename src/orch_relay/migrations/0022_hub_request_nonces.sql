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
