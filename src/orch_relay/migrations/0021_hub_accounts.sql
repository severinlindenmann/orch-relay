-- Relay accounts of kind `hub` (orch-relay E1, orch-hub contract H0 §4-§5). One row per hub, keyed by
-- hub_id = H(label || suite || hk_root_pub)[0:16]; the card is stored as its canonical JSON (cj), the
-- fields the relay compares are kept as columns. Public data only: no secret is ever stored here.
-- Per-workspace accounts are untouched.
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
