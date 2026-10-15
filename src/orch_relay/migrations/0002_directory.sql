CREATE TABLE invites (
    code_hash TEXT PRIMARY KEY, expires_ms INTEGER NOT NULL,
    used_ms INTEGER, used_by TEXT, request_digest TEXT
);
CREATE TABLE accounts (
    person_id TEXT PRIMARY KEY, pk_pub TEXT NOT NULL, created_ms INTEGER NOT NULL
);
CREATE TABLE devices (
    device_id TEXT PRIMARY KEY, person_id TEXT NOT NULL REFERENCES accounts(person_id),
    cert BLOB NOT NULL, dk_sig_pub TEXT NOT NULL, dk_kx_pub TEXT NOT NULL,
    scopes_max BLOB NOT NULL, expires_ms INTEGER
);
CREATE TABLE revocations (
    device_id TEXT PRIMARY KEY REFERENCES devices(device_id), person_id TEXT NOT NULL,
    record BLOB NOT NULL, reason TEXT NOT NULL, received_ms INTEGER NOT NULL, cursor INTEGER NOT NULL UNIQUE
);
CREATE INDEX revocation_feed ON revocations(person_id, cursor);
CREATE TABLE workspaces (
    workspace_id TEXT PRIMARY KEY, owner_person_id TEXT NOT NULL REFERENCES accounts(person_id),
    wsk_pub TEXT NOT NULL, delegation BLOB NOT NULL, card BLOB NOT NULL,
    card_seq INTEGER NOT NULL, wxk_version INTEGER NOT NULL, client_hosted INTEGER NOT NULL
);
CREATE TABLE sessions (
    token_hash TEXT PRIMARY KEY, kind TEXT NOT NULL CHECK(kind IN ('device', 'workspace')),
    subject_id TEXT NOT NULL, expires_ms INTEGER NOT NULL
);
CREATE INDEX subject_sessions ON sessions(kind, subject_id);
CREATE INDEX session_expiry ON sessions(expires_ms);
-- Accepted recovery request digests survive restart and reason upgrades.
CREATE TABLE recovery_receipts (
    kind TEXT NOT NULL, request_digest TEXT NOT NULL, subject_id TEXT NOT NULL,
    PRIMARY KEY(kind, request_digest)
);
-- Shared authorization state. G2/G3 publish these inside the same write transactions.
CREATE TABLE ever_persons (
    workspace_id TEXT NOT NULL, person_id TEXT NOT NULL, PRIMARY KEY(workspace_id, person_id)
);
CREATE TABLE members (
    workspace_id TEXT NOT NULL, device_id TEXT NOT NULL, person_id TEXT NOT NULL,
    scopes BLOB NOT NULL, PRIMARY KEY(workspace_id, device_id)
);
CREATE TABLE member_lists (
    workspace_id TEXT NOT NULL, list_seq INTEGER NOT NULL, epoch INTEGER NOT NULL,
    list BLOB NOT NULL, PRIMARY KEY(workspace_id, list_seq)
);
CREATE TABLE ever_devices (
    workspace_id TEXT NOT NULL, device_id TEXT NOT NULL, first_epoch INTEGER NOT NULL,
    PRIMARY KEY(workspace_id, device_id)
);
CREATE TABLE rotation_due (
    workspace_id TEXT NOT NULL, device_id TEXT NOT NULL, revocation_cursor INTEGER NOT NULL,
    epoch INTEGER NOT NULL, PRIMARY KEY(workspace_id, device_id)
);
CREATE TABLE card_key_wraps (
    workspace_id TEXT NOT NULL, device_id TEXT NOT NULL, card_seq INTEGER NOT NULL,
    sealed TEXT NOT NULL, PRIMARY KEY(workspace_id, device_id, card_seq)
);
CREATE TABLE wk_grants (
    workspace_id TEXT NOT NULL, device_id TEXT NOT NULL, epoch INTEGER NOT NULL,
    grant BLOB NOT NULL, PRIMARY KEY(workspace_id, device_id, epoch)
);
CREATE TABLE holders (
    workspace_id TEXT PRIMARY KEY, gen INTEGER NOT NULL, lease_until_ms INTEGER NOT NULL,
    cursor INTEGER NOT NULL DEFAULT 0, poll_token TEXT
);
