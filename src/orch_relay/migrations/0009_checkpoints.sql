-- G4: signed checkpoints, genesis pins, staging and restore transitions (protocol-v2 §19.8).
-- 0008 is reserved for the pairing binding; the runner applies files in name order either way.
CREATE TABLE checkpoint_genesis (
    workspace_id TEXT PRIMARY KEY, body BLOB NOT NULL
);
-- Stored workspace checkpoints by h_checkpoint. superseded_ms starts the 24 h retention; a
-- transition-referenced checkpoint is permanent (P3-D13/D19).
CREATE TABLE checkpoints (
    workspace_id TEXT NOT NULL, hash TEXT NOT NULL, n INTEGER NOT NULL, body BLOB NOT NULL,
    superseded_ms INTEGER, permanent INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(workspace_id, hash)
);
CREATE INDEX checkpoint_retention ON checkpoints(workspace_id, permanent, superseded_ms);
CREATE TABLE checkpoint_heads (
    workspace_id TEXT PRIMARY KEY, hash TEXT NOT NULL
);
-- Expired endpoints answer 410 checkpoint_gone, unknown ones 404.
CREATE TABLE checkpoint_gone (
    workspace_id TEXT NOT NULL, hash TEXT NOT NULL, PRIMARY KEY(workspace_id, hash)
);
-- P3-D19: immutable, branch-agnostic, hash-addressed. skip_acc is the ancestor at
-- skip_height(seq) on the node's own branch, so a proof page costs O(limit + log N). Hashes are
-- their 32 raw bytes (acc_0 is 32 zero bytes).
CREATE TABLE log_nodes (
    workspace_id TEXT NOT NULL, log TEXT NOT NULL, acc BLOB NOT NULL, seq INTEGER NOT NULL,
    head BLOB NOT NULL, prev_acc BLOB NOT NULL, skip_acc BLOB NOT NULL,
    PRIMARY KEY(workspace_id, log, acc)
) WITHOUT ROWID;
-- P3-D20 staging sets: source is 'null' or a checkpoint hash; bytes counts pages and manifest.
CREATE TABLE checkpoint_staging (
    workspace_id TEXT NOT NULL, source TEXT NOT NULL, target TEXT NOT NULL,
    expires_ms INTEGER NOT NULL, manifest BLOB, bytes INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(workspace_id, source, target)
);
CREATE INDEX checkpoint_staging_expiry ON checkpoint_staging(expires_ms);
CREATE TABLE checkpoint_staging_pages (
    workspace_id TEXT NOT NULL, source TEXT NOT NULL, target TEXT NOT NULL, i INTEGER NOT NULL,
    body BLOB NOT NULL,
    PRIMARY KEY(workspace_id, source, target, i),
    FOREIGN KEY(workspace_id, source, target) REFERENCES checkpoint_staging ON DELETE CASCADE
);
-- The manifest's descriptors, one row each (pos = manifest order), so a page PUT checks one
-- slot instead of re-reading the manifest or the set.
CREATE TABLE checkpoint_staging_slots (
    workspace_id TEXT NOT NULL, source TEXT NOT NULL, target TEXT NOT NULL, i INTEGER NOT NULL,
    pos INTEGER NOT NULL, descriptor BLOB NOT NULL,
    PRIMARY KEY(workspace_id, source, target, i),
    FOREIGN KEY(workspace_id, source, target) REFERENCES checkpoint_staging ON DELETE CASCADE
);
-- Applied restore transitions (R5: applied ids only), ordered by target_n.
CREATE TABLE checkpoint_transitions (
    workspace_id TEXT NOT NULL, restore_id TEXT NOT NULL, target_n INTEGER NOT NULL,
    bundle BLOB NOT NULL, PRIMARY KEY(workspace_id, restore_id)
);
CREATE UNIQUE INDEX checkpoint_transition_order ON checkpoint_transitions(workspace_id, target_n);
CREATE TABLE checkpoint_baselines (
    workspace_id TEXT NOT NULL, hash TEXT NOT NULL, offer_id TEXT NOT NULL,
    until_ms INTEGER NOT NULL, PRIMARY KEY(workspace_id, hash)
);
-- Exact retries of accepted publications (digest of cj(body)).
CREATE TABLE checkpoint_receipts (
    workspace_id TEXT NOT NULL, digest TEXT NOT NULL, result BLOB NOT NULL,
    PRIMARY KEY(workspace_id, digest)
);
-- Charged refusals of final publications: 16 per holder generation, 48 per workspace-hour.
CREATE TABLE checkpoint_failures (
    workspace_id TEXT NOT NULL, gen INTEGER NOT NULL, at_ms INTEGER NOT NULL
);
CREATE INDEX checkpoint_failure_window ON checkpoint_failures(workspace_id, at_ms);
-- R4 coverage: devices first seen as restore evidence or signers (G2 ever_devices holds the
-- list members). No signer-binding table: signers are registered devices (review L3).
CREATE TABLE checkpoint_ever_devices (
    workspace_id TEXT NOT NULL, device_id TEXT NOT NULL, PRIMARY KEY(workspace_id, device_id)
);
-- Revocations learned through THIS workspace's accepted restores (F1 #387: completeness never uses
-- out-of-band evidence), one row per verified (device, person) pair at its strongest reason, with
-- the evidence and the restore that carried it. Never deleted; a reason only upgrades.
CREATE TABLE checkpoint_revocations (
    workspace_id TEXT NOT NULL, device_id TEXT NOT NULL, person_id TEXT NOT NULL,
    reason TEXT NOT NULL, record BLOB NOT NULL, device_cert BLOB NOT NULL, pk_pub TEXT NOT NULL,
    restore_id TEXT NOT NULL, target_hash TEXT NOT NULL,
    PRIMARY KEY(workspace_id, device_id, person_id)
);
-- revocation.unpublished (provisional, orch-52): globally held revocations an accepted workspace
-- restore did not carry, with an authenticated reference (the §19.5 feed cursor and the record's
-- digest) for later retrieval. Durable; the retrieval route is designed separately.
CREATE TABLE checkpoint_unpublished (
    workspace_id TEXT NOT NULL, restore_id TEXT NOT NULL, target_hash TEXT NOT NULL,
    device_id TEXT NOT NULL, person_id TEXT NOT NULL, reason TEXT NOT NULL,
    cursor INTEGER NOT NULL, digest TEXT NOT NULL,
    PRIMARY KEY(workspace_id, restore_id, device_id, person_id)
);
-- P3-D29: a person first known from self-certified restore evidence. The account row exists
-- only so the revoked device and its revocation can be stored; it grants nothing until the
-- person creates the account by invite.
CREATE TABLE evidence_persons (
    person_id TEXT PRIMARY KEY REFERENCES accounts(person_id)
);
