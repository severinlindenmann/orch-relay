-- Webhook doorbells for orch follow-ups (orch-relay #81, design FU11-FU13). One row per hook:
-- only H(id) = SHA-256("orch/v2/hook|" || id) is stored, never the id, a body or a header. The first
-- ring sets rung_ms; later rings change nothing. The workspace host registers, revokes and fetches
-- with its W session; a hook never outlives expires_ms (at most 14 days after it was registered).
CREATE TABLE hooks (
    hook_hash TEXT PRIMARY KEY CHECK (length(hook_hash) = 64),
    workspace_id TEXT NOT NULL,
    created_ms INTEGER NOT NULL,
    expires_ms INTEGER NOT NULL,
    rung_ms INTEGER
);
CREATE INDEX hooks_workspace ON hooks(workspace_id);
CREATE INDEX hooks_expires ON hooks(expires_ms);
