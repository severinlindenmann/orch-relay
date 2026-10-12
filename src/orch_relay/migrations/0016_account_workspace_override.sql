-- P3-D36 (review F2, pre-public checklist item 4): an audited per-account override of the
-- workspaces-per-account cap (ORCH_RELAY_ACCOUNT_WORKSPACES). Written only by the operator command
-- `orch-relay account-cap set` (never an HTTP route), override and audit row in one transaction.
CREATE TABLE account_workspace_override (
    person_id TEXT PRIMARY KEY,
    cap INTEGER NOT NULL CHECK (typeof(cap) = 'integer' AND cap BETWEEN 1 AND 10000),
    set_by TEXT NOT NULL,
    set_at_ms INTEGER NOT NULL,
    note TEXT
);
-- Append-only: every change of an override, oldest first (old_cap NULL: no override before).
CREATE TABLE account_workspace_override_audit (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    person_id TEXT NOT NULL,
    old_cap INTEGER,
    new_cap INTEGER NOT NULL,
    set_by TEXT NOT NULL,
    set_at_ms INTEGER NOT NULL,
    note TEXT
);
CREATE TRIGGER account_workspace_override_audit_no_update
BEFORE UPDATE ON account_workspace_override_audit
BEGIN
    SELECT RAISE(ABORT, 'account_workspace_override_audit is append-only');
END;
CREATE TRIGGER account_workspace_override_audit_no_delete
BEFORE DELETE ON account_workspace_override_audit
BEGIN
    SELECT RAISE(ABORT, 'account_workspace_override_audit is append-only');
END;
