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
-- REPLACE (and INSERT OR REPLACE) deletes a conflicting row without firing a DELETE trigger
-- (recursive_triggers is off), so a row naming an existing seq is refused here (review F1).
CREATE TRIGGER account_workspace_override_audit_no_replace
BEFORE INSERT ON account_workspace_override_audit
WHEN EXISTS (SELECT 1 FROM account_workspace_override_audit WHERE seq = NEW.seq)
BEGIN
    SELECT RAISE(ABORT, 'account_workspace_override_audit is append-only');
END;
