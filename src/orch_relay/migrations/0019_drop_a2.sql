-- P3-D39 (D39a2; amendment A2, P3 design §14.5): the decide-class budget, the daily creation counters
-- and the claim time. 0018 stays D40a's; db.migrate applies by version set, so the landing order of
-- the two does not matter. The migration inserts nothing, so every restore route regenerates alike.

-- The decide-class budget (item 13): one row per (workspace, device, UTC day of the request's `now`),
-- charged at admission by an upsert (INSERT ... ON CONFLICT DO UPDATE ... WHERE; changes() = 0 means
-- refused), persisted so a restart does not refill it. The caps (50 creations, 64 MiB) live in the
-- upsert's WHERE, not in CHECKs, so they can be configured. D39a2's budget PR uses it; the periodic
-- sweep deletes rows older than the previous day.
CREATE TABLE drop_decide_budget (
    workspace_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    day INTEGER NOT NULL,                   -- floor(now_ms / 86400000)
    creations INTEGER NOT NULL CHECK (creations >= 0),
    bytes INTEGER NOT NULL CHECK (bytes >= 0),
    PRIMARY KEY (workspace_id, device_id, day)
);

-- Version-1 creations per UTC day (item 8 "rate of new objects"): scope 'workspace' (id = the
-- workspace, cap 1 000) or 'device' (id = "workspace:device", cap 250); the same shape and upsert as
-- the budget above, the caps again in the upsert's WHERE.
CREATE TABLE drop_creations (
    scope TEXT NOT NULL CHECK (scope IN ('workspace', 'device')),
    id TEXT NOT NULL,
    day INTEGER NOT NULL,
    creations INTEGER NOT NULL CHECK (creations >= 0),
    PRIMARY KEY (scope, id, day)
);

-- The claim time (item 7): the relay clock at the claim's commit, set once with claimed_by (D39b),
-- never changed. D39a2 alone owns the column and the trigger (one owner: no "duplicate column").
ALTER TABLE drop_objects ADD COLUMN claimed_ms INTEGER;
CREATE TRIGGER drop_objects_claimed_ms_immutable
BEFORE UPDATE OF claimed_ms ON drop_objects
WHEN OLD.claimed_ms IS NOT NULL AND NEW.claimed_ms IS NOT OLD.claimed_ms
BEGIN SELECT RAISE(ABORT, 'claimed_ms is immutable'); END;
-- No REPLACE over an existing object: it would delete the row and reset claimed_ms without firing
-- the update trigger. A BEFORE INSERT trigger fires before conflict resolution, so it also refuses
-- INSERT OR REPLACE, INSERT OR IGNORE and INSERT ... ON CONFLICT over an existing object (a future
-- idempotent insert checks existence first). Same pattern as drop_versions_no_replace.
CREATE TRIGGER drop_objects_no_replace
BEFORE INSERT ON drop_objects
WHEN EXISTS (SELECT 1 FROM drop_objects WHERE object_id = NEW.object_id)
BEGIN SELECT RAISE(ABORT, 'drop_objects is never replaced'); END;
