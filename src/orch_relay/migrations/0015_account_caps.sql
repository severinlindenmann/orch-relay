-- P3-D34 (G3, G4 pre-public-deploy gates): per-account caps.
-- The owner's workspaces, for the per-account staged-bytes cap and the live-workspace cap.
CREATE INDEX workspace_owner ON workspaces(owner_person_id);
-- Distinct self-certified revocation pairs (a device without association, a pair new to the
-- global revocations table) that an owner person's accepted restores added to the global table.
-- Re-carrying a pair the table already holds is never counted.
CREATE TABLE account_evidence_pairs (
    person_id TEXT PRIMARY KEY, pairs INTEGER NOT NULL
);
-- Backfill (approximate: a pair first carried by another owner is counted for each owner whose
-- workspaces carried it): the distinct self-certified chain pairs of each owner's workspaces.
INSERT INTO account_evidence_pairs(person_id, pairs)
    SELECT w.owner_person_id, count(DISTINCT r.device_id || ':' || r.person_id)
    FROM checkpoint_revocations r JOIN workspaces w ON w.workspace_id = r.workspace_id
    WHERE NOT EXISTS (
        SELECT 1 FROM devices d WHERE d.device_id = r.device_id
        AND NOT EXISTS (SELECT 1 FROM evidence_persons e WHERE e.person_id = d.person_id))
    GROUP BY w.owner_person_id;
