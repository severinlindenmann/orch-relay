-- orch-relay E3 (orch-core#896): the per-workspace "cut over to hub" switch. One row per workspace that named a hub.
-- `pending`: the workspace (its own signed session) said it will join `hub_id`; nothing changes on the direct path.
-- `cut_over`: from `cut_over_ms` the direct path (bridge envelopes, pairing, push registrations, push sends) is refused
-- with `cut_over`; the mailbox stays readable until `drain_until_ms`, then it is purged (`purged_ms`) and refused too.
-- `set_by` records who made the last change. Reversal (row deleted) is the workspace's own act only. Public data only.
CREATE TABLE IF NOT EXISTS workspace_cutover (
    workspace_id TEXT PRIMARY KEY CHECK (length(workspace_id) = 32),
    hub_id TEXT NOT NULL CHECK (length(hub_id) = 32),
    state TEXT NOT NULL CHECK (state IN ('pending', 'cut_over')),
    set_by TEXT NOT NULL CHECK (set_by IN ('workspace', 'hub')),
    requested_ms INTEGER NOT NULL,
    cut_over_ms INTEGER,
    drain_until_ms INTEGER,
    purged_ms INTEGER,
    CHECK ((state = 'cut_over') = (cut_over_ms IS NOT NULL AND drain_until_ms IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS workspace_cutover_drain ON workspace_cutover (drain_until_ms)
    WHERE state = 'cut_over' AND purged_ms IS NULL;
