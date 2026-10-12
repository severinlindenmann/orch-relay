-- P3-D33 (G1): a final publication folds outside the global write lock and inserts its new log_nodes
-- in short chunks before its commit.
-- Heads folded by charged refusals of final publications, per workspace and rolling hour (budget by
-- work, next to the 16/48 refusal counts of checkpoint_failures).
CREATE TABLE checkpoint_refused_heads (
    workspace_id TEXT NOT NULL, at_ms INTEGER NOT NULL, heads INTEGER NOT NULL
);
CREATE INDEX checkpoint_refused_heads_window ON checkpoint_refused_heads(workspace_id, at_ms);
-- Stored log_nodes per workspace (the G4 storage quota's input), and how many of them were inserted
-- by a publication that was then not accepted (orphans: verified WSK-signed heads nothing references).
CREATE TABLE checkpoint_node_usage (
    workspace_id TEXT PRIMARY KEY, nodes INTEGER NOT NULL, orphaned INTEGER NOT NULL DEFAULT 0
);
INSERT INTO checkpoint_node_usage(workspace_id, nodes)
    SELECT workspace_id, count(*) FROM log_nodes GROUP BY workspace_id;
