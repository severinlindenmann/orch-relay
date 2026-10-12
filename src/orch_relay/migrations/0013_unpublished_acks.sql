-- P3-D31: retrieval of unpublished revocation evidence. The view itself is derived (revocations,
-- ever_devices, devices and checkpoint_revocations); only the host's acknowledgement is stored. It is
-- a per-workspace high-water mark of §19.5 cursors that drives notices.unpublished and nothing else:
-- it never retires, hides or deletes an item. gen and at_ms record the holder generation and time of
-- the last raise. checkpoint_unpublished is kept but no longer written (the view replaces it).
CREATE TABLE unpublished_acks (
    workspace_id TEXT PRIMARY KEY, cursor INTEGER NOT NULL, gen INTEGER NOT NULL,
    at_ms INTEGER NOT NULL
);
