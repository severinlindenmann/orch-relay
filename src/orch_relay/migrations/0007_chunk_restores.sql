-- P3-D27: how often an expired, byte-identical response chunk was stored again. Durable, so the
-- per-chunk restoration cap survives a relay restart; it lives and dies with the rid_seen record.
ALTER TABLE rid_chunks ADD COLUMN restores INTEGER NOT NULL DEFAULT 0;
