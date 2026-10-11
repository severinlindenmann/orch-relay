CREATE TABLE membership_receipts (
    workspace_id TEXT NOT NULL, request_digest TEXT NOT NULL,
    accepted_ms INTEGER NOT NULL, list_seq INTEGER NOT NULL, epoch INTEGER NOT NULL,
    PRIMARY KEY(workspace_id, request_digest)
);
CREATE INDEX membership_receipt_expiry ON membership_receipts(workspace_id, accepted_ms);
