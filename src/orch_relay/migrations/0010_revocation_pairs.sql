-- orch-core #397 (F1 §5.10, decision row 152): every verified revocation is retained per
-- (device_id, person_id). The 0002 table kept one person per device id (PRIMARY KEY device_id), so
-- a first-come row dropped another person's genuine revocation of the same id. Same columns and
-- order, so existing writers keep their shape; no foreign key to devices any more, because restore
-- evidence no longer registers its device (no first-come association). Existing rows keep their
-- cursor (the §19.5 feed position). Restore-signer refusal matches by pair; the device-auth cutoff
-- (sessions, member certificates, registration) still matches by device id.
CREATE TABLE revocation_pairs (
    device_id TEXT NOT NULL, person_id TEXT NOT NULL,
    record BLOB NOT NULL, reason TEXT NOT NULL, received_ms INTEGER NOT NULL,
    cursor INTEGER NOT NULL UNIQUE,
    PRIMARY KEY(device_id, person_id)
);
INSERT INTO revocation_pairs SELECT device_id, person_id, record, reason, received_ms, cursor
    FROM revocations;
DROP TABLE revocations;
ALTER TABLE revocation_pairs RENAME TO revocations;
CREATE INDEX revocation_feed ON revocations(person_id, cursor);
