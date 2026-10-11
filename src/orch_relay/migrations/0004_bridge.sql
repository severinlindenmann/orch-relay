-- G3: replay digests outlive bodies, including across relay restart.
CREATE TABLE rid_seen (
 workspace_id TEXT NOT NULL, device_id TEXT NOT NULL, rid TEXT NOT NULL,
 req_digest TEXT NOT NULL, req_epoch INTEGER NOT NULL, first_ms INTEGER NOT NULL,
 requeues INTEGER NOT NULL DEFAULT 0, last_requeue_ms INTEGER NOT NULL,
 keep_until_ms INTEGER NOT NULL, offer TEXT,
 PRIMARY KEY(workspace_id, device_id, rid)
);
CREATE INDEX rid_expiry ON rid_seen(keep_until_ms);
CREATE TABLE rid_chunks (
 workspace_id TEXT NOT NULL, device_id TEXT NOT NULL, rid TEXT NOT NULL,
 idx INTEGER NOT NULL, digest TEXT NOT NULL,
 PRIMARY KEY(workspace_id, device_id, rid, idx),
 FOREIGN KEY(workspace_id, device_id, rid) REFERENCES rid_seen ON DELETE CASCADE
);
CREATE TABLE bridge_msgs (
 n INTEGER PRIMARY KEY AUTOINCREMENT, workspace_id TEXT NOT NULL, device_id TEXT NOT NULL,
 rid TEXT NOT NULL, direction INTEGER NOT NULL, offer TEXT, idx INTEGER NOT NULL,
 flags INTEGER NOT NULL, stream TEXT NOT NULL, body BLOB NOT NULL,
 expires_ms INTEGER NOT NULL, delivered INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX bridge_route ON bridge_msgs(workspace_id, direction, device_id, rid, n);
CREATE INDEX bridge_expiry ON bridge_msgs(expires_ms);
CREATE TABLE request_mailboxes (
 workspace_id TEXT NOT NULL, device_id TEXT NOT NULL, rid TEXT NOT NULL,
 expires_ms INTEGER NOT NULL, PRIMARY KEY(workspace_id, device_id, rid)
);
CREATE TABLE queue_totals (
 workspace_id TEXT NOT NULL, device_id TEXT NOT NULL, direction INTEGER NOT NULL,
 bodies INTEGER NOT NULL DEFAULT 0, pending INTEGER NOT NULL DEFAULT 0,
 count INTEGER NOT NULL DEFAULT 0,
 PRIMARY KEY(workspace_id, device_id, direction)
);
CREATE TRIGGER bridge_insert AFTER INSERT ON bridge_msgs BEGIN
 INSERT INTO queue_totals VALUES (NEW.workspace_id, NEW.device_id, NEW.direction,
 length(NEW.body), length(NEW.body)*(1-NEW.delivered), 1-NEW.delivered)
 ON CONFLICT(workspace_id, device_id, direction) DO UPDATE SET
 bodies=bodies+length(NEW.body), pending=pending+length(NEW.body)*(1-NEW.delivered), count=count+1-NEW.delivered;
END;
CREATE TRIGGER bridge_delete AFTER DELETE ON bridge_msgs BEGIN
 UPDATE queue_totals SET bodies=bodies-length(OLD.body),
 pending=pending-length(OLD.body)*(1-OLD.delivered), count=count-1+OLD.delivered
 WHERE workspace_id=OLD.workspace_id AND device_id=OLD.device_id AND direction=OLD.direction;
 DELETE FROM queue_totals WHERE bodies=0;
END;
CREATE TRIGGER bridge_delivery AFTER UPDATE OF delivered ON bridge_msgs BEGIN
 UPDATE queue_totals SET pending=pending+length(NEW.body)*(OLD.delivered-NEW.delivered),
 count=count+OLD.delivered-NEW.delivered
 WHERE workspace_id=NEW.workspace_id AND device_id=NEW.device_id AND direction=NEW.direction;
END;
CREATE TABLE holder_delivery (
 workspace_id TEXT PRIMARY KEY, delivered INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE cert_requests (
 request_id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, person_id TEXT NOT NULL,
 primary_device_id TEXT NOT NULL, request BLOB NOT NULL, expires_ms INTEGER NOT NULL,
 state TEXT NOT NULL, challenge BLOB, cert BLOB, rejection BLOB
);
CREATE INDEX cert_queue_person ON cert_requests(person_id, state, expires_ms);
