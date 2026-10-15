-- Empty device IDs are reserved for anonymous pairing accounting. Wire IDs
-- remain unchanged; workspace/global budgets include both kinds of traffic.
DROP TRIGGER bridge_insert;
DROP TRIGGER bridge_delete;
DROP TRIGGER bridge_delivery;
DELETE FROM queue_totals;
INSERT INTO queue_totals
SELECT workspace_id, CASE WHEN offer IS NULL THEN device_id ELSE '' END, direction,
 sum(length(body)), sum(length(body)*(1-delivered)), sum(1-delivered)
FROM bridge_msgs GROUP BY workspace_id, CASE WHEN offer IS NULL THEN device_id ELSE '' END, direction;
CREATE TRIGGER bridge_insert AFTER INSERT ON bridge_msgs BEGIN
 INSERT INTO queue_totals VALUES (NEW.workspace_id, (CASE WHEN NEW.offer IS NULL THEN NEW.device_id ELSE '' END), NEW.direction,
 length(NEW.body), length(NEW.body)*(1-NEW.delivered), 1-NEW.delivered)
 ON CONFLICT(workspace_id, device_id, direction) DO UPDATE SET
 bodies=bodies+length(NEW.body), pending=pending+length(NEW.body)*(1-NEW.delivered), count=count+1-NEW.delivered;
END;
CREATE TRIGGER bridge_delete AFTER DELETE ON bridge_msgs BEGIN
 UPDATE queue_totals SET bodies=bodies-length(OLD.body),
 pending=pending-length(OLD.body)*(1-OLD.delivered), count=count-1+OLD.delivered
 WHERE workspace_id=OLD.workspace_id AND device_id=(CASE WHEN OLD.offer IS NULL THEN OLD.device_id ELSE '' END) AND direction=OLD.direction;
 DELETE FROM queue_totals WHERE bodies=0;
END;
CREATE TRIGGER bridge_delivery AFTER UPDATE OF delivered ON bridge_msgs BEGIN
 UPDATE queue_totals SET pending=pending+length(NEW.body)*(OLD.delivered-NEW.delivered),
 count=count+OLD.delivered-NEW.delivered
 WHERE workspace_id=NEW.workspace_id AND device_id=(CASE WHEN NEW.offer IS NULL THEN NEW.device_id ELSE '' END) AND direction=NEW.direction;
END;
