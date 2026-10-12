-- P3-D30 (orch-52 rulings 2 and 3): a new registration of a device id (PUT /v2/devices/{device},
-- POST /v2/accounts) is refused when any workspace's chain holds a revocation of that id, whatever
-- the person, and GET /v2/devices/{device}/revocation reads the chain evidence of each pair. Both
-- look up checkpoint_revocations by device id, which its primary key (leading workspace_id) cannot
-- serve. No column is added: the per-pair list joins the registry, accounts and this table. The
-- runner applies this file once, in its own transaction; IF NOT EXISTS keeps a re-run harmless.
CREATE INDEX IF NOT EXISTS checkpoint_revocation_device ON checkpoint_revocations(device_id, person_id);
