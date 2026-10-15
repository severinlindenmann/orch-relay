-- P3-D39 (D39a1; amendment A1): Drop objects, versions, wraps, the device-only audience and the
-- charged usage (P3 design §14.5). Ids are lower-case hex, times integer ms of the relay clock,
-- signed objects and wrap records stored as their cj text. Blobs live in files under
-- <data>/drop/blobs/<o>/<v>.<rand> (the path relative to drop/blobs is in blob_path).
CREATE TABLE drop_objects (
    object_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,            -- space_id (space_kind 'workspace' only in P4)
    owner_person_id TEXT NOT NULL,         -- the space's card owner: the account quota
    object_kind TEXT NOT NULL CHECK (object_kind IN ('file', 'document')),
    current INTEGER NOT NULL CHECK (current >= 1),
    inbox INTEGER NOT NULL CHECK (inbox IN (0, 1)),
    claimed_by TEXT,                        -- §10.5; NULL until claimed (D39b)
    expires_ms INTEGER,                     -- the head's; NULL for a document without expiry
    tombstone_ms INTEGER,                   -- set when retired (now) or expired (= expires_ms); row deleted 30 d later
    tombstone_kind TEXT CHECK (tombstone_kind IN ('expired', 'retired')),  -- the list state (A1)
    head_author_id TEXT NOT NULL,           -- the newest version's author: `direction` without a descriptor (A1)
    head_hash TEXT NOT NULL,                -- the newest version's parent_hash_next: retire's expect_head (A1)
    audience TEXT NOT NULL CHECK (audience IN ('space', 'inbox', 'devices')),  -- the newest version's recipients kind (A1, R2)
    n INTEGER NOT NULL,                     -- latest change position (version, wrap, claim, state change)
    created_ms INTEGER NOT NULL,
    CHECK ((tombstone_ms IS NULL) = (tombstone_kind IS NULL))
);
-- The device-only `recipients` list of the newest version (audience = 'devices'), one row per listed
-- device plus the newest version's device author (A1): the list, read and PUT step 6 filters use it
-- without parsing descriptors. Visibility is keyed on drop_objects.audience, never on whether rows
-- exist: 'devices' with no row for a device hides the object from it. Rows exist only for 'devices';
-- a new version's commit replaces them; membership removal and revocation never touch them; an expiry
-- tombstoning deletes them; a retired tombstone keeps them until the object row is deleted. Charged as
-- head bytes at 65 B each (P3-D39 item 8: workspace, global and, while live, the author device's share);
-- at most the workspace's member devices per object. The relay knows nothing of tickets.
CREATE TABLE drop_audience (
    object_id TEXT NOT NULL REFERENCES drop_objects(object_id) ON DELETE CASCADE,
    device_id TEXT NOT NULL,
    PRIMARY KEY (object_id, device_id)
);
-- The list scan: in P4 an object is visible only within its own workspace (P3-D39 item 4),
-- so no per-object access table is needed (Opus M1).
CREATE INDEX drop_objects_scan ON drop_objects(workspace_id, n);
CREATE INDEX drop_objects_expiry ON drop_objects(expires_ms)
    WHERE expires_ms IS NOT NULL AND tombstone_ms IS NULL;
CREATE INDEX drop_objects_tombstone ON drop_objects(tombstone_ms) WHERE tombstone_ms IS NOT NULL;

CREATE TABLE drop_versions (
    object_id TEXT NOT NULL REFERENCES drop_objects(object_id) ON DELETE CASCADE,
    version INTEGER NOT NULL CHECK (version >= 1),
    author_kind TEXT NOT NULL CHECK (author_kind IN ('device', 'workspace')),
    author_id TEXT NOT NULL,
    descriptor TEXT NOT NULL,               -- the signed drop_object, cj
    parent_hash_next TEXT NOT NULL,         -- b64u H("orch/v2/drop-parent|" || cj(o)): the next version's parent_hash
    content_hash TEXT NOT NULL,
    content_len INTEGER NOT NULL,
    head_len INTEGER NOT NULL,
    descriptor_len INTEGER NOT NULL,        -- bytes of descriptor: the page byte cut without parsing
    blob TEXT NOT NULL CHECK (blob IN ('stored', 'pruned')),
    blob_path TEXT,                         -- '<o>/<v>.<rand>' under drop/blobs; NULL once pruned
    received_ms INTEGER NOT NULL,
    PRIMARY KEY (object_id, version)
);
CREATE INDEX drop_versions_author ON drop_versions(author_id);

CREATE TABLE drop_wraps (
    object_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    target_kind TEXT NOT NULL CHECK (target_kind IN ('wk', 'wxk', 'device')),
    target_id TEXT NOT NULL,
    key_version INTEGER NOT NULL,
    record TEXT NOT NULL,                   -- the wrap record, cj
    PRIMARY KEY (object_id, version, target_kind, target_id, key_version),
    FOREIGN KEY (object_id, version) REFERENCES drop_versions(object_id, version) ON DELETE CASCADE
);
CREATE INDEX drop_wraps_target ON drop_wraps(target_kind, target_id);

-- Charged usage; scope 'workspace' | 'account' | 'device' (key "ws:device") | 'global' (id '').
-- Blob bytes and head bytes are separate quotas (Opus M4); head_bytes includes every stored wrap (L5)
-- and the audience rows at 65 B each. D39a1 charges; D39a2 enforces the caps and reserves.
CREATE TABLE drop_usage (
    scope TEXT NOT NULL,
    id TEXT NOT NULL,
    blob_bytes INTEGER NOT NULL CHECK (blob_bytes >= 0),
    head_bytes INTEGER NOT NULL CHECK (head_bytes >= 0),
    versions INTEGER NOT NULL CHECK (versions >= 0),       -- live versions (blob stored)
    documents INTEGER NOT NULL CHECK (documents >= 0),     -- documents not tombstoned
    PRIMARY KEY (scope, id)
);

-- The relay-wide change position (D39a1 judgement call, not in the §14.5 sketch): `n` must never be
-- reused, but drop_objects rows are deleted when their tombstone ends, so max(n) cannot serve.
CREATE TABLE drop_counter (
    id INTEGER PRIMARY KEY CHECK (id = 0),
    n INTEGER NOT NULL CHECK (n >= 0)
);
INSERT INTO drop_counter VALUES (0, 0);

-- Descriptors are immutable once stored (the 0016 audit-table pattern): no UPDATE of the signed
-- columns, and no REPLACE (which deletes without a DELETE trigger) over an existing version.
CREATE TRIGGER drop_versions_immutable
BEFORE UPDATE OF object_id, version, author_kind, author_id, descriptor, parent_hash_next,
                 content_hash, content_len, head_len, descriptor_len, received_ms ON drop_versions
BEGIN SELECT RAISE(ABORT, 'drop_versions is immutable'); END;
CREATE TRIGGER drop_versions_no_replace
BEFORE INSERT ON drop_versions
WHEN EXISTS (SELECT 1 FROM drop_versions WHERE object_id = NEW.object_id AND version = NEW.version)
BEGIN SELECT RAISE(ABORT, 'drop_versions is immutable'); END;
