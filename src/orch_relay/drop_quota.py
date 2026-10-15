"""Drop quotas and reservations (P3-D39 item 8, D39a2 part 1; P3 design §14.2, §14.5).

What is bounded, and where. `drop_usage` (0017) holds the charged usage per scope: `workspace`,
`global`, `account` (blob bytes and live versions only) and `device` (the author device's share in
one workspace, key "workspace:device"; only device-authored versions charge it). The caps live here
(`Quotas`), not in CHECKs, so they can be configured and tested small.

Two checks, one authority. A `PUT` is checked twice against the same caps:
 - at step 9, before it reads a blob byte, against the committed usage of a read snapshot plus the
   in-memory *reservations* of the uploads in flight (event loop only, no await between the check
   and the take), so a refused upload costs no bandwidth and concurrent uploads cannot all pass on
   one free slice of quota;
 - in the commit's write transaction, against the live `drop_usage` rows, **without** reservations.
   The commit is the authority: under the directory's single writer the rows it reads are exactly
   what it charges onto, so no interleaving of snapshots, reservations and releases can overshoot a
   cap. A reservation is only an early refusal; a crash drops them with the temp files.

Refusals (item 8): a stored-bytes cap is 429 `quota_exceeded` naming the cap in `quota`, with
`Retry-After: 600` (the sweep period; not transient: it stays until expiry, pruning or a retire
frees usage); a global ceiling is 503 `overloaded`, `Retry-After: 600`. The version-1 creation rate
(1 000 per workspace and 250 per device per UTC day) is 429 `rate_limited`, `Retry-After` the
seconds to the next 00:00 UTC, charged by an upsert in the commit transaction only.
"""

from collections import Counter

from .bridge import refuse

KIB, MIB, GIB = 1024, 1024 * 1024, 1024 * 1024 * 1024
DAY_MS = 86_400_000
AUDIENCE_ROW = 65  # head bytes per drop_audience row (the D39a1 constant, kept in one place)
SWEEP = 600  # Retry-After of a stored-bytes 429 and of a global 503 (the expiry sweep period)

FIELDS = ("blob", "head", "versions", "documents")


class Quotas:
    """The caps of item 8. The two global ceilings come from the environment
    (`ORCH_RELAY_DROP_GLOBAL_BYTES`, default 4 GiB public; `ORCH_RELAY_DROP_GLOBAL_HEAD_BYTES`,
    default 512 MiB public; 1 GiB and 128 MiB are recommended for the internal instance); the rest
    are fixed defaults that tests set per instance."""

    def __init__(self, env):
        self.global_blob = _env_int(env, "ORCH_RELAY_DROP_GLOBAL_BYTES", 4 * GIB)
        self.global_head = _env_int(env, "ORCH_RELAY_DROP_GLOBAL_HEAD_BYTES", 512 * MIB)
        self.ws_blob, self.ws_head = 512 * MIB, 32 * MIB
        self.ws_versions, self.ws_documents = 4096, 256
        self.account_blob = 1 * GIB
        # Per-(device, workspace) shares (Opus N5): one `operate` member cannot lock the workspace.
        self.dev_blob, self.dev_head = 256 * MIB, 8 * MIB
        self.dev_versions, self.dev_documents = 1024, 64
        self.doc_versions = 1024  # one document's chain (the phone's cap); no per-member share
        self.ws_creations, self.dev_creations = 1000, 250  # version-1 creations per UTC day

    def limits(self, ws, owner, device):
        """The ordered checks for an upload: (usage key, field, cap, name, status). The author's
        own share first (so a member learns it is its own share), then the workspace, the account
        and, last, the global ceilings (503)."""
        out = []
        if device is not None:
            key = ("device", f"{ws}:{device}")
            out += [
                (key, "blob", self.dev_blob, "drop_device", 429),
                (key, "head", self.dev_head, "drop_device_head", 429),
                (key, "versions", self.dev_versions, "drop_device_versions", 429),
                (key, "documents", self.dev_documents, "drop_device_documents", 429),
            ]
        key = ("workspace", ws)
        out += [
            (key, "blob", self.ws_blob, "drop_ws", 429),
            (key, "head", self.ws_head, "drop_head_ws", 429),
            (key, "versions", self.ws_versions, "drop_versions", 429),
            (key, "documents", self.ws_documents, "drop_documents", 429),
            (("account", owner), "blob", self.account_blob, "drop_account", 429),
            (("global", ""), "blob", self.global_blob, "drop_global", 503),
            (("global", ""), "head", self.global_head, "drop_global_head", 503),
        ]
        return out


def _env_int(env, name, default):
    raw = env.get(name)
    if raw is None:
        return default
    if not raw.isdecimal() or int(raw) < 1:
        raise ValueError(f"{name} must be a positive decimal integer")
    return int(raw)


class Need:
    """What one stored version charges (mirrors `Drop.insert`): blob bytes, head bytes
    (descriptor, every wrap, 65 B per audience row), one live version and, for the first version
    of a document, one document. Gross: the audience rows a new document version releases are not
    netted off at admission (a conservative bound; the exact charge is in the commit)."""

    def __init__(self, blob, head, versions=1, documents=0):
        self.blob, self.head, self.versions, self.documents = blob, head, versions, documents

    @classmethod
    def of(cls, plan, new_document):
        o = plan.o
        head = (
            len(plan.descriptor.encode())
            + sum(len(t.encode()) for t in plan.wrap_texts)
            + AUDIENCE_ROW * len(plan.devices)
        )
        return cls(o["content_len"], head, 1, int(new_document))

    def get(self, field):
        return getattr(self, field)


def usage_keys(ws, owner, device):
    keys = [("workspace", ws), ("global", ""), ("account", owner)]
    if device is not None:
        keys.append(("device", f"{ws}:{device}"))
    return keys


def read_usage(con, keys):
    """Committed usage per key (a missing row is zero): {key: {field: int}}."""
    out = {}
    for scope, ident in keys:
        row = con.execute(
            "SELECT blob_bytes, head_bytes, versions, documents FROM drop_usage "
            "WHERE scope=? AND id=?",
            (scope, ident),
        ).fetchone()
        out[(scope, ident)] = (
            dict(zip(FIELDS, row, strict=True)) if row else dict.fromkeys(FIELDS, 0)
        )
    return out


def check(quotas, usage, reserved, need, ws, owner, device, o):
    """Refuse the upload when it would pass a cap: `usage` (committed, per key) plus `reserved`
    (in-flight reservations, or empty) plus `need`. A field the upload does not add to is not
    checked, so an operator lowering a cap never blocks a write that adds nothing there."""
    if o["object_kind"] == "document" and o["version"] > quotas.doc_versions:
        refuse("quota_exceeded", 429, SWEEP, quota="drop_doc_versions")
    for key, field, cap, name, status in quotas.limits(ws, owner, device):
        add = need.get(field)
        if add <= 0:
            continue
        held = usage[key][field] + reserved.get(key, {}).get(field, 0)
        if held + add > cap:
            if status == 503:
                refuse("overloaded", 503, SWEEP)
            refuse("quota_exceeded", 429, SWEEP, quota=name)


class Reservations:
    """In-memory reservations of the uploads in flight, touched on the event loop only. `take`
    adds an upload's `Need` to every scope it will charge and returns a token; `release` (in the
    request's `finally`, also on a disconnect or a cancellation) removes it."""

    def __init__(self):
        self.held = {}  # key -> Counter(field -> amount)

    def view(self):
        return self.held

    def take(self, keys, need):
        for key in keys:
            row = self.held.setdefault(key, Counter())
            for field in FIELDS:
                row[field] += need.get(field)
        return (tuple(keys), need)

    def release(self, token):
        keys, need = token
        for key in keys:
            row = self.held[key]
            for field in FIELDS:
                row[field] -= need.get(field)
            if not any(row.values()):
                del self.held[key]


# --- the daily creation counters ---------------------------------------------------------------


def day_of(now_ms):
    return now_ms // DAY_MS


def seconds_to_midnight(now_ms):
    """Whole seconds from `now_ms` to the next 00:00 UTC, at least 1 and at most 86 400."""
    return max(1, min(86_400, -(-(DAY_MS - now_ms % DAY_MS) // 1000)))


def creation_scopes(quotas, ws, device):
    scopes = [("workspace", ws, quotas.ws_creations)]
    if device is not None:
        scopes.append(("device", f"{ws}:{device}", quotas.dev_creations))
    return scopes


def creations_left(con, quotas, ws, device, day):
    """A non-charging read for step 9 (the early refusal): True when both counters have room."""
    for scope, ident, cap in creation_scopes(quotas, ws, device):
        row = con.execute(
            "SELECT creations FROM drop_creations WHERE scope=? AND id=? AND day=?",
            (scope, ident, day),
        ).fetchone()
        if row is not None and row[0] + 1 > cap:
            return False
    return True


def charge_creation(con, quotas, ws, device, day):
    """The commit's charge: an upsert per scope whose WHERE holds the cap; `changes() = 0` (the
    conflict branch's WHERE failed) refuses. All or nothing: a refusal at the second scope rolls
    back the first scope's charge to a savepoint, so the False answer leaves no partial charge
    whatever the caller does next."""
    con.execute("SAVEPOINT creation")
    for scope, ident, cap in creation_scopes(quotas, ws, device):
        con.execute(
            "INSERT INTO drop_creations (scope, id, day, creations) VALUES (?,?,?,1) "
            "ON CONFLICT (scope, id, day) DO UPDATE SET creations = creations + 1 "
            "WHERE creations + 1 <= ?",
            (scope, ident, day, cap),
        )
        if con.execute("SELECT changes()").fetchone()[0] == 0:
            con.execute("ROLLBACK TO creation")
            con.execute("RELEASE creation")
            return False
    con.execute("RELEASE creation")
    return True


def refuse_creations(now_ms):
    refuse("rate_limited", 429, seconds_to_midnight(now_ms))
