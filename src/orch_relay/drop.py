"""Drop at the relay (P3-D39, D39a1): protocol-v2 §19.9, P3 design §14.2.

Write and read of Drop objects. The routes are plain ASGI endpoints (not the buffering request /
response endpoints of the JSON routes): the `PUT` reads one streamed `ODU2` frame, checks the head
before any blob byte is read, can answer early and then drain the declared remainder in its own
pool, and streams the blob to a temporary file whose writes, hashing and `fsync` run off the event
loop through a dedicated limiter (16 tokens). The commit runs under the directory lock in one write
transaction that re-checks the fence and every state check against live rows.

Check order of the `PUT` (§14.2 item 3; each refusal stops, nothing is stored before step 11):
 1 transport (Content-Length, declared cap, query) - 2 session, principal, fence at admission,
 the read bucket, an upload slot - 3 If-Match - 4 frame and head - 5 descriptor - 6 object state
 (another space, a device outside a device-only audience: 403; a tombstone: 410) - 7 exact retry -
 8 CAS - 9 wraps - 10 blob - 11 commit (fence, then 5's eligibility, 6, 7, 8, 9 on live rows).

Lock order: the in-memory slot tables (event loop only), then Directory.lock, then Directory.budget;
a pooled read connection is never held while taking the lock. Quotas, reservations and the MiB
buckets are drop_quota.py (D39a2 part 1: reserved at step 9, enforced in the commit); the sweepers
beyond the start-up sweep, retire, decide-class uploads and list walks are later D39a2 parts; claims
and host re-wraps are D39b.
"""

import asyncio
import hashlib
import inspect
import logging
import os
import re
import secrets
import sqlite3
import time
from collections import Counter
from contextlib import suppress
from pathlib import Path

import anyio
import anyio.to_thread
from starlette.concurrency import run_in_threadpool
from starlette.routing import Route

from . import proto as P
from .bridge import refuse
from .directory import DAY, Refusal, fail, pair_revoked
from .drop_quota import (
    AUDIENCE_ROW,
    Need,
    Quotas,
    Reservations,
    charge_creation,
    check,
    creations_left,
    day_of,
    read_usage,
    refuse_creations,
    usage_keys,
)

log = logging.getLogger(__name__)

KIB, MIB = 1024, 1024 * 1024
MAGIC = b"ODU2"
MAX_HEAD = 512 * KIB
MAX_DESCRIPTOR = 96 * KIB
MAX_META = 64 * KIB + 16
MAX_WRAPS = 1024
MAX_WRAP = 512
MAX_RECIPIENTS = 1024
ORD2 = b"ORD2"
ORD2_HEADER = 40
MAX_CHUNK = 64 * MIB
DEFAULT_MAX_BLOB = 26 * MIB  # ORCH_RELAY_DROP_MAX_BLOB_BYTES, 1..256 MiB
DEFAULT_MAX_TTL = 604_800_000  # ORCH_RELAY_DROP_MAX_TTL_MS
SKEW = 300_000
MIN_FILE_LIFE = 60_000  # amendment A1, Opus delta R3
TOMBSTONE = 30 * DAY
LIST_LIMIT, LIST_BYTES, LIST_JSON_CAP = 64, 2 * MIB, 16 * KIB
PAGE_LIMIT, PAGE_BYTES = 256, 1 * MIB
IO = 64 * KIB
FILE_TOKENS = 16
WRAP_LEN = {"wk": 16 + 32 + 16, "wxk": 65 + 32 + 16, "device": 65 + 32 + 16}
DESCRIPTOR_FIELDS = {
    "v",
    "suite",
    "kind",
    "object_id",
    "space_id",
    "space_kind",
    "object_kind",
    "version",
    "parent",
    "parent_hash",
    "author_kind",
    "author_id",
    "content_hash",
    "content_len",
    "dek_commit",
    "meta",
    "recipients",
    "origin",
    "created_ms",
    "expires_ms",
}
WRAP_FIELDS = {"object_id", "version", "target_kind", "target_id", "key_version", "wrap"}
DECIMAL = re.compile(r"0|[1-9][0-9]{0,15}")
HEX32 = re.compile(r"[0-9a-f]{32}")


class Limits:
    """Transfer and drain bounds (§14.2 items 2 and 8); tests shorten them per instance."""

    idle = 30.0  # seconds between body reads or writes
    min_rate = 64 * KIB  # bytes per second, averaged after the head
    grace = 30.0  # seconds before the average rate is judged
    max_transfer = 600.0  # from the upload slot to the last byte (review F2)
    head_s = 30.0  # the frame and the head, from the upload slot (review F2)
    drain_idle = 5.0
    drain_total = 30.0
    brief_bytes = 64 * KIB  # refusals before a slot: read at most this much, or brief_s
    brief_s = 1.0


class Slots:
    """Counting slots with per-key caps, touched on the event loop only. `take` refuses 429
    `quota_exceeded` (`"quota": "slot"`) at a key's cap and 503 `overloaded` at the total."""

    def __init__(self, total, caps):
        self.total, self.caps = total, caps
        self.used = Counter()
        self.count = 0

    def free(self, keys):
        return self.count < self.total and all(self.used[k] < self.caps[k[0]] for k in keys)

    def take(self, keys):
        for key in keys:
            if self.used[key] >= self.caps[key[0]]:
                refuse("quota_exceeded", 429, 1, quota="slot")
        if self.count >= self.total:
            refuse("overloaded", 503, 1)
        for key in keys:
            self.used[key] += 1
        self.count += 1
        return list(keys)

    def release(self, keys):
        for key in keys:
            self.used[key] -= 1
            if not self.used[key]:
                del self.used[key]
        self.count -= 1


class Disconnected(Exception):
    """The client went away (http.disconnect)."""


class Breach(Exception):
    """A transfer bound was breached: idle, minimum rate or maximum duration."""


def no(code, status, **details):
    refuse(code, status, 1 if status in (429, 503) else None, **details)


def need(ok, code="malformed", status=400, **details):
    if not ok:
        no(code, status, **details)


def b64(value, length=None):
    try:
        return P.unb64u(value, length)
    except (ValueError, TypeError):
        fail("malformed")


def hex32(value):
    need(isinstance(value, str) and HEX32.fullmatch(value) is not None)
    return value


def integer(value, low=0, high=P.MAX_SAFE_INT):
    need(type(value) is int and low <= value <= high)
    return value


def parent_hash(o):
    return P.b64u(hashlib.sha256(P.L["h_drop_parent"] + P.cj(o)).digest())


def if_match(text):
    """§10.6/§19.9: the bare decimal or its quoted form; anything else (absent, lists, `*`, W/)
    is 428 `precondition_required`."""
    if text is not None and len(text) >= 2 and text[0] == text[-1] == '"':
        text = text[1:-1]
    if text is None or not DECIMAL.fullmatch(text) or int(text) > P.MAX_SAFE_INT:
        no("precondition_required", 428)
    return int(text)


def tombstone_until(row, now):
    """The tombstone's end (ms), or None while the object is live (§14.2 item 7)."""
    if row["tombstone_ms"] is not None:
        return row["tombstone_ms"] + TOMBSTONE
    if row["expires_ms"] is not None and row["expires_ms"] <= now:
        return row["expires_ms"] + TOMBSTONE  # expired, before the sweep (A1)
    return None


def state_of(row, blob, now):
    if row["tombstone_kind"] is not None:
        return row["tombstone_kind"]
    if row["expires_ms"] is not None and row["expires_ms"] <= now:
        return "expired"
    return "pruned" if blob == "pruned" else "live"


def env_int(env, name, default, low, high):
    raw = env.get(name)
    if raw is None:
        return default
    if not re.fullmatch(r"[0-9]+", raw) or not low <= int(raw) <= high:
        raise ValueError(f"{name} must be a decimal integer in {low}..{high}")
    return int(raw)


class Plan:
    """A checked head: the descriptor, its wraps and what the commit inserts."""

    def __init__(self, signed, records, head_len):
        self.signed, self.o, self.records, self.head_len = signed, signed["o"], records, head_len
        self.descriptor = P.cj(signed).decode()
        self.wrap_texts = [P.cj(r).decode() for r in records]
        o = self.o
        self.inbox = o["recipients"] == "inbox"
        if self.inbox:
            self.audience, self.devices = "inbox", []
        elif o["space_id"] in o["recipients"]:
            self.audience, self.devices = "space", []
        else:
            self.audience = "devices"
            self.devices = sorted(
                set(o["recipients"]) | ({o["author_id"]} if o["author_kind"] == "device" else set())
            )


class Drop:
    def __init__(self, directory, bridge, data, env=None):
        env = os.environ if env is None else env
        self.d, self.bridge = directory, bridge
        self.root = Path(data) / "drop"
        self.tmp, self.blobs = self.root / "tmp", self.root / "blobs"
        self.max_blob = env_int(
            env, "ORCH_RELAY_DROP_MAX_BLOB_BYTES", DEFAULT_MAX_BLOB, 1, 256 * MIB
        )
        self.max_ttl = env_int(
            env, "ORCH_RELAY_DROP_MAX_TTL_MS", DEFAULT_MAX_TTL, 1, 10 * 365 * DAY
        )
        self.max_body = 8 + MAX_HEAD + self.max_blob
        # Item 8: the caps (drop_quota.py). Parsed only with Drop on: with it off nothing of Drop
        # runs, so a bad ORCH_RELAY_DROP_GLOBAL_* value cannot abort a start (D39a2 review L6).
        self.quotas = Quotas(env) if enabled(env) else Quotas({})
        self.reserved = Reservations()  # in-flight upload reservations, event loop only
        self.limits = Limits()
        self.files = None  # anyio.CapacityLimiter(FILE_TOKENS), made on the event loop
        self.uploads = Slots(16, {"device": 2, "person": 3, "workspace": 4})
        self.downloads = Slots(32, {"device": 4, "person": 8})
        self.reads = Slots(8, {"device": 2, "person": 4})
        self.drains = Slots(32, {"device": 2})
        self.hooks = {}  # tests: "head", "before_commit", "drain", "answered"

    async def hook(self, name, **info):
        """Test hooks at the PUT's phase boundaries; a hook may be a coroutine function."""
        if name in self.hooks:
            result = self.hooks[name](**info)
            if inspect.isawaitable(result):
                await result

    def limiter(self):
        if self.files is None:
            self.files = anyio.CapacityLimiter(FILE_TOKENS)
        return self.files

    async def io(self, fn, *args):
        return await anyio.to_thread.run_sync(fn, *args, limiter=self.limiter())

    # --- storage ---------------------------------------------------------------------------------

    def prepare_dirs(self):
        for path in (self.root, self.tmp, self.blobs):
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
            os.chmod(path, 0o700)

    def startup_sweep(self):
        """Before serving (§14.5): delete tmp/*, blob files without a `stored` row, and mark a
        `stored` row whose file is missing as `pruned` (error log), releasing its blob bytes and
        its wraps, with a new `n` when it is the object's newest version (list state `pruned`).
        Also makes a database restored without `data/drop/` consistent."""
        self.prepare_dirs()
        for entry in self.tmp.iterdir():
            with suppress(OSError):
                entry.unlink()
        with self.d.lock:
            con = self.bridge.connection("write")
            con.execute("BEGIN IMMEDIATE")
            with con:
                known = set()
                for row in self.stored_rows(con):
                    path = self.blobs / row["blob_path"]
                    if path.is_file():
                        known.add(row["blob_path"])
                        continue
                    log.error("drop blob missing, pruned: %s/%s", row["object_id"], row["version"])
                    con.execute("SAVEPOINT prune")
                    try:
                        self.prune(con, row)
                    except sqlite3.Error:  # one bad row never wedges the start (item 12)
                        log.exception("drop prune failed: %s/%s", row["object_id"], row["version"])
                        con.execute("ROLLBACK TO prune")
                    con.execute("RELEASE prune")
        for folder in list(self.blobs.iterdir()):
            if not folder.is_dir():
                with suppress(OSError):
                    folder.unlink()
                continue
            for entry in list(folder.iterdir()):
                if f"{folder.name}/{entry.name}" not in known:
                    with suppress(OSError):
                        entry.unlink()
            with suppress(OSError):
                folder.rmdir()  # only when empty

    @staticmethod
    def stored_rows(con, batch=1024):
        """The `stored` versions in key order, in batches of `batch` rows and only the columns the
        sweep needs (never a descriptor: review F5, a start-up must not load every head)."""
        last = ("", 0)
        while True:
            rows = con.execute(
                "SELECT v.object_id, v.version, v.author_kind, v.author_id, v.content_len, "
                "v.blob_path, o.workspace_id, o.owner_person_id, o.current, o.tombstone_ms "
                "FROM drop_versions v JOIN drop_objects o ON o.object_id=v.object_id "
                "WHERE v.blob='stored' AND (v.object_id, v.version) > (?, ?) "
                "ORDER BY v.object_id, v.version LIMIT ?",
                (*last, batch),
            ).fetchall()
            yield from rows
            if len(rows) < batch:
                return
            last = (rows[-1]["object_id"], rows[-1]["version"])

    def prune(self, con, row):
        o, v = row["object_id"], row["version"]
        wrap_bytes = con.execute(
            "SELECT coalesce(sum(length(record)),0) FROM drop_wraps WHERE object_id=? AND version=?",
            (o, v),
        ).fetchone()[0]
        con.execute("DELETE FROM drop_wraps WHERE object_id=? AND version=?", (o, v))
        con.execute(
            "UPDATE drop_versions SET blob='pruned', blob_path=NULL WHERE object_id=? AND version=?",
            (o, v),
        )
        device = row["author_id"] if row["author_kind"] == "device" else None
        self.charge(
            con,
            row["workspace_id"],
            row["owner_person_id"],
            device,
            blob=-row["content_len"],
            head=-wrap_bytes,
            versions=-1,
        )
        if v == row["current"] and row["tombstone_ms"] is None:
            con.execute("UPDATE drop_objects SET n=? WHERE object_id=?", (self.position(con), o))

    @staticmethod
    def position(con):
        """The next relay-wide change position (never reused)."""
        con.execute("UPDATE drop_counter SET n=n+1 WHERE id=0")
        return con.execute("SELECT n FROM drop_counter WHERE id=0").fetchone()[0]

    @staticmethod
    def charge(con, ws, owner, device, blob=0, head=0, versions=0, documents=0):
        """drop_usage per scope (§14.5): workspace, global and the author device's share carry
        every counter; the account carries blob bytes and live versions. The caps are enforced by
        drop_quota (a reservation at step 9, authoritatively in the commit)."""
        rows = [
            ("workspace", ws, blob, head, versions, documents),
            ("global", "", blob, head, versions, documents),
            ("account", owner, blob, 0, versions, 0),
        ]
        if device is not None:
            rows.append(("device", f"{ws}:{device}", blob, head, versions, documents))
        for row in rows:
            if min(row[2:]) >= 0:
                con.execute(
                    "INSERT INTO drop_usage VALUES (?,?,?,?,?,?) ON CONFLICT(scope,id) DO UPDATE SET "
                    "blob_bytes=blob_bytes+excluded.blob_bytes, "
                    "head_bytes=head_bytes+excluded.head_bytes, "
                    "versions=versions+excluded.versions, documents=documents+excluded.documents",
                    row,
                )
            else:  # a release: the row exists (CHECK refuses a negative candidate row)
                con.execute(
                    "UPDATE drop_usage SET blob_bytes=blob_bytes+?, head_bytes=head_bytes+?, "
                    "versions=versions+?, documents=documents+? WHERE scope=? AND id=?",
                    (*row[2:], row[0], row[1]),
                )

    # --- authorization ---------------------------------------------------------------------------

    def admit(self, headers, write=False, upload_cost=None):
        """Step 2 on a read snapshot: session (401), a `drop:` device (403), for a W write the
        fence at admission (409 `fenced`, before any slot or body read), then one read-class token
        (P3-D35; a refusal after authentication is charged too). `upload_cost` (a PUT: tokens for
        its declared body, one per started MiB) then charges the upload bucket of the device, or
        of the W session's workspace (item 8); a device's workspace bucket is charged once the
        head names the workspace."""
        d = self.d
        with self.bridge.reading("query") as con:
            con.execute("BEGIN")
            now = d.clock()
            session = d.authenticate(con, headers, now)
            try:
                if session["kind"] == "device" and session["scopes_max"][0].startswith("drop:"):
                    fail("not_eligible")
                if write and session["kind"] == "workspace":
                    d.fence(con, headers, session["subject_id"], now)
                if write and session["kind"] == "device":
                    # Review F8 (§14.2 step 2, "a non-member"): a device with `operate` in no
                    # workspace gets neither an upload slot nor a drain.
                    scopes = con.execute(
                        "SELECT scopes FROM members WHERE device_id=?", (session["subject_id"],)
                    ).fetchall()
                    need(any("operate" in P.parse_json(r[0]) for r in scopes), "not_eligible", 403)
                if session["kind"] == "workspace":
                    # Review F3: a host's slots also count against its account (the card owner),
                    # so one account's workspaces cannot take every relay-wide slot.
                    owner = con.execute(
                        "SELECT owner_person_id FROM workspaces WHERE workspace_id=?",
                        (session["subject_id"],),
                    ).fetchone()
                    session["person_id"] = owner[0] if owner else session["subject_id"]
            except Refusal:
                d.throttle(session, now)
                raise
            d.throttle(session, now)
            if upload_cost:
                key = (
                    ("drop-up", session["subject_id"])
                    if session["kind"] == "device"
                    else ("drop-up-workspace", session["subject_id"])
                )
                self.take(session, [key], upload_cost, "up")
            return session

    def take(self, session, keys, cost, kind):
        """Charge Drop transfer buckets (one token per started MiB). A cost above a bucket's
        burst can never be paid, so an upload that large is refused 413 `too_large` (no
        Retry-After that never comes true); a download's cost is clamped to the burst. The
        start-up check (`check_buckets`) makes both unreachable with the default limits."""
        d = self.d
        for key in keys:
            burst = d.throttles[key[0]][0]
            if cost > burst and kind == "up":
                no("too_large", 413)
        if kind == "down":
            cost = min(cost, *(d.throttles[key[0]][0] for key in keys))
        d.throttle(session, d.clock(), "keys", keys, cost)

    def check_buckets(self):
        """Start-up, Drop on: every bucket must hold the cost of the largest body it charges, or
        the largest uploads (and downloads) would be refused forever."""
        mib = lambda n: -(-n // MIB)
        want = {
            "drop-up": (mib(self.max_body), "ORCH_RELAY_THROTTLE_DROP_UP"),
            "drop-up-workspace": (mib(self.max_body), "ORCH_RELAY_THROTTLE_DROP_UP_WORKSPACE"),
            "drop-down": (mib(self.max_blob), "ORCH_RELAY_THROTTLE_DROP_DOWN"),
            "drop-down-person": (mib(self.max_blob), "ORCH_RELAY_THROTTLE_DROP_DOWN_PERSON"),
        }
        for name, (cost, env) in want.items():
            burst = self.d.throttles[name][0]
            if burst < cost:
                raise ValueError(
                    f"{env}: burst {burst} is below {cost}, the tokens of a maximal body "
                    f"(ORCH_RELAY_DROP_MAX_BLOB_BYTES={self.max_blob}); raise the burst or lower "
                    "the blob cap"
                )

    @staticmethod
    def slot_keys(session, workspace=None):
        """Device sessions: the device and its person. W sessions: the workspace (uploads) or the
        session as a device (reads, downloads), and its account under the person caps (F3)."""
        if session["kind"] == "workspace":
            first = ("workspace" if workspace else "device", session["subject_id"])
            return [first, ("person", session["person_id"])]
        return [("device", session["subject_id"]), ("person", session["person_id"])]

    @staticmethod
    def member(con, ws, device):
        row = con.execute(
            "SELECT scopes FROM members WHERE workspace_id=? AND device_id=?", (ws, device)
        ).fetchone()
        return P.parse_json(row[0]) if row else None

    def sees_workspace(self, con, session, ws):
        if session["kind"] == "workspace":
            return session["subject_id"] == ws
        scopes = self.member(con, ws, session["subject_id"])
        return scopes is not None and "look" in scopes

    def visible(self, con, session, row):
        """§14.2 item 6: the caller may see this object (any state)."""
        if not self.sees_workspace(con, session, row["workspace_id"]):
            return False
        if session["kind"] == "workspace" or row["audience"] != "devices":
            return True
        return (
            con.execute(
                "SELECT 1 FROM drop_audience WHERE object_id=? AND device_id=?",
                (row["object_id"], session["subject_id"]),
            ).fetchone()
            is not None
        )

    # --- PUT: steps 4-9 --------------------------------------------------------------------------

    def parse_head(self, raw, o_path):
        """Step 4's parse and step 5's shape checks that need no database (400)."""
        try:
            head = P.parse_json(raw)
        except ValueError:
            fail("malformed")
        need(isinstance(head, dict) and set(head) == {"descriptor", "wraps"})
        signed, records = head["descriptor"], head["wraps"]
        need(isinstance(signed, dict) and set(signed) == {"o", "sig"} and isinstance(records, list))
        o = signed["o"]
        need(isinstance(o, dict) and set(o) == DESCRIPTOR_FIELDS)
        need(o["v"] == 2 and type(o["v"]) is int and o["suite"] == 2 and type(o["suite"]) is int)
        need(o["kind"] == "drop_object" and isinstance(signed["sig"], str))
        need(len(P.cj(signed)) <= MAX_DESCRIPTOR)
        need(isinstance(o["meta"], str) and len(b64(o["meta"])) <= MAX_META)
        need(hex32(o["object_id"]) == o_path)
        hex32(o["space_id"])
        need(o["space_kind"] == "workspace")
        need(o["object_kind"] in ("file", "document"))
        integer(o["version"], 1)
        need(type(o["parent"]) is int and o["parent"] == o["version"] - 1)
        if o["version"] == 1:
            need(o["parent_hash"] is None)
        else:
            b64(o["parent_hash"], 32)
        need(o["author_kind"] in ("device", "workspace"))
        hex32(o["author_id"])
        b64(o["content_hash"], 32)
        integer(o["content_len"], ORD2_HEADER + 16, self.max_blob)
        b64(o["dek_commit"], 32)
        need(o["origin"] in ("human", "agent"))
        integer(o["created_ms"])
        r = o["recipients"]
        if r == "inbox":
            need(o["object_kind"] == "file")  # M7: an inbox document is 400
        else:
            need(isinstance(r, list) and 1 <= len(r) <= MAX_RECIPIENTS)  # [] is 400 (A1, R2)
            for ident in r:
                hex32(ident)
            need(r == sorted(set(r)))
        if o["object_kind"] == "file":
            integer(o["expires_ms"])
        else:
            need(o["expires_ms"] is None)  # P4 documents carry no expiry
        need(len(records) <= MAX_WRAPS)
        return signed, records

    def check_wrap_shapes(self, o, records):
        """Step 9's shape rules (400): field set, this object and version, the §5.3 framing and
        at most 512 B, unique targets, `wk`/`wxk` to the own space, `sk` refused until P6, the
        inbox rule (one `wxk`, optionally the author's own `device` wrap, never `wk`) and the
        member-writer `wk` wrap."""
        seen = set()
        kinds = Counter()
        for rec in records:
            need(isinstance(rec, dict) and set(rec) == WRAP_FIELDS)
            need(rec["object_id"] == o["object_id"] and rec["version"] == o["version"])
            need(type(rec["version"]) is int)
            kind = rec["target_kind"]
            need(kind in WRAP_LEN)  # `sk` and anything else: 400 until P6
            hex32(rec["target_id"])
            integer(rec["key_version"], 0, 2**32 - 1)
            need(isinstance(rec["wrap"], str) and len(rec["wrap"]) <= (MAX_WRAP * 4 + 2) // 3)
            raw = b64(rec["wrap"])
            need(len(raw) <= MAX_WRAP and len(raw) == WRAP_LEN[kind])
            if kind != "wk":
                need(P.SUITE.pub_ok(raw[:65]))
            key = (kind, rec["target_id"], rec["key_version"])
            need(key not in seen)
            seen.add(key)
            kinds[kind] += 1
            if kind in ("wk", "wxk"):
                need(rec["target_id"] == o["space_id"])  # cross-workspace targets are P6 (M1)
            else:
                need(rec["key_version"] == 0)
        if o["recipients"] == "inbox":
            need(kinds["wxk"] == 1 and kinds["wk"] == 0)
            for rec in records:
                if rec["target_kind"] == "device":
                    need(o["author_kind"] == "device" and rec["target_id"] == o["author_id"])
        elif o["author_kind"] == "device" or o["space_id"] in o["recipients"]:
            need(
                kinds["wk"] == 1
            )  # the member-writer wrap; a W author may omit it only for devices

    def eligibility(self, con, session, signed, now, signature=True):
        """Step 5's database checks: the expiry window (400; its 410 is in step 6), the author is
        the principal (403), the signature (401, only once: keys never change), the write scope
        (403), and only then the recipients as the space or its current member devices (400).
        JUDGEMENT CALL (authorization pass): §14.2 lists the recipients check before the author,
        but run first it would tell a caller without write scope which device ids are members
        of any workspace (400 versus 403); after the scope check it reveals nothing new."""
        o = signed["o"]
        ws = o["space_id"]
        if o["object_kind"] == "file":
            need(o["expires_ms"] <= now + self.max_ttl + SKEW)
        kind, ident = session["kind"], session["subject_id"]
        need(
            o["author_kind"] == ("device" if kind == "device" else "workspace")
            and o["author_id"] == ident,
            "not_eligible",
            403,
        )
        if signature:
            if kind == "device":
                pub = con.execute(
                    "SELECT dk_sig_pub FROM devices WHERE device_id=?", (ident,)
                ).fetchone()
            else:
                pub = con.execute(
                    "SELECT wsk_pub FROM workspaces WHERE workspace_id=?", (ident,)
                ).fetchone()
            if pub is None or P.verify_object(signed, P.unb64u(pub[0]), "drop_object") is None:
                no("bad_signature", 401)
        if kind == "device":
            scopes = self.member(con, ws, ident)
            need(scopes is not None and "operate" in scopes, "not_eligible", 403)
        else:
            need(ident == ws, "not_eligible", 403)
        if isinstance(o["recipients"], list):
            for target in o["recipients"]:
                need(target == ws or self.member(con, ws, target) is not None)

    def object_state(self, con, session, o, now):
        """Step 6: another space's id or a device outside a device-only audience is 403 (never
        its state), then an expired descriptor or an expired or tombstoned object is 410.
        Returns the row or None."""
        row = con.execute(
            "SELECT * FROM drop_objects WHERE object_id=?", (o["object_id"],)
        ).fetchone()
        if row is not None:
            need(row["workspace_id"] == o["space_id"], "not_eligible", 403)
            need(self.visible(con, session, row), "not_eligible", 403)
        # A resent body that has expired (orch-f1 R4) is 410 here, after the 403s, so that a
        # device outside a device-only audience gets 403 before any 410 (Opus delta R1).
        if o["expires_ms"] is not None and o["expires_ms"] <= now:
            no("expired", 410)
        if row is not None and (
            row["tombstone_ms"] is not None
            or (row["expires_ms"] is not None and row["expires_ms"] <= now)
        ):
            no("expired", 410)
        return row

    @staticmethod
    def exact_retry(con, o, row):
        """Step 7: version `version` stored with the same cj(o) (the signature may differ)."""
        if row is None or o["version"] > row["current"]:
            return False
        stored = con.execute(
            "SELECT descriptor FROM drop_versions WHERE object_id=? AND version=?",
            (o["object_id"], o["version"]),
        ).fetchone()
        return stored is not None and P.cj(P.parse_json(stored[0].encode())["o"]) == P.cj(o)

    @staticmethod
    def cas(o, row, expected, request_now):
        """Step 8 (§10.6), against `row` (a read snapshot, or live rows in the commit)."""
        if o["object_kind"] == "file":
            need(o["version"] == 1)
            need(o["expires_ms"] >= request_now + MIN_FILE_LIFE)  # the 60 s floor (A1)
        if row is not None and row["claimed_by"] is not None:
            no("not_eligible", 403)  # a claimed object takes no new version (M7)
        current = row["current"] if row is not None else 0
        if (
            expected != current
            or o["parent"] != current
            or o["version"] != current + 1
            or o["parent_hash"] != (row["head_hash"] if row is not None else None)
            or (row is not None and row["object_kind"] != o["object_kind"])
        ):
            no("version_conflict", 409, current=current)

    def wrap_state(self, con, o, records, now):
        """Step 9's state checks: `wk` at the current list epoch (409 `stale_epoch`), `wxk` at the
        card's `wxk_version` (409 `bad_wxk_version`), `device` wraps to a current member (or the
        author) with an unrevoked, unexpired certificate (403)."""
        ws = o["space_id"]
        epoch = con.execute(
            "SELECT epoch FROM member_lists WHERE workspace_id=? ORDER BY list_seq DESC LIMIT 1",
            (ws,),
        ).fetchone()
        epoch = epoch[0] if epoch else 0
        card = con.execute(
            "SELECT wxk_version FROM workspaces WHERE workspace_id=?", (ws,)
        ).fetchone()
        for rec in records:
            kind = rec["target_kind"]
            if kind == "wk" and rec["key_version"] != epoch:
                no("stale_epoch", 409, epoch=epoch)
            elif kind == "wxk" and (card is None or rec["key_version"] != card[0]):
                no("bad_wxk_version", 409)
            elif kind == "device":
                target = rec["target_id"]
                author = o["author_kind"] == "device" and target == o["author_id"]
                need(author or self.member(con, ws, target) is not None, "not_eligible", 403)
                device = con.execute(
                    "SELECT * FROM devices WHERE device_id=?", (target,)
                ).fetchone()
                need(
                    device is not None
                    and not pair_revoked(con, target, device["person_id"])
                    and (device["expires_ms"] is None or device["expires_ms"] > now),
                    "not_eligible",
                    403,
                )

    def precheck(self, session, o_path, expected, raw, content_length, request_now, cost=0):
        """Steps 4 (parse) to 9 on a read snapshot, before any blob byte. Returns ("retry",
        version) for an exact retry, else ("store", plan)."""
        signed, records = self.parse_head(raw, o_path)
        o = signed["o"]
        need(content_length == 8 + len(raw) + o["content_len"])  # M3
        plan = Plan(signed, records, len(raw))
        with self.bridge.reading("query") as con:
            con.execute("BEGIN")
            self.eligibility(con, session, signed, request_now)
            if session["kind"] == "device" and cost:
                # The device's workspace upload bucket (item 8, R-D12), charged as soon as the
                # device is eligible to write here (step 5): every later refusal, the exact
                # retry and a part-2 budget 429 spend it too, and it is never refunded. Not
                # earlier: a device could otherwise drain a workspace it may not write to. A W
                # session's was charged at admission.
                self.take(session, [("drop-up-workspace", o["space_id"])], cost, "up")
            row = self.object_state(con, session, o, request_now)
            if self.exact_retry(con, o, row):
                return "retry", o["version"]
            self.cas(o, row, expected, request_now)
            self.check_wrap_shapes(o, records)
            self.wrap_state(con, o, records, request_now)
            self.quota_snapshot(con, plan, row, request_now)
        return "store", plan

    def quota_snapshot(self, con, plan, row, request_now):
        """Step 9, after the wraps (item 8): the version-1 creation rate (429 `rate_limited`),
        then what the reservation needs: the owner, the author device's share, the committed
        usage of every scope this version charges. The reservation itself is taken on the event
        loop (`reserve`); the commit re-checks everything on live rows."""
        o = plan.o
        ws = o["space_id"]
        plan.device = o["author_id"] if o["author_kind"] == "device" else None
        plan.owner = (
            row["owner_person_id"]
            if row is not None
            else con.execute(
                "SELECT owner_person_id FROM workspaces WHERE workspace_id=?", (ws,)
            ).fetchone()[0]
        )
        if row is None and not creations_left(
            con, self.quotas, ws, plan.device, day_of(request_now)
        ):
            refuse_creations(request_now)
        plan.need = Need.of(plan, row is None and o["object_kind"] == "document")
        plan.keys = usage_keys(ws, plan.owner, plan.device)
        plan.usage = read_usage(con, plan.keys)

    def reserve(self, plan):
        """Step 9, on the event loop with no await between the check and the take: refuse a
        version that would pass a cap with the in-flight reservations counted, else reserve its
        bytes, head bytes, version and document until the request ends."""
        o = plan.o
        check(
            self.quotas,
            plan.usage,
            self.reserved.view(),
            plan.need,
            o["space_id"],
            plan.owner,
            plan.device,
            o,
        )
        return self.reserved.take(plan.keys, plan.need)

    def enforce(self, con, plan, row, request_now, now):
        """The commit's authority (item 8): the caps against the live usage rows (no
        reservations: each upload's own commit decides), then, for a new object, the creation
        counters by upsert. A refusal propagates out of the write transaction (rolled back)."""
        o = plan.o
        ws = o["space_id"]
        usage = read_usage(con, plan.keys)
        check(
            self.quotas,
            usage,
            {},
            Need.of(plan, row is None and o["object_kind"] == "document"),
            ws,
            plan.owner,
            plan.device,
            o,
        )
        if row is None and not charge_creation(
            con, self.quotas, ws, plan.device, day_of(request_now)
        ):
            refuse_creations(request_now)

    # --- PUT: step 11 ----------------------------------------------------------------------------

    def commit(self, headers, plan, expected, blob_path, request_now):
        """Under the directory lock, one write transaction: the fence on the live `holders` row
        first, then the session, 5's eligibility, 6, 7, 8 and 9 on live rows, then the rows, the
        usage and a new change position. Returns (status, version, workspace)."""
        d, o = self.d, plan.o
        with d.lock:
            con = self.bridge.connection("write")
            con.execute("BEGIN IMMEDIATE")
            with con:
                now = d.clock()
                session = d.authenticate(con, headers, now)
                if session["kind"] == "workspace":
                    d.fence(con, headers, session["subject_id"], now)  # orch-52 change 0
                self.eligibility(con, session, plan.signed, now, signature=False)
                row = self.object_state(con, session, o, now)
                if self.exact_retry(con, o, row):
                    return 200, o["version"], o["space_id"]
                self.cas(o, row, expected, request_now)
                self.wrap_state(con, o, plan.records, now)
                self.enforce(con, plan, row, request_now, now)
                self.insert(con, plan, row, blob_path, now)
        return 201, o["version"], o["space_id"]

    def insert(self, con, plan, row, blob_path, now):
        o, ws = plan.o, plan.o["space_id"]
        n = self.position(con)
        head_hash = parent_hash(o)
        device = o["author_id"] if o["author_kind"] == "device" else None
        old_audience = 0
        if row is None:
            owner = con.execute(
                "SELECT owner_person_id FROM workspaces WHERE workspace_id=?", (ws,)
            ).fetchone()[0]
            con.execute(
                "INSERT INTO drop_objects (object_id, workspace_id, owner_person_id, object_kind, "
                "current, inbox, expires_ms, head_author_id, head_hash, audience, n, created_ms) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    o["object_id"],
                    ws,
                    owner,
                    o["object_kind"],
                    o["version"],
                    int(plan.inbox),
                    o["expires_ms"],
                    o["author_id"],
                    head_hash,
                    plan.audience,
                    n,
                    now,
                ),
            )
        else:
            owner = row["owner_person_id"]
            old_audience = con.execute(
                "SELECT count(*) FROM drop_audience WHERE object_id=?", (o["object_id"],)
            ).fetchone()[0]
            con.execute("DELETE FROM drop_audience WHERE object_id=?", (o["object_id"],))
            con.execute(
                "UPDATE drop_objects SET current=?, expires_ms=?, head_author_id=?, head_hash=?, "
                "audience=?, n=? WHERE object_id=?",
                (
                    o["version"],
                    o["expires_ms"],
                    o["author_id"],
                    head_hash,
                    plan.audience,
                    n,
                    o["object_id"],
                ),
            )
            if old_audience:  # the previous head author's share carried them (A1)
                old = row["head_author_id"]
                self.charge(
                    con,
                    ws,
                    owner,
                    None if old == ws else old,
                    head=-AUDIENCE_ROW * old_audience,
                )
        con.executemany(
            "INSERT INTO drop_audience VALUES (?,?)",
            [(o["object_id"], device_id) for device_id in plan.devices],
        )
        con.execute(
            "INSERT INTO drop_versions VALUES (?,?,?,?,?,?,?,?,?,?,'stored',?,?)",
            (
                o["object_id"],
                o["version"],
                o["author_kind"],
                o["author_id"],
                plan.descriptor,
                head_hash,
                o["content_hash"],
                o["content_len"],
                plan.head_len,
                len(plan.descriptor.encode()),
                blob_path,
                now,
            ),
        )
        con.executemany(
            "INSERT INTO drop_wraps VALUES (?,?,?,?,?,?)",
            [
                (
                    o["object_id"],
                    o["version"],
                    rec["target_kind"],
                    rec["target_id"],
                    rec["key_version"],
                    text,
                )
                for rec, text in zip(plan.records, plan.wrap_texts, strict=True)
            ],
        )
        head = (
            len(plan.descriptor.encode())
            + sum(len(t.encode()) for t in plan.wrap_texts)
            + AUDIENCE_ROW * len(plan.devices)
        )
        self.charge(
            con,
            ws,
            owner,
            device,
            blob=o["content_len"],
            head=head,
            versions=1,
            documents=int(row is None and o["object_kind"] == "document"),
        )

    # --- blob files ------------------------------------------------------------------------------

    def open_tmp(self):
        name = self.tmp / secrets.token_hex(16)
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        return name, os.fdopen(fd, "wb", buffering=0)

    @staticmethod
    def write(handle, digest, data):
        handle.write(data)
        digest.update(data)

    def land(self, tmp, o):
        """fsync, then rename to a unique final path and fsync the directories, all before the
        directory lock (Opus L8). Returns the path relative to drop/blobs."""
        fd = os.open(tmp, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        folder = self.blobs / o["object_id"]
        folder.mkdir(mode=0o700, exist_ok=True)
        rel = f"{o['object_id']}/{o['version']}.{secrets.token_hex(8)}"
        os.rename(tmp, self.blobs / rel)
        for path in (folder, self.blobs, self.tmp):
            fd = os.open(path, os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        return rel

    @staticmethod
    def unlink(path):
        if path is not None:
            with suppress(OSError):
                Path(path).unlink()

    @staticmethod
    def check_ord2(header, o):
        """Step 10 (Opus L10): an ORD2 header naming this descriptor's suite, object and version,
        and a `content_len` consistent with its chunk size (the last chunk at least a tag)."""
        need(
            header[:4] == ORD2
            and header[4] == 2
            and header[5] == o["suite"]
            and header[6:8] == b"\0\0"
            and header[8:24] == bytes.fromhex(o["object_id"])
            and int.from_bytes(header[24:28], "big") == o["version"]
        )
        chunk = int.from_bytes(header[28:32], "big")
        need(0 < chunk <= MAX_CHUNK)
        body, step = o["content_len"] - ORD2_HEADER, chunk + 16
        need(body >= 16 and body - (-(-body // step) - 1) * step >= 16)

    # --- reads -----------------------------------------------------------------------------------

    def object_for_read(self, con, session, o_id, now):
        """The read answer order (§14.2 item 6): absent 404 (an ended tombstone too), not
        visible 403 (every version and state), tombstoned or expired 410."""
        row = con.execute("SELECT * FROM drop_objects WHERE object_id=?", (o_id,)).fetchone()
        until = tombstone_until(row, now) if row is not None else None
        if row is None or (until is not None and until <= now):
            no("not_found", 404)
        need(self.visible(con, session, row), "not_eligible", 403)
        if until is not None:
            no("expired", 410)
        return row

    def version_row(self, con, o_id, version):
        row = con.execute(
            "SELECT * FROM drop_versions WHERE object_id=? AND version=?", (o_id, version)
        ).fetchone()
        if row is None:
            no("not_found", 404)
        return row

    @staticmethod
    def usable_wraps(con, session, o_id, version, ws):
        """§14.2 item 6: a W session its workspace's `wk` and `wxk` wraps; a device its
        workspace's `wk` wraps and its own `device` wraps, never `wxk` (Opus N2)."""
        if session["kind"] == "workspace":
            sql = "target_kind IN ('wk','wxk') AND target_id=?"
            args = (ws,)
        else:
            sql = "((target_kind='wk' AND target_id=?) OR (target_kind='device' AND target_id=?))"
            args = (ws, session["subject_id"])
        return [
            r[0]
            for r in con.execute(
                "SELECT record FROM drop_wraps WHERE object_id=? AND version=? AND "
                + sql
                + " ORDER BY target_kind, target_id, key_version",
                (o_id, version, *args),
            )
        ]

    def read_meta(self, session, route, o_id, version):
        """GET descriptor or wraps: one snapshot, spliced from the stored cj text."""
        with self.bridge.reading("query") as con:
            con.execute("BEGIN")
            now = self.d.clock()
            row = self.object_for_read(con, session, o_id, now)
            vrow = self.version_row(con, o_id, version)
            if route == "descriptor":
                return b'{"descriptor":' + vrow["descriptor"].encode() + b"}"
            wraps = self.usable_wraps(con, session, o_id, version, row["workspace_id"])
            return (
                b'{"claimed_by":'
                + P.cj(row["claimed_by"])
                + b',"wraps":['
                + ",".join(wraps).encode()
                + b"]}"
            )

    def read_blob(self, session, o_id, version):
        """GET blob: the answer order, then an unclaimed inbox 403 and a pruned blob 410; opens
        the file inside the snapshot (an unlink after it keeps the open file readable)."""
        with self.bridge.reading("query") as con:
            con.execute("BEGIN")
            now = self.d.clock()
            row = self.object_for_read(con, session, o_id, now)
            vrow = self.version_row(con, o_id, version)
            need(not row["inbox"] or row["claimed_by"] is not None, "not_eligible", 403)
            if vrow["blob"] != "stored":
                no("expired", 410)
            try:
                handle = open(self.blobs / vrow["blob_path"], "rb")  # noqa: SIM115
            except OSError:
                no("expired", 410)
            return handle, vrow["content_len"]

    def descriptors_page(self, session, o_id, query):
        """GET descriptors?after=&limit= (§14.2 item 7): ascending by version, at most `limit`
        (≤ 256) and cut before 1 MiB by the stored descriptor_len, at least one entry."""
        need(set(query) <= {"after", "limit"})
        after, limit = query.get("after", "0"), query.get("limit", str(PAGE_LIMIT))
        need(DECIMAL.fullmatch(after) is not None and DECIMAL.fullmatch(limit) is not None)
        after, limit = int(after), int(limit)
        need(1 <= limit <= PAGE_LIMIT)
        with self.bridge.reading("query") as con:
            con.execute("BEGIN")
            now = self.d.clock()
            self.object_for_read(con, session, o_id, now)
            # Review F4: the cut is chosen from the stored lengths, then only the descriptors
            # that fit are read (never limit + 1 full descriptors for a 1 MiB page).
            sizes = con.execute(
                "SELECT version, descriptor_len FROM drop_versions WHERE object_id=? "
                "AND version>? ORDER BY version LIMIT ?",
                (o_id, after, limit + 1),
            ).fetchall()
            more = len(sizes) > limit
            chosen, size = [], NEXT_RESERVE + len("descriptors")
            for row in sizes[:limit]:
                if chosen and size + row["descriptor_len"] + 1 > PAGE_BYTES:
                    more = True
                    break
                chosen.append(row["version"])
                size += row["descriptor_len"] + 1
            rows = (
                con.execute(
                    "SELECT version, descriptor, descriptor_len FROM drop_versions WHERE "
                    "object_id=? AND version>=? AND version<=? ORDER BY version",
                    (o_id, chosen[0], chosen[-1]),
                ).fetchall()
                if chosen
                else []
            )
        return splice(rows, more, "descriptors", PAGE_BYTES)

    def list_page(self, session, raw):
        """POST /v2/drop/list (§14.2 item 7): by change position, the caller's visible objects,
        spliced from stored cj text, cut by count and by bytes (at least one entry)."""
        try:
            body = P.parse_json(raw)
        except ValueError:
            fail("malformed")
        need(isinstance(body, dict) and {"workspace_id", "direction"} <= set(body))
        need(set(body) <= {"workspace_id", "direction", "after", "limit"})
        ws = hex32(body["workspace_id"])
        need(body["direction"] in ("received", "sending"))
        after = integer(body.get("after", 0))
        limit = integer(body.get("limit", LIST_LIMIT), 1, LIST_LIMIT)
        me = session["subject_id"]
        with self.bridge.reading("query") as con:
            con.execute("BEGIN")
            now = self.d.clock()
            need(self.sees_workspace(con, session, ws), "not_eligible", 403)
            author = "o.head_author_id" + ("=?" if body["direction"] == "sending" else "<>?")
            # An ended tombstone is gone (its row awaits the D39a2 sweep).
            sql = (
                "SELECT o.*, v.descriptor, v.descriptor_len, v.blob FROM drop_objects o "
                "LEFT JOIN drop_versions v ON v.object_id=o.object_id AND v.version=o.current "
                f"WHERE o.workspace_id=? AND o.n>? AND {author} AND coalesce(o.tombstone_ms, "
                "CASE WHEN o.expires_ms<=? THEN o.expires_ms END, ?) + ? > ?"
            )
            args = [ws, after, me, now, now, TOMBSTONE, now]
            if session["kind"] == "device":
                sql += (
                    " AND (o.audience<>'devices' OR EXISTS (SELECT 1 FROM drop_audience a "
                    "WHERE a.object_id=o.object_id AND a.device_id=?))"
                )
                args.append(me)
            rows = con.execute(sql + " ORDER BY o.n LIMIT ?", (*args, limit + 1)).fetchall()
            entries = []
            for row in rows[:limit]:
                state = state_of(row, row["blob"], now)
                wraps = []
                if state == "live":
                    wraps = self.usable_wraps(con, session, row["object_id"], row["current"], ws)
                entries.append((row["n"], entry(row, state, wraps, now)))
        return splice_list(entries, len(rows) > limit)

    # --- ASGI ------------------------------------------------------------------------------------

    async def endpoint(self, scope, receive, send, route):
        if route == "put":
            return await self.upload(scope, receive, send)
        if route == "blob":
            return await self.download(scope, receive, send)
        return await self.json_read(scope, receive, send, route)

    async def json_read(self, scope, receive, send, route):
        """List, descriptor pages, descriptor and wraps. List and descriptor pages hold a read
        slot (8 relay-wide, 4 per person, 2 per device) until the body is handed to the socket."""
        headers = header_map(scope)
        slot = None
        body = Body(receive, self.limits)
        try:
            try:
                query = query_map(scope)
                raw = b""
                if route == "list":
                    declared = headers.get("content-length")
                    if declared and declared.isdecimal() and int(declared) > LIST_JSON_CAP:
                        no("too_large", 413)
                    raw = await body.read_all(LIST_JSON_CAP)
                    need(not query)
                else:
                    o_id = path_object(scope)
                    version = path_version(scope) if route != "descriptors" else None
                    need(route == "descriptors" or not query)
                session = await run_in_threadpool(self.admit, headers)
                extra = []
                if route in ("list", "descriptors"):
                    slot = self.reads.take(self.slot_keys(session))
                if route == "list":
                    payload = await run_in_threadpool(self.list_page, session, raw)
                elif route == "descriptors":
                    payload = await run_in_threadpool(self.descriptors_page, session, o_id, query)
                else:
                    payload = await run_in_threadpool(self.read_meta, session, route, o_id, version)
                    if route == "descriptor":
                        extra = etag(version)
                status = 200
            except Refusal as error:
                status, payload, extra = error.status, error_body(error), retry_headers(error)
            except (ValueError, TypeError, KeyError, AttributeError):
                status, payload, extra = 400, b'{"error":"malformed"}', []
            await self.send_json(send, status, payload, extra)
        except (TimeoutError, Disconnected, Breach):
            log.info("drop read closed: transfer bound or disconnect")
        finally:
            if slot is not None:
                self.reads.release(slot)  # only once the body was handed to the socket

    async def send_json(self, send, status, payload, extra=(), more=False, close=False):
        if isinstance(payload, dict):
            payload = P.cj(payload)
        headers = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(payload)).encode()),
            (b"cache-control", b"no-store"),
            *extra,
        ]
        if close:
            headers.append((b"connection", b"close"))
        await asyncio.wait_for(
            send({"type": "http.response.start", "status": status, "headers": headers}),
            self.limits.idle,
        )
        await asyncio.wait_for(
            send({"type": "http.response.body", "body": payload, "more_body": more}),
            self.limits.idle,
        )

    async def answer(self, send, body, status, payload, extra=(), mode="full", device=None):
        """Send the answer while body bytes may be unread (§14.2 item 2), then release the upload
        slot (`body.on_answer`). `mode`: "none" closes at once (a 413 for a declared length, a
        breached transfer), "brief" reads at most 64 KiB or 1 s first (refusals before a slot),
        "full" drains the declared remainder in the drain pool (32 relay-wide, 2 per device; when
        full, no drain) for at most 5 s idle and 30 s in all. The response is complete by its
        Content-Length; the final empty body message ends it and the connection closes."""
        pending = not body.done
        await self.send_json(send, status, payload, extra, more=pending, close=pending)
        if body.on_answer is not None:
            body.on_answer()
        if not pending:
            return
        await self.hook("answered", status=status, mode=mode)
        try:
            if mode == "brief":
                await body.drain(self.limits.brief_bytes, self.limits.brief_s, self.limits.brief_s)
            elif mode == "full":
                keys = [("device", device)] if device else []
                if self.drains.free(keys):
                    taken = self.drains.take(keys)
                    try:
                        await self.hook("drain")
                        await body.drain(None, self.limits.drain_idle, self.limits.drain_total)
                    finally:
                        self.drains.release(taken)
        except (TimeoutError, Disconnected, Breach):
            pass
        with suppress(Exception):
            await send({"type": "http.response.body", "body": b"", "more_body": False})

    async def upload(self, scope, receive, send):
        """PUT /v2/drop/{o}/versions: the check order of §14.2 item 3."""
        headers = header_map(scope)
        body = Body(receive, self.limits)
        slot, tmp, final, device, reservation = None, None, None, None, None
        mode = "brief"  # steps 1-2: close at once after at most 64 KiB or 1 s

        def free():
            nonlocal slot
            if slot is not None:
                self.uploads.release(slot)
                slot = None

        body.on_answer = free
        try:
            # 1. transport
            declared = headers.get("content-length")
            need(
                declared is not None and declared.isdecimal() and "transfer-encoding" not in headers
            )
            declared = int(declared)
            if declared > self.max_body:
                mode = "none"
                no("too_large", 413)
            body.declared = declared
            need(not query_map(scope))
            o_path = path_object(scope)
            # 2. session, principal, fence at admission, read bucket, an upload slot
            cost = max(1, -(-declared // MIB))  # one bucket token per started MiB of body
            session = await run_in_threadpool(self.admit, headers, True, cost)
            device = session["subject_id"]
            slot = self.uploads.take(self.slot_keys(session, workspace=True))
            mode = "full"  # from here on early answers drain
            held = time.monotonic()
            body.deadline = held + min(self.limits.head_s, self.limits.max_transfer)
            request_now = self.d.clock()
            # 3. If-Match
            expected = if_match(headers.get("if-match"))
            # 4. the frame's magic and head_len, the head
            frame = await body.read_exact(8)
            need(frame[:4] == MAGIC)
            head_len = int.from_bytes(frame[4:8], "big")
            if head_len > MAX_HEAD:
                no("too_large", 413)  # after the slot: drained like steps 3-9 (review F9)
            need(declared >= 8 + head_len)
            raw = await body.read_exact(head_len)
            body.deadline = held + self.limits.max_transfer  # the whole transfer (review F2)
            await self.hook("head")
            # 5-9 on a read snapshot, before any blob byte
            outcome, value = await run_in_threadpool(
                self.precheck, session, o_path, expected, raw, declared, request_now, cost
            )
            del raw
            if outcome == "retry":
                return await self.answer(
                    send, body, 200, {"version": value}, etag(value), device=device
                )
            plan = value
            if session["kind"] == "device":
                # The workspace's share of the slots, once the head names the workspace.
                key = ("workspace", plan.o["space_id"])
                if self.uploads.used[key] >= self.uploads.caps["workspace"]:
                    no("quota_exceeded", 429, quota="slot")
                self.uploads.used[key] += 1
                slot.append(key)
            reservation = self.reserve(plan)
            # 10. the blob, streamed to drop/tmp, landed at a unique final path
            mode = "none"  # a failure while streaming closes; the body was the client's
            tmp, handle = await self.io(self.open_tmp)
            try:
                await self.stream(body, handle, plan.o)
            finally:
                await self.io(handle.close)
            final = await self.io(self.land, tmp, plan.o)
            tmp = None
            await self.hook("before_commit", plan=plan)
            # 11. the commit, shielded: a cancellation after the commit never unlinks the
            # committed file (review F6); the outcome decides whether the file stays.
            landed, final = self.blobs / final, None
            commit = asyncio.ensure_future(
                run_in_threadpool(
                    self.commit,
                    headers,
                    plan,
                    expected,
                    landed.relative_to(self.blobs).as_posix(),
                    request_now,
                )
            )
            commit.add_done_callback(lambda f, path=landed: self.settle(f, path))
            status, version, ws = await asyncio.shield(commit)
            # The commit's outcome is known: its bytes are in `drop_usage` now, so release the
            # reservation before the answer is sent (a slow send must not count them twice).
            self.reserved.release(reservation)
            reservation = None
            if status != 200 and self.d.changed:
                self.d.changed(("ws", ws))
            return await self.answer(send, body, status, {"version": version}, etag(version))
        except Refusal as error:
            return await self.answer(
                send,
                body,
                error.status,
                error_body(error),
                retry_headers(error),
                mode=mode,
                device=device,
            )
        except Disconnected:
            return None  # nothing to answer; the reservation and files go below
        except (TimeoutError, Breach):
            return await self.answer(send, body, 400, b'{"error":"malformed"}', mode="none")
        except OSError:  # after TimeoutError, an OSError subclass
            # Review F7: a disk error (ENOSPC, EIO) while storing the blob: transient, retryable.
            log.exception("drop upload: storage error")
            return await self.answer(
                send, body, 503, b'{"error":"overloaded"}', [(b"retry-after", b"60")], mode="none"
            )
        except sqlite3.OperationalError:
            # Review N2: the database is full or busy past its timeout at the commit: transient.
            log.exception("drop upload: database error")
            return await self.answer(
                send, body, 503, b'{"error":"overloaded"}', [(b"retry-after", b"60")], mode="none"
            )
        except (ValueError, TypeError, KeyError, AttributeError):
            return await self.answer(
                send, body, 400, b'{"error":"malformed"}', mode=mode, device=device
            )
        finally:
            if reservation is not None:
                self.reserved.release(reservation)
            if tmp is not None:
                await self.io(self.unlink, tmp)
            if final is not None:
                await self.io(self.unlink, self.blobs / final)
            free()

    def settle(self, commit, path):
        """After the commit's thread finished (also when the request was cancelled meanwhile):
        the landed file goes only when the commit certainly stored no row for it: a refusal or a
        database error (the transaction rolled back) or a concurrent identical upload (200).
        A cancelled or otherwise unknown outcome keeps the file (review N1): the thread may have
        committed, and the start-up sweep deletes a file that no `stored` row names."""
        if commit.cancelled():
            return
        error = commit.exception()
        if error is not None:
            if isinstance(error, (Refusal, sqlite3.Error)):
                self.unlink(path)
            return
        if commit.result()[0] != 201:
            self.unlink(path)

    async def stream(self, body, handle, o):
        """Step 10: exactly `content_len` bytes in 64 KiB writes, hashed as they land, the ORD2
        header checked as soon as it has arrived; then the length and the hash."""
        digest = hashlib.sha256()
        want, have = o["content_len"], 0
        header = bytearray()
        pending = bytearray()
        body.start_rate()
        async for data in body.rest():
            if have + len(pending) + len(data) > want:
                fail("malformed")  # a long body
            if len(header) < ORD2_HEADER:
                header += data[: ORD2_HEADER - len(header)]
                if len(header) == ORD2_HEADER:
                    self.check_ord2(bytes(header), o)
            pending += data
            if len(pending) >= IO:
                chunk, pending = bytes(pending), bytearray()
                await self.io(self.write, handle, digest, chunk)
                have += len(chunk)
        if pending:
            await self.io(self.write, handle, digest, bytes(pending))
            have += len(pending)
        need(have == want)  # a short body
        need(P.b64u(digest.digest()) == o["content_hash"])

    async def download(self, scope, receive, send):
        """GET blob: streamed in 64 KiB reads through the file limiter, never buffered; a
        download slot (32 relay-wide, 4 per device, 8 per person) for the whole transfer, with
        the idle, minimum-rate and duration bounds on the sends."""
        headers = header_map(scope)
        slot, handle = None, None
        try:
            try:
                need(not query_map(scope))
                o_id, version = path_object(scope), path_version(scope)
                session = await run_in_threadpool(self.admit, headers)
                slot = self.downloads.take(self.slot_keys(session))
                handle, size = await run_in_threadpool(self.read_blob, session, o_id, version)
                # One token per started MiB served, taken before the first byte is read (item 8).
                keys = [
                    ("drop-down", session["subject_id"]),
                    ("drop-down-person", session["person_id"]),
                ]
                await run_in_threadpool(self.take, session, keys, max(1, -(-size // MIB)), "down")
            except Refusal as error:
                await self.send_json(send, error.status, error_body(error), retry_headers(error))
                return
            except (ValueError, TypeError, KeyError, AttributeError):
                await self.send_json(send, 400, b'{"error":"malformed"}')
                return
            await asyncio.wait_for(
                send(
                    {
                        "type": "http.response.start",
                        "status": 200,
                        "headers": [
                            (b"content-type", b"application/octet-stream"),
                            (b"content-length", str(size).encode()),
                            (b"etag", f'"{version}"'.encode()),
                            (b"cache-control", b"no-store"),
                        ],
                    }
                ),
                self.limits.idle,
            )
            start, sent = time.monotonic(), 0
            while sent < size:
                data = await self.io(handle.read, min(IO, size - sent))
                if not data:
                    log.error("drop blob shorter than its content_len: %s/%s", o_id, version)
                    return  # the client sees a short body
                await asyncio.wait_for(
                    send({"type": "http.response.body", "body": data, "more_body": True}),
                    self.limits.idle,
                )
                sent += len(data)
                check_rate(self.limits, start, sent)
            await send({"type": "http.response.body", "body": b"", "more_body": False})
        except (TimeoutError, Breach):
            log.info("drop download closed: transfer bound")
        finally:
            if handle is not None:
                with suppress(Exception):
                    await self.io(handle.close)
            if slot is not None:
                self.downloads.release(slot)


# --- helpers ---------------------------------------------------------------------------------------


def check_rate(limits, start, done):
    elapsed = time.monotonic() - start
    if elapsed > limits.max_transfer:
        raise Breach("duration")
    if elapsed >= limits.grace and done < limits.min_rate * elapsed:
        raise Breach("rate")


class Body:
    """The request body through ASGI `receive`, with the idle bound on every read."""

    def __init__(self, receive, limits):
        self.receive, self.limits = receive, limits
        self.buffer = bytearray()
        self.done = False
        self.on_answer = None
        self.declared = None
        self.received = 0
        self.start = None
        self.deadline = None  # monotonic: the head or the whole transfer must end by then

    async def more(self, timeout=None):
        if self.done:
            return False
        if timeout is None:  # a transfer read (a drain passes its own bounds)
            timeout = self.limits.idle
            if self.deadline is not None:
                timeout = min(timeout, self.deadline - time.monotonic())
                if timeout <= 0:
                    raise Breach("duration")
        try:
            message = await asyncio.wait_for(self.receive(), timeout)
        except TimeoutError as exc:
            raise Breach("idle") from exc
        if message["type"] == "http.disconnect":
            self.done = True
            raise Disconnected
        data = message.get("body", b"")
        self.received += len(data)
        self.buffer += data
        if not message.get("more_body", False):
            self.done = True
        return True

    async def read_exact(self, n):
        while len(self.buffer) < n:
            if not await self.more():
                fail("malformed")  # the body ended early
            self.check()
        out = bytes(self.buffer[:n])
        del self.buffer[:n]
        return out

    async def read_all(self, cap):
        while await self.more():
            if len(self.buffer) > cap:
                no("too_large", 413)
        if len(self.buffer) > cap:
            no("too_large", 413)
        return bytes(self.buffer)

    def check(self):
        if self.start is not None:
            check_rate(self.limits, self.start, self.received)

    def start_rate(self):
        self.start = time.monotonic()
        self.received = len(self.buffer)

    async def rest(self):
        if self.buffer:
            data, self.buffer = bytes(self.buffer), bytearray()
            yield data
        while await self.more():
            self.check()
            if self.buffer:
                data, self.buffer = bytes(self.buffer), bytearray()
                yield data

    async def drain(self, limit, idle, total):
        """Read and discard at most `limit` bytes (None: the declared remainder), ending at
        `idle` seconds without data or `total` seconds in all."""
        self.buffer = bytearray()
        end = time.monotonic() + total
        read = 0
        while not self.done and (limit is None or read < limit):
            left = end - time.monotonic()
            if left <= 0:
                return
            before = self.received
            await self.more(min(idle, left))
            read += self.received - before
            self.buffer = bytearray()


def header_map(scope):
    out = {}
    for key, value in scope["headers"]:
        name = key.decode("latin-1").lower()
        text = value.decode("latin-1")
        if name in out:
            out[name] = out[name] + "," + text  # a repeated header never parses as one value
        else:
            out[name] = text
    return out


def query_map(scope):
    from urllib.parse import parse_qsl

    pairs = parse_qsl(scope.get("query_string", b"").decode("latin-1"), keep_blank_values=True)
    out = dict(pairs)
    need(len(out) == len(pairs))
    return out


def path_object(scope):
    return hex32(scope["path_params"]["o"])


def path_version(scope):
    text = scope["path_params"]["v"]
    need(DECIMAL.fullmatch(text) is not None and 1 <= int(text) <= P.MAX_SAFE_INT)
    return int(text)


def etag(version):
    return [(b"etag", f'"{version}"'.encode())]


def error_body(error):
    return {"error": error.code, **getattr(error, "details", {})}


def retry_headers(error):
    if error.status in (429, 503):
        return [(b"retry-after", str(error.retry or 1).encode())]
    return []


def entry(row, state, wraps, now):
    """One list entry, keys in cj order, the descriptor and wraps spliced from stored text."""
    until = tombstone_until(row, now)
    live = state in ("live", "pruned")
    descriptor = row["descriptor"].encode() if live and row["descriptor"] else b"null"
    return b"".join(
        (
            b'{"claimed_by":',
            P.cj(row["claimed_by"]),
            b',"descriptor":',
            descriptor,
            b',"n":',
            str(row["n"]).encode(),
            b',"object_id":',
            P.cj(row["object_id"]),
            b',"state":',
            P.cj(state),
            b',"tombstone_until_ms":',
            P.cj(until),
            b',"version":',
            str(row["current"]).encode(),
            b',"wraps":[',
            ",".join(wraps).encode(),
            b"]}",
        )
    )


NEXT_RESERVE = len(b'{"next":,"objects":[]}') + 16


def splice_list(entries, more):
    out, size = [], NEXT_RESERVE
    for n, text in entries:
        if out and size + len(text) + 1 > LIST_BYTES:
            more = True
            break
        out.append((n, text))
        size += len(text) + 1
    nxt = str(out[-1][0]).encode() if more and out else b"null"
    return b'{"next":' + nxt + b',"objects":[' + b",".join(t for _, t in out) + b"]}"


def splice(rows, more, field, cap):
    """A descriptor page: the byte cut uses the stored descriptor_len (Opus L-a)."""
    out, size = [], NEXT_RESERVE + len(field)
    for row in rows:
        if out and size + row["descriptor_len"] + 1 > cap:
            more = True
            break
        out.append(row)
        size += row["descriptor_len"] + 1
    nxt = str(out[-1]["version"]).encode() if more and out else b"null"
    return (
        b'{"'
        + field.encode()
        + b'":['
        + b",".join(r["descriptor"].encode() for r in out)
        + b'],"next":'
        + nxt
        + b"}"
    )


class Endpoint:
    """A plain ASGI endpoint (Starlette treats a non-function endpoint as an ASGI app)."""

    def __init__(self, drop, route):
        self.drop, self.route = drop, route

    async def __call__(self, scope, receive, send):
        await self.drop.endpoint(scope, receive, send, self.route)


ROUTES = (
    ("put", "/v2/drop/{o}/versions", "PUT"),
    ("list", "/v2/drop/list", "POST"),
    ("descriptors", "/v2/drop/{o}/descriptors", "GET"),
    ("descriptor", "/v2/drop/{o}/versions/{v}/descriptor", "GET"),
    ("wraps", "/v2/drop/{o}/versions/{v}/wraps", "GET"),
    ("blob", "/v2/drop/{o}/versions/{v}/blob", "GET"),
)


def enabled(env=None):
    """Review F1 (deploy gate): D39a1 alone has no quotas, reservations, upload bucket, expiry
    sweeper or retire, so any `operate` member could fill the disk. The Drop routes exist only
    with ORCH_RELAY_DROP=1 (default off: they answer 404 as absent routes). Migration 0017 and the
    start-up sweep run either way. D39a2 decides whether the switch stays as a kill-switch."""
    env = os.environ if env is None else env
    return env.get("ORCH_RELAY_DROP", "0") == "1"


def install(app, env=None):
    drop = Drop(app.state.directory, app.state.bridge, app.state.data_dir)
    app.state.drop = drop
    if enabled(env):
        drop.check_buckets()
        for route, path, method in ROUTES:
            app.router.routes.append(Route(path, Endpoint(drop, route), methods=[method]))
    return drop
