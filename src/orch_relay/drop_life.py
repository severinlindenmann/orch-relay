"""Drop lifecycle (P3-D39 item 5, 10, 12 and amendment A1; D39a2 part 2): the periodic sweeps and
the host's retire.

The sweeps (one cycle every `SWEEP_PERIOD` seconds, only with `ORCH_RELAY_DROP=1`; the `n`-assigning
ones may never run while the Drop switch is off, until PR 4's state check gates them):

 1. expiry: a file at or past `expires_ms` becomes an `expired` tombstone (`tombstone_ms =
    expires_ms`, not the sweep time), its version, wraps and usage are released, its audience rows
    deleted, and it gets a new change position `n`;
 2. a retired document's versions, wraps and bytes are released in batches (a retire only counts the
    document out at once);
 3. a tombstone older than 30 days is deleted (no `n`: there is no entry left), releasing the
    audience rows a retired device-only tombstone still holds;
 4. superseded document blobs outside the newest 8 versions and older than 30 days are pruned (head
    bytes of the descriptor stay charged; no `n`: only the newest version's pruning shows in a list);
 5. `device` wraps of devices that are no longer members of the object's workspace (removed or
    revoked) are deleted, their head bytes released;
 6. day rows of `drop_decide_budget` and `drop_creations` older than the previous UTC day.

Every transaction deletes at most `BATCH` rows, cascaded wraps and audience rows included (one
object always completes: a file is at most one version, 1 024 wraps and as many audience rows). An
object whose sweep fails (a usage underflow against `CHECK >= 0`) is rolled back to its savepoint,
logged and skipped for the rest of the cycle, so one bad row never wedges the sweeper. Files are
unlinked only after the batch commits.

Retire (`Life.retire`, one write transaction): the fence on the live `holders` row, the object row
again (404), the precondition `{expect_version, expect_head}` (409 `version_conflict`), the bounded
idempotent answer for a tombstone, else the tombstone with a new `n`.
"""

import asyncio
import logging
import time
import traceback
from contextlib import suppress
from pathlib import Path

from starlette.concurrency import run_in_threadpool

from . import proto as P
from .bridge import refuse
from .directory import revoked_sql
from .drop_quota import AUDIENCE_ROW, DAY_MS, day_of

log = logging.getLogger(__name__)

TOMBSTONE = 30 * DAY_MS
BATCH = 4096  # deleted rows per write transaction, cascaded rows included (item 12)
KEEP_VERSIONS = 8  # newest document versions that always keep their blob (item 5)
PRUNE_AGE = 30 * DAY_MS
SWEEP_PERIOD = 600  # seconds (item 5: a sweeper deletes within 10 minutes)
LOG_EVERY = 300.0  # seconds between logged sweep-cycle failures (the first is logged at once)
KEEP_DAYS = 1  # day rows older than the previous UTC day are deleted


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


def release_head(con, ws, device, nbytes, workspace=True):
    """Give back head bytes: the workspace and the global ceiling (unless `workspace` is False)
    and the author device's share (`device`, None for a workspace author)."""
    if not nbytes:
        return
    keys = [("workspace", ws), ("global", "")] if workspace else []
    if device is not None:
        keys.append(("device", f"{ws}:{device}"))
    for scope, ident in keys:
        con.execute(
            "UPDATE drop_usage SET head_bytes=head_bytes-? WHERE scope=? AND id=?",
            (nbytes, scope, ident),
        )


class Life:
    def __init__(self, drop):
        self.drop = drop
        self.d, self.bridge = drop.d, drop.bridge
        self.period = SWEEP_PERIOD
        self.cycles = 0
        self.failures = 0  # consecutive failed cycles; reset by a successful one
        self.failures_total = 0
        self.last_logged = None
        self.object_failures, self.first_failure, self.cycle_bad = 0, None, False

    @property
    def on(self):
        return self.drop.on

    # --- release ---------------------------------------------------------------------------------

    def free_versions(self, con, obj, limit):
        """Delete the object's versions and their wraps, oldest first, releasing each version's
        blob bytes, live-version count (only while its blob is `stored`) and head bytes (the
        descriptor and the wraps still stored) from every scope that carries them. Stops before a
        version that would take the batch past `limit` rows (the first always goes). Returns
        (rows deleted, blob paths to unlink after the commit, more versions remain)."""
        o, ws, owner = obj["object_id"], obj["workspace_id"], obj["owner_person_id"]
        versions = con.execute(
            "SELECT version, author_kind, author_id, content_len, descriptor_len, blob, blob_path "
            "FROM drop_versions WHERE object_id=? ORDER BY version",
            (o,),
        ).fetchall()
        rows, paths = 0, []
        for v in versions:
            count, size = con.execute(
                "SELECT count(*), coalesce(sum(length(record)),0) FROM drop_wraps "
                "WHERE object_id=? AND version=?",
                (o, v["version"]),
            ).fetchone()
            if rows and rows + 1 + count > limit:
                return rows, paths, True
            stored = v["blob"] == "stored"
            device = v["author_id"] if v["author_kind"] == "device" else None
            self.drop.charge(
                con,
                ws,
                owner,
                device,
                blob=-v["content_len"] if stored else 0,
                head=-(v["descriptor_len"] + size),
                versions=-1 if stored else 0,
            )
            con.execute("DELETE FROM drop_wraps WHERE object_id=? AND version=?", (o, v["version"]))
            con.execute(
                "DELETE FROM drop_versions WHERE object_id=? AND version=?", (o, v["version"])
            )
            if stored and v["blob_path"]:
                paths.append(self.drop.blobs / v["blob_path"])
            rows += 1 + count
        return rows, paths, False

    def audience(self, con, obj, kind):
        """The tombstoning's audience rows (item 5, amendment A1, Opus delta R3): an expiry deletes
        them and releases their 65 B each from the workspace, the global ceiling and the head
        author's share; a retire keeps them, moving the charge off the author's share to the
        workspace alone until the object row is deleted. Returns the rows touched."""
        o, ws = obj["object_id"], obj["workspace_id"]
        count = con.execute(
            "SELECT count(*) FROM drop_audience WHERE object_id=?", (o,)
        ).fetchone()[0]
        author = obj["head_author_id"]
        device = None if author == ws else author
        release_head(con, ws, device, AUDIENCE_ROW * count, workspace=kind == "expired")
        if kind == "expired":
            con.execute("DELETE FROM drop_audience WHERE object_id=?", (o,))
            return count
        return 0

    def tombstone(self, con, obj, kind, now, limit=BATCH):
        """Make a live object an `expired` or `retired` tombstone: a file's version, wraps and
        usage go in this transaction (at most one version and 1 024 wraps), a document's count is
        released at once and its versions are left to `sweep_documents`. Assigns the new `n`.
        Returns (rows deleted, blob paths)."""
        o, ws, owner = obj["object_id"], obj["workspace_id"], obj["owner_person_id"]
        rows, paths = 0, []
        if obj["object_kind"] == "file":
            rows, paths, _more = self.free_versions(con, obj, 1 << 30)
        else:
            first = con.execute(
                "SELECT author_kind, author_id FROM drop_versions WHERE object_id=? AND version=1",
                (o,),
            ).fetchone()
            creator = first["author_id"] if first and first["author_kind"] == "device" else None
            self.drop.charge(con, ws, owner, creator, documents=-1)
        rows += self.audience(con, obj, kind)
        stamp = obj["expires_ms"] if kind == "expired" else now
        con.execute(
            "UPDATE drop_objects SET tombstone_ms=?, tombstone_kind=?, n=? WHERE object_id=?",
            (stamp, kind, self.drop.position(con), o),
        )
        return rows + 1, paths

    # --- the sweeps ------------------------------------------------------------------------------

    def transaction(self, work):
        """One write transaction under the directory lock; the files `work` names are unlinked
        after it commits. `work(con, now)` returns (progress, paths, workspaces)."""
        with self.d.lock:
            con = self.bridge.connection("write")
            con.execute("BEGIN IMMEDIATE")
            with con:
                progress, paths, changed = work(con, self.d.clock())
        for path in paths:
            with suppress(OSError):
                Path(path).unlink()
        return progress, changed

    def drain(self, work):
        """Repeat `work(con, now, skip)` in its own transaction until it makes no progress and
        skips nothing new; the workspaces whose `n` moved are returned."""
        skip, changed = set(), set()
        total = 0
        while True:
            skipped = len(skip)
            progress, moved = self.transaction(lambda con, now: work(con, now, skip))
            changed |= moved
            total += progress
            if not progress and len(skip) == skipped:  # a newly skipped object may unblock more
                return total, changed

    def guarded(self, con, skip, key, fn):
        """Run one object's sweep under a savepoint: a failure rolls it back whole, skips the object
        for the rest of the cycle and is counted; `run` reports one summary line per cycle with
        the first traceback (never one traceback per object; item 12, R3)."""
        con.execute("SAVEPOINT sweep")
        try:
            result = fn()
        except Exception:  # noqa: BLE001 any failure of one object: isolate it, never block the batch (R3)
            self.object_failures += 1
            if self.first_failure is None:
                self.first_failure = (key, traceback.format_exc())
            con.execute("ROLLBACK TO sweep")
            con.execute("RELEASE sweep")
            skip.add(key)
            return None
        con.execute("RELEASE sweep")
        return result

    def sweep_expiry(self, con, now, skip):
        rows = con.execute(
            "SELECT * FROM drop_objects WHERE tombstone_ms IS NULL AND expires_ms IS NOT NULL "
            "AND expires_ms<=? ORDER BY expires_ms, object_id LIMIT ?",
            (now, BATCH + len(skip)),
        ).fetchall()
        budget, done, paths, changed = BATCH, 0, [], set()
        for obj in rows:
            if obj["object_id"] in skip or (done and budget <= 0):
                continue
            result = self.guarded(
                con,
                skip,
                obj["object_id"],
                lambda obj=obj: self.tombstone(con, obj, "expired", now),
            )
            if result is None:
                continue
            used, freed = result
            budget -= used
            done += 1
            paths += freed
            changed.add(obj["workspace_id"])
        return done, paths, changed

    def sweep_documents(self, con, now, skip):
        """A tombstoned object that still has versions (a retired document): release them in
        batches. No new `n`: the retire assigned it."""
        rows = con.execute(
            "SELECT o.* FROM drop_objects o WHERE o.tombstone_ms IS NOT NULL AND EXISTS "
            "(SELECT 1 FROM drop_versions v WHERE v.object_id=o.object_id) "
            "ORDER BY o.tombstone_ms, o.object_id LIMIT ?",
            (1 + len(skip),),
        ).fetchall()
        for obj in rows:
            if obj["object_id"] in skip:
                continue
            result = self.guarded(
                con,
                skip,
                obj["object_id"],
                lambda obj=obj: self.free_versions(con, obj, BATCH),
            )
            if result is not None:
                used, paths, _more = result
                return used, paths, set()
        return 0, [], set()

    def sweep_tombstones(self, con, now, skip):
        """Tombstones past their 30 days, once no version is left to release: the audience rows of
        a retired device-only tombstone give back their workspace and global head bytes."""
        rows = con.execute(
            "SELECT * FROM drop_objects WHERE tombstone_ms IS NOT NULL AND tombstone_ms<=? "
            "AND NOT EXISTS (SELECT 1 FROM drop_versions v WHERE v.object_id=drop_objects.object_id)"
            " ORDER BY tombstone_ms, object_id LIMIT ?",
            (now - TOMBSTONE, BATCH + len(skip)),
        ).fetchall()
        budget, done = BATCH, 0
        for obj in rows:
            if obj["object_id"] in skip or (done and budget <= 0):
                continue

            def end(obj=obj):
                count = con.execute(
                    "SELECT count(*) FROM drop_audience WHERE object_id=?", (obj["object_id"],)
                ).fetchone()[0]
                release_head(con, obj["workspace_id"], None, AUDIENCE_ROW * count)
                con.execute("DELETE FROM drop_objects WHERE object_id=?", (obj["object_id"],))
                return 1 + count

            used = self.guarded(con, skip, obj["object_id"], end)
            if used is not None:
                budget -= used
                done += 1
        return done, [], set()

    def sweep_pruning(self, con, now, skip):
        """Document blobs that are neither among the newest 8 versions nor younger than 30 days."""
        rows = con.execute(
            "SELECT v.object_id, v.version, v.author_kind, v.author_id, v.content_len, "
            "v.blob_path, o.workspace_id, o.owner_person_id, o.current, o.tombstone_ms "
            "FROM drop_versions v JOIN drop_objects o ON o.object_id=v.object_id "
            "WHERE o.object_kind='document' AND o.tombstone_ms IS NULL AND v.blob='stored' "
            "AND v.version<=o.current-? AND v.received_ms<=? ORDER BY v.object_id, v.version "
            "LIMIT ?",
            (KEEP_VERSIONS, now - PRUNE_AGE, BATCH + len(skip)),
        ).fetchall()
        budget, done, paths = BATCH, 0, []
        for row in rows:
            key = (row["object_id"], row["version"])
            if key in skip or (done and budget <= 0):
                continue
            count = con.execute(
                "SELECT count(*) FROM drop_wraps WHERE object_id=? AND version=?", key
            ).fetchone()[0]
            if (
                self.guarded(con, skip, key, lambda row=row: self.drop.prune(con, row) or True)
                is None
            ):
                continue
            budget -= 1 + count
            done += 1
            paths.append(self.drop.blobs / row["blob_path"])
        return done, paths, set()

    def sweep_device_wraps(self, con, now, skip):
        """`device` wraps whose target is no longer a member of the object's workspace or has a
        revocation: unreachable at once (the read filter), deleted here (item 10)."""
        rows = con.execute(
            "SELECT w.object_id, w.version, w.target_id, w.key_version, length(w.record) AS size, "
            "o.workspace_id, o.owner_person_id, v.author_kind, v.author_id "
            "FROM drop_wraps w JOIN drop_objects o ON o.object_id=w.object_id "
            "JOIN drop_versions v ON v.object_id=w.object_id AND v.version=w.version "
            "WHERE w.target_kind='device' AND (NOT EXISTS (SELECT 1 FROM members m WHERE "
            "m.workspace_id=o.workspace_id AND m.device_id=w.target_id) OR "
            + revoked_sql("w.target_id")
            + ") LIMIT ?",
            (BATCH + len(skip),),
        ).fetchall()
        done = 0
        for w in rows:
            key = (w["object_id"], w["version"], w["target_id"], w["key_version"])
            if key in skip or done >= BATCH:
                continue

            def drop_wrap(w=w, key=key):
                device = w["author_id"] if w["author_kind"] == "device" else None
                con.execute(
                    "DELETE FROM drop_wraps WHERE object_id=? AND version=? AND "
                    "target_kind='device' AND target_id=? AND key_version=?",
                    key,
                )
                release_head(con, w["workspace_id"], device, w["size"])
                return 1

            if self.guarded(con, skip, key, drop_wrap) is not None:
                done += 1
        return done, [], set()

    def sweep_days(self, con, now, skip):
        """The two daily tables keep the current and the previous UTC day (a slow upload that
        began before midnight still charges its start day)."""
        cut = day_of(now) - KEEP_DAYS
        done = 0
        for table, key in (
            ("drop_decide_budget", "workspace_id, device_id, day"),
            ("drop_creations", "scope, id, day"),
        ):
            done += con.execute(
                f"DELETE FROM {table} WHERE rowid IN "
                f"(SELECT rowid FROM {table} WHERE day<? LIMIT ?)",
                (cut, BATCH),
            ).rowcount
        return done, [], set()

    PHASES = (
        "sweep_expiry",
        "sweep_documents",
        "sweep_tombstones",
        "sweep_pruning",
        "sweep_device_wraps",
        "sweep_days",
    )

    def run(self):
        """One cycle of every sweep. Nothing runs, and nothing assigns a position, unless
        ORCH_RELAY_DROP=1 (returns None). Returns the workspaces whose `n` moved."""
        if not self.on:
            return None
        changed = set()
        self.object_failures, self.first_failure, self.cycle_bad = 0, None, False
        for name in self.PHASES:
            _total, moved = self.drain(getattr(self, name))
            changed |= moved
        self.cycles += 1
        if self.object_failures:  # a cycle with any failed object is a failed cycle
            self.cycle_bad = True
            key, trace = self.first_failure
            self.failed(
                f"drop sweep failed, skipped {self.object_failures} object(s) this cycle "
                f"(first: {key})",
                trace,
            )
        return changed

    def failed(self, summary, detail=""):
        """Count a failed cycle and log it: the first at once, then at most once per LOG_EVERY."""
        self.failures += 1
        self.failures_total += 1
        now = time.monotonic()
        if self.last_logged is None or now - self.last_logged >= LOG_EVERY:
            log.error(
                "%s (%d in a row, %d in all)\n%s",
                summary,
                self.failures,
                self.failures_total,
                detail,
            )
            self.last_logged = now

    def start(self):
        """The periodic task (a new asyncio task, on the running loop), or None with Drop off."""
        if not self.on:
            return None
        return asyncio.create_task(self.maintenance())

    async def maintenance(self):
        while True:
            try:
                changed = await run_in_threadpool(self.run)
                if changed and self.d.changed:
                    self.d.changed(*[("ws", ws) for ws in sorted(changed)])
            except Exception:  # noqa: BLE001 any failure: log it (rate-limited), the next cycle retries (R3)
                self.failed("drop sweep cycle failed", traceback.format_exc())
            else:
                if not self.cycle_bad:  # `run` already counted a cycle with failed objects
                    self.failures, self.last_logged = 0, None
            await asyncio.sleep(self.period)

    # --- retire ----------------------------------------------------------------------------------

    def retire(self, headers, o_id, version, head):
        """POST /v2/drop/{o}/retire, in one write transaction (§14.2 item 5, amendment A1). The
        caller parsed the body (`version` an int >= 1, `head` the 32 decoded bytes). Returns
        ({"state": ...}, the workspace whose `n` moved or None)."""
        d = self.d
        paths, moved = [], None
        with d.lock:
            con = self.bridge.connection("write")
            con.execute("BEGIN IMMEDIATE")
            with con:
                now = d.clock()
                session = d.authenticate(con, headers, now)
                if session["kind"] != "workspace":
                    refuse("not_eligible", 403)
                ws = session["subject_id"]
                d.fence(con, headers, ws, now)  # orch-52 change 0: the live holders row
                obj = con.execute(
                    "SELECT * FROM drop_objects WHERE object_id=?", (o_id,)
                ).fetchone()
                until = tombstone_until(obj, now) if obj is not None else None
                if obj is None or (until is not None and until <= now):
                    refuse("not_found", 404)
                if obj["workspace_id"] != ws:
                    refuse("not_eligible", 403)
                blob = con.execute(
                    "SELECT blob FROM drop_versions WHERE object_id=? AND version=?",
                    (o_id, obj["current"]),
                ).fetchone()
                state = state_of(obj, blob[0] if blob else None, now)
                if obj["current"] != version or P.unb64u(obj["head_hash"], 32) != head:
                    refuse("version_conflict", 409, current=obj["current"], state=state)
                if until is not None:  # a tombstone, retired or expired: the bounded retry
                    return {"state": state}, None
                _rows, paths = self.tombstone(con, obj, "retired", now)
                moved = ws
        for path in paths:
            with suppress(OSError):
                Path(path).unlink()
        return {"state": "retired"}, moved
