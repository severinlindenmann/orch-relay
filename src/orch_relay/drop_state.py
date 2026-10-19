"""P3-D39 (D39a2 part 4): the Drop high-water state and the relay `generation` (design §14.2 item 14,
amendment A2 revisions 3 to 5).

The `generation` (meta key `drop_generation`, 32 lower-case hex characters) changes only when the
Drop dataset was restored or replaced. The relay detects that structurally: `ORCH_RELAY_STATE`
(a directory outside the data directory that no backup, restore, rollback or reset touches) holds

* `drop-hwm.json`: `{"generation": <hex>, "n": <committed drop_counter.n>}`, written atomically (a
  temporary file in the state directory, `fsync`, `rename`, a directory `fsync`) at every start, at
  most every 60 s while the counter changes, and at a clean shutdown. A failed periodic or shutdown
  write never blocks or fails a commit: it is logged at ERROR and retried at the next tick.
* `drop-hwm.lock`: a separate file, never renamed, locked exclusively (`flock`) by `serve` for the
  process lifetime. Contention is retried for 30 s and then counts as a failed check.

Start order: the state check (directory, `realpath`, writability, not the data directory or inside
it), then the lock, then the generation check with the start write of `drop-hwm.json` (inside the
one write transaction that regenerates the meta row, so a failed write leaves the row alone), and
only then the Drop routes and the sweeps that assign change positions.

A failed check (RH) means two things, enforced in `drop.py` and `drop_life.py` through `ok` and
`may_assign`: with ORCH_RELAY_DROP=1 no Drop route (404 as absent); with the counter above 0, Drop on
or off, no code that assigns a change position. The process stays up and serves every other route.

The check and the writer run whenever ORCH_RELAY_STATE is set, Drop is on, or the Drop tables are
not empty (RF). Clocks, the sleep and the lock wait are injected, never widened.
"""

import asyncio
import fcntl
import json
import logging
import os
import re
import secrets
import sqlite3
import tempfile
import threading
import time
from contextlib import closing, suppress
from pathlib import Path

from . import db

log = logging.getLogger(__name__)

HWM, LOCK = "drop-hwm.json", "drop-hwm.lock"
KEY = "drop_generation"
LOCK_WAIT_S = 30.0
LOCK_POLL_S = 0.25
WRITE_EVERY_S = 60.0
TICK_S = 1.0
LOG_EVERY_S = 60.0
GENERATION = re.compile(r"[0-9a-f]{32}")


class StateError(Exception):
    """The state check failed; the message says why (logged at ERROR)."""


class State:
    def __init__(self, data_dir, env=None, drop_on=False, hold_lock=False):
        env = os.environ if env is None else env
        self.raw = env.get("ORCH_RELAY_STATE") or None
        self.data = Path(data_dir)
        self.path = self.data / db.DB_NAME
        self.drop_on, self.hold_lock = drop_on, hold_lock
        self.monotonic, self.sleep = time.monotonic, time.sleep  # injected by tests
        self.lock_wait, self.write_every = LOCK_WAIT_S, WRITE_EVERY_S
        self.ok = False  # no Drop route and no `n`-assigning code until `start` says so
        self.required = False
        self.dir = None
        self.lock_fd = None
        self.generation = None  # held in memory from the start check (Opus delta L1)
        self.written_n = self.written_at = self.last_logged = None
        self.failed_writes = 0
        self.flush_lock = threading.Lock()  # one writer at a time: the mark never goes down

    # --- the start ---------------------------------------------------------------------------------

    def tables_nonempty(self):
        with closing(db.connect(self.path)) as con:
            n = con.execute("SELECT n FROM drop_counter WHERE id=0").fetchone()[0]
            return n > 0 or con.execute("SELECT 1 FROM drop_objects LIMIT 1").fetchone() is not None

    def start(self):
        """The start check. Returns `ok`; a failure is logged at ERROR and lasts until the next
        start (no retry while the process runs)."""
        try:
            self.required = self.drop_on or self.raw is not None or self.tables_nonempty()
            if not self.required:
                self.ok = True  # Drop off, nothing configured, nothing stored: nothing to guard
                return True
            self.check()
        except Exception as exc:  # noqa: BLE001  any failure is a failed check; the process stays up (Opus LOW-2)
            self.required = True
            log.error(
                "drop state check failed: %s (Drop routes are off%s; other routes keep serving)",
                exc,
                ", no change positions are assigned" if self.counter_above_zero() else "",
            )
            self.ok, self.generation = False, None
            self.release()
        else:
            self.ok = True
        return self.ok

    def counter_above_zero(self):
        try:
            return self.counter() > 0
        except Exception:  # noqa: BLE001
            return True  # fail closed

    def counter(self):
        with closing(db.connect_existing(self.path)) as con:
            return con.execute("SELECT n FROM drop_counter WHERE id=0").fetchone()[0]

    def check(self):
        if self.raw is None:
            raise StateError("ORCH_RELAY_STATE is not set")
        state = Path(os.path.realpath(self.raw))
        data = Path(os.path.realpath(self.data))
        if not state.is_dir():
            raise StateError(f"ORCH_RELAY_STATE {state} is not an existing directory")
        if state == data or data in state.parents:
            raise StateError(f"ORCH_RELAY_STATE {state} is the data directory or inside it")
        if not os.access(state, os.W_OK | os.X_OK):
            raise StateError(f"ORCH_RELAY_STATE {state} is not writable")
        self.dir = state
        try:
            st = state.stat()
            if st.st_mode & 0o022 or st.st_uid != os.getuid():
                log.warning(
                    "ORCH_RELAY_STATE %s is group/world-writable or not owned by this user "
                    "(mode %o, uid %d); it should be 0700 and owned by the relay user",
                    state,
                    st.st_mode & 0o7777,
                    st.st_uid,
                )
        except OSError:
            pass
        if self.hold_lock:
            self.take_lock()
            for leftover in self.dir.glob(".drop-hwm.*.tmp"):  # a crash between create and rename
                with suppress(OSError):
                    leftover.unlink()
        self.start_write()

    def take_lock(self):
        fd = os.open(self.dir / LOCK, os.O_CREAT | os.O_RDWR | os.O_CLOEXEC, 0o600)
        deadline = self.monotonic() + self.lock_wait
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.lock_fd = fd
                return
            except OSError:
                if self.monotonic() >= deadline:
                    os.close(fd)
                    raise StateError(f"{self.dir / LOCK} is locked by another process") from None
                self.sleep(LOCK_POLL_S)

    def release(self):
        if self.lock_fd is not None:
            with suppress(OSError):
                os.close(self.lock_fd)  # closing drops the flock
            self.lock_fd = None

    def read_hwm(self):
        """The file's `(generation, n)`, or None when missing, unreadable or malformed."""
        try:
            data = json.loads((self.dir / HWM).read_text())
            gen, n = data["generation"], data["n"]
            if (
                set(data) == {"generation", "n"}
                and isinstance(gen, str)
                and GENERATION.fullmatch(gen)
                and type(n) is int
                and n >= 0
            ):
                return gen, n
        except (OSError, ValueError, KeyError, TypeError):
            pass
        return None

    def start_write(self):
        """The generation check and the start write in one write transaction: regenerate the row
        when it is missing or malformed, when the file is missing or unreadable, names another
        generation, or holds an `n` above the counter (a restore, a rollback or a reset)."""
        con = db.connect(self.path)
        con.isolation_level = None
        try:
            con.execute("BEGIN IMMEDIATE")
            try:
                row = con.execute("SELECT value FROM meta WHERE key=?", (KEY,)).fetchone()
                n = con.execute("SELECT n FROM drop_counter WHERE id=0").fetchone()[0]
                hwm = self.read_hwm()
                gen = row[0] if row else None
                stale = hwm is None or hwm[0] != gen or hwm[1] > n
                if gen is None or not GENERATION.fullmatch(gen) or stale:
                    new = secrets.token_hex(16)
                    log.warning(
                        "drop generation regenerated (row %s, high-water file %s, counter %d)",
                        "missing" if row is None else "present",
                        "missing" if hwm is None else f"n={hwm[1]}",
                        n,
                    )
                    con.execute(
                        "INSERT INTO meta(key, value) VALUES (?, ?) "
                        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                        (KEY, new),
                    )
                    gen = new
                self.write(gen, n)  # a failure rolls the row back: the check has failed
                con.execute("COMMIT")
            except BaseException:
                con.execute("ROLLBACK")
                raise
        finally:
            con.close()
        self.generation = gen
        self.written_n, self.written_at = n, self.monotonic()

    # --- the writer --------------------------------------------------------------------------------

    def write(self, generation, n):
        """drop-hwm.json by a temporary file in the state directory, fsync, rename, directory fsync."""
        text = json.dumps({"generation": generation, "n": n}, sort_keys=True) + "\n"
        fd, tmp = tempfile.mkstemp(dir=self.dir, prefix=".drop-hwm.", suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                f.write(text)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.dir / HWM)
        except BaseException:
            with suppress(OSError):
                os.unlink(tmp)
            raise
        dfd = os.open(self.dir, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)

    def flush(self):
        """Write the committed counter now; never raises (logged at ERROR, retried by the next tick)."""
        try:
            with self.flush_lock:
                n = (
                    self.counter()
                )  # committed, from the database (never an in-memory next position)
                if self.written_n is not None and n < self.written_n:
                    # the database went backwards under a running process (a swapped file)
                    log.error(
                        "drop counter %d is below the written high-water mark %d while running; "
                        "Drop routes are off until the next start",
                        n,
                        self.written_n,
                    )
                    self.ok = False
                    return False
                n = max(n, self.written_n or 0)
                self.write(self.generation, n)
                self.written_n, self.written_at = n, self.monotonic()
        except (OSError, sqlite3.Error) as exc:
            self.failed_writes += 1
            now = self.monotonic()
            if self.last_logged is None or now - self.last_logged >= LOG_EVERY_S:
                self.last_logged = now
                log.error(
                    "drop-hwm.json write failed (%s); will retry (%d so far)",
                    exc,
                    self.failed_writes,
                )
            return False
        self.last_logged = None
        return True

    def tick(self):
        """One writer step: when the counter moved and the last write is 60 s old, write it."""
        if not self.ok or self.dir is None or self.generation is None:
            return False
        if self.written_at is not None and self.monotonic() - self.written_at < self.write_every:
            return False
        try:
            if self.counter() == self.written_n:
                return False
        except sqlite3.Error:
            pass  # fall through to a write attempt, which logs a persistent failure
        return self.flush()

    async def maintenance(self):
        while True:
            try:
                await asyncio.get_running_loop().run_in_executor(None, self.tick)
            except Exception:
                log.exception("drop-hwm writer step failed")
            await asyncio.sleep(TICK_S)

    def shutdown(self):
        """A clean shutdown: the last write, then the lock."""
        if self.ok and self.dir is not None and self.generation is not None:
            self.flush()
        self.release()
