"""SQLite (WAL) setup and the one fresh schema (V3-D36: no production data, no migrations; a database from an
older schema is wiped, never upgraded)."""

import sqlite3
import threading
import time
from contextlib import contextmanager
from importlib import resources
from pathlib import Path

DB_NAME = "relay.sqlite3"


def connect(path: Path, **options) -> sqlite3.Connection:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path, timeout=5, **options)
    con.execute("PRAGMA busy_timeout=5000")
    _set_wal(con)
    con.execute("PRAGMA synchronous=FULL")
    con.execute("PRAGMA foreign_keys=ON")
    return con


class Connections:
    """The relay process's connections, owned by no thread (P3-D32 round 2, review F1).

    One shared write connection, used only under the caller's global lock, and a bounded pool of
    query-only read connections borrowed per use. anyio retires idle worker threads and starts new
    ones, so per-thread connections would pile up; here the number of open connections never
    exceeds `size` + 1. A borrow beyond the pool gets a temporary connection that is closed on
    return. "read" connections never wait (busy_timeout=0: callers fall back to the locked path on
    sqlite3.Error); "query" ones wait like the write connection.
    """

    def __init__(self, path, size=48):
        self.path, self.size = path, size
        self.mutex = threading.Lock()
        self.idle = {"read": [], "query": []}
        self.pooled = []
        self.writer = None

    def open(self, purpose):
        con = connect(self.path, check_same_thread=False)
        con.row_factory = sqlite3.Row
        if purpose != "write":
            con.execute("PRAGMA query_only=ON")
        if purpose == "read":
            con.execute("PRAGMA busy_timeout=0")
        return con

    def write(self):
        """The shared write connection; callers hold the relay's global lock."""
        with self.mutex:
            con = self.writer
        if con is None:
            con = self.open("write")
            with self.mutex:
                if self.writer is None:
                    self.writer = con
                else:
                    con.close()
                    con = self.writer
        if con.in_transaction:
            con.rollback()
        return con

    @contextmanager
    def borrow(self, purpose="read"):
        """A read connection for one use; its snapshot is ended when it is returned."""
        with self.mutex:
            idle = self.idle[purpose]
            con = idle.pop() if idle else None
            pooled = con is not None or len(self.pooled) < self.size
            if con is None and pooled:
                self.pooled.append(None)  # reserve the slot while opening
        if con is None:
            try:
                con = self.open(purpose)
            except BaseException:
                if pooled:
                    with self.mutex:
                        self.pooled.remove(None)
                raise
            if pooled:
                with self.mutex:
                    self.pooled[self.pooled.index(None)] = con
        healthy = True  # a refusal raised by the caller leaves the connection reusable
        try:
            yield con
        finally:
            try:
                if con.in_transaction:
                    con.rollback()
            except sqlite3.Error:
                healthy = False
            with self.mutex:
                keep = pooled and healthy and con in self.pooled
                if keep:
                    self.idle[purpose].append(con)
                elif pooled and con in self.pooled:
                    self.pooled.remove(con)
            if not keep:
                con.close()

    def count(self):
        """Open connections owned by the pool (temporaries are closed on return)."""
        with self.mutex:
            return sum(con is not None for con in self.pooled) + (self.writer is not None)

    def close(self):
        with self.mutex:
            for con in [*self.pooled, self.writer]:
                if con is not None:
                    con.close()
            self.pooled, self.writer = [], None
            self.idle = {"read": [], "query": []}


def _set_wal(con: sqlite3.Connection, deadline_s: float = 5.0) -> None:
    """Switch to WAL. On a fresh file, racing connections can get "database is locked" here without
    the busy handler being consulted, so retry briefly (WAL is persistent: one success is enough)."""
    end = time.monotonic() + deadline_s
    delay = 0.005
    while True:
        try:
            con.execute("PRAGMA journal_mode=WAL")
            return
        except sqlite3.OperationalError as e:
            if "locked" not in str(e) or time.monotonic() >= end:
                raise
            time.sleep(delay)
            delay = min(delay * 2, 0.1)


SCHEMA_VERSION = 1  # PRAGMA user_version of a database created from schema.sql


def schema_sql() -> str:
    return resources.files("orch_relay").joinpath("schema.sql").read_text()


def _statements(sql: str):
    """Split a script into complete statements (so we never use executescript's implicit COMMIT)."""
    buf = ""
    for line in sql.splitlines(keepends=True):
        buf += line
        if sqlite3.complete_statement(buf):
            if buf.strip():
                yield buf
            buf = ""
    if buf.strip():
        yield buf


def init_schema(path: Path) -> bool:
    """Create the schema in a fresh database; True when it was created, False when already current.

    One write transaction (BEGIN IMMEDIATE) re-reads the version inside it, so concurrent starters serialise.
    A database that has tables but not this schema's version is refused: delete it (no data is kept across
    schema changes)."""
    con = connect(path)
    con.isolation_level = None  # explicit transaction control
    try:
        con.execute("BEGIN IMMEDIATE")
        try:
            (version,) = con.execute("PRAGMA user_version").fetchone()
            if version == SCHEMA_VERSION:
                created = False
            elif version == 0 and not con.execute("SELECT 1 FROM sqlite_master").fetchone():
                for stmt in _statements(schema_sql()):
                    con.execute(stmt)
                con.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
                created = True
            else:
                raise RuntimeError(
                    f"{path}: database is from another schema (user_version {version}); "
                    "delete it, orch-relay keeps no data across schema changes"
                )
            con.execute("COMMIT")
        except BaseException:
            con.execute("ROLLBACK")
            raise
        return created
    finally:
        con.close()
