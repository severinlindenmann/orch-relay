"""SQLite (WAL) setup and a tiny numbered-.sql migration runner."""

import sqlite3
import time
from importlib import resources
from pathlib import Path

DB_NAME = "relay.sqlite3"


def connect(path: Path) -> sqlite3.Connection:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path, timeout=5)
    con.execute("PRAGMA busy_timeout=5000")
    _set_wal(con)
    con.execute("PRAGMA synchronous=NORMAL")
    con.execute("PRAGMA foreign_keys=ON")
    return con


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


def _migration_files(mdir: Path | None) -> list[tuple[str, str]]:
    if mdir is None:
        entries = [
            (e.name, e.read_text())
            for e in resources.files("orch_relay").joinpath("migrations").iterdir()
            if e.name.endswith(".sql")
        ]
    else:
        entries = [(p.name, p.read_text()) for p in Path(mdir).glob("*.sql")]
    return sorted((n.removesuffix(".sql"), sql) for n, sql in entries)


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


def migrate(path: Path, mdir: Path | None = None) -> list[str]:
    """Apply pending migrations in order; return the versions applied.

    Each migration runs in its own write transaction (BEGIN IMMEDIATE) and the applied set is
    re-read inside it, so concurrent runners serialise instead of re-applying a migration.
    Migration files must not contain their own BEGIN/COMMIT.
    """
    con = connect(path)
    con.isolation_level = None  # explicit transaction control
    applied = []
    try:
        for version, sql in _migration_files(mdir):
            con.execute("BEGIN IMMEDIATE")
            try:
                con.execute(
                    "CREATE TABLE IF NOT EXISTS schema_migrations ("
                    "version TEXT PRIMARY KEY, applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"
                )
                seen = con.execute(
                    "SELECT 1 FROM schema_migrations WHERE version = ?", (version,)
                ).fetchone()
                if not seen:
                    for stmt in _statements(sql):
                        con.execute(stmt)
                    con.execute("INSERT INTO schema_migrations(version) VALUES (?)", (version,))
                    applied.append(version)
                con.execute("COMMIT")
            except BaseException:
                con.execute("ROLLBACK")
                raise
        return applied
    finally:
        con.close()
