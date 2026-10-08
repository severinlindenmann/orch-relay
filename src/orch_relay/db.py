"""SQLite (WAL) setup and a tiny numbered-.sql migration runner."""

import sqlite3
from importlib import resources
from pathlib import Path

DB_NAME = "relay.sqlite3"


def connect(path: Path) -> sqlite3.Connection:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA foreign_keys=ON")
    return con


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


def migrate(path: Path, mdir: Path | None = None) -> list[str]:
    """Apply pending migrations in order; return the versions applied."""
    con = connect(path)
    try:
        con.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations ("
            "version TEXT PRIMARY KEY, applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"
        )
        done = {r[0] for r in con.execute("SELECT version FROM schema_migrations")}
        applied = []
        for version, sql in _migration_files(mdir):
            if version in done:
                continue
            con.executescript(f"BEGIN;\n{sql}\nINSERT INTO schema_migrations(version) "
                              f"VALUES ('{version}');\nCOMMIT;")
            applied.append(version)
        return applied
    finally:
        con.close()
