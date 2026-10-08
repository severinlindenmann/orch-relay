import sqlite3

from orch_relay import db


def test_migrate_creates_schema_and_wal(tmp_path):
    path = tmp_path / "relay.sqlite3"
    applied = db.migrate(path)
    assert applied and applied[0].startswith("0001")
    con = sqlite3.connect(path)
    assert con.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    names = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"schema_migrations", "meta"} <= names
    rows = con.execute("SELECT version FROM schema_migrations").fetchall()
    assert len(rows) == len(applied)


def test_migrate_is_idempotent(tmp_path):
    path = tmp_path / "relay.sqlite3"
    db.migrate(path)
    assert db.migrate(path) == []


def test_migrate_applies_only_pending(tmp_path, monkeypatch):
    mdir = tmp_path / "m"
    mdir.mkdir()
    (mdir / "0001_a.sql").write_text("CREATE TABLE a (x);")
    path = tmp_path / "r.sqlite3"
    assert db.migrate(path, mdir) == ["0001_a"]
    (mdir / "0002_b.sql").write_text("CREATE TABLE b (x);")
    assert db.migrate(path, mdir) == ["0002_b"]
    assert db.migrate(path, mdir) == []
