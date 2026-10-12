import sqlite3

import pytest

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


def test_concurrent_migrate_same_fresh_db(tmp_path):
    import threading

    mdir = tmp_path / "m"
    mdir.mkdir()
    (mdir / "0001_a.sql").write_text("CREATE TABLE a (x);\nALTER TABLE a ADD COLUMN y;")
    path = tmp_path / "r.sqlite3"
    results, errors = [], []
    barrier = threading.Barrier(4)

    def run():
        barrier.wait()
        try:
            results.append(db.migrate(path, mdir))
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    ts = [threading.Thread(target=run) for _ in range(4)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert not errors
    assert sorted(len(r) for r in results) == [0, 0, 0, 1]


def test_failed_migration_rolls_back(tmp_path):
    import pytest

    mdir = tmp_path / "m"
    mdir.mkdir()
    (mdir / "0001_bad.sql").write_text("CREATE TABLE a (x);\nINSERT INTO nope VALUES (1);")
    path = tmp_path / "r.sqlite3"
    with pytest.raises(sqlite3.OperationalError):
        db.migrate(path, mdir)
    con = sqlite3.connect(path)
    names = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert "a" not in names


def test_0010_rekeys_revocations_per_pair_and_keeps_rows(tmp_path):
    """orch-core #397: 0010 rebuilds the 0002 revocations table keyed by (device_id, person_id),
    keeping every existing row and its feed cursor, and without the foreign key to devices."""
    import shutil
    from importlib import resources

    mdir = tmp_path / "m"
    mdir.mkdir()
    src = resources.files("orch_relay").joinpath("migrations")
    for e in src.iterdir():
        if e.name.endswith(".sql") and e.name < "0010":
            shutil.copy(str(e), mdir / e.name)
    path = tmp_path / "r.sqlite3"
    db.migrate(path, mdir)
    con = sqlite3.connect(path)
    with con:
        con.execute("INSERT INTO accounts VALUES ('p1','pk',0)")
        con.execute("INSERT INTO devices VALUES ('d1','p1','{}','s','k','[]',NULL)")
        con.execute("INSERT INTO revocations VALUES ('d1','p1','{}','lost',5,7)")
    con.close()
    shutil.copy(str(src.joinpath("0010_revocation_pairs.sql")), mdir / "0010_revocation_pairs.sql")
    assert db.migrate(path, mdir) == ["0010_revocation_pairs"]
    con = sqlite3.connect(path)
    con.execute("PRAGMA foreign_keys=ON")
    assert con.execute("SELECT * FROM revocations").fetchall() == [("d1", "p1", "{}", "lost", 5, 7)]
    with con:  # another person's pair of the same id, for a device that is not registered at all
        con.execute("INSERT INTO revocations VALUES ('d1','p2','{}','compromised',6,8)")
        con.execute("INSERT INTO revocations VALUES ('d9','p2','{}','lost',6,9)")
    with pytest.raises(sqlite3.IntegrityError):
        con.execute("INSERT INTO revocations VALUES ('d1','p1','{}','lost',6,10)")
    index = con.execute("SELECT sql FROM sqlite_master WHERE name='revocation_feed'").fetchone()
    assert index and "person_id, cursor" in index[0]
