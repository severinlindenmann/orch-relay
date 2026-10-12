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


def test_0011_indexes_chain_revocations_by_device_and_keeps_rows(tmp_path):
    """P3-D30: 0011 adds the checkpoint_revocations(device_id, person_id) index the registration
    refusal and the per-pair revocation list use; rows are kept, it applies once and re-running its
    SQL is harmless (IF NOT EXISTS)."""
    import shutil
    from importlib import resources

    mdir = tmp_path / "m"
    mdir.mkdir()
    src = resources.files("orch_relay").joinpath("migrations")
    for e in src.iterdir():
        if e.name.endswith(".sql") and e.name < "0011":
            shutil.copy(str(e), mdir / e.name)
    path = tmp_path / "r.sqlite3"
    db.migrate(path, mdir)
    row = ("w", "d1", "p1", "lost", b"{}", b"{}", "pk", "r", "t")
    con = sqlite3.connect(path)
    with con:
        con.execute("INSERT INTO checkpoint_revocations VALUES (?,?,?,?,?,?,?,?,?)", row)
    con.close()
    name = "0011_registration_lookup.sql"
    shutil.copy(str(src.joinpath(name)), mdir / name)
    assert db.migrate(path, mdir) == ["0011_registration_lookup"]
    assert db.migrate(path, mdir) == []
    con = sqlite3.connect(path)
    assert con.execute("SELECT * FROM checkpoint_revocations").fetchall() == [row]
    index = con.execute(
        "SELECT sql FROM sqlite_master WHERE name='checkpoint_revocation_device'"
    ).fetchone()
    assert index and "(device_id, person_id)" in index[0]
    plan = con.execute(
        "EXPLAIN QUERY PLAN SELECT 1 FROM checkpoint_revocations WHERE device_id='d1' LIMIT 1"
    ).fetchall()
    assert any("checkpoint_revocation_device" in str(r) for r in plan)
    with con:
        con.execute(src.joinpath(name).read_text().split("\n")[-2])  # the CREATE, again: no-op


def test_0012_drops_evidence_only_device_rows_and_keeps_revocations(tmp_path):
    """P3-D30 round 2 (review R1): 0012 deletes device rows of evidence-only persons (and their
    sessions); accounts, evidence_persons, other devices and every revocation stay."""
    import shutil
    from importlib import resources

    mdir = tmp_path / "m"
    mdir.mkdir()
    src = resources.files("orch_relay").joinpath("migrations")
    for e in src.iterdir():
        if e.name.endswith(".sql") and e.name < "0012":
            shutil.copy(str(e), mdir / e.name)
    path = tmp_path / "r.sqlite3"
    db.migrate(path, mdir)
    con = sqlite3.connect(path)
    with con:
        con.execute("INSERT INTO accounts VALUES ('pe','pk',0),('pa','pk2',0)")
        con.execute("INSERT INTO evidence_persons VALUES ('pe')")
        con.execute("INSERT INTO devices VALUES ('de','pe','{}','s','k','[]',NULL)")
        con.execute("INSERT INTO devices VALUES ('da','pa','{}','s','k','[]',NULL)")
        con.execute("INSERT INTO sessions VALUES ('t1','device','de',9),('t2','device','da',9)")
        con.execute("INSERT INTO revocations VALUES ('de','pe','{}','lost',5,7)")
        # A registered AND revoked device of a real account (delta review S-a): it stays.
        con.execute("INSERT INTO revocations VALUES ('da','pa','{}','lost',5,8)")
        con.execute("INSERT INTO revocations VALUES ('da','pe','{}','compromised',5,9)")
    con.close()
    name = "0012_drop_evidence_devices.sql"
    shutil.copy(str(src.joinpath(name)), mdir / name)
    assert db.migrate(path, mdir) == ["0012_drop_evidence_devices"]
    assert db.migrate(path, mdir) == []
    con = sqlite3.connect(path)
    assert con.execute("SELECT device_id FROM devices").fetchall() == [("da",)]
    assert con.execute("SELECT token_hash FROM sessions").fetchall() == [("t2",)]
    assert con.execute("SELECT person_id FROM evidence_persons").fetchall() == [("pe",)]
    assert con.execute("SELECT COUNT(*) FROM accounts").fetchone()[0] == 2
    assert con.execute("SELECT * FROM revocations ORDER BY cursor").fetchall() == [
        ("de", "pe", "{}", "lost", 5, 7),
        ("da", "pa", "{}", "lost", 5, 8),
        ("da", "pe", "{}", "compromised", 5, 9),
    ]
