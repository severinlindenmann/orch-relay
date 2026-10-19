"""P3-D39 (D39a2, migration 0019): the decide-class budget table and its upsert, the daily creation
counters, `claimed_ms` and its trigger, and the no-replace trigger on `drop_objects`."""

import re
import shutil
import sqlite3
from importlib import resources
from pathlib import Path

import pytest

from orch_relay import db

SRC = Path(__file__).resolve().parents[1] / "src" / "orch_relay"
OBJECT = (
    "INSERT INTO drop_objects (object_id, workspace_id, owner_person_id, object_kind, current, "
    "inbox, expires_ms, head_author_id, head_hash, audience, n, created_ms) "
    "VALUES (?, 'w', 'p', 'file', 1, 1, 100, 'd', 'h', 'inbox', 1, 5)"
)

# The decide-class upsert of P3-D39 item 13, verbatim apart from the bind names.
BUDGET = (
    "INSERT INTO drop_decide_budget (workspace_id, device_id, day, creations, bytes) "
    "VALUES (?, ?, ?, 1, ?) ON CONFLICT (workspace_id, device_id, day) DO UPDATE "
    "SET creations = creations + 1, bytes = bytes + excluded.bytes "
    "WHERE creations + 1 <= 50 AND bytes + excluded.bytes <= 67108864"
)


@pytest.fixture
def con(tmp_path):
    path = tmp_path / "relay.sqlite3"
    assert "0019_drop_a2" in db.migrate(path)
    con = sqlite3.connect(path)
    con.execute("PRAGMA foreign_keys=ON")
    yield con
    con.close()


def test_0019_upgrades_a_0017_database_and_keeps_its_rows(tmp_path):
    mdir = tmp_path / "m"
    mdir.mkdir()
    for entry in resources.files("orch_relay").joinpath("migrations").iterdir():
        if entry.name.endswith(".sql") and entry.name < "0018":
            shutil.copy(str(entry), mdir / entry.name)
    path = tmp_path / "relay.sqlite3"
    assert db.migrate(path, mdir)[-1] == "0017_drop"
    old = sqlite3.connect(path)
    old.execute(OBJECT, ("a" * 32,))
    old.commit()
    old.close()
    assert db.migrate(path) == ["0018_push", "0019_drop_a2"]  # 0018 is D40a's push table
    con = sqlite3.connect(path)
    assert con.execute("SELECT object_id, claimed_ms FROM drop_objects").fetchall() == [
        ("a" * 32, None)
    ]
    assert db.migrate(path) == []
    con.close()


def test_0019_inserts_nothing(con):
    for table in ("drop_decide_budget", "drop_creations"):
        assert con.execute(f"SELECT count(*) FROM {table}").fetchone() == (0,)
    assert con.execute("SELECT n FROM drop_counter").fetchone() == (0,)
    assert con.execute("SELECT count(*) FROM meta WHERE key='drop_generation'").fetchone() == (0,)


def test_decide_budget_upsert_charges_the_first_upload_and_refuses_at_the_caps(con):
    def spend(nbytes, day=7):
        con.execute(BUDGET, ("w", "d", day, nbytes))
        return con.execute("SELECT changes()").fetchone()[0]

    assert spend(1000) == 1  # no row yet: the insert branch charges it
    assert con.execute("SELECT creations, bytes FROM drop_decide_budget").fetchone() == (1, 1000)
    assert spend(1000) == 1
    assert con.execute("SELECT creations, bytes FROM drop_decide_budget").fetchone() == (2, 2000)
    left = 67_108_864 - 2000
    assert spend(left + 1) == 0  # one byte over: the conflict branch's WHERE fails, nothing changes
    assert con.execute("SELECT creations, bytes FROM drop_decide_budget").fetchone() == (2, 2000)
    assert spend(left) == 1  # exactly the remaining bytes
    assert spend(1) == 0
    assert spend(1000, day=8) == 1  # another UTC day, another row
    for _ in range(49):
        spend(1, day=9)
    assert con.execute("SELECT creations FROM drop_decide_budget WHERE day=9").fetchone() == (49,)
    assert spend(1, day=9) == 1  # the 50th creation
    assert spend(1, day=9) == 0  # the 51st


def test_budget_and_creation_tables_refuse_negative_counts(con):
    with pytest.raises(sqlite3.IntegrityError):
        con.execute("INSERT INTO drop_decide_budget VALUES ('w','d',1,-1,0)")
    with pytest.raises(sqlite3.IntegrityError):
        con.execute("INSERT INTO drop_creations VALUES ('workspace','w',1,-1)")
    with pytest.raises(sqlite3.IntegrityError):
        con.execute("INSERT INTO drop_creations VALUES ('person','w',1,1)")


def test_claimed_ms_is_set_once_and_never_changed(con):
    con.execute(OBJECT, ("a" * 32,))
    assert con.execute("SELECT claimed_ms FROM drop_objects").fetchone() == (None,)
    con.execute("UPDATE drop_objects SET claimed_by='w', claimed_ms=1234")  # NULL -> value
    con.execute("UPDATE drop_objects SET claimed_ms=1234")  # the same value is not a change
    con.execute("UPDATE drop_objects SET n=9")  # other columns still update
    for statement in (
        "UPDATE drop_objects SET claimed_ms=1235",
        "UPDATE drop_objects SET claimed_ms=NULL",
    ):
        with pytest.raises(sqlite3.IntegrityError, match="claimed_ms is immutable"):
            con.execute(statement)
    assert con.execute("SELECT claimed_ms, n FROM drop_objects").fetchone() == (1234, 9)


@pytest.mark.parametrize(
    "verb",
    [
        "INSERT OR REPLACE",
        "INSERT OR IGNORE",
        "REPLACE",
        "INSERT",
    ],
)
def test_drop_objects_is_never_replaced(con, verb):
    """REPLACE deletes the row without firing the update trigger and would reset `claimed_ms`;
    the BEFORE INSERT trigger fires ahead of conflict resolution, so every variant is refused."""
    con.execute(OBJECT, ("a" * 32,))
    con.execute("UPDATE drop_objects SET claimed_by='w', claimed_ms=99")
    statement = OBJECT.replace("INSERT", verb, 1) if verb != "INSERT" else OBJECT
    with pytest.raises(sqlite3.IntegrityError, match="never replaced"):
        con.execute(statement, ("a" * 32,))
    assert con.execute("SELECT claimed_ms FROM drop_objects").fetchone() == (99,)


def test_drop_objects_upsert_on_an_existing_object_is_refused(con):
    con.execute(OBJECT, ("a" * 32,))
    with pytest.raises(sqlite3.IntegrityError, match="never replaced"):
        con.execute(OBJECT + " ON CONFLICT (object_id) DO UPDATE SET n = 2", ("a" * 32,))
    con.execute(OBJECT, ("b" * 32,))  # a new object is fine
    assert con.execute("SELECT count(*) FROM drop_objects").fetchone() == (2,)


def test_no_code_writes_drop_objects_by_position_or_replace():
    """The migration's reach is a convention too: named-column inserts only, and never a REPLACE,
    OR IGNORE or ON CONFLICT on `drop_objects` (a future idempotent insert checks existence)."""
    for path in SRC.glob("*.py"):
        text = path.read_text()
        for statement in re.findall(r"INSERT[^\"]*?INTO drop_objects[^\"]*", text):
            assert "OR REPLACE" not in statement and "OR IGNORE" not in statement, path
            assert re.match(r"INSERT INTO drop_objects \(", statement), (path, statement)
        assert not re.search(r"REPLACE INTO drop_objects", text), path


def test_object_id_is_immutable_so_update_or_replace_cannot_reset_claimed_ms(con):
    con.execute(OBJECT, ("a" * 32,))
    con.execute("UPDATE drop_objects SET claimed_by='w', claimed_ms=99")
    con.execute(OBJECT, ("b" * 32,))
    for verb in ("UPDATE", "UPDATE OR REPLACE"):
        with pytest.raises(sqlite3.IntegrityError, match="object_id is immutable"):
            con.execute(
                f"{verb} drop_objects SET object_id=? WHERE object_id=?", ("a" * 32, "b" * 32)
            )
    assert con.execute(
        "SELECT claimed_ms FROM drop_objects WHERE object_id=?", ("a" * 32,)
    ).fetchone() == (99,)
