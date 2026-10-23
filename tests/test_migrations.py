import sqlite3
import threading

import pytest

from orch_relay import db

TABLES = {
    "hub_accounts",
    "hub_op_revoked",
    "hub_request_nonces",
    "hub_push_targets",
    "hub_mailbox",
    "hub_revoked_channels",
    "hub_channel_nonces",
}


def test_a_fresh_database_gets_the_one_schema_in_wal(tmp_path):
    path = tmp_path / "relay.sqlite3"
    assert db.init_schema(path) is True
    con = sqlite3.connect(path)
    assert con.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert con.execute("PRAGMA user_version").fetchone()[0] == db.SCHEMA_VERSION
    names = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert names == TABLES  # nothing of the per-workspace relay, no migration bookkeeping


def test_init_is_idempotent(tmp_path):
    path = tmp_path / "relay.sqlite3"
    db.init_schema(path)
    assert db.init_schema(path) is False


def test_a_database_of_another_schema_is_refused_not_upgraded(tmp_path):
    path = tmp_path / "relay.sqlite3"
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE schema_migrations (version TEXT)")  # what the old 25 migrations left
    con.commit()
    con.close()
    with pytest.raises(RuntimeError, match="another schema"):
        db.init_schema(path)
    con = sqlite3.connect(path)
    names = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert names == {"schema_migrations"}  # nothing was created or changed


def test_a_newer_version_is_refused(tmp_path):
    path = tmp_path / "relay.sqlite3"
    db.init_schema(path)
    con = sqlite3.connect(path)
    con.execute(f"PRAGMA user_version={db.SCHEMA_VERSION + 1}")
    con.close()
    with pytest.raises(RuntimeError, match="another schema"):
        db.init_schema(path)


def test_concurrent_start_on_a_fresh_database(tmp_path):
    path = tmp_path / "r.sqlite3"
    results, errors = [], []
    barrier = threading.Barrier(4)

    def run():
        barrier.wait()
        try:
            results.append(db.init_schema(path))
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    ts = [threading.Thread(target=run) for _ in range(4)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert not errors
    assert sorted(results) == [False, False, False, True]
