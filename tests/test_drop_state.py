"""P3-D39 (D39a2 part 4, §14.2 item 14): the Drop high-water state. `ORCH_RELAY_STATE`,
`drop-hwm.json`, `drop-hwm.lock`, the start order, the restore detection that regenerates the
`generation`, the failure rules (RH) and the state-check gate in front of the `n`-assigning code."""

import json
import logging
import os
import re
import shutil
import sqlite3
import time
from contextlib import closing
from pathlib import Path

import pytest
from directory_support import DEVICE, NOW, WS
from drop_support import TOKENS, put, rows, setup, upload
from fastapi.testclient import TestClient

from orch_relay import cli, db
from orch_relay import drop_state as S
from orch_relay.app import create_app


@pytest.fixture
def dirs(tmp_path, monkeypatch):
    """A data directory and a state directory, siblings (the deployed layout)."""
    data, state = tmp_path / "data", tmp_path / "state"
    data.mkdir()
    state.mkdir(mode=0o700)
    monkeypatch.setenv("ORCH_RELAY_STATE", str(state))
    return data, state


def hwm(state):
    return json.loads((state / S.HWM).read_text())


def meta(data):
    with closing(db.connect(data / db.DB_NAME)) as con:
        row = con.execute("SELECT value FROM meta WHERE key='drop_generation'").fetchone()
        return row and row[0]


def counter(data):
    with closing(db.connect(data / db.DB_NAME)) as con:
        return con.execute("SELECT n FROM drop_counter").fetchone()[0]


def start(data, serve=False):
    """A relay on `data` with the test clock set before the lifespan (the sweeper's first cycle
    runs at the start and must not see the wall clock)."""
    app = create_app(data, serve=serve)
    app.state.directory.clock = lambda: NOW
    return TestClient(app)


def list_page(c, who=WS, **extra):
    return c.post(
        "/v2/drop/list",
        json={"workspace_id": WS, "direction": "received", **extra},
        headers={"Authorization": "Bearer " + TOKENS[who]},
    )


def prep(c):
    """The vector workspace on first use; later runs only need the test clock."""
    d = c.app.state.directory
    if rows(d.path, "workspaces"):
        d.clock = lambda: NOW
    else:
        setup(d)


def seed(data, *labels):
    """Run one relay session that stores one file per label; returns the objects."""
    out = []
    with start(data) as c:
        prep(c)
        for label in labels:
            s, _w, b = upload(label)
            assert put(c, s, b).status_code == 201
            out.append(s["o"]["object_id"])
    return out


def fake_clock(state):
    t = [0.0]
    state.monotonic = lambda: t[0]
    state.sleep = lambda s: t.__setitem__(0, t[0] + s)
    return t


# --- a good start -----------------------------------------------------------------------------------


def test_the_start_writes_the_high_water_file_with_the_generation_and_counter(dirs):
    data, state = dirs
    with start(data) as c:
        g = c.app.state.drop.state.generation
        assert re.fullmatch(r"[0-9a-f]{32}", g) and meta(data) == g
        assert hwm(state) == {"generation": g, "n": 0}
        assert c.app.state.drop.state.ok and c.app.state.drop.state.required
        assert list_page(c).status_code in (200, 401, 403)  # the route exists
    assert sorted(p.name for p in state.iterdir()) == [
        S.HWM
    ]  # no temp file left, no lock (not serve)


def test_a_plain_restart_keeps_the_generation_and_the_shutdown_writes_the_counter(dirs):
    data, state = dirs
    (o,) = seed(data, "a")
    assert hwm(state)["n"] == 1  # the shutdown write, always a committed value
    g = hwm(state)["generation"]
    with start(data) as c:
        assert c.app.state.drop.state.generation == g
    assert hwm(state) == {"generation": g, "n": 1}
    assert o  # one object stored


def test_the_state_files_and_the_lock_are_in_the_state_directory_for_serve_only(dirs):
    data, state = dirs
    with start(data, serve=True):
        assert sorted(p.name for p in state.iterdir()) == sorted([S.HWM, S.LOCK])
        assert oct((state / S.LOCK).stat().st_mode & 0o777) == "0o600"
    assert (state / S.LOCK).exists()  # never removed, only unlocked


# --- restore detection ------------------------------------------------------------------------------


def prime(data, state, n=3, generation=None):
    """A state directory that remembers `n` committed positions of `generation` (a real earlier run)."""
    seed(data, *[f"o{i}" for i in range(n)])
    if generation is not None:
        (state / S.HWM).write_text(json.dumps({"generation": generation, "n": n}))
    return hwm(state)["generation"]


def test_a_counter_below_the_high_water_mark_regenerates(dirs):
    data, state = dirs
    old = prime(data, state, 3)
    (state / S.HWM).write_text(json.dumps({"generation": old, "n": 99}))
    with start(data) as c:
        new = c.app.state.drop.state.generation
        assert new != old and meta(data) == new
        assert hwm(state) == {
            "generation": new,
            "n": 3,
        }  # the file is re-based on the restored counter


def test_a_counter_equal_to_the_mark_does_not_regenerate(dirs):
    data, state = dirs
    old = prime(data, state, 3)
    with start(data) as c:
        assert c.app.state.drop.state.generation == old


def test_a_mark_naming_another_generation_regenerates(dirs):
    data, state = dirs
    old = prime(data, state, 2)
    (state / S.HWM).write_text(json.dumps({"generation": "1" * 32, "n": 2}))
    with start(data) as c:
        assert c.app.state.drop.state.generation not in (old, "1" * 32)


def test_a_missing_mark_with_a_non_empty_database_regenerates(dirs):
    data, state = dirs
    old = prime(data, state, 2)
    (state / S.HWM).unlink()
    with start(data) as c:
        new = c.app.state.drop.state.generation
        assert new != old and hwm(state) == {"generation": new, "n": 2}


@pytest.mark.parametrize(
    "text",
    [
        "",
        "not json",
        "[]",
        '{"generation": "x", "n": 1}',
        '{"generation": "%s", "n": -1}',
        '{"generation": "%s", "n": "1"}',
        '{"generation": "%s", "n": 1, "extra": 1}',
        '{"n": 1}',
    ],
)
def test_an_unreadable_or_malformed_mark_regenerates(dirs, text):
    data, state = dirs
    old = prime(data, state, 1)
    (state / S.HWM).write_text(text.replace("%s", old))
    with start(data) as c:
        assert c.app.state.drop.state.generation != old


def test_a_missing_row_regenerates_even_with_a_matching_mark(dirs):
    data, state = dirs
    old = prime(data, state, 1)
    with closing(db.connect(data / db.DB_NAME)) as con, con:
        con.execute("DELETE FROM meta WHERE key='drop_generation'")  # the restore runbook step
    with start(data) as c:
        assert c.app.state.drop.state.generation != old


def test_a_malformed_row_regenerates(dirs):
    data, state = dirs
    prime(data, state, 1)
    with closing(db.connect(data / db.DB_NAME)) as con, con:
        con.execute("UPDATE meta SET value='NOT-HEX' WHERE key='drop_generation'")
    with start(data) as c:
        assert re.fullmatch(r"[0-9a-f]{32}", c.app.state.drop.state.generation)


def test_step_b_an_empty_new_data_directory_with_the_old_state_regenerates(dirs, tmp_path):
    data, state = dirs
    old = prime(data, state, 3)
    new_data = (
        tmp_path / "data-new"
    )  # `mv data data.bak; mkdir data`: the state directory untouched
    new_data.mkdir()
    with start(new_data) as c:
        assert c.app.state.drop.state.generation != old
        assert hwm(state)["n"] == 0


def test_a_cp_a_rollback_of_the_data_directory_regenerates_and_a_stale_list_is_409(dirs, tmp_path):
    data, state = dirs
    seed(data, "a")
    backup = tmp_path / "data.bak"
    shutil.copytree(data, backup)  # the earlier copy: n 1
    seed(data, "b", "c")  # n 3 (the setup rows are seeded again: same ids, ok)
    g_before = hwm(state)["generation"]
    shutil.rmtree(data)
    shutil.copytree(backup, data)  # §6.2 `cp -a` rollback
    with start(data) as c:
        prep(c)
        new = c.app.state.drop.state.generation
        assert new != g_before
        stale = list_page(c, after=1, generation=g_before)
        assert (stale.status_code, stale.json()) == (409, {"error": "generation_changed"})
        again = list_page(c, after=1, generation=new)
        assert again.status_code == 200


def test_the_check_runs_before_the_start_up_sweep_whose_pruning_renumbers(dirs, tmp_path):
    data, state = dirs
    seed(data, "a")
    backup = tmp_path / "relay.bak"
    with closing(db.connect(data / db.DB_NAME)) as src, closing(sqlite3.connect(backup)) as dst:
        src.backup(dst)  # `sqlite3 .backup` at n 1
    seed(data, "b", "c")  # n 3, the host stored (G, 3)
    g = hwm(state)["generation"]
    for f in (data / db.DB_NAME, data / (db.DB_NAME + "-wal"), data / (db.DB_NAME + "-shm")):
        f.unlink(missing_ok=True)
    shutil.copy(backup, data / db.DB_NAME)
    shutil.rmtree(data / "drop")  # restored without data/drop: the sweep prunes a (n 2)
    with start(data) as c:
        prep(c)
        assert counter(data) == 2  # the pruning did renumber past ...
        # ... but a host that stored (G, 3) is answered 409, with or without its generation
        for extra in ({"after": 3, "generation": g}, {"after": 3}):
            r = list_page(c, **extra)
            assert (r.status_code, r.json()) == (409, {"error": "generation_changed"}), extra


# --- failure rules ----------------------------------------------------------------------------------


def failed(c, caplog=None):
    st = c.app.state.drop.state
    return not st.ok


def drop_routes_are_absent(c):
    r = list_page(c)
    return r.status_code == 404 and r.json() == {"detail": "Not Found"}


def test_unset_with_drop_on_serves_no_drop_route_and_everything_else(dirs, monkeypatch, caplog):
    data, _ = dirs
    monkeypatch.delenv("ORCH_RELAY_STATE")
    with caplog.at_level(logging.ERROR), start(data) as c:
        assert failed(c) and drop_routes_are_absent(c)
        assert c.get("/healthz").json()["ok"] is True
        assert c.app.state.drop.state.generation is None
    assert "ORCH_RELAY_STATE is not set" in caplog.text
    assert meta(data) is None  # the row was not touched


@pytest.mark.parametrize("kind", ["missing", "file", "inside", "equal", "symlink_inside"])
def test_an_invalid_state_directory_fails_the_check(dirs, monkeypatch, tmp_path, kind):
    data, _ = dirs
    bad = {
        "missing": tmp_path / "nope",
        "file": tmp_path / "afile",
        "inside": data / "state",
        "equal": data,
        "symlink_inside": tmp_path / "link",
    }[kind]
    if kind == "file":
        bad.write_text("x")
    elif kind == "inside":
        bad.mkdir()
    elif kind == "symlink_inside":
        (data / "real").mkdir()
        bad.symlink_to(data / "real")  # realpath lands inside the data directory
    monkeypatch.setenv("ORCH_RELAY_STATE", str(bad))
    with start(data) as c:
        assert failed(c) and drop_routes_are_absent(c)
        assert c.get("/healthz").status_code == 200
    assert sorted(p.name for p in data.glob("**/drop-hwm*")) == []  # nothing written inside data


def test_a_relative_state_path_is_resolved_and_a_data_dir_given_as_a_symlink_is_caught(
    dirs, monkeypatch, tmp_path
):
    data, _state = dirs
    link = tmp_path / "datalink"
    link.symlink_to(data)
    monkeypatch.setenv("ORCH_RELAY_STATE", str(link / "inner"))
    (data / "inner").mkdir()
    with start(link) as c:  # data given through a symlink; the state directory is inside it
        assert failed(c)


def test_an_unwritable_state_directory_fails_the_check(dirs):
    data, state = dirs
    state.chmod(0o500)
    try:
        with start(data) as c:
            assert failed(c) and drop_routes_are_absent(c)
    finally:
        state.chmod(0o700)


def test_a_failed_start_write_fails_the_check_and_leaves_the_row_alone(dirs, monkeypatch, caplog):
    data, state = dirs
    old = prime(data, state, 1)
    with closing(db.connect(data / db.DB_NAME)) as con, con:
        con.execute("DELETE FROM meta WHERE key='drop_generation'")

    def boom(self, generation, n):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(S.State, "write", boom)
    with caplog.at_level(logging.ERROR), start(data) as c:
        assert failed(c) and drop_routes_are_absent(c)
        assert c.get("/healthz").status_code == 200
    assert meta(data) is None  # the regenerated row was rolled back with the failed write
    assert hwm(state)["generation"] == old and "check failed" in caplog.text


def test_a_second_serve_fails_its_check_while_the_first_keeps_serving(dirs):
    data, state = dirs
    with start(data, serve=True) as first:
        setup(first.app.state.directory)
        g = first.app.state.drop.state.generation
        before = (state / S.HWM).stat().st_ino
        first.app.state.drop.state.flush()  # a rename of drop-hwm.json: its inode changes
        assert (state / S.HWM).stat().st_ino != before
        second = create_app(data, serve=True)
        t = fake_clock(second.state.drop.state)
        with TestClient(second) as c2:
            st = c2.app.state.drop.state
            assert not st.ok and t[0] >= S.LOCK_WAIT_S  # retried for 30 s, then failed
            assert drop_routes_are_absent(c2) and c2.get("/healthz").status_code == 200
            assert st.generation is None and st.lock_fd is None
        assert meta(data) == g  # the loser did not touch the row ...
        assert hwm(state)["generation"] == g  # ... nor the file
        assert first.app.state.drop.state.ok and list_page(first).status_code == 200


def test_the_lock_is_a_separate_file_that_survives_hwm_renames(dirs):
    data, state = dirs
    with start(data, serve=True) as c:
        lock_ino = (state / S.LOCK).stat().st_ino
        for _ in range(3):
            c.app.state.drop.state.flush()
        assert (state / S.LOCK).stat().st_ino == lock_ino
        other = S.State(data, os.environ, drop_on=True, hold_lock=True)
        fake_clock(other)
        assert not other.start()


def test_lock_contention_is_retried_and_succeeds_when_the_holder_goes_away(dirs):
    data, _state = dirs
    holder = S.State(data, os.environ, drop_on=True, hold_lock=True)
    assert seed(data) == [] and holder.start()
    waiter = S.State(data, os.environ, drop_on=True, hold_lock=True)
    t = fake_clock(waiter)
    polls = []

    def sleep(seconds):
        polls.append(seconds)
        t[0] += seconds
        if len(polls) == 3:
            holder.release()  # a restart overlap ends

    waiter.sleep = sleep
    assert waiter.start() and len(polls) == 3 and t[0] < S.LOCK_WAIT_S
    waiter.release()


def test_a_non_serve_app_takes_no_lock_so_admin_tools_never_collide(dirs):
    data, _state = dirs
    with start(data, serve=True), start(data) as c:  # not serve: the check passes without the lock
        assert c.app.state.drop.state.ok and c.app.state.drop.state.lock_fd is None


def test_serve_is_the_only_caller_that_asks_for_the_lock(monkeypatch):
    seen = {}

    def fake_run(app, **kw):
        seen["lock"] = app.state.drop.state.hold_lock

    monkeypatch.setattr("uvicorn.run", fake_run)
    assert cli.main(["serve"]) == 0
    assert seen == {"lock": True}
    assert create_app(Path("/nonexistent-never-started")).state.drop.state.hold_lock is False


def test_drop_off_with_the_state_set_and_non_empty_tables_runs_check_and_writer(dirs, monkeypatch):
    data, state = dirs
    old = prime(data, state, 2)
    monkeypatch.setenv("ORCH_RELAY_DROP", "0")
    (state / S.HWM).write_text(json.dumps({"generation": old, "n": 50}))  # a restore, Drop off
    with start(data) as c:
        st = c.app.state.drop.state
        assert st.required and st.ok and st.generation != old  # regenerated with Drop off
        assert hwm(state) == {"generation": st.generation, "n": 2}
        assert list_page(c).status_code == 404  # no Drop route with Drop off
        assert counter(data) == 2


def test_drop_off_and_state_unset_with_non_empty_tables_fails_the_check_and_freezes_n(
    dirs, monkeypatch, caplog
):
    data, _ = dirs
    (o,) = seed(data, "a")
    monkeypatch.setenv("ORCH_RELAY_DROP", "0")
    monkeypatch.delenv("ORCH_RELAY_STATE")
    with caplog.at_level(logging.ERROR), start(data) as c:
        assert failed(c) and c.app.state.drop.state.required
        assert c.app.state.drop.life.run() is None
        assert not c.app.state.drop.may_assign()
    assert "not set" in caplog.text and o and counter(data) == 1


def test_drop_off_empty_database_and_nothing_configured_needs_no_check(dirs, monkeypatch):
    data, _ = dirs
    monkeypatch.setenv("ORCH_RELAY_DROP", "0")
    monkeypatch.delenv("ORCH_RELAY_STATE")
    with start(data) as c:
        st = c.app.state.drop.state
        assert st.ok and not st.required and st.generation is None
        assert c.app.state.drop.may_assign()


def test_drop_on_unset_with_counter_zero_serves_no_route_but_may_assign(dirs, monkeypatch):
    data, _ = dirs
    monkeypatch.delenv("ORCH_RELAY_STATE")
    with start(data) as c:
        assert failed(c) and drop_routes_are_absent(c)
        assert c.app.state.drop.may_assign()  # n = 0: nothing a client could hold


# --- the gate ---------------------------------------------------------------------------------------


def test_a_failed_check_with_n_above_zero_runs_no_startup_pruning(dirs, monkeypatch):
    data, state = dirs
    (o,) = seed(data, "a")
    blobs = [p for p in (data / "drop" / "blobs").rglob("*") if p.is_file()]
    assert len(blobs) == 1
    blobs[0].unlink()  # a restored database without data/drop: the sweep would prune and renumber
    monkeypatch.delenv("ORCH_RELAY_STATE")
    with start(data) as c:
        assert failed(c)
        with closing(db.connect(data / db.DB_NAME)) as con:
            assert con.execute("SELECT n FROM drop_counter").fetchone()[0] == 1
            assert con.execute("SELECT blob FROM drop_versions").fetchone()[0] == "stored"
    # with the check passing, the same start does prune (n 2): the gate is what held it back
    monkeypatch.setenv("ORCH_RELAY_STATE", str(state))
    with start(data):
        pass
    assert counter(data) == 2 and o


def test_a_failed_check_with_n_above_zero_runs_no_sweeper_cycle(dirs, monkeypatch):
    data, state = dirs
    seed(data, "a")
    monkeypatch.setenv("ORCH_RELAY_STATE", str(data))  # invalid: equal to the data directory
    with start(data) as c:
        d = c.app.state.directory
        prep(c)
        with closing(db.connect(d.path)) as con, con:
            con.execute("UPDATE drop_objects SET expires_ms=?", (NOW - 10,))
        assert c.app.state.drop.life.run() is None
        assert counter(data) == 1
        assert rows(d.path, "drop_objects")[0]["tombstone_kind"] is None
    monkeypatch.setenv("ORCH_RELAY_STATE", str(state))
    with start(data) as c:
        prep(c)
        # the same sweep ran at this start, with the check passed
        assert rows(c.app.state.directory.path, "drop_objects")[0]["tombstone_kind"] == "expired"


def test_a_failed_check_with_n_zero_does_not_stop_the_sweepers(dirs, monkeypatch):
    data, _ = dirs
    monkeypatch.delenv("ORCH_RELAY_STATE")
    with start(data) as c:
        assert c.app.state.drop.life.run() == set()


def test_a_failed_check_serves_no_route_and_never_a_route_for_a_wrong_method(dirs, monkeypatch):
    data, _ = dirs
    monkeypatch.delenv("ORCH_RELAY_STATE")
    with start(data) as c:
        for method, path in (
            ("POST", "/v2/drop/list"),
            ("GET", "/v2/drop/" + "a" * 32 + "/descriptors"),
            ("POST", "/v2/drop/" + "a" * 32 + "/retire"),
            ("PUT", "/v2/drop/" + "a" * 32 + "/versions"),
            ("GET", "/v2/drop/" + "a" * 32 + "/versions/1/blob"),
        ):
            r = c.request(method, path, headers={"Authorization": "Bearer FAKE-workspace"})
            assert (r.status_code, r.json()) == (404, {"detail": "Not Found"}), path


# --- the writer -------------------------------------------------------------------------------------


def writer(c):
    st = c.app.state.drop.state
    t = fake_clock(st)
    st.written_at = 0.0
    return st, t


def test_the_writer_writes_a_committed_counter_at_most_every_60_seconds(dirs):
    data, state = dirs
    with start(data) as c:
        prep(c)
        st, t = writer(c)
        assert st.tick() is False  # nothing changed
        s1, _w, b1 = upload("a")
        assert put(c, s1, b1).status_code == 201  # n 1
        t[0] = 59.9
        assert st.tick() is False and hwm(state)["n"] == 0  # not before 60 s
        t[0] = 60.0
        assert st.tick() is True and hwm(state)["n"] == 1
        s2, _w, b2 = upload("b")
        assert put(c, s2, b2).status_code == 201  # n 2
        t[0] = 119.0
        assert st.tick() is False and hwm(state)["n"] == 1
        t[0] = 120.0
        assert st.tick() is True and hwm(state)["n"] == 2
        assert st.tick() is False  # unchanged: no write


def test_a_commit_a_long_time_after_the_last_write_is_written_at_the_next_tick(dirs):
    data, state = dirs
    with start(data) as c:
        prep(c)
        st, t = writer(c)
        t[0] = 10_000.0
        s1, _w, b1 = upload("a")
        assert put(c, s1, b1).status_code == 201
        assert st.tick() is True and hwm(state)["n"] == 1


def test_the_writer_reads_the_committed_counter_not_an_in_memory_position(dirs, monkeypatch):
    data, state = dirs
    with start(data) as c:
        prep(c)
        st, t = writer(c)
        with closing(db.connect(data / db.DB_NAME)) as con:
            con.isolation_level = None
            con.execute("BEGIN IMMEDIATE")
            con.execute("UPDATE drop_counter SET n=7")  # an uncommitted position
            t[0] = 100.0
            monkeypatch.setattr(S.State, "counter", lambda self: 0)  # a reader sees the old value
            assert st.tick() is False and hwm(state)["n"] == 0
            con.execute("ROLLBACK")
        monkeypatch.undo()
        assert hwm(state)["n"] == 0


def test_a_failing_write_is_logged_retried_and_never_blocks_a_commit(dirs, caplog):
    data, state = dirs
    with start(data) as c:
        prep(c)
        st, t = writer(c)
        s1, _w, b1 = upload("a")
        assert put(c, s1, b1).status_code == 201
        state.chmod(0o500)  # read-only: the temporary file cannot be created
        try:
            t[0] = 60.0
            with caplog.at_level(logging.ERROR):
                assert st.tick() is False and st.failed_writes == 1
            assert "drop-hwm.json write failed" in caplog.text
            s2, _w, b2 = upload("b")
            assert put(c, s2, b2).status_code == 201  # commits go on
            t[0] = 61.0
            assert st.tick() is False and st.failed_writes == 2  # retried at the next tick
        finally:
            state.chmod(0o700)
        t[0] = 62.0
        assert st.tick() is True and hwm(state)["n"] == 2  # recovered
        assert [p.name for p in state.iterdir() if p.name.startswith(".drop-hwm.")] == []


def test_a_persistent_failure_is_logged_at_most_once_a_minute(dirs, caplog):
    data, state = dirs
    with start(data) as c:
        prep(c)
        st, t = writer(c)
        s1, _w, b1 = upload("a")
        put(c, s1, b1)
        state.chmod(0o500)
        try:
            with caplog.at_level(logging.ERROR):
                for i in range(30):
                    t[0] = 60.0 + i
                    st.tick()
            assert caplog.text.count("write failed") == 1  # 30 retries within a minute: one line
            t[0] = 200.0
            with caplog.at_level(logging.ERROR):
                st.tick()
            assert caplog.text.count("write failed") == 2
        finally:
            state.chmod(0o700)


def test_the_temporary_file_is_in_the_state_directory_and_the_rename_is_atomic(dirs, monkeypatch):
    data, state = dirs
    seen = []
    real = os.replace

    def replace(src, dst):
        seen.append((Path(src).parent, Path(dst)))
        assert (
            json.loads(Path(src).read_text())["n"] >= 0
        )  # the content is complete before the rename
        return real(src, dst)

    monkeypatch.setattr(os, "replace", replace)
    with start(data):
        pass
    assert seen and all(parent == state.resolve() or parent == state for parent, _ in seen)
    assert all(dst.name == S.HWM for _, dst in seen)


def test_a_crashed_write_leaves_the_old_file_whole(dirs, monkeypatch):
    data, state = dirs
    with start(data) as c:
        g = c.app.state.drop.state.generation

        def die(src, dst):
            raise OSError("killed between create and rename")

        monkeypatch.setattr(os, "replace", die)
        assert c.app.state.drop.state.flush() is False
        monkeypatch.undo()
        assert hwm(state) == {"generation": g, "n": 0}
        assert [p.name for p in state.iterdir()] == [S.HWM]  # the temporary file was removed


def test_leftover_temporary_files_are_removed_at_a_serve_start(dirs):
    data, state = dirs
    (state / ".drop-hwm.abc.tmp").write_text("{")
    with start(data, serve=True):
        assert not (state / ".drop-hwm.abc.tmp").exists()
    (state / ".drop-hwm.def.tmp").write_text("{")
    with start(data):  # not serve: another process may be mid-write
        assert (state / ".drop-hwm.def.tmp").exists()


def test_the_maintenance_task_writes_while_the_relay_runs(dirs, monkeypatch):
    data, state = dirs
    monkeypatch.setattr(S, "TICK_S", 0.01)
    app = create_app(data)
    app.state.directory.clock = lambda: NOW
    app.state.drop.state.write_every = 0.0  # the 60 s are injected away; the task is the real one
    with TestClient(app) as c:
        prep(c)
        s1, _w, b1 = upload("a")
        assert put(c, s1, b1).status_code == 201
        for _ in range(300):
            if hwm(state)["n"] == 1:
                break
            time.sleep(0.01)
        assert hwm(state)["n"] == 1


def test_the_shutdown_write_is_a_committed_value_after_commits(dirs):
    data, state = dirs
    with start(data) as c:
        prep(c)
        s1, _w, b1 = upload("a")
        assert put(c, s1, b1).status_code == 201
        s2, _w, b2 = upload("b")
        assert put(c, s2, b2).status_code == 201
        assert hwm(state)["n"] == 0  # nothing written yet: the 60 s have not passed
    assert hwm(state)["n"] == 2


def test_a_list_page_never_goes_without_a_generation_even_after_the_row_is_deleted(dirs):
    data, _ = dirs
    with start(data) as c:
        prep(c)
        with closing(db.connect(data / db.DB_NAME)) as con, con:
            con.execute("DELETE FROM meta WHERE key='drop_generation'")
        page = list_page(c, DEVICE).json()
        assert re.fullmatch(r"[0-9a-f]{32}", page["generation"])
