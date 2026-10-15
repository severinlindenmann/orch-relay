"""P3-D39 (D39a2 part 2): the Drop sweeps (expiry, tombstones, document pruning, device wraps, day
rows), the host's retire (amendment A1) and `rotation_required`, over HTTP (TestClient) and on the
sweeper directly."""

import asyncio
import json
import logging
import os
from contextlib import closing

import pytest
from directory_support import DEVICE, NOW, WS
from drop_support import (
    DAY,
    LAPTOP,
    TOKENS,
    WS_B,
    apply_op,
    default_wraps,
    descriptor,
    frame,
    headers,
    object_id,
    put,
    rows,
    setup,
    upload,
    usage,
)
from fastapi.testclient import TestClient

from orch_relay import db
from orch_relay import drop_life as L
from orch_relay import proto as P
from orch_relay.app import create_app
from orch_relay.drop import parent_hash

MIN10 = 600_000


@pytest.fixture
def client(tmp_path):
    with TestClient(create_app(tmp_path)) as c:
        setup(c.app.state.directory)
        yield c


def path_of(c):
    return c.app.state.directory.path


def life(c):
    return c.app.state.drop.life


def sql(c, statement, *args):
    with closing(db.connect(path_of(c))) as con, con:
        return con.execute(statement, args).rowcount


def at(c, now):
    c.app.state.directory.clock = lambda: now


def counter(c):
    return rows(path_of(c), "drop_counter")[0]["n"]


def objects(c):
    return {r["object_id"]: r for r in rows(path_of(c), "drop_objects")}


def blob_files(c):
    return sorted(p for p in c.app.state.drop.blobs.rglob("*") if p.is_file())


ZERO = (0, 0, 0, 0)


def all_zero(c):
    return all(v == ZERO for v in usage(path_of(c)).values())


def doc_chain(client, label, count, author=DEVICE):
    """`count` versions of one document, each `If-Match` the previous one."""
    chain = []
    for v in range(1, count + 1):
        s, _w, body = upload(
            label,
            kind="document",
            version=v,
            parent=chain[-1]["o"] if chain else None,
            author=author,
        )
        assert put(client, s, body, if_match=str(v - 1)).status_code == 201, v
        chain.append(s)
    return chain


def retire_request(client, o_id, version=1, head=None, author=WS, **kw):
    body = {"expect_version": version, "expect_head": head}
    body.update(kw)
    return client.post(
        f"/v2/drop/{o_id}/retire",
        content=P.cj({k: v for k, v in body.items() if v is not Ellipsis}),
        headers={**headers(author, if_match=None), "Content-Type": "application/json"},
    )


def head_of(signed):
    return parent_hash(signed["o"])


def retire(client, signed, **kw):
    kw.setdefault("head", head_of(signed))
    kw.setdefault("version", signed["o"]["version"])
    return retire_request(client, signed["o"]["object_id"], **kw)


def listing(c, author=DEVICE, **extra):
    return c.post(
        "/v2/drop/list",
        json={"workspace_id": WS, "direction": "received", **extra},
        headers={"Authorization": "Bearer " + TOKENS[author]},
    ).json()["objects"]


# --- the switch ------------------------------------------------------------------------------------


def test_with_drop_off_no_sweeper_runs_or_assigns_a_position(tmp_path, monkeypatch):
    """Pin (owner decision 15 Oct): the `n`-assigning sweepers exist only with ORCH_RELAY_DROP=1."""
    with TestClient(create_app(tmp_path / "on")) as c:
        setup(c.app.state.directory)
        s, _w, b = upload("a")
        assert put(c, s, b).status_code == 201
        blob = blob_files(c)[0]
        blob.unlink()  # a restore without data/drop for this one
    monkeypatch.setenv("ORCH_RELAY_DROP", "0")
    with TestClient(create_app(tmp_path / "on")) as c:  # the same data directory, Drop off
        drop = c.app.state.drop
        assert drop.on is False and drop.life.start() is None
        before = (counter(c), rows(path_of(c), "drop_objects"), rows(path_of(c), "drop_versions"))
        at(c, NOW + 30 * DAY)  # long after the file expired
        assert drop.life.run() is None
        assert drop.life.cycles == 0
        after = (counter(c), rows(path_of(c), "drop_objects"), rows(path_of(c), "drop_versions"))
        assert before == after
        assert after[2][0]["blob"] == "stored"  # the start-up sweep did not prune it either
        assert after[1][0]["tombstone_kind"] is None


def test_with_drop_on_the_sweeper_is_a_task_that_the_lifespan_owns(client):
    assert life(client).on is True

    async def probe():
        task = life(client).start()
        assert isinstance(task, asyncio.Task)
        task.cancel()

    asyncio.run(probe())


def test_the_maintenance_loop_runs_a_cycle_then_wakes_the_changed_workspaces(client):
    s, _w, b = upload("a")
    assert put(client, s, b).status_code == 201
    at(client, s["o"]["expires_ms"])
    woken = []
    client.app.state.directory.changed = lambda *keys: woken.extend(keys)
    life(client).period = 0.01

    async def probe():
        task = asyncio.create_task(life(client).maintenance())
        for _ in range(200):
            await asyncio.sleep(0.01)
            if woken:
                break
        task.cancel()

    asyncio.run(probe())
    assert woken == [("ws", WS)]
    assert life(client).cycles >= 1


# --- expiry ----------------------------------------------------------------------------------------


def expect_released(client):
    assert all_zero(client) and rows(path_of(client), "drop_wraps") == []
    assert rows(path_of(client), "drop_versions") == [] and blob_files(client) == []


def test_expiry_tombstones_a_file_and_releases_everything(client):
    s, _w, b = upload("a", expires=NOW + 3600_000)
    assert put(client, s, b).status_code == 201
    o = s["o"]
    n0 = counter(client)
    at(client, o["expires_ms"] - 1)
    assert life(client).run() == set()  # a ms early: nothing
    assert objects(client)[o["object_id"]]["tombstone_kind"] is None
    at(client, o["expires_ms"] + 4 * 60_000)  # the sweep runs late
    assert life(client).run() == {WS}
    row = objects(client)[o["object_id"]]
    assert (row["tombstone_kind"], row["tombstone_ms"]) == ("expired", o["expires_ms"])
    assert row["n"] == n0 + 1 and counter(client) == n0 + 1
    assert row["current"] == 1 and row["head_hash"] == head_of(s)  # kept for retire's retry
    expect_released(client)
    assert life(client).run() == set()  # idempotent: no second tombstone, no new position
    assert counter(client) == n0 + 1


def test_expiry_boundary_is_at_or_past_expires_ms(client):
    s, _w, b = upload("a", expires=NOW + 3600_000)
    assert put(client, s, b).status_code == 201
    at(client, s["o"]["expires_ms"])
    life(client).run()
    assert objects(client)[s["o"]["object_id"]]["tombstone_kind"] == "expired"


def test_expiry_deletes_a_device_only_files_audience_and_keeps_the_row(client):
    s, _w, b = upload("a", author=LAPTOP, recipients=[LAPTOP, DEVICE], expires=NOW + 3600_000)
    assert put(client, s, b, author=LAPTOP).status_code == 201
    assert len(rows(path_of(client), "drop_audience")) == 2
    at(client, s["o"]["expires_ms"])
    life(client).run()
    assert rows(path_of(client), "drop_audience") == []
    row = objects(client)[s["o"]["object_id"]]
    assert row["audience"] == "devices"  # visible to the W session only (Opus delta R3)
    expect_released(client)


def test_expired_tombstone_lists_with_the_sweeps_position_and_reads_410(client):
    s, _w, b = upload("a", expires=NOW + 3600_000)
    assert put(client, s, b).status_code == 201
    exp = s["o"]["expires_ms"]
    at(client, exp + 1000)
    life(client).run()
    sql(client, "UPDATE sessions SET expires_ms=?", NOW + 60 * DAY)
    (entry,) = listing(client, WS, after=1)  # an after list sees the sweep's position
    assert entry["n"] == 2 and entry["state"] == "expired" and entry["descriptor"] is None
    assert entry["tombstone_until_ms"] == exp + 30 * DAY  # the same value before the sweep
    r = client.get(
        f"/v2/drop/{s['o']['object_id']}/versions/1/descriptor",
        headers={"Authorization": "Bearer " + TOKENS[DEVICE]},
    )
    assert r.status_code == 410


def test_a_document_never_expires(client):
    chain = doc_chain(client, "d", 1)
    at(client, NOW + 365 * DAY)
    life(client).run()
    assert objects(client)[chain[0]["o"]["object_id"]]["tombstone_kind"] is None


# --- tombstones ------------------------------------------------------------------------------------


def test_tombstones_end_after_30_days_without_a_new_position(client):
    s, _w, b = upload("a", expires=NOW + 3600_000)
    assert put(client, s, b).status_code == 201
    exp = s["o"]["expires_ms"]
    at(client, exp)
    life(client).run()
    n = counter(client)
    at(client, exp + 30 * DAY - 1)
    life(client).run()
    assert s["o"]["object_id"] in objects(client)  # one ms short
    at(client, exp + 30 * DAY)
    assert life(client).run() == set()
    assert objects(client) == {} and counter(client) == n


def test_a_retired_device_only_tombstone_keeps_then_releases_its_audience_charge(client):
    s, _w, b = upload("a", author=LAPTOP, recipients=[LAPTOP, DEVICE])
    assert put(client, s, b, author=LAPTOP).status_code == 201
    audience = 2 * 65
    head_before = usage(path_of(client))[("workspace", WS)][1]
    assert retire(client, s).status_code == 200
    u = usage(path_of(client))
    assert u[("workspace", WS)] == (0, audience, 0, 0)  # only the audience rows stay charged
    assert u[("global", "")] == (0, audience, 0, 0)
    assert u[("device", f"{WS}:{LAPTOP}")] == ZERO  # off the author's share (Opus delta R3)
    assert head_before > audience
    assert len(rows(path_of(client), "drop_audience")) == 2
    at(client, NOW + 30 * DAY - 1)
    life(client).run()
    assert usage(path_of(client))[("workspace", WS)] == (0, audience, 0, 0)
    at(client, NOW + 30 * DAY)
    life(client).run()
    assert all_zero(client) and rows(path_of(client), "drop_audience") == []


def test_a_tombstone_with_versions_left_is_not_deleted_before_they_are_released(client):
    chain = doc_chain(client, "d", 2)
    assert retire(client, chain[1]).status_code == 200
    sql(client, "UPDATE drop_objects SET tombstone_ms=?", NOW - 40 * DAY)
    with closing(db.connect(path_of(client))) as con:
        con.row_factory = __import__("sqlite3").Row
        with con:
            con.execute("BEGIN IMMEDIATE")
            done, _p, _c = life(client).sweep_tombstones(con, NOW, set())
    assert done == 0 and len(objects(client)) == 1


# --- document pruning --------------------------------------------------------------------------------


def test_pruning_keeps_the_newest_8_and_anything_younger_than_30_days(client):
    chain = doc_chain(client, "d", 10)
    o_id = chain[0]["o"]["object_id"]
    n = counter(client)
    at(client, NOW + 30 * DAY - 1)
    life(client).run()
    assert all(v["blob"] == "stored" for v in rows(path_of(client), "drop_versions"))
    at(client, NOW + 30 * DAY)  # old enough now: versions 1 and 2 only (the newest 8 stay)
    life(client).run()
    versions = {v["version"]: v for v in rows(path_of(client), "drop_versions")}
    assert [v for v, r in versions.items() if r["blob"] == "pruned"] == [1, 2]
    assert versions[1]["blob_path"] is None and versions[1]["descriptor"]  # the chain stays
    assert len(blob_files(client)) == 8
    wrapped = {r["version"] for r in rows(path_of(client), "drop_wraps")}
    assert wrapped == set(range(3, 11))
    assert counter(client) == n and objects(client)[o_id]["n"] == n  # a superseded prune: no n
    u = usage(path_of(client))[("workspace", WS)]
    assert u[2] == 8 and u[3] == 1
    life(client).run()  # idempotent
    assert len(blob_files(client)) == 8


def test_pruning_counts_the_newest_8_from_the_head_not_from_age(client):
    chain = doc_chain(client, "d", 8)
    at(client, NOW + 90 * DAY)
    life(client).run()
    assert all(v["blob"] == "stored" for v in rows(path_of(client), "drop_versions"))
    assert len(chain) == 8


def test_pruned_blob_reads_410_and_the_descriptor_stays(client):
    chain = doc_chain(client, "d", 9)
    at(client, NOW + 30 * DAY)
    life(client).run()
    at(client, NOW)
    o_id = chain[0]["o"]["object_id"]
    auth = {"Authorization": "Bearer " + TOKENS[DEVICE]}
    assert client.get(f"/v2/drop/{o_id}/versions/1/blob", headers=auth).status_code == 410
    assert client.get(f"/v2/drop/{o_id}/versions/1/descriptor", headers=auth).status_code == 200
    assert client.get(f"/v2/drop/{o_id}/versions/2/blob", headers=auth).status_code == 200


def test_a_tombstoned_document_is_not_pruned(client):
    doc_chain(client, "d", 10)
    sql(client, "UPDATE drop_objects SET tombstone_ms=?, tombstone_kind='retired'", NOW)
    at(client, NOW + 29 * DAY)
    with closing(db.connect(path_of(client))) as con:
        con.row_factory = __import__("sqlite3").Row
        with con:
            con.execute("BEGIN IMMEDIATE")
            done, _p, _c = life(client).sweep_pruning(con, NOW + 90 * DAY, set())
    assert done == 0


# --- device wraps ----------------------------------------------------------------------------------


def device_only(client, label="a"):
    """A W-authored file addressed to the laptop and the phone: two `device` wraps."""
    s, _w, b = upload(label, author=WS, recipients=[LAPTOP, DEVICE])
    assert put(client, s, b).status_code == 201
    return s


def device_wraps(client):
    return sorted(r["target_id"] for r in rows(path_of(client), "drop_wraps"))


def test_a_removed_members_device_wraps_are_deleted_and_its_head_bytes_released(client):
    s = device_only(client)
    assert device_wraps(client) == sorted([LAPTOP, DEVICE])
    size = {r["target_id"]: len(r["record"]) for r in rows(path_of(client), "drop_wraps")}
    sql(client, "DELETE FROM members WHERE device_id=?", LAPTOP)
    before = usage(path_of(client))[("workspace", WS)][1]
    n = counter(client)
    life(client).run()
    assert device_wraps(client) == [DEVICE]
    assert usage(path_of(client))[("workspace", WS)][1] == before - size[LAPTOP]
    assert usage(path_of(client))[("global", "")][1] == before - size[LAPTOP]
    assert counter(client) == n  # the descriptor and the head stay; no position
    assert s["o"]["object_id"] in objects(client)


def test_a_revoked_members_device_wraps_are_deleted_too(client):
    device_only(client)
    sql(
        client,
        "INSERT INTO revocations VALUES (?,?,?,?,?,?)",
        LAPTOP,
        "p",
        b"{}",
        "lost",
        NOW,
        99,
    )
    life(client).run()
    assert device_wraps(client) == [DEVICE]


def test_a_current_members_device_wraps_stay(client):
    device_only(client)
    life(client).run()
    assert device_wraps(client) == sorted([LAPTOP, DEVICE])


def test_device_wrap_release_charges_the_author_devices_share(client):
    from drop_support import wrap

    s, data, _dek = descriptor(object_id("b"), author=LAPTOP, recipients="inbox")
    wraps = default_wraps(s["o"]) + [wrap(s["o"], "device", LAPTOP)]
    assert put(client, s, frame(s, wraps, data), author=LAPTOP).status_code == 201
    size = next(
        len(r["record"])
        for r in rows(path_of(client), "drop_wraps")
        if r["target_kind"] == "device"
    )
    sql(client, "DELETE FROM members WHERE device_id=?", LAPTOP)
    share = ("device", f"{WS}:{LAPTOP}")
    before = usage(path_of(client))[share][1]
    life(client).run()
    assert usage(path_of(client))[share][1] == before - size
    assert [r["target_kind"] for r in rows(path_of(client), "drop_wraps")] == ["wxk"]


# --- day rows --------------------------------------------------------------------------------------


def test_day_rows_older_than_the_previous_utc_day_are_deleted(client):
    today = NOW // DAY
    for day in (today - 3, today - 2, today - 1, today):
        sql(client, "INSERT INTO drop_decide_budget VALUES (?,?,?,1,1)", WS, DEVICE, day)
        sql(client, "INSERT INTO drop_creations VALUES ('device',?,?,1)", f"{WS}:{DEVICE}", day)
    life(client).run()
    kept = [r["day"] for r in rows(path_of(client), "drop_decide_budget")]
    assert sorted(kept) == [today - 1, today]
    kept = [r["day"] for r in rows(path_of(client), "drop_creations")]
    assert sorted(kept) == [today - 1, today]


# --- batches and failures ----------------------------------------------------------------------------


def test_every_transaction_deletes_at_most_batch_rows_and_the_sweep_still_finishes(
    client, monkeypatch
):
    for label in "abcde":
        s, _w, b = upload(label, expires=NOW + 3600_000)
        assert put(client, s, b).status_code == 201
    at(client, NOW + 7200_000)
    monkeypatch.setattr(L, "BATCH", 4)  # a file is 3 rows: version, wrap, the object itself
    count = []
    real = life(client).transaction

    def spy(work):
        count.append(1)
        return real(work)

    monkeypatch.setattr(life(client), "transaction", spy)
    life(client).drain(life(client).sweep_expiry)
    assert all(r["tombstone_kind"] == "expired" for r in objects(client).values())
    assert len(count) >= 3 + 1  # two files fit one batch of 4 rows at most; the last pass is empty
    assert len(count) > 2


def test_one_bad_object_is_logged_and_skipped_not_fatal(client, caplog):
    a, _w, ab = upload("a", expires=NOW + 3600_000)
    b_, _w, bb = upload("b", expires=NOW + 3600_000)
    assert put(client, a, ab).status_code == 201 and put(client, b_, bb).status_code == 201
    sql(  # the author's device share is missing its bytes: a release would underflow the CHECK
        client,
        "UPDATE drop_usage SET blob_bytes=0 WHERE scope='account'",
    )
    at(client, NOW + 7200_000)
    with caplog.at_level(logging.ERROR):
        life(client).run()
    # both underflow the account row here, so both are skipped and rolled back whole
    assert all(r["tombstone_kind"] is None for r in objects(client).values())
    assert "drop sweep failed" in caplog.text
    assert len(rows(path_of(client), "drop_versions")) == 2 and len(blob_files(client)) == 2


def test_a_bad_object_does_not_block_the_good_one_behind_it(client, caplog):
    a, _w, ab = upload("a", expires=NOW + 3600_000)
    assert put(client, a, ab).status_code == 201
    b_, _w, bb = upload("b", expires=NOW + 7200_000, author=LAPTOP)
    assert put(client, b_, bb, author=LAPTOP).status_code == 201
    sql(
        client, "UPDATE drop_usage SET blob_bytes=0 WHERE scope='device' AND id=?", f"{WS}:{DEVICE}"
    )
    at(client, NOW + 8000_000)
    with caplog.at_level(logging.ERROR):
        life(client).run()
    rows_ = objects(client)
    assert rows_[a["o"]["object_id"]]["tombstone_kind"] is None  # rolled back, skipped
    assert rows_[b_["o"]["object_id"]]["tombstone_kind"] == "expired"  # the next one still goes


# --- N3: an EIO after the rename leaves no blob ---------------------------------------------------


def test_n3_an_eio_on_the_directory_fsync_unlinks_the_landed_blob(client, monkeypatch):
    real = os.fsync
    seen = []

    def flaky(fd):
        seen.append(fd)
        if len(seen) == 2:  # the first is the file, the second a directory after the rename
            raise OSError(5, "EIO")
        return real(fd)

    monkeypatch.setattr(os, "fsync", flaky)
    s, _w, b = upload("a")
    r = put(client, s, b)
    assert r.status_code == 503 and r.headers["retry-after"] == "60"
    assert blob_files(client) == [] and rows(path_of(client), "drop_objects") == []
    assert list(client.app.state.drop.tmp.iterdir()) == []


# --- retire ----------------------------------------------------------------------------------------


def test_retire_a_file_releases_everything_in_the_transaction(client):
    s, _w, b = upload("a")
    assert put(client, s, b).status_code == 201
    n = counter(client)
    notified = []
    client.app.state.directory.changed = lambda *keys: notified.extend(keys)
    r = retire(client, s)
    assert (r.status_code, r.json()) == (200, {"state": "retired"})
    row = objects(client)[s["o"]["object_id"]]
    assert (row["tombstone_kind"], row["tombstone_ms"], row["n"]) == ("retired", NOW, n + 1)
    assert row["current"] == 1 and row["head_hash"] == head_of(s)
    expect_released(client)
    assert notified == [("ws", WS)]
    (entry,) = listing(client, LAPTOP)
    assert entry["state"] == "retired" and entry["tombstone_until_ms"] == NOW + 30 * DAY
    assert (entry["descriptor"], entry["wraps"], entry["n"]) == (None, [], n + 1)
    auth = {"Authorization": "Bearer " + TOKENS[DEVICE]}
    url = f"/v2/drop/{s['o']['object_id']}/versions/1/blob"
    assert client.get(url, headers=auth).status_code == 410
    assert put(client, s, b).status_code == 410  # the id stays taken


def test_retire_is_idempotent_against_the_tombstone_and_assigns_no_new_position(client):
    s, _w, b = upload("a")
    assert put(client, s, b).status_code == 201
    assert retire(client, s).status_code == 200
    n, notified = counter(client), []
    client.app.state.directory.changed = lambda *keys: notified.extend(keys)
    r = retire(client, s)
    assert (r.status_code, r.json()) == (200, {"state": "retired"})
    assert counter(client) == n and notified == []
    assert objects(client)[s["o"]["object_id"]]["tombstone_ms"] == NOW


def test_retire_checks_the_precondition_against_the_tombstone_too(client):
    s, _w, b = upload("a")
    assert put(client, s, b).status_code == 201
    assert retire(client, s).status_code == 200
    r = retire(client, s, head=P.b64u(b"\1" * 32))
    assert (r.status_code, r.json()) == (
        409,
        {"error": "version_conflict", "current": 1, "state": "retired"},
    )
    r = retire(client, s, version=2)
    assert r.status_code == 409 and r.json()["current"] == 1


def test_retire_of_an_expired_file_answers_expired_swept_or_not(client):
    s, _w, b = upload("a", expires=NOW + 3600_000)
    assert put(client, s, b).status_code == 201
    at(client, s["o"]["expires_ms"] + 10)
    sql(client, "UPDATE sessions SET expires_ms=?", NOW + 60 * DAY)
    sql(client, "UPDATE holders SET lease_until_ms=?", NOW + 60 * DAY)
    n = counter(client)
    r = retire(client, s)  # past expires_ms, before the sweep
    assert (r.status_code, r.json()) == (200, {"state": "expired"})
    assert counter(client) == n
    assert objects(client)[s["o"]["object_id"]]["tombstone_kind"] is None  # nothing was changed
    life(client).run()
    r = retire(client, s)  # the sweeper tombstoned it meanwhile
    assert (r.status_code, r.json()) == (200, {"state": "expired"})
    assert counter(client) == n + 1  # only the sweep's position


def test_retire_conflicts_leave_the_object_untouched(client):
    s, _w, b = upload("a")
    assert put(client, s, b).status_code == 201
    before = (rows(path_of(client), "drop_objects"), usage(path_of(client)), counter(client))
    r = retire(client, s, version=2)
    assert (r.status_code, r.json()) == (
        409,
        {"error": "version_conflict", "current": 1, "state": "live"},
    )
    r = retire(client, s, head=P.b64u(b"\2" * 32))
    assert r.status_code == 409 and r.json()["state"] == "live"
    assert before == (
        rows(path_of(client), "drop_objects"),
        usage(path_of(client)),
        counter(client),
    )
    assert len(blob_files(client)) == 1


def test_a_member_version_written_after_the_decision_is_never_taken_along(client):
    chain = doc_chain(client, "d", 1)
    s2, _w, b2 = upload("d", kind="document", version=2, parent=chain[0]["o"])
    assert put(client, s2, b2, if_match="1").status_code == 201
    r = retire(client, chain[0])  # the host decided about version 1
    assert (r.status_code, r.json()) == (
        409,
        {"error": "version_conflict", "current": 2, "state": "live"},
    )
    assert objects(client)[chain[0]["o"]["object_id"]]["tombstone_kind"] is None
    assert retire(client, s2).status_code == 200


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"expect_version": 1},
        {"expect_head": "x"},
        {"expect_version": 1, "expect_head": "HEAD", "extra": 1},
        {"expect_version": 0, "expect_head": "HEAD"},
        {"expect_version": -1, "expect_head": "HEAD"},
        {"expect_version": True, "expect_head": "HEAD"},
        {"expect_version": 1.0, "expect_head": "HEAD"},
        {"expect_version": "1", "expect_head": "HEAD"},
        {"expect_version": 2**53, "expect_head": "HEAD"},
        {"expect_version": 1, "expect_head": None},
        {"expect_version": 1, "expect_head": 7},
        {"expect_version": 1, "expect_head": "HEAD="},  # padded: not canonical
        {"expect_version": 1, "expect_head": "SHORT"},
        {"expect_version": 1, "expect_head": "HEAD-"},
    ],
)
def test_retire_body_shape_is_400(client, body):
    s, _w, b = upload("a")
    assert put(client, s, b).status_code == 201
    good = head_of(s)
    body = {
        k: (
            good + "="
            if v == "HEAD="
            else good[:-1]
            if v == "HEAD-"
            else good
            if v == "HEAD"
            else v
        )
        for k, v in body.items()
    }
    if body.get("expect_head") == "SHORT":
        body["expect_head"] = P.b64u(b"\1" * 31)
    r = client.post(
        f"/v2/drop/{s['o']['object_id']}/retire",
        content=json.dumps(body).encode(),
        headers=headers(WS, if_match=None),
    )
    assert (r.status_code, r.json()) == (400, {"error": "malformed"})
    assert objects(client)[s["o"]["object_id"]]["tombstone_kind"] is None


def test_retire_rejects_non_json_and_an_empty_body_and_a_query(client):
    s, _w, b = upload("a")
    assert put(client, s, b).status_code == 201
    url = f"/v2/drop/{s['o']['object_id']}/retire"
    for content in (b"", b"nope", b"[]", b"null"):
        assert (
            client.post(url, content=content, headers=headers(WS, if_match=None)).status_code == 400
        )
    good = P.cj({"expect_version": 1, "expect_head": head_of(s)})
    assert (
        client.post(url + "?x=1", content=good, headers=headers(WS, if_match=None)).status_code
        == 400
    )
    assert (
        client.post(
            url, content=b"{" + b" " * 16384, headers=headers(WS, if_match=None)
        ).status_code
        == 413
    )


def test_only_the_host_retires_a_device_gets_403_even_for_its_own_upload(client):
    s, _w, b = upload("a")
    assert put(client, s, b).status_code == 201
    for who in (DEVICE, LAPTOP):
        r = retire(client, s, author=who)
        assert (r.status_code, r.json()) == (403, {"error": "not_eligible"})
    assert objects(client)[s["o"]["object_id"]]["tombstone_kind"] is None
    r = client.post(f"/v2/drop/{s['o']['object_id']}/retire", content=b"{}")
    assert r.status_code == 401


def test_retire_of_a_decide_only_device_is_403_as_well(client):
    sql(
        client,
        "UPDATE members SET scopes=? WHERE device_id=?",
        P.cj(["look", "decide"]),
        LAPTOP,
    )
    s, _w, b = upload("a")
    assert put(client, s, b).status_code == 201
    assert retire(client, s, author=LAPTOP).status_code == 403


def test_retire_404_for_an_absent_id_and_for_an_ended_tombstone(client):
    s, _w, b = upload("a")
    r = retire(client, s)  # never stored
    assert (r.status_code, r.json()) == (404, {"error": "not_found"})
    assert put(client, s, b).status_code == 201
    assert retire(client, s).status_code == 200
    at(client, NOW + 30 * DAY - 1)
    sql(client, "UPDATE holders SET lease_until_ms=?", NOW + 60 * DAY)
    sql(client, "UPDATE sessions SET expires_ms=?", NOW + 60 * DAY)
    assert retire(client, s).status_code == 200  # one ms before the end: still the retry
    at(client, NOW + 30 * DAY)  # the tombstone ended (the row may still await the sweep)
    r = retire(client, s)
    assert (r.status_code, r.json()) == (404, {"error": "not_found"})


def test_retire_403_for_another_workspaces_object_not_404(client):
    apply_op(
        client.app.state.directory,
        {"op": "foreign_object", "object_id": object_id("f"), "workspace_id": WS_B},
    )
    r = retire_request(client, object_id("f"), 1, P.b64u(b"x" * 32))
    assert (r.status_code, r.json()) == (403, {"error": "not_eligible"})
    assert retire_request(client, object_id("nobody"), 1, P.b64u(b"x" * 32)).status_code == 404


def test_retire_refuses_a_stale_host_at_admission_and_changes_nothing(client):
    s, _w, b = upload("a")
    assert put(client, s, b).status_code == 201
    before = (rows(path_of(client), "drop_objects"), usage(path_of(client)))
    for holder in ("2", None):
        r = client.post(
            f"/v2/drop/{s['o']['object_id']}/retire",
            content=P.cj({"expect_version": 1, "expect_head": head_of(s)}),
            headers=headers(WS, if_match=None, holder=holder),
        )
        assert (r.status_code, r.json()) == (409, {"error": "fenced"})
    assert before == (rows(path_of(client), "drop_objects"), usage(path_of(client)))


def test_takeover_between_admission_and_the_transaction_changes_nothing(client):
    """Takeover-versus-retire (orch-52 change 0): the fence passed at admission, a takeover
    commits, and the retire's own transaction sees the new generation: 409, nothing changed."""
    s, _w, b = upload("a")
    assert put(client, s, b).status_code == 201
    d = client.app.state.directory
    real, calls = d.fence, []

    def fence(con, headers_, ws, now):
        calls.append(1)
        real(con, headers_, ws, now)
        if len(calls) == 1:  # right after the admission's check
            sql(client, "UPDATE holders SET gen=gen+1")

    d.fence = fence
    before = (rows(path_of(client), "drop_objects"), usage(path_of(client)), counter(client))
    r = retire(client, s)
    assert (r.status_code, r.json()) == (409, {"error": "fenced"}) and len(calls) == 2
    assert before == (
        rows(path_of(client), "drop_objects"),
        usage(path_of(client)),
        counter(client),
    )
    assert len(blob_files(client)) == 1


def test_a_retire_committed_before_the_takeover_stands(client):
    s, _w, b = upload("a")
    assert put(client, s, b).status_code == 201
    assert retire(client, s).status_code == 200
    sql(client, "UPDATE holders SET gen=gen+1")
    r = retire(client, s)  # the old holder retrying after the takeover: fenced, not 200
    assert r.status_code == 409 and r.json() == {"error": "fenced"}
    assert objects(client)[s["o"]["object_id"]]["tombstone_kind"] == "retired"


def test_retire_checks_the_fence_before_the_object(client):
    r = retire_request(client, object_id("zzz"), 1, P.b64u(b"x" * 32), author=WS)
    assert r.status_code == 404
    sql(client, "UPDATE holders SET gen=7")
    r = retire_request(client, object_id("zzz"), 1, P.b64u(b"x" * 32), author=WS)
    assert r.status_code == 409


def test_retire_a_document_counts_it_out_at_once_and_the_sweep_frees_the_versions(client):
    chain = doc_chain(client, "d", 3)
    o_id = chain[0]["o"]["object_id"]
    u = usage(path_of(client))
    assert u[("workspace", WS)][3] == 1 and u[("workspace", WS)][2] == 3
    n = counter(client)
    r = retire(client, chain[2])
    assert (r.status_code, r.json()) == (200, {"state": "retired"})
    u = usage(path_of(client))
    assert u[("workspace", WS)][3] == 0 and u[("device", f"{WS}:{DEVICE}")][3] == 0
    assert u[("workspace", WS)][2] == 3 and len(blob_files(client)) == 3  # the sweeper frees them
    assert counter(client) == n + 1
    life(client).run()
    expect_released(client)
    row = objects(client)[o_id]
    assert (row["tombstone_kind"], row["current"], row["n"]) == ("retired", 3, n + 1)
    assert counter(client) == n + 1  # releasing the versions assigns no position
    assert retire(client, chain[2]).json() == {"state": "retired"}  # the idempotent answer stays


def test_a_retired_document_frees_a_workspace_document_slot(client):
    client.app.state.drop.quotas.ws_documents = 1
    first = doc_chain(client, "d1", 1)
    s, _w, b = upload("d2", kind="document")
    assert put(client, s, b).status_code == 429  # the only way out is a retire
    assert retire(client, first[0]).status_code == 200
    assert put(client, s, b).status_code == 201


def test_retire_of_a_files_frees_its_quota_before_seven_days(client):
    s, _w, b = upload("a")
    client.app.state.drop.quotas.dev_blob = s["o"]["content_len"] + 10  # room for one file only
    assert put(client, s, b).status_code == 201
    other, _w, ob = upload("b")
    assert put(client, other, ob).status_code == 429
    assert retire(client, s).status_code == 200
    assert put(client, other, ob).status_code == 201


def test_retire_an_inbox_file_and_a_claimed_one(client):
    s, _w, b = upload("a", recipients="inbox")
    assert put(client, s, b).status_code == 201
    assert retire(client, s).status_code == 200
    expect_released(client)
    c, _w, cb = upload("c", recipients="inbox")
    assert put(client, c, cb).status_code == 201
    sql(client, "UPDATE drop_objects SET claimed_by=? WHERE object_id=?", WS, c["o"]["object_id"])
    assert retire(client, c).status_code == 200


def test_a_device_outside_a_retired_device_only_audience_sees_no_entry(client):
    s, _w, b = upload("a", author=LAPTOP, recipients=[LAPTOP])
    assert put(client, s, b, author=LAPTOP).status_code == 201
    assert retire(client, s).status_code == 200
    assert listing(client, DEVICE) == []  # 403-class: hidden in every state
    # the author is in the audience, whose rows a retire keeps: it still sees the retired entry
    assert [e["state"] for e in listing(client, LAPTOP, direction="sending")] == ["retired"]
    assert [e["state"] for e in listing(client, WS)] == ["retired"]


def test_retire_unlinks_the_blob_only_after_the_commit(client, monkeypatch):
    s, _w, b = upload("a")
    assert put(client, s, b).status_code == 201
    (blob,) = blob_files(client)
    seen = []
    real = life(client).tombstone

    def spy(*a, **k):
        seen.append(blob.exists())  # still on disk inside the transaction
        return real(*a, **k)

    monkeypatch.setattr(life(client), "tombstone", spy)
    assert retire(client, s).status_code == 200
    assert seen == [True] and not blob.exists()


# --- rotation_required -------------------------------------------------------------------------------


def due(client, ws=WS):
    sql(client, "INSERT INTO rotation_due VALUES (?,?,?,?)", ws, LAPTOP, 5, 1)


def test_rotation_required_refuses_a_wk_wrap_while_a_rotation_is_due(client):
    due(client)
    s, _w, b = upload("a")
    r = put(client, s, b)
    assert (r.status_code, r.json()) == (409, {"error": "rotation_required", "epoch": 1})
    assert rows(path_of(client), "drop_objects") == [] and blob_files(client) == []
    sql(client, "DELETE FROM rotation_due")
    assert put(client, s, b).status_code == 201


def test_rotation_required_does_not_apply_to_wk_less_uploads(client):
    due(client)
    s, _w, b = upload("a", recipients="inbox")  # one wxk wrap
    assert put(client, s, b).status_code == 201
    d, _w, db_ = upload("d", author=WS, recipients=[LAPTOP])  # device wraps only
    assert put(client, d, db_).status_code == 201


def test_rotation_required_applies_to_a_host_wk_wrap_and_to_other_workspaces_not_at_all(client):
    due(client, WS_B)  # another workspace's rotation is not ours
    s, _w, b = upload("a")
    assert put(client, s, b).status_code == 201
    sql(client, "DELETE FROM rotation_due")
    due(client)
    h, _w, hb = upload("h", author=WS)
    r = put(client, h, hb, author=WS)
    assert (r.status_code, r.json()["error"]) == (409, "rotation_required")


def test_a_stale_epoch_is_answered_before_rotation_required(client):
    due(client)
    s, data, _dek = descriptor(object_id("a"))
    from drop_support import wrap

    body = frame(s, [wrap(s["o"], "wk", key_version=2)], data)
    r = put(client, s, body)
    assert (r.status_code, r.json()["error"]) == (409, "stale_epoch")


def test_rotation_opening_during_the_transfer_refuses_in_the_commit(client):
    s, _w, b = upload("a")
    client.app.state.drop.hooks["before_commit"] = lambda **kw: due(client)
    r = put(client, s, b)
    assert (r.status_code, r.json()["error"]) == (409, "rotation_required")
    assert rows(path_of(client), "drop_objects") == [] and blob_files(client) == []
    assert all_zero(client) or usage(path_of(client)) == {}


def test_an_exact_retry_is_200_even_while_a_rotation_is_due(client):
    s, _w, b = upload("a")
    assert put(client, s, b).status_code == 201
    due(client)
    assert put(client, s, b).status_code == 200  # step 7 comes before the wraps
