"""P3-D39 (D39a2 part 3, amendment A2 item 13 and item 6): decide-class uploads (the shape, the
budget charged at admission, its give-back, the slot, the commit-time authority) and the visibility
of unclaimed inbox objects (host and author only)."""

import asyncio
import sqlite3
import threading
from contextlib import closing

import pytest
from directory_support import DEVICE, NOW, WS
from drop_support import DAY, LAPTOP, TOKENS, descriptor, frame, object_id, put, rows, setup
from drop_support import upload as plain_upload
from fastapi.testclient import TestClient
from test_drop_transfer import Harness
from test_drop_transfer import put as aput

from orch_relay import db
from orch_relay import drop as DR
from orch_relay import drop_quota as Q
from orch_relay import proto as P
from orch_relay.app import create_app
from orch_relay.directory import Refusal

DECIDE = ["look", "decide"]
FULL = ["look", "decide", "operate", "type"]
HIDDEN = {"error": "not_eligible"}
TODAY = NOW // DAY


@pytest.fixture
def client(tmp_path):
    with TestClient(create_app(tmp_path)) as c:
        setup(c.app.state.directory)
        scopes(c, DEVICE, DECIDE)  # the phone: look and decide, never operate
        yield c


@pytest.fixture
def h(tmp_path):
    h = Harness(tmp_path)
    scopes_at(h.d.path, DEVICE, DECIDE)
    return h


def path_of(c):
    return c.app.state.directory.path


def scopes_at(path, device, value):
    with closing(db.connect(path)) as con, con:
        con.execute("UPDATE members SET scopes=? WHERE device_id=?", (P.cj(value), device))


def scopes(c, device, value):
    scopes_at(path_of(c), device, value)


def sql(c, statement, *args):
    with closing(db.connect(path_of(c))) as con, con:
        con.execute(statement, args)


def budget(path, device=DEVICE, day=TODAY):
    with closing(db.connect(path)) as con:
        row = con.execute(
            "SELECT creations, bytes FROM drop_decide_budget WHERE workspace_id=? AND "
            "device_id=? AND day=?",
            (WS, device, day),
        ).fetchone()
        return None if row is None else tuple(row)


def inbox(label, author=DEVICE, device_wrap=True, **kw):
    """(signed, body) of an inbox file: one wxk and, by default, the author's own device wrap."""
    o_id = object_id(label) if len(label) != 32 else label
    signed, data, _ = descriptor(o_id, author=author, recipients="inbox", **kw)
    wraps = [DR_wrap(signed["o"], "wxk")]
    if device_wrap:
        wraps.append(DR_wrap(signed["o"], "device", author))
    return signed, frame(signed, wraps, data)


def DR_wrap(o, kind, target=None):
    from drop_support import wrap

    return wrap(o, kind, target)


def upload(label, **kw):
    signed, _w, body = plain_upload(label, **kw)
    return signed, body


def get(c, o_id, what, author=DEVICE, version=1):
    return c.get(
        f"/v2/drop/{o_id}/versions/{version}/{what}",
        headers={"Authorization": "Bearer " + TOKENS[author]},
    )


def listing(c, author=DEVICE, direction="received", **extra):
    return c.post(
        "/v2/drop/list",
        json={"workspace_id": WS, "direction": direction, **extra},
        headers={"Authorization": "Bearer " + TOKENS[author]},
    )


def revive(client, now):
    revive_dir(client.app.state.directory, now)


def revive_dir(d, now):
    d.clock = lambda: now
    with closing(db.connect(d.path)) as con, con:
        con.execute("UPDATE sessions SET expires_ms=?", (now + 900_000,))
        con.execute("UPDATE devices SET expires_ms=?", (now + 30 * DAY,))
        con.execute("UPDATE holders SET lease_until_ms=?", (now + 40_000,))


def stored_nothing(c, objects=0):
    assert len(rows(path_of(c), "drop_objects")) == objects
    drop = c.app.state.drop
    assert drop.uploads.count == 0 and drop.uploads.used == {}
    assert drop.reserved.view() == {}


# --- the shape: what a decide-only device may upload ----------------------------------------------


def test_a_decide_only_device_uploads_a_new_inbox_file(client):
    signed, body = inbox("a")
    r = put(client, signed, body)
    assert (r.status_code, r.json()) == (201, {"version": 1})
    obj = rows(path_of(client), "drop_objects")[0]
    assert (obj["audience"], obj["inbox"], obj["head_author_id"]) == ("inbox", 1, DEVICE)
    kinds = sorted(w["target_kind"] for w in rows(path_of(client), "drop_wraps"))
    assert kinds == ["device", "wxk"]  # one wxk and the author's own device wrap, never wk
    assert budget(path_of(client)) == (1, signed["o"]["content_len"])


def test_without_the_device_wrap_it_is_201_too(client):
    signed, body = inbox("a", device_wrap=False)
    assert put(client, signed, body).status_code == 201


def shapes():
    return {
        "document": {"kind": "document"},
        "space_recipients": {"recipients": None},
        "device_only": {"recipients": [LAPTOP]},
    }


@pytest.mark.parametrize("name", ["document", "space_recipients", "device_only"])
def test_any_other_recipients_or_kind_is_403_and_charges_nothing(client, name):
    kw = dict(shapes()[name])
    signed, _w, body = plain_upload("x", **kw)
    r = put(client, signed, body)
    assert (r.status_code, r.content) == (403, b'{"error":"not_eligible"}')
    assert budget(path_of(client)) is None
    stored_nothing(client)


def test_if_match_one_on_a_new_id_is_403_not_a_409(client):
    signed, body = inbox("a")
    r = put(client, signed, body, if_match="1")
    assert (r.status_code, r.json()) == (403, HIDDEN)
    assert budget(path_of(client)) is None
    stored_nothing(client)


def test_a_second_version_from_a_decide_only_device_is_403(client):
    signed, body = inbox("a")
    assert put(client, signed, body).status_code == 201
    again, _w, b2 = plain_upload(signed["o"]["object_id"], version=2, parent=signed["o"])
    r = put(client, again, b2, if_match="1")
    assert (r.status_code, r.json()) == (403, HIDDEN)
    assert budget(path_of(client)) == (1, signed["o"]["content_len"])  # nothing more charged


def test_the_403_is_the_same_for_a_foreign_object_id(client):
    """No new oracle: the shape 403 comes before step 6, so another space's id answers the same."""
    from drop_support import apply_op

    foreign = object_id("foreign")
    apply_op(
        client.app.state.directory,
        {
            "op": "foreign_object",
            "object_id": foreign,
            "workspace_id": __import__("drop_support").WS_B,
        },
    )
    signed, _w, body = plain_upload(foreign, kind="document")
    r = put(client, signed, body)
    assert (r.status_code, r.content) == (403, b'{"error":"not_eligible"}')


def test_a_wk_wrap_on_the_inbox_file_is_400(client):
    signed, data, _ = descriptor(object_id("a"), recipients="inbox")
    o = signed["o"]
    body = frame(signed, [DR_wrap(o, "wxk"), DR_wrap(o, "wk")], data)
    assert put(client, signed, body).status_code == 400
    assert budget(path_of(client)) is None


def test_look_only_device_is_refused_before_any_slot(client):
    scopes(client, DEVICE, ["look"])
    signed, body = inbox("a")
    seen = []
    client.app.state.drop.hooks["drain"] = lambda: seen.append(1)
    r = put(client, signed, body)
    assert (r.status_code, r.json()) == (403, HIDDEN)
    assert seen == []  # step 2: no slot, no drain
    assert budget(path_of(client)) is None


def test_a_device_with_operate_is_not_charged_to_the_decide_budget(client):
    scopes(client, DEVICE, FULL)
    signed, body = inbox("a")
    assert put(client, signed, body).status_code == 201
    assert budget(path_of(client)) is None


def test_a_member_with_decide_in_one_workspace_and_operate_in_another_is_admitted(client):
    """Step 2 looks at every membership: operate anywhere or decide anywhere."""
    scopes(client, DEVICE, ["look"])
    sql(client, "INSERT INTO members VALUES (?,?,?,?)", "e" * 32, DEVICE, "p", P.cj(DECIDE))
    signed, body = inbox("a")
    assert put(client, signed, body).status_code == 403  # step 5: no decide in WS
    scopes(client, DEVICE, DECIDE)
    assert put(client, *inbox("b")).status_code == 201


# --- the object state a decide-only device sees -----------------------------------------------------


def test_own_object_again_is_409_and_the_exact_retry_is_200_without_a_charge(client):
    signed, body = inbox("a")
    assert put(client, signed, body).status_code == 201
    other, other_body = inbox(signed["o"]["object_id"], content=b"different")
    r = put(client, other, other_body)
    assert (r.status_code, r.json()) == (409, {"error": "version_conflict", "current": 1})
    client.app.state.drop.quotas.decide_creations = 1  # the budget is spent
    r = put(client, signed, body)
    assert (r.status_code, r.json()) == (200, {"version": 1})
    assert budget(path_of(client)) == (1, signed["o"]["content_len"])


def test_another_authors_unclaimed_inbox_id_is_403(client):
    scopes(client, LAPTOP, FULL)
    signed, body = inbox("a", author=LAPTOP)
    assert put(client, signed, body, author=LAPTOP).status_code == 201
    mine, mine_body = inbox(signed["o"]["object_id"])
    r = put(client, mine, mine_body)
    assert (r.status_code, r.content) == (403, b'{"error":"not_eligible"}')
    assert budget(path_of(client)) is None


def test_a_tombstone_the_author_sees_is_410(client):
    signed, body = inbox("a")
    assert put(client, signed, body).status_code == 201
    sql(client, "UPDATE drop_objects SET tombstone_ms=?, tombstone_kind='retired'", NOW)
    again, again_body = inbox(signed["o"]["object_id"], content=b"new")
    r = put(client, again, again_body)
    assert (r.status_code, r.json()) == (410, {"error": "expired"})


def test_no_stale_epoch_and_no_rotation_required_for_a_wk_less_upload(client):
    from drop_support import apply_op

    apply_op(client.app.state.directory, {"op": "epoch", "epoch": 2})
    apply_op(client.app.state.directory, {"op": "rotation_due"})
    assert put(client, *inbox("a")).status_code == 201


def test_an_old_wxk_is_409_bad_wxk_version_and_not_charged(client):
    signed, data, _ = descriptor(object_id("a"), recipients="inbox")
    body = frame(signed, [DR_wrap(signed["o"], "wxk")], data)
    sql(client, "UPDATE workspaces SET wxk_version=2")
    r = put(client, signed, body)
    assert (r.status_code, r.json()) == (409, {"error": "bad_wxk_version"})
    assert budget(path_of(client)) is None


# --- the budget -------------------------------------------------------------------------------------


def test_the_51st_creation_is_429_with_the_quota_and_the_seconds_to_midnight(client):
    drop = client.app.state.drop
    assert (drop.quotas.decide_creations, drop.quotas.decide_bytes) == (50, 64 * 1024 * 1024)
    drop.quotas.decide_creations = 2
    for label in "ab":
        assert put(client, *inbox(label)).status_code == 201
    r = put(client, *inbox("c"))
    assert r.status_code == 429
    assert r.json() == {"error": "rate_limited", "quota": "drop_decide_creations"}
    assert r.headers["retry-after"] == str(Q.seconds_to_midnight(NOW))
    stored_nothing(client, 2)
    assert budget(path_of(client))[0] == 2  # a refusal does not count


def test_content_len_over_the_remaining_bytes_is_429_drop_decide_bytes(client):
    drop = client.app.state.drop
    first, body = inbox("a")
    drop.quotas.decide_bytes = first["o"]["content_len"] * 2 - 1
    assert put(client, first, body).status_code == 201
    r = put(client, *inbox("b"))
    assert r.status_code == 429
    assert r.json() == {"error": "rate_limited", "quota": "drop_decide_bytes"}
    assert budget(path_of(client)) == (1, first["o"]["content_len"])


def test_a_blob_over_an_empty_days_bytes_is_refused_by_the_insert_branch_too(client):
    client.app.state.drop.quotas.decide_bytes = 10
    r = put(client, *inbox("a"))
    assert (r.status_code, r.json()["quota"]) == (429, "drop_decide_bytes")
    assert budget(path_of(client)) is None


def test_the_exact_cap_is_accepted(client):
    drop = client.app.state.drop
    first, body = inbox("a")
    second, body2 = inbox("b")
    drop.quotas.decide_bytes = first["o"]["content_len"] + second["o"]["content_len"]
    drop.quotas.decide_creations = 2
    assert put(client, first, body).status_code == 201
    assert put(client, second, body2).status_code == 201
    assert budget(path_of(client)) == (2, drop.quotas.decide_bytes)


def test_retry_after_at_23_59_59_500_is_1_and_the_next_day_is_charged_afresh(client):
    drop = client.app.state.drop
    drop.quotas.decide_creations = 1
    midnight = (NOW // DAY + 1) * DAY
    revive(client, midnight - 500)
    s, b = inbox("a", now=midnight - 500)
    assert put(client, s, b).status_code == 201
    s, b = inbox("b", now=midnight - 500)
    r = put(client, s, b)
    assert (r.status_code, r.headers["retry-after"]) == (429, "1")
    revive(client, midnight)
    s, b = inbox("c", now=midnight)
    assert put(client, s, b).status_code == 201  # 00:00:00.000 UTC is a new day: a new row
    assert budget(path_of(client), day=midnight // DAY - 1)[0] == 1
    assert budget(path_of(client), day=midnight // DAY)[0] == 1


def test_the_budget_is_per_device_and_per_workspace(client):
    scopes(client, LAPTOP, DECIDE)
    client.app.state.drop.quotas.decide_creations = 1
    assert put(client, *inbox("a")).status_code == 201
    assert put(client, *inbox("b", author=LAPTOP), author=LAPTOP).status_code == 201
    assert budget(path_of(client), LAPTOP)[0] == 1 and budget(path_of(client))[0] == 1
    assert put(client, *inbox("c")).status_code == 429


def test_the_budget_survives_a_restart(tmp_path):
    with TestClient(create_app(tmp_path)) as c:
        setup(c.app.state.directory)
        scopes(c, DEVICE, DECIDE)
        c.app.state.drop.quotas.decide_creations = 1
        assert put(c, *inbox("a")).status_code == 201
    with TestClient(create_app(tmp_path)) as c:
        c.app.state.directory.clock = lambda: NOW  # the persisted rows and sessions stay
        c.app.state.drop.quotas.decide_creations = 1
        assert put(c, *inbox("b")).status_code == 429


def test_the_upsert_is_all_or_nothing_under_threads(tmp_path):
    """Two concurrent charges for the last creation: one wins, one 429 (the single writer)."""
    with TestClient(create_app(tmp_path)) as c:
        setup(c.app.state.directory)
        scopes(c, DEVICE, DECIDE)
        drop = c.app.state.drop
        drop.quotas.decide_creations = 1
        signed, _ = inbox("a")

        class P:
            o = signed["o"]
            charged = None

        out = []

        def go():
            try:
                drop.charge_budget(P, NOW)
                out.append("ok")
            except Refusal as refusal:
                out.append(refusal.status)

        threads = [threading.Thread(target=go) for _ in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert sorted(map(str, out)) == ["429"] * 5 + ["ok"]
        assert budget(drop.d.path)[0] == 1


# --- the commit-time authority ----------------------------------------------------------------------


def test_decide_removed_during_the_transfer_is_403_at_the_commit_and_stays_charged(client):
    drop = client.app.state.drop
    signed, body = inbox("a")
    drop.hooks["before_commit"] = lambda plan: scopes(client, DEVICE, ["look"])
    r = put(client, signed, body)
    assert (r.status_code, r.content) == (403, b'{"error":"not_eligible"}')
    stored_nothing(client)
    assert [p for p in drop.blobs.rglob("*") if p.is_file()] == []
    assert budget(path_of(client)) == (1, signed["o"]["content_len"])  # all received: all charged


def test_a_device_removed_during_the_transfer_is_403_at_the_commit(client):
    drop = client.app.state.drop
    drop.hooks["before_commit"] = lambda plan: sql(
        client, "DELETE FROM members WHERE device_id=?", DEVICE
    )
    r = put(client, *inbox("a"))
    assert r.status_code == 403
    stored_nothing(client)


def test_operate_removed_but_decide_kept_is_charged_at_the_commit(client):
    scopes(client, DEVICE, FULL)
    drop = client.app.state.drop
    drop.hooks["before_commit"] = lambda plan: scopes(client, DEVICE, DECIDE)
    signed, body = inbox("a")
    assert put(client, signed, body).status_code == 201
    assert budget(path_of(client)) == (1, signed["o"]["content_len"])


def test_operate_removed_with_the_budget_spent_is_429_at_the_commit_with_nothing_stored(client):
    scopes(client, DEVICE, FULL)
    drop = client.app.state.drop
    drop.quotas.decide_creations = 1
    sql(client, "INSERT INTO drop_decide_budget VALUES (?,?,?,1,0)", WS, DEVICE, TODAY)
    drop.hooks["before_commit"] = lambda plan: scopes(client, DEVICE, DECIDE)
    r = put(client, *inbox("a"))
    assert (r.status_code, r.json()["quota"]) == (429, "drop_decide_creations")
    stored_nothing(client)
    assert budget(path_of(client)) == (1, 0)  # no charge: the stream was admitted under operate
    assert rows(path_of(client), "drop_usage") == []


def test_operate_removed_on_the_days_first_upload_inserts_the_row(client):
    """A plain UPDATE would refuse the first upload of a day (no row); the upsert inserts."""
    scopes(client, DEVICE, FULL)
    drop = client.app.state.drop
    drop.hooks["before_commit"] = lambda plan: scopes(client, DEVICE, DECIDE)
    signed, body = inbox("a")
    assert put(client, signed, body).status_code == 201
    assert budget(path_of(client)) == (1, signed["o"]["content_len"])


def test_decide_at_admission_and_operate_at_the_commit_keeps_the_charge(client):
    drop = client.app.state.drop
    drop.hooks["before_commit"] = lambda plan: scopes(client, DEVICE, FULL)
    signed, body = inbox("a")
    assert put(client, signed, body).status_code == 201
    assert budget(path_of(client)) == (1, signed["o"]["content_len"])


def test_a_charge_at_admission_after_midnight_commit_goes_to_the_request_day(client):
    drop = client.app.state.drop
    midnight = (NOW // DAY + 1) * DAY
    start = midnight - 2000
    revive(client, start)
    drop.hooks["before_commit"] = lambda plan: revive(client, midnight + 1000)
    signed, body = inbox("a", now=start)
    assert put(client, signed, body).status_code == 201
    assert budget(path_of(client), day=start // DAY) == (1, signed["o"]["content_len"])
    assert budget(path_of(client), day=midnight // DAY) is None


def test_the_give_back_after_midnight_goes_to_the_request_day(h):
    midnight = (NOW // DAY + 1) * DAY
    start = midnight - 2000
    revive_dir(h.d, start)
    signed, body = inbox("a", now=start, content=b"\1" * 100_000)
    head = 8 + int.from_bytes(body[4:8], "big")
    cut = head + signed["o"]["content_len"] // 2
    h.drop.hooks["head"] = lambda: h.d.__setattr__("clock", lambda: midnight + 5)
    asyncio.run(aput(h, body, signed, chunks=[body[:cut]], then="disconnect"))
    with closing(db.connect(h.d.path)) as con:
        rows_ = con.execute("SELECT day, creations, bytes FROM drop_decide_budget").fetchall()
    assert [tuple(r) for r in rows_] == [(start // DAY, 1, cut - head)]  # the old day's row only


# --- the error path: what an aborted stream costs -----------------------------------------------------


def received_of(body, signed, cut):
    """Blob bytes the relay sees when `cut` bytes of the whole body arrived."""
    head = 8 + int.from_bytes(body[4:8], "big")
    return max(0, min(cut, len(body)) - head)


def test_a_disconnect_after_half_the_blob_charges_one_creation_and_the_bytes_received(h):
    signed, body = inbox("a", content=b"\1" * 200_000)
    head = 8 + int.from_bytes(body[4:8], "big")
    cut = head + signed["o"]["content_len"] // 2
    chunks = [body[:cut]]
    peer = asyncio.run(aput(h, body, signed, chunks=chunks, then="disconnect"))
    assert peer.sent == [] or peer.status in (400, 429)
    assert budget(h.d.path) == (1, cut - head)  # the unreceived half was given back
    assert rows(h.d.path, "drop_objects") == []
    assert h.drop.reserved.view() == {} and h.drop.uploads.count == 0
    assert h.drop.uploads.used == {}


def test_a_disconnect_before_the_first_blob_byte_keeps_one_creation_and_no_bytes(h):
    signed, body = inbox("a", content=b"\1" * 100_000)
    head = 8 + int.from_bytes(body[4:8], "big")
    asyncio.run(aput(h, body, signed, chunks=[body[:head]], then="disconnect"))
    assert budget(h.d.path) == (1, 0)


def test_a_short_body_a_bad_hash_and_a_non_ord2_blob_are_charged(h):
    signed, body = inbox("a")
    h.d.clock = lambda: NOW
    # a wrong content hash: every byte arrives, the commit never happens, all of it stays charged
    bad = body[:-1] + bytes([body[-1] ^ 1])
    peer = asyncio.run(aput(h, bad, signed))
    assert peer.status == 400
    assert budget(h.d.path) == (1, signed["o"]["content_len"])


def test_a_refusal_at_the_quota_reservation_gives_the_whole_charge_back(h):
    signed, body = inbox("a")
    h.drop.quotas.ws_blob = 10  # the reservation refuses right after the charge
    peer = asyncio.run(aput(h, body, signed))
    assert (peer.status, peer.json["error"]) == (429, "quota_exceeded")
    assert budget(h.d.path) == (0, 0)  # charged, then refunded: 1 creation and the bytes


def test_the_global_503_at_the_reservation_is_refunded_too(h):
    signed, body = inbox("a")
    h.drop.quotas.global_blob = 10
    peer = asyncio.run(aput(h, body, signed))
    assert peer.status == 503
    assert budget(h.d.path) == (0, 0)


def test_a_lost_give_back_leaves_the_full_charge(h, monkeypatch):
    def boom(*args):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(DR, "give_back_decide", boom)
    signed, body = inbox("a", content=b"\1" * 100_000)
    head = 8 + int.from_bytes(body[4:8], "big")
    asyncio.run(aput(h, body, signed, chunks=[body[: head + 500]], then="disconnect"))
    assert budget(h.d.path) == (1, signed["o"]["content_len"])  # over-charged, never under


def test_a_lost_refund_at_the_reservation_over_charges(h, monkeypatch):
    monkeypatch.setattr(
        DR, "give_back_decide", lambda *a: (_ for _ in ()).throw(sqlite3.OperationalError("x"))
    )
    signed, body = inbox("a")
    h.drop.quotas.ws_blob = 10
    peer = asyncio.run(aput(h, body, signed))
    assert peer.status == 429
    assert budget(h.d.path) == (1, signed["o"]["content_len"])


def test_a_commit_keeps_the_charge_and_gives_nothing_back(h):
    signed, body = inbox("a")
    peer = asyncio.run(aput(h, body, signed))
    assert peer.status == 201
    assert budget(h.d.path) == (1, signed["o"]["content_len"])


def test_an_exact_retry_is_never_charged(h):
    signed, body = inbox("a")
    assert asyncio.run(aput(h, body, signed)).status == 201
    peer = asyncio.run(aput(h, body, signed, then="stall"))
    assert peer.status == 200
    assert budget(h.d.path) == (1, signed["o"]["content_len"])


def test_a_concurrent_identical_upload_that_loses_to_the_commit_is_refunded(h):
    """Both pass step 7 before either commits (an exact retry only at the commit): the loser's
    200 refunds its charge. The decide slot serializes one device, so the rival is a second
    request made after the first landed but before the second's commit."""
    signed, body = inbox("a")

    async def go():
        async def rival(plan):
            h.drop.hooks.pop("before_commit")
            h.drop.uploads.used.pop(
                ("decide", DEVICE), None
            )  # let the rival in, as a retry would be
            second = await aput(h, body, signed)
            assert second.status == 201

        h.drop.hooks["before_commit"] = rival
        first = await aput(h, body, signed)
        return first

    first = asyncio.run(go())
    assert first.status == 200  # the exact retry won at the commit
    assert budget(h.d.path) == (1, signed["o"]["content_len"])  # one charge in all, not two


# --- the slot -----------------------------------------------------------------------------------------


def test_a_second_concurrent_decide_class_upload_is_429_slot_before_any_byte(h):
    first, body1 = inbox("a")
    second, body2 = inbox("b")

    async def go():
        gate, reached = asyncio.Event(), asyncio.Event()

        async def hold(plan):
            reached.set()
            await gate.wait()

        h.drop.hooks["before_commit"] = hold
        one = asyncio.create_task(aput(h, body1, first))
        await reached.wait()
        assert h.drop.uploads.used[("decide", DEVICE)] == 1
        refusal = await aput(h, body2, second, chunks=[])
        gate.set()
        return refusal, await one

    refusal, win = asyncio.run(go())
    assert win.status == 201
    assert (refusal.status, refusal.json) == (429, {"error": "quota_exceeded", "quota": "slot"})
    assert budget(h.d.path) == (1, first["o"]["content_len"])  # the refused one charged nothing
    assert h.drop.uploads.count == 0 and h.drop.uploads.used == {}


def test_a_device_with_operate_elsewhere_gets_the_slot_at_step_5(h):
    """Decide-only for this workspace but `operate` in another: no slot at step 2, one at step 5."""
    sql_ = "INSERT INTO members VALUES (?,?,?,?)"
    with closing(db.connect(h.d.path)) as con, con:
        con.execute(sql_, ("e" * 32, DEVICE, "person", P.cj(["look", "decide", "operate"])))
    first, body1 = inbox("a")
    second, body2 = inbox("b")

    async def go():
        gate, reached = asyncio.Event(), asyncio.Event()

        async def hold(plan):
            reached.set()
            await gate.wait()

        h.drop.hooks["before_commit"] = hold
        one = asyncio.create_task(aput(h, body1, first))
        await reached.wait()
        assert h.drop.uploads.used[("decide", DEVICE)] == 1  # taken at step 5
        refusal = await aput(h, body2, second)
        gate.set()
        return refusal, await one

    refusal, win = asyncio.run(go())
    assert win.status == 201
    assert (refusal.status, refusal.json) == (429, {"error": "quota_exceeded", "quota": "slot"})
    assert h.drop.uploads.used == {}


def test_sequential_decide_class_uploads_reuse_the_slot(h):
    for label in "abc":
        signed, body = inbox(label)
        assert asyncio.run(aput(h, body, signed)).status == 201
    assert h.drop.uploads.used == {}


# --- visibility: an unclaimed inbox object is the host's and its author's -------------------------------


def seeded(client):
    """The phone's unclaimed inbox file a; the laptop's space file b (n 2)."""
    a, ab = inbox("a")
    assert put(client, a, ab).status_code == 201
    b, bb = upload("b", author=LAPTOP)
    assert put(client, b, bb, author=LAPTOP).status_code == 201
    return a["o"]["object_id"], b["o"]["object_id"]


def test_other_member_devices_get_403_with_the_one_body_on_every_read_and_put(client):
    a, _b = seeded(client)
    again, again_body = inbox(a, author=LAPTOP)
    scopes(client, LAPTOP, FULL)
    bodies = set()
    for what in ("descriptor", "wraps", "blob"):
        r = get(client, a, what, LAPTOP)
        assert r.status_code == 403
        bodies.add((r.content, r.headers["content-type"]))
    r = client.get(
        f"/v2/drop/{a}/descriptors", headers={"Authorization": "Bearer " + TOKENS[LAPTOP]}
    )
    bodies.add((r.content, r.headers["content-type"]))
    r = put(client, again, again_body, author=LAPTOP)
    assert r.status_code == 403
    bodies.add((r.content, r.headers["content-type"]))
    # the same bytes as every other 403: a foreign id and a wrong scope
    other = put(client, *upload("zz", kind="document"), author=DEVICE)
    bodies.add((other.content, other.headers["content-type"]))
    assert bodies == {(b'{"error":"not_eligible"}', "application/json")}


def test_the_author_reads_its_descriptor_and_wraps_but_not_the_blob(client):
    a, _b = seeded(client)
    assert get(client, a, "descriptor").status_code == 200
    assert get(client, a, "wraps").status_code == 200
    r = get(client, a, "blob")
    assert (r.status_code, r.json()) == (403, HIDDEN)


def test_the_host_sees_it_in_a_list_and_reads_it(client):
    a, b = seeded(client)
    assert [e["object_id"] for e in listing(client, WS).json()["objects"]] == [a, b]
    assert get(client, a, "descriptor", WS).status_code == 200


def test_the_list_hides_it_from_members_and_shows_it_to_its_author_in_sending(client):
    a, b = seeded(client)
    scopes(client, LAPTOP, FULL)
    assert [e["object_id"] for e in listing(client, LAPTOP).json()["objects"]] == []
    assert [e["object_id"] for e in listing(client, DEVICE, "sending").json()["objects"]] == [a]
    assert [e["object_id"] for e in listing(client, DEVICE).json()["objects"]] == [b]
    assert [e["object_id"] for e in listing(client, LAPTOP, "sending").json()["objects"]] == [b]


def test_the_filter_runs_before_the_page_limit_no_gaps_and_no_leaks(client):
    """Three hidden inbox objects, then a visible one: a page of 1 holds the visible one and ends."""
    for label in "abc":
        assert put(client, *inbox(label)).status_code == 201
    b, bb = upload("vis", author=WS)
    assert put(client, b, bb, author=WS).status_code == 201
    page = listing(client, LAPTOP, limit=1).json()
    assert [e["n"] for e in page["objects"]] == [4] and page["next"] is None
    assert listing(client, LAPTOP, after=1).json()["objects"][0]["n"] == 4
    # the byte cut counts only visible entries too
    again = listing(client, LAPTOP, limit=2).json()
    assert len(again["objects"]) == 1 and again["next"] is None


def test_it_is_hidden_in_every_state_a_tombstone_included(client):
    a, _b = seeded(client)
    sql(
        client,
        "UPDATE drop_objects SET tombstone_ms=?, tombstone_kind='retired', n=9 WHERE object_id=?",
        NOW,
        a,
    )
    scopes(client, LAPTOP, FULL)
    assert get(client, a, "descriptor", LAPTOP).status_code == 403
    assert listing(client, LAPTOP).json()["objects"] == []
    assert [e["state"] for e in listing(client, DEVICE, "sending").json()["objects"]] == ["retired"]
    assert get(client, a, "descriptor").status_code == 410  # the author's own
    host = {e["object_id"]: e for e in listing(client, WS).json()["objects"]}
    assert host[a]["state"] == "retired"


def test_once_claimed_it_follows_the_claimed_visibility(client):
    a, _b = seeded(client)
    scopes(client, LAPTOP, FULL)
    sql(
        client,
        "UPDATE drop_objects SET claimed_by=?, claimed_ms=?, n=5 WHERE object_id=?",
        WS,
        NOW + 7,
        a,
    )
    assert get(client, a, "descriptor", LAPTOP).status_code == 200
    assert get(client, a, "blob", LAPTOP).status_code == 200
    entry = listing(client, LAPTOP).json()["objects"][-1]
    assert (entry["object_id"], entry["claimed_by"], entry["claimed_ms"]) == (a, WS, NOW + 7)
    assert entry["expires_ms"] == NOW + 7 * DAY


def test_claimed_ms_and_expires_ms_are_null_or_int_and_a_document_has_no_expiry(client):
    scopes(client, DEVICE, FULL)
    d, db_ = upload("doc", kind="document")
    assert put(client, d, db_).status_code == 201
    entry = listing(client, WS).json()["objects"][0]
    assert (entry["claimed_ms"], entry["expires_ms"]) == (None, None)
    f, fb = upload("file")
    assert put(client, f, fb).status_code == 201
    entries = {e["object_id"]: e for e in listing(client, WS).json()["objects"]}
    e = entries[f["o"]["object_id"]]
    assert (e["claimed_ms"], e["expires_ms"]) == (None, NOW + 7 * DAY)


def test_a_device_session_sees_claimed_ms_too(client):
    scopes(client, LAPTOP, FULL)
    a, _b = seeded(client)
    sql(
        client,
        "UPDATE drop_objects SET claimed_by=?, claimed_ms=?, n=7 WHERE object_id=?",
        WS,
        12345,
        a,
    )
    got = {e["object_id"]: e for e in listing(client, LAPTOP).json()["objects"]}
    assert got[a]["claimed_ms"] == 12345


def test_the_list_entry_key_order_is_cj(client):
    import json

    seeded(client)
    entry = json.loads(listing(client, WS).content)["objects"][0]
    assert list(entry) == sorted(entry)
    assert {"claimed_ms", "expires_ms"} <= set(entry)
