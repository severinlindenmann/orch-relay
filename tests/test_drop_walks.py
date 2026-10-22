"""P3-D39 (D39a2 part 4, §14.2 item 14): W-session list walks. `direction: "all"`, the relay's
`generation` in every page, `until` (a walk's bounded high-watermark), 409 `generation_changed`, the
check order, concurrent changes during a walk and the A1 state interplay."""

import re
from contextlib import closing

import pytest
from directory_support import DEVICE, NOW, WS
from drop_support import (
    DAY,
    LAPTOP,
    TOKENS,
    headers,
    object_id,
    put,
    rows,
    setup,
    sync_counter,
    upload,
)
from fastapi.testclient import TestClient

from orch_relay import db
from orch_relay import drop as DR
from orch_relay import proto as P
from orch_relay.app import create_app
from orch_relay.drop import parent_hash

STALE = "0" * 32
GONE = {"error": "generation_changed"}


@pytest.fixture
def client(tmp_path):
    with TestClient(create_app(tmp_path)) as c:
        setup(c.app.state.directory)
        yield c


def path_of(c):
    return c.app.state.directory.path


def sql(c, statement, *args):
    with closing(db.connect(path_of(c))) as con, con:
        con.execute(statement, args)
        sync_counter(con)


def generation(c):
    return c.app.state.drop.state.generation


def ask(c, who=WS, direction="all", **extra):
    return c.post(
        "/v2/drop/list",
        json={"workspace_id": WS, "direction": direction, **extra},
        headers={"Authorization": "Bearer " + TOKENS[who]},
    )


def walk(c, who=WS, direction="all", limit=None, after=None, hook=None):
    """A complete walk the way the client guidance says: page 1 without `until`, the rest with
    `until` and `generation`. Returns (entries, first page). `hook(page_number)` runs between pages."""
    pages, entries = [], []
    extra = {} if limit is None else {"limit": limit}
    if after is not None:
        extra["after"] = after
        extra["generation"] = generation(c)
    page = ask(c, who, direction, **extra).json()
    pages.append(page)
    while True:
        entries += page["objects"]
        assert page["generation"] == generation(c) and page["until"] == pages[0]["until"]
        if page["next"] is None:
            return entries, pages
        assert page["next"] == page["objects"][-1]["n"] <= page["until"]
        if hook:
            hook(len(pages))
        req = {
            **extra,
            "after": page["next"],
            "until": page["until"],
            "generation": page["generation"],
        }
        page = ask(c, who, direction, **req).json()
        pages.append(page)


def put_all(client, *specs):
    out = []
    for label, kw in specs:
        s, _w, b = upload(label, **kw)
        assert put(client, s, b, author=kw.get("author")).status_code == 201
        out.append(s)
    return out


def retire(client, signed):
    return client.post(
        f"/v2/drop/{signed['o']['object_id']}/retire",
        content=P.cj(
            {"expect_version": signed["o"]["version"], "expect_head": parent_hash(signed["o"])}
        ),
        headers={**headers(WS, if_match=None), "Content-Type": "application/json"},
    )


# --- generation -------------------------------------------------------------------------------------


@pytest.mark.parametrize("who", [WS, DEVICE, LAPTOP])
@pytest.mark.parametrize("direction", ["received", "sending", "all"])
def test_every_page_carries_generation_and_until(client, who, direction):
    if direction == "all" and who != WS:
        pytest.skip("device `all` is 403, tested separately")
    put_all(client, ("a", {}), ("b", {"author": LAPTOP}))
    page = ask(client, who, direction).json()
    assert re.fullmatch(r"[0-9a-f]{32}", page["generation"])
    assert page["generation"] == generation(client) and page["until"] == 2
    assert set(page) == {"objects", "next", "generation", "until"}


def test_the_generation_is_the_meta_row_and_stable_across_a_restart(tmp_path):
    with TestClient(create_app(tmp_path)) as c:
        first = generation(c)
        stored = rows(c.app.state.directory.path, "meta")
        assert {r["key"]: r["value"] for r in stored}["drop_generation"] == first
    with TestClient(create_app(tmp_path)) as c:
        assert generation(c) == first  # a plain restart keeps it


def test_a_meta_row_changed_or_deleted_while_running_changes_nothing(client):
    page = ask(client).json()
    sql(client, "DELETE FROM meta WHERE key='drop_generation'")
    assert ask(client).json()["generation"] == page["generation"]  # held in memory (L1)


# --- direction all ----------------------------------------------------------------------------------


def test_all_lists_both_authors_and_every_state_for_the_w_session(client):
    a, b, c_, d = put_all(
        client,
        ("a", {}),
        ("b", {"author": LAPTOP}),
        ("c", {"author": WS, "recipients": [LAPTOP]}),
        ("d", {"recipients": "inbox"}),
    )
    assert retire(client, c_).status_code == 200
    got = {e["object_id"]: e["state"] for e in ask(client).json()["objects"]}
    assert got == {
        a["o"]["object_id"]: "live",
        b["o"]["object_id"]: "live",
        c_["o"]["object_id"]: "retired",
        d["o"]["object_id"]: "live",  # the phone's unclaimed inbox file: the W session sees it
    }
    # received and sending stay usable for the W session
    assert len(ask(client, direction="received").json()["objects"]) == 3
    assert len(ask(client, direction="sending").json()["objects"]) == 1


@pytest.mark.parametrize("who", [DEVICE, LAPTOP])
def test_a_device_asking_for_all_is_403_not_eligible(client, who):
    put_all(client, ("a", {}))
    r = ask(client, who, "all")
    assert (r.status_code, r.json()) == (403, {"error": "not_eligible"})
    r = ask(client, who, "all", after=0, generation=generation(client))
    assert (r.status_code, r.json()) == (403, {"error": "not_eligible"})


def test_a_device_never_sees_an_unclaimed_inbox_file_in_received_and_the_author_in_sending(client):
    (d,) = put_all(client, ("d", {"recipients": "inbox"}))
    assert ask(client, LAPTOP, "received").json()["objects"] == []
    assert ask(client, DEVICE, "received").json()["objects"] == []
    assert [e["object_id"] for e in ask(client, DEVICE, "sending").json()["objects"]] == [
        d["o"]["object_id"]
    ]
    assert [e["object_id"] for e in ask(client, WS, "all").json()["objects"]] == [
        d["o"]["object_id"]
    ]


# --- 400 --------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "extra",
    [
        {"until": 1},  # until without generation
        {"until": 1, "after": 0},
        {"after": 0},  # all with after, without generation
        {"after": 3, "until": 2, "generation": "g"},  # replaced below: valid generation
        {"generation": "A" * 32},  # upper case
        {"generation": "a" * 31},
        {"generation": "a" * 33},
        {"generation": 7},
        {"generation": None},
        {"generation": "g" * 32},
        {"generation": "a" * 32, "until": "5"},
        {"generation": "a" * 32, "until": True},
        {"generation": "a" * 32, "until": -1},
        {"generation": "a" * 32, "until": None},
    ],
)
def test_malformed_walk_requests_are_400(client, extra):
    extra = dict(extra)
    if extra.get("generation") == "g":
        extra["generation"] = generation(client)
    r = ask(client, WS, "all", **extra)
    assert (r.status_code, r.json()) == (400, {"error": "malformed"}), extra


def test_after_above_until_is_400_not_409(client):
    put_all(client, ("a", {}))
    r = ask(client, WS, "all", after=2, until=1, generation=generation(client))
    assert (r.status_code, r.json()) == (400, {"error": "malformed"})


def test_until_without_generation_is_400_for_received_and_sending_too(client):
    for who, direction in ((DEVICE, "received"), (DEVICE, "sending"), (WS, "received")):
        assert ask(client, who, direction, until=0).status_code == 400
    assert ask(client, DEVICE, "received", after=0).status_code == 200  # optional there


def test_unknown_direction_and_unknown_key_are_400(client):
    assert ask(client, WS, "everything").status_code == 400
    assert ask(client, WS, "all", generations="x").status_code == 400


def test_400_comes_before_the_403_for_a_device_asking_for_all(client):
    r = ask(client, DEVICE, "all", until=1)  # malformed: until without generation
    assert (r.status_code, r.json()) == (400, {"error": "malformed"})


# --- 409 --------------------------------------------------------------------------------------------


def test_a_stale_generation_is_409_with_the_exact_body(client):
    put_all(client, ("a", {}))
    for who, direction in (
        (WS, "all"),
        (WS, "received"),
        (DEVICE, "received"),
        (LAPTOP, "sending"),
    ):
        r = ask(client, who, direction, after=1, generation=STALE)
        assert (r.status_code, r.json()) == (409, GONE), (who, direction)
        assert r.content == b'{"error":"generation_changed"}'
    # also on a first page that merely carries a generation
    assert ask(client, WS, "all", generation=STALE).status_code == 409


def test_a_stale_generation_on_a_continued_walk_is_409(client):
    put_all(client, ("a", {}), ("b", {}), ("c", {}))
    first = ask(client, limit=1).json()
    r = ask(client, limit=1, after=first["next"], until=first["until"], generation=STALE)
    assert (r.status_code, r.json()) == (409, GONE)


def test_after_or_until_above_the_counter_is_409_with_the_current_generation(client):
    put_all(client, ("a", {}), ("b", {}))
    g = generation(client)
    for extra in (
        {"after": 3, "generation": g},
        {"after": 3, "until": 9, "generation": g},
        {"after": 0, "until": 3, "generation": g},
    ):
        r = ask(client, WS, "all", **extra)
        assert (r.status_code, r.json()) == (409, GONE), extra
    # no generation sent: the counter check answers on its own (a restore the start check missed)
    for who, direction in ((DEVICE, "received"), (WS, "received"), (LAPTOP, "sending")):
        r = ask(client, who, direction, after=3)
        assert (r.status_code, r.json()) == (409, GONE)
    assert ask(client, DEVICE, "received", after=2).status_code == 200  # == counter is fine


def test_the_409_follows_authorization_and_the_400s(client):
    put_all(client, ("a", {}))
    g = generation(client)
    assert ask(client, DEVICE, "all", after=0, generation=STALE).status_code == 403
    assert ask(client, WS, "all", after=0).status_code == 400
    assert ask(client, WS, "all", after=0, until=0).status_code == 400
    r = client.post("/v2/drop/list", json={"workspace_id": WS, "direction": "all", "generation": g})
    assert r.status_code == 401
    other = "ab" * 16
    r = client.post(
        "/v2/drop/list",
        json={"workspace_id": other, "direction": "received", "generation": STALE},
        headers={"Authorization": "Bearer " + TOKENS[DEVICE]},
    )
    assert (r.status_code, r.json()) == (403, {"error": "not_eligible"})  # not a member: no oracle


# --- until and the walk -----------------------------------------------------------------------------


def test_the_first_page_returns_the_counter_as_until_and_empty_is_fine(client):
    page = ask(client).json()
    assert (page["objects"], page["next"], page["until"]) == ([], None, 0)
    put_all(client, ("a", {}), ("b", {}))
    assert ask(client).json()["until"] == 2
    assert ask(client, after=2, generation=generation(client)).json()["objects"] == []


def test_a_walk_in_pages_of_one_ends_at_until_and_lists_each_object_once(client):
    put_all(client, ("a", {}), ("b", {"author": LAPTOP}), ("c", {}), ("d", {"author": LAPTOP}))
    entries, pages = walk(client, limit=1)
    assert [e["n"] for e in entries] == [1, 2, 3, 4]
    assert len(pages) == 4 and [p["next"] for p in pages] == [1, 2, 3, None]
    assert {p["until"] for p in pages} == {4} and {p["generation"] for p in pages} == {
        generation(client)
    }


def test_next_is_above_after_and_at_most_until(client):
    put_all(client, *[(f"o{i}", {}) for i in range(5)])
    after = 0
    first = ask(client, limit=2).json()
    page = first
    while page["next"] is not None:
        assert after < page["next"] <= page["until"]
        after = page["next"]
        page = ask(
            client, limit=2, after=after, until=first["until"], generation=first["generation"]
        ).json()
    assert page["next"] is None and page["until"] == first["until"]  # echoed on the last page too


def test_the_last_page_of_a_walk_cut_at_until_has_next_null_even_with_more_rows_above(client):
    put_all(client, ("a", {}), ("b", {}))
    first = ask(client, limit=1).json()  # until 2
    put_all(client, ("c", {}), ("d", {}))  # n 3 and 4 appear during the walk
    page = ask(
        client, limit=1, after=first["next"], until=first["until"], generation=first["generation"]
    ).json()
    assert [e["n"] for e in page["objects"]] == [2] and page["next"] is None
    # an until-less continuation would run on to the new rows
    assert [
        e["n"] for e in ask(client, after=2, generation=first["generation"]).json()["objects"]
    ] == [3, 4]


def test_changes_during_a_walk_land_above_until_and_the_next_walk_has_them(client):
    a, b, c_ = put_all(client, ("a", {}), ("b", {}), ("c", {}))  # n 1..3

    def during(page_no):
        if page_no == 1:
            put_all(client, ("new", {}))  # a new object: n 4
            assert retire(client, b).status_code == 200  # a retire: n 5

    entries, pages = walk(client, limit=1, hook=during)
    assert {p["until"] for p in pages} == {3}
    # the retire of b happened after page 1 returned a: b left the range (n 5 > until 3)
    assert [e["object_id"] for e in entries] == [a["o"]["object_id"], c_["o"]["object_id"]]
    assert all(e["n"] <= 3 for e in entries)
    assert len({e["object_id"] for e in entries}) == len(entries)  # no entry twice
    follow, pages2 = walk(client, after=pages[0]["until"])
    assert [(e["n"], e["state"]) for e in follow] == [(4, "live"), (5, "retired")]
    assert pages2[0]["until"] == 5


def test_an_expiry_sweep_between_pages_lands_above_until_and_the_follow_up_walk_has_it(client):
    put_all(client, ("a", {"expires": NOW + 3_600_000}), ("b", {}))
    first = ask(client, limit=1).json()  # n 1 (a), until 2
    assert [e["state"] for e in first["objects"]] == ["live"]
    d = client.app.state.directory
    d.clock = lambda: NOW + 3_600_000 + 60_000
    sql(client, "UPDATE sessions SET expires_ms=?", NOW + 30 * DAY)
    assert client.app.state.drop.life.run() == {WS}  # the sweep: a gets n 3
    page = ask(client, limit=1, after=1, until=2, generation=first["generation"]).json()
    assert [e["n"] for e in page["objects"]] == [2] and page["next"] is None
    follow = ask(client, after=2, generation=first["generation"]).json()
    assert [(e["n"], e["state"]) for e in follow["objects"]] == [(3, "expired")]


def test_a_version_wrap_or_claim_during_a_walk_also_moves_the_object_out_of_the_range(client):
    o_id = object_id("doc")
    v1, _w1, b1 = upload(o_id, kind="document")
    assert put(client, v1, b1).status_code == 201
    put_all(client, ("x", {}))
    first = ask(client, limit=1).json()  # n 1 is the document; until 2
    v2, _w2, b2 = upload(o_id, kind="document", version=2, parent=v1["o"])
    assert put(client, v2, b2, if_match="1").status_code == 201  # n 3
    page = ask(client, limit=1, after=first["next"], until=2, generation=first["generation"]).json()
    assert [e["n"] for e in page["objects"]] == [2]  # the document moved to n 3: out of this walk
    follow = ask(client, after=2, generation=first["generation"]).json()["objects"]
    assert [(e["n"], e["version"]) for e in follow] == [(3, 2)]


def test_a_walk_cut_by_bytes_and_by_count_at_the_same_until(client, monkeypatch):
    put_all(client, *[(f"o{i}", {}) for i in range(4)])
    monkeypatch.setattr(DR, "LIST_BYTES", 10)  # one entry per page: the byte cut
    entries, pages = walk(client)
    assert [e["n"] for e in entries] == [1, 2, 3, 4] and {p["until"] for p in pages} == {4}
    assert [p["next"] for p in pages] == [1, 2, 3, None]
    monkeypatch.undo()
    entries, pages = walk(client, limit=3)  # the count cut
    assert [e["n"] for e in entries] == [1, 2, 3, 4] and [p["next"] for p in pages] == [3, None]


def test_the_stored_generation_until_pair_makes_the_next_walk_incremental(client):
    put_all(client, ("a", {}), ("b", {}))
    _entries, pages = walk(client)
    stored = (pages[0]["generation"], pages[0]["until"])
    put_all(client, ("c", {}))
    page = ask(client, after=stored[1], generation=stored[0]).json()
    assert [e["n"] for e in page["objects"]] == [3] and page["until"] == 3
    assert ask(client, after=3, generation=stored[0]).json()["objects"] == []


def test_a_tombstone_that_ends_during_a_walk_is_absent_and_raises_no_position(client):
    a, _b = put_all(client, ("a", {}), ("b", {}))
    assert retire(client, a).status_code == 200  # n 3 (a leaves the n 1 slot)
    first = ask(client, limit=1).json()
    assert [e["state"] for e in first["objects"]] == ["live"]  # b at n 2
    before = rows(path_of(client), "drop_counter")[0]["n"]
    client.app.state.directory.clock = lambda: NOW + 31 * DAY  # a's tombstone has ended
    sql(client, "UPDATE sessions SET expires_ms=?", NOW + 60 * DAY)
    page = ask(
        client, limit=1, after=first["next"], until=first["until"], generation=first["generation"]
    ).json()
    assert (page["objects"], page["next"]) == ([], None)  # a's row (n 3, at until) has ended
    assert rows(path_of(client), "drop_counter")[0]["n"] == before


def test_the_a1_state_field_in_a_walk(client):
    a, b, c_ = put_all(
        client,
        ("a", {"expires": NOW + 3_600_000}),
        ("b", {}),
        ("c", {"author": LAPTOP, "recipients": [LAPTOP]}),
    )
    assert retire(client, b).status_code == 200
    client.app.state.directory.clock = lambda: NOW + 3_600_000 + 1
    sql(client, "UPDATE sessions SET expires_ms=?", NOW + 30 * DAY)
    entries, _ = walk(client)
    states = {e["object_id"]: (e["state"], e["descriptor"] is None) for e in entries}
    # `expired` is computed at read time before the sweep; the tombstones carry no descriptor
    assert states == {
        a["o"]["object_id"]: ("expired", True),
        b["o"]["object_id"]: ("retired", True),
        c_["o"]["object_id"]: ("live", False),
    }
    assert client.app.state.drop.life.run() == {WS}
    follow, _ = walk(client, after=4)  # after the retire's n: the sweep's n
    assert [(e["object_id"], e["state"]) for e in follow] == [(a["o"]["object_id"], "expired")]
    again, _ = walk(client, after=follow[0]["n"])
    assert again == []


def test_all_costs_no_more_than_received_and_keeps_the_page_limits(client):
    put_all(client, *[(f"o{i}", {}) for i in range(3)])
    assert ask(client, WS, "all", limit=65).status_code == 400
    assert ask(client, WS, "all", limit=0).status_code == 400
    page = ask(client, WS, "all", limit=64).json()
    assert len(page["objects"]) == 3 and page["next"] is None
