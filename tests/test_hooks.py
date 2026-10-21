"""orch-relay #81: webhook doorbells for follow-ups (design FU11-FU13): the host's register, revoke and
fetch routes, the public `POST /h/<id>`, the expiry sweep. Public FAKE data only."""

import hashlib
import sqlite3
import statistics
import time
from contextlib import closing

import pytest
from directory_support import NOW, WS
from fastapi.testclient import TestClient
from push_support import auth, clear, long_sessions, seed_push

from orch_relay import db, hooks
from orch_relay.app import create_app

HOUR = 3_600_000
DAY = 24 * HOUR
OTHER_WS = "ab" * 16


def hid(n):
    return f"hk_{n:032x}"


def hh(n):
    return hooks.hook_hash(hid(n))


@pytest.fixture
def c(tmp_path, monkeypatch):
    clear(monkeypatch)
    with TestClient(create_app(tmp_path / "data")) as client:
        d = client.app.state.directory
        seed_push(d)
        long_sessions(d)
        client.d, client.h = d, client.app.state.hooks
        yield client


def host(session="FAKE-workspace", holder="1"):
    return auth(session, holder)


def register(c, *ns, expires=NOW + DAY, headers=None, ws=WS):
    body = {"hooks": [{"hook_hash": hh(n), "expires_ms": expires} for n in ns]}
    return c.post(f"/v2/workspaces/{ws}/hooks", json=body, headers=headers or host())


def revoke(c, *ns):
    body = {"hook_hashes": [hh(n) for n in ns]}
    return c.post(f"/v2/workspaces/{WS}/hooks/revoke", json=body, headers=host())


def fetch(c, ack=()):
    return c.post(f"/v2/workspaces/{WS}/hooks/fetch", json={"ack": list(ack)}, headers=host())


def ring(c, n=1, **kw):
    return c.post(f"/h/{hid(n)}", **kw)


def table(d):
    with closing(db.connect(d.path)) as con:
        con.row_factory = sqlite3.Row
        return con.execute(
            "SELECT hook_hash, workspace_id, created_ms, expires_ms, rung_ms FROM hooks "
            "ORDER BY hook_hash"
        ).fetchall()


def test_hash_label_and_migration(c):
    assert hh(1) == hashlib.sha256(b"orch/v2/hook|" + hid(1).encode()).hexdigest()
    assert table(c.d) == []


# --- host routes: auth ----------------------------------------------------------------------


@pytest.mark.parametrize("name", ["hooks", "hooks/revoke", "hooks/fetch"])
def test_host_routes_need_the_workspace_session_and_the_fence(c, name):
    url = f"/v2/workspaces/{WS}/{name}"
    body = {"hooks": [], "hook_hashes": [], "ack": []}
    key = {"hooks": "hooks", "hooks/revoke": "hook_hashes", "hooks/fetch": "ack"}[name]
    body = {key: [{"hook_hash": hh(1), "expires_ms": NOW + HOUR}] if key == "hooks" else [hh(1)]}
    assert c.post(url, json=body, headers={"Content-Type": "application/json"}).status_code == 401
    r = c.post(url, json=body, headers=host("FAKE-device"))
    assert (r.status_code, r.json()["error"]) == (403, "not_eligible")  # a device is not the host
    assert c.post(url, json=body, headers=host(holder=None)).json()["error"] == "fenced"
    assert c.post(url, json=body, headers=host(holder="2")).json()["error"] == "fenced"
    r = c.post(f"/v2/workspaces/{OTHER_WS}/{name}", json=body, headers=host())
    assert (r.status_code, r.json()["error"]) == (403, "not_eligible")  # another workspace
    assert table(c.d) == []


def test_host_routes_reject_bad_shapes(c):
    url = f"/v2/workspaces/{WS}/hooks"
    for body in (
        {},
        {"hooks": []},
        {"hooks": "x"},
        {"hooks": [{"hook_hash": "zz", "expires_ms": NOW + HOUR}]},
        {"hooks": [{"hook_hash": hh(1)}]},
        {"hooks": [{"hook_hash": hh(1), "expires_ms": "soon"}]},
        {"hooks": [{"hook_hash": hh(1), "expires_ms": NOW + HOUR, "x": 1}]},
        {"hooks": [{"hook_hash": hh(1), "expires_ms": NOW + HOUR}], "x": 1},
        {"hooks": [{"hook_hash": hh(i), "expires_ms": NOW + HOUR} for i in range(65)]},
    ):
        r = c.post(url, json=body, headers=host())
        assert (r.status_code, r.json()["error"]) == (400, "malformed"), body
    r = c.post(url, content=b"{}", headers={**host(), "Content-Type": "text/plain"})
    assert r.status_code == 400
    assert c.post(url + "?x=1", json={}, headers=host()).status_code == 400
    big = c.post(url, content=b" " * (hooks.REQUEST_CAP + 1), headers=host())
    assert (big.status_code, big.json()["error"]) == (413, "too_large")
    assert table(c.d) == []


# --- register / revoke / fetch ----------------------------------------------------------------


def test_register_stores_only_the_hash_and_expiry(c):
    r = register(c, 1, 2)
    assert (r.status_code, r.json()) == (200, {"registered": 2})
    rows = table(c.d)
    assert [tuple(x) for x in rows] == sorted((hh(n), WS, NOW, NOW + DAY, None) for n in (1, 2))
    with closing(db.connect(c.d.path)) as con:
        dump = "\n".join(con.iterdump())
    assert hid(1) not in dump and hid(2) not in dump


def test_register_lifetime_bounds(c):
    for expires in (NOW, NOW - 1, NOW + hooks.MAX_LIFE_MS + 1):
        assert register(c, 1, expires=expires).json()["error"] == "malformed"
    assert register(c, 1, expires=NOW + hooks.MAX_LIFE_MS).status_code == 200
    assert len(table(c.d)) == 1


def test_register_is_idempotent_and_keeps_a_ring(c):
    register(c, 1)
    ring(c)
    c.h.drain()
    assert register(c, 1, expires=NOW + 2 * DAY).status_code == 200
    (row,) = table(c.d)
    assert (row["expires_ms"], row["rung_ms"]) == (NOW + 2 * DAY, NOW)


def test_a_hash_held_by_another_workspace_is_not_taken_and_not_revealed(c):
    with closing(db.connect(c.d.path)) as con, con:
        con.execute("INSERT INTO hooks VALUES (?,?,?,?,NULL)", (hh(1), OTHER_WS, NOW, NOW + DAY))
    mine, theirs = register(c, 2), register(c, 1)
    assert (theirs.status_code, theirs.json()) == (mine.status_code, mine.json())  # no oracle
    revoke(c, 1)  # another workspace's hook is not ours to revoke or change
    rows = {r["hook_hash"]: r["workspace_id"] for r in table(c.d)}
    assert rows == {hh(1): OTHER_WS, hh(2): WS}
    assert table(c.d)[0]["expires_ms"] == NOW + DAY


def test_register_caps_256_per_workspace(c):
    for start in range(0, 256, 64):
        assert register(c, *range(start, start + 64)).status_code == 200
    r = register(c, 999)
    assert (r.status_code, r.json()["error"]) == (429, "quota_exceeded")
    assert register(c, 5).status_code == 200  # a retry of a held hook is not a new row
    revoke(c, 0)
    assert register(c, 999).status_code == 200
    assert len(table(c.d)) == 256


def test_register_makes_room_from_expired_hooks(c):
    register(c, 1, expires=NOW + HOUR)
    c.d.clock = lambda: NOW + 2 * HOUR
    long_sessions(c.d)
    assert register(c, 2, expires=NOW + 3 * HOUR).status_code == 200
    assert [r["hook_hash"] for r in table(c.d)] == [hh(2)]


def test_revoke_and_fetch_flow(c):
    register(c, 1, 2)
    assert ring(c, 1).status_code == 204
    c.h.drain()
    assert fetch(c).json() == {"rings": [{"hook_hash": hh(1), "rung_ms": NOW}]}
    assert fetch(c).json()["rings"], "a fetch alone does not clear the ring"
    assert fetch(c, [hh(1)]).json() == {"rings": []}
    ring(c, 1)
    c.h.drain()  # the hook is still registered: a new first ring after the ack
    assert len(fetch(c).json()["rings"]) == 1
    assert revoke(c, 1, 2, 3).json() == {"revoked": 2}
    assert table(c.d) == [] and fetch(c).json() == {"rings": []}
    assert ring(c, 1).status_code == 204
    c.h.drain()
    assert table(c.d) == []


def test_fetch_hides_expired_rings_and_is_per_workspace(c):
    register(c, 1, expires=NOW + HOUR)
    with closing(db.connect(c.d.path)) as con, con:
        con.execute("INSERT INTO hooks VALUES (?,?,?,?,?)", (hh(7), OTHER_WS, NOW, NOW + DAY, NOW))
    ring(c, 1)
    c.h.drain()
    assert [r["hook_hash"] for r in fetch(c).json()["rings"]] == [hh(1)]
    c.d.clock = lambda: NOW + 2 * HOUR
    long_sessions(c.d)
    assert fetch(c).json() == {"rings": []}


# --- the public doorbell ----------------------------------------------------------------------


def answer(r):
    return (r.status_code, r.content, sorted(r.headers.items()))


def test_the_answer_is_constant_for_every_id_and_state(c):
    register(c, 1, 2, expires=NOW + HOUR)
    revoke(c, 2)
    answers = {
        "known": ring(c, 1),
        "unknown": ring(c, 3),
        "revoked": ring(c, 2),
        "garbage": c.post("/h/not-an-id"),
        "long": c.post("/h/" + "x" * 5000),
        "unicode": c.post("/h/%F0%9F%94%94"),
        "body": ring(c, 1, content=b"x" * 1000, headers={"Content-Type": "application/json"}),
        "query": c.post(f"/h/{hid(1)}?a=b"),
    }
    first = answer(answers["known"])
    assert first[:2] == (204, b"")
    for name, r in answers.items():
        a = answer(r)
        assert a[:2] == first[:2], name
        # headers differ only by the request-specific Date, never by id or state
        assert {k: v for k, v in a[2] if k != "date"} == {k: v for k, v in first[2] if k != "date"}
    c.d.clock = lambda: NOW + 2 * HOUR  # expired
    assert answer(ring(c, 1))[:2] == (204, b"")


def test_only_get_is_not_a_doorbell(c):
    assert c.get(f"/h/{hid(1)}").status_code == 405
    assert c.put(f"/h/{hid(1)}").status_code == 405


def test_first_ring_is_recorded_once_and_no_body_is_kept(c):
    register(c, 1)
    secret = b"TOP-SECRET-PAYLOAD-" + b"A" * 200
    sig = {"X-Hub-Signature-256": "sha256=deadbeef", "Content-Type": "application/json"}
    ring(c, content=secret, headers=sig)
    c.h.drain()
    (row,) = table(c.d)
    assert row["rung_ms"] == NOW
    c.d.clock = lambda: NOW + 5000
    ring(c, content=b"later", headers=sig)
    c.h.drain()
    assert table(c.d)[0]["rung_ms"] == NOW  # later rings change nothing
    with closing(db.connect(c.d.path)) as con:
        dump = "\n".join(con.iterdump())
    assert "TOP-SECRET" not in dump and "deadbeef" not in dump


def test_a_ring_queued_before_registration_does_not_ring_it(c, monkeypatch):
    monkeypatch.setattr(c.h, "drain", lambda: 0)
    ring(c)  # before anyone registered this id
    c.d.clock = lambda: NOW + 1000
    register(c, 1)
    type(c.h).drain(c.h)
    assert table(c.d)[0]["rung_ms"] is None
    ring(c, 1)
    type(c.h).drain(c.h)
    assert table(c.d)[0]["rung_ms"] == NOW + 1000  # a ring made after registration does


def test_expired_hooks_do_not_ring(c):
    register(c, 1, expires=NOW + HOUR)
    c.d.clock = lambda: NOW + HOUR
    ring(c)
    c.h.drain()
    assert table(c.d)[0]["rung_ms"] is None


def test_oversized_declared_body_is_refused_unread_for_any_id(c):
    register(c, 1)
    big = {"Content-Length": str(hooks.RING_BODY_CAP + 1)}
    for n in (1, 2):  # known and unknown: the same 413, from the header alone
        r = c.post(f"/h/{hid(n)}", content=b"x" * (hooks.RING_BODY_CAP + 1), headers=big)
        assert (r.status_code, r.content) == (413, b"")
    c.h.drain()
    assert table(c.d)[0]["rung_ms"] is None  # an oversized ring does not ring
    r = c.post(f"/h/{hid(1)}", content=b"x" * hooks.RING_BODY_CAP)
    assert r.status_code == 204


def test_oversized_chunked_body_is_refused_for_any_id(c):
    register(c, 1)

    def chunks(n):
        yield b"x" * n

    for n in (1, 2):
        r = c.post(f"/h/{hid(n)}", content=chunks(hooks.RING_BODY_CAP + 1))
        assert (r.status_code, r.content) == (413, b"")
    assert c.post(f"/h/{hid(1)}", content=chunks(hooks.RING_BODY_CAP)).status_code == 204


def test_the_handler_never_touches_the_database(c, monkeypatch):
    register(c, 1)

    def boom(*a, **k):
        raise AssertionError("database access in the doorbell")

    monkeypatch.setattr(c.h, "drain", lambda: 0)  # the background task is not the handler
    monkeypatch.setattr(c.d, "connection", boom)
    monkeypatch.setattr(c.d, "reader", boom)
    for n in (1, 2):
        assert ring(c, n).status_code == 204


def test_per_address_limit_is_429_whatever_the_id(c):
    burst = hooks.LIMITS["hook-ip"][0]
    codes = [c.post(f"/h/{hid(1000 + n)}").status_code for n in range(burst + 3)]
    assert codes[:burst] == [204] * burst and codes[burst:] == [429] * 3
    r = c.post(f"/h/{hid(1)}")
    assert r.status_code == 429 and r.headers["retry-after"]


def test_the_address_is_the_canonical_one(c, monkeypatch):
    seen = []
    monkeypatch.setattr(c.d, "client_address", lambda peer, headers: seen.append(peer) or "x")
    ring(c)
    assert seen == ["testclient"]


def test_per_hook_limit_drops_silently(c, monkeypatch):
    monkeypatch.setattr(c.h, "drain", lambda: 0)  # keep the queue to look at
    register(c, 1)
    burst = hooks.LIMITS["hook"][0]
    for _ in range(burst + 5):
        assert ring(c).status_code == 204
    assert len(c.h.queue) == burst  # the rest never reached the queue, still 204


def test_per_workspace_limit_drops_silently(c, monkeypatch):
    monkeypatch.setitem(hooks.LIMITS, "hook-ws", (2, 1))
    register(c, 1, 2, 3, 4)
    for n in (1, 2, 3, 4):
        assert ring(c, n).status_code == 204
    c.h.drain()
    assert sum(r["rung_ms"] is not None for r in table(c.d)) == 2


def test_queue_is_bounded(c, monkeypatch):
    monkeypatch.setattr(c.h, "drain", lambda: 0)
    monkeypatch.setattr(hooks, "QUEUE_MAX", 3)
    monkeypatch.setitem(hooks.LIMITS, "hook-ip", (10**6, 10**6))
    for n in range(10):
        assert ring(c, n).status_code == 204
    assert len(c.h.queue) == 3 and c.h.dropped == 7


def test_sweep_deletes_expired_hooks_and_their_rings(c):
    register(c, 1, expires=NOW + HOUR)
    register(c, 2, expires=NOW + DAY)
    ring(c, 1)
    c.h.drain()
    assert c.h.sweep(NOW + HOUR) == 1
    assert [r["hook_hash"] for r in table(c.d)] == [hh(2)]
    assert c.h.sweep(NOW + HOUR) == 0


def test_background_task_records_rings(c):
    register(c, 1)
    ring(c)
    deadline = time.time() + 5
    while time.time() < deadline and table(c.d)[0]["rung_ms"] is None:
        time.sleep(0.05)
    assert table(c.d)[0]["rung_ms"] == NOW


@pytest.mark.slow
def test_timing_parity_between_known_and_unknown_ids(c, monkeypatch):
    for name in ("hook-ip", "hook", "hook-ws"):
        monkeypatch.setitem(hooks.LIMITS, name, (10**9, 10**9))
    known = list(range(1, 201))
    for start in range(0, 200, 64):
        register(c, *known[start : start + 64])
    ids = {"known": known, "unknown": list(range(10_001, 10_201))}
    samples = {"known": [], "unknown": []}
    for _round in range(3):
        for i in range(200):
            for kind in ("known", "unknown"):  # interleaved: drift hits both alike
                n = ids[kind][i]
                t = time.perf_counter()
                r = c.post(f"/h/{hid(n)}")
                samples[kind].append(time.perf_counter() - t)
                assert r.status_code == 204
        c.h.drain()
        with closing(db.connect(c.d.path)) as con, con:
            con.execute("UPDATE hooks SET rung_ms=NULL")
    a, b = (statistics.median(samples[k]) for k in ("known", "unknown"))
    # both paths do identical work in the handler; allow 25 % + 0.2 ms of scheduling noise
    assert abs(a - b) <= 0.25 * max(a, b) + 0.0002, (a, b)
    p = lambda xs: sorted(xs)[int(0.9 * len(xs))]
    assert (
        abs(p(samples["known"]) - p(samples["unknown"]))
        <= 0.5 * max(p(samples["known"]), p(samples["unknown"])) + 0.001
    )
