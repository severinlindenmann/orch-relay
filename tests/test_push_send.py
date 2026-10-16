"""P3-D40b: the host's send route (protocol §19.10, P3 design §14.3 items 4-7), against a fake APNs."""

import hashlib
import json
from contextlib import closing

import pytest
from directory_support import DEVICE, NOW, PERSON, WS
from drop_support import LAPTOP
from fake_apns import FakeApns, wait_for
from fastapi.testclient import TestClient
from push_support import (
    BOB,
    KID,
    TEAM,
    TOKEN_A,
    TOKEN_B,
    TOKEN_C,
    TOPIC,
    auth,
    clear,
    configure,
    long_sessions,
    outer,
    push_env,
    register,
    rid,
    rows,
    seed_push,
    send,
)

from orch_relay import db
from orch_relay import proto as P
from orch_relay import push_send as PS
from orch_relay.apns import apns_body
from orch_relay.app import create_app

PHONE, LAP = DEVICE, LAPTOP
PEOPLE = sorted([PHONE, LAP])


def body_for(o):
    """The APNs body, spelled out from §19.10 (not by the code under test)."""
    inner = P.cj(o).decode()
    return (
        '{"aps":{"alert":{"title":"orch","body":"New activity in orch"},"mutable-content":1},'
        '"o":' + json.dumps(inner) + "}"
    ).encode()


@pytest.fixture
def c(tmp_path, monkeypatch):
    keys = configure(monkeypatch, tmp_path)
    with TestClient(create_app(tmp_path / "data")) as client:
        d = client.app.state.directory
        seed_push(d)
        push = client.app.state.push
        client.d, client.push, client.keys = d, push, keys
        client.fake = FakeApns(keys, TEAM, TOPIC, KID)
        push.apns.transport = client.fake
        push.apns.retry_delays = (0, 0)
        push.sender.rate_per_s = 10_000
        assert register(client, TOKEN_A, 1).status_code == 200  # phone, sandbox
        assert (
            register(client, TOKEN_B, 2, session="FAKE-laptop", env="production").status_code == 200
        )
        yield client
    assert client.fake.errors == []


def sent(c, n, seconds=5.0):
    assert wait_for(lambda: len(c.fake.requests) >= n, seconds), len(c.fake.requests)
    return c.fake.requests


def quiet(c):
    """Let the pump finish what is queued (nothing more is expected)."""
    assert wait_for(lambda: c.push.outbox.queued() == 0 and not c.push.sender.active.total())


def pause(c, env="sandbox"):
    c.push.apns.states[env].paused_until_s = 1e18  # sends stay queued


# --- the exact APNs request ----------------------------------------------------------------------


def test_the_apns_request_is_exact(c):
    o = outer(7)
    r = send(c, [PHONE], o, priority="high", ttl_s=100)
    assert (r.status_code, r.json()) == (200, {"accepted": 1})
    (req,) = sent(c, 1)
    assert req.env == "sandbox" and req.path == "/3/device/" + TOKEN_A.hex()
    assert req.headers == {
        "authorization": "bearer " + req.jwt,
        "apns-topic": TOPIC,
        "apns-push-type": "alert",
        "apns-priority": "10",
        "apns-expiration": str(NOW // 1000 + 100),
    }
    assert req.body == body_for(o)
    assert json.loads(req.body)["o"] == P.cj(o).decode()


@pytest.mark.parametrize(
    ("priority", "ttl", "prio", "exp"),
    [
        ("high", 0, "10", "0"),
        ("normal", 0, "5", "0"),
        ("normal", 86400, "5", str(NOW // 1000 + 86400)),
    ],
)
def test_priority_and_expiration(c, priority, ttl, prio, exp):
    send(c, [PHONE], outer(), priority=priority, ttl_s=ttl)
    (req,) = sent(c, 1)
    assert (req.headers["apns-priority"], req.headers["apns-expiration"]) == (prio, exp)


def test_the_largest_outer_makes_a_3175_byte_body(c):
    o = outer(3)
    base = len(P.cj(o)) - len(o["c"])
    o["c"] = "A" * (3072 - base)
    assert len(P.cj(o)) == 3072
    assert P.b64u(P.unb64u(o["c"])) == o["c"]  # canonical
    send(c, [PHONE], o)
    (req,) = sent(c, 1)
    assert len(req.body) == 3175 and req.body == body_for(o)
    o2 = dict(o, c="A" * (3073 - base))  # one byte more: refused
    assert send(c, [PHONE], o2).status_code == 400


def test_the_environment_picks_the_key_and_the_gateway(c):
    send(c, [PHONE, LAP] if PHONE < LAP else [LAP, PHONE])
    reqs = sent(c, 2)
    assert {r.env: r.token_hex for r in reqs} == {
        "sandbox": TOKEN_A.hex(),
        "production": TOKEN_B.hex(),
    }
    # each JWT verifies under its own environment's key only (FakeApns checked that), and differs
    assert len({r.jwt for r in reqs}) == 2


def test_one_key_for_both_environments_signs_one_jwt(tmp_path, monkeypatch):
    clear(monkeypatch)
    keys = configure(monkeypatch, tmp_path, same_key=True)
    with TestClient(create_app(tmp_path / "data")) as client:
        d = client.app.state.directory
        seed_push(d)
        push = client.app.state.push
        fake = FakeApns(
            keys, TEAM, TOPIC, {"sandbox": KID["sandbox"], "production": KID["sandbox"]}
        )
        push.apns.transport, push.apns.retry_delays = fake, (0, 0)
        register(client, TOKEN_A, 1)
        register(client, TOKEN_B, 2, env="production")
        assert send(client, [PHONE]).json() == {"accepted": 1}
        assert wait_for(lambda: len(fake.requests) == 2)
        assert {r.env for r in fake.requests} == {"sandbox", "production"}
        assert fake.requests[0].jwt == fake.requests[1].jwt  # one token per key
        assert push.apns.jwt.signed == 1
    assert fake.errors == []


def test_the_jwt_is_cached_and_renewed_after_40_minutes(c):
    for n in range(3):
        send(c, [PHONE], outer(n))
    sent(c, 3)
    assert len({r.jwt for r in c.fake.requests}) == 1 and c.push.apns.jwt.signed == 1
    long_sessions(c.d)
    c.d.clock = lambda: NOW + 39 * 60_000
    send(c, [PHONE], outer(10))
    sent(c, 4)
    assert c.push.apns.jwt.signed == 1
    c.d.clock = lambda: NOW + 40 * 60_000
    send(c, [PHONE], outer(11))
    sent(c, 5)
    assert c.push.apns.jwt.signed == 2 and c.fake.requests[-1].jwt != c.fake.requests[0].jwt


# --- targets and accepted ------------------------------------------------------------------------


def test_accepted_counts_targets_not_registrations(c):
    register(c, TOKEN_C, 3, env="production")  # a second registration for the phone
    r = send(c, sorted([PHONE, LAP, BOB, "00" * 16]))
    assert r.json() == {"accepted": 2}  # bob and the unknown id are skipped silently
    sent(c, 3)
    quiet(c)
    assert len(c.fake.requests) == 3
    # a member with no registration is accepted, nothing is sent for it
    with closing(db.connect(c.d.path)) as con, con:
        con.execute("DELETE FROM push_subscriptions WHERE device_id=?", (LAP,))
    c.fake.requests.clear()
    assert send(c, PEOPLE, outer(2)).json() == {"accepted": 2}
    sent(c, 2)
    quiet(c)
    assert {r.token_hex for r in c.fake.requests} == {TOKEN_A.hex(), TOKEN_C.hex()}


def test_revoked_expired_and_removed_devices_are_skipped(c):
    with closing(db.connect(c.d.path)) as con, con:
        con.execute("UPDATE devices SET expires_ms=? WHERE device_id=?", (NOW, LAP))
    assert send(c, PEOPLE).json() == {"accepted": 1}
    sent(c, 1)
    with closing(db.connect(c.d.path)) as con, con:
        con.execute(
            "INSERT INTO revocations VALUES (?,?,?,?,?,?)", (PHONE, PERSON, b"x", "lost", NOW, 1)
        )
    assert send(c, PEOPLE, outer(2)).json() == {"accepted": 0}
    with closing(db.connect(c.d.path)) as con, con:
        con.execute("DELETE FROM members WHERE device_id=?", (PHONE,))
    quiet(c)
    assert len(c.fake.requests) == 1


# --- checks and refusals -------------------------------------------------------------------------


@pytest.mark.parametrize(
    "patch",
    [
        {"targets": []},
        {"targets": [PHONE, PHONE]},
        {"targets": sorted([PHONE, LAP], reverse=True)},
        {"targets": ["zz"]},
        {"targets": [PHONE.upper()]},
        {"targets": "x"},
        {"targets": [f"{i:032x}" for i in range(1025)]},
        {"priority": "low"},
        {"priority": None},
        {"ttl_s": -1},
        {"ttl_s": 86401},
        {"ttl_s": True},
        {"ttl_s": "5"},
        {"ttl_s": 1.5},
        {"extra": 1},
        {"outer": []},
        {"outer": dict(outer(), extra=1)},
        {"outer": {k: v for k, v in outer().items() if k != "c"}},
        {"outer": dict(outer(), v=1)},
        {"outer": dict(outer(), v=True)},
        {"outer": dict(outer(), ws="ab" * 16)},
        {"outer": dict(outer(), epoch="1")},
        {"outer": dict(outer(), epoch=-1)},
        {"outer": dict(outer(), epoch=2**32)},
        {"outer": dict(outer(), c="AA==")},  # not canonical
        {"outer": dict(outer(), c="")},
        {"outer": dict(outer(), c="A" * 4000)},  # over 3,072
    ],
)
def test_malformed_requests(c, patch):
    r = send(c, patch.pop("targets", [PHONE]), **patch)
    assert (r.status_code, r.json()) == (400, {"error": "malformed"})
    assert c.push.outbox.queued() == 0 and c.push.outbox.lru == {}


def test_a_body_missing_a_field_and_the_path_must_be_a_workspace(c):
    r = c.post(
        f"/v2/workspaces/{WS}/push", json={"targets": [PHONE]}, headers=auth("FAKE-workspace", "1")
    )
    assert r.status_code == 400
    r = c.post("/v2/workspaces/zz/push", json={}, headers=auth("FAKE-workspace", "1"))
    assert r.status_code == 400
    r = c.post(f"/v2/workspaces/{WS}/push?x=1", json={}, headers=auth("FAKE-workspace", "1"))
    assert r.status_code == 400
    r = c.post(
        f"/v2/workspaces/{WS}/push",
        content=b" " * (64 * 1024 + 1),
        headers=auth("FAKE-workspace", "1"),
    )
    assert (r.status_code, r.json()) == (413, {"error": "too_large"})


def test_the_outer_must_name_this_workspace(c):
    o = outer(ws="cd" * 16)
    assert send(c, [PHONE], o).status_code == 400


def test_stale_epoch_names_the_current_one(c):
    r = send(c, [PHONE], outer(epoch=2))
    assert (r.status_code, r.json()) == (409, {"error": "stale_epoch", "epoch": 1})
    r = send(c, [PHONE], outer(epoch=0))
    assert r.json() == {"error": "stale_epoch", "epoch": 1}
    assert c.push.outbox.queued() == 0 and c.push.outbox.lru == {}


def test_who_may_send(c):
    assert send(c, [PHONE], session="nope").status_code == 401
    assert (
        c.post(
            f"/v2/workspaces/{WS}/push", json={}, headers={"Content-Type": "application/json"}
        ).status_code
        == 401
    )
    for session in ("FAKE-device", "FAKE-laptop", "FAKE-agent"):  # a member device cannot send
        r = send(c, [PHONE], session=session)
        assert (r.status_code, r.json()) == (403, {"error": "not_eligible"}), session
    other = "cd" * 16
    assert send(c, [PHONE], ws=other).status_code == 403  # the W session of another workspace
    assert c.push.outbox.queued() == 0


def test_a_missing_or_stale_holder_is_fenced_before_any_effect(c):
    for holder in (None, "0", "2", "x"):
        r = send(c, [PHONE], holder=holder)
        assert r.status_code in (409, 400), holder
        if holder in (None, "0", "2"):
            assert r.json() == {"error": "fenced"}
    with closing(db.connect(c.d.path)) as con, con:  # an expired lease
        con.execute("UPDATE holders SET lease_until_ms=?", (NOW,))
    assert send(c, [PHONE]).json() == {"error": "fenced"}
    # nothing was charged or remembered: budgets untouched, LRU empty, nothing queued
    assert c.push.outbox.queued() == 0 and c.push.outbox.lru == {}
    assert not [k for k in c.push.outbox.buckets.table if k[0].startswith("push-")]


def test_the_fence_is_checked_again_at_the_effect(c, monkeypatch):
    real = PS.parse_send

    def takeover(raw, ws):
        out = real(raw, ws)
        with closing(db.connect(c.d.path)) as con, con:  # a takeover after admission
            con.execute("UPDATE holders SET gen=2")
        return out

    monkeypatch.setattr(PS, "parse_send", takeover)
    r = send(c, [PHONE])
    assert (r.status_code, r.json()) == (409, {"error": "fenced"})
    assert c.push.outbox.queued() == 0 and c.push.outbox.lru == {}
    assert not [k for k in c.push.outbox.buckets.table if k[0].startswith("push-")]
    assert c.fake.requests == []


# --- idempotency (the dedup LRU) -----------------------------------------------------------------


def test_an_exact_retry_sends_nothing_again(c):
    o = outer(5)
    assert send(c, [PHONE], o).json() == {"accepted": 1}
    sent(c, 1)
    assert send(c, [PHONE], o).json() == {"accepted": 1}  # still accepted, nothing sent
    quiet(c)
    assert len(c.fake.requests) == 1
    send(c, [PHONE], outer(6))  # another outer is another push
    sent(c, 2)
    # the key is (ws, outer, device): another device still receives the retry
    send(c, [LAP], o)
    sent(c, 3)
    assert c.fake.requests[-1].env == "production"


def test_the_lru_forgets_after_24_hours_and_is_bounded(c, monkeypatch):
    long_sessions(c.d)
    o = outer(5)
    send(c, [PHONE], o)
    sent(c, 1)
    c.d.clock = lambda: NOW + 24 * 3_600_000 - 1
    send(c, [PHONE], o)
    quiet(c)
    assert len(c.fake.requests) == 1
    c.d.clock = lambda: NOW + 24 * 3_600_000
    send(c, [PHONE], o)
    sent(c, 2)
    monkeypatch.setattr(PS, "LRU_ENTRIES", 3)
    for n in range(10, 16):
        send(c, [PHONE], outer(n))
    quiet(c)
    assert len(c.push.outbox.lru) == 3


def test_a_skipped_push_is_not_remembered(c):
    pause(c)
    c.push.outbox.caps = (0, 0, 0)  # a full queue
    r = send(c, [PHONE], outer(9))
    assert r.status_code == 503
    assert c.push.outbox.lru == {}
    c.push.outbox.caps = (PS.QUEUE_TOTAL, PS.QUEUE_WORKSPACE, PS.QUEUE_ACCOUNT)
    assert send(c, [PHONE], outer(9)).json() == {"accepted": 1}  # the same outer now goes out
    assert c.push.outbox.queued("sandbox") == 1


# --- budgets (item 7) ----------------------------------------------------------------------------


def test_per_workspace_device_budget_20_burst_2_per_minute_ignoring_priority(c):
    long_sessions(c.d)
    for n in range(25):
        assert send(c, [PHONE], outer(n), priority="high" if n % 2 else "normal").json() == {
            "accepted": 1
        }
    quiet(c)
    assert len(c.fake.requests) == 20  # the rest are skipped, still accepted
    c.d.clock = lambda: NOW + 30_000  # 30 s: one token back
    send(c, [PHONE], outer(100), priority="normal")
    send(c, [PHONE], outer(101), priority="high")
    quiet(c)
    assert len(c.fake.requests) == 21
    c.d.clock = lambda: NOW + 90_000  # two more tokens back (two per minute)
    for n in range(102, 106):
        send(c, [PHONE], outer(n))
    quiet(c)
    assert len(c.fake.requests) == 23


def test_the_per_workspace_request_budget_is_a_429(tmp_path, monkeypatch):
    clear(monkeypatch)
    keys = configure(monkeypatch, tmp_path)
    monkeypatch.setenv("ORCH_RELAY_THROTTLE_PUSH_WS", "3/60")  # the override form
    with TestClient(create_app(tmp_path / "data")) as client:
        seed_push(client.app.state.directory)
        client.app.state.push.apns.transport = FakeApns(keys, TEAM, TOPIC, KID)
        register(client, TOKEN_A, 1)
        for n in range(3):
            assert send(client, [PHONE], outer(n)).status_code == 200
        r = send(client, [PHONE], outer(9))
        assert (r.status_code, r.json()) == (429, {"error": "rate_limited"})
        assert int(r.headers["Retry-After"]) >= 1
        client.app.state.directory.clock = lambda: NOW + 1000  # 60 per minute: one token per second
        assert send(client, [PHONE], outer(9)).status_code == 200


def test_throttle_defaults_and_overrides():
    assert PS.THROTTLES == {"push-ws-device": (20, 2), "push-device": (60, 6), "push-ws": (120, 20)}
    got = PS.throttle_settings({"ORCH_RELAY_THROTTLE_PUSH_DEVICE": "7/5"})
    assert got["push-device"] == (7, 5) and got["push-ws"] == (120, 20)
    with pytest.raises(ValueError):
        PS.throttle_settings({"ORCH_RELAY_THROTTLE_PUSH_WS": "0/5"})


# --- queue admission (item 6) --------------------------------------------------------------------


def test_queue_is_all_or_nothing_with_retry_after(c):
    pause(c, "sandbox")
    pause(c, "production")
    c.push.outbox.caps = (1, 1000, 1000)  # room for one send; this request needs two
    r = send(c, PEOPLE)
    assert r.status_code == 503 and r.json() == {"error": "overloaded"}
    assert int(r.headers["Retry-After"]) >= 1
    assert c.push.outbox.queued() == 0
    assert c.push.outbox.lru == {}  # nothing remembered ...
    assert not [
        k for k in c.push.outbox.buckets.table if k[0].startswith("push-")
    ]  # ... or charged
    assert send(c, [PHONE]).json() == {"accepted": 1}
    assert c.push.outbox.queued() == 1 and c.push.outbox.total == 1


def test_per_workspace_and_per_account_caps(c):
    pause(c, "sandbox")
    pause(c, "production")
    c.push.outbox.caps = (100, 1, 100)
    assert send(c, [PHONE], outer(1)).status_code == 200
    assert send(c, [PHONE], outer(2)).status_code == 503  # 1 per workspace
    c.push.outbox.caps = (100, 100, 1)
    assert send(c, [PHONE], outer(3)).status_code == 503  # 1 per owner account
    c.push.outbox.caps = (100, 100, 100)
    assert send(c, [PHONE], outer(3)).status_code == 200
    assert c.push.outbox.per_account == {PERSON: 2} and c.push.outbox.per_ws == {WS: 2}


def test_outbox_caps_across_workspaces_and_accounts():
    box = PS.Outbox(("sandbox",), PS.THROTTLES, 1000)

    def sends(ws, account, device, n):
        return [
            PS.Send(f"{i:032x}", b"", b"", "sandbox", ws, account, device, b"", 10, 0, 10**12)
            for i in range(n)
        ]

    assert PS.QUEUE_TOTAL == 4096 and PS.QUEUE_WORKSPACE == 1024 and PS.QUEUE_ACCOUNT == 2048
    h = b"h" * 32
    for k in range(8):  # one account's workspaces: 2 x 1024 reach the account cap
        ws = f"{k:032x}"
        if k < 2:
            assert (
                len(box.commit(ws, "A", h, [(f"d{k}", sends(ws, "A", f"d{k}", 1024))], 0)) == 1024
            )
        else:
            with pytest.raises(Exception) as caught:
                box.commit(ws, "A", h, [(f"d{k}", sends(ws, "A", f"d{k}", 1))], 0)
            assert caught.value.status == 503
    # another account still has the rest of the instance queue: 4096 - 2048 = 2048
    for k in range(10, 12):
        ws = f"{k:032x}"
        assert len(box.commit(ws, "B", h, [(f"e{k}", sends(ws, "B", f"e{k}", 1024))], 0)) == 1024
    assert box.total == 4096
    with pytest.raises(Exception) as caught:
        box.commit("f" * 32, "C", h, [("g", sends("f" * 32, "C", "g", 1))], 0)
    assert caught.value.status == 503
    # over one workspace's 1,024 in a single request
    box2 = PS.Outbox(("sandbox",), PS.THROTTLES, 1000)
    with pytest.raises(Exception) as caught:
        box2.commit("a" * 32, "A", h, [("d", sends("a" * 32, "A", "d", 1025))], 0)
    assert caught.value.status == 503 and box2.total == 0 and box2.lru == {}


def test_per_device_budget_across_workspaces():
    box = PS.Outbox(("sandbox",), PS.THROTTLES, 1000)
    one = lambda ws, n: PS.Send(
        f"{n:032x}", b"", b"", "sandbox", ws, "A", "dev", b"", 10, 0, 10**12
    )
    queued = 0
    for n in range(80):  # many workspaces, one device: 60 burst
        ws = f"{n:032x}"
        queued += len(box.commit(ws, "A", bytes([n]) * 32, [("dev", [one(ws, n)])], 0))
    assert queued == 60
    queued = len(box.commit("f" * 32, "A", b"z" * 32, [("dev", [one("f" * 32, 99)])], 10 * 60_000))
    assert queued == 1  # 6 per minute refill: 10 minutes give the burst's worth back


def test_waiting_longer_than_the_ttl_drops_the_send(c):
    pause(c)
    send(c, [PHONE], outer(1), ttl_s=30)
    assert c.push.outbox.queued() == 1
    c.d.clock = lambda: NOW + 30_001
    c.push.outbox.expire("sandbox", c.d.clock())
    assert c.push.outbox.queued() == 0 and c.push.outbox.total == 0
    assert c.fake.requests == []
    # ttl 0 still waits 5 s; and no wait ever exceeds 600 s
    c.d.clock = lambda: NOW
    send(c, [PHONE], outer(2), ttl_s=0)
    send(c, [PHONE], outer(3), ttl_s=86400)
    deadlines = sorted(s.deadline_ms for s in c.push.outbox.queues["sandbox"])
    assert deadlines == [NOW + 5_000, NOW + 600_000]


# --- the answer table (item 6) -------------------------------------------------------------------


def settle(c, n):
    sent(c, n)
    quiet(c)


def test_200_is_done(c):
    send(c, [PHONE])
    settle(c, 1)
    assert c.push.sender.results[-1][1:] == ("ok", 200)
    assert len(rows(c.d)) == 2


def test_410_deletes_registrations_not_refreshed_after_apples_timestamp(c):
    register(c, TOKEN_A, 4, env="production")  # the same token string in the other environment
    assert len(rows(c.d, "token_mac=?", (c.push.token_mac(TOKEN_A),))) == 2
    # Apple's stamp is before the last refresh: the registrations stay
    c.fake.reply((410, {"reason": "Unregistered", "timestamp": NOW - 1}))
    send(c, [PHONE])
    settle(c, 2)
    assert len(rows(c.d, "token_mac=?", (c.push.token_mac(TOKEN_A),))) == 2
    c.fake.reply((410, {"reason": "Unregistered", "timestamp": NOW}))  # last_seen is not after it
    send(c, [PHONE], outer(2))
    settle(c, 4)
    assert rows(c.d, "token_mac=?", (c.push.token_mac(TOKEN_A),)) == []
    assert [r["device_id"] for r in rows(c.d)] == [LAP]  # other tokens are untouched


def test_410_spares_a_registration_refreshed_after_the_stamp(c):
    c.d.clock = lambda: NOW + 5000
    long_sessions(c.d)
    assert register(c, TOKEN_A, 1).status_code == 200  # the app re-registered: last_seen NOW+5000
    c.fake.reply((410, {"reason": "Unregistered", "timestamp": NOW + 4999}))
    send(c, [PHONE])
    settle(c, 1)
    assert len(rows(c.d, "registration_id=?", (rid(1),))) == 1


@pytest.mark.parametrize("reason", ["BadDeviceToken", "DeviceTokenNotForTopic"])
def test_400_bad_token_deletes_the_token_in_that_environment(c, reason):
    register(c, TOKEN_A, 4, env="production")  # the same token string in the other environment
    c.fake.reply((400, {"reason": reason}))
    send(c, [PHONE])
    settle(c, 2)
    left = {(r["registration_id"], r["env"]) for r in rows(c.d)}
    assert (rid(1), "sandbox") not in left and (rid(4), "production") in left


def test_403_renews_once_and_retries_once(c):
    c.fake.reply((403, {"reason": "ExpiredProviderToken"}))
    send(c, [PHONE])
    settle(c, 2)
    first, second = c.fake.requests
    assert first.jwt != second.jwt and c.push.apns.jwt.signed == 2
    assert c.push.sender.results[-1][1] == "ok"
    assert not c.push.apns.paused("sandbox", NOW / 1000)


def test_403_twice_pauses_queues_meanwhile_and_recovers(c, caplog):
    caplog.set_level("DEBUG")
    long_sessions(c.d)
    clock = [NOW]
    c.d.clock = lambda: clock[0]
    c.fake.reply(
        (403, {"reason": "InvalidProviderToken"}), (403, {"reason": "InvalidProviderToken"})
    )
    send(c, [PHONE], outer(1))
    assert wait_for(lambda: c.push.apns.paused("sandbox", clock[0] / 1000))
    assert len(c.fake.requests) == 2  # the first send and its one retry; then the send is dropped
    state = c.push.apns.states["sandbox"]
    assert state.paused_until_s == NOW / 1000 + 1200 and state.backoff_s == 2400
    assert "apns_auth" in "\n".join(r.getMessage() for r in caplog.records)
    # while paused, a send is queued, not sent; it waits at most 600 s and is then dropped
    send(c, [PHONE], outer(2))
    assert c.push.outbox.queued("sandbox") == 1
    clock[0] = NOW + 599_000
    c.push.sender.notify()
    assert not wait_for(lambda: len(c.fake.requests) > 2, 0.2)
    assert c.push.outbox.queued("sandbox") == 1
    clock[0] = NOW + 601_000
    c.push.sender.notify()
    assert wait_for(lambda: c.push.outbox.queued("sandbox") == 0)
    assert c.push.outbox.total == 0 and not c.push.outbox.per_ws
    assert len(c.fake.requests) == 2
    # the pause ends: the first send renews the JWT, is delivered, and the backoff resets
    clock[0] = NOW + 1_199_999
    send(c, [PHONE], outer(3))
    assert not wait_for(lambda: len(c.fake.requests) > 2, 0.2)
    clock[0] = NOW + 1_200_000
    jwt_before = c.fake.requests[-1].jwt
    c.push.sender.notify()
    sent(c, 3)
    assert c.fake.requests[-1].jwt != jwt_before and c.push.apns.jwt.signed == 3
    assert wait_for(lambda: c.push.sender.results[-1][1] == "ok")
    assert state.backoff_s == 1200 and not state.renew_next


def test_the_backoff_doubles_to_two_hours_and_a_success_resets_it():
    import asyncio
    import tempfile
    from pathlib import Path

    from fake_apns import FakeApns as Fake

    from orch_relay.apns import Apns
    from orch_relay.push_config import load

    with tempfile.TemporaryDirectory(dir="/tmp") as tmp:
        env, keys = push_env(Path(tmp), envs=("sandbox",))
        config = load(env)
        fake = Fake(keys, TEAM, TOPIC, KID)
        clock = [1_790_000_000.0]
        apns = Apns(config, transport=fake, clock_s=lambda: clock[0], retry_delays=())
        send_ = PS.Send(
            rid(1), b"", b"", "sandbox", WS, "A", PHONE, apns_body(P.cj(outer())), 10, 0, 10**15
        )
        send_.token = TOKEN_A
        fake.default = (403, {"reason": "ExpiredProviderToken"})
        waits = []

        async def run():
            for _ in range(6):
                result = await apns.deliver(send_)
                assert result.kind == "auth_paused"
                waits.append(apns.states["sandbox"].paused_until_s - clock[0])
                clock[0] = apns.states["sandbox"].paused_until_s  # the pause ends
                assert not apns.paused("sandbox", clock[0])
            fake.default = (200, None)
            assert (await apns.deliver(send_)).kind == "ok"

        asyncio.run(run())
        assert waits == [1200, 2400, 4800, 7200, 7200, 7200]
        assert apns.states["sandbox"].backoff_s == 1200  # recovered
        assert fake.errors == []


def test_403_pause_logs_apns_auth_without_secrets_and_other_envs_continue(c, caplog):
    caplog.set_level("DEBUG")
    c.fake.reply(
        (403, {"reason": "InvalidProviderToken"}), (403, {"reason": "InvalidProviderToken"})
    )
    send(c, [PHONE])
    assert wait_for(lambda: c.push.apns.paused("sandbox", NOW / 1000))
    assert not c.push.apns.paused("production", NOW / 1000)
    send(c, [LAP], outer(2))  # production still delivers
    assert wait_for(lambda: any(r.env == "production" for r in c.fake.requests))
    text = "\n".join(r.getMessage() for r in caplog.records)
    assert "apns_auth" in text and rid(1)[:8] in text
    assert rid(1) not in text  # only the first 8 digits
    assert_no_secrets(c, text)


@pytest.mark.parametrize("reason", ["TopicDisallowed", "BadTopic"])
def test_400_topic_errors_pause_the_environment_with_the_same_backoff(c, reason, caplog):
    caplog.set_level("DEBUG")
    c.fake.reply((400, {"reason": reason}))
    send(c, [PHONE])
    assert wait_for(lambda: c.push.apns.paused("sandbox", NOW / 1000))
    assert c.push.apns.states["sandbox"].paused_until_s == NOW / 1000 + 1200
    assert c.push.apns.states["sandbox"].backoff_s == 2400
    assert reason in "\n".join(r.getMessage() for r in caplog.records)
    assert len(rows(c.d)) == 2  # the registration stays


def test_429_and_413_drop_the_send_and_keep_the_registration(c, caplog):
    caplog.set_level("DEBUG")
    c.fake.reply((429, {"reason": "TooManyRequests"}), (413, {"reason": "PayloadTooLarge"}))
    send(c, [PHONE], outer(1))
    settle(c, 1)
    send(c, [PHONE], outer(2))
    settle(c, 2)
    assert [r[1:] for r in c.push.sender.results] == [("dropped", 429), ("dropped", 413)]
    assert len(rows(c.d)) == 2 and len(c.fake.requests) == 2  # no retry
    assert "PayloadTooLarge" in "\n".join(r.getMessage() for r in caplog.records)
    assert not c.push.apns.paused("sandbox", NOW / 1000)


@pytest.mark.parametrize("failure", [(500, None), (503, None), "connection"])
def test_5xx_and_connection_errors_retry_at_most_twice(c, failure):
    from fake_apns import refuse_connection

    bad = refuse_connection() if failure == "connection" else failure
    c.fake.reply(bad, bad, (200, None))
    send(c, [PHONE], outer(1))
    settle(c, 3)
    assert c.push.sender.results[-1][1] == "ok" and len(c.fake.requests) == 3
    c.fake.reply(bad, bad, bad, (200, None))
    send(c, [PHONE], outer(2))
    settle(c, 6)
    assert c.push.sender.results[-1][1] == "failed" and len(c.fake.requests) == 6
    c.fake.script.clear()


def test_retries_stop_at_the_sends_deadline(c):
    long_sessions(c.d)
    clock = [NOW]
    c.d.clock = lambda: clock[0]
    c.push.apns.retry_delays = (400, 400)  # seconds
    slept = []

    async def fake_sleep(seconds):
        slept.append(seconds)
        clock[0] += int(seconds * 1000)

    c.push.apns.sleep = fake_sleep
    c.fake.reply((503, None), (503, None), (503, None))
    send(c, [PHONE], outer(1), ttl_s=1)  # ttl 1 s leaves no room for a 400 s retry
    settle(c, 1)
    assert slept == [] and c.push.sender.results[-1][1] == "failed"
    c.fake.reply((503, None), (503, None), (503, None))
    send(c, [PHONE], outer(2), ttl_s=600)
    assert wait_for(lambda: len(c.push.sender.results) == 2)
    assert slept == [400]  # the second retry would end past the 600 s deadline
    assert len(c.fake.requests) == 3


def test_unknown_answers_are_dropped(c):
    c.fake.reply((418, {"reason": "Teapot"}))
    send(c, [PHONE])
    settle(c, 1)
    assert c.push.sender.results[-1][1:] == ("dropped", 418)


def test_sends_run_at_most_16_streams_per_environment(c):
    import asyncio

    live = {"now": 0, "max": 0}
    gate = {}

    async def slow_post(env, path, headers, body):
        gate.setdefault("event", asyncio.Event())
        live["now"] += 1
        live["max"] = max(live["max"], live["now"])
        await gate["event"].wait()
        live["now"] -= 1
        return 200, b""

    c.fake.post = slow_post
    ws, h = WS, b"h" * 32
    targets = [
        (
            f"{n:032x}",
            [
                PS.Send(
                    rid(1000 + n),
                    c.push.seal(rid(1000 + n), TOKEN_A),
                    b"m",
                    "sandbox",
                    ws,
                    "A",
                    f"{n:032x}",
                    apns_body(P.cj(outer())),
                    10,
                    0,
                    NOW + 600_000,
                )
            ],
        )
        for n in range(40)
    ]
    assert len(c.push.outbox.commit(ws, "A", h, targets, NOW)) == 40
    c.push.sender.notify()
    assert wait_for(lambda: live["now"] == 16)
    assert not wait_for(lambda: live["now"] > 16, 0.3)
    assert c.push.outbox.queued("sandbox") == 24  # the rest wait in the queue
    c.push.sender.loop.call_soon_threadsafe(gate["event"].set)
    assert wait_for(lambda: c.push.outbox.queued() == 0 and live["now"] == 0)
    assert live["max"] == 16


# --- hygiene -------------------------------------------------------------------------------------


def assert_no_secrets(c, text):
    cfg = c.push.config
    forbidden = [TOKEN_A.hex(), TOKEN_B.hex(), TOKEN_C.hex(), cfg.k_tok.hex(), cfg.k_mac.hex()]
    forbidden += [r.jwt for r in c.fake.requests] + [r.jwt.split(".")[2] for r in c.fake.requests]
    forbidden += [str(c.push.apns.jwt.tokens)]
    for secret in forbidden:
        assert secret not in text, secret[:12]
    assert "BEGIN" not in text and "PRIVATE" not in text
    for needle in ("aps", "mutable-content", "outer", "AAAA"):
        assert needle not in text  # no payload content


def test_no_token_jwt_key_or_payload_in_logs_through_a_full_session(c, caplog):
    caplog.set_level("DEBUG")
    register(c, TOKEN_C, 9, env="production")
    c.fake.reply(
        (403, {"reason": "ExpiredProviderToken"}),
        (200, None),
        (400, {"reason": "BadDeviceToken"}),
        (410, {"reason": "Unregistered", "timestamp": NOW + 5}),
        (500, None),
        (200, None),
        (429, None),
    )
    for n in range(4):
        send(c, [PHONE, LAP], outer(n), priority="normal")
    quiet(c)
    unregister_all = c.post(
        "/v2/push/unregister",
        json={"workspace_id": WS, "registration_id": None},
        headers=auth("FAKE-device"),
    )
    assert unregister_all.status_code == 200
    text = "\n".join(f"{r.name} {r.getMessage()}" for r in caplog.records)
    text += "\n".join(str(r.args) + str(r.exc_text) for r in caplog.records)
    assert_no_secrets(c, text)
    hashed = hashlib.sha256(P.cj(outer(0))).hexdigest()
    assert hashed not in text


def test_a_failed_registration_row_is_unreadable_without_the_secret(c):
    (row,) = rows(c.d, "registration_id=?", (rid(1),))
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    from orch_relay.push_config import derive

    wrong, _ = derive(bytes(32))
    with pytest.raises(InvalidTag):
        AESGCM(wrong).decrypt(
            bytes(row["token_sealed"][:12]),
            bytes(row["token_sealed"][12:]),
            b"orch-relay/push-token|" + rid(1).encode(),
        )
