"""Long-poll admission, event-driven wakeups and idle cost (security review finding 2)."""

import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing

import pytest
from bridge_support import CRID, HOST, RID, binary
from directory_support import DEVICE, NOW, PERSON, RECORD, WS, seed
from fastapi.testclient import TestClient

from orch_relay import db
from orch_relay.app import create_app

PROXY = "10.9.9.9"
PAIR = f"/v2/workspaces/{WS}/pair/{CRID}/{RID}"
DEVICE_POLL = f"/v2/workspaces/{WS}/bridge/{RID}"


@pytest.fixture
def client(tmp_path):
    # Requests arrive from the trusted proxy, so X-Forwarded-For selects the client address.
    with TestClient(create_app(tmp_path), client=(PROXY, 50000)) as client:
        seed(client.app.state.directory)
        client.app.state.directory.trusted_proxy = PROXY
        yield client


def sql(client, statement, args=()):
    with closing(db.connect(client.app.state.directory.path)) as con, con:
        return con.execute(statement, args).fetchall()


def post(client, raw, host=False):
    return client.post(
        DEVICE_POLL,
        content=raw,
        headers={
            **(HOST if host else {"Authorization": "Bearer FAKE-device"}),
            "Content-Type": "application/octet-stream",
        },
    )


def wait_admitted(client, count=1):
    deadline = time.monotonic() + 3
    while sum(client.app.state.bridge.polls.values()) < count:
        assert time.monotonic() < deadline, "long polls were not admitted"
        time.sleep(0.01)


def test_pair_poll_admission_uses_canonical_address(client):
    polls = client.app.state.bridge.polls
    polls[("pair", "198.51.100.7")] = 4
    r = client.get(PAIR, params={"wait": 1}, headers={"X-Forwarded-For": "198.51.100.7"})
    assert r.status_code == 429 and r.json() == {"error": "quota_exceeded"}
    assert r.headers["retry-after"]
    assert polls == {("pair", "198.51.100.7"): 4}
    # Another canonical address (not the proxy peer) is admitted independently.
    r = client.get(PAIR, params={"wait": 0}, headers={"X-Forwarded-For": "198.51.100.8"})
    assert r.status_code == 200


def test_pair_poll_pool_ceiling_is_separate(client):
    polls = client.app.state.bridge.polls
    for i in range(128):
        polls[("pair", f"192.0.2.{i}")] = 4
    r = client.get(PAIR, params={"wait": 1}, headers={"X-Forwarded-For": "198.51.100.7"})
    assert r.status_code == 503 and r.json() == {"error": "overloaded"}
    # Authenticated polls still have the remaining shared slots.
    r = client.get(DEVICE_POLL, params={"wait": 0}, headers={"Authorization": "Bearer FAKE-device"})
    assert r.status_code == 200
    polls.clear()


def test_idle_long_poll_does_not_run_write_transactions(client, monkeypatch):
    bridge = client.app.state.bridge
    calls = []
    original = bridge.transaction

    def counted(*args):
        calls.append(args[-1])
        return original(*args)

    monkeypatch.setattr(bridge, "transaction", counted)
    started = time.monotonic()
    r = client.get(DEVICE_POLL, params={"wait": 2}, headers={"Authorization": "Bearer FAKE-device"})
    assert r.status_code == 200 and r.json() == {"chunks": []}
    assert time.monotonic() - started >= 1.9
    # Only the admitting transaction runs; idle checks use read-only snapshots.
    assert calls == [True]


def test_device_poll_wakes_on_response(client):
    assert post(client, binary("bridge_device_post")).status_code == 202
    with ThreadPoolExecutor() as pool:
        pending = pool.submit(
            client.get,
            DEVICE_POLL,
            params={"wait": 10},
            headers={"Authorization": "Bearer FAKE-device"},
        )
        wait_admitted(client)
        time.sleep(0.1)
        posted = time.monotonic()
        assert post(client, binary("bridge_host_post"), True).status_code == 202
        r = pending.result(timeout=5)
        assert time.monotonic() - posted < 0.5
    assert len(r.json()["chunks"]) == 1
    assert client.app.state.bridge.polls == {}


def test_host_poll_wakes_on_request(client):
    with ThreadPoolExecutor() as pool:
        pending = pool.submit(
            client.get, f"/v2/workspaces/{WS}/host/poll", params={"wait": 10}, headers=HOST
        )
        wait_admitted(client)
        time.sleep(0.1)
        posted = time.monotonic()
        assert post(client, binary("bridge_device_post")).status_code == 202
        r = pending.result(timeout=5)
        assert time.monotonic() - posted < 0.5
    assert [item["device"] for item in r.json()["items"]] == [DEVICE]


def test_cert_poll_wakes_on_request(client):
    from bridge_support import OBJECTS
    from directory_support import PRIMARY

    from orch_relay.directory import token_hash

    sql(
        client,
        "INSERT INTO sessions VALUES (?,?,?,?)",
        (token_hash("FAKE-primary"), "device", PRIMARY, NOW + 900000),
    )
    with ThreadPoolExecutor() as pool:
        pending = pool.submit(
            client.get,
            f"/v2/persons/{PERSON}/cert-requests",
            params={"wait": 10},
            headers={"Authorization": "Bearer FAKE-primary"},
        )
        wait_admitted(client)
        time.sleep(0.1)
        posted = time.monotonic()
        r = client.post(
            f"/v2/persons/{PERSON}/cert-requests",
            json={"request": OBJECTS["request"]},
            headers=HOST,
        )
        assert r.status_code == 200
        r = pending.result(timeout=5)
        assert time.monotonic() - posted < 0.5
    assert len(r.json()["requests"]) == 1


def test_device_poll_ends_promptly_on_revocation(client):
    with ThreadPoolExecutor() as pool:
        pending = pool.submit(
            client.get,
            DEVICE_POLL,
            params={"wait": 10},
            headers={"Authorization": "Bearer FAKE-device"},
        )
        wait_admitted(client)
        revoked = time.monotonic()
        assert client.post("/v2/revocations", json={"record": RECORD}).status_code == 200
        assert pending.result(timeout=5).status_code == 401
        assert time.monotonic() - revoked < 0.5
    assert client.app.state.bridge.polls == {}


def test_device_poll_reauthorizes_on_slow_tick(client):
    # Session expiry has no commit to wake on; the slow tick (<= 1 s) re-checks it.
    with ThreadPoolExecutor() as pool:
        pending = pool.submit(
            client.get,
            DEVICE_POLL,
            params={"wait": 10},
            headers={"Authorization": "Bearer FAKE-device"},
        )
        wait_admitted(client)
        time.sleep(0.3)  # let the admitting step finish, so only the tick can notice
        expired = time.monotonic()
        sql(client, "UPDATE sessions SET expires_ms=? WHERE kind='device'", (NOW,))
        assert pending.result(timeout=5).status_code == 401
        assert time.monotonic() - expired < 1.6
    assert client.app.state.bridge.polls == {}


def test_host_poll_fenced_promptly_after_takeover(client):
    with ThreadPoolExecutor() as pool:
        pending = pool.submit(
            client.get, f"/v2/workspaces/{WS}/host/poll", params={"wait": 10}, headers=HOST
        )
        wait_admitted(client)
        took = time.monotonic()
        r = client.post(
            f"/v2/workspaces/{WS}/host/hold", headers=HOST, json={"gen": None, "take_over": True}
        )
        assert r.status_code == 200
        assert pending.result(timeout=5).json() == {"error": "fenced"}
        assert time.monotonic() - took < 0.5


def throughput(client, seconds=1.0):
    count, end = 0, time.perf_counter() + seconds
    while time.perf_counter() < end:
        r = client.get(f"/v2/workspaces/{WS}/card", headers={"Authorization": "Bearer FAKE-device"})
        assert r.status_code == 200
        count += 1
    return count / seconds


@pytest.mark.slow
def test_idle_long_polls_do_not_starve_other_routes(client):
    """Before the event-driven loop, 50 idle pair polls cut this route by about 10x."""
    throughput(client, 0.3)  # warm up
    baseline = throughput(client)
    polls = 200
    with ThreadPoolExecutor(polls) as pool:
        pending = [
            pool.submit(
                client.get,
                PAIR,
                params={"wait": 6},
                headers={"X-Forwarded-For": f"198.51.{i // 4}.{i % 4 + 1}"},
            )
            for i in range(polls)
        ]
        wait_admitted(client, polls)
        loaded = throughput(client, 2.0)
        statuses = [f.result(timeout=15).status_code for f in pending]
    print(
        f"other-route throughput: {baseline:.0f} req/s idle, {loaded:.0f} req/s with {polls} polls"
    )
    assert statuses == [200] * polls
    assert loaded >= baseline / 2


def test_directory_receipt_replays_do_not_wake_polls(client, monkeypatch):
    # Exact receipt replays are unthrottled 200s; they must not fan out to every waiter.
    from directory_support import CERT

    calls = []
    monkeypatch.setattr(client.app.state.directory, "changed", lambda: calls.append(True))
    for _ in range(3):
        assert client.put(f"/v2/devices/{DEVICE}", json={"cert": CERT}).status_code == 200
    assert len(calls) == 1  # only the first PUT stored a receipt
    for _ in range(3):
        assert client.post("/v2/revocations", json={"record": RECORD}).status_code == 200
    assert len(calls) == 2  # only the first revocation changed state


def test_wake_all_fan_outs_are_coalesced(client):
    import asyncio

    from orch_relay.bridge import Bridge

    class Counter:
        sets = 0

        def set(self):
            Counter.sets += 1

    async def burst():
        bridge = Bridge(client.app.state.directory)
        bridge.waiters[("ws", WS)] = {Counter()}
        for _ in range(200):
            bridge.wake_all()
            await asyncio.sleep(0.001)
        await asyncio.sleep(0.3)

    started = time.monotonic()
    asyncio.run(burst())
    elapsed = time.monotonic() - started
    assert 1 <= Counter.sets <= elapsed / 0.25 + 2


def test_pair_poll_ipv6_parent_cap(client):
    bridge = client.app.state.bridge
    bridge.pair_parents["2001:db8:0:100::/56"] = 32
    r = client.get(PAIR, params={"wait": 1}, headers={"X-Forwarded-For": "2001:db8:0:1ab::1"})
    assert r.status_code == 429 and r.json() == {"error": "quota_exceeded"}
    assert bridge.polls == {} and bridge.pair_parents == {"2001:db8:0:100::/56": 32}
    del bridge.pair_parents["2001:db8:0:100::/56"]
    with ThreadPoolExecutor() as pool:
        pending = pool.submit(
            client.get, PAIR, params={"wait": 1}, headers={"X-Forwarded-For": "2001:db8:0:1ab::1"}
        )
        wait_admitted(client)
        assert bridge.pair_parents == {"2001:db8:0:100::/56": 1}
        assert pending.result(timeout=5).status_code == 200
    assert bridge.polls == {} and bridge.pair_parents == {}


def test_anonymous_pair_request_wakes_only_host_polls(client, monkeypatch):
    from bridge_support import request

    woken = []
    monkeypatch.setattr(client.app.state.bridge, "wake", lambda *keys: woken.extend(keys))
    fixture = request("pair_device_post")
    from orch_relay import proto as P

    r = client.post(
        fixture["path"],
        content=P.unb64u(fixture["body_b64u"]),
        headers={**fixture["headers"], "X-Forwarded-For": "198.51.100.7"},
    )
    assert r.status_code == 202, r.text
    assert woken == [("ws", WS)]
