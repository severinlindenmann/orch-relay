"""Long-poll admission, event-driven wakeups and idle cost (security review finding 2)."""

import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing

import pytest
from bridge_support import CRID, HOST, RID, binary
from directory_support import DEVICE, NOW, PERSON, PRIMARY, RECORD, WS, seed
from fastapi.testclient import TestClient

from orch_relay import db
from orch_relay import proto as P
from orch_relay.app import create_app
from orch_relay.directory import token_hash

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
        # Every finished poll unregisters its wakeups (an unbounded map would grow fan-outs).
        assert client.app.state.bridge.waiters == {}


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

    probes = []
    probe = bridge.probe

    def counted_probe(*args):
        probes.append(True)
        return probe(*args)

    monkeypatch.setattr(bridge, "transaction", counted)
    monkeypatch.setattr(bridge, "probe", counted_probe)
    started = time.monotonic()
    r = client.get(DEVICE_POLL, params={"wait": 2}, headers={"Authorization": "Bearer FAKE-device"})
    assert r.status_code == 200 and r.json() == {"chunks": []}
    assert time.monotonic() - started >= 1.9
    # Only the admitting step: idle checks and the deadline check are read-only.
    assert calls == [True]
    assert len(probes) <= 3


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


def device_poll_pending(pool, client, wait=10):
    future = pool.submit(
        client.get,
        DEVICE_POLL,
        params={"wait": wait},
        headers={"Authorization": "Bearer FAKE-device"},
    )
    wait_admitted(client)
    time.sleep(0.3)  # let the admitting step finish, so only a wakeup can notice
    return future


def test_device_poll_ends_at_session_expiry(client):
    # Session expiry has no commit to wake on; the poll's expiry timer re-checks it.
    d = client.app.state.directory
    started = time.monotonic()
    d.clock = lambda: NOW + int((time.monotonic() - started) * 1000)
    sql(client, "UPDATE sessions SET expires_ms=? WHERE kind='device'", (NOW + 1000,))
    with ThreadPoolExecutor() as pool:
        pending = device_poll_pending(pool, client)
        assert pending.result(timeout=5).status_code == 401
        assert 0.9 <= time.monotonic() - started < 1.6


def test_device_poll_ends_promptly_on_logout(client):
    with ThreadPoolExecutor() as pool:
        pending = device_poll_pending(pool, client)
        out = time.monotonic()
        r = client.post(
            "/v2/session/logout", json={}, headers={"Authorization": "Bearer FAKE-device"}
        )
        assert r.status_code == 200
        assert pending.result(timeout=5).status_code == 401
        assert time.monotonic() - out < 0.5


def test_device_poll_rechecks_membership_on_wake(client):
    bridge = client.app.state.bridge
    with ThreadPoolExecutor() as pool:
        pending = device_poll_pending(pool, client)
        sql(client, "DELETE FROM members WHERE device_id=?", (DEVICE,))
        removed = time.monotonic()
        client.portal.call(bridge.wake, ("members", WS))
        assert pending.result(timeout=5).status_code == 403
        assert time.monotonic() - removed < 0.5


def test_timed_out_poll_reauthorizes_at_deadline(client):
    with ThreadPoolExecutor() as pool:
        pending = device_poll_pending(pool, client, wait=1)
        sql(client, "UPDATE sessions SET expires_ms=? WHERE kind='device'", (NOW,))
        assert pending.result(timeout=5).status_code == 401


@pytest.mark.slow
def test_device_poll_reauthorizes_on_slow_tick(client):
    # An out-of-band change with no wakeup and no known expiry is seen within the tick.
    with ThreadPoolExecutor() as pool:
        pending = device_poll_pending(pool, client, wait=20)
        expired = time.monotonic()
        sql(client, "UPDATE sessions SET expires_ms=? WHERE kind='device'", (NOW,))
        assert pending.result(timeout=15).status_code == 401
        assert 4.5 <= time.monotonic() - expired < 7.6


def host_poll(client, wait):
    return client.get(f"/v2/workspaces/{WS}/host/poll", params={"wait": wait}, headers=HOST)


def test_host_poll_waits_despite_past_revocation(client):
    sql(
        client,
        "INSERT INTO revocations VALUES (?,?,?,?,?,?)",
        (DEVICE, PERSON, P.cj(RECORD), "lost", NOW, 1),
    )
    # The first response delivers the durable notice to this holder generation.
    started = time.monotonic()
    assert host_poll(client, 2).json()["notices"]["revocations_cursor"] == 1
    assert time.monotonic() - started < 0.5
    started = time.monotonic()
    r = host_poll(client, 2)
    assert time.monotonic() - started >= 1.9
    assert r.json()["items"] == [] and r.json()["notices"]["revocations_cursor"] == 1
    # A new holder generation gets the current notices once again.
    client.post(
        f"/v2/workspaces/{WS}/host/hold", headers=HOST, json={"gen": None, "take_over": True}
    )
    gen2 = {**HOST, "Orch-Holder": "2"}
    started = time.monotonic()
    r = client.get(f"/v2/workspaces/{WS}/host/poll", params={"wait": 2}, headers=gen2)
    assert r.json()["notices"]["revocations_cursor"] == 1
    assert time.monotonic() - started < 0.5


def test_host_poll_wakes_on_new_revocation(client):
    assert host_poll(client, 0).status_code == 200
    with ThreadPoolExecutor() as pool:
        pending = pool.submit(host_poll, client, 10)
        wait_admitted(client)
        time.sleep(0.3)
        revoked = time.monotonic()
        assert client.post("/v2/revocations", json={"record": RECORD}).status_code == 200
        r = pending.result(timeout=5)
        assert time.monotonic() - revoked < 0.5
    notices = r.json()["notices"]
    assert notices["revocations_cursor"] == 1
    assert [row["device_id"] for row in notices["rotation_due"]] == [DEVICE]


def test_host_poll_returns_undelivered_notice_change_at_once(client):
    assert host_poll(client, 0).status_code == 200
    sql(client, "INSERT INTO rotation_due VALUES (?,?,?,?)", (WS, DEVICE, 1, 1))
    started = time.monotonic()
    r = host_poll(client, 5)
    assert time.monotonic() - started < 0.5
    assert r.json()["notices"]["rotation_due"] == [
        {"device_id": DEVICE, "revocation_cursor": 1, "epoch": 1}
    ]
    started = time.monotonic()
    assert host_poll(client, 1).json()["items"] == []
    assert time.monotonic() - started >= 0.9


def test_timed_out_host_poll_rebuilds_notices(client):
    with ThreadPoolExecutor() as pool:
        pending = pool.submit(host_poll, client, 1)
        wait_admitted(client)
        time.sleep(0.3)
        # No wakeup: the deadline must rebuild rather than return the first step's result.
        sql(client, "INSERT INTO rotation_due VALUES (?,?,?,?)", (WS, DEVICE, 1, 1))
        r = pending.result(timeout=5)
    assert r.json()["notices"]["rotation_due"] == [
        {"device_id": DEVICE, "revocation_cursor": 1, "epoch": 1}
    ]


def test_host_poll_wakes_on_cert_challenge(client):
    from bridge_support import OBJECTS

    sql(
        client,
        "INSERT INTO sessions VALUES (?,?,?,?)",
        (token_hash("FAKE-primary"), "device", PRIMARY, NOW + 900000),
    )
    r = client.post(
        f"/v2/persons/{PERSON}/cert-requests", json={"request": OBJECTS["request"]}, headers=HOST
    )
    assert r.status_code == 200
    assert host_poll(client, 0).json()["notices"]["cert_requests"] == []
    with ThreadPoolExecutor() as pool:
        pending = pool.submit(host_poll, client, 10)
        wait_admitted(client)
        time.sleep(0.3)
        challenged = time.monotonic()
        r = client.post(
            f"/v2/cert-requests/{CRID}/challenge",
            json={"challenge": OBJECTS["challenge"]},
            headers={"Authorization": "Bearer FAKE-primary"},
        )
        assert r.status_code == 200
        r = pending.result(timeout=5)
        assert time.monotonic() - challenged < 0.5
    assert r.json()["notices"]["cert_requests"] == [CRID]


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
                f"/v2/workspaces/{WS}/pair/{CRID}/{i:032x}",  # <= 16 waiters per rid
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


def test_directory_wakes_only_affected_polls_and_only_on_change(client, monkeypatch):
    # Exact receipt replays are unthrottled 200s; they must not wake anything.
    from directory_support import CERT

    calls = []
    monkeypatch.setattr(client.app.state.directory, "changed", lambda *keys: calls.append(keys))
    for _ in range(3):
        assert client.put(f"/v2/devices/{DEVICE}", json={"cert": CERT}).status_code == 200
    assert calls == [(("subject", DEVICE),)]  # only the first PUT stored a receipt
    for _ in range(3):
        assert client.post("/v2/revocations", json={"record": RECORD}).status_code == 200
    # The revoked device's polls and the hosts of workspaces it was ever in.
    assert calls[1:] == [(("subject", DEVICE), ("ws", WS))]


@pytest.mark.parametrize(
    "groups,address",
    [
        ({"198.51.100.0/24": 32}, "198.51.100.77"),
        ({"2001:db8:0:100::/56": 32}, "2001:db8:0:1ab::1"),
        ({"2001:db8::/48": 64}, "2001:db8:0:1ab::1"),
    ],
)
def test_pair_poll_allocation_caps(client, groups, address):
    bridge = client.app.state.bridge
    bridge.pair_groups.update(groups)
    r = client.get(PAIR, params={"wait": 1}, headers={"X-Forwarded-For": address})
    assert r.status_code == 429 and r.json() == {"error": "quota_exceeded"}
    assert bridge.polls == {} and bridge.pair_groups == groups
    bridge.pair_groups.clear()
    with ThreadPoolExecutor() as pool:
        pending = pool.submit(
            client.get, PAIR, params={"wait": 1}, headers={"X-Forwarded-For": address}
        )
        wait_admitted(client)
        expected = (
            {"198.51.100.0/24": 1}
            if "." in address
            else {"2001:db8:0:100::/56": 1, "2001:db8::/48": 1}
        )
        assert bridge.pair_groups == expected
        assert pending.result(timeout=5).status_code == 200
    assert bridge.polls == {} and bridge.pair_groups == {}


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


def test_identical_resends_and_replays_wake_nobody(client, monkeypatch):
    woken = []
    monkeypatch.setattr(client.app.state.bridge, "wake", lambda *keys: woken.append(keys))
    for _ in range(3):
        assert post(client, binary("bridge_device_post")).status_code == 202
    for _ in range(3):
        assert post(client, binary("bridge_host_post"), True).status_code == 202
    assert woken == [(("ws", WS),), (("rid", WS, RID, DEVICE),)]


def test_waiting_pair_polls_per_rid_are_capped(client):
    # Device polls on a rid are bounded by the per-device cap (they wait on own keys).
    bridge = client.app.state.bridge
    key = ("pair", WS, CRID, RID)
    crowd = {object() for _ in range(16)}
    bridge.waiters[key] = crowd
    r = client.get(PAIR, params={"wait": 1}, headers={"X-Forwarded-For": "198.51.100.7"})
    assert r.status_code == 429 and r.json() == {"error": "quota_exceeded"}
    assert bridge.polls == {} and bridge.waiters == {key: crowd}
    bridge.waiters.clear()


async def raw_get(app, path, query, headers):
    """A bare ASGI GET returning the status. Waiting clients must cost (almost) nothing
    on the shared event loop, or the test measures httpx rather than the relay."""
    import asyncio

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": query.encode(),
        "root_path": "",
        "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
        "client": (PROXY, 50000),
        "server": ("relay", 80),
    }
    sent, status = [False], []

    async def receive():
        if not sent[0]:
            sent[0] = True
            return {"type": "http.request", "body": b"", "more_body": False}
        await asyncio.Event().wait()  # never disconnects

    async def send(message):
        if message["type"] == "http.response.start":
            status.append(message["status"])

    await app(scope, receive, send)
    return status[0]


@pytest.mark.slow
def test_long_poll_ceiling_does_not_starve_other_routes(tmp_path, monkeypatch):
    """4,096 waiting device polls (the real POLL_CEILING) in one process and event loop.

    One seeded device stands in for 683 devices (the per-device cap of 6 is lifted); each
    poll still authenticates on every check. Before the event-loop probes, expiry timers
    and the jittered tick, this setup cut the other route from ~118 to ~2 req/s.
    """
    import asyncio

    import httpx

    from orch_relay import bridge as B

    monkeypatch.setattr(B, "DEVICE_POLLS", B.POLL_CEILING)
    app = create_app(tmp_path)
    db.migrate(app.state.data_dir / db.DB_NAME)
    seed(app.state.directory)
    polls = B.POLL_CEILING

    async def run():
        transport = httpx.ASGITransport(app=app, client=(PROXY, 50000))
        async with httpx.AsyncClient(
            transport=transport, base_url="http://relay", timeout=120
        ) as c:

            async def throughput(seconds):
                count, end = 0, time.perf_counter() + seconds
                while time.perf_counter() < end:
                    r = await c.get(
                        f"/v2/workspaces/{WS}/card", headers={"Authorization": "Bearer FAKE-device"}
                    )
                    assert r.status_code == 200
                    count += 1
                return count / seconds

            await throughput(0.3)
            baseline = await throughput(2)
            tasks = [
                asyncio.create_task(
                    raw_get(
                        app,
                        f"/v2/workspaces/{WS}/bridge/{i:032x}",
                        "wait=25",
                        {"Authorization": "Bearer FAKE-device"},
                    )
                )
                for i in range(polls)
            ]
            deadline = time.monotonic() + 90
            while sum(app.state.bridge.polls.values()) < polls:
                assert time.monotonic() < deadline, "polls were not admitted"
                await asyncio.sleep(0.05)
            await asyncio.sleep(1)  # let every admitting step finish
            loaded = await throughput(8)  # spans more than one jittered tick (5-7 s)
            assert not any(task.done() for task in tasks)
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            return baseline, loaded

    try:
        baseline, loaded = asyncio.run(run())
    finally:
        app.state.bridge.close()
    print(f"other route: {baseline:.0f} req/s idle, {loaded:.0f} req/s with {polls} waiting polls")
    assert app.state.bridge.polls == {} and app.state.bridge.waiters == {}
    assert loaded >= baseline / 2


@pytest.mark.slow
def test_long_poll_ceiling_deadline_does_not_stall_other_routes(tmp_path, monkeypatch):
    """4,096 device polls admitted together also time out together.

    Each timed-out device poll answers from a cheap event-loop check; a write transaction
    per poll at the deadline stalled the other route for seconds (re-review D1).
    """
    import asyncio

    import httpx

    from orch_relay import bridge as B

    monkeypatch.setattr(B, "DEVICE_POLLS", B.POLL_CEILING)
    app = create_app(tmp_path)
    db.migrate(app.state.data_dir / db.DB_NAME)
    seed(app.state.directory)
    polls, wait = B.POLL_CEILING, 25  # the longest wait leaves room for admission
    bridge = app.state.bridge
    first_steps = []
    original = bridge.transaction

    def counted(*args):
        result = original(*args)
        first_steps.append(args[-1])
        return result

    monkeypatch.setattr(bridge, "transaction", counted)

    async def run():
        transport = httpx.ASGITransport(app=app, client=(PROXY, 50000))
        async with httpx.AsyncClient(
            transport=transport, base_url="http://relay", timeout=120
        ) as c:

            async def card():
                started = time.perf_counter()
                r = await c.get(
                    f"/v2/workspaces/{WS}/card", headers={"Authorization": "Bearer FAKE-device"}
                )
                assert r.status_code == 200
                done.append(time.perf_counter())
                return done[-1] - started

            done, timeouts = [], []

            for _ in range(20):
                await card()
            started = time.perf_counter()
            idle = [await card() for _ in range(200)]
            baseline = len(idle) / (time.perf_counter() - started)
            tasks = [
                asyncio.create_task(
                    raw_get(
                        app,
                        f"/v2/workspaces/{WS}/bridge/{i:032x}",
                        f"wait={wait}",
                        {"Authorization": "Bearer FAKE-device"},
                    )
                )
                for i in range(polls)
            ]
            for task in tasks:
                task.add_done_callback(lambda _task: timeouts.append(time.perf_counter()))
            admitted = time.monotonic()
            while first_steps.count(True) < polls:  # past the admission herd of first steps
                assert time.monotonic() < admitted + 60, "polls were not admitted"
                await asyncio.sleep(0.05)
            await asyncio.sleep(0.5)
            assert not any(task.done() for task in tasks), "admission outlasted the wait"
            latencies = []
            end = time.monotonic() + 60
            while not all(task.done() for task in tasks):  # spans every deadline
                assert time.monotonic() < end, "polls did not time out"
                latencies.append(await card())
            for _ in range(50):
                latencies.append(await card())
            # Throughput only while the polls time out (+-0.5 s), not the idle wait before.
            start, stop = min(timeouts) - 0.5, max(timeouts) + 0.5
            loaded = sum(start <= t <= stop for t in done) / (stop - start)
            statuses = {task.result() for task in tasks}
            # Device polls must not add deadline write transactions.
            assert first_steps.count(False) == 0
            return baseline, loaded, max(latencies), statuses

    try:
        baseline, loaded, worst, statuses = asyncio.run(run())
    finally:
        app.state.bridge.close()
    print(
        f"other route: {baseline:.0f} req/s idle, {loaded:.0f} req/s across {polls} poll "
        f"deadlines (worst single request {worst:.2f} s)"
    )
    assert statuses == {200}
    assert app.state.bridge.polls == {} and app.state.bridge.waiters == {}
    # Deterministic pin above (no deadline write transactions); this bound only catches
    # gross stalls, since this laptop's shared CPU makes short windows swing about 5x.
    assert loaded >= baseline / 10


def test_membership_publish_wakes_that_workspace(tmp_path):
    from members_support import BODY, HEADERS, load_state

    with TestClient(create_app(tmp_path)) as c:
        load_state(c.app.state.directory)
        calls = []
        c.app.state.directory.changed = lambda *keys: calls.append(keys)
        r = c.put(f"/v2/workspaces/{WS}/membership", content=P.cj(BODY), headers=HEADERS)
        assert r.status_code == 200, r.text
        assert calls == [(("ws", WS), ("members", WS))]


def test_deadline_rebuild_reauthorizes_without_a_prior_check(client, monkeypatch):
    # The admitting step outlasts the wait, so no read-only check runs before the
    # deadline; the deadline step itself must re-authorize.
    bridge = client.app.state.bridge
    original = bridge.transaction

    def slow_first(*args):
        result = original(*args)
        if args[-1]:
            sql(client, "UPDATE sessions SET expires_ms=? WHERE kind='device'", (NOW,))
            time.sleep(1.2)
        return result

    monkeypatch.setattr(bridge, "transaction", slow_first)
    r = client.get(DEVICE_POLL, params={"wait": 1}, headers={"Authorization": "Bearer FAKE-device"})
    assert r.status_code == 401


@pytest.mark.parametrize(
    "path,headers,status",
    [
        # A member device of another workspace (no membership here).
        (f"/v2/workspaces/{'ab' * 16}/bridge/{RID}", {"Authorization": "Bearer FAKE-device"}, 403),
        # A host with a stale holder generation.
        (f"/v2/workspaces/{WS}/host/poll", {**HOST, "Orch-Holder": "7"}, 409),
        # Someone else's cert queue.
        (f"/v2/persons/{'cd' * 16}/cert-requests", {"Authorization": "Bearer FAKE-device"}, 403),
        # An anonymous pair poll on an unknown workspace.
        (f"/v2/workspaces/{'ab' * 16}/pair/{CRID}/{RID}", {}, 401),
    ],
)
def test_unauthorized_wait_takes_no_slot_or_waiter(client, monkeypatch, path, headers, status):
    bridge = client.app.state.bridge
    admitted = []
    monkeypatch.setattr(bridge, "admit", lambda key: admitted.append(key))
    r = client.get(path, params={"wait": 1}, headers=headers)
    assert r.status_code == status
    assert admitted == [] and bridge.polls == {} and bridge.waiters == {}


def test_responses_wake_only_the_target_devices_polls(client, monkeypatch):
    # A co-member polling the same rid reads none of these chunks, so it is not woken.
    bridge = client.app.state.bridge
    sql(client, "INSERT INTO members VALUES (?,?,?,?)", (WS, PRIMARY, PERSON, P.cj(["look"])))
    sql(
        client,
        "INSERT INTO sessions VALUES (?,?,?,?)",
        (token_hash("FAKE-primary"), "device", PRIMARY, NOW + 900000),
    )
    assert post(client, binary("bridge_device_post")).status_code == 202
    probed = []
    probe = bridge.probe
    monkeypatch.setattr(bridge, "probe", lambda *args: probed.append(args[3]) or probe(*args))
    with ThreadPoolExecutor() as pool:
        other = pool.submit(
            client.get,
            DEVICE_POLL,
            params={"wait": 2},
            headers={"Authorization": "Bearer FAKE-primary"},
        )
        wait_admitted(client)
        time.sleep(0.3)
        assert post(client, binary("bridge_host_post"), True).status_code == 202
        time.sleep(0.3)
        assert probed == []
        assert other.result(timeout=5).json() == {"chunks": []}


def test_host_pair_answers_not_blocked_by_anonymous_pair_windows(client):
    from bridge_support import request, seen

    d = client.app.state.directory
    with closing(db.connect(d.path)) as con, con:
        seen(con, binary("pair_device_post"))
    # Anonymous traffic has exhausted the workspace and global pair-post windows.
    d.windows[("pair-POST", WS, 60000)] = (NOW + 60000, 60)
    d.windows[("pair-POST", "global", 60000)] = (NOW + 60000, 6000)
    fixture = request("pair_host_post")
    r = client.post(
        fixture["path"],
        content=P.unb64u(fixture["body_b64u"]),
        headers={**fixture["headers"], "X-Forwarded-For": "203.0.113.5"},
    )
    assert r.status_code == 202, r.text


def test_host_chunks_do_not_spend_the_devices_post_rate(client):
    windows = client.app.state.directory.windows
    assert post(client, binary("bridge_device_post")).status_code == 202
    windows[("bridge-post", DEVICE, 1000)] = (NOW + 1000, 20)
    for i in range(3):
        chunk = bytearray(binary("bridge_host_post"))
        chunk[72:80] = i.to_bytes(8, "big")
        assert post(client, bytes(chunk), True).status_code == 202
    assert windows[("bridge-post", DEVICE, 1000)] == (NOW + 1000, 20)
    assert windows[("bridge-host-post", (WS, DEVICE), 1000)][1] == 3


@pytest.mark.parametrize(
    "method,path,headers,body,status",
    [
        ("POST", DEVICE_POLL, {}, "bridge_device_post", 401),
        ("POST", DEVICE_POLL, {**HOST, "Orch-Holder": "7"}, "bridge_host_post", 409),
        (
            "GET",
            f"/v2/workspaces/{'ab' * 16}/bridge/{RID}",
            {"Authorization": "Bearer FAKE-device"},
            None,
            403,
        ),
        ("GET", f"/v2/workspaces/{WS}/host/poll", {}, None, 401),
        ("GET", DEVICE_POLL, HOST, None, 403),  # host sessions have no device mailbox
        ("POST", f"/v2/cert-requests/{'ef' * 16}/challenge", HOST, {}, 403),
        (
            "POST",
            f"/v2/workspaces/{WS}/host/hold",
            {"Authorization": "Bearer FAKE-device"},
            {},
            403,
        ),
        ("POST", f"/v2/workspaces/{'ab' * 16}/pair/{CRID}/{RID}", {}, "pair_device_post", 401),
        (
            "POST",
            f"/v2/workspaces/{WS}/pair/{CRID}/{RID}",
            {**HOST, "Orch-Holder": "7"},
            "pair_host_post",
            409,
        ),
        (
            "POST",
            f"/v2/persons/{PERSON}/cert-requests",
            {"Authorization": "Bearer FAKE-device"},
            {},
            403,
        ),
        ("POST", f"/v2/cert-requests/{CRID}/challenge", {}, {}, 401),
    ],
)
def test_unauthorized_requests_take_no_lock_or_budget(
    client, monkeypatch, method, path, headers, body, status
):
    # Refusals that need no data come from a read-only check: no Directory.lock, no
    # BEGIN IMMEDIATE + collect(), no rate window, no wake.
    bridge = client.app.state.bridge
    d = client.app.state.directory
    calls, woken = [], []
    monkeypatch.setattr(bridge, "transaction", lambda *args: calls.append(args))
    monkeypatch.setattr(bridge, "wake", lambda *keys: woken.append(keys))
    windows = dict(d.windows)
    if isinstance(body, str):
        kwargs = {
            "content": binary(body),
            "headers": {**headers, "Content-Type": "application/octet-stream"},
        }
    elif body is not None:
        kwargs = {"json": body, "headers": headers}
    else:
        kwargs = {"headers": headers}
    r = client.request(method, path, **kwargs)
    assert r.status_code == status, r.text
    assert calls == [] and woken == [] and d.windows == windows


def test_cert_answers_from_non_device_sessions_reveal_no_request_ids(client):
    # Deliberate: the session kind is refused before the request lookup (403, not 404).
    for ident in ("ef" * 16, CRID):
        for route in ("challenge", "rejection"):
            r = client.post(f"/v2/cert-requests/{ident}/{route}", json={}, headers=HOST)
            assert r.status_code == 403 and r.json() == {"error": "not_eligible"}


def test_pair_poll_wakes_on_host_answer(client):
    from bridge_support import request, seen

    with closing(db.connect(client.app.state.directory.path)) as con, con:
        seen(con, binary("pair_device_post"))
    fixture = request("pair_host_post")
    path = fixture["path"]
    with ThreadPoolExecutor() as pool:
        pending = pool.submit(
            client.get, path, params={"wait": 10}, headers={"X-Forwarded-For": "198.51.100.7"}
        )
        wait_admitted(client)
        time.sleep(0.3)
        answered = time.monotonic()
        r = client.post(path, content=P.unb64u(fixture["body_b64u"]), headers=fixture["headers"])
        assert r.status_code == 202, r.text
        r = pending.result(timeout=5)
        assert time.monotonic() - answered < 0.5
    assert len(r.json()["chunks"]) == 1


def test_certificate_completion_wakes_requesting_host(client, monkeypatch):
    # Completion does not change the notices list (ids with challenge, cert or rejection),
    # so the woken host poll re-checks and keeps waiting; the wake itself is pinned here.
    from bridge_support import OBJECTS
    from directory_support import CERT

    bridge = client.app.state.bridge
    sql(
        client,
        "INSERT INTO sessions VALUES (?,?,?,?)",
        (token_hash("FAKE-primary"), "device", PRIMARY, NOW + 900000),
    )
    r = client.post(
        f"/v2/persons/{PERSON}/cert-requests", json={"request": OBJECTS["request"]}, headers=HOST
    )
    assert r.status_code == 200
    r = client.post(
        f"/v2/cert-requests/{CRID}/challenge",
        json={"challenge": OBJECTS["challenge"]},
        headers={"Authorization": "Bearer FAKE-primary"},
    )
    assert r.status_code == 200
    assert host_poll(client, 0).json()["notices"]["cert_requests"] == [CRID]
    probed = []
    probe = bridge.probe
    monkeypatch.setattr(bridge, "probe", lambda *args: probed.append(args[0]) or probe(*args))
    with ThreadPoolExecutor() as pool:
        pending = pool.submit(host_poll, client, 2)
        wait_admitted(client)
        time.sleep(0.3)
        probed.clear()  # the poll's own first step wakes its key once
        assert client.put(f"/v2/devices/{DEVICE}", json={"cert": CERT}).status_code == 200
        time.sleep(0.3)
        assert probed == ["host_poll"]
        assert pending.result(timeout=5).json()["items"] == []
    assert sql(client, "SELECT state FROM cert_requests") == [("signed",)]


def test_host_poll_ends_promptly_on_workspace_logout(client):
    with ThreadPoolExecutor() as pool:
        pending = pool.submit(host_poll, client, 10)
        wait_admitted(client)
        time.sleep(0.3)
        out = time.monotonic()
        r = client.post(
            "/v2/session/logout", json={}, headers={"Authorization": "Bearer FAKE-workspace"}
        )
        assert r.status_code == 200
        assert pending.result(timeout=5).status_code == 401
        assert time.monotonic() - out < 0.5


def test_preauthorize_database_error_falls_back_to_transaction(client, monkeypatch):
    import sqlite3

    bridge = client.app.state.bridge

    def broken(*args):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(bridge, "preauthorize", broken)
    started = time.monotonic()
    r = client.get(DEVICE_POLL, params={"wait": 5}, headers={"Authorization": "Bearer FAKE-device"})
    assert r.status_code == 200 and r.json() == {"chunks": []}
    assert time.monotonic() - started < 1
    assert client.get(DEVICE_POLL).status_code == 401
    assert bridge.polls == {}
