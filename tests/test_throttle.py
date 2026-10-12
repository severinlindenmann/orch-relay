"""P3-D35 (pre-public-deploy blocker 4): per-session read throttling, poll counters, proxy warning.

Authenticated requests on the directory, bridge and checkpoint routes are charged a token bucket of
their session (and of their workspace for W sessions; proof and transition pages also a page
bucket) once the session is authenticated: a request with no valid session charges nothing, and a
valid session's refused requests charge only its own buckets. All clocks are injected and frozen,
so every count below is exact.
"""

import asyncio
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing

import pytest
from bridge_support import HOST, RID, binary
from directory_support import DEVICE, NOW, PERSON, WS, seed
from fastapi.testclient import TestClient

from orch_relay import bridge as B
from orch_relay import db
from orch_relay import directory as D
from orch_relay.app import create_app
from orch_relay.directory import Buckets, Refusal, token_hash

PROXY = "10.9.9.9"
OTHER = "ab" * 16
DEV = {"Authorization": "Bearer FAKE-device"}
DEV2 = {"Authorization": "Bearer FAKE-device-2"}
W2 = {"Authorization": "Bearer FAKE-workspace-2", "Orch-Holder": "1"}
BAD = {"Authorization": "Bearer nope"}


@pytest.fixture
def client(tmp_path):
    with TestClient(create_app(tmp_path), client=(PROXY, 50000)) as client:
        d = client.app.state.directory
        seed(d)
        d.trusted_proxy = PROXY
        sql(
            client,
            "INSERT INTO sessions VALUES (?,?,?,?),(?,?,?,?)",
            (
                token_hash("FAKE-device-2"),
                "device",
                DEVICE,
                NOW + 900_000,
                token_hash("FAKE-workspace-2"),
                "workspace",
                WS,
                NOW + 900_000,
            ),
        )
        yield client
        assert client.app.state.bridge.waiters == {}


def sql(client, statement, args=()):
    with closing(db.connect(client.app.state.directory.path)) as con, con:
        return con.execute(statement, args).fetchall()


def limit(client, **limits):
    """Small buckets for a test: name=(burst, refill per minute)."""
    for name, value in limits.items():
        client.app.state.directory.throttles[name.replace("_", "-")] = value


def get(client, path, headers, **params):
    return client.get(path, params=params, headers=headers)


CARD_PATH = f"/v2/workspaces/{WS}/card"
DIRECTORY_GETS = [
    (f"/v2/workspaces/{WS}/members", DEV),
    (CARD_PATH, DEV),
    (f"/v2/workspaces/{WS}/grants", DEV),
    (f"/v2/workspaces/{WS}/card-key", DEV),
    (f"/v2/devices/{DEVICE}", DEV),
    (f"/v2/persons/{PERSON}/revocations", DEV),
    (f"/v2/workspaces/{WS}/members", HOST),
    (f"/v2/devices/{DEVICE}", HOST),
]
BRIDGE_GETS = [
    (f"/v2/workspaces/{WS}/bridge/{RID}", DEV),
    (f"/v2/workspaces/{WS}/host/poll", HOST),
    (f"/v2/persons/{PERSON}/cert-requests", DEV),
]
CHECKPOINT_GETS = [
    (f"/v2/workspaces/{WS}/checkpoint", DEV),
    (f"/v2/workspaces/{WS}/checkpoint", HOST),
    (f"/v2/workspaces/{WS}/unpublished", HOST),
]


# --- the bucket ---------------------------------------------------------------------------------


def test_defaults_and_their_arithmetic():
    # (burst, refill per minute). Honest hosts and phones poll at most every few seconds (long
    # polls wait up to 25 s); a sync reads the card, members, grants and a few certificates; a
    # device walks at most a few dozen proof pages. Each default is far above that.
    assert D.THROTTLES == {
        "session": (600, 600),
        "workspace": (1200, 1200),
        "page-session": (256, 120),
        "page-workspace": (512, 240),
    }
    assert D.THROTTLE_TABLE == 65_536


def take(buckets, key, now, burst=3, rate=60, charge=True):
    buckets.take(key, burst, rate, now, charge)


def test_bucket_fires_at_burst_not_below_and_refills():
    b = Buckets()
    for _ in range(3):
        take(b, "k", NOW)
    with pytest.raises(Refusal) as refused:
        take(b, "k", NOW)
    assert (refused.value.code, refused.value.status, refused.value.retry) == (
        "rate_limited",
        429,
        1,
    )
    with pytest.raises(Refusal):
        take(b, "k", NOW + 999)  # 60 per minute: one token per 1,000 ms
    take(b, "k", NOW + 1000)
    with pytest.raises(Refusal):
        take(b, "k", NOW + 1000)
    # A slow refill names the full wait: 6 per minute, 10 s per token.
    with pytest.raises(Refusal) as refused:
        for _ in range(3):
            take(b, "slow", NOW, rate=6)
        take(b, "slow", NOW, rate=6)
    assert refused.value.retry == 10
    # Refill never exceeds the burst, and a clock that goes back adds nothing.
    take(b, "k", NOW + 3_600_000)
    take(b, "k", NOW + 3_600_000)
    take(b, "k", NOW + 3_600_000)
    with pytest.raises(Refusal):
        take(b, "k", NOW + 3_600_000)
    with pytest.raises(Refusal):
        take(b, "k", NOW)


def test_bucket_check_without_charge_has_no_side_effects():
    b = Buckets()
    take(b, "k", NOW, charge=False)
    assert dict(b.table) == {}
    take(b, "k", NOW)
    before = dict(b.table)
    take(b, "k", NOW + 500, charge=False)
    assert dict(b.table) == before and list(b.table) == ["k"]


def test_bucket_table_is_bounded_lru():
    b = Buckets(limit=4)
    for i in range(1000):
        take(b, i, NOW)
    assert list(b.table) == [996, 997, 998, 999]
    take(b, 996, NOW)  # used: now the most recent
    take(b, "new", NOW)
    assert list(b.table) == [998, 999, 996, "new"]


# --- directory ---------------------------------------------------------------------------------


@pytest.mark.parametrize("path,headers", DIRECTORY_GETS + BRIDGE_GETS + CHECKPOINT_GETS)
def test_authenticated_reads_fire_at_the_limit_not_below(client, path, headers):
    limit(client, session=(3, 60))
    statuses = [get(client, path, headers).status_code for _ in range(3)]
    assert 429 not in statuses
    r = get(client, path, headers)
    assert r.status_code == 429 and r.json() == {"error": "rate_limited"}
    assert r.headers["retry-after"] == "1"
    client.app.state.directory.clock = lambda: NOW + 1000
    assert get(client, path, headers).status_code != 429


def test_unauthenticated_requests_charge_no_bucket(client):
    d = client.app.state.directory
    limit(client, session=(3, 60), workspace=(3, 60))
    for headers in (BAD, {}, {"Authorization": "Basic x"}):
        for path, _ in DIRECTORY_GETS + BRIDGE_GETS + CHECKPOINT_GETS:
            for _ in range(4):
                assert get(client, path, headers).status_code == 401
    for i in range(200):  # a flood of distinct tokens creates no entry
        assert get(client, CARD_PATH, {"Authorization": f"Bearer t{i}"}).status_code == 401
    assert dict(d.buckets.table) == {}
    for headers in (DEV, HOST):
        assert [get(client, CARD_PATH, headers).status_code for _ in range(3)] == [200] * 3


def test_a_sessions_refusals_charge_only_its_own_bucket(client):
    limit(client, session=(3, 60))
    other = f"/v2/workspaces/{OTHER}/card"
    assert [get(client, other, DEV).status_code for _ in range(3)] == [404] * 3
    assert get(client, other, DEV).status_code == 429
    assert get(client, CARD_PATH, DEV).status_code == 429
    # Another session of the same device, and the host, are unaffected.
    assert [get(client, CARD_PATH, DEV2).status_code for _ in range(3)] == [200] * 3
    assert [get(client, CARD_PATH, HOST).status_code for _ in range(3)] == [200] * 3
    # Refusals after authentication on every family are charged too.
    for path, headers in [
        (f"/v2/workspaces/{OTHER}/bridge/{RID}", DEV),  # 403 not a member
        (f"/v2/workspaces/{WS}/host/poll", {**HOST, "Orch-Holder": "7"}),  # 409 fenced
        (f"/v2/workspaces/{OTHER}/checkpoint", DEV),  # 403
    ]:
        client.app.state.directory.buckets.table.clear()
        statuses = [get(client, path, headers).status_code for _ in range(4)]
        assert 429 not in statuses[:3] and statuses[3] == 429


def test_workspace_sessions_share_the_workspace_bucket(client):
    limit(client, session=(100, 60), workspace=(3, 60))
    host = {**HOST, "Orch-Holder": "1"}
    assert [get(client, CARD_PATH, host).status_code for _ in range(2)] == [200] * 2
    assert get(client, CARD_PATH, W2).status_code == 200
    assert get(client, CARD_PATH, W2).status_code == 429
    assert get(client, CARD_PATH, host).status_code == 429
    # Device sessions of that workspace are not charged the workspace bucket.
    assert get(client, CARD_PATH, DEV).status_code == 200


def test_bucket_table_bounded_under_many_valid_sessions(client):
    d = client.app.state.directory
    d.buckets.limit = 8
    for i in range(40):
        sql(
            client,
            "INSERT INTO sessions VALUES (?,?,?,?)",
            (token_hash(f"many-{i}"), "device", DEVICE, NOW + 900_000),
        )
        assert get(client, CARD_PATH, {"Authorization": f"Bearer many-{i}"}).status_code == 200
    assert len(d.buckets.table) == 8


def test_throttled_request_takes_no_lock(client, monkeypatch):
    d = client.app.state.directory
    limit(client, session=(1, 60))
    assert get(client, CARD_PATH, DEV).status_code == 200
    taken = []
    real = d.connection
    monkeypatch.setattr(d, "connection", lambda purpose: taken.append(purpose) or real(purpose))
    assert get(client, CARD_PATH, DEV).status_code == 429
    assert get(client, f"/v2/workspaces/{WS}/bridge/{RID}", DEV).status_code == 429
    assert taken == []


# --- bridge ------------------------------------------------------------------------------------


def post(client, raw, headers=DEV):
    return client.post(
        f"/v2/workspaces/{WS}/bridge/{RID}",
        content=raw,
        headers={**headers, "Content-Type": "application/octet-stream"},
    )


def test_identical_resends_are_charged(client):
    limit(client, session=(3, 60))
    raw = binary("bridge_device_post")
    assert [post(client, raw).status_code for _ in range(3)] == [202] * 3
    r = post(client, raw)
    assert r.status_code == 429 and r.headers["retry-after"] == "1"
    assert post(client, raw, DEV2).status_code == 202


def test_throttled_wait_takes_no_slot(client, monkeypatch):
    bridge = client.app.state.bridge
    limit(client, session=(1, 60))
    assert get(client, f"/v2/workspaces/{WS}/bridge/{RID}", DEV).status_code == 200
    admitted = []
    monkeypatch.setattr(bridge, "admit", lambda key: admitted.append(key))
    r = get(client, f"/v2/workspaces/{WS}/bridge/{RID}", DEV, wait=1)
    assert r.status_code == 429 and admitted == [] and bridge.polls == {}


def test_anonymous_pairing_charges_no_bucket(client):
    from bridge_support import CRID

    for _ in range(5):
        r = get(client, f"/v2/workspaces/{WS}/pair/{CRID}/{RID}", {"X-Forwarded-For": "192.0.2.9"})
        assert r.status_code == 200
    assert dict(client.app.state.directory.buckets.table) == {}


# --- checkpoints -------------------------------------------------------------------------------


def test_proof_and_transition_pages_have_their_own_bucket(client):
    limit(client, session=(100, 60), page_session=(2, 60))
    proof = f"/v2/workspaces/{WS}/proof"
    transitions = f"/v2/workspaces/{WS}/transitions"
    assert get(client, proof, DEV, log="workspace").status_code != 429
    assert get(client, transitions, DEV).status_code != 429
    assert get(client, proof, DEV, log="workspace").status_code == 429
    assert get(client, transitions, DEV).status_code == 429
    # The plain read bucket is unaffected; other sessions too.
    assert get(client, f"/v2/workspaces/{WS}/checkpoint", DEV).status_code == 404
    assert get(client, transitions, DEV2).status_code != 429
    limit(client, page_workspace=(1, 60))
    assert get(client, transitions, HOST).status_code != 429
    assert get(client, transitions, W2).status_code == 429


def test_checkpoint_writes_are_charged_after_authorization(client):
    limit(client, session=(2, 60), workspace=(100, 60))
    path = f"/v2/workspaces/{WS}/baselines"
    host = {**HOST, "Orch-Holder": "1"}
    for _ in range(5):
        assert client.post(path, json={}, headers=BAD).status_code == 401
    assert dict(client.app.state.directory.buckets.table) == {}
    statuses = [client.post(path, json={}, headers=host).status_code for _ in range(3)]
    assert 429 not in statuses[:2] and statuses[2] == 429


# --- unauthenticated reads (item 4) --------------------------------------------------------------


def test_revocation_read_has_a_parent_window(client, monkeypatch):
    monkeypatch.setattr(D, "REVOCATION_READ_PARENT", 3)
    path = f"/v2/devices/{DEVICE}/revocation"

    def read(address):
        return client.get(path, headers={"X-Forwarded-For": address})

    assert [read(f"2001:db8:0:{i}::1").status_code for i in range(1, 4)] == [404] * 3
    r = read("2001:db8:0:4::1")  # a fresh /64 in the same /56
    assert r.status_code == 429 and r.headers["retry-after"]
    assert read("2001:db8:0:100::1").status_code == 404  # another /56
    assert read("192.0.2.1").status_code == 404


# --- N4: proxy configuration ---------------------------------------------------------------------


def test_forwarded_header_without_trusted_proxy_warns_once(client, caplog):
    d = client.app.state.directory
    d.trusted_proxy = None
    with caplog.at_level(logging.WARNING, logger="orch_relay.directory"):
        for _ in range(3):
            client.get(f"/v2/devices/{DEVICE}/revocation", headers={"X-Forwarded-For": "1.2.3.4"})
    warnings = [r for r in caplog.records if "ORCH_RELAY_TRUSTED_PROXY" in r.getMessage()]
    assert len(warnings) == 1 and warnings[0].levelno == logging.WARNING


def test_no_warning_with_trusted_proxy(client, caplog):
    with caplog.at_level(logging.WARNING, logger="orch_relay.directory"):
        client.get(f"/v2/devices/{DEVICE}/revocation", headers={"X-Forwarded-For": "1.2.3.4"})
    assert not [r for r in caplog.records if "ORCH_RELAY_TRUSTED_PROXY" in r.getMessage()]


def test_startup_warns_behind_proxy_without_trusted_proxy(tmp_path, monkeypatch, caplog):
    monkeypatch.setenv("ORCH_RELAY_BEHIND_PROXY", "1")
    monkeypatch.delenv("ORCH_RELAY_TRUSTED_PROXY", raising=False)
    with caplog.at_level(logging.WARNING, logger="orch_relay.directory"):
        create_app(tmp_path)
    assert [r for r in caplog.records if "ORCH_RELAY_TRUSTED_PROXY" in r.getMessage()]
    caplog.clear()
    monkeypatch.setenv("ORCH_RELAY_TRUSTED_PROXY", "127.0.0.1")
    with caplog.at_level(logging.WARNING, logger="orch_relay.directory"):
        create_app(tmp_path)
    assert not [r for r in caplog.records if "ORCH_RELAY_TRUSTED_PROXY" in r.getMessage()]


def test_throttle_settings_from_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("ORCH_RELAY_THROTTLE_SESSION", "10/30")
    monkeypatch.setenv("ORCH_RELAY_THROTTLE_PAGE_WORKSPACE", "7/1")
    monkeypatch.setenv("ORCH_RELAY_THROTTLE_TABLE", "99")
    d = create_app(tmp_path).state.directory
    assert d.throttles == {**D.THROTTLES, "session": (10, 30), "page-workspace": (7, 1)}
    assert d.buckets.limit == 99
    for bad in ("10", "0/5", "5/0", "x/1", "-1/2"):
        monkeypatch.setenv("ORCH_RELAY_THROTTLE_SESSION", bad)
        with pytest.raises(ValueError):
            create_app(tmp_path)


# --- N3: running poll counters -------------------------------------------------------------------


def test_admit_keeps_running_counters_without_scanning(client, monkeypatch):
    bridge = client.app.state.bridge
    polls = bridge.polls
    for i in range(100):
        polls[("device", f"{i:032x}")] = 3
    polls[("pair", "192.0.2.1")] = 2

    def scan(*args):
        raise AssertionError("admit scanned the poll table")

    for name in ("values", "items", "keys", "__iter__"):
        monkeypatch.setattr(type(polls), name, scan)
    bridge.admit(("pair", "192.0.2.2"))
    bridge.admit(("workspace", WS))
    assert (polls.total, polls.kinds["pair"], polls.kinds["device"]) == (304, 3, 300)
    bridge.release(("pair", "192.0.2.2"))
    bridge.release(("workspace", WS))
    monkeypatch.undo()
    polls.clear()
    assert (polls.total, sum(polls.kinds.values())) == (0, 0)


def test_counters_follow_direct_table_writes(client):
    polls = client.app.state.bridge.polls
    polls[("pair", "a")] = 4
    polls[("pair", "a")] -= 1
    polls[("device", "b")] = 2
    assert (polls.total, polls.kinds["pair"]) == (5, 3)
    del polls[("pair", "a")]
    assert polls.pop(("device", "b")) == 2
    assert polls == {} and polls.total == 0 and not +polls.kinds


def assert_drained(bridge):
    assert bridge.polls == {} and bridge.polls.total == 0 and not +bridge.polls.kinds
    assert bridge.pair_groups == {}


def test_counters_return_to_zero_after_timeout_and_exception(client, monkeypatch):
    from bridge_support import CRID

    bridge = client.app.state.bridge
    assert get(client, f"/v2/workspaces/{WS}/bridge/{RID}", DEV, wait=1).status_code == 200
    pair = f"/v2/workspaces/{WS}/pair/{CRID}/{RID}"
    assert get(client, pair, {"X-Forwarded-For": "2001:db8::1"}, wait=1).status_code == 200
    assert_drained(bridge)

    def broken(*args):
        raise ValueError("boom")

    monkeypatch.setattr(bridge, "transaction", broken)
    assert get(client, f"/v2/workspaces/{WS}/bridge/{RID}", DEV, wait=5).status_code == 400
    assert get(client, pair, {"X-Forwarded-For": "2001:db8::1"}, wait=5).status_code == 400
    assert_drained(bridge)


def test_counters_return_to_zero_after_replaced_poll(client):
    bridge = client.app.state.bridge
    path = f"/v2/workspaces/{WS}/host/poll"
    host = {**HOST, "Orch-Holder": "1"}
    with ThreadPoolExecutor() as pool:
        first = pool.submit(get, client, path, host, wait=10)
        deadline = time.monotonic() + 3
        while bridge.polls.total < 1:
            assert time.monotonic() < deadline
            time.sleep(0.01)
        assert get(client, path, host).status_code == 200  # replaces the waiting poll
        assert first.result(timeout=5).json()["items"] == []
    assert_drained(bridge)


def test_counters_return_to_zero_after_cancel(tmp_path):
    from test_bridge_longpoll import raw_get

    app = create_app(tmp_path)
    db.migrate(app.state.data_dir / db.DB_NAME)
    seed(app.state.directory)
    bridge = app.state.bridge

    async def run():
        task = asyncio.create_task(
            raw_get(app, f"/v2/workspaces/{WS}/bridge/{RID}", "wait=20", DEV)
        )
        for _ in range(300):
            if bridge.polls.total:
                break
            await asyncio.sleep(0.01)
        assert bridge.polls.total == 1
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)

    try:
        asyncio.run(run())
    finally:
        bridge.close()
    assert_drained(bridge)
    assert bridge.waiters == {}


def test_pair_ceiling_uses_the_running_count(client):
    polls = client.app.state.bridge.polls
    polls[("pair", "x")] = B.PAIR_POLL_CEILING
    with pytest.raises(Refusal) as refused:
        client.app.state.bridge.admit(("pair", "192.0.2.77"))
    assert refused.value.code == "overloaded"
    polls.clear()
    polls[("device", "y")] = B.POLL_CEILING
    with pytest.raises(Refusal) as refused:
        client.app.state.bridge.admit(("device", DEVICE))
    assert refused.value.code == "overloaded"
    polls.clear()
