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
from directory_support import DEVICE, NOW, PERSON, PRIMARY, WS, issue_login, seed
from fastapi.testclient import TestClient

from orch_relay import bridge as B
from orch_relay import db
from orch_relay import directory as D
from orch_relay.app import create_app
from orch_relay.directory import Buckets, Refusal, token_hash

PROXY = "10.9.9.9"
OTHER = "ab" * 16
DEV = {"Authorization": "Bearer FAKE-device"}
DEV2 = {"Authorization": "Bearer FAKE-device-2"}  # another device (PRIMARY) of the same person
SAME = {"Authorization": "Bearer FAKE-device-same"}  # another session of DEVICE
W2 = {"Authorization": "Bearer FAKE-workspace-2", "Orch-Holder": "1"}
BAD = {"Authorization": "Bearer nope"}


@pytest.fixture
def client(tmp_path):
    with TestClient(create_app(tmp_path), client=(PROXY, 50000)) as client:
        d = client.app.state.directory
        seed(d)
        d.trusted_proxy = PROXY
        for token, kind, ident in (
            ("FAKE-device-2", "device", PRIMARY),
            ("FAKE-device-same", "device", DEVICE),
            ("FAKE-workspace-2", "workspace", WS),
        ):
            sql(
                client,
                "INSERT INTO sessions VALUES (?,?,?,?)",
                (token_hash(token), kind, ident, NOW + 900_000),
            )
        sql(client, "INSERT INTO ever_devices VALUES (?,?,?)", (WS, PRIMARY, 1))
        sql(client, "INSERT INTO members VALUES (?,?,?,?)", (WS, PRIMARY, PERSON, '["look"]'))
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
    from orch_relay import checkpoints as C
    from orch_relay import proto as P

    # (burst, refill per minute). Honest hosts and phones poll at most every few seconds (long
    # polls wait up to 25 s); a sync reads the card, members, grants and a few certificates.
    # A first sync walks one proof page per grown log: a full 64 MiB set is 17 pages (16 of
    # 56,678 heads at 57 tokens, then 28 heads at 1) = 913 tokens, plus 5,001 small logs.
    assert (
        (D.PAGE_BYTES, D.PROOF_PAGE_HEADS)
        == (C.PAGE_CAP, C.PROOF_PAGE_HEADS)
        == (
            4 * 1024 * 1024,
            56_678,
        )
    )
    assert D.STAGE_HEADS == C.STAGE_CAP // 74 == 906_876
    assert (D.FULL_SET_TOKENS, D.PAGE_BURST) == (16 * 57 + 1, 913 + 5_001)
    # One manifest describes at most MANIFEST_PAGES pages: one more minimal descriptor does not fit.
    one = {"i": 0, "kind": "appended", "log": "workspace", "after_seq": 0, "count": 1}
    one["digest"] = "sha256:" + "0" * 64
    assert len(P.cj({"pages": [one] * D.MANIFEST_PAGES})) <= C.PAGE_CAP
    assert len(P.cj({"pages": [one] * (D.MANIFEST_PAGES + 1)})) > C.PAGE_CAP
    assert D.MANIFEST_PAGES == 27_776
    assert D.THROTTLES == {
        "session": (600, 600),
        "person": (1200, 1200),
        "workspace": (1200, 1200),
        "page-session": (5_914, 600),
        "page-person": (11_828, 1200),
        "page-workspace": (11_828, 1200),
        "staging": (28_801, 600),
        "host-answer": (1200, 1200),
    }
    # P3-D36: staging is weighted by body size, one token per started 64 KiB (at least one). A
    # set holds at most MANIFEST_PAGES pages plus its manifest and STAGE_CAP bytes in all, so
    # its tokens are at most one per piece plus floor(STAGE_CAP / 64 KiB) = 1,024 (each piece's
    # extra tokens are floor((size - 1) / 64 KiB), and their sum is at most the total over it).
    assert D.STAGE_TOKEN_BYTES == 64 * 1024 and D.STAGE_BYTES == C.STAGE_CAP
    assert D.STAGING_BURST == D.MANIFEST_PAGES + 1 + C.STAGE_CAP // D.STAGE_TOKEN_BYTES
    assert [D.staging_tokens(n) for n in (0, 1, 65_536, 65_537, C.PAGE_CAP)] == [1, 1, 1, 2, 64]
    assert D.THROTTLE_TABLE == 16_384  # per key class


def take(buckets, key, now, burst=3, rate=60, charge=True, cost=1, debt=False):
    buckets.take(key, burst, rate, now, charge, cost, debt)


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


def retry(buckets, key, now, **kw):
    with pytest.raises(Refusal) as refused:
        take(buckets, key, now, **kw)
    return refused.value.retry


def test_retry_after_counts_partial_refill_and_rounds_up():
    b = Buckets()
    take(b, "seven", NOW, burst=1, rate=7)
    assert retry(b, "seven", NOW, burst=1, rate=7) == 9  # 8.57 s to the next token
    take(b, "six", NOW, burst=1, rate=6)
    assert retry(b, "six", NOW + 5_500, burst=1, rate=6) == 5  # 4.5 s left of 10 s
    take(b, "six", NOW + 10_000, burst=1, rate=6)


def test_clock_going_back_keeps_the_latest_time():
    b = Buckets()
    take(b, "k", NOW + 5_000)
    take(b, "k", NOW)  # the clock went back: no refill, the stored time stays NOW + 5,000
    take(b, "k", NOW + 5_000)  # back to it: still no refill
    with pytest.raises(Refusal):
        take(b, "k", NOW + 5_000)


def test_debt_is_charged_after_the_work_and_delays_the_next():
    b = Buckets()
    take(b, "k", NOW, burst=5)  # up front
    take(b, "k", NOW, burst=5, cost=2, debt=True)
    take(b, "k", NOW, burst=5)
    take(b, "k", NOW, burst=5, cost=3, debt=True)  # never refused: the level goes below zero
    assert retry(b, "k", NOW, burst=5) == 3  # level -2: three seconds to one token
    take(b, "k", NOW + 3_000, burst=5)
    assert retry(b, "k", NOW, burst=5, cost=2) == 2


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


def test_eviction_keeps_depleted_buckets_and_classes_apart():
    b = Buckets(limit=4)
    take(b, ("session", "attacker"), NOW, burst=1)  # depleted
    for i in range(100):  # fresh identities of the same class, each charged once
        take(b, ("session", i), NOW)
    assert ("session", "attacker") in b.table  # never reset by the flood
    with pytest.raises(Refusal):
        take(b, ("session", "attacker"), NOW, burst=1)
    for i in range(1000):  # another class cannot evict it either
        take(b, ("host-answer", i), NOW)
    assert ("session", "attacker") in b.table
    assert sum(1 for key in b.table if key[0] == "host-answer") == 4
    # A full (idle, refilled) bucket is evicted before a partly used one, though older.
    b = Buckets(limit=2)
    take(b, ("c", "idle"), NOW)
    take(b, ("c", "busy"), NOW + 60_000, burst=1)
    take(b, ("c", "new"), NOW + 60_000)
    assert list(b.table) == [("c", "busy"), ("c", "new")]
    # A clock that goes back makes no depleted bucket look refilled.
    b = Buckets(limit=2)
    take(b, ("c", "depleted"), NOW + 60_000, burst=1)
    take(b, ("c", "used"), NOW + 60_000)
    take(b, ("c", "late"), NOW)
    assert list(b.table) == [("c", "depleted"), ("c", "late")]


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
    # Another session of the same device shares its bucket (F2); another device of the person,
    # and the host, are unaffected.
    assert get(client, CARD_PATH, SAME).status_code == 429
    assert [get(client, CARD_PATH, DEV2).status_code for _ in range(3)] == [200] * 3
    assert [get(client, CARD_PATH, HOST).status_code for _ in range(3)] == [200] * 3
    # Refusals after authentication on every family are charged too.
    for path, headers in [
        (f"/v2/workspaces/{OTHER}/bridge/{RID}", DEV),  # 403 not a member
        (f"/v2/workspaces/{WS}/host/poll", {**HOST, "Orch-Holder": "7"}),  # 409 fenced
        (f"/v2/workspaces/{OTHER}/checkpoint", DEV),  # 403
    ]:
        client.app.state.directory.buckets.clear()
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
    for i in range(40):  # W sessions are keyed by token (their workspace bucket is shared)
        sql(
            client,
            "INSERT INTO sessions VALUES (?,?,?,?)",
            (token_hash(f"many-{i}"), "workspace", WS, NOW + 900_000),
        )
        assert get(client, CARD_PATH, {"Authorization": f"Bearer many-{i}"}).status_code == 200
    # Per key class: 8 session buckets, and the one workspace bucket they share.
    assert sorted(key[0] for key in d.buckets.table) == ["session"] * 8 + ["workspace"]


def test_logout_and_login_do_not_refill_a_device(client):
    limit(client, session=(3, 60))
    served = 0
    for _ in range(6):
        token = issue_login(client).json()["token"]
        headers = {"Authorization": f"Bearer {token}"}
        served += sum(get(client, CARD_PATH, headers).status_code == 200 for _ in range(3))
        assert client.post("/v2/session/logout", json={}, headers=headers).status_code == 200
    assert served == 3


def test_a_persons_devices_share_the_person_bucket(client):
    limit(client, session=(100, 60), person=(3, 60))
    assert [get(client, CARD_PATH, h).status_code for h in (DEV, DEV2, SAME)] == [200] * 3
    assert get(client, CARD_PATH, DEV2).status_code == 429
    assert get(client, CARD_PATH, HOST).status_code == 200


def test_workspace_buckets_are_per_workspace(client):
    d = client.app.state.directory
    limit(client, session=(100, 60), workspace=(2, 60))
    with closing(db.connect(d.path)) as con, con:
        row = list(con.execute("SELECT * FROM workspaces WHERE workspace_id=?", (WS,)).fetchone())
        con.execute("INSERT INTO workspaces VALUES (?,?,?,?,?,?,?,?)", (OTHER, *row[1:]))
        con.execute(
            "INSERT INTO sessions VALUES (?,?,?,?)",
            (token_hash("FAKE-workspace-other"), "workspace", OTHER, NOW + 900_000),
        )
    other = {"Authorization": "Bearer FAKE-workspace-other"}
    assert [get(client, CARD_PATH, HOST).status_code for _ in range(2)] == [200] * 2
    assert get(client, CARD_PATH, HOST).status_code == 429
    assert get(client, f"/v2/workspaces/{OTHER}/card", other).status_code == 200


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
    assert post(client, raw, SAME).status_code == 429  # the same device (F2)
    assert get(client, CARD_PATH, DEV2).status_code == 200


def test_host_answers_spend_only_the_targets_answer_bucket(client):
    d = client.app.state.directory
    limit(client, session=(1, 60), workspace=(1, 60), host_answer=(2, 60))
    host = {**HOST, "Orch-Holder": "1"}
    assert post(client, binary("bridge_device_post")).status_code == 202
    answer = binary("bridge_host_post")
    assert [post(client, answer, host).status_code for _ in range(2)] == [202] * 2
    r = post(client, answer, host)
    assert r.status_code == 429 and r.headers["retry-after"] == "1"
    # The host's own session and workspace were never charged by the answers.
    assert ("session", ("token", token_hash("FAKE-workspace"))) not in d.buckets.table
    assert ("workspace", WS) not in d.buckets.table
    assert get(client, f"/v2/workspaces/{WS}/host/poll", host).status_code == 200
    # Answers to another member are a separate bucket.
    session = {"kind": "workspace", "subject_id": WS, "token_hash": token_hash("FAKE-workspace")}
    d.throttle(session, NOW, "host-answer", (WS, PRIMARY))
    # A refused answer (stale generation) is charged to the host's read buckets, not the target's.
    limit(client, session=(100, 60), workspace=(100, 60))
    d.buckets.clear()
    stale = {**HOST, "Orch-Holder": "7"}
    assert post(client, answer, stale).status_code == 409
    assert ("host-answer", (WS, DEVICE)) not in d.buckets.table
    assert ("session", ("token", token_hash("FAKE-workspace"))) in d.buckets.table


def host_answer(target=DEVICE):
    raw = bytearray(binary("bridge_host_post"))
    raw[24:40] = bytes.fromhex(target)
    return bytes(raw)


def test_answers_without_a_request_are_charged_to_the_host(client):
    """Security review: a W session must not choose fresh (workspace, target) keys at will."""
    d = client.app.state.directory
    limit(client, session=(3, 60), workspace=(100, 60))
    host = {**HOST, "Orch-Holder": "1"}
    statuses = [post(client, host_answer(f"{i:032x}"), host).status_code for i in range(4)]
    assert 429 not in statuses[:3] and statuses[3] == 429
    assert not [key for key in d.buckets.table if key[0] == "host-answer"]
    # No request on the rid: the same, also for the real target.
    d.buckets.clear()
    statuses = [post(client, host_answer(), host).status_code for _ in range(4)]
    assert statuses == [410, 410, 410, 429]


def test_a_pairing_request_does_not_open_a_bridge_answer_key(client):
    from bridge_support import CRID

    d = client.app.state.directory
    stranger = "cd" * 16  # an id an anonymous pairing request may name
    sql(
        client,
        "INSERT INTO rid_seen VALUES (?,?,?,'digest',0,?,0,?,?,?)",
        (WS, stranger, RID, NOW, NOW, NOW + 900_000, CRID),
    )
    limit(client, session=(100, 60), workspace=(100, 60))
    assert post(client, host_answer(stranger), {**HOST, "Orch-Holder": "1"}).status_code == 403
    assert not [key for key in d.buckets.table if key[0] == "host-answer"]


def test_only_a_hosts_response_uses_the_answer_key(client):
    """Delta review T1: a member's host-direction frame naming another member's live request
    charges only the member; a W session's request-direction frame is not an answer."""
    d = client.app.state.directory
    assert post(client, binary("bridge_device_post")).status_code == 202  # DEVICE's live request
    d.buckets.clear()
    assert post(client, host_answer(DEVICE), DEV2).status_code == 400  # a member, direction 2
    assert ("host-answer", (WS, DEVICE)) not in d.buckets.table
    assert ("session", ("device", PRIMARY)) in d.buckets.table
    d.buckets.clear()
    host = {**HOST, "Orch-Holder": "1"}
    assert post(client, binary("bridge_device_post"), host).status_code == 400  # W, direction 1
    assert ("host-answer", (WS, DEVICE)) not in d.buckets.table
    assert ("session", ("token", token_hash("FAKE-workspace"))) in d.buckets.table


def test_answer_key_pins_pair_rid_and_snapshot_errors(client, monkeypatch):
    """Delta review T3: one pair key per workspace, the rid must match, and a snapshot error
    falls back to the host's read buckets (as the pre-check's own sqlite3.Error fallback, which
    charges nothing)."""
    import sqlite3

    bridge, d = client.app.state.bridge, client.app.state.directory
    host = {"kind": "workspace", "subject_id": WS, "token_hash": token_hash("FAKE-workspace")}
    assert post(client, binary("bridge_device_post")).status_code == 202
    answer = host_answer(DEVICE)
    params = {"ws": WS, "rid": RID}
    assert bridge.answer_key("bridge", "POST", host, params, answer) == (WS, DEVICE)
    assert bridge.answer_key("bridge", "POST", host, {"ws": WS, "rid": "ee" * 16}, answer) is None
    for target in (DEVICE, PRIMARY, "cd" * 16):
        pair = {"ws": WS, "offer": "aa" * 16, "rid": RID}
        assert bridge.answer_key("pair", "POST", host, pair, host_answer(target)) == (WS, "pair")

    class Broken:
        def __enter__(self):
            raise sqlite3.OperationalError("database is locked")

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(bridge, "reading", lambda purpose="read": Broken())
    assert bridge.answer_key("bridge", "POST", host, params, answer) is None
    monkeypatch.undo()

    def broken(*args):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(bridge, "preauthorize", broken)
    d.buckets.clear()
    assert get(client, f"/v2/workspaces/{WS}/bridge/{RID}", DEV).status_code == 200
    assert dict(d.buckets.table) == {}  # documented: the fallback charges nothing


def test_answers_are_keyed_per_requesting_member(client):
    limit(client, host_answer=(2, 60))
    host = {**HOST, "Orch-Holder": "1"}
    request = bytearray(binary("bridge_device_post"))
    assert post(client, bytes(request)).status_code == 202
    request[24:40] = bytes.fromhex(PRIMARY)
    assert post(client, bytes(request), DEV2).status_code == 202
    assert [post(client, host_answer(), host).status_code for _ in range(3)] == [202, 202, 429]
    assert post(client, host_answer(PRIMARY), host).status_code == 202


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
    limit(client, session=(1, 60), page_session=(2, 60))
    proof = f"/v2/workspaces/{WS}/proof"
    transitions = f"/v2/workspaces/{WS}/transitions"
    assert get(client, proof, DEV, log="workspace").status_code != 429
    assert get(client, transitions, DEV).status_code != 429
    assert get(client, proof, DEV, log="workspace").status_code == 429
    assert get(client, transitions, DEV).status_code == 429
    # The plain read bucket is unaffected (pages never take it); other devices too.
    assert get(client, f"/v2/workspaces/{WS}/checkpoint", DEV).status_code == 404
    assert get(client, transitions, DEV2).status_code != 429
    limit(client, page_workspace=(1, 60))
    assert get(client, transitions, HOST).status_code != 429  # W sessions take page-workspace
    assert get(client, transitions, W2).status_code == 429


def test_proof_pages_are_weighted_by_heads(client, monkeypatch):
    from orch_relay import checkpoints as C

    heads = {"n": 2_500}
    monkeypatch.setattr(
        C.Relay, "read", lambda self, route, query: {"heads": ["h"] * heads["n"], "next": None}
    )
    limit(client, page_session=(5, 60))
    proof = f"/v2/workspaces/{WS}/proof"
    assert get(client, proof, DEV).status_code == 200  # 3 tokens: 1 up front, 2 after
    assert get(client, proof, DEV).status_code == 200  # 5 - 3 = 2 >= 1: served, now -1
    r = get(client, proof, DEV)
    assert r.status_code == 429 and r.headers["retry-after"] == "2"
    heads["n"] = 1
    client.app.state.directory.clock = lambda: NOW + 2_000
    assert get(client, proof, DEV).status_code == 200  # a small page costs one token


def test_transition_pages_are_weighted_by_bytes(client, monkeypatch):
    """Delta review T2: a transition page weighs its canonical bytes at 74 per head."""
    from orch_relay import checkpoints as C
    from orch_relay import proto as P

    bundle = "x" * (2_500 * 74)  # 2,500 heads' worth of bytes: 3 tokens
    monkeypatch.setattr(
        C.Relay, "read", lambda self, route, query: {"transitions": [bundle], "next": None}
    )
    assert len(P.cj([bundle])) // 74 == 2_500
    limit(client, page_session=(5, 60))
    transitions = f"/v2/workspaces/{WS}/transitions"
    assert get(client, transitions, DEV).status_code == 200  # 3 tokens
    assert get(client, transitions, DEV).status_code == 200  # 2 left: served, now -1
    r = get(client, transitions, DEV)
    assert r.status_code == 429 and r.headers["retry-after"] == "2"


def test_default_page_burst_covers_a_first_sync_and_throttles_full_pages(client):
    d = client.app.state.directory
    session = {"kind": "device", "subject_id": DEVICE, "person_id": PERSON}

    def page(heads, who=session):
        d.throttle(who, NOW, "page")
        cost = max(1, -(-heads // D.PAGE_TOKEN_HEADS))
        if cost > 1:
            d.throttle(who, NOW, "page", cost=cost - 1, debt=True)

    # A first sync of a 5,000-ticket workspace under a full 64 MiB set, all at one instant.
    for _ in range(D.STAGE_HEADS // D.PROOF_PAGE_HEADS):
        page(D.PROOF_PAGE_HEADS)
    page(D.STAGE_HEADS % D.PROOF_PAGE_HEADS)
    for _ in range(D.SYNC_LOGS):
        page(1)
    with pytest.raises(Refusal):
        page(1)
    # A flood of full pages from a fresh device: 104 served (5,914 / 57), then refused.
    flood = {"kind": "device", "subject_id": PRIMARY, "person_id": "f" * 32}
    served = 0
    with pytest.raises(Refusal):
        while True:
            page(D.PROOF_PAGE_HEADS, flood)
            served += 1
    assert served == 104


def test_staging_has_its_own_workspace_bucket(client):
    d = client.app.state.directory
    limit(client, session=(1, 60), workspace=(1, 60), staging=(2, 60))
    host = {**HOST, "Orch-Holder": "1"}
    page = f"/v2/workspaces/{WS}/staging/sha256:{'0' * 64}/sha256:{'1' * 64}/pages/0"
    statuses = [client.put(page, json={}, headers=host).status_code for _ in range(3)]
    assert 429 not in statuses[:2] and statuses[2] == 429
    assert ("session", ("token", token_hash("FAKE-workspace"))) not in d.buckets.table
    assert get(client, CARD_PATH, host).status_code == 200  # the host's session is untouched
    # A refused staging PUT (another workspace) never charges that workspace's staging bucket.
    other = f"/v2/workspaces/{OTHER}/staging/sha256:{'0' * 64}/sha256:{'1' * 64}/pages/0"
    limit(client, session=(100, 60), workspace=(100, 60))
    d.buckets.clear()
    assert client.put(other, json={}, headers=W2).status_code == 403
    assert ("staging", OTHER) not in d.buckets.table


def test_staging_buckets_are_per_workspace(client):
    d = client.app.state.directory
    limit(client, staging=(1, 60))
    with closing(db.connect(d.path)) as con, con:
        row = list(con.execute("SELECT * FROM workspaces WHERE workspace_id=?", (WS,)).fetchone())
        con.execute("INSERT INTO workspaces VALUES (?,?,?,?,?,?,?,?)", (OTHER, *row[1:]))
        con.execute("INSERT INTO holders VALUES (?,?,?,?,?)", (OTHER, 1, NOW + 40_000, 0, None))
        con.execute(
            "INSERT INTO sessions VALUES (?,?,?,?)",
            (token_hash("FAKE-workspace-other"), "workspace", OTHER, NOW + 900_000),
        )
    pages = "staging/sha256:" + "0" * 64 + "/sha256:" + "1" * 64 + "/pages/0"
    host = {**HOST, "Orch-Holder": "1"}
    other = {"Authorization": "Bearer FAKE-workspace-other", "Orch-Holder": "1"}
    assert client.put(f"/v2/workspaces/{WS}/{pages}", json={}, headers=host).status_code != 429
    assert client.put(f"/v2/workspaces/{WS}/{pages}", json={}, headers=host).status_code == 429
    assert client.put(f"/v2/workspaces/{OTHER}/{pages}", json={}, headers=other).status_code != 429


def stage_all(d, sizes, now=NOW, ws=WS):
    """Charge one staging PUT per body size, as authorize() does; the number served."""
    session = {"kind": "workspace", "subject_id": ws, "token_hash": "t"}
    served = 0
    for size in sizes:
        d.throttle(session, now, "staging", ws, cost=D.staging_tokens(size))
        served += 1
    return served


def small_set(pages):
    """Body sizes of an honest set of `pages` one-head pages plus its manifest (real encodings)."""
    from orch_relay import proto as P

    head = "sha256:" + "0" * 64
    body = {"kind": "appended", "log": "0" * 26, "after_seq": 0, "from_acc": head}
    body = {**body, "heads": [head], "digest": head}
    one = {"i": 0, "kind": "appended", "log": "0" * 26, "after_seq": 0, "count": 1, "digest": head}
    manifest = P.cj({"pages": [{**one, "i": i} for i in range(pages)]})
    return [len(P.cj(body))] * pages + [len(manifest)]


def test_default_staging_burst_covers_honest_sets_at_once(client):
    """P3-D36: with an injected clock that never moves, an honest 5,001-page set, a full 64 MiB
    set in 4 MiB pages and the largest set by page count each upload with no 429."""
    from orch_relay import checkpoints as C

    d = client.app.state.directory
    sizes = small_set(5_001)
    assert sum(D.staging_tokens(n) for n in sizes) == 5_001 + 14  # a ~0.9 MB manifest
    assert stage_all(d, sizes) == 5_002
    d.buckets.clear()
    full = [C.PAGE_CAP] * 15 + [C.PAGE_CAP - 4096, 4096]  # 64 MiB with its manifest
    assert sum(full) == C.STAGE_CAP and sum(D.staging_tokens(n) for n in full) == 1_025
    assert stage_all(d, full) == 17
    d.buckets.clear()
    largest = [300] * D.MANIFEST_PAGES + [C.PAGE_CAP]  # 27,776 pages and a full manifest
    assert stage_all(d, largest) == D.MANIFEST_PAGES + 1
    assert stage_all(d, [10] * 961) == 961  # 28,801 - 27,776 - 64 left, exactly
    with pytest.raises(Refusal):
        stage_all(d, [10])
    stage_all(d, [1], ws=OTHER)  # another workspace is unaffected


def test_staging_flood_is_cut_off_and_refills_at_ten_a_second(client):
    from orch_relay import checkpoints as C

    d = client.app.state.directory
    session = {"kind": "workspace", "subject_id": WS, "token_hash": "t"}
    served = 0
    with pytest.raises(Refusal) as refused:
        while True:
            stage_all(d, [10])
            served += 1
    assert served == D.STAGING_BURST == 28_801
    assert refused.value.retry == 1  # 600 per minute: one token per 100 ms
    assert stage_all(d, [10] * 60, NOW + 6_000) == 60  # exactly 60 back after 6 s
    with pytest.raises(Refusal):
        stage_all(d, [10], NOW + 6_000)
    # A flood of identical 4 MiB re-PUTs is cut off at 450 (28,801 // 64), then one per 6.4 s.
    d.buckets.clear()
    served = 0
    with pytest.raises(Refusal) as refused:
        while True:
            stage_all(d, [C.PAGE_CAP])
            served += 1
    assert served == 450 and refused.value.retry == 7  # 64 - 1 tokens missing at 10/s
    assert stage_all(d, [C.PAGE_CAP], NOW + 6_300) == 1
    # A full burst is back after 28,801 / 600 min (about 48 min), never beyond the burst.
    later = NOW + 6_300 + 28_801 * 100
    assert d.buckets.table[("staging", WS)][0] < D.STAGING_BURST * Buckets.UNIT
    d.throttle(session, later, "staging", WS, cost=D.STAGING_BURST)
    with pytest.raises(Refusal):
        d.throttle(session, later + 10_000_000, "staging", WS, cost=D.STAGING_BURST + 1)


def test_staging_puts_are_weighted_by_body_size(client):
    """The HTTP route charges one token per started 64 KiB of the body it read, at least one."""
    d = client.app.state.directory
    limit(client, staging=(70, 60))
    host = {**HOST, "Orch-Holder": "1", "Content-Type": "application/json"}
    base = f"/v2/workspaces/{WS}/staging/null/sha256:{'1' * 64}"

    def level():
        return d.buckets.table[("staging", WS)][0] // Buckets.UNIT

    client.put(f"{base}/pages/0", content=b"{}", headers=host)
    assert level() == 69
    client.put(f"{base}/pages/1", content=b" " * 65_536 + b"{}", headers=host)  # 65,538 bytes
    assert level() == 67
    client.put(f"{base}/manifest", content=b" " * (4 * 65_536), headers=host)
    assert level() == 63
    r = client.put(f"{base}/pages/2", content=b" " * (64 * 65_536), headers=host)  # 64 tokens
    assert (r.status_code, r.json()["error"]) == (429, "rate_limited")
    assert level() == 63  # a refusal charges nothing of the staging bucket


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
    # The refused read charged neither window (both are checked before either is charged).
    windows = client.app.state.directory.windows
    assert ("revocation-read", "2001:db8:0:4::/64", D.MINUTE) not in windows
    assert windows[("revocation-read-parent", "2001:db8::/56", D.MINUTE)][1] == 3


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
    # Only pair polls count against the pair share.
    polls[("device", "y")] = B.PAIR_POLL_CEILING + 10
    client.app.state.bridge.admit(("pair", "192.0.2.77"))
    client.app.state.bridge.release(("pair", "192.0.2.77"))
    polls[("device", "y")] = B.POLL_CEILING
    with pytest.raises(Refusal) as refused:
        client.app.state.bridge.admit(("device", DEVICE))
    assert refused.value.code == "overloaded"
    polls.clear()
