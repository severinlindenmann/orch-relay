"""Protocol §19.3 bridge regressions against the real HTTP application."""

import json
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path

import pytest
from bridge_support import CRID, HOST, OBJECTS, RID, binary
from directory_support import CERT, DEVICE, NOW, PERSON, PRIMARY, RECORD, WS, V, seed, signed
from fastapi.testclient import TestClient

from orch_relay import db
from orch_relay import proto as P
from orch_relay.app import create_app
from orch_relay.directory import token_hash


@pytest.fixture
def client(tmp_path):
    with TestClient(create_app(tmp_path)) as client:
        seed(client.app.state.directory)
        yield client


def fixture_request(name):
    return json.loads(Path(f"tests/http_fixtures/{name}.json").read_text())["cases"][0]["request"]


def post_fixture(client, name):
    r = fixture_request(name)
    return client.post(r["path"], content=P.unb64u(r["body_b64u"]), headers=r["headers"])


def test_replay_coalesces(client):
    assert post_fixture(client, "bridge_device_post").status_code == 202
    assert post_fixture(client, "bridge_device_post").status_code == 202
    r = client.get(
        f"/v2/workspaces/{WS}/host/poll",
        headers={"Authorization": "Bearer FAKE-workspace", "Orch-Holder": "1"},
    )
    assert r.status_code == 200
    assert len(r.json()["items"]) == 1


def test_fence_hold_conflict(client):
    r = client.post(
        f"/v2/workspaces/{WS}/host/hold",
        json={"gen": None, "take_over": False},
        headers={"Authorization": "Bearer FAKE-workspace"},
    )
    assert r.status_code == 409
    assert r.json() == {"error": "holder_conflict"}


def sql(client, statement, args=()):
    with closing(db.connect(client.app.state.directory.path)) as con, con:
        return con.execute(statement, args).fetchall()


def host_poll(client, **query):
    return client.get(f"/v2/workspaces/{WS}/host/poll", params=query, headers=HOST)


def post_raw(client, raw, host=False, rid=RID):
    return client.post(
        f"/v2/workspaces/{WS}/bridge/{rid}",
        content=raw,
        headers={
            **(HOST if host else {"Authorization": "Bearer FAKE-device"}),
            "Content-Type": "application/octet-stream",
        },
    )


def advance(client, ms):
    client.app.state.directory.clock = lambda: NOW + ms
    sql(client, "UPDATE holders SET lease_until_ms=?", (NOW + ms + 40000,))
    sql(client, "UPDATE sessions SET expires_ms=?", (NOW + ms + 900000,))


def test_replay_ttl_conflict_and_response_nonconsuming(client):
    assert post_raw(client, binary("bridge_device_post")).status_code == 202
    assert post_raw(client, binary("bridge_host_post"), True).status_code == 202
    before = sql(client, "SELECT n,expires_ms FROM bridge_msgs")
    advance(client, 10000)
    assert post_raw(client, binary("bridge_device_post")).status_code == 202
    assert post_raw(client, binary("bridge_host_post"), True).status_code == 202
    assert sql(client, "SELECT n,expires_ms FROM bridge_msgs") == before
    assert post_raw(client, binary("bridge_device_post")[:-1] + b"X").json() == {
        "error": "rid_conflict"
    }
    url = f"/v2/workspaces/{WS}/bridge/{RID}"
    headers = {"Authorization": "Bearer FAKE-device"}
    first = client.get(url, headers=headers)
    assert len(first.json()["chunks"]) == 1
    assert client.get(url, headers=headers).json() == first.json()
    assert client.get(url, headers=headers, params={"after": 0}).json() == {"chunks": []}
    assert sql(client, "SELECT pending FROM queue_totals WHERE direction=2") == [(0,)]
    advance(client, 60000)
    assert post_raw(client, binary("bridge_host_post"), True).status_code == 202
    assert client.get(url, headers=headers).json() == {"chunks": []}


def test_replay_requeue_interval_exhaustion_and_retention(client):
    raw = binary("bridge_device_post")
    assert post_raw(client, raw).status_code == 202
    n = host_poll(client).json()["items"][0]["n"]
    assert host_poll(client, after=n).status_code == 200
    retry = post_raw(client, raw)
    assert retry.status_code == 429 and retry.headers["retry-after"] == "10"
    for i in range(1, 9):
        advance(client, i * 10000)
        assert post_raw(client, raw).status_code == 202
        n = host_poll(client).json()["items"][0]["n"]
        host_poll(client, after=n)
    assert post_raw(client, raw).json() == {"error": "retry_exhausted"}
    assert sql(client, "SELECT first_ms,keep_until_ms FROM rid_seen") == [(NOW, NOW + 900000)]


def test_fence_host_write_takeover_and_cursor_never_rewinds(client):
    assert post_raw(client, binary("bridge_device_post")).status_code == 202
    n = host_poll(client).json()["items"][0]["n"]
    assert host_poll(client, after=n + 1).status_code == 400
    host_poll(client, after=n)
    assert host_poll(client, after=0).json()["items"] == []
    assert sql(client, "SELECT cursor FROM holders") == [(n,)]
    r = client.post(
        f"/v2/workspaces/{WS}/host/hold", json={"gen": None, "take_over": True}, headers=HOST
    )
    assert r.json() == {"gen": 2, "lease_s": 40, "cursor": n}
    assert post_raw(client, binary("bridge_host_post"), True).json() == {"error": "fenced"}
    assert host_poll(client).json() == {"error": "fenced"}


def test_old_epoch_only_refusal_or_stored_replay(client):
    assert post_raw(client, binary("bridge_device_post")).status_code == 202
    sql(client, "UPDATE member_lists SET epoch=2")
    assert post_raw(client, binary("bridge_host_post"), True).json()["error"] == "stale_epoch"
    refusal = bytearray(binary("bridge_host_post"))
    refusal[6] = 7
    assert post_raw(client, bytes(refusal), True).status_code == 202
    assert post_raw(client, bytes(refusal), True).status_code == 202
    assert post_raw(client, binary("bridge_host_post"), True).json()["error"] == "chunk_conflict"
    sql(client, "DELETE FROM rid_seen")
    assert post_raw(client, bytes(refusal), True).status_code == 410


def setup_pair_queue(client, challenge=None):
    sql(
        client,
        "INSERT INTO sessions VALUES (?,?,?,?)",
        (token_hash("FAKE-primary"), "device", PRIMARY, NOW + 900000),
    )
    assert (
        client.post(
            f"/v2/persons/{PERSON}/cert-requests",
            json={"request": OBJECTS["request"]},
            headers=HOST,
        ).status_code
        == 200
    )
    r = client.post(
        f"/v2/cert-requests/{CRID}/challenge",
        json={"challenge": challenge or OBJECTS["challenge"]},
        headers={"Authorization": "Bearer FAKE-primary"},
    )
    assert r.status_code == 200, r.text


def test_pair_completion_requires_both_keys_and_certificate_retry(client):
    challenge = signed(
        {**OBJECTS["challenge"]["o"], "dk_kx_pub": V["certs"]["signed"]["laptop"]["o"]["dk_kx_pub"]}
    )
    setup_pair_queue(client, challenge)
    sql(client, "DELETE FROM devices WHERE device_id=?", (DEVICE,))
    cert = OBJECTS["cert"]
    assert client.put(f"/v2/devices/{DEVICE}", json={"cert": cert}).status_code == 200
    assert sql(client, "SELECT state FROM cert_requests") == [("challenged",)]
    # A matching certificate's exact recovery receipt must still complete a later request.
    sql(client, "UPDATE cert_requests SET challenge=?", (P.cj(OBJECTS["challenge"]),))
    assert client.put(f"/v2/devices/{DEVICE}", json={"cert": cert}).status_code == 200
    assert sql(client, "SELECT state FROM cert_requests") == [("signed",)]
    r = client.post(
        f"/v2/cert-requests/{CRID}/rejection",
        json={"rejection": OBJECTS["cert_rejection"]},
        headers={"Authorization": "Bearer FAKE-primary"},
    )
    assert r.status_code == 409 and r.json()["error"] == "already_signed"


def test_pair_primary_session_rejection_and_expiry(client):
    setup_pair_queue(client)
    url = f"/v2/cert-requests/{CRID}/rejection"
    body = {"rejection": OBJECTS["cert_rejection"]}
    assert (
        client.post(url, json=body, headers={"Authorization": "Bearer FAKE-device"}).status_code
        == 403
    )
    assert client.post(url, json=body).status_code == 401
    assert (
        client.post(url, json=body, headers={"Authorization": "Bearer FAKE-primary"}).status_code
        == 200
    )
    resigned = {"rejection": signed(OBJECTS["cert_rejection"]["o"])}
    assert (
        client.post(
            url, json=resigned, headers={"Authorization": "Bearer FAKE-primary"}
        ).status_code
        == 200
    )
    assert client.put(f"/v2/devices/{DEVICE}", json={"cert": CERT}).status_code == 200
    assert sql(client, "SELECT state FROM cert_requests") == [("rejected",)]
    advance(client, 660000)
    assert client.get(f"/v2/cert-requests/{CRID}", headers=HOST).status_code == 404


@pytest.mark.parametrize("offset,expected", [(599999, "signed"), (600000, "expired")])
def test_pair_completion_expiry_boundary(client, offset, expected):
    setup_pair_queue(client)
    advance(client, offset)
    assert client.put(f"/v2/devices/{DEVICE}", json={"cert": CERT}).status_code == 200
    assert client.get(f"/v2/cert-requests/{CRID}", headers=HOST).json()["state"] == expected


def test_budget_responses_released_on_delivery_and_revocation(client):
    assert post_raw(client, binary("bridge_device_post")).status_code == 202
    raw = binary("bridge_host_post") + bytes(256 * 1024 - len(binary("bridge_host_post")))
    for i in range(8):
        chunk = bytearray(raw)
        chunk[72:80] = i.to_bytes(8, "big")
        assert post_raw(client, bytes(chunk), True).status_code == 202
    chunk[72:80] = (8).to_bytes(8, "big")
    assert post_raw(client, bytes(chunk), True).json() == {"error": "quota_exceeded"}
    r = client.get(
        f"/v2/workspaces/{WS}/bridge/{RID}", headers={"Authorization": "Bearer FAKE-device"}
    )
    assert len(r.json()["chunks"]) == 8
    assert post_raw(client, bytes(chunk), True).status_code == 202
    assert client.post("/v2/revocations", json={"record": RECORD}).status_code == 200
    assert sql(client, "SELECT * FROM queue_totals") == []
    assert sql(client, "SELECT count(*) FROM rid_seen") == [(1,)]


def test_budget_chunk_digest_boundary(client):
    assert post_raw(client, binary("bridge_device_post")).status_code == 202
    for i in range(65):
        advance(client, i * 1000)
        raw = bytearray(binary("bridge_host_post"))
        raw[72:80] = i.to_bytes(8, "big")
        r = post_raw(client, bytes(raw), True)
        assert r.status_code == (202 if i < 64 else 429)
    assert sql(client, "SELECT count(*) FROM rid_chunks") == [(64,)]


def test_pair_ipv6_parent_caps(client):
    bridge = client.app.state.bridge
    d = client.app.state.directory
    url = request = fixture_request("pair_device_post")
    params = {"ws": WS, "offer": url["path"].split("/")[-2], "rid": RID}
    from orch_relay.directory import Refusal

    for method, cap in (("GET", 960), ("POST", 480)):
        d.windows[("pair-" + method, "2001:db8::/56", 60000)] = (NOW + 60000, cap)
        with pytest.raises(Refusal) as error:
            bridge.transaction(
                "pair",
                params,
                method,
                P.unb64u(request["body_b64u"]) if method == "POST" else b"",
                {},
                {},
                "2001:db8:0:23::1",
                "token",
                True,
            )
        assert error.value.code == "rate_limited"


def wait_poll_started(client):
    deadline = time.monotonic() + 3
    while not sql(client, "SELECT poll_token FROM holders")[0][0]:
        assert time.monotonic() < deadline
        time.sleep(0.01)


@pytest.mark.slow
def test_fence_replaced_poll_empty_and_takeover_wakeup(client):
    with ThreadPoolExecutor() as pool:
        first = pool.submit(host_poll, client, wait=3)
        wait_poll_started(client)
        assert host_poll(client).status_code == 200
        assert first.result(timeout=2).json()["items"] == []
        sql(client, "UPDATE holders SET poll_token=NULL")
        second = pool.submit(host_poll, client, wait=3)
        wait_poll_started(client)
        client.post(
            f"/v2/workspaces/{WS}/host/hold", headers=HOST, json={"gen": None, "take_over": True}
        )
        assert second.result(timeout=2).json() == {"error": "fenced"}


@pytest.mark.slow
def test_poll_reauthorizes_device_after_revoke(client):
    with ThreadPoolExecutor() as pool:
        pending = pool.submit(
            client.get,
            f"/v2/workspaces/{WS}/bridge/{RID}",
            headers={"Authorization": "Bearer FAKE-device"},
            params={"wait": 3},
        )
        deadline = time.monotonic() + 2
        while not client.app.state.bridge.polls:
            assert time.monotonic() < deadline
            time.sleep(0.01)
        assert client.post("/v2/revocations", json={"record": RECORD}).status_code == 200
        assert pending.result(timeout=2).status_code == 401
    assert client.app.state.bridge.polls == {}


@pytest.mark.parametrize(
    "direction,device_bytes,workspace_bytes,global_bytes,expected",
    [
        (1, 8 * 1024 * 1024, 0, 0, "quota_exceeded"),
        (1, 0, 16 * 1024 * 1024, 0, "quota_exceeded"),
        (2, 2 * 1024 * 1024, 0, 0, "quota_exceeded"),
        (2, 0, 16 * 1024 * 1024, 0, "quota_exceeded"),
        (1, 0, 0, 256 * 1024 * 1024, "overloaded"),
    ],
)
def test_budget_persisted_totals_no_eviction(
    client, direction, device_bytes, workspace_bytes, global_bytes, expected
):
    import sqlite3

    from orch_relay.directory import Refusal

    with closing(db.connect(client.app.state.directory.path)) as con, con:
        con.row_factory = sqlite3.Row
        for ws, device, amount in (
            ("other-workspace", DEVICE, device_bytes),
            (WS, "other-device", workspace_bytes),
            ("global-workspace", "global-device", global_bytes),
        ):
            if amount:
                con.execute(
                    "INSERT INTO queue_totals VALUES (?,?,?,?,?,1)",
                    (ws, device, direction, amount, amount),
                )
        before = list(con.execute("SELECT * FROM queue_totals"))
        with pytest.raises(Refusal) as error:
            client.app.state.bridge.budget(con, WS, DEVICE, direction, 1)
        assert error.value.code == expected
        assert list(con.execute("SELECT * FROM queue_totals")) == before


def test_budget_mailbox_and_replay_record_caps(client):
    with closing(db.connect(client.app.state.directory.path)) as con, con:
        con.executemany(
            "INSERT INTO request_mailboxes VALUES (?,?,?,?)",
            ((WS, DEVICE, f"{i:032x}", NOW + 60000) for i in range(128)),
        )
    assert post_raw(client, binary("bridge_device_post")).json() == {"error": "quota_exceeded"}
    assert sql(client, "SELECT count(*) FROM request_mailboxes") == [(128,)]
    sql(client, "DELETE FROM request_mailboxes")
    with closing(db.connect(client.app.state.directory.path)) as con, con:
        con.executemany(
            "INSERT INTO rid_seen VALUES (?,?,?,'digest',1,?,0,?,?,NULL)",
            ((WS, DEVICE, f"{i:032x}", NOW, NOW, NOW + 900000) for i in range(4096)),
        )
    assert post_raw(client, binary("bridge_device_post")).json() == {"error": "quota_exceeded"}
    assert sql(client, "SELECT count(*) FROM rid_seen") == [(4096,)]


def test_budget_rejected_poll_does_not_release_another_slot(client):
    bridge = client.app.state.bridge
    bridge.polls[("device", DEVICE)] = 6
    r = client.get(
        f"/v2/workspaces/{WS}/bridge/{RID}",
        headers={"Authorization": "Bearer FAKE-device"},
        params={"wait": 1},
    )
    assert r.status_code == 429
    assert bridge.polls[("device", DEVICE)] == 6
    bridge.polls.clear()


def test_pair_request_lifetime_and_person_limit(client):
    from bridge_support import insert_queue, queue_entry

    with closing(db.connect(client.app.state.directory.path)) as con, con:
        for i in range(64):
            entry = queue_entry()
            entry = json.loads(P.cj(entry))
            entry["request"]["o"].update(request_id=f"{i:032x}", workspace_id=f"{i:032x}")
            insert_queue(con, entry)
    r = client.post(
        f"/v2/persons/{PERSON}/cert-requests", json={"request": OBJECTS["request"]}, headers=HOST
    )
    assert r.status_code == 429
    assert sql(client, "SELECT count(*) FROM cert_requests") == [(64,)]
    advance(client, 600000)
    fresh = signed(
        {**OBJECTS["request"]["o"], "created_ms": NOW + 600000, "expires_ms": NOW + 1200000},
        "wsk_a.sig",
    )
    assert (
        client.post(
            f"/v2/persons/{PERSON}/cert-requests", json={"request": fresh}, headers=HOST
        ).status_code
        == 200
    )


def test_sweep_releases_expired_bytes_preserves_replay(client):
    assert post_raw(client, binary("bridge_device_post")).status_code == 202
    advance(client, 60000)
    client.app.state.bridge.sweep()
    assert sql(client, "SELECT * FROM queue_totals") == []
    assert sql(client, "SELECT count(*) FROM rid_seen") == [(1,)]


def test_fence_host_poll_pagination_does_not_ack(client):
    for i in range(17):
        raw = bytearray(binary("bridge_device_post"))
        rid = f"{i:032x}"
        raw[40:56] = bytes.fromhex(rid)
        assert post_raw(client, bytes(raw), rid=rid).status_code == 202
    first = host_poll(client).json()
    assert len(first["items"]) == 16 and first["next"]
    second = host_poll(client, next=first["next"], after=0).json()
    assert len(second["items"]) == 1
    assert sql(client, "SELECT cursor FROM holders") == [(0,)]
    assert host_poll(client, after=0).json() == first
    assert host_poll(client, after=1, next=first["next"]).status_code == 400


def test_fence_new_holder_must_receive_before_ack(client):
    assert post_raw(client, binary("bridge_device_post")).status_code == 202
    n = host_poll(client).json()["items"][0]["n"]
    hold = client.post(
        f"/v2/workspaces/{WS}/host/hold", json={"gen": None, "take_over": True}, headers=HOST
    )
    new_headers = {**HOST, "Orch-Holder": str(hold.json()["gen"])}
    assert (
        client.get(
            f"/v2/workspaces/{WS}/host/poll", params={"after": n}, headers=new_headers
        ).status_code
        == 400
    )
    r = client.get(f"/v2/workspaces/{WS}/host/poll", headers=new_headers)
    assert r.json()["items"][0]["n"] == n


def test_budget_request_capacity_released_by_ack(client):
    assert post_raw(client, binary("bridge_device_post")).status_code == 202
    n = host_poll(client).json()["items"][0]["n"]
    host_poll(client, after=n)
    pending, count, bodies = sql(client, "SELECT pending,count,bodies FROM queue_totals")[0]
    assert pending == count == 0
    assert bodies == len(binary("bridge_device_post"))
    advance(client, 60000)
    client.app.state.bridge.sweep()
    assert sql(client, "SELECT * FROM queue_totals") == []


def test_host_poll_whole_json_budget(client):
    for i in range(4):
        raw = bytearray(binary("bridge_device_post"))
        rid = f"{i:032x}"
        raw[40:56] = bytes.fromhex(rid)
        raw.extend(bytes(1024 * 1024 - len(raw)))
        assert post_raw(client, bytes(raw), rid=rid).status_code == 202
    response = host_poll(client)
    assert len(response.content) <= 4 * 1024 * 1024
    assert response.json()["next"]


@pytest.mark.parametrize(
    "path,headers",
    [
        (f"/v2/workspaces/{WS}/host/poll", HOST),
        (f"/v2/workspaces/{WS}/bridge/{RID}", {"Authorization": "Bearer FAKE-device"}),
        (f"/v2/workspaces/{WS}/pair/{CRID}/{RID}", {}),
        (f"/v2/persons/{PERSON}/cert-requests", {"Authorization": "Bearer FAKE-device"}),
    ],
)
def test_long_poll_wait_releases_lock_and_transaction(client, monkeypatch, path, headers):
    directory = client.app.state.directory
    original = directory.assert_can_wait
    calls = []

    def check_lock_from_another_thread():
        acquired = directory.lock.acquire(timeout=0.5)
        assert acquired, "long poll retained the directory lock"
        directory.lock.release()

    def check_wait():
        original()
        # Also detect a lock retained by the transaction's worker thread.
        with ThreadPoolExecutor(max_workers=1) as pool:
            pool.submit(check_lock_from_another_thread).result(timeout=1)
        with closing(db.connect(directory.path)) as con:
            con.execute("PRAGMA busy_timeout=0")
            con.execute("BEGIN IMMEDIATE")
            con.rollback()
        calls.append(True)

    monkeypatch.setattr(directory, "assert_can_wait", check_wait)
    response = client.get(path, headers=headers, params={"wait": 1})
    assert response.status_code == 200
    assert calls, "long poll must check wait safety before sleeping"
    assert client.app.state.bridge.polls == {}


def forged_pair(client, ws, rid=RID, size=65536):
    raw = bytearray(binary("pair_device_post"))
    raw[8:24] = bytes.fromhex(ws)
    raw[24:40] = bytes.fromhex(DEVICE)
    raw[40:56] = bytes.fromhex(rid)
    raw[-64:] = bytes(64)  # No victim signature or credentials.
    raw.extend(bytes(size - len(raw)))
    return client.post(
        f"/v2/workspaces/{ws}/pair/{raw[56:72].hex()}/{rid}",
        content=bytes(raw),
        headers={"Content-Type": "application/octet-stream"},
    )


def other_pair_workspace(client):
    other = V["ids"]["workspace_b"]
    sql(
        client,
        "INSERT INTO workspaces SELECT ?,owner_person_id,wsk_pub,delegation,card,card_seq,"
        "wxk_version,client_hosted FROM workspaces WHERE workspace_id=?",
        (other, WS),
    )
    return other


def test_pair_forged_device_rate_isolation(client):
    other = other_pair_workspace(client)
    windows = client.app.state.directory.windows
    # Distinct rids: identical resends are free, so each post must be new work.
    for i in range(20):
        assert forged_pair(client, other, rid=f"{i:032x}").status_code == 202
    assert ("bridge-post", DEVICE, 1000) not in windows
    assert post_raw(client, binary("bridge_device_post")).status_code == 202
    assert windows[("bridge-post", DEVICE, 1000)][1] == 1
    # Anonymous posts still exhaust the workspace/address pairing limit.
    for i in range(20, 60):
        assert forged_pair(client, other, rid=f"{i:032x}").status_code == 202
    response = forged_pair(client, other)
    assert response.status_code == 429
    assert response.json() == {"error": "rate_limited"}


@pytest.mark.parametrize("direction", [1, 2])
def test_pair_forged_device_storage_isolation(client, direction):
    other = other_pair_workspace(client)
    assert forged_pair(client, other).status_code == 202
    if direction == 2:
        # A workspace response to the forged device must also remain pairing state.
        sql(client, "INSERT INTO holders VALUES (?,1,?,0,NULL)", (other, NOW + 40000))
        sql(
            client,
            "INSERT INTO sessions VALUES (?,?,?,?)",
            (token_hash("FAKE-other-workspace"), "workspace", other, NOW + 900000),
        )
        raw = bytearray(binary("pair_host_post"))
        raw[8:24] = bytes.fromhex(other)
        raw[24:40] = bytes.fromhex(DEVICE)
        response = client.post(
            f"/v2/workspaces/{other}/pair/{raw[56:72].hex()}/{RID}",
            content=bytes(raw),
            headers={
                "Authorization": "Bearer FAKE-other-workspace",
                "Orch-Holder": "1",
                "Content-Type": "application/octet-stream",
            },
        )
        assert response.status_code == 202
        sql(client, "DELETE FROM bridge_msgs WHERE workspace_id=? AND direction=1", (other,))
    assert sql(client, "SELECT device_id FROM queue_totals WHERE workspace_id=?", (other,)) == [
        ("",)
    ]
    # Fill authenticated storage exactly to its boundary after the next request.
    raw = binary("bridge_device_post" if direction == 1 else "bridge_host_post")
    cap = (8 if direction == 1 else 2) * 1024 * 1024
    sql(
        client,
        "INSERT INTO queue_totals VALUES (?,?,?,?,?,1)",
        (WS, DEVICE, direction, cap - len(raw), cap - len(raw)),
    )
    if direction == 2:
        assert post_raw(client, binary("bridge_device_post")).status_code == 202
    assert post_raw(client, raw, host=direction == 2).status_code == 202
    # Delivery and deletion use the same anonymous accounting key.
    sql(client, "UPDATE bridge_msgs SET delivered=1 WHERE workspace_id=?", (other,))
    assert sql(client, "SELECT pending,count FROM queue_totals WHERE workspace_id=?", (other,)) == [
        (0, 0)
    ]
    sql(client, "DELETE FROM bridge_msgs WHERE workspace_id=?", (other,))
    assert sql(client, "SELECT * FROM queue_totals WHERE workspace_id=?", (other,)) == []


def test_pair_forged_device_replay_isolation_and_bound(client):
    other = other_pair_workspace(client)
    assert forged_pair(client, other).status_code == 202
    with closing(db.connect(client.app.state.directory.path)) as con, con:
        con.executemany(
            "INSERT INTO rid_seen VALUES (?,?,?,'digest',0,?,0,?,?,?)",
            ((other, DEVICE, f"{i:032x}", NOW, NOW, NOW + 900000, CRID) for i in range(4095)),
        )
    assert post_raw(client, binary("bridge_device_post")).status_code == 202
    r = forged_pair(client, other, rid="ab" * 16)
    assert r.status_code == 429 and r.json() == {"error": "quota_exceeded"}


def test_pair_mailboxes_do_not_charge_device_and_are_bounded(client):
    with closing(db.connect(client.app.state.directory.path)) as con, con:
        for i in range(128):
            rid = f"{i:032x}"
            con.execute(
                "INSERT INTO rid_seen VALUES (?,?,?,'digest',0,?,0,?,?,?)",
                (WS, DEVICE, rid, NOW, NOW, NOW + 900000, CRID),
            )
            con.execute(
                "INSERT INTO request_mailboxes VALUES (?,?,?,?)", (WS, DEVICE, rid, NOW + 60000)
            )
    assert post_raw(client, binary("bridge_device_post")).status_code == 202
    r = forged_pair(client, WS, rid="ab" * 16)
    assert r.status_code == 429 and r.json() == {"error": "quota_exceeded"}


def test_pair_accounting_migrates_retained_bodies(tmp_path):
    from bridge_support import queue_body

    migrations = Path("src/orch_relay/migrations")
    legacy = tmp_path / "legacy"
    legacy.mkdir()
    for source in sorted(migrations.glob("*.sql")):
        if source.name < "0005":
            (legacy / source.name).write_bytes(source.read_bytes())
    path = tmp_path / "old.sqlite3"
    db.migrate(path, legacy)
    with closing(db.connect(path)) as con, con:
        queue_body(con, binary("pair_device_post"))
        queue_body(con, binary("bridge_device_post"))
    assert db.migrate(path) == ["0005_pair_accounting", "0006_holder_notices"]
    with closing(db.connect(path)) as con:
        rows = con.execute(
            "SELECT device_id,pending,count FROM queue_totals ORDER BY device_id"
        ).fetchall()
    assert rows == [
        ("", len(binary("pair_device_post")), 1),
        (DEVICE, len(binary("bridge_device_post")), 1),
    ]


@pytest.mark.parametrize("resign", [False, True])
@pytest.mark.parametrize("state", ["challenged", "signed", "rejected"])
@pytest.mark.parametrize("offset", [599999, 600000, 600001])
def test_challenge_retry_expiry_and_retained_terminals(client, resign, state, offset):
    setup_pair_queue(client)
    if state == "signed":
        assert client.put(f"/v2/devices/{DEVICE}", json={"cert": CERT}).status_code == 200
    elif state == "rejected":
        assert (
            client.post(
                f"/v2/cert-requests/{CRID}/rejection",
                json={"rejection": OBJECTS["cert_rejection"]},
                headers={"Authorization": "Bearer FAKE-primary"},
            ).status_code
            == 200
        )
    before = sql(client, "SELECT * FROM cert_requests")[0]
    advance(client, offset)
    challenge = signed(OBJECTS["challenge"]["o"]) if resign else OBJECTS["challenge"]
    if resign:
        assert challenge["sig"] != OBJECTS["challenge"]["sig"]
    response = client.post(
        f"/v2/cert-requests/{CRID}/challenge",
        json={"challenge": challenge},
        headers={"Authorization": "Bearer FAKE-primary"},
    )
    expired = state == "challenged" and offset >= 600000
    assert response.status_code == (410 if expired else 200)
    assert response.json() == ({"error": "expired"} if expired else {})
    # A refused POST rolls back its sweep; GET commits only the expiry transition.
    assert sql(client, "SELECT * FROM cert_requests")[0] == before
    fetched = client.get(f"/v2/cert-requests/{CRID}", headers=HOST)
    assert fetched.status_code == 200
    assert fetched.json()["state"] == ("expired" if expired else state)
    after = sql(client, "SELECT * FROM cert_requests")[0]
    expected = list(before)
    if expired:
        expected[6] = "expired"
    assert after == tuple(expected)
    # Also reject retries after expiry has been persisted by GET/maintenance.
    again = client.post(
        f"/v2/cert-requests/{CRID}/challenge",
        json={"challenge": challenge},
        headers={"Authorization": "Bearer FAKE-primary"},
    )
    assert again.status_code == response.status_code
    assert sql(client, "SELECT * FROM cert_requests")[0] == after


def test_host_poll_skips_request_whose_device_certificate_expired(client):
    # Revocation and departure prune queued rows; only certificate expiry reaches handoff.
    sql(client, "UPDATE devices SET expires_ms=? WHERE device_id=?", (NOW + 5000, DEVICE))
    assert post_raw(client, binary("bridge_device_post")).status_code == 202
    advance(client, 10000)
    r = host_poll(client)
    assert r.status_code == 200
    assert r.json()["items"] == []


def test_device_mailbox_reads_only_own_response_chunks(client):
    assert post_raw(client, binary("bridge_device_post")).status_code == 202
    assert post_raw(client, binary("bridge_host_post"), True).status_code == 202
    sql(client, "INSERT INTO members VALUES (?,?,?,?)", (WS, PRIMARY, PERSON, P.cj(["look"])))
    sql(
        client,
        "INSERT INTO sessions VALUES (?,?,?,?)",
        (token_hash("FAKE-primary"), "device", PRIMARY, NOW + 900000),
    )
    url = f"/v2/workspaces/{WS}/bridge/{RID}"
    other = client.get(url, headers={"Authorization": "Bearer FAKE-primary"})
    assert other.status_code == 200
    assert other.json() == {"chunks": []}
    own = client.get(url, headers={"Authorization": "Bearer FAKE-device"})
    assert len(own.json()["chunks"]) == 1


def post_cert_request(client):
    return client.post(
        f"/v2/persons/{PERSON}/cert-requests", json={"request": OBJECTS["request"]}, headers=HOST
    )


def test_cert_request_to_revoked_primary_rejected(client):
    sql(
        client,
        "INSERT INTO revocations VALUES (?,?,?,?,?,?)",
        (PRIMARY, PERSON, P.cj(RECORD), "lost", NOW, 1),
    )
    r = post_cert_request(client)
    assert r.status_code == 403 and r.json() == {"error": "revoked"}
    assert sql(client, "SELECT count(*) FROM cert_requests") == [(0,)]


def test_cert_request_to_drop_scoped_primary_rejected(client):
    sql(
        client,
        "UPDATE devices SET scopes_max=? WHERE device_id=?",
        (P.cj(["drop:" + WS]), PRIMARY),
    )
    r = post_cert_request(client)
    assert r.status_code == 403 and r.json() == {"error": "not_for_this_device"}
    assert sql(client, "SELECT count(*) FROM cert_requests") == [(0,)]


def test_identical_resends_do_not_spend_post_rate(client):
    windows = client.app.state.directory.windows
    assert post_raw(client, binary("bridge_device_post")).status_code == 202
    assert post_raw(client, binary("bridge_host_post"), True).status_code == 202
    windows[("bridge-post", DEVICE, 1000)] = (NOW + 1000, 20)
    # A coalesced request resend and a stored chunk replay are free.
    assert post_raw(client, binary("bridge_device_post")).status_code == 202
    assert post_raw(client, binary("bridge_host_post"), True).status_code == 202
    assert windows[("bridge-post", DEVICE, 1000)] == (NOW + 1000, 20)
    # New work is still charged.
    fresh = bytearray(binary("bridge_device_post"))
    fresh[40:56] = bytes.fromhex("ab" * 16)
    r = post_raw(client, bytes(fresh), rid="ab" * 16)
    assert r.status_code == 429 and r.json() == {"error": "rate_limited"}
    new = bytearray(binary("bridge_host_post"))
    new[72:80] = (1).to_bytes(8, "big")
    r = post_raw(client, bytes(new), True)
    assert r.status_code == 429 and r.json() == {"error": "rate_limited"}
