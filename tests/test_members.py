"""Membership transactions through the HTTP boundary."""

import copy
from contextlib import closing

import pytest
from directory_support import DEVICE, NOW, PERSON, RECORD, WS, V, seed, signed
from fastapi.testclient import TestClient
from members_support import BODY, HEADERS, holder, load_state, snapshot

from orch_relay import db
from orch_relay import proto as P
from orch_relay.app import create_app
from orch_relay.directory import DAY


def test_members_route(tmp_path):
    with TestClient(create_app(tmp_path)) as client:
        seed(client.app.state.directory)
        response = client.get(
            f"/v2/workspaces/{WS}/members",
            headers={"Authorization": "Bearer FAKE-workspace"},
        )
        assert response.status_code == 200
        assert response.json() == {"member_list": {}}


def put(client, body):
    return client.put(f"/v2/workspaces/{WS}/membership", content=P.cj(body), headers=HEADERS)


def changed(body=BODY, **updates):
    out = copy.deepcopy(body)
    out["member_list"] = signed({**out["member_list"]["o"], **updates}, "wsk_a.sig")
    if "epoch" in updates:
        out["grants"] = [
            signed({**g["o"], "epoch": updates["epoch"]}, "wsk_a.sig") for g in out["grants"]
        ]
    return out


CASES = [c for c in V["p3"]["cases"] if c["op"] == "membership"]


@pytest.mark.parametrize("case", CASES, ids=lambda c: c["name"])
def test_p3_membership(tmp_path, case):
    a = case["args"]
    with TestClient(create_app(tmp_path)) as c:
        d = c.app.state.directory
        load_state(d, case["state"], a["directory"], a["now_ms"])
        before = snapshot(d)
        raw = a.get("body_raw", P.cj(a["body"]))
        r = c.put(f"/v2/workspaces/{WS}/membership", content=raw, headers=HEADERS)
        expected = case["expect"]["result"]
        assert (
            {"ok": r.json()} if r.status_code == 200 else {"refuse": r.json()["error"]}
        ) == expected
        after = snapshot(d)
        if "refuse" in expected:
            assert after == before
        else:
            state = case["expect"]["state"]
            assert {
                r[1]: {"revocation_cursor": r[2], "epoch": r[3]} for r in after["rotation_due"]
            } == state["rotation_due"]
            assert {
                r[1] + "/" + str(r[2]): P.parse_json(r[3]) for r in after["wk_grants"]
            } == state["grants"]
            assert {
                r[1]: {"card_seq": r[2], "sealed": r[3]} for r in after["card_key_wraps"]
            } == state["wraps"]
            assert sorted(r[1] for r in after["ever_devices"]) == state["ever_devices"]
            assert sorted(r[1] for r in after["ever_persons"]) == state["ever_persons"]


def test_first_list_requires_owner(tmp_path):
    with TestClient(create_app(tmp_path)) as c:
        load_state(c.app.state.directory)
        body = changed(
            members=[m for m in BODY["member_list"]["o"]["members"] if m["person_id"] != PERSON]
        )
        body["grants"] = [g for g in body["grants"] if g["o"]["device_id"] != DEVICE]
        del body["card_key_wraps"]
        before = snapshot(c.app.state.directory)
        r = put(c, body)
        assert r.status_code == 403 and r.json() == {"error": "other_person"}
        assert snapshot(c.app.state.directory) == before


def test_retry_retention_restart_and_fence(tmp_path):
    with TestClient(create_app(tmp_path)) as c:
        load_state(c.app.state.directory)
        assert put(c, BODY).status_code == 200
    with TestClient(create_app(tmp_path)) as c:
        d = c.app.state.directory
        d.clock = lambda: NOW + 7 * DAY - 1
        with closing(db.connect(d.path)) as con, con:
            con.execute("UPDATE sessions SET expires_ms=?", (NOW + 8 * DAY,))
            holder(con, NOW + 7 * DAY)
            con.execute("UPDATE workspaces SET card_seq=2")
            con.execute("UPDATE devices SET expires_ms=?", (NOW,))
        assert put(c, BODY).status_code == 200
        r = c.put(
            f"/v2/workspaces/{WS}/membership",
            content=P.cj(BODY),
            headers={**HEADERS, "Orch-Holder": "0"},
        )
        assert r.json() == {"error": "fenced"}
        d.clock = lambda: NOW + 7 * DAY
        assert put(c, BODY).json() == {"error": "stale_list"}
        assert c.get(f"/v2/workspaces/{WS}/members", headers=HEADERS).json() == {
            "member_list": BODY["member_list"]
        }


@pytest.mark.parametrize("epoch", [2, 9])
def test_first_epoch_adjacency(tmp_path, epoch):
    with TestClient(create_app(tmp_path)) as c:
        load_state(c.app.state.directory)
        r = put(c, changed(epoch=epoch))
        assert r.status_code == 409
        assert r.json() == {"error": "stale_epoch", "epoch": 0}


def test_revocation_rotation_and_mailbox_cleanup(tmp_path):
    with TestClient(create_app(tmp_path)) as c:
        d = c.app.state.directory
        load_state(d)
        assert put(c, BODY).status_code == 200
        with closing(db.connect(d.path)) as con, con:
            con.execute(
                "CREATE TABLE request_mailboxes(workspace_id TEXT, device_id TEXT, payload BLOB)"
            )
            con.execute("INSERT INTO request_mailboxes VALUES (?,?,?)", (WS, DEVICE, b"request"))
        assert c.post("/v2/revocations", json={"record": RECORD}).status_code == 200
        s = snapshot(d)
        assert s["rotation_due"] == [(WS, DEVICE, 1, 1)]
        assert all(r[1] != DEVICE for r in s["wk_grants"] + s["card_key_wraps"])
        with closing(db.connect(d.path)) as con:
            assert con.execute("SELECT COUNT(*) FROM request_mailboxes").fetchone()[0] == 0
        # An exact retry must neither resurrect keys nor clear the obligation.
        assert put(c, BODY).status_code == 200
        assert snapshot(d) == s
        body = changed(
            list_seq=2,
            members=[m for m in BODY["member_list"]["o"]["members"] if m["device_id"] != DEVICE],
        )
        body["grants"] = [g for g in body["grants"] if g["o"]["device_id"] != DEVICE]
        del body["card_key_wraps"]
        assert put(c, body).json() == {"error": "rotation_required"}
        assert put(c, changed(body, epoch=2)).status_code == 200
        assert not snapshot(d)["rotation_due"]
        assert PERSON in [r[1] for r in snapshot(d)["ever_persons"]]


def test_rotation_preserves_included_or_newer_obligations(tmp_path):
    with TestClient(create_app(tmp_path)) as c:
        d = c.app.state.directory
        load_state(d)
        assert put(c, BODY).status_code == 200
        laptop = V["ids"]["device_laptop"]
        with closing(db.connect(d.path)) as con, con:
            # Isolate both clearing predicates without relying on revoked-member rejection.
            con.execute("INSERT INTO rotation_due VALUES (?,?,?,?)", (WS, DEVICE, 1, 1))
            con.execute("INSERT INTO rotation_due VALUES (?,?,?,?)", (WS, laptop, 2, 3))
        assert put(c, changed(list_seq=2, epoch=2)).status_code == 200
        assert snapshot(d)["rotation_due"] == [(WS, DEVICE, 1, 1), (WS, laptop, 2, 3)]


def test_wrap_conflict_rolls_back_earlier_wrap_and_keys(tmp_path):
    with TestClient(create_app(tmp_path)) as c:
        d = c.app.state.directory
        load_state(d)
        assert put(c, BODY).status_code == 200
        wrap = BODY["card_key_wraps"]["wraps"][0]
        bob = V["ids"]["device_bob_phone"]
        wraps = {
            "card_seq": 1,
            "wraps": [
                {**wrap, "device_id": bob},
                {**wrap, "sealed": BODY["grants"][0]["o"]["sealed"]},
            ],
        }
        before = snapshot(d)
        r = c.put(f"/v2/workspaces/{WS}/card-keys", json=wraps, headers=HEADERS)
        assert r.status_code == 409 and r.json() == {"error": "wrap_conflict"}
        assert snapshot(d) == before
        body = changed(list_seq=2, epoch=2)
        body["card_key_wraps"] = wraps
        assert put(c, body).json() == {"error": "wrap_conflict"}
        assert snapshot(d) == before


def test_device_reads_only_own_grants_from_first_epoch(tmp_path):
    with TestClient(create_app(tmp_path)) as c:
        d = c.app.state.directory
        load_state(d)
        assert put(c, BODY).status_code == 200
        second = changed(list_seq=2, epoch=2)
        assert put(c, second).status_code == 200
        headers = {"Authorization": "Bearer FAKE-device"}
        route = f"/v2/workspaces/{WS}/grants"
        r = c.get(route, headers=headers)
        assert r.json() == {"grants": [BODY["grants"][0], second["grants"][0]]}
        with closing(db.connect(d.path)) as con, con:
            con.execute("UPDATE ever_devices SET first_epoch=2 WHERE device_id=?", (DEVICE,))
        assert c.get(route, headers=headers).json() == {"grants": [second["grants"][0]]}
        assert c.get(route + "?epoch=1", headers=headers).status_code == 404
        assert c.get(route, headers=HEADERS).status_code == 403
        assert c.get(f"/v2/workspaces/{WS}/card-key?card_seq=1", headers=HEADERS).status_code == 403


@pytest.mark.parametrize("patch", [{"epoch": 4}, {"epoch": 1, "list_seq": 3}])
def test_current_epoch_hint(tmp_path, patch):
    with TestClient(create_app(tmp_path)) as c:
        load_state(c.app.state.directory)
        assert put(c, BODY).status_code == 200
        assert put(c, changed(list_seq=2, epoch=2)).status_code == 200
        r = (
            put(c, changed(list_seq=4, **patch))
            if "list_seq" not in patch
            else put(c, changed(**patch))
        )
        assert r.status_code == 409 and r.json() == {"error": "stale_epoch", "epoch": 2}


def test_expired_holder_and_session_gate_exact_retry(tmp_path):
    with TestClient(create_app(tmp_path)) as c:
        d = c.app.state.directory
        load_state(d)
        assert put(c, BODY).status_code == 200
        d.clock = lambda: NOW + 40_000
        assert put(c, BODY).json() == {"error": "fenced"}
        d.clock = lambda: NOW + 900_000
        assert put(c, BODY).json() == {"error": "unauthenticated"}


def test_departure_prunes_workspace_queues_only(tmp_path):
    with TestClient(create_app(tmp_path)) as c:
        d = c.app.state.directory
        load_state(d)
        assert put(c, BODY).status_code == 200
        other_ws = V["ids"]["workspace_b"]
        with closing(db.connect(d.path)) as con, con:
            con.execute("CREATE TABLE bridge_msgs(workspace_id TEXT, device_id TEXT, payload BLOB)")
            con.execute("CREATE TABLE rid_seen(workspace_id TEXT, device_id TEXT, digest TEXT)")
            for ws in (WS, other_ws):
                con.execute("INSERT INTO bridge_msgs VALUES (?,?,?)", (ws, DEVICE, b"request"))
                con.execute("INSERT INTO rid_seen VALUES (?,?,?)", (ws, DEVICE, "receipt"))
        body = changed(
            list_seq=2,
            epoch=2,
            members=[m for m in BODY["member_list"]["o"]["members"] if m["device_id"] != DEVICE],
        )
        body["grants"] = body["grants"][1:]
        del body["card_key_wraps"]
        assert put(c, body).status_code == 200
        with closing(db.connect(d.path)) as con:
            assert [tuple(r) for r in con.execute("SELECT * FROM bridge_msgs")] == [
                (other_ws, DEVICE, b"request")
            ]
            assert con.execute("SELECT COUNT(*) FROM rid_seen").fetchone()[0] == 2
        assert (
            c.get(
                f"/v2/workspaces/{WS}/grants", headers={"Authorization": "Bearer FAKE-device"}
            ).status_code
            == 403
        )
