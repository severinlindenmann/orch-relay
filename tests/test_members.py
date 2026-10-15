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
from ref import orch_protocol_ref as R


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


def commit(epoch, key="relay test WK"):
    """A G2b wk_commit for a test key at this epoch (the relay cannot open grants, so any key serves)."""
    epoch = min(epoch, R.MAX_EPOCH)  # an out-of-range list still carries a well-formed commitment
    return P.b64u(R.wk_commit(bytes.fromhex(WS), epoch, R.fake(f"{key} {epoch}")))


def changed(body=BODY, **updates):
    out = copy.deepcopy(body)
    if "epoch" in updates and "wk_commit" not in updates:
        updates["wk_commit"] = commit(updates["epoch"])
    out["member_list"] = signed(
        {k: v for k, v in {**out["member_list"]["o"], **updates}.items() if v is not None},
        "wsk_a.sig",
    )
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


@pytest.mark.parametrize(
    "epoch,list_seq,status,error",
    [
        (2, 2, 200, None),  # a refused first publication burned (1, 1)
        (2**16, 9, 200, None),
        (1, 5, 200, None),
        (2**16 + 1, 1, 409, "bad_epoch"),
        (2**32, 1, 400, "malformed"),
    ],
)
def test_first_list_epoch_range(tmp_path, epoch, list_seq, status, error):
    """G2b check 4 (replaces the old epoch=1/list_seq=1 pin): 1 <= epoch <= 2^16, any list_seq."""
    with TestClient(create_app(tmp_path)) as c:
        load_state(c.app.state.directory)
        before = snapshot(c.app.state.directory)
        r = put(c, changed(epoch=epoch, list_seq=list_seq))
        assert r.status_code == status, r.text
        if error:
            assert r.json() == {"error": error}
            assert snapshot(c.app.state.directory) == before
        else:
            assert r.json() == {"list_seq": list_seq, "epoch": epoch}


def test_revocation_rotation_and_mailbox_cleanup(tmp_path):
    with TestClient(create_app(tmp_path)) as c:
        d = c.app.state.directory
        load_state(d)
        assert put(c, BODY).status_code == 200
        with closing(db.connect(d.path)) as con, con:
            con.execute(
                "INSERT INTO request_mailboxes VALUES (?,?,?,?)", (WS, DEVICE, "rid", NOW + 60000)
            )
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


@pytest.mark.parametrize(
    "patch,error",
    [
        ({"epoch": 4, "list_seq": 4}, None),  # epochs 3 and list_seq 3 burned
        ({"epoch": 2 + 2**16, "list_seq": 3}, None),
        ({"epoch": 3 + 2**16, "list_seq": 3}, "bad_epoch"),
        ({"epoch": 1, "list_seq": 3}, "bad_epoch"),  # epochs never fall
        ({"epoch": 2**32, "list_seq": 3}, "malformed"),
    ],
)
def test_publication_epoch_rules(tmp_path, patch, error):
    """G2b check 6 (replaces adjacency): prev <= epoch <= prev + 2^16."""
    with TestClient(create_app(tmp_path)) as c:
        d = c.app.state.directory
        load_state(d)
        assert put(c, BODY).status_code == 200
        assert put(c, changed(list_seq=2, epoch=2)).status_code == 200
        before = snapshot(d)
        r = put(c, changed(**patch))
        if error:
            assert r.json() == {"error": error}
            assert r.status_code == (400 if error == "malformed" else 409)
            assert snapshot(d) == before
        else:
            assert r.status_code == 200, r.text


def test_wk_commit_fixed_within_epoch(tmp_path):
    """G2b check 7b: the same epoch keeps its wk_commit; a new epoch is free; 409 wk_commit_changed."""
    with TestClient(create_app(tmp_path)) as c:
        d = c.app.state.directory
        load_state(d)
        assert put(c, BODY).status_code == 200
        before = snapshot(d)
        r = put(c, changed(list_seq=2, wk_commit=commit(1, "second key")))
        assert r.status_code == 409 and r.json() == {"error": "wk_commit_changed"}
        assert snapshot(d) == before
        assert put(c, changed(list_seq=3)).status_code == 200
        assert put(c, changed(list_seq=4, epoch=2, wk_commit=commit(2, "second key"))).json() == {
            "list_seq": 4,
            "epoch": 2,
        }
        r = put(c, changed(list_seq=5, epoch=2, wk_commit=commit(2)))
        assert r.status_code == 409 and r.json() == {"error": "wk_commit_changed"}


def test_wk_commit_legacy_previous_row_fails_closed(tmp_path):
    """No legacy skip: a stored pre-G2b list without wk_commit refuses a same-epoch list
    (wk_commit_changed); the host recovers by rotating to a higher epoch."""
    with TestClient(create_app(tmp_path)) as c:
        d = c.app.state.directory
        load_state(d)
        assert put(c, BODY).status_code == 200
        legacy = {k: v for k, v in BODY["member_list"]["o"].items() if k != "wk_commit"}
        with closing(db.connect(d.path)) as con, con:
            con.execute("UPDATE member_lists SET list=?", (P.cj(signed(legacy, "wsk_a.sig")),))
        before = snapshot(d)
        r = put(c, changed(list_seq=2))
        assert r.status_code == 409 and r.json() == {"error": "wk_commit_changed"}
        assert snapshot(d) == before
        assert put(c, changed(list_seq=3, epoch=2)).json() == {"list_seq": 3, "epoch": 2}


@pytest.mark.parametrize(
    "value",
    [None, P.b64u(bytes(31)), P.b64u(bytes(33)), P.b64u(bytes(32))[:-1] + "B", 7],
    ids=["missing", "short", "long", "not_canonical", "not_string"],
)
def test_wk_commit_shape(tmp_path, value):
    """G2b check 2: wk_commit is required and canonical b64u of exactly 32 bytes."""
    with TestClient(create_app(tmp_path)) as c:
        load_state(c.app.state.directory)
        r = put(c, changed(wk_commit=value))
        assert r.status_code == 400 and r.json() == {"error": "malformed"}


def test_removal_needs_higher_epoch_and_may_skip(tmp_path):
    """G2b check 7: a removal needs epoch > previous; a skip satisfies it."""
    with TestClient(create_app(tmp_path)) as c:
        load_state(c.app.state.directory)
        assert put(c, BODY).status_code == 200
        body = changed(
            list_seq=2,
            members=[m for m in BODY["member_list"]["o"]["members"] if m["device_id"] != DEVICE],
        )
        body["grants"] = [g for g in body["grants"] if g["o"]["device_id"] != DEVICE]
        del body["card_key_wraps"]
        assert put(c, body).json() == {"error": "rotation_required"}
        assert put(c, changed(body, epoch=3)).json() == {"list_seq": 2, "epoch": 3}


def test_grant_epoch_is_u32(tmp_path):
    with TestClient(create_app(tmp_path)) as c:
        d = c.app.state.directory
        load_state(d)
        body = copy.deepcopy(BODY)
        body["grants"][0] = signed({**body["grants"][0]["o"], "epoch": 2**32}, "wsk_a.sig")
        r = put(c, body)
        assert r.status_code == 400 and r.json() == {"error": "malformed"}
        assert put(c, BODY).status_code == 200
        route = f"/v2/workspaces/{WS}/grants"
        headers = {"Authorization": "Bearer FAKE-device"}
        assert c.get(route + f"?epoch={2**32 - 1}", headers=headers).status_code == 404
        r = c.get(route + f"?epoch={2**32}", headers=headers)
        assert r.status_code == 400 and r.json() == {"error": "malformed"}


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
            for ws in (WS, other_ws):
                con.execute(
                    "INSERT INTO bridge_msgs(workspace_id,device_id,rid,direction,idx,flags,stream,body,expires_ms) VALUES (?,?,'rid',1,0,0,'',?,?)",
                    (ws, DEVICE, b"request", NOW + 60000),
                )
                con.execute(
                    "INSERT INTO rid_seen VALUES (?,?,'rid','receipt',1,?,0,?,?,NULL)",
                    (ws, DEVICE, NOW, NOW, NOW + 900000),
                )
        body = changed(
            list_seq=2,
            epoch=2,
            members=[m for m in BODY["member_list"]["o"]["members"] if m["device_id"] != DEVICE],
        )
        body["grants"] = body["grants"][1:]
        del body["card_key_wraps"]
        assert put(c, body).status_code == 200
        with closing(db.connect(d.path)) as con:
            assert [
                tuple(r) for r in con.execute("SELECT workspace_id,device_id,body FROM bridge_msgs")
            ] == [(other_ws, DEVICE, b"request")]
            assert con.execute("SELECT COUNT(*) FROM rid_seen").fetchone()[0] == 2
        assert (
            c.get(
                f"/v2/workspaces/{WS}/grants", headers={"Authorization": "Bearer FAKE-device"}
            ).status_code
            == 403
        )


@pytest.mark.parametrize("scoped_agent", [False, True], ids=["above_cert", "drop_agent"])
def test_member_certificate_scope_limit(tmp_path, scoped_agent):
    with TestClient(create_app(tmp_path)) as c:
        d = c.app.state.directory
        load_state(d)
        maximum = ["drop:" + WS] if scoped_agent else ["look"]
        scopes = maximum if scoped_agent else ["look", "decide", "operate"]
        cert = signed(
            {**V["certs"]["signed"]["phone"]["o"], "scopes_max": maximum, "expires_ms": NOW + 10000}
        )
        with closing(db.connect(d.path)) as con, con:
            con.execute("UPDATE devices SET cert=? WHERE device_id=?", (P.cj(cert), DEVICE))
        members = copy.deepcopy(BODY["member_list"]["o"]["members"])
        next(m for m in members if m["device_id"] == DEVICE)["scopes"] = scopes
        before = snapshot(d)
        r = put(c, changed(members=members))
        assert r.status_code == 403 and r.json() == {"error": "scope_exceeded"}
        assert snapshot(d) == before


@pytest.mark.parametrize("invalid", ["cert_expired", "revoked"])
def test_card_keys_rechecks_certificate_after_publication(tmp_path, invalid):
    with TestClient(create_app(tmp_path)) as c:
        d = c.app.state.directory
        load_state(d)
        if invalid == "cert_expired":
            cert = signed({**V["certs"]["signed"]["phone"]["o"], "expires_ms": NOW + 1000})
            with closing(db.connect(d.path)) as con, con:
                con.execute(
                    "UPDATE devices SET cert=?,expires_ms=? WHERE device_id=?",
                    (P.cj(cert), NOW + 1000, DEVICE),
                )
        body = copy.deepcopy(BODY)
        del body["card_key_wraps"]
        assert put(c, body).status_code == 200
        if invalid == "revoked":
            assert c.post("/v2/revocations", json={"record": RECORD}).status_code == 200
        else:
            d.clock = lambda: NOW + 1000
        before = snapshot(d)
        r = c.put(f"/v2/workspaces/{WS}/card-keys", json=BODY["card_key_wraps"], headers=HEADERS)
        assert r.status_code == 403 and r.json() == {"error": invalid}
        assert snapshot(d) == before


def test_membership_receipt_is_workspace_scoped(tmp_path):
    with TestClient(create_app(tmp_path)) as c:
        d = c.app.state.directory
        load_state(d)
        assert put(c, BODY).status_code == 200
        with closing(db.connect(d.path)) as con, con:
            # Relocate an exact-body receipt to isolate the SQL scope predicate.
            # The signed body normally makes such a cross-workspace match impossible.
            con.execute("UPDATE membership_receipts SET workspace_id=?", (V["ids"]["workspace_b"],))
        before = snapshot(d)
        r = put(c, BODY)
        assert r.status_code == 409 and r.json() == {"error": "stale_list"}
        assert snapshot(d) == before


@pytest.mark.parametrize("case", V["member_lists"], ids=lambda c: c["name"])
def test_member_list_vectors_against_production(tmp_path, case):
    """Replay every suite-2 list with its signature and abstract directory preconditions."""
    from members_support import BASE

    state = copy.deepcopy(BASE["state"])
    state["list"] = case["prev"]
    directory = {
        "persons": {PERSON: case["directory"]["owner_pk_pub"]},
        "certs": case["directory"]["certs"],
        "revoked": case["directory"]["revoked"],
    }
    o = case["signed"]["o"]
    # The list vectors model grant availability as (device, epoch) pairs. Supply
    # real signed grants for those pairs belonging to the proposed membership.
    available = {tuple(pair) for pair in case["directory"]["grants"]}
    grants = [
        signed(
            {**BODY["grants"][0]["o"], "device_id": m["device_id"], "epoch": o["epoch"]},
            "wsk_a.sig",
        )
        for m in o["members"]
        if (m["device_id"], o["epoch"]) in available
    ]
    with TestClient(create_app(tmp_path)) as c:
        d = c.app.state.directory
        load_state(d, state, directory, case["now_ms"])
        with closing(db.connect(d.path)) as con, con:
            con.execute(
                "UPDATE workspaces SET wsk_pub=?", (P.b64u(bytes.fromhex(case["wsk_pub"])),)
            )
        assert case["card_workspace_id"] == WS
        before = snapshot(d)
        r = put(c, {"member_list": case["signed"], "grants": grants})
        if "refuse" in case["expect"]:
            assert r.status_code >= 400
            assert r.json() == {"error": case["expect"]["refuse"]}
            assert snapshot(d) == before
        else:
            assert r.status_code == 200, r.text
            assert r.json() == {"list_seq": o["list_seq"], "epoch": o["epoch"]}
            stored = c.get(f"/v2/workspaces/{WS}/members", headers=HEADERS).json()
            assert stored["member_list"] == case["signed"]
            assert stored["member_list"]["o"] == case["expect"]["ok"]
