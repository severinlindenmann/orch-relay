"""Replay G1 P3 state transitions through the production database and authorization code."""

import copy
import sqlite3
from contextlib import closing

import pytest
from directory_support import CARD, DEVICE, NOW, PERSON, RECORD, V, seed
from fastapi.testclient import TestClient

from orch_relay import db
from orch_relay import proto as P
from orch_relay.app import create_app
from orch_relay.directory import DAY, Refusal, checked, digest, token_hash

CASES = V["p3"]["cases"]


def cases(op):
    return pytest.mark.parametrize(
        "case", [c for c in CASES if c["op"] == op], ids=lambda c: c["name"]
    )


def subject_state(con, subject):
    if subject is None:
        con.execute("DELETE FROM devices WHERE device_id=?", (DEVICE,))
        return
    con.execute(
        "UPDATE devices SET dk_sig_pub=?, expires_ms=? WHERE device_id=?",
        (subject["pub"], subject.get("expires_ms"), DEVICE),
    )
    if subject.get("revoked"):
        con.execute(
            "INSERT INTO revocations VALUES (?,?,?,?,?,?)",
            (DEVICE, PERSON, P.cj(RECORD), "lost", NOW, 1),
        )


@cases("login")
def test_p3_login(tmp_path, case):
    a, state, expected = case["args"], case["state"], case["expect"]
    with TestClient(create_app(tmp_path)) as c:
        d = c.app.state.directory
        seed(d)
        d.clock = lambda: a["now_ms"]
        d.origin = a["origin"]
        d.random = lambda n: bytes.fromhex(a["token"])
        d.challenges = {
            P.b64u(bytes.fromhex(k)): (v, "testclient") for k, v in state["challenges"].items()
        }
        with closing(db.connect(d.path)) as con, con:
            con.execute("DELETE FROM sessions")
            subject_state(con, a["subject"])
            for token, session in state["tokens"].items():
                con.execute(
                    "INSERT INTO sessions VALUES (?,?,?,?)",
                    (token, session["kind"], session["id"], session["expires_ms"]),
                )
        response = c.post(
            "/v2/session/login",
            json={
                "challenge": P.b64u(bytes.fromhex(a["challenge"])),
                "kind": a["kind"],
                "id": a["ident"],
                "sig": P.b64u(bytes.fromhex(a["sig"])),
            },
        )
        assert {"status": response.status_code, **response.json()} == expected["result"]
        assert {P.unb64u(k).hex(): v[0] for k, v in d.challenges.items()} == expected["state"][
            "challenges"
        ]
        with closing(db.connect(d.path)) as con:
            tokens = {
                h: {"kind": k, "id": i, "expires_ms": e}
                for h, k, i, e in con.execute("SELECT * FROM sessions")
            }
            assert tokens == expected["state"]["tokens"]


@cases("session_gate")
def test_p3_session_gate(tmp_path, case):
    a = case["args"]
    with TestClient(create_app(tmp_path)) as c:
        d = c.app.state.directory
        seed(d)
        d.clock = lambda: a["now_ms"]
        with closing(db.connect(d.path)) as con, con:
            subject_state(con, a["subject"])
            s = a["session"]
            con.execute(
                "UPDATE sessions SET kind=?,subject_id=?,expires_ms=? WHERE token_hash=?",
                (s["kind"], s["id"], s["expires_ms"], token_hash("FAKE-device")),
            )
            if s["kind"] == "workspace":
                con.execute(
                    "INSERT INTO workspaces VALUES (?,?,?,?,?,?,?,?)",
                    (
                        s["id"],
                        PERSON,
                        CARD["o"]["wsk_pub"],
                        P.cj(CARD["delegation"]),
                        P.cj(CARD),
                        1,
                        1,
                        0,
                    ),
                )
            if not a["members"]:
                con.execute("DELETE FROM members")
        r = c.get(
            "/v2/workspaces/" + a["workspace"] + "/card",
            headers={"Authorization": "Bearer FAKE-device"},
        )
        result = {"ok": True} if r.status_code == 200 else {"refuse": r.json()["error"]}
        assert result == case["expect"]["result"]


@cases("quota")
def test_p3_recovery_quota(tmp_path, case):
    a, state = case["args"], case["state"]
    with TestClient(create_app(tmp_path)) as c:
        d = c.app.state.directory
        seed(d)
        if state:
            for purpose, count in [
                ("revocation-person", state["total"]),
                ("revocation-repeat", state["repeat"]),
            ]:
                d.windows[(purpose, PERSON, DAY)] = ((state["day"] + 1) * DAY, count)
        record = copy.deepcopy(RECORD)
        if not a["valid_signature"]:
            record["sig"] = P.b64u(bytes(64))
        with closing(db.connect(d.path)) as con:
            con.row_factory = sqlite3.Row
            with con:
                if a["already_revoked"]:
                    con.execute(
                        "INSERT INTO revocations VALUES (?,?,?,?,?,?)",
                        (DEVICE, PERSON, P.cj(RECORD), "lost", NOW, 1),
                    )
                for h in state.get("accepted", []):
                    con.execute(
                        "INSERT INTO recovery_receipts VALUES (?,?,?)", ("revocation", h, DEVICE)
                    )
            try:
                with con:
                    d.recovery(
                        con, {"record": record}, bytes.fromhex(a["raw"]), "testclient", a["now_ms"]
                    )
                result = {
                    "ok": "retry"
                    if digest(bytes.fromhex(a["raw"])) in state.get("accepted", [])
                    else "charged"
                }
            except Refusal as error:
                result = {"refuse": error.code}
            assert result == case["expect"]["result"]
            expected = case["expect"]["state"]
            total = d.windows.get(("revocation-person", PERSON, DAY))
            if not expected:
                assert total is None
            else:
                assert total == ((expected["day"] + 1) * DAY, expected["total"])
                repeat = d.windows.get(("revocation-repeat", PERSON, DAY), (0, 0))[1]
                assert repeat == expected["repeat"]
                assert [
                    r[0]
                    for r in con.execute(
                        "SELECT request_digest FROM recovery_receipts ORDER BY rowid"
                    )
                ] == expected["accepted"]


@cases("revocation")
def test_p3_revocation(tmp_path, case):
    a, state = case["args"], case["state"]
    with TestClient(create_app(tmp_path)) as c:
        d = c.app.state.directory
        seed(d)
        with closing(db.connect(d.path)) as con:
            con.row_factory = sqlite3.Row
            with con:
                con.execute("DELETE FROM sessions")
                for h, did in state["sessions"].items():
                    con.execute(
                        "INSERT INTO sessions VALUES (?,?,?,?)", (h, "device", did, NOW + 900_000)
                    )
                for did, record in state["revocations"].items():
                    con.execute(
                        "INSERT INTO revocations VALUES (?,?,?,?,?,?)",
                        (did, PERSON, P.cj(record), record["o"]["reason"], NOW, state["cursor"]),
                    )
                con.execute(
                    "CREATE TABLE bridge_msgs(workspace_id TEXT, device_id TEXT, kind TEXT, envelope BLOB)"
                )
                for ws, workspace in state["workspaces"].items():
                    for did, grant in workspace["grants"].items():
                        con.execute(
                            "INSERT INTO wk_grants VALUES (?,?,?,?)", (ws, did, 1, P.cj(grant))
                        )
                    for did, wrap in workspace["wraps"].items():
                        con.execute(
                            "INSERT INTO card_key_wraps VALUES (?,?,?,?)", (ws, did, 1, P.cj(wrap))
                        )
                    for key in ("mailboxes", "responses"):
                        for did, entries in workspace[key].items():
                            for entry in entries:
                                con.execute(
                                    "INSERT INTO bridge_msgs VALUES (?,?,?,?)",
                                    (ws, did, key, entry),
                                )
                    for did, due in workspace["rotation_due"].items():
                        con.execute(
                            "INSERT INTO rotation_due VALUES (?,?,?,?)",
                            (ws, did, due["revocation_cursor"], due["epoch"]),
                        )
            try:
                with con:
                    checked(P.verify_revocation(a["record"], bytes.fromhex(a["pk_pub"]), a["cert"]))
                    d.revoke(con, a["record"], NOW)
                result = {"ok": a["record"]["o"]["device_id"]}
            except Refusal as error:
                result = {"refuse": error.code}
            assert result == case["expect"]["result"]
            expected = case["expect"]["state"]
            assert {
                r["device_id"]: P.parse_json(r["record"])
                for r in con.execute("SELECT * FROM revocations")
            } == expected["revocations"]
            assert (
                con.execute("SELECT COALESCE(MAX(cursor),0) FROM revocations").fetchone()[0]
                == expected["cursor"]
            )
            assert {
                r["token_hash"]: r["subject_id"] for r in con.execute("SELECT * FROM sessions")
            } == expected["sessions"]
            for ws, workspace in expected["workspaces"].items():
                assert {
                    r["device_id"]: {
                        "epoch": r["epoch"],
                        "revocation_cursor": r["revocation_cursor"],
                    }
                    for r in con.execute("SELECT * FROM rotation_due WHERE workspace_id=?", (ws,))
                } == workspace["rotation_due"]
                assert {
                    r["device_id"]: P.parse_json(r["grant"])
                    for r in con.execute("SELECT * FROM wk_grants WHERE workspace_id=?", (ws,))
                } == workspace["grants"]
                assert {
                    r["device_id"]: P.parse_json(r["sealed"])
                    for r in con.execute("SELECT * FROM card_key_wraps WHERE workspace_id=?", (ws,))
                } == workspace["wraps"]
                for key in ("mailboxes", "responses"):
                    actual = {}
                    for r in con.execute(
                        "SELECT * FROM bridge_msgs WHERE workspace_id=? AND kind=?", (ws, key)
                    ):
                        actual.setdefault(r["device_id"], []).append(r["envelope"])
                    assert actual == workspace[key]
