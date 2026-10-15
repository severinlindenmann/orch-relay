"""Replay G1 P3 state transitions through the production database and authorization code."""

import copy
import hashlib
import sqlite3
from contextlib import closing

import pytest
from directory_support import CARD, CERT, DEVICE, NOW, PERSON, RECORD, WS, V, seed, signed
from fastapi.testclient import TestClient

from orch_relay import db
from orch_relay import proto as P
from orch_relay.app import create_app
from orch_relay.directory import DAY, HOUR, Refusal, checked, digest, token_hash

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
        if case["name"] == "valid_dummy_signature_still_401":
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import ec

            d.dummy_pub = (
                ec.derive_private_key(
                    int.from_bytes(
                        hashlib.sha256(
                            b"FAKE orch v2 test vector: P3 dummy verification key"
                        ).digest(),
                        "big",
                    )
                    % (P.P256_N - 1)
                    + 1,
                    ec.SECP256R1(),
                )
                .public_key()
                .public_bytes(
                    serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
                )
            )
            assert P.SUITE.verify(
                d.dummy_pub,
                bytes.fromhex(a["sig"]),
                P.auth_bytes(a["origin"], bytes.fromhex(a["challenge"]), a["kind"], a["ident"]),
            )
        for k, v in state["challenges"].items():
            d.add_challenge(P.b64u(bytes.fromhex(k)), v, "testclient", None)
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
        result = {"status": response.status_code, **response.json()}
        if response.status_code == 429:
            result["retry_after"] = int(response.headers["retry-after"])
        assert result == expected["result"]
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
    certificate = not a.get("revocation", True) or case["name"] in {
        "expired_certificate_no_quota_charge",
        "revoked_device_no_quota_charge",
    }
    kind = "certificate" if certificate else "revocation"
    with TestClient(create_app(tmp_path)) as c:
        d = c.app.state.directory
        seed(d)
        if state:
            d.windows[(kind + "-person", PERSON, DAY)] = ((state["day"] + 1) * DAY, state["total"])
            d.windows[("revocation-repeat", PERSON, DAY)] = (
                (state["day"] + 1) * DAY,
                state["repeat"],
            )
        record = copy.deepcopy(CERT if certificate else RECORD)
        prior = None
        if a["already_revoked"]:
            prior = RECORD
            record = signed({**RECORD["o"], "reason": "compromised"})
        if case["name"] == "superseded_revocation_no_quota_charge":
            prior = signed({**RECORD["o"], "reason": "compromised"})
        if case["name"] == "expired_certificate_no_quota_charge":
            record = signed({**CERT["o"], "created_ms": NOW - 1000, "expires_ms": NOW})
        if case["name"] == "revoked_device_no_quota_charge":
            prior = RECORD
        if not a["valid_signature"]:
            record["sig"] = P.b64u(bytes(64))
        with closing(db.connect(d.path)) as con:
            con.row_factory = sqlite3.Row
            with con:
                if certificate and prior is None:
                    con.execute("DELETE FROM members")
                    con.execute("DELETE FROM devices WHERE device_id=?", (DEVICE,))
                if prior:
                    con.execute(
                        "INSERT INTO revocations VALUES (?,?,?,?,?,?)",
                        (DEVICE, PERSON, P.cj(prior), prior["o"]["reason"], NOW, 1),
                    )
                for h in state.get("accepted", []):
                    con.execute("INSERT INTO recovery_receipts VALUES (?,?,?)", (kind, h, DEVICE))
            try:
                with con:
                    d.recovery(
                        con,
                        {"cert" if certificate else "record": record},
                        bytes.fromhex(a["raw"]),
                        "testclient",
                        a["now_ms"],
                        DEVICE if certificate else None,
                    )
                result = {
                    "ok": "retry"
                    if digest(bytes.fromhex(a["raw"])) in state.get("accepted", [])
                    else "unchanged"
                    if not a.get("changes_state", True)
                    else "charged"
                }
            except Refusal as error:
                # The abstract quota vectors model no-charge outcomes; HTTP retains its refusal.
                if case["name"] in {
                    "expired_certificate_no_quota_charge",
                    "revoked_device_no_quota_charge",
                }:
                    assert error.code == (
                        "cert_expired" if "expired" in case["name"] else "revoked"
                    )
                    result = {"ok": "unchanged"}
                else:
                    result = {"refuse": error.code}
            assert result == case["expect"]["result"]
            expected = case["expect"]["state"]
            total = d.windows.get((kind + "-person", PERSON, DAY))
            if not expected:
                assert total is None
            else:
                assert total == ((expected["day"] + 1) * DAY, expected["total"])
                assert (
                    d.windows.get(("revocation-repeat", PERSON, DAY), (0, 0))[1]
                    == expected["repeat"]
                )
                receipts = list(expected["accepted"])
                if case["name"] == "superseded_revocation_no_quota_charge":
                    # HTTP caches accepted no-ops for free exact address retries;
                    # the abstract person-quota model records only state changes.
                    receipts.append(digest(bytes.fromhex(a["raw"])))
                assert [
                    r[0]
                    for r in con.execute(
                        "SELECT request_digest FROM recovery_receipts ORDER BY rowid"
                    )
                ] == receipts
            if result != {"ok": "charged"}:
                assert (
                    kind + "-address",
                    "testclient",
                    HOUR if certificate else 60_000,
                ) not in d.windows


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
                                    "INSERT INTO bridge_msgs(workspace_id,device_id,rid,direction,idx,flags,stream,body,expires_ms) VALUES (?,?,'rid',?,0,0,'',?,?)",
                                    (ws, did, 1 if key == "mailboxes" else 2, entry, NOW + 60000),
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
                        "SELECT * FROM bridge_msgs WHERE workspace_id=? AND direction=?",
                        (ws, 1 if key == "mailboxes" else 2),
                    ):
                        actual.setdefault(r["device_id"], []).append(r["body"])
                    assert actual == workspace[key]


@cases("certificate")
def test_p3_certificate(tmp_path, case):
    a, state = case["args"], case["state"]
    with TestClient(create_app(tmp_path)) as c:
        d = c.app.state.directory
        seed(d, devices=False, card=False)
        d.clock = lambda: a["now_ms"]
        with closing(db.connect(d.path)) as con, con:
            for cert in state.values():
                d.store_device(con, cert)
        r = c.put("/v2/devices/" + a["signed"]["o"]["device_id"], json={"cert": a["signed"]})
        result = (
            {"ok": "retry" if state else "stored"}
            if r.status_code == 200
            else {"refuse": r.json()["error"]}
        )
        assert result == case["expect"]["result"]
        with closing(db.connect(d.path)) as con:
            assert {
                did: P.parse_json(cert)
                for did, cert in con.execute("SELECT device_id,cert FROM devices")
            } == case["expect"]["state"]
        assert d.windows.get(("certificate-person", PERSON, DAY), (0, 0))[1] == (
            1 if result == {"ok": "stored"} else 0
        )


@cases("directory")
def test_p3_directory(tmp_path, case):
    a, state = case["args"], case["state"]
    with TestClient(create_app(tmp_path)) as c:
        d = c.app.state.directory
        seed(d)
        with closing(db.connect(d.path)) as con, con:
            con.execute("DELETE FROM ever_persons")
            con.execute("DELETE FROM ever_devices")
            for person in state["ever_persons"]:
                con.execute("INSERT INTO ever_persons VALUES (?,?)", (WS, person))
            for did in state["ever_devices"]:
                con.execute("INSERT INTO ever_devices VALUES (?,?,?)", (WS, did, 1))
            for cursor, record in enumerate(a["records"], 1):
                con.execute(
                    "INSERT INTO revocations VALUES (?,?,?,?,?,?)",
                    (record["o"]["device_id"], a["person"], P.cj(record), "lost", NOW, cursor),
                )
            con.execute("DELETE FROM members")  # Historical authority survives departure.
        path = (
            "/v2/devices/" + a["device"]
            if "device" in a
            else "/v2/persons/" + a["person"] + "/revocations"
        )
        r = c.get(path, headers={"Authorization": "Bearer FAKE-workspace"})
        result = (
            {"ok": [item["record"] for item in r.json()["revocations"]]}
            if r.status_code == 200
            else {"refuse": r.json()["error"]}
        )
        assert result == case["expect"]["result"]
        with closing(db.connect(d.path)) as con:
            assert (
                sorted(
                    r[0]
                    for r in con.execute(
                        "SELECT person_id FROM ever_persons WHERE workspace_id=?", (WS,)
                    )
                )
                == state["ever_persons"]
            )
            assert (
                sorted(
                    r[0]
                    for r in con.execute(
                        "SELECT device_id FROM ever_devices WHERE workspace_id=?", (WS,)
                    )
                )
                == state["ever_devices"]
            )


@cases("first_card")
def test_p3_first_card(tmp_path, case):
    a, state = case["args"], case["state"]
    with TestClient(create_app(tmp_path)) as c:
        d = c.app.state.directory
        seed(d, card=bool(state))
        d.clock = lambda: a["now_ms"]
        if state:
            d.windows[("card-owner", PERSON, HOUR)] = ((state["hour"] + 1) * HOUR, state["count"])
        r = c.put(
            "/v2/workspaces/" + WS + "/card",
            json={"card": a["card"]},
            headers={"Authorization": "Bearer FAKE-workspace", "Orch-Holder": "1"},
        )
        result = (
            {"ok": "retry" if state else "stored"}
            if r.status_code == 200
            else {"refuse": r.json()["error"]}
        )
        assert result == case["expect"]["result"]
        assert d.windows.get(("card-owner", PERSON, HOUR), (0, 0))[1] == case["expect"][
            "state"
        ].get("count", 0)
        with closing(db.connect(d.path)) as con:
            row = con.execute("SELECT card FROM workspaces").fetchone()
            if case["expect"]["state"]:
                card = P.parse_json(row[0])
                assert {"o": card["o"], "delegation": card["delegation"]["o"]} == case["expect"][
                    "state"
                ]["card"]
            else:
                assert row is None
            if not state:
                assert con.execute("SELECT COUNT(*) FROM ever_persons").fetchone()[0] == 0
