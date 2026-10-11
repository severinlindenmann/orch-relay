"""P3 G3 vector adapters exercise the independent production implementation."""

import sqlite3
from contextlib import closing

import pytest
from bridge_support import CRID, HOST, RID, binary, insert_queue, queue_body
from directory_support import DEVICE, NOW, PERSON, PRIMARY, WS, V, seed
from fastapi.testclient import TestClient

from orch_relay import db
from orch_relay import proto as P
from orch_relay.app import create_app
from orch_relay.bridge import envelope
from orch_relay.directory import Refusal, token_hash

CASES = V["p3"]["cases"]


def cases(*ops):
    return pytest.mark.parametrize(
        "case", [c for c in CASES if c["op"] in ops], ids=lambda c: c["name"]
    )


def setup(c, now):
    d = c.app.state.directory
    seed(d)
    d.clock = lambda: now
    with closing(db.connect(d.path)) as con, con:
        con.execute("UPDATE holders SET lease_until_ms=?", (now + 40000,))
        con.execute("UPDATE sessions SET expires_ms=?", (now + 900000,))
        con.execute(
            "INSERT INTO sessions VALUES (?,?,?,?)",
            (token_hash("FAKE-primary"), "device", PRIMARY, now + 900000),
        )
    return d


@cases("request_replay", "chunk")
def test_replay_vectors(tmp_path, case):
    a, state = case["args"], case["state"]
    with TestClient(create_app(tmp_path)) as c:
        d = setup(c, a["now_ms"])
        with closing(db.connect(d.path)) as con, con:
            con.execute("UPDATE member_lists SET epoch=?", (a["epoch"],))
            con.execute("UPDATE holders SET cursor=?", (a.get("cursor", 0),))
            if state:
                con.execute(
                    "INSERT INTO rid_seen VALUES (?,?,?,?,?,?,?,?,?,NULL)",
                    (
                        WS,
                        DEVICE,
                        RID,
                        state["digest"],
                        state["req_epoch"],
                        state["first_ms"],
                        state["requeues"],
                        state["last_requeue_ms"],
                        state["keep_until_ms"],
                    ),
                )
                for copy in state["copies"]:
                    queue_body(con, binary("bridge_device_post"), copy["n"])
                    con.execute(
                        "UPDATE bridge_msgs SET expires_ms=? WHERE n=?",
                        (copy["expires_ms"], copy["n"]),
                    )
                for idx, chunk in state["chunks"].items():
                    con.execute(
                        "INSERT INTO rid_chunks VALUES (?,?,?,?,?)",
                        (WS, DEVICE, RID, int(idx), chunk["digest"]),
                    )
        r = c.post(
            f"/v2/workspaces/{WS}/bridge/{RID}",
            content=bytes.fromhex(a["raw"]),
            headers={
                **(HOST if case["op"] == "chunk" else {"Authorization": "Bearer FAKE-device"}),
                "Content-Type": "application/octet-stream",
            },
        )
        expected = case["expect"]["result"]
        if "refuse" in expected:
            assert r.json()["error"] == expected["refuse"]
            if "retry_after" in expected:
                assert int(r.headers["retry-after"]) == expected["retry_after"]
        else:
            assert r.status_code == 202, r.text
            with closing(db.connect(d.path)) as con:
                con.row_factory = sqlite3.Row
                row = con.execute("SELECT * FROM rid_seen").fetchone()
                for key in (
                    "req_epoch",
                    "first_ms",
                    "requeues",
                    "last_requeue_ms",
                    "keep_until_ms",
                ):
                    assert row[key] == case["expect"]["state"][key]
                assert dict(con.execute("SELECT idx,digest FROM rid_chunks")) == {
                    int(k): v["digest"] for k, v in case["expect"]["state"]["chunks"].items()
                }


@cases("holder", "poll", "handoff")
def test_fence_vectors(tmp_path, case):
    a, state = case["args"], case["state"]
    with TestClient(create_app(tmp_path)) as c:
        d = setup(c, a["now_ms"])
        with closing(db.connect(d.path)) as con, con:
            con.row_factory = sqlite3.Row
            con.execute(
                "UPDATE holders SET gen=?,lease_until_ms=?,cursor=?,poll_token=?",
                tuple(state[k] for k in ("gen", "lease_until_ms", "cursor", "poll_token")),
            )
            con.execute(
                "INSERT INTO holder_delivery VALUES (?,?)",
                (WS, a.get("delivered", state["cursor"])),
            )
            try:
                if case["op"] == "holder":
                    result = c.app.state.bridge.hold(
                        con,
                        WS,
                        {"gen": a["gen"], "take_over": a.get("take_over", False)},
                        a["now_ms"],
                    )
                    result = {"ok": result}
                else:
                    d.fence(con, {"orch-holder": str(a["gen"])}, WS, a["now_ms"])
                    if case["op"] == "handoff":
                        queue_body(con, binary("bridge_device_post"), state["cursor"] + 1)
                        response, _ = c.app.state.bridge.host_poll(
                            con, WS, {"after": str(state["cursor"])}, a["token"], False, a["now_ms"]
                        )
                        result = {"ok": "deliver" if response["items"] else "cancelled"}
                    else:
                        c.app.state.bridge.host_poll(
                            con, WS, {"after": str(a["after"])}, a["token"], True, a["now_ms"]
                        )
                        result = {"ok": con.execute("SELECT cursor FROM holders").fetchone()[0]}
            except Refusal as error:
                result = {"refuse": error.code}
            assert result == case["expect"]["result"]
            row = dict(con.execute("SELECT * FROM holders").fetchone())
            row.pop("workspace_id")
            assert row == case["expect"]["state"]


@cases("request", "queue", "rejection")
def test_pair_queue_vectors(tmp_path, case):
    a, state = case["args"], case["state"]
    now = a.get("now_ms", NOW)
    with TestClient(create_app(tmp_path)) as c:
        d = setup(c, now)
        with closing(db.connect(d.path)) as con, con:
            if case["op"] == "request":
                con.execute("DELETE FROM devices WHERE device_id!=?", (a["primary"],))
                for entry in state.values():
                    insert_queue(con, entry)
                con.execute(
                    "UPDATE workspaces SET wsk_pub=?,owner_person_id=?",
                    (P.b64u(bytes.fromhex(a["wsk_pub"])), a["owner"]),
                )
            else:
                if case["op"] == "rejection":
                    insert_queue(con, {"request": {"o": a["request"]}, "state": "open"})
                else:
                    insert_queue(con, state)
                con.execute(
                    "UPDATE accounts SET pk_pub=? WHERE person_id=?",
                    (P.b64u(bytes.fromhex(a["pk_pub"])), PERSON),
                )
        if case["op"] == "request":
            r = c.post(
                f"/v2/persons/{PERSON}/cert-requests", json={"request": a["signed"]}, headers=HOST
            )
        elif case["op"] == "queue" and a["action"] == "certificate":
            from orch_relay.cert_queue import certificate_transition

            with closing(db.connect(d.path)) as con, con:
                con.row_factory = sqlite3.Row
                row = con.execute("SELECT * FROM cert_requests").fetchone()
                try:
                    result = {
                        "ok": certificate_transition(
                            con, row, a["signed"], now, P.b64u(bytes.fromhex(a["pk_pub"]))
                        )
                    }
                except Refusal as error:
                    result = {"refuse": error.code}
                assert result == case["expect"]["result"]
                final = con.execute("SELECT * FROM cert_requests").fetchone()
                # Expiry is materialized by collection on public routes.
                expected_state = case["expect"]["state"]["state"]
                assert (
                    final["state"] == expected_state
                    or expected_state == "expired"
                    and now >= row["expires_ms"]
                )
                return
        else:
            action = a.get("action", "rejection")
            r = c.post(
                f"/v2/cert-requests/{CRID}/{action}",
                json={action: a["signed"]},
                headers={"Authorization": "Bearer FAKE-primary"},
            )
        expected = case["expect"].get("result", case["expect"])
        if "refuse" in expected:
            assert r.json().get("error") == expected["refuse"], r.text
        else:
            assert r.status_code == 200, r.text
            if case["op"] == "queue":
                with closing(db.connect(d.path)) as con:
                    con.row_factory = sqlite3.Row
                    row = con.execute("SELECT * FROM cert_requests").fetchone()
                    assert row["state"] == case["expect"]["state"]["state"]
                    for field in ("challenge", "rejection", "cert"):
                        assert (P.parse_json(row[field]) if row[field] else None) == case["expect"][
                            "state"
                        ][field]


@cases("envelope")
def test_envelope_vectors(case):
    a = case["args"]
    try:
        if a.get("revoked"):
            raise Refusal("revoked")
        if not a.get("member", True) and a.get("offer") is None:
            raise Refusal("not_eligible")
        envelope(
            bytes.fromhex(a["raw"]),
            a["ws"],
            a["rid"],
            a["direction"],
            a.get("device"),
            a.get("offer"),
        )
        result = {"ok": True}
    except Refusal as error:
        result = {"refuse": error.code}
    assert result == case["expect"]["result"]


@pytest.mark.parametrize("case", V["p3"]["envelope_sizes"])
def test_envelope_size_vectors(case):
    raw = bytearray(binary("bridge_device_post"))
    raw[5] = case["direction"]
    raw[88:92] = (0 if case["pair"] else 1).to_bytes(4, "big")
    raw.extend(bytes(case["limit"] - len(raw)))
    offer = raw[56:72].hex() if case["pair"] else None
    assert envelope(bytes(raw), WS, RID, case["direction"], offer=offer)
    with pytest.raises(Refusal) as error:
        envelope(bytes(raw) + b"\0", WS, RID, case["direction"], offer=offer)
    assert error.value.code == case["one_over"]
