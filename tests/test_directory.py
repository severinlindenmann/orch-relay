import copy
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing

import pytest
from directory_support import (
    CARD,
    CERT,
    DEVICE,
    NOW,
    PERSON,
    PK,
    PRIMARY,
    RECORD,
    WS,
    V,
    issue_login,
    seed,
    sign,
    signed,
)
from fastapi.testclient import TestClient

from orch_relay import cli, db
from orch_relay import proto as P
from orch_relay.app import create_app
from orch_relay.directory import DAY, HOUR, MINUTE, digest


def account_body(c, invite):
    challenge = c.post("/v2/session/challenge", json={}).json()["challenge"]
    return {
        "invite": invite,
        "pk_pub": PK,
        "device_cert": CERT,
        "challenge": challenge,
        "sig": sign(
            "phone.sig",
            P.auth_bytes(c.app.state.directory.origin, P.unb64u(challenge), "device", DEVICE),
        ),
    }


def test_invite_atomic_account_retry_restart(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("ORCH_RELAY_DATA", str(tmp_path))
    assert cli.main(["invite", "create", "--ttl", "7d"]) == 0
    invite = capsys.readouterr().out.strip()
    P.unb64u(invite, 32)
    with TestClient(create_app(tmp_path)) as c:
        d = c.app.state.directory
        d.clock = lambda: NOW
        body = account_body(c, invite)
        raw = P.cj(body)
        headers = {"Content-Type": "application/json"}
        with ThreadPoolExecutor(max_workers=2) as pool:
            responses = list(
                pool.map(lambda _: c.post("/v2/accounts", content=raw, headers=headers), range(2))
            )
        assert [r.status_code for r in responses] == [200, 200]
        assert responses[0].json() == {"person_id": PERSON}
        with closing(db.connect(d.path)) as con:
            assert con.execute("SELECT COUNT(*) FROM accounts").fetchone()[0] == 1
            row = con.execute("SELECT code_hash, request_digest FROM invites").fetchone()
            assert row == (digest(invite.encode()), digest(raw))
        assert c.post("/v2/accounts", content=raw + b" ", headers=headers).status_code != 200
    with TestClient(create_app(tmp_path)) as c:
        c.app.state.directory.clock = lambda: NOW
        assert c.post("/v2/accounts", content=raw, headers=headers).json() == {"person_id": PERSON}
        assert issue_login(c).status_code == 200
    assert invite.encode() not in (tmp_path / db.DB_NAME).read_bytes()


def test_invite_bad_possession_does_not_spend_invite(tmp_path):
    from orch_relay.directory import create_invite

    invite = create_invite(tmp_path / db.DB_NAME, DAY)
    with TestClient(create_app(tmp_path)) as c:
        c.app.state.directory.clock = lambda: NOW
        body = account_body(c, invite)
        body["sig"] = P.b64u(bytes(64))
        assert c.post("/v2/accounts", json=body).json() == {"error": "bad_signature"}
        with closing(db.connect(c.app.state.directory.path)) as con:
            assert con.execute("SELECT COUNT(*) FROM accounts").fetchone()[0] == 0
            assert con.execute("SELECT used_ms FROM invites").fetchone()[0] is None
        assert c.post("/v2/accounts", json=account_body(c, invite)).status_code == 200


def test_revoke_cleanup_upgrade_and_recovery_after_restart(tmp_path):
    with TestClient(create_app(tmp_path)) as c:
        d = c.app.state.directory
        seed(d)
        token = issue_login(c).json()["token"]
        with closing(db.connect(d.path)) as con, con:
            con.execute("INSERT INTO wk_grants VALUES (?,?,?,?)", (WS, DEVICE, 1, b"{}"))
            con.execute("INSERT INTO card_key_wraps VALUES (?,?,?,?)", (WS, DEVICE, 1, "opaque"))
            con.execute("CREATE TABLE bridge_msgs(device_id TEXT, envelope BLOB)")
            con.execute("INSERT INTO bridge_msgs VALUES (?,?)", (DEVICE, b"opaque"))
        assert c.post("/v2/revocations", json={"record": RECORD}).status_code == 200
        assert (
            c.get("/v2/devices/" + DEVICE, headers={"Authorization": "Bearer " + token}).status_code
            == 401
        )
        assert issue_login(c).json() == {"error": "revoked"}
        with closing(db.connect(d.path)) as con:
            for table in ("wk_grants", "card_key_wraps", "bridge_msgs"):
                assert con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0
            assert con.execute("SELECT revocation_cursor,epoch FROM rotation_due").fetchone() == (
                1,
                1,
            )
        stronger = signed({**RECORD["o"], "reason": "compromised"})
        assert c.post("/v2/revocations", json={"record": stronger}).status_code == 200
        assert c.post("/v2/revocations", json={"record": RECORD}).status_code == 200
        assert c.get("/v2/devices/" + DEVICE + "/revocation").json()["record"] == stronger
    with TestClient(create_app(tmp_path)) as c:
        c.app.state.directory.clock = lambda: NOW
        assert c.get("/v2/devices/" + DEVICE + "/revocation").json()["record"] == stronger
        with closing(db.connect(c.app.state.directory.path)) as con:
            assert con.execute("SELECT revocation_cursor FROM rotation_due").fetchone()[0] == 2
        cert = V["certs"]["signed"]["laptop"]
        assert (
            c.put("/v2/devices/" + cert["o"]["device_id"], json={"cert": cert}).status_code == 200
        )
        assert issue_login(c, key="laptop.sig", ident=cert["o"]["device_id"]).status_code == 200


def test_recovery_quota_reserve_and_exact_retries(tmp_path):
    with TestClient(create_app(tmp_path)) as c:
        d = c.app.state.directory
        seed(d)
        assert c.post("/v2/revocations", json={"record": RECORD}).status_code == 200
        for i in range(24):
            # New address windows while retaining the full person day.
            d.clock = lambda i=i: NOW + (i + 1) * MINUTE
            record = signed({**RECORD["o"], "revoked_ms": NOW + i + 1})
            assert c.post("/v2/revocations", json={"record": record}).status_code == 200
        d.clock = lambda: NOW + 25 * MINUTE
        record = signed({**RECORD["o"], "revoked_ms": NOW + 25})
        assert c.post("/v2/revocations", json={"record": record}).status_code == 429
        assert c.post("/v2/revocations", json={"record": RECORD}).status_code == 200
        fresh = signed({**RECORD["o"], "device_id": PRIMARY})
        assert c.post("/v2/revocations", json={"record": fresh}).status_code == 200
        total = d.windows[("revocation-person", PERSON, DAY)][1]
        assert total == 26
        invalid = copy.deepcopy(record)
        invalid["sig"] = P.b64u(bytes(64))
        assert c.post("/v2/revocations", json={"record": invalid}).status_code == 401
        assert d.windows[("revocation-person", PERSON, DAY)][1] == total
        # Idle activity and a different window duration do not prune the day.
        d.clock = lambda: NOW + HOUR
        c.post("/v2/session/challenge", json={})
        assert d.windows[("revocation-person", PERSON, DAY)][1] == total


def test_first_card_quota_owner_and_authenticated_idempotency(tmp_path):
    with TestClient(create_app(tmp_path)) as c:
        d = c.app.state.directory
        seed(d, card=False)
        assert c.put("/v2/workspaces/" + WS + "/card", json={"card": CARD}).status_code == 200
        assert c.put("/v2/workspaces/" + WS + "/card", json={"card": CARD}).status_code == 401
        headers = {"Authorization": "Bearer FAKE-workspace", "Orch-Holder": "1"}
        with closing(db.connect(d.path)) as con, con:
            con.execute("INSERT INTO holders VALUES (?,?,?,?,?)", (WS, 1, NOW + 40_000, 0, None))
        alternate_sig = copy.deepcopy(CARD)
        sig = P.unb64u(CARD["sig"])
        alternate_sig["sig"] = P.b64u(
            sig[:32] + (P.P256_N - int.from_bytes(sig[32:], "big")).to_bytes(32, "big")
        )
        assert c.put(
            "/v2/workspaces/" + WS + "/card", json={"card": alternate_sig}, headers=headers
        ).json() == {"card_seq": 1}
        assert c.put(
            "/v2/workspaces/" + WS + "/card",
            json={"card": CARD},
            headers={**headers, "Orch-Holder": "0"},
        ).json() == {"error": "fenced"}
        d.clock = lambda: NOW + 40_000
        assert c.put(
            "/v2/workspaces/" + WS + "/card", json={"card": CARD}, headers=headers
        ).json() == {"error": "fenced"}
        assert d.windows[("card-owner", PERSON, HOUR)][1] == 1


@pytest.mark.parametrize(
    "content", [b'{"x":1,"x":2}', b'{"x":1.0}', b'{"x":NaN}', b"[]", b'{"x":"\xed\xa0\x80"}']
)
def test_strict_http_json(tmp_path, content):
    with TestClient(create_app(tmp_path)) as c:
        r = c.post(
            "/v2/session/challenge", content=content, headers={"Content-Type": "application/json"}
        )
        assert r.status_code == 400
        assert r.json() == {"error": "malformed"}


def test_feed_pagination_and_request_time_gate(tmp_path):
    with TestClient(create_app(tmp_path)) as c:
        d = c.app.state.directory
        seed(d)
        for did in (DEVICE, V["ids"]["device_laptop"]):
            assert (
                c.post(
                    "/v2/revocations", json={"record": signed({**RECORD["o"], "device_id": did})}
                ).status_code
                == 200
            )
        token = issue_login(c, key="primary.sig", ident=PRIMARY).json()["token"]
        headers = {"Authorization": "Bearer " + token}
        path = "/v2/persons/" + PERSON + "/revocations"
        first = c.get(path, params={"limit": "1"}, headers=headers).json()
        assert first["revocations"][0]["cursor"] == 1
        second = c.get(path, params={"limit": "1", "next": first["next"]}, headers=headers).json()
        assert second["revocations"][0]["cursor"] == 2 and second["next"] is None
        assert c.get(path + "?limit=1&limit=2", headers=headers).status_code == 400
        assert c.get(path, params={"limit": "257"}, headers=headers).status_code == 400
        assert (
            c.get(path, params={"after": "1", "next": first["next"]}, headers=headers).status_code
            == 400
        )
