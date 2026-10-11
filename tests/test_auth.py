from fastapi.testclient import TestClient

from orch_relay import db
from orch_relay.app import create_app


def test_challenge_single_use_and_logout(tmp_path):
    with TestClient(create_app(tmp_path)) as c:
        r = c.post("/v2/session/challenge", json={})
        assert r.status_code == 200
        challenge = r.json()["challenge"]
        body = {"challenge": challenge, "kind": "device", "id": "00" * 16, "sig": "AA" * 43}
        assert c.post("/v2/session/login", json=body).json() == {"error": "bad_signature"}
        assert c.post("/v2/session/login", json=body).json() == {"error": "unknown_challenge"}
        assert c.post("/v2/session/logout", json={}).json() == {}


def test_challenge_cap_never_evicts(tmp_path):
    with TestClient(create_app(tmp_path)) as c:
        issued = [c.post("/v2/session/challenge", json={}) for _ in range(16)]
        assert all(r.status_code == 200 for r in issued)
        assert c.post("/v2/session/challenge", json={}).status_code == 429
        assert len(c.app.state.directory.challenges) == 16


def test_full_durability(tmp_path):
    con = db.connect(tmp_path / "test.sqlite3")
    assert con.execute("PRAGMA synchronous").fetchone()[0] == 2
    con.close()


from contextlib import closing
from unittest.mock import patch

import pytest
from directory_support import DEVICE, LOGIN, NOW, WS, V, issue_login, seed

from orch_relay import proto as P
from orch_relay.directory import canonical_address, token_hash


def test_overlapping_tokens_logout_and_restart(tmp_path):
    with TestClient(create_app(tmp_path)) as c:
        seed(c.app.state.directory)
        tokens = [issue_login(c).json()["token"] for _ in range(2)]
        assert tokens[0] != tokens[1]
        with closing(db.connect(tmp_path / db.DB_NAME)) as con:
            rows = con.execute("SELECT token_hash FROM sessions").fetchall()
            assert all(t not in {r[0] for r in rows} for t in tokens)
        for t in tokens:
            assert (
                c.get("/v2/devices/" + DEVICE, headers={"Authorization": "Bearer " + t}).status_code
                == 200
            )
        assert (
            c.post(
                "/v2/session/logout", json={}, headers={"Authorization": "Bearer " + tokens[0]}
            ).status_code
            == 200
        )
        challenge = c.post("/v2/session/challenge", json={}).json()["challenge"]
    with TestClient(create_app(tmp_path)) as c:
        c.app.state.directory.clock = lambda: NOW
        assert not c.app.state.directory.challenges
        assert (
            c.post("/v2/session/login", json={**LOGIN, "challenge": challenge}).json()["error"]
            == "unknown_challenge"
        )
        assert (
            c.get(
                "/v2/devices/" + DEVICE, headers={"Authorization": "Bearer " + tokens[0]}
            ).status_code
            == 401
        )
        assert (
            c.get(
                "/v2/devices/" + DEVICE, headers={"Authorization": "Bearer " + tokens[1]}
            ).status_code
            == 200
        )
        c.app.state.directory.clock = lambda: NOW + 900_000
        assert (
            c.get(
                "/v2/devices/" + DEVICE, headers={"Authorization": "Bearer " + tokens[1]}
            ).status_code
            == 401
        )


@pytest.mark.parametrize("condition", ["revoked", "expired", "unknown"])
def test_bad_signature_hides_subject_status(tmp_path, condition):
    from directory_support import PERSON, RECORD

    with TestClient(create_app(tmp_path)) as c:
        d = c.app.state.directory
        seed(d)
        with closing(db.connect(d.path)) as con, con:
            if condition == "revoked":
                con.execute(
                    "INSERT INTO revocations VALUES (?,?,?,?,?,?)",
                    (DEVICE, PERSON, P.cj(RECORD), "lost", NOW, 1),
                )
            elif condition == "expired":
                con.execute("UPDATE devices SET expires_ms=?", (NOW,))
            else:
                con.execute("DELETE FROM devices WHERE device_id=?", (DEVICE,))
        with patch.object(P.SUITE, "verify", wraps=P.SUITE.verify) as verify:
            r = issue_login(c, key="primary.sig")
            assert r.json() == {"error": "bad_signature"}
            assert verify.call_count == 1
        if condition != "unknown":
            assert issue_login(c).json()["error"] == (
                "revoked" if condition == "revoked" else "cert_expired"
            )


@pytest.mark.parametrize(
    "peer,xff,proxy,expected",
    [
        ("::ffff:192.0.2.1", None, None, "192.0.2.1"),
        ("2001:db8:12:34::1", None, None, "2001:db8:12:34::/64"),
        ("2001:db8:12:34::ffff", None, None, "2001:db8:12:34::/64"),
        ("192.0.2.1", "198.51.100.1", "127.0.0.1", "192.0.2.1"),
        ("127.0.0.1", "198.51.100.1", "127.0.0.1", "198.51.100.1"),
        ("127.0.0.1", "forged, ::ffff:198.51.100.1", "127.0.0.1", "198.51.100.1"),
        ("127.0.0.1", "invalid", "127.0.0.1", "127.0.0.1"),
    ],
)
def test_address_canonicalization(peer, xff, proxy, expected):
    assert canonical_address(peer, xff, proxy) == expected


def test_challenge_global_cap_and_full_minute(tmp_path):
    with TestClient(create_app(tmp_path)) as c:
        d = c.app.state.directory
        d.clock = lambda: NOW
        for i in range(65_536):
            d.add_challenge(str(i), NOW + 60_000, "other", None)
        assert c.post("/v2/session/challenge", json={}).status_code == 429
        assert len(d.challenges) == 65_536
        for challenge in list(d.challenges):
            d.remove_challenge(challenge)
        for _ in range(60):
            r = c.post("/v2/session/challenge", json={})
            assert r.status_code == 200
            c.post("/v2/session/login", json={**LOGIN, "challenge": r.json()["challenge"]})
        assert c.post("/v2/session/challenge", json={}).status_code == 429
        d.clock = lambda: (NOW // 60_000 + 1) * 60_000
        assert c.post("/v2/session/challenge", json={}).status_code == 200


def test_login_malformed_attempt_consumes_challenge(tmp_path):
    with TestClient(create_app(tmp_path)) as c:
        challenge = c.post("/v2/session/challenge", json={}).json()["challenge"]
        assert c.post("/v2/session/login", json={"challenge": challenge}).status_code == 400
        assert (
            c.post("/v2/session/login", json={**LOGIN, "challenge": challenge}).json()["error"]
            == "unknown_challenge"
        )


def test_workspace_login_scope_and_holder(tmp_path):
    with TestClient(create_app(tmp_path)) as c:
        seed(c.app.state.directory)
        token = issue_login(c, key="wsk_a.sig", kind="workspace", ident=WS).json()["token"]
        headers = {"Authorization": "Bearer " + token}
        assert c.get("/v2/workspaces/" + WS + "/card", headers=headers).status_code == 200
        with closing(db.connect(c.app.state.directory.path)) as con, con:
            con.execute(
                "UPDATE sessions SET subject_id=? WHERE token_hash=?",
                ("00" * 16, token_hash(token)),
            )
        assert c.get("/v2/workspaces/" + WS + "/card", headers=headers).status_code == 401


@pytest.mark.parametrize("case", V["relay_auth"]["cases"], ids=lambda c: c["name"])
def test_relay_auth_vectors(tmp_path, case):
    with TestClient(create_app(tmp_path)) as c:
        d = c.app.state.directory
        seed(d)
        d.origin = case["origin"]
        for k, v in case["state"]["challenges"].items():
            d.add_challenge(P.b64u(bytes.fromhex(k)), v, "testclient", None)
        for step in case["steps"]:
            d.clock = lambda step=step: step["now_ms"]
            r = c.post(
                "/v2/session/login",
                json={
                    "challenge": P.b64u(bytes.fromhex(case["challenge"])),
                    "kind": step["kind"],
                    "id": step["id"],
                    "sig": P.b64u(bytes.fromhex(step["sig"])),
                },
            )
            assert r.status_code == step["expect"]["status"]
            if "error" in step["expect"]:
                assert r.json() == {"error": step["expect"]["error"]}
