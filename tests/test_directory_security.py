"""Regression tests for the G1 security review, including mutation survivors."""

import asyncio
import copy
import statistics
import time
from contextlib import closing

import pytest
from directory_support import CERT, DEVICE, NOW, PERSON, RECORD, WS, V, seed, signed
from fastapi.testclient import TestClient
from test_directory import account_body

from orch_relay import db
from orch_relay import proto as P
from orch_relay.app import create_app
from orch_relay.directory import (
    DAY,
    HOUR,
    MINUTE,
    Directory,
    Refusal,
    body_cap,
    canonical_address,
    create_invite,
)


def test_challenge_issuance_stays_flat_at_50000(tmp_path):
    d = Directory(tmp_path / "unused", "https://relay.example")

    def measure():
        samples = []
        for batch in range(5):
            start = time.perf_counter()
            for i in range(100):
                address = f"2001:db8:ffff:{batch * 100 + i:x}::/64"
                challenge = d.issue(address, NOW)["challenge"]
                d.consume(challenge, NOW)
            samples.append((time.perf_counter() - start) / 100)
        return statistics.median(samples)

    empty = measure()
    for i in range(50_000):
        d.issue(f"2001:db8:{i // 65536:x}:{i % 65536:x}::/64", NOW)
    full = measure()
    assert full < empty * 5, (empty, full)
    assert len(d.challenges) == 50_000
    # Exercise the real issuance path to the ceiling; rejection preserves every token.
    for i in range(50_000, 65_536):
        d.issue(f"2001:db8:0:{i:x}::/64", NOW)
    before = dict(d.challenges)
    with pytest.raises(Refusal, match="rate_limited"):
        d.issue("2001:db8:1::/64", NOW)
    assert d.challenges == before


def test_challenge_counters_consumption_and_expiry(tmp_path):
    d = Directory(tmp_path / "unused", "https://relay.example")
    address, parent = "2001:db8::/64", "2001:db8::/56"
    tokens = [d.issue(address, NOW)["challenge"] for _ in range(16)]
    with pytest.raises(Refusal):
        d.issue(address, NOW)
    d.consume(tokens[0], NOW)
    replacement = d.issue(address, NOW + 1)["challenge"]
    with pytest.raises(Refusal) as error:
        d.consume(tokens[1], NOW + MINUTE)
    assert error.value.code == "expired"
    d.issue("192.0.2.1", NOW + MINUTE)
    assert d.challenge_addresses[address] == d.challenge_parents[parent] == 1
    d.consume(replacement, NOW + MINUTE)
    assert address not in d.challenge_addresses and parent not in d.challenge_parents


@pytest.mark.parametrize("revocation,cap", [(False, 30), (True, 10)])
@pytest.mark.parametrize("junk", [b"{", b"{}", None])
def test_recovery_address_gate_counts_invalid_attempts(tmp_path, revocation, cap, junk):
    with TestClient(create_app(tmp_path), client=("127.0.0.1", 123)) as c:
        d = c.app.state.directory
        seed(d)
        d.trusted_proxy = "127.0.0.1"
        path = "/v2/revocations" if revocation else "/v2/devices/" + DEVICE
        method = c.post if revocation else c.put
        if junk is None:
            obj = copy.deepcopy(RECORD if revocation else CERT)
            obj["sig"] = P.b64u(bytes(64))
            junk = P.cj({"record" if revocation else "cert": obj})
        headers = {"Content-Type": "application/json", "X-Forwarded-For": "192.0.2.1"}
        for _ in range(cap):
            assert method(path, content=junk, headers=headers).status_code in (400, 401)
        r = method(path, content=junk, headers=headers)
        assert r.status_code == 429 and r.json() == {"error": "rate_limited"}
        assert int(r.headers["retry-after"]) > 0
        headers["X-Forwarded-For"] = "192.0.2.2"
        assert method(path, content=junk, headers=headers).status_code in (400, 401)
        assert not any(key[0].endswith("-person") for key in d.windows)


@pytest.mark.parametrize("revocation", [False, True])
@pytest.mark.parametrize("already_stored", [False, True])
def test_exact_accepted_recovery_retry_free_at_full_address_budget(
    tmp_path, revocation, already_stored
):
    with TestClient(create_app(tmp_path)) as c:
        d = c.app.state.directory
        seed(d)
        if revocation and already_stored:
            stronger = signed({**RECORD["o"], "reason": "compromised"})
            assert c.post("/v2/revocations", json={"record": stronger}).status_code == 200
        if not revocation and not already_stored:
            with closing(db.connect(d.path)) as con, con:
                con.execute("DELETE FROM members")
                con.execute("DELETE FROM devices WHERE device_id=?", (DEVICE,))
        path = "/v2/revocations" if revocation else "/v2/devices/" + DEVICE
        method = c.post if revocation else c.put
        body = {"record": RECORD} if revocation else {"cert": CERT}
        assert method(path, json=body).status_code == 200
        kind, duration, cap = (
            ("revocation", MINUTE, 10) if revocation else ("certificate", HOUR, 30)
        )
        d.windows[(kind + "-address", "testclient", duration)] = (NOW + duration, cap)
        before = dict(d.windows)
        assert method(path, json=body).status_code == 200
        assert d.windows == before
        # A different byte representation must pass the address gate.
        assert (
            method(
                path, content=P.cj(body) + b" ", headers={"Content-Type": "application/json"}
            ).status_code
            == 429
        )


@pytest.mark.parametrize("revoked", [True, False])
def test_exact_certificate_retry_rechecks_status(tmp_path, revoked):
    with TestClient(create_app(tmp_path)) as c:
        d = c.app.state.directory
        seed(d)
        cert = signed({**V["certs"]["signed"]["agent"]["o"], "expires_ms": NOW + 1000})
        path = "/v2/devices/" + cert["o"]["device_id"]
        raw = P.cj({"cert": cert})
        headers = {"Content-Type": "application/json"}
        assert c.put(path, content=raw, headers=headers).status_code == 200
        if revoked:
            record = signed({**RECORD["o"], "device_id": cert["o"]["device_id"]})
            assert c.post("/v2/revocations", json={"record": record}).status_code == 200
        else:
            d.clock = lambda: NOW + 1000
        r = c.put(path, content=raw, headers=headers)
        assert r.status_code == (403 if revoked else 400)
        assert r.json() == {"error": "revoked" if revoked else "cert_expired"}


def test_used_invite_refuses_different_account(tmp_path):
    invite = create_invite(tmp_path / db.DB_NAME, DAY)
    with TestClient(create_app(tmp_path)) as c:
        c.app.state.directory.clock = lambda: NOW
        assert c.post("/v2/accounts", json=account_body(c, invite)).status_code == 200
        body = account_body(c, invite)
        bob = V["ids"]["person_bob"]
        body["pk_pub"] = P.b64u(bytes.fromhex(V["keys"]["person_bob.sig"]["pub"]))
        body["device_cert"] = signed(
            {**V["certs"]["signed"]["laptop"]["o"], "person_id": bob}, "person_bob.sig"
        )
        from directory_support import sign

        body["sig"] = sign(
            "laptop.sig",
            P.auth_bytes(
                c.app.state.directory.origin,
                P.unb64u(body["challenge"]),
                "device",
                V["ids"]["device_laptop"],
            ),
        )
        r = c.post("/v2/accounts", json=body)
        assert r.status_code == 403 and r.json() == {"error": "not_eligible"}
        with closing(db.connect(c.app.state.directory.path)) as con:
            assert con.execute("SELECT COUNT(*) FROM accounts").fetchone()[0] == 1
        # The second account is otherwise valid with a fresh invite.
        body["invite"] = create_invite(c.app.state.directory.path, DAY)
        challenge = c.post("/v2/session/challenge", json={}).json()["challenge"]
        body["challenge"] = challenge
        body["sig"] = sign(
            "laptop.sig",
            P.auth_bytes(
                c.app.state.directory.origin,
                P.unb64u(challenge),
                "device",
                V["ids"]["device_laptop"],
            ),
        )
        assert c.post("/v2/accounts", json=body).status_code == 200


@pytest.mark.parametrize("route", ["card", "feed", "certificate"])
def test_drop_scoped_device_cannot_read_directory(tmp_path, route):
    with TestClient(create_app(tmp_path)) as c:
        d = c.app.state.directory
        seed(d)
        agent = V["certs"]["signed"]["agent"]
        with closing(db.connect(d.path)) as con, con:
            d.store_device(con, agent)
            did = agent["o"]["device_id"]
            con.execute("UPDATE sessions SET subject_id=? WHERE kind='device'", (did,))
            con.execute("INSERT INTO members VALUES (?,?,?,?)", (WS, did, PERSON, P.cj(["look"])))
        path = {
            "card": f"/v2/workspaces/{WS}/card",
            "feed": f"/v2/persons/{PERSON}/revocations",
            "certificate": f"/v2/devices/{DEVICE}",
        }[route]
        r = c.get(path, headers={"Authorization": "Bearer FAKE-device"})
        assert r.status_code == 403 and r.json() == {"error": "not_eligible"}
        # All other authorization conditions are met.
        with closing(db.connect(d.path)) as con, con:
            con.execute("UPDATE devices SET scopes_max=? WHERE device_id=?", (P.cj(["look"]), did))
        assert c.get(path, headers={"Authorization": "Bearer FAKE-device"}).status_code == 200


def test_streaming_cap_stops_receiving_before_body_is_buffered(tmp_path):
    app = create_app(tmp_path)
    cap = body_cap("login")
    received, sent = [], []

    async def receive():
        received.append(1)
        return {"type": "http.request", "body": b"!" * 1024, "more_body": len(received) < 100}

    async def send(message):
        sent.append(message)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/v2/session/login",
        "raw_path": b"/v2/session/login",
        "query_string": b"",
        "root_path": "",
        "headers": [(b"content-type", b"application/json")],
        "client": ("192.0.2.1", 123),
        "server": ("relay.example", 80),
    }
    asyncio.run(app(scope, receive, send))
    assert sent[0]["status"] == 413
    assert len(received) == cap // 1024 + 1


@pytest.mark.parametrize("part", [0, 1])
@pytest.mark.parametrize("value", [0, P.P256_N, 2**256 - 1])
def test_ecdsa_out_of_range_refused(part, value):
    sig = bytearray(P.unb64u(CERT["sig"]))
    sig[part * 32 : (part + 1) * 32] = value.to_bytes(32, "big")
    pub = bytes.fromhex(V["keys"]["person_alice.sig"]["pub"])
    assert not P.SUITE.verify(pub, bytes(sig), P.L["sig_" + CERT["o"]["kind"]] + P.cj(CERT["o"]))


def test_missing_proxy_header_warns(caplog):
    assert canonical_address("127.0.0.1", None, "127.0.0.1") == "127.0.0.1"
    assert "Trusted proxy sent no X-Forwarded-For" in caplog.text


def test_long_poll_lock_assertion(tmp_path):
    d = Directory(tmp_path / "unused", "https://relay.example")
    d.assert_can_wait()
    with d.lock, pytest.raises(AssertionError, match="long poll"):
        d.assert_can_wait()


def test_account_device_collision_rolls_back_invite_and_account(tmp_path):
    invite = create_invite(tmp_path / db.DB_NAME, DAY)
    with TestClient(create_app(tmp_path)) as c:
        d = c.app.state.directory
        seed(d)
        body = account_body(c, invite)
        bob = V["ids"]["person_bob"]
        body["pk_pub"] = P.b64u(bytes.fromhex(V["keys"]["person_bob.sig"]["pub"]))
        body["device_cert"] = signed({**CERT["o"], "person_id": bob}, "person_bob.sig")
        r = c.post("/v2/accounts", json=body)
        assert r.status_code == 409 and r.json() == {"error": "cert_conflict"}
        with closing(db.connect(d.path)) as con:
            assert con.execute("SELECT COUNT(*) FROM accounts").fetchone()[0] == 1
            assert con.execute("SELECT used_ms FROM invites").fetchone()[0] is None


def test_rate_window_expiry_is_lazy_and_keeps_live_person_budget(tmp_path):
    d = Directory(tmp_path / "unused", "https://relay.example")
    d.rate("certificate-person", PERSON, DAY, 64, NOW)
    for i in range(200):
        d.rate("old", str(i), MINUTE, 1, NOW)
    next_minute = (NOW // MINUTE + 1) * MINUTE
    for i in range(4):
        d.rate("new", str(i), MINUTE, 1, next_minute)
    assert not any(key[0] == "old" for key in d.windows)
    assert d.windows[("certificate-person", PERSON, DAY)][1] == 1
    # Fixed windows refresh even when an expired key is behind the cleanup batch.
    d.rate("new", "0", MINUTE, 1, next_minute + MINUTE)
    assert d.windows[("new", "0", MINUTE)][1] == 1
