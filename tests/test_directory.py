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
from ref import orch_protocol_ref as R

S = R.SUITES[2]


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
            con.execute(
                "INSERT INTO bridge_msgs(workspace_id,device_id,rid,direction,idx,flags,stream,body,expires_ms) VALUES (?,?,'rid',1,0,0,'',?,?)",
                (WS, DEVICE, b"opaque", NOW + 60000),
            )
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
        assert (
            c.get("/v2/devices/" + DEVICE + "/revocation").json()["pairs"][0]["revocation"]
            == stronger
        )
    with TestClient(create_app(tmp_path)) as c:
        c.app.state.directory.clock = lambda: NOW
        assert (
            c.get("/v2/devices/" + DEVICE + "/revocation").json()["pairs"][0]["revocation"]
            == stronger
        )
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
        assert c.post("/v2/revocations", json={"record": record}).status_code == 200
        assert c.post("/v2/revocations", json={"record": RECORD}).status_code == 200
        fresh = signed({**RECORD["o"], "device_id": PRIMARY})
        assert c.post("/v2/revocations", json={"record": fresh}).status_code == 200
        total = d.windows[("revocation-person", PERSON, DAY)][1]
        assert total == 2
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


def test_revocation_must_fit_feed_page(tmp_path):
    from orch_relay.directory import body_cap

    cap = body_cap("revocations")

    with TestClient(create_app(tmp_path)) as c:
        seed(c.app.state.directory)
        raw = P.cj({"record": RECORD})
        # Even a heavily padded, valid HTTP body must fit a feed entry after acceptance.
        response = c.post(
            "/v2/revocations",
            content=raw + b" " * (cap - len(raw)),
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 200  # The canonical record is tiny.
        malformed_large = {**RECORD, "sig": "A" * cap}
        assert c.post("/v2/revocations", json={"record": malformed_large}).json() == {
            "error": "too_large"
        }


def test_database_work_is_off_event_loop(tmp_path, monkeypatch):
    import asyncio

    real_connect = db.connect

    def connect(path):
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return real_connect(path)
        pytest.fail("SQLite connection opened on the event loop")

    monkeypatch.setattr(db, "connect", connect)
    with TestClient(create_app(tmp_path)) as c:
        assert c.post("/v2/session/challenge", json={}).status_code == 200


def test_card_owner_quota_spans_addresses_and_workspace_ids(tmp_path):
    with TestClient(create_app(tmp_path)) as c:
        d = c.app.state.directory
        seed(d, card=False)
        d.trusted_proxy = "127.0.0.1"
        for i in range(11):
            ws = f"{i:032x}"
            card = copy.deepcopy(CARD)
            card["o"]["workspace_id"] = ws
            card["delegation"] = signed({**card["delegation"]["o"], "workspace_id": ws})
            card["sig"] = sign("wsk_a.sig", P.L["sig_card_wsk"] + P.cj(card["o"]))
            # Reset only address state; owner accounting must still limit fresh ids.
            d.windows.pop(("card-address", "testclient", HOUR), None)
            r = c.put("/v2/workspaces/" + ws + "/card", json={"card": card})
            assert r.status_code == (200 if i < 10 else 429)
        assert d.windows[("card-owner", PERSON, HOUR)][1] == 10


def test_stream_caps_precede_parsing_and_auth(tmp_path):
    from orch_relay.directory import body_cap

    with TestClient(create_app(tmp_path)) as c:
        d = c.app.state.directory
        cap = body_cap("login")
        r = c.post(
            "/v2/session/login",
            content=iter([b"!" * cap, b"!"]),
            headers={"Content-Type": "application/json"},
        )
        assert r.status_code == 413 and r.json() == {"error": "too_large"}
        r = c.post("/v2/session/login", content=b"!", headers={"Content-Length": str(cap + 1)})
        assert r.status_code == 413
        r = d.handle("login", None, "POST", b"!" * (cap + 1), {}, {}, "testclient")
        assert r.status_code == 413
        assert d.challenges == {} and d.windows == {}


def test_canonical_retry_at_full_person_quota_and_invalid_signature(tmp_path):
    with TestClient(create_app(tmp_path)) as c:
        d = c.app.state.directory
        seed(d)
        d.windows[("certificate-person", PERSON, DAY)] = (NOW + DAY, 64)
        before = dict(d.windows)
        cert = signed(CERT["o"])
        r = c.put("/v2/devices/" + DEVICE, json={"cert": cert})
        assert r.status_code == 200
        cert["sig"] = P.b64u(bytes(64))
        r = c.put("/v2/devices/" + DEVICE, json={"cert": cert})
        assert r.status_code == 400 and r.json() == {"error": "cert_invalid"}
        assert (
            d.windows[("certificate-person", PERSON, DAY)]
            == before[("certificate-person", PERSON, DAY)]
        )
        assert d.windows[("certificate-address", "testclient", HOUR)][1] == 2
        with closing(db.connect(d.path)) as con:
            assert (
                P.parse_json(
                    con.execute("SELECT cert FROM devices WHERE device_id=?", (DEVICE,)).fetchone()[
                        0
                    ]
                )
                == CERT
            )


def test_device_token_capacity_expiry_and_random_dummy(tmp_path):
    from orch_relay.directory import Directory

    with TestClient(create_app(tmp_path)) as c:
        d = c.app.state.directory
        seed(d)
        assert P.SUITE.pub_ok(d.dummy_pub)
        assert d.dummy_pub != Directory(d.path, d.origin).dummy_pub
        with closing(db.connect(d.path)) as con, con:
            con.execute("DELETE FROM sessions")
        for _ in range(8):
            assert issue_login(c).status_code == 200
        r = issue_login(c)
        assert r.status_code == 429 and r.json() == {"error": "quota_exceeded"}
        assert r.headers["retry-after"] == "900"
        with closing(db.connect(d.path)) as con:
            assert con.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 8
        d.clock = lambda: NOW + 900_000
        assert issue_login(c).status_code == 200


def test_ipv6_parent_challenge_limits(tmp_path):
    from orch_relay.directory import Directory, Refusal

    d = Directory(tmp_path / "unused", "https://relay.example")
    for subnet in range(16):
        for _ in range(16):
            d.issue(f"2001:db8:1234:{subnet:x}::/64", NOW)
    with pytest.raises(Refusal) as error:
        d.issue("2001:db8:1234:10::/64", NOW)
    assert error.value.status == 429
    assert len(d.challenges) == 256
    assert d.issue("2001:db8:1234:100::/64", NOW)
    for challenge in list(d.challenges):
        d.remove_challenge(challenge)
    d.windows[("challenge-parent", "2001:db8:1234::/56", MINUTE)] = (NOW + MINUTE, 960)
    with pytest.raises(Refusal):
        d.issue("2001:db8:1234:20::/64", NOW)
    assert not d.challenges


@pytest.mark.parametrize(
    "device,workspace,incoming,allowed",
    [(2097151, 16777215, 1, True), (2097152, 2097152, 1, False), (0, 16777216, 1, False)],
)
def test_g3_response_budget_hook(device, workspace, incoming, allowed):
    from orch_relay.directory import Refusal, check_response_budget

    if allowed:
        check_response_budget(device, workspace, incoming)
    else:
        with pytest.raises(Refusal) as error:
            check_response_budget(device, workspace, incoming)
        assert error.value.code == "quota_exceeded" and error.value.status == 429


def test_workspace_filter_before_pagination_and_card_history(tmp_path):
    with TestClient(create_app(tmp_path)) as c:
        d = c.app.state.directory
        seed(d)
        with closing(db.connect(d.path)) as con, con:
            # Put an unseen device first, so post-pagination filtering would lose the visible row.
            for cursor, did in enumerate((PRIMARY, DEVICE), 1):
                record = signed({**RECORD["o"], "device_id": did})
                con.execute(
                    "INSERT INTO revocations VALUES (?,?,?,?,?,?)",
                    (did, PERSON, P.cj(record), "lost", NOW, cursor),
                )
            con.execute("DELETE FROM members")
        headers = {"Authorization": "Bearer FAKE-workspace"}
        r = c.get("/v2/persons/" + PERSON + "/revocations?limit=1", headers=headers)
        assert [x["cursor"] for x in r.json()["revocations"]] == [2]
        assert r.json()["next"] is None
        assert c.get("/v2/devices/" + DEVICE, headers=headers).status_code == 200
        assert c.get("/v2/devices/" + PRIMARY, headers=headers).status_code == 403
        assert c.get("/v2/workspaces/" + WS + "/card", headers=headers).status_code == 200
        # A live same-person device with historical authority is still not a current member.
        token = issue_login(c, key="laptop.sig", ident=V["ids"]["device_laptop"]).json()["token"]
        assert (
            c.get(
                "/v2/workspaces/" + WS + "/card", headers={"Authorization": "Bearer " + token}
            ).status_code
            == 403
        )


def test_legacy_card_only_history_does_not_authorize_feed(tmp_path):
    with TestClient(create_app(tmp_path)) as c:
        d = c.app.state.directory
        seed(d)
        with closing(db.connect(d.path)) as con, con:
            # The earlier G1 card writer inserted this person without an accepted list.
            con.execute("DELETE FROM ever_devices")
            con.execute("DELETE FROM members")
        r = c.get(
            "/v2/persons/" + PERSON + "/revocations",
            headers={"Authorization": "Bearer FAKE-workspace"},
        )
        assert r.status_code == 403 and r.json() == {"error": "not_eligible"}
        with closing(db.connect(d.path)) as con:
            assert con.execute("SELECT person_id FROM ever_persons").fetchone()[0] == PERSON


# --- orch-core #397 (migration 0010): revocations retained per (device, person) ------------------


def _other_person_row(con, did, reason="compromised"):
    """Bob's verified-looking "revocation" of alice's device id, as restore evidence stores it."""
    bob = V["ids"]["person_bob"]
    record = signed({**RECORD["o"], "device_id": did, "person_id": bob, "reason": reason})
    con.execute(
        "INSERT INTO revocations VALUES (?,?,?,?,?,(SELECT coalesce(max(cursor),0)+1 FROM revocations))",
        (did, bob, P.cj(record), reason, NOW),
    )
    return record


def test_revoke_keeps_every_pair_and_upgrades_per_pair(tmp_path):
    """Another person's revocation of a device id never drops or blocks the device's person's own: a
    first-come row used to make alice's revocation a no-op (prior = bob's compromised row)."""
    with TestClient(create_app(tmp_path)) as c:
        d = c.app.state.directory
        seed(d)
        with closing(db.connect(d.path)) as con, con:
            bob_record = _other_person_row(con, DEVICE)
        stronger = signed({**RECORD["o"], "reason": "compromised"})
        assert c.post("/v2/revocations", json={"record": stronger}).status_code == 200
        with closing(db.connect(d.path)) as con:
            rows = dict(
                con.execute("SELECT person_id,record FROM revocations WHERE device_id=?", (DEVICE,))
            )
        assert rows == {PERSON: P.cj(stronger), V["ids"]["person_bob"]: P.cj(bob_record)}
        # The registered person's record is the one GET /revocation names; bob's row stays.
        assert (
            c.get("/v2/devices/" + DEVICE + "/revocation").json()["pairs"][0]["revocation"]
            == stronger
        )
        with closing(db.connect(d.path)) as con, con:
            con.row_factory = __import__("sqlite3").Row
            d.revoke(con, RECORD, NOW)  # weaker for alice's pair: no change
            assert (
                con.execute(
                    "SELECT reason FROM revocations WHERE device_id=? AND person_id=?",
                    (DEVICE, PERSON),
                ).fetchone()[0]
                == "compromised"
            )


BOB = V["ids"]["person_bob"]
BOB_PK = P.b64u(bytes.fromhex(V["keys"]["person_bob.sig"]["pub"]))
INTRUDER_PK = P.b64u(bytes.fromhex(V["keys"]["intruder.sig"]["pub"]))


def _cert_of(person, key, did=DEVICE):
    base = next(c for c in V["certs"]["signed"].values() if c["o"]["device_id"] == did)
    return signed({**base["o"], "person_id": person}, key)


def _chain_row(con, did, person, key, pk, reason="compromised", ws=WS):
    """An accepted restore's evidence pair, as apply_evidence writes it: the chain row and the
    global (§19.5) row of the same pair."""
    record = signed({**RECORD["o"], "device_id": did, "person_id": person, "reason": reason}, key)
    cert = _cert_of(person, key, did)
    con.execute(
        "INSERT INTO checkpoint_revocations VALUES (?,?,?,?,?,?,?,?,?)",
        (ws, did, person, reason, P.cj(record), P.cj(cert), pk, "r", "t"),
    )
    con.execute(
        "INSERT INTO revocations VALUES (?,?,?,?,?,(SELECT coalesce(max(cursor),0)+1 FROM revocations))",
        (did, person, P.cj(record), reason, NOW),
    )
    return record, cert


def _own_row(con, did=DEVICE, reason="lost"):
    record = signed({**RECORD["o"], "device_id": did, "reason": reason})
    con.execute(
        "INSERT INTO revocations VALUES (?,?,?,?,?,(SELECT coalesce(max(cursor),0)+1 FROM revocations))",
        (did, PERSON, P.cj(record), reason, NOW),
    )
    return record


def test_revocation_route_lists_every_pair_registered_person_first(tmp_path):
    """P3-D30 (orch-52 ruling 3): one entry per held pair; the registered person's pair first even
    though it sorts last by person_id and has the highest cursor, then by person_id; provenance and
    the evidence the relay holds for each."""
    intruder = R.person_id(S, P.unb64u(INTRUDER_PK)).hex()
    with TestClient(create_app(tmp_path)) as c:
        d = c.app.state.directory
        seed(d)
        with closing(db.connect(d.path)) as con, con:
            chain, chain_cert = _chain_row(con, DEVICE, intruder, "intruder.sig", INTRUDER_PK)
            feed = _other_person_row(con, DEVICE)
            own = _own_row(con)
        assert PERSON > max(BOB, intruder)
        body = c.get("/v2/devices/" + DEVICE + "/revocation").json()
        assert body == {
            "pairs": [
                {
                    "person_id": PERSON,
                    "reason": "lost",
                    "revocation": own,
                    "device_cert": CERT,
                    "pk_pub": PK,
                    "provenance": "registry",
                },
                {
                    "person_id": BOB,
                    "reason": "compromised",
                    "revocation": feed,
                    "device_cert": None,
                    "pk_pub": None,
                    "provenance": "feed",
                },
                {
                    "person_id": intruder,
                    "reason": "compromised",
                    "revocation": chain,
                    "device_cert": chain_cert,
                    "pk_pub": INTRUDER_PK,
                    "provenance": "chain",
                },
            ]
        }


def test_revocation_route_without_registry_orders_by_person(tmp_path):
    """No association: every pair is chain or feed, ordered by person_id; a pre-0010 evidence-only
    registry row (P3-D29, written by a restore) is no association and so not 'registry'."""
    with TestClient(create_app(tmp_path)) as c:
        d = c.app.state.directory
        seed(d)
        with closing(db.connect(d.path)) as con, con:
            con.execute("INSERT INTO evidence_persons VALUES (?)", (PERSON,))
            own, own_cert = _chain_row(con, DEVICE, PERSON, "person_alice.sig", PK, reason="lost")
            bob = _other_person_row(con, DEVICE)
        pairs = c.get("/v2/devices/" + DEVICE + "/revocation").json()["pairs"]
        assert [(p["person_id"], p["provenance"]) for p in pairs] == [
            (BOB, "feed"),
            (PERSON, "chain"),
        ]
        assert pairs[0]["revocation"] == bob and pairs[1]["revocation"] == own
        assert pairs[1]["pk_pub"] == PK and pairs[1]["device_cert"] == own_cert
        assert c.get("/v2/devices/" + PRIMARY + "/revocation").json() == {"error": "not_found"}


@pytest.mark.parametrize("who", ["own", "other"])
def test_device_auth_cutoff_is_per_registry_pair(tmp_path, who):
    """P3-D30 (orch-52 ruling 2): another person's pair for the registered device id never ends its
    sessions, login, stored-certificate retries or member certificates; the registry person's does."""
    import sqlite3

    from orch_relay.directory import Refusal
    from orch_relay.members import certificate

    with TestClient(create_app(tmp_path)) as c:
        d = c.app.state.directory
        seed(d)
        with closing(db.connect(d.path)) as con, con:
            (_own_row if who == "own" else _other_person_row)(con, DEVICE)
        cut = who == "own"
        session = c.get("/v2/devices/" + DEVICE, headers={"Authorization": "Bearer FAKE-device"})
        assert session.status_code == (403 if cut else 200)
        login = issue_login(c)
        assert login.json() == {"error": "revoked"} if cut else login.status_code == 200
        put = c.put("/v2/devices/" + DEVICE, json={"cert": CERT})
        assert (put.status_code, put.json()) == (
            (403, {"error": "revoked"}) if cut else (200, {"device_id": DEVICE})
        )
        member = {"device_id": DEVICE, "person_id": PERSON, "scopes": ["look"]}
        with closing(db.connect(d.path)) as con:
            con.row_factory = sqlite3.Row
            if cut:
                with pytest.raises(Refusal) as refused:
                    certificate(con, member, PERSON, [], NOW)
                assert refused.value.code == "revoked"
            else:
                certificate(con, member, PERSON, [], NOW)


def test_cutoff_person_comes_from_the_registry_row_not_the_request(tmp_path):
    """The pair is (device, devices.person_id): bob's revoked pair for alice's device never turns
    bob's certificate for that id or bob's list entry into 'revoked'; they keep their own refusals."""
    import sqlite3

    from orch_relay.directory import Refusal
    from orch_relay.members import certificate

    with TestClient(create_app(tmp_path)) as c:
        d = c.app.state.directory
        seed(d)
        with closing(db.connect(d.path)) as con, con:
            con.execute("INSERT INTO accounts VALUES (?,?,?)", (BOB, BOB_PK, NOW))
            _other_person_row(con, DEVICE)
        bob_cert = _cert_of(BOB, "person_bob.sig")
        r = c.put("/v2/devices/" + DEVICE, json={"cert": bob_cert})
        assert (r.status_code, r.json()) == (409, {"error": "cert_conflict"})
        with closing(db.connect(d.path)) as con:
            con.row_factory = sqlite3.Row
            with pytest.raises(Refusal) as refused:
                certificate(
                    con,
                    {"device_id": DEVICE, "person_id": BOB, "scopes": ["look"]},
                    PERSON,
                    [BOB],
                    NOW,
                )
            assert refused.value.code == "other_person"


def _register(c, route, invite):
    if route == "put":
        return c.put("/v2/devices/" + DEVICE, json={"cert": CERT})
    return c.post("/v2/accounts", json=account_body(c, invite))


@pytest.mark.parametrize("route", ["put", "account"])
@pytest.mark.parametrize(
    "evidence,refused",
    [("chain_other", True), ("chain_own", True), ("feed_own", True), ("feed_other", False)],
)
def test_new_registration_refused_on_chain_learned_revocation(tmp_path, route, evidence, refused):
    """P3-D30 (orch-52 rulings 2 and 4): PUT /v2/devices and POST /v2/accounts refuse a new
    registration of a device id with a chain-learned revocation of ANY person (403 revoked, nothing
    written), and a revocation of the new pair itself; out-of-band-only evidence of another person
    (a squatted id) never refuses it, and the registered device then logs in (with the invite used,
    it must: the cutoff after registration is per pair)."""
    from orch_relay.directory import create_invite

    invite = create_invite(tmp_path / db.DB_NAME, DAY)
    with TestClient(create_app(tmp_path)) as c:
        d = c.app.state.directory
        seed(d, accounts=route == "put", devices=False, card=False)
        with closing(db.connect(d.path)) as con, con:
            if evidence == "chain_other":
                _chain_row(con, DEVICE, BOB, "person_bob.sig", BOB_PK)
            elif evidence == "chain_own":
                _chain_row(con, DEVICE, PERSON, "person_alice.sig", PK)
            elif evidence == "feed_own":
                _own_row(con)
            else:
                _other_person_row(con, DEVICE)
        r = _register(c, route, invite)
        with closing(db.connect(d.path)) as con:
            devices = con.execute("SELECT person_id FROM devices").fetchall()
            accounts = con.execute("SELECT person_id FROM accounts").fetchall()
            used = con.execute("SELECT used_ms FROM invites").fetchone()[0]
        if refused:
            assert (r.status_code, r.json()) == (403, {"error": "revoked"})
            assert devices == [] and used is None
            assert accounts == ([(PERSON,)] if route == "put" else [])
        else:
            assert r.status_code == 200, r.text
            assert devices == [(PERSON,)]
            assert issue_login(c).status_code == 200


def test_account_exact_retry_after_revocation_writes_nothing(tmp_path):
    """The exact same account request is answered 200 from the invite's digest even after the device
    was revoked; it writes nothing and grants nothing (login stays refused)."""
    from orch_relay.directory import create_invite

    invite = create_invite(tmp_path / db.DB_NAME, DAY)
    with TestClient(create_app(tmp_path)) as c:
        d = c.app.state.directory
        d.clock = lambda: NOW
        body = account_body(c, invite)
        assert c.post("/v2/accounts", json=body).status_code == 200
        assert c.post("/v2/revocations", json={"record": RECORD}).status_code == 200
        with closing(db.connect(d.path)) as con:
            before = [
                con.execute(f"SELECT * FROM {t}").fetchall()
                for t in ("accounts", "devices", "invites", "sessions")
            ]
        assert c.post("/v2/accounts", json=body).json() == {"person_id": PERSON}
        with closing(db.connect(d.path)) as con:
            after = [
                con.execute(f"SELECT * FROM {t}").fetchall()
                for t in ("accounts", "devices", "invites", "sessions")
            ]
        assert after == before
        assert issue_login(c).json() == {"error": "revoked"}


@pytest.mark.parametrize("who", ["own", "other", "unregistered"])
def test_revoke_cutoff_only_for_the_registry_pair(tmp_path, who):
    """P3-D30: revoke() always stores the pair, but deletes sessions, prunes the device's queues and
    sets rotation_due only when the record's person is the registry person. A revocation of an
    unregistered id has nothing to cut off."""
    import sqlite3

    with TestClient(create_app(tmp_path)) as c:
        d = c.app.state.directory
        seed(d)
        did = DEVICE if who != "unregistered" else V["ids"]["device_intruder"]
        person, key = (PERSON, "person_alice.sig") if who == "own" else (BOB, "person_bob.sig")
        record = signed({**RECORD["o"], "device_id": did, "person_id": person}, key)
        with closing(db.connect(d.path)) as con, con:
            con.row_factory = sqlite3.Row
            con.execute("INSERT INTO wk_grants VALUES (?,?,?,?)", (WS, DEVICE, 1, b"{}"))
            d.revoke(con, record, NOW)
        cut = who == "own"
        with closing(db.connect(d.path)) as con:
            assert con.execute(
                "SELECT 1 FROM revocations WHERE device_id=? AND person_id=?", (did, person)
            ).fetchone()
            sessions = con.execute("SELECT COUNT(*) FROM sessions WHERE kind='device'").fetchone()[
                0
            ]
            grants = con.execute("SELECT COUNT(*) FROM wk_grants").fetchone()[0]
            due = con.execute("SELECT COUNT(*) FROM rotation_due").fetchone()[0]
        assert sessions == (0 if cut else 1)
        assert grants == (0 if cut else 1)
        assert due == (1 if cut else 0)


@pytest.mark.parametrize("who", ["own", "other", "evidence_only"])
def test_bridge_notice_cursor_counts_registry_pairs_only(tmp_path, who):
    """P3-D30: the host's revocations_cursor moves only for an associated pair of an ever-device: the
    registry person's, and not when that registry row belongs to a P3-D29 evidence-only person
    (the unpublished-eligibility filter); another person's pair never moves it."""
    from orch_relay.bridge import notices

    with TestClient(create_app(tmp_path)) as c:
        d = c.app.state.directory
        seed(d)
        with closing(db.connect(d.path)) as con, con:
            (_other_person_row if who == "other" else _own_row)(con, DEVICE)
            if who == "evidence_only":
                con.execute("INSERT INTO evidence_persons VALUES (?)", (PERSON,))
            assert notices(con, WS)["revocations_cursor"] == (1 if who == "own" else 0)
