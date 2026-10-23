"""E1: hub -> relay requests signed by HK_op (orch-hub contract phase 4, protocol.md §10.8). FAKE keys only.

Part 1 runs the shared `relay_request` vectors through `HubAccounts.authenticate`; part 2 is adversarial and goes
through the real HTTP stack (a test-only route behind `app.state.hub_request_auth`)."""

import json
from pathlib import Path

import pytest
from fastapi import Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from push_support import clear
from test_hub_accounts import HID, NOW, OP1, ROGUE, ROOT, Key, card1, make_card, op_cert, revocation

from orch_relay import hub_accounts as H
from orch_relay import proto as P
from orch_relay.app import create_app
from orch_relay.common import Refusal, error_response

VECTORS = json.loads((Path(__file__).parent / "vectors/hub/vectors_hub.json").read_text())
CASES = [c for c in VECTORS["cases"] if c["check"] == "relay_request"]


@pytest.fixture
def relay(tmp_path, monkeypatch):
    def make(dev=True, now=NOW):
        clear(monkeypatch)
        listing = tmp_path / "allow.txt"
        listing.write_text(f"{ROOT.text}\n")
        monkeypatch.setenv("ORCH_RELAY_HUB_ALLOWLIST", str(listing))
        if dev:
            monkeypatch.setenv("ORCH_RELAY_DEV", "1")
        else:
            monkeypatch.delenv("ORCH_RELAY_DEV", raising=False)
        client = TestClient(create_app(tmp_path / ("data-dev" if dev else "data-real")))
        client.__enter__()
        client.app.state.clock = [now]
        client.app.state.core.clock = lambda: client.app.state.clock[0]
        made.append(client)
        return client

    made = []
    yield make
    for client in made:
        client.__exit__(None, None, None)


def insert_account(client, card):
    """Store a card as the relay would hold it (bypassing registration so a dev card can sit on a real relay)."""
    o, op = card["o"], card["op_cert"]["o"]
    d = client.app.state.core
    with d.lock:
        con = d.connection("write")
        with con:
            con.execute(
                "INSERT INTO hub_accounts VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    o["hub_id"],
                    o["hk_root_pub"],
                    op["cert_id"],
                    op["op_seq"],
                    op["expires_ms"],
                    o["card_seq"],
                    int(o["dev"]),
                    P.cj(card).decode(),
                    0,
                    0,
                ),
            )


def run_vector(relay, a):
    client = relay(dev=a["dev_mode"], now=a["now_ms"])
    card = a["hub_card"]
    if card["o"]["hub_id"] == a["hub_id"]:
        insert_account(client, card)
    d = client.app.state.core
    with d.lock:
        con = d.connection("write")
        with con:
            for cert in a.get("revoked_op_certs", []):
                con.execute(
                    "INSERT INTO hub_op_revoked VALUES (?,?,?,?)", (card["o"]["hub_id"], cert, 0, 0)
                )
            for hub, seen in a.get("nonces", {}).items():
                for nonce, ts in seen.items():
                    con.execute("INSERT INTO hub_request_nonces VALUES (?,?,?)", (hub, nonce, ts))
    r = a["request"]
    return client.app.state.hub_accounts.authenticate(
        r["method"], r["target"], r["headers"], bytes.fromhex(r["body_hex"])
    )


def test_vectors_present():
    assert len(CASES) == 24


@pytest.mark.parametrize("case", CASES, ids=lambda c: c["name"])
def test_vector(case, relay):
    expect = case["expect"]
    if "ok" in expect:
        assert run_vector(relay, case["args"]) == expect["ok"]["hub"]
        return
    with pytest.raises(Refusal) as e:
        run_vector(relay, case["args"])
    assert e.value.code == expect["error"]


# --- adversarial, over HTTP ---------------------------------------------------------------------------------------


def req_bytes(hub, cert, ts, nonce, method, target, body):
    return H.request_bytes(hub, cert, ts, nonce, method, target, body)


def signed_headers(
    key, hub=HID, cert="aa" * 16, ts=NOW, nonce=b"\x01" * 16, method="POST", target=None, body=b"{}"
):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    target = target or f"/v2/hubs/{hub}/push"
    r, s = decode_dss_signature(
        key.priv.sign(
            req_bytes(hub, cert, ts, nonce, method, target, body), ec.ECDSA(hashes.SHA256())
        )
    )
    return {
        "Orch-Hub": hub,
        "Orch-Hub-Op-Cert": cert,
        "Orch-Hub-Ts": str(ts),
        "Orch-Hub-Nonce": nonce.hex(),
        "Orch-Hub-Signature": P.b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big")),
    }


@pytest.fixture
def http(relay):
    client = relay(dev=True)
    calls = []

    async def route(hub_id_text: str, tail: str, request: Request):
        try:
            hub, body = await client.app.state.hub_request_auth(request)
        except Refusal as error:
            return error_response(error)
        calls.append((hub, body))
        return JSONResponse({"ok": True})

    client.app.add_api_route("/v2/hubs/{hub_id_text}/{tail}", route, methods=["POST", "GET"])
    # E2 installs the real catch-all below /v2/hubs/{hub}/; this test-only route must be matched first
    client.app.router.routes.insert(0, client.app.router.routes.pop())
    assert client.post("/v2/hubs", json=card1()).status_code == 200
    client.calls = calls
    return client


def post(client, headers, target=None, body=b"{}", method="POST"):
    return client.request(method, target or f"/v2/hubs/{HID}/push", headers=headers, content=body)


def err(r, status, code):
    assert (r.status_code, r.json()["error"]) == (status, code), r.text


def test_valid_request_is_accepted_once(http):
    h = signed_headers(OP1)
    assert post(http, h).status_code == 200
    assert http.calls == [(HID, b"{}")]
    err(post(http, h), 401, "replay")  # same nonce: the state change is not repeated
    assert len(http.calls) == 1


def test_old_timestamp_is_refused_outside_the_window(http):
    h = signed_headers(OP1)
    assert post(http, h).status_code == 200
    http.app.state.clock[0] = NOW + 240_000
    err(post(http, h), 401, "stale_timestamp")  # outside the window the ts check refuses first


def test_window_boundary_is_exactly_120_seconds(http):
    for i, (delta, ok) in enumerate(
        [(-120_000, True), (120_000, True), (-120_001, False), (120_001, False)]
    ):
        h = signed_headers(OP1, ts=NOW + delta, nonce=bytes([0x40 + i]) * 16)
        if ok:
            assert post(http, h).status_code == 200
        else:
            err(post(http, h), 401, "stale_timestamp")


def test_same_nonce_is_accepted_for_two_hubs(http):
    other_op = Key("hk_op_rogue")
    card = make_card(ROGUE, other_op, op_cert(ROGUE, other_op, 1, "cc"))
    insert_account(http, card)
    other = card["o"]["hub_id"]
    nonce = b"\x77" * 16
    assert post(http, signed_headers(OP1, nonce=nonce)).status_code == 200
    h = signed_headers(other_op, hub=other, cert="cc" * 16, nonce=nonce)
    assert post(http, h, target=f"/v2/hubs/{other}/push").status_code == 200
    err(post(http, h, target=f"/v2/hubs/{other}/push"), 401, "replay")  # still once per hub


def test_nonce_recorded_only_after_signature(http):
    h = signed_headers(OP1)
    bad = {**h, "Orch-Hub-Signature": P.b64u(b"\x01" * 64)}
    err(post(http, bad), 401, "bad_hub_signature")
    assert post(http, h).status_code == 200  # the failed attempt did not burn the nonce


def test_changed_body(http):
    h = signed_headers(OP1, body=b'{"to":"a"}')
    err(post(http, h, body=b'{"to":"b"}'), 401, "bad_hub_signature")
    assert http.calls == []


def test_changed_target_same_hub(http):
    h = signed_headers(OP1, target=f"/v2/hubs/{HID}/push")
    err(post(http, h, target=f"/v2/hubs/{HID}/mailbox"), 401, "bad_hub_signature")


def test_target_outside_the_hubs_own_account(http):
    other = "1d" * 16
    h = signed_headers(OP1, target=f"/v2/hubs/{other}/push")
    err(post(http, h, target=f"/v2/hubs/{other}/push"), 403, "other_hub")
    assert http.calls == []


def test_percent_encoded_target_is_malformed_at_the_route(http):
    t = f"/v2/hubs/{HID}/pu%73h"
    err(
        http.request("POST", t, headers=signed_headers(OP1, target=t), content=b"{}"),
        400,
        "malformed",
    )
    assert http.calls == []


def test_stale_timestamp_reports_server_time(http):
    h = signed_headers(OP1, ts=NOW - 121_000)
    r = post(http, h)
    err(r, 401, "stale_timestamp")
    assert r.json()["server_ms"] == NOW


def test_wrong_signer_and_old_op_cert(http):
    err(post(http, signed_headers(ROOT)), 401, "bad_hub_signature")  # HK_root cannot sign requests
    err(post(http, signed_headers(OP1, cert="bb" * 16)), 401, "stale_op_cert")


def test_revoked_op_cert_refused_at_use(http):
    assert post(http, signed_headers(OP1)).status_code == 200
    r = http.post(
        "/v2/hubs/op-revoked",
        json={"hk_root_pub": ROOT.text, "revocation": revocation(ROOT, "aa" * 16)},
    )
    assert r.status_code == 200
    err(post(http, signed_headers(OP1, nonce=b"\x02" * 16)), 401, "unknown_hub")


def test_expired_op_cert_refused_at_use(http):
    assert post(http, signed_headers(OP1)).status_code == 200
    late = NOW + 10**9  # the cert expires at NOW + 10**9
    http.app.state.clock[0] = late
    err(post(http, signed_headers(OP1, ts=late, nonce=b"\x03" * 16)), 401, "unknown_hub")


def test_rotated_card_replaces_the_signer(http):
    from test_hub_accounts import card2

    assert http.post("/v2/hubs", json=card2()).status_code == 200
    err(post(http, signed_headers(OP1)), 401, "stale_op_cert")


def test_dev_card_on_real_relay(relay):
    client = relay(dev=False)
    insert_account(client, card1(dev=True))  # a dev card that somehow sits on a real relay
    with pytest.raises(Refusal) as e:
        client.app.state.hub_accounts.authenticate(
            "POST", f"/v2/hubs/{HID}/push", signed_headers(OP1), b"{}"
        )
    assert (e.value.code, e.value.status) == ("unknown_hub", 401)


def test_unknown_hub_and_missing_headers(http):
    h = signed_headers(OP1, hub="2e" * 16, target=f"/v2/hubs/{'2e' * 16}/push")
    err(post(http, h, target=f"/v2/hubs/{'2e' * 16}/push"), 401, "unknown_hub")
    h = signed_headers(OP1)
    del h["Orch-Hub-Nonce"]
    err(post(http, h), 400, "malformed")


def test_bad_method(http):
    h = signed_headers(OP1, method="PATCH")
    r = http.request("PATCH", f"/v2/hubs/{HID}/push", headers=h, content=b"{}")
    assert r.status_code == 405 and http.calls == []


def test_nonces_are_pruned(http):
    assert post(http, signed_headers(OP1)).status_code == 200
    http.app.state.clock[0] = NOW + 250_000
    assert post(http, signed_headers(OP1, ts=NOW + 250_000, nonce=b"\x09" * 16)).status_code == 200
    d = http.app.state.core
    with d.reader("query") as con:
        assert con.execute("SELECT count(*) FROM hub_request_nonces").fetchone()[0] == 1


def test_real_card_on_dev_relay(relay):
    client = relay(dev=True)
    insert_account(client, card1(dev=False))  # a real card that sits on a dev relay
    with pytest.raises(Refusal) as e:
        client.app.state.hub_accounts.authenticate(
            "POST", f"/v2/hubs/{HID}/push", signed_headers(OP1), b"{}"
        )
    assert (e.value.code, e.value.status) == ("unknown_hub", 401)
