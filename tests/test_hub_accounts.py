"""E1: relay accounts of kind `hub`, registered by hub card (orch-hub contract H0 §4-§5). FAKE keys only
(seed = SHA-256("FAKE orch v2 test vector: hub/" || name), like the shared vectors)."""

import hashlib
import json
from contextlib import closing
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from push_support import clear

from orch_relay import db
from orch_relay import hub_accounts as H
from orch_relay import proto as P
from orch_relay.app import create_app

V = json.loads((Path(__file__).parent / "vectors/hub/vectors_hub.json").read_text())
NOW = V["now_ms"]
N = P.P256_N


class Key:
    def __init__(self, name):
        from cryptography.hazmat.primitives.asymmetric import ec

        seed = hashlib.sha256(b"FAKE orch v2 test vector: hub/" + name.encode()).digest()
        self.priv = ec.derive_private_key(int.from_bytes(seed, "big") % (N - 1) + 1, ec.SECP256R1())
        raw = self.priv.public_key().public_numbers()
        self.pub = b"\x04" + raw.x.to_bytes(32, "big") + raw.y.to_bytes(32, "big")
        self.text = P.b64u(self.pub)

    def sign(self, label, o):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

        r, s = decode_dss_signature(self.priv.sign(label + P.cj(o), ec.ECDSA(hashes.SHA256())))
        return {"o": o, "sig": P.b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))}


def header(kind):
    return {"v": 2, "suite": 2, "kind": kind, "hv": 0}


def op_cert(root, op, seq=1, cert="aa", dev=True, issued=NOW - 1000, expires=NOW + 10**9):
    o = {
        **header("hub.op_cert"),
        "hub_id": H.hub_id(root.pub),
        "cert_id": cert * 16,
        "op_seq": seq,
        "hk_op_pub": op.text,
        "issued_ms": issued,
        "expires_ms": expires,
        "dev": dev,
    }
    return root.sign(H.L_OP_CERT, o)


def make_card(root, op, cert, card_seq=1, dev=True, relay_url=None, hub=None, reader=1, **extra):
    o = {
        **header("hub.card"),
        "hub_id": hub or H.hub_id(root.pub),
        "hk_root_pub": root.text,
        "hxk_pub": Key("hxk").text,
        "relay_url": relay_url,
        "tls_spki_sha256": P.b64u(b"\x07" * 32),
        "card_seq": card_seq,
        "reader": reader,
        "issued_ms": NOW - 1000,
        "dev": dev,
        **extra,
    }
    card = op.sign(H.L_CARD, o)
    card["op_cert"] = cert
    return card


def revocation(root, cert_id, dev=True):
    o = {
        **header("hub.op_revoked"),
        "hub_id": H.hub_id(root.pub),
        "cert_id": cert_id,
        "revoked_ms": NOW,
        "dev": dev,
    }
    return root.sign(H.L_OP_REVOKED, o)


ROOT, OP1, OP2 = Key("hk_root"), Key("hk_op"), Key("hk_op_next")
ROGUE = Key("hk_root_rogue")
HID = H.hub_id(ROOT.pub)


def card1(dev=True, **kw):
    return make_card(ROOT, OP1, op_cert(ROOT, OP1, 1, "aa", dev), dev=dev, **kw)


def card2(card_seq=1, dev=True, **kw):
    return make_card(ROOT, OP2, op_cert(ROOT, OP2, 2, "bb", dev), card_seq, dev=dev, **kw)


def make_client(tmp_path, monkeypatch, dev, allow=(ROOT, ROGUE)):
    clear(monkeypatch)
    listing = tmp_path / "hub-allowlist.txt"
    listing.write_text("# operator allowlist\n" + "".join(f"{k.text}  # fake\n" for k in allow))
    monkeypatch.setenv("ORCH_RELAY_HUB_ALLOWLIST", str(listing))
    if dev:
        monkeypatch.setenv("ORCH_RELAY_DEV", "1")
    else:
        monkeypatch.delenv("ORCH_RELAY_DEV", raising=False)
    client = TestClient(create_app(tmp_path / "data"))
    client.__enter__()
    client.app.state.core.clock = lambda: NOW
    return client


@pytest.fixture
def c(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch, dev=True)
    yield client
    client.__exit__(None, None, None)


@pytest.fixture
def real(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch, dev=False)
    yield client
    client.__exit__(None, None, None)


def put(client, card):
    return client.post("/v2/hubs", json=card)


def revoke(client, root, cert_id, signer=None, dev=True):
    body = {"hk_root_pub": root.text, "revocation": revocation(signer or root, cert_id, dev)}
    return client.post("/v2/hubs/op-revoked", json=body)


def err(r, status, code):
    assert (r.status_code, r.json()["error"]) == (status, code), r.text


def test_register_and_read(c):
    r = put(c, card1())
    assert r.status_code == 200
    assert r.json() == {
        "hub_id": HID,
        "op_cert_id": "aa" * 16,
        "op_seq": 1,
        "card_seq": 1,
        "created": True,
    }
    shown = c.get(f"/v2/hubs/{HID}").json()
    assert shown["revoked"] is False and shown["card"]["o"]["hub_id"] == HID
    err(c.get("/v2/hubs/" + "00" * 16), 404, "unknown_hub")


def test_resend_is_idempotent_and_card_with_relay_url(c):
    same = (
        card1()
    )  # ECDSA signatures are randomised: a resend is the same bytes, not a re-signed card
    assert put(c, same).json()["created"] is True
    assert put(c, same).json()["created"] is False
    err(put(c, card1(relay_url="https://relay.dev.severin.io")), 409, "stale_card")
    assert put(c, card1(card_seq=2, relay_url="https://relay.dev.severin.io")).status_code == 200
    err(put(c, card1(card_seq=1)), 409, "stale_card")


def test_rotation_replaces_and_old_op_seq_is_refused(c):
    put(c, card1())
    r = put(c, card2())
    assert r.status_code == 200 and r.json()["op_seq"] == 2 and r.json()["created"] is False
    assert c.get(f"/v2/hubs/{HID}").json()["card"]["op_cert"]["o"]["op_seq"] == 2
    # the old HK_op cannot roll the rotation back, however high its card_seq
    err(put(c, card1(card_seq=2**53 - 1)), 409, "stale_op_cert")
    # the same op_seq under another cert_id
    other = make_card(ROOT, OP1, op_cert(ROOT, OP1, 2, "cc"), 9)
    err(put(c, other), 409, "stale_op_cert")


def test_foreign_root_and_wrong_ids_refused(c):
    put(c, card1())
    # a card of another root claiming this hub_id
    forged = make_card(ROGUE, Key("hk_op_rogue"), op_cert(ROGUE, Key("hk_op_rogue")), hub=HID)
    err(put(c, forged), 400, "hub_id_mismatch")
    # an op cert of another root under this root's card
    swapped = make_card(ROOT, OP1, op_cert(ROGUE, OP1))
    err(put(c, swapped), 401, "bad_signature")
    # an op cert signed by the op key itself
    selfcert = make_card(ROOT, OP1, op_cert(OP1, OP1))
    err(put(c, selfcert), 401, "bad_signature")
    # a different hub registers as its own account and never touches this one
    rogue = make_card(ROGUE, Key("hk_op_rogue"), op_cert(ROGUE, Key("hk_op_rogue")))
    assert put(c, rogue).json()["hub_id"] == H.hub_id(ROGUE.pub)
    assert c.get(f"/v2/hubs/{HID}").json()["card"]["o"]["hk_root_pub"] == ROOT.text


def test_dev_marker_must_match_relay(c, real):
    err(put(c, card1(dev=False)), 403, "dev_mismatch")
    err(put(real, card1(dev=True)), 403, "dev_refused")
    assert put(real, card1(dev=False)).status_code == 200
    # a dev op cert under a real card is refused too
    mixed = make_card(ROOT, OP1, op_cert(ROOT, OP1, dev=True), dev=False)
    err(put(real, mixed), 403, "dev_refused")


def test_revocation(c):
    put(c, card1())
    err(revoke(c, ROOT, "aa" * 16, signer=ROGUE), 401, "bad_signature")  # another root signed it
    err(revoke(c, ROOT, "aa" * 16, signer=OP1), 401, "bad_signature")  # only HK_root revokes
    r = revoke(c, ROOT, "aa" * 16)
    assert r.status_code == 200 and r.json()["revoked"] is True
    assert revoke(c, ROOT, "aa" * 16).status_code == 200  # idempotent
    assert c.get(f"/v2/hubs/{HID}").json()["revoked"] is True
    err(put(c, card1(card_seq=2)), 403, "revoked")
    # the rotation to a fresh op cert re-opens the account
    assert put(c, card2()).status_code == 200
    assert c.get(f"/v2/hubs/{HID}").json()["revoked"] is False


def test_not_allowlisted_root_cannot_create_but_listed_can_rotate(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch, dev=True, allow=(ROOT,))
    with client:
        rogue = make_card(ROGUE, Key("hk_op_rogue"), op_cert(ROGUE, Key("hk_op_rogue")))
        err(put(client, rogue), 403, "not_allowed")
        assert put(client, card1()).status_code == 200
        # removing the entry later does not strand an existing account's rotation
        (tmp_path / "hub-allowlist.txt").write_text("")
        assert put(client, card2()).status_code == 200
        err(
            put(client, make_card(ROGUE, Key("hk_op_rogue"), op_cert(ROGUE, Key("hk_op_rogue")))),
            403,
            "not_allowed",
        )
        (tmp_path / "hub-allowlist.txt").unlink()  # unreadable list = nobody
        err(put(client, rogue), 403, "not_allowed")
    client.__exit__(None, None, None) if False else None


def test_revocation_for_unadmitted_root_is_refused_and_stores_nothing(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch, dev=True, allow=(ROOT,))
    with client:
        err(revoke(client, ROGUE, "aa" * 16), 403, "unknown_hub")
        with closing(db.connect(client.app.state.core.path)) as con:
            assert con.execute("SELECT count(*) FROM hub_op_revoked").fetchone() == (0,)
        # allowlisted root, no account yet: stored, and applied when the hub registers
        assert revoke(client, ROOT, "aa" * 16).json()["revoked"] is True
        err(put(client, card1()), 403, "revoked")
        assert put(client, card2()).status_code == 200  # a fresh op cert is fine
        # storage bound per hub
        for n in range(H.MAX_REVOCATIONS_PER_HUB):
            client.app.state.core.windows.clear()
            r = revoke(client, ROOT, f"{n + 16:032x}")
            if r.status_code != 200:
                break
        client.app.state.core.windows.clear()
        err(revoke(client, ROOT, "ff" * 16), 429, "quota_exceeded")


def test_revocation_before_registration_and_dev_marker_not_checked(real):
    # L2-8: a root-signed revocation is accepted whatever its dev marker (here dev:true at a real relay)
    assert revoke(real, ROOT, "aa" * 16, dev=True).status_code == 200
    err(put(real, card1(dev=False)), 403, "revoked")


def test_malformed_bodies(c):
    for body in (b"", b"[]", b'{"o":1,"sig":"x"}', b"{" * 40, b'{"a":1.5}'):
        r = c.post("/v2/hubs", content=body, headers={"content-type": "application/json"})
        assert r.status_code == 400 and r.json()["error"] == "malformed"
    r = c.post(
        "/v2/hubs", content=b"x" * (H.REQUEST_CAP + 1), headers={"content-type": "application/json"}
    )
    assert r.status_code == 413
    assert (
        c.post("/v2/hubs", content=b"{}", headers={"content-type": "text/plain"}).status_code == 400
    )
    err(c.post("/v2/hubs/op-revoked", json={"hk_root_pub": ROOT.text}), 400, "malformed")
    assert c.get("/v2/hubs/NOT-HEX").status_code == 400


def test_account_cap_and_rate_limit(c):
    c.app.state.hub_accounts.max_accounts = 1
    assert put(c, card1()).status_code == 200
    rogue = make_card(ROGUE, Key("hk_op_rogue"), op_cert(ROGUE, Key("hk_op_rogue")))
    err(put(c, rogue), 429, "quota_exceeded")
    assert put(c, card2()).status_code == 200  # a rotation is not a new account
    c.app.state.hub_accounts.max_accounts = 1000
    c.app.state.core.windows.clear()
    for _ in range(H.REGISTER_PER_HOUR):
        c.post("/v2/hubs", json={})
    err(c.post("/v2/hubs", json={}), 429, "rate_limited")


def test_card_with_reader_registers_and_reader_downgrade_is_refused(c):
    assert put(c, card1(reader=2)).status_code == 200
    err(put(c, card1(card_seq=2, reader=1)), 409, "reader_downgrade")
    assert put(c, card1(card_seq=2, reader=3)).status_code == 200


def test_unknown_extra_card_field_is_still_malformed(c):
    err(put(c, card1(extra_field=1)), 400, "malformed")
