"""E2: hub push targets, push sends and channel mailboxes (orch-hub contract §10.8.1). FAKE keys only.

Part 1 replays the shared `relay_route_*` vectors and the signed requests of `phase4.relay_routes`; part 2 drives every
route over HTTP (signed by HK_op, a fake APNs behind the existing sender); part 3 is adversarial."""

import hashlib
import json
import struct
from pathlib import Path

import pytest
from fake_apns import FakeApns, wait_for
from fastapi.testclient import TestClient
from push_support import KID, TEAM, TOKEN_A, TOKEN_B, TOPIC, clear, configure, rid
from test_hub_accounts import NOW, OP1, ROGUE, Key, make_card, op_cert
from test_hub_relay_requests import insert_account

from orch_relay import hub_accounts as H
from orch_relay import hub_phone as HP
from orch_relay import proto as P
from orch_relay.app import create_app
from orch_relay.directory import Refusal

VECTORS = json.loads((Path(__file__).parent / "vectors/hub/vectors_hub.json").read_text())
ROUTE_CASES = [
    c
    for c in VECTORS["cases"]
    if c["check"] == "relay_route"
    and "cutover" not in c["name"]  # the cut-over cases: test_cutover_gate.py
]
ROUTES = VECTORS["phase4"]["relay_routes"]
CARD = next(c for c in VECTORS["cases"] if c["check"] == "relay_request")["args"]["hub_card"]
HUB = CARD["o"]["hub_id"]
CERT = CARD["op_cert"]["o"]["cert_id"]
CH = "a521208444bffafc2188fe6b5f1f286f"  # the vectors' channel
CH2 = "5e1b2a08851687fe75c4fa214a501b97"
MSG = "c8aa32bb1061a22d4186323aa01b2902"


# --- part 1: the shared vectors ---------------------------------------------------------------------------------------


def test_vectors_present():
    assert len(ROUTE_CASES) == 36 and set(ROUTES) - {"cutover_get", "cutover_put"} == {
        "mailbox_put",
        "push_put",
        "push_seal",
        "push_send",
    }


@pytest.mark.parametrize("case", ROUTE_CASES, ids=lambda c: c["name"])
def test_route_vector(case):
    a, expect = case["args"], case["expect"]
    path, _, query = a["target"].partition("?")
    try:
        H.parse_target(
            a["target"], a["hub_id"]
        )  # E1's canonical-target check (other_hub lives there)
        if not a.get("push_configured", True) and not HP.push_exempt(a["method"], path):
            raise Refusal("not_found")  # E5R-1: the install() gate of a relay without push
        route, ch, mid, _body = HP.match(
            a["method"], path, query, a["hub_id"], bytes.fromhex(a["body_hex"])
        )
    except Refusal as e:
        assert "error" in expect and e.code == expect["error"]
        return
    assert expect["ok"] == {
        "route": route,
        "channel_id": ch,
        **({"id": mid} if mid and route != "push_send" else {}),
    }


@pytest.mark.parametrize(
    "name", ["push_put", "push_send", "mailbox_put", "cutover_put", "cutover_get"]
)
def test_signed_bytes_vector(name):
    v = ROUTES[name]
    raw = bytes.fromhex(v["signed_hex"])
    assert raw.startswith(H.L_RELAY_REQ + b"\x02" + bytes.fromhex(HUB))
    ts = struct.unpack(">Q", raw[len(H.L_RELAY_REQ) + 33 : len(H.L_RELAY_REQ) + 41])[0]
    nonce = raw[len(H.L_RELAY_REQ) + 41 : len(H.L_RELAY_REQ) + 57]
    rebuilt = H.request_bytes(
        HUB, CERT, ts, nonce, v["method"], v["target"], bytes.fromhex(v["body_hex"])
    )
    assert rebuilt == raw


# --- part 2: the routes over HTTP -------------------------------------------------------------------------------------


class Hub:
    """Signs requests as a hub (HK_op) with a fresh nonce each time unless told otherwise."""

    def __init__(self, client, key, hub, cert):
        self.client, self.key, self.hub, self.cert, self.n = client, key, hub, cert, 0

    def headers(self, method, target, body=b"", nonce=None, ts=None):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

        self.n += 1
        nonce = nonce or hashlib.sha256(self.hub.encode() + self.n.to_bytes(4, "big")).digest()[:16]
        ts = self.client.app.state.clock[0] if ts is None else ts
        message = H.request_bytes(self.hub, self.cert, ts, nonce, method, target, body)
        r, s = decode_dss_signature(self.key.priv.sign(message, ec.ECDSA(hashes.SHA256())))
        return {
            "Orch-Hub": self.hub,
            "Orch-Hub-Op-Cert": self.cert,
            "Orch-Hub-Ts": str(ts),
            "Orch-Hub-Nonce": nonce.hex(),
            "Orch-Hub-Signature": P.b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big")),
        }

    def call(self, method, target, body=b"", **kw):
        if isinstance(body, dict):
            body = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        return self.client.request(
            method, target, headers=self.headers(method, target, body, **kw), content=body
        )

    def base(self, hub=None):
        return f"/v2/hubs/{hub or self.hub}"

    def push_put(self, ch=CH, token=TOKEN_A, env="sandbox", topic=TOPIC, **kw):
        body = {"v": 2, "env": env, "topic": topic, "token": P.b64u(token)}
        return self.call("PUT", f"{self.base()}/push/{ch}", body, **kw)

    def push_delete(self, ch=CH, **kw):
        return self.call("DELETE", f"{self.base()}/push/{ch}", **kw)

    def outer(self, mid, ch=CH, c="AAEC"):
        return {"v": 2, "hub": self.hub, "ch": ch, "id": mid, "c": c}

    def send(self, mid, ch=CH, c="AAEC", priority="high", ttl_s=60, **kw):
        body = {"v": 2, "outer": self.outer(mid, ch, c), "priority": priority, "ttl_s": ttl_s}
        return self.call("POST", f"{self.base()}/push/{ch}/send", body, **kw)

    def mb_put(self, mid=MSG, ch=CH, c=b"sealed message", ttl_s=3600, **kw):
        body = {"v": 2, "c": P.b64u(c), "ttl_s": ttl_s}
        return self.call("PUT", f"{self.base()}/mailbox/{ch}/{mid}", body, **kw)

    def mb_get(self, mid=MSG, ch=CH, **kw):
        return self.call("GET", f"{self.base()}/mailbox/{ch}/{mid}", **kw)

    def mb_delete(self, mid=MSG, ch=CH, **kw):
        return self.call("DELETE", f"{self.base()}/mailbox/{ch}/{mid}", **kw)

    def mb_purge(self, ch=CH, **kw):
        return self.call("DELETE", f"{self.base()}/mailbox/{ch}", **kw)


def err(r, status, code):
    assert (r.status_code, r.json()["error"]) == (status, code), r.text


def make(tmp_path, monkeypatch, configured=True):
    if configured:
        keys = configure(monkeypatch, tmp_path)
    else:
        clear(monkeypatch)
        keys = None
    listing = tmp_path / "allow.txt"
    listing.write_text(f"{CARD['o']['hk_root_pub']}\n{ROGUE.text}\n")
    monkeypatch.setenv("ORCH_RELAY_HUB_ALLOWLIST", str(listing))
    monkeypatch.setenv("ORCH_RELAY_DEV", "1")
    client = TestClient(create_app(tmp_path / "data"))
    client.__enter__()
    client.app.state.clock = [NOW]
    d = client.app.state.directory
    d.clock = lambda: client.app.state.clock[0]
    client.keys = keys
    if keys:
        push = client.app.state.push
        client.fake = FakeApns(keys, TEAM, TOPIC, KID)
        push.apns.transport = client.fake
        push.apns.retry_delays = (0, 0)
        push.sender.rate_per_s = 10_000
    assert client.post("/v2/hubs", json=CARD).status_code == 200
    return client


@pytest.fixture
def hub(tmp_path, monkeypatch):
    client = make(tmp_path, monkeypatch)
    yield Hub(client, OP1, HUB, CERT)
    client.__exit__(None, None, None)
    assert client.fake.errors == []


@pytest.fixture
def other(hub):
    """A second hub account on the same relay (same channel ids are possible for both)."""
    op = Key("hk_op_rogue")
    card = make_card(ROGUE, op, op_cert(ROGUE, op, 1, "cc"))
    insert_account(hub.client, card)
    return Hub(hub.client, op, card["o"]["hub_id"], "cc" * 16)


def settle(hub, n):
    assert wait_for(lambda: len(hub.client.fake.requests) >= n)
    assert wait_for(lambda: hub.client.app.state.push.outbox.queued() == 0)


def rows(hub, table="hub_push_targets", where="1", args=()):
    d = hub.client.app.state.directory
    with d.reader("query") as con:
        con.execute("BEGIN")
        return [dict(r) for r in con.execute(f"SELECT * FROM {table} WHERE {where}", args)]


def test_vector_requests_end_to_end(hub):
    """The vectors' own bodies and targets, signed by the vector hub's HK_op, through all seven routes."""
    put, send, mb = ROUTES["push_put"], ROUTES["push_send"], ROUTES["mailbox_put"]
    r = hub.call(put["method"], put["target"], bytes.fromhex(put["body_hex"]))
    assert (r.status_code, r.json()) == (200, {"channel_id": CH, "registered": True})
    r = hub.call(send["method"], send["target"], bytes.fromhex(send["body_hex"]))
    assert (r.status_code, r.json()) == (200, {"accepted": 1})
    settle(hub, 1)
    outer = json.loads(bytes.fromhex(send["body_hex"]))["outer"]
    (req,) = hub.client.fake.requests
    assert req.outer == P.cj(outer).decode()  # the relay hands the sealed outer to APNs unchanged
    r = hub.call(mb["method"], mb["target"], bytes.fromhex(mb["body_hex"]))
    assert r.status_code == 200 and r.json()["id"] == MSG and r.json()["stored"] is True
    stored = P.unb64u(json.loads(bytes.fromhex(mb["body_hex"]))["c"])
    r = hub.mb_get()
    assert r.json() == {"id": MSG, "c": P.b64u(stored), "expires_ms": NOW + 86_400_000}
    assert hub.mb_delete().json() == {"id": MSG, "deleted": True}
    hub.mb_put()
    hub.mb_put(mid="11" * 16)
    assert hub.mb_purge().json() == {"channel_id": CH, "deleted": 2}
    assert hub.push_delete().json() == {"channel_id": CH, "registered": False}


def test_token_is_sealed_at_rest_and_never_returned(hub):
    r = hub.push_put()
    assert TOKEN_A.hex() not in r.text and P.b64u(TOKEN_A) not in r.text
    (row,) = rows(hub)
    assert TOKEN_A not in bytes(row["token_sealed"]) and row[
        "token_mac"
    ] == hub.client.app.state.push.token_mac(TOKEN_A)
    assert (row["hub_id"], row["channel_id"], row["env"], row["topic"]) == (
        HUB,
        CH,
        "sandbox",
        TOPIC,
    )


def test_push_target_replace_and_exact_repeat(hub):
    assert hub.push_put().status_code == 200
    (first,) = rows(hub)
    hub.client.app.state.clock[0] += 5000
    assert hub.push_put().status_code == 200  # an exact repeat is a no-op
    assert rows(hub) == [first]
    assert hub.push_put(token=TOKEN_B).status_code == 200  # a new token replaces the held one
    (second,) = rows(hub)
    assert second["token_mac"] != first["token_mac"] and second["created_ms"] == first["created_ms"]
    assert hub.send(MSG).json() == {"accepted": 1}
    settle(hub, 1)
    assert hub.client.fake.requests[0].path == "/3/device/" + TOKEN_B.hex()


def test_send_priority_ttl_dedup_and_no_target(hub):
    assert hub.send(MSG).json() == {"accepted": 0}  # no target: not an error
    hub.push_put()
    mid = "ab" * 16
    assert hub.send(mid, priority="normal", ttl_s=100).json() == {"accepted": 1}
    assert hub.send(mid, priority="normal", ttl_s=100).json() == {
        "accepted": 0
    }  # a retry reaches the phone once
    assert hub.send(mid, c="AAEDBA").json() == {
        "accepted": 0
    }  # keyed by (hub, channel, id), not by the bytes
    assert hub.send("cd" * 16, ttl_s=0).json() == {"accepted": 1}
    settle(hub, 2)
    a, b = hub.client.fake.requests
    assert (a.headers["apns-priority"], a.headers["apns-expiration"]) == (
        "5",
        str(NOW // 1000 + 100),
    )
    assert (b.headers["apns-priority"], b.headers["apns-expiration"]) == ("10", "0")


def test_apns_gone_removes_the_hub_target(hub):
    hub.push_put()
    hub.client.fake.reply((410, {"reason": "Unregistered", "timestamp": NOW + 1}))
    hub.send(MSG)
    settle(hub, 1)
    assert wait_for(lambda: rows(hub) == [])
    assert hub.send("ee" * 16).json() == {"accepted": 0}


def test_mailbox_basics_and_expiry(hub):
    r = hub.mb_put(ttl_s=60)
    assert r.json() == {"id": MSG, "stored": True, "expires_ms": NOW + 60_000}
    hub.client.app.state.clock[0] = NOW + 59_000
    assert hub.mb_get().status_code == 200
    hub.client.app.state.clock[0] = NOW + 60_000
    err(hub.mb_get(), 404, "not_found")  # an expired message is gone
    assert hub.mb_put(c=b"new bytes", ttl_s=60).status_code == 200  # ... and its id is free again
    assert hub.mb_purge().json() == {"channel_id": CH, "deleted": 1}
    err(hub.mb_get(), 404, "not_found")


def test_mailbox_put_is_idempotent_and_conflicts(hub):
    first = hub.mb_put(ttl_s=60).json()
    hub.client.app.state.clock[0] += 30_000
    again = hub.mb_put(ttl_s=3600).json()
    assert again == first  # the same c again: 200, the expiry stays
    r = hub.mb_put(c=b"another message")
    err(r, 409, "message_conflict")
    assert hub.mb_get().json()["c"] == P.b64u(b"sealed message")


def test_deletes_are_idempotent(hub):
    assert hub.push_delete().json() == {"channel_id": CH, "registered": False}  # no target was held
    assert hub.mb_delete().json() == {"id": MSG, "deleted": True}
    assert hub.mb_purge().json() == {"channel_id": CH, "deleted": 0}
    err(hub.mb_get(), 404, "not_found")


def test_purge_touches_only_its_channel(hub):
    hub.mb_put()
    hub.mb_put(ch=CH2)
    assert hub.mb_purge().json()["deleted"] == 1
    assert hub.mb_get(ch=CH2).status_code == 200


# --- part 3: adversarial ----------------------------------------------------------------------------------------------


def all_routes(h):
    return {
        "push_put": lambda **k: h.push_put(**k),
        "push_delete": lambda **k: h.push_delete(**k),
        "push_send": lambda **k: h.send(MSG, **k),
        "mailbox_put": lambda **k: h.mb_put(**k),
        "mailbox_get": lambda **k: h.mb_get(**k),
        "mailbox_delete": lambda **k: h.mb_delete(**k),
        "mailbox_purge": lambda **k: h.mb_purge(**k),
    }


@pytest.mark.parametrize("name", list(all_routes(Hub(None, None, HUB, CERT))))
def test_replayed_nonce_on_each_route(hub, name):
    call = all_routes(hub)[name]
    nonce = b"\x5a" * 16
    hub.push_put(nonce=b"\x01" * 16)  # a target, so send has something to repeat
    assert call(nonce=nonce).status_code in (200, 404)
    err(call(nonce=nonce), 401, "replay")
    if name == "push_send":
        settle(hub, 1)
        assert len(hub.client.fake.requests) == 1  # the replay did not send a second push


@pytest.mark.parametrize("name", list(all_routes(Hub(None, None, HUB, CERT))))
def test_unsigned_or_other_hubs_signature_is_refused_on_each_route(hub, other, name):
    method, target, body = {
        "push_put": ("PUT", f"/v2/hubs/{HUB}/push/{CH}", b"{}"),
        "push_delete": ("DELETE", f"/v2/hubs/{HUB}/push/{CH}", b""),
        "push_send": ("POST", f"/v2/hubs/{HUB}/push/{CH}/send", b"{}"),
        "mailbox_put": ("PUT", f"/v2/hubs/{HUB}/mailbox/{CH}/{MSG}", b"{}"),
        "mailbox_get": ("GET", f"/v2/hubs/{HUB}/mailbox/{CH}/{MSG}", b""),
        "mailbox_delete": ("DELETE", f"/v2/hubs/{HUB}/mailbox/{CH}/{MSG}", b""),
        "mailbox_purge": ("DELETE", f"/v2/hubs/{HUB}/mailbox/{CH}", b""),
    }[name]
    err(
        hub.client.request(method, target, content=body), 400, "malformed"
    )  # no signature headers at all
    # the other hub signs a request for this hub's account: its headers name itself, the target is not its own
    r = other.client.request(
        method, target, headers=other.headers(method, target, body), content=body
    )
    err(r, 403, "other_hub")
    # ... and naming this hub with the other hub's key is a bad signature
    forged = {**other.headers(method, target, body), "Orch-Hub": HUB, "Orch-Hub-Op-Cert": CERT}
    err(
        other.client.request(method, target, headers=forged, content=body), 401, "bad_hub_signature"
    )
    assert rows(hub) == [] and rows(hub, "hub_mailbox") == []


def test_hubs_are_isolated(hub, other):
    hub.push_put()
    hub.mb_put()
    other.push_put(token=TOKEN_B)  # the same channel id under another hub is another target
    other.mb_put(c=b"theirs")
    assert len(rows(hub)) == 2
    assert other.mb_get().json()["c"] == P.b64u(b"theirs") and hub.mb_get().json()["c"] == P.b64u(
        b"sealed message"
    )
    assert other.send(MSG).json() == {"accepted": 1}
    settle(hub, 1)
    assert [r.path for r in hub.client.fake.requests] == ["/3/device/" + TOKEN_B.hex()]
    assert hub.mb_purge().json()["deleted"] == 1
    assert other.mb_get().status_code == 200  # the other hub's mailbox is untouched
    assert other.push_delete().status_code == 200 and len(rows(hub)) == 1


def test_outer_must_name_this_hub_and_channel(hub, other):
    hub.push_put()
    base = hub.base()
    for outer in (
        {**hub.outer(MSG), "hub": other.hub},
        {**hub.outer(MSG), "ch": CH2},
        {**hub.outer(MSG), "extra": 1},
        {**hub.outer(MSG), "id": "zz" * 16},
        {**hub.outer(MSG), "c": "AA=="},
        {**hub.outer(MSG), "v": 1},
    ):
        body = {"v": 2, "outer": outer, "priority": "high", "ttl_s": 1}
        err(hub.call("POST", f"{base}/push/{CH}/send", body), 400, "malformed")
    big = hub.outer(MSG, c=P.b64u(b"x" * 3000))
    err(
        hub.call(
            "POST", f"{base}/push/{CH}/send", {"v": 2, "outer": big, "priority": "high", "ttl_s": 1}
        ),
        413,
        "too_large",
    )
    assert hub.client.fake.requests == []


@pytest.mark.parametrize(
    "body",
    [
        {"v": 2, "env": "staging", "topic": TOPIC, "token": P.b64u(TOKEN_A)},
        {
            "v": 2,
            "env": "sandbox",
            "topic": "io.other.app",
            "token": P.b64u(TOKEN_A),
        },  # not this relay's topic
        {"v": 2, "env": "sandbox", "topic": "bad topic", "token": P.b64u(TOKEN_A)},
        {"v": 2, "env": "sandbox", "topic": TOPIC, "token": P.b64u(b"short")},
        {"v": 2, "env": "sandbox", "topic": TOPIC, "token": P.b64u(b"t" * 101)},
        {"v": 1, "env": "sandbox", "topic": TOPIC, "token": P.b64u(TOKEN_A)},
        {"v": 2, "env": "sandbox", "topic": TOPIC, "token": P.b64u(TOKEN_A), "extra": 1},
        {"v": 2, "env": "sandbox", "topic": TOPIC},
    ],
)
def test_push_put_bodies(hub, body):
    err(hub.call("PUT", f"{hub.base()}/push/{CH}", body), 400, "malformed")
    assert rows(hub) == []


def test_malformed_requests_after_authentication(hub):
    base = hub.base()
    err(hub.call("PUT", f"{base}/push/{CH}", b"not json"), 400, "malformed")
    err(
        hub.call("DELETE", f"{base}/push/{CH}", b"{}"), 400, "malformed"
    )  # DELETE has an empty body
    err(hub.call("GET", f"{base}/mailbox/{CH}/{MSG}", b" "), 400, "malformed")
    err(
        hub.call("PUT", f"{base}/push/{'A' * 32}", {"v": 2}), 400, "malformed"
    )  # channel id is lower-case hex
    err(
        hub.call("GET", f"{base}/mailbox/{CH}/{MSG}?after=1"), 400, "malformed"
    )  # no route takes a query
    err(hub.call("GET", f"{base}/settings"), 404, "not_found")
    err(hub.call("GET", f"{base}/push/{CH}"), 404, "not_found")  # a known path, another method
    err(hub.call("POST", f"{base}/push/{CH}/send/x"), 404, "not_found")
    err(
        hub.call("PUT", f"{base}/mailbox/{CH}/not-an-id", {"v": 2, "c": "AA", "ttl_s": 60}),
        404,
        "not_found",
    )
    for ttl in (59, 604_801, "60", True):
        err(
            hub.call("PUT", f"{base}/mailbox/{CH}/{MSG}", {"v": 2, "c": "AA", "ttl_s": ttl}),
            400,
            "malformed",
        )
    for c in ("", "AA==", "A", 7):
        err(
            hub.call("PUT", f"{base}/mailbox/{CH}/{MSG}", {"v": 2, "c": c, "ttl_s": 60}),
            400,
            "malformed",
        )
    for bad in ({"priority": "urgent"}, {"ttl_s": 86_401}, {"ttl_s": -1}, {"ttl_s": 1.5}, {"v": 3}):
        body = {"v": 2, "outer": hub.outer(MSG), "priority": "high", "ttl_s": 1, **bad}
        err(hub.call("POST", f"{base}/push/{CH}/send", body), 400, "malformed")


def test_target_quota_is_configurable_per_hub(hub, other):
    hub.client.app.state.hub_phone.max_targets = 64
    for n in range(64):
        assert hub.push_put(ch=rid(n + 1)).status_code == 200
    r = hub.push_put(ch=rid(999))
    err(r, 429, "quota_exceeded")
    assert int(r.headers["retry-after"]) >= 1
    assert hub.push_put(ch=rid(1), token=TOKEN_B).status_code == 200  # replacing one needs no room
    assert hub.push_put(ch=rid(1), token=TOKEN_B).status_code == 200
    assert other.push_put(ch=rid(999)).status_code == 200  # the quota is per hub
    assert hub.push_delete(ch=rid(2)).status_code == 200
    assert hub.push_put(ch=rid(999)).status_code == 200  # room again


def test_mailbox_message_count_quota(hub, other):
    for n in range(256):
        assert hub.mb_put(mid=f"{n + 1:032x}", c=bytes([n % 256]) * 8).status_code == 200
    r = hub.mb_put(mid="ff" * 16)
    err(r, 429, "quota_exceeded")
    assert int(r.headers["retry-after"]) >= 1
    assert (
        hub.mb_put(mid=f"{1:032x}", c=bytes([0]) * 8).status_code == 200
    )  # an idempotent repeat needs no room
    assert hub.mb_put(mid="ff" * 16, ch=CH2).status_code == 200  # per channel
    assert other.mb_put(mid="ff" * 16).status_code == 200  # per hub
    assert hub.mb_delete(mid=f"{5:032x}").status_code == 200
    assert hub.mb_put(mid="ff" * 16).status_code == 200


def test_mailbox_byte_quota_and_message_size(hub, monkeypatch):
    monkeypatch.setattr(HP, "MAX_MAILBOX_BYTES", 40 * 1024)
    assert hub.mb_put(mid="01" * 16, c=b"a" * 16_384).status_code == 200
    assert hub.mb_put(mid="02" * 16, c=b"b" * 16_384).status_code == 200
    err(hub.mb_put(mid="03" * 16, c=b"c" * 16_384), 429, "quota_exceeded")
    assert hub.mb_put(mid="03" * 16, c=b"c" * 8_192).status_code == 200  # exactly 40 KiB held
    err(hub.mb_put(mid="04" * 16, c=b"d"), 429, "quota_exceeded")
    err(hub.mb_put(mid="05" * 16, ch=CH2, c=b"x" * 16_385), 413, "too_large")  # 16 KiB per message
    assert hub.mb_put(mid="05" * 16, ch=CH2, c=b"x" * 16_384).status_code == 200


def test_the_default_quotas_agree_with_the_contract():
    assert (HP.MAX_TARGETS_PER_HUB, HP.MAX_MESSAGES, HP.MAX_MAILBOX_BYTES, HP.MAX_MESSAGE) == (
        4096,  # default, ORCH_RELAY_HUB_PUSH_TARGETS (D10-1)
        256,
        4 * 1024 * 1024,
        16 * 1024,
    )
    # 256 messages of at most 16 KiB are at most 4 MiB, so the byte quota never binds before the count quota
    assert HP.MAX_MESSAGES * HP.MAX_MESSAGE == HP.MAX_MAILBOX_BYTES


def test_without_push_configuration_every_route_but_the_purge_is_not_found_after_authentication(
    tmp_path, monkeypatch
):
    client = make(tmp_path, monkeypatch, configured=False)
    try:
        h = Hub(client, OP1, HUB, CERT)
        for name, call in all_routes(h).items():
            if name != "mailbox_purge":
                err(call(), 404, "not_found")
        r = h.mb_purge()  # E5R-1: the revocation record never depends on push (§10.8.1)
        assert r.status_code == 200 and r.json() == {"channel_id": CH, "deleted": 0}, r.text
        err(
            client.get(f"/v2/hubs/{HUB}/mailbox/{CH}"), 400, "malformed"
        )  # unsigned: still refused first
        err(
            client.request("PUT", f"/v2/hubs/{HUB}/push/{CH}", content=b"{}"), 400, "malformed"
        )  # still unauthenticated
        err(h.push_put(ts=NOW - 500_000), 401, "stale_timestamp")  # authentication comes first
    finally:
        client.__exit__(None, None, None)


def test_per_workspace_and_hub_account_routes_still_work(hub):
    c = hub.client
    assert (
        c.get(f"/v2/hubs/{HUB}").json()["card"]["o"]["hub_id"] == HUB
    )  # the public card read stays unsigned
    assert c.post("/v2/push/register", json={}).status_code == 401  # v2 push is not shadowed
    assert c.post(f"/v2/workspaces/{'ab' * 16}/push", json={}).status_code == 401
    assert c.post("/v2/hubs/op-revoked", json={}).status_code == 400


def test_migration_is_idempotent_and_ordered_after_0022(tmp_path):
    from importlib import resources

    from orch_relay import db

    names = sorted(e.name for e in resources.files("orch_relay").joinpath("migrations").iterdir())
    assert names.index("0023_hub_phone.sql") == names.index("0022_hub_request_nonces.sql") + 1
    path = tmp_path / "relay.db"
    first = db.migrate(path)
    assert "0023" in "".join(first) and db.migrate(path) == []
    sql = resources.files("orch_relay").joinpath("migrations/0023_hub_phone.sql").read_text()
    con = db.connect(path)
    con.executescript(sql)  # running the file again changes nothing and fails nowhere
    con.close()


def test_target_cap_comes_from_the_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("ORCH_RELAY_HUB_PUSH_TARGETS", "2")
    client = make(tmp_path, monkeypatch)
    try:
        h = Hub(client, OP1, HUB, CERT)
        assert client.app.state.hub_phone.max_targets == 2
        assert h.push_put(ch=rid(1)).status_code == 200 and h.push_put(ch=rid(2)).status_code == 200
        err(h.push_put(ch=rid(3)), 429, "quota_exceeded")
    finally:
        client.__exit__(None, None, None)


_OK_PUT = json.dumps({"v": 2, "env": "sandbox", "topic": "t", "token": "A" * 43}).encode()


@pytest.mark.parametrize(
    ("method", "tail", "query", "body", "code"),
    [
        # (1) a query is refused before anything else, even on an unknown path or a bad {ch}
        ("GET", f"/mailbox/{CH}/{MSG}", "after=1", b"", "malformed"),
        ("GET", "/settings", "x=1", b"", "malformed"),
        ("GET", "/push/zz", "x=1", b"", "malformed"),
        # (2) under mailbox/ with one or two further segments a bad {ch} is malformed, whatever the method
        ("PUT", "/mailbox/zz", "", b"", "malformed"),
        ("GET", "/mailbox/zz", "", b"", "malformed"),
        ("POST", "/mailbox/zz", "", b"", "malformed"),
        ("GET", f"/mailbox/{'A' * 32}/{MSG}", "", b"", "malformed"),
        ("PATCH", "/mailbox/zz/" + MSG, "", b"", "malformed"),
        ("GET", "/mailbox/zz/nothex", "", b"", "malformed"),  # (2) beats the bad {id} of (3)
        # (3) shapes and methods not in the table are not_found
        ("PUT", f"/mailbox/{CH}", "", b"", "not_found"),
        ("GET", f"/mailbox/{CH}/nothex", "", b"", "not_found"),
        ("PUT", f"/mailbox/{CH}/nothex", "", b"junk", "not_found"),  # (3) beats the body of (4)
        ("GET", f"/mailbox/{CH}/{MSG}/more", "", b"", "not_found"),
        ("GET", "/mailbox/zz/a/b", "", b"", "not_found"),  # three further segments: no shape
        (
            "GET",
            "/push/zz",
            "",
            b"",
            "not_found",
        ),  # push: a method the table lacks, even with a bad {ch}
        ("POST", "/push/zz", "", b"", "not_found"),
        ("POST", "/push/zz/other", "", b"", "not_found"),
        ("GET", "/push/zz/send", "", b"", "not_found"),
        ("POST", f"/push/{CH}/send/x", "", b"", "not_found"),
        ("PUT", "/nothing", "", b"", "not_found"),
        ("PUT", "/", "", b"", "not_found"),
        # (4) the body, then {ch} (push/, for a path and method that are in the table)
        ("PUT", "/push/zz", "", b"junk", "malformed"),
        ("PUT", "/push/zz", "", _OK_PUT, "malformed"),  # good body, bad {ch}
        ("DELETE", "/push/zz", "", b"", "malformed"),
        ("DELETE", f"/push/{CH}", "", b"{}", "malformed"),
        ("POST", "/push/zz/send", "", b"", "malformed"),
        # 413 is found only when {ch} is valid: a bad {ch} stays malformed
        ("PUT", f"/mailbox/zz/{MSG}", "", b"", "malformed"),
    ],
)
def test_order_of_refusals_matches_the_spec_text(method, tail, query, body, code):
    """§10.8.1 order of refusals, item by item, with the mixed cases (model: orch-hub
    `test_order_of_refusals_matches_the_spec_text`)."""
    with pytest.raises(Refusal) as e:
        HP.match(method, f"/v2/hubs/{HUB}{tail}", query, HUB, body)
    assert e.value.code == code


def test_too_large_is_found_only_when_the_channel_is_valid(hub):
    base = hub.base()
    big = {"v": 2, "c": "A" * 30_000, "ttl_s": 60}
    err(hub.call("PUT", f"{base}/mailbox/{CH}/{MSG}", big), 413, "too_large")
    err(hub.call("PUT", f"{base}/mailbox/{'z' * 32}/{MSG}", big), 400, "malformed")
    outer = hub.outer(MSG)
    outer = {**outer, "c": "A" * 4000}
    body = {"v": 2, "outer": outer, "priority": "high", "ttl_s": 1}
    err(hub.call("POST", f"{base}/push/{CH}/send", body), 413, "too_large")
    err(hub.call("POST", f"{base}/push/{'z' * 32}/send", body), 400, "malformed")


def test_mixed_refusals_over_http(hub):
    base = hub.base()
    err(hub.call("GET", f"{base}/push/zz"), 404, "not_found")  # bad {ch} but no such method
    err(hub.call("DELETE", f"{base}/push/zz"), 400, "malformed")
    err(hub.call("GET", f"{base}/mailbox/zz/nothex"), 400, "malformed")
    err(hub.call("GET", f"{base}/mailbox/{CH}/nothex"), 404, "not_found")
    err(hub.call("GET", f"{base}/push/zz?x=1"), 400, "malformed")
