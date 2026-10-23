"""E5: a phone reads its own channel mailbox (orch-hub contract §10.8.4) and the revoked-channel store fed by the hub's
signed mailbox purge (§10.8.1). FAKE keys only.

Part 1 replays the shared `channel_request_*` / `channel_route_*` vectors; part 2 drives the routes over HTTP with a
channel key and a channel certificate signed by the vector hub's HK_op; part 3 is adversarial."""

import json
import struct
from contextlib import closing
from pathlib import Path

import pytest
from test_hub_accounts import NOW, OP1, Key
from test_hub_phone import CERT, HUB, MSG, Hub, err, make, rows
from test_hub_relay_requests import insert_account

from orch_relay import db
from orch_relay import hub_accounts as H
from orch_relay import hub_channels as HC
from orch_relay import proto as P
from orch_relay.app import create_app
from orch_relay.common import Refusal

VECTORS = json.loads((Path(__file__).parent / "vectors/hub/vectors_hub.json").read_text())
REQUEST_CASES = [c for c in VECTORS["cases"] if c["check"] == "channel_request"]
ROUTE_CASES = [c for c in VECTORS["cases"] if c["check"] == "channel_route"]
API = VECTORS["phase4"]["channel_api"]
MSG2 = "11" * 16


# --- part 1: the shared vectors ---------------------------------------------------------------------------------------


def test_vectors_present():
    assert len(REQUEST_CASES) == 25 and len(ROUTE_CASES) == 8


def run_vector(tmp_path, monkeypatch, a):
    import test_hub_relay_requests as T

    # One relay per case, clock fixed at the case's `now_ms`; the card is held only when it is the target hub's.
    from push_support import clear

    clear(monkeypatch)
    monkeypatch.delenv("ORCH_RELAY_DEV", raising=False)
    if a["dev_mode"]:
        monkeypatch.setenv("ORCH_RELAY_DEV", "1")
    from fastapi.testclient import TestClient

    with TestClient(create_app(tmp_path / "data")) as client:
        d = client.app.state.core
        d.clock = lambda: a["now_ms"]
        card = a["hub_card"]
        if card["o"]["hub_id"] == a["hub_id"]:
            T.insert_account(client, card)
        with d.lock:
            con = d.connection("write")
            with con:
                for cert in a.get("revoked_op_certs", []):
                    con.execute(
                        "INSERT INTO hub_op_revoked VALUES (?,?,?,?)",
                        (card["o"]["hub_id"], cert, 0, 0),
                    )
                for hub, chans in a.get("revoked_channels", {}).items():
                    for ch in chans:
                        con.execute("INSERT INTO hub_revoked_channels VALUES (?,?,?)", (hub, ch, 0))
                for key, seen in a.get("nonces", {}).items():
                    hub, ch = key.split("/")
                    for nonce, ts in seen.items():
                        con.execute(
                            "INSERT INTO hub_channel_nonces VALUES (?,?,?,?)", (hub, ch, nonce, ts)
                        )
        r = a["request"]
        return client.app.state.hub_channels.authenticate(
            r["method"], r["target"], r["headers"], bytes.fromhex(r["body_hex"])
        )


@pytest.mark.parametrize("case", REQUEST_CASES, ids=lambda c: c["name"])
def test_request_vector(case, tmp_path, monkeypatch):
    expect = case["expect"]
    if "ok" in expect:
        got = run_vector(tmp_path, monkeypatch, case["args"])
        assert got == (expect["ok"]["hub"], expect["ok"]["channel_id"])
        assert case["args"]["request"]["headers"]["Orch-Channel-Nonce"] == expect["ok"]["nonce"]
        return
    with pytest.raises(Refusal) as e:
        run_vector(tmp_path, monkeypatch, case["args"])
    assert e.value.code == expect["error"]


@pytest.mark.parametrize("case", ROUTE_CASES, ids=lambda c: c["name"])
def test_route_vector(case):
    a, expect = case["args"], case["expect"]
    try:
        got = HC.route(a["method"], a["target"], bytes.fromhex(a["body_hex"]))
    except Refusal as e:
        assert e.code == expect["error"]
        return
    want = expect["ok"]
    assert got == {"hub": want["hub"], "channel_id": want["channel_id"], "route": want["route"]} | (
        {"id": want["id"]} if "id" in want else {}
    )


def test_signed_bytes_vector():
    req = API["channel_request"]["request"]
    h = req["headers"]
    raw = bytes.fromhex(API["channel_request"]["signed_hex"])
    hub, ch, _ = HC.parse_target(req["target"])
    rebuilt = HC.request_bytes(
        hub,
        ch,
        int(h["Orch-Channel-Ts"]),
        bytes.fromhex(h["Orch-Channel-Nonce"]),
        req["method"],
        req["target"],
        bytes.fromhex(req["body_hex"]),
    )
    assert rebuilt == raw and raw.startswith(b"orch/v2/hub-channel-relay-req|\x02")
    assert struct.unpack(">Q", raw[30 + 33 : 30 + 41])[0] == int(h["Orch-Channel-Ts"])


# --- part 2: over HTTP ------------------------------------------------------------------------------------------------


class Phone:
    """A channel: its own key and a `hub.channel_cert` signed by the vector hub's HK_op."""

    def __init__(
        self,
        client,
        name="phone",
        hub=HUB,
        cert_id=CERT,
        issued=NOW - 1000,
        expires=NOW + 31 * 86_400_000,
    ):
        self.client, self.hub, self.key, self.n = client, hub, Key(name), 0
        self.channel_id = HC.channel_id(self.key.pub)
        o = {
            "v": 2,
            "suite": 2,
            "kind": "hub.channel_cert",
            "hv": 0,
            "hub_id": hub,
            "op_cert_id": cert_id,
            "channel_id": self.channel_id,
            "user_id": "ab" * 16,
            "key_pub": self.key.text,
            "factor": "se-unlocked",
            "issued_ms": issued,
            "expires_ms": expires,
            "dev": True,
        }
        self.cert = OP1.sign(HC.L_CHANNEL_CERT, o)

    def headers(self, method, target, body=b"", nonce=None, ts=None, cert=None, key=None):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

        self.n += 1
        nonce = nonce or bytes([self.n]) * 16
        ts = self.client.app.state.clock[0] if ts is None else ts
        try:
            hub, ch, _ = HC.parse_target(target.partition("?")[0])
        except Refusal:  # a deliberately malformed target: sign it as this channel's anyway
            hub, ch = self.hub, self.channel_id
        message = HC.request_bytes(hub, ch, ts, nonce, method, target.partition("?")[0], body)
        r, s = decode_dss_signature((key or self.key).priv.sign(message, ec.ECDSA(hashes.SHA256())))
        return {
            "Orch-Channel-Cert": P.b64u(P.cj(cert or self.cert)),
            "Orch-Channel-Ts": str(ts),
            "Orch-Channel-Nonce": nonce.hex(),
            "Orch-Channel-Signature": P.b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big")),
        }

    def target(self, tail="mailbox", ch=None, hub=None):
        return f"/v2/hub-channels/{hub or self.hub}/{ch or self.channel_id}/{tail}"

    def call(self, method, tail="mailbox", body=b"", ch=None, target=None, **kw):
        target = target or self.target(tail, ch)
        return self.client.request(
            method, target, headers=self.headers(method, target, body, **kw), content=body
        )

    def list(self, **kw):
        return self.call("GET", **kw)

    def get(self, mid=MSG, **kw):
        return self.call("GET", f"mailbox/{mid}", **kw)

    def delete(self, mid=MSG, **kw):
        return self.call("DELETE", f"mailbox/{mid}", **kw)


@pytest.fixture
def hub(tmp_path, monkeypatch):
    client = make(tmp_path, monkeypatch)
    yield Hub(client, OP1, HUB, CERT)
    client.__exit__(None, None, None)


@pytest.fixture
def phone(hub):
    return Phone(hub.client)


def test_list_get_delete(hub, phone):
    assert phone.list().json() == {"messages": []}
    assert hub.mb_put(ch=phone.channel_id, c=b"one").status_code == 200
    assert hub.mb_put(mid=MSG2, ch=phone.channel_id, c=b"two").status_code == 200
    r = phone.list()
    assert r.status_code == 200 and r.headers["cache-control"] == "no-store"
    assert r.json() == {
        "messages": [
            {"id": MSG2, "expires_ms": NOW + 3_600_000},
            {"id": MSG, "expires_ms": NOW + 3_600_000},
        ]
    }  # sorted by id
    assert phone.get().json() == {"id": MSG, "c": P.b64u(b"one"), "expires_ms": NOW + 3_600_000}
    assert phone.delete().json() == {"id": MSG, "deleted": True}
    assert phone.delete().json() == {"id": MSG, "deleted": True}  # also when absent
    err(phone.get(), 404, "not_found")
    assert [m["id"] for m in phone.list().json()["messages"]] == [MSG2]
    assert (
        hub.mb_get(ch=phone.channel_id, mid=MSG2).status_code == 200
    )  # the hub's own view is untouched


def test_expired_message_is_not_listed_or_served(hub, phone):
    hub.mb_put(ch=phone.channel_id, ttl_s=60)
    hub.client.app.state.clock[0] += 61_000
    assert phone.list().json() == {"messages": []}
    err(phone.get(), 404, "not_found")


def test_a_channel_never_sees_another_hubs_or_channels_messages(hub, phone):
    other = Phone(hub.client, "phone2")
    hub.mb_put(ch=other.channel_id)
    assert phone.list().json() == {"messages": []}
    err(phone.get(), 404, "not_found")
    assert [m["id"] for m in other.list().json()["messages"]] == [MSG]


def test_works_on_a_relay_without_push_configuration(tmp_path, monkeypatch):
    client = make(tmp_path, monkeypatch, configured=False)
    try:
        assert Phone(client).list().json() == {"messages": []}
    finally:
        client.__exit__(None, None, None)


# --- the revoked-channel store ----------------------------------------------------------------------------------------


def test_purge_revokes_the_channel_at_once_and_permanently(hub, phone):
    hub.mb_put(ch=phone.channel_id)
    other = Phone(hub.client, "phone2")
    assert phone.list().status_code == 200
    assert hub.mb_purge(ch=phone.channel_id).json() == {
        "channel_id": phone.channel_id,
        "deleted": 1,
    }
    for r in (phone.list(), phone.get(), phone.delete()):
        err(r, 403, "channel_revoked")
    assert hub.mb_purge(ch=phone.channel_id).status_code == 200  # the hub repeats it; idempotent
    err(phone.list(), 403, "channel_revoked")
    assert other.list().status_code == 200  # another channel of the same hub is untouched
    hub.mb_put(ch=phone.channel_id)  # even a message the hub puts later is not readable
    err(phone.list(), 403, "channel_revoked")
    assert rows(hub, "hub_revoked_channels") == [
        {"hub_id": HUB, "channel_id": phone.channel_id, "revoked_ms": NOW}
    ]


def test_revocation_survives_a_restart(hub, phone, tmp_path, monkeypatch):
    hub.mb_purge(ch=phone.channel_id)
    hub.client.__exit__(None, None, None)
    from fastapi.testclient import TestClient

    with TestClient(create_app(tmp_path / "data")) as again:  # a fresh process on the same database
        again.app.state.core.clock = lambda: NOW
        again.app.state.clock = [NOW]
        err(Phone(again).list(), 403, "channel_revoked")


def test_only_the_key_holder_learns_the_revocation(hub, phone):
    hub.mb_purge(ch=phone.channel_id)
    stranger = Key("stranger")
    r = phone.call(
        "GET", key=stranger
    )  # a signature by another key is `bad_channel_signature`, not `channel_revoked`
    err(r, 401, "bad_channel_signature")


def test_a_purge_of_another_hub_does_not_revoke_this_hubs_channel(hub, phone):
    op = Key("hk_op_rogue")
    from test_hub_accounts import ROGUE, make_card, op_cert

    card = make_card(ROGUE, op, op_cert(ROGUE, op, 1, "cc"))
    insert_account(hub.client, card)
    other = Hub(hub.client, op, card["o"]["hub_id"], "cc" * 16)
    assert other.mb_purge(ch=phone.channel_id).status_code == 200
    assert phone.list().status_code == 200
    assert rows(hub, "hub_revoked_channels", "hub_id=?", (card["o"]["hub_id"],))


# --- adversarial ------------------------------------------------------------------------------------------------------


def test_replay_is_refused_and_recorded_only_after_the_signature(hub, phone):
    t = phone.target()
    h = phone.headers("GET", t, nonce=b"\x07" * 16)
    assert hub.client.get(t, headers=h).status_code == 200
    err(hub.client.get(t, headers=h), 401, "replay")
    # A forged request that reuses a fresh nonce never burns it.
    forged = phone.headers("GET", t, nonce=b"\x08" * 16, key=Key("stranger"))
    err(hub.client.get(t, headers=forged), 401, "bad_channel_signature")
    again = phone.headers("GET", t, nonce=b"\x08" * 16)
    assert hub.client.get(t, headers=again).status_code == 200
    # A nonce of one channel is not another channel's.
    other = Phone(hub.client, "phone2")
    t2 = other.target()
    assert (
        hub.client.get(t2, headers=other.headers("GET", t2, nonce=b"\x07" * 16)).status_code == 200
    )


def test_nonces_are_pruned_after_the_retention_window(hub, phone):
    assert phone.list(nonce=b"\x09" * 16).status_code == 200
    assert len(rows(hub, "hub_channel_nonces")) == 1
    hub.client.app.state.clock[0] += HC.NONCE_RETENTION_MS + 1000
    assert phone.list(nonce=b"\x0a" * 16).status_code == 200
    assert [r["nonce"] for r in rows(hub, "hub_channel_nonces")] == [(b"\x0a" * 16).hex()]


def test_stale_timestamp_carries_server_time(hub, phone):
    r = phone.list(ts=NOW - 121_000)
    err(r, 401, "stale_timestamp")
    assert r.json()["server_ms"] == NOW
    assert phone.list(ts=NOW + 119_000).status_code == 200


def test_stale_certificate(hub):
    expired = Phone(hub.client, "old", issued=NOW - 10_000, expires=NOW - 1)
    err(expired.list(), 401, "cert_expired")
    future = Phone(hub.client, "future", issued=NOW + 10**9, expires=NOW + 2 * 10**9)
    err(future.list(), 401, "cert_invalid")
    stale_op = Phone(hub.client, "stale", cert_id="ee" * 16)
    err(stale_op.list(), 401, "stale_op_cert")
    foreign = Phone(hub.client, "foreign", hub="ab" * 16)
    err(foreign.list(), 401, "unknown_hub")


def test_another_channels_mailbox_is_refused(hub, phone):
    victim = Phone(hub.client, "victim")
    hub.mb_put(ch=victim.channel_id)
    for call in (phone.list, phone.get, phone.delete):
        err(call(ch=victim.channel_id), 403, "other_user")
    assert [m["id"] for m in victim.list().json()["messages"]] == [MSG]
    # Another hub's prefix with this hub's cert: the cert names a different hub.
    other_hub = "cd" * 16
    err(phone.call("GET", target=phone.target(hub=other_hub)), 401, "unknown_hub")


def test_duplicate_channel_headers_are_refused_in_any_spelling(hub, phone):
    t = phone.target()
    h = phone.headers("GET", t)
    for name in (
        "Orch-Channel-Nonce",
        "Orch-Channel-Ts",
        "Orch-Channel-Cert",
        "Orch-Channel-Signature",
    ):
        raw = list(h.items()) + [(name.upper(), h[name])]
        r = hub.client.get(t, headers=raw)
        err(r, 400, "malformed")
        raw = list(h.items()) + [(name.lower(), "00")]
        err(hub.client.get(t, headers=raw), 400, "malformed")
    assert (
        hub.client.get(t, headers=phone.headers("GET", t)).status_code == 200
    )  # nothing was burnt


def test_missing_and_broken_headers(hub, phone):
    t = phone.target()
    h = phone.headers("GET", t)
    for name in h:
        err(hub.client.get(t, headers={k: v for k, v in h.items() if k != name}), 400, "malformed")
    err(hub.client.get(t, headers={**h, "Orch-Channel-Ts": "01790000000000"}), 400, "malformed")
    err(hub.client.get(t, headers={**h, "Orch-Channel-Cert": "A" * 4097}), 400, "malformed")
    err(hub.client.get(t, headers={**h, "Orch-Channel-Nonce": "AB" * 16}), 400, "malformed")


def test_target_shapes(hub, phone):
    t = phone.target()
    err(phone.call("GET", target=t + "?x=1"), 400, "malformed")
    err(phone.call("GET", target=phone.target("mailbox/")), 400, "malformed")
    err(phone.call("GET", target=phone.target("mailbox/%41")), 400, "malformed")
    err(phone.call("GET", target=phone.target("../mailbox")), 400, "malformed")
    err(
        phone.call("GET", target=phone.target(hub=HUB.upper())), 400, "malformed"
    )  # not lower-case hex


def test_routes_and_bodies(hub, phone):
    err(phone.call("DELETE"), 404, "not_found")  # emptying the whole mailbox stays the hub's
    err(phone.call("GET", "push"), 404, "not_found")
    err(phone.call("GET", "mailbox/xyz"), 404, "not_found")
    err(phone.call("GET", body=b"{}"), 400, "malformed")
    r = phone.client.put(phone.target(), headers=phone.headers("GET", phone.target()))
    assert r.status_code == 405  # PUT/POST are not routes at all
    r = phone.client.get(f"/v2/hub-channels/{HUB}/{phone.channel_id}")
    assert r.status_code == 400 and r.json() == {"error": "malformed"}  # unauthenticated, no tail


def test_a_hub_op_signed_request_does_not_work_on_the_channel_prefix(hub, phone):
    t = phone.target()
    headers = hub.headers("GET", t)
    r = hub.client.get(t, headers=headers)
    err(r, 400, "malformed")


def test_the_hub_prefix_never_accepts_a_channel_signature(hub, phone):
    t = f"/v2/hubs/{HUB}/mailbox/{phone.channel_id}/{MSG}"
    r = hub.client.get(t, headers=phone.headers("GET", phone.target(f"mailbox/{MSG}")))
    assert r.status_code == 400  # no Orch-Hub headers: malformed


def test_read_budget_per_channel(hub, phone, monkeypatch):
    monkeypatch.setattr(HC, "NONCES_PER_CHANNEL", 3)
    for _ in range(3):
        assert phone.list().status_code == 200
    r = phone.list()
    err(r, 429, "quota_exceeded")
    assert r.headers["retry-after"] == str(HC.RETRY_S)
    assert len(rows(hub, "hub_channel_nonces")) == 3  # the refused read kept no nonce
    other = Phone(hub.client, "phone2")
    assert other.list().status_code == 200
    hub.client.app.state.clock[0] += 241_000
    assert phone.list().status_code == 200  # the window moved on


# --- the migration ----------------------------------------------------------------------------------------------------


def test_migration_is_idempotent(tmp_path):
    path = tmp_path / "m.db"
    first = db.migrate(path)
    assert "0025_hub_channels" in first and first[-1] == "0025_hub_channels"
    assert db.migrate(path) == []
    sql = next(text for name, text in db._migration_files(None) if name == "0025_hub_channels")
    with closing(db.connect(path)) as con:
        con.isolation_level = None
        for _ in range(2):  # the script itself can be run again over an existing schema
            for stmt in db._statements(sql):
                con.execute(stmt)
        con.execute("INSERT INTO hub_revoked_channels VALUES (?,?,?)", ("a" * 32, "b" * 32, 1))
        con.execute(
            "INSERT OR IGNORE INTO hub_revoked_channels VALUES (?,?,?)", ("a" * 32, "b" * 32, 2)
        )
        assert con.execute("SELECT revoked_ms FROM hub_revoked_channels").fetchall()[0][0] == 1


def test_hub_helpers_unchanged():
    assert H.FIELDS["hub.channel_cert"]["factor"]("se-unlocked") and not H.FIELDS[
        "hub.channel_cert"
    ]["factor"]("x")
