"""docs/protocol-v2.md: tests/vectors_v2.json is the contract between orch-core (host), orch-relay (server) and
orch mobile (browser). These tests prove that

- the file is exactly what the reference produces (regenerate and compare);
- every case can be replayed from the JSON alone (its inputs are complete), with the stated result;
- the primitives agree with code independent of the reference (HKDF, the label table, small-order points).
"""
import copy
import hashlib
import hmac
import json

import pytest

from ref import orch_protocol_ref as R

VEC = json.loads(R.VECTORS.read_text(encoding="utf-8"))
SUITES = sorted(VEC["suites"])


def by_name(cases):
    return pytest.mark.parametrize("c", cases, ids=lambda c: c["name"])


def each_suite(section, *path):
    """(suite, case) for every case of a section in both suites."""
    out = []
    for sid in SUITES:
        node = VEC["suites"][sid][section]
        for p in path:
            node = node[p]
        out += [pytest.param(R.SUITES[int(sid)], c, id=f"suite{sid}-{c['name']}") for c in node]
    return pytest.mark.parametrize("S,c", out)


def test_vector_file_is_up_to_date():
    assert R.render(R.build()) == R.VECTORS.read_text(encoding="utf-8"), "run: uv run python -m ref.orch_protocol_ref"


def test_keys_are_labelled_fake():
    assert "FAKE" in VEC["comment"]
    for sid in SUITES:
        for name, k in VEC["suites"][sid]["keys"].items():
            n, kind = name.rsplit(".", 1)
            assert k["seed"] == R.fake(f"suite{sid}/{n}/{kind}").hex()


# --- labels (§3) ---------------------------------------------------------------------------------------

def test_labels_are_distinct_and_versioned():
    vals = list(VEC["labels"].values())
    assert len(vals) == len(set(vals))
    assert all(v.startswith("orch/v2/") and v.isascii() for v in vals)


def test_no_signature_or_aad_label_is_a_prefix_of_another():
    """Signed and associated-data inputs are label || bytes: a prefix relation would let one domain's input
    parse as another's."""
    vals = [v for k, v in VEC["labels"].items() if k.startswith(("sig_", "aad_", "h_", "mac_"))]
    for a in vals:
        assert a.endswith("|"), a
        for b in vals:
            assert a == b or not b.startswith(a), (a, b)


def test_spec_mandated_labels():
    """The spec fixes these literally (orch-v2.md §5.1, §6.2, §6.3, §9, §10)."""
    assert VEC["labels"]["kdf_seal"] == "orch/v2/seal"
    assert VEC["labels"]["kdf_bridge"] == "orch/v2/bridge"
    assert VEC["labels"]["kdf_push"] == "orch/v2/push"
    assert VEC["labels"]["sig_ws_envelope"] == "orch/v2/ws-envelope|"
    assert VEC["labels"]["sig_publish"] == "orch/v2/publish|"


# --- encodings (§2) ----------------------------------------------------------------------------------

@by_name(VEC["encodings"]["canonical_json"])
def test_canonical_json(c):
    assert R.cj(c["value"]).hex() == c["bytes"]


@by_name(VEC["encodings"]["strict_parse"])
def test_strict_parse(c):
    try:
        R.parse_json(c["text"].encode())
        ok = True
    except ValueError:
        ok = False
    assert ok == c["ok"]


@by_name(VEC["encodings"]["b64u"])
def test_b64u(c):
    try:
        got = R.unb64u(c["text"]).hex()
    except ValueError:
        got = None
    assert got == c["bytes"]


# --- primitives (§1, §5) -----------------------------------------------------------------------------

def rfc5869(ikm: bytes, salt: bytes, info: bytes, n: int = 32) -> bytes:
    """Independent of the `cryptography` HKDF the reference uses."""
    prk = hmac.new(salt or bytes(32), ikm, hashlib.sha256).digest()
    okm, t, i = b"", b"", 1
    while len(okm) < n:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm, i = okm + t, i + 1
    return okm[:n]


@each_suite("hkdf")
def test_hkdf(S, c):
    ikm, salt, info = (bytes.fromhex(c[k]) for k in ("ikm", "salt", "info"))
    assert info.decode() == c["info_text"]
    assert rfc5869(ikm, salt, info).hex() == c["okm"]


def test_small_order_list():
    pts = VEC["ed25519_small_order"]
    assert len(pts) == 8 and "01" + "00" * 31 in pts
    for p in pts:
        pt = R._ed_decode(bytes.fromhex(p))
        assert pt is not None and R._ed_mul(8, pt) == (0, 1)
        assert not R.ed25519_pub_ok(bytes.fromhex(p))


@each_suite("sign")
def test_sign(S, c):
    assert S.verify(bytes.fromhex(c["pub"]), bytes.fromhex(c["sig"]), bytes.fromhex(c["msg"])) == c["valid"]


@each_suite("salted_aead")
def test_salted_aead(S, c):
    k, aad, pt, salt = (bytes.fromhex(c[x]) for x in ("k_base", "aad", "plaintext", "salt"))
    assert R.salted_seal(k, c["msg_label"].encode(), aad, pt, salt).hex() == c["sealed"]
    assert R.salted_open(k, c["msg_label"].encode(), aad, bytes.fromhex(c["sealed"])) == pt


@each_suite("seal")
def test_seal_to_device(S, c):
    eph = bytes.fromhex(c["eph_seed"])
    assert S.kx_pub(S.kx_key(eph)).hex() == c["eph_pub"]
    assert R.seal_aad(S, c["purpose"], bytes.fromhex(c["object_id"]), c["epoch"]).hex() == c["aad"]
    got = R.seal_to(S, bytes.fromhex(c["recipient_kx_pub"]), bytes.fromhex(c["recipient_id"]), c["purpose"],
                    bytes.fromhex(c["object_id"]), c["epoch"], bytes.fromhex(c["plaintext"]), eph)
    assert got.hex() == c["sealed"]
    assert c["sealed"].startswith(c["eph_pub"])


@each_suite("seal_open")
def test_seal_open(S, c):
    sid = str(S.id)
    seed = bytes.fromhex(VEC["suites"][sid]["keys"][c["recipient"] + ".kx"]["seed"])
    try:
        got = R.open_sealed(S, S.kx_key(seed), bytes.fromhex(c["recipient_id"]), c["purpose"],
                            bytes.fromhex(c["object_id"]), c["epoch"], bytes.fromhex(c["sealed"])).hex()
    except Exception:
        got = None
    assert got == c["plaintext"]


# --- certificates, revocations, cards, member lists, grants (§6, §7) ------------------------------------

@each_suite("certs", "cases")
def test_certs(S, c):
    assert R.verify_cert(S, c["signed"], bytes.fromhex(c["pk_pub"]), c["now_ms"], set(c["revoked"])) == c["expect"]


@each_suite("revocations")
def test_revocations(S, c):
    assert R.verify_revocation(S, c["signed"], bytes.fromhex(c["pk_pub"]), c["cert"]) == c["expect"]


@each_suite("card", "cases")
def test_cards(S, c):
    assert R.relay_accept_card(S, c["stored"], c["card"], bytes.fromhex(c["owner_pk_pub"])) == c["expect"]


@pytest.mark.parametrize("sid", SUITES)
def test_card_sealed_part_opens_with_the_wrapped_card_key(sid):
    S, v = R.SUITES[int(sid)], VEC["suites"][sid]
    seed = bytes.fromhex(v["keys"]["phone.kx"]["seed"])
    ws = bytes.fromhex(v["ids"]["workspace_a"])
    ck = R.open_sealed(S, S.kx_key(seed), bytes.fromhex(v["ids"]["device_phone"]), "card", ws, 1,
                       bytes.fromhex(v["card"]["card_key_wrap_to_phone"]["sealed"]))
    assert ck.hex() == v["card"]["card_key"]
    part = R.open_card_sealed_part(S, ck, ws, 1, R.unb64u(v["card"]["card"]["sealed"]))
    assert part == v["card"]["sealed_part_plaintext"]


@each_suite("wk_grants", "cases")
def test_wk_grants(S, c):
    v = VEC["suites"][str(S.id)]
    d = c["device"]
    priv = S.kx_key(bytes.fromhex(v["keys"][d + ".kx"]["seed"]))
    got = R.open_wk_grant(S, bytes.fromhex(c["wsk_pub"]), c["signed"], bytes.fromhex(v["ids"]["workspace_a"]),
                          bytes.fromhex(v["ids"]["device_" + d]), priv)
    assert got == c["expect"]


@each_suite("member_lists")
def test_member_lists(S, c):
    d = c["directory"]
    ds = {"owner_pk_pub": bytes.fromhex(d["owner_pk_pub"]), "certs": d["certs"], "revoked": set(d["revoked"]),
          "grants": {(x, e) for x, e in d["grants"]}}
    assert R.relay_accept_member_list(S, bytes.fromhex(c["wsk_pub"]), c["prev"], c["signed"], ds, c["now_ms"]) == c["expect"]


# --- bridge v2 (§8) ------------------------------------------------------------------------------------

def _strip(r):
    from ref._vectors import EXPECT_KEYS
    return {k: v for k, v in r.items() if k in EXPECT_KEYS}


@pytest.mark.parametrize("sid", SUITES)
def test_bridge_header_and_seal(sid):
    S, c = R.SUITES[int(sid)], VEC["suites"][sid]["bridge"]["seal"][0]
    hb = bytes.fromhex(c["header"])
    assert len(hb) == R.HEADER_LEN == 108
    assert R.Header.decode(hb).as_json() == c["header_fields"]
    k = bytes.fromhex(c["k_bridge"])
    assert R.message_key(k, hb[92:108]).hex() == c["message_key"]
    assert R.seal_body(k, hb, bytes.fromhex(c["plaintext"])).hex() == c["sealed"]
    env = bytes.fromhex(c["envelope"])
    assert env[:108] == hb and env[108:-64].hex() == c["sealed"]
    phone = bytes.fromhex(VEC["suites"][sid]["keys"]["phone.sig"]["pub"])
    assert S.verify(phone, env[-64:], R.L["sig_bridge"] + env[:-64])


@each_suite("bridge", "host_cases")
def test_host_cases(S, c):
    state = copy.deepcopy(c["state"])
    for step in c.get("steps", [c]):
        got = R.host_check(bytes.fromhex(step["envelope"]), state, step["now_ms"], step["mailbox_id"])
        assert _strip(got) == step["expect"]


@each_suite("bridge", "device_cases")
def test_device_cases(S, c):
    ctx = copy.deepcopy(c["ctx"])
    assert _strip(R.device_check(bytes.fromhex(c["envelope"]), ctx, c["mailbox"], c["now_ms"])) == c["expect"]


@each_suite("bridge", "pair_answers")
def test_pair_answers(S, c):
    ctx = copy.deepcopy(c["ctx"])
    assert _strip(R.open_pair_answer(bytes.fromhex(c["envelope"]), ctx, c["now_ms"])) == c["expect"]


@each_suite("bridge", "links")
def test_links(S, c):
    assert R.parse_pair_fragment(c["fragment"]) == c["parsed"]


@pytest.mark.parametrize("sid", SUITES)
def test_sas(sid):
    S, c = R.SUITES[int(sid)], VEC["suites"][sid]["bridge"]["sas"]
    code = R.sas(S, *(bytes.fromhex(c[k]) for k in ("workspace", "offer", "dk_sig_pub", "dk_kx_pub", "wsk_pub",
                                                     "sas_nonce")))
    assert code == c["code"] and len(code) == 6 and set(code) <= set(R.B32)


@each_suite("cert_request", "cases")
def test_cert_request(S, c):
    v = VEC["suites"][str(S.id)]
    me = bytes.fromhex(v["ids"]["device_primary"])
    priv = S.kx_key(bytes.fromhex(v["keys"]["primary.kx"]["seed"]))
    got = R.primary_open_cert_request(S, c["signed"], v["cert_request"]["card"], c["card_part"],
                                      bytes.fromhex(v["ids"]["person_alice"]), me, priv, c["now_ms"])
    assert got == c["expect"]
    if "ok" in got:   # the primary shows the same code as the phone and the host (§8.4)
        assert got["sas"] == v["bridge"]["sas"]["code"]


@pytest.mark.parametrize("sid", SUITES)
def test_enroll_mac(sid):
    S, c = R.SUITES[int(sid)], VEC["suites"][sid]["enroll"]
    mac = R.enroll_mac(bytes.fromhex(c["code"]), S, bytes.fromhex(c["space_id"]), bytes.fromhex(c["dk_sig_pub"]),
                       bytes.fromhex(c["dk_kx_pub"]))
    assert mac.hex() == c["mac"]


@pytest.mark.parametrize("sid", SUITES)
def test_webauthn_challenges(sid):
    c = VEC["suites"][sid]["webauthn"]
    a = c["assertion"]
    got = R.assertion_challenge(bytes.fromhex(a["workspace"]), bytes.fromhex(a["device"]), bytes.fromhex(a["rid"]),
                                a["epoch"], a["purpose"], a["scope"], a["expires_ms"], bytes.fromhex(a["nonce"]),
                                a["subject"])
    assert got.hex() == a["challenge"]
    r = c["registration"]
    assert R.registration_challenge(bytes.fromhex(r["workspace"]), bytes.fromhex(r["device"]), r["expires_ms"],
                                    bytes.fromhex(r["nonce"])).hex() == r["challenge"]


# --- push (§9) ---------------------------------------------------------------------------------------

@each_suite("push", "cases")
def test_push(S, c):
    assert R.sw_open_push(S, c["raw"].encode(), c["keys"], c["now_ms"]) == c["expect"]


@pytest.mark.parametrize("sid", SUITES)
def test_push_fits_and_shows_only_routing_fields(sid):
    p = VEC["suites"][sid]["push"]
    assert len(p["raw"].encode()) <= R.MAX_PUSH
    assert set(json.loads(p["raw"])) == {"v", "ws", "epoch", "c"}


# --- Drop (§10) --------------------------------------------------------------------------------------

@pytest.mark.parametrize("sid", SUITES)
def test_drop_content(sid):
    S, d = R.SUITES[int(sid)], VEC["suites"][sid]["drop"]
    dek, obj = bytes.fromhex(d["dek"]), bytes.fromhex(d["object_id"])
    blob = R.drop_encrypt(S, dek, obj, 1, bytes.fromhex(d["content"]), bytes.fromhex(d["nonce_prefix"]), d["chunk_size"])
    assert blob.hex() == d["blob"]
    assert R.drop_decrypt(S, dek, obj, 1, blob).hex() == d["content"]
    assert R.drop_decrypt(S, dek, obj, 1, bytes.fromhex(d["empty_blob"])) == b""
    for bad in (blob[:-1], blob[:-(512 + 16)], blob[:40] + blob[40 + 528:]):    # truncated, a chunk cut, a chunk removed
        with pytest.raises(Exception):
            R.drop_decrypt(S, dek, obj, 1, bad)
    assert R.drop_meta_open(S, dek, obj, 1, bytes.fromhex(d["meta_sealed"])) == d["meta"]
    assert R.b64u(R.dek_commit(obj, 1, dek)) == d["dek_commit"]


@pytest.mark.parametrize("sid", SUITES)
def test_drop_wraps(sid):
    S, v = R.SUITES[int(sid)], VEC["suites"][sid]
    d = v["drop"]

    def kx(name):
        return S.kx_key(bytes.fromhex(v["keys"][name]["seed"]))

    wk1 = bytes.fromhex(v["hkdf"][0]["ikm"])
    sk1 = bytes.fromhex(next(h for h in v["hkdf"] if h["name"] == "k_wrap_sk_epoch_1")["ikm"])
    assert R.unwrap_dek(S, d["wraps"]["wk"], wk=wk1).hex() == d["dek"]
    assert R.unwrap_dek(S, d["wraps"]["sk"], sk=sk1).hex() == d["dek"]
    assert R.unwrap_dek(S, d["wraps"]["wxk_b"], kx_priv=kx("wxk_b_1.kx")).hex() == d["dek"]
    assert R.unwrap_dek(S, d["wraps"]["device"], kx_priv=kx("phone.kx")).hex() == d["dek"]
    for n in d["wrap_negative"]:
        kw = {"wk": wk1} if n["record"]["target_kind"] == "wk" else {"kx_priv": kx("wxk_b_1.kx")}
        with pytest.raises(Exception):
            R.unwrap_dek(S, n["record"], **kw)


@each_suite("drop", "descriptor_cases")
def test_drop_descriptors(S, c):
    assert R.verify_drop_object(S, c["signed"], bytes.fromhex(c["author_pub"])) == c["expect"]


@each_suite("drop", "claims")
def test_drop_claims(S, c):
    obj = copy.deepcopy(c["object"])
    for st in c["steps"]:
        assert R.relay_claim(S, obj, st["claim"], c["cards"]) == st["expect"]
    assert obj == c["after"]


@each_suite("drop", "documents")
def test_drop_documents(S, c):
    doc = dict(c["doc"])
    assert R.relay_put_version(doc, c["if_match"], {"version": c["version"], "parent": c["parent"]}) == c["expect"]


# --- ws→ws (§11) ---------------------------------------------------------------------------------------

@pytest.mark.parametrize("sid", SUITES)
def test_ws_envelope_layout(sid):
    w = VEC["suites"][sid]["ws_envelopes"]
    hb = bytes.fromhex(w["header"])
    assert len(hb) == R.WX_HEADER_LEN == 60
    f = w["header_fields"]
    assert hb == R.WX_HEADER.pack(b"ORWX", 2, f["suite"], f["flags"], 0, bytes.fromhex(f["id"]),
                                  bytes.fromhex(f["from_ws"]), bytes.fromhex(f["to_ws"]), f["wxk_version"])
    env = bytes.fromhex(w["envelope"])
    body = bytes.fromhex(w["sealed_body"])
    assert env == hb + len(body).to_bytes(4, "big") + body + env[-64:]
    assert R.ws_envelope_hash(hb, body).hex() == w["envelope_hash"]


@each_suite("ws_envelopes", "cases")
def test_ws_receive(S, c):
    st = copy.deepcopy(c["state"])
    for step in c.get("steps", [c]):
        assert R.ws_receive(bytes.fromhex(step["envelope"]), st, step["now_ms"]) == step["expect"]


# --- publish, relay auth (§12) -----------------------------------------------------------------------

@each_suite("publish", "cases")
def test_publish(S, c):
    v = VEC["suites"][str(S.id)]
    cards = {v["ids"]["workspace_a"]: v["card"]["card"]["o"]}
    nonces = copy.deepcopy(c["nonces"])
    got = R.publish_check(S, c["headers"], c["method"], c["host"], c["target"], bytes.fromhex(c["body"]), cards,
                          nonces, c["now_ms"])
    assert got == c["expect"]


@pytest.mark.parametrize("sid", SUITES)
def test_relay_auth(sid):
    S, a = R.SUITES[int(sid)], VEC["suites"][sid]["relay_auth"]
    sb = R.relay_auth_signed_bytes(S, a["origin"], bytes.fromhex(a["challenge"]), a["kind"], bytes.fromhex(a["id"]))
    assert sb.hex() == a["signed_bytes"]
    assert S.verify(bytes.fromhex(VEC["suites"][sid]["keys"]["phone.sig"]["pub"]), bytes.fromhex(a["sig"]), sb)


@pytest.mark.parametrize("sid", SUITES)
def test_question_hash(sid):
    q = VEC["suites"][sid]["question_hash"]
    assert R.b64u(R.question_hash(q["content"])) == q["content_hash"]
