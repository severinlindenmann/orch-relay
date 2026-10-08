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
    card = v["card"]["card"]
    assert R.open_card_sealed_part(S, card["o"], ck, R.unb64u(card["sealed"])) == v["card"]["sealed_part_plaintext"]
    with pytest.raises(ValueError):          # a CK that is not the committed one is refused before decryption
        R.open_card_sealed_part(S, card["o"], bytes(32), R.unb64u(card["sealed"]))


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
    got = R.relay_accept_member_list(S, bytes.fromhex(c["wsk_pub"]), c["card_workspace_id"], c["prev"], c["signed"],
                                     ds, c["now_ms"])
    assert got == c["expect"]


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
    prim = copy.deepcopy(c["primary"])
    priv = S.kx_key(bytes.fromhex(v["keys"][c["me"] + ".kx"]["seed"]))
    for st in c["steps"]:
        got = R.primary_open_cert_request(S, st["signed"], c["card"], bytes.fromhex(c["person_id"]),
                                          bytes.fromhex(v["ids"]["device_" + c["me"]]), priv, prim, st["now_ms"])
        assert got == st["expect"]


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
    last = {}
    for st in c["steps"]:
        assert R.sw_open_push(S, st["raw"].encode(), c["keys"], last, st["now_ms"]) == st["expect"]


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
        assert R.relay_claim(S, obj, st["claim"], c["cards"], c["epochs"]) == st["expect"]
    assert obj == c["after"]


@each_suite("drop", "documents")
def test_drop_documents(S, c):
    doc = copy.deepcopy(c["doc"])
    assert R.relay_put_version(doc, c["if_match"], c["descriptor"]) == c["expect"]


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


@each_suite("relay_auth", "cases")
def test_relay_auth_cases(S, c):
    st = copy.deepcopy(c["state"])
    for s in c["steps"]:
        got = R.relay_auth_check(S, st, c["origin"], bytes.fromhex(c["challenge"]), s["kind"], bytes.fromhex(s["id"]),
                                 bytes.fromhex(s["sig"]), bytes.fromhex(s["pub"]), s["now_ms"])
        assert got == s["expect"]


@each_suite("enroll", "cases")
def test_enroll(S, c):
    v = VEC["suites"][str(S.id)]
    codes = copy.deepcopy(c["codes"])
    for s in c["steps"]:
        assert R.primary_check_enroll(S, s["signed"], bytes.fromhex(v["ids"]["person_alice"]), codes,
                                      s["now_ms"]) == s["expect"]


@each_suite("decisions", "cases")
def test_decisions(S, c):
    assert R.host_check_decision(S, c["meta"], c["workspace_id"], bytes.fromhex(c["dk_sig_pub"])) == c["expect"]


@each_suite("revocation_op")
def test_revocation_op(S, c):
    st = copy.deepcopy(c["state"])
    assert R.host_revocation(S, st, c["meta"]) == c["expect"]
    assert st == c["state_after"]


@each_suite("drop", "document_chains")
def test_document_chains(S, c):
    assert R.verify_doc_chain(c["versions"]) == c["expect"]


@pytest.mark.parametrize("sid", SUITES)
def test_cert_challenge_and_single_signature(sid):
    S, cr = R.SUITES[int(sid)], VEC["suites"][sid]["cert_request"]
    ch = cr["challenge"]
    assert set(ch["o"]) == R.CHALLENGE_FIELDS and "sas_nonce" not in cr["inner"]
    assert R.cert_sas(S, ch["o"]) == cr["cert_code"]
    cert = cr["signed_cert"]["ok"]["o"]
    assert (cert["dk_sig_pub"], cert["dk_kx_pub"]) == (ch["o"]["dk_sig_pub"], ch["o"]["dk_kx_pub"])
    assert cr["sign_again"] == {"refuse": "already_signed"}
    # the phone shows the code of the very challenge the primary signed
    ans = next(c for c in VEC["suites"][sid]["bridge"]["pair_answers"]
               if c["name"] == "cert_pending_with_the_primarys_challenge_shows_its_code")
    assert ans["expect"]["cert_code"] == cr["cert_code"]


# --- cross-side round trips: one side's output is the other side's input ------------------------------

class World:
    """Every party of one suite, from the vector file's FAKE keys."""

    def __init__(self, sid):
        self.S = S = R.SUITES[int(sid)]
        self.v = v = VEC["suites"][sid]
        self.sig = {n[:-4]: S.sig_key(bytes.fromhex(x["seed"])) for n, x in v["keys"].items() if n.endswith(".sig")}
        self.kx = {n[:-3]: S.kx_key(bytes.fromhex(x["seed"])) for n, x in v["keys"].items() if n.endswith(".kx")}
        self.pub = {n: bytes.fromhex(x["pub"]) for n, x in v["keys"].items()}
        self.id = {n: bytes.fromhex(x) for n, x in v["ids"].items() if len(x) == 32}
        self.ws = self.id["workspace_a"]


def _host_state(w, wk2, offer, secret):
    hc = next(c for c in w.v["bridge"]["host_cases"] if c["name"] == "pair_first_time")
    st = copy.deepcopy(hc["state"])
    st["offers"] = {offer.hex(): {"secret": secret.hex(), "expires_ms": hc["now_ms"] + R.OFFER_TTL_MS,
                                  "sas_nonce": R.b64u(R.fake("round trip sas nonce")), "used": False, "unverified": []}}
    return st, hc["now_ms"]


def _phone_req(w, ws, offer, secret, meta, seq, now, rid):
    S = w.S
    h = R.Header(R.TO_HOST, 0, S.id, ws, w.id["device_phone"], rid, offer, seq, now, 0, R.fake(f"salt {rid.hex()}")[:16])
    return R.envelope(S, R.k_pair(secret, ws, offer), w.sig["phone"], h, R.frame(meta))


@pytest.mark.parametrize("sid", SUITES)
def test_round_trip_pairing_through_cert_pending(sid):
    """phone → host → primary → host → phone, with the outputs of each step as the inputs of the next."""
    w = World(sid)
    S, ws = w.S, w.ws
    offer, secret = R.fake("rt offer")[:16], R.fake("rt secret")
    st, now = _host_state(w, None, offer, secret)
    ctx = {"suite": S.id, "workspace": ws.hex(), "device": w.id["device_phone"].hex(), "offer": offer.hex(),
           "secret": secret.hex(), "wsk_pin": R.wsk_pin(S, w.pub["wsk_a.sig"]).hex(),
           "pk_pin": R.pk_pin(S, w.pub["person_alice.sig"]).hex(), "dk_sig_pub": R.b64u(w.pub["phone.sig"]),
           "dk_kx_pub": R.b64u(w.pub["phone.kx"]), "offset_ms": 0, "pending": {}}

    def ask(meta, seq, t):
        rid = R.fake(f"rt rid {seq}")[:16]
        ctx["pending"][rid.hex()] = {"next": 0}
        req = _phone_req(w, ws, offer, secret, meta, seq, t, rid)
        res = R.host_check(req, st, t, rid.hex())
        env = R.host_respond(S, w.sig["wsk_a"], st, req, res, t, R.fake(f"rt resp {seq}")[:16])
        return res, R.open_pair_answer(env, ctx, t)

    # 1. pair: the host's code and the phone's code agree
    res, ans = ask({"op": "pair", "dk_sig_pub": ctx["dk_sig_pub"], "dk_kx_pub": ctx["dk_kx_pub"], "label": "rt",
                    "cert": None}, 1, now)
    assert res["result"] == "pair_pending" and ans["state"] == "pending" and ans["sas"] == res["sas"]
    # 2. pending while the human has not confirmed: the full five-field answer, which the phone accepts
    _, ans = ask({"op": "pair_status"}, 2, now + 10)
    assert ans["state"] == "pending" and ans["sas"] == res["sas"]
    # 3. the human confirmed; no certificate yet: the host asks the primary
    held = st["pending_pairs"][w.id["device_phone"].hex()]
    held.update(state="cert_pending", cert_pending_since=now + 20, primary_label="Mac", challenge=None)
    inner = {"device_id": w.id["device_phone"].hex(), "dk_sig_pub": held["dk_sig_pub"], "dk_kx_pub": held["dk_kx_pub"],
             "label": held["label"], "scopes_max": ["look", "decide", "operate"], "offer_id": offer.hex()}
    req_id = R.fake("rt request")[:16]
    creq = R.make_cert_request(S, w.sig["wsk_a"], ws, w.id["person_alice"], w.id["device_primary"],
                               w.pub["primary.kx"], req_id, inner, now + 20, R.fake("rt eph"))
    prim = {"seen": [], "open": {}}
    card = w.v["card"]["card"]
    opened = R.primary_open_cert_request(S, creq, card, w.id["person_alice"], w.id["device_primary"],
                                         w.kx["primary"], prim, now + 30)
    assert opened["ok"] == inner
    chal = R.primary_issue_challenge(S, w.sig["person_alice"], prim, creq["o"], opened["ok"], R.fake("rt nonce"))
    held["challenge"] = chal
    _, ans = ask({"op": "pair_status"}, 3, now + 40)
    assert ans["state"] == "cert_pending" and ans["cert_code"] == R.cert_sas(S, chal["o"])
    # 4. the human confirmed the code on the primary: it certifies its own challenge's keys, once
    cert = R.primary_sign_cert(S, w.sig["person_alice"], prim, req_id.hex(), R.b64u(b"\0" * 32), now + 50, None,
                               inner["scopes_max"])["ok"]
    held.update(state="approved", scopes=["look", "decide"], cert=cert)
    _, ans = ask({"op": "pair_status"}, 4, now + 60)
    assert ans["state"] == "approved" and ans["device_id"] == w.id["device_phone"].hex()


@pytest.mark.parametrize("sid", SUITES)
def test_round_trip_r1_attack_fails(sid):
    """R1: the host sends the primary a request for the intruder's key while the phone waits; the primary's
    challenge names the intruder's key, so the phone never shows a code and raises the alarm."""
    w = World(sid)
    S, ws = w.S, w.ws
    inner = {"device_id": w.id["device_intruder"].hex(), "dk_sig_pub": R.b64u(w.pub["intruder.sig"]),
             "dk_kx_pub": R.b64u(w.pub["intruder.kx"]), "label": "Severin's iPhone",
             "scopes_max": ["look"], "offer_id": R.fake("offer id")[:16].hex()}
    creq = R.make_cert_request(S, w.sig["wsk_a"], ws, w.id["person_alice"], w.id["device_primary"],
                               w.pub["primary.kx"], R.fake("r1")[:16], inner, 1_790_000_000_000, R.fake("r1 eph"))
    prim = {"seen": [], "open": {}}
    opened = R.primary_open_cert_request(S, creq, w.v["card"]["card"], w.id["person_alice"],
                                         w.id["device_primary"], w.kx["primary"], prim, 1_790_000_000_000)
    chal = R.primary_issue_challenge(S, w.sig["person_alice"], prim, creq["o"], opened["ok"], R.fake("r1 nonce"))
    c = {"workspace": ws.hex(), "device": w.id["device_phone"].hex(), "dk_sig_pub": R.b64u(w.pub["phone.sig"]),
         "dk_kx_pub": R.b64u(w.pub["phone.kx"])}
    assert R.check_cert_challenge(S, chal, w.pub["person_alice.sig"], c, 1_790_000_000_000) == {"drop": "not_my_key"}
    # nor can the host make a challenge of its own for the phone's keys: it does not hold PK
    forged = {"o": {**chal["o"], "device_id": c["device"], "dk_sig_pub": c["dk_sig_pub"], "dk_kx_pub": c["dk_kx_pub"]},
              "sig": R.b64u(S.sign(w.sig["wsk_a"], R.L["sig_cert_challenge"] + R.cj(chal["o"])))}
    assert R.check_cert_challenge(S, forged, w.pub["person_alice.sig"], c, 1_790_000_000_000) == \
        {"drop": "challenge_signature"}


@pytest.mark.parametrize("sid", SUITES)
def test_round_trip_bridge_request_and_refusal(sid):
    """device request → host_check → host_respond → device_check, for an accepted request and a stale_epoch."""
    w = World(sid)
    S, ws = w.S, w.ws
    hc = next(c for c in w.v["bridge"]["host_cases"] if c["name"] == "full_request_accepted")
    st, now = copy.deepcopy(hc["state"]), hc["now_ms"]
    wk = {e: bytes.fromhex(x) for e, x in st["wk"].items()}
    for epoch, seq, want in ((2, 11, "accept"), (1, 12, "stale_epoch")):
        rid = R.fake(f"rt bridge {seq}")[:16]
        h = R.Header(R.TO_HOST, 0, S.id, ws, w.id["device_phone"], rid, R.ZERO_ID, seq, now, epoch,
                     R.fake(f"rt bridge salt {seq}")[:16])
        req = R.envelope(S, R.k_bridge(wk[str(epoch)], ws, epoch), w.sig["phone"], h,
                         R.frame({"op": "http", "method": "GET", "path": "/"}))
        res = R.host_check(req, st, now, rid.hex())
        assert res.get("code", res["result"]) == want
        env = R.host_respond(S, w.sig["wsk_a"], st, req, res, now, R.fake(f"rt bridge resp {seq}")[:16])
        dctx = {"suite": S.id, "workspace": ws.hex(), "device": w.id["device_phone"].hex(),
                "wsk_pub": R.b64u(w.pub["wsk_a.sig"]), "wk": st["wk"], "offset_ms": 0,
                "pending": {rid.hex(): {"next": 0, "stream": False, "epoch": epoch}}}
        got = R.device_check(env, dctx, {"id": rid.hex(), "idx": 0, "last": True, "stream": False}, now)
        assert got["result"] == "accept"
        assert got.get("fetch_grants") == (True if want == "stale_epoch" else None)


@pytest.mark.parametrize("sid", SUITES)
def test_round_trip_card(sid):
    """host makes a card → relay accepts it → a peer device unwraps CK, checks ck_commit, reads the sealed part."""
    w = World(sid)
    S, ws = w.S, w.ws
    deleg = R.make_delegation(S, w.sig["person_alice"], ws, w.pub["wsk_a.sig"], w.id["person_alice"], False, 1)
    ck = R.fake("rt card key")
    part = {"name": "rt", "description": "", "capabilities": [], "hosted_by": None}
    o = {k: v for k, v in w.v["card"]["card"]["o"].items() if k not in ("sealed_hash", "ck_commit")}
    card = R.make_card(S, w.sig["wsk_a"], deleg, o, R.card_sealed_part(S, ck, ws, 1, part), ck)
    assert R.relay_accept_card(S, None, card, w.pub["person_alice.sig"]) == {"ok": card["o"]}
    wrap = R.seal_to(S, w.pub["laptop.kx"], w.id["device_laptop"], "card", ws, 1, ck, R.fake("rt card eph"))
    ck2 = R.open_sealed(S, w.kx["laptop"], w.id["device_laptop"], "card", ws, 1, wrap)
    assert R.open_card_sealed_part(S, card["o"], ck2, R.unb64u(card["sealed"])) == part


@pytest.mark.parametrize("sid", SUITES)
def test_round_trip_ws_ticket_refusal_and_result(sid):
    """A sends B a depth-2 ticket → B refuses → A receives the refusal; a refusal is never answered; a second
    reply to the same ticket is refused."""
    w = World(sid)
    S = w.S
    a, b = w.id["workspace_a"], w.id["workspace_b"]
    origin = "https://relay.dev.severin.io"
    tid = R.fake("rt ticket")[:16]
    hb = R.wx_header(S, 0, tid, a, b, 1)
    body = {"kind": "ticket", "in_reply_to": None, "depth": 2, "deadline_ms": 1_790_086_400_000,
            "ticket": {"title": "x"}, "result": None, "refusal": None, "attachments": []}
    env = R.build_ws_envelope(S, w.sig["wsk_a"], hb, body, w.pub["wxk_b_1.kx"], R.fake("rt ws eph"))
    B = {"suite": S.id, "workspace": b.hex(), "wxk_version": 1,
         "wxk": {"1": {"seed": w.v["keys"]["wxk_b_1.kx"]["seed"], "retired_ms": None}},
         "peers": {a.hex(): {"wsk_pub": R.b64u(w.pub["wsk_a.sig"]), "owner_pk_pub": R.b64u(w.pub["person_alice.sig"]),
                             "relay_url": origin, "revoked": []}}, "seen": {}, "sent": {}}
    A = {"suite": S.id, "workspace": a.hex(), "wxk_version": 1,
         "wxk": {"1": {"seed": w.v["keys"]["wxk_a_1.kx"]["seed"], "retired_ms": None}},
         "peers": {b.hex(): {"wsk_pub": R.b64u(w.pub["wsk_b.sig"]), "owner_pk_pub": R.b64u(w.pub["person_bob.sig"]),
                             "relay_url": origin, "revoked": []}}, "seen": {},
         "sent": {tid.hex(): {"to": b.hex(), "consumed": []}}}
    now = 1_790_000_000_000
    r = R.ws_receive(env, B, now)
    assert r == {"result": "refuse", "code": "depth_exceeded"}
    refusal = R.build_ws_refusal(S, w.sig["wsk_b"], b, tid, a, w.pub["wxk_a_1.kx"], 1, r["code"],
                                 R.fake("rt refusal")[:16], R.fake("rt refusal eph"), now)
    got = R.ws_receive(refusal, A, now + 1)
    assert got["result"] == "deliver" and got["code"] == "depth_exceeded"
    # the same refusal again is a duplicate, never a second delivery; a late result is refused, silently
    assert R.ws_receive(refusal, A, now + 2)["result"] == "duplicate"
    rh = R.wx_header(S, 0, R.fake("rt late result")[:16], b, a, 1)
    late = R.build_ws_envelope(S, w.sig["wsk_b"], rh, {**body, "kind": "result", "depth": 0, "in_reply_to": tid.hex(),
                                                      "ticket": None, "result": {"status": "done"}},
                               w.pub["wxk_a_1.kx"], R.fake("rt late eph"))
    assert R.ws_receive(late, A, now + 3) == {"result": "refuse", "code": "unknown_reply"}


@pytest.mark.parametrize("sid", SUITES)
def test_round_trip_drop_claim(sid):
    """writer wraps a DEK to two WXKs → B unwraps and rewraps under its WK → relay claim → B reads the DEK."""
    w = World(sid)
    S = w.S
    d = w.v["drop"]
    obj, dek = bytes.fromhex(d["object_id"]), bytes.fromhex(d["dek"])
    b = w.id["workspace_b"]
    rec = R.wrap_dek(S, "wxk", b, 1, obj, 1, dek, kx_pub=w.pub["wxk_b_1.kx"], eph_seed=R.fake("rt claim eph"))
    got = R.unwrap_dek(S, rec, kx_priv=w.kx["wxk_b_1"])
    wk_b = R.fake("rt WK b")
    new = R.wrap_dek(S, "wk", b, 3, obj, 1, got, wk=wk_b, salt=R.fake("rt claim salt")[:16])
    claim = R.sign_object(S, w.sig["wsk_b"], {"v": 2, "suite": S.id, "kind": "drop_claim", "object_id": obj.hex(),
                                              "workspace_id": b.hex(), "wrap": new})
    state = {"object_id": obj.hex(), "version": 1, "state": "inbox", "claimed_by": None, "wraps": [rec]}
    cards = {b.hex(): {"wsk_pub": R.b64u(w.pub["wsk_b.sig"])}}
    assert R.relay_claim(S, state, claim, cards, {b.hex(): 3}) == {"status": 200, "claimed_by": b.hex()}
    assert R.unwrap_dek(S, state["wraps"][0], wk=wk_b) == dek
