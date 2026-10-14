"""H12d (P3-D38) relay-owned vectors: `reader_decl` (orch-core orch-v2-host §9.3), the pair-request meta v2
(protocol §8.3) and `rd` in the request meta (§8.6). TEST SUPPORT ONLY.

Every key is FAKE (SHA-256 of a public label). Self-contained: reads the suite's keys and ids from the already built
vectors and adds nothing to the older groups.

Every `kat` digest here is a FAKE stand-in, NOT core's `reader_kat_1` digest: core owns the KAT corpus and its digest
construction (F1 §11.5). The cases check the declaration's form, signature, binding and level rules, which the relay
reference computes from §9.3 alone; a case whose outcome compares a digest with an expected value carries
`depends_on_core`, and its expected value is the same stand-in, so it tests the comparison, not the digest.
"""
import copy
import hashlib

from ref import orch_protocol_ref as R
from ref._vectors import _strip

NOW = 1_790_000_000_000
KAT_STANDIN = "sha256:" + hashlib.sha256(b"FAKE stand-in for core's reader_kat_1 view digest").hexdigest()
KAT_OTHER = "sha256:" + hashlib.sha256(b"FAKE another reader_kat_1 view digest").hexdigest()
CORE = "reader_kat_1 (F1 §11.5, orch-core): the expected digest here is a FAKE stand-in"


def add_reader(out):
    for sid, v in out["suites"].items():
        v["reader_decl"] = _suite(R.SUITES[int(sid)], v)


def _suite(S, v):  # noqa: C901 (a builder: long by nature)
    fake = R.fake
    keys, ids = v["keys"], v["ids"]
    sig = {n[:-4]: S.sig_key(bytes.fromhex(x["seed"])) for n, x in keys.items() if n.endswith(".sig")}
    pub = {n: bytes.fromhex(x["pub"]) for n, x in keys.items()}
    ws = bytes.fromhex(ids["workspace_a"])
    offer, secret = fake("offer id")[:16], fake(f"suite{S.id}/pairing secret")
    attempt = fake("pairing attempt a")[:16].hex()
    pk_pin = R.b64u(R.pk_pin(S, pub["person_alice.sig"]))
    phone_sig, phone_kx = pub["phone.sig"], pub["phone.kx"]

    o = {"v": 1, "kind": "reader_decl", "suite": S.id, "workspace_id": ws.hex(),
         "device_id": R.device_id(S, phone_sig).hex(), "dk_hash": R.b64u(R.dk_hash(S, phone_sig, phone_kx)),
         "who": {"pk_pin": pk_pin}, "reader": 1, "kat": {"1": {"view": KAT_STANDIN}},
         "bind": {"via": "pair", "offer_id": offer.hex(), "attempt": attempt}, "created_ms": NOW}
    ctx = {"workspace_id": ws.hex(), "dk_sig_pub": R.b64u(phone_sig), "dk_kx_pub": R.b64u(phone_kx),
           "who": {"pk_pin": pk_pin}, "bind": {"via": "pair", "offer_id": offer.hex(), "attempt": attempt},
           "host_max": 1, "surfaces": ["view"]}
    valid = R.make_reader_decl(S, sig["phone"], o)

    decls = []

    def case(name, decl, ctx_=None, core=False, expect=None):
        c = {"name": name, "decl": decl, "ctx": ctx_ or ctx}
        if core:
            c["depends_on_core"] = CORE
        got = R.verify_reader_decl(S, decl, c["ctx"])
        if expect is not None:
            assert ("ok" in got) if expect == "ok" else got.get("reason") == expect, (name, got)
        c["expect"] = got
        decls.append(c)

    def signed(**changes):
        return R.make_reader_decl(S, sig["phone"], {**o, **changes})

    case("valid_pairing_declaration", valid, expect="ok")
    case("wrong_workspace", signed(workspace_id=fake("workspace b")[:16].hex()), expect="workspace")
    case("wrong_device_id", signed(device_id=R.device_id(S, pub["laptop.sig"]).hex()), expect="device")
    case("dk_hash_of_another_key", signed(dk_hash=R.b64u(R.dk_hash(S, phone_sig, pub["intruder.kx"]))),
         expect="keys")
    case("offer_id_of_another_offer", signed(bind={**o["bind"], "offer_id": fake("g3b other offer")[:16].hex()}),
         expect="bind")
    case("attempt_of_another_attempt", signed(bind={**o["bind"], "attempt": fake("g3b pairing attempt b")[:16].hex()}),
         expect="bind")
    case("wrong_who", signed(who={"pk_pin": R.b64u(R.pk_pin(S, pub["person_bob.sig"]))}), expect="who")
    case("who_person_id_where_the_pairing_names_pk_pin", signed(who={"person_id": ids["person_alice"]}), expect="who")
    case("reader_0_is_valid_without_kat", signed(reader=0, kat={}), expect="ok")
    case("higher_unknown_level_7_with_kat_1_only_accepted",
         signed(reader=7, kat={"1": {"view": KAT_STANDIN}, "7": {"surface_of_level_7": "anything"}}), expect="ok")
    case("reader_1_without_kat_1", signed(kat={}), expect="kat_missing")
    case("kat_1_without_the_required_surface", signed(kat={"1": {"log": KAT_STANDIN}}), expect="kat_missing")
    case("kat_1_not_a_digest", signed(kat={"1": {"view": "sha256:" + "G" * 64}}), expect="shape")
    case("kat_1_unknown_surface", signed(kat={"1": {"view": KAT_STANDIN, "screen": KAT_STANDIN}}), expect="shape")
    case("kat_level_key_with_a_leading_zero", signed(kat={"01": {"view": KAT_STANDIN}}), expect="shape")
    case("kat_1_matches_the_expected_digest", valid, {**ctx, "kat": {"1": {"view": KAT_STANDIN}}}, core=True,
         expect="ok")
    case("wrong_kat_1_digest", signed(kat={"1": {"view": KAT_OTHER}}), {**ctx, "kat": {"1": {"view": KAT_STANDIN}}},
         core=True, expect="kat_mismatch")
    case("signature_by_another_key", R.make_reader_decl(S, sig["intruder"], o), expect="signature")
    case("signature_under_another_label",
         {"o": o, "sig": R.b64u(S.sign(sig["phone"], R.L["sig_relay_auth"] + R.cj(o)))}, expect="signature")
    case("tampered_after_signing", {"o": {**o, "reader": 2}, "sig": valid["sig"]}, expect="signature")
    case("unknown_field", signed(extra=True), expect="shape")
    case("version_2", signed(v=2), expect="shape")
    case("other_suite", signed(suite=3 - S.id), expect="shape")
    case("reader_negative", signed(reader=-1), expect="shape")
    case("reader_above_2_31_minus_1", signed(reader=2 ** 31), expect="shape")
    case("reader_boolean", signed(reader=True), expect="shape")
    case("bind_pair_with_an_extra_field", signed(bind={**o["bind"], "rid": "00" * 16}), expect="shape")
    case("over_2_kib", signed(kat={"1": {"view": KAT_STANDIN}, "9": {"pad": "x" * 2048}}), expect="shape")

    size = len(R.cj(valid))
    assert size <= R.READER_DECL_MAX and size < 1024, size

    # ------------------------------------------------------------------ the pair-request meta v2 (§8.3)
    kp = R.k_pair(secret, ws, offer)
    meta_v1 = {"op": "pair", "dk_sig_pub": R.b64u(phone_sig), "dk_kx_pub": R.b64u(phone_kx),
               "label": "Severin's iPhone", "cert": None, "attempt": attempt}
    meta_v2 = {**meta_v1, "reader_decl": valid}
    host_state = {"suite": S.id, "workspace": ws.hex(), "epoch": 2, "wk": {}, "members": {}, "certs": {},
                  "revoked": [], "seq": {}, "rids": {}, "streams": {}, "unverified": [],
                  "offers": {offer.hex(): {"secret": secret.hex(), "expires_ms": NOW + R.OFFER_TTL_MS,
                                           "sas_nonce": R.b64u(fake("sas nonce")), "used": False, "unverified": []}},
                  "pending_pairs": {}, "wsk_pub": R.b64u(pub["wsk_a.sig"]),
                  "owner_pk_pub": R.b64u(pub["person_alice.sig"]), "owner_person_id": ids["person_alice"]}

    def preq(meta, seq=1):
        h = R.Header(R.TO_HOST, 0, S.id, ws, R.device_id(S, phone_sig), fake(f"reader pair rid {seq}")[:16], offer,
                     seq, NOW, 0, fake(f"reader pair salt {seq}")[:16])
        return R.envelope(S, kp, sig["phone"], h, R.frame(meta))

    pair = []

    def pcase(name, meta, result):
        s = copy.deepcopy(host_state)
        env = preq(meta)
        mb = R.Header.decode(env).rid.hex()
        got = _strip(R.host_check(env, s, NOW, mb))
        assert got["result"] == result or got.get("code") == result, (name, got)
        c = {"name": name, "meta": meta, "state": host_state, "steps": [
            {"envelope": env.hex(), "mailbox_id": mb, "now_ms": NOW, "expect": got}]}
        if "reader_decl" in got:
            # step 5, the host's gate: the declaration against this request's keys, the offer stream's workspace,
            # the link's pk_pin and this attempt (orch-v2-host §9.3, §9.4)
            c["gate"] = {"ctx": ctx, "expect": R.verify_reader_decl(S, got["reader_decl"], ctx)}
        pair.append(c)

    pcase("meta_v2_with_reader_decl_pending", meta_v2, "pair_pending")
    pcase("meta_v1_without_reader_decl_still_pending", meta_v1, "pair_pending")
    pcase("meta_v2_reader_decl_null_malformed", {**meta_v1, "reader_decl": None}, "malformed")
    pcase("meta_v2_reader_decl_without_sig_malformed", {**meta_v1, "reader_decl": {"o": o}}, "malformed")
    pcase("meta_v2_reader_decl_over_2_kib_malformed",
          {**meta_v1, "reader_decl": signed(kat={"1": {"view": KAT_STANDIN}, "9": {"pad": "x" * 2048}})}, "malformed")
    pcase("meta_v2_with_another_unknown_field_malformed", {**meta_v2, "rd": R.reader_decl_digest(valid)}, "malformed")
    pcase("meta_v2_with_a_declaration_that_fails_the_gate_still_pending",
          {**meta_v1, "reader_decl": R.make_reader_decl(S, sig["intruder"], o)}, "pair_pending")
    assert pair[0]["gate"]["expect"]["ok"]["level"] == 1
    assert pair[-1]["gate"]["expect"]["reason"] == "signature"

    # ------------------------------------------------------------------ rd in the request meta (§8.6)
    wk2 = fake(f"suite{S.id}/reader rd wk 2")
    rd = R.reader_decl_digest(valid)
    phone = R.device_id(S, phone_sig).hex()
    rstate = {"suite": S.id, "workspace": ws.hex(), "epoch": 2, "wk": {"2": wk2.hex()},
              "members": {phone: ["look", "decide", "operate"]}, "certs": {phone: {"dk_sig_pub": R.b64u(phone_sig)}},
              "revoked": [], "seq": {}, "rids": {}, "streams": {}, "unverified": [], "offers": {}, "pending_pairs": {},
              "wsk_pub": R.b64u(pub["wsk_a.sig"]), "owner_pk_pub": R.b64u(pub["person_alice.sig"]),
              "owner_person_id": ids["person_alice"]}

    def rreq(meta, seq, ts=NOW):
        h = R.Header(R.TO_HOST, 0, S.id, ws, bytes.fromhex(phone), fake(f"reader rd rid {seq}")[:16], R.ZERO_ID, seq,
                     ts, 2, fake(f"reader rd salt {seq}")[:16])
        return R.envelope(S, R.k_bridge(wk2, ws, 2), sig["phone"], h, R.frame(meta))

    meta_rd = {"op": "http", "method": "GET", "path": "/api/status", "rd": rd}
    first = rreq(meta_rd, 1)
    later = R.make_reader_decl(S, sig["phone"], {**o, "created_ms": NOW + 1000, "bind": {"via": "declare"}})
    request = []

    def rchain(name, steps):
        s = copy.deepcopy(rstate)
        st = []
        for env, now in steps:
            mb = R.Header.decode(env).rid.hex()
            st.append({"envelope": env.hex(), "mailbox_id": mb, "now_ms": now,
                       "expect": _strip(R.host_check(env, s, now, mb))})
        request.append({"name": name, "state": rstate, "steps": st})

    rchain("request_meta_with_rd_accepted", [(first, NOW)])
    # a resend keeps the rd of its first send (the same bytes): the host answers it from the rid record (§8.6 step 5),
    # never against the device's newer declaration
    rchain("resend_after_a_new_declaration_replays_the_first_send", [(first, NOW), (first, NOW + 2000)])
    rchain("request_meta_without_rd_accepted_by_the_bridge", [(rreq({k: x for k, x in meta_rd.items() if k != "rd"}, 1),
                                                               NOW)])
    assert request[0]["steps"][0]["expect"]["meta"]["rd"] == rd
    # the op still runs (no outcome recorded): the rid record answers, the request is never run again
    assert request[1]["steps"][1]["expect"].get("code") == "already_done", request[1]["steps"][1]["expect"]

    return {"label": R.LABELS["sig_reader_decl"], "max_bytes": R.READER_DECL_MAX, "host_max": 1,
            "kat_standin": KAT_STANDIN,
            "digest": {"decl": valid, "cj_bytes": len(R.cj(valid)), "rd": rd},
            "later_declaration": {"decl": later, "rd": R.reader_decl_digest(later)},
            "decls": decls, "pair_meta": pair, "request_meta": request}
