"""Builds tests/vectors_v2.json from the reference (ref/orch_protocol_ref.py). TEST SUPPORT ONLY.

Every key is FAKE: derived from SHA-256 of a public label. Every "random" value (salts, nonces, ephemeral
keys, ids) is fixed the same way, so the file is reproducible byte for byte.
"""
from __future__ import annotations

import copy
import json

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from ref import orch_protocol_ref as R
from ref.orch_protocol_ref import b64u, cj, fake, u32

NOW = 1_790_000_000_000


def _j(x):
    """A JSON-safe deep copy of a state (bytes never appear in states; sets become sorted lists)."""
    return json.loads(json.dumps(x, default=lambda v: sorted(v) if isinstance(v, set) else v))


class K:
    """The fixed key material of one suite."""

    def __init__(self, suite: R.Suite):
        self.s = suite
        self.seeds, self.priv, self.pub = {}, {}, {}

    def sig(self, name):
        seed = fake(f"suite{self.s.id}/{name}/sig")
        p = self.s.sig_key(seed)
        self.seeds[name + ".sig"], self.priv[name + ".sig"], self.pub[name + ".sig"] = seed, p, self.s.sig_pub(p)
        return p

    def kx(self, name):
        seed = fake(f"suite{self.s.id}/{name}/kx")
        p = self.s.kx_key(seed)
        self.seeds[name + ".kx"], self.priv[name + ".kx"], self.pub[name + ".kx"] = seed, p, self.s.kx_pub(p)
        return p

    def as_json(self):
        return {n: {"seed": self.seeds[n].hex(), "pub": self.pub[n].hex()} for n in sorted(self.seeds)}


def build() -> dict:
    out = {
        "comment": "orch v2 protocol test vectors (docs/protocol-v2.md). Every key here is FAKE: derived from "
                   "SHA-256 of a public label. Regenerate with: uv run python -m ref.orch_protocol_ref",
        "version": 2,
        "labels": R.LABELS,
        "constants": {
            "bridge": {"magic": R.MAGIC.decode(), "header_len": R.HEADER_LEN, "overhead": R.OVERHEAD,
                       "max_request": R.MAX_REQUEST, "max_chunk": R.MAX_CHUNK, "max_meta": R.MAX_META,
                       "window_ms": R.WINDOW_MS, "seq_window": R.SEQ_WINDOW, "rid_retention_ms": R.RID_RETENTION_MS,
                       "per_device": R.PER_DEVICE, "max_records": R.MAX_RECORDS, "busy_allowance": R.BUSY_ALLOWANCE,
                       "budget": R.BUDGET, "offer_budget": R.OFFER_BUDGET, "budget_window_ms": R.BUDGET_WINDOW_MS,
                       "max_offset_ms": R.MAX_OFFSET_MS, "max_label": R.MAX_LABEL, "offer_ttl_ms": R.OFFER_TTL_MS,
                       "cert_pending_ms": R.CERT_PENDING_MS},
            "skew_ms": R.SKEW_MS,
            "push": {"max_bytes": R.MAX_PUSH, "max_age_ms": R.PUSH_MAX_AGE_MS, "kinds": list(R.PUSH_KINDS)},
            "drop": {"magic": R.DROP_MAGIC.decode(), "header_len": R.DROP_HEADER_LEN,
                     "default_chunk": R.DEFAULT_CHUNK, "max_chunk": R.MAX_CHUNK_SIZE},
            "ws_envelope": {"magic": R.WX_MAGIC.decode(), "header_len": R.WX_HEADER_LEN,
                            "max_bytes": R.MAX_WS_ENVELOPE, "max_deadline_ms": R.MAX_DEADLINE_MS,
                            "wxk_overlap_ms": R.WXK_OVERLAP_MS, "seen_retention_ms": R.SEEN_RETENTION_MS,
                            "body_kinds": list(R.BODY_KINDS), "refusals": list(R.WS_REFUSALS)},
            "publish": {"window_ms": R.PUBLISH_WINDOW_MS, "nonce_retention_ms": R.NONCE_RETENTION_MS},
            "seal_purposes": list(R.SEAL_PURPOSES),
            "scope_order": R.SCOPE_ORDER,
        },
        "encodings": _encodings(),
        "ed25519_small_order": R.ed25519_small_order_encodings(),
        "suites": {str(sid): _suite(R.SUITES[sid]) for sid in (1, 2)},
    }
    return out


def _encodings():
    good = {"a": 1, "b": [True, None, "ü"], "Z": {"y": -3}}
    return {
        "canonical_json": [
            {"name": "sorted_ascii_keys", "value": good, "bytes": cj(good).hex()},
            {"name": "astral_and_escapes", "value": {"t": "a\"\\\n 😀"}, "bytes": cj({"t": "a\"\\\n 😀"}).hex()},
        ],
        "strict_parse": [
            {"name": n, "text": t, "ok": ok} for n, t, ok in (
                ("valid", '{"a":1}', True),
                ("duplicate_key", '{"a":1,"a":2}', False),
                ("nan", '{"a":NaN}', False),
                ("infinity", '{"a":-Infinity}', False),
                ("float", '{"a":1.0}', False),
                ("exponent", '{"a":1e3}', False),
                ("too_large_integer", '{"a":9007199254740992}', False),
                ("largest_safe_integer", '{"a":9007199254740991}', True),
                ("non_ascii_key", '{"ä":1}', False),
                ("lone_surrogate", '{"a":"\\ud800"}', False),
            )],
        "b64u": [
            {"name": n, "text": t, "bytes": b} for n, t, b in (
                ("canonical", "AAE", "0001"),
                ("padded", "AAE=", None),
                ("non_canonical_trailing_bits", "AAF", None),
                ("standard_alphabet", "+/8", None),
                ("one_char_too_many", "AAAAA", None),
            )],
    }


def _parse_ok(text):
    try:
        R.parse_json(text.encode())
        return True
    except ValueError:
        return False


def _suite(S: R.Suite) -> dict:  # noqa: C901 (a builder: long by nature)
    k = K(S)
    pk, pk_bob = k.sig("person_alice"), k.sig("person_bob")
    for n in ("primary", "phone", "laptop", "intruder", "agent", "bob_phone"):
        k.sig(n), k.kx(n)
    wsk_a, _, wsk_x = k.sig("wsk_a"), k.sig("wsk_b"), k.sig("wsk_intruder")
    for n in ("wxk_a_1", "wxk_a_2", "wxk_b_1"):
        k.kx(n)
    pub = k.pub
    pid, pid_bob = R.person_id(S, pub["person_alice.sig"]), R.person_id(S, pub["person_bob.sig"])
    dev = {n: R.device_id(S, pub[n + ".sig"]) for n in ("primary", "phone", "laptop", "intruder", "agent", "bob_phone")}
    ws_a, ws_b = fake("workspace a")[:16], fake("workspace b")[:16]
    space = fake("shared space")[:16]
    pvk = fake(f"suite{S.id}/personal vault key")

    o = {"suite": S.id, "name": S.name, "keys": k.as_json(),
         "ids": {"person_alice": pid.hex(), "person_bob": pid_bob.hex(), "workspace_a": ws_a.hex(),
                 "workspace_b": ws_b.hex(), "shared_space": space.hex(),
                 **{f"device_{n}": d.hex() for n, d in dev.items()},
                 "pk_pin_alice": R.pk_pin(S, pub["person_alice.sig"]).hex(),
                 "wsk_pin_a": R.wsk_pin(S, pub["wsk_a.sig"]).hex()}}

    # --- signatures (§1.2) --------------------------------------------------------------------------
    msg = b"orch v2 signature vector"
    sig = S.sign(k.priv["phone.sig"], msg)
    sign = [
        {"name": "valid", "pub": pub["phone.sig"].hex(), "msg": msg.hex(), "sig": sig.hex(), "valid": True},
        {"name": "other_key", "pub": pub["laptop.sig"].hex(), "msg": msg.hex(), "sig": sig.hex(), "valid": False},
        {"name": "one_bit_of_msg", "pub": pub["phone.sig"].hex(), "msg": (msg[:-1] + bytes([msg[-1] ^ 1])).hex(),
         "sig": sig.hex(), "valid": False},
        {"name": "short_signature", "pub": pub["phone.sig"].hex(), "msg": msg.hex(), "sig": sig[:63].hex(),
         "valid": False},
    ]
    if S.id == 1:
        s_int = int.from_bytes(sig[32:], "little")
        sign += [
            {"name": "s_plus_l_not_canonical", "pub": pub["phone.sig"].hex(), "msg": msg.hex(),
             "sig": (sig[:32] + (s_int + R.ED_L).to_bytes(32, "little")).hex(), "valid": False},
            {"name": "small_order_public_key", "pub": R.ed25519_small_order_encodings()[0], "msg": msg.hex(),
             "sig": sig.hex(), "valid": False},
            {"name": "identity_public_key", "pub": "01" + "00" * 31, "msg": msg.hex(),
             "sig": ("01" + "00" * 63), "valid": False},
            {"name": "non_canonical_y_public_key", "pub": (R.ED_P + 1).to_bytes(32, "little").hex(), "msg": msg.hex(),
             "sig": sig.hex(), "valid": False},
        ]
    else:
        nb = R.P256_N.to_bytes(32, "big")
        s_int = int.from_bytes(sig[32:], "big")
        sign += [
            {"name": "high_s_twin_verifies", "pub": pub["phone.sig"].hex(), "msg": msg.hex(),
             "sig": (sig[:32] + (R.P256_N - s_int).to_bytes(32, "big")).hex(), "valid": True},
            {"name": "r_zero", "pub": pub["phone.sig"].hex(), "msg": msg.hex(), "sig": (bytes(32) + sig[32:]).hex(),
             "valid": False},
            {"name": "s_equals_n", "pub": pub["phone.sig"].hex(), "msg": msg.hex(), "sig": (sig[:32] + nb).hex(),
             "valid": False},
            {"name": "point_not_on_curve", "pub": (pub["phone.sig"][:-1] + bytes([pub["phone.sig"][-1] ^ 1])).hex(),
             "msg": msg.hex(), "sig": sig.hex(), "valid": False},
        ]
    for c in sign:
        assert S.verify(bytes.fromhex(c["pub"]), bytes.fromhex(c["sig"]), bytes.fromhex(c["msg"])) == c["valid"], c["name"]
    o["sign"] = sign

    # --- HKDF derivations (§3, §5) ------------------------------------------------------------------
    wk1, wk2 = fake(f"suite{S.id}/WK a epoch 1"), fake(f"suite{S.id}/WK a epoch 2")
    secret = fake(f"suite{S.id}/pairing secret")
    offer = fake("offer id")[:16]
    ck = fake(f"suite{S.id}/card key")
    dek = fake(f"suite{S.id}/DEK")
    obj = fake("drop object")[:16]
    sk1 = fake(f"suite{S.id}/SK space epoch 1")
    hk = []

    def hk_entry(name, ikm, salt, info, okm):
        hk.append({"name": name, "ikm": ikm.hex(), "salt": salt.hex(), "info": info.hex(),
                   "info_text": info.decode("ascii"), "okm": okm.hex()})

    for name, ikm, info, f in (
            ("k_bridge_epoch_1", wk1, R.ctx("orch/v2/bridge", ws_a, 1), lambda: R.k_bridge(wk1, ws_a, 1)),
            ("k_bridge_epoch_2", wk2, R.ctx("orch/v2/bridge", ws_a, 2), lambda: R.k_bridge(wk2, ws_a, 2)),
            ("k_push_epoch_1", wk1, R.ctx("orch/v2/push", ws_a, 1), lambda: R.k_push(wk1, ws_a, 1)),
            ("k_wrap_wk_epoch_1", wk1, R.ctx("orch/v2/wrap-wk", ws_a, 1), lambda: R.k_wrap_wk(wk1, ws_a, 1)),
            ("k_wrap_sk_epoch_1", sk1, R.ctx("orch/v2/wrap-sk", space, 1), lambda: R.k_wrap_sk(sk1, space, 1)),
            ("k_pair", secret, R.ctx("orch/v2/pair", ws_a, offer), lambda: R.k_pair(secret, ws_a, offer)),
            ("k_card_seq_1", ck, R.ctx("orch/v2/card", ws_a, 1), lambda: R.k_card(ck, ws_a, 1)),
            ("k_drop_content_v1", dek, R.ctx("orch/v2/drop-content", obj, 1), lambda: R.drop_content_key(dek, obj, 1)),
            ("k_label", pvk, R.ctx("orch/v2/label", pid), lambda: R.k_label(pvk, pid))):
        okm = f()
        assert okm == R.hkdf(ikm, b"", info)
        hk_entry(name, ikm, b"", info, okm)
    kb1 = R.k_bridge(wk1, ws_a, 1)
    salt = fake("bridge salt")[:16]
    hk_entry("k_msg_bridge", kb1, salt, R.L["kdf_bridge_msg"], R.message_key(kb1, salt))
    o["hkdf"] = hk

    # --- SALTED-AEAD (§5.1) -------------------------------------------------------------------------
    s_salt = fake("salted salt")[:16]
    blob = R.salted_seal(kb1, b"orch/v2/push-msg", b"aad", b"hello", s_salt)
    o["salted_aead"] = [{"name": "push_msg_label", "k_base": kb1.hex(), "msg_label": "orch/v2/push-msg",
                         "aad": b"aad".hex(), "salt": s_salt.hex(), "plaintext": b"hello".hex(),
                         "k_msg": R.hkdf(kb1, s_salt, b"orch/v2/push-msg").hex(), "sealed": blob.hex()}]

    # --- sealing to a device / a WXK (§5.3) ---------------------------------------------------------
    seals = []
    eph = fake(f"suite{S.id}/eph wk grant")
    sealed = R.seal_to(S, pub["phone.kx"], dev["phone"], "wk", ws_a, 1, wk1, eph)
    eph_pub = S.kx_pub(S.kx_key(eph))
    ss = S.kx(S.kx_key(eph), pub["phone.kx"])
    seals.append({"name": "wk_to_phone", "purpose": "wk", "recipient_id": dev["phone"].hex(),
                  "recipient_kx_pub": pub["phone.kx"].hex(), "object_id": ws_a.hex(), "epoch": 1, "extra_aad": "",
                  "eph_seed": eph.hex(), "eph_pub": eph_pub.hex(), "shared_secret": ss.hex(),
                  "key": R.seal_key(S, ss, eph_pub, pub["phone.kx"], "wk", dev["phone"]).hex(),
                  "aad": R.seal_aad(S, "wk", ws_a, 1).hex(), "plaintext": wk1.hex(), "sealed": sealed.hex()})
    opens = []
    for name, kw in (("as_sealed", {}), ("other_purpose", {"purpose": "sk"}), ("other_recipient_id", {"rid": dev["laptop"]}),
                     ("other_object_id", {"obj": ws_b}), ("other_epoch", {"epoch": 2}),
                     ("other_recipient_key", {"priv": k.priv["laptop.kx"]}),
                     ("tampered", {"blob": sealed[:-1] + bytes([sealed[-1] ^ 1])})):
        try:
            pt = R.open_sealed(S, kw.get("priv", k.priv["phone.kx"]), kw.get("rid", dev["phone"]), kw.get("purpose", "wk"),
                               kw.get("obj", ws_a), kw.get("epoch", 1), kw.get("blob", sealed))
            res = pt.hex()
        except Exception:
            res = None
        opens.append({"name": name, "recipient": "laptop" if "priv" in kw else "phone",
                      "recipient_id": kw.get("rid", dev["phone"]).hex(), "purpose": kw.get("purpose", "wk"),
                      "object_id": kw.get("obj", ws_a).hex(), "epoch": kw.get("epoch", 1),
                      "sealed": kw.get("blob", sealed).hex(), "plaintext": res})
    o["seal"] = seals
    o["seal_open"] = opens

    # --- device certificates, revocations (§6) -----------------------------------------------------
    def label_sealed(d, text):
        return b64u(R.salted_seal(R.k_label(pvk, pid), R.L["kdf_label_msg"], R.L["aad_label"] + bytes([S.id]) + d,
                                  text.encode(), fake("label salt " + text)[:16]))

    def cert(name, scopes=("look", "decide", "operate", "type"), expires=None, created=NOW - 86_400_000,
             signer=pk, person=pid, label=None, **over):
        c = {"v": 2, "suite": S.id, "kind": "device_cert", "device_id": dev[name].hex(), "person_id": person.hex(),
             "dk_sig_pub": b64u(pub[name + ".sig"]), "dk_kx_pub": b64u(pub[name + ".kx"]),
             "label_sealed": label_sealed(dev[name], label or name), "created_ms": created, "expires_ms": expires,
             "scopes_max": list(scopes)}
        c.update(over)
        return R.sign_object(S, signer, c)

    certs = {"primary": cert("primary"), "phone": cert("phone"), "laptop": cert("laptop"),
             "agent": cert("agent", scopes=[f"drop:{space.hex()}"], expires=NOW + 7 * 86_400_000),
             "bob_phone": cert("bob_phone", signer=pk_bob, person=pid_bob)}
    o["label_sealed"] = {"pvk": pvk.hex(), "label_key": R.k_label(pvk, pid).hex(), "device_id": dev["phone"].hex(),
                         "label": "phone", "salt": fake("label salt phone")[:16].hex(),
                         "aad": (R.L["aad_label"] + bytes([S.id]) + dev["phone"]).hex(),
                         "sealed": certs["phone"]["o"]["label_sealed"]}
    cert_cases = []

    def cc(name, signed, pkp=pub["person_alice.sig"], now=NOW, revoked=()):
        cert_cases.append({"name": name, "signed": signed, "signed_bytes": (R.L["sig_device_cert"] + cj(signed["o"])).hex()
                           if isinstance(signed, dict) and isinstance(signed.get("o"), dict) else None,
                           "pk_pub": pkp.hex(), "now_ms": now, "revoked": list(revoked),
                           "expect": R.verify_cert(S, signed, pkp, now, set(revoked))})

    cc("valid", certs["phone"])
    cc("valid_scoped_agent", certs["agent"])
    cc("signed_by_another_person", certs["bob_phone"])
    cc("other_persons_cert_under_its_own_key", certs["bob_phone"], pkp=pub["person_bob.sig"])
    cc("revoked", certs["phone"], revoked=[dev["phone"].hex()])
    cc("expired", cert("phone", expires=NOW - 1))
    cc("expires_exactly_now", cert("phone", expires=NOW))
    cc("created_in_the_future", cert("phone", created=NOW + R.SKEW_MS + 1))
    cc("device_id_not_of_key", cert("phone", device_id=dev["laptop"].hex()))
    cc("person_id_not_of_key", cert("phone", person_id=pid_bob.hex()))
    cc("scopes_not_a_prefix", cert("phone", scopes=["look", "operate"]))
    cc("scoped_agent_without_expiry", cert("agent", scopes=[f"drop:{space.hex()}"]))
    cc("expires_null_ok", cert("laptop", expires=None))
    tampered = copy.deepcopy(certs["phone"])
    tampered["o"]["scopes_max"] = ["look"]
    cc("tampered_after_signing", tampered)
    extra = copy.deepcopy(certs["phone"])
    extra["extra"] = 1
    cc("extra_top_level_field", extra)
    cc("signed_under_the_revocation_label", {"o": certs["phone"]["o"], "sig": b64u(
        S.sign(pk, R.L["sig_revocation"] + cj(certs["phone"]["o"])))})
    o["certs"] = {"signed": certs, "cases": cert_cases}

    rev = R.sign_object(S, pk, {"v": 2, "suite": S.id, "kind": "revocation", "person_id": pid.hex(),
                                "device_id": dev["phone"].hex(), "revoked_ms": NOW, "reason": "lost"})
    rev_bob = R.sign_object(S, pk_bob, {"v": 2, "suite": S.id, "kind": "revocation", "person_id": pid_bob.hex(),
                                        "device_id": dev["phone"].hex(), "revoked_ms": NOW, "reason": "lost"})
    rev_bad = R.sign_object(S, pk, {"v": 2, "suite": S.id, "kind": "revocation", "person_id": pid.hex(),
                                    "device_id": dev["phone"].hex(), "revoked_ms": NOW, "reason": "bored"})
    o["revocations"] = [
        {"name": n, "signed": s_, "pk_pub": p_.hex(), "cert": certs["phone"]["o"],
         "expect": R.verify_revocation(S, s_, p_, certs["phone"]["o"])}
        for n, s_, p_ in (("valid", rev, pub["person_alice.sig"]),
                          ("by_another_person_for_alices_device", rev_bob, pub["person_bob.sig"]),
                          ("verified_with_the_wrong_person_key", rev, pub["person_bob.sig"]),
                          ("reason_not_in_the_list", rev_bad, pub["person_alice.sig"]))]

    # --- card (§7.1) ---------------------------------------------------------------------------------
    part = {"name": "Client A — billing", "description": "Invoices and reminders", "capabilities": ["tickets", "drop"],
            "hosted_by": None}
    card_o = {"v": 2, "suite": S.id, "kind": "card", "workspace_id": ws_a.hex(), "wsk_pub": b64u(pub["wsk_a.sig"]),
              "wxk_pub": b64u(pub["wxk_a_1.kx"]), "wxk_version": 1, "owner_person_id": pid.hex(),
              "relay_url": "https://relay.dev.severin.io", "card_seq": 1, "issued_ms": NOW}
    deleg = R.make_delegation(S, pk, ws_a, pub["wsk_a.sig"], pid, False, NOW - 86_400_000)
    ck2 = fake(f"suite{S.id}/card key 2")
    sp = R.card_sealed_part(S, ck, ws_a, 1, part)
    sp2 = R.card_sealed_part(S, ck2, ws_a, 2, part)
    card1 = R.make_card(S, wsk_a, deleg, card_o, sp, ck)
    c2o = {**card_o, "card_seq": 2, "wxk_pub": b64u(pub["wxk_a_2.kx"]), "wxk_version": 2}
    card2 = R.make_card(S, wsk_a, deleg, c2o, sp2, ck2)
    ck_wrap = R.seal_to(S, pub["phone.kx"], dev["phone"], "card", ws_a, 1, ck, fake(f"suite{S.id}/eph card"))
    st1 = {"o": card1["o"], "delegation": deleg["o"]}
    st2 = {"o": card2["o"], "delegation": deleg["o"]}
    card_cases = []

    def crd(name, card, stored=None, owner=pub["person_alice.sig"]):
        card_cases.append({"name": name, "card": card, "stored": stored, "owner_pk_pub": owner.hex(),
                           "expect": R.relay_accept_card(S, stored, card, owner)})

    crd("first_registration", card1)
    crd("wxk_rotation_seq_2_signed_by_wsk_alone", card2, stored=st1)
    crd("replayed_older_card", card1, stored=st2)
    crd("same_seq", card1, stored=st1)
    deleg_x = R.make_delegation(S, pk, ws_a, pub["wsk_intruder.sig"], pid, False, NOW)
    crd("wsk_changed", R.make_card(S, wsk_x, deleg_x, {**card_o, "card_seq": 2,
                                                      "wsk_pub": b64u(pub["wsk_intruder.sig"])}, sp, ck), stored=st1)
    crd("wxk_changed_without_version", R.make_card(S, wsk_a, deleg, {**card_o, "card_seq": 2,
                                                                      "wxk_pub": b64u(pub["wxk_a_2.kx"])}, sp, ck), stored=st1)
    crd("wxk_version_skips", R.make_card(S, wsk_a, deleg, {**c2o, "wxk_version": 3}, sp2, ck2), stored=st1)
    crd("delegation_changed", R.make_card(S, wsk_a, R.make_delegation(S, pk, ws_a, pub["wsk_a.sig"], pid, True, NOW),
                                          c2o, sp2, ck2), stored=st1)
    crd("delegation_signed_by_another_person", R.make_card(S, wsk_a, R.make_delegation(
        S, pk_bob, ws_a, pub["wsk_a.sig"], pid, False, NOW), card_o, sp, ck))
    crd("delegation_for_another_wsk", R.make_card(S, wsk_a, deleg_x, card_o, sp, ck))
    crd("card_signed_by_another_wsk", R.make_card(S, wsk_x, deleg, card_o, sp, ck))
    crd("owner_is_another_person", card1, owner=pub["person_bob.sig"])
    crd("sealed_part_swapped", dict(card1, sealed=b64u(R.card_sealed_part(S, ck, ws_a, 1, {**part, "name": "Else"}))))
    crd("relay_url_with_path", R.make_card(S, wsk_a, deleg, {**card_o, "relay_url": "https://relay.dev.severin.io/x"},
                                           sp, ck))
    crd("relay_url_loopback_http", R.make_card(S, wsk_a, deleg, {**card_o, "relay_url": "http://127.0.0.1:8787"}, sp, ck))
    crd("relay_url_plain_http", R.make_card(S, wsk_a, deleg, {**card_o, "relay_url": "http://relay.example.com"}, sp, ck))
    o["card"] = {"card_key": ck.hex(), "sealed_part_plaintext": part, "k_card": R.k_card(ck, ws_a, 1).hex(),
                 "aad": (R.L["aad_card"] + bytes([S.id]) + ws_a + u32(1)).hex(), "sealed_part": sp.hex(),
                 "ck_commit": b64u(R.ck_commit(ws_a, 1, ck)),
                 "signed_bytes_wsk": (R.L["sig_card_wsk"] + cj(card1["o"])).hex(),
                 "signed_bytes_delegation": (R.L["sig_ws_delegation"] + cj(deleg["o"])).hex(),
                 "card": card1, "card_seq_2": card2,
                 "card_key_wrap_to_phone": {"eph_seed": fake(f"suite{S.id}/eph card").hex(), "sealed": ck_wrap.hex()},
                 "cases": card_cases,
                 "hosted_marker": [
                     {"name": n_, "delegation": {"client_hosted": f_}, "sealed_part": {**part, "hosted_by": h_},
                      "expect": R.card_hosted_marker({"client_hosted": f_}, {**part, "hosted_by": h_})}
                     for n_, f_, h_ in (("own_machine", False, None), ("client_hosted_with_name", True, "Client AG"),
                                        ("client_hosted_but_name_sealed_null", True, None),
                                        ("name_without_the_flag", False, "Client AG"))]}

    # --- WK grants, member lists (§7.2, §7.3) -------------------------------------------------------
    grants = {(d, e): R.make_wk_grant(S, wsk_a, ws_a, dev[d], pub[d + ".kx"], e, {1: wk1, 2: wk2}[e],
                                      fake(f"suite{S.id}/eph grant {d} {e}"))
              for d in ("primary", "phone", "laptop") for e in (1, 2)}
    o["wk_grants"] = {"grant_phone_epoch_1": grants[("phone", 1)], "cases": [
        {"name": n, "signed": g, "wsk_pub": w.hex(), "device": d_, "expect": R.open_wk_grant(
            S, w, g, ws_a, dev[d_], k.priv[d_ + ".kx"])}
        for n, g, w, d_ in (("valid", grants[("phone", 1)], pub["wsk_a.sig"], "phone"),
                            ("signed_by_another_workspace", R.make_wk_grant(S, wsk_x, ws_a, dev["phone"], pub["phone.kx"], 1,
                                                                            wk1, fake("x")), pub["wsk_a.sig"], "phone"),
                            ("grant_for_another_device", grants[("laptop", 1)], pub["wsk_a.sig"], "phone"))]}

    def mlist(epoch, seq, members, signer=wsk_a, ws=ws_a):
        return R.sign_object(S, signer, {"v": 2, "suite": S.id, "kind": "member_list", "workspace_id": ws.hex(),
                                         "epoch": epoch, "list_seq": seq, "issued_ms": NOW,
                                         "members": sorted(({"device_id": dev[n].hex(), "scopes": sc}
                                                            for n, sc in members), key=lambda m: m["device_id"])})

    full = ["look", "decide", "operate", "type"]
    l1 = mlist(1, 1, [("primary", full), ("phone", ["look", "decide"])])
    dstate = {"owner_pk_pub": pub["person_alice.sig"], "certs": {dev[n].hex(): certs[n] for n in certs},
              "revoked": set(), "grants": {(dev[d].hex(), e) for d, e in grants}}
    ml_cases = []

    def ml(name, prev, signed, mutate=None, signer_pub=pub["wsk_a.sig"]):
        ds = copy.deepcopy(dstate)
        if mutate:
            mutate(ds)
        ml_cases.append({"name": name, "prev": prev, "signed": signed, "card_workspace_id": ws_a.hex(),
                         "directory": {"owner_pk_pub": ds["owner_pk_pub"].hex(), "certs": ds["certs"],
                                       "revoked": sorted(ds["revoked"]), "grants": sorted([d, e] for d, e in ds["grants"])},
                         "wsk_pub": signer_pub.hex(), "now_ms": NOW,
                         "expect": R.relay_accept_member_list(S, signer_pub, ws_a.hex(), prev, signed, ds, NOW)})

    ml("first_list", None, l1)
    ml("first_list_for_another_workspace", None, mlist(1, 1, [("primary", full)], ws=ws_b))
    ml("first_list_not_epoch_1", None, mlist(2, 1, [("primary", full)]))
    ml("add_device_same_epoch", l1["o"], mlist(1, 2, [("primary", full), ("phone", ["look", "decide"]), ("laptop", full)]))
    ml("remove_device_with_rotation", l1["o"], mlist(2, 2, [("primary", full)]))
    ml("remove_device_without_rotation", l1["o"], mlist(1, 2, [("primary", full)]))
    ml("epoch_skips", l1["o"], mlist(3, 2, [("primary", full)]))
    ml("list_seq_not_increasing", l1["o"], mlist(1, 1, [("primary", full), ("phone", ["look"])]))
    ml("revoked_member", l1["o"], mlist(2, 2, [("primary", full), ("phone", ["look"])]),
       lambda d: d["revoked"].add(dev["phone"].hex()))
    ml("other_persons_device", l1["o"], mlist(1, 2, [("primary", full), ("phone", ["look"]), ("bob_phone", ["look"])]))
    ml("scoped_agent_as_member", l1["o"], mlist(1, 2, [("primary", full), ("phone", ["look"]), ("agent", ["look"])]))
    ml("scopes_above_cert", l1["o"], mlist(1, 2, [("primary", full), ("phone", ["look", "operate"])]))
    ml("missing_grant_for_new_epoch", l1["o"], mlist(2, 2, [("primary", full)]),
       lambda d: d["grants"].discard((dev["primary"].hex(), 2)))
    ml("signed_by_another_workspace_key", l1["o"], mlist(1, 2, [("primary", full)], signer=wsk_x))
    o["member_lists"] = ml_cases

    # --- cert request to the primary, its challenge (§8.4) ----------------------------------------------
    inner = {"device_id": dev["phone"].hex(), "dk_sig_pub": b64u(pub["phone.sig"]), "dk_kx_pub": b64u(pub["phone.kx"]),
             "label": "Severin's iPhone", "scopes_max": full, "offer_id": offer.hex()}
    req_id = fake("cert request id")[:16]

    def creq_(inner_=inner, rid=req_id, signer=wsk_a, primary="primary", person=pid):
        return R.make_cert_request(S, signer, ws_a, person, dev[primary], pub[primary + ".kx"], rid, inner_, NOW,
                                   fake(f"suite{S.id}/eph cert request {rid.hex()}"))

    creq = creq_()
    hosted_card = {**card1, "delegation": R.make_delegation(S, pk, ws_a, pub["wsk_a.sig"], pid, True, NOW)}
    cr_cases = []

    def crc(name, steps, card=card1, me="primary", person=pid, prim=None):
        p_ = prim if prim is not None else {"seen": [], "open": {}}
        before = copy.deepcopy(p_)
        out_ = []
        for s_, t in steps:
            out_.append({"signed": s_, "now_ms": t, "expect": R.primary_open_cert_request(
                S, s_, card, person, dev[me], k.priv[me + ".kx"], p_, t)})
        cr_cases.append({"name": name, "card": card, "me": me, "person_id": person.hex(), "primary": before,
                         "steps": out_})

    crc("valid", [(creq, NOW + 1000)])
    crc("expired", [(creq, NOW + R.CERT_PENDING_MS)])
    crc("signed_by_another_workspace", [(creq_(signer=wsk_x), NOW)])
    crc("from_a_client_hosted_workspace_warns", [(creq, NOW + 1000)], card=hosted_card)
    crc("not_for_this_device", [(creq_(primary="laptop"), NOW)])
    crc("card_of_another_person", [(creq, NOW)], person=pid_bob)
    crc("drop_scope_refused", [(creq_(inner_={**inner, "scopes_max": [f"drop:{space.hex()}"]}), NOW)])
    crc("replayed_request_id", [(creq, NOW), (creq, NOW + 5)], prim={"seen": [], "open": {}})
    crc("second_open_request_for_the_workspace", [(creq, NOW), (creq_(rid=fake("cert request 2")[:16]), NOW + 5)])
    # "open" = unexpired, neither signed nor rejected: an expired or rejected request never blocks the workspace
    rid2 = fake("cert request 2")[:16]
    later = R.make_cert_request(S, wsk_a, ws_a, pid, dev["primary"], pub["primary.kx"], rid2, inner,
                                NOW + R.CERT_PENDING_MS, fake(f"suite{S.id}/eph cert request later"))
    open_cases = []

    def opc(name, ops):
        p_ = {"seen": [], "open": {}}
        before = copy.deepcopy(p_)
        steps = []
        for op in ops:
            if op[0] == "open":
                steps.append({"op": "open", "signed": op[1], "now_ms": op[2], "expect": R.primary_open_cert_request(
                    S, op[1], card1, pid, dev["primary"], k.priv["primary.kx"], p_, op[2])})
            elif op[0] == "challenge":
                R.primary_issue_challenge(S, pk, p_, op[1]["o"], inner, fake(f"suite{S.id}/primary nonce"))
                steps.append({"op": "challenge", "request_id": op[1]["o"]["request_id"],
                              "primary_nonce": fake(f"suite{S.id}/primary nonce").hex()})
            elif op[0] == "reject":
                R.primary_reject(p_, op[1])
                steps.append({"op": "reject", "request_id": op[1]})
            else:
                steps.append({"op": "sign", "request_id": op[1], "now_ms": op[2], "expect": R.primary_sign_cert(
                    S, pk, p_, op[1], certs["phone"]["o"]["label_sealed"], op[2], None, full)})
        open_cases.append({"name": name, "primary": before, "steps": steps})

    opc("next_request_after_the_first_expired", [("open", creq, NOW), ("open", later, NOW + R.CERT_PENDING_MS)])
    opc("next_request_after_the_first_was_rejected", [("open", creq, NOW), ("reject", req_id.hex()),
                                                       ("open", creq_(rid=rid2), NOW + 5)])
    opc("sign_after_reject_refused", [("open", creq, NOW), ("challenge", creq), ("reject", req_id.hex()),
                                      ("sign", req_id.hex(), NOW + 10)])
    opc("sign_after_expiry_refused", [("open", creq, NOW), ("challenge", creq),
                                      ("sign", req_id.hex(), NOW + R.CERT_PENDING_MS)])
    opc("sign_while_open_then_next_request", [("open", creq, NOW), ("challenge", creq),
                                              ("sign", req_id.hex(), NOW + 10), ("open", creq_(rid=rid2), NOW + 20)])
    crc("inner_with_a_host_nonce_is_malformed", [(creq_(inner_={**inner, "sas_nonce": b64u(fake("sas nonce"))}), NOW)])
    prim = {"seen": [], "open": {}}
    R.primary_open_cert_request(S, creq, card1, pid, dev["primary"], k.priv["primary.kx"], prim, NOW)
    p_nonce = fake(f"suite{S.id}/primary nonce")
    chal = R.primary_issue_challenge(S, pk, prim, creq["o"], inner, p_nonce)
    phone_cert = R.primary_sign_cert(S, pk, prim, req_id.hex(), certs["phone"]["o"]["label_sealed"], NOW,
                                     None, full)
    again = R.primary_sign_cert(S, pk, prim, req_id.hex(), certs["phone"]["o"]["label_sealed"], NOW, None, full)
    # R1: a host that sends the primary a request for ITS key gets a challenge for that key, which the phone refuses
    attack_inner = {**inner, "device_id": dev["intruder"].hex(), "dk_sig_pub": b64u(pub["intruder.sig"]),
                    "dk_kx_pub": b64u(pub["intruder.kx"])}
    attack_chal = R.make_cert_challenge(S, pk, creq["o"], attack_inner, p_nonce)
    o["cert_request"] = {"signed": creq, "inner": inner, "cases": cr_cases,
                         "challenge": chal, "primary_nonce": p_nonce.hex(), "cert_code": R.cert_sas(S, chal["o"]),
                         "signed_bytes_challenge": (R.L["sig_cert_challenge"] + cj(chal["o"])).hex(),
                         "signed_cert": phone_cert, "sign_again": again, "attack_challenge": attack_chal,
                         "open_cases": open_cases}
    challenges = {"valid": chal, "attack": attack_chal,
                  "signed_by_wsk": {"o": chal["o"], "sig": b64u(S.sign(wsk_a, R.L["sig_cert_challenge"] + cj(chal["o"])))},
                  "other_workspace": R.make_cert_challenge(S, pk, {**creq["o"], "workspace_id": ws_b.hex()}, inner, p_nonce),
                  "expired": R.make_cert_challenge(S, pk, {**creq["o"], "expires_ms": NOW - 1}, inner, p_nonce)}

    # enrolment of a scoped agent device (§6.4)
    code = fake("enrollment code")
    code_id = fake("code id")[:16]
    mac = R.enroll_mac(code, S, space, pub["agent.sig"], pub["agent.kx"])
    ereq = R.make_enroll_request(S, k.priv["agent.sig"], pid, space, code_id, pub["agent.sig"], pub["agent.kx"], mac)
    codes = {code_id.hex(): {"code": code.hex(), "space_id": space.hex(), "expires_ms": NOW + 3_600_000, "used": False}}
    en_cases = []

    def enc(name, steps, codes_=codes):
        cs = copy.deepcopy(codes_)
        before = copy.deepcopy(cs)
        en_cases.append({"name": name, "codes": before, "steps": [
            {"signed": s_, "now_ms": t, "expect": R.primary_check_enroll(S, s_, pid, cs, t)} for s_, t in steps]})

    enc("valid_then_reused", [(ereq, NOW), (ereq, NOW + 1)])
    enc("expired_code", [(ereq, NOW + 3_600_000)])
    enc("unknown_code", [(ereq, NOW)], codes_={})
    enc("mac_over_other_keys", [(R.make_enroll_request(S, k.priv["agent.sig"], pid, space, code_id, pub["agent.sig"],
                                                       pub["agent.kx"], R.enroll_mac(code, S, space, pub["intruder.sig"],
                                                                                     pub["agent.kx"])), NOW)])
    enc("signed_by_another_key", [({"o": ereq["o"], "sig": b64u(S.sign(k.priv["intruder.sig"],
                                                                       R.L["sig_enroll_request"] + cj(ereq["o"])))}, NOW)])
    enc("other_space", [(R.make_enroll_request(S, k.priv["agent.sig"], pid, fake("other space")[:16], code_id,
                                               pub["agent.sig"], pub["agent.kx"], mac), NOW)])
    o["enroll"] = {"code": code.hex(), "space_id": space.hex(), "dk_sig_pub": pub["agent.sig"].hex(),
                   "dk_kx_pub": pub["agent.kx"].hex(), "code_link": f"v2.{pid.hex()}.{space.hex()}.{code_id.hex()}.{b64u(code)}",
                   "mac": mac.hex(), "request": ereq, "cases": en_cases}

    # --- bridge v2 (§8) --------------------------------------------------------------------------------
    o["bridge"] = _bridge(S, k, certs, ws_a, wk1, wk2, dev, offer, secret, pid, grants, challenges)

    # --- WebAuthn challenges (§8.7) ---------------------------------------------------------------------
    subj = {"kind": "action", "shown": "Move L-0042 to done", "digest": ""}
    o["webauthn"] = {
        "assertion": {"workspace": ws_a.hex(), "device": dev["phone"].hex(), "rid": fake("rid a")[:16].hex(),
                      "epoch": 1, "purpose": "fresh", "scope": "operate", "expires_ms": NOW + 120_000,
                      "nonce": fake("assert nonce").hex(), "subject": subj,
                      "challenge": R.assertion_challenge(ws_a, dev["phone"], fake("rid a")[:16], 1, "fresh", "operate",
                                                         NOW + 120_000, fake("assert nonce"), subj).hex()},
        "registration": {"workspace": ws_a.hex(), "device": dev["phone"].hex(), "expires_ms": NOW + 120_000,
                         "nonce": fake("reg nonce").hex(),
                         "challenge": R.registration_challenge(ws_a, dev["phone"], NOW + 120_000, fake("reg nonce")).hex()},
    }

    # --- questions and decisions (§13) ------------------------------------------------------------------
    qc = {"question_id": fake("question")[:16].hex(), "ticket": "L-0042", "text": "Ship it?", "options": ["yes", "no"]}
    dec = {"decision_id": fake("decision")[:16].hex(), "question_id": qc["question_id"],
           "content_hash": b64u(R.question_hash(qc)), "answer": "yes"}
    dmeta = R.sign_decision(S, k.priv["phone.sig"], ws_a.hex(), dec)
    o["question_hash"] = {"content": qc, "content_hash": b64u(R.question_hash(qc))}
    o["decisions"] = {"signed_bytes": R.decision_signed_bytes(ws_a.hex(), dec).hex(), "cases": [
        {"name": n, "meta": m_, "workspace_id": w_, "dk_sig_pub": pub["phone.sig"].hex(),
         "expect": R.host_check_decision(S, m_, w_, pub["phone.sig"])}
        for n, m_, w_ in (("valid", dmeta, ws_a.hex()),
                          ("answer_changed_after_signing", {**dmeta, "answer": "no"}, ws_a.hex()),
                          ("replayed_into_another_workspace", dmeta, ws_b.hex()),
                          ("signed_by_another_device", R.sign_decision(S, k.priv["laptop.sig"], ws_a.hex(), dec), ws_a.hex()),
                          ("without_signature", {k_: v for k_, v in dmeta.items() if k_ != "sig"}, ws_a.hex()))]}

    # --- revocation pushed to a host over the bridge (§6.2) --------------------------------------------
    def hstate():
        return {"owner_pk_pub": b64u(pub["person_alice.sig"]), "owner_person_id": pid.hex(), "revoked": [],
                "members": {dev["primary"].hex(): full, dev["phone"].hex(): ["look", "decide", "operate"]}}

    rv_cases = []
    for n, m_ in (("member_revoked_rotates", {"op": "revocation", "record": rev}),
                  ("non_member_recorded_no_rotation", {"op": "revocation", "record": R.sign_object(
                      S, pk, {**rev["o"], "device_id": dev["laptop"].hex()})}),
                  ("signed_by_another_person", {"op": "revocation", "record": rev_bob}),
                  ("record_of_another_person_under_its_key", {"op": "revocation", "record": R.sign_object(
                      S, pk, {**rev["o"], "person_id": pid_bob.hex()})}),
                  ("extra_field", {"op": "revocation", "record": rev, "why": "x"})):
        s_ = hstate()
        before = copy.deepcopy(s_)
        r_ = R.host_revocation(S, s_, m_)
        rv_cases.append({"name": n, "state": before, "meta": m_, "expect": r_, "state_after": s_})
    o["revocation_op"] = rv_cases

    # --- push (§9) -------------------------------------------------------------------------------------
    payload = {"kind": "question", "id": "q-" + fake("question")[:8].hex(), "label": "Ship L-0042?", "ts_ms": NOW}
    p_salt = fake("push salt")[:16]
    raw = R.seal_push(S, wsk_a, wk1, ws_a, 1, payload, p_salt)
    keys = {ws_a.hex(): {"wsk_pub": b64u(pub["wsk_a.sig"]), "wk": {"1": wk1.hex()}}}
    pushes = []

    def pc(name, steps, keys_=keys):
        last = {}
        pushes.append({"name": name, "keys": keys_, "steps": [
            {"raw": r_.decode(), "now_ms": t, "expect": R.sw_open_push(S, r_, keys_, last, t)} for r_, t in steps]})

    pc("valid", [(raw, NOW)])
    pc("unknown_workspace", [(raw, NOW)], keys_={})
    pc("epoch_not_held", [(R.seal_push(S, wsk_a, wk2, ws_a, 2, payload, p_salt), NOW)])
    pc("older_than_24_h", [(raw, NOW + R.PUSH_MAX_AGE_MS + 1)])
    pc("exactly_24_h", [(raw, NOW + R.PUSH_MAX_AGE_MS)])
    pc("epoch_field_changed", [(raw.replace(b'"epoch":1', b'"epoch":2'), NOW)],
       keys_={ws_a.hex(): {"wsk_pub": b64u(pub["wsk_a.sig"]), "wk": {"1": wk1.hex(), "2": wk1.hex()}}})
    pc("unknown_kind", [(R.seal_push(S, wsk_a, wk1, ws_a, 1, {**payload, "kind": "exec"}, p_salt), NOW)])
    pc("extra_field", [(R.seal_push(S, wsk_a, wk1, ws_a, 1, {**payload, "url": "https://x"}, p_salt), NOW)])
    pc("forged_by_a_member_device", [(R.seal_push(S, k.priv["phone.sig"], wk1, ws_a, 1, payload, p_salt), NOW)])
    newer = R.seal_push(S, wsk_a, wk1, ws_a, 1, {**payload, "ts_ms": NOW + 10, "label": "Answered on phone",
                                                  "kind": "question.closed"}, fake("push salt 2")[:16])
    pc("replayed", [(raw, NOW), (raw, NOW + 5)])
    pc("older_after_newer_for_the_same_id", [(newer, NOW + 20), (raw, NOW + 30)])
    o["push"] = {"payload": payload, "salt": p_salt.hex(), "k_push": R.k_push(wk1, ws_a, 1).hex(),
                 "aad": R.push_aad(S, ws_a, 1).hex(),
                 "signed_bytes": R.push_signed_bytes(S, ws_a, 1, payload).hex(), "raw": raw.decode(), "cases": pushes}

    # --- Drop (§10) ------------------------------------------------------------------------------------
    o["drop"] = _drop(S, k, ws_a, ws_b, space, obj, dek, wk1, sk1, dev, certs)

    # --- ws→ws envelopes (§11) ---------------------------------------------------------------------------
    o["ws_envelopes"] = _ws(S, k, ws_a, ws_b, dev, certs, card1)

    # --- publish, relay auth (§12) -----------------------------------------------------------------------
    nonce = fake("publish nonce")[:16]
    body = b'{"app":"invoices","files":1}'
    hdrs = R.sign_publish(S, wsk_a, ws_a, NOW, nonce, "PUT", "pub.dev.severin.io", "/v1/apps/invoices?x=1", body)
    cards = {ws_a.hex(): card1["o"]}
    pub_cases = []

    def pbc(name, h_, now=NOW, method="PUT", host="pub.dev.severin.io", target="/v1/apps/invoices?x=1", b=body,
            nonces=None):
        n_ = nonces if nonces is not None else {}
        before = copy.deepcopy(n_)
        pub_cases.append({"name": name, "headers": h_, "method": method, "host": host, "target": target,
                          "body": b.hex(), "now_ms": now, "nonces": before,
                          "expect": R.publish_check(S, h_, method, host, target, b, cards, n_, now)})
        return n_

    st_ = pbc("valid", hdrs)
    pbc("replayed_nonce", hdrs, now=NOW + 1000, nonces=st_)
    pbc("replay_after_nonce_retention_is_stale", hdrs, now=NOW + R.NONCE_RETENTION_MS, nonces=copy.deepcopy(st_))
    pbc("ts_at_window_edge", hdrs, now=NOW + R.PUBLISH_WINDOW_MS)
    pbc("ts_past_window", hdrs, now=NOW + R.PUBLISH_WINDOW_MS + 1)
    pbc("other_path", hdrs, target="/v1/apps/other")
    pbc("other_body", hdrs, b=b'{"app":"invoices","files":2}')
    pbc("other_method", hdrs, method="DELETE")
    pbc("other_host", hdrs, host="pub.example.com")
    pbc("upper_case_nonce", {**hdrs, "Orch-Nonce": hdrs["Orch-Nonce"].upper()})
    pbc("ts_with_leading_zero", {**hdrs, "Orch-Ts": "0" + hdrs["Orch-Ts"]})
    pbc("unknown_workspace", {**hdrs, "Orch-Workspace": ws_b.hex()})
    o["publish"] = {"signed_bytes": R.publish_signed_bytes(S, ws_a, NOW, nonce, "PUT", "pub.dev.severin.io",
                                                           "/v1/apps/invoices?x=1", body).hex(),
                    "headers": hdrs, "cases": pub_cases}
    chal = fake("relay challenge")
    rab = R.relay_auth_signed_bytes(S, "https://relay.dev.severin.io", chal, "device", dev["phone"])
    o["relay_auth"] = {"origin": "https://relay.dev.severin.io", "challenge": chal.hex(), "kind": "device",
                       "id": dev["phone"].hex(), "signed_bytes": rab.hex(),
                       "sig": S.sign(k.priv["phone.sig"], rab).hex(), "cases": []}
    origin = "https://relay.dev.severin.io"

    def ra(name, steps, exp=NOW + R.RELAY_CHALLENGE_MS):
        st = {"challenges": {chal.hex(): exp}}
        before = copy.deepcopy(st)
        out_ = []
        for kind, sig_, _, t in steps:
            out_.append({"kind": kind, "id": dev["phone"].hex(), "sig": sig_.hex(), "pub": pub["phone.sig"].hex(),
                         "now_ms": t, "expect": R.relay_auth_check(S, st, origin, chal, kind, dev["phone"], sig_,
                                                                   pub["phone.sig"], t)})
        o["relay_auth"]["cases"].append({"name": name, "origin": origin, "challenge": chal.hex(), "state": before,
                                         "steps": out_})

    good = S.sign(k.priv["phone.sig"], rab)
    ra("valid_then_challenge_reused", [("device", good, "device", NOW), ("device", good, "device", NOW + 1)])
    ra("expired_challenge", [("device", good, "device", NOW + R.RELAY_CHALLENGE_MS)])
    ra("signed_for_another_origin", [("device", S.sign(k.priv["phone.sig"], R.relay_auth_signed_bytes(
        S, "https://evil.example", chal, "device", dev["phone"])), "device", NOW)])
    ra("signed_as_a_workspace_presented_as_a_device", [("device", S.sign(k.priv["phone.sig"], R.relay_auth_signed_bytes(
        S, origin, chal, "workspace", dev["phone"])), "workspace", NOW)])
    ra("signed_by_another_key", [("device", S.sign(k.priv["laptop.sig"], rab), "device", NOW)])
    ra("unknown_kind", [("agent", good, "device", NOW)])
    return o


def _bridge(S, k, certs, ws, wk1, wk2, dev, offer, secret, pid, grants, challenges):
    pub = k.pub
    wsk = k.priv["wsk_a.sig"]
    kb = {1: R.k_bridge(wk1, ws, 1), 2: R.k_bridge(wk2, ws, 2)}
    kp = R.k_pair(secret, ws, offer)
    out = {}

    def hdr(direction=R.TO_HOST, flags=0, device=dev["phone"], rid=None, stream=R.ZERO_ID, seq=1, ts=NOW, epoch=2,
            salt=None, **kw):
        return R.Header(direction, flags, kw.pop("suite", S.id), ws, device, rid or fake(f"rid-{seq}-{epoch}")[:16],
                        stream, seq, ts, epoch, salt or fake(f"salt-{direction}-{seq}-{ts}-{epoch}")[:16], **kw)

    h = hdr()
    pt = R.frame({"op": "http", "method": "GET", "path": "/api/status"})
    out["seal"] = [{"name": "request_body", "k_bridge": kb[2].hex(), "header": h.encode().hex(),
                    "header_fields": h.as_json(), "message_key": R.message_key(kb[2], h.salt).hex(),
                    "plaintext": pt.hex(), "sealed": R.seal_body(kb[2], h.encode(), pt).hex(),
                    "envelope": R.envelope(S, kb[2], k.priv["phone.sig"], h, pt).hex()}]

    def state():
        return {"suite": S.id, "workspace": ws.hex(), "epoch": 2, "wk": {"1": wk1.hex(), "2": wk2.hex()},
                "members": {dev["primary"].hex(): ["look", "decide", "operate", "type"],
                            dev["phone"].hex(): ["look", "decide", "operate"]},
                "certs": {dev[n].hex(): {"dk_sig_pub": certs[n]["o"]["dk_sig_pub"]} for n in ("primary", "phone", "laptop")},
                "revoked": [], "seq": {}, "rids": {}, "streams": {}, "unverified": [],
                "offers": {offer.hex(): {"secret": secret.hex(), "expires_ms": NOW + R.OFFER_TTL_MS,
                                         "sas_nonce": b64u(fake("sas nonce")), "used": False, "unverified": []}},
                "pending_pairs": {}, "wsk_pub": b64u(pub["wsk_a.sig"]),
                "owner_pk_pub": b64u(pub["person_alice.sig"]), "owner_person_id": pid.hex()}

    def req(signer="phone", meta=None, data=b"", raw_pt=None, key=None, **kw):
        hh = hdr(**kw)
        pt_ = raw_pt if raw_pt is not None else R.frame(meta or {"op": "http", "method": "GET", "path": "/"}, data)
        kk = key if key is not None else (kp if hh.epoch == 0 else kb.get(hh.epoch, kb[2]))
        return R.envelope(S, kk, k.priv[signer + ".sig"], hh, pt_)

    cases = []

    def case(name, env, mutate=None, now=NOW, mailbox_id=None):
        s = state()
        if mutate:
            mutate(s)
        before = _j(s)
        mb = mailbox_id or (R.Header.decode(env).rid.hex() if len(env) >= R.HEADER_LEN else "")
        res = R.host_check(env, s, now, mb)
        cases.append({"name": name, "envelope": env.hex(), "mailbox_id": mb, "state": before, "now_ms": now,
                      "expect": _strip(res)})
        return s

    def chain(name, steps, mutate=None):
        s = state()
        if mutate:
            mutate(s)
        before = _j(s)
        st = []
        for env, now in steps:
            mb = R.Header.decode(env).rid.hex()
            st.append({"envelope": env.hex(), "mailbox_id": mb, "now_ms": now,
                       "expect": _strip(R.host_check(env, s, now, mb))})
        cases.append({"name": name, "state": before, "steps": st})

    full = req(meta={"op": "http", "method": "POST", "path": "/api/tickets/L-1/move",
                     "headers": {"content-type": "application/json"}}, data=b'{"to":"testing"}', seq=7)
    case("full_request_accepted", full)
    chain("replayed_request", [(full, NOW), (full, NOW + 60_000)])
    case("previous_epoch_refused_stale_epoch", req(seq=3, epoch=1))
    chain("stale_epoch_consumes_its_seq_then_a_new_request_runs", [
        (req(seq=3, epoch=1), NOW), (req(seq=3, epoch=2), NOW + 10), (req(seq=4, epoch=2), NOW + 20)])
    case("future_epoch_dropped", req(seq=3, epoch=3, key=kb[2]))
    case("epoch_whose_key_the_host_deleted_dropped", req(seq=3, epoch=1), lambda s: s["wk"].pop("1"))
    case("sealed_under_another_epochs_key_dropped", req(seq=3, epoch=2, key=kb[1]))
    case("removed_device_not_member", req(signer="laptop", device=dev["laptop"], seq=1))
    case("revoked_device", req(seq=4), lambda s: s["revoked"].append(dev["phone"].hex()))
    case("signed_by_another_members_key", req(signer="primary", seq=4))
    case("other_suite_dropped", req(seq=4, suite=3 - S.id))
    case("old_magic_v1_dropped", req(seq=4, magic=b"SHRB"))
    case("version_1_dropped", req(seq=4, version=1))
    case("other_workspace_dropped", req(seq=4), lambda s: s.update(workspace=fake("workspace b")[:16].hex()))
    case("mailbox_id_differs_from_rid", req(seq=4), mailbox_id="00" * 16)
    case("old_timestamp", req(seq=4, ts=NOW - R.WINDOW_MS - 1))
    case("timestamp_at_window_edge", req(seq=4, ts=NOW - R.WINDOW_MS))
    case("sequence_zero", req(seq=0))
    chain("repeated_sequence", [(req(seq=5), NOW), (req(seq=5, rid=fake("other rid")[:16]), NOW + 1)])
    case("meta_with_a_duplicate_key", req(seq=5, raw_pt=_raw_meta('{"op":"http","op":"cancel"}')))
    case("meta_with_a_float", req(seq=5, raw_pt=_raw_meta('{"op":"http","n":1.5}')))
    case("meta_without_op", req(seq=5, raw_pt=_raw_meta('{"method":"GET"}')))
    case("stream_of_another_device", req(seq=5, stream=fake("their stream")[:16]),
         lambda s: s["streams"].update({fake("their stream")[:16].hex(): dev["primary"].hex()}))
    case("refusal_budget_spent_drops_unverified", req(signer="laptop", device=dev["laptop"], seq=1),
         lambda s: s.update(unverified=[NOW - i for i in range(R.BUDGET)]))
    case("quota_busy", req(seq=6), lambda s: s.update(limits={"per_device": 1}, rids={
        "aa" * 16: {"device": dev["phone"].hex(), "digest": "00" * 32, "outcome": None, "until": NOW + 1}}))
    # pairing at epoch 0 (§8.3)
    meta_pair = {"op": "pair", "dk_sig_pub": b64u(pub["phone.sig"]), "dk_kx_pub": b64u(pub["phone.kx"]),
                 "label": "Severin's iPhone", "cert": None}

    def preq(signer="phone", meta=None, key=None, device=None, **kw):
        return req(signer=signer, meta=meta or meta_pair, key=key or kp, device=device or dev[signer], epoch=0,
                   stream=offer, seq=kw.pop("seq", 1), **kw)

    case("pair_first_time", preq())
    chain("pair_resend_then_other_key", [(preq(), NOW), (preq(rid=fake("resend")[:16]), NOW + 5),
                                         (preq(signer="intruder", meta={**meta_pair, "dk_sig_pub": b64u(pub["intruder.sig"]),
                                                                        "dk_kx_pub": b64u(pub["intruder.kx"])}), NOW + 9)])
    case("pair_unknown_offer_dropped", preq(), lambda s: s.update(offers={}))
    case("pair_sealed_under_another_secret_dropped", preq(key=R.k_pair(fake("other secret"), ws, offer)))
    case("pair_expired_offer", preq(), now=NOW + R.OFFER_TTL_MS)
    case("pair_device_id_not_of_key", preq(device=dev["laptop"]))
    case("pair_signed_by_another_key", preq(signer="intruder", device=dev["phone"]))
    case("pair_stale_timestamp", preq(ts=NOW - R.WINDOW_MS - 1))
    case("pair_with_a_label_full_of_controls", preq(meta={**meta_pair, "label": "a‮b​c\x07" + "x" * 90}))
    case("pair_with_existing_cert", preq(signer="laptop", meta={**meta_pair, "dk_sig_pub": b64u(pub["laptop.sig"]),
                                                                 "dk_kx_pub": b64u(pub["laptop.kx"]), "cert": certs["laptop"]}))
    case("pair_with_another_persons_cert", preq(signer="bob_phone", meta={
        **meta_pair, "dk_sig_pub": b64u(pub["bob_phone.sig"]), "dk_kx_pub": b64u(pub["bob_phone.kx"]),
        "cert": certs["bob_phone"]}))
    case("pair_with_a_cert_for_another_key", preq(meta={**meta_pair, "cert": certs["laptop"]}))
    case("pair_with_a_revoked_cert", preq(signer="laptop", meta={**meta_pair, "dk_sig_pub": b64u(pub["laptop.sig"]),
                                                                  "dk_kx_pub": b64u(pub["laptop.kx"]), "cert": certs["laptop"]}),
         lambda s: s["revoked"].append(dev["laptop"].hex()))
    case("pair_meta_with_extra_field", preq(meta={**meta_pair, "mac": "00"}))
    case("pair_other_op_at_epoch_0", preq(meta={"op": "http", "method": "GET", "path": "/"}))

    def held(state_):
        return lambda s: s["pending_pairs"].update({dev["phone"].hex(): {
            "offer_id": offer.hex(), "dk_sig_pub": b64u(pub["phone.sig"]), "dk_kx_pub": b64u(pub["phone.kx"]),
            "label": "Severin's iPhone", "sas_nonce": b64u(fake("sas nonce")), "cert": None, "cert_state": "needed",
            **state_}}) or s["offers"][offer.hex()].update(used=True)

    status = {"op": "pair_status"}
    case("pair_status_pending", preq(meta=status, seq=2), held({"state": "pending"}))
    case("pair_status_cert_pending", preq(meta=status, seq=2),
         held({"state": "cert_pending", "cert_pending_since": NOW - 1000, "primary_label": "MacBook Pro",
               "challenge": None}))
    case("pair_status_cert_pending_with_the_primarys_challenge", preq(meta=status, seq=2),
         held({"state": "cert_pending", "cert_pending_since": NOW - 1000, "primary_label": "MacBook Pro",
               "challenge": challenges["valid"]}))
    case("pair_status_cert_pending_expired", preq(meta=status, seq=2),
         held({"state": "cert_pending", "cert_pending_since": NOW - R.CERT_PENDING_MS, "primary_label": "MacBook Pro"}))
    case("pair_status_approved", preq(meta=status, seq=2),
         held({"state": "approved", "scopes": ["look", "decide", "operate"], "cert": certs["phone"]}))
    case("pair_status_rejected", preq(meta=status, seq=2), held({"state": "rejected"}))
    case("pair_status_without_pairing", preq(meta=status, seq=2))
    out["host_cases"] = cases

    # the device side (§8.8)
    def resp(meta, data=b"", flags=R.F_LAST, seq=0, epoch=2, ts=NOW, signer=None, key=None, rid=None, **kw):
        hh = hdr(direction=R.TO_DEVICE, flags=flags, seq=seq, epoch=epoch, ts=ts, rid=rid or fake("rid a")[:16], **kw)
        return R.envelope(S, key or kb[epoch], signer or wsk, hh, R.frame(meta, data))

    def dctx(**over):
        c = {"suite": S.id, "workspace": ws.hex(), "device": dev["phone"].hex(), "wsk_pub": b64u(pub["wsk_a.sig"]),
             "wk": {"1": wk1.hex(), "2": wk2.hex()}, "offset_ms": 0,
             "pending": {fake("rid a")[:16].hex(): {"next": 0, "stream": False, "epoch": 2}}}
        c.update(over)
        return c

    dcases = []

    def dc(name, env, c=None, now=NOW, mailbox=None):
        c = c or dctx()
        before = _j(c)
        hh = R.Header.decode(env)
        mb = mailbox or {"id": hh.rid.hex(), "idx": hh.seq, "last": bool(hh.flags & R.F_LAST),
                         "stream": bool(hh.flags & R.F_STREAM)}
        dcases.append({"name": name, "envelope": env.hex(), "ctx": before, "mailbox": mb, "now_ms": now,
                       "expect": _strip(R.device_check(env, c, mb, now))})

    dc("response_accepted", resp({"status": 200, "headers": {}}, b"ok"))
    dc("response_in_another_epoch_than_the_request", resp({"status": 200, "headers": {}}, epoch=1))
    dc("stale_epoch_refusal", resp({"refusal": "stale_epoch", "epoch": 3}, flags=R.F_LAST | R.F_REFUSAL))
    dc("stale_epoch_refusal_not_higher_than_the_request", resp({"refusal": "stale_epoch", "epoch": 2},
                                                              flags=R.F_LAST | R.F_REFUSAL))
    dc("signed_by_a_member_device_not_the_host", resp({"status": 200, "headers": {}}, signer=k.priv["primary.sig"]))
    dc("signed_by_another_workspace", resp({"status": 200, "headers": {}}, signer=k.priv["wsk_intruder.sig"]))
    dc("tag_under_another_key", resp({"status": 200, "headers": {}}, key=kb[1]))
    dc("other_suite", resp({"status": 200, "headers": {}}, suite=3 - S.id))
    dc("unknown_request", resp({"status": 200, "headers": {}}, rid=fake("rid z")[:16]))
    dc("old_timestamp", resp({"status": 200, "headers": {}}, ts=NOW - R.WINDOW_MS - 1))
    dc("stale_timestamp_refusal_adopts_the_offset", resp({"refusal": "stale_timestamp", "host_ms": NOW + 3_600_000},
                                                         flags=R.F_LAST | R.F_REFUSAL, ts=NOW + 3_600_000))
    out["device_cases"] = dcases

    # every answer to an epoch-0 request (§8.3 step 4)
    def pans(meta, flags=R.F_LAST, signer=None, key=None, ts=NOW, rid=None):
        hh = hdr(direction=R.TO_DEVICE, flags=flags, seq=0, epoch=0, ts=ts, rid=rid or fake("pair rid")[:16],
                 stream=offer)
        return R.envelope(S, key or kp, signer or wsk, hh, R.frame(meta))

    pctx = {"suite": S.id, "workspace": ws.hex(), "device": dev["phone"].hex(), "offer": offer.hex(),
            "secret": secret.hex(), "wsk_pin": R.wsk_pin(S, pub["wsk_a.sig"]).hex(),
            "pk_pin": R.pk_pin(S, pub["person_alice.sig"]).hex(), "dk_sig_pub": b64u(pub["phone.sig"]),
            "dk_kx_pub": b64u(pub["phone.kx"]), "offset_ms": 0, "pending": {fake("pair rid")[:16].hex(): {"next": 0}}}
    pending = {"state": "pending", "wsk_pub": b64u(pub["wsk_a.sig"]), "sas_nonce": b64u(fake("sas nonce")),
               "dk_sig_pub": b64u(pub["phone.sig"]), "dk_kx_pub": b64u(pub["phone.kx"])}
    acases = []

    def ac(name, env, now=NOW):
        c = copy.deepcopy(pctx)
        acases.append({"name": name, "envelope": env.hex(), "ctx": copy.deepcopy(pctx), "now_ms": now,
                       "expect": _strip(R.open_pair_answer(env, c, now))})

    ac("pending_accepted_shows_the_code", pans(pending))
    ac("pending_for_another_key", pans({**pending, "dk_sig_pub": b64u(pub["intruder.sig"])}))
    ac("pending_with_a_host_key_not_of_the_pin", pans({**pending, "wsk_pub": b64u(pub["wsk_intruder.sig"])},
                                                      signer=k.priv["wsk_intruder.sig"]))
    ac("pending_signed_by_another_key", pans(pending, signer=k.priv["wsk_intruder.sig"]))
    ac("pending_sealed_under_another_secret", pans(pending, key=R.k_pair(fake("other secret"), ws, offer)))
    ac("approved_with_cert", pans({"state": "approved", "scopes": ["look", "decide", "operate"], "cert": certs["phone"],
                                   "pk_pub": b64u(pub["person_alice.sig"]), "epoch": 2, "wsk_pub": b64u(pub["wsk_a.sig"])}))
    ac("approved_with_a_cert_of_another_person", pans({"state": "approved", "scopes": ["look"], "cert": certs["bob_phone"],
                                                       "pk_pub": b64u(pub["person_bob.sig"]), "epoch": 2,
                                                       "wsk_pub": b64u(pub["wsk_a.sig"])}))
    ac("approved_with_a_cert_for_another_device", pans({"state": "approved", "scopes": ["look"], "cert": certs["laptop"],
                                                        "pk_pub": b64u(pub["person_alice.sig"]), "epoch": 2,
                                                        "wsk_pub": b64u(pub["wsk_a.sig"])}))
    cp = {"state": "cert_pending", "primary_label": "MacBook Pro", "pk_pub": b64u(pub["person_alice.sig"]),
          "challenge": None, "wsk_pub": b64u(pub["wsk_a.sig"])}
    ac("cert_pending_waiting_for_the_primary", pans(cp))
    ac("cert_pending_with_the_primarys_challenge_shows_its_code", pans({**cp, "challenge": challenges["valid"]}))
    ac("r1_attack_challenge_for_another_key_raises_the_alarm", pans({**cp, "challenge": challenges["attack"]}))
    ac("challenge_signed_by_the_host_not_pk", pans({**cp, "challenge": challenges["signed_by_wsk"]}))
    ac("challenge_for_another_workspace", pans({**cp, "challenge": challenges["other_workspace"]}))
    ac("challenge_expired", pans({**cp, "challenge": challenges["expired"]}))
    ac("cert_pending_with_a_pk_not_of_the_pin", pans({**cp, "pk_pub": b64u(pub["person_bob.sig"]),
                                                      "challenge": challenges["valid"]}))
    ac("rejected", pans({"state": "rejected", "wsk_pub": b64u(pub["wsk_a.sig"])}))
    ac("refusal_other_person", pans({"refusal": "other_person", "wsk_pub": b64u(pub["wsk_a.sig"])},
                                    flags=R.F_LAST | R.F_REFUSAL))
    ac("refusal_outside_the_window", pans({"refusal": "pairing_closed", "wsk_pub": b64u(pub["wsk_a.sig"])},
                                          flags=R.F_LAST | R.F_REFUSAL, ts=NOW - R.WINDOW_MS - 1))
    ac("refusal_stale_timestamp_adopts_offset", pans({"refusal": "stale_timestamp", "host_ms": NOW - 7_200_000,
                                                      "wsk_pub": b64u(pub["wsk_a.sig"])}, flags=R.F_LAST | R.F_REFUSAL,
                                                     ts=NOW - 7_200_000))
    ac("refusal_stale_timestamp_from_a_key_not_of_the_pin", pans(
        {"refusal": "stale_timestamp", "host_ms": NOW - 7_200_000, "wsk_pub": b64u(pub["wsk_intruder.sig"])},
        flags=R.F_LAST | R.F_REFUSAL, signer=k.priv["wsk_intruder.sig"], ts=NOW - 7_200_000))
    out["pair_answers"] = acases

    links = []
    good = f"v2.{ws.hex()}.{offer.hex()}.{b64u(secret)}.{b64u(R.wsk_pin(S, pub['wsk_a.sig']))}." \
           f"{b64u(R.pk_pin(S, pub['person_alice.sig']))}"
    for name, frag in (("valid", good), ("with_hash", "#" + good), ("version_1", "v1" + good[2:]),
                       ("upper_case_workspace", good.replace(ws.hex(), ws.hex().upper())),
                       ("without_pk_pin", good.rsplit(".", 1)[0]),
                       ("non_canonical_secret", good.replace(b64u(secret), b64u(secret)[:-1] + _bump(b64u(secret)[-1])))):
        links.append({"name": name, "fragment": frag, "parsed": R.parse_pair_fragment(frag)})
    out["links"] = links
    out["sas"] = {"workspace": ws.hex(), "offer": offer.hex(), "dk_sig_pub": pub["phone.sig"].hex(),
                  "dk_kx_pub": pub["phone.kx"].hex(), "wsk_pub": pub["wsk_a.sig"].hex(),
                  "sas_nonce": fake("sas nonce").hex(),
                  "code": R.sas(S, ws, offer, pub["phone.sig"], pub["phone.kx"], pub["wsk_a.sig"], fake("sas nonce"))}
    return out


def _bump(c):
    """A b64u character whose low bits differ: decodes to the same bytes only in a lenient decoder."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    return alphabet[alphabet.index(c) ^ 1]


def _raw_meta(text):
    b = text.encode()
    return len(b).to_bytes(4, "big") + b


EXPECT_KEYS = ("result", "code", "why", "scopes", "meta", "data", "outcome", "high", "host_ms", "epoch", "status",
               "answer", "label", "sas", "cert_state", "wsk_pub", "stream", "last", "refusal", "offset_ms",
               "clock_wrong", "pin_failure", "fetch_grants", "state", "scopes", "primary_label", "device_id",
               "alarm", "cert_code")


def _strip(r):
    return {k_: v for k_, v in r.items() if k_ in EXPECT_KEYS}


def _drop(S, k, ws_a, ws_b, space, obj, dek, wk1, sk1, dev, certs):
    pub = k.pub
    prefix = fake("drop nonce prefix")[:8]
    content = bytes(range(256)) * 5                                  # 1280 bytes, chunk size 512 → 3 chunks
    blob = R.drop_encrypt(S, dek, obj, 1, content, prefix, chunk=512)
    empty = R.drop_encrypt(S, dek, obj, 1, b"", prefix, chunk=512)
    meta = {"name": "invoice.pdf", "mime": "application/pdf", "size": len(content), "transcript": None}
    msealed = R.drop_meta_seal(S, dek, obj, 1, meta)
    wraps = {
        "wk": R.wrap_dek(S, "wk", ws_a, 1, obj, 1, dek, wk=wk1, salt=fake("wrap salt")[:16]),
        "sk": R.wrap_dek(S, "sk", space, 1, obj, 1, dek, sk=sk1, salt=fake("wrap salt sk")[:16]),
        "wxk_b": R.wrap_dek(S, "wxk", ws_b, 1, obj, 1, dek, kx_pub=pub["wxk_b_1.kx"], eph_seed=fake("eph wrap b")),
        "wxk_a": R.wrap_dek(S, "wxk", ws_a, 1, obj, 1, dek, kx_pub=pub["wxk_a_1.kx"], eph_seed=fake("eph wrap a")),
        "device": R.wrap_dek(S, "device", dev["phone"], 0, obj, 1, dek, kx_pub=pub["phone.kx"], eph_seed=fake("eph wrap d")),
    }
    unwrapped = {
        "wk": R.unwrap_dek(S, wraps["wk"], wk=wk1).hex(),
        "sk": R.unwrap_dek(S, wraps["sk"], sk=sk1).hex(),
        "wxk_b": R.unwrap_dek(S, wraps["wxk_b"], kx_priv=k.priv["wxk_b_1.kx"]).hex(),
        "device": R.unwrap_dek(S, wraps["device"], kx_priv=k.priv["phone.kx"]).hex(),
    }
    assert all(v == dek.hex() for v in unwrapped.values())
    neg = []
    for name, rec, kw in (("wk_wrap_moved_to_another_object", {**wraps["wk"], "object_id": fake("other obj")[:16].hex()},
                           {"wk": wk1}),
                          ("wxk_wrap_relabelled_as_device", {**wraps["wxk_b"], "target_kind": "device"},
                           {"kx_priv": k.priv["wxk_b_1.kx"]}),
                          ("wk_wrap_other_version", {**wraps["wk"], "version": 2}, {"wk": wk1})):
        try:
            R.unwrap_dek(S, rec, **kw)
            ok = True
        except Exception:
            ok = False
        neg.append({"name": name, "record": rec, "opens": ok})

    def desc(signer, author_kind, author_id, **over):
        d = {"v": 2, "suite": S.id, "kind": "drop_object", "object_id": obj.hex(), "space_id": ws_a.hex(),
             "space_kind": "workspace", "object_kind": "file", "version": 1, "parent": 0, "author_kind": author_kind,
             "author_id": author_id, "content_hash": b64u(R.H(blob)), "content_len": len(blob),
             "dek_commit": b64u(R.dek_commit(obj, 1, dek)), "meta": b64u(msealed), "recipients": "inbox",
             "origin": "human", "created_ms": NOW, "expires_ms": NOW + 7 * 86_400_000, "parent_hash": None}
        d.update(over)
        return R.sign_object(S, signer, d)

    d_phone = desc(k.priv["phone.sig"], "device", dev["phone"].hex())
    dcases = [{"name": n, "signed": s_, "author_pub": p_.hex(), "expect": R.verify_drop_object(S, s_, p_)}
              for n, s_, p_ in (("valid_by_phone", d_phone, pub["phone.sig"]),
                                ("verified_with_another_key", d_phone, pub["laptop.sig"]),
                                ("file_with_version_2", desc(k.priv["phone.sig"], "device", dev["phone"].hex(),
                                                             version=2, parent=1), pub["phone.sig"]),
                                ("recipients_unsorted", desc(k.priv["phone.sig"], "device", dev["phone"].hex(),
                                                             recipients=sorted([ws_a.hex(), ws_b.hex()], reverse=True)),
                                 pub["phone.sig"]),
                                ("version_1_with_a_parent_hash", desc(k.priv["phone.sig"], "device", dev["phone"].hex(),
                                                                      parent_hash=b64u(bytes(32))), pub["phone.sig"]))]
    # claim-once
    claim_wrap = R.wrap_dek(S, "wk", ws_b, 1, obj, 1, dek, wk=fake(f"suite{S.id}/WK b epoch 1"),
                            salt=fake("claim wrap salt")[:16])

    def claim(signer, ws_hex, w=claim_wrap):
        return R.sign_object(S, signer, {"v": 2, "suite": S.id, "kind": "drop_claim", "object_id": obj.hex(),
                                         "workspace_id": ws_hex, "wrap": w})

    cards = {ws_a.hex(): {"wsk_pub": b64u(pub["wsk_a.sig"])}, ws_b.hex(): {"wsk_pub": b64u(pub["wsk_b.sig"])}}
    inbox = {"object_id": obj.hex(), "version": 1, "state": "inbox", "claimed_by": None,
             "wraps": [wraps["wxk_a"], wraps["wxk_b"]]}
    epochs = {ws_a.hex(): 1, ws_b.hex(): 1}
    ccases = []

    def clc(name, steps):
        s = copy.deepcopy(inbox)
        before = copy.deepcopy(s)
        st = []
        for signed in steps:
            st.append({"claim": signed, "expect": R.relay_claim(S, s, signed, cards, epochs)})
        ccases.append({"name": name, "object": before, "cards": cards, "epochs": epochs, "steps": st,
                       "after": copy.deepcopy(s)})

    claim_a_wrap = R.wrap_dek(S, "wk", ws_a, 1, obj, 1, dek, wk=wk1, salt=fake("claim wrap salt a")[:16])
    clc("b_claims_then_a_loses", [claim(k.priv["wsk_b.sig"], ws_b.hex()),
                                  claim(k.priv["wsk_a.sig"], ws_a.hex(), claim_a_wrap)])
    clc("claim_repeated_is_idempotent", [claim(k.priv["wsk_b.sig"], ws_b.hex()), claim(k.priv["wsk_b.sig"], ws_b.hex())])
    clc("claim_signed_by_another_workspace", [claim(k.priv["wsk_a.sig"], ws_b.hex())])
    clc("claim_with_a_wrap_for_another_workspace", [claim(k.priv["wsk_b.sig"], ws_b.hex(), claim_a_wrap)])
    clc("claim_with_a_wrap_for_another_version", [claim(k.priv["wsk_b.sig"], ws_b.hex(), {**claim_wrap, "version": 2})])
    clc("claim_with_a_wrap_under_another_epoch", [claim(k.priv["wsk_b.sig"], ws_b.hex(),
                                                        {**claim_wrap, "key_version": 2})])
    # documents: a chain of descriptors, each naming the hash of its parent (§10.6)
    def docv(ver, parent_o, author="phone", tag=""):
        return desc(k.priv[author + ".sig"], "device", dev[author].hex(), object_kind="document", version=ver,
                    parent=ver - 1, content_hash=b64u(R.H(f"doc v{ver}{tag}".encode())),
                    parent_hash=None if parent_o is None else b64u(R.drop_parent_hash(parent_o)))["o"]

    v1 = docv(1, None)
    v2 = docv(2, v1)
    v3 = docv(3, v2)
    v2x = docv(2, v1, author="laptop", tag="x")              # another writer's version 2
    v3x = docv(3, v2x, author="laptop", tag="x")
    v4 = docv(4, v3)
    v4x = docv(4, v3x, author="laptop", tag="x")
    docs = []
    for name, cur, head, im, new in (("put_on_current", 3, v3, "3", v4), ("stale_if_match", 4, v4, "3", v4),
                                     ("missing_if_match", 3, v3, None, v4),
                                     ("version_skips", 3, v3, "3", {**v4, "version": 5, "parent": 4}),
                                     ("if_match_with_leading_zero", 3, v3, "03", v4),
                                     ("fork_parent_hash_of_another_version_3", 3, v3, "3", v4x),
                                     ("first_version", 0, None, "0", v1)):
        d = {"current": cur, "head": head}
        before = copy.deepcopy(d)
        docs.append({"name": name, "doc": before, "if_match": im, "descriptor": new,
                     "expect": R.relay_put_version(d, im, new)})
    chains = [{"name": n, "versions": vs, "expect": R.verify_doc_chain(vs)}
              for n, vs in (("valid", [v1, v2, v3, v4]), ("fork_served_by_the_relay", [v1, v2, v3x]),
                            ("version_missing", [v1, v3]))]
    return {"dek": dek.hex(), "object_id": obj.hex(), "content": content.hex(), "chunk_size": 512,
            "nonce_prefix": prefix.hex(), "k_content": R.drop_content_key(dek, obj, 1).hex(), "blob": blob.hex(),
            "empty_blob": empty.hex(), "meta": meta, "meta_sealed": msealed.hex(),
            "dek_commit": b64u(R.dek_commit(obj, 1, dek)), "wraps": wraps, "wrap_negative": neg,
            "descriptor": d_phone, "descriptor_cases": dcases, "claims": ccases, "documents": docs,
            "document_chains": chains}


def _ws(S, k, ws_a, ws_b, dev, certs, card_a):
    """ws→ws envelopes (§11): A sends to B."""
    pub = k.pub
    env_id = fake("envelope 1")[:16]

    def body(**over):
        b = {"kind": "ticket", "in_reply_to": None, "depth": 0, "deadline_ms": NOW + 86_400_000,
             "ticket": {"title": "Reconcile March invoices", "body": "See attached.", "type": "task"}, "result": None,
             "refusal": None, "attachments": []}
        b.update(over)
        return b

    def env(b=None, flags=0, wxk_version=1, signer=None, eid=env_id, to_pub=None, cosig=None, from_ws=ws_a,
            to_ws=ws_b):
        hb = R.wx_header(S, flags, eid, from_ws, to_ws, wxk_version)
        return R.build_ws_envelope(S, signer or k.priv["wsk_a.sig"], hb, b or body(), to_pub or pub["wxk_b_1.kx"],
                                   fake(f"suite{S.id}/eph ws {eid.hex()} {flags}"), cosig)

    plain = env()
    hb = plain[:R.WX_HEADER_LEN]
    blen = int.from_bytes(plain[R.WX_HEADER_LEN:R.WX_HEADER_LEN + 4], "big")
    sealed_body = plain[R.WX_HEADER_LEN + 4:R.WX_HEADER_LEN + 4 + blen]
    # co-signed by the phone's device key
    hb_c = R.wx_header(S, R.F_COSIGNED, fake("envelope 2")[:16], ws_a, ws_b, 1)
    body_c = R.seal_to(S, pub["wxk_b_1.kx"], ws_b, "ws-envelope", fake("envelope 2")[:16], 1, R.cj(body()),
                       fake(f"suite{S.id}/eph ws {fake('envelope 2')[:16].hex()} 1"), extra_aad=hb_c)
    cos_dev = R.device_cosign(S, k.priv["phone.sig"], certs["phone"], hb_c, body_c)
    cosigned = env(flags=R.F_COSIGNED, eid=fake("envelope 2")[:16], cosig=cos_dev)
    # co-signed by a WebAuthn assertion (ES256 authenticator, whatever the suite)
    auth = ec.derive_private_key(int.from_bytes(fake("authenticator"), "big") % (R.P256_N - 1) + 1, ec.SECP256R1())
    from cryptography.hazmat.primitives import serialization as ser
    cred_pub = auth.public_key().public_bytes(ser.Encoding.X962, ser.PublicFormat.UncompressedPoint)
    cred_id = fake("credential id")[:16]
    eid3 = fake("envelope 3")[:16]
    hb_w = R.wx_header(S, R.F_COSIGNED, eid3, ws_a, ws_b, 1)
    body_w = R.seal_to(S, pub["wxk_b_1.kx"], ws_b, "ws-envelope", eid3, 1, R.cj(body()),
                       fake(f"suite{S.id}/eph ws {eid3.hex()} 1"), extra_aad=hb_w)
    eh = R.ws_envelope_hash(hb_w, body_w)
    origin = card_a["o"]["relay_url"]
    rp = origin.split("://")[1]
    cdj = json.dumps({"type": "webauthn.get", "challenge": b64u(eh), "origin": origin, "crossOrigin": False},
                     separators=(",", ":")).encode()
    def wa(rp_id=rp, origin_=origin, flags=0x05, challenge=eh, bind_pub=cred_pub):
        cdj_ = json.dumps({"type": "webauthn.get", "challenge": b64u(challenge), "origin": origin_,
                           "crossOrigin": False}, separators=(",", ":")).encode()
        ad_ = R.H(rp_id.encode()) + bytes([flags]) + (7).to_bytes(4, "big")
        sig_ = auth.sign(ad_ + R.H(cdj_), ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
        return {"type": "webauthn", "cert": certs["phone"], "credential_id": b64u(cred_id),
                "credential_pub": b64u(cred_pub),
                "bind_sig": b64u(S.sign(k.priv["phone.sig"], R.L["sig_webauthn_bind"] + R.lp16(cred_id) + bind_pub)),
                "rp_id": rp_id, "origin": origin_, "authenticator_data": b64u(ad_), "client_data_json": b64u(cdj_),
                "signature": b64u(sig_)}

    cos_wa = wa()
    assert cdj  # the documented client data of the valid case is wa()'s
    webauthn_env = env(flags=R.F_COSIGNED, eid=eid3, cosig=cos_wa)

    def rstate(**over):
        s = {"suite": S.id, "workspace": ws_b.hex(), "wxk_version": 1,
             "wxk": {"1": {"seed": k.seeds["wxk_b_1.kx"].hex(), "retired_ms": None}},
             "peers": {ws_a.hex(): {"wsk_pub": b64u(pub["wsk_a.sig"]), "owner_pk_pub": b64u(pub["person_alice.sig"]),
                                    "relay_url": origin, "revoked": []}},
             "seen": {}, "sent": {}}
        s.update(over)
        return s

    cases = []

    def rc(name, e, now=NOW, st=None):
        s = st or rstate()
        before = _j(s)
        cases.append({"name": name, "envelope": e.hex(), "state": before, "now_ms": now,
                      "expect": R.ws_receive(e, s, now)})
        return s

    def rchain(name, steps, st=None):
        s = st or rstate()
        before = _j(s)
        cases.append({"name": name, "state": before, "steps": [
            {"envelope": e.hex(), "now_ms": t, "expect": R.ws_receive(e, s, t)} for e, t in steps]})

    rc("ticket_accepted", plain)
    rchain("duplicate_returns_the_stored_outcome", [(plain, NOW), (plain, NOW + 5000)])
    rc("cosigned_by_device_key", cosigned)
    rc("cosigned_by_webauthn", webauthn_env)
    for n_, kw in (("webauthn_rp_id_of_another_site", {"rp_id": "evil.example"}),
                   ("webauthn_origin_of_another_site", {"origin_": "https://evil.example"}),
                   ("webauthn_user_not_verified", {"flags": 0x01}),
                   ("webauthn_challenge_of_another_envelope", {"challenge": R.H(b"another envelope")}),
                   ("webauthn_bind_sig_over_another_key", {"bind_pub": b"\x04" + bytes(64)})):
        rc(n_, env(flags=R.F_COSIGNED, eid=eid3, cosig=wa(**kw)))
    rc("cosigned_by_a_revoked_device", cosigned, st=rstate(peers={ws_a.hex(): {
        "wsk_pub": b64u(pub["wsk_a.sig"]), "owner_pk_pub": b64u(pub["person_alice.sig"]), "relay_url": origin,
        "revoked": [dev["phone"].hex()]}}))
    stripped = cosigned[:len(cosigned) - 4 - len(R.cj(cos_dev))]
    rc("cosigned_flag_but_cosignature_stripped", stripped)
    rc("cosignature_of_another_persons_device", env(flags=R.F_COSIGNED, eid=fake("envelope 2")[:16], cosig={
        **cos_dev, "cert": certs["bob_phone"]}))
    rc("not_pinned_dropped", plain, st=rstate(peers={}))
    rc("signed_by_another_workspace_dropped", env(signer=k.priv["wsk_intruder.sig"]))
    rc("for_another_workspace_dropped", env(to_ws=ws_a))
    rc("previous_wxk_inside_14_days", env(wxk_version=1), now=NOW, st=rstate(
        wxk_version=2, wxk={"1": {"seed": k.seeds["wxk_b_1.kx"].hex(), "retired_ms": NOW - R.WXK_OVERLAP_MS + 1},
                            "2": {"seed": k.seeds["wxk_a_2.kx"].hex(), "retired_ms": None}}))
    rc("previous_wxk_after_14_days", env(wxk_version=1), st=rstate(
        wxk_version=2, wxk={"1": {"seed": k.seeds["wxk_b_1.kx"].hex(), "retired_ms": NOW - R.WXK_OVERLAP_MS},
                            "2": {"seed": k.seeds["wxk_a_2.kx"].hex(), "retired_ms": None}}))
    rc("unknown_wxk_version", env(wxk_version=7))
    # §7.4: after stale_wxk the sender reseals under a NEW id; the old id with other bytes is a conflict
    eid_s = fake("envelope stale")[:16]
    rchain("reseal_after_stale_wxk_needs_a_new_id", [
        (env(wxk_version=7, eid=eid_s), NOW),
        (env(wxk_version=1, eid=eid_s), NOW + 5),
        (env(wxk_version=1, eid=fake("envelope resealed")[:16]), NOW + 10)])
    rc("depth_2_refused", env(body(depth=2), eid=fake("envelope d2")[:16]))
    rc("depth_1_accepted", env(body(depth=1), eid=fake("envelope d1")[:16]))
    rc("deadline_passed", env(body(deadline_ms=NOW - R.SKEW_MS - 1), eid=fake("envelope dl")[:16]))
    rc("deadline_too_far", env(body(deadline_ms=NOW + R.MAX_DEADLINE_MS + 1), eid=fake("envelope df")[:16]))
    ours = fake("our ticket")[:16].hex()

    def sent_():
        return {ours: {"to": ws_a.hex(), "consumed": []}}

    res_body = body(kind="result", in_reply_to=ours, ticket=None, result={"status": "done", "summary": "Reconciled."})
    rc("result_for_a_ticket_we_sent", env(res_body, eid=fake("envelope r")[:16]), st=rstate(sent=sent_()))
    rchain("second_result_for_the_same_ticket_refused", [
        (env(res_body, eid=fake("envelope r")[:16]), NOW),
        (env({**res_body, "result": {"status": "done", "summary": "Again."}}, eid=fake("envelope r3")[:16]), NOW + 5)],
        st=rstate(sent=sent_()))
    ref_ = R.build_ws_refusal(S, k.priv["wsk_a.sig"], ws_a, bytes.fromhex(ours), ws_b, pub["wxk_b_1.kx"], 1,
                              "depth_exceeded", fake("envelope rf")[:16], fake(f"suite{S.id}/eph refusal"), NOW)
    rc("refusal_for_a_ticket_we_sent", ref_, st=rstate(sent=sent_()))
    rchain("refusal_after_a_result_refused_silently", [(env(res_body, eid=fake("envelope r")[:16]), NOW),
                                                         (ref_, NOW + 5)], st=rstate(sent=sent_()))
    rc("refusal_for_a_ticket_we_never_sent_is_dropped_not_answered", ref_)
    rc("refusal_flag_on_a_result_body_is_dropped", env(res_body, flags=R.F_WS_REFUSAL, eid=fake("envelope rr")[:16]),
       st=rstate(sent=sent_()))
    rc("refusal_body_without_the_flag_is_malformed", env(body(kind="refusal", in_reply_to=ours, ticket=None,
                                                             refusal={"code": "depth_exceeded"}),
                                                        eid=fake("envelope rn")[:16]), st=rstate(sent=sent_()))
    # seen ids are per sender: the same id from another pinned workspace is a different envelope
    ws_c = fake("workspace c")[:16]
    from_c = env(signer=k.priv["wsk_intruder.sig"], from_ws=ws_c)
    rchain("same_id_from_two_senders", [(plain, NOW), (from_c, NOW + 1)], st=rstate(peers={
        ws_a.hex(): {"wsk_pub": b64u(pub["wsk_a.sig"]), "owner_pk_pub": b64u(pub["person_alice.sig"]),
                     "relay_url": origin, "revoked": []},
        ws_c.hex(): {"wsk_pub": b64u(pub["wsk_intruder.sig"]), "owner_pk_pub": b64u(pub["person_bob.sig"]),
                     "relay_url": origin, "revoked": []}}))
    rc("result_for_a_ticket_we_never_sent", env(body(kind="result", in_reply_to=fake("our ticket")[:16].hex(),
                                                     ticket=None, result={"status": "done", "summary": "x"}),
                                                eid=fake("envelope r2")[:16]))
    rc("body_with_extra_field", env({**body(), "exec": "rm -rf /"}, eid=fake("envelope x")[:16]))
    # the body was sealed for A's header, then re-signed by an intruder under its own from_ws (§11.2)
    hb_x = R.wx_header(S, 0, env_id, ws_b, ws_b, 1)
    relabelled = hb_x + plain[R.WX_HEADER_LEN:R.WX_HEADER_LEN + 4 + blen] + S.sign(
        k.priv["wsk_intruder.sig"], R.L["sig_ws_envelope"] + hb_x + sealed_body)
    rc("body_lifted_under_another_senders_header", relabelled, st=rstate(peers={
        ws_b.hex(): {"wsk_pub": b64u(pub["wsk_intruder.sig"]), "owner_pk_pub": b64u(pub["person_bob.sig"]),
                     "relay_url": origin, "revoked": []}}, workspace=ws_b.hex()))
    return {"header": hb.hex(), "header_fields": {"magic": "ORWX", "v": 2, "suite": S.id, "flags": 0, "reserved": 0,
                                                  "id": env_id.hex(), "from_ws": ws_a.hex(), "to_ws": ws_b.hex(),
                                                  "wxk_version": 1},
            "body_plaintext": body(), "sealed_body": sealed_body.hex(),
            "eph_seed": fake(f"suite{S.id}/eph ws {env_id.hex()} 0").hex(),
            "signed_bytes": (R.L["sig_ws_envelope"] + hb + sealed_body).hex(), "envelope": plain.hex(),
            "envelope_hash": R.ws_envelope_hash(hb, sealed_body).hex(),
            "cosign_device": cos_dev, "cosign_webauthn": cos_wa, "cases": cases}
