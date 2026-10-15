"""G3b (P3-D28) pairing-binding vector groups: cert_binding, rejected_forms, approved_anchor. TEST SUPPORT ONLY.

Every key is FAKE (SHA-256 of a public label). The groups are new and self-contained: they read the suite's
keys, ids and card from the already built vectors and add nothing to the older groups.
"""
import copy
import json

from ref import orch_protocol_ref as R
from ref._p3_vectors import replay
from ref._vectors import _strip  # the bridge groups' expect keys, so the same replay helpers apply

NOW = 1_790_000_000_000


def add_g3b(out):
    for sid, v in out["suites"].items():
        _suite(R.SUITES[int(sid)], v)


def _suite(S, v):  # noqa: C901 (a builder: long by nature)
    keys, ids = v["keys"], v["ids"]
    fake = R.fake
    sig = {n[:-4]: S.sig_key(bytes.fromhex(x["seed"])) for n, x in keys.items() if n.endswith(".sig")}
    pub = {n: bytes.fromhex(x["pub"]) for n, x in keys.items()}
    dev = {n[7:]: bytes.fromhex(x) for n, x in ids.items() if n.startswith("device_")}
    ws, pid = bytes.fromhex(ids["workspace_a"]), bytes.fromhex(ids["person_alice"])
    pk, wsk = sig["person_alice"], sig["wsk_a"]
    offer, secret = fake("offer id")[:16], fake(f"suite{S.id}/pairing secret")
    other_offer = fake("g3b other offer")[:16]
    attempt_a, attempt_b = fake("pairing attempt a")[:16].hex(), fake("g3b pairing attempt b")[:16].hex()
    # the phone's own earlier attempt (fresh keys per uncertified attempt): group-local FAKE keys
    old_seed_sig, old_seed_kx = fake(f"suite{S.id}/g3b phone earlier attempt/sig"), fake(f"suite{S.id}/g3b phone earlier attempt/kx")
    old_sig_pub, old_kx_pub = S.sig_pub(S.sig_key(old_seed_sig)), S.kx_pub(S.kx_key(old_seed_kx))
    old_dev = R.device_id(S, old_sig_pub)
    old_hash = R.b64u(R.dk_hash(S, old_sig_pub, old_kx_pub))

    def inner_for(sig_pub, kx_pub, attempt, offer_=offer):
        return {"device_id": R.device_id(S, sig_pub).hex(), "dk_sig_pub": R.b64u(sig_pub), "dk_kx_pub": R.b64u(kx_pub),
                "label": "Severin's iPhone", "scopes_max": ["look", "decide", "operate", "type"],
                "offer_id": offer_.hex(), "attempt": attempt}

    inner = inner_for(pub["phone.sig"], pub["phone.kx"], attempt_a)
    inner_old = inner_for(old_sig_pub, old_kx_pub, attempt_b)          # the earlier attempt on the same offer
    inner_intruder = inner_for(pub["intruder.sig"], pub["intruder.kx"], attempt_a)

    def creq(inner_, label, created=NOW):
        # the current request reuses the §8.4 request id, so relay adapters can address it at one route
        rid = fake("cert request id")[:16] if label == "current" else fake(f"g3b request {label}")[:16]
        return R.make_cert_request(S, wsk, ws, pid, dev["primary"], pub["primary.kx"], rid, inner_, created,
                                   fake(f"suite{S.id}/g3b eph {label}"))

    req = creq(inner, "current")
    req_old = creq(inner_old, "earlier", NOW - 300_000)
    req_intruder = creq(inner_intruder, "intruder")
    req_other_offer = creq({**inner, "offer_id": other_offer.hex()}, "other offer")
    req_other_attempt = creq({**inner, "attempt": attempt_b}, "other attempt")
    nonce = fake(f"suite{S.id}/g3b primary nonce")
    chal = R.make_cert_challenge(S, pk, req["o"], inner, nonce)
    rej = R.make_cert_rejection(S, pk, req["o"])

    # ------------------------------------------------------------------ relay: the queue binds both objects
    relay = []

    def rcase(name, op, state, args, want):
        c = {"name": name, "op": op, "state": copy.deepcopy(state), "args": copy.deepcopy(args)}
        c["expect"] = replay(S, c)
        result = c["expect"]["result"]
        actual = result.get("refuse", result.get("ok"))
        assert actual == want, (name, actual, want)
        relay.append(c)
        return copy.deepcopy(c["expect"]["state"])

    rq = {"signed": req, "wsk_pub": pub["wsk_a.sig"].hex(), "ws": ws.hex(), "owner": pid.hex(),
          "primary": dev["primary"].hex(), "now_ms": NOW}
    q = rcase("request_with_the_attempt_binding_admitted", "request", {}, rq, req["o"]["request_id"])
    for field in ("offer_id", "attempt", "device_id", "dk_hash"):
        stripped = {k_: x for k_, x in req["o"].items() if k_ != field}
        rcase(f"request_without_{field}_malformed", "request", {}, {**rq, "signed": R.sign_object(S, wsk, stripped)},
              "malformed")
    rcase("request_offer_id_not_hex_malformed", "request", {},
          {**rq, "signed": R.sign_object(S, wsk, {**req["o"], "offer_id": "XY" * 16})}, "malformed")
    rcase("request_dk_hash_not_32_bytes_malformed", "request", {},
          {**rq, "signed": R.sign_object(S, wsk, {**req["o"], "dk_hash": R.b64u(bytes(31))})}, "malformed")
    entry = q[req["o"]["request_id"]]
    qa = {"action": "challenge", "signed": chal, "pk_pub": pub["person_alice.sig"].hex(), "now_ms": NOW}
    challenged = rcase("challenge_bound_to_the_request_stored", "queue", entry, qa, "challenged")
    # an old challenge (earlier attempt, same offer) replayed into the new attempt's request
    old_chal = R.make_cert_challenge(S, pk, {**req_old["o"], "request_id": req["o"]["request_id"],
                                             "expires_ms": req["o"]["expires_ms"]}, inner_old, nonce)
    rcase("challenge_of_an_earlier_attempt_refused", "queue", entry, {**qa, "signed": old_chal}, "not_for_this_device")
    rcase("challenge_other_offer_refused", "queue", entry,
          {**qa, "signed": R.sign_object(S, pk, {**chal["o"], "offer_id": other_offer.hex()})}, "not_for_this_device")
    rcase("challenge_other_attempt_refused", "queue", entry,
          {**qa, "signed": R.sign_object(S, pk, {**chal["o"], "attempt": attempt_b})}, "not_for_this_device")
    rcase("challenge_for_another_device_refused", "queue", entry,
          {**qa, "signed": R.make_cert_challenge(S, pk, req["o"], inner_intruder, nonce)}, "not_for_this_device")
    rcase("challenge_same_device_other_kx_key_refused", "queue", entry,
          {**qa, "signed": R.sign_object(S, pk, {**chal["o"], "dk_kx_pub": R.b64u(pub["intruder.kx"])})},
          "not_for_this_device")
    rcase("challenge_without_offer_id_malformed", "queue", entry,
          {**qa, "signed": R.sign_object(S, pk, {k_: x for k_, x in chal["o"].items() if k_ != "offer_id"})}, "malformed")
    rcase("challenge_attempt_not_hex_malformed", "queue", entry,
          {**qa, "signed": R.sign_object(S, pk, {**chal["o"], "attempt": "XY" * 16})}, "malformed")
    ra = {**qa, "action": "rejection", "signed": rej}
    rcase("rejection_dk_hash_not_32_bytes_malformed", "queue", entry,
          {**ra, "signed": R.sign_object(S, pk, {**rej["o"], "dk_hash": R.b64u(bytes(31))})}, "malformed")
    rcase("rejection_attempt_not_hex_malformed", "queue", entry,
          {**ra, "signed": R.sign_object(S, pk, {**rej["o"], "attempt": "XY" * 16})}, "malformed")
    rcase("rejection_before_any_challenge_stored", "queue", entry, ra, "rejected")
    rcase("rejection_after_the_challenge_stored", "queue", challenged, ra, "rejected")
    # a reused offer: the earlier attempt's rejection, re-addressed to this request, is refused by attempt/device
    rcase("rejection_of_an_earlier_attempt_refused", "queue", entry,
          {**ra, "signed": R.make_cert_rejection(S, pk, {**req_old["o"], "request_id": req["o"]["request_id"],
                                                          "expires_ms": req["o"]["expires_ms"]})}, "not_for_this_device")
    rcase("rejection_other_attempt_refused", "queue", entry,
          {**ra, "signed": R.sign_object(S, pk, {**rej["o"], "attempt": attempt_b})}, "not_for_this_device")
    rcase("rejection_other_offer_refused", "queue", entry,
          {**ra, "signed": R.sign_object(S, pk, {**rej["o"], "offer_id": other_offer.hex()})}, "not_for_this_device")
    rcase("rejection_for_another_device_refused", "queue", entry,
          {**ra, "signed": R.sign_object(S, pk, {**rej["o"], "device_id": dev["intruder"].hex()})}, "not_for_this_device")
    rcase("rejection_other_dk_hash_refused", "queue", entry,
          {**ra, "signed": R.sign_object(S, pk, {**rej["o"], "dk_hash": req_intruder["o"]["dk_hash"]})},
          "not_for_this_device")
    rcase("rejection_other_expiry_malformed", "queue", entry,
          {**ra, "signed": R.sign_object(S, pk, {**rej["o"], "expires_ms": rej["o"]["expires_ms"] + 1})}, "malformed")
    for field in ("device_id", "dk_hash", "attempt", "expires_ms"):
        rcase(f"rejection_without_{field}_malformed", "queue", entry,
              {**ra, "signed": R.sign_object(S, pk, {k_: x for k_, x in rej["o"].items() if k_ != field})}, "malformed")
    # the old (pre-G3b) three-identifier rejection no longer fits the exact field set
    legacy = {k_: rej["o"][k_] for k_ in ("v", "suite", "kind", "request_id", "workspace_id", "person_id")}
    rcase("rejection_in_the_old_shape_malformed", "queue", entry, {**ra, "signed": R.sign_object(S, pk, legacy)},
          "malformed")

    # ------------------------------------------------------------------ primary: clear binding == sealed inner
    primary = []
    card = v["card"]["card"]
    kx_primary = S.kx_key(bytes.fromhex(keys["primary.kx"]["seed"]))

    def pcase(name, signed, want):
        prim = {"seen": [], "open": {}}
        got = R.primary_open_cert_request(S, signed, card, pid, dev["primary"], kx_primary, prim, NOW + 1000)
        assert ("ok" in got) == (want == "ok") and got.get("refuse", "ok") == want, (name, got)
        primary.append({"name": name, "card": card, "me": "primary", "person_id": pid.hex(),
                        "primary": {"seen": [], "open": {}}, "steps": [{"signed": signed, "now_ms": NOW + 1000,
                                                                         "expect": got}]})

    pcase("request_with_the_attempt_binding_opens", req, "ok")
    for field, value in (("offer_id", other_offer.hex()), ("attempt", attempt_b), ("device_id", dev["intruder"].hex()),
                         ("dk_hash", req_intruder["o"]["dk_hash"])):
        pcase(f"clear_{field}_differs_from_the_sealed_inner_malformed", R.sign_object(S, wsk, {**req["o"], field: value}),
              "malformed")
    # the clear binding is right, but the sealed inner (the pre-G3b shape) has no attempt
    old_inner = R.seal_to(S, pub["primary.kx"], dev["primary"], "cert-request", bytes.fromhex(req["o"]["request_id"]),
                          0, R.cj({k_: x for k_, x in inner.items() if k_ != "attempt"}),
                          fake(f"suite{S.id}/g3b eph no attempt"))
    pcase("inner_without_attempt_malformed", R.sign_object(S, wsk, {**req["o"], "sealed": R.b64u(old_inner)}),
          "malformed")
    pcase("request_without_the_clear_binding_malformed",
          R.sign_object(S, wsk, {k_: x for k_, x in req["o"].items() if k_ not in ("offer_id", "attempt", "device_id",
                                                                                  "dk_hash")}), "malformed")

    # ------------------------------------------------------------------ host: the attempt in the pair request
    kp = R.k_pair(secret, ws, offer)
    meta_pair = {"op": "pair", "dk_sig_pub": R.b64u(pub["phone.sig"]), "dk_kx_pub": R.b64u(pub["phone.kx"]),
                 "label": "Severin's iPhone", "cert": None, "attempt": attempt_a}
    host_state = {"suite": S.id, "workspace": ws.hex(), "epoch": 2, "wk": {}, "members": {}, "certs": {},
                  "revoked": [], "seq": {}, "rids": {}, "streams": {}, "unverified": [],
                  "offers": {offer.hex(): {"secret": secret.hex(), "expires_ms": NOW + R.OFFER_TTL_MS,
                                           "sas_nonce": R.b64u(fake("sas nonce")), "used": False, "unverified": []}},
                  "pending_pairs": {}, "wsk_pub": R.b64u(pub["wsk_a.sig"]),
                  "owner_pk_pub": R.b64u(pub["person_alice.sig"]), "owner_person_id": pid.hex()}

    def preq(meta, seq=1, rid=None, ts=NOW):
        h = R.Header(R.TO_HOST, 0, S.id, ws, dev["phone"], rid or fake(f"g3b pair rid {seq}")[:16], offer, seq, ts, 0,
                     fake(f"g3b pair salt {seq}")[:16])
        return R.envelope(S, kp, sig["phone"], h, R.frame(meta))

    host = []

    def hchain(name, steps, state=None):
        s = copy.deepcopy(state or host_state)
        before = copy.deepcopy(s)
        st = []
        for env, now in steps:
            mb = R.Header.decode(env).rid.hex()
            st.append({"envelope": env.hex(), "mailbox_id": mb, "now_ms": now,
                       "expect": _strip(R.host_check(env, s, now, mb))})
        host.append({"name": name, "state": before, "steps": st})
        return s

    hchain("pair_without_attempt_malformed", [(preq({k_: x for k_, x in meta_pair.items() if k_ != "attempt"}), NOW)])
    hchain("pair_attempt_not_hex_malformed", [(preq({**meta_pair, "attempt": "AB" * 16}), NOW)])
    hchain("pair_resend_keeps_the_attempt_new_attempt_closed", [
        (preq(meta_pair), NOW), (preq(meta_pair, seq=2), NOW + 5), (preq({**meta_pair, "attempt": attempt_b}, seq=3), NOW + 9)])
    assert host[-1]["steps"][1]["expect"]["result"] == "pair_pending"
    assert host[-1]["steps"][2]["expect"]["code"] == "pairing_closed", host[-1]["steps"][2]["expect"]

    # ------------------------------------------------------------------ the phone: answers to pair_status
    def pans(meta, seq=0, ts=NOW, rid=None):
        h = R.Header(R.TO_DEVICE, R.F_LAST, S.id, ws, dev["phone"], rid or fake("g3b status rid")[:16], offer, seq,
                     ts, 0, fake(f"g3b answer salt {seq} {ts} {json.dumps(meta, sort_keys=True)[:64]}")[:16])
        return R.envelope(S, kp, wsk, h, R.frame(meta))

    ctx0 = {"suite": S.id, "workspace": ws.hex(), "device": dev["phone"].hex(), "offer": offer.hex(),
            "secret": secret.hex(), "wsk_pin": R.wsk_pin(S, pub["wsk_a.sig"]).hex(),
            "pk_pin": R.pk_pin(S, pub["person_alice.sig"]).hex(), "dk_sig_pub": R.b64u(pub["phone.sig"]),
            "dk_kx_pub": R.b64u(pub["phone.kx"]), "attempt": attempt_a,
            "earlier_attempts": [{"device_id": old_dev.hex(), "dk_hash": old_hash}],
            "offset_ms": 0, "pending": {}}

    def chain(group, name, steps, ctx=None):
        """steps: (meta, now, restart). Every step answers its own pending rid; ctx persists (and survives a
        restart: the test round-trips it through JSON) between steps."""
        c = copy.deepcopy(ctx or ctx0)
        before = copy.deepcopy(c)
        out_ = []
        for i, (meta, now, restart) in enumerate(steps):
            rid = fake(f"g3b {name} rid {i}")[:16]
            c["pending"][rid.hex()] = {"next": 0}
            if restart:
                c = json.loads(json.dumps(c))
            env = pans(meta, rid=rid, ts=now)
            res = _strip(R.open_pair_answer(env, c, now))
            out_.append({"envelope": env.hex(), "now_ms": now, "restart": restart, "add_pending": rid.hex(),
                         "expect": res, "ctx_after": copy.deepcopy(c)})
        group.append({"name": name, "ctx": before, "steps": out_})
        return out_

    wpub, ppub = R.b64u(pub["wsk_a.sig"]), R.b64u(pub["person_alice.sig"])
    cp = {"state": "cert_pending", "primary_label": "MacBook Pro", "pk_pub": ppub, "challenge": None, "wsk_pub": wpub}

    def one(group, name, meta, now=NOW, ctx=None):
        return chain(group, name, [(meta, now, False)], ctx)[0]["expect"]

    challenges = []
    assert "cert_code" in one(challenges, "challenge_bound_to_this_attempt_shows_its_code", {**cp, "challenge": chal})
    assert one(challenges, "challenge_from_another_offer_dropped_without_alarm", {
        **cp, "challenge": R.make_cert_challenge(S, pk, req_other_offer["o"], {**inner, "offer_id": other_offer.hex()},
                                                 nonce)}) == {"result": "drop", "why": "not_for_this_pairing"}
    assert one(challenges, "challenge_of_another_attempt_with_these_keys_dropped", {
        **cp, "challenge": R.make_cert_challenge(S, pk, req_other_attempt["o"], {**inner, "attempt": attempt_b},
                                                 nonce)})["why"] == "not_for_this_pairing"
    # an old challenge (the phone's own earlier keys) replayed into the new attempt: a stale attempt, no alarm
    assert one(challenges, "challenge_of_an_earlier_attempt_replayed_dropped_without_alarm", {
        **cp, "challenge": R.make_cert_challenge(S, pk, req_old["o"], inner_old, nonce)}) == \
        {"result": "drop", "why": "stale_attempt"}
    # check order: keys BEFORE the offer and the attempt, so a host-chosen offer_id cannot silence the alarm
    for nm, inn in (("other_offer", {**inner_intruder, "offer_id": other_offer.hex()}),
                    ("other_attempt", {**inner_intruder, "attempt": attempt_b}), ("this_attempt", inner_intruder)):
        assert one(challenges, f"challenge_for_a_foreign_key_{nm}_raises_the_alarm", {
            **cp, "challenge": R.make_cert_challenge(S, pk, req_intruder["o"], inn, nonce)}) == \
            {"result": "drop", "why": "not_my_key", "alarm": True}
    # the old (pre-G3b) challenge shape fails the exact field set
    legacy_chal = {k_: x for k_, x in chal["o"].items() if k_ not in ("offer_id", "attempt")}
    assert one(challenges, "challenge_in_the_old_shape_dropped", {
        **cp, "challenge": R.sign_object(S, pk, legacy_chal)})["why"] == "challenge_signature"
    # after a challenge was seen, a challenge for another request in this attempt is dropped, also after a restart
    steps = chain(challenges, "second_challenge_for_another_request_after_restart_dropped", [
        ({**cp, "challenge": chal}, NOW, False),
        ({**cp, "challenge": R.make_cert_challenge(S, pk, req_other_attempt["o"] | {"request_id": fake("g3b rid x")[:16].hex()},
                                                   inner, nonce)}, NOW + 1000, True)])
    assert steps[1]["expect"]["why"] == "not_for_this_pairing"
    # a phone that forgot its earlier keys fails closed: the earlier attempt's challenge raises the alarm
    assert one(challenges, "challenge_of_an_earlier_attempt_without_its_memory_raises_the_alarm", {
        **cp, "challenge": R.make_cert_challenge(S, pk, req_old["o"], inner_old, nonce)},
        ctx={**ctx0, "earlier_attempts": []})["alarm"] is True
    # round 2 (F1, probe case A): the phone's OLD signing key with the host's kx key is not a stale attempt
    inner_old_sig_foreign_kx = inner_for(old_sig_pub, pub["intruder.kx"], attempt_a)
    req_old_sig_foreign_kx = creq(inner_old_sig_foreign_kx, "old sig foreign kx")
    assert one(challenges, "challenge_earlier_device_foreign_kx_raises_the_alarm", {
        **cp, "challenge": R.make_cert_challenge(S, pk, req_old_sig_foreign_kx["o"], inner_old_sig_foreign_kx, nonce)}) \
        == {"result": "drop", "why": "not_my_key", "alarm": True}
    # round 2 (F3): expiry before the alarm: an expired foreign challenge is dropped silently
    assert one(challenges, "expired_foreign_challenge_dropped_without_alarm", {
        **cp, "challenge": R.make_cert_challenge(S, pk, req_intruder["o"], inner_intruder, nonce)},
        now=req_intruder["o"]["expires_ms"]) == {"result": "drop", "why": "challenge_expired"}
    assert one(challenges, "expired_challenge_of_an_earlier_attempt_dropped_as_expired", {
        **cp, "challenge": R.make_cert_challenge(S, pk, req_old["o"], inner_old, nonce)},
        now=req_old["o"]["expires_ms"]) == {"result": "drop", "why": "challenge_expired"}
    # ... but for this attempt's own keys the attempt and the offer still come before the expiry
    assert one(challenges, "expired_challenge_with_these_keys_other_offer_not_for_this_pairing", {
        **cp, "challenge": R.make_cert_challenge(S, pk, req_other_offer["o"], {**inner, "offer_id": other_offer.hex()},
                                                 nonce)}, now=req_other_offer["o"]["expires_ms"]) == \
        {"result": "drop", "why": "not_for_this_pairing"}

    # ------------------------------------------------------------------ rejected: two exact forms
    forms = []
    long_ = {"state": "rejected", "wsk_pub": wpub, "pk_pub": ppub, "rejection": rej}
    unattributed = {"result": "accept", "state": "rejected", "attributed": False}

    def rj(name, meta, why=None, alarm=False, now=NOW, ctx=None):
        got = dict(one(forms, name, meta, now, ctx))
        want = {"result": "accept", "state": "rejected", "attributed": why == "ok"}
        if why not in (None, "ok"):
            want["why"] = why
        if alarm:
            want["alarm"] = True
        got.pop("wsk_pub", None)
        assert got == want, (name, got, want)

    rj("short_form_unattributed_without_alarm", {"state": "rejected", "wsk_pub": wpub})
    rj("short_form_with_an_extra_field_not_a_pairing_answer",
       {"state": "rejected", "wsk_pub": wpub, "primary_label": "MacBook Pro"}, "not_a_pairing_answer")
    rj("rejection_earlier_device_other_dk_hash_raises_the_alarm",
       {**long_, "rejection": R.make_cert_rejection(S, pk, req_old_sig_foreign_kx["o"])}, "not_my_key", alarm=True)
    rj("expired_foreign_rejection_unattributed_without_alarm",
       {**long_, "rejection": R.make_cert_rejection(S, pk, req_intruder["o"])}, "rejection_expired",
       now=req_intruder["o"]["expires_ms"])
    rj("expired_rejection_this_device_other_attempt_not_for_this_pairing",
       {**long_, "rejection": R.make_cert_rejection(S, pk, req_other_attempt["o"])}, "not_for_this_pairing",
       now=req_other_attempt["o"]["expires_ms"])
    rj("long_form_before_any_challenge_denied_by_the_owner", long_, "ok")
    rj("long_form_stripped_of_the_rejection_unattributed", {"state": "rejected", "wsk_pub": wpub, "pk_pub": ppub},
       "not_a_pairing_answer")
    rj("long_form_without_pk_pub_unattributed", {"state": "rejected", "wsk_pub": wpub, "rejection": rej}, "pk_pin")
    rj("long_form_with_an_extra_field_unattributed", {**long_, "reason": "no"}, "not_a_pairing_answer")
    rj("pk_not_of_the_pin_unattributed", {**long_, "pk_pub": R.b64u(pub["person_bob.sig"]),
                                          "rejection": R.sign_object(S, sig["person_bob"], {
                                              **rej["o"], "person_id": R.person_id(S, pub["person_bob.sig"]).hex()})},
       "pk_pin")
    rj("rejection_signed_by_the_host_unattributed",
       {**long_, "rejection": {"o": rej["o"], "sig": R.b64u(S.sign(wsk, R.L["sig_cert_rejection"] + R.cj(rej["o"])))}},
       "rejection_signature")
    rj("rejection_in_the_old_shape_unattributed", {**long_, "rejection": R.sign_object(S, pk, legacy)},
       "rejection_signature")
    rj("rejection_for_another_workspace_unattributed",
       {**long_, "rejection": R.sign_object(S, pk, {**rej["o"], "workspace_id": ids["workspace_b"]})},
       "not_for_this_workspace")
    rj("rejection_other_offer_unattributed",
       {**long_, "rejection": R.make_cert_rejection(S, pk, req_other_offer["o"])}, "not_for_this_pairing")
    rj("rejection_other_attempt_same_keys_unattributed",
       {**long_, "rejection": R.make_cert_rejection(S, pk, req_other_attempt["o"])}, "not_for_this_pairing")
    # a reused offer: the earlier attempt's (unexpired) rejection replayed into this attempt
    rj("reused_offer_earlier_attempts_rejection_unattributed_without_alarm",
       {**long_, "rejection": R.make_cert_rejection(S, pk, req_old["o"])}, "stale_attempt")
    rj("rejection_for_a_foreign_device_raises_the_alarm",
       {**long_, "rejection": R.make_cert_rejection(S, pk, req_intruder["o"])}, "not_my_key", alarm=True)
    rj("rejection_for_this_device_id_other_kx_key_raises_the_alarm",
       {**long_, "rejection": R.sign_object(S, pk, {**rej["o"], "dk_hash": req_intruder["o"]["dk_hash"]})},
       "not_my_key", alarm=True)
    # the foreign-device alarm wins over a host-chosen offer (order: device before offer and attempt)
    rj("rejection_for_a_foreign_device_other_offer_raises_the_alarm",
       {**long_, "rejection": R.sign_object(S, pk, {**R.make_cert_rejection(S, pk, req_intruder["o"])["o"],
                                                    "offer_id": other_offer.hex()})}, "not_my_key", alarm=True)
    # expired signature inside a fresh, WSK-signed outer answer
    rj("expired_rejection_in_a_fresh_answer_unattributed", long_, "rejection_expired", now=rej["o"]["expires_ms"])
    steps = chain(forms, "rejection_after_the_challenge_of_the_same_request_denied", [
        ({**cp, "challenge": chal}, NOW, False), (long_, NOW + 1000, False)])
    assert steps[1]["expect"]["attributed"] is True
    other_req_rej = R.make_cert_rejection(S, pk, {**req["o"], "request_id": fake("g3b rid x")[:16].hex()})
    steps = chain(forms, "rejection_for_another_request_after_a_challenge_and_restart_unattributed", [
        ({**cp, "challenge": chal}, NOW, False), ({**long_, "rejection": other_req_rej}, NOW + 1000, True)])
    assert steps[1]["expect"] == {**unattributed, "why": "not_for_this_pairing", "wsk_pub": wpub}
    # replay after an app restart: the phone persisted its earlier attempt's device, so the old rejection is stale
    steps = chain(forms, "earlier_attempts_rejection_replayed_after_restart_unattributed", [
        ({"state": "rejected", "wsk_pub": wpub, "pk_pub": ppub, "rejection": R.make_cert_rejection(S, pk, req_old["o"])},
         NOW, True)])
    assert steps[0]["expect"]["why"] == "stale_attempt"
    # the host relays the primary's rejection unchanged in the long form
    held = {"offer_id": offer.hex(), "dk_sig_pub": meta_pair["dk_sig_pub"], "dk_kx_pub": meta_pair["dk_kx_pub"],
            "label": "Severin's iPhone", "attempt": attempt_a, "sas_nonce": R.b64u(fake("sas nonce")), "cert": None,
            "cert_state": "needed"}
    used = copy.deepcopy(host_state)
    used["offers"][offer.hex()]["used"] = True
    for name, extra in (("host_rejected_on_the_primary_long_form", {"rejection": rej}),
                        ("host_rejected_on_the_host_short_form", {})):
        st_ = copy.deepcopy(used)
        st_["pending_pairs"][dev["phone"].hex()] = {**held, "state": "rejected", **extra}
        hchain(name, [(preq({"op": "pair_status"}, seq=2), NOW)], st_)
    assert set(host[-2]["steps"][0]["expect"]["answer"]) == {"state", "wsk_pub", "pk_pub", "rejection"}
    assert set(host[-1]["steps"][0]["expect"]["answer"]) == {"state", "wsk_pub"}

    # ------------------------------------------------------------------ approved: the join anchor (Q6)
    answers = []
    cert = v["cert_request"]["signed_cert"]["ok"]
    assert cert["o"]["dk_sig_pub"] == R.b64u(pub["phone.sig"])
    base = {"state": "approved", "scopes": ["look", "decide", "operate"], "cert": cert, "pk_pub": ppub, "epoch": 2,
            "list_seq": 3, "card_seq": 2, "baseline": {"n": 7, "hash": "sha256:" + R.H(b"g3b baseline").hex()},
            "wsk_pub": wpub}
    assert one(answers, "approved_with_the_anchor", base)["anchor"]["list_seq"] == 3
    assert one(answers, "approved_without_a_baseline_checkpoint", {**base, "baseline": None})["state"] == "approved"
    for name, patch in (("approved_without_list_seq", {"list_seq": None}), ("approved_without_card_seq", {"card_seq": None}),
                        ("approved_list_seq_zero", {"list_seq": 0}), ("approved_card_seq_not_an_integer", {"card_seq": "2"}),
                        ("approved_baseline_not_a_hash", {"baseline": {"n": 7, "hash": "00" * 32}}),
                        ("approved_epoch_zero", {"epoch": 0})):
        meta = {k_: x for k_, x in {**base, **patch}.items() if x is not None}
        assert one(answers, name, meta) == {"result": "drop", "why": "not_a_pairing_answer"}, name
    assert one(answers, "approved_without_the_baseline_field", {k_: x for k_, x in base.items() if k_ != "baseline"}) \
        == {"result": "drop", "why": "not_a_pairing_answer"}
    # round 2 (F5): equal baseline n never takes the new hash; F6: scopes move only with a higher list_seq
    other_base = {"n": 7, "hash": "sha256:" + R.H(b"g3b other baseline").hex()}
    steps = chain(answers, "approved_again_same_baseline_n_other_hash_keeps_the_baseline", [
        (base, NOW, False), ({**base, "baseline": other_base}, NOW + 1000, False)])
    assert steps[1]["expect"]["anchor"]["baseline"] == base["baseline"]
    steps = chain(answers, "approved_again_same_list_seq_other_scopes_keeps_the_floor", [
        (base, NOW, False), ({**base, "scopes": ["look"]}, NOW + 1000, False)])
    assert steps[1]["expect"]["anchor"]["scopes"] == steps[1]["expect"]["scopes"] == base["scopes"]
    steps = chain(answers, "approved_again_higher_list_seq_takes_its_scopes", [
        (base, NOW, False), ({**base, "scopes": ["look"], "list_seq": 4}, NOW + 1000, False)])
    assert steps[1]["expect"]["anchor"]["scopes"] == ["look"]
    steps = chain(answers, "approved_again_with_lower_values_keeps_the_floor", [
        (base, NOW, False), ({**base, "list_seq": 2, "card_seq": 1, "epoch": 1, "baseline": None}, NOW + 1000, True)])
    assert steps[1]["expect"]["anchor"] == steps[0]["expect"]["anchor"]

    # the join: list and card floors, and the own entry with exactly the approved scopes
    wk = {e: fake(f"suite{S.id}/g3b WK epoch {e}") for e in (1, 2, 3)}
    full = ["look", "decide", "operate", "type"]

    def mlist(epoch, seq, phone_scopes=("look", "decide", "operate"), with_phone=True):
        members = [{"device_id": dev["primary"].hex(), "person_id": pid.hex(), "scopes": full}]
        if with_phone:
            members.append({"device_id": dev["phone"].hex(), "person_id": pid.hex(), "scopes": list(phone_scopes)})
        return R.make_member_list(S, wsk, ws, epoch, seq, NOW, wk[epoch], members)

    anchor = R._approved_anchor(base)
    join = []

    def jcase(name, steps):
        state = {"head": None, "wk_commits": {}, "sealing_blocked": [], "anchor": copy.deepcopy(anchor),
                 "device": dev["phone"].hex()}
        before = copy.deepcopy(state)
        out_ = []
        for op, arg in steps:
            if op == "list":
                got = R.device_accept_member_list(S, pub["wsk_a.sig"], ws.hex(), state, arg)
            else:
                got = R.device_join_card(state["anchor"], arg)
            out_.append({"op": op, "signed" if op == "list" else "card_o": arg, "expect": got,
                         "state": copy.deepcopy(state)})
        join.append({"name": name, "card_workspace_id": ws.hex(), "wsk_pub": pub["wsk_a.sig"].hex(), "state": before,
                     "steps": out_})
        return out_

    assert jcase("list_at_the_anchor_joins", [("list", mlist(2, 3))])[0]["expect"] == {"ok": "advanced"}
    assert jcase("list_above_the_anchor_joins", [("list", mlist(3, 5))])[0]["expect"] == {"ok": "advanced"}
    assert jcase("list_below_the_anchor_list_seq_refused", [("list", mlist(2, 2))])[0]["expect"] == {"refuse": "below_anchor"}
    assert jcase("list_below_the_anchor_epoch_refused", [("list", mlist(1, 4))])[0]["expect"] == {"refuse": "below_anchor"}
    assert jcase("list_without_this_device_not_a_member", [("list", mlist(2, 3, with_phone=False))])[0]["expect"] == \
        {"refuse": "not_a_member"}
    # round 2 (F2): above the anchor the list's scopes rule (an owner change after approval)
    assert jcase("list_above_the_anchor_with_changed_scopes_joins",
                 [("list", mlist(2, 4, phone_scopes=["look"]))])[0]["expect"] == {"ok": "advanced"}
    assert jcase("list_with_other_scopes_refused", [("list", mlist(2, 3, phone_scopes=["look"]))])[0]["expect"] == \
        {"refuse": "scopes_mismatch"}
    got = jcase("refused_join_keeps_the_floor_for_the_retry", [("list", mlist(2, 2)), ("list", mlist(2, 3))])
    assert [s_["expect"] for s_ in got] == [{"refuse": "below_anchor"}, {"ok": "advanced"}]
    card_o = v["card"]["card"]["o"]
    for name, seq, want in (("card_below_the_anchor_refused", 1, {"refuse": "below_anchor"}),
                            ("card_at_the_anchor_accepted", 2, {"ok": 2}), ("card_above_the_anchor_accepted", 3, {"ok": 3})):
        assert jcase(name, [("card", {**card_o, "card_seq": seq})])[0]["expect"] == want

    v["cert_binding"] = {"relay": relay, "primary": primary, "host": host, "challenges": challenges,
                         "earlier_attempt_keys": {"sig_seed": old_seed_sig.hex(), "kx_seed": old_seed_kx.hex(),
                                                  "device_id": old_dev.hex(), "dk_hash": old_hash},
                         "attempts": {"current": attempt_a, "other": attempt_b}}
    v["rejected_forms"] = {"answers": forms, "objects": {"rejection": rej, "request": req}}
    v["approved_anchor"] = {"answers": answers, "join": join}
