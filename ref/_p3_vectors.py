"""P3-D1..D11/D17/D22 vector builder. All keys are public FAKE test seeds."""
import copy

from ref import orch_protocol_ref as R

NOW = 1_790_000_000_000


def replay(S, c):
    """Replay only JSON inputs; also expose resulting state to pin transactional behavior."""
    state = copy.deepcopy(c["state"])
    a = copy.deepcopy(c["args"])
    op = c["op"]
    if op == "membership":
        d = a.pop("directory")
        d["owner_pk_pub"] = bytes.fromhex(d["owner_pk_pub"])
        d["persons"] = {p: bytes.fromhex(k) for p, k in d.get("persons", {}).items()}
        result = R.relay_membership(S, bytes.fromhex(a["wsk_pub"]), a["ws"], state, d, a["body_raw"].encode() if "body_raw" in a else a["body"], a["now_ms"])
    elif op == "directory":
        result = R.relay_directory_read(state, **a)
    elif op == "certificate":
        a["pk_pub"] = bytes.fromhex(a["pk_pub"])
        result = R.relay_certificate(S, state, **a)
    elif op == "first_card":
        a["owner_pk_pub"] = bytes.fromhex(a["owner_pk_pub"])
        result = R.relay_first_card(S, state, **a)
    elif op == "rejection":
        result = R.verify_cert_rejection(S, a["signed"], bytes.fromhex(a["pk_pub"]), a["request"])
    elif op == "queue":
        result = R.relay_cert_queue(S, state, a["action"], a["signed"], bytes.fromhex(a["pk_pub"]), a["now_ms"])
    elif op == "request":
        result = R.relay_cert_request(S, a["signed"], bytes.fromhex(a["wsk_pub"]), a["ws"], a["owner"],
                                     a["primary"], state, a["now_ms"])
    elif op == "holder":
        result = R.relay_holder(state, **a)
    elif op == "poll":
        result = R.relay_poll(state, **a)
    elif op == "request_replay":
        a["raw"] = bytes.fromhex(a["raw"])
        result = R.relay_bridge_request(state, **a)
    elif op == "chunk":
        a["raw"] = bytes.fromhex(a["raw"])
        result = R.relay_bridge_chunk(state, **a)
    elif op == "quota":
        a["raw"] = bytes.fromhex(a["raw"])
        result = R.relay_recovery_quota(state, **a)
    elif op == "envelope":
        a["raw"] = bytes.fromhex(a["raw"])
        result = R.relay_envelope_check(S, **a)
    elif op == "session_gate":
        result = R.relay_session_gate(**a)
    elif op == "handoff":
        result = R.relay_poll_handoff(state, **a)
    elif op == "revocation":
        a["pk_pub"] = bytes.fromhex(a["pk_pub"])
        result = R.relay_revoke(S, state, **a)
    elif op == "login":
        for k in ("challenge", "ident", "sig", "token"):
            a[k] = bytes.fromhex(a[k])
        result = R.relay_session_login(S, state, **a)
    else:
        raise AssertionError(op)
    return {"result": result, "state": state}


def add_p3(out):
    for sid, v in out["suites"].items():
        S = R.SUITES[int(sid)]
        keys, ids = v["keys"], v["ids"]
        priv = lambda n: S.sig_key(bytes.fromhex(keys[n + ".sig"]["seed"]))
        pub = lambda n: keys[n + ".sig"]["pub"]
        sign = lambda o, n="wsk_a": R.sign_object(S, priv(n), o)
        ws, person, phone = ids["workspace_a"], ids["person_alice"], ids["device_phone"]
        certs = v["certs"]["signed"]
        cases = []

        def case(name, op, state, args, want):
            c = {"name": name, "op": op, "state": copy.deepcopy(state), "args": copy.deepcopy(args)}
            c["expect"] = replay(S, c)
            result = c["expect"]["result"]
            actual = result.get("refuse", result.get("error", result.get("ok", result.get("status"))))
            assert actual == want, (name, actual, want)
            cases.append(c)
            return copy.deepcopy(c["expect"]["state"])

        # P3-D6/D7: an adding person's grants are judged against this body's signed persons.
        ds = {"owner_pk_pub": pub("person_alice"), "persons": {ids["person_bob"]: pub("person_bob")},
              "certs": {c["o"]["device_id"]: c for c in certs.values()}, "revoked": []}
        member = lambda n: {"device_id": ids["device_" + n], "person_id": certs[n]["o"]["person_id"], "scopes": ["look"]}
        lo = {"v": 2, "suite": S.id, "kind": "member_list", "workspace_id": ws, "epoch": 1,
              "list_seq": 1, "issued_ms": NOW, "persons": [ids["person_bob"]],
              "members": sorted([member("phone"), member("bob_phone")], key=lambda m: m["device_id"])}
        grants = [R.make_wk_grant(S, priv("wsk_a"), bytes.fromhex(ws), bytes.fromhex(ids["device_" + n]),
                                 bytes.fromhex(keys[n + ".kx"]["pub"]), 1, R.fake("P3 wk"), R.fake("P3 eph " + n))
                  for n in ("phone", "bob_phone")]
        wraps = {"card_seq": 1, "wraps": [{"device_id": phone, "sealed": R.b64u(bytes.fromhex(v["card"]["card_key_wrap_to_phone"]["sealed"]))}]}
        body = {"member_list": sign(lo), "grants": grants, "card_key_wraps": wraps}
        st = {"list": None, "grants": {}, "wraps": {}, "card_seq": 1, "rotation_due": {}, "publications": {}}
        args = {"wsk_pub": pub("wsk_a"), "ws": ws, "directory": ds, "body": body, "now_ms": NOW}
        committed = case("second_person_and_grants_in_one_commit", "membership", st, args, {"list_seq": 1, "epoch": 1})
        case("changed_http_whitespace_is_not_exact_retry", "membership", committed,
             {**args, "body_raw": " " + R.cj(body).decode()}, "stale_list")
        stale = copy.deepcopy(committed); stale["card_seq"] = 2
        case("exact_retry_before_card_and_cert_freshness", "membership", stale, {**args, "now_ms": NOW + 10**12}, {"list_seq": 1, "epoch": 1})
        for name, changed, want in [
            ("person_not_listed", {**lo, "persons": []}, "other_person"),
            ("duplicate_person", {**lo, "persons": [ids["person_bob"]] * 2}, "malformed"),
            ("entry_person_mismatch", {**lo, "members": [{**m, "person_id": person} for m in lo["members"]]}, "other_person"),
            ("missing_person_field", {**lo, "members": [{k: x for k, x in m.items() if k != "person_id"} for m in lo["members"]]}, "malformed"),
            ("other_workspace", {**lo, "workspace_id": ids["workspace_b"]}, "other_workspace"),
            ("invalid_member_scope", {**lo, "members": [{**m, "scopes": ["operate"]} for m in lo["members"]]}, "scope_exceeded"),
        ]:
            case(name, "membership", st, {**args, "body": {**body, "member_list": sign(changed)}}, want)
        for name, b, want in [
            ("missing_grant_atomic_no_write", {**body, "grants": grants[:1]}, "missing_grant"),
            ("duplicate_grant", {**body, "grants": grants + grants[:1]}, "malformed"),
            ("grant_wrong_epoch", {**body, "grants": [sign({**grants[0]["o"], "epoch": 2})]}, "not_for_this_device"),
            ("grant_wrong_workspace", {**body, "grants": [sign({**grants[0]["o"], "workspace_id": ids["workspace_b"]})]}, "other_workspace"),
            ("grant_bad_signature", {**body, "grants": [sign(grants[0]["o"], "wsk_intruder")]}, "bad_signature"),
            ("grant_bad_sealed", {**body, "grants": [sign({**grants[0]["o"], "sealed": "AA"})]}, "malformed"),
            ("stale_wrap_atomic_no_write", {**body, "card_key_wraps": {**wraps, "card_seq": 2}}, "stale_card"),
            ("foreign_wrap", {**body, "card_key_wraps": {**wraps, "wraps": [{**wraps["wraps"][0], "device_id": ids["device_intruder"]}]}}, "not_for_this_device"),
            ("bad_wrap", {**body, "card_key_wraps": {**wraps, "wraps": [{"device_id": phone, "sealed": "AA"}]}}, "malformed"),
        ]:
            case(name, "membership", st, {**args, "body": b}, want)
        case("revoked_member_atomic_no_write", "membership", st, {**args, "directory": {**ds, "revoked": [phone]}}, "revoked")
        conflict = copy.deepcopy(committed)
        conflict["grants"][phone + "/1"] = sign({**grants[0]["o"], "sealed": R.b64u(R.fake("other"))})
        case("committed_grant_conflict", "membership", conflict,
             {**args, "body": {**body, "member_list": sign({**lo, "list_seq": 2})}}, "grant_conflict")
        due = copy.deepcopy(committed); due["rotation_due"] = {ids["device_laptop"]: {"epoch": 1, "revocation_cursor": 9}}
        retained = case("rotation_due_survives_same_epoch_and_restart", "membership", due,
                        {**args, "body": {**body, "member_list": sign({**lo, "list_seq": 2})}}, {"list_seq": 2, "epoch": 1})
        rotated = {**body, "member_list": sign({**lo, "list_seq": 3, "epoch": 2}),
                   "grants": [sign({**g["o"], "epoch": 2}) for g in grants]}
        case("rotation_due_clears_higher_excluding_list", "membership", retained, {**args, "body": rotated}, {"list_seq": 3, "epoch": 2})

        # Cert queue state machine and domain separation.
        cr = v["cert_request"]["cases"][0]["steps"][0]["signed"]
        ch = v["cert_request"]["challenge"]
        ro = {"v": 2, "suite": S.id, "kind": "cert_rejection", **{k: cr["o"][k] for k in ("request_id", "workspace_id", "person_id")}}
        rejection = sign(ro, "person_alice")
        ra = {"signed": rejection, "pk_pub": pub("person_alice"), "request": cr["o"]}
        case("cert_rejection_valid", "rejection", {}, ra, ro)
        for name, obj, want in [
            ("rejection_wrong_signer", sign(ro, "wsk_a"), "bad_signature"),
            ("rejection_wrong_label", {"o": ro, "sig": R.b64u(S.sign(priv("person_alice"), R.L["sig_cert_challenge"] + R.cj(ro)))}, "bad_signature"),
            ("rejection_extra_field", sign({**ro, "reason": "no"}, "person_alice"), "malformed"),
            ("rejection_other_person", sign({**ro, "person_id": ids["person_bob"]}, "person_alice"), "other_person"),
            ("rejection_other_workspace", sign({**ro, "workspace_id": ids["workspace_b"]}, "person_alice"), "other_workspace"),
            ("rejection_other_request", sign({**ro, "request_id": R.fake("other req")[:16].hex()}, "person_alice"), "not_for_this_device"),
        ]:
            case(name, "rejection", {}, {**ra, "signed": obj}, want)
        rq = {"signed": cr, "wsk_pub": pub("wsk_a"), "ws": ws, "owner": person,
              "primary": ids["device_primary"], "now_ms": NOW}
        q = case("request_admission", "request", {}, rq, cr["o"]["request_id"])
        case("request_exact_retry", "request", q, rq, cr["o"]["request_id"])
        cr2 = sign({**cr["o"], "request_id": R.fake("second request")[:16].hex()})
        case("request_open_limit", "request", q, {**rq, "signed": cr2}, "request_open")
        case("request_bad_signature", "request", {}, {**rq, "signed": sign(cr["o"], "wsk_intruder")}, "bad_signature")
        case("request_expired", "request", {}, {**rq, "now_ms": cr["o"]["expires_ms"]}, "expired")
        entry = q[cr["o"]["request_id"]]
        qa = {"action": "challenge", "signed": ch, "pk_pub": pub("person_alice"), "now_ms": NOW}
        challenged = case("open_to_challenged", "queue", entry, qa, "challenged")
        case("challenge_exact_retry", "queue", challenged, qa, "challenged")
        case("challenge_no_replacement", "queue", challenged,
             {**qa, "signed": sign({**ch["o"], "primary_nonce": R.b64u(R.fake("different nonce"))}, "person_alice")}, "replayed")
        cert = v["cert_request"]["signed_cert"]["ok"]
        signed = case("challenged_to_signed", "queue", challenged, {**qa, "action": "certificate", "signed": cert}, "signed")
        case("certificate_exact_retry", "queue", signed, {**qa, "action": "certificate", "signed": cert}, "signed")
        reject_args = {**qa, "action": "rejection", "signed": rejection}
        case("rejection_after_signing", "queue", signed, reject_args, "already_signed")
        rejected = case("challenged_to_rejected", "queue", challenged, reject_args, "rejected")
        case("open_to_rejected", "queue", entry, reject_args, "rejected")
        case("rejection_exact_retry", "queue", rejected, reject_args, "rejected")
        case("cannot_sign_after_rejection", "queue", rejected, {**qa, "action": "certificate", "signed": cert}, "replayed")
        case("cannot_challenge_after_rejection", "queue", rejected, {**qa, "signed": sign({**ch["o"], "primary_nonce": R.b64u(R.fake("n2"))}, "person_alice")}, "replayed")
        case("other_keys_do_not_complete", "queue", challenged, {**qa, "action": "certificate", "signed": certs["laptop"]}, "unmatched")
        for action, obj in (("challenge", ch), ("rejection", rejection), ("certificate", cert)):
            case(action + "_expiry_race", "queue", entry if action == "challenge" else challenged,
                 {**qa, "action": action, "signed": obj, "now_ms": cr["o"]["expires_ms"]}, "expired")
        case("request_retention_ends", "queue", signed, {**qa, "now_ms": cr["o"]["expires_ms"] + 60000}, "not_found")
        case("challenge_wrong_device_key", "queue", entry,
             {**qa, "signed": sign({**ch["o"], "device_id": ids["device_laptop"]}, "person_alice")}, "malformed")
        case("challenge_wrong_expiry", "queue", entry,
             {**qa, "signed": sign({**ch["o"], "expires_ms": NOW + 1}, "person_alice")}, "malformed")

        # Holder generations, durable acknowledgement and poll cancellation token.
        holder = {"gen": 0, "lease_until_ms": 0, "cursor": 0, "poll_token": None}
        h = case("holder_acquire", "holder", holder, {"now_ms": NOW, "gen": None}, {"gen": 1, "lease_s": 40, "cursor": 0})
        case("holder_conflict", "holder", h, {"now_ms": NOW + 1, "gen": None}, "holder_conflict")
        case("holder_renew", "holder", h, {"now_ms": NOW + 15000, "gen": 1}, {"gen": 1, "lease_s": 40, "cursor": 0})
        h2 = case("explicit_takeover", "holder", h, {"now_ms": NOW + 1, "gen": None, "take_over": True}, {"gen": 2, "lease_s": 40, "cursor": 0})
        case("old_holder_fenced", "holder", h2, {"now_ms": NOW + 2, "gen": 1}, "fenced")
        case("expired_holder_fenced", "holder", h, {"now_ms": NOW + 40000, "gen": 1}, "fenced")
        pa = {"now_ms": NOW + 1, "gen": 1, "after": 1, "token": "poll-one", "delivered": 3}
        polled = case("ack_only_contiguous_completed_prefix", "poll", h, pa, 1)
        again = case("lost_poll_response_redelivered", "poll", polled, {**pa, "token": "poll-two"}, 1)
        case("cursor_never_moves_back", "poll", again, {**pa, "after": 0}, 1)
        case("cannot_ack_undelivered", "poll", h, {**pa, "after": 4}, "malformed")
        case("poll_after_takeover_fenced", "poll", h2, pa, "fenced")
        case("poll_after_lease_expiry_fenced", "poll", h, {**pa, "now_ms": NOW + 40000}, "fenced")

        handoff = {"now_ms": NOW + 2, "gen": 1, "token": "poll-two"}
        case("poll_wakeup_current_generation", "handoff", again, handoff, "deliver")
        case("second_poll_cancels_first", "handoff", again, {**handoff, "token": "poll-one"}, "cancelled")
        case("takeover_during_poll_fenced_at_handoff", "handoff", h2, handoff, "fenced")
        case("lease_expires_during_poll", "handoff", again, {**handoff, "now_ms": NOW + 50000}, "fenced")

        # Real, verifiable ORB2 envelopes for relay cases and shared HTTP fixtures.
        rid = R.fake("P3 rid")[:16]
        def env(direction, epoch, flags=0, idx=0, salt="normal"):
            h = R.Header(direction, flags, S.id, bytes.fromhex(ws), bytes.fromhex(phone), rid, R.ZERO_ID,
                         idx, NOW, epoch, R.fake("P3 salt " + salt)[:16])
            return R.envelope(S, R.k_bridge(R.fake("P3 wk"), h.workspace, epoch), priv("phone" if direction == 1 else "wsk_a"), h,
                              R.frame({"refusal": "stale_epoch", "epoch": 2} if flags & R.F_REFUSAL else {"op": "http"}))
        req, resp, refusal = env(1, 1), env(2, 1, R.F_LAST), env(2, 1, R.F_LAST | R.F_REFUSAL)
        ba = {"raw": req.hex(), "epoch": 1, "now_ms": NOW, "cursor": 0}
        bs = case("new_request_queued", "request_replay", {}, ba, "queued")
        case("new_rid_stale_epoch_hint", "request_replay", {}, {**ba, "epoch": 2}, "stale_epoch")
        case("undelivered_resend_coalesced", "request_replay", bs, {**ba, "epoch": 2}, "coalesced")
        case("rid_conflict", "request_replay", bs, {**ba, "raw": env(1, 1, salt="other").hex()}, "rid_conflict")
        case("ten_second_retry_floor", "request_replay", bs, {**ba, "cursor": 1, "now_ms": NOW + 9999}, "rate_limited")
        next_bs = bs
        for i in range(1, 9):
            next_bs = case(f"requeue_{i}_after_rotation", "request_replay", next_bs,
                           {**ba, "epoch": 2, "cursor": i, "now_ms": NOW + i * 10000}, "queued")
        case("ninth_requeue_refused", "request_replay", next_bs, {**ba, "cursor": 9, "now_ms": NOW + 90000}, "retry_exhausted")
        tail = case("late_copy_extends_metadata_only", "request_replay", bs, {**ba, "cursor": 1, "now_ms": NOW + 899999}, "queued")
        case("conflict_detected_after_900s_with_live_copy", "request_replay", tail,
             {**ba, "raw": env(1, 1, salt="conflict").hex(), "now_ms": NOW + 900001}, "rid_conflict")
        ca = {"raw": resp.hex(), "epoch": 1, "now_ms": NOW + 1}
        stored = case("current_epoch_response", "chunk", bs, ca, "stored")
        case("old_epoch_stored_replay_no_ttl_extension", "chunk", stored, {**ca, "epoch": 2, "now_ms": NOW + 50000}, "replay")
        case("expired_chunk_not_resurrected", "chunk", stored, {**ca, "epoch": 2, "now_ms": NOW + 70000}, "replay")
        case("chunk_conflict", "chunk", stored, {**ca, "raw": env(2, 1, R.F_LAST, salt="other").hex()}, "chunk_conflict")
        case("old_epoch_new_data_refused", "chunk", bs, {**ca, "epoch": 2}, "stale_epoch")
        case("old_epoch_refusal_known_rid", "chunk", bs, {**ca, "epoch": 2, "raw": refusal.hex()}, "stored")
        case("old_epoch_refusal_unknown_rid", "chunk", {}, {**ca, "epoch": 2, "raw": refusal.hex()}, "expired")
        case("response_epoch_must_match_request", "chunk", bs, {**ca, "epoch": 2, "raw": env(2, 2, R.F_LAST | R.F_REFUSAL).hex()}, "stale_epoch")
        ea = {"raw": req.hex(), "ws": ws, "rid": rid.hex(), "direction": 1, "device": phone}
        case("envelope_route_valid", "envelope", {}, ea, True)
        for name, patch, want in [("header_device_mismatch", {"device": ids["device_laptop"]}, "not_for_this_device"),
                                   ("not_member", {"member": False}, "not_eligible"),
                                   ("revoked", {"revoked": True}, "revoked"),
                                   ("wrong_route", {"ws": ids["workspace_b"]}, "malformed")]:
            case(name, "envelope", {}, {**ea, **patch}, want)
        # Store compact size inputs separately to avoid multi-megabyte duplicate vector fields.
        sizes = [{"direction": d, "pair": pair, "limit": limit, "at_limit": True, "one_over": "too_large"}
                 for d, pair, limit in [(1, False, 1048576), (2, False, 262144), (1, True, 65536)]]

        # Recovery quotas: no attacker can charge the account without a verified fresh submission.
        qu = {"raw": "00", "now_ms": NOW, "valid_signature": False, "already_revoked": False}
        case("invalid_signature_no_person_charge", "quota", {}, qu, "bad_signature")
        qs = case("valid_revocation_charged", "quota", {}, {**qu, "valid_signature": True}, "charged")
        case("exact_retry_free", "quota", qs, {**qu, "valid_signature": True}, "retry")
        full_repeat = {"day": NOW // 86400000, "total": 24, "repeat": 24, "accepted": []}
        case("reserved_share_blocks_repeated_revocations", "quota", full_repeat, {**qu, "valid_signature": True, "already_revoked": True}, "rate_limited")
        case("reserved_share_allows_new_revocation", "quota", full_repeat, {**qu, "valid_signature": True}, "charged")
        case("window_not_idle_pruned", "quota", {**full_repeat, "total": 32}, {**qu, "valid_signature": True}, "rate_limited")

        challenge = R.fake("P3 login challenge")
        origin = "https://relay.dev.severin.io"
        msg = R.relay_auth_signed_bytes(S, origin, challenge, "device", bytes.fromhex(phone))
        la = {"origin": origin, "challenge": challenge.hex(), "kind": "device", "ident": phone,
              "sig": S.sign(priv("phone"), msg).hex(), "subject": {"pub": R.b64u(bytes.fromhex(pub("phone"))), "revoked": False, "expires_ms": None},
              "now_ms": NOW, "token": R.fake("P3 token").hex()}
        ls = {"challenges": {challenge.hex(): NOW + 60000}, "tokens": {}}
        logged = case("login_valid", "login", ls, la, 200)
        case("login_unknown_id_dummy_key", "login", ls, {**la, "subject": None}, "bad_signature")
        case("login_revoked_after_valid_signature", "login", ls, {**la, "subject": {**la["subject"], "revoked": True}}, "revoked")
        case("login_bad_signature_hides_revocation", "login", ls, {**la, "sig": "00" * 64, "subject": {**la["subject"], "revoked": True}}, "bad_signature")
        case("login_expired_certificate", "login", ls, {**la, "subject": {**la["subject"], "expires_ms": NOW}}, "cert_expired")
        logged["challenges"][challenge.hex()] = NOW + 60000
        case("login_preserves_concurrent_tokens", "login", logged, {**la, "token": R.fake("P3 token two").hex()}, 200)
        sa = {"session": {"kind": "device", "id": phone, "expires_ms": NOW + 900000}, "now_ms": NOW,
              "subject": la["subject"], "workspace": ws, "members": [phone]}
        case("live_session_gate", "session_gate", {}, sa, True)
        case("session_expires_during_poll", "session_gate", {}, {**sa, "now_ms": NOW + 900000}, "unauthenticated")
        case("revoked_during_poll", "session_gate", {}, {**sa, "subject": {**la["subject"], "revoked": True}}, "revoked")
        case("certificate_expires_during_poll", "session_gate", {}, {**sa, "subject": {**la["subject"], "expires_ms": NOW}}, "cert_expired")
        case("removed_during_poll", "session_gate", {}, {**sa, "members": []}, "not_eligible")
        case("workspace_token_cannot_cross_workspaces", "session_gate", {},
             {**sa, "session": {"kind": "workspace", "id": ids["workspace_b"], "expires_ms": NOW + 1000}}, "not_eligible")
        rev = v["revocations"][0]["signed"]
        rs = {"revocations": {}, "cursor": 0, "sessions": {"FAKE-hashed-token": phone}, "workspaces": {ws: {
            "list": lo, "mailboxes": {phone: ["sealed"]}, "responses": {phone: ["sealed"]},
            "grants": {phone: grants[0]}, "wraps": {phone: wraps}, "rotation_due": {}}}}
        rargs = {"record": rev, "pk_pub": pub("person_alice"), "cert": certs["phone"]["o"]}
        revoked = case("revocation_atomic_cleanup_and_obligation", "revocation", rs, rargs, phone)
        case("revocation_exact_retry_no_new_cursor", "revocation", revoked, rargs, phone)
        compromised = sign({**rev["o"], "reason": "compromised"}, "person_alice")
        upgraded = case("revocation_strength_upgrade", "revocation", revoked, {**rargs, "record": compromised}, phone)
        case("revocation_never_downgrades", "revocation", upgraded, rargs, phone)
        case("invalid_revocation_no_effect", "revocation", rs, {**rargs, "record": sign(rev["o"], "wsk_a")}, "bad_signature")
        case("revocation_other_person_no_effect", "revocation", rs, {**rargs, "cert": certs["bob_phone"]["o"]}, "other_person")
        case("unlisted_person_account_missing", "membership", st, {**args, "directory": {**ds, "persons": {}}}, "other_person")
        ds_exp = copy.deepcopy(ds)
        ds_exp["certs"][phone] = sign({**certs["phone"]["o"], "expires_ms": NOW}, "person_alice")
        case("publication_cert_expiry_rechecked", "membership", st, {**args, "directory": ds_exp}, "cert_expired")
        tampered_list = copy.deepcopy(body)
        tampered_list["member_list"]["o"]["persons"] = []
        case("persons_covered_by_list_signature", "membership", st, {**args, "body": tampered_list}, "bad_signature")
        ds_missing = copy.deepcopy(ds); ds_missing["certs"].pop(phone)
        case("publication_requires_stored_cert", "membership", st, {**args, "directory": ds_missing}, "cert_invalid")
        for field, val, want in (("person_id", ids["person_bob"], "other_person"),
                                 ("workspace_id", ids["workspace_b"], "other_workspace"),
                                 ("primary_device_id", phone, "not_for_this_device")):
            case("request_wrong_" + field, "request", {}, {**rq, "signed": sign({**cr["o"], field: val})}, want)
        after_rejection = {cr["o"]["request_id"]: rejected}
        case("rejected_request_releases_open_slot", "request", after_rejection, {**rq, "signed": cr2}, cr2["o"]["request_id"])
        ch_bad_sig = sign(ch["o"], "wsk_a")
        case("challenge_host_cannot_sign_for_pk", "queue", entry, {**qa, "signed": ch_bad_sig}, "bad_signature")
        # (G0a review 1) An unrelated persons entry cannot create read authority.
        victim = {**body, "member_list": sign({**lo, "persons": sorted([ids["person_bob"], R.fake("victim")[:16].hex()])})}
        case("victim_person_without_member", "membership", st, {**args, "body": victim}, "other_person")
        laptop_rev = sign({**rev["o"], "device_id": ids["device_laptop"]}, "person_alice")
        read = {"person": person, "records": [rev, laptop_rev]}
        case("directory_other_workspace_person", "directory", {"ever_persons": [], "ever_devices": []}, read, "not_eligible")
        case("directory_filtered_feed", "directory", committed, read, [rev])
        case("directory_unseen_device", "directory", committed, {**read, "device": ids["device_laptop"]}, "not_eligible")
        departed = copy.deepcopy(committed)
        departed["list"]["members"] = sorted([*lo["members"], member("laptop")], key=lambda m: m["device_id"])
        departed["grants"][ids["device_laptop"] + "/1"] = sign({**grants[0]["o"], "device_id": ids["device_laptop"]})
        departed["wraps"][ids["device_laptop"]] = {"card_seq": 1, "sealed": wraps["wraps"][0]["sealed"]}
        case("departed_grants_and_wraps_pruned", "membership", departed, {**args, "body": rotated}, {"list_seq": 3, "epoch": 2})
        conflicting = copy.deepcopy(committed)
        conflicting["wraps"][phone]["sealed"] = "other"
        case("wrap_conflict_atomic", "membership", conflicting,
             {**args, "body": {**body, "member_list": sign({**lo, "list_seq": 2})}}, "wrap_conflict")

        # (G0a review 3) A second fixed nonce produces reproducible, distinct P-256 signatures.
        def resign(obj):
            if S.id != 2:
                return sign(obj["o"], "person_alice")
            from cryptography.hazmat.primitives.asymmetric import ec
            msg = R.L[R.KIND_LABEL[obj["o"]["kind"]]] + R.cj(obj["o"])
            nonce = int.from_bytes(R.fake("G0a alternate nonce " + obj["o"]["kind"]), "big") % (R.P256_N - 1) + 1
            r = ec.derive_private_key(nonce, ec.SECP256R1()).public_key().public_numbers().x % R.P256_N
            scalar = (pow(nonce, -1, R.P256_N) * (int.from_bytes(R.H(msg), "big") + r * priv("person_alice").private_numbers().private_value)) % R.P256_N
            result = {"o": obj["o"], "sig": R.b64u(r.to_bytes(32, "big") + scalar.to_bytes(32, "big"))}
            assert result["sig"] != obj["sig"]
            assert R.verify_object(S, bytes.fromhex(pub("person_alice")), result, obj["o"]["kind"])
            return result
        for action, obj, old, want in (("challenge", ch, challenged, "challenged"), ("rejection", rejection, rejected, "rejected"), ("certificate", cert, signed, "signed")):
            case(action + "_resigned_identical", "queue", old, {**qa, "action": action, "signed": resign(obj)}, want)
            case(action + "_invalid_signature_retry", "queue", old, {**qa, "action": action, "signed": {**obj, "sig": R.b64u(bytes(64))}}, "bad_signature")
        case("rejection_different_content_conflict", "queue", rejected,
             {**qa, "action": "rejection", "signed": sign({**ro, "request_id": R.fake("different rejection")[:16].hex()}, "person_alice")}, "not_for_this_device")
        certargs = {"signed": cert, "pk_pub": pub("person_alice"), "now_ms": NOW}
        certstate = case("certificate_directory_insert", "certificate", {}, certargs, "stored")
        case("certificate_directory_resigned_retry", "certificate", certstate, {**certargs, "signed": resign(cert)}, "retry")
        case("certificate_directory_content_conflict", "certificate", certstate,
             {**certargs, "signed": sign({**cert["o"], "created_ms": cert["o"]["created_ms"] - 1}, "person_alice")}, "cert_conflict")
        case("only_kx_key_differs_no_completion", "queue", challenged,
             {**qa, "action": "certificate", "signed": sign({**cert["o"], "dk_kx_pub": certs["laptop"]["o"]["dk_kx_pub"]}, "person_alice")}, "unmatched")

        # (G0a review 7) Exact boundaries, including allowed side, prevent smaller caps.
        case("expired_undelivered_copy_requeues", "request_replay", bs, {**ba, "now_ms": NOW + 60000}, "queued")
        case("rid_before_900s_conflicts", "request_replay", bs, {**ba, "raw": env(1, 1, salt="new").hex(), "now_ms": NOW + 899999}, "rid_conflict")
        case("rid_at_900s_new_record", "request_replay", bs, {**ba, "raw": env(1, 1, salt="new").hex(), "now_ms": NOW + 900000}, "queued")
        case("response_at_rid_expiry", "chunk", bs, {**ca, "now_ms": NOW + 900000}, "expired")
        chunks = {**bs, "chunks": {str(i): {"digest": "other", "expires_ms": NOW + 60000, "flags": 0} for i in range(63)}}
        chunks64 = case("chunk_64_allowed", "chunk", chunks, {**ca, "raw": env(2, 1, idx=63).hex()}, "stored")
        case("chunk_65_refused", "chunk", chunks64, {**ca, "raw": env(2, 1, idx=64).hex()}, "quota_exceeded")
        for count, want in ((32, "charged"), (63, "charged"), (64, "rate_limited")):
            case(f"certificate_quota_{count}", "quota", {**full_repeat, "total": count},
                 {**qu, "valid_signature": True, "revocation": False}, want)
        for count, want in ((63, cr["o"]["request_id"]), (64, "quota_exceeded")):
            many = {str(i): {**entry, "request": sign({**cr["o"], "workspace_id": R.fake("queue ws " + str(i))[:16].hex(), "request_id": R.fake("queue rid " + str(i))[:16].hex()})} for i in range(count)}
            case(f"open_request_limit_{count}", "request", many, rq, want)
        for lifetime, want in ((600000, cr["o"]["request_id"]), (600001, "expired")):
            case(f"request_lifetime_{lifetime}", "request", {}, {**rq, "signed": sign({**cr["o"], "created_ms": NOW, "expires_ms": NOW + lifetime})}, want)
        for reason in ("expired_certificate", "revoked_device", "superseded_revocation"):
            case(reason + "_no_quota_charge", "quota", full_repeat, {**qu, "valid_signature": True, "changes_state": False}, "unchanged")
        fa = {"card": v["card"]["card"], "owner_pk_pub": pub("person_alice"), "now_ms": NOW}
        first = case("first_card_charged_after_verification", "first_card", {}, fa, "stored")
        case("first_card_retry_free", "first_card", first, fa, "retry")
        for field in ("card", "delegation"):
            bad = copy.deepcopy(fa["card"])
            if field == "card":
                bad["sig"] = R.b64u(bytes(64))
            else:
                bad["delegation"]["sig"] = R.b64u(bytes(64))
            case("invalid_" + field + "_no_owner_charge", "first_card", {}, {**fa, "card": bad}, "bad_signature")
        dummy_sig = S.sign(S.sig_key(R.fake("P3 dummy verification key")), msg)
        case("valid_dummy_signature_still_401", "login", ls, {**la, "subject": None, "sig": dummy_sig.hex()}, "bad_signature")
        tokens = {str(i): {"kind": "device", "id": phone, "expires_ms": NOW + 1} for i in range(8)}
        case("device_token_cap_eight", "login", {**ls, "tokens": tokens}, la, "quota_exceeded")
        v["p3"] = {"cases": cases, "envelope_sizes": sizes, "objects": {"publication": body, "cert_rejection": rejection,
                    "request": cr, "challenge": ch, "cert": cert, "bridge_request": req.hex(), "bridge_response": resp.hex(),
                    "bridge_refusal": refusal.hex(), "login": {"challenge": R.b64u(challenge), "kind": "device", "id": phone, "sig": R.b64u(bytes.fromhex(la["sig"]))}}}
