"""P3-D39 (D39a1) Drop HTTP transcripts: PUT versions, list, descriptor pages, descriptor, wraps and blob.

Every expected answer comes from the reference model (ref/drop_relay.py) run on the case's preconditions:
`given.prior` (earlier requests, each answered 2xx, replayed first), `given.ops` (state changes without a
D39a1 route: a D39a2 retire or expiry sweep, a D39b claim, a pruned blob after a restore, another
workspace's object, a new list epoch, the clock) and `given.relay` (in-memory relay conditions: full slots, an
empty bucket, a session's device state). The upload frame is given as hex (`body_hex`); a blob answer as
`response.body_hex`. Public FAKE material only.
"""
import copy

from ref import drop_relay as M
from ref import orch_protocol_ref as R
from ref._drop_build import NOW, Builder

ROUTES = [
    ("drop_put", "PUT", "/v2/drop/{o}/versions", "client", "D(m)|W(g)",
     "401:bad_signature 409:version_conflict,stale_epoch,bad_wxk_version,rotation_required 410:expired "
     "428:precondition_required "
     "429:quota_exceeded,rate_limited 503:overloaded"),
    ("drop_list", "POST", "/v2/drop/list", "client", "D(m)|W", "429:quota_exceeded,rate_limited 503:overloaded"),
    ("drop_descriptors", "GET", "/v2/drop/{o}/descriptors", "client", "D(m)|W",
     "404:not_found 410:expired 429:quota_exceeded,rate_limited 503:overloaded"),
    ("drop_descriptor_get", "GET", "/v2/drop/{o}/versions/{v}/descriptor", "client", "D(m)|W",
     "404:not_found 410:expired 429:rate_limited"),
    ("drop_wraps_get", "GET", "/v2/drop/{o}/versions/{v}/wraps", "client", "D(m)|W",
     "404:not_found 410:expired 429:rate_limited"),
    ("drop_blob_get", "GET", "/v2/drop/{o}/versions/{v}/blob", "client", "D(m)|W",
     "404:not_found 410:expired 429:quota_exceeded,rate_limited 503:overloaded"),
    # D39a2 (amendment A1): the host's retire of a file or a document
    ("drop_retire", "POST", "/v2/drop/{o}/retire", "host", "W(g)", "404:not_found 409:version_conflict"),
]
NAMES = {r[0] for r in ROUTES}
PUT_CAP = 8 + M.MAX_HEAD + M.MAX_BLOB  # the whole-body maximum (413 for a declared length above it)
CAPS = {"drop_put": PUT_CAP, "drop_list": 16384, "drop_retire": 16384}
CONDITIONS = {
    "precondition_required": "If-Match is absent or not a decimal without leading zeros (or its quoted form).",
    "version_conflict": "The object's current version differs from If-Match, parent or version, or parent_hash "
                        "is not the hash of the current head.",
}
TOKENS = {}


def build(v):
    b = Builder(v)
    TOKENS.update({b.phone: "FAKE-device", b.laptop: "FAKE-laptop", b.ws: "FAKE-workspace", b.agent: "FAKE-agent"})
    base = M.initial_state(v, NOW)
    ph, lap, ws = b.phone, b.laptop, b.ws

    def headers(who, extra=None, json_body=False):
        h = {"Authorization": "Bearer " + TOKENS[who]}
        h["Content-Type"] = "application/json" if json_body else "application/octet-stream"
        if who == ws:
            h["Orch-Holder"] = "1"
        h.update(extra or {})
        return h

    def put_req(signed_body, who=ph, if_match="0", extra=None, query=None, body=None):
        signed, frame_ = signed_body
        h = headers(who, extra)
        if if_match is not None:
            h["If-Match"] = if_match
        return {"method": "PUT", "path": f"/v2/drop/{signed['o']['object_id']}/versions", "query": query or {},
                "headers": h, "body_hex": (frame_ if body is None else body).hex()}

    def get_req(o_id, what, who=ph, version=1, query=None):
        path = f"/v2/drop/{o_id}/descriptors" if what == "descriptors" else f"/v2/drop/{o_id}/versions/{version}/{what}"
        h = {"Authorization": "Bearer " + TOKENS[who]}
        return {"method": "GET", "path": path, "query": query or {}, "headers": h}

    def list_req(who=ph, **body):
        body = {"workspace_id": ws, "direction": "received", **body}
        return {"method": "POST", "path": "/v2/drop/list", "query": {}, "headers": headers(who, json_body=True)
                if who != ws else {**headers(who, json_body=True)}, "json": body}

    def retire_req(signed_body, who=ws, version=None, head=None, extra=None, body=None, query=None,
                   o_id=None):
        signed, _frame = signed_body
        o = signed["o"]
        payload = {"expect_version": o["version"] if version is None else version,
                   "expect_head": M.parent_hash(o) if head is None else head}
        if body is not None:
            payload = body
        return {"method": "POST", "path": f"/v2/drop/{o_id or o['object_id']}/retire", "query": query or {},
                "headers": headers(who, extra, json_body=True), "json": payload}

    def principal_of(request):
        token = request["headers"].get("Authorization", "")[7:]
        who = next(k for k, t in TOKENS.items() if t == token)
        return b.principal(who)

    def model(state, request):
        p = principal_of(request)
        path = request["path"].split("/")
        if request["method"] == "PUT":
            body = bytes.fromhex(request["body_hex"])
            length = int(request["headers"]["Content-Length"]) if "Content-Length" in request["headers"] else None
            return M.put(state, p, path[3], body.hex(), request["headers"].get("If-Match"),
                         request["headers"].get("Orch-Holder"), length)
        if len(path) > 4 and path[4] == "retire":
            return M.retire(state, p, path[3], request["json"], request["headers"].get("Orch-Holder"))
        if path[3] == "list":
            return M.list_page(state, p, request["json"])
        if path[4] == "descriptors":
            q = request["query"]
            return M.descriptors(state, p, path[3], int(q.get("after", "0")), int(q.get("limit", "256")))
        return M.read(state, p, path[3], int(path[5]), path[6])

    def case(name, request, prior=(), ops=(), relay=None, condition=None, response=None, scenario=None):
        state = copy.deepcopy(base)
        for p in prior:
            got = model(state, p)
            assert got["status"] in (200, 201), (name, got)
        for o in ops:
            M.apply(state, o)
        result = response or model(state, request)
        status = result["status"]
        resp = {"status": status, "headers": {"Content-Type": "application/json"}}
        if result.get("blob"):
            ver = state["versions"][f"{request['path'].split('/')[3]}/{request['path'].split('/')[5]}"]
            data = blob_of(ver)
            resp["headers"] = {"Content-Type": "application/octet-stream", "Content-Length": str(len(data)),
                               "ETag": f'"{ver["descriptor"]["o"]["version"]}"', "Cache-Control": "no-store"}
            resp["body_hex"] = data.hex()
        else:
            resp["json"] = result["json"]
            if status in (200, 201) and request["method"] == "PUT":
                resp["headers"]["ETag"] = f'"{result["json"]["version"]}"'
            if status == 200 and request["path"].endswith("/descriptor"):
                resp["headers"]["ETag"] = f'"{request["path"].split("/")[5]}"'
            if status in (429, 503):
                resp["headers"]["Retry-After"] = result.get("retry", "1")
        given = {"scenario": scenario or name, "now_ms": state["now_ms"],
                 "condition": condition or name.replace("_", " ")}
        if prior:
            given["prior"] = list(prior)
        if ops:
            given["ops"] = list(ops)
        if relay:
            given["relay"] = relay
        return {"name": name, "given": given, "request": request, "response": resp}

    blobs = {}

    def remember(signed_body):
        signed, frame_ = signed_body
        head_len = int.from_bytes(frame_[4:8], "big")
        blobs[R.cj(signed["o"])] = frame_[8 + head_len:]
        return signed_body

    def blob_of(ver):
        return blobs[R.cj(ver["descriptor"]["o"])]

    def up(label, **kw):
        return remember(b.upload(label, **kw))

    out = {}
    m = {"error": "malformed"}

    def generic(name, request, prior=(), json_route=False):
        """The common refusals of every authenticated route (§19.6)."""
        cs = []
        q = copy.deepcopy(request)
        q["query"] = {**q["query"], "unexpected": "1"}
        cs.append(case("refusal_400_malformed", q, prior, response={"status": 400, "json": m}))
        q = copy.deepcopy(request)
        q["headers"].pop("Authorization")
        cs.append(case("refusal_401_unauthenticated", q, prior, response={"status": 401, "json": {"error": "unauthenticated"}}))
        cs.append(case("refusal_403_not_eligible", copy.deepcopy(request), prior, relay={"device": "drop_scoped"},
                       condition="A drop: scoped device (P6) is refused on every Drop route.",
                       response={"status": 403, "json": {"error": "not_eligible"}}))
        cs.append(case("refusal_400_cert_expired", copy.deepcopy(request), prior, relay={"device": "cert_expired"},
                       response={"status": 400, "json": {"error": "cert_expired"}}))
        cs.append(case("refusal_403_revoked", copy.deepcopy(request), prior, relay={"device": "revoked"},
                       response={"status": 403, "json": {"error": "revoked"}}))
        cs.append(case("refusal_429_rate_limited", copy.deepcopy(request), prior, relay={"bucket": "empty"},
                       condition="The session's read bucket (P3-D35) has no token left; burst 1, 1 per minute.",
                       response={"status": 429, "json": {"error": "rate_limited"}, "retry": "60"}))
        return cs

    # --- PUT -------------------------------------------------------------------------------------------
    file_ = up("fx put")
    ok = put_req(file_)
    cs = [case("success", ok, condition="A member phone with operate uploads a file to its workspace.")]
    cs.append(case("exact_retry", ok, prior=[ok], condition="The same descriptor o is stored at this version: 200 "
                                                          "before the CAS, the blob never read."))
    cs += generic("drop_put", ok)
    q = put_req(file_, if_match=None)
    cs.append(case("refusal_428_precondition_required", q))
    cs.append(case("if_match_with_a_leading_zero", put_req(file_, if_match="00")))
    cs.append(case("if_match_quoted", put_req(file_, if_match='"0"')))
    d1 = up("fx doc", kind="document")
    d1b = up("fx doc", kind="document", content=b"another version 1")
    cs.append(case("refusal_409_version_conflict", put_req(d1b), prior=[put_req(d1)]))
    d2 = up("fx doc", kind="document", version=2, parent=d1[0]["o"], author=lap)
    cs.append(case("next_version_by_another_member", put_req(d2, lap, "1"), prior=[put_req(d1)]))
    cs.append(case("refusal_409_stale_epoch", put_req(up("fx epoch")), ops=[{"op": "epoch", "epoch": 2}],
                   condition="A removal published list epoch 2; the wk wrap names epoch 1."))
    cs.append(case("same_dek_rewrapped_at_the_new_epoch",
                   put_req(up("fx epoch", wraps=lambda o: [b.wrap(o, "wk", key_version=2)])),
                   ops=[{"op": "epoch", "epoch": 2}]))
    cs.append(case("refusal_409_rotation_required", put_req(up("fx rotation")), ops=[{"op": "rotation_due"}],
                   condition="A revocation's rotation_due row is open: a wk wrap is refused until the host rotates "
                             "(owner question 6); 409 with the current epoch."))
    cs.append(case("rotation_due_does_not_refuse_a_wk_less_inbox_upload",
                   put_req(up("fx rotation inbox", recipients="inbox")), ops=[{"op": "rotation_due"}]))
    cs.append(case("refusal_409_bad_wxk_version",
                   put_req(up("fx wxk", wraps=lambda o: [b.wrap(o, "wk"), b.wrap(o, "wxk", key_version=2)]))))
    host = up("fx host", author=ws)
    cs.append(case("refusal_409_fenced", put_req(host, ws, extra={"Orch-Holder": "0"}),
                   condition="A stale host: holder generation 1 is current, the request names 0."))
    cs.append(case("host_upload", put_req(host, ws)))
    cs.append(case("inbox_with_a_wk_wrap", put_req(up("fx inbox wk", recipients="inbox",
                                                       wraps=lambda o: [b.wrap(o, "wxk"), b.wrap(o, "wk")]))))
    cs.append(case("inbox_with_the_authors_device_wrap", put_req(up(
        "fx inbox", recipients="inbox", wraps=lambda o: [b.wrap(o, "wxk"), b.wrap(o, "device", ph)]))))
    cs.append(case("refusal_429_quota_exceeded", ok, relay={"upload_slots": "device"},
                   condition="The device already holds its 2 upload slots.",
                   response={"status": 429, "json": {"error": "quota_exceeded", "quota": "slot"}}))
    cs.append(case("refusal_503_overloaded", ok, relay={"upload_slots": "relay"},
                   condition="All 16 relay-wide upload slots are held.",
                   response={"status": 503, "json": {"error": "overloaded"}}))
    # D39a2 (P3-D39 item 8): stored-bytes caps (429 `quota_exceeded` naming the cap, Retry-After 600:
    # not transient), a global ceiling (503, Retry-After 600), the MiB upload bucket and the daily
    # version-1 creation counters (Retry-After the seconds to 00:00 UTC of the relay's clock).
    for name, scope, field, quota, cond in (
            ("device_share", "device", "blob", "drop_device",
             "The device's blob share in this workspace (256 MiB) is full."),
            ("workspace_bytes", "workspace", "blob", "drop_ws", "The workspace's 512 MiB of blobs are full."),
            ("workspace_head_bytes", "workspace", "head", "drop_head_ws",
             "The workspace's 32 MiB of descriptor and wrap bytes are full."),
            ("account_bytes", "account", "blob", "drop_account",
             "The owner account's 1 GiB of blobs is full.")):
        cs.append(case("refusal_429_quota_exceeded_" + name, ok, relay={"usage": {"scope": scope, "field": field}},
                       condition=cond + " Not transient: it stays until expiry, pruning or a retire frees usage.",
                       response={"status": 429, "json": {"error": "quota_exceeded", "quota": quota},
                                 "retry": "600"}))
    cs.append(case("refusal_503_overloaded_global_ceiling", ok, relay={"usage": {"scope": "global", "field": "blob"}},
                   condition="The relay-wide blob ceiling (ORCH_RELAY_DROP_GLOBAL_BYTES) is reached.",
                   response={"status": 503, "json": {"error": "overloaded"}, "retry": "600"}))
    cs.append(case("refusal_429_rate_limited_upload_bucket", ok, relay={"bucket": "drop_up_empty"},
                   condition="The device's upload bucket (one token per started MiB; burst 1, 1 per minute) is empty.",
                   response={"status": 429, "json": {"error": "rate_limited"}, "retry": "60"}))
    midnight = max(1, min(86_400, -(-(86_400_000 - NOW % 86_400_000) // 1000)))
    cs.append(case("refusal_429_rate_limited_creations", ok, relay={"creations": "device_full"},
                   condition="The device has made its 250 version-1 creations of this UTC day; Retry-After is "
                             "the seconds to 00:00 UTC.",
                   response={"status": 429, "json": {"error": "rate_limited", "quota": "drop_creations"},
                             "retry": str(midnight)}))
    foreign = b.oid("fx foreign")
    cs.append(case("another_space", put_req(up(foreign)),
                   ops=[{"op": "foreign_object", "object_id": foreign, "workspace_id": b.ws_b}]))
    inbox = up("fx claimed", recipients="inbox")
    cs.append(case("claimed_object", put_req(up("fx claimed", recipients="inbox", content=b"other")),
                   prior=[put_req(inbox)], ops=[{"op": "claim", "object_id": inbox[0]["o"]["object_id"],
                                                 "workspace_id": ws}]))
    hid = up("fx hidden", author=ws, recipients=[lap])
    mine = up(hid[0]["o"]["object_id"], recipients=[lap])
    cs.append(case("outside_a_device_only_audience", put_req(mine), prior=[put_req(hid, ws)]))
    cs.append(case("outside_a_device_only_audience_retired", put_req(mine), prior=[put_req(hid, ws)],
                   ops=[{"op": "retire", "object_id": hid[0]["o"]["object_id"]}]))
    cs.append(case("recipients_empty", put_req(up("fx empty", recipients=[]))))
    cs.append(case("file_expiring_in_under_60_s", put_req(up("fx floor", expires=NOW + 59_999))))
    own = up("fx own", recipients=[lap], expires=NOW + 120_000)
    later = NOW + 120_000
    cs.append(case("expired_device_only_file_by_its_author_before_the_sweep", put_req(own), prior=[put_req(own)],
                   ops=[{"op": "clock", "now_ms": later}]))
    cs.append(case("expired_device_only_file_by_its_author_after_the_sweep", put_req(own), prior=[put_req(own)],
                   ops=[{"op": "clock", "now_ms": later}, {"op": "expire_sweep",
                                                           "object_id": own[0]["o"]["object_id"]}]))
    cs.append(case("refusal_401_bad_signature", put_req(up("fx forged", sign_as="laptop")),
                   condition="The phone's descriptor signed with another device's key."))
    s0, f0 = file_
    head_len = int.from_bytes(f0[4:8], "big")
    cs.append(case("bad_frame_magic", put_req(file_, body=b"ODU1" + f0[4:])))
    cs.append(case("content_length_not_the_frame", put_req(file_, extra={"Content-Length": str(len(f0) + 1)}),
                   condition="Content-Length is one byte above the frame (a short blob)."))
    long_ = up("fx long", data=lambda blob: blob + b"\0")
    cs.append(case("blob_one_byte_long_for_its_descriptor", put_req(long_)))

    def rehashed(label, mutate):
        signed, blob = b.descriptor(b.oid(label))
        blob = mutate(blob)
        o = {**signed["o"], "content_len": len(blob), "content_hash": R.b64u(R.H(blob))}
        signed = R.sign_object(R.SUITES[2], b.key("phone"), o)
        return remember((signed, M.frame({"descriptor": signed, "wraps": b.default_wraps(o)}, blob)))

    cs.append(case("wrong_content_hash", put_req(up("fx hash", data=lambda blob: blob[:-1] + bytes([blob[-1] ^ 1])))))
    cs.append(case("not_an_ord2_header", put_req(rehashed("fx ord3", lambda blob: b"ORD3" + blob[4:]))))
    cs.append(case("descriptor_over_96_kib", put_req(up("fx big", meta=R.b64u(b"m" * M.MAX_META),
                                                        recipients=sorted(R.fake(f"r{i}")[:16].hex() for i in range(300))))))
    cs.append(case("meta_over_its_cap", put_req(up("fx meta", meta=R.b64u(b"m" * (M.MAX_META + 1))))))
    cs.append(case("foreign_wxk_target", put_req(up("fx fwxk", wraps=lambda o: [b.wrap(o, "wk"),
                                                                                b.wrap(o, "wxk", target=b.ws_b)]))))
    cs.append(case("foreign_recipients_id", put_req(up("fx frec", recipients=sorted([ws, b.ws_b])))))
    cs.append(case("document_with_an_expiry", put_req(up("fx dexp", kind="document", expires_ms=NOW + 100_000))))
    cs.append(case("inbox_document", put_req(up("fx idoc", kind="document", recipients="inbox"))))
    tomb = up("fx tomb")
    cs.append(case("refusal_410_expired", put_req(up("fx tomb", content=b"new")), prior=[put_req(tomb)],
                   ops=[{"op": "retire", "object_id": tomb[0]["o"]["object_id"]}],
                   condition="The id is a retired tombstone (D39a2 retire)."))
    cs.append(case("tombstoned_exact_retry", put_req(tomb), prior=[put_req(tomb)],
                   ops=[{"op": "retire", "object_id": tomb[0]["o"]["object_id"]}]))
    cs.append(case("expires_ms_passed", put_req(up("fx past", expires=NOW))))
    over_head = b"ODU2" + (M.MAX_HEAD + 1).to_bytes(4, "big")
    q = put_req(file_)
    q.pop("body_hex")
    q["body_recipe"] = {"prefix_b64u": R.b64u(over_head), "byte": 32, "count": M.MAX_HEAD + 1, "suffix_b64u": ""}
    cs.append(case("head_over_512_kib", q, response={"status": 413, "json": {"error": "too_large"}}))
    q = put_req(file_)
    q.pop("body_hex")
    q["body_recipe"] = {"prefix_b64u": "", "byte": 32, "count": PUT_CAP + 1, "suffix_b64u": ""}
    cs.append(case("refusal_413_too_large", q, response={"status": 413, "json": {"error": "too_large"}},
                   condition="The declared Content-Length is one byte above 8 + 512 KiB + 26 MiB; nothing is read."))
    out["drop_put"] = cs

    # --- retire (D39a2, amendment A1) ------------------------------------------------------------------
    rf = up("fx retire")
    up_rf = put_req(rf)
    rt = retire_req(rf)
    cs = [case("success", rt, prior=[up_rf],
               condition="The host retires a file the phone uploaded, naming the version and head it decided about.")]
    cs.append(case("retire_a_document", retire_req(d1), prior=[put_req(d1)],
                   condition="A document is tombstoned at once; its versions are released by the batched sweeper."))
    claimed = up("fx retire claimed", recipients="inbox")
    cs.append(case("retire_a_claimed_inbox_file", retire_req(claimed), prior=[put_req(claimed)],
                   ops=[{"op": "claim", "object_id": claimed[0]["o"]["object_id"], "workspace_id": ws}]))
    cs.append(case("idempotent_retry", rt, prior=[up_rf, rt],
                   condition="Same expect_version and expect_head against the tombstone: 200 with its state, "
                             "nothing changed and no new n (only while the tombstone lives)."))
    cs.append(case("a_file_the_sweep_expired_answers_expired", rt, prior=[up_rf],
                   ops=[{"op": "expire_sweep", "object_id": rf[0]["o"]["object_id"]}]))
    cs.append(case("refusal_409_version_conflict", retire_req(rf, version=2), prior=[up_rf],
                   condition="The host decided about another version than the newest (a member wrote meanwhile)."))
    cs.append(case("refusal_409_version_conflict_head", retire_req(rf, head=R.b64u(b"\x01" * 32)), prior=[up_rf],
                   condition="The version matches but the head hash is not the stored head."))
    cs.append(case("version_conflict_against_the_tombstone", retire_req(rf, version=2), prior=[up_rf, rt],
                   condition="The precondition is checked against a tombstone too; the body names state retired."))
    cs.append(case("refusal_404_not_found", retire_req(rf), condition="No such object id."))
    cs.append(case("refusal_403_not_eligible", retire_req(rf, ph), prior=[up_rf],
                   condition="Only the host (a W session) retires; a member device, even the uploader, gets 403."))
    foreign_r = b.oid("fx retire foreign")
    cs.append(case("another_space", retire_req(rf, o_id=foreign_r), prior=[up_rf],
                   ops=[{"op": "foreign_object", "object_id": foreign_r, "workspace_id": b.ws_b}],
                   condition="The id belongs to another workspace: 403, never 404."))
    cs.append(case("refusal_409_fenced", retire_req(rf, extra={"Orch-Holder": "0"}), prior=[up_rf],
                   condition="A stale host: holder generation 1 is current, the request names 0."))
    q = retire_req(rf)
    q["headers"].pop("Authorization")
    cs.append(case("refusal_401_unauthenticated", q, prior=[up_rf],
                   response={"status": 401, "json": {"error": "unauthenticated"}}))
    cs.append(case("refusal_400_malformed", retire_req(rf, query={"unexpected": "1"}), prior=[up_rf],
                   response={"status": 400, "json": m}))
    good_head = M.parent_hash(rf[0]["o"])
    for label, body in (
            ("missing_expect_head", {"expect_version": 1}),
            ("extra_field", {"expect_version": 1, "expect_head": good_head, "force": True}),
            ("expect_version_zero", {"expect_version": 0, "expect_head": good_head}),
            ("expect_version_a_string", {"expect_version": "1", "expect_head": good_head}),
            ("expect_head_padded", {"expect_version": 1, "expect_head": good_head + "="}),
            ("expect_head_31_bytes", {"expect_version": 1, "expect_head": R.b64u(b"\x01" * 31)})):
        cs.append(case("malformed_" + label, retire_req(rf, body=body), prior=[up_rf]))
    big = retire_req(rf)
    big.pop("json")
    big["body_recipe"] = {"prefix_b64u": "", "byte": 32, "count": CAPS["drop_retire"] + 1, "suffix_b64u": ""}
    cs.append(case("refusal_413_too_large", big, prior=[up_rf], response={"status": 413, "json": {"error": "too_large"}},
                   condition="The body is one byte above the 16 KiB JSON cap: refused before parsing."))
    out["drop_retire"] = cs

    # --- reads --------------------------------------------------------------------------------------------
    a = up("fx a")                                   # phone, to the space
    bl = up("fx b", author=lap)                      # laptop, to the space
    hb = up("fx c", author=ws, recipients=[lap])     # host, device-only (the laptop)
    ib = up("fx d", recipients="inbox", wraps=lambda o: [b.wrap(o, "wxk"), b.wrap(o, "device", ph)])
    wide = up("fx e", wraps=lambda o: [b.wrap(o, "wk"), b.wrap(o, "wxk"), b.wrap(o, "device", ph),
                                       b.wrap(o, "device", lap)])
    world = [put_req(a), put_req(bl, lap), put_req(hb, ws), put_req(ib), put_req(wide)]
    oid = {k: x[0]["o"]["object_id"] for k, x in {"a": a, "b": bl, "c": hb, "d": ib, "e": wide}.items()}

    cs = [case("success", list_req(lap), prior=world,
               condition="The laptop lists what others wrote: positions ascending, its usable wraps, the "
                         "unclaimed inbox item listed (no wrap a device can open), claimed_by in every entry.")]
    cs += generic("drop_list", list_req(lap), prior=world)
    cs.append(case("sending", list_req(ph, direction="sending"), prior=world))
    cs.append(case("device_outside_the_audience", list_req(ph), prior=world,
                   condition="The host's device-only object for the laptop is not listed for the phone."))
    cs.append(case("workspace_session", list_req(ws), prior=world,
                   condition="A W session sees every object of its workspace with its wk and wxk wraps."))
    cs.append(case("first_page", list_req(lap, limit=1), prior=world))
    cs.append(case("after_the_last_position", list_req(lap, after=5), prior=world))
    cs.append(case("states", list_req(lap), prior=world + [put_req(up("fx exp", expires=NOW + 120_000))],
                   ops=[{"op": "retire", "object_id": oid["b"]}, {"op": "prune", "object_id": oid["e"]},
                        {"op": "clock", "now_ms": NOW + 120_000}],
                   condition="b retired (D39a2), e's blob pruned after a restore (the start-up sweep), the "
                             "new file expired before the sweep: tombstones with descriptor null and wraps []."))
    cs.append(case("an_after_list_sees_a_retire", list_req(lap, after=5), prior=world,
                   ops=[{"op": "retire", "object_id": oid["a"]}]))
    cs.append(case("retired_hidden_tombstone_not_listed", list_req(ph), prior=world,
                   ops=[{"op": "retire", "object_id": oid["c"]}]))
    q = list_req(lap)
    q.pop("json")
    q["body_recipe"] = {"prefix_b64u": "", "byte": 32, "count": 16385, "suffix_b64u": ""}
    cs.append(case("refusal_413_too_large", q, response={"status": 413, "json": {"error": "too_large"}}))
    cs.append(case("refusal_429_quota_exceeded", list_req(lap), relay={"read_slots": "device"},
                   response={"status": 429, "json": {"error": "quota_exceeded", "quota": "slot"}},
                   condition="The device holds its 2 list or descriptor-page read slots."))
    cs.append(case("refusal_503_overloaded", list_req(lap), relay={"read_slots": "relay"},
                   response={"status": 503, "json": {"error": "overloaded"}}))
    cs.append(case("other_workspace", list_req(ph, workspace_id=b.ws_b)))
    out["drop_list"] = cs

    docs = []
    parent = None
    for ver in range(1, 4):
        s = up("fx chain", kind="document", version=ver, parent=parent)
        docs.append(put_req(s, if_match=str(ver - 1)))
        parent = s[0]["o"]
    chain = docs[0]["path"].split("/")[3]
    cs = [case("success", get_req(chain, "descriptors"), prior=docs)]
    cs += generic("drop_descriptors", get_req(chain, "descriptors"), prior=docs)
    cs.append(case("first_page", get_req(chain, "descriptors", query={"limit": "2"}), prior=docs))
    cs.append(case("next_page", get_req(chain, "descriptors", query={"after": "2", "limit": "2"}), prior=docs))
    cs.append(case("refusal_404_not_found", get_req(b.oid("fx absent"), "descriptors")))
    cs.append(case("not_visible", get_req(oid["c"], "descriptors"), prior=world))
    cs.append(case("refusal_410_expired", get_req(chain, "descriptors"), prior=docs,
                   ops=[{"op": "retire", "object_id": chain}]))
    cs.append(case("refusal_429_quota_exceeded", get_req(chain, "descriptors"), prior=docs,
                   relay={"read_slots": "device"},
                   response={"status": 429, "json": {"error": "quota_exceeded", "quota": "slot"}}))
    cs.append(case("refusal_503_overloaded", get_req(chain, "descriptors"), prior=docs, relay={"read_slots": "relay"},
                   response={"status": 503, "json": {"error": "overloaded"}}))
    out["drop_descriptors"] = cs

    for name, what in (("drop_descriptor_get", "descriptor"), ("drop_wraps_get", "wraps"), ("drop_blob_get", "blob")):
        target = oid["e"] if what != "descriptor" else oid["a"]
        cs = [case("success", get_req(target, what, lap), prior=world)]
        cs += generic(name, get_req(target, what, lap), prior=world)
        cs.append(case("refusal_404_not_found", get_req(b.oid("fx absent"), what)))
        cs.append(case("version_absent", get_req(target, what, version=2), prior=world))
        cs.append(case("foreign_object", get_req(foreign, what),
                       ops=[{"op": "foreign_object", "object_id": foreign, "workspace_id": b.ws_b}]))
        cs.append(case("not_visible_any_version", get_req(oid["c"], what, version=7), prior=world))
        cs.append(case("not_visible_tombstone", get_req(oid["c"], what), prior=world,
                       ops=[{"op": "retire", "object_id": oid["c"]}]))
        cs.append(case("refusal_410_expired", get_req(target, what, version=9), prior=world,
                       ops=[{"op": "retire", "object_id": target}],
                       condition="Retired (D39a2): 410 before the absent version's 404."))
        own_get = [put_req(own)]
        cs.append(case("expired_device_only_audience_before_the_sweep", get_req(own[0]["o"]["object_id"], what, lap),
                       prior=own_get, ops=[{"op": "clock", "now_ms": later}]))
        cs.append(case("expired_device_only_audience_after_the_sweep", get_req(own[0]["o"]["object_id"], what, lap),
                       prior=own_get, ops=[{"op": "clock", "now_ms": later},
                                           {"op": "expire_sweep", "object_id": own[0]["o"]["object_id"]}]))
        cs.append(case("expired_device_only_workspace_after_the_sweep",
                       get_req(own[0]["o"]["object_id"], what, ws), prior=own_get,
                       ops=[{"op": "clock", "now_ms": later},
                            {"op": "expire_sweep", "object_id": own[0]["o"]["object_id"]}]))
        if what == "wraps":
            cs.append(case("device_view", get_req(oid["e"], what, ph), prior=world))
            cs.append(case("workspace_view", get_req(oid["e"], what, ws), prior=world))
            cs.append(case("unclaimed_inbox", get_req(oid["d"], what, lap), prior=world))
        if what == "blob":
            cs.append(case("unclaimed_inbox", get_req(oid["d"], what, lap), prior=world))
            cs.append(case("claimed_inbox", get_req(oid["d"], what, lap), prior=world,
                           ops=[{"op": "claim", "object_id": oid["d"], "workspace_id": ws}]))
            cs.append(case("pruned_blob", get_req(oid["e"], what, lap), prior=world,
                           ops=[{"op": "prune", "object_id": oid["e"]}]))
            cs.append(case("refusal_429_quota_exceeded", get_req(target, what, lap), prior=world,
                           relay={"download_slots": "device"},
                           response={"status": 429, "json": {"error": "quota_exceeded", "quota": "slot"}}))
            cs.append(case("refusal_503_overloaded", get_req(target, what, lap), prior=world,
                           relay={"download_slots": "relay"}, response={"status": 503, "json": {"error": "overloaded"}}))
        if what == "descriptor":
            cs.append(case("unclaimed_inbox", get_req(oid["d"], what, lap), prior=world))
        out[name] = cs
    return out


def enrich(output, v):
    built = build(v)
    for name, cases in built.items():
        output[name]["cases"] = cases
    return output
