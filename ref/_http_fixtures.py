"""Generate exact HTTP examples. No live server, no private keys. Run python -m ref._http_fixtures.

Route-specific refusals plus the common §19.6 refusals are expanded into every fixture. Conditions
are scenario preconditions, not wire fields. State-machine vectors separately specify the state.
"""
import copy
import json
from pathlib import Path

from ref import orch_protocol_ref as R
from ref import _checkpoint_http as CP

# Separate role rows share a path but have distinct auth, body and response semantics.
# id, method, path, role, auth, route-specific status/code pairs
ROUTES = [
    ("session_challenge", "POST", "/v2/session/challenge", "client", "none", "429:rate_limited"),
    ("session_login", "POST", "/v2/session/login", "client", "none", "400:cert_expired,cert_invalid 401:unknown_challenge,expired,bad_signature 403:revoked 429:quota_exceeded"),
    ("session_logout", "POST", "/v2/session/logout", "client", "logout", ""),
    ("accounts", "POST", "/v2/accounts", "client", "none", "400:cert_invalid 401:bad_signature,unknown_challenge,expired 403:not_eligible,revoked 409:account_exists"),
    ("device_put", "PUT", "/v2/devices/{device}", "client", "none", "400:cert_invalid,cert_expired 403:revoked,other_person 409:cert_conflict 429:rate_limited"),
    ("device_get", "GET", "/v2/devices/{device}", "client", "D(p)|W", "403:not_eligible 404:not_found"),
    ("revocations_post", "POST", "/v2/revocations", "client", "none", "401:bad_signature 403:other_person 429:rate_limited"),
    ("revocation_get", "GET", "/v2/devices/{device}/revocation", "client", "none", "404:not_found 429:rate_limited"),
    ("revocation_feed", "GET", "/v2/persons/{person}/revocations", "client", "D(p)|W", "403:not_eligible"),
    ("card_put", "PUT", "/v2/workspaces/{ws}/card", "host", "first|W(g)", "400:wrong_suite,delegation_mismatch 401:bad_signature 403:other_person 409:other_workspace,wsk_changed,delegation_changed,stale_card,wxk_changed_without_version,bad_wxk_version 429:rate_limited"),
    ("card_get", "GET", "/v2/workspaces/{ws}/card", "client", "D(m)|W", "403:not_eligible 404:not_found"),
    ("membership", "PUT", "/v2/workspaces/{ws}/membership", "host", "W(g)", "400:cert_invalid 401:bad_signature 403:revoked,other_person,scope_exceeded,cert_expired,not_for_this_device 409:other_workspace,stale_list,bad_epoch,rotation_required,wk_commit_changed,missing_grant,grant_conflict,stale_card,wrap_conflict,fenced"),
    ("card_keys", "PUT", "/v2/workspaces/{ws}/card-keys", "host", "W(g)", "403:not_eligible,not_for_this_device 409:stale_card,wrap_conflict,fenced"),
    ("grants", "GET", "/v2/workspaces/{ws}/grants", "device", "D(m)", "403:not_eligible 404:not_found"),
    ("members", "GET", "/v2/workspaces/{ws}/members", "client", "D(m)|W", "403:not_eligible 404:not_found"),
    ("card_key", "GET", "/v2/workspaces/{ws}/card-key", "device", "D(m)", "403:not_eligible 404:not_found"),
    ("bridge_device_post", "POST", "/v2/workspaces/{ws}/bridge/{rid}", "device", "D(m)", "400:wrong_suite 403:not_for_this_device,not_eligible,revoked 409:rid_conflict,stale_epoch,retry_exhausted 429:rate_limited,quota_exceeded 503:overloaded"),
    ("bridge_device_poll", "GET", "/v2/workspaces/{ws}/bridge/{rid}", "device", "D(m)", "401:unauthenticated 403:not_eligible 429:quota_exceeded 503:overloaded"),
    ("host_hold", "POST", "/v2/workspaces/{ws}/host/hold", "host", "W", "409:holder_conflict,fenced"),
    ("host_poll", "GET", "/v2/workspaces/{ws}/host/poll", "host", "W(g)", "409:fenced 401:unauthenticated 503:overloaded"),
    ("bridge_host_post", "POST", "/v2/workspaces/{ws}/bridge/{rid}", "host", "W(g)", "400:wrong_suite 403:not_eligible,revoked 409:chunk_conflict,stale_epoch,fenced,retry_exhausted 410:expired 429:rate_limited,quota_exceeded 503:overloaded"),
    ("pair_device_post", "POST", "/v2/workspaces/{ws}/pair/{offer}/{rid}", "device", "none", "400:wrong_suite 401:unknown_workspace 429:rate_limited,quota_exceeded 503:overloaded"),
    ("pair_host_post", "POST", "/v2/workspaces/{ws}/pair/{offer}/{rid}", "host", "W(g)", "400:wrong_suite 401:unknown_workspace 429:rate_limited,quota_exceeded 503:overloaded"),
    ("pair_poll", "GET", "/v2/workspaces/{ws}/pair/{offer}/{rid}", "device", "none", "429:rate_limited 503:overloaded"),
    ("cert_requests_post", "POST", "/v2/persons/{person}/cert-requests", "host", "W(g)", "401:bad_signature 403:other_person,not_for_this_device 409:request_open,replayed,other_workspace 410:expired 429:quota_exceeded"),
    ("cert_requests_poll", "GET", "/v2/persons/{person}/cert-requests", "primary", "D(p)", "403:not_eligible 429:quota_exceeded 503:overloaded"),
    ("cert_challenge", "POST", "/v2/cert-requests/{id}/challenge", "primary", "D(p)", "401:bad_signature 403:other_person,not_for_this_device 409:replayed,other_workspace,already_signed 410:expired 404:not_found"),
    ("cert_rejection", "POST", "/v2/cert-requests/{id}/rejection", "primary", "D(p)", "401:bad_signature 403:other_person,not_for_this_device 409:already_signed,replayed,other_workspace 410:expired 404:not_found"),
    ("cert_request_get", "GET", "/v2/cert-requests/{id}", "host", "W", "404:not_found"),
]

ROUTES += CP.ROUTES

CONDITIONS = {
    "malformed": "Unknown query parameter; strict route parsing refuses before dispatch.",
    "too_large": "Whole HTTP body is exactly one byte above this route's published cap; refuse before parsing.",
    "wrong_suite": "Instance configured for suite 2 receives the supplied suite-1 object/header; suite gate precedes context checks.",
    "cert_invalid": "Directory certificate validation fails (certificate absent, invalid shape, key or PK binding).",
    "cert_expired": "Device certificate expires at the request-time clock; session admission or publication recheck fails.",
    "unknown_challenge": "Challenge is absent from the relay's outstanding challenge set (also after prior use).",
    "expired": "Challenge or non-terminal cert request expires at now_ms; challenges are consumed.",
    "bad_signature": "Trusted directory verification key differs from the artifact's signing key; artifact remains valid under its fixture key.",
    "revoked": "The authenticated or publication-target device has a verified permanent revocation in the directory.",
    "not_eligible": "Principal fails current membership/person/workspace gate; for account creation, invite is unknown, used or expired.",
    "not_for_this_device": "Authenticated device/addressee differs from the header or request target; for grants/wraps, target is outside the proposed list.",
    "other_person": "No account for the signed person, or certificate/request person is neither owner nor authorized person.",
    "account_exists": "Person account exists under a different request digest; this is not an exact retry.",
    "cert_conflict": "A certificate with different canonical content is already committed for this device id.",
    "delegation_mismatch": "The supplied card's delegation binds a different workspace or WSK than its card.",
    "other_workspace": "Authenticated/route workspace differs from the signed object's workspace.",
    "wsk_changed": "Held card has another WSK; replacement is forbidden.",
    "delegation_changed": "Held card's delegation differs from this card's delegation.",
    "stale_card": "Card sequence is behind held state (or an unequal card at the same sequence); wraps name an old card sequence.",
    "wxk_changed_without_version": "Held card has this WXK version but a different exchange key.",
    "bad_wxk_version": "Held card's WXK version does not allow the submitted version/key transition.",
    "scope_exceeded": "Member scopes exceed its certificate's prefix or certificate is a scoped agent.",
    "stale_list": "Held member-list sequence is at least this sequence, and bytes differ from any committed publication retry.",
    "bad_epoch": "Proposed epoch is outside 1..2^16 for a first list, or below the held epoch, or above it by more than 2^16.",
    "rotation_required": "A device is removed but the submitted epoch is not above the held epoch.",
    "wk_commit_changed": "Held list has the same epoch and another wk_commit; one WK per epoch, ever (G2b).",
    "missing_grant": "Publication omits a proposed member's grant at its epoch.",
    "wrap_conflict": "A different wrap is committed for the same device and card sequence.",
    "grant_conflict": "Another sealed grant is committed for this device and epoch; this is not an exact publication retry.",
    "fenced": "Current holder generation is 1; header generation 0 has no write authority (hold uses stale gen).",
    "rid_conflict": "Replay record for this workspace/device/rid has another full-envelope digest.",
    "stale_epoch": "New request epoch differs from current epoch 2, or response fails the known-rid/request-epoch/old-chunk rule.",
    "retry_exhausted": "Known identical rid has no undelivered copy and has used eight requeues; terminal exhaustion.",
    "holder_conflict": "An unexpired holder exists and gen is null with take_over false.",
    "chunk_conflict": "The same workspace/device/rid/chunk index has another stored envelope digest.",
    "unknown_workspace": "No card exists for the route workspace.",
    "request_open": "Another unexpired open or challenged certificate request exists for the workspace.",
    "replayed": "Request id is bound to other bytes, challenge replacement was attempted, or request was rejected.",
    "already_signed": "Certificate request is signed; this challenge/rejection is not an exact prior retry.",
    "not_found": "Authorized resource is absent, or certificate request retention has ended.",
    "unauthenticated": "Authorization header is absent; no valid bearer session.",
    "rate_limited": "Applicable full-duration address/person rate window or outstanding challenge cap is full.",
    "quota_exceeded": "Applicable device/workspace storage, concurrent poll, chunk or open-request cap is full.",
    "overloaded": "Global queued-body or concurrent-poll budget is full; existing state is not evicted.",
}


CONDITIONS.update(CP.CONDITIONS)

# (G0a review 2) Whole JSON body caps, enforced before parsing.
JSON_CAPS = {r[0]: (2097152 if r[0] == "membership" else 65536 if r[0] in
             {"accounts", "card_put", "card_keys", "cert_requests_post"} else 16384)
             for r in ROUTES if r[1] in {"POST", "PUT"} and r[0] not in
             {"bridge_device_post", "bridge_host_post", "pair_device_post", "pair_host_post"}}
JSON_CAPS.update(CP.CAPS)
BODY_CAPS = {**JSON_CAPS, "bridge_device_post": 1048576, "bridge_host_post": 262144,
             "pair_device_post": 65536, "pair_host_post": 65536}


def refusals(row):
    name, method, _, _, auth, spec = row
    result = {(400, "malformed")}
    if name in BODY_CAPS:
        result.add((413 if name in JSON_CAPS and name != "checkpoint_put" else 400, "too_large"))
    if auth not in ("none", "logout"):
        result |= {(401, "unauthenticated"), (403, "not_eligible")}
        if "D(" in auth:
            result |= {(400, "cert_expired"), (403, "revoked")}
    if "W(g)" in auth:
        result.add((409, "fenced"))
    if name in {"accounts", "device_put", "revocations_post", "membership", "card_put", "cert_requests_post", "cert_challenge", "cert_rejection"}:
        result.add((400, "wrong_suite"))
    for group in spec.split():
        status, codes = group.split(":")
        result.update((int(status), c) for c in codes.split(","))
    return sorted(result)


def condition_for(name, code):
    """(G0a review 6) Describe this route's gate, not unrelated routes' preconditions."""
    if code == "not_eligible":
        return {"accounts": "Invite is unknown, used or expired.",
                "device_get": "W workspace has never admitted this person or device.",
                "revocation_feed": "Requested person is not in the W workspace's ever_persons."}.get(name, f"Principal lacks the person or workspace authority required by {name}.")
    if code == "cert_expired":
        return "A proposed member certificate has expired; publication is refused with 403." if name == "membership" else f"Device certificate used by {name} has expired (400)."
    if code == "revoked":
        return f"The target device for {name} is revoked." if name in {"membership", "bridge_host_post", "device_put", "accounts"} else f"The device authenticating {name} is revoked."
    if code == "quota_exceeded" and name == "session_login":
        return "Eight live device tokens exist; the earliest expires in 20 seconds."
    if code == "expired":
        return {"bridge_host_post": "Response rid is unknown or its keep_until_ms has elapsed, or an identical chunk's copy expired after first receipt + 900 s (P3-D27).",
                "accounts": "The fresh login challenge has expired.",
                "session_login": "The single-use login challenge has expired."}.get(name, f"The certificate request for {name} has expired.")
    if code == "not_for_this_device":
        return f"Target device/request binding required by {name} fails."
    if name == "membership" and code == "bad_epoch":
        return "Held list is (list_seq 1, epoch 2); this list's epoch 1 falls below it. Epochs may skip, never fall."
    if name == "membership" and code == "wk_commit_changed":
        return "Held list (list_seq 1, epoch 1) carries wk_commit A; this list (list_seq 2) keeps epoch 1 with wk_commit B."
    if code == "retry_exhausted" and name == "bridge_host_post":
        return "This identical chunk's copy has expired and it was already stored again eight times (P3-D27); terminal."
    if code == "rate_limited" and name == "bridge_device_post":
        return "Acknowledged rid has no live copy; 1001 ms remain before another requeue (Retry-After: 2)."
    return f"{name}: {CONDITIONS[code]}"


def build(vectors=None):
    corpus = vectors or json.loads(R.VECTORS.read_text())
    v = corpus["suites"]["2"]
    alternate = corpus["suites"]["1"]
    ids, objs = v["ids"], v["p3"]["objects"]
    ws, person, device = ids["workspace_a"], ids["person_alice"], ids["device_phone"]
    bridge = bytes.fromhex(objs["bridge_request"])
    rid = R.Header.decode(bridge).rid.hex()
    offer = R.fake("P3 HTTP offer")[:16].hex()
    crid = objs["request"]["o"]["request_id"]
    cert, card = v["certs"]["signed"]["phone"], v["card"]["card"]
    revocation = v["revocations"][0]["signed"]
    publication = objs["publication"]
    alice_pk = R.b64u(bytes.fromhex(v["keys"]["person_alice.sig"]["pub"]))
    # P3-D30: GET /v2/devices/{device}/revocation lists every held pair, the registered person's first.
    registry_pair = {"person_id": person, "reason": revocation["o"]["reason"], "revocation": revocation,
                     "device_cert": cert, "pk_pub": alice_pk, "provenance": "registry"}
    def chunk(raw):
        h = R.Header.decode(raw)
        return {"id": h.rid.hex(), "idx": h.seq, "last": bool(h.flags & R.F_LAST), "stream": bool(h.flags & R.F_STREAM), "envelope": R.b64u(raw)}
    # Real pairing envelopes (epoch 0, offer bound to header stream).
    S = R.SUITES[2]
    def pair(direction):
        keyname = "phone.sig" if direction == 1 else "wsk_a.sig"
        key = S.sig_key(bytes.fromhex(v["keys"][keyname]["seed"]))
        h = R.Header(direction, 0 if direction == 1 else R.F_LAST, 2, bytes.fromhex(ws), bytes.fromhex(device),
                     bytes.fromhex(rid), bytes.fromhex(offer), 0, 1790000000000, 0, R.fake("pair fixture salt")[:16])
        meta = {"op": "pair", "dk_sig_pub": cert["o"]["dk_sig_pub"], "dk_kx_pub": cert["o"]["dk_kx_pub"], "label": "Fixture phone", "cert": None}
        if direction == 2:
            meta = {"state": "pending", "wsk_pub": card["o"]["wsk_pub"], "sas_nonce": R.b64u(R.fake("fixture SAS")), "dk_sig_pub": cert["o"]["dk_sig_pub"], "dk_kx_pub": cert["o"]["dk_kx_pub"]}
        return R.envelope(S, R.k_pair(R.fake("fixture pairing secret"), bytes.fromhex(ws), bytes.fromhex(offer)), key, h, R.frame(meta))
    preq, presp = pair(1), pair(2)
    ck = {"workspace_id": ws, "device_id": device, "card_seq": 1, "sealed": publication["card_key_wraps"]["wraps"][0]["sealed"]}
    shapes = {
        "session_challenge": ({}, {"challenge": objs["login"]["challenge"], "expires_ms": 1790000060000}),
        "session_login": (objs["login"], {"token": R.b64u(R.fake("P3 token")), "expires_ms": 1790000900000}),
        "session_logout": ({}, {}),
        "accounts": ({"invite": "FAKE-single-use-invite", "pk_pub": R.b64u(bytes.fromhex(v["keys"]["person_alice.sig"]["pub"])), "device_cert": cert, "challenge": objs["login"]["challenge"], "sig": objs["login"]["sig"]}, {"person_id": person}),
        "device_put": ({"cert": cert}, {"device_id": device}), "device_get": (None, {"cert": cert}),
        "revocations_post": ({"record": revocation}, {"device_id": device}), "revocation_get": (None, {"pairs": [registry_pair]}),
        "revocation_feed": (None, {"revocations": [{"cursor": 1, "record": revocation}], "next": None}),
        "card_put": ({"card": card}, {"card_seq": 1}), "card_get": (None, {"card": card}),
        "membership": (publication, {"list_seq": 1, "epoch": 1}),
        "card_keys": (publication["card_key_wraps"], {"stored": 1}),
        "grants": (None, {"grants": [publication["grants"][0]]}), "members": (None, {"member_list": publication["member_list"]}),
        "card_key": (None, ck), "bridge_device_post": (bridge, {}), "bridge_host_post": (bytes.fromhex(objs["bridge_response"]), {}),
        "bridge_device_poll": (None, {"chunks": [chunk(bytes.fromhex(objs["bridge_response"]))]}),
        "host_hold": ({"gen": None, "take_over": False}, {"gen": 1, "lease_s": 40, "cursor": 0}),
        "host_poll": (None, {"items": [{"n": 1, "route": "bridge", "device": device, "rid": rid, "offer": None, "envelope": R.b64u(bridge)}],
                            "notices": {"revocations_cursor": 0, "cert_requests": [], "rotation_due": []}, "next": None}),
        "pair_device_post": (preq, {}), "pair_host_post": (presp, {}), "pair_poll": (None, {"chunks": [chunk(presp)]}),
        "cert_requests_post": ({"request": objs["request"]}, {"request_id": crid}),
        "cert_requests_poll": (None, {"requests": [objs["request"]]}),
        "cert_challenge": ({"challenge": objs["challenge"]}, {}), "cert_rejection": ({"rejection": objs["cert_rejection"]}, {}),
        "cert_request_get": (None, {"state": "challenged", "challenge": objs["challenge"], "cert": None, "rejection": None}),
    }
    query = {"revocation_feed": {"after": "0", "limit": "256"}, "grants": {"epoch": "1"}, "card_key": {"card_seq": "1"},
             "bridge_device_poll": {"wait": "25"}, "pair_poll": {"wait": "25"}, "host_poll": {"after": "0", "wait": "25"}, "cert_requests_poll": {"wait": "25"}}
    cp_shapes, cp_query, cp_paths = CP.shapes(v)
    shapes.update(cp_shapes)
    query.update(cp_query)
    output = {}
    for row in ROUTES:
        name, method, path, role, auth, _ = row
        actual = path
        for k, val in {"ws": ws, "person": person, "device": device, "rid": rid, "offer": offer, "id": crid, **cp_paths}.items():
            actual = actual.replace("{" + k + "}", val)
        req, resp = shapes[name]
        headers = {}
        if auth != "none":
            headers["Authorization"] = "Bearer FAKE-" + ("primary" if role == "primary" else "workspace" if role == "host" else "device")
        if "W(g)" in auth:
            headers["Orch-Holder"] = "1"
        request = {"method": method, "path": actual, "query": query.get(name, {}), "headers": headers}
        if isinstance(req, bytes):
            headers["Content-Type"] = "application/octet-stream"
            request["body_b64u"] = R.b64u(req)
        elif req is not None:
            headers["Content-Type"] = "application/json"
            request["json"] = req
        status = 202 if name in {"bridge_device_post", "bridge_host_post", "pair_device_post", "pair_host_post"} else 200
        success = {"name": "success", "given": {"scenario": "authorized_current_state", "now_ms": 1790000000000},
                   "request": request, "response": {"status": status, "headers": {"Content-Type": "application/json"}, "json": resp}}
        cases = [success]
        for code_status, code in refusals(row):
            err = {"error": code}
            if code == "restore_missing_revocation":
                err["devices"] = [device]
            if code == "stale_epoch":
                err["epoch"] = 2
            response = {"status": code_status, "headers": {"Content-Type": "application/json"}, "json": err}
            if code_status in (429, 503):
                response["headers"]["Retry-After"] = "2" if name == "bridge_device_post" and code == "rate_limited" else "20"
            # The same signed artifact may be refused against a different trusted key, epoch,
            # principal, or stored state. Signatures remain verifiable as artifacts in all examples.
            refused_request = copy.deepcopy(request)
            condition = {"scenario": code, "now_ms": 1790000000000,
                         "condition": condition_for(name, code)}
            if code == "malformed":
                refused_request["query"]["unexpected"] = "1"
            elif code == "wrong_suite":
                if "body_b64u" in refused_request:
                    key = "bridge_response" if role == "host" else "bridge_request"
                    refused_request["body_b64u"] = R.b64u(bytes.fromhex(alternate["p3"]["objects"][key]))
                elif name == "checkpoint_put":
                    refused_request["json"]["checkpoint"] = alternate["checkpoints"]["objects"]["checkpoint"]
                else:
                    alt = alternate["p3"]["objects"]
                    replacements = {"card": alternate["card"]["card"], "cert": alternate["certs"]["signed"]["phone"],
                                    "device_cert": alternate["certs"]["signed"]["phone"], "record": alternate["revocations"][0]["signed"],
                                    "request": alt["request"], "challenge": alt["challenge"], "rejection": alt["cert_rejection"]}
                    if name == "membership":
                        refused_request["json"] = alt["publication"]
                    elif name == "accounts":
                        refused_request["json"].update(device_cert=replacements["device_cert"],
                            pk_pub=R.b64u(bytes.fromhex(alternate["keys"]["person_alice.sig"]["pub"])),
                            sig=alt["login"]["sig"], challenge=alt["login"]["challenge"])
                    else:
                        refused_request["json"] = {k: replacements[k] for k in refused_request["json"]}
            elif name == "accounts" and code == "cert_invalid":
                refused_request["json"]["device_cert"] = copy.deepcopy(next(
                    c["signed"] for c in v["certs"]["cases"] if c["name"] == "tampered_after_signing"))
            elif name == "device_put" and code == "cert_expired":
                refused_request["json"]["cert"] = copy.deepcopy(next(
                    c["signed"] for c in v["certs"]["cases"] if c["name"] == "expired"))
            elif name == "card_put" and code == "bad_signature":
                refused_request["json"]["card"] = copy.deepcopy(next(
                    c["card"] for c in v["card"]["cases"] if c["name"] == "card_signed_by_another_wsk"))
            elif name == "card_put" and code == "delegation_mismatch":
                refused_request["json"]["card"] = copy.deepcopy(next(
                    c["card"] for c in v["card"]["cases"] if c["name"] == "delegation_for_another_wsk"))
            elif name == "membership" and code in {"not_for_this_device", "other_workspace", "bad_epoch", "rotation_required",
                                                   "wk_commit_changed"}:
                vector_name = {"not_for_this_device": "grant_wrong_epoch", "other_workspace": "other_workspace",
                               "bad_epoch": "rotation_due_survives_same_epoch_and_restart",
                               "rotation_required": "rotation_due_survives_same_epoch_and_restart",
                               "wk_commit_changed": "wk_commit_changed_same_epoch"}[code]
                refused_request["json"] = copy.deepcopy(next(
                    c["args"]["body"] for c in v["p3"]["cases"] if c["name"] == vector_name))
            elif code == "missing_grant":
                refused_request["json"]["grants"] = refused_request["json"]["grants"][:-1]
            elif code == "unauthenticated":
                refused_request["headers"].pop("Authorization", None)
            elif code == "fenced":
                if name == "host_hold":
                    refused_request["json"] = {"gen": 0, "take_over": False}
                else:
                    refused_request["headers"]["Orch-Holder"] = "0"
            elif code == "too_large":
                limit = BODY_CAPS[name]
                refused_request.pop("json", None)
                refused_request.pop("body_b64u", None)
                # A byte-exact recipe avoids megabytes of repeated padding in a portable fixture.
                # It is raw HTTP bytes, not an extra JSON field sent to the relay.
                refused_request["body_recipe"] = {"prefix_b64u": "", "byte": 32, "count": limit + 1, "suffix_b64u": ""}
            cases.append({"name": f"refusal_{code_status}_{code}", "given": condition,
                          "request": refused_request, "response": response})
        def extra(label, request_patch=None, response_json=None, given=None):
            c = copy.deepcopy(success); c["name"] = label
            if request_patch:
                c["request"].update(request_patch)
            if response_json is not None:
                c["response"]["json"] = response_json
            if given:
                c["given"]["scenario"] = given
            cases.append(c)
        if name == "membership":
            vector = next(c for c in v["p3"]["cases"] if c["name"] == "victim_person_without_member")
            c = copy.deepcopy(success)
            c.update(name="victim_person_without_member", given={"condition": "persons names a victim with no member device in this publication."})
            c["request"]["json"] = vector["args"]["body"]
            c["response"].update(status=403, json={"error": "other_person"})
            cases.append(c)
        if name in {"device_get", "revocation_feed"}:
            c = copy.deepcopy(success)
            c.update(name="other_workspace_person_refused", given={"condition": "W belongs to a workspace whose ever_persons excludes the requested person."})
            c["request"]["headers"]["Authorization"] = "Bearer FAKE-workspace-token"
            c["response"].update(status=403, json={"error": "not_eligible"})
            cases.append(c)
        if name == "revocation_feed":
            extra("filtered_workspace_feed", response_json={"revocations": [{"cursor": 1, "record": v["revocations"][0]["signed"]}], "next": None},
                  given="W ever_devices contains only the phone; records for the same person's other devices are excluded before pagination")
            cases[-1]["request"]["headers"]["Authorization"] = "Bearer FAKE-workspace-token"
        if name == "revocation_get":
            # P3-D30: bob's out-of-band pair ('feed', no evidence held) and the intruder's restore-carried
            # pair ('chain', with the carried certificate and key) for the same id; both sort before alice
            # by person_id, yet the registered person's pair comes first, then by person_id.
            S2 = R.SUITES[2]
            def key(name_):
                return S2.sig_key(bytes.fromhex(v["keys"][name_ + ".sig"]["seed"]))
            def other(name_, reason):
                pk = bytes.fromhex(v["keys"][name_ + ".sig"]["pub"])
                pid = R.person_id(S2, pk).hex()
                rec = R.sign_object(S2, key(name_), {**revocation["o"], "person_id": pid, "reason": reason})
                return pid, pk, rec
            bob_id, _, bob_rec = other("person_bob", "compromised")
            q_id, q_pk, q_rec = other("intruder", "lost")
            q_cert = R.sign_object(S2, key("intruder"), {**cert["o"], "person_id": q_id})
            pairs = [registry_pair] + sorted([
                {"person_id": bob_id, "reason": "compromised", "revocation": bob_rec, "device_cert": None,
                 "pk_pub": None, "provenance": "feed"},
                {"person_id": q_id, "reason": "lost", "revocation": q_rec, "device_cert": q_cert,
                 "pk_pub": R.b64u(q_pk), "provenance": "chain"}], key=lambda p: p["person_id"])
            assert person > max(bob_id, q_id)
            extra("every_pair_registered_person_first", response_json={"pairs": pairs}, given="every_pair")
            cases[-1]["given"]["condition"] = ("The relay also holds every non-registry pair of the response: 'chain' pairs as "
                                               "an accepted restore's evidence (certificate and key), 'feed' pairs in the "
                                               "revocation table only.")
        if name in {"device_put", "cert_challenge", "cert_rejection"}:
            action = {"device_put": "certificate", "cert_challenge": "challenge", "cert_rejection": "rejection"}[name]
            vec = next(c for c in v["p3"]["cases"] if c["name"] == action + "_resigned_identical")
            field = "cert" if name == "device_put" else action
            extra("resigned_identical", {"json": {field: vec["args"]["signed"]}}, given="Same canonical signed object, different valid P-256 signature; no state change")
        if name == "host_hold":
            extra("renew", {"json": {"gen": 1, "take_over": False}})
            extra("explicit_takeover", {"json": {"gen": None, "take_over": True}}, {"gen": 2, "lease_s": 40, "cursor": 1})
        if name == "card_put":
            extra("first_card_without_session", {"headers": {"Content-Type": "application/json"}})
        if name in {"membership", "accounts", "device_put", "revocations_post", "card_keys", "cert_challenge", "cert_rejection"}:
            extra("exact_retry", given="exact_bytes_already_committed")
        if name == "cert_request_get":
            for state in ("open", "signed", "rejected", "expired"):
                extra(state, response_json={"state": state, "challenge": objs["challenge"] if state == "signed" else None,
                                           "cert": objs["cert"] if state == "signed" else None,
                                           "rejection": objs["cert_rejection"] if state == "rejected" else None})
        if name == "bridge_host_post":
            extra("expired_identical_chunk_restored", given="expired_identical_chunk")
        if name in {"bridge_device_poll", "pair_poll"}:
            extra("after_first_chunk", {"query": {"after": "0", "wait": "0"}}, {"chunks": []})
        if name == "host_poll":
            notices = {"revocations_cursor": 1, "cert_requests": [crid], "rotation_due": [{"device_id": device, "revocation_cursor": 1, "epoch": 1}]}
            extra("durable_notices", response_json={"items": [], "notices": notices, "next": None})
            extra("pair_item", response_json={"items": [{"n": 2, "route": "pair", "device": device, "rid": rid, "offer": offer, "envelope": R.b64u(preq)}],
                                              "notices": {"revocations_cursor": 0, "cert_requests": [], "rotation_due": []}, "next": None})
        if name == "session_logout":
            extra("expired_token_retry", given="token_expired_or_already_logged_out")
        output[name] = {"contract": "orch-relay-http-v2", "suite": 2, "route": {"method": method, "path": path, "role": role, "auth": auth},
                        "cases": cases}
    return CP.enrich(output, v)


if __name__ == "__main__":
    directory = R.VECTORS.parent / "http_fixtures"
    directory.mkdir(exist_ok=True)
    for name, value in build().items():
        (directory / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")
    print(f"wrote {len(ROUTES)} HTTP fixtures")
