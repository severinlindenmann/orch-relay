"""P3-D39 (D39a1) Drop relay contract: the executable model of protocol-v2 §19.9 and P3 design §14.2
for the PUT check order (steps 3-11), the reads in their answer order and the list. Test support,
never server code: the production relay replays the same `drop.relay_put` vectors and the Drop HTTP
fixtures, whose expected answers this model computes.

State is JSON-portable:
  {"now_ms", "counter",
   "workspaces": {ws: {"owner", "epoch", "wxk_version", "members": {device: scopes},
                       "holder": {"gen", "lease_until_ms"}, "wsk_pub": hex}},
   "devices": {device: {"sig_pub": hex, "revoked": bool, "expires_ms": int|None, "drop_scoped": bool}},
   "objects": {o: {"workspace_id", "object_kind", "current", "inbox", "claimed_by", "expires_ms",
                   "tombstone_ms", "tombstone_kind", "head_author_id", "head_hash", "audience",
                   "audience_devices": [...], "n"}},
   "versions": {"o/v": {"descriptor": signed, "blob": "stored"|"pruned", "wraps": [record, ...]}}}
Transport limits, slots, buckets and the drain are the HTTP layer's; they are not modelled here.
"""
import copy
import re

from ref import orch_protocol_ref as R

S = R.SUITES[2]
KIB, MIB, DAY = 1024, 1024 * 1024, 86_400_000
MAGIC = b"ODU2"
MAX_HEAD = 512 * KIB
MAX_DESCRIPTOR = 96 * KIB
MAX_META = 64 * KIB + 16
MAX_WRAPS = MAX_RECIPIENTS = 1024
MAX_WRAP = 512
MAX_BLOB = 26 * MIB
MAX_TTL, SKEW, MIN_FILE_LIFE = 7 * DAY, 300_000, 60_000
TOMBSTONE = 30 * DAY
LIST_LIMIT, PAGE_LIMIT = 64, 256
WRAP_LEN = {"wk": 64, "wxk": 113, "device": 113}
HEX32 = re.compile(r"[0-9a-f]{32}")
# The relay's `generation` in the fixtures (D39a2 part 4): the production replay pins its own to this
# value; a real relay's is random. `state["generation"]` overrides it (a restored dataset).
GENERATION = "3f9a0c4be17d2858a6c1b04e93d7f5aa"
DECIMAL = re.compile(r"0|[1-9][0-9]{0,15}")


class Refusal(Exception):
    def __init__(self, status, code, **fields):
        self.result = {"status": status, "json": {"error": code, **fields}}


def no(status, code, **fields):
    raise Refusal(status, code, **fields)


def need(ok, status=400, code="malformed", **fields):
    if not ok:
        no(status, code, **fields)


def frame(head_obj, blob):
    head = R.cj(head_obj)
    return MAGIC + len(head).to_bytes(4, "big") + head + blob


def parse_frame(body, content_length):
    """Step 4 (and the frame half of step 1): magic, big-endian head_len, the head."""
    need(content_length == len(body) and len(body) >= 8)
    need(body[:4] == MAGIC)
    head_len = int.from_bytes(body[4:8], "big")
    if head_len > MAX_HEAD:
        no(413, "too_large")
    need(len(body) >= 8 + head_len)
    try:
        head = R.parse_json(body[8:8 + head_len])
    except (ValueError, UnicodeError):
        no(400, "malformed")
    return head, body[8:8 + head_len], body[8 + head_len:]


def b64(value, length=None):
    try:
        return R.unb64u(value, length)
    except (ValueError, TypeError):
        no(400, "malformed")


def hex32(value):
    need(isinstance(value, str) and HEX32.fullmatch(value) is not None)
    return value


def integer(value, low=0, high=2**53 - 1):
    need(type(value) is int and low <= value <= high)
    return value


def parent_hash(o):
    return R.b64u(R.drop_parent_hash(o))


def shape(head, o_path):
    need(isinstance(head, dict) and set(head) == {"descriptor", "wraps"})
    signed, records = head["descriptor"], head["wraps"]
    need(isinstance(signed, dict) and set(signed) == {"o", "sig"} and isinstance(records, list))
    o = signed["o"]
    need(isinstance(o, dict) and set(o) == R.DROP_OBJECT_FIELDS)
    need(o["v"] == 2 and type(o["v"]) is int and o["suite"] == 2 and type(o["suite"]) is int)
    need(o["kind"] == "drop_object" and isinstance(signed["sig"], str))
    need(len(R.cj(signed)) <= MAX_DESCRIPTOR)
    need(isinstance(o["meta"], str) and len(b64(o["meta"])) <= MAX_META)
    need(hex32(o["object_id"]) == o_path)
    hex32(o["space_id"])
    need(o["space_kind"] == "workspace" and o["object_kind"] in ("file", "document"))
    integer(o["version"], 1)
    need(type(o["parent"]) is int and o["parent"] == o["version"] - 1)
    if o["version"] == 1:
        need(o["parent_hash"] is None)
    else:
        b64(o["parent_hash"], 32)
    need(o["author_kind"] in ("device", "workspace"))
    hex32(o["author_id"])
    b64(o["content_hash"], 32)
    integer(o["content_len"], 56, MAX_BLOB)
    b64(o["dek_commit"], 32)
    need(o["origin"] in ("human", "agent"))
    integer(o["created_ms"])
    r = o["recipients"]
    if r == "inbox":
        need(o["object_kind"] == "file")
    else:
        need(isinstance(r, list) and 1 <= len(r) <= MAX_RECIPIENTS)
        for ident in r:
            hex32(ident)
        need(r == sorted(set(r)))
    if o["object_kind"] == "file":
        integer(o["expires_ms"])
    else:
        need(o["expires_ms"] is None)
    need(len(records) <= MAX_WRAPS)
    return signed, records


def member(state, ws, device):
    w = state["workspaces"].get(ws)
    return None if w is None else w["members"].get(device)


def sees_workspace(state, principal, ws):
    if principal["kind"] == "workspace":
        return principal["id"] == ws
    scopes = member(state, ws, principal["id"])
    return scopes is not None and "look" in scopes


def visible(state, principal, obj):
    if not sees_workspace(state, principal, obj["workspace_id"]):
        return False
    if principal["kind"] == "workspace":
        return True
    if obj["inbox"] and obj["claimed_by"] is None:  # amendment A2: the W session's and the author's
        return obj["head_author_id"] == principal["id"]
    return obj["audience"] != "devices" or principal["id"] in obj["audience_devices"]


def decide_shape(o, expected):
    """Item 13 (amendment A2): a new inbox file at version 1, If-Match 0; request-only, no state."""
    return (o["object_kind"] == "file" and o["recipients"] == "inbox" and o["version"] == 1
            and o["parent"] == 0 and expected == 0)


def eligibility(state, principal, signed, now, expected, signature=True):
    o = signed["o"]
    ws = o["space_id"]
    if o["object_kind"] == "file":
        need(o["expires_ms"] <= now + MAX_TTL + SKEW)
    kind, ident = principal["kind"], principal["id"]
    need(o["author_kind"] == kind and o["author_id"] == ident, 403, "not_eligible")
    if signature:
        if kind == "device":
            pub = state["devices"].get(ident, {}).get("sig_pub")
        else:
            pub = state["workspaces"].get(ident, {}).get("wsk_pub")
        if pub is None or R.verify_object(S, bytes.fromhex(pub), signed, "drop_object") is None:
            no(401, "bad_signature")
    if kind == "device":
        scopes = member(state, ws, ident)
        need(scopes is not None and ("operate" in scopes or ("decide" in scopes and decide_shape(o, expected))),
             403, "not_eligible")
    else:
        need(ident == ws, 403, "not_eligible")
    if isinstance(o["recipients"], list):
        for target in o["recipients"]:
            need(target == ws or member(state, ws, target) is not None)


def object_state(state, principal, o, now):
    obj = state["objects"].get(o["object_id"])
    if obj is not None:
        need(obj["workspace_id"] == o["space_id"], 403, "not_eligible")
        need(visible(state, principal, obj), 403, "not_eligible")
    if o["expires_ms"] is not None and o["expires_ms"] <= now:
        no(410, "expired")
    if obj is not None and (obj["tombstone_ms"] is not None
                            or (obj["expires_ms"] is not None and obj["expires_ms"] <= now)):
        no(410, "expired")
    return obj


def exact_retry(state, o, obj):
    if obj is None or o["version"] > obj["current"]:
        return False
    stored = state["versions"].get(f"{o['object_id']}/{o['version']}")
    return stored is not None and R.cj(stored["descriptor"]["o"]) == R.cj(o)


def cas(o, obj, expected, request_now):
    if o["object_kind"] == "file":
        need(o["version"] == 1)
        need(o["expires_ms"] >= request_now + MIN_FILE_LIFE)
    if obj is not None and obj["claimed_by"] is not None:
        no(403, "not_eligible")
    current = obj["current"] if obj is not None else 0
    if (expected != current or o["parent"] != current or o["version"] != current + 1
            or o["parent_hash"] != (obj["head_hash"] if obj is not None else None)
            or (obj is not None and obj["object_kind"] != o["object_kind"])):
        no(409, "version_conflict", current=current)


def wrap_shapes(o, records):
    seen, kinds = set(), {"wk": 0, "wxk": 0, "device": 0}
    for rec in records:
        need(isinstance(rec, dict) and set(rec) == {"object_id", "version", "target_kind", "target_id",
                                                     "key_version", "wrap"})
        need(rec["object_id"] == o["object_id"] and rec["version"] == o["version"]
             and type(rec["version"]) is int)
        kind = rec["target_kind"]
        need(kind in WRAP_LEN)
        hex32(rec["target_id"])
        integer(rec["key_version"], 0, 2**32 - 1)
        need(isinstance(rec["wrap"], str))
        raw = b64(rec["wrap"])
        need(len(raw) <= MAX_WRAP and len(raw) == WRAP_LEN[kind])
        if kind != "wk":
            need(S.sig_pub_ok(raw[:65]))  # a P-256 point (the §5.3 ephemeral key)
        key = (kind, rec["target_id"], rec["key_version"])
        need(key not in seen)
        seen.add(key)
        kinds[kind] += 1
        if kind in ("wk", "wxk"):
            need(rec["target_id"] == o["space_id"])
        else:
            need(rec["key_version"] == 0)
    if o["recipients"] == "inbox":
        need(kinds["wxk"] == 1 and kinds["wk"] == 0)
        for rec in records:
            if rec["target_kind"] == "device":
                need(o["author_kind"] == "device" and rec["target_id"] == o["author_id"])
    elif o["author_kind"] == "device" or o["space_id"] in o["recipients"]:
        need(kinds["wk"] == 1)


def wrap_state(state, o, records, now):
    w = state["workspaces"][o["space_id"]]
    for rec in records:
        kind = rec["target_kind"]
        if kind == "wk" and rec["key_version"] != w["epoch"]:
            no(409, "stale_epoch", epoch=w["epoch"])
        elif kind == "wk" and w.get("rotation_due"):  # an open rotation_due (owner question 6)
            no(409, "rotation_required", epoch=w["epoch"])
        elif kind == "wxk" and rec["key_version"] != w["wxk_version"]:
            no(409, "bad_wxk_version")
        elif kind == "device":
            target = rec["target_id"]
            author = o["author_kind"] == "device" and target == o["author_id"]
            need(author or member(state, o["space_id"], target) is not None, 403, "not_eligible")
            dev = state["devices"].get(target)
            need(dev is not None and not dev["revoked"]
                 and (dev["expires_ms"] is None or dev["expires_ms"] > now), 403, "not_eligible")


def check_blob(o, blob):
    """Step 10: an ORD2 header for this descriptor, a consistent length, the exact length and hash."""
    need(len(blob) == o["content_len"])
    h = blob[:40]
    need(len(h) == 40 and h[:4] == b"ORD2" and h[4] == 2 and h[5] == o["suite"] and h[6:8] == b"\0\0"
         and h[8:24] == bytes.fromhex(o["object_id"]) and int.from_bytes(h[24:28], "big") == o["version"])
    chunk = int.from_bytes(h[28:32], "big")
    need(0 < chunk <= R.MAX_CHUNK_SIZE)
    body, step = o["content_len"] - 40, chunk + 16
    need(body >= 16 and body - (-(-body // step) - 1) * step >= 16)
    need(R.b64u(R.H(blob)) == o["content_hash"])


def if_match(text):
    if text is not None and len(text) >= 2 and text[0] == text[-1] == '"':
        text = text[1:-1]
    if text is None or not DECIMAL.fullmatch(text) or int(text) > 2**53 - 1:
        no(428, "precondition_required")
    return int(text)


def admit(state, principal, holder, write):
    if principal["kind"] == "device":
        dev = state["devices"][principal["id"]]
        need(not dev.get("drop_scoped"), 403, "not_eligible")
    elif write:
        h = state["workspaces"][principal["id"]]["holder"]
        if holder is None or not re.fullmatch(r"[0-9]+", holder):
            no(409, "fenced") if holder is None else no(400, "malformed")
        if int(holder) != h["gen"] or h["lease_until_ms"] <= state["now_ms"]:
            no(409, "fenced")


def put(state, principal, o_path, body_hex, if_match_header, holder=None, content_length=None):
    """PUT /v2/drop/{o}/versions on `state` (mutated only by a 201). Returns {status, json}."""
    try:
        return _put(state, principal, o_path, bytes.fromhex(body_hex), if_match_header, holder,
                    content_length)
    except Refusal as refusal:
        return refusal.result


def _put(state, principal, o_path, body, im, holder, content_length):
    now = state["now_ms"]
    admit(state, principal, holder, True)
    expected = if_match(im)
    head, raw, blob = parse_frame(body, len(body) if content_length is None else content_length)
    signed, records = shape(head, o_path)
    o = signed["o"]
    need(8 + len(raw) + o["content_len"] == (len(body) if content_length is None else content_length))
    eligibility(state, principal, signed, now, expected)
    obj = object_state(state, principal, o, now)
    if exact_retry(state, o, obj):
        return {"status": 200, "json": {"version": o["version"]}}
    cas(o, obj, expected, now)
    wrap_shapes(o, records)
    wrap_state(state, o, records, now)
    check_blob(o, blob)
    state["counter"] += 1
    if o["recipients"] == "inbox":
        audience, devices = "inbox", []
    elif o["space_id"] in o["recipients"]:
        audience, devices = "space", []
    else:
        audience = "devices"
        devices = sorted(set(o["recipients"]) | ({o["author_id"]} if o["author_kind"] == "device" else set()))
    prior = state["objects"].get(o["object_id"])
    state["objects"][o["object_id"]] = {
        "workspace_id": o["space_id"], "object_kind": o["object_kind"], "current": o["version"],
        "inbox": o["recipients"] == "inbox", "claimed_by": prior["claimed_by"] if prior else None,
        "claimed_ms": prior.get("claimed_ms") if prior else None,
        "expires_ms": o["expires_ms"], "tombstone_ms": None, "tombstone_kind": None,
        "head_author_id": o["author_id"], "head_hash": parent_hash(o), "audience": audience,
        "audience_devices": devices, "n": state["counter"],
        "created_ms": prior["created_ms"] if prior else now,
    }
    state["versions"][f"{o['object_id']}/{o['version']}"] = {
        "descriptor": signed, "blob": "stored",
        "wraps": sorted(records, key=lambda r: (r["target_kind"], r["target_id"], r["key_version"])),
    }
    return {"status": 201, "json": {"version": o["version"]}}


# --- reads -----------------------------------------------------------------------------------------


def tombstone_until(obj, now):
    if obj["tombstone_ms"] is not None:
        return obj["tombstone_ms"] + TOMBSTONE
    if obj["expires_ms"] is not None and obj["expires_ms"] <= now:
        return obj["expires_ms"] + TOMBSTONE
    return None


def object_for_read(state, principal, o_id):
    now = state["now_ms"]
    obj = state["objects"].get(o_id)
    until = tombstone_until(obj, now) if obj else None
    if obj is None or (until is not None and until <= now):
        no(404, "not_found")
    need(visible(state, principal, obj), 403, "not_eligible")
    if until is not None:
        no(410, "expired")
    return obj


def usable(state, principal, o_id, version, ws):
    out = []
    for rec in state["versions"][f"{o_id}/{version}"]["wraps"]:
        k, t = rec["target_kind"], rec["target_id"]
        if principal["kind"] == "workspace":
            ok = k in ("wk", "wxk") and t == ws
        else:
            ok = (k == "wk" and t == ws) or (k == "device" and t == principal["id"])
        if ok:
            out.append(rec)
    return out


def read(state, principal, o_id, version, what):
    """GET .../versions/{v}/{descriptor|wraps|blob}: {status, json} (blob: {status, blob_hex})."""
    try:
        admit(state, principal, None, False)
        obj = object_for_read(state, principal, o_id)
        ver = state["versions"].get(f"{o_id}/{version}")
        if ver is None:
            no(404, "not_found")
        if what == "descriptor":
            return {"status": 200, "json": {"descriptor": ver["descriptor"]}}
        if what == "wraps":
            return {"status": 200, "json": {"claimed_by": obj["claimed_by"],
                                            "wraps": usable(state, principal, o_id, version, obj["workspace_id"])}}
        need(not obj["inbox"] or obj["claimed_by"] is not None, 403, "not_eligible")
        if ver["blob"] != "stored":
            no(410, "expired")
        return {"status": 200, "blob": True}
    except Refusal as refusal:
        return refusal.result


def descriptors(state, principal, o_id, after=0, limit=PAGE_LIMIT):
    try:
        admit(state, principal, None, False)
        object_for_read(state, principal, o_id)
        found = sorted(int(k.split("/")[1]) for k in state["versions"] if k.split("/")[0] == o_id)
        page = [v for v in found if v > after][:limit + 1]
        more = len(page) > limit
        page = page[:limit]
        return {"status": 200, "json": {"descriptors": [state["versions"][f"{o_id}/{v}"]["descriptor"] for v in page],
                                        "next": page[-1] if more and page else None}}
    except Refusal as refusal:
        return refusal.result


def state_of(obj, blob, now):
    if obj["tombstone_kind"] is not None:
        return obj["tombstone_kind"]
    if obj["expires_ms"] is not None and obj["expires_ms"] <= now:
        return "expired"
    return "pruned" if blob == "pruned" else "live"


def list_page(state, principal, body):
    """POST /v2/drop/list (§14.2 items 7 and 14; no byte cut in the model: fixtures stay far below
    2 MiB). `generation` and `until` are echoed on every page; a walk is cut at `until`."""
    try:
        admit(state, principal, None, False)
        need(isinstance(body, dict) and {"workspace_id", "direction"} <= set(body)
             <= {"workspace_id", "direction", "after", "limit", "generation", "until"})
        ws = hex32(body["workspace_id"])
        direction = body["direction"]
        need(direction in ("received", "sending", "all"))
        after = integer(body.get("after", 0))
        limit = integer(body.get("limit", LIST_LIMIT), 1, LIST_LIMIT)
        generation = hex32(body["generation"]) if "generation" in body else None
        until = None
        if "until" in body:
            need(generation is not None)
            until = integer(body["until"])
            need(after <= until)
        need(direction != "all" or "after" not in body or generation is not None)
        need(sees_workspace(state, principal, ws), 403, "not_eligible")
        need(direction != "all" or principal["kind"] == "workspace", 403, "not_eligible")
        counter, current = state["counter"], state.get("generation", GENERATION)
        if (generation is not None and generation != current) or after > counter or (
                until is not None and until > counter):
            no(409, "generation_changed")
        until = counter if until is None else until
        now, me = state["now_ms"], principal["id"]
        rows = []
        for o_id, obj in state["objects"].items():
            ends = tombstone_until(obj, now)
            if (obj["workspace_id"] != ws or obj["n"] <= after or obj["n"] > until
                    or (ends is not None and ends <= now)):
                continue
            if direction != "all" and (obj["head_author_id"] == me) != (direction == "sending"):
                continue
            if not visible(state, principal, obj):
                continue
            rows.append((obj["n"], o_id, obj))
        rows.sort()
        more = len(rows) > limit
        entries = []
        for n, o_id, obj in rows[:limit]:
            ver = state["versions"].get(f"{o_id}/{obj['current']}")
            st = state_of(obj, ver["blob"] if ver else None, now)
            entries.append({
                "n": n, "object_id": o_id, "version": obj["current"], "state": st,
                "tombstone_until_ms": tombstone_until(obj, now),
                "descriptor": ver["descriptor"] if ver and st in ("live", "pruned") else None,
                "wraps": usable(state, principal, o_id, obj["current"], ws) if st == "live" else [],
                "claimed_by": obj["claimed_by"], "claimed_ms": obj.get("claimed_ms"),
                "expires_ms": obj["expires_ms"],
            })
        return {"status": 200, "json": {"objects": entries,
                                        "next": entries[-1]["n"] if more and entries else None,
                                        "generation": current, "until": until}}
    except Refusal as refusal:
        return refusal.result


# --- retire (D39a2, amendment A1) ------------------------------------------------------------------------


def retire(state, principal, o_id, body, holder=None):
    """POST /v2/drop/{o}/retire on `state` (mutated only by the retire itself): W sessions only, the
    body `{expect_version, expect_head}` (both required), 404 for an absent or ended tombstone, 403 for
    another space, 409 `version_conflict` (`current`, `state`) against the live row, the bounded
    idempotent 200 for a tombstone, else a `retired` tombstone with a new `n` (a file's version is
    released with it, a document's versions go with the sweeper, not modelled)."""
    try:
        admit(state, principal, holder, True)
        need(principal["kind"] == "workspace", 403, "not_eligible")
        need(isinstance(body, dict) and set(body) == {"expect_version", "expect_head"})
        version = integer(body["expect_version"], 1)
        head = b64(body["expect_head"], 32)
        now = state["now_ms"]
        obj = state["objects"].get(o_id)
        until = tombstone_until(obj, now) if obj else None
        if obj is None or (until is not None and until <= now):
            no(404, "not_found")
        need(obj["workspace_id"] == principal["id"], 403, "not_eligible")
        ver = state["versions"].get(f"{o_id}/{obj['current']}")
        st = state_of(obj, ver["blob"] if ver else None, now)
        if obj["current"] != version or R.unb64u(obj["head_hash"], 32) != head:
            no(409, "version_conflict", current=obj["current"], state=st)
        if until is not None:
            return {"status": 200, "json": {"state": st}}
        state["counter"] += 1
        obj.update(n=state["counter"], tombstone_ms=now, tombstone_kind="retired")
        if obj["object_kind"] == "file":
            for key in [k for k in state["versions"] if k.split("/")[0] == o_id]:
                del state["versions"][key]
        return {"status": 200, "json": {"state": "retired"}}
    except Refusal as refusal:
        return refusal.result


# --- state operations that have no D39a1 route (D39a2 sweeps and retire, D39b claim) ------------------


def apply(state, op):
    """A state change a fixture or vector names as a precondition: `retire` (tombstone now, new n),
    `expire_sweep` (expired tombstone at expires_ms, audience rows deleted, new n), `claim` (claimed_by, claimed_ms = now,
    new n), `scopes` (a member's scopes), `prune` (the listed version's blob gone after a restore, wraps deleted, new n), `clock`."""
    kind = op["op"]
    if kind == "clock":
        state["now_ms"] = op["now_ms"]
        return
    if kind == "rotation_due":  # a revocation left a rotation_due row open (wk wraps are refused)
        for w in state["workspaces"].values():
            w["rotation_due"] = True
        return
    if kind == "scopes":  # a member device's scopes change (a phone holds `look` and `decide` only)
        for w in state["workspaces"].values():
            if op["device"] in w["members"]:
                w["members"][op["device"]] = list(op["scopes"])
        return
    if kind == "epoch":  # a membership publication at a new epoch (a removal)
        for w in state["workspaces"].values():
            w["epoch"] = op["epoch"]
        return
    if kind == "foreign_object":  # an object of another workspace (no member of it here)
        state["counter"] += 1
        state["objects"][op["object_id"]] = {
            "workspace_id": op["workspace_id"], "object_kind": "file", "current": 1, "inbox": False,
            "claimed_by": None, "claimed_ms": None, "expires_ms": state["now_ms"] + DAY, "tombstone_ms": None,
            "tombstone_kind": None, "head_author_id": op["workspace_id"], "head_hash": "x" * 43,
            "audience": "space", "audience_devices": [], "n": state["counter"], "created_ms": state["now_ms"]}
        return
    obj = state["objects"][op["object_id"]]
    state["counter"] += 1
    obj["n"] = state["counter"]
    if kind == "retire":
        obj.update(tombstone_ms=state["now_ms"], tombstone_kind="retired")
        for key in [k for k in state["versions"] if k.split("/")[0] == op["object_id"]]:
            del state["versions"][key]
    elif kind == "expire_sweep":
        obj.update(tombstone_ms=obj["expires_ms"], tombstone_kind="expired", audience_devices=[])
        for key in [k for k in state["versions"] if k.split("/")[0] == op["object_id"]]:
            del state["versions"][key]
    elif kind == "claim":
        obj["claimed_by"] = op["workspace_id"]
        obj["claimed_ms"] = state["now_ms"]
    elif kind == "prune":
        ver = state["versions"][f"{op['object_id']}/{obj['current']}"]
        ver.update(blob="pruned", wraps=[])
    else:
        raise ValueError(kind)


def initial_state(v, now):
    """The vector workspace A as tests/drop_support.setup seeds it."""
    certs = v["certs"]["signed"]
    ids = v["ids"]
    full = ["look", "decide", "operate", "type"]
    devices = {}
    for name in ("phone", "laptop", "primary", "agent"):
        o = certs[name]["o"]
        devices[o["device_id"]] = {"sig_pub": R.unb64u(o["dk_sig_pub"]).hex(), "revoked": False,
                                   "expires_ms": o.get("expires_ms"),
                                   "drop_scoped": o["scopes_max"][0].startswith("drop:")}
    return {
        "now_ms": now, "counter": 0,
        "workspaces": {ids["workspace_a"]: {
            "owner": ids["person_alice"], "epoch": 1, "wxk_version": 1,
            "members": {ids["device_phone"]: full, ids["device_laptop"]: full},
            "holder": {"gen": 1, "lease_until_ms": now + 40_000},
            "wsk_pub": R.unb64u(v["card"]["card"]["o"]["wsk_pub"]).hex()}},
        "devices": devices, "objects": {}, "versions": {},
    }


def snapshot(state):
    return copy.deepcopy(state)
