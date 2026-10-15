"""P3-D39 (D39a1) relay-owned vector sections under suite 2's `drop`: `upload_frame` (the ODU2 encoding:
big-endian head_len, a head at and above the cap, a blob one byte short and long) and `relay_put` (chains of
PUT steps against one state, ref/drop_relay.py). The production relay replays both
(tests/test_drop_vectors.py). Public FAKE material only."""
import copy

from ref import drop_relay as M
from ref._drop_build import NOW, Builder


def add_drop_relay(out):
    v = out["suites"]["2"]
    b = Builder(v)
    base = M.initial_state(v, NOW)

    def step(state, who, signed_body, if_match, holder=None, content_length=None, recipe=None):
        signed, body = signed_body
        o_id = signed["o"]["object_id"] if signed else b.oid("frame")
        p = b.principal(who)
        result = M.put(state, p, o_id, body.hex(), if_match, holder, content_length)
        s = {"op": "put", "principal": p, "object_id": o_id, "if_match": if_match, "holder": holder,
             "body_hex": body.hex(), "expect": result}
        if content_length is not None:
            s["content_length"] = content_length
        if recipe is not None:  # a large body: prefix bytes, then `byte` repeated `count` times
            s.pop("body_hex")
            s["body_recipe"] = recipe
        return s

    def op(state, **o):
        M.apply(state, o)
        return {**o}

    cases = []

    def case(name, build, ops=()):
        state = copy.deepcopy(base)
        for o in ops:
            M.apply(state, o)
        start = copy.deepcopy(state)
        steps = build(state)
        cases.append({"name": name, "state": start, "steps": steps,
                      "after": {k: {f: x[f] for f in ("current", "n", "audience", "head_hash", "tombstone_kind",
                                                       "claimed_by")}
                                for k, x in state["objects"].items()}})

    ph, lap, ws = b.phone, b.laptop, b.ws
    d = b.oid("vector doc")

    def chain(state, n):
        steps, parent = [], None
        for ver in range(1, n + 1):
            s = b.upload(d, kind="document", version=ver, parent=parent)
            steps.append(step(state, ph, s, str(ver - 1)))
            parent = s[0]["o"]
        return steps, parent

    def create(state):
        return chain(state, 2)[0]
    case("create_with_if_match_0_then_the_next_version", create)

    def if_match_only(state):
        f = b.upload("vector if-match")
        return [step(state, ph, f, "1"), step(state, ph, f, "00"), step(state, ph, f, "0")]
    case("the_same_upload_with_a_wrong_then_the_right_if_match", if_match_only)

    def stale(state):
        steps, v1 = chain(state, 1)
        steps.append(step(state, lap, b.upload(d, kind="document", version=2, parent=v1, author=lap), "1"))
        steps.append(step(state, ph, b.upload(d, kind="document", version=2, parent=v1, content=b"mine"), "1"))
        return steps
    case("stale_writer_gets_version_conflict", stale)

    def fork(state):
        steps, _ = chain(state, 2)
        v1 = steps[0]
        v1o = M.R.parse_json(bytes.fromhex(v1["body_hex"])[8:8 + int.from_bytes(bytes.fromhex(v1["body_hex"])[4:8], "big")])
        steps.append(step(state, ph, b.upload(d, kind="document", version=3, parent=v1o["descriptor"]["o"]), "2"))
        return steps
    case("fork_attempt_with_the_parent_hash_of_version_1", fork)

    def file_v2(state):
        f = b.upload("vector file")
        steps = [step(state, ph, f, "0")]
        steps.append(step(state, ph, b.upload("vector file", version=2, parent=f[0]["o"]), "1"))
        return steps
    case("file_version_2_refused", file_v2)

    def retry(state):
        steps, _ = chain(state, 2)
        first = b.upload(d, kind="document")
        steps.append(step(state, ph, first, "0"))
        return steps
    case("exact_retry_after_the_head_moved", retry)

    def epoch(state):
        o_id = b.oid("vector epoch")
        old = b.upload(o_id, wraps=lambda o: [b.wrap(o, "wk", key_version=1)])
        new = b.upload(o_id, wraps=lambda o: [b.wrap(o, "wk", key_version=2)])
        return [step(state, ph, old, "0"), step(state, ph, new, "0")]
    case("wk_wrap_at_an_old_epoch_then_the_same_dek_rewrapped", epoch, ops=[{"op": "epoch", "epoch": 2}])

    def tomb(state):
        f = b.upload("vector expiring", expires=NOW + 120_000)
        steps = [step(state, ph, f, "0")]
        steps.append(op(state, op="clock", now_ms=NOW + 120_000))
        steps.append(step(state, ph, f, "0"))
        return steps
    case("tombstoned_then_retry", tomb)

    def inbox_doc(state):
        return [step(state, ph, b.upload("vector inbox doc", kind="document", recipients="inbox"), "0")]
    case("inbox_document_refused", inbox_doc)

    def retired(state):
        f = b.upload("vector retired")
        steps = [step(state, ph, f, "0"), op(state, op="retire", object_id=f[0]["o"]["object_id"])]
        steps.append(step(state, ph, f, "0"))
        return steps
    case("retired_file_then_retry", retired)

    def reuse(state):
        f = b.upload("vector reuse")
        steps = [step(state, ph, f, "0"), op(state, op="retire", object_id=f[0]["o"]["object_id"])]
        steps.append(step(state, lap, b.upload("vector reuse", author=lap, content=b"new"), "0"))
        return steps
    case("retired_file_then_version_1_under_the_same_id", reuse)

    def audience(state):
        o_id = b.oid("vector restricted")
        f = b.upload(o_id, author=ws, recipients=[lap])
        steps = [step(state, ws, f, "0", holder="1")]
        steps.append(step(state, ph, b.upload(o_id, recipients=[lap]), "0"))
        steps.append(op(state, op="retire", object_id=o_id))
        steps.append(step(state, ph, b.upload(o_id, recipients=[lap]), "0"))
        steps.append(step(state, lap, b.upload(o_id, author=lap, recipients=[lap]), "0"))
        return steps
    case("outside_a_device_only_audience_403_before_410", audience)

    def host(state):
        f = b.upload("vector host", author=ws)
        return [step(state, ws, f, "0", holder="0"), step(state, ws, f, "0", holder="1")]
    case("stale_holder_fenced_then_current_holder", host)

    # upload_frame: the encoding, against the initial state
    frames = []

    def fcase(name, body, content_length=None, recipe=None, signed=None):
        state = copy.deepcopy(base)
        s = step(state, ph, (signed, body), "0", content_length=content_length, recipe=recipe)
        s["name"] = name
        frames.append(s)

    signed, body = b.upload("frame")
    head_len = int.from_bytes(body[4:8], "big")
    fcase("valid_frame", body, signed=signed)
    assert body[4:8] == head_len.to_bytes(4, "big")  # u32 big-endian
    fcase("head_len_little_endian", body[:4] + head_len.to_bytes(4, "little") + body[8:], signed=signed)
    fcase("bad_magic", b"ODU1" + body[4:], signed=signed)
    olen = signed["o"]["content_len"]
    fcase("blob_one_byte_short", body[:-1], signed=signed)
    fcase("blob_one_byte_long", body + b"\0", signed=signed)
    fcase("content_length_above_the_frame", body, content_length=len(body) + 1, signed=signed)
    at_cap = b"ODU2" + M.MAX_HEAD.to_bytes(4, "big")
    state = copy.deepcopy(base)
    big = at_cap + b" " * M.MAX_HEAD + b"\0" * olen
    r = M.put(state, b.principal(ph), signed["o"]["object_id"], big.hex(), "0")
    frames.append({"name": "head_at_the_cap_parsed_then_malformed", "op": "put", "principal": b.principal(ph),
                   "object_id": signed["o"]["object_id"], "if_match": "0", "holder": None,
                   "body_recipe": {"prefix_hex": at_cap.hex(), "byte": 32, "count": M.MAX_HEAD,
                                   "suffix_hex": (b"\0" * olen).hex()}, "expect": r})
    over = b"ODU2" + (M.MAX_HEAD + 1).to_bytes(4, "big")
    big = over + b" " * (M.MAX_HEAD + 1)
    r = M.put(copy.deepcopy(base), b.principal(ph), signed["o"]["object_id"], big.hex(), "0")
    frames.append({"name": "head_above_the_cap", "op": "put", "principal": b.principal(ph),
                   "object_id": signed["o"]["object_id"], "if_match": "0", "holder": None,
                   "body_recipe": {"prefix_hex": over.hex(), "byte": 32, "count": M.MAX_HEAD + 1,
                                   "suffix_hex": ""}, "expect": r})
    assert [f["expect"]["status"] for f in frames] == [201, 413, 400, 400, 400, 400, 400, 413]
    v["drop"]["upload_frame"] = {"state": base, "cases": frames}
    v["drop"]["relay_put"] = cases
