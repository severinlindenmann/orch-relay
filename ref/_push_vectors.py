"""P3-D40b relay-owned vector `push.apns_envelope` (suite 2's `push` section): the sealed outer object
travels as the string `o` of the APNs body (protocol-v2 §19.10). `body` is the exact request body as text
(ASCII), `body_len` its byte length, `cj_outer` the canonical JSON of the outer. A relay refuses an outer
above 3,072 canonical bytes (400 `malformed`), so the largest body is 3,175 bytes. Public FAKE material only."""

import json

from ref import orch_protocol_ref as R

ALERT = '{"aps":{"alert":{"title":"orch","body":"New activity in orch"},"mutable-content":1},"o":'
MAX_OUTER = 3072
MAX_BODY = 3175


def body_of(outer):
    cj = R.cj(outer).decode()
    return cj, ALERT + json.dumps(cj) + "}"


def add_push_relay(out):
    v = out["suites"]["2"]
    sealed = json.loads(v["push"]["raw"])
    cases = []

    def case(name, outer):
        cj, body = body_of(outer)
        cases.append(
            {
                "name": name,
                "outer": outer,
                "cj_outer": cj,
                "body": body,
                "body_len": len(body.encode()),
                "expect": {"ok": True},
            }
        )
        return cj

    cj = case("sealed_outer", sealed)
    assert cj == v["push"]["raw"]  # the vector's raw outer is already canonical
    edge = {"v": 2, "ws": sealed["ws"], "epoch": sealed["epoch"], "c": ""}
    spare = MAX_OUTER - len(R.cj(edge))
    edge["c"] = "A" * spare
    assert len(R.cj(edge)) == MAX_OUTER
    case("largest_outer", edge)
    over = dict(edge, c="A" * (spare + 1))
    cases.append(
        {
            "name": "outer_one_byte_over",
            "outer": over,
            "cj_outer": R.cj(over).decode(),
            "expect": {"refuse": "malformed"},
        }
    )
    assert cases[1]["body_len"] == MAX_BODY
    v["push"]["apns_envelope"] = {
        "alert": {"title": "orch", "body": "New activity in orch"},
        "mutable_content": 1,
        "max_outer": MAX_OUTER,
        "max_body": MAX_BODY,
        "cases": cases,
    }
