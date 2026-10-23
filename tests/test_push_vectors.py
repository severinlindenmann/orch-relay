"""P3-D40b: the `push.apns_envelope` vector, replayed by the production relay (the APNs body bytes and
the 3,072-byte outer edge) and cross-checked against an independent spelling of §19.10's body."""

import json
from pathlib import Path

import pytest

from orch_relay import proto as P
from orch_relay.apns import apns_body
from orch_relay.common import MAX_OUTER

VECTORS = json.loads(Path("tests/vectors_v2.json").read_text())["suites"]["2"]["push"]
ENVELOPE = VECTORS["apns_envelope"]
CASES = ENVELOPE["cases"]


def test_the_vector_states_the_caps():
    assert (ENVELOPE["max_outer"], ENVELOPE["max_body"]) == (MAX_OUTER, 3175)
    assert ENVELOPE["alert"] == {"title": "orch", "body": "New activity in orch"}
    assert ENVELOPE["mutable_content"] == 1
    assert [c["name"] for c in CASES] == ["sealed_outer", "largest_outer", "outer_one_byte_over"]


@pytest.mark.parametrize("case", CASES, ids=lambda c: c["name"])
def test_replay(case):
    outer = case["outer"]
    raw = P.cj(outer)
    if "refuse" in case["expect"]:  # the hub path's outer_check (hub_phone) enforces the same edge
        assert len(raw) == len(case["cj_outer"].encode()) == MAX_OUTER + 1
        return
    assert len(raw) <= MAX_OUTER
    assert raw.decode() == case["cj_outer"]
    body = apns_body(raw)
    assert body.decode("ascii") == case["body"] and len(body) == case["body_len"]
    # the NSE reads userInfo["o"] as a string holding cj(outer); nothing else rides along
    parsed = json.loads(body)
    assert list(parsed) == ["aps", "o"] and parsed["o"] == case["cj_outer"]
    assert parsed["aps"] == {"alert": ENVELOPE["alert"], "mutable-content": 1}
    assert json.loads(parsed["o"]) == outer and P.cj(json.loads(parsed["o"])) == raw


def test_the_sealed_outer_is_the_vectors_raw_push():
    assert CASES[0]["cj_outer"] == VECTORS["raw"]
    assert CASES[1]["body_len"] == 3175 and len(CASES[1]["cj_outer"].encode()) == 3072
