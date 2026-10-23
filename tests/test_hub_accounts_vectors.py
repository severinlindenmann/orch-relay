"""E1: the relay's card verification against the shared hub contract vectors (orch-hub H0, V3-D8)."""

import json
from pathlib import Path

import pytest

from orch_relay import hub_accounts as H
from orch_relay import proto as P
from orch_relay.common import Refusal

VECTORS = json.loads((Path(__file__).parent / "vectors/hub/vectors_hub.json").read_text())
CHECKS = ("card", "card_text", "op_cert", "op_revoked")
CASES = [c for c in VECTORS["cases"] if c["check"] in CHECKS and not c["args"].get("pinned_root")]


def run(check, a):
    dev, now = a.get("dev_mode", True), a.get("now_ms", 0)
    revoked = frozenset(a.get("revoked_op_certs", []))
    if check == "op_cert":
        root = P.unb64u(a["hk_root_pub"], 65)
        return {"cert_id": H.verify_op_cert(a["signed"], root, now, dev, revoked)["cert_id"]}
    if check == "op_revoked":
        root = P.unb64u(a["hk_root_pub"], 65)
        return {"cert_id": H.verify_op_revoked(a["signed"], root)["cert_id"]}
    card = H.parse(bytes.fromhex(a["text_hex"])) if check == "card_text" else a["card"]
    held = None
    if a.get("held_card"):
        H.verify_card(a["held_card"], now, dev, revoked)
        held = a["held_card"]
    o, op, _root = H.verify_card(card, now, dev, revoked, held)
    return {"hub_id": o["hub_id"], "op_cert_id": op["cert_id"]}


def test_vectors_present():
    assert VECTORS["contract"] == "orch.hub/0" and len(CASES) >= 30


@pytest.mark.parametrize("case", CASES, ids=lambda c: c["name"])
def test_case(case):
    expect = case["expect"]
    if "ok" in expect:
        assert run(case["check"], case["args"]) == expect["ok"]
        return
    with pytest.raises(Refusal) as e:
        run(case["check"], case["args"])
    assert e.value.code == expect["error"]
