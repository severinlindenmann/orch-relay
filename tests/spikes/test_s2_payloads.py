"""Spike S2: the .apns payloads that make_push.py writes open (or are refused) exactly as intended with ref."""
import importlib.util
import json
import time
from pathlib import Path

from ref import orch_protocol_ref as R

SPEC = importlib.util.spec_from_file_location("make_push", Path(__file__).parents[2] / "spikes" / "s2" / "make_push.py")
mp = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mp)

NOW = int(time.time() * 1000)
APNS_LIMIT = 4096


def keys():
    m = mp.material()
    return {m["ws"]: {"wsk_pub": m["wsk_pub"], "wk": m["wk"]}}


def open_(body, last=None):
    assert isinstance(body["o"], str)                      # the relay forwards `o` as a string, unchanged
    return R.sw_open_push(R.SUITES[2], body["o"].encode(), keys(), {} if last is None else last, NOW + 2000)


def test_all_payloads_fit_in_4kb_and_outer_in_3kb():
    for name, body in mp.build(NOW).items():
        apns = {k: v for k, v in body.items() if k != "Simulator Target Bundle"}
        assert len(json.dumps(apns, separators=(",", ":"))) < APNS_LIMIT, name
        assert len(body["o"].encode()) <= R.MAX_PUSH, name
        assert body["aps"]["alert"] == mp.GENERIC and body["aps"]["mutable-content"] == 1
        assert "thread-id" not in body["aps"] and set(body) == {"Simulator Target Bundle", "aps", "o"}


def test_valid_question_then_closed_then_replay():
    b = mp.build(NOW)
    last = {}
    r = open_(b["01_question"], last)
    assert r["result"] == "show" and r["label"] == "Ship L-0042?" and r["tag"] == mp.DEMO_QUESTION_ID
    c = open_(b["05_question_closed"], last)
    assert c["result"] == "show" and c["kind"] == "question.closed" and c["tag"] == r["tag"]
    assert open_(b["01_question"], last) == {"result": "drop", "why": "replay"}


def test_bad_payloads_are_refused_with_the_expected_reason():
    b = mp.build(NOW)
    assert open_(b["02_tampered"]) == {"result": "drop", "why": "tag"}
    assert open_(b["03_forged_by_member_device"]) == {"result": "drop", "why": "signature"}
    assert open_(b["04_stale_25h"]) == {"result": "drop", "why": "stale"}


def test_app_material_has_k_push_not_wk():
    m = mp.material()
    kp = bytes.fromhex(mp.k_push_hex(m))
    assert kp == R.k_push(bytes.fromhex(m["wk"]["1"]), bytes.fromhex(m["ws"]), 1)
    app = {"ws", "wsk_pub", "k_push", "suite"}
    assert set(json.loads(json.dumps({"suite": 2, "ws": m["ws"], "wsk_pub": m["wsk_pub"], "k_push": {"1": kp.hex()}}))) == app
