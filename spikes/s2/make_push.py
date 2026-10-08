"""Spike S2: write `.apns` files (for `xcrun simctl push`) carrying protocol v2 section 9 sealed pushes (suite 2).

Uses ref/orch_protocol_ref.py only; demo workspace A material comes from tests/vectors_v2.json (suite 2).
Usage: uv run python spikes/s2/make_push.py [outdir] [--now-ms N]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from ref import orch_protocol_ref as R

BUNDLE_ID = "io.severin.orch"
DEMO_QUESTION_ID = "q-0167f4bf37be9ccc"
GENERIC = {"title": "orch", "body": "New activity"}   # what the relay sends in the clear: nothing about content


def material() -> dict:
    vec = json.loads((ROOT / "tests" / "vectors_v2.json").read_text(encoding="utf-8"))
    s2 = vec["suites"]["2"]
    case0 = s2["push"]["cases"][0]
    assert case0["name"] == "valid"
    keys = case0["keys"]                                      # the `valid` case: workspace A
    ws_hex, entry = next(iter(keys.items()))
    return {
        "suite": 2,
        "ws": ws_hex,
        "wsk_pub": entry["wsk_pub"],
        "wk": entry["wk"],                                    # {"1": hex}
        "wsk_seed": s2["keys"]["wsk_a.sig"]["seed"],          # host-side only, never bundled into the app
        "phone_seed": s2["keys"]["phone.sig"]["seed"],        # a member device (holds K_push, not WSK)
    }


def k_push_hex(m: dict, epoch: int = 1) -> str:
    return R.k_push(bytes.fromhex(m["wk"][str(epoch)]), bytes.fromhex(m["ws"]), epoch).hex()


def seal(m: dict, payload: dict, signer_seed: str | None = None) -> str:
    S = R.SUITES[2]
    ws = bytes.fromhex(m["ws"])
    wsk = S.sig_key(bytes.fromhex(signer_seed or m["wsk_seed"]))
    raw = R.seal_push(S, wsk, bytes.fromhex(m["wk"]["1"]), ws, 1, payload, os.urandom(16))
    return raw.decode()          # cj(outer): the exact bytes the relay forwards, as a JSON string


def apns(outer: str, bundle: str = BUNDLE_ID) -> dict:
    """The APNs JSON body the relay would send: fixed generic alert, mutable-content, no thread-id, and the sealed
    outer object as a JSON string in `o` (the receiver feeds those exact bytes to the section 9 rules)."""
    return {
        "Simulator Target Bundle": bundle,
        "aps": {"alert": dict(GENERIC), "mutable-content": 1, "sound": "default"},
        "o": outer,
    }


def build(now_ms: int) -> dict[str, dict]:
    m = material()
    q = {"kind": "question", "id": DEMO_QUESTION_ID, "label": "Ship L-0042?", "ts_ms": now_ms}
    closed = {"kind": "question.closed", "id": DEMO_QUESTION_ID, "label": "Answered on laptop", "ts_ms": now_ms + 1000}
    valid = seal(m, q)
    tampered = json.loads(valid)
    c = tampered["c"]
    tampered["c"] = c[:40] + ("A" if c[40] != "A" else "B") + c[41:]
    tampered = json.dumps(tampered, sort_keys=True, separators=(",", ":"))
    forged = seal(m, {**q, "label": "Wire 5000 EUR to attacker.example"}, signer_seed=m["phone_seed"])
    stale = seal(m, {**q, "id": "q-stale0000000001", "ts_ms": now_ms - 25 * 3600 * 1000, "label": "Old news"})
    return {
        "01_question": apns(valid),
        "02_tampered": apns(tampered),
        "03_forged_by_member_device": apns(forged),
        "04_stale_25h": apns(stale),
        "05_question_closed": apns(seal(m, closed)),
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("outdir", nargs="?", default=str(Path(__file__).parent / "out"))
    ap.add_argument("--now-ms", type=int, default=int(time.time() * 1000))
    a = ap.parse_args()
    out = Path(a.outdir)
    out.mkdir(parents=True, exist_ok=True)
    for name, body in build(a.now_ms).items():
        (out / f"{name}.apns").write_text(json.dumps(body, indent=1), encoding="utf-8")
        apns_body = {k: v for k, v in body.items() if k != "Simulator Target Bundle"}
        print(f"{name}.apns  APNs payload {len(json.dumps(apns_body, separators=(',', ':')))} bytes "
              f"(outer object {len(body['o'].encode())} bytes)")
    m = material()
    # public half + K_push(ws, e) only: a push receiver never needs WK_e
    app_material = {"suite": 2, "ws": m["ws"], "wsk_pub": m["wsk_pub"], "k_push": {"1": k_push_hex(m)}}
    (out / "demo_material.json").write_text(json.dumps(app_material, indent=1), encoding="utf-8")
    print("demo_material.json written (K_push + WSK pub, what the app is provisioned with; spike only)")


if __name__ == "__main__":
    main()
