"""Security review l2-e3 of orch-relay#88 (E3 cut-over). Adversarial tests; FAKE keys and tokens only.

Each test asserts the SAFE behaviour, so it fails on a44155e and documents a finding:
  F1 (P1) the cut-over PUT/DELETE is not fenced: a workspace session without the current holder generation changes
     a durable, DoS-capable state that every other workspace write (bridge, push send, hooks, membership) refuses.
  F2 (P1) after the drain window ("every direct route is refused") the hook routes still accept the workspace.
"""

from push_support import auth
from test_cutover import (  # noqa: F401  (fixture `c`)
    DAY,
    HID,
    WS,
    advance,
    c,
    code,
    cut_over,
    url,
)

from orch_relay import hooks


def test_f1_cutover_change_needs_the_holder_fence(c):  # noqa: F811
    # Baseline: a workspace write without the current holder generation is fenced.
    stale = auth("FAKE-workspace", "999")
    r = c.post(f"/v2/workspaces/{WS}/hooks", json={"hooks": []}, headers=stale)
    assert r.status_code == 409 and r.json()["error"] == "fenced", r.text
    # The cut-over must be fenced the same way (a stale/split-brain host must not cut the workspace off).
    r = c.put(url(), json={"v": 2, "hub_id": HID, "state": "cut_over"}, headers=stale)
    code(r, 409, "fenced")


def test_f1_reversal_needs_the_holder_fence(c):  # noqa: F811
    cut_over(c)
    r = c.delete(url(), headers=auth("FAKE-workspace", "999"))
    code(r, 409, "fenced")


def test_f2_hook_routes_are_refused_after_the_drain(c):  # noqa: F811
    cut_over(c)
    advance(c, 7 * DAY + 1000)
    c.app.state.bridge.sweep()
    host = auth("FAKE-workspace", "1")
    hh = hooks.hook_hash(f"hk_{1:032x}")
    body = {"hooks": [{"hook_hash": hh, "expires_ms": c.d.clock() + DAY}]}
    code(c.post(f"/v2/workspaces/{WS}/hooks", json=body, headers=host), 403, "cut_over")
    code(
        c.post(f"/v2/workspaces/{WS}/hooks/fetch", json={"ack": []}, headers=host), 403, "cut_over"
    )
