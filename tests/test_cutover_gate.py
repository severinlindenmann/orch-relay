"""E3 round 2 (orch-relay#88; Opus review l2-e3: L2-E3-1..5): the holder fence, ONE cut-over gate with an allow-list,
the guard test that names every route, the 24 h `pending` expiry, registered hubs only, uniform anonymous answers, and the
shared hub vectors of contract §10.8.3. FAKE keys and tokens only."""

import json
from pathlib import Path

import pytest
from push_support import auth
from test_cutover import (  # noqa: F401  (fixture `c`)
    DAY,
    HID,
    OTHER,
    WS,
    advance,
    c,
    code,
    cut_over,
    hub_call,
    name,
    sql,
    url,
)

from orch_relay import cutover as C
from orch_relay import hooks
from orch_relay.directory import Refusal

SRC = Path(C.__file__).parent
VECTORS = json.loads((Path(__file__).parent / "vectors/hub/vectors_hub.json").read_text())
HOST = auth("FAKE-workspace", "1")
DEVICE = auth("FAKE-device")


# --- the guard test: every route is named, gated or on the allow-list ------------------------------------------------


def registered(app):
    for route in app.routes:
        path = getattr(route, "path", None)
        if path is None:
            continue
        for method in sorted(getattr(route, "methods", None) or ()):
            if method not in ("HEAD", "OPTIONS"):
                yield method, path


def test_every_route_is_named_in_the_policy(c):  # noqa: F811
    seen = list(registered(c.app))
    assert len(seen) > 40
    unnamed = [(m, p) for m, p in seen if C.name_of(m, p) is None]
    assert unnamed == [], (
        f"name these in cutover.NAMES (gated or allowed) or exempt them: {unnamed}"
    )
    assert {C.name_of(m, p) for m, p in seen} <= set(C.CLASS)


def test_the_allow_list_is_exactly_the_agreed_routes(c):  # noqa: F811
    allowed = {C.name_of(m, p) for m, p in registered(c.app)}
    opened = {n for n in allowed if C.CLASS[n] in ("open", "drain")}
    # mailbox reads during the drain, push unregister, the cut-over routes: nothing else
    assert opened == {
        "bridge_get",
        "pair_get",
        "host_hold",
        "host_poll",
        "push_unregister",
        "cutover",
        "cutover_hub",
    }


def test_every_closed_name_is_enforced_in_the_source():
    """Each gated policy name is the literal argument of a guard call somewhere outside cutover.py (bridge.py builds
    its six from the route and method, so those are checked by the behaviour tests instead)."""
    text = "\n".join(p.read_text() for p in SRC.glob("*.py") if p.name != "cutover.py")
    built = {"bridge_get", "bridge_post", "pair_get", "pair_post", "host_hold", "host_poll"}
    for name_, cls in C.CLASS.items():
        if cls in ("closed", "drain") and name_ not in built:
            assert f'"{name_}"' in text, name_


def test_an_unnamed_route_is_refused_fail_closed(c):  # noqa: F811
    cut_over(c)
    advance(c, 0)
    with c.d.reader("query") as con, pytest.raises(Refusal) as e:
        con.execute("BEGIN")
        C.guard(con, WS, c.d.clock(), "a_route_nobody_named")
    assert e.value.code == "cut_over"


# --- L2-E3-2: after the cut-over every other direct route is refused -----------------------------------------------


def hook_body():
    hh = hooks.hook_hash(f"hk_{1:032x}")
    return {"hooks": [{"hook_hash": hh, "expires_ms": 0}]}


CLOSED_CALLS = {
    "hooks_register": lambda cl: cl.post(
        f"/v2/workspaces/{WS}/hooks", json=hook_body(), headers=HOST
    ),
    "hooks_revoke": lambda cl: cl.post(
        f"/v2/workspaces/{WS}/hooks/revoke", json={"hooks": []}, headers=HOST
    ),
    "hooks_fetch": lambda cl: cl.post(
        f"/v2/workspaces/{WS}/hooks/fetch", json={"ack": []}, headers=HOST
    ),
    "members": lambda cl: cl.get(f"/v2/workspaces/{WS}/members", headers=DEVICE),
    "card_get": lambda cl: cl.get(f"/v2/workspaces/{WS}/card", headers=DEVICE),
    "card_put": lambda cl: cl.put(f"/v2/workspaces/{WS}/card", json={"card": {}}, headers=HOST),
    "membership": lambda cl: cl.put(f"/v2/workspaces/{WS}/membership", json={}, headers=HOST),
    "checkpoint": lambda cl: cl.get(f"/v2/workspaces/{WS}/checkpoint", headers=DEVICE),
    "cert_requests": lambda cl: cl.post(
        f"/v2/persons/{'c' * 32}/cert-requests", json={}, headers=HOST
    ),
}


@pytest.mark.parametrize("which", sorted(CLOSED_CALLS))
def test_closed_routes_are_refused_at_once_and_after_the_purge(c, which):  # noqa: F811
    if which not in ("card_put", "membership"):
        assert CLOSED_CALLS[which](c).json().get("error") != "cut_over"  # open before
    cut_over(c)
    r = CLOSED_CALLS[which](c)
    code(r, 403, "cut_over")
    assert r.json()["drained"] is False
    advance(c, 7 * DAY + 1000)
    r = CLOSED_CALLS[which](c)
    code(r, 403, "cut_over")
    assert r.json()["drained"] is True


def test_hooks_are_purged_with_the_rest(c):  # noqa: F811
    sql(
        c,
        "INSERT INTO hooks(hook_hash, workspace_id, created_ms, expires_ms) VALUES (?,?,?,?)",
        ("a" * 64, WS, 1, 2**60),
    )
    cut_over(c)
    advance(c, 7 * DAY + 1000)
    c.app.state.bridge.sweep()
    assert sql(c, "SELECT count(*) FROM hooks WHERE workspace_id=?", (WS,))[0][0] == 0


def test_a_cert_request_row_is_purged(c):  # noqa: F811
    sql(
        c,
        "INSERT INTO cert_requests VALUES (?,?,?,?,?,?,'open',NULL,NULL,NULL)",
        ("e" * 32, WS, "f" * 32, "1" * 32, "{}", 2**60),
    )
    cut_over(c)
    advance(c, 7 * DAY + 1000)
    c.app.state.bridge.sweep()
    assert sql(c, "SELECT count(*) FROM cert_requests WHERE workspace_id=?", (WS,))[0][0] == 0


def test_allow_list_still_works_after_the_purge(c):  # noqa: F811
    cut_over(c)
    advance(c, 7 * DAY + 1000)
    c.app.state.bridge.sweep()
    assert c.get(url(), headers=auth("FAKE-workspace")).json()["purged"] is True
    from push_support import unregister

    assert unregister(c).status_code == 200


# --- L2-E3-1: the fence --------------------------------------------------------------------------------------------


def test_cutover_changes_need_the_holder_fence(c):  # noqa: F811
    stale = auth("FAKE-workspace", "999")
    for body in ("pending", "cut_over"):
        r = c.put(url(), json={"v": 2, "hub_id": HID, "state": body}, headers=stale)
        code(r, 409, "fenced")
    no_holder = auth("FAKE-workspace")
    code(
        c.put(url(), json={"v": 2, "hub_id": HID, "state": "cut_over"}, headers=no_holder),
        409,
        "fenced",
    )
    assert c.get(url(), headers=stale).json() == {"state": "direct"}  # a read stays unfenced
    cut_over(c)
    code(c.delete(url(), headers=stale), 409, "fenced")
    assert c.get(url(), headers=stale).json()["state"] == "cut_over"


# --- L2-E3-4: pending expires, only registered hubs ----------------------------------------------------------------


def test_pending_expires_after_24_hours(c):  # noqa: F811
    assert name(c).status_code == 200
    advance(c, DAY - 1000)
    assert c.get(url(), headers=auth("FAKE-workspace")).json()["state"] == "pending"
    assert hub_call(c).status_code == 200  # still in time
    c.delete(url(), headers=auth("FAKE-workspace", "1"))
    assert name(c).status_code == 200
    advance(c, 3 * DAY)
    assert c.get(url(), headers=auth("FAKE-workspace")).json() == {"state": "direct"}
    code(hub_call(c), 403, "other_hub")  # a late confirm finds nothing
    assert name(c, state="pending").status_code == 200  # naming again is fine


def test_only_a_registered_hub_can_be_named(c):  # noqa: F811
    stranger = "ab" * 16
    for state in ("pending", "cut_over"):
        code(name(c, hub=stranger, state=state), 403, "unknown_hub")
    assert c.get(url(), headers=auth("FAKE-workspace")).json() == {"state": "direct"}
    assert name(c, hub=OTHER).status_code == 200  # registered, though not the one that confirms


# --- L2-E3-5: anonymous callers learn nothing ----------------------------------------------------------------------


def test_anonymous_pairing_cannot_read_the_cutover_state(c):  # noqa: F811
    cut_over(c)
    unknown = "d" * 32
    path = "/v2/workspaces/{}/pair/" + "0" * 32 + "/" + "1" * 32
    got = []
    for ws in (WS, unknown):
        got.append(
            c.post(
                path.format(ws),
                content=b"x" * 200,
                headers={"Content-Type": "application/octet-stream"},
            )
        )
    assert got[0].status_code == got[1].status_code == 401
    assert got[0].json() == got[1].json() == {"error": "unknown_workspace"}
    advance(c, 7 * DAY + 1000)
    r = c.get(path.format(WS))
    assert r.json() == c.get(path.format(unknown)).json()


# --- contract §10.8.3 (orch-hub#34): hub body, pending over cut_over, shared vectors ---------------------------------


def test_the_hub_put_body_is_exactly_state_cut_over(c):  # noqa: F811
    name(c)
    for body in (
        b"",
        b"{}",
        b'{"v":2,"state":"pending"}',
        b'{"v":2,"state":"cut_over","hub_id":"%s"}' % HID.encode(),
    ):
        code(hub_call(c, body=body), 400, "malformed")
    assert hub_call(c).status_code == 200


def test_pending_over_cut_over_is_cut_over(c):  # noqa: F811
    cut_over(c)
    r = name(c, hub=HID, state="pending")
    code(r, 403, "cut_over")


CASES = [x for x in VECTORS["cases"] if x["check"] == "relay_route" and "cutover" in x["name"]]
STATE_CASES = [x for x in VECTORS["cases"] if x["check"] == "cutover"]


def test_vectors_present():
    assert len(CASES) == 8 and len(STATE_CASES) == 14


@pytest.mark.parametrize("case", CASES, ids=lambda x: x["name"])
def test_route_vectors(case):
    a, expect = case["args"], case["expect"]
    try:
        route, ws = C.match(a["method"], a["target"], bytes.fromhex(a["body_hex"]))
    except Refusal as e:
        assert e.code == expect["error"]
        return
    assert expect["ok"] == {"route": route, "workspace_id": ws}


@pytest.mark.parametrize("case", STATE_CASES, ids=lambda x: x["name"])
def test_state_vectors(c, case):  # noqa: F811
    a, expect = case["args"], case["expect"]
    row = a["row"]
    if row is not None:
        now = c.d.clock()
        cols = "workspace_id, hub_id, state, set_by, requested_ms, cut_over_ms, drain_until_ms"
        over = row["state"] == "cut_over"
        sql(
            c,
            f"INSERT INTO workspace_cutover({cols}) VALUES (?,?,?,?,?,?,?)",
            (
                WS,
                row["hub_id"],
                row["state"],
                "workspace",
                now,
                now if over else None,
                now + 7 * DAY if over else None,
            ),
        )
    body = bytes.fromhex(a["body_hex"])
    # `registered_hubs` (vectors, §10.8.3): the hubs that have an account at this relay; a case without it names a hub
    # the relay never saw and expects it to exist, so it gets a stub row (the check is existence only).
    named = json.loads(body).get("hub_id") if body.startswith(b"{") else None
    stubs = a.get("registered_hubs", [named])
    for hub in stubs:
        if hub and not sql(c, "SELECT 1 FROM hub_accounts WHERE hub_id=?", (hub,)):
            sql(
                c,
                "INSERT INTO hub_accounts VALUES (?,?,?,?,?,?,?,?,?,?)",
                (hub, "k", "b" * 32, 1, 2**60, 1, 1, "{}", 0, 0),
            )
    if a["side"] == "hub":
        r = hub_call(c, a["method"], body=body)
        if "ok" in expect:
            assert r.status_code == 200, r.text
            assert {k: r.json()[k] for k in expect["ok"]} == expect["ok"]
        else:
            code(r, 403, expect["error"])
        return
    r = c.request(
        a["method"],
        url(),
        content=body,
        headers={**auth("FAKE-workspace", "1"), "Content-Type": "application/json"},
    )
    if "error" in expect:
        assert r.json()["error"] == expect["error"], r.text
        return
    assert r.status_code == 200, r.text
    got = sql(c, "SELECT hub_id, state FROM workspace_cutover WHERE workspace_id=?", (WS,))
    want = expect["ok"]["row"]
    assert (got[0][0], got[0][1]) == (want["hub_id"], want["state"]) if want else got == []
