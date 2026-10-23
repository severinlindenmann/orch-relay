"""E3 (orch-core#896): the per-workspace cut-over switch. FAKE keys and tokens only.

The direct path (bridge envelopes, push registrations) is unchanged until a workspace is cut over to a hub; after
that it is refused with `cut_over` while the mailbox drains, then purged. Only the workspace's own session can set
or reverse the state; a hub can only confirm what the workspace named and never reverses."""

import itertools
from contextlib import closing
from pathlib import Path

import pytest
from bridge_support import RID, binary
from directory_support import NOW, WS
from fastapi.testclient import TestClient
from push_support import auth, configure, register, rows, seed_push, send, unregister
from test_hub_accounts import HID, OP1, ROGUE, ROOT, Key, card1, make_card, op_cert
from test_hub_relay_requests import insert_account, signed_headers

from orch_relay import db
from orch_relay.app import create_app

DAY = 86_400_000
HOST = {"Authorization": "Bearer FAKE-workspace", "Orch-Holder": "1"}
DEVICE_AUTH = {"Authorization": "Bearer FAKE-device", "Content-Type": "application/octet-stream"}
WS_AUTH = {"Authorization": "Bearer FAKE-workspace", "Content-Type": "application/json"}
OP_ROGUE = Key("hk_op_rogue")
ROGUE_CARD = make_card(ROGUE, OP_ROGUE, op_cert(ROGUE, OP_ROGUE, 1, "cc"))
OTHER = ROGUE_CARD["o"]["hub_id"]
nonces = itertools.count(1)


@pytest.fixture
def c(tmp_path, monkeypatch):
    listing = tmp_path / "allow.txt"
    listing.write_text(f"{ROOT.text}\n")
    monkeypatch.setenv("ORCH_RELAY_HUB_ALLOWLIST", str(listing))
    monkeypatch.setenv("ORCH_RELAY_DEV", "1")
    configure(monkeypatch, tmp_path)
    with TestClient(create_app(tmp_path / "data")) as client:
        d = client.app.state.directory
        seed_push(d)
        client.d = d
        assert client.post("/v2/hubs", json=card1()).status_code == 200
        insert_account(client, ROGUE_CARD)
        yield client


def url(ws=WS):
    return f"/v2/workspaces/{ws}/cutover"


def hub_url(hub=HID, ws=WS):
    return f"/v2/hubs/{hub}/workspaces/{ws}/cutover"


HUB_BODY = b'{"state":"cut_over","v":2}'  # contract 10.8.3: the signed bytes name the act


def hub_call(c, method="PUT", hub=HID, ws=WS, key=OP1, cert="aa" * 16, body=None):
    target = hub_url(hub, ws)
    body = (HUB_BODY if method == "PUT" else b"") if body is None else body
    headers = signed_headers(
        key,
        hub=hub,
        cert=cert,
        method=method,
        target=target,
        body=body,
        nonce=next(nonces).to_bytes(16, "big"),
        ts=c.d.clock(),
    )
    return c.request(method, target, headers=headers, content=body)


def name(c, hub=HID, state="pending", session="FAKE-workspace"):
    return c.put(url(), json={"v": 2, "hub_id": hub, "state": state}, headers=auth(session, "1"))


def post_request(c):
    return c.post(
        f"/v2/workspaces/{WS}/bridge/{RID}",
        content=binary("bridge_device_post"),
        headers=DEVICE_AUTH,
    )


def post_response(c):
    return c.post(
        f"/v2/workspaces/{WS}/bridge/{RID}",
        content=binary("bridge_host_post"),
        headers={**HOST, "Content-Type": "application/octet-stream"},
    )


def read_response(c):
    return c.get(
        f"/v2/workspaces/{WS}/bridge/{RID}", headers={"Authorization": "Bearer FAKE-device"}
    )


def code(r, status, error):
    assert (r.status_code, r.json()["error"]) == (status, error), r.text


def sql(c, statement, args=()):
    with closing(db.connect(c.d.path)) as con, con:
        return con.execute(statement, args).fetchall()


def advance(c, ms):
    c.d.clock = lambda: NOW + ms
    sql(c, "UPDATE holders SET lease_until_ms=?", (NOW + ms + 40_000,))
    sql(c, "UPDATE sessions SET expires_ms=?", (NOW + ms + 900_000,))


def cut_over(c):
    assert name(c).status_code == 200
    r = hub_call(c)
    assert r.status_code == 200, r.text
    return r.json()


# --- the direct path is unchanged without a cut-over ---------------------------------------------------------------


def test_direct_path_is_unchanged_without_cutover(c):
    assert c.get(url(), headers=auth("FAKE-workspace")).json() == {"state": "direct"}
    assert post_request(c).status_code == 202
    assert post_response(c).status_code == 202
    assert read_response(c).status_code == 200
    assert register(c).status_code == 200
    assert send(c, ["a" * 32]).status_code != 403  # reaches its own checks, not the gate


def test_naming_a_hub_changes_nothing_on_the_direct_path(c):
    r = name(c)
    assert (r.status_code, r.json()["state"], r.json()["hub_id"]) == (200, "pending", HID)
    assert post_request(c).status_code == 202
    assert register(c).status_code == 200


# --- after the cut-over -------------------------------------------------------------------------------------------


def test_cutover_refuses_direct_requests_and_the_mailbox_drains(c):
    assert post_request(c).status_code == 202
    assert post_response(c).status_code == 202
    assert register(c).status_code == 200
    state = cut_over(c)
    assert (state["state"], state["hub_id"]) == ("cut_over", HID)
    assert state["drain_until_ms"] == state["cut_over_ms"] + 7 * DAY
    # refused with a clear code: envelopes, pairing writes, push registration and push sends
    for r in (post_request(c), post_response(c), register(c, registration=2)):
        code(r, 403, "cut_over")
        assert r.json()["drained"] is False
    code(send(c, ["a" * 32]), 403, "cut_over")
    # an anonymous pairing request learns nothing: it is answered as for an unknown workspace (L2-E3-5)
    code(
        c.post(
            f"/v2/workspaces/{WS}/pair/{'0' * 32}/{RID}", content=b"x" * 200, headers=DEVICE_AUTH
        ),
        401,
        "unknown_workspace",
    )
    # but what is already in the mailbox is still readable, and push cleanup still works
    r = read_response(c)
    assert r.status_code == 200 and len(r.json()["chunks"]) == 1
    assert c.get(f"/v2/workspaces/{WS}/host/poll", headers=HOST).status_code == 200
    assert unregister(c).status_code == 200


def test_mailbox_is_purged_after_the_drain_window(c):
    assert post_request(c).status_code == 202
    assert post_response(c).status_code == 202
    assert register(c).status_code == 200
    cut_over(c)
    advance(c, 7 * DAY - 1000)
    assert read_response(c).status_code == 200  # still inside the window
    advance(c, 7 * DAY + 1000)
    code(read_response(c), 403, "cut_over")
    assert read_response(c).json()["drained"] is True
    c.app.state.bridge.sweep()
    assert sql(c, "SELECT count(*) FROM bridge_msgs WHERE workspace_id=?", (WS,))[0][0] == 0
    assert sql(c, "SELECT count(*) FROM rid_seen WHERE workspace_id=?", (WS,))[0][0] == 0
    assert rows(c.d, "workspace_id=?", (WS,)) == []
    assert c.get(url(), headers=auth("FAKE-workspace")).json()["purged"] is True
    c.app.state.bridge.sweep()  # idempotent


def test_other_workspaces_keep_their_direct_path(c):
    cut_over(c)
    other = "b" * 32
    assert (
        c.get(url(other), headers=auth("FAKE-workspace")).status_code == 403
    )  # not its own workspace
    assert sql(c, "SELECT count(*) FROM workspace_cutover")[0][0] == 1


def test_workspace_can_cut_over_by_itself(c):
    r = name(c, state="cut_over")
    assert (r.status_code, r.json()["state"]) == (200, "cut_over")
    code(post_request(c), 403, "cut_over")
    first = r.json()
    assert name(c, state="cut_over").json() == first  # idempotent, times kept


# --- who may do what -----------------------------------------------------------------------------------------------


def test_hub_request_for_a_workspace_that_named_another_hub_is_refused(c):
    assert name(c, hub=OTHER).status_code == 200
    code(hub_call(c), 403, "other_hub")  # HID did not get named
    assert c.get(url(), headers=auth("FAKE-workspace")).json()["state"] == "pending"
    code(hub_call(c, "GET"), 403, "other_hub")
    assert post_request(c).status_code == 202


def test_hub_cannot_cut_over_a_workspace_that_never_named_it(c):
    code(hub_call(c), 403, "other_hub")  # no row at all: same answer as another hub's workspace
    code(hub_call(c, ws="c" * 32), 403, "other_hub")  # unknown workspace: indistinguishable
    assert post_request(c).status_code == 202
    assert sql(c, "SELECT count(*) FROM workspace_cutover")[0][0] == 0


def test_hub_request_needs_the_hub_signature(c):
    assert name(c).status_code == 200
    r = c.put(hub_url(), content=b"")
    assert r.status_code in (400, 401), r.text
    other = hub_call(
        c, hub=OTHER, key=OP_ROGUE, cert="cc" * 16
    )  # a registered hub, but not the named one
    code(other, 403, "other_hub")
    r = hub_call(c, key=OP_ROGUE)  # right hub id, wrong key
    assert r.status_code == 401
    assert c.get(url(), headers=auth("FAKE-workspace")).json()["state"] == "pending"


def test_hub_cannot_reverse_the_cutover(c):
    cut_over(c)
    code(hub_call(c, "DELETE"), 403, "not_allowed")
    code(hub_call(c, "DELETE", hub=OTHER, key=OP_ROGUE, cert="cc" * 16), 403, "not_allowed")
    assert c.get(url(), headers=auth("FAKE-workspace")).json()["state"] == "cut_over"
    code(post_request(c), 403, "cut_over")
    # the hub's PUT is a confirm, never a way back; a repeat changes nothing
    first = c.get(url(), headers=auth("FAKE-workspace")).json()
    assert hub_call(c).json() == first


def test_hub_cannot_move_a_cutover_workspace_to_itself(c):
    assert name(c, hub=OTHER, state="cut_over").status_code == 200
    code(hub_call(c), 403, "other_hub")
    assert c.get(url(), headers=auth("FAKE-workspace")).json()["hub_id"] == OTHER


def test_workspace_reverses_the_cutover_by_its_own_signature(c):
    cut_over(c)
    code(post_request(c), 403, "cut_over")
    # a member device is not the workspace: it can read the state, never change it
    assert c.get(url(), headers=auth("FAKE-device")).json()["state"] == "cut_over"
    code(c.delete(url(), headers=auth("FAKE-device")), 403, "not_eligible")
    code(name(c, state="cut_over", session="FAKE-device"), 403, "not_eligible")
    assert c.get(url(), headers=auth("FAKE-workspace")).json()["state"] == "cut_over"
    r = c.delete(url(), headers=auth("FAKE-workspace", "1"))
    assert (r.status_code, r.json()) == (200, {"state": "direct"})
    assert post_request(c).status_code == 202
    assert register(c).status_code == 200
    assert c.delete(url(), headers=auth("FAKE-workspace", "1")).status_code == 200  # idempotent
    code(hub_call(c), 403, "other_hub")  # the hub's old confirm no longer works


def test_naming_a_hub_never_weakens_a_cutover(c):
    cut_over(c)
    r = name(c, hub=OTHER, state="pending")
    code(r, 403, "cut_over")  # contract 10.8.3
    assert c.get(url(), headers=auth("FAKE-workspace")).json()["state"] == "cut_over"


def test_requests_are_strict(c):
    for body in (
        {"v": 2, "hub_id": HID},
        {"v": 2, "hub_id": HID, "state": "direct"},
        {"v": 2, "hub_id": "xx", "state": "pending"},
        {"v": 1, "hub_id": HID, "state": "pending"},
        {"v": 2, "hub_id": HID, "state": "pending", "extra": 1},
    ):
        code(c.put(url(), json=body, headers=auth("FAKE-workspace", "1")), 400, "malformed")
    assert c.put(url(), content=b"[]", headers=auth("FAKE-workspace", "1")).status_code == 400
    code(c.get(url() + "?x=1", headers=auth("FAKE-workspace")), 400, "malformed")
    assert c.get(url()).status_code == 401  # no session
    assert sql(c, "SELECT count(*) FROM workspace_cutover")[0][0] == 0


# --- migration -----------------------------------------------------------------------------------------------------


def test_migration_is_idempotent_and_after_the_existing_ones(tmp_path):
    path = tmp_path / "m.sqlite3"
    first = db.migrate(path)
    assert "0024_workspace_cutover" in first
    assert first == sorted(first) and first.index("0024_workspace_cutover") > first.index(
        "0022_hub_request_nonces"
    )
    assert db.migrate(path) == []
    mig = Path(__file__).parent.parent / "src/orch_relay/migrations/0024_workspace_cutover.sql"
    with closing(db.connect(path)) as con, con:
        for stmt in db._statements(mig.read_text()):  # applying the script again changes nothing
            con.execute(stmt)


def test_route_wins_over_a_later_hub_catch_all(c):
    """E2 adds `/v2/hubs/{hub}/{tail:path}` after this module's install; the cut-over route must still answer."""
    from fastapi.responses import JSONResponse

    async def catch_all(hub_id_text: str, tail: str):
        return JSONResponse({"error": "not_found"}, status_code=404)

    c.app.add_api_route(
        "/v2/hubs/{hub_id_text}/{tail:path}", catch_all, methods=["GET", "PUT", "POST", "DELETE"]
    )
    assert name(c).status_code == 200
    assert hub_call(c).status_code == 200
