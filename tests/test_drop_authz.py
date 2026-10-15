"""P3-D39 authorization matrix: every Drop route against no session, the wrong principal kind
(a `drop:` scoped device; an author of the other kind), the wrong workspace (a W session of
another workspace, a non-member device), a device outside a device-only audience, and a stale
holder generation. Nothing is stored and nothing beyond the documented 403/404 oracle leaks."""

from contextlib import closing

import pytest
from directory_support import DEVICE, NOW, WS
from drop_support import LAPTOP, PRIMARY, WS_B, put, rows, setup, upload
from fastapi.testclient import TestClient

from orch_relay import db
from orch_relay.app import create_app
from orch_relay.directory import token_hash

READS = ("descriptor", "wraps", "blob", "descriptors", "list")


@pytest.fixture
def c(tmp_path):
    with TestClient(create_app(tmp_path)) as client:
        d = client.app.state.directory
        setup(d)
        with closing(db.connect(d.path)) as con, con:
            con.execute(
                "INSERT INTO workspaces SELECT ?,owner_person_id,wsk_pub,delegation,card,card_seq,"
                "wxk_version,client_hosted FROM workspaces WHERE workspace_id=?",
                (WS_B, WS),
            )
            for token, kind, ident in (
                ("FAKE-workspace-b", "workspace", WS_B),
                ("FAKE-primary", "device", PRIMARY),  # registered, not a member of WS
            ):
                con.execute(
                    "INSERT INTO sessions VALUES (?,?,?,?)",
                    (token_hash(token), kind, ident, NOW + 900_000),
                )
        # a device-only object (the laptop) and a space object with a claimed inbox file
        hidden, _, hb = upload("hidden", author=WS, recipients=[LAPTOP])
        assert put(client, hidden, hb).status_code == 201
        client.hidden = hidden["o"]["object_id"]
        yield client


def read(c, route, token, o_id, holder=None):
    h = {"Authorization": "Bearer " + token} if token else {}
    if holder is not None:
        h["Orch-Holder"] = holder
    if route == "list":
        return c.post(
            "/v2/drop/list", json={"workspace_id": WS, "direction": "received"}, headers=h
        )
    if route == "descriptors":
        return c.get(f"/v2/drop/{o_id}/descriptors", headers=h)
    return c.get(f"/v2/drop/{o_id}/versions/1/{route}", headers=h)


@pytest.mark.parametrize("route", READS)
def test_reads_no_session_wrong_kind_wrong_workspace(c, route):
    assert read(c, route, None, c.hidden).json() == {"error": "unauthenticated"}
    assert read(c, route, "garbage", c.hidden).status_code == 401
    assert read(c, route, "FAKE-agent", c.hidden).json() == {"error": "not_eligible"}  # drop:
    assert read(c, route, "FAKE-workspace-b", c.hidden).json() == {"error": "not_eligible"}
    assert read(c, route, "FAKE-primary", c.hidden).json() == {"error": "not_eligible"}


@pytest.mark.parametrize("route", ("descriptor", "wraps", "blob", "descriptors"))
def test_reads_outside_the_audience_403_never_state(c, route):
    assert read(c, route, "FAKE-device", c.hidden).json() == {"error": "not_eligible"}
    assert read(c, route, "FAKE-laptop", c.hidden).status_code == 200
    with closing(db.connect(c.app.state.directory.path)) as con, con:
        con.execute("UPDATE drop_objects SET tombstone_ms=?, tombstone_kind='retired'", (NOW,))
    assert read(c, route, "FAKE-device", c.hidden).json() == {"error": "not_eligible"}
    assert read(c, route, "FAKE-laptop", c.hidden).json() == {"error": "expired"}


def test_list_outside_the_audience_has_no_entry_nor_wraps(c):
    lap = read(c, "list", "FAKE-laptop", None).json()["objects"]
    assert [e["object_id"] for e in lap] == [c.hidden]
    assert {w["target_id"] for w in lap[0]["wraps"]} == {LAPTOP}
    assert read(c, "list", "FAKE-device", None).json() == {"objects": [], "next": None}


@pytest.mark.parametrize("route", READS)
def test_reads_need_no_holder_generation(c, route):
    """Reads are `W`, not `W(g)` (§19.9): a stale or absent Orch-Holder changes nothing."""
    assert read(c, route, "FAKE-workspace", c.hidden, holder="0").status_code == 200
    assert read(c, route, "FAKE-workspace", c.hidden).status_code == 200


def test_put_matrix_stores_nothing(c):
    path = c.app.state.directory.path
    before = (rows(path, "drop_objects"), rows(path, "drop_versions"), rows(path, "drop_usage"))
    signed, _, body = upload("m")
    url = f"/v2/drop/{signed['o']['object_id']}/versions"
    plain = {"If-Match": "0", "Content-Type": "application/octet-stream"}
    assert c.put(url, content=body, headers=plain).json() == {"error": "unauthenticated"}
    agent = {**plain, "Authorization": "Bearer FAKE-agent"}
    assert c.put(url, content=body, headers=agent).json() == {"error": "not_eligible"}
    # the wrong kind: a W session sending a device-authored descriptor, and the reverse
    assert put(c, signed, body, author=WS).json() == {"error": "not_eligible"}
    host, _, hb = upload("h", author=WS)
    assert put(c, host, hb, author=DEVICE).json() == {"error": "not_eligible"}
    # the wrong workspace: a W session of another workspace, a non-member device, a member
    # writing into a workspace it is not a member of
    b = {**plain, "Authorization": "Bearer FAKE-workspace-b", "Orch-Holder": "1"}
    assert c.put(f"/v2/drop/{host['o']['object_id']}/versions", content=hb, headers=b).json() == {
        "error": "fenced"
    }  # no holder row for B: fenced first
    prim, _, pb = upload("p", author=PRIMARY, recipients=[WS])
    assert c.put(
        f"/v2/drop/{prim['o']['object_id']}/versions",
        content=pb,
        headers={**plain, "Authorization": "Bearer FAKE-primary"},
    ).json() == {"error": "not_eligible"}
    foreign, _, fb = upload("f", space=WS_B, recipients=[WS_B])
    assert put(c, foreign, fb).json() == {"error": "not_eligible"}
    # recipients naming a non-member are 400 only once the caller may write (no member oracle)
    probe, _, pr = upload("probe", space=WS_B, recipients=[PRIMARY])
    assert put(c, probe, pr).json() == {"error": "not_eligible"}
    # outside the audience, and a stale holder
    out, _, ob = upload(c.hidden)
    assert put(c, out, ob).json() == {"error": "not_eligible"}
    assert put(c, host, hb, holder="0").json() == {"error": "fenced"}
    assert put(c, host, hb, holder="x").json() == {"error": "malformed"}
    after = (rows(path, "drop_objects"), rows(path, "drop_versions"), rows(path, "drop_usage"))
    assert [list(map(tuple, t)) for t in after] == [list(map(tuple, t)) for t in before]
    assert len([p for p in c.app.state.drop.blobs.rglob("*") if p.is_file()]) == 1
