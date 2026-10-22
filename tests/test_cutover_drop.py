"""E3 round 2 (L2-E3-2): Drop is a direct route too. After the cut-over every Drop route of the workspace is refused,
and at the end of the drain the sweep releases its objects, versions, usage and blob files."""

from contextlib import closing

import pytest
from directory_support import DEVICE, NOW, WS
from drop_support import DAY, TOKENS, headers, put, rows, setup, upload, usage
from fastapi.testclient import TestClient

from orch_relay import db
from orch_relay.app import create_app

HUB = "ab" * 16


@pytest.fixture
def client(tmp_path):
    with TestClient(create_app(tmp_path)) as c:
        setup(c.app.state.directory)
        yield c


def cut(c, drain_until):
    with closing(db.connect(c.app.state.directory.path)) as con, con:
        con.execute(
            "INSERT INTO workspace_cutover(workspace_id, hub_id, state, set_by, requested_ms, cut_over_ms, "
            "drain_until_ms) VALUES (?,?, 'cut_over', 'workspace', ?, ?, ?)",
            (WS, HUB, NOW, NOW, drain_until),
        )


def test_drop_is_refused_after_the_cutover_and_purged_after_the_drain(client):
    s, _w, body = upload("a")
    assert put(client, s, body).status_code == 201
    blobs = [p for p in client.app.state.drop.blobs.rglob("*") if p.is_file()]
    assert len(blobs) == 1
    cut(client, NOW + 7 * DAY)
    o = s["o"]["object_id"]
    auth = {"Authorization": "Bearer " + TOKENS[DEVICE]}
    for r in (
        put(client, s, body, if_match="1"),
        client.get(f"/v2/drop/{o}/versions/1/blob", headers=auth),
        client.get(f"/v2/drop/{o}/versions/1/descriptor", headers=auth),
        client.get(f"/v2/drop/{o}/versions/1/wraps", headers=auth),
        client.post(
            "/v2/drop/list",
            json={"workspace_id": WS, "direction": "received"},
            headers={**headers(DEVICE, if_match=None), "Content-Type": "application/json"},
        ),
    ):
        assert (r.status_code, r.json()["error"]) == (403, "cut_over"), r.text
    # before the end of the drain nothing is released; after it the sweep empties the workspace
    client.app.state.drop.life.run()
    assert len(rows(client.app.state.directory.path, "drop_objects")) == 1
    client.app.state.directory.clock = lambda: NOW + 7 * DAY + 1000
    client.app.state.drop.life.run()
    path = client.app.state.directory.path
    assert rows(path, "drop_objects") == [] and rows(path, "drop_versions") == []
    assert all(v == (0, 0, 0, 0) for v in usage(path).values())
    assert not [p for p in client.app.state.drop.blobs.rglob("*") if p.is_file()]
