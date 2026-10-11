"""Protocol §19.3 bridge regressions against the real HTTP application."""

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from directory_support import WS, seed
from orch_relay.app import create_app
from orch_relay import proto as P


@pytest.fixture
def client(tmp_path):
    with TestClient(create_app(tmp_path)) as client:
        seed(client.app.state.directory)
        yield client


def fixture_request(name):
    return json.loads(Path(f"tests/http_fixtures/{name}.json").read_text())["cases"][0]["request"]


def post_fixture(client, name):
    r = fixture_request(name)
    return client.post(r["path"], content=P.unb64u(r["body_b64u"]), headers=r["headers"])


def test_replay_coalesces(client):
    assert post_fixture(client, "bridge_device_post").status_code == 202
    assert post_fixture(client, "bridge_device_post").status_code == 202
    r = client.get(f"/v2/workspaces/{WS}/host/poll", headers={
        "Authorization": "Bearer FAKE-workspace", "Orch-Holder": "1"
    })
    assert r.status_code == 200
    assert len(r.json()["items"]) == 1


def test_fence_hold_conflict(client):
    r = client.post(f"/v2/workspaces/{WS}/host/hold", json={"gen": None, "take_over": False},
                    headers={"Authorization": "Bearer FAKE-workspace"})
    assert r.status_code == 409
    assert r.json() == {"error": "holder_conflict"}
