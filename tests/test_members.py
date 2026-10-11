"""Membership transactions through the HTTP boundary."""

from fastapi.testclient import TestClient
from directory_support import WS, seed
from orch_relay.app import create_app


def test_members_route(tmp_path):
    with TestClient(create_app(tmp_path)) as client:
        seed(client.app.state.directory)
        response = client.get(
            f"/v2/workspaces/{WS}/members",
            headers={"Authorization": "Bearer FAKE-workspace"},
        )
        assert response.status_code == 200
        assert response.json() == {"member_list": {}}
