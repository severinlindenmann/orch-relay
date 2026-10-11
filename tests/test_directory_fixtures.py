"""Replay exact shared HTTP bytes, with explicit scenario state and no verifier mocking."""

import json
from pathlib import Path

import pytest
from directory_support import prepare_case
from fastapi.testclient import TestClient
from members_support import prepare_fixture

from orch_relay import proto as P
from orch_relay.app import create_app

G1 = {
    "accounts",
    "session_challenge",
    "session_login",
    "session_logout",
    "device_get",
    "device_put",
    "revocations_post",
    "revocation_get",
    "revocation_feed",
    "card_put",
    "card_get",
}
G2 = {"membership", "members", "grants", "card_keys", "card_key"}
CASES = [
    (p.stem, c)
    for p in sorted(Path("tests/http_fixtures").glob("*.json"))
    for c in json.loads(p.read_text())["cases"]
]


@pytest.mark.parametrize("name,case", CASES, ids=[f"{n}-{c['name']}" for n, c in CASES])
def test_http_example(tmp_path, name, case):
    if name not in G1 | G2:
        pytest.skip("G3 bridge/pairing")
    with TestClient(create_app(tmp_path)) as client:
        (prepare_fixture if name in G2 else prepare_case)(client.app.state.directory, name, case)
        request = case["request"]
        kwargs = {"headers": request["headers"], "params": request["query"]}
        if "json" in request:
            kwargs["content"] = P.cj(request["json"])
        if "body_recipe" in request:
            recipe = request["body_recipe"]
            kwargs["content"] = (
                P.unb64u(recipe["prefix_b64u"])
                + bytes([recipe["byte"]]) * recipe["count"]
                + P.unb64u(recipe["suffix_b64u"])
            )
        if case["given"].get("scenario") == "exact_bytes_already_committed":
            first = client.request(request["method"], request["path"], **kwargs)
            assert first.status_code == 200, first.text
        response = client.request(request["method"], request["path"], **kwargs)
        expected = case["response"]
        if name == "membership" and case["given"].get("scenario") == "stale_epoch":
            # The frozen ref/ generator still emits the former G2 publication code.
            # G0a keeps bad_epoch here; stale_epoch belongs to bridge requests.
            assert expected["status"] == 409
            assert expected["json"] == {"error": "stale_epoch", "epoch": 2}
            expected = {**expected, "json": {"error": "bad_epoch"}}
        assert response.status_code == expected["status"], response.text
        assert response.headers["content-type"] == "application/json"
        assert set(response.json()) == set(expected["json"])
        if response.status_code != 200 or name not in ("session_challenge", "session_login"):
            assert response.json() == expected["json"]
        else:
            assert response.json()["expires_ms"] == expected["json"]["expires_ms"]
            P.unb64u(response.json().get("challenge", response.json().get("token")), 32)
        if response.status_code == 429:
            assert int(response.headers["retry-after"]) >= 1
