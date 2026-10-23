"""GET /v2/relay-info (H12d, P3-D38; protocol §19.1, orch-core orch-v2-host §9.8).

`{"v": 1, "reader": N, "max_publication_bytes": M}`: N is a code constant (RELAY_READER_LEVEL), never a
setting; M is the configured ORCH_RELAY_MAX_PUBLICATION_BYTES (P3-D37). Unauthenticated, no workspace
data, `Cache-Control: no-store`, throttled per address (60/min) and per IPv6 /56 (960/min) like the
public revocation read. An honest-operator statement, never a security control: a hostile relay can
claim any level. Clocks are injected and frozen, so every count is exact. FAKE data only.
"""

import inspect

import pytest
from fastapi.testclient import TestClient

from orch_relay import common as D
from orch_relay import relay_info as RI
from orch_relay.app import create_app

PATH = "/v2/relay-info"
PROXY = "10.9.9.9"
NOW = 1_790_000_000_000
WS = "ab" * 16
DEVICE = "cd" * 16
MAX_PUBLICATION = RI.MAX_PUBLICATION
STAGE_CAP = RI.STAGE_CAP


@pytest.fixture
def client(tmp_path):
    with TestClient(create_app(tmp_path), client=(PROXY, 50000)) as client:
        d = client.app.state.core
        d.clock = lambda: NOW
        d.trusted_proxy = PROXY
        yield client


def get(client, address="192.0.2.1", **kw):
    return client.get(PATH, headers={"X-Forwarded-For": address, **kw.pop("headers", {})}, **kw)


def test_shape_and_values(client):
    r = get(client)
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/json"
    assert r.headers["cache-control"] == "no-store"
    assert r.json() == {"v": 1, "reader": 1, "max_publication_bytes": MAX_PUBLICATION}
    assert list(r.json()) == ["v", "reader", "max_publication_bytes"]
    assert "set-cookie" not in r.headers and "access-control-allow-origin" not in r.headers


def test_level_is_the_code_constant_and_needs_convenience():
    assert RI.RELAY_READER_LEVEL == 1 and type(RI.RELAY_READER_LEVEL) is int
    # No setting can change it: the level is a constant, never read from the environment.
    assert "environ" not in inspect.getsource(RI.answer)


@pytest.mark.parametrize(
    "name",
    ["ORCH_RELAY_READER", "ORCH_RELAY_READER_LEVEL", "ORCH_RELAY_RELAY_INFO_READER", "READER"],
)
def test_an_operator_setting_cannot_change_the_level(tmp_path, monkeypatch, name):
    monkeypatch.setenv(name, "7")
    with TestClient(create_app(tmp_path)) as c:
        assert c.get(PATH).json()["reader"] == 1


@pytest.mark.parametrize("value", ["1", "4194304", str(STAGE_CAP)])
def test_max_follows_the_setting(tmp_path, monkeypatch, value):
    monkeypatch.setenv("ORCH_RELAY_MAX_PUBLICATION_BYTES", value)
    with TestClient(create_app(tmp_path)) as c:
        body = c.get(PATH).json()
        assert body["max_publication_bytes"] == int(value)


def test_max_defaults_without_the_setting(tmp_path, monkeypatch):
    monkeypatch.delenv("ORCH_RELAY_MAX_PUBLICATION_BYTES", raising=False)
    with TestClient(create_app(tmp_path)) as c:
        assert c.get(PATH).json()["max_publication_bytes"] == 16 * 1024 * 1024


def test_no_auth_and_the_same_answer_for_any_caller_or_state(client):
    """No session is needed, a bad or valid bearer changes nothing, and no workspace data appears."""
    empty = get(client).json()
    client.app.state.core.clock = lambda: NOW
    answers = [
        get(client, address="192.0.2.2").json(),
        get(client, address="192.0.2.3", headers={"Authorization": "Bearer nope"}).json(),
        get(client, address="192.0.2.4", headers={"Authorization": "Bearer FAKE-device"}).json(),
        get(client, address="192.0.2.5", headers={"Orch-Holder": "1", "Cookie": "a=b"}).json(),
    ]
    assert all(a == empty for a in answers)
    text = str(answers)
    assert WS not in text and DEVICE not in text


def test_query_parameters_are_refused(client):
    r = client.get(PATH, params={"workspace": WS}, headers={"X-Forwarded-For": "192.0.2.9"})
    assert r.status_code == 400 and r.json() == {"error": "malformed"}
    assert r.headers["cache-control"] == "no-store"


def test_other_methods_are_refused(client):
    for method in ("POST", "PUT", "DELETE", "PATCH"):
        assert client.request(method, PATH).status_code == 405


def test_address_window_is_deterministic(client, monkeypatch):
    monkeypatch.setattr(RI, "RELAY_INFO_READ", 3)
    assert [get(client).status_code for _ in range(3)] == [200] * 3
    r = get(client)
    assert r.status_code == 429 and r.json() == {"error": "rate_limited"}
    assert r.headers["retry-after"] == "40"  # to the end of the frozen clock's minute window
    assert r.headers["cache-control"] == "no-store"
    assert get(client, address="192.0.2.77").status_code == 200  # another address
    windows = client.app.state.core.windows
    assert windows[("relay-info", "192.0.2.1", D.MINUTE)][1] == 3
    client.app.state.core.clock = lambda: NOW + D.MINUTE  # the next window
    assert get(client).status_code == 200


def test_the_default_caps(client):
    assert (RI.RELAY_INFO_READ, RI.RELAY_INFO_READ_PARENT) == (60, 960)
    assert [get(client).status_code for _ in range(60)] == [200] * 60
    assert get(client).status_code == 429


def test_ipv6_parent_window(client, monkeypatch):
    monkeypatch.setattr(RI, "RELAY_INFO_READ_PARENT", 3)
    assert [get(client, f"2001:db8:0:{i}::1").status_code for i in range(1, 4)] == [200] * 3
    r = get(client, "2001:db8:0:4::1")  # a fresh /64 in the same /56
    assert r.status_code == 429 and r.headers["retry-after"]
    assert get(client, "2001:db8:0:100::1").status_code == 200  # another /56
    # The refused read charged neither window (both are checked before either is charged).
    windows = client.app.state.core.windows
    assert ("relay-info", "2001:db8:0:4::/64", D.MINUTE) not in windows
    assert windows[("relay-info-parent", "2001:db8::/56", D.MINUTE)][1] == 3


def test_windows_are_separate_from_the_revocation_read(client, monkeypatch):
    monkeypatch.setattr(RI, "RELAY_INFO_READ", 1)
    assert get(client).status_code == 200
    assert get(client).status_code == 429
    r = client.get(f"/v2/devices/{DEVICE}/revocation", headers={"X-Forwarded-For": "192.0.2.1"})
    assert r.status_code == 404  # its own window is untouched


def test_route_is_in_the_protocol_table():
    from pathlib import Path

    doc = (Path(__file__).resolve().parents[1] / "docs/protocol-v2.md").read_text()
    table = doc.split("## 19. Relay HTTP API", 1)[1]
    assert "| `GET /v2/relay-info` | none |" in table
