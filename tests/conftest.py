"""Test-wide settings. The Drop routes (P3-D39) are off by default in production (review F1,
ORCH_RELAY_DROP); the suite runs with them on, and tests/test_drop_authz.py checks the off state."""

import os

import pytest

os.environ.setdefault("ORCH_RELAY_DROP", "1")


@pytest.fixture(autouse=True)
def drop_state_dir(tmp_path_factory, monkeypatch):
    """D39a2 part 4: with Drop on, a relay without a valid ORCH_RELAY_STATE serves no Drop route.
    Every test gets its own state directory, outside any data directory it uses."""
    monkeypatch.setenv("ORCH_RELAY_STATE", str(tmp_path_factory.mktemp("state")))


@pytest.fixture(autouse=True)
def _no_real_apns(monkeypatch):
    """A test that forgot to inject a transport must never reach Apple: the gateways go nowhere."""
    from orch_relay import apns

    monkeypatch.setattr(
        apns, "GATEWAYS", {"production": "http://127.0.0.1:1", "sandbox": "http://127.0.0.1:1"}
    )
