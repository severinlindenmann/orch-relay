"""Test-wide settings. The Drop routes (P3-D39) are off by default in production (review F1,
ORCH_RELAY_DROP); the suite runs with them on, and tests/test_drop_authz.py checks the off state."""

import os

os.environ.setdefault("ORCH_RELAY_DROP", "1")


import pytest


@pytest.fixture(autouse=True)
def _no_real_apns(monkeypatch):
    """A test that forgot to inject a transport must never reach Apple: the gateways go nowhere."""
    from orch_relay import apns

    monkeypatch.setattr(
        apns, "GATEWAYS", {"production": "http://127.0.0.1:1", "sandbox": "http://127.0.0.1:1"}
    )
