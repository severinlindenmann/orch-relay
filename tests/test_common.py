"""The shared plumbing and the V3-D36 surface: the relay serves hubs only (D68, D69, D76, D77)."""

import pytest

from orch_relay import common as C
from orch_relay.app import create_app

NOW = 1_790_000_000_000


def test_the_route_surface_is_hub_only(tmp_path):
    docs = ("/docs", "/docs/oauth2-redirect", "/openapi.json", "/redoc")  # FastAPI's own
    paths = {r.path for r in create_app(tmp_path).routes if hasattr(r, "methods")} - set(docs)
    assert {"/healthz", "/v2/relay-info", "/v2/hubs", "/v2/hubs/op-revoked"} <= paths
    assert all(
        p in ("/healthz", "/v2/relay-info") or p.startswith(("/v2/hubs", "/v2/hub-channels"))
        for p in paths
    ), sorted(paths)


def test_fixed_window_refuses_over_the_cap_and_a_check_charges_nothing(tmp_path):
    core = C.Core(tmp_path / "r.db")
    try:
        for _ in range(3):
            core.rate("p", "a", C.MINUTE, 3, NOW, charge=False)
        for _ in range(3):
            core.rate("p", "a", C.MINUTE, 3, NOW)
        with pytest.raises(C.Refusal) as caught:
            core.rate("p", "a", C.MINUTE, 3, NOW)
        assert (caught.value.code, caught.value.status) == ("rate_limited", 429)
        core.rate("p", "a", C.MINUTE, 3, NOW + C.MINUTE)  # the next window
    finally:
        core.close()


def test_buckets_evict_full_entries_first_and_refill():
    b = C.Buckets(limit=2)
    b.take(("k", 1), 2, 60, NOW)
    b.take(("k", 1), 2, 60, NOW)
    with pytest.raises(C.Refusal):
        b.take(("k", 1), 2, 60, NOW)
    b.take(("k", 1), 2, 60, NOW + 1000)  # 60 per minute = one token a second
    b.take(("k", 2), 2, 60, NOW)
    b.take(("k", 3), 2, 60, NOW)
    assert len(b.table) == 2


def test_client_address_trusts_one_proxy_hop_only():
    assert (
        C.canonical_address("10.0.0.1", "203.0.113.5, 198.51.100.7", "10.0.0.1") == "198.51.100.7"
    )
    assert C.canonical_address("192.0.2.1", "203.0.113.5", "10.0.0.1") == "192.0.2.1"
    assert C.canonical_address("2001:db8::1", None, None) == "2001:db8::/64"
    assert C.ipv6_parent("2001:db8:0:1::/64") == "2001:db8::/56"
