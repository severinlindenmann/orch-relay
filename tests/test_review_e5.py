"""Adversarial test from the Opus conformance review of orch-relay#90 (E5), tag l2-d15bH. FAKE keys only."""

import pytest
from test_hub_channels import Phone, hub  # noqa: F401 - the fixture
from test_hub_phone import err


@pytest.mark.xfail(
    strict=True,
    reason="E5R-1: the purge/revocation is gated by push.enabled, the channel read is not",
)
def test_revocation_does_not_depend_on_push_config(hub, monkeypatch):  # noqa: F811
    phone = Phone(hub.client)
    assert hub.mb_put(ch=phone.channel_id, c=b"sign request").status_code == 200
    # the relay loses its push configuration (restart without APNs config, same database)
    push = hub.client.app.state.push
    monkeypatch.setattr(type(push), "enabled", property(lambda s: False))
    r = hub.mb_purge(ch=phone.channel_id)  # the hub revokes the phone
    assert r.status_code == 200, r.text  # today: 404 not_found, nothing recorded
    err(
        phone.list(), 403, "channel_revoked"
    )  # today: 200 with the held message, readable until its TTL


def test_proof_revoked_phone_keeps_reading_without_push_config(hub, monkeypatch):  # noqa: F811
    phone = Phone(hub.client)
    hub.mb_put(ch=phone.channel_id, c=b"sign request")
    monkeypatch.setattr(type(hub.client.app.state.push), "enabled", property(lambda s: False))
    err(hub.mb_purge(ch=phone.channel_id), 404, "not_found")
    assert [m["id"] for m in phone.list().json()["messages"]] != []  # E5R-1: still served
    assert phone.get().status_code == 200
