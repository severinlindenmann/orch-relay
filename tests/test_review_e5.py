"""Adversarial test from the Opus conformance review of orch-relay#90 (E5), tag l2-d15bH. FAKE keys only."""

from test_hub_channels import Phone, hub  # noqa: F401 - the fixture
from test_hub_phone import err


def test_revocation_does_not_depend_on_push_config(hub, monkeypatch):  # noqa: F811
    phone = Phone(hub.client)
    assert hub.mb_put(ch=phone.channel_id, c=b"sign request").status_code == 200
    # the relay loses its push configuration (restart without APNs config, same database)
    push = hub.client.app.state.push
    monkeypatch.setattr(type(push), "enabled", property(lambda s: False))
    r = hub.mb_purge(ch=phone.channel_id)  # the hub revokes the phone
    assert r.status_code == 200 and r.json()["deleted"] == 1, r.text  # E5R-1: recorded without push
    err(phone.list(), 403, "channel_revoked")  # the held message is gone for the revoked phone
    err(phone.get(), 403, "channel_revoked")
