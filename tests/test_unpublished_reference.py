"""P3-D31: the reference model of the unpublished view, beyond replaying its vector group."""

import copy

from checkpoint_support import S, cases

from ref import checkpoints as C
from ref._unpublished_vectors import verify_item


def served():
    for case in cases("unpublished"):
        for step in case["steps"]:
            yield from step["expect"].get("items", [])


def test_every_served_item_verifies_on_its_own():
    """U11.2: the host verifies each item independently under the person key it names."""
    items = list(served())
    assert len(items) > 30
    assert all(verify_item(item) is None for item in items)


def test_the_item_check_refuses_mismatched_evidence():
    """The runner's check fails a relay that serves another device's certificate, another
    person's key, a wrong digest or a chain reason as strong as the served one."""
    items = {(i["device_id"], i["person_id"]): i for i in served()}
    one, other = [items[k] for k in sorted(items)[:2]]
    assert one["person_id"] != other["person_id"] or one["device_id"] != other["device_id"]
    for field, value, why in [
        ("device_cert", other["device_cert"], {"device_cert", "person_id"}),
        ("pk_pub", other["pk_pub"], {"person_id"}),
        ("provenance", {**one["provenance"], "digest": C.ZERO}, {"digest"}),
        ("chain_reason", one["reason"], {"chain_reason"}),
    ]:
        if field == "pk_pub" and value == one["pk_pub"]:
            continue
        assert verify_item({**one, field: value}) in why, field


def test_the_first_item_is_always_served(monkeypatch):
    """A page never comes back empty while items exist after the position, even when one item
    alone exceeds the byte bound (the walk would otherwise never advance)."""
    case = next(c for c in cases("unpublished") if c["name"] == "paging_limit_walk")
    state = copy.deepcopy(case["state"])
    monkeypatch.setattr(C, "UNPUBLISHED_BYTES", 100)
    first = C.dispatch(S, state, "unpublished_get", query={})
    assert len(first["items"]) == 1 and first["more"]
    rest = C.dispatch(S, state, "unpublished_get", query={"cursor": first["cursor"]})
    assert len(rest["items"]) == 1 and not rest["more"]
