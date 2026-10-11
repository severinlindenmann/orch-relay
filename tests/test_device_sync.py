"""§19.8 device synchronisation: F1's own receiver cases as an independent oracle for the
reference judge, plus the targeted checks behind the device walk and the review-3 transport fix."""

import copy
import hashlib
import json
from pathlib import Path

import pytest

from ref import checkpoints as C
from ref import orch_protocol_ref as R

HERE = Path(__file__).parent
F1 = json.loads((HERE / "vectors/f1_receiver_e9a26d9.json").read_text())
S = R.SUITES[2]
V = json.loads(R.VECTORS.read_text())["suites"]["2"]
CASES = {c["name"]: c for c in V["checkpoints"]["cases"]}
MERGED = "e9a26d95c247c4ff7794ae9abfc816a9032e576f"  # orch-core #387 (receiver revocation split), on develop


def by_name(cases):
    return pytest.mark.parametrize("c", cases, ids=lambda c: c["name"])


def test_extract_matches_the_f1_snapshot():
    """The extract is a byte-faithful subset of orch-core checkpoint.json at #387 (e9a26d95), which is also the
    commit tests/vectors/f1 pins (SOURCE)."""
    src = F1["source"]
    assert src["commit"] == MERGED
    assert f"Commit: {MERGED}" in (HERE / "vectors/f1/SOURCE").read_text()
    assert len(F1["transition_cases"]) == 115 and len(F1["workspace_n_offers"]) == 30
    raw = (HERE / "vectors/f1/checkpoint.json").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == src["sha256"]
    full = json.loads(raw)
    assert all(full[k] == F1[k] for k in src["keys"])
    assert set(F1) == {"source", "note", *src["keys"]} and F1["note"] == full["note"]


def judge(f1, held, offered, now, **kw):
    return C.judge_offer(
        S,
        held["o"] if held else None,
        offered["o"],
        genesis=f1["genesis"],
        workspace_id=f1["workspace_id"],
        now=C.timestamp(now),
        wsk_pub=f1["wsk_pub"],
        **kw,
    )


REFUSED = ("chain.diverged", None, (), ())
NOTHING = {"known_devices": {}, "known": [], "local": [], "learned_later": []}


def view(c):
    """The case's receiver view (orch-core #387 ReceiverView): every field given, {} / [] meaning none."""
    return {
        "restore": c["restore"],
        "applied": c["applied"],
        "proofs": c["proofs"],
        "card": c["pinned_delegation"],
        "known": c["known_revocations"],
        "local": c["local_revocations"],
        "known_devices": c["known_devices"],
        "learned_later": [],
    }


@by_name(F1["transition_cases"])
def test_f1_transition_cases_against_reference_judge(c):
    """orch-core #387's receiver cases: one defect each, judged with the case's own view and clock."""
    got = judge(
        F1,
        c["held"],
        c["offered"],
        c["now"],
        **{**view(c), "learned_later": c["learned_later_in_walk"]},
    )
    alarms = (c["restore"]["event"]["actor"]["device"],) if c.get("alarm") else ()
    assert got == (c["expect"], c["recorded"], alarms, tuple(c["unpublished"]))
    if c["learned_later_in_walk"]:  # only the receiver's order separates this case from a refusal
        for field in ("known", "local"):  # held when judging, in either collection
            again = judge(
                F1,
                c["held"],
                c["offered"],
                c["now"],
                **{**view(c), field: c["learned_later_in_walk"]},
            )
            if (
                c["name"] == "cross_person_compromised_learned_later_no_alarm"
            ):  # another person's: never refuses
                assert again == ("ok", c["recorded"], (), ()), field
            else:
                assert again == REFUSED, field


@by_name(F1["workspace_n_offers"])
def test_f1_workspace_n_offers_against_reference_judge(c):
    held = c["held"] if "held" in c else F1["workspace_n_held"]
    got = judge(F1, held, c["checkpoint"], c["now"], proofs=c.get("proofs"), **NOTHING)
    assert got == (c["expect"], None, (), ())


@pytest.mark.parametrize("missing", sorted(NOTHING))
def test_judge_requires_every_receiver_view_field(missing):
    """orch-core #377 B1 / #387: every ReceiverView field is required (local_revocations included); forgetting one
    fails loudly instead of meaning "nothing known"."""
    c = F1["workspace_n_offers"][0]
    fields = {k: v for k, v in NOTHING.items() if k != missing}
    assert judge(F1, F1["workspace_n_held"], c["checkpoint"], c["now"], **NOTHING)[0] == c["expect"]
    with pytest.raises(TypeError):
        judge(F1, F1["workspace_n_held"], c["checkpoint"], c["now"], **fields)


def _evidence_case():
    c = copy.deepcopy(
        next(
            x
            for x in F1["transition_cases"]
            if x["name"] == "own_evidence_for_a_known_active_device"
        )
    )
    assert judge(F1, c["held"], c["offered"], c["now"], **view(c))[0] == "ok"
    return c


def test_judge_with_explicit_none_known_devices_refuses():
    """An explicit None is not "no devices" ({} is): it fails closed instead of skipping evidence binding."""
    c = _evidence_case()
    got = judge(F1, c["held"], c["offered"], c["now"], **{**view(c), "known_devices": None})
    assert got == REFUSED


def test_known_device_without_a_stored_key_binds_the_person_only():
    """orch-core binds person and, only when it stores one, the key: a None pk_pub is "no key", not a value."""
    c = _evidence_case()
    device, kd = next(iter(c["known_devices"].items()))
    keyless = {device: {"person_id": kd["person_id"], "pk_pub": None}}
    got = judge(F1, c["held"], c["offered"], c["now"], **{**view(c), "known_devices": keyless})
    assert got[0] == "ok"
    absent = {device: {"person_id": kd["person_id"]}}
    got = judge(F1, c["held"], c["offered"], c["now"], **{**view(c), "known_devices": absent})
    assert got[0] == "ok"
    other = {device: {"person_id": "ff" * 16, "pk_pub": None}}
    got = judge(F1, c["held"], c["offered"], c["now"], **{**view(c), "known_devices": other})
    assert got == REFUSED


def test_walk_alarm_case_alarms_through_the_device_state():
    """The walk raises C3 alarms itself (raise_alarms over every learned revocation, across walks): the
    shared alarm case, replayed as device state, alarms for the signer and keeps the transition."""
    c = next(x for x in F1["transition_cases"] if x.get("alarm"))
    signer = c["restore"]["device_cert"]["o"]
    signed = {"device": signer["device_id"], "person_id": signer["person_id"]}
    dev = {"signers": {c["restore"]["event"]["id"]: signed}, "alarms": []}
    C.raise_alarms(dev, [x["revocation"] for x in c["learned_later_in_walk"]])
    assert dev["alarms"] == [signer["device_id"]]
    # #387: matched by device and person, like the refusal; another person's revocation of the id never alarms.
    other = {
        "signers": {c["restore"]["event"]["id"]: {**signed, "person_id": "ff" * 16}},
        "alarms": [],
    }
    C.raise_alarms(other, [x["revocation"] for x in c["learned_later_in_walk"]])
    assert other["alarms"] == []


@pytest.mark.parametrize("field", ["known", "local"])
def test_f1_held_revocation_of_signer_refuses_device_and_person(field):
    # Review 1 / C3 in F1 terms: a held revocation (either collection) refuses the signer whatever the reason;
    # #387: only when it names the signer's device and person.
    c = copy.deepcopy(
        next(x for x in F1["transition_cases"] if x["name"] == "restore_accumulator_fold")
    )
    assert judge(F1, c["held"], c["offered"], c["now"], **view(c))[0] == "ok"
    signer = c["restore"]["device_cert"]["o"]
    for reason in ("lost", "retired", "compromised"):
        # Another person's revocation of the signer's id never refuses as C3. Held as chain-learned, a workspace
        # restore would still have to carry it (completeness, which it cannot for its own signer): F1 does the same.
        other = "chain.diverged" if field == "known" else "ok"
        for person, expect in ((signer["person_id"], "chain.diverged"), ("ff" * 16, other)):
            rev = {"o": {"device_id": signer["device_id"], "reason": reason, "person_id": person}}
            got = judge(
                F1, c["held"], c["offered"], c["now"], **{**view(c), field: [{"revocation": rev}]}
            )
            assert got[0] == expect, (reason, person)


def _publication(name="ticket_restore"):
    case = CASES[name]
    state = copy.deepcopy(case["state"])
    for step in case["steps"][:-1]:
        C.dispatch(S, state, **step["input"])
    return state, copy.deepcopy(case["steps"][-1]["input"])


def test_ticket_restore_verifies_only_the_named_log_context(monkeypatch):
    # Review 3: no search over T's tickets. Add many ticket entries; still two event contexts.
    state, publication = _publication()
    calls = []
    real = C.event_bytes
    monkeypatch.setattr(C, "event_bytes", lambda *a, **k: calls.append(a[3]) or real(*a, **k))
    assert C.dispatch(S, state, **publication)["status"] == 200
    log = publication["body"]["restore"]["log"]
    assert calls == [log, log]


def test_failed_publications_are_charged_and_bounded():
    case = CASES["publish_failure_budget"]
    state = copy.deepcopy(case["state"])
    results = [C.dispatch(S, state, **s["input"]) for s in case["steps"]]
    errors = [r.get("error") for r in results]
    assert errors.count("restore_invalid") == C.FAILURE_BUDGET
    last = len(errors) - 1 - errors[::-1].index("restore_invalid")
    assert results[last + 1] == {"status": 429, "error": "quota_exceeded"}
    assert results[-1]["status"] == 200
    # A refusal changes nothing but the failure log.
    assert len(state["transitions"]) == 1


def test_device_sync_never_mutates_the_device_on_refusal():
    case = CASES["walk_replayed_old_restore_source_not_work"]
    state = copy.deepcopy(case["state"])
    device = copy.deepcopy(case["steps"][0]["input"]["body"])
    before = copy.deepcopy(device)
    assert (
        C.dispatch(S, state, "device_sync", device, now_ms=case["steps"][0]["input"]["now_ms"])[
            "status"
        ]
        == 409
    )
    assert device == before


def _hostile_reader(monkeypatch, op, page):
    """A relay that never ends a page sequence; fail instead of hanging if the walk keeps asking."""
    real, calls = C.read, []

    def read(state, o, args, now):
        if o == op:
            calls.append(1)
            assert len(calls) < 200, "unbounded paging loop"
            return page(args)
        return real(state, o, args, now)

    monkeypatch.setattr(C, "read", read)


@pytest.mark.parametrize(
    "op,page",
    [
        ("transitions", lambda a: {"transitions": [], "next": str(a["after_n"])}),
        ("proof", lambda a: {"heads": ["sha256:" + "11" * 32], "next": a["from"]}),
        ("proof", lambda a: {"heads": [], "next": a["from"]}),
    ],
)
def test_walk_paging_is_bounded_against_a_hostile_relay(monkeypatch, op, page):
    case = CASES["walk_two_restores_then_growth"]
    state = copy.deepcopy(case["state"])
    step = case["steps"][0]["input"]
    _hostile_reader(monkeypatch, op, page)
    assert C.dispatch(S, state, **step) == {"status": 409, "error": "sync_incomplete"}


def test_ignored_never_commits_a_state_walked_above_the_endpoint(monkeypatch):
    # Review N2/N08: a relay that serves transitions beyond E and then E itself (lower n).
    case = CASES["walk_two_restores_then_growth"]
    state = copy.deepcopy(case["state"])
    device = case["steps"][0]["input"]["body"]
    lower = state["transitions"][0]["target_hash"]  # E = the first restore's target
    real = C.read

    def read(st, op, args, now):
        if op == "transitions":
            return real(st, op, {**args, "to": C.checkpoint_hash(st["held"])}, now)
        return real(st, op, args, now)

    monkeypatch.setattr(C, "read", read)
    before = copy.deepcopy(device)
    result = C.dispatch(
        S, state, "device_sync", device, now_ms=case["steps"][0]["input"]["now_ms"], endpoint=lower
    )
    assert result == {"status": 409, "error": "chain_diverged"}
    assert device == before


def test_device_head_budget_bounds_wsk_signed_heights(monkeypatch):
    # Review L3: a WSK holder can sign any height; the device's own ceiling bounds the walk.
    case = CASES["walk_plain_growth"]
    state = copy.deepcopy(case["state"])
    step = case["steps"][0]["input"]
    monkeypatch.setattr(C, "DEVICE_MAX_HEADS", 1)
    assert C.dispatch(S, state, **step) == {"status": 409, "error": "sync_incomplete"}
    monkeypatch.setattr(C, "DEVICE_MAX_HEADS", 2)
    assert C.dispatch(S, state, **step)["status"] == 200


def test_budget_not_charged_to_a_fenced_holder_and_reset_per_generation():
    case = CASES["publish_budget_per_holder_generation"]
    state = copy.deepcopy(case["state"])
    results = [C.dispatch(S, state, **s["input"]) for s in case["steps"]]
    assert [r.get("error") for r in results[-3:]] == ["quota_exceeded", "fenced", None]
    # A newer generation gets its own slice; the old generation's refusals still count toward the ceiling.
    assert state["generation"] == 2 and len(state["failures"]) == C.FAILURE_BUDGET


def test_takeovers_cannot_exceed_the_workspace_ceiling():
    case = CASES["publish_budget_workspace_ceiling_across_takeovers"]
    state = copy.deepcopy(case["state"])
    results = [C.dispatch(S, state, **s["input"]) for s in case["steps"]]
    errors = [r.get("error") for r in results]
    assert errors.count("restore_invalid") == C.WORKSPACE_FAILURE_CEILING
    assert "quota_exceeded" in errors and results[-1]["status"] == 200


def test_device_refuses_a_restore_line_over_the_line_cap(monkeypatch):
    case = CASES["walk_two_restores_then_growth"]
    state = copy.deepcopy(case["state"])
    step = case["steps"][0]["input"]
    size = len(R.cj(state["transitions"][0]["line"])) + 1
    monkeypatch.setattr(C, "LINE_CAP", size - 1)
    assert C.dispatch(S, state, **step) == {"status": 409, "error": "chain_diverged"}
    monkeypatch.setattr(C, "LINE_CAP", size)
    assert C.dispatch(S, copy.deepcopy(case["state"]), **step)["status"] == 200


def test_known_evidence_must_match_the_receivers_stored_key():
    # PR #41 completeness rule: person ids agree, but the receiver stored another key for the device.
    c = next(x for x in F1["transition_cases"] if x["name"] == "receiver_retired_to_lost")
    kw = {
        "restore": c["restore"],
        "applied": c["applied"],
        "proofs": c["proofs"],
        "card": c["pinned_delegation"],
        "known_devices": c["known_devices"],
        "local": [],
        "learned_later": [],
    }
    known = copy.deepcopy(c["known_revocations"])
    carried = {e["revocation"]["o"]["device_id"]: e for e in c["restore"]["event"]["revocations"]}
    known[0]["pk_pub"] = carried[known[0]["revocation"]["o"]["device_id"]]["pk_pub"]
    assert judge(F1, c["held"], c["offered"], c["now"], known=known, **kw)[0] == "ok"
    known[0]["pk_pub"] = c["restore"]["pk_pub"]  # the owner's key, not the device person's
    assert judge(F1, c["held"], c["offered"], c["now"], known=known, **kw) == REFUSED


def test_initial_requires_registered_members_and_the_owner_key():
    st = CASES["first_checkpoint_full_proof"]["state"]
    owner = st["delegation"]["o"]["owner_person_id"]
    args = (st["ws"], st["wsk_pub"], st["owner_pk"], st["delegation"])
    fresh = C.initial(*args, {"d1": []}, {"d1": owner}, {owner: st["owner_pk"]})
    assert (
        fresh["registry"] == {"d1": owner}
        and fresh["bound"] == {}
        and fresh["global_revocations"] == {}
    )
    with pytest.raises(C.Refusal):
        C.initial(
            *args, {"d1": []}, {}, {owner: st["owner_pk"]}
        )  # an unregistered member never defaults
    with pytest.raises(C.Refusal):
        C.initial(*args, {"d1": []}, {"d1": owner}, {})


def test_known_holder_is_strict_about_its_state():
    st = copy.deepcopy(CASES["first_checkpoint_full_proof"]["state"])
    del st["registry"]
    with pytest.raises(KeyError):
        C.known_holder(st, "d1")


def test_device_binds_evidence_for_a_known_active_device():
    """orch-core #377 / re-review F2: the PoC, as a test. The receiver knows the device only as active."""
    c = next(
        x
        for x in F1["transition_cases"]
        if x["name"] == "foreign_evidence_for_a_known_revoked_device"
    )
    kw = {
        "restore": c["restore"],
        "applied": c["applied"],
        "proofs": c["proofs"],
        "card": c["pinned_delegation"],
        "local": [],
        "learned_later": [],
    }
    rev = c["known_revocations"][0]["revocation"]["o"]
    assert (
        judge(F1, c["held"], c["offered"], c["now"], known=[], known_devices={}, **kw)[0] == "ok"
    )  # nothing known: accepted
    active = {rev["device_id"]: {"person_id": rev["person_id"]}}
    got = judge(F1, c["held"], c["offered"], c["now"], known=[], known_devices=active, **kw)
    assert got == REFUSED


def test_resumed_endpoint_must_be_the_requested_hash(monkeypatch):
    case = CASES["walk_endpoint_gone_keeps_held"]
    state = copy.deepcopy(case["state"])
    step = {**case["steps"][0]["input"], "now_ms": case["steps"][0]["input"]["now_ms"] - C.DAY}
    real = C.read

    def read(st, op, args, now):
        if op == "get" and args.get("hash") == step["endpoint"]:
            return real(st, op, {}, now)  # serves the current H for an older requested E
        return real(st, op, args, now)

    monkeypatch.setattr(C, "read", read)
    assert C.dispatch(S, state, **step) == {"status": 409, "error": "chain_diverged"}


def test_device_binds_evidence_for_a_known_device_to_its_stored_key():
    c = next(x for x in F1["transition_cases"] if x["name"] == "receiver_retired_to_lost")
    kw = {
        "restore": c["restore"],
        "applied": c["applied"],
        "proofs": c["proofs"],
        "card": c["pinned_delegation"],
        "local": [],
        "learned_later": [],
    }
    item = c["restore"]["event"]["revocations"][0]
    d, person = item["revocation"]["o"]["device_id"], item["revocation"]["o"]["person_id"]
    ok = {d: {"person_id": person, "pk_pub": item["pk_pub"]}}
    assert (
        judge(
            F1,
            c["held"],
            c["offered"],
            c["now"],
            known=c["known_revocations"],
            known_devices=ok,
            **kw,
        )[0]
        == "ok"
    )
    bad = {d: {"person_id": person, "pk_pub": c["restore"]["pk_pub"]}}
    got = judge(
        F1,
        c["held"],
        c["offered"],
        c["now"],
        known=c["known_revocations"],
        known_devices=bad,
        **kw,
    )
    assert got == REFUSED


def test_alarms_read_round_two_signer_format():
    """A round-2 signer (bare device id, no person) matches by device; a recorded person must match (#387)."""
    dev = {"signers": {"r1": "d1", "r2": {"device": "d2", "person_id": "p"}}, "alarms": []}
    revs = [
        {"o": {"reason": "compromised", "device_id": d, "person_id": "q"}} for d in ("d1", "d2")
    ]
    C.raise_alarms(dev, revs)
    assert dev["alarms"] == ["d1"]
    C.raise_alarms(dev, [{"o": {"reason": "compromised", "device_id": "d2", "person_id": "p"}}])
    assert dev["alarms"] == ["d1", "d2"]
    C.raise_alarms(dev, [{"o": {"reason": "lost", "device_id": "d3", "person_id": "p"}}])
    assert dev["alarms"] == ["d1", "d2"]


# --- F1 §5.10 at orch-core e9a26d95 (#387): the receiver runtime (signed material from the walk vectors) ---------


def _walk_result(name, step=-1):
    return CASES[name]["steps"][step]["expect"]


def _learned_device():
    """A device that chain-learned the laptop's lost revocation from an accepted restore (with provenance)."""
    dev = copy.deepcopy(_walk_result("walk_chain_learned_with_provenance")["device"])
    ((laptop, item),) = dev["revocations"].items()
    return dev, laptop, item


def test_chain_learned_entries_carry_their_occurrence():
    """Provenance names the accepted checkpoint by hash, the restore event, its seq, head and accumulator node:
    never a height alone. The head and node re-derive from the stored line and the T the walk accepted."""
    dev, laptop, item = _learned_device()
    prov = item["provenance"]
    assert set(prov) == {"checkpoint", "log", "event", "seq", "head", "acc"}
    assert set(prov["checkpoint"]) == {"n", "hash"} and prov["checkpoint"] == C.reference(
        dev["held"]
    )
    entry = dev["held"]["o"]["workspace_log"]
    assert (
        prov["seq"] == entry["seq"]
        and prov["head"] == entry["head"]
        and prov["acc"] == entry["acc"]
    )
    assert C.evidence_ok(S, item) == laptop


def test_another_workspace_sees_chain_evidence_only_as_local():
    """Cross-workspace isolation: chain-learned evidence of one workspace, given to another workspace's device, is
    out of band there (verified, its own reason, no provenance), never chain-learned."""
    _, laptop, item = _learned_device()
    other = C.device_initial("ff" * 16, "w", "pk", "g", {}, {})
    got = C.device_learn(S, other, item)["device"]
    assert got["revocations"] == {} and set(got["local"]) == {laptop}
    assert (
        "provenance" not in got["local"][laptop]
        and C.evidence_ok(S, got["local"][laptop]) == laptop
    )
    assert other["local"] == {}  # device_learn never mutates its input


def test_device_learn_keeps_the_strongest_local_reason():
    _, laptop, lost = _learned_device()
    bad = _walk_result("walk_failed_walk_drops_alarm_of_uncommitted_transition")["device"]["local"][
        laptop
    ]
    assert bad["revocation"]["o"]["reason"] == "compromised"
    dev = C.device_initial("ff" * 16, "w", "pk", "g", {}, {})
    dev = C.device_learn(S, dev, bad)["device"]
    dev = C.device_learn(S, dev, lost)[
        "device"
    ]  # weaker: admitted, but the compromised reason stays
    assert dev["local"][laptop]["revocation"]["o"]["reason"] == "compromised"


@pytest.mark.parametrize("defect", ["extra_field", "other_key", "unsigned", "not_a_dict"])
def test_unverifiable_evidence_is_never_admitted(defect):
    _, _laptop, item = _learned_device()
    item = {k: item[k] for k in ("revocation", "device_cert", "pk_pub")}
    if defect == "extra_field":
        item["note"] = "x"
    elif defect == "other_key":
        item["pk_pub"] = CASES["walk_plain_growth"]["state"]["wsk_pub"]
    elif defect == "unsigned":
        item["revocation"] = {**item["revocation"], "sig": item["device_cert"]["sig"]}
    else:
        item = [item]
    assert C.evidence_ok(S, item) is None
    dev = C.device_initial("ff" * 16, "w", "pk", "g", {}, {})
    assert C.admit_local(S, dev, item) is False and dev["local"] == {}
    with pytest.raises(C.Refusal):
        C.device_learn(S, dev, item)


def test_failed_walk_refusal_carries_only_what_changed():
    """A refused walk returns `device` only when it kept new evidence or alarms; H, applied ids, signers and the
    chain-learned revocations are those of the committed state."""
    case = CASES["walk_failed_walk_keeps_evidence_and_alarms_committed_signer"]
    committed = case["steps"][0]["expect"]["device"]
    failed = case["steps"][1]["expect"]
    kept = failed["device"]
    for key in ("held", "applied", "signers", "revocations", "devices", "forward", "pending"):
        assert kept[key] == committed[key], key
    assert kept["local"] != committed["local"] and kept["alarms"] != committed["alarms"]
    plain = _walk_result("walk_spliced_proof_page")
    assert plain == {
        "status": 409,
        "error": "sync_incomplete",
    }  # nothing verified: no device in the refusal


def test_unexpected_walk_errors_still_keep_verified_evidence(monkeypatch):
    """A non-Refusal error late in a walk (here: a crash in the final judge) is `malformed`, and the evidence the walk
    verified before it is kept like for any refusal."""
    case = CASES["walk_failed_walk_drops_alarm_of_uncommitted_transition"]
    state = copy.deepcopy(case["state"])
    step = copy.deepcopy(case["steps"][0]["input"])
    real = C.judge_offer
    calls = []

    def judge(*a, **k):
        calls.append(1)
        if (
            k.get("restore") is not None
            and k["restore"]["event"]["id"] == "01ZZZZZZZZZZZZZZZZZZZZZZZZ"
        ):
            raise KeyError("boom")
        return real(*a, **k)

    monkeypatch.setattr(C, "judge_offer", judge)
    got = C.dispatch(S, state, **step)
    assert got["status"] == 400 and got["error"] == "malformed"
    assert got["device"] == case["steps"][0]["expect"]["device"]


def _poisoned_device():
    """Security review flags (1)/(2), PoC: another person (bob) certifies the laptop's device id under his own key
    and revokes it. The device does not know the laptop yet, so bob's evidence binds it first (F1 row 151). Then
    alice, the laptop's real person and the workspace owner, revokes it as compromised."""
    case = CASES["device_learn_admission"]
    bob = case["steps"][2]["input"]["body"]["evidence"]
    alice = _walk_result("walk_failed_walk_drops_alarm_of_uncommitted_transition")["device"][
        "local"
    ]
    ((laptop, alice_bad),) = alice.items()
    dev = copy.deepcopy(
        CASES["walk_failed_walk_drops_alarm_of_uncommitted_transition"]["steps"][0]["input"]["body"]
    )
    dev = C.device_learn(S, dev, bob)["device"]
    assert (
        dev["local"][laptop]["revocation"]["o"]["person_id"] == bob["revocation"]["o"]["person_id"]
    )
    return dev, laptop, alice_bad


def test_poisoned_binding_never_drops_a_genuine_signer_revocation():
    """The first binding stays bob's (no replacement), but alice's verified revocation is kept, not discarded, and
    still refuses her laptop as a restore signer (C3): without it the poisoned binding failed open."""
    dev, laptop, alice_bad = _poisoned_device()
    got = C.dispatch(S, {}, "device_learn", {"device": dev, "evidence": alice_bad})
    assert got["status"] == 200 and got["admitted"] is False
    told = got["device"]
    assert (
        told["local"][laptop]["revocation"]["o"]["person_id"]
        != alice_bad["revocation"]["o"]["person_id"]
    )
    assert list(told["contested"].values()) == [alice_bad]
    case = CASES[
        "walk_retry_after_failed_walk_refuses_former_alarm"
    ]  # the relay of t1, signed by the laptop
    state = copy.deepcopy(case["state"])
    step = {**case["steps"][0]["input"], "body": told}
    assert C.dispatch(S, state, **step) == {"status": 409, "error": "chain_diverged"}
    # Control (up to t1): with only bob's (poisoning) evidence the laptop's restore is accepted, as F1 requires;
    # before the fix alice's revocation was refused (revocation_conflict) and this was the device's state: fail open.
    t1 = CASES["walk_failed_walk_keeps_evidence_and_alarms_committed_signer"]["steps"][0]["input"][
        "endpoint"
    ]
    upto = {**step, "endpoint": t1}
    assert C.dispatch(S, copy.deepcopy(case["state"]), **{**upto, "body": dev})["status"] == 200
    assert C.dispatch(S, copy.deepcopy(case["state"]), **{**upto, "body": told}) == {
        "status": 409,
        "error": "chain_diverged",
    }
