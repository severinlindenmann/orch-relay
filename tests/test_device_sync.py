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
F1 = json.loads((HERE / "vectors/f1_receiver_f1094b3.json").read_text())
S = R.SUITES[2]
V = json.loads(R.VECTORS.read_text())["suites"]["2"]
CASES = {c["name"]: c for c in V["checkpoints"]["cases"]}


def by_name(cases):
    return pytest.mark.parametrize("c", cases, ids=lambda c: c["name"])


def test_extract_matches_the_f1_snapshot_once_resynced():
    """The extract is a byte-faithful subset of orch-core f1094b3 checkpoint.json. When
    tests/vectors/f1 is re-synced to f1094b3 (PR #41), the subset must equal that snapshot."""
    src = F1["source"]
    assert src["commit"].startswith("f1094b3")
    assert len(F1["transition_cases"]) == 25 and len(F1["workspace_n_offers"]) == 12
    snapshot = HERE / "vectors/f1/checkpoint.json"
    if "f1094b3" not in (HERE / "vectors/f1/SOURCE").read_text():
        pytest.skip("tests/vectors/f1 still pins an older orch-core commit (PR #41 re-syncs it)")
    raw = snapshot.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == src["sha256"]
    full = json.loads(raw)
    assert all(full[k] == F1[k] for k in src["keys"])


F52 = json.loads((HERE / "vectors/f1_receiver_orch52.json").read_text())


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


@by_name(F1["transition_cases"])
def test_f1_transition_cases_against_reference_judge(c):
    # f1094b3 predates the pinned card and the clock: pin the bundle's own delegation, judge at T.at.
    restore = c["restore"]
    got = judge(
        F1,
        c["held"],
        c["offered"],
        c["offered"]["o"]["at"],
        restore=restore,
        applied=c["applied"],
        proofs=c["proofs"],
        known=c.get("known_revocations", []),
        card=restore.get("delegation"),
    )
    assert got == (c["expect"], c["recorded"])


@by_name(F1["workspace_n_offers"])
def test_f1_workspace_n_offers_against_reference_judge(c):
    got = judge(
        F1,
        F1["workspace_n_held"],
        c["checkpoint"],
        c["checkpoint"]["o"]["at"],
        restore=c.get("restore"),
        applied=c.get("applied", []),
        proofs=c.get("proofs"),
    )
    assert got == (c["expect"], c.get("recorded"))


@by_name(F52["transition_cases"])
def test_orch52_transition_cases_against_reference_judge(c):
    """orch-52's receiver cases (fix/restore-receiver-vectors head, not yet merged): one defect each."""
    kw = {
        "restore": c["restore"],
        "applied": c["applied"],
        "proofs": c["proofs"],
        "card": c["pinned_delegation"],
    }
    got = judge(
        F52,
        c["held"],
        c["offered"],
        c["now"],
        known=c.get("known_revocations", []),
        known_devices=c.get("known_devices"),
        **kw,
    )
    assert got == (c["expect"], c["recorded"])
    if "learned_later_in_walk" in c:
        again = judge(
            F52, c["held"], c["offered"], c["now"], known=c["learned_later_in_walk"], **kw
        )
        assert again == ("chain.diverged", None)


@by_name(F52["workspace_n_offers"])
def test_orch52_workspace_n_offers_against_reference_judge(c):
    held = c["held"] if "held" in c else F52["workspace_n_held"]
    got = judge(
        F52,
        held,
        c["checkpoint"],
        c["now"],
        restore=c.get("restore"),
        applied=c.get("applied", []),
        proofs=c.get("proofs"),
    )
    assert got == (c["expect"], c.get("recorded"))


def test_f1_known_revocation_of_signer_refuses_on_ticket_logs_too():
    # Review 1 in F1 terms: known revocations refuse the signer whatever the log.
    c = copy.deepcopy(
        next(x for x in F1["transition_cases"] if x["name"] == "restore_accumulator_fold")
    )
    signer = c["restore"]["device_cert"]["o"]["device_id"]
    for reason in ("lost", "retired", "compromised"):
        rev = {
            "o": {
                "device_id": signer,
                "reason": reason,
                "person_id": c["restore"]["device_cert"]["o"]["person_id"],
            }
        }
        got = judge(
            F1,
            c["held"],
            c["offered"],
            c["offered"]["o"]["at"],
            restore=c["restore"],
            applied=[],
            proofs=c["proofs"],
            known=[{"revocation": rev}],
            card=c["restore"]["delegation"],
        )
        assert got == ("chain.diverged", None), reason


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
    c = next(x for x in F52["transition_cases"] if x["name"] == "receiver_retired_to_lost")
    kw = {
        "restore": c["restore"],
        "applied": c["applied"],
        "proofs": c["proofs"],
        "card": c["pinned_delegation"],
    }
    known = copy.deepcopy(c["known_revocations"])
    carried = {e["revocation"]["o"]["device_id"]: e for e in c["restore"]["event"]["revocations"]}
    known[0]["pk_pub"] = carried[known[0]["revocation"]["o"]["device_id"]]["pk_pub"]
    assert judge(F52, c["held"], c["offered"], c["now"], known=known, **kw)[0] == "ok"
    known[0]["pk_pub"] = c["restore"]["pk_pub"]  # the owner's key, not the device person's
    assert judge(F52, c["held"], c["offered"], c["now"], known=known, **kw) == (
        "chain.diverged",
        None,
    )


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
    """orch-52 #377 / re-review F2: the PoC, as a test. The receiver knows the device only as active."""
    c = next(
        x
        for x in F52["transition_cases"]
        if x["name"] == "foreign_evidence_for_a_known_revoked_device"
    )
    kw = {
        "restore": c["restore"],
        "applied": c["applied"],
        "proofs": c["proofs"],
        "card": c["pinned_delegation"],
    }
    rev = c["known_revocations"][0]["revocation"]["o"]
    assert (
        judge(F52, c["held"], c["offered"], c["now"], known=[], **kw)[0] == "ok"
    )  # nothing known: accepted
    active = {rev["device_id"]: {"person_id": rev["person_id"]}}
    got = judge(F52, c["held"], c["offered"], c["now"], known=[], known_devices=active, **kw)
    assert got == ("chain.diverged", None)


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
    c = next(x for x in F52["transition_cases"] if x["name"] == "receiver_retired_to_lost")
    kw = {
        "restore": c["restore"],
        "applied": c["applied"],
        "proofs": c["proofs"],
        "card": c["pinned_delegation"],
    }
    item = c["restore"]["event"]["revocations"][0]
    d, person = item["revocation"]["o"]["device_id"], item["revocation"]["o"]["person_id"]
    ok = {d: {"person_id": person, "pk_pub": item["pk_pub"]}}
    assert (
        judge(
            F52,
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
        F52,
        c["held"],
        c["offered"],
        c["now"],
        known=c["known_revocations"],
        known_devices=bad,
        **kw,
    )
    assert got == ("chain.diverged", None)


def test_alarms_read_round_two_signer_format():
    dev = {"signers": {"r1": "d1", "r2": {"device": "d2", "person_id": "p"}}, "alarms": []}
    rev = {"o": {"reason": "compromised"}}
    C.raise_alarms(dev, {"d1": rev, "d2": rev})
    assert dev["alarms"] == ["d1", "d2"]
