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


@by_name(F1["transition_cases"])
def test_f1_transition_cases_against_reference_judge(c):
    got = C.judge_offer(
        S,
        c["held"]["o"] if c["held"] else None,
        c["offered"]["o"],
        genesis=c["offered"]["o"]["genesis"],
        wsk_pub=F1["wsk_pub"],
        restore=c["restore"],
        applied=c["applied"],
        proofs=c["proofs"],
        known=c.get("known_revocations", []),
    )
    assert got == (c["expect"], c["recorded"])


@by_name(F1["workspace_n_offers"])
def test_f1_workspace_n_offers_against_reference_judge(c):
    got = C.judge_offer(
        S,
        F1["workspace_n_held"]["o"],
        c["checkpoint"]["o"],
        genesis=F1["genesis"],
        wsk_pub=F1["wsk_pub"],
        restore=c.get("restore"),
        applied=c.get("applied", []),
        proofs=c.get("proofs"),
    )
    assert got == (c["expect"], c.get("recorded"))


def test_f1_known_revocation_of_signer_refuses_on_ticket_logs_too():
    # Review 1 in F1 terms: known revocations refuse the signer whatever the log.
    c = copy.deepcopy(next(x for x in F1["transition_cases"] if x["name"] == "restore_accumulator_fold"))
    signer = c["restore"]["device_cert"]["o"]["device_id"]
    for reason in ("lost", "retired", "compromised"):
        rev = {"o": {"device_id": signer, "reason": reason}}
        got = C.judge_offer(
            S, c["held"]["o"], c["offered"]["o"], genesis=F1["genesis"], wsk_pub=F1["wsk_pub"],
            restore=c["restore"], applied=[], proofs=c["proofs"], known=[{"revocation": rev}],
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
    assert C.dispatch(S, state, "device_sync", device, now_ms=case["steps"][0]["input"]["now_ms"])["status"] == 409
    assert device == before
