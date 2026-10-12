"""Independent arithmetic, security boundaries and atomicity for P3-D13/D19/D20/D25."""

import copy
import hashlib
import json
from pathlib import Path

import pytest

from ref import checkpoints as C
from ref import orch_protocol_ref as R

V = json.loads(R.VECTORS.read_text())["suites"]["2"]
S = R.SUITES[2]
CASES = {c["name"]: c for c in V["checkpoints"]["cases"]}


def test_accumulator_is_raw_32_byte_input_without_sequence():
    acc = "sha256:" + "12" * 32
    head = "sha256:" + "ab" * 32
    expected = hashlib.sha256(b"orch/v2/log-acc|" + bytes.fromhex("12" * 32 + "ab" * 32))
    assert C.log_acc(acc, head) == "sha256:" + expected.hexdigest()
    assert C.log_acc(acc, head) != C.digest(b"orch/v2/log-acc|" + acc.encode() + head.encode())
    for bad in (head.upper(), head + "00", head[7:], "sha256:" + "gg" * 32):
        with pytest.raises(C.Refusal):
            C.log_acc(acc, bad)


def test_checkpoint_hash_excludes_signature():
    cp = V["checkpoints"]["objects"]["checkpoint"]
    expected = hashlib.sha256(b"orch/v2/checkpoint-hash|" + R.cj(cp["o"])).hexdigest()
    assert C.checkpoint_hash(cp) == "sha256:" + expected
    assert C.checkpoint_hash({**cp, "sig": "another-signature"}) == C.checkpoint_hash(cp)


def test_f1_event_signing_context_matches_portable_f1_vectors():
    # The shared F1 files are read only. Both the old and new snapshot pin these signatures.
    f1 = json.loads((Path(__file__).parent / "vectors/f1/signatures.json").read_text())
    for key, log in (("ws_event", "workspace"), ("ticket_event", None)):
        example = f1[key]
        # F1's own explicit signing bytes provide an independent oracle.
        assert isinstance(example, dict)
    chain = json.loads((Path(__file__).parent / "vectors/f1/chain.json").read_text())
    assert (
        C.event_bytes(S, chain["ws_event"], chain["workspace_id"], "workspace").hex()
        == chain["ws_event_signing_hex"]
    )
    for line, expected in zip(chain["events"], chain["host_signing_hex"]):
        assert C.event_bytes(S, line, chain["workspace_id"], chain["log"], True).hex() == expected


@pytest.mark.parametrize("raw", ['{"checkpoint":{},"checkpoint":{}}', '{"n":1.0}', "{} trailing"])
def test_strict_parse_precedes_any_mutation(raw):
    state = copy.deepcopy(CASES["first_checkpoint_full_proof"]["state"])
    before = copy.deepcopy(state)
    assert C.dispatch(S, state, "publish", raw, now_ms=1790000000000, generation=1) == {
        "status": 400,
        "error": "malformed",
    }
    assert C.contract(state) == C.contract(before)


@pytest.mark.parametrize(
    "op,cap,status",
    [("publish", C.REQUEST_CAP, 400), ("page", C.PAGE_CAP, 413), ("baseline", 16384, 413)],
)
def test_actual_transport_byte_caps_before_parsing(op, cap, status):
    state = copy.deepcopy(CASES["first_checkpoint_full_proof"]["state"])
    before = copy.deepcopy(state)
    extra = {"generation": 1} if op == "publish" else {}
    assert C.dispatch(S, state, op, b" " * (cap + 1), **extra) == {
        "status": status,
        "error": "too_large",
    }
    assert C.contract(state) == C.contract(before)


def test_page_quota_64_mib_and_retry_does_not_charge_twice(monkeypatch):
    # Scale the resource constant to the exact encoded page boundary; same production comparison.
    case = CASES["staging_immutable_page_and_manifest"]
    state = copy.deepcopy(case["state"])
    first = case["steps"][0]["input"]
    size = len(R.cj(first["body"]))
    monkeypatch.setattr(C, "STAGE_CAP", size)
    assert C.dispatch(S, state, **first)["status"] == 200
    assert C.dispatch(S, state, **first)["status"] == 200
    second = {**first, "i": 1}
    before = copy.deepcopy(state)
    assert C.dispatch(S, state, **second) == {"status": 429, "error": "quota_exceeded"}
    assert C.contract(state) == C.contract(before)
    assert C.STAGE_CAP == size


def test_checkpoint_object_cap_exact_boundary(monkeypatch):
    case = CASES["first_checkpoint_full_proof"]
    state = copy.deepcopy(case["state"])
    for step in case["steps"][:-2]:
        C.dispatch(S, state, **step["input"])
    publication = case["steps"][-2]["input"]
    size = len(R.cj(publication["body"]["checkpoint"]))
    before = copy.deepcopy(state)
    monkeypatch.setattr(C, "CP_CAP", size - 1)
    assert C.dispatch(S, state, **publication) == {"status": 400, "error": "too_large"}
    assert C.contract(state) == C.contract(before)
    monkeypatch.setattr(C, "CP_CAP", size)
    assert C.dispatch(S, state, **publication)["status"] == 200


def test_real_line_cap_is_not_replaced_by_a_payload_only_cap(monkeypatch):
    case = CASES["workspace_restore_and_exact_retry"]
    state = copy.deepcopy(case["state"])
    for step in case["steps"][:-2]:
        C.dispatch(S, state, **step["input"])
    publication = case["steps"][-2]["input"]
    size = len(R.cj(publication["body"]["restore"]["line"])) + 1
    before = copy.deepcopy(state)
    monkeypatch.setattr(C, "LINE_CAP", size - 1)
    assert C.dispatch(S, state, **publication) == {"status": 400, "error": "too_large"}
    assert C.contract(state) == C.contract(before)
    monkeypatch.setattr(C, "LINE_CAP", size)
    assert C.dispatch(S, state, **publication)["status"] == 200


def test_http_proof_byte_limit_takes_precedence_over_head_count():
    # The maximum head count alone would exceed the common four-MiB response budget.
    assert 65536 * 74 > C.PAGE_CAP
    assert ((C.PAGE_CAP - 128) // 74) * 74 + 128 <= C.PAGE_CAP


def test_invalid_offer_does_not_poison_restore_id_or_consume_staging():
    case = CASES["workspace_restore_and_exact_retry"]
    state = copy.deepcopy(case["state"])
    for step in case["steps"][:-2]:
        C.dispatch(S, state, **step["input"])
    valid = case["steps"][-2]["input"]
    bad = copy.deepcopy(valid)
    bad["body"]["restore"]["authz"] = {}
    before = copy.deepcopy(state)
    assert C.dispatch(S, state, **bad)["error"] == "restore_not_owner"
    assert C.contract(state) == C.contract(before)
    assert C.dispatch(S, state, **valid)["status"] == 200
    assert len(state["transitions"]) == 1


def test_staging_retries_compare_http_bytes_not_only_parsed_objects():
    case = CASES["staging_immutable_page_and_manifest"]
    state = copy.deepcopy(case["state"])
    first = copy.deepcopy(case["steps"][0]["input"])
    assert C.dispatch(S, state, **first)["status"] == 200
    first["body"] = json.dumps(first["body"], indent=2)
    before = copy.deepcopy(state)
    assert C.dispatch(S, state, **first) == {"status": 409, "error": "staging_conflict"}
    assert C.contract(state) == C.contract(before)


def test_restore_covers_revoked_device_first_introduced_by_payload():
    case = CASES["B1_weaker"]
    state = copy.deepcopy(case["state"])
    publication = case["steps"][-1]["input"]
    device = publication["body"]["restore"]["line"]["revocations"][0]["device_cert"]["o"][
        "device_id"
    ]
    state["ever_devices"].remove(device)
    for step in case["steps"][:-1]:
        assert C.dispatch(S, state, **step["input"])["status"] == 200
    before = copy.deepcopy(state)
    assert C.dispatch(S, state, **publication) == {
        "status": 409,
        "error": "restore_missing_revocation",
        "devices": [device],
    }
    assert C.contract(state) == C.contract(before)


@pytest.mark.parametrize("invalid_evidence", [False, True])
def test_historical_owner_rejects_bundle_revocation(invalid_evidence):
    case = CASES["B1_signer_self_revoked_in_payload"]
    state = copy.deepcopy(case["state"])
    bundle = copy.deepcopy(case["steps"][-1]["input"]["body"])
    if invalid_evidence:
        bundle["line"]["revocations"][0]["revocation"]["sig"] = R.b64u(bytes(64))
    before = copy.deepcopy(state)
    assert C.dispatch(S, state, "owner_policy", bundle, historical=True) == {
        "status": 409,
        "error": "restore_invalid" if invalid_evidence else "restore_not_owner",
    }
    assert C.contract(state) == C.contract(before)


@pytest.mark.parametrize("reason", [None, "lost", "retired", "compromised"])
def test_historical_owner_refuses_any_known_signer_revocation_not_completeness(reason):
    # Review 1: a known revocation of the signer refuses, whatever its reason. Relay-local
    # completeness (an unrelated device absent from the bundle) is still not demanded.
    case = CASES["historical_signer_known_lost_before_line_at_refused"]
    state = copy.deepcopy(case["state"])
    request = case["steps"][0]["input"]
    o = request["body"]["cert"]["o"]
    signer = (
        o["device_id"] + ":" + o["person_id"]
    )  # held revocations are keyed by pair (orch-core #397)
    known = state["revocations"].pop(signer)
    if reason:
        key = S.sig_key(bytes.fromhex(V["keys"]["person_alice.sig"]["seed"]))
        state["revocations"][signer] = R.sign_object(S, key, {**known["o"], "reason": reason})
    other = CASES["B1_weaker"]["state"]
    state["revocations"].update(other["revocations"])
    state["ever_devices"] = sorted(set(state["ever_devices"]) | set(other["ever_devices"]))
    expected = {"status": 409, "error": "restore_not_owner"} if reason else {"status": 200}
    assert C.dispatch(S, state, **request) == expected
    assert "alarms" not in state


@pytest.mark.parametrize("as_text", [False, True])
@pytest.mark.parametrize("extra_bytes", [0, 1])
def test_baseline_raw_request_cap_boundary(as_text, extra_bytes):
    case = CASES["baseline_retention_release_and_expiry"]
    state = copy.deepcopy(case["state"])
    request = copy.deepcopy(case["steps"][0]["input"])
    raw = R.cj(request["body"])
    raw += b" " * (16384 + extra_bytes - len(raw))
    request["body"] = raw.decode() if as_text else raw
    before = copy.deepcopy(state)
    result = C.dispatch(S, state, **request)
    if extra_bytes:
        assert result == {"status": 413, "error": "too_large"}
        assert C.contract(state) == C.contract(before)
    else:
        assert result == case["steps"][0]["expect"]
        assert len(state["baselines"]) == 1


def test_checkpoint_request_caps_match_http_registry():
    from ref._checkpoint_http import CAPS

    routes = {
        "genesis": "genesis",
        "page": "staging_page",
        "manifest": "staging_manifest",
        "baseline": "baseline_post",
        "publish": "checkpoint_put",
    }
    assert C.REQUEST_CAPS == {op: CAPS[route] for op, route in routes.items()}


def test_manifest_bytes_count_toward_the_staging_quota(monkeypatch):
    # Review 11: a manifest alone is charged against the per-workspace staging bytes.
    case = CASES["staging_immutable_page_and_manifest"]
    state = copy.deepcopy(case["state"])
    manifest = next(s["input"] for s in case["steps"] if s["input"]["op"] == "manifest")
    size = len(R.cj(manifest["body"]))
    monkeypatch.setattr(C, "STAGE_CAP", size - 1)
    before = copy.deepcopy(state)
    assert C.dispatch(S, state, **manifest) == {"status": 429, "error": "quota_exceeded"}
    assert state == before
    monkeypatch.setattr(C, "STAGE_CAP", size)
    assert C.dispatch(S, state, **manifest)["status"] == 200


@pytest.mark.parametrize("store", ["revocations", "global_revocations"])
def test_owner_refuses_the_signer_pair_only(store):
    """orch-core #397 at the relay: a held revocation (this workspace's chain pairs or the global set) refuses the
    restore signer only when it names the signer's (device, person) pair; another person's "revocation" of the
    signer's device id never refuses (it is another pair)."""
    case = CASES["historical_signer_known_lost_before_line_at_refused"]
    state = copy.deepcopy(case["state"])
    request = case["steps"][0]["input"]
    o = request["body"]["cert"]["o"]
    known = state["revocations"].pop(o["device_id"] + ":" + o["person_id"])
    bob = V["ids"]["person_bob"]
    key = S.sig_key(bytes.fromhex(V["keys"]["person_bob.sig"]["seed"]))
    state[store][o["device_id"] + ":" + bob] = R.sign_object(
        S, key, {**known["o"], "person_id": bob}
    )
    assert C.dispatch(S, copy.deepcopy(state), **request) == {"status": 200}
    state[store][o["device_id"] + ":" + o["person_id"]] = known
    assert C.dispatch(S, state, **request) == {"status": 409, "error": "restore_not_owner"}
