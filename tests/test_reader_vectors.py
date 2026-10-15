"""H12d (P3-D38) relay-owned vectors: reader_decl, the pair-request meta v2 (§8.3) and `rd` (§8.6).

Each case replays from the JSON alone; the signature, label, size and digest are also checked without the
reference's verifier. The `kat` digests are core's real reader_kat_1 digests (H12d-1, F1 §11.5; the level-1 view
set is provisional until H12d-2). FAKE keys only.
"""

import copy
import hashlib
import json

import pytest

from ref import orch_protocol_ref as R
from ref._vectors import EXPECT_KEYS

VEC = json.loads(R.VECTORS.read_text(encoding="utf-8"))
SUITES = sorted(VEC["suites"])
LABEL = "orch/v2/sig/reader-decl|"


def each(group):
    out = []
    for sid in SUITES:
        for c in VEC["suites"][sid]["reader_decl"][group]:
            out.append(pytest.param(R.SUITES[int(sid)], c, id=f"suite{sid}-{c['name']}"))
    return pytest.mark.parametrize("S,c", out)


def strip(r):
    return {k: v for k, v in r.items() if k in EXPECT_KEYS}


def test_label_is_registered_and_prefix_free():
    assert VEC["labels"]["sig_reader_decl"] == LABEL
    others = [v for k, v in VEC["labels"].items() if k != "sig_reader_decl"]
    assert all(not v.startswith(LABEL) and not LABEL.startswith(v) for v in others)
    for sid in SUITES:
        assert VEC["suites"][sid]["reader_decl"]["label"] == LABEL


def test_label_is_prefix_free_with_the_vendored_f1_labels():
    from pathlib import Path

    f1 = json.loads((Path(__file__).parent / "vectors/f1/labels.json").read_text())["labels"]
    for v in f1.values():
        assert v == LABEL or (not v.startswith(LABEL) and not LABEL.startswith(v))


@each("decls")
def test_decl_cases(S, c):
    assert R.verify_reader_decl(S, c["decl"], c["ctx"]) == c["expect"]


@each("decls")
def test_decl_signature_independently(S, c):
    """Valid cases verify under the context's dk_sig with the label, computed here without the reference."""
    if "ok" not in c["expect"]:
        return
    msg = LABEL.encode() + R.cj(c["decl"]["o"])
    assert S.verify(R.unb64u(c["ctx"]["dk_sig_pub"]), R.unb64u(c["decl"]["sig"], 64), msg)
    digest = "sha256:" + hashlib.sha256(R.cj(c["decl"])).hexdigest()
    assert c["expect"]["ok"]["digest"] == digest
    assert c["expect"]["ok"]["level"] == min(c["decl"]["o"]["reader"], c["ctx"]["host_max"])


def test_case_list_covers_the_design():
    """orch-core orch-v2-host §9.12, relay-owned reader_decl cases."""
    for sid in SUITES:
        got = {c["name"]: c["expect"] for c in VEC["suites"][sid]["reader_decl"]["decls"]}
        reason = {n: e.get("reason", "ok") for n, e in got.items()}
        assert reason["valid_pairing_declaration"] == "ok"
        assert reason["wrong_workspace"] == "workspace"
        assert reason["wrong_device_id"] == "device"
        assert reason["dk_hash_of_another_key"] == "keys"
        assert reason["offer_id_of_another_offer"] == reason["attempt_of_another_attempt"] == "bind"
        assert reason["wrong_who"] == "who"
        assert reason["reader_0_is_valid_without_kat"] == "ok"
        assert got["higher_unknown_level_7_with_kat_1_only_accepted"]["ok"]["level"] == 1
        assert reason["wrong_kat_1_digest"] == "kat_mismatch"
        assert reason["signature_by_another_key"] == "signature"
        assert reason["over_2_kib"] == "shape"


CORE_KAT = {
    "log": "sha256:70b450df574b6c372005b7504a7f9efe80552cb2841193b960fe538c6aa6fc0e",
    "view": "sha256:d76e4593ec191e91ca2f6bddef570cbfa1af14dae702bb5ded0572eebe1d9085",
}


def test_kat_digests_are_cores_real_ones():
    for sid in SUITES:
        g = VEC["suites"][sid]["reader_decl"]
        assert "kat_standin" not in g
        assert {k: g["kat_core"][k] for k in CORE_KAT} == CORE_KAT
        for c in g["decls"]:
            assert "depends_on_core" not in c
            if "kat" in c["ctx"]:
                assert c["ctx"]["kat"]["1"]["view"] == CORE_KAT["view"]
        ok = next(c for c in g["decls"] if c["name"] == "kat_1_matches_the_expected_digest")
        assert ok["decl"]["o"]["kat"]["1"]["view"] == CORE_KAT["view"] and "ok" in ok["expect"]


def test_h12d_review_f3_f4_cases():
    for sid in SUITES:
        g = VEC["suites"][sid]["reader_decl"]
        got = {c["name"]: c["expect"] for c in g["decls"]}
        assert "ok" in got["valid_declare_declaration"]
        assert "ok" in got["created_ms_2_53_minus_1_accepted"]
        for n in (
            "bind_declare_with_an_extra_field",
            "bind_enrol_with_an_extra_field",
            "created_ms_negative",
        ):
            assert got[n]["reason"] == "shape", n
        c = next(
            x for x in g["pair_meta"] if x["name"] == "meta_v2_reader_decl_sig_not_a_string_pending"
        )
        assert (
            c["steps"][0]["expect"]["result"] == "pair_pending"
        )  # the bridge does not look at `sig`'s type
        assert c["gate"]["expect"]["reason"] == "shape"  # the host gate refuses it


def test_size_and_digest():
    for sid in SUITES:
        g = VEC["suites"][sid]["reader_decl"]
        assert g["max_bytes"] == 2048
        assert len(R.cj(g["digest"]["decl"])) == g["digest"]["cj_bytes"] < 1024
        assert (
            g["digest"]["rd"] == "sha256:" + hashlib.sha256(R.cj(g["digest"]["decl"])).hexdigest()
        )
        over = next(c for c in g["decls"] if c["name"] == "over_2_kib")
        assert len(R.cj(over["decl"])) > 2048


@each("pair_meta")
def test_pair_meta_cases(S, c):
    state = copy.deepcopy(c["state"])
    for step in c["steps"]:
        got = R.host_check(
            bytes.fromhex(step["envelope"]), state, step["now_ms"], step["mailbox_id"]
        )
        assert strip(got) == step["expect"]
    if "gate" in c:
        decl = c["steps"][-1]["expect"]["reader_decl"]
        assert decl == c["meta"]["reader_decl"]  # kept verbatim
        assert R.verify_reader_decl(S, decl, c["gate"]["ctx"]) == c["gate"]["expect"]
        assert c["gate"]["ctx"]["bind"]["attempt"] == c["meta"]["attempt"]
        assert c["gate"]["ctx"]["dk_sig_pub"] == c["meta"]["dk_sig_pub"]


@each("request_meta")
def test_request_meta_cases(S, c):
    state = copy.deepcopy(c["state"])
    for step in c["steps"]:
        got = R.host_check(
            bytes.fromhex(step["envelope"]), state, step["now_ms"], step["mailbox_id"]
        )
        assert strip(got) == step["expect"]


def test_rd_travels_inside_the_seal():
    """The relay sees only the envelope: `rd` is in the sealed meta, never in clear bytes."""
    for sid in SUITES:
        g = VEC["suites"][sid]["reader_decl"]
        c = next(x for x in g["request_meta"] if x["name"] == "request_meta_with_rd_accepted")
        env = bytes.fromhex(c["steps"][0]["envelope"])
        assert g["digest"]["rd"].encode() not in env and b'"rd"' not in env
        assert c["steps"][0]["expect"]["meta"]["rd"] == g["digest"]["rd"]
