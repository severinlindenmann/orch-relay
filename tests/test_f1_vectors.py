"""Relay-side check of the ticket-format F1 vectors in tests/vectors/f1/ (byte-identical copies of orch-core's
plugins/orch-core/tests/vectors/f1/*.json, see tests/vectors/f1/SOURCE).

Nothing here imports orch-core. Every expected value is recomputed from the F1 text (orch-core
docs/architecture/orch-v2-ticket-format.md: section numbers are quoted in the tests) using the relay reference
(`ref.orch_protocol_ref`: cj, strict parse, labels) and the helpers below.

Verification follows the pinned F1 text; no orch-core code is imported.
"""

import hashlib
import json
import os
import posixpath
import re
import subprocess
import sys
import unicodedata
from datetime import datetime
from pathlib import Path

import pytest

from ref import orch_protocol_ref as R

F1 = Path(__file__).parent / "vectors" / "f1"


def load(name):
    return json.loads((F1 / f"{name}.json").read_text(encoding="utf-8"))


def by_name(cases):
    return pytest.mark.parametrize("c", cases, ids=lambda c: c["name"])


needs_unicode_16 = pytest.mark.skipif(
    unicodedata.unidata_version != "16.0.0" and not os.environ.get("CI"),
    reason=f"F1 section 11.3 pins Unicode 16.0; this Python has {unicodedata.unidata_version} and the relay "
    "does not bundle 16.0 tables (CI runs Python 3.14, which has 16.0)",
)


def test_unicode_tables_are_16_0_in_ci():
    """A skip is not a pass: in CI the text tests must run, so other Unicode data fails here."""
    if os.environ.get("CI"):
        assert unicodedata.unidata_version == "16.0.0"


def sha(b: bytes) -> str:
    return "sha256:" + hashlib.sha256(b).hexdigest()


def hl(label: str, data: bytes) -> str:
    """`sha256:` + hex(SHA-256(label || data)) (F1 §5.6)."""
    return sha(label.encode() + data)


# --- text rules (F1 §11.3) ----------------------------------------------------------------------------

BIDI = {
    0x202A,
    0x202B,
    0x202C,
    0x202D,
    0x202E,
    0x2066,
    0x2067,
    0x2068,
    0x2069,
    0x200E,
    0x200F,
    0x061C,
}


def normalize(s: str) -> str:
    """The way in: CRLF and lone CR to LF, then NFC. Nothing else changes."""
    return unicodedata.normalize("NFC", s.replace("\r\n", "\n").replace("\r", "\n"))


def forbidden(c: str) -> bool:
    o = ord(c)
    return (
        (o < 0x20 and c not in "\n\t")
        or o == 0x7F
        or 0x80 <= o <= 0x9F
        or o in BIDI
        or unicodedata.category(c)
        in ("Cn", "Cs")  # unassigned in Unicode 16.0, or a lone surrogate
    )


def text_ok(s: str) -> bool:
    """What hash and signature functions require of a string: already normalised and free of refused code points.
    They refuse, they never normalise (§5.6, §11.3)."""
    return s == normalize(s) and not any(forbidden(c) for c in s)


def check_text(v):
    """Every string inside a hashed value must pass the text rules."""
    if isinstance(v, str):
        if not text_ok(v):
            raise ValueError("text rules")
    elif isinstance(v, list):
        for x in v:
            check_text(x)
    elif isinstance(v, dict):
        for k, x in v.items():
            check_text(k)
            check_text(x)


def cjt(v) -> bytes:
    check_text(v)
    return R.cj(v)


# --- the hashes of F1 §5.6 ----------------------------------------------------------------------------

# F1 additions are registered locally: this task only changes the independent test model.
L = R.LABELS | {
    "h_checkpoint": "orch/v2/checkpoint-hash|",
    "h_log_acc": "orch/v2/log-acc|",
}


def section_hash(text: str) -> str:
    check_text(text)
    # section text has its leading and trailing LF removed already (§4) and is at most 65 536 bytes
    if text.startswith("\n") or text.endswith("\n") or len(text.encode()) > 65536:
        raise ValueError("not section text")
    return hl(L["h_section"], text.encode())


def value_hash(v) -> str:
    return hl(L["h_value"], cjt(v))


def people_canon(p: dict) -> dict:
    return {k: (sorted(set(v)) if isinstance(v, list) else v) for k, v in p.items()}


def people_hash(p: dict) -> str:
    return hl(L["h_people"], cjt(people_canon(p)))


def policy_canon(p: dict) -> dict:
    out = dict(p)
    for k in ("approvers", "not"):
        out[k] = sorted(set(p[k]))
    if isinstance(p["applies"], list):
        out["applies"] = sorted(set(p["applies"]))
    return out


def policy_hash(gate: str, p: dict) -> str:
    tokens = {"owner", "maintainer", "member", "ticket_owner", "assignees", "reviewers", "watchers"}
    applies = p.get("applies")
    if (
        set(p) != {"approvers", "count", "not", "applies", "independent"}
        or not p["approvers"]
        or not set(p["approvers"]) <= tokens
        or not set(p["not"]) <= tokens
        or type(p["count"]) is not int
        or p["count"] < 1
        or type(p["independent"]) is not bool
        or not (
            applies in ("all", "off")
            or isinstance(applies, list)
            and applies
            and set(applies) <= {"feature", "bug", "chore", "spike", "epic"}
        )
        or gate == "code"
        and (not p["independent"] or "assignees" not in p["not"])
    ):
        raise ValueError("invalid policy")
    return hl(L["h_policy"], cjt({"gate": gate, "policy": policy_canon(p)}))


def grant_secret_hash(secret: bytes) -> str:
    """F1 section 10.1 A3 / 10.8: the grant secret is 32 random bytes; any other length is refused."""
    if len(secret) != 32:
        raise ValueError("grant secret must be 32 bytes")
    return hl(L["h_grant_secret"], secret)


def question_id(workspace_id: str, ticket: str, question: str) -> str:
    h = hashlib.sha256(
        L["h_question_id"].encode()
        + cjt({"workspace_id": workspace_id, "ticket": ticket, "question": question})
    ).digest()
    return h[:16].hex()


def question_hash(qid, ticket, text, options) -> str:
    return hl(
        L["h_question"],
        cjt({"question_id": qid, "ticket": ticket, "text": text, "options": options}),
    )


# --- labels (F1 §5.6, §5.3, §5.5, §5.10) -------------------------------------------------------------------

F1_LABELS = {
    "h_checkpoint": "orch/v2/checkpoint-hash|",
    "h_log_acc": "orch/v2/log-acc|",
    "section": "orch/v2/section|",
    "value": "orch/v2/value|",
    "gate": "orch/v2/gate|",
    "policy": "orch/v2/policy|",
    "people": "orch/v2/people|",
    "question": "orch/v2/question|",
    "question_id": "orch/v2/question-id|",
    "event": "orch/v2/event|",
    "grant_secret": "orch/v2/grant-secret|",
    "sig_ticket_event": "orch/v2/sig/ticket-event|",
    "sig_ws_event": "orch/v2/sig/ws-event|",
    "sig_host_event": "orch/v2/sig/host-event|",
    "sig_checkpoint": "orch/v2/sig/checkpoint|",
}


def test_labels_are_the_ones_the_f1_text_names():
    assert load("labels")["labels"] == F1_LABELS


def test_f1_labels_are_in_the_protocol_registry():
    """The independent F1 registry extends the relay registry with the two pinned hash labels."""
    registry = set(L.values())
    for name, label in F1_LABELS.items():
        assert label in registry, name
    assert R.LABELS["h_question"] == F1_LABELS["question"]


def test_f1_labels_are_prefix_free_with_every_protocol_label():
    """Signed and hashed inputs are label || bytes: no label may be a prefix of another (protocol §3). The
    protocol's own check covers sig_/aad_/h_/mac_; this one covers all of them against all of F1's."""
    f1 = list(F1_LABELS.values())
    everything = [v for v in L.values() if v.endswith("|")]
    for a in f1:
        assert a.endswith("|") and a.startswith("orch/v2/") and a.isascii()
        for b in everything:
            assert a == b or not (a.startswith(b) or b.startswith(a)), (a, b)


# --- canonical JSON: depth and -0 (F1 §11.2, protocol §2.3) ---------------------------------------------


@by_name(load("canon")["depth"])
def test_canon_depth_and_minus_zero(c):
    try:
        v = R.parse_json(c["text"].encode())
    except ValueError:
        assert not c["ok"]
        return
    assert c["ok"]
    assert R.cj(v).decode() == c["canonical"]


# --- text (F1 §11.3) --------------------------------------------------------------------------------------

TEXT = load("text")


def test_text_vectors_are_pinned_to_unicode_16():
    assert TEXT["unicode_version"] == "16.0.0"


@needs_unicode_16
@by_name(TEXT["normalize"])
def test_text_normalize(c):
    out = normalize(c["input"])
    assert out == c["output"]
    assert text_ok(out)


@needs_unicode_16
@by_name(TEXT["kept_invisible"])
def test_text_invisible_characters_are_kept(c):
    """§11.3: other invisible characters stay (shown as ⟨U+…⟩ in prompts); nothing is stripped."""
    assert normalize(c["input"]) == c["input"]
    assert text_ok(c["input"])


@needs_unicode_16
@by_name(TEXT["refused"])
def test_text_refused_after_normalising(c):
    assert not text_ok(normalize(c["input"]))


@needs_unicode_16
@by_name(TEXT["refused_not_normalised"])
def test_text_refused_by_hash_functions_not_normalised(c):
    """§5.6: a hash function refuses a string that is not already NFC/LF; every hash entry point refuses it."""
    s = c["input"]
    assert not text_ok(s)
    for fn in (section_hash, value_hash):
        with pytest.raises(ValueError):
            fn(s)


# --- the plain hashes ---------------------------------------------------------------------------------------

H = load("hashes")


@pytest.mark.parametrize("c", H["artifact_digest"], ids=lambda c: c["hash"][7:15])
def test_artifact_digest_is_plain_sha256(c):
    assert sha(bytes.fromhex(c["bytes_hex"])) == c["hash"]


@pytest.mark.parametrize("c", H["grant_secret_hash"], ids=lambda c: c["hash"][7:15])
def test_grant_secret_hash(c):
    assert grant_secret_hash(bytes.fromhex(c["secret_hex"])) == c["hash"]


@pytest.mark.parametrize(
    "secret_hex", H["grant_secret_hash_refused"], ids=lambda s: f"{len(s) // 2}_bytes"
)
def test_grant_secret_must_be_32_bytes(secret_hex):
    """F1 section 10.1 A3 and 10.8 state the 32-byte secret; the hash helper refuses any other length."""
    with pytest.raises(ValueError):
        grant_secret_hash(bytes.fromhex(secret_hex))


@pytest.mark.parametrize("c", H["section_hash"], ids=lambda c: c["hash"][7:15])
def test_section_hash(c):
    assert section_hash(c["text"]) == c["hash"]


def test_section_hash_of_the_empty_section_is_the_missing_section_hash():
    """§5.6: a missing section has the hash of ''."""
    assert section_hash("") == hl(L["h_section"], b"")


@pytest.mark.parametrize(
    "text", H["section_hash_refused"], ids=lambda t: f"{len(t)}_chars_{hash(t) & 0xFFFF:x}"
)
def test_section_hash_refused(text):
    with pytest.raises(ValueError):
        section_hash(text)


@pytest.mark.parametrize("c", H["value_hash"], ids=lambda c: c["hash"][7:15])
def test_value_hash(c):
    assert value_hash(c["value"]) == c["hash"]


@pytest.mark.parametrize("v", H["value_hash_refused"], ids=lambda v: json.dumps(v)[:20])
def test_value_hash_refused(v):
    with pytest.raises(ValueError):
        value_hash(v)


@pytest.mark.parametrize("c", H["people_hash"], ids=lambda c: c["hash"][7:15])
def test_people_hash(c):
    assert people_hash(c["people"]) == c["hash"]


@pytest.mark.parametrize("c", H["policy_hash"], ids=lambda c: c["gate"])
def test_policy_hash(c):
    assert policy_hash(c["gate"], c["policy"]) == c["hash"]


@pytest.mark.parametrize("c", H["question_id"], ids=lambda c: c["question"])
def test_question_id(c):
    assert question_id(c["workspace_id"], c["ticket"], c["question"]) == c["qid"]


@pytest.mark.parametrize("c", H["question_hash"], ids=lambda c: c["hash"][7:15])
def test_question_hash(c):
    assert question_hash(c["qid"], c["ticket"], c["text"], c["options"]) == c["hash"]


@pytest.mark.parametrize("c", H["question_hash_refused"], ids=["text", "option_label"])
def test_question_hash_refused(c):
    with pytest.raises(ValueError):
        question_hash("0" * 32, "01J9ZK4Q7M3R8T2V6X0B5N1C9D", c["text"], c["options"])


# --- gate hash (F1 §5.7) -----------------------------------------------------------------------------------

GATES = ("requirements", "plan", "verify", "code")
G_KEYS = {
    "workspace_id",
    "uid",
    "gate",
    "schema",
    "hash_v",
    "sections",
    "fields",
    "addon_packages",
    "tasks",
    "artifacts",
    "receipts",
    "source_sha",
    "prior",
    "policy_hash",
    "people_hash",
}
G_SECTIONS = {
    "requirements": {"summary", "context", "requirements", "out_of_scope"},
    "plan": {"plan", "decisions"},
    "verify": {"verification", "findings"},
    "code": set(),
}
HASH_RE = re.compile(r"sha256:[0-9a-f]{64}")


@by_name(load("gate_hash")["gate_hash"])
def test_gate_hash(c):
    G = c["G"]
    assert R.cj(G).hex() == c["cj_hex"]
    assert hl(L["h_gate"], R.cj(G)) == c["hash"]
    assert G["gate"] == c["gate"] in GATES


@by_name(load("gate_hash")["gate_hash"])
def test_gate_input_has_the_shape_of_the_f1_table(c):
    """The 15 keys are always present; empty values where a gate does not use one (§5.7)."""
    G, g = c["G"], c["gate"]
    assert set(G) == G_KEYS
    assert (G["schema"], G["hash_v"]) == ("orch.ticket/2", 1)
    assert re.fullmatch(r"[0-9a-f]{32}", G["workspace_id"])
    assert {k for k in G["sections"] if "." not in k} <= G_SECTIONS[g]
    assert all(k.split(".")[0] in G["addon_packages"] for k in G["sections"] if "." in k)
    assert all(HASH_RE.fullmatch(h) for h in G["sections"].values())
    assert set(G["fields"]) >= {"ticket_type", "size", "acceptance", "links", "addons"}
    assert (G["fields"]["links"] is None) == (g in ("requirements", "plan"))
    if g != "plan":
        assert G["tasks"] == []
    if g == "code":
        assert G["artifacts"] == {} and G["sections"] == {}
    if g != "verify":
        assert G["receipts"] == {}
    if g in ("requirements", "plan"):
        assert G["source_sha"] == []
    assert set(G["prior"]) <= set(GATES[: GATES.index(g)])
    assert HASH_RE.fullmatch(G["policy_hash"]) and HASH_RE.fullmatch(G["people_hash"])


def test_gate_hashes_cover_the_four_gates_and_the_documented_variants():
    names = {c["name"] for c in load("gate_hash")["gate_hash"]}
    assert {c["gate"] for c in load("gate_hash")["gate_hash"]} == set(GATES)
    assert {"verify_null_receipt", "requirements_chore"} <= names


def test_gate_inputs_reuse_hashes_that_are_recomputable():
    """The requirements case embeds the empty people hash and the hash of '' for its empty sections."""
    c = next(c for c in load("gate_hash")["gate_hash"] if c["name"] == "requirements")
    assert c["G"]["people_hash"] == people_hash({})
    assert section_hash("") in c["G"]["sections"].values()


# --- chain and signed bytes (F1 §5.3, §5.5) ----------------------------------------------------------------

CH = load("chain")
SIGNED_OUT = ("seq", "at", "prev", "ws_seq", "sig", "host_sig")


def envelope(label_key, log, event):
    return L[label_key].encode() + R.cj(
        {"contract": 1, "suite": 2, "workspace_id": CH["workspace_id"], "log": log, "event": event}
    )


def head(e) -> str:
    return hl(L["h_event"], R.cj(e))


def test_chain_has_three_events_and_a_log_head():
    assert len(CH["events"]) == 3 == len(CH["heads"])
    assert CH["log_head"] == CH["heads"][-1]


def test_event_heads_cover_the_full_event_with_host_sig():
    for e, h in zip(CH["events"], CH["heads"]):
        assert head(e) == h
        assert "host_sig" in e
        assert head({k: v for k, v in e.items() if k != "host_sig"}) != h


def test_prev_links_and_seq():
    evs = CH["events"]
    assert [e["seq"] for e in evs] == [1, 2, 3]
    assert evs[0]["prev"] is None
    for i in (1, 2):
        assert evs[i]["prev"] == CH["heads"][i - 1]
    assert evs[1]["based_on"] == CH["heads"][0] and evs[2]["based_on"] == CH["heads"][1]


def test_ws_seq_is_non_decreasing():
    assert [e["ws_seq"] for e in CH["events"]] == sorted(e["ws_seq"] for e in CH["events"])


def test_host_signing_bytes():
    """`host_sig` signs the event without `host_sig` (so with seq, at, prev, ws_seq and sig), §5.5."""
    for e, hx in zip(CH["events"], CH["host_signing_hex"]):
        body = {k: v for k, v in e.items() if k != "host_sig"}
        assert envelope("sig_host_event", CH["log"], body).hex() == hx


def test_person_event_signing_bytes_drop_the_unsigned_fields():
    """The device signs the event without seq, at, prev, ws_seq, sig and host_sig, §5.3."""
    e = CH["events"][1]
    body = {k: v for k, v in e.items() if k not in SIGNED_OUT}
    assert envelope("sig_ticket_event", CH["log"], body).hex() == CH["ticket_event_signing_hex"]
    assert {"id", "type", "actor", "auth", "based_on", "roster_v", "hash_v", "gate_gen"} <= set(
        body
    )


def test_person_event_signature_cannot_be_replayed_into_another_log_or_workspace():
    e = CH["events"][1]
    body = {k: v for k, v in e.items() if k not in SIGNED_OUT}
    good = envelope("sig_ticket_event", CH["log"], body)
    assert envelope("sig_ticket_event", "01J9ZK4Q7M3R8T2V6X0B5N1C9E", body) != good
    assert envelope("sig_ws_event", CH["log"], body) != good
    assert envelope("sig_host_event", CH["log"], body) != good


def test_workspace_event_signing_bytes():
    ws = CH["ws_event"]
    assert envelope("sig_ws_event", "workspace", ws).hex() == CH["ws_event_signing_hex"]


def test_workspace_host_signing_bytes_carry_the_line_fields():
    """The host signs the workspace line (the signed event plus seq, at, prev, ws_seq). Only the signed bytes are
    in the file, not the line, so check them against the event and the stated fields."""
    raw = bytes.fromhex(CH["ws_log_host_signing_hex"])
    label = L["sig_host_event"].encode()
    assert raw.startswith(label)
    o = R.parse_json(raw[len(label) :])
    assert (o["contract"], o["suite"], o["workspace_id"], o["log"]) == (
        1,
        2,
        CH["workspace_id"],
        "workspace",
    )
    line = o["event"]
    assert {k: v for k, v in line.items() if k not in SIGNED_OUT} == CH["ws_event"]
    assert (line["seq"], line["prev"]) == (1, None) and isinstance(line["at"], str)


def test_lines_are_cj_plus_lf():
    for e, hx in zip(CH["events"], CH["lines_hex"]):
        assert R.cj(e) + b"\n" == bytes.fromhex(hx)
        assert R.cj(R.parse_json(bytes.fromhex(hx))) + b"\n" == bytes.fromhex(hx)


@pytest.mark.parametrize("hx", CH["non_cj_lines"], ids=lambda h: h[:16] + str(len(h)))
def test_non_cj_lines_are_refused(hx):
    """§5.5: strictly parse each line and check that it is `cj`. These parse, but are not `cj` plus one LF."""
    raw = bytes.fromhex(hx)
    try:
        obj = R.parse_json(raw)
    except ValueError:
        return
    assert R.cj(obj) + b"\n" != raw


def verify_chain(events):
    """The reader's rule (F1 section 5.5): seq counts from 1, prev of seq 1 is null, every other prev is the head
    of the line before. Returns the seq of the first broken line, or None."""
    prev = None
    for n, e in enumerate(events, start=1):
        if e["seq"] != n or e["prev"] != prev:
            return n
        prev = head(e)
    return None


def test_a_tampered_line_breaks_the_chain_at_its_successor():
    """The file names no tamper recipe (core should add one); the head matches events[1] with `gate` set to `plan`,
    found by search. A reader stops at seq 3, whose prev no longer matches the head of line 2."""
    e1, e2, e3 = CH["events"]
    assert verify_chain([e1, e2, e3]) is None
    tampered = e2 | {"gate": "plan"}
    assert head(tampered) == CH["tampered_event_head"] != CH["heads"][1]
    assert verify_chain([e1, tampered, e3]) == 3


# --- repo identity (F1 §5.7) ---------------------------------------------------------------------------------

R_ID = load("repo_identity")
LABEL = r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
SEG = r"[A-Za-z0-9._~-]+"
URL_RE = re.compile(
    rf"https://(?P<host>[^/:]+)(:(?P<port>[1-9][0-9]{{0,4}}))?(?P<path>(/{SEG})+)", re.ASCII
)
LOCAL_RE = re.compile(
    r"local:[A-Za-z0-9][A-Za-z0-9._-]{0,99}", re.ASCII
)  # repo name pattern, F1 §3
OCTET = r"(0|[1-9][0-9]{0,2})"


def host_ok(h: str) -> bool:
    if len(h) > 253 or not re.fullmatch(rf"{LABEL}(\.{LABEL})*", h, re.ASCII):
        return False
    last = h.rsplit(".", 1)[-1]
    if (
        last.isdigit()
    ):  # an all-numeric last label only as a plain dotted quad without leading zeros
        parts = h.split(".")
        return len(parts) == 4 and all(re.fullmatch(OCTET, p) and int(p) <= 255 for p in parts)
    return True


def canonical_identity(s: str) -> bool:
    """Is `s` exactly the canonical repo identity form of §5.7 (anything else is refused, never converted)?"""
    if LOCAL_RE.fullmatch(s):
        return True
    m = URL_RE.fullmatch(s)
    if not m or not host_ok(m["host"]):
        return False
    port = m["port"]
    if port is not None and not 1 <= int(port) <= 65535 or port == "443":
        return False
    segs = m["path"][1:].split("/")
    return not any(x in (".", "..") for x in segs) and not segs[-1].lower().endswith(".git")


@pytest.mark.parametrize("s", R_ID["ok"])
def test_repo_identity_canonical_forms_are_accepted(s):
    assert canonical_identity(s)


@pytest.mark.parametrize("s", R_ID["refused"], ids=lambda s: s[:60] or "empty")
def test_repo_identity_other_forms_are_refused(s):
    assert not canonical_identity(s)


@pytest.mark.parametrize("pair", R_ID["same"], ids=lambda p: p[0])
def test_repo_identities_compare_ignoring_ascii_case(pair):
    a, b = pair
    assert canonical_identity(a) and canonical_identity(b) and a != b
    assert a.lower() == b.lower()


# --- byte identity, the reference's own question hash, deep input -----------------------------------------------


def test_vector_files_match_the_recorded_sha256():
    """SOURCE records the orch-core commit and the sha256 of each copy: a hand edit of a copied file fails."""
    rec = dict(
        line.split()[::-1]
        for line in (F1 / "SOURCE").read_text().splitlines()
        if line.startswith("sha256:")
    )
    assert "Commit: f1094b3fc2a4c3e5ae16dc8fd23162b8360bba09" in (F1 / "SOURCE").read_text()
    assert {p.name for p in F1.iterdir()} == {n + ".json" for n in FILE_KEYS} | {"SOURCE"}
    files = sorted(p.name for p in F1.glob("*.json"))
    assert files == sorted(rec) and set(files) == {name + ".json" for name in FILE_KEYS}
    for name in files:
        assert "sha256:" + hashlib.sha256((F1 / name).read_bytes()).hexdigest() == rec[name]


def test_canon_depth_cases_are_in_the_protocol_vectors():
    proto = json.loads(R.VECTORS.read_text(encoding="utf-8"))["encodings"]["strict_parse"]
    by = {c["name"]: c for c in proto}
    for c in load("canon")["depth"]:
        assert by[c["name"]]["text"] == c["text"] and by[c["name"]]["ok"] == c["ok"]


@pytest.mark.parametrize("c", H["question_hash"], ids=lambda c: c["hash"][7:15])
def test_reference_question_hash_is_the_f1_question_hash(c):
    """Protocol section 13's content_hash digest and F1's question hash are one hash (F1 writes it as sha256:hex)."""
    content = {
        "question_id": c["qid"],
        "ticket": c["ticket"],
        "text": c["text"],
        "options": c["options"],
    }
    assert "sha256:" + R.question_hash(content).hex() == c["hash"]


def test_very_deep_input_is_a_value_error_not_a_recursion_error():
    deep = b"[" * 200000 + b"]" * 200000
    with pytest.raises(ValueError):
        R.parse_json(deep)


# Exact upstream family and top-level field inventory.
FILE_KEYS = {
    "genesis": ["genesis", "note", "pins", "refused", "valid", "workspace_id"],
    "canon": ["depth"],
    "labels": ["labels"],
    "restore": ["host_cases", "pins", "scenarios", "schema_cases"],
    "effective_policy": ["cases", "pins", "scenarios"],
    "section_text": ["cases", "note", "pins"],
    "checkpoint": [
        "divergence",
        "forged",
        "genesis",
        "note",
        "pins",
        "ticket_checkpoint",
        "ticket_log",
        "ticket_offers",
        "transition_cases",
        "workspace_checkpoint",
        "workspace_id",
        "workspace_log",
        "workspace_n_held",
        "workspace_n_offers",
        "workspace_offers",
        "wsk_pub",
    ],
    "gate_hash": ["gate_hash", "note", "pins"],
    "artifact_refs": ["cases", "pins", "regex"],
    "hashes": [
        "artifact_digest",
        "grant_secret_hash",
        "grant_secret_hash_refused",
        "people_hash",
        "pins",
        "policy_hash",
        "policy_hash_refused",
        "question_hash",
        "question_hash_refused",
        "question_id",
        "section_hash",
        "section_hash_refused",
        "value_hash",
        "value_hash_refused",
    ],
    "replay": ["genesis", "name", "now", "pins", "steps", "workspace_id"],
    "refusal_order": ["pins", "scenarios"],
    "questions": ["pins", "scenarios"],
    "signatures": [
        "host_refused",
        "host_unsigned_ticket_event",
        "keys",
        "note",
        "person_accepted_despite_change",
        "person_refused",
        "pins",
        "ticket_event",
        "workspace_id",
        "ws_event",
    ],
    "chain": [
        "events",
        "heads",
        "host_signing_hex",
        "lines_hex",
        "log",
        "log_head",
        "non_cj_lines",
        "tampered_event_head",
        "ticket_event_signing_hex",
        "workspace_id",
        "ws_event",
        "ws_event_signing_hex",
        "ws_log_host_signing_hex",
    ],
    "tamper": [
        "cases",
        "genesis",
        "heads",
        "note",
        "now",
        "pins",
        "ticket_events",
        "ticket_lines_hex",
        "workspace_events",
        "workspace_id",
        "workspace_lines_hex",
    ],
    "generation": ["pins", "scenarios"],
    "devices": ["pins", "scenarios"],
    "repo_identity": ["mapping", "mapping_note", "ok", "pins", "refused", "same"],
    "approvals": ["pins", "scenarios"],
    "index": ["files", "note"],
    "revocation": ["pins", "scenarios"],
    "text": ["kept_invisible", "normalize", "refused", "refused_not_normalised", "unicode_version"],
    "status": ["pins", "scenarios"],
}


@pytest.mark.parametrize("name", sorted(FILE_KEYS))
def test_family_parse_and_shape(name):
    assert sorted(load(name)) == FILE_KEYS[name]


# --- Real P-256 signatures (§5.3, §5.5), independently built signed bytes ---

S = R.SUITES[2]
SIG = load("signatures")


def signed_event_bytes(e, ws, log, host=False):
    omit = ("host_sig",) if host else SIGNED_OUT
    label = (
        "sig_host_event" if host else "sig_ws_event" if log == "workspace" else "sig_ticket_event"
    )
    return L[label].encode() + cjt(
        {
            "contract": 1,
            "suite": 2,
            "workspace_id": ws,
            "log": log,
            "event": {k: v for k, v in e.items() if k not in omit},
        }
    )


def signature_ok(pub, signature, data):
    try:
        return S.verify(R.unb64u(pub, 65), R.unb64u(signature, 64), data)
    except (ValueError, TypeError):
        return False


def person_ok(e, cert, ws, log):
    return cert is not None and signature_ok(
        cert["o"]["dk_sig_pub"], e.get("sig"), signed_event_bytes(e, ws, log)
    )


def host_ok_event(e, wsk, ws, log):
    return signature_ok(wsk, e.get("host_sig"), signed_event_bytes(e, ws, log, True))


@pytest.mark.parametrize("kind", ["ticket_event", "ws_event"])
def test_real_event_signatures(kind):
    c = SIG[kind]
    e, ws, log = c["event"], SIG["workspace_id"], c["log"]
    assert signed_event_bytes(e, ws, log).hex() == c["person_signing_hex"]
    assert signed_event_bytes(e, ws, log, True).hex() == c["host_signing_hex"]
    assert person_ok(e, c["cert"], ws, log)
    assert host_ok_event(e, SIG["keys"]["wsk"]["pub_b64u"], ws, log)
    assert head(e) == c["head"]


@by_name(SIG["person_refused"])
def test_person_signature_refused(c):
    assert not person_ok(c["event"], c["cert"], c["workspace_id"], c["log"])


@by_name(SIG["person_accepted_despite_change"])
def test_person_signature_unsigned_fields(c):
    assert person_ok(c["event"], c["cert"], c["workspace_id"], c["log"])


@by_name(SIG["host_refused"])
def test_host_signature_refused(c):
    assert not host_ok_event(c["event"], c["wsk_pub"], c["workspace_id"], c["log"])


def test_host_signature_required():
    assert not host_ok_event(
        SIG["host_unsigned_ticket_event"],
        SIG["keys"]["wsk"]["pub_b64u"],
        SIG["workspace_id"],
        SIG["ticket_event"]["log"],
    )


# §5.7: raw config values, no URL library normalization or insteadOf expansion.
def map_remote(raw, name, additional=()):
    local = "local:" + name
    if not raw or additional or not raw.isascii():
        return local
    m = re.fullmatch(r"(https|ssh)://([^/]+)(/.*)", raw)
    if m:
        scheme, authority, path = m.groups()
        if "@" in authority:
            user, authority = authority.split("@", 1)
            if scheme != "ssh" or user != "git":
                return local
        hp = authority.split(":")
        host = hp[0].lower()
        if len(hp) > 2:
            return local
        port = hp[1] if len(hp) == 2 else None
        if port == ("443" if scheme == "https" else "22"):
            port = None
    else:
        m = re.fullmatch(r"(?:git@)?([^/@:]+):([^/].*)", raw)
        if not m:
            return local
        host, path = m.groups()
        host, path, port = host.lower(), "/" + path, None
    path = path.removesuffix("/").removesuffix(".git")
    mapped = "https://" + host + (":" + port if port is not None else "") + path
    return mapped if canonical_identity(mapped) else local


def ascii_fold(s):
    """F1 §2 / §8.1: only ASCII A–Z fold; NFC non-ASCII stays exact."""
    return unicodedata.normalize("NFC", s).translate(
        str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")
    )


def repo_paths_unique(repos):
    """§2: compare resulting settings, including unchanged entries and leading //."""
    names = [ascii_fold(name) for name in repos]
    paths = [ascii_fold(posixpath.normpath(re.sub(r"/+", "/", r["path"]))) for r in repos.values()]
    return len(names) == len(set(names)) and len(paths) == len(set(paths))


def addon_heading_key(heading):
    """§8.1: ASCII heading grammar, then ASCII alphanumerics only in its key."""
    if len(heading) > 40 or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9,&/'-]| (?! ))*", heading):
        raise ValueError("invalid addon heading")
    return re.sub(r"[^a-z0-9]", "", ascii_fold(heading))


@pytest.mark.parametrize("heading", ["Plan", "PLAN", "P-l a,n", "P/l&an"])
def test_addon_heading_ascii_key(heading):
    assert addon_heading_key(heading) == "plan"


@pytest.mark.parametrize("heading", ["Key", "İdea", "ſummary", "Café", "a  b", "a" * 41])
def test_addon_heading_refuses_non_ascii_and_bad_grammar(heading):
    with pytest.raises(ValueError):
        addon_heading_key(heading)


@pytest.mark.parametrize(
    "a, b, same",
    [("/A", "/a", True), ("/É", "/é", False), ("/é", "/e\u0301", True), ("//a", "/a", True)],
)
def test_repo_path_comparison(a, b, same):
    assert repo_paths_unique({"one": {"path": a}, "two": {"path": b}}) != same


def branch_ok(branch):
    """F1 §3: git branch names, with the additional reserved names and Unicode exclusions."""
    return (
        isinstance(branch, str)
        and bool(branch)
        and not branch.startswith(("-", "refs/"))
        and branch not in {"HEAD", "@"}
        and not branch.endswith(".")
        and not any(x in branch for x in ("..", "@{"))
        and not unicodedata.category(branch[0]).startswith("M")
        and not any(
            c in " ~^:?*[\\"
            or unicodedata.category(c) in {"Cc", "Cf", "Co", "Zs", "Zl", "Zp", "Cn", "Cs"}
            or 0xFE00 <= ord(c) <= 0xFE0F
            or 0xE0100 <= ord(c) <= 0xE01EF
            or 0x180B <= ord(c) <= 0x180F
            or ord(c) in {0x034F, 0x115F, 0x1160, 0x3164, 0xFFA0, 0x17B4, 0x17B5, 0x2800}
            for c in branch
        )
        and all(
            part and not part.startswith(".") and not part.endswith(".lock")
            for part in branch.split("/")
        )
    )


@pytest.mark.parametrize("branch", ["main", "feature/x", "café", "a.locked", "a@b"])
def test_branch_names_accepted(branch):
    assert branch_ok(branch)


@pytest.mark.parametrize(
    "branch",
    [
        "",
        "-x",
        "HEAD",
        "@",
        "refs/heads/main",
        "a..b",
        "a@{b",
        "/a",
        "a/",
        "a//b",
        ".a",
        "a/.b",
        "a.lock",
        "a.",
        "a b",
        "a~b",
        "a^b",
        "a:b",
        "a?b",
        "a*b",
        "a[b",
        "a\\b",
        "a\x00b",
        "a\x85b",
        "a\u200db",
        "a\u00adb",
    ],
)
def test_branch_names_refused(branch):
    assert not branch_ok(branch)


def links_branches_ok(links):
    """The branch-name part of the §3 links schema shares the settings rule."""
    return (
        isinstance(links, dict)
        and isinstance(links.get("branches"), dict)
        and all(branch_ok(branch) for branch in links["branches"].values())
    )


@pytest.mark.parametrize(
    "branch, ok", [("feature/x", True), ("a\u200db", False), ("a\u00adb", False)]
)
def test_branch_rule_applies_to_links_and_settings(branch, ok):
    assert links_branches_ok({"branches": {"a": branch}}) == ok
    assert settings_schema_ok({"repos": {"a": {"path": "../a", "default_branch": branch}}}) == ok


def settings_schema_ok(values):
    """F1 §2 / §5.4.2: validate declarations without repairing their values."""
    if not isinstance(values, dict) or not values.keys() <= {
        "repos",
        "grant_hours",
        "claim_ttl_min",
        "lease_ttl_min",
    }:
        return False
    for key, low, high in (
        ("grant_hours", 1, 24),
        ("claim_ttl_min", 15, 1440),
        ("lease_ttl_min", 5, 1440),
    ):
        if key in values and (type(values[key]) is not int or not low <= values[key] <= high):
            return False
    repos = values.get("repos", {})
    if not isinstance(repos, dict):
        return False
    for name, repo in repos.items():
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}", name):
            return False
        if repo is None:
            continue
        if not isinstance(repo, dict) or not {"path"} <= repo.keys() <= {
            "path",
            "remote",
            "default_branch",
        }:
            return False
        if not isinstance(repo["path"], str) or not repo["path"]:
            return False
        if "remote" in repo and (
            not isinstance(repo["remote"], str) or not canonical_identity(repo["remote"])
        ):
            return False
        if "default_branch" in repo and not branch_ok(repo["default_branch"]):
            return False
    return True


@by_name(R_ID["mapping"])
def test_repo_identity_mapping(c):
    assert map_remote(c["raw"], c["repo_name"], c.get("local_git_add", ())) == c["canonical"]


# §5.11 genesis, including the different append/replay signature precedence.
def milliseconds(at):
    from datetime import datetime

    return int(datetime.fromisoformat(at).timestamp() * 1000)


def genesis_result(e, ws, replay=False):
    cert, owner, delegation = e["device_cert"], e["owner"], e["delegation"]
    if not host_ok_event(e, e["wsk_pub"], ws, "workspace"):
        return "chain.broken"
    good_sig = person_ok(e, cert, ws, "workspace")
    if replay and not good_sig:
        return "chain.broken"
    if e["roster_v"] != 0 or e["seq"] != 1:
        return "genesis.invalid"
    pk = R.unb64u(owner["pk_pub"])
    pid = R.person_id(S, pk).hex()
    if not (
        pid == delegation["o"]["owner_person_id"] == cert["o"]["person_id"]
        and owner["person"] == "p_" + pid
    ):
        return "genesis.invalid"
    if "ok" not in R.verify_delegation(S, delegation, pk):
        return "genesis.invalid"
    if delegation["o"]["workspace_id"] != ws or delegation["o"]["wsk_pub"] != e["wsk_pub"]:
        return "genesis.invalid"
    if (
        "ok" not in R.verify_cert(S, cert, pk, milliseconds(e["at"]))
        or "operate" not in cert["o"]["scopes_max"]
        or e["actor"]["device"] != "d_" + cert["o"]["device_id"]
    ):
        return "genesis.invalid"
    return "ok" if good_sig else "sig.invalid"


@by_name([load("genesis")["valid"]] + load("genesis")["refused"])
def test_genesis_checks(c):
    e, ws = c["event"], load("genesis")["workspace_id"]
    assert head(e) == c["head"]
    for replay in (False, True):
        assert genesis_result(e, ws, replay) == c.get("replay" if replay else "append", "ok")


# §5.5: never sort lines; report the physical position, not the supplied seq.
def chain_failure(events, log, ws, wsk, certs, ws_height):
    certs = dict(certs)
    repos = {}
    prev, order = None, (0, "")
    for pos, e in enumerate(events, 1):
        if e["type"] == "settings.changed" and not settings_schema_ok(e.get("set")):
            return pos, "chain.broken"
        if e["type"] == "settings.changed":
            for name, repo in e["set"].get("repos", {}).items():
                if repo is None:
                    repos.pop(name, None)
                else:
                    repos[name] = repo
            if not repo_paths_unique(repos):
                return pos, "chain.broken"
        if (
            e["type"] == "ticket.updated"
            and "ticket.links" in e.get("set", {})
            and not links_branches_ok(e["set"]["ticket.links"])
        ):
            return pos, "chain.broken"
        if e["seq"] != pos or e["prev"] != prev or not host_ok_event(e, wsk, ws, log):
            return pos, "chain.broken"
        # §5.2: sig, auth and roster_v belong to person events only; a host event carrying one breaks the chain.
        if e["actor"]["kind"] != "person" and any(k in e for k in ("sig", "auth", "roster_v")):
            return pos, "chain.broken"
        if e["actor"]["kind"] == "person":
            cert = certs.get(e["actor"]["device"])
            if e["type"] == "workspace.created":
                cert = e["device_cert"]
            if e["type"] == "device.added" and e["actor"]["device"] == e["device"]:
                cert = e["cert"]
            if not person_ok(e, cert, ws, log):
                return pos, "chain.broken"
        if log != "workspace":
            current = (e["ws_seq"], e["at"])
            if current < order or e["ws_seq"] > ws_height:
                return pos, "chain.bad_ws_seq"
            order = current
        if "device_cert" in e:
            certs["d_" + e["device_cert"]["o"]["device_id"]] = e["device_cert"]
        if e["type"] == "device.added":
            certs[e["device"]] = e["cert"]
        prev = head(e)
    return None


def chain_break(events, log, ws, wsk, certs, ws_height):
    failure = chain_failure(events, log, ws, wsk, certs, ws_height)
    return failure[0] if failure else None


TAMPER = load("tamper")


@by_name(TAMPER["cases"])
def test_signed_chain_tampering(c):
    workspace = TAMPER["workspace_events"]
    certs = {
        "d_" + e["device_cert"]["o"]["device_id"]: e["device_cert"]
        for e in workspace
        if "device_cert" in e
    }
    broken = chain_break(
        c["events"],
        c["log"],
        TAMPER["workspace_id"],
        workspace[0]["wsk_pub"],
        certs if c["log"] != "workspace" else {},
        len(workspace),
    )
    assert broken == c["chain_broken_at"]
    if "replay_expect" in c:
        failure = chain_failure(
            c["events"],
            c["log"],
            TAMPER["workspace_id"],
            workspace[0]["wsk_pub"],
            certs,
            len(workspace),
        )
        assert (failure[1] if failure else "ok") == c["replay_expect"]
        # Exercise the stateful reader's step-1 precedence with the same signed prefix.
        state = F1State(TAMPER["workspace_id"])
        state.wsk, state.certs = workspace[0]["wsk_pub"], certs
        state.logs = {"workspace": workspace, c["log"]: c["events"][: broken - 1]}
        if broken > 1:
            previous = c["events"][broken - 2]
            state.log_order[c["log"]] = (previous["ws_seq"], previous["at"])
        assert state.judge(c["events"][broken - 1], c["log"], replay=True) == c["replay_expect"]
    if c["log"] == "workspace":
        stopped = {
            uid: next((i for i, e in enumerate(events, 1) if e["ws_seq"] >= broken), None)
            for uid, events in TAMPER["ticket_events"].items()
        }
        assert stopped == c["ticket_events_stopped_from"]
        # The same stop, found by the reader itself: ticket logs checked against ws height broken - 1.
        for uid, events in TAMPER["ticket_events"].items():
            assert (
                chain_break(
                    events, uid, TAMPER["workspace_id"], workspace[0]["wsk_pub"], certs, broken - 1
                )
                == stopped[uid]
            )


def test_signed_chain_heads_and_lines():
    for log, events in {"workspace": TAMPER["workspace_events"], **TAMPER["ticket_events"]}.items():
        assert [head(e) for e in events] == TAMPER["heads"][log]
        key = "workspace_lines_hex" if log == "workspace" else "ticket_lines_hex"
        assert [(R.cj(e) + b"\n").hex() for e in events] == TAMPER[key]


# --- Checkpoint receivers (§5.10). Restore authorization is tested separately. ---
CP = load("checkpoint")


def checkpoint_schema_and_signature_ok(signed):
    o = signed["o"]
    common = {"v", "suite", "kind", "workspace_id", "at"}
    fields = (
        {"uid", "seq", "head", "acc"}
        if o["kind"] == "ticket_checkpoint"
        else {"genesis", "n", "workspace_log", "tickets"}
    )
    return (
        set(signed) == {"o", "sig"}
        and set(o) == common | fields
        and o["v"] == 2
        and o["suite"] == 2
        and o["kind"] in {"ticket_checkpoint", "workspace_checkpoint"}
        and isinstance(o["at"], str)
        and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", o["at"])
        is not None
        # A real UTC date: `at` is compared as a string and must not decrease, so an impossible
        # high value would refuse every later honest checkpoint.
        and datetime.strptime(o["at"], "%Y-%m-%dT%H:%M:%S%z") is not None
        and all(
            entry_ok(x)
            for x in (
                [{k: o[k] for k in ("seq", "head", "acc")}]
                if o["kind"] == "ticket_checkpoint"
                else [o["workspace_log"], *o["tickets"].values()]
            )
        )
        and (o["kind"] != "workspace_checkpoint" or type(o["n"]) is int and o["n"] >= 1)
        and o["workspace_id"] == CP["workspace_id"]
        and (o["kind"] != "workspace_checkpoint" or o["genesis"] == CP["genesis"])
        and signature_ok(CP["wsk_pub"], signed["sig"], L["sig_checkpoint"].encode() + cjt(o))
    )


def entry_ok(entry):
    return (
        set(entry) == {"seq", "head", "acc"}
        and type(entry["seq"]) is int
        and entry["seq"] >= 1
        and all(HASH_RE.fullmatch(entry[k]) for k in ("head", "acc"))
    )


def checkpoint_ok(signed):
    try:
        return bool(checkpoint_schema_and_signature_ok(signed))
    except (KeyError, TypeError, ValueError, AttributeError):
        return False


def workspace_checkpoint_ok(signed):
    """H, C, T and every receiver offer are workspace checkpoints (a ticket checkpoint is refused)."""
    return checkpoint_ok(signed) and signed["o"]["kind"] == "workspace_checkpoint"


# Receiver state the shared vectors do not carry as such.
# The workspace card's PK-signed delegation (P3-D24: "the card's delegation"). Relays hold it with the card and
# devices pin it with the genesis; it is the delegation of the genesis event whose head is the pinned genesis.
GENESIS_EVENT = load("genesis")["valid"]["event"]
CARD_DELEGATION = GENESIS_EVENT["delegation"]
# The relay clock for the shared vectors: after every vector checkpoint, so the ceiling never binds there.
VECTOR_CLOCK = "2026-10-10T10:05:00Z"
# P3-D25 / relay design R3a: every published checkpoint, T included, has o.at <= relay clock + 300 s.
FUTURE_CEILING_MS = 300_000


def test_card_delegation_is_the_pinned_genesis_owner():
    assert head(GENESIS_EVENT) == CP["genesis"]
    pk = R.unb64u(GENESIS_EVENT["owner"]["pk_pub"])
    assert "ok" in R.verify_delegation(S, CARD_DELEGATION, pk)
    assert CARD_DELEGATION["o"]["workspace_id"] == CP["workspace_id"]
    assert CARD_DELEGATION["o"]["wsk_pub"] == CP["wsk_pub"]


@pytest.mark.parametrize("kind", ["ticket_checkpoint", "workspace_checkpoint"])
def test_checkpoint_signed_objects(kind):
    c = CP[kind]
    assert checkpoint_ok(c["signed"])
    assert (L["sig_checkpoint"].encode() + cjt(c["signed"]["o"])).hex() == c["signing_hex"]


@by_name(CP["forged"])
def test_forged_checkpoint(c):
    assert not checkpoint_ok(c["checkpoint"])


def height_conflict(held, offered):
    return offered["seq"] < held["seq"] or (
        offered["seq"] == held["seq"]
        and (
            offered["head"] != held["head"] or ("acc" in offered and offered["acc"] != held["acc"])
        )
    )


@by_name(CP["ticket_offers"])
def test_ticket_checkpoint_offer(c):
    assert (
        "chain.diverged" if height_conflict(CP["ticket_checkpoint"]["signed"]["o"], c) else "ok"
    ) == c["expect"]


@by_name(CP["workspace_offers"])
def test_workspace_checkpoint_log_offer(c):
    offered = {"seq": c["log_seq"], "head": c["head"]}
    assert (
        "chain.diverged"
        if height_conflict(CP["workspace_checkpoint"]["signed"]["o"]["workspace_log"], offered)
        else "ok"
    ) == c["expect"]


@by_name(CP["divergence"])
def test_checkpoint_against_local_log(c):
    h = CP["ticket_checkpoint"]["signed"]["o"]
    heads = c["ticket_heads"]
    diverged = len(heads) < h["seq"] or heads[h["seq"] - 1] != h["head"]
    assert (["chain.diverged"] if diverged else []) == c["expect"]


def strength(rev):
    return 2 if rev["o"]["reason"] == "compromised" else 1


def revocation_evidence_ok(entry):
    try:
        cert, rev, pk = entry["device_cert"], entry["revocation"], R.unb64u(entry["pk_pub"])
        # Evidence remains usable after expiry; verify at certificate creation time.
        return "ok" in R.verify_cert(S, cert, pk, cert["o"]["created_ms"]) and "ok" in (
            R.verify_revocation(S, rev, pk, cert["o"])
        )
    except (KeyError, TypeError, ValueError):
        return False


def restore_envelope_ok(e, log):
    """F1 §§5.1–5.3 / P3 R0, before signature or authorization checks."""
    from datetime import datetime

    ulid = r"[0-7][0-9A-HJKMNP-TV-Z]{25}"
    actor = e["actor"]
    if not (
        type(e["v"]) is int
        and e["v"] == 2
        and type(e["hash_v"]) is int
        and e["hash_v"] == 1
        and e["type"] == "restore"
        and re.fullmatch(ulid, e["id"])
        and type(e["seq"]) is int
        and e["seq"] >= 1
        and type(e["roster_v"]) is int
        and e["roster_v"] >= 0
        and (log == "workspace" or type(e["ws_seq"]) is int and e["ws_seq"] >= 1)
        and isinstance(actor, dict)
        and set(actor) == {"kind", "id", "device"}
        and actor["kind"] == "person"
        and re.fullmatch(r"p_[0-9a-f]{32}", actor["id"])
        and re.fullmatch(r"d_[0-9a-f]{32}", actor["device"])
        and e["auth"]
        in {
            "passphrase",
            "secure-enclave",
            "secure-enclave-unlocked",
            "webauthn",
            "tpm",
            "windows-hello",
        }
        and all(
            e[k] is None if e["seq"] == 1 else HASH_RE.fullmatch(e[k]) for k in ("based_on", "prev")
        )
        and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", e["at"])
        and isinstance(e["abandoned_decisions"], list)
        and all(re.fullmatch(ulid, ident) for ident in e["abandoned_decisions"])
    ):
        return False
    datetime.strptime(e["at"], "%Y-%m-%dT%H:%M:%S%z")
    for key in ("sig", "host_sig"):
        R.unb64u(e[key], 64)
    return True


def restore_schema_ok(e, log):
    try:
        entries, source = e["revocations"], e["source"]
        ids = [x["revocation"]["o"]["device_id"] for x in entries]
        note = e.get("note", "")
        required = {
            "v",
            "id",
            "seq",
            "at",
            "type",
            "actor",
            "based_on",
            "prev",
            "hash_v",
            "roster_v",
            "auth",
            "sig",
            "host_sig",
            "from_seq",
            "head",
            "abandoned",
            "abandoned_decisions",
            "revocations",
            "source",
            "reason",
        }
        if log != "workspace":
            required.add("ws_seq")
        abandoned = e["abandoned"]
        return (
            required <= set(e) <= required | {"note"}
            and restore_envelope_ok(e, log)
            and (
                abandoned is None
                or (
                    set(abandoned) == {"seq", "head"}
                    and type(abandoned["seq"]) is int
                    and abandoned["seq"] > e["from_seq"]
                    and HASH_RE.fullmatch(abandoned["head"])
                )
            )
            and len(cjt(e)) + 1 <= 524288
            and e["reason"] in {"rollback", "diverged", "broken", "other"}
            and isinstance(note, str)
            and "\n" not in note
            and "\r" not in note
            and len(note.encode()) <= 280
            and isinstance(entries, list)
            and all(set(x) == {"revocation", "device_cert", "pk_pub"} for x in entries)
            and ids == sorted(set(ids))
            and (log == "workspace" or entries == [])
            and (
                source is None
                or (
                    set(source) == {"n", "hash"}
                    and type(source["n"]) is int
                    and source["n"] >= 1
                    and HASH_RE.fullmatch(source["hash"])
                )
            )
            and type(e["from_seq"]) is int
            and e["from_seq"] >= 1
            and HASH_RE.fullmatch(e["head"]) is not None
        )
    except (KeyError, TypeError, ValueError):
        return False


ZERO_ACC = "sha256:" + "00" * 32


def log_acc(acc, event_head):
    if not all(isinstance(v, str) and HASH_RE.fullmatch(v) for v in (acc, event_head)):
        raise ValueError("accumulator inputs must be 32-byte hashes")
    return hl(L["h_log_acc"], bytes.fromhex(acc[7:]) + bytes.fromhex(event_head[7:]))


def fold(acc, heads):
    for h in heads:
        acc = log_acc(acc, h)
    return acc


def growth_ok(old, new, heads):
    try:
        return (
            isinstance(heads, list)
            and len(heads) == new["seq"] - old["seq"]
            and (heads[-1] == new["head"] if heads else old["head"] == new["head"])
            and fold(old["acc"], heads) == new["acc"]
        )
    except (TypeError, ValueError, KeyError):
        return False


def checkpoint_ref(signed):
    return {"n": signed["o"]["n"], "hash": hl(L["h_checkpoint"], cjt(signed["o"]))}


def entries(signed):
    return {"workspace": signed["o"]["workspace_log"], **signed["o"]["tickets"]}


def transition_ok(held, offered, restore, applied, known, card=CARD_DELEGATION):
    """P3-D24 receiver policy intentionally does not infer the owner's current roster role.

    It is bound to the workspace card's owner: the bundle's delegation must be byte-identical (cj) to the card's.
    """
    try:
        e, log, C = restore["event"], restore["log"], restore["C"]
        cert, pk, delegation = (
            restore["device_cert"],
            R.unb64u(restore["pk_pub"]),
            restore["delegation"],
        )
        if (
            restore["T"] != offered
            or C != held
            # Redundant while it holds: held only ever comes from an accepted (verified) offer, and C == held.
            or (C is not None and not workspace_checkpoint_ok(C))
            or e["source"] != (checkpoint_ref(C) if C else None)
            or e["id"] in applied
            or e["type"] != "restore"
            or not restore_schema_ok(e, log)
            or e["seq"] != e["from_seq"] + 1
            or e["prev"] != e["head"]
            or not host_ok_event(e, CP["wsk_pub"], CP["workspace_id"], log)
            or not person_ok(e, cert, CP["workspace_id"], log)
            # §19.8 R0: the card's delegation content (`o` equal), verified under the owner PK below; an owner
            # re-signing the same content is the same delegation.
            or R.cj(delegation["o"]) != R.cj(card["o"])
            or "ok" not in R.verify_delegation(S, delegation, pk)
            or delegation["o"]["workspace_id"] != CP["workspace_id"]
            or delegation["o"]["wsk_pub"] != CP["wsk_pub"]
            or "ok" not in R.verify_cert(S, cert, pk, milliseconds(e["at"]))
            or e["actor"]["id"] != "p_" + delegation["o"]["owner_person_id"]
            or e["actor"]["device"] != "d_" + cert["o"]["device_id"]
            or "operate" not in cert["o"]["scopes_max"]
            or any(s.startswith("drop:") for s in cert["o"]["scopes_max"])
            or (C and e["at"] < C["o"]["at"])
            or e["at"] > offered["o"]["at"]
            # Relay design R3: a ticket restore names a workspace seq T already commits.
            or (log != "workspace" and e["ws_seq"] > offered["o"]["workspace_log"]["seq"])
        ):
            return "chain.diverged", None
        carried = {x["revocation"]["o"]["device_id"]: x for x in e["revocations"]}
        for x in known:
            r = x["revocation"]
            device = r["o"]["device_id"]
            # §19.8 R1: the signer is unrevoked by every revocation the receiver holds, for every log.
            if device == cert["o"]["device_id"]:
                return "chain.diverged", None
            # Completeness (R4) applies to workspace restores only; a ticket restore carries [].
            if log != "workspace":
                continue
            if (
                device not in carried
                or strength(carried[device]["revocation"]) < strength(r)
                # F1 §5.10 / R4: evidence for a known device is from its known person (and stored key).
                or carried[device]["revocation"]["o"]["person_id"] != r["o"]["person_id"]
                or ("pk_pub" in x and carried[device]["pk_pub"] != x["pk_pub"])
            ):
                return "chain.diverged", None
        if not all(revocation_evidence_ok(x) for x in e["revocations"]):
            return "chain.diverged", None
        if cert["o"]["device_id"] in carried:
            return "chain.diverged", None
    except (KeyError, TypeError, ValueError, IndexError):
        return "chain.diverged", None
    try:
        old = entries(C).get(log) if C else None
        old = old or {"seq": 0, "head": None, "acc": ZERO_ACC}
        retained = {"seq": e["from_seq"], "head": e["head"], "acc": restore["acc_from"]}
        if old["seq"] > retained["seq"]:
            abandoned = e["abandoned"]
            if (
                not abandoned
                or abandoned["seq"] < old["seq"]
                or (abandoned["seq"] == old["seq"] and abandoned["head"] != old["head"])
            ):
                return "chain.diverged", None
            if not growth_ok(retained, old, restore.get("abandoned_heads")):
                return "sync.incomplete", None
            if log_acc(restore["acc_before"], e["head"]) != retained["acc"]:
                return "sync.incomplete", None
        else:
            if not growth_ok(old, retained, restore.get("forward_heads")):
                return "sync.incomplete", None
            if C is None and log == "workspace" and restore["forward_heads"][0] != CP["genesis"]:
                return "sync.incomplete", None
        return "ok", retained
    except (KeyError, TypeError, ValueError, IndexError):
        # Incomplete accumulator evidence is not evidence of equivocation.
        return "sync.incomplete", None


def checkpoint_offer(
    held, offered, restore=None, applied=(), proofs=None, known=(), *, now, card=CARD_DELEGATION
):
    """A receiver with held H (or None), relay clock `now`, and the workspace card's delegation.

    `checkpoint_time` is the relay's refusal of an `o.at` beyond its clock + 300 s (P3-D25, relay §19.8 R3a):
    409 `checkpoint_time` for every publication, restores included; `o.at == clock + 300 s` is accepted.
    """
    if not workspace_checkpoint_ok(offered):
        return "chain.diverged", None
    if held == offered:
        return "ok", None
    old, new = entries(held) if held else {}, entries(offered)
    if held:
        h, o = held["o"], offered["o"]
        if o["n"] == h["n"]:
            return ("ok", None) if o == h else ("chain.diverged", None)
        if o["n"] < h["n"]:
            stale = new.keys() <= old.keys() and all(
                new[k]["seq"] < old[k]["seq"] or new[k] == old[k] for k in new
            )
            return ("ignored", None) if stale else ("chain.diverged", None)
        if o["at"] < h["at"] or not old.keys() <= new.keys():
            return "chain.diverged", None
    if milliseconds(offered["o"]["at"]) > milliseconds(now) + FUTURE_CEILING_MS:
        return "checkpoint_time", None
    recorded = None
    if restore:
        result, retained = transition_ok(held, offered, restore, applied, known, card)
        if result != "ok":
            return result, None
        log, e = restore["log"], restore["event"]
        old[log] = retained
        recorded = e["id"]
        if (
            not proofs
            or not isinstance(proofs.get(log), list)
            or not proofs[log]
            or proofs[log][0] != head(e)
        ):
            return "sync.incomplete", None
    elif held is None:
        return "ok", None
    for log, target in new.items():
        prior = old.get(log, {"seq": 0, "head": None, "acc": ZERO_ACC})
        if height_conflict(prior, target):
            return "chain.diverged", None
        if prior == target:
            continue
        if not growth_ok(prior, target, (proofs or {}).get(log)):
            return "sync.incomplete", None
    return "ok", recorded


@by_name(CP["transition_cases"])
def test_checkpoint_transition(c):
    assert checkpoint_offer(
        c["held"],
        c["offered"],
        c.get("restore"),
        c["applied"],
        c.get("proofs"),
        c.get("known_revocations", ()),
        now=VECTOR_CLOCK,
    ) == (c["expect"], c["recorded"])


@by_name(load("restore")["schema_cases"])
def test_restore_schema(c):
    from copy import deepcopy

    state = F1State(CP["workspace_id"])
    before = deepcopy(state.__dict__)
    assert state.append(c["event"], c["log"]) == c["expect"]
    assert state.append(c["event"], c["log"], replay=True) == c["replay"]
    assert state.__dict__ == before


@by_name(CP["workspace_n_offers"])
def test_workspace_checkpoint_receiver(c):
    result, recorded = checkpoint_offer(
        CP["workspace_n_held"],
        c["checkpoint"],
        c.get("restore"),
        c.get("applied", ()),
        c.get("proofs"),
        now=VECTOR_CLOCK,
    )
    assert result == c["expect"]
    assert recorded == c.get("recorded")


# --- Stateful append verification for the shared protocol scenarios ---
# This deliberately implements only the event types exercised below. Unknown types fail,
# rather than silently receiving an 'ok'. No expected result is passed into the model.


class F1State:
    def __init__(self, ws):
        self.ws = ws
        self.wsk = None
        self.logs = {}
        self.seen = {}
        self.members = {}
        self.certs = {}
        self.removed = set()
        self.revoked = set()
        self.revocations = []
        self.roster = 0
        self.questions = {}
        self.answers = {}
        self.owners = {}
        self.grants = {}
        self.effective = {}
        self.device_keys = {}
        self.tombstones = set()
        self.gens = {}
        self.approvals = {}
        self.retired = {}
        self.ticket_types = {}
        self.log_order = {}
        self.last_order = None
        self.repos = {}

    def cert_valid(self, cert, at):
        o = cert["o"]
        member = self.members.get("p_" + o["person_id"])
        return (
            member is not None
            and "d_" + o["device_id"] not in self.removed | self.revoked
            and "ok" in R.verify_cert(S, cert, R.unb64u(member["pk_pub"]), milliseconds(at))
        )

    def judge(self, e, log, replay=False):
        t, a = e["type"], e["actor"]
        lines = self.logs.get(log, [])
        # §5.11 step 0 at append: field set (`validation.*`). sig, auth and roster_v are person-only (§5.2).
        if a["kind"] != "person" and any(k in e for k in ("sig", "auth", "roster_v")):
            return "chain.broken" if replay else "validation.field_set"
        if t == "settings.changed" and (
            not settings_schema_ok(e.get("set")) or not repo_paths_unique(self.updated_repos(e))
        ):
            return "chain.broken" if replay else "validation.event"
        if (
            t == "ticket.updated"
            and "ticket.links" in e.get("set", {})
            and not links_branches_ok(e["set"]["ticket.links"])
        ):
            return "chain.broken" if replay else "validation.event"
        if t == "restore" and not restore_schema_ok(e, log):
            return "chain.broken" if replay else "validation.event"
        # §5.11 steps 1–4, in order. At append, person signature is step 5.
        if e["seq"] != len(lines) + 1 or e["prev"] != (head(lines[-1]) if lines else None):
            return "chain.broken"
        wsk = self.wsk if self.wsk is not None else e.get("wsk_pub")
        if not host_ok_event(e, wsk, self.ws, log):
            return "chain.broken"
        # §5.11 step 1: replay verifies person signatures before ws_seq range/order.
        if replay and a["kind"] == "person":
            cert = self.certs.get(a["device"])
            if t == "workspace.created":
                cert = e["device_cert"]
            if t == "device.added" and a["device"] == e["device"]:
                cert = e["cert"]
            if not person_ok(e, cert, self.ws, log):
                return "chain.broken"
        if log != "workspace":
            current = (e["ws_seq"], e["at"], log, e["seq"])
            if (
                e["ws_seq"] > len(self.logs.get("workspace", []))
                or (not replay and e["ws_seq"] < len(self.logs.get("workspace", [])))
                or (not replay and self.last_order and current < self.last_order)
                # §5.5 holds on replay too, per log: ws_seq never decreases along a ticket log, and at never
                # goes back within one ws_seq. Only the cross-log merged order above is append-only.
                or (log in self.log_order and (e["ws_seq"], e["at"]) < self.log_order[log])
            ):
                return "chain.bad_ws_seq"
        if e["id"] in self.seen.get(log, set()):
            return "event.duplicate_id"
        if (not lines and e["based_on"] is not None) or (
            lines and e["based_on"] not in {head(x) for x in lines}
        ):
            return "event.bad_base"
        if log != "workspace":
            if not lines and t != "ticket.created":
                return "ticket.unknown"
            if lines and t == "ticket.created":
                return "ticket.exists"
        workspace_types = {
            "workspace.created",
            "member.added",
            "device.added",
            "device.removed",
            "device.revoked",
            "settings.changed",
            "grant.issued",
            "restore",
        }
        ticket_types = {
            "ticket.updated",
            "gate.approved",
            "gate.invalidated",
            "ticket.created",
            "log.added",
            "question.asked",
            "question.answered",
            "restore",
        }
        if t not in (workspace_types if log == "workspace" else ticket_types):
            return "event.unknown_type"
        if a["kind"] != "person" and not (
            t in {"device.revoked", "gate.invalidated"}
            and a["kind"] == "host"
            or t in {"question.asked", "log.added"}
            and a["kind"] == "agent"
        ):
            return "event.bad_actor"
        if t == "workspace.created":
            if self.wsk is not None:
                return "genesis.invalid"
            return genesis_result(e, self.ws)
        if self.wsk is None:
            return "genesis.invalid"
        if a["kind"] == "person":
            member = self.members.get(a["id"])
            if member is None:
                return "member.unknown"
            cert = None if a["device"] in self.tombstones else self.certs.get(a["device"])
            recovery = t == "device.added" and a["device"] == e["device"]
            if cert is None and recovery:
                active = any(
                    c["o"]["person_id"] == a["id"][2:] and self.cert_valid(c, e["at"])
                    for c in self.certs.values()
                )
                if active:
                    return "device.unknown"
                cert = e["cert"]
                # Recovery cert checks have the device.added refusal codes.
                result = self.added_cert_result(e)
                if result != "ok":
                    return result
            if cert is None or "p_" + cert["o"]["person_id"] != a["id"]:
                return "device.unknown"
            if not self.cert_valid(cert, e["at"]):
                return "device.invalid"
            required = (
                "operate"
                if t in {"member.added", "settings.changed", "grant.issued", "restore"}
                else "decide"
            )
            if required not in cert["o"]["scopes_max"]:
                return "device.scope"
            if member["role"] == "viewer" and t not in {
                "question.answered",
                "device.added",
                "device.removed",
                "device.revoked",
            }:
                return "role.denied"
            if e["roster_v"] != self.roster:
                return "members.stale"
            if not person_ok(e, cert, self.ws, log):
                return "sig.invalid"
        elif a["kind"] == "agent":
            grant = self.grants.get(a.get("grant"))
            if (
                grant is None
                or grant["actor"]["id"] != a.get("for")
                or not grant["issued_at"] <= e["at"] < grant["expires_at"]
            ):
                return "grant.invalid"
            if grant["verbs"] != "agent" and t not in grant["verbs"]:
                return "grant.verb"
        # §5.11 step 7: rules of the event type.
        role = self.members.get(a.get("id"), {}).get("role")
        if t in {"settings.changed", "restore"} and role != "owner":
            return "role.denied"
        if t == "settings.changed":
            repos = self.updated_repos(e)
            identities = set()
            for name, repo in repos.items():
                remote = repo.get("remote")
                if remote is None:
                    continue
                if remote.startswith("local:") and remote != "local:" + name:
                    return "settings.invalid"
                if ascii_fold(remote) in identities:
                    return "settings.invalid"
                identities.add(ascii_fold(remote))
        if t == "member.added":
            if "d_" + e["device_cert"]["o"]["device_id"] in self.tombstones:
                return "device.exists"
            if role != "owner" and not (role == "maintainer" and e["role"] in {"member", "viewer"}):
                return "role.denied"
            if R.person_id(S, R.unb64u(e["pk_pub"])).hex() != e["person"][
                2:
            ] or "ok" not in R.verify_cert(
                S, e["device_cert"], R.unb64u(e["pk_pub"]), milliseconds(e["at"])
            ):
                return "device.cert"
        if t == "device.added":
            if e["device"] in self.tombstones:
                return "device.exists"
            if e["device"] in self.revoked:
                return "device.invalid"
            if e["device"] in self.certs and e["device"] not in self.removed:
                return "device.exists"
            return self.added_cert_result(e)
        if t == "device.revoked":
            cert = self.certs.get(e["device"])
            if cert is None:
                return "device.unknown"
            pk = self.device_keys[e["device"]]
            result = R.verify_revocation(S, e["revocation"], R.unb64u(pk), cert["o"])
            if "ok" not in result or e["reason"] != e["revocation"]["o"]["reason"]:
                return "device.cert"
            prior = self.effective.get(e["device"])
            if prior and strength(e["revocation"]) <= strength(prior):
                return "device.exists"
        if t == "restore":
            # Evidence for every entry precedes *any* effective-revocation comparison.
            for entry in e["revocations"]:
                if not revocation_evidence_ok(entry):
                    return "device.cert"
                device = "d_" + entry["revocation"]["o"]["device_id"]
                if device in self.certs and (
                    self.certs[device]["o"]["person_id"] != entry["revocation"]["o"]["person_id"]
                    or self.device_keys[device] != entry["pk_pub"]
                ):
                    return "device.cert"
            for entry in e["revocations"]:
                rev = entry["revocation"]
                prior = self.effective.get("d_" + rev["o"]["device_id"])
                if prior and R.cj(prior) != R.cj(rev) and strength(rev) <= strength(prior):
                    return "device.exists"
        if t == "device.removed":
            cert = self.certs.get(e["device"])
            if cert is None:
                return "device.unknown"
            if role != "owner" and a["id"] != "p_" + cert["o"]["person_id"]:
                return "role.denied"
        if t == "restore" and (e["from_seq"] != len(lines) or e["head"] != head(lines[-1])):
            return "restore.bad_head"
        if t == "gate.approved" and e["gate_gen"] != self.gens[log][GATES.index(e["gate"])]:
            return "gate.stale"
        if t == "gate.invalidated" and e["voided"] != self.retired.get((log, e["gate"]), []):
            return "gate.invalidated_mismatch"
        if t == "question.asked":
            q = e["question"]
            qid = question_id(self.ws, log, q["id"])
            if e["qid"] != qid:
                return "question.bad_id"
            if e["hash"] != question_hash(qid, log, q["text"], q["options"]):
                return "question.bad_hash"
        if t == "question.answered":
            key = log, e["question"]
            if key in self.answers:
                return "question.answered"
            q = self.questions[key]
            if role not in {"owner", "maintainer"} and not (
                q["question"]["to"] == "ticket_owner" and a["id"] == self.owners[log]
            ):
                return "answer.not_allowed"
            if e["hash"] != q["hash"]:
                return "question.stale"
            if "option" in e and e["option"] not in {x["key"] for x in q["question"]["options"]}:
                return "answer.bad_option"
        return "ok"

    def raise_gates(self, log, indexes):
        # Default F1 policies in these scenarios: code is off, plan applies to feature/epic.
        for i in indexes:
            gate = GATES[i]
            if gate == "code" or (
                gate == "plan" and self.ticket_types[log] not in {"feature", "epic"}
            ):
                continue
            self.gens[log][i] += 1
            old = self.approvals[log].pop(gate, None)
            if old:
                self.retired.setdefault((log, gate), []).append(old["id"])

    def apply_revocation(self, rev):
        device = "d_" + rev["o"]["device_id"]
        if self.effective.get(device) == rev:
            return
        self.revoked.add(device)
        self.effective[device] = rev
        self.revocations.append(rev)
        if rev["o"]["reason"] == "compromised":
            self.grants = {k: g for k, g in self.grants.items() if g["actor"]["device"] != device}

    def added_cert_result(self, e):
        if e["device"] in self.tombstones:
            return "device.exists"
        cert, a = e["cert"], e["actor"]
        o = cert["o"]
        if e["device"] != "d_" + o["device_id"] or a["id"] != "p_" + o["person_id"]:
            return "device.cert"
        result = R.verify_cert(
            S, cert, R.unb64u(self.members[a["id"]]["pk_pub"]), milliseconds(e["at"])
        )
        if result.get("refuse") == "cert_expired":
            return "device.invalid"
        if "ok" not in result:
            return "device.cert"
        if "decide" not in o["scopes_max"]:
            return "device.scope"
        return "ok"

    def updated_repos(self, e):
        repos = dict(self.repos)
        for name, repo in e["set"].get("repos", {}).items():
            if repo is None:
                repos.pop(name, None)
            else:
                repos[name] = repo
        return repos

    def append(self, e, log, replay=False):
        result = self.judge(e, log, replay)
        if result != "ok":
            return result
        self.logs.setdefault(log, []).append(e)
        self.seen.setdefault(log, set()).add(e["id"])
        t = e["type"]
        if t == "settings.changed":
            self.repos = self.updated_repos(e)
        if t == "workspace.created":
            self.wsk = e["wsk_pub"]
            self.members[e["owner"]["person"]] = e["owner"] | {"role": "owner"}
            self.roster += 1
        if t == "member.added":
            self.members[e["person"]] = {"pk_pub": e["pk_pub"], "role": e["role"]}
            self.roster += 1
        if "device_cert" in e:
            c = e["device_cert"]
            self.certs["d_" + c["o"]["device_id"]] = c
            self.device_keys["d_" + c["o"]["device_id"]] = self.members["p_" + c["o"]["person_id"]][
                "pk_pub"
            ]
        if t == "device.added":
            self.certs[e["device"]] = e["cert"]
            self.device_keys[e["device"]] = self.members[e["actor"]["id"]]["pk_pub"]
            self.removed.discard(e["device"])
        if t == "device.removed":
            self.removed.add(e["device"])
        if t == "device.revoked":
            self.apply_revocation(e["revocation"])
        if t == "grant.issued":
            self.grants[e["grant"]] = e
        if t == "ticket.created":
            self.owners[log] = e["owner"]
            self.ticket_types[log] = e["ticket_type"]
            self.gens[log] = [0, 0, 0, 0]
            self.approvals[log] = {}
        if t == "ticket.updated":
            paths = set(e["set"]) | {"body." + k for k in e.get("sections", {})}
            requirements = {"ticket.type", "ticket.size", "ticket.acceptance"} | {
                "body." + k for k in G_SECTIONS["requirements"]
            }
            bounds = [
                requirements,
                requirements | {"ticket.tasks", "body.plan", "body.decisions"},
                {
                    "ticket.type",
                    "ticket.size",
                    "ticket.acceptance",
                    "ticket.links",
                    "body.verification",
                    "body.findings",
                },
                {"ticket.type", "ticket.size", "ticket.acceptance", "ticket.links"},
            ]
            changed = [i for i, bound in enumerate(bounds) if paths & bound]
            if changed:
                self.raise_gates(log, range(min(changed), 4))
        if t == "gate.approved":
            self.approvals[log][e["gate"]] = e
            self.raise_gates(log, range(GATES.index(e["gate"]) + 1, 4))
        if t == "question.asked":
            self.questions[log, e["question"]["id"]] = e
        if t == "question.answered":
            self.answers[log, e["question"]] = e["id"]
        if t == "restore":
            self.seen[log].update(e["abandoned_decisions"])
            for uid in self.gens if log == "workspace" else [log]:
                self.raise_gates(uid, range(4))
            for entry in e["revocations"]:
                device = "d_" + entry["revocation"]["o"]["device_id"]
                if device not in self.certs:
                    self.tombstones.add(device)
                    self.certs[device] = entry["device_cert"]
                    self.device_keys[device] = entry["pk_pub"]
                self.apply_revocation(entry["revocation"])
        if log != "workspace":
            self.last_order = (e["ws_seq"], e["at"], log, e["seq"])
            self.log_order[log] = (e["ws_seq"], e["at"])
        return result


SCENARIOS = [
    s
    for family in ("devices", "revocation", "questions", "restore", "refusal_order")
    for s in load(family)["scenarios"]
] + [load("replay")]


def check_scenario_step(state, step, index, replay=False):
    """Vector index notes: schema refusals never advance state; replay-only steps test both paths.

    `expect` on older schema-refused steps names the model rule, not a store schema code.
    Keep checking that rule independently; `replay_expect` explicitly pins a replay result.
    """
    from copy import deepcopy

    e, log = step["event"], step["log"]
    if step.get("replay_only"):
        assert state.judge(e, log) == "chain.bad_ws_seq"
        replay = True
    if "replay_expect" in step:
        assert state.judge(e, log, replay=True) == step["replay_expect"]
        if step["replay_expect"] == "chain.broken":
            lines = state.logs.get(log, [])
            assert (
                chain_break(
                    lines + [e], log, state.ws, state.wsk, state.certs, len(state.logs["workspace"])
                )
                == len(lines) + 1
            )
    before = deepcopy(state.__dict__)
    result = state.append(e, log, replay=replay)
    assert result == step["expect"], (index, step.get("note"))
    if result != "ok":
        assert state.__dict__ == before
    for uid, expected in step.get("after", {}).get("tickets", {}).items():
        assert state.gens[uid] == expected["gens"]
        if "approved" in expected:
            assert list(state.approvals[uid]) == expected["approved"]
        if "counting" in expected:
            assert {g: [e["actor"]["id"]] for g, e in state.approvals[uid].items()} == expected[
                "counting"
            ]
    if "workspace" in step.get("after", {}):
        assert sorted(state.revoked) == step["after"]["workspace"]["devices_revoked"]
    if "raised" in step:
        for uid in state.gens:
            assert [
                g for i, g in enumerate(GATES) if state.gens[uid][i] > before["gens"][uid][i]
            ] == step["raised"]


@by_name(SCENARIOS)
def test_protocol_scenario(c):
    state = F1State(c["workspace_id"])
    for i, step in enumerate(c["steps"]):
        check_scenario_step(state, step, i)
    assert head(state.logs["workspace"][0]) == c["genesis"]
    if "qid" in c:
        asked = next(iter(state.questions.values()))
        assert asked["qid"] == c["qid"] and asked["hash"] == c["hash"]
    if "answer_id" in c:
        assert list(state.answers.values()) == [c["answer_id"]]
    if "host_knows_revocations" in c:
        # §5.10: log-only reader cannot infer the missing host-persisted revocations.
        missing = [r for r in c["host_knows_revocations"] if r not in state.revocations]
        assert ("refused" if missing else "ok") == c["host_expect"]


@pytest.mark.parametrize("c", H["policy_hash_refused"], ids=lambda c: c["why"])
def test_policy_hash_refused(c):
    with pytest.raises(ValueError):
        policy_hash(c["gate"], c["policy"])


@by_name([c for c in R_ID["mapping"] if "local_git_config" in c or "local_git_add" in c])
def test_raw_origin_config_ignores_insteadof_and_preserves_multiple_values(c, tmp_path):
    config = tmp_path / "config"

    def git_config(*args):
        return subprocess.check_output(["git", "config", "--file", str(config), *args], text=True)

    git_config("--add", "remote.origin.url", c["raw"])
    for key, value in c.get("local_git_config", {}).items():
        git_config("--add", key, value)
    for key, value in c.get("local_git_add", {}).items():
        git_config("--add", key, value)
    raw = git_config("--get-all", "remote.origin.url").splitlines()
    assert raw[0] == c["raw"]
    assert map_remote(raw[0], c["repo_name"], raw[1:]) == c["canonical"]


def test_valid_signed_chains_and_missing_signer_certificate():
    workspace = TAMPER["workspace_events"]
    wsk, ws = workspace[0]["wsk_pub"], TAMPER["workspace_id"]
    assert chain_break(workspace, "workspace", ws, wsk, {}, len(workspace)) is None
    certs = {
        "d_" + e["device_cert"]["o"]["device_id"]: e["device_cert"]
        for e in workspace
        if "device_cert" in e
    }
    for log, events in TAMPER["ticket_events"].items():
        assert chain_break(events, log, ws, wsk, certs, len(workspace)) is None
        assert chain_break(events, log, ws, wsk, {}, len(workspace)) == 1


@by_name(load("revocation")["scenarios"])
def test_revocation_identity_checks(c):
    state = F1State(c["workspace_id"])
    checks = {x["step"]: x["identity"] for x in c.get("identity_checks", [])}
    for i, step in enumerate(c["steps"]):
        e = step["event"]
        if i in checks:
            cert = state.certs[e["device"]]["o"]
            pk = R.unb64u(state.members["p_" + cert["person_id"]]["pk_pub"])
            r = R.verify_revocation(S, e["revocation"], pk, cert)
            identity = r.get("refuse", "ok")
            if identity == "ok" and e["reason"] != e["revocation"]["o"]["reason"]:
                identity = "device.reason_mismatch"
            assert identity == checks[i]
        check_scenario_step(state, step, i)


def test_first_checkpoint_requires_signature_and_pinned_genesis():
    from copy import deepcopy

    first = CP["workspace_checkpoint"]["signed"]
    assert checkpoint_offer(None, first, now=VECTOR_CLOCK) == ("ok", None)
    changed = deepcopy(first)
    changed["o"]["genesis"] = "sha256:" + "0" * 64
    assert checkpoint_offer(None, changed, now=VECTOR_CLOCK) == ("chain.diverged", None)
    changed = deepcopy(first)
    changed["sig"] = R.b64u(bytes(64))
    assert checkpoint_offer(None, changed, now=VECTOR_CLOCK) == ("chain.diverged", None)


def test_checkpoint_lower_n_extra_uid_diverges(monkeypatch):
    """§5.10: a lower-n offer naming a ticket H lacks has a higher seq for it (H's is 0): divergence.

    No shared vector yet (asked the core for `lower_n_extra_uid`); signatures are out of scope here.
    """
    monkeypatch.setattr(sys.modules[__name__], "workspace_checkpoint_ok", lambda signed: True)
    log = {"seq": 3, "head": "sha256:" + "a" * 64}
    held = {"o": {"n": 5, "workspace_log": log, "tickets": {}}}
    offered = {
        "o": {
            "n": 4,
            "workspace_log": log,
            "tickets": {"01EXTRA": {"seq": 1, "head": "sha256:" + "b" * 64}},
        }
    }
    assert checkpoint_offer(held, offered, now=VECTOR_CLOCK) == ("chain.diverged", None)


def test_agent_event_with_person_fields_refused_at_append():
    """§5.11 step 0 / §5.2: an agent or host event carrying sig, auth or roster_v is refused before any other check."""
    state = F1State("ws")
    e = {"type": "log.added", "actor": {"kind": "agent"}, "seq": 99, "prev": None, "sig": "x"}
    assert state.judge(e, "01TICKET") == "validation.field_set"


def checkpoint_at(clock, last_at):
    """§5.10: checkpoint writers never move their timestamp backwards."""
    return max(clock, last_at)


def restore_at(clock, last_at, held):
    """§5.10 (f1094b3f): restore append sets at = max(clock, C.o.at, last at). F1 has no host-side 300 s
    refusal; the 300 s rule is the receiver ceiling of P3-D25 (`checkpoint_offer(..., now=)`)."""
    return max(clock, last_at, held["o"]["at"] if held else last_at)


def test_checkpoint_and_restore_clock_rules():
    from datetime import timedelta

    held = CP["workspace_n_held"]
    at = held["o"]["at"]
    assert checkpoint_at("2026-10-10T10:00:00Z", at) == at
    assert checkpoint_at("2026-10-10T11:00:00Z", at) == "2026-10-10T11:00:00Z"
    assert restore_at(at, "2026-10-10T10:00:00Z", held) == at
    assert restore_at("2026-10-10T11:00:00Z", at, held) == "2026-10-10T11:00:00Z"
    assert (
        restore_at("2026-10-10T09:00:00Z", "2026-10-10T09:30:00Z", None) == "2026-10-10T09:30:00Z"
    )
    # Far behind the held checkpoint: the host still writes C.o.at (no invented refusal).
    clock = datetime.fromisoformat(at) - timedelta(seconds=301)
    assert restore_at(clock.strftime("%Y-%m-%dT%H:%M:%SZ"), "2026-10-10T09:00:00Z", held) == at


@pytest.mark.parametrize("acc,h", [("sha256:" + "00" * 31, ZERO_ACC), (ZERO_ACC, "00" * 32)])
def test_accumulator_requires_two_decoded_32_byte_inputs(acc, h):
    with pytest.raises(ValueError):
        log_acc(acc, h)


@pytest.mark.parametrize(
    "kind,log", [("workspace_checkpoint", "workspace_log"), ("ticket_checkpoint", "ticket_log")]
)
def test_checkpoint_accumulators_from_full_logs(kind, log):
    o = CP[kind]["signed"]["o"]
    entry = o["workspace_log"] if kind == "workspace_checkpoint" else o
    assert fold(ZERO_ACC, CP[log]["heads"]) == entry["acc"]


class RestoreCommit:
    """Small atomic-publication model for §5.10's durable evidence/source contract.

    A single durable snapshot represents the transaction boundary. This verifies semantics,
    not any production store's filesystem or crash-recovery implementation.
    """

    def __init__(self, held, evidence):
        self.durable = {"held": held, "evidence": evidence, "transitions": {}}

    def commit(self, event, target, fault=None):
        from copy import deepcopy

        old = self.durable
        prior = old["transitions"].get(event["id"])
        if prior:
            return "prior_result" if prior == (event, target) else "chain.diverged"
        expected_source = checkpoint_ref(old["held"]) if old["held"] else None
        if event["source"] != expected_source:
            return "chain.diverged"
        carried = {x["revocation"]["o"]["device_id"]: x for x in event["revocations"]}
        for device, entry in old["evidence"].items():
            if device not in carried or strength(carried[device]["revocation"]) < strength(
                entry["revocation"]
            ):
                return "validation.restore"
        if not restore_schema_ok(event, "workspace") or not all(
            revocation_evidence_ok(x) for x in carried.values()
        ):
            return "validation.restore"
        staged = deepcopy(old)
        staged["evidence"].update(carried)
        staged["transitions"][event["id"]] = (event, target)
        staged["held"] = target
        if fault == "before_commit":
            return "no_accepted_restore"
        self.durable = staged
        return "revocation_and_transition_retained"


@by_name(load("restore")["host_cases"])
def test_restore_atomic_publication(c):
    from copy import deepcopy

    scenario = load("restore")["scenarios"][0]
    event = deepcopy(next(x["event"] for x in scenario["steps"] if x["event"]["type"] == "restore"))
    evidence = {x["revocation"]["o"]["device_id"]: x for x in event["revocations"]}
    store = RestoreCommit(None, {} if c.get("learned") else evidence)
    before = deepcopy(store.durable)
    target = CP["workspace_n_held"]
    if "missing" in c:
        event["revocations"] = []
    if c["name"] == "stale_source":
        store.durable["held"] = target
        before = deepcopy(store.durable)
    if c["name"] == "exact_restore_retry":
        store.commit(event, target)
        before = deepcopy(store.durable)
    result = store.commit(event, target, c.get("fault"))
    assert result == c["expect"]
    if result == "revocation_and_transition_retained":
        assert store.durable["evidence"] == evidence
        assert store.durable["transitions"][event["id"]] == (event, target)
        assert store.durable["held"] == target
    else:
        assert store.durable == before


def test_restore_line_cap_includes_lf():
    from copy import deepcopy

    e = deepcopy(CP["transition_cases"][0]["restore"]["event"])
    e["abandoned_decisions"] = []
    e["note"] = ""
    remaining = 524288 - len(cjt(e)) - 1
    # Each additional 26-byte id takes 29 bytes (quotes and comma), except the first.
    count = (remaining + 1) // 29
    e["abandoned_decisions"] = [f"{i:026d}" for i in range(count)]
    e["note"] = "x" * (524288 - len(cjt(e)) - 1)
    assert len(cjt(e)) + 1 == 524288
    assert restore_schema_ok(e, "workspace")
    e["note"] += "x"
    assert not restore_schema_ok(e, "workspace")


# Local signed regression cases; request matching vectors from orch-core.
def published_f1_key(name):
    from cryptography.hazmat.primitives.asymmetric import ec

    key = SIG["keys"][name]
    private = ec.derive_private_key(int(key["scalar_hex"], 16), ec.SECP256R1())
    assert R.b64u(S.sig_pub(private)) == key["pub_b64u"]
    return private


def local_transition(name="restore_accumulator_fold"):
    from copy import deepcopy

    return deepcopy(next(c for c in CP["transition_cases"] if c["name"] == name))


def sign_checkpoint(o):
    return {
        "o": o,
        "sig": R.b64u(S.sign(published_f1_key("wsk"), L["sig_checkpoint"].encode() + cjt(o))),
    }


def resign_transition(c, person="dk_sev1", host="wsk"):
    """Rebuild both outer signatures, the event head, tail proof and target signature.

    `person`/`host` name the signing keys; anything but the bundle's device key and the WSK yields a
    well-formed signature by the wrong key, isolating one signature check.
    """
    r = c["restore"]
    e, log = r["event"], r["log"]
    e["sig"] = R.b64u(
        S.sign(published_f1_key(person), signed_event_bytes(e, CP["workspace_id"], log))
    )
    e["host_sig"] = R.b64u(
        S.sign(published_f1_key(host), signed_event_bytes(e, CP["workspace_id"], log, True))
    )
    target = c["offered"]
    entry = target["o"]["workspace_log"] if log == "workspace" else target["o"]["tickets"][log]
    c["proofs"][log] = [head(e)]
    entry.update(head=head(e), acc=log_acc(r["acc_from"], head(e)))
    target["sig"] = sign_checkpoint(target["o"])["sig"]
    r["T"] = target
    # Negatives must reach the intended check with valid signatures and accumulator evidence.
    assert person_ok(e, r["device_cert"], CP["workspace_id"], log) == (
        SIG["keys"][person]["pub_b64u"] == r["device_cert"]["o"]["dk_sig_pub"]
    )
    assert host_ok_event(e, CP["wsk_pub"], CP["workspace_id"], log) == (host == "wsk")
    assert checkpoint_ok(target)
    assert fold(r["acc_from"], c["proofs"][log]) == entry["acc"]


def offer_local_transition(c, now=VECTOR_CLOCK, known=(), card=CARD_DELEGATION):
    return checkpoint_offer(
        c["held"], c["offered"], c["restore"], proofs=c["proofs"], known=known, now=now, card=card
    )


@pytest.mark.parametrize("bootstrap", [False, True])
@pytest.mark.parametrize("offset", [-1, 0, 1])
def test_restore_position_upper_bound(bootstrap, offset):
    from datetime import datetime, timedelta

    c = local_transition(
        "null_source_with_pinned_genesis" if bootstrap else "restore_accumulator_fold"
    )
    at = datetime.fromisoformat(c["offered"]["o"]["at"]) + timedelta(seconds=offset)
    c["restore"]["event"]["at"] = at.strftime("%Y-%m-%dT%H:%M:%SZ")
    resign_transition(c)
    expected = ("chain.diverged", None) if offset > 0 else ("ok", c["restore"]["event"]["id"])
    assert offer_local_transition(c) == expected


@pytest.mark.parametrize("offset", [-1, 0])
def test_restore_position_lower_bound(offset):
    from datetime import datetime, timedelta

    c = local_transition()
    at = datetime.fromisoformat(c["held"]["o"]["at"]) + timedelta(seconds=offset)
    c["restore"]["event"]["at"] = at.strftime("%Y-%m-%dT%H:%M:%SZ")
    resign_transition(c)
    expected = ("chain.diverged", None) if offset < 0 else ("ok", c["restore"]["event"]["id"])
    assert offer_local_transition(c) == expected


def local_revocation_evidence(cert, pk_name="pk_sev", reason="compromised"):
    from copy import deepcopy

    o = cert["o"]
    rev = {
        "v": 2,
        "suite": 2,
        "kind": "revocation",
        "person_id": o["person_id"],
        "device_id": o["device_id"],
        "revoked_ms": o["created_ms"] + 1000,
        "reason": reason,
    }
    return {
        "device_cert": deepcopy(cert),
        "pk_pub": SIG["keys"][pk_name]["pub_b64u"],
        "revocation": R.sign_object(S, published_f1_key(pk_name), rev),
    }


@pytest.mark.parametrize("reason", ["lost", "retired", "compromised"])
def test_restore_bundle_revokes_its_signer(reason):
    c = local_transition()
    assert offer_local_transition(c) == ("ok", c["restore"]["event"]["id"])
    evidence = local_revocation_evidence(c["restore"]["device_cert"], reason=reason)
    assert revocation_evidence_ok(evidence)
    c["restore"]["event"]["revocations"] = [evidence]
    resign_transition(c)
    # Empty local knowledge: historical bundle validity itself must reject the signer.
    assert offer_local_transition(c) == ("chain.diverged", None)


@pytest.mark.parametrize(
    "field,value",
    [
        ("v", 3),
        ("v", True),
        ("hash_v", 2),
        ("hash_v", True),
        ("type", "log.added"),
        ("id", "not-a-ulid"),
        ("seq", True),
        ("seq", 0),
        ("roster_v", -1),
        ("roster_v", True),
        ("roster_v", "1"),
        ("auth", "unknown"),
        ("auth", []),
        ("based_on", None),
        ("based_on", "not-a-hash"),
        ("prev", None),
        ("at", "2026-10-10"),
        ("at", "2026-02-30T10:00:40Z"),
        ("actor", None),
        ("actor", {"kind": "agent"}),
        ("abandoned_decisions", "01J9ZK00000000000000000002"),
        ("abandoned_decisions", ["not-a-ulid"]),
        ("abandoned_decisions", [1]),
        ("from_seq", True),
        ("from_seq", 0),
        ("head", "bad"),
        ("source", {"n": True, "hash": ZERO_ACC}),
        ("abandoned", {"seq": True, "head": ZERO_ACC}),
        ("reason", "unknown"),
        ("revocations", {}),
        # Added for the mutation sweep: each kills one schema clause no other rule covers.
        ("at", "2026-10-10T10:00:40+00:00"),
        ("abandoned_decisions", {}),
        ("abandoned", {"seq": 1, "head": ZERO_ACC}),
        ("abandoned", {"seq": 3, "head": "bad"}),
        ("source", {"n": 0, "hash": ZERO_ACC}),
        ("source", {"n": 3, "hash": "bad"}),
    ],
)
def test_restore_signed_schema_refusal(field, value):
    c = local_transition()
    c["restore"]["event"][field] = value
    resign_transition(c)
    assert not restore_schema_ok(c["restore"]["event"], "workspace")
    assert offer_local_transition(c) == ("chain.diverged", None)


@pytest.mark.parametrize(
    "field,value", [("extra", "x"), ("kind", "host"), ("id", "p_bad"), ("device", "d_bad")]
)
def test_restore_signed_actor_schema(field, value):
    c = local_transition()
    c["restore"]["event"]["actor"][field] = value
    resign_transition(c)
    assert not restore_schema_ok(c["restore"]["event"], "workspace")
    assert offer_local_transition(c) == ("chain.diverged", None)


@pytest.mark.parametrize("value", [0, True, "1", None])
def test_restore_ticket_ws_seq_schema(value):
    c = local_transition()
    e = c["restore"]["event"]
    e["ws_seq"] = value
    assert not restore_schema_ok(e, "ticket")
    e["ws_seq"] = 1
    assert restore_schema_ok(e, "ticket")
    assert not restore_schema_ok(e, "workspace")


@pytest.mark.parametrize("field", ["sig", "host_sig"])
@pytest.mark.parametrize("value", [None, "bad", "=" * 86])
def test_restore_signature_encoding_schema(field, value):
    c = local_transition()
    c["restore"]["event"][field] = value
    assert not restore_schema_ok(c["restore"]["event"], "workspace")


@pytest.mark.parametrize(
    "defect",
    [
        "revocation_signature",
        "certificate_signature",
        "revocation_person",
        "revocation_device",
        "certificate_person",
        "certificate_device",
        "account_key",
    ],
)
def test_restore_transition_embedded_evidence(defect):
    from copy import deepcopy

    c = local_transition()
    # A different, valid device of the owner: do not trip the self-revocation check.
    cert_o = deepcopy(c["restore"]["device_cert"]["o"])
    pub = S.sig_pub(published_f1_key("dk_sev2"))
    cert_o.update(dk_sig_pub=R.b64u(pub), device_id=R.device_id(S, pub).hex())
    cert = R.sign_object(S, published_f1_key("pk_sev"), cert_o)
    evidence = local_revocation_evidence(cert)
    assert revocation_evidence_ok(evidence)
    c["restore"]["event"]["revocations"] = [evidence]
    resign_transition(c)
    assert offer_local_transition(c) == ("ok", c["restore"]["event"]["id"])
    valid = deepcopy(c)

    if defect.endswith("signature"):
        key = "revocation" if defect.startswith("revocation") else "device_cert"
        evidence[key]["sig"] = R.b64u(bytes(64))
    elif defect == "account_key":
        evidence["pk_pub"] = SIG["keys"]["pk_lena"]["pub_b64u"]
    else:
        key = "revocation" if defect.startswith("revocation") else "device_cert"
        field = "person_id" if defect.endswith("person") else "device_id"
        evidence[key]["o"][field] = "0" * 32
        # Valid PK signature over an invalid identity binding.
        evidence[key] = R.sign_object(S, published_f1_key("pk_sev"), evidence[key]["o"])
    assert not revocation_evidence_ok(evidence)
    resign_transition(c)
    assert offer_local_transition(c) == ("chain.diverged", None)
    # Refusal returns no ID to record; the valid offer with the same ID remains usable.
    assert offer_local_transition(valid) == ("ok", valid["restore"]["event"]["id"])


# --- Local signed regressions for the relay security review of PR #41 (request shared vectors from orch-core).
# Each negative changes one thing, re-signs everything else validly, and expects a refusal; where useful the
# same bundle is shown accepted when only that one thing is undone.


def person_hex(pk_name):
    return R.person_id(S, R.unb64u(SIG["keys"][pk_name]["pub_b64u"])).hex()


def device_hex(dk_name):
    return R.device_id(S, R.unb64u(SIG["keys"][dk_name]["pub_b64u"])).hex()


def reissue_cert(cert, pk_name="pk_sev", dk=None, **fields):
    from copy import deepcopy

    o = deepcopy(cert["o"])
    if dk:
        o.update(dk_sig_pub=SIG["keys"][dk]["pub_b64u"], device_id=device_hex(dk))
    o.update(fields)
    return R.sign_object(S, published_f1_key(pk_name), o)


def reissue_delegation(pk_name="pk_sev", **fields):
    from copy import deepcopy

    o = deepcopy(CARD_DELEGATION["o"])
    o.update(fields)
    return R.sign_object(S, published_f1_key(pk_name), o)


def utc(at, seconds=0):
    from datetime import timedelta

    return (datetime.fromisoformat(at) + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def accepted(c):
    return ("ok", c["restore"]["event"]["id"])


def test_local_signing_reproduces_the_shared_vectors():
    """RFC 6979: re-signing an unchanged object reproduces the shared bytes, so the helpers sign what the
    vectors sign."""
    c = local_transition()
    original = local_transition()
    resign_transition(c)
    assert c == original
    assert (
        sign_checkpoint(CP["workspace_checkpoint"]["signed"]["o"])
        == CP["workspace_checkpoint"]["signed"]
    )
    assert reissue_delegation() == CARD_DELEGATION
    assert offer_local_transition(c) == accepted(c)


def foreign_owner_bundle():
    """Review PoC 1: lena self-issues a delegation over the public workspace_id/wsk_pub, certifies her own
    device and signs the restore; a WSK holder adds host_sig and T."""
    c = local_transition()
    r = c["restore"]
    lena = person_hex("pk_lena")
    r["delegation"] = reissue_delegation("pk_lena", owner_person_id=lena)
    r["device_cert"] = reissue_cert(r["device_cert"], "pk_lena", dk="dk_lena1", person_id=lena)
    r["pk_pub"] = SIG["keys"]["pk_lena"]["pub_b64u"]
    r["event"]["actor"] = {
        "kind": "person",
        "id": "p_" + lena,
        "device": "d_" + device_hex("dk_lena1"),
    }
    resign_transition(c, person="dk_lena1")
    return c


def test_restore_delegation_of_another_person():
    c = foreign_owner_bundle()
    r = c["restore"]
    pk = R.unb64u(r["pk_pub"])
    assert "ok" in R.verify_delegation(S, r["delegation"], pk)
    assert "ok" in R.verify_cert(S, r["device_cert"], pk, milliseconds(r["event"]["at"]))
    assert offer_local_transition(c) == ("chain.diverged", None)
    # Only the card binding refuses it: a receiver whose card names lena accepts the same bundle.
    assert offer_local_transition(c, card=r["delegation"]) == accepted(c)


def test_restore_delegation_must_carry_the_card_content():
    c = local_transition()
    # Same owner, workspace and WSK, validly PK-signed, but other content than the card's delegation.
    other = reissue_delegation(issued_ms=CARD_DELEGATION["o"]["issued_ms"] + 1)
    assert "ok" in R.verify_delegation(S, other, R.unb64u(c["restore"]["pk_pub"]))
    c["restore"]["delegation"] = other
    resign_transition(c)
    assert offer_local_transition(c) == ("chain.diverged", None)
    assert offer_local_transition(c, card=other) == accepted(c)


def randomized_signature(pk_name, signed):
    """A fresh (non-RFC 6979) P-256 signature over the same object, as a real owner device would make."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    kind = signed["o"]["kind"]
    msg = R.LABELS[R.KIND_LABEL[kind]].encode() + R.cj(signed["o"])
    r, s_ = decode_dss_signature(published_f1_key(pk_name).sign(msg, ec.ECDSA(hashes.SHA256())))
    return {"o": signed["o"], "sig": R.b64u(r.to_bytes(32, "big") + s_.to_bytes(32, "big"))}


def test_restore_delegation_owner_resignature_is_the_same_delegation():
    """§19.8 R0: `o` equal to the card's and verified under the owner PK; the signature bytes may differ."""
    c = local_transition()
    resigned = randomized_signature("pk_sev", CARD_DELEGATION)
    assert resigned["sig"] != CARD_DELEGATION["sig"]
    assert "ok" in R.verify_delegation(S, resigned, R.unb64u(c["restore"]["pk_pub"]))
    c["restore"]["delegation"] = resigned
    resign_transition(c)
    assert offer_local_transition(c) == accepted(c)
    # The card's content signed by another key is refused (verify under the owner PK).
    c["restore"]["delegation"] = randomized_signature("pk_lena", CARD_DELEGATION)
    resign_transition(c)
    assert offer_local_transition(c) == ("chain.diverged", None)


def owner_policy_defect(c, defect):
    """Apply one P3-D24 defect; return the card the receiver holds."""
    r = c["restore"]
    e, cert = r["event"], r["device_cert"]
    card = CARD_DELEGATION
    person, host = "dk_sev1", "wsk"
    if defect == "person_sig_by_another_key":
        person = "dk_sev2"
    elif defect == "host_sig_by_another_key":
        host = "wsk_other"
    elif defect == "bundle_key_is_not_the_card_owner":
        # The card's delegation, but pk_pub and the certificate belong to lena.
        r["pk_pub"] = SIG["keys"]["pk_lena"]["pub_b64u"]
        r["device_cert"] = reissue_cert(cert, "pk_lena", person_id=person_hex("pk_lena"))
    elif defect in ("card_for_another_workspace", "card_for_another_wsk"):
        field, value = (
            ("workspace_id", "f" * 32)
            if defect == "card_for_another_workspace"
            else ("wsk_pub", SIG["keys"]["wsk_other"]["pub_b64u"])
        )
        card = r["delegation"] = reissue_delegation(**{field: value})
    elif defect == "cert_not_signed_by_the_pk":
        r["device_cert"] = R.sign_object(S, published_f1_key("pk_mara"), cert["o"])
    elif defect == "actor_id_is_not_the_owner":
        e["actor"]["id"] = "p_" + person_hex("pk_lena")
    elif defect == "actor_device_is_not_the_cert":
        e["actor"]["device"] = "d_" + device_hex("dk_sev2")
    elif defect == "cert_without_operate":
        r["device_cert"] = reissue_cert(cert, scopes_max=["look", "decide"])
    elif defect == "cert_with_drop_scope":
        r["device_cert"] = reissue_cert(
            cert, scopes_max=["drop:" + "ab" * 16], expires_ms=milliseconds(e["at"]) + 86_400_000
        )
    elif defect == "cert_expired_at_line_at":
        r["device_cert"] = reissue_cert(cert, expires_ms=milliseconds(e["at"]))
    else:
        raise AssertionError(defect)
    resign_transition(c, person=person, host=host)
    return card


OWNER_POLICY_DEFECTS = [
    "person_sig_by_another_key",
    "host_sig_by_another_key",
    "bundle_key_is_not_the_card_owner",
    "card_for_another_workspace",
    "card_for_another_wsk",
    "cert_not_signed_by_the_pk",
    "actor_id_is_not_the_owner",
    "actor_device_is_not_the_cert",
    "cert_without_operate",
    "cert_with_drop_scope",
    "cert_expired_at_line_at",
]


@pytest.mark.parametrize("defect", OWNER_POLICY_DEFECTS)
def test_restore_owner_device_policy_single_defect(defect):
    """P3-D24 / R1: each signature and policy check refuses on its own (review finding 2)."""
    c = local_transition()
    assert offer_local_transition(c) == accepted(c)
    card = owner_policy_defect(c, defect)
    assert offer_local_transition(c, card=card) == ("chain.diverged", None)


def test_restore_cert_unexpired_at_line_at_is_accepted():
    c = local_transition()
    r = c["restore"]
    r["device_cert"] = reissue_cert(
        r["device_cert"], expires_ms=milliseconds(r["event"]["at"]) + 1000
    )
    resign_transition(c)
    assert offer_local_transition(c) == accepted(c)


@pytest.mark.parametrize(
    "change",
    [{"hash": "sha256:" + "11" * 32}, {"n": 2}, {"n": 4}],
    ids=["hash", "n_lower", "n_higher"],
)
def test_restore_signed_source_must_name_the_held_checkpoint(change):
    """Review finding 3: C == held and C is valid, but the owner-signed source names another checkpoint."""
    c = local_transition()
    assert c["restore"]["C"] == c["held"] and workspace_checkpoint_ok(c["held"])
    c["restore"]["event"]["source"].update(change)
    resign_transition(c)
    assert offer_local_transition(c) == ("chain.diverged", None)


@pytest.mark.parametrize("field", ["seq", "prev"])
def test_restore_line_must_chain_onto_the_retained_head(field):
    """F1 §5.10: line.seq = from_seq + 1 and line.prev = head (review finding 4)."""
    c = local_transition()
    e = c["restore"]["event"]
    if field == "seq":
        e["seq"] = e["from_seq"] + 2
    else:
        e["prev"] = e["abandoned"]["head"]
    resign_transition(c)
    assert offer_local_transition(c) == ("chain.diverged", None)


@pytest.mark.parametrize(
    "abandoned,ok",
    [
        (None, False),
        ({"seq": 2, "head": "sha256:" + "33" * 32}, False),
        ({"seq": 3, "head": "sha256:" + "33" * 32}, False),
        ({"seq": 4, "head": "sha256:" + "33" * 32}, True),
    ],
    ids=["null", "below_C", "equal_height_other_head", "above_C"],
)
def test_restore_abandoned_names_at_least_the_held_entry(abandoned, ok):
    """F1 §5.10: `abandoned` names the highest known entry above from_seq, C's included (review finding 5)."""
    c = local_transition()
    e = c["restore"]["event"]
    assert e["from_seq"] < c["held"]["o"]["workspace_log"]["seq"] == 3
    e["abandoned"] = abandoned
    resign_transition(c)
    assert offer_local_transition(c) == (accepted(c) if ok else ("chain.diverged", None))


def test_target_must_commit_to_the_restore_head():
    """Review finding 6: a WSK-signed T whose restored entry folds a different head X with a consistent proof."""
    c = local_transition()
    resign_transition(c)
    r = c["restore"]
    x = "sha256:" + "22" * 32
    entry = c["offered"]["o"]["workspace_log"]
    assert entry["seq"] == r["event"]["from_seq"] + 1
    entry.update(head=x, acc=log_acc(r["acc_from"], x))
    c["offered"] = r["T"] = sign_checkpoint(c["offered"]["o"])
    c["proofs"]["workspace"] = [x]
    assert workspace_checkpoint_ok(c["offered"])
    assert growth_ok({"seq": r["event"]["from_seq"], "acc": r["acc_from"]}, entry, [x])
    assert offer_local_transition(c) == ("sync.incomplete", None)


@pytest.mark.parametrize(
    "field,value",
    [
        ("genesis", "sha256:" + "0" * 64),
        ("workspace_id", "f" * 32),
        ("n", 0),
        ("n", True),
        ("n", "1"),
        ("at", "2026-99-99T99:99:99Z"),
        ("at", "2026-02-30T10:00:00Z"),
        ("at", "2026-10-1T10:00:00Z"),
        ("at", "2026-10-10T10:00:00+00:00"),
        ("kind", "ticket_checkpoint"),
        ("v", 3),
        ("suite", 1),
        ("extra", 1),
        ("tickets", None),
        ("kind", "other_checkpoint"),
        ("workspace_log", {"seq": True, "head": ZERO_ACC, "acc": ZERO_ACC}),
        ("workspace_log", {"seq": 0, "head": ZERO_ACC, "acc": ZERO_ACC}),
        ("workspace_log", {"seq": 1, "head": "bad", "acc": ZERO_ACC}),
        ("workspace_log", {"seq": 1, "head": ZERO_ACC, "acc": ZERO_ACC, "x": 1}),
    ],
)
def test_wsk_signed_checkpoint_trust_root(field, value):
    """Review finding 7: a validly WSK-signed checkpoint with another genesis, workspace, n or an impossible at
    (and the schema fields), so that only the named check can refuse it."""
    from copy import deepcopy

    o = deepcopy(CP["workspace_checkpoint"]["signed"]["o"])
    o[field] = value
    if value is None:
        del o[field]
    signed = sign_checkpoint(o)
    assert signature_ok(CP["wsk_pub"], signed["sig"], L["sig_checkpoint"].encode() + cjt(o))
    assert not checkpoint_ok(signed)
    assert checkpoint_offer(None, signed, now=VECTOR_CLOCK) == ("chain.diverged", None)


def test_checkpoint_signed_object_has_exactly_o_and_sig():
    signed = dict(CP["workspace_checkpoint"]["signed"], note="x")
    assert not checkpoint_ok(signed)
    assert checkpoint_offer(None, signed, now=VECTOR_CLOCK) == ("chain.diverged", None)


def test_valid_ticket_checkpoint_is_not_a_workspace_offer():
    """Review finding 11: refused, not a KeyError."""
    ticket = CP["ticket_checkpoint"]["signed"]
    assert checkpoint_ok(ticket)
    assert checkpoint_offer(None, ticket, now=VECTOR_CLOCK) == ("chain.diverged", None)
    assert checkpoint_offer(CP["workspace_n_held"], ticket, now=VECTOR_CLOCK) == (
        "chain.diverged",
        None,
    )
    c = local_transition()
    c["restore"]["C"] = ticket
    assert offer_local_transition(c) == ("chain.diverged", None)


@pytest.mark.parametrize("ahead,ok", [(299, True), (300, True), (301, False)])
def test_receiver_future_ceiling(ahead, ok):
    """P3-D25 / R3a: o.at <= relay clock + 300 s for every published checkpoint, T included (finding 8)."""
    refused = ("checkpoint_time", None)
    first = CP["workspace_checkpoint"]["signed"]
    now = utc(first["o"]["at"], -ahead)
    assert checkpoint_offer(None, first, now=now) == (("ok", None) if ok else refused)
    growth = next(c for c in CP["workspace_n_offers"] if c["name"] == "verified_accumulator_growth")
    held, offered = CP["workspace_n_held"], growth["checkpoint"]
    now = utc(offered["o"]["at"], -ahead)
    result = checkpoint_offer(held, offered, proofs=growth["proofs"], now=now)
    assert result == (("ok", None) if ok else refused)
    c = local_transition()
    now = utc(c["offered"]["o"]["at"], -ahead)
    assert offer_local_transition(c, now=now) == (accepted(c) if ok else refused)


def test_far_future_checkpoint_cannot_freeze_the_receiver():
    from copy import deepcopy

    o = deepcopy(CP["workspace_checkpoint"]["signed"]["o"])
    o["at"] = "2100-01-01T00:00:00Z"
    assert checkpoint_offer(None, sign_checkpoint(o), now=VECTOR_CLOCK) == ("checkpoint_time", None)
    c = local_transition()
    c["offered"]["o"]["at"] = "2100-01-01T00:00:00Z"
    resign_transition(c)
    assert offer_local_transition(c) == ("checkpoint_time", None)
    # An identical retry of the held checkpoint is not a new publication.
    held = CP["workspace_n_held"]
    assert checkpoint_offer(held, held, now=utc(held["o"]["at"], -3600)) == ("ok", None)


def completeness_case(pk_name, reason="lost"):
    """The relay holds lena's `lost` for dk_lena1; the bundle carries evidence for that device signed by pk_name."""
    c = local_transition("relay_requires_every_held_revocation")
    known = c["known_revocations"]
    assert known[0]["revocation"]["o"]["device_id"] == device_hex("dk_lena1")
    assert known[0]["revocation"]["o"]["person_id"] == person_hex("pk_lena")
    cert = reissue_cert(
        c["restore"]["device_cert"], pk_name, dk="dk_lena1", person_id=person_hex(pk_name)
    )
    evidence = local_revocation_evidence(cert, pk_name=pk_name, reason=reason)
    assert revocation_evidence_ok(evidence)
    c["restore"]["event"]["revocations"] = [evidence]
    resign_transition(c)
    return c, known


def test_completeness_accepts_the_known_persons_evidence():
    c, known = completeness_case("pk_lena")
    assert offer_local_transition(c, known=known) == accepted(c)


def test_completeness_refuses_evidence_from_another_person():
    """Review finding 9 / PoC 2: mara-signed `compromised` evidence for lena's known device."""
    c, known = completeness_case("pk_mara", reason="compromised")
    assert offer_local_transition(c, known=known) == ("chain.diverged", None)


def test_completeness_refuses_evidence_under_another_stored_key():
    from copy import deepcopy

    c, known = completeness_case("pk_lena")
    known = deepcopy(known)
    known[0]["pk_pub"] = SIG["keys"]["pk_lena"]["pub_b64u"]
    assert offer_local_transition(c, known=known) == accepted(c)
    # A receiver whose stored key for the device's person differs refuses (person ids alone agree here).
    known[0]["pk_pub"] = SIG["keys"]["pk_mara"]["pub_b64u"]
    assert offer_local_transition(c, known=known) == ("chain.diverged", None)


def ticket_transition(ws_seq):
    """A signed ticket-log restore over the shared held checkpoint: a new ticket log, forward proof from acc_0."""
    from copy import deepcopy

    c = local_transition()
    r, held = c["restore"], c["held"]
    uid = CP["ticket_checkpoint"]["signed"]["o"]["uid"]
    first = CP["ticket_log"]["heads"][0]
    assert uid not in held["o"]["tickets"]
    r["log"] = uid
    r["event"].update(
        seq=2,
        from_seq=1,
        head=first,
        prev=first,
        based_on=first,
        ws_seq=ws_seq,
        abandoned=None,
        abandoned_decisions=[],
        revocations=[],
    )
    r["acc_from"] = log_acc(ZERO_ACC, first)
    r["forward_heads"] = [first]
    target = c["offered"]["o"]
    target["workspace_log"] = deepcopy(held["o"]["workspace_log"])
    target["tickets"] = {uid: {"seq": 2, "head": first, "acc": first}}
    c["proofs"] = {}
    resign_transition(c)
    return c


@pytest.mark.parametrize("ws_seq,ok", [(1, True), (3, True), (4, False)])
def test_ticket_restore_ws_seq_is_committed_by_the_target(ws_seq, ok):
    """Relay design R3: a ticket restore has ws_seq <= T.workspace_log.seq (review finding 10)."""
    c = ticket_transition(ws_seq)
    assert c["offered"]["o"]["workspace_log"]["seq"] == 3
    assert offer_local_transition(c) == (accepted(c) if ok else ("chain.diverged", None))


@pytest.mark.parametrize("reason", ["compromised", "lost", "retired"])
def test_ticket_restore_signer_known_revoked(reason):
    """§19.8 R1: the signer must be unrevoked by every held revocation, on the ticket path too (round 2, 1)."""
    c = ticket_transition(3)
    assert offer_local_transition(c) == accepted(c)
    known = [local_revocation_evidence(c["restore"]["device_cert"], reason=reason)]
    assert revocation_evidence_ok(known[0])
    assert offer_local_transition(c, known=known) == ("chain.diverged", None)


def test_ticket_restore_is_not_checked_for_revocation_completeness():
    """F1 §5.10 / R4: a ticket restore carries []; held revocations do not refuse it."""
    known = local_transition("relay_requires_every_held_revocation")["known_revocations"]
    c = ticket_transition(3)
    assert offer_local_transition(c, known=known) == accepted(c)


@by_name([c for c in TAMPER["cases"] if "field_set" in c["name"] and c["chain_broken_at"]])
def test_field_set_tamper_refused_at_append(c):
    """§5.11 step 0: the shared host/agent field-set tamper events are refused by the append path too."""
    workspace = TAMPER["workspace_events"]
    broken = c["chain_broken_at"]
    state = F1State(TAMPER["workspace_id"])
    state.wsk = workspace[0]["wsk_pub"]
    state.logs = {"workspace": workspace, c["log"]: c["events"][: broken - 1]}
    assert state.judge(c["events"][broken - 1], c["log"]) == "validation.field_set"
    assert state.judge(c["events"][broken - 1], c["log"], replay=True) == "chain.broken"


@pytest.mark.parametrize("field", ["sig", "auth", "roster_v"])
def test_host_event_with_person_fields_refused_at_append(field):
    state = F1State("ws")
    e = {"type": "device.revoked", "actor": {"kind": "host"}, "seq": 99, "prev": None, field: "x"}
    assert state.judge(e, "workspace") == "validation.field_set"


def test_restore_revocation_entry_has_exactly_three_fields():
    c = local_transition()
    cert = reissue_cert(c["restore"]["device_cert"], dk="dk_sev2")
    evidence = local_revocation_evidence(cert)
    c["restore"]["event"]["revocations"] = [evidence]
    resign_transition(c)
    assert offer_local_transition(c) == accepted(c)
    evidence["note"] = "x"
    resign_transition(c)
    assert revocation_evidence_ok(evidence)
    assert not restore_schema_ok(c["restore"]["event"], "workspace")
    assert offer_local_transition(c) == ("chain.diverged", None)


@pytest.mark.parametrize("defect", ["seq_skips_a_head", "head_is_not_the_last_proof_head"])
def test_wsk_signed_growth_entry_must_match_its_proof(defect):
    """§5.10 growth: exactly t - s heads, the last the offered head. A WSK-signed entry whose acc folds the proof
    but whose seq or head disagrees with it is incomplete."""
    from copy import deepcopy

    growth = next(c for c in CP["workspace_n_offers"] if c["name"] == "verified_accumulator_growth")
    held, o, proofs = CP["workspace_n_held"], deepcopy(growth["checkpoint"]["o"]), growth["proofs"]
    ((uid, heads),) = proofs.items()
    entry = o["tickets"][uid]
    assert entry["acc"] == fold(held["o"]["tickets"][uid]["acc"], heads)
    if defect == "seq_skips_a_head":
        entry["seq"] += 1
    else:
        entry["head"] = "sha256:" + "77" * 32
    offered = sign_checkpoint(o)
    assert workspace_checkpoint_ok(offered)
    assert checkpoint_offer(held, offered, proofs=proofs, now=VECTOR_CLOCK) == (
        "sync.incomplete",
        None,
    )


@pytest.mark.parametrize(
    "case", ["source_precedes_retained_prefix", "null_source_with_pinned_genesis"]
)
def test_forward_proof_must_derive_acc_from(case):
    """§5.10: when from_seq >= C.seq, acc_from comes from a forward proof from C (or acc_0). A T re-signed over
    another acc_from is incomplete."""
    c = local_transition(case)
    assert offer_local_transition(c) == accepted(c)
    c["restore"]["acc_from"] = "sha256:" + "44" * 32
    resign_transition(c)
    assert offer_local_transition(c) == ("sync.incomplete", None)


def test_restore_seq_true_is_not_seq_one():
    """`seq: true` equals 1 in Python; with the seq-1 nulls it must still fail the integer rule."""
    e = local_transition()["restore"]["event"]
    e.update(seq=True, based_on=None, prev=None)
    assert not restore_schema_ok(e, "workspace")
    e["seq"] = 1
    assert restore_schema_ok(e, "workspace")


@pytest.mark.parametrize("note", [[], {}, 5])
def test_restore_note_must_be_a_string(note):
    """A non-string note is refused, not an uncaught AttributeError from `note.encode()`."""
    e = local_transition()["restore"]["event"]
    e["note"] = note
    assert restore_schema_ok(e, "workspace") is False
