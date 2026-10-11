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
import re
import subprocess
import sys
import unicodedata
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

L = R.LABELS


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
    """Every F1 label is a protocol label (protocol §3); `question` is the protocol's `h_question`."""
    registry = set(R.LABELS.values())
    for name, label in F1_LABELS.items():
        assert label in registry, name
    assert R.LABELS["h_question"] == F1_LABELS["question"]


def test_f1_labels_are_prefix_free_with_every_protocol_label():
    """Signed and hashed inputs are label || bytes: no label may be a prefix of another (protocol §3). The
    protocol's own check covers sig_/aad_/h_/mac_; this one covers all of them against all of F1's."""
    f1 = list(F1_LABELS.values())
    everything = [v for v in R.LABELS.values() if v.endswith("|")]
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
    assert "Commit: 8ae6354e13f5e53b338798f25282cb4453161177" in (F1 / "SOURCE").read_text()
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
    "restore": ["pins", "scenarios"],
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


def branch_ok(branch):
    """F1 §3: git branch names, with the additional reserved names and Unicode exclusions."""
    return (
        isinstance(branch, str)
        and bool(branch)
        and not branch.startswith(("-", "refs/"))
        and branch not in {"HEAD", "@"}
        and not branch.endswith(".")
        and not any(x in branch for x in ("..", "@{"))
        and not any(c in " ~^:?*[\\" or unicodedata.category(c) in {"Cc", "Cf"} for c in branch)
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
def chain_break(events, log, ws, wsk, certs, ws_height):
    certs = dict(certs)
    prev, order = None, (0, "")
    for pos, e in enumerate(events, 1):
        if e["type"] == "settings.changed" and not settings_schema_ok(e.get("set")):
            return pos
        if e["seq"] != pos or e["prev"] != prev or not host_ok_event(e, wsk, ws, log):
            return pos
        # §5.2: sig, auth and roster_v belong to person events only; a host event carrying one breaks the chain.
        if e["actor"]["kind"] != "person" and any(k in e for k in ("sig", "auth", "roster_v")):
            return pos
        if log != "workspace":
            current = (e["ws_seq"], e["at"])
            if current < order or e["ws_seq"] > ws_height:
                return pos
            order = current
        if e["actor"]["kind"] == "person":
            cert = certs.get(e["actor"]["device"])
            if e["type"] == "workspace.created":
                cert = e["device_cert"]
            if e["type"] == "device.added" and e["actor"]["device"] == e["device"]:
                cert = e["cert"]
            if not person_ok(e, cert, ws, log):
                return pos
        if "device_cert" in e:
            certs["d_" + e["device_cert"]["o"]["device_id"]] = e["device_cert"]
        if e["type"] == "device.added":
            certs[e["device"]] = e["cert"]
        prev = head(e)
    return None


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


def checkpoint_ok(signed):
    o = signed["o"]
    common = {"v", "suite", "kind", "workspace_id", "at"}
    fields = (
        {"uid", "seq", "head"}
        if o["kind"] == "ticket_checkpoint"
        else {"genesis", "n", "workspace_log", "tickets"}
    )
    return (
        set(signed) == {"o", "sig"}
        and set(o) == common | fields
        and o["v"] == 2
        and o["suite"] == 2
        and o["workspace_id"] == CP["workspace_id"]
        and (o["kind"] != "workspace_checkpoint" or o["genesis"] == CP["genesis"])
        and signature_ok(CP["wsk_pub"], signed["sig"], L["sig_checkpoint"].encode() + cjt(o))
    )


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
        offered["seq"] == held["seq"] and offered["head"] != held["head"]
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


def checkpoint_offer(held, offered, restore=None, applied=()):
    """Height-only receiver; restore metadata is supplied after owner verification (§5.10)."""
    if held is None:
        return ("ok", None) if checkpoint_ok(offered) else ("chain.diverged", None)
    h, o = held["o"], offered["o"]
    if not checkpoint_ok(offered):
        return "chain.diverged", None
    if held == offered:
        return "ok", None
    old = {"workspace": h["workspace_log"], **h["tickets"]}
    new = {"workspace": o["workspace_log"], **o["tickets"]}
    # §5.10: a missing held uid is divergence only in an offer with a higher n; an older checkpoint
    # naturally lacks tickets created after it (stale delivery comes first).
    if o["n"] > h["n"] and not old.keys() <= new.keys():
        return "chain.diverged", None
    # A uid H lacks counts as seq 0 there, so a lower-n offer naming one has a higher seq: divergence.
    if o["n"] < h["n"] and new.keys() - old.keys():
        return "chain.diverged", None
    shared = old.keys() & new.keys()
    conflicts = {log for log in shared if height_conflict(old[log], new[log])}
    if restore and o["n"] > h["n"] and restore["log"] in conflicts:
        log = restore["log"]
        abandoned, prior = restore["abandoned"], old[log]
        valid = (
            restore["id"] not in applied
            and conflicts == {log}
            and restore["from_seq"] < prior["seq"] <= abandoned["seq"]
            and (prior["seq"] != abandoned["seq"] or prior["head"] == abandoned["head"])
            and new[log]["seq"] >= restore["from_seq"] + 1
        )
        return ("ok", restore["id"]) if valid else ("chain.diverged", None)
    same_height_fork = any(
        new[k]["seq"] == old[k]["seq"] and new[k]["head"] != old[k]["head"] for k in shared
    )
    if same_height_fork:
        return "chain.diverged", None
    if o["n"] > h["n"] and not conflicts:
        return "ok", None
    if o["n"] < h["n"] and all(new[k]["seq"] <= old[k]["seq"] for k in shared):
        return "ignored", None
    return ("ok", None) if o == h else ("chain.diverged", None)


@by_name(CP["workspace_n_offers"])
def test_workspace_checkpoint_receiver(c):
    result, recorded = checkpoint_offer(
        CP["workspace_n_held"], c["checkpoint"], c.get("restore"), c.get("applied", ())
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
        self.restore_start = None
        self.restore_end = None
        self.restore_open = False
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
        if t == "settings.changed" and not settings_schema_ok(e.get("set")):
            return "chain.broken" if replay else "validation.event"
        if (
            t == "ticket.updated"
            and "ticket.links" in e.get("set", {})
            and not links_branches_ok(e["set"]["ticket.links"])
        ):
            return "chain.broken" if replay else "validation.event"
        # §5.11 steps 1–4, in order. At append, person signature is step 5.
        if e["seq"] != len(lines) + 1 or e["prev"] != (head(lines[-1]) if lines else None):
            return "chain.broken"
        wsk = self.wsk if self.wsk is not None else e.get("wsk_pub")
        if not host_ok_event(e, wsk, self.ws, log):
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
                or (
                    self.restore_start is not None
                    and self.restore_start <= e["ws_seq"] < self.restore_end
                )
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
            "ticket.created",
            "log.added",
            "question.asked",
            "question.answered",
            "restore",
        }
        if t not in (workspace_types if log == "workspace" else ticket_types):
            return "event.unknown_type"
        if a["kind"] != "person" and not (
            t == "device.revoked"
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
            cert = self.certs.get(a["device"])
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
                if remote.lower() in identities:
                    return "settings.invalid"
                identities.add(remote.lower())
        if t == "member.added":
            if role != "owner" and not (role == "maintainer" and e["role"] in {"member", "viewer"}):
                return "role.denied"
            if R.person_id(S, R.unb64u(e["pk_pub"])).hex() != e["person"][
                2:
            ] or "ok" not in R.verify_cert(
                S, e["device_cert"], R.unb64u(e["pk_pub"]), milliseconds(e["at"])
            ):
                return "device.cert"
        if t == "device.added":
            if e["device"] in self.revoked:
                return "device.invalid"
            if e["device"] in self.certs and e["device"] not in self.removed:
                return "device.exists"
            return self.added_cert_result(e)
        if t == "device.revoked":
            cert = self.certs.get(e["device"])
            if cert is None:
                return "device.unknown"
            pk = self.members["p_" + cert["o"]["person_id"]]["pk_pub"]
            result = R.verify_revocation(S, e["revocation"], R.unb64u(pk), cert["o"])
            if "ok" not in result or e["reason"] != e["revocation"]["o"]["reason"]:
                return "device.cert"
        if t == "device.removed":
            cert = self.certs.get(e["device"])
            if cert is None:
                return "device.unknown"
            if role != "owner" and a["id"] != "p_" + cert["o"]["person_id"]:
                return "role.denied"
        if t == "restore" and (e["from_seq"] != len(lines) or e["head"] != head(lines[-1])):
            return "restore.bad_head"
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

    def added_cert_result(self, e):
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
        if t == "device.added":
            self.certs[e["device"]] = e["cert"]
            self.removed.discard(e["device"])
        if t == "device.removed":
            self.removed.add(e["device"])
        if t == "device.revoked":
            self.revoked.add(e["device"])
            self.revocations.append(e["revocation"])
            if log == "workspace" and self.restore_open and e["actor"]["kind"] == "host":
                self.restore_end = e["seq"]
        if t == "grant.issued":
            self.grants[e["grant"]] = e
        if t == "ticket.created":
            self.owners[log] = e["owner"]
        if t == "question.asked":
            self.questions[log, e["question"]["id"]] = e
        if t == "question.answered":
            self.answers[log, e["question"]] = e["id"]
        # The re-append window after a workspace restore holds only host device.revoked lines; any
        # other workspace event closes it, so a much later host revocation can't widen it.
        if (
            log == "workspace"
            and t != "restore"
            and not (t == "device.revoked" and e["actor"]["kind"] == "host")
        ):
            self.restore_open = False
        if t == "restore":
            self.seen[log].update(e["abandoned_decisions"])
            if log == "workspace":
                self.restore_start = self.restore_end = e["seq"]
                self.restore_open = True
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
    before = deepcopy(state.__dict__) if step.get("schema_refused") else None
    result = state.append(e, log, replay=replay)
    assert result == step["expect"], (index, step.get("note"))
    if step.get("schema_refused"):
        assert result != "ok"
        assert state.__dict__ == before


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
    assert checkpoint_offer(None, first) == ("ok", None)
    changed = deepcopy(first)
    changed["o"]["genesis"] = "sha256:" + "0" * 64
    assert checkpoint_offer(None, changed) == ("chain.diverged", None)
    changed = deepcopy(first)
    changed["sig"] = R.b64u(bytes(64))
    assert checkpoint_offer(None, changed) == ("chain.diverged", None)


def test_checkpoint_lower_n_extra_uid_diverges(monkeypatch):
    """§5.10: a lower-n offer naming a ticket H lacks has a higher seq for it (H's is 0): divergence.

    No shared vector yet (asked the core for `lower_n_extra_uid`); signatures are out of scope here.
    """
    monkeypatch.setattr(sys.modules[__name__], "checkpoint_ok", lambda signed: True)
    log = {"seq": 3, "head": "sha256:" + "a" * 64}
    held = {"o": {"n": 5, "workspace_log": log, "tickets": {}}}
    offered = {
        "o": {
            "n": 4,
            "workspace_log": log,
            "tickets": {"01EXTRA": {"seq": 1, "head": "sha256:" + "b" * 64}},
        }
    }
    assert checkpoint_offer(held, offered) == ("chain.diverged", None)


def test_restore_window_replayed_workspace_first():
    """§5.10: the re-append window closes at the first other workspace event.

    The shared scenario appends ticket steps before the late host revocation, so a window that never
    closed would not be noticed there. Replaying the whole workspace log first, then the ticket steps,
    must still accept every ticket step.
    """
    c = next(
        s
        for s in load("restore")["scenarios"]
        if s["name"] == "restore_window_ends_before_a_later_host_revocation"
    )
    state = F1State(c["workspace_id"])
    ordered = [s for s in c["steps"] if s["log"] == "workspace"] + [
        s for s in c["steps"] if s["log"] != "workspace"
    ]
    for i, step in enumerate(ordered):
        check_scenario_step(state, step, i, replay=True)


def test_agent_event_with_person_fields_refused_at_append():
    """§5.11 step 0 / §5.2: an agent or host event carrying sig, auth or roster_v is refused before any other check."""
    state = F1State("ws")
    e = {"type": "log.added", "actor": {"kind": "agent"}, "seq": 99, "prev": None, "sig": "x"}
    assert state.judge(e, "01TICKET") == "validation.field_set"
