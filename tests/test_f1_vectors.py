"""Relay-side check of the ticket-format F1 vectors in tests/vectors/f1/ (byte-identical copies of orch-core's
plugins/orch-core/tests/vectors/f1/*.json, see tests/vectors/f1/SOURCE).

Nothing here imports orch-core. Every expected value is recomputed from the F1 text (orch-core
docs/architecture/orch-v2-ticket-format.md: section numbers are quoted in the tests) using the relay reference
(`ref.orch_protocol_ref`: cj, strict parse, labels) and the helpers below.

Not verifiable from the F1 text alone, or not in the shared files at all, is listed in the PR description.
"""

import hashlib
import json
import os
import re
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
    assert set(G["sections"]) <= G_SECTIONS[g]
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


@pytest.mark.skip(
    reason="the shared repo_identity.json holds only canonical-form acceptance and refusal; the raw "
    "remote mapping cases of F1 §11.5 (ssh with/without port, scp-like, userinfo removal, "
    "file:// to local:) have no vectors yet, so the mapping has nothing to verify against"
)
def test_repo_identity_mapping_from_raw_remote_urls():
    raise AssertionError


# --- byte identity, the reference's own question hash, deep input -----------------------------------------------


def test_vector_files_match_the_recorded_sha256():
    """SOURCE records the orch-core commit and the sha256 of each copy: a hand edit of a copied file fails."""
    rec = dict(
        line.split()[::-1]
        for line in (F1 / "SOURCE").read_text().splitlines()
        if line.startswith("sha256:")
    )
    files = sorted(p.name for p in F1.glob("*.json"))
    assert files == sorted(rec) and len(files) == 7
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
