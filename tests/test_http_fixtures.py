"""Portable HTTP transcripts: route/refusal coverage, exact shapes, signatures and ORB2 framing."""

import json
import re
from pathlib import Path

import pytest

from ref import orch_protocol_ref as R
from ref._http_fixtures import BODY_CAPS, ROUTES, build, refusals

ROOT = Path(__file__).resolve().parents[1]
DOC = (ROOT / "docs/protocol-v2.md").read_text()
FILES = sorted(
    p for p in (ROOT / "tests/http_fixtures").glob("*.json") if p.name != "MANIFEST.json"
)
CORPUS = json.loads(R.VECTORS.read_text())["suites"]
V = CORPUS["2"]
S = R.SUITES[2]


def test_all_contract_routes_have_fixtures():
    table = DOC.split("## 19. Relay HTTP API", 1)[1]
    routes = set(re.findall(r"`(GET|POST|PUT|DELETE) (/v2/[^`?\[]+)", table))
    actual = {
        (f["route"]["method"], f["route"]["path"])
        for f in (json.loads(p.read_text()) for p in FILES)
    }
    assert actual == routes
    # Both authenticated directions of these POST routes need independent examples.
    for suffix in ("bridge/{rid}", "pair/{offer}/{rid}"):
        roles = {r[3] for r in ROUTES if r[1] == "POST" and r[2].endswith(suffix)}
        assert roles == {"host", "device"}


def test_fixtures_are_reproducible():
    expected = build()
    assert {p.stem for p in FILES} == set(expected)
    for path in FILES:
        assert json.loads(path.read_text()) == expected[path.stem]


def test_explicit_route_refusals_are_covered():
    """Independent doc extraction prevents a forgotten route-table error in the generator."""
    fixtures = [json.loads(p.read_text()) for p in FILES]
    for line in DOC.split("## 19. Relay HTTP API", 1)[1].splitlines():
        match = re.match(r"\| `(GET|POST|PUT|DELETE) (/v2/[^`?\[]+)", line)
        if not match:
            continue
        matching = [
            f for f in fixtures if (f["route"]["method"], f["route"]["path"]) == match.groups()
        ]
        # Escaped pipes occur in the hold request shape, so isolate the refusal cell from the right.
        cell = line.rsplit("|", 3)[1]
        explicit = set(re.findall(r"`([a-z_]+)`", cell)) - {"epoch"}
        actual = {c["response"]["json"].get("error") for f in matching for c in f["cases"]}
        assert explicit <= actual, (match.groups(), explicit - actual)


def signed_objects(value):
    if isinstance(value, dict):
        if "o" in value and "sig" in value:
            yield value
        for child in value.values():
            yield from signed_objects(child)
    elif isinstance(value, list):
        for child in value:
            yield from signed_objects(child)


def check_signatures(value, *, card_refusal=None, cert_refusal=None, genesis_refusal=False, checkpoint_refusal=False):
    for signed in signed_objects(value):
        o = signed["o"]
        corpus = CORPUS[str(o["suite"])]
        suite = R.SUITES[o["suite"]]
        if o["kind"] == "workspace_checkpoint" and checkpoint_refusal:
            assert R.verify_object(
                suite, bytes.fromhex(corpus["keys"]["wsk_a.sig"]["pub"]), signed,
                "workspace_checkpoint",
            ) is None
            continue
        if o["kind"] == "card":
            result = R.verify_card(
                suite, signed, bytes.fromhex(corpus["keys"]["person_alice.sig"]["pub"])
            )
            if card_refusal:
                assert result == {"refuse": card_refusal}
            else:
                assert "ok" in result
            continue
        if o["kind"] == "device_cert" and cert_refusal:
            assert R.verify_cert(
                suite,
                signed,
                bytes.fromhex(corpus["keys"]["person_alice.sig"]["pub"]),
                1790000000000,
            ) == {"refuse": cert_refusal}
            continue
        if o["kind"] in {"device_cert", "revocation", "cert_challenge", "cert_rejection"}:
            owner = (
                "person_bob" if o["person_id"] == corpus["ids"]["person_bob"] else "person_alice"
            )
        elif o["kind"] == "genesis_pin":
            if genesis_refusal:
                assert R.verify_object(
                    suite, bytes.fromhex(corpus["keys"]["phone.sig"]["pub"]), signed,
                    "genesis_pin",
                ) is None
                continue
            owner = "phone"
        elif o["kind"] == "ws_delegation":
            owner = "person_alice"
        else:
            owner = "wsk_a"
        assert (
            R.verify_object(
                suite, bytes.fromhex(corpus["keys"][owner + ".sig"]["pub"]), signed, o["kind"]
            )
            == o
        )


def check_envelope(text):
    raw = R.unb64u(text)
    h = R.Header.decode(raw)
    assert h.magic == R.MAGIC and h.version == 2 and h.suite in (1, 2)
    corpus = CORPUS[str(h.suite)]
    suite = R.SUITES[h.suite]
    hb, body, sig = R.split(raw)
    key = "phone.sig" if h.direction == R.TO_HOST else "wsk_a.sig"
    assert suite.verify(bytes.fromhex(corpus["keys"][key]["pub"]), sig, R.bridge_signed(hb, body))
    return h


def envelopes(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if key in {"envelope", "body_b64u"}:
                yield check_envelope(child)
            else:
                yield from envelopes(child)
    elif isinstance(value, list):
        for child in value:
            yield from envelopes(child)


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.stem)
def test_http_fixture(path):
    f = R.parse_json(path.read_bytes())
    assert set(f) == {"contract", "suite", "route", "cases"}
    assert f["contract"] == "orch-relay-http-v2" and f["suite"] == 2
    assert len({c["name"] for c in f["cases"]}) == len(f["cases"])
    row = next(r for r in ROUTES if r[0] == path.stem)
    actual = {
        (c["response"]["status"], c["response"]["json"]["error"])
        for c in f["cases"]
        if "error" in c["response"]["json"]
    }
    assert actual == set(refusals(row))
    registry = DOC.split("**Relay and orch-publish HTTP**", 1)[1].split("**Primary device", 1)[0]
    allowed = {
        int(status): set(re.findall(r"`([a-z_]+)`", cell))
        for status, cell in re.findall(r"\| (\d+) \| ([^\n]+)", registry)
    }
    for c in f["cases"]:
        request, response = c["request"], c["response"]
        assert request["method"] == f["route"]["method"]
        pattern = re.sub(r"\{[a-z_]+\}", lambda m: ("(?:null|sha256:[0-9a-f]{64})" if m[0] == "{source_hash}" else "sha256:[0-9a-f]{64}" if m[0] in {"{hash}", "{target_hash}"} else "[0-9]+" if m[0] == "{i}" else "[0-9a-f]{32}"), f["route"]["path"])
        assert re.fullmatch(pattern, request["path"])
        assert "Orch-Host-API" not in request["headers"]
        assert "host_api" not in json.dumps(c)
        if request["method"] == "GET":
            assert "json" not in request and "body_b64u" not in request
        assert all(isinstance(v, str) for v in request["query"].values())
        assert response["headers"]["Content-Type"] == "application/json"
        if response["status"] >= 400:
            code = response["json"]["error"]
            assert code in allowed[response["status"]], (response["status"], code)
            assert set(response["json"]) == (
                {"error", "epoch"} if code == "stale_epoch" else {"error", "devices"} if code == "restore_missing_revocation" else {"error"}
            )
        if response["status"] in (429, 503):
            assert re.fullmatch(r"[0-9]+", response["headers"]["Retry-After"])
        scenario = c["given"].get("scenario", c["name"])
        check_signatures(
            request,
            checkpoint_refusal=path.stem == "checkpoint_put" and scenario == "bad_signature",
            genesis_refusal=path.stem == "genesis" and scenario == "bad_signature",
            card_refusal=scenario
            if path.stem == "card_put" and scenario in {"bad_signature", "delegation_mismatch"}
            else None,
            cert_refusal="cert_invalid"
            if path.stem == "accounts" and scenario == "cert_invalid"
            else None,
        )
        check_signatures(response)
        list(envelopes(c))
        if "body_recipe" in request:
            recipe = request["body_recipe"]
            raw = (
                R.unb64u(recipe["prefix_b64u"])
                + bytes([recipe["byte"]]) * recipe["count"]
                + R.unb64u(recipe["suffix_b64u"])
            )
            assert len(raw) == BODY_CAPS[path.stem] + 1
            assert response["json"] == {"error": "too_large"}
        if path.stem in {"session_login", "accounts"} and "json" in request:
            body = request["json"]
            kind, ident = (
                (body["kind"], body["id"])
                if path.stem == "session_login"
                else ("device", body["device_cert"]["o"]["device_id"])
            )
            suite_id = body["device_cert"]["o"]["suite"] if path.stem == "accounts" else 2
            suite = R.SUITES[suite_id]
            corpus = CORPUS[str(suite_id)]
            msg = R.relay_auth_signed_bytes(
                suite,
                "https://relay.dev.severin.io",
                R.unb64u(body["challenge"], 32),
                kind,
                bytes.fromhex(ident),
            )
            assert suite.verify(
                bytes.fromhex(corpus["keys"]["phone.sig"]["pub"]), R.unb64u(body["sig"], 64), msg
            )


def test_fixture_success_shapes():
    for f in build().values():
        for c in f["cases"]:
            if c["response"]["status"] >= 400:
                continue
            body = c["response"]["json"]
            if "chunks" in body:
                assert set(body) == {"chunks"}
                for chunk in body["chunks"]:
                    assert set(chunk) == {"id", "idx", "last", "stream", "envelope"}
                    h = check_envelope(chunk["envelope"])
                    assert (chunk["id"], chunk["idx"], chunk["last"], chunk["stream"]) == (
                        h.rid.hex(),
                        h.seq,
                        bool(h.flags & R.F_LAST),
                        bool(h.flags & R.F_STREAM),
                    )
            if "items" in body:
                assert set(body) == {"items", "notices", "next"}
                assert set(body["notices"]) == {
                    "revocations_cursor",
                    "cert_requests",
                    "rotation_due",
                }
                for item in body["items"]:
                    assert set(item) == {"n", "route", "device", "rid", "offer", "envelope"}
                    h = check_envelope(item["envelope"])
                    assert item["device"] == h.device.hex() and item["rid"] == h.rid.hex()
                    assert item["offer"] == (h.stream.hex() if item["route"] == "pair" else None)


def test_json_caps_match_route_tables_and_success_bodies_fit():
    """Caps cover every JSON write before parsing, including unauthenticated endpoints."""
    for name, fixture in build().items():
        success = fixture["cases"][0]
        if "json" not in success["request"]:
            continue
        path = fixture["route"]["path"]
        row = next(
            line
            for line in DOC.splitlines()
            if line.startswith(f"| `{fixture['route']['method']} {path}`")
        )
        amount, unit = re.search(r"JSON cap (\d+) (KiB|MiB)", row).groups()
        cap = int(amount) * (1024 if unit == "KiB" else 1024 * 1024)
        assert BODY_CAPS[name] == cap
        assert len(R.cj(success["request"]["json"])) <= cap
        oversized = next(
            c for c in fixture["cases"] if c["response"]["json"].get("error") == "too_large"
        )
        assert oversized["response"]["status"] == (400 if name == "checkpoint_put" else 413)
        assert oversized["request"]["body_recipe"]["count"] == cap + 1


def test_workspace_fixtures_do_not_invent_device_session_failures():
    for name, fixture in build().items():
        auth = fixture["route"]["auth"]
        if "W" not in auth or "D(" in auth:
            continue
        errors = {
            (c["response"]["status"], c["response"]["json"].get("error")) for c in fixture["cases"]
        }
        assert (400, "cert_expired") not in errors
        if name == "membership":
            assert (403, "cert_expired") in errors  # proposed member's certificate
        if name not in {"membership", "bridge_host_post"}:
            assert (403, "revoked") not in errors


def test_checkpoint_fixture_state_machine_bindings():
    from ref import checkpoints as C
    from ref._checkpoint_http import ROUTES as CHECKPOINT_ROUTES

    names = {row[0] for row in CHECKPOINT_ROUTES}
    fixtures = build()
    for name in names:
        fixture = fixtures[name]
        assert "vector" in fixture["cases"][0]["given"]
        for case in fixture["cases"]:
            binding = case["given"].get("vector")
            if binding is None:
                continue
            vector = next(c for c in V["checkpoints"]["cases"] if c["name"] == binding["name"])
            import copy
            state = copy.deepcopy(vector["state"])
            for step in vector["steps"][:binding["step"] + 1]:
                result = C.dispatch(S, state, **step["input"])
            assert result["status"] == case["response"]["status"]
            assert {k: v for k, v in result.items() if k != "status"} == case["response"]["json"]
