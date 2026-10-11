"""Portable HTTP transcripts: route/refusal coverage, exact shapes, signatures and ORB2 framing."""
import json
import re
from pathlib import Path

import pytest

from ref import orch_protocol_ref as R
from ref._http_fixtures import ROUTES, build, refusals

ROOT = Path(__file__).resolve().parents[1]
DOC = (ROOT / "docs/protocol-v2.md").read_text()
FILES = sorted((ROOT / "tests/http_fixtures").glob("*.json"))
CORPUS = json.loads(R.VECTORS.read_text())["suites"]
V = CORPUS["2"]
S = R.SUITES[2]


def test_all_contract_routes_have_fixtures():
    table = DOC.split("## 19. Relay HTTP API", 1)[1]
    routes = set(re.findall(r"`(GET|POST|PUT|DELETE) (/v2/[^`?\[]+)", table))
    actual = {(f["route"]["method"], f["route"]["path"])
              for f in (json.loads(p.read_text()) for p in FILES)}
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
        match = re.match(r"\| `(GET|POST|PUT) (/v2/[^`?\[]+)", line)
        if not match:
            continue
        matching = [f for f in fixtures if (f["route"]["method"], f["route"]["path"]) == match.groups()]
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


def check_signatures(value):
    for signed in signed_objects(value):
        o = signed["o"]
        corpus = CORPUS[str(o["suite"])]
        suite = R.SUITES[o["suite"]]
        if o["kind"] == "card":
            assert "ok" in R.verify_card(suite, signed, bytes.fromhex(corpus["keys"]["person_alice.sig"]["pub"]))
            continue
        if o["kind"] in {"device_cert", "revocation", "cert_challenge", "cert_rejection"}:
            owner = "person_bob" if o["person_id"] == corpus["ids"]["person_bob"] else "person_alice"
        elif o["kind"] == "ws_delegation":
            owner = "person_alice"
        else:
            owner = "wsk_a"
        assert R.verify_object(suite, bytes.fromhex(corpus["keys"][owner + ".sig"]["pub"]), signed, o["kind"]) == o


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
    actual = {(c["response"]["status"], c["response"]["json"]["error"])
              for c in f["cases"] if "error" in c["response"]["json"]}
    assert actual == set(refusals(row))
    registry = DOC.split("**Relay and orch-publish HTTP**", 1)[1].split("**Primary device", 1)[0]
    allowed = {int(status): set(re.findall(r"`([a-z_]+)`", cell))
               for status, cell in re.findall(r"\| (\d+) \| ([^\n]+)", registry)}
    for c in f["cases"]:
        request, response = c["request"], c["response"]
        assert request["method"] == f["route"]["method"]
        pattern = re.sub(r"\{[a-z]+\}", "[0-9a-f]{32}", f["route"]["path"])
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
            assert set(response["json"]) == ({"error", "epoch"} if code == "stale_epoch" else {"error"})
        if response["status"] in (429, 503):
            assert re.fullmatch(r"[0-9]+", response["headers"]["Retry-After"])
        check_signatures(request)
        check_signatures(response)
        list(envelopes(c))
        if "body_recipe" in request:
            recipe = request["body_recipe"]
            raw = R.unb64u(recipe["prefix_b64u"]) + bytes([recipe["byte"]]) * recipe["count"] + R.unb64u(recipe["suffix_b64u"])
            caps = {"membership": 2097152, "bridge_device_post": 1048576, "bridge_host_post": 262144, "pair_device_post": 65536, "pair_host_post": 65536}
            assert len(raw) == caps[path.stem] + 1
            assert response["json"] == {"error": "too_large"}
        if path.stem in {"session_login", "accounts"}:
            body = request["json"]
            kind, ident = (body["kind"], body["id"]) if path.stem == "session_login" else ("device", body["device_cert"]["o"]["device_id"])
            suite_id = body["device_cert"]["o"]["suite"] if path.stem == "accounts" else 2
            suite = R.SUITES[suite_id]
            corpus = CORPUS[str(suite_id)]
            msg = R.relay_auth_signed_bytes(suite, "https://relay.dev.severin.io", R.unb64u(body["challenge"], 32), kind, bytes.fromhex(ident))
            assert suite.verify(bytes.fromhex(corpus["keys"]["phone.sig"]["pub"]), R.unb64u(body["sig"], 64), msg)


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
                        h.rid.hex(), h.seq, bool(h.flags & R.F_LAST), bool(h.flags & R.F_STREAM))
            if "items" in body:
                assert set(body) == {"items", "notices", "next"}
                assert set(body["notices"]) == {"revocations_cursor", "cert_requests", "rotation_due"}
                for item in body["items"]:
                    assert set(item) == {"n", "route", "device", "rid", "offer", "envelope"}
                    h = check_envelope(item["envelope"])
                    assert item["device"] == h.device.hex() and item["rid"] == h.rid.hex()
                    assert item["offer"] == (h.stream.hex() if item["route"] == "pair" else None)
