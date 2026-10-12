# ruff: noqa: F811  (the imported `relay` fixture is a parameter name)
"""P3-D37: a hard maximum publication size (docs/p3-relay-design.md §10, protocol §19.8).

ORCH_RELAY_MAX_PUBLICATION_BYTES bounds the staged bytes of one set (manifest plus pages, the
`checkpoint_staging.bytes` accounting), because phase A's memory is about linear in its heads and
the publication gate admits a set above its heads cap alone. Refused as `too_large` (permanent,
never 429): at the manifest PUT from the size the manifest implies (before any page is uploaded),
at each page PUT (running total), and again at the final publication before any fold. The default
publication heads cap follows from the maximum, so one maximal publication always fits alone.
FAKE keys only.
"""

from contextlib import closing
from types import SimpleNamespace

import pytest
from checkpoint_support import WS, replay
from fastapi.testclient import TestClient
from test_publication_phases import (  # noqa: F401  (relay is a fixture)
    HOST,
    URL,
    append,
    failures,
    node_count,
    published,
    put,
    relay,
    sql,
    usage,
)

from orch_relay import checkpoints, db
from orch_relay import proto as P
from orch_relay.app import create_app
from orch_relay.checkpoints import ZERO, digest, page_digest
from ref import checkpoints as C

MIB = 1024 * 1024
TARGET = digest(b"FAKE max-publication target")
BASE = f"/v2/workspaces/{WS}/staging/null/{TARGET}"


def fake_page(tag, heads=1, after_seq=0):
    p = {"kind": "appended", "log": "workspace", "after_seq": after_seq, "from_acc": ZERO}
    p["heads"] = [digest(f"FAKE max {tag} {k}".encode()) for k in range(heads)]
    p["digest"] = page_digest(p)
    return p


def put_page(client, i, p):
    r = client.put(f"{BASE}/pages/{i}", content=P.cj(p), headers=HOST)
    return r


def put_manifest(client, manifest):
    return client.put(f"{BASE}/manifest", content=P.cj(manifest), headers=HOST)


def manifest_of(pages):
    return {"pages": [C.descriptor(i, p) for i, p in enumerate(pages)]}


def staged(path, target=TARGET):
    """(bytes, manifest stored, page indices) of the staged set, or None."""
    row = sql(
        path,
        "SELECT bytes, manifest IS NOT NULL FROM checkpoint_staging WHERE workspace_id=? "
        "AND target=?",
        (WS, target),
    )
    if not row:
        return None
    pages = sql(
        path,
        "SELECT i FROM checkpoint_staging_pages WHERE workspace_id=? AND target=? ORDER BY i",
        (WS, target),
    )
    return row[0][0], bool(row[0][1]), [i for (i,) in pages]


def refused(r, status=413):
    return (r.status_code, r.json(), "retry-after" in r.headers) == (
        status,
        {"error": "too_large"},
        False,
    )


# --- configuration --------------------------------------------------------------------------------


def test_default_is_16_mib_and_the_heads_cap_follows_it():
    caps = checkpoints.Caps()
    assert checkpoints.MAX_PUBLICATION == 16 * MIB == caps.max_publication
    # One maximal set (226,719 heads at 74 bytes each) always fits the default heads cap alone.
    assert checkpoints.PUBLISH_HEADS == 16 * MIB // 74 == 226_719


def test_max_publication_comes_from_the_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("ORCH_RELAY_MAX_PUBLICATION_BYTES", "7400")
    with TestClient(create_app(tmp_path)) as client:
        cps = client.app.state.checkpoints
        assert cps.caps.max_publication == 7400
        # Unset, the publication heads cap is the heads the maximum implies.
        assert cps.gate.cap == 100
    monkeypatch.setenv("ORCH_RELAY_PUBLISH_HEADS", "1234")
    with TestClient(create_app(tmp_path)) as client:
        assert client.app.state.checkpoints.gate.cap == 1234  # an explicit cap is kept
    monkeypatch.delenv("ORCH_RELAY_PUBLISH_HEADS")
    monkeypatch.delenv("ORCH_RELAY_MAX_PUBLICATION_BYTES")
    with TestClient(create_app(tmp_path)) as client:
        cps = client.app.state.checkpoints
        assert (cps.caps.max_publication, cps.gate.cap) == (16 * MIB, 226_719)


@pytest.mark.parametrize("value", ["0", "-1", "x", "1.5", "", " ", "1e6", str(64 * MIB + 1)])
def test_max_publication_is_validated_at_start_up(tmp_path, monkeypatch, value):
    with pytest.raises(ValueError, match="ORCH_RELAY_MAX_PUBLICATION_BYTES"):
        checkpoints.Caps({"ORCH_RELAY_MAX_PUBLICATION_BYTES": value})
    monkeypatch.setenv("ORCH_RELAY_MAX_PUBLICATION_BYTES", value)
    with pytest.raises(ValueError, match="ORCH_RELAY_MAX_PUBLICATION_BYTES"):
        create_app(tmp_path)


def test_max_publication_bounds_are_inclusive():
    assert checkpoints.Caps({"ORCH_RELAY_MAX_PUBLICATION_BYTES": "1"}).max_publication == 1
    top = checkpoints.Caps({"ORCH_RELAY_MAX_PUBLICATION_BYTES": str(checkpoints.STAGE_CAP)})
    assert top.max_publication == checkpoints.STAGE_CAP == 64 * MIB


# --- staging: page PUTs (running total) -----------------------------------------------------------


@pytest.mark.parametrize("slack", [0, -1])
def test_page_put_refuses_beyond_the_maximum_running_total(relay, slack):
    pages = [fake_page(k) for k in range(3)]
    size = len(P.cj(pages[0]))
    assert all(len(P.cj(p)) == size for p in pages)
    relay.cps.caps.max_publication = 2 * size + slack
    assert put_page(relay.client, 0, pages[0]).status_code == 200
    r = put_page(relay.client, 1, pages[1])
    if slack:  # max + 1 bytes would be staged: refused, nothing written
        assert refused(r), r.text
        assert staged(relay.path) == (size, False, [0])
        return
    assert r.status_code == 200, r.text  # exactly at the maximum: honest use
    r = put_page(relay.client, 2, pages[2])
    assert refused(r), r.text
    # The refusal writes nothing: the set keeps what it had (at most the maximum) until it
    # expires; an identical retry of a staged page is still the usual no-op.
    assert staged(relay.path) == (2 * size, False, [0, 1])
    assert put_page(relay.client, 1, pages[1]).status_code == 200
    assert refused(put_page(relay.client, 2, pages[2]))


def test_page_put_refusal_is_permanent_and_precedes_the_staging_quotas(relay):
    p = fake_page(0)
    relay.cps.caps.max_publication = len(P.cj(p)) - 1
    relay.cps.caps.account_stage = 0  # the transient 429 quota would refuse too
    assert refused(put_page(relay.client, 0, p))
    assert staged(relay.path) is None


def test_page_put_refusal_comes_after_authorization(relay):
    relay.cps.caps.max_publication = 1
    p = fake_page(0)
    nobody = {**HOST, "Authorization": "Bearer FAKE-nobody"}
    r = relay.client.put(f"{BASE}/pages/0", content=P.cj(p), headers=nobody)
    assert (r.status_code, r.json()) == (401, {"error": "unauthenticated"})
    r = relay.client.put(f"{BASE}/pages/0", content=P.cj(p), headers={**HOST, "Orch-Holder": "0"})
    assert (r.status_code, r.json()) == (409, {"error": "fenced"})
    assert refused(put_page(relay.client, 0, p))


# --- staging: the manifest PUT (implied size, before any page) ------------------------------------


def implied(manifest, staged_bytes=0, staged_pages=()):
    """The lower bound the relay computes: what is staged, the manifest, and 74 bytes per head
    of every page not staged yet (a head is 73 JSON bytes plus a separator)."""
    rest = sum(d["count"] for d in manifest["pages"] if d["i"] not in staged_pages)
    return staged_bytes + len(P.cj(manifest)) + 74 * rest


def test_manifest_put_refuses_an_oversized_set_before_any_page(relay):
    pages = [fake_page(k, heads=50, after_seq=50 * k) for k in range(4)]
    manifest = manifest_of(pages)
    bound = implied(manifest)
    assert bound < sum(len(P.cj(p)) for p in pages) + len(P.cj(manifest))  # a lower bound
    relay.cps.caps.max_publication = bound - 1
    assert refused(put_manifest(relay.client, manifest))
    assert staged(relay.path) is None  # zero pages, no set, no manifest
    relay.cps.caps.max_publication = bound  # exactly what the manifest implies: accepted
    r = put_manifest(relay.client, manifest)
    assert (r.status_code, r.json()) == (200, {"complete": False, "missing": [0, 1, 2, 3]})
    assert staged(relay.path) == (len(P.cj(manifest)), True, [])
    # The pages are larger than 74 bytes per head: the running total stops them at the maximum.
    codes = [put_page(relay.client, i, p).status_code for i, p in enumerate(pages)]
    assert codes[0] == 200 and codes[-1] == 413, codes
    assert staged(relay.path)[0] <= bound


def test_manifest_put_counts_the_pages_already_staged_exactly(relay):
    pages = [fake_page(k, heads=50, after_seq=50 * k) for k in range(2)]
    manifest = manifest_of(pages)
    relay.cps.caps.max_publication = 16 * MIB
    assert put_page(relay.client, 0, pages[0]).status_code == 200
    bound = implied(manifest, len(P.cj(pages[0])), {0})
    relay.cps.caps.max_publication = bound - 1
    assert refused(put_manifest(relay.client, manifest))
    assert staged(relay.path) == (len(P.cj(pages[0])), False, [0])
    relay.cps.caps.max_publication = bound
    assert put_manifest(relay.client, manifest).status_code == 200


def test_manifest_put_without_pages_is_bounded_by_its_own_bytes(relay):
    manifest = manifest_of([fake_page(0)])
    relay.cps.caps.max_publication = len(P.cj(manifest)) + 74 - 1
    assert refused(put_manifest(relay.client, manifest))
    relay.cps.caps.max_publication = len(P.cj(manifest)) + 74
    assert put_manifest(relay.client, manifest).status_code == 200


# --- the final publication (phase A, defence in depth) --------------------------------------------


def set_bytes(path, body):
    return staged(path, C.checkpoint_hash(body["checkpoint"]))[0]


@pytest.fixture
def big(relay, monkeypatch):
    """A staged 30-head append (staged under the default maximum), with spies on phase A's work
    and its gate reservation."""
    body, _ = append(relay, 30, 10)
    seen = SimpleNamespace(pages=0, folds=0, gate=[], accepted=[], body=body)
    real_page, real_fold = checkpoints.Relay.page_body, checkpoints.Relay.fold

    def page_body(self, stage, d):
        seen.pages += 1
        return real_page(self, stage, d)

    def fold(self, *args, **kwargs):
        seen.folds += 1
        return real_fold(self, *args, **kwargs)

    monkeypatch.setattr(checkpoints.Relay, "page_body", page_body)
    monkeypatch.setattr(checkpoints.Relay, "fold", fold)
    relay.cps.hooks["phase_a"] = lambda **kw: seen.gate.append(relay.cps.gate.heads)
    relay.cps.hooks["after_a"] = lambda **kw: seen.accepted.append(kw["memo"].accepted)
    return seen


def test_publication_refuses_a_set_staged_beyond_the_maximum_before_any_fold(relay, big):
    size = set_bytes(relay.path, big.body)
    before, stored = published(relay.path), node_count(relay.path)
    relay.cps.caps.max_publication = size - 1  # e.g. lowered after the set was staged
    r = relay.client.put(URL, content=P.cj(big.body), headers=HOST)
    assert refused(r, 400), r.text
    # No fold, no staged page read, nothing reserved in the gate, phase A not accepted.
    assert (big.pages, big.folds, big.gate, big.accepted) == (0, 0, [0], [False])
    # Charged like the route's other permanent size refusal (400 too_large), with no fold work.
    assert failures(relay.path) == 1
    assert sql(relay.path, "SELECT count(*) FROM checkpoint_refused_heads")[0][0] == 0
    assert published(relay.path) == before and node_count(relay.path) == stored
    assert set_bytes(relay.path, big.body) == size  # the staged set is kept, like any refusal
    # Exactly at the maximum: accepted.
    relay.cps.caps.max_publication = size
    assert put(relay.client, big.body)["result"] == "accepted"
    assert big.folds > 0


def test_publication_rechecks_the_maximum_in_phase_c(relay, big):
    """Defence in depth: phase C re-runs the publication against live state and refuses too."""
    size = set_bytes(relay.path, big.body)
    before = published(relay.path)

    def lower(**kw):
        relay.cps.caps.max_publication = size - 1

    relay.cps.hooks["before_c"] = lower
    r = relay.client.put(URL, content=P.cj(big.body), headers=HOST)
    assert refused(r, 400), r.text
    assert published(relay.path) == before and failures(relay.path) == 1


def test_publication_refusal_comes_after_authorization(relay, big):
    relay.cps.caps.max_publication = 1
    nobody = {**HOST, "Authorization": "Bearer FAKE-nobody"}
    assert put(relay.client, big.body, nobody) == {"status": 401, "error": "unauthenticated"}
    assert put(relay.client, big.body, {**HOST, "Orch-Holder": "0"}) == {
        "status": 409,
        "error": "fenced",
    }
    assert failures(relay.path) == 0
    assert put(relay.client, big.body) == {"status": 400, "error": "too_large"}


def test_publication_within_the_maximum_is_unchanged(relay):
    body, _ = append(relay, 300, 100)
    seen = []
    relay.cps.hooks["phase_a"] = lambda **kw: seen.append(relay.cps.gate.heads)
    relay.cps.caps.max_publication = set_bytes(relay.path, body)
    assert put(relay.client, body)["result"] == "accepted"
    assert len(seen) == 1 and 300 <= seen[0] < 400  # reserved from its staged bytes, as before
    assert usage(relay.path) == (node_count(relay.path), 0)


# --- restores use the same maximum ----------------------------------------------------------------

RESTORE = "workspace_restore_and_exact_retry"


def test_restore_publication_uses_the_same_maximum(tmp_path):
    from checkpoint_support import CORPUS

    c = next(x for x in CORPUS["suites"]["2"]["checkpoints"]["cases"] if x["name"] == RESTORE)
    with TestClient(create_app(tmp_path)) as client:
        path = tmp_path / db.DB_NAME
        replay(client, path, c, upto=2)
        body = c["steps"][2]["input"]["body"]
        cps = client.app.state.checkpoints
        size = set_bytes(path, body)
        before = published(path)
        cps.caps.max_publication = size - 1
        r = client.put(URL, content=P.cj(body), headers=HOST)
        assert refused(r, 400), r.text
        assert published(path) == before
        cps.caps.max_publication = size
        expect = {k: v for k, v in c["steps"][2]["expect"].items() if k != "status"}
        assert put(client, body) == {"status": 200, **expect}


def test_restore_staging_is_refused_beyond_the_maximum(tmp_path):
    """The restore's staging PUTs are the same routes: one byte under its page refuses it (413
    too_large, nothing stored); its whole set exactly at the maximum stages as in the vector."""
    from checkpoint_support import CORPUS, step

    c = next(x for x in CORPUS["suites"]["2"]["checkpoints"]["cases"] if x["name"] == RESTORE)
    page_step, manifest_step = c["steps"][0], c["steps"][1]
    assert (page_step["input"]["op"], manifest_step["input"]["op"]) == ("page", "manifest")
    page_size = len(P.cj(page_step["input"]["body"]))
    whole = page_size + len(P.cj(manifest_step["input"]["body"]))
    with TestClient(create_app(tmp_path)) as client:
        path = tmp_path / db.DB_NAME
        replay(client, path, c, upto=0)
        cps = client.app.state.checkpoints
        cps.caps.max_publication = page_size - 1
        result = step(client, path, page_step["input"], c)
        assert result == {"status": 413, "error": "too_large"}, result
        with closing(db.connect(path)) as con:
            assert con.execute("SELECT count(*) FROM checkpoint_staging").fetchone()[0] == 0
        cps.caps.max_publication = whole
        assert step(client, path, page_step["input"], c) == page_step["expect"]
        assert step(client, path, manifest_step["input"], c) == manifest_step["expect"]
