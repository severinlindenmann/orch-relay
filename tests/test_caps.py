# ruff: noqa: F811  (the imported `relay` fixture is a parameter name)
"""P3-D34: the G3 and G4 pre-public-deploy caps (docs/p3-relay-design.md §10).

- G3: staged bytes per owner person across all of its workspaces (429 quota_exceeded), and live
  workspaces per account at the first card (429 quota_exceeded).
- G4: stored log_nodes per workspace, checked in phase A and phase C of a final publication before
  phase B inserts anything (429 quota_exceeded, uncharged, its fold work recorded as refused heads);
  checkpoint_receipts and checkpoint_gone bounded per workspace (newest kept).
- Self-certified restore evidence: distinct new global revocation pairs per owner person.

Every cap: a test that fails without it, honest use just under it, authorization before it, and
live re-checks or concurrency where they matter. FAKE keys only.
"""

import copy
import threading
from contextlib import closing

import pytest
from checkpoint_support import CORPUS, WS, WS_B, replay, seed
from fastapi.testclient import TestClient
from test_publication_phases import (  # noqa: F401  (relay is a fixture)
    HOST,
    NOW,
    URL,
    append,
    entry,
    failures,
    node_count,
    page,
    published,
    put,
    relay,
    sql,
    stage,
    usage,
)

from orch_relay import checkpoints, db
from orch_relay import proto as P
from orch_relay.app import create_app
from orch_relay.checkpoints import ZERO, digest, page_digest
from ref import checkpoints as C
from ref import orch_protocol_ref as R

V = CORPUS["suites"]["2"]
S = R.SUITES[2]
WSK = S.sig_key(bytes.fromhex(V["keys"]["wsk_a.sig"]["seed"]))
W_A = {"Authorization": "Bearer FAKE-workspace", "Orch-Holder": "1"}
W_B = {"Authorization": "Bearer FAKE-workspace-b", "Orch-Holder": "1"}


def case(name, section="checkpoints"):
    return next(c for c in V[section]["cases"] if c["name"] == name)


# --- G3: staged bytes per owner person ------------------------------------------------------------


def staging_page(tag):
    p = {"kind": "appended", "log": "workspace", "after_seq": 0, "from_acc": ZERO}
    p["heads"] = [digest(f"FAKE caps {tag}".encode())]
    p["digest"] = page_digest(p)
    return p


PAGE_BYTES = len(P.cj(staging_page("x")))  # every tag below has the same length


@pytest.fixture
def two(tmp_path):
    """WS and WS_B, both owned by the same person, with their own W tokens and holders."""
    base = case("staging_immutable_page_and_manifest")
    with TestClient(create_app(tmp_path)) as client:
        path = tmp_path / db.DB_NAME
        seed(path, base["state"], base)
        seed(path, base["state"], base, ws=WS_B)
        client.app.state.directory.clock = lambda: NOW
        owners = sql(path, "SELECT DISTINCT owner_person_id FROM workspaces")
        assert len(owners) == 1
        yield client, path, client.app.state.checkpoints


def stage_one(client, ws, headers, tag, i=0):
    url = f"/v2/workspaces/{ws}/staging/null/{digest(f'FAKE set {tag}'.encode())}/pages/{i}"
    r = client.put(url, content=P.cj(staging_page(f"{tag}{i}")), headers={**headers, **JSON})
    return r


JSON = {"Content-Type": "application/json"}


def staged_total(path):
    return sql(path, "SELECT coalesce(sum(bytes),0) FROM checkpoint_staging")[0][0]


def test_account_stage_cap_spans_the_owners_workspaces(two):
    client, path, cps = two
    cps.caps.account_stage = 2 * PAGE_BYTES
    assert stage_one(client, WS, W_A, "a").status_code == 200
    # Honest use up to the cap is not refused (the bound is inclusive).
    assert stage_one(client, WS_B, W_B, "b").status_code == 200
    r = stage_one(client, WS_B, W_B, "b", 1)
    assert (r.status_code, r.json()) == (429, {"error": "quota_exceeded"}), r.text
    assert int(r.headers["retry-after"]) >= 1
    assert staged_total(path) == 2 * PAGE_BYTES  # nothing written by the refusal
    # Another owner's workspace is another account: not charged against this one.
    other = sql(
        path,
        "SELECT person_id FROM accounts WHERE person_id NOT IN "
        "(SELECT owner_person_id FROM workspaces)",
    )[0][0]
    sql(path, "UPDATE workspaces SET owner_person_id=? WHERE workspace_id=?", (other, WS_B))
    assert stage_one(client, WS_B, W_B, "b", 1).status_code == 200


def test_account_stage_cap_is_released_by_expiry_and_deletion(two):
    client, path, cps = two
    cps.caps.account_stage = PAGE_BYTES
    assert stage_one(client, WS, W_A, "a").status_code == 200
    assert stage_one(client, WS_B, W_B, "b").status_code == 429
    # An expired set no longer counts (it is purged by the next staging write as well).
    client.app.state.directory.clock = lambda: NOW + checkpoints.HOUR
    assert stage_one(client, WS_B, W_B, "b").status_code == 200
    assert stage_one(client, WS, W_A, "c").status_code == 429
    # A deleted set (commit or sweep) releases its bytes.
    sql(path, "DELETE FROM checkpoint_staging WHERE workspace_id=?", (WS_B,))
    assert stage_one(client, WS, W_A, "c").status_code == 200


def test_account_stage_cap_precedes_the_global_ceiling_and_follows_the_workspace_quota(two):
    client, _path, cps = two
    assert stage_one(client, WS, W_A, "a").status_code == 200
    cps.caps.account_stage = PAGE_BYTES
    cps.global_stage_cap = PAGE_BYTES
    # Over both: the account's own cap (429) answers before the shared ceiling (503).
    r = stage_one(client, WS_B, W_B, "b")
    assert (r.status_code, r.json()) == (429, {"error": "quota_exceeded"})
    cps.caps.account_stage = 10 * PAGE_BYTES
    r = stage_one(client, WS_B, W_B, "b")
    assert (r.status_code, r.json()) == (503, {"error": "overloaded"})


def test_account_stage_cap_refuses_only_after_authorization(two):
    client, _path, cps = two
    cps.caps.account_stage = 0
    r = stage_one(client, WS, {"Authorization": "Bearer FAKE-nobody", "Orch-Holder": "1"}, "a")
    assert (r.status_code, r.json()) == (401, {"error": "unauthenticated"})
    r = stage_one(client, WS, {**W_A, "Orch-Holder": "0"}, "a")
    assert (r.status_code, r.json()) == (409, {"error": "fenced"})
    r = stage_one(client, WS, W_B, "a")  # B's token on A's workspace
    assert (r.status_code, r.json()) == (403, {"error": "not_eligible"})
    assert stage_one(client, WS, W_A, "a").status_code == 429


def test_account_stage_cap_is_exact_under_concurrent_staging(two):
    client, path, cps = two
    cps.caps.account_stage = 5 * PAGE_BYTES
    barrier, results = threading.Barrier(12), []

    def worker(k):
        ws, headers = (WS, W_A) if k % 2 else (WS_B, W_B)
        barrier.wait()
        results.append(stage_one(client, ws, headers, "same", k).status_code)

    threads = [threading.Thread(target=worker, args=(k,)) for k in range(12)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    assert sorted(results) == [200] * 5 + [429] * 7
    assert staged_total(path) == 5 * PAGE_BYTES


def test_account_stage_cap_comes_from_the_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("ORCH_RELAY_ACCOUNT_STAGE_BYTES", "12345")
    monkeypatch.setenv("ORCH_RELAY_WORKSPACE_NODES", "678")
    monkeypatch.setenv("ORCH_RELAY_ACCOUNT_EVIDENCE", "9")
    monkeypatch.setenv("ORCH_RELAY_ACCOUNT_WORKSPACES", "3")
    with TestClient(create_app(tmp_path)) as client:
        caps = client.app.state.checkpoints.caps
        assert (caps.account_stage, caps.nodes, caps.evidence) == (12345, 678, 9)
        assert client.app.state.directory.account_workspaces == 3
    defaults = checkpoints.Caps()
    assert defaults.account_stage == checkpoints.GLOBAL_STAGE_CAP // 8 == 512 * 1024 * 1024
    assert defaults.nodes == 4_000_000 and defaults.evidence == 50_000


# --- G3: live workspaces per account (first card) -------------------------------------------------


def card_for(ws):
    from directory_support import CARD, sign, signed

    card = copy.deepcopy(CARD)
    card["o"]["workspace_id"] = ws
    card["delegation"] = signed({**card["delegation"]["o"], "workspace_id": ws})
    card["sig"] = sign("wsk_a.sig", P.L["sig_card_wsk"] + P.cj(card["o"]))
    return card


def test_live_workspaces_per_account_are_capped_at_the_first_card(tmp_path):
    from directory_support import PERSON
    from directory_support import seed as dseed

    from orch_relay.directory import HOUR

    with TestClient(create_app(tmp_path)) as c:
        d = c.app.state.directory
        dseed(d, card=False)
        d.account_workspaces = 3
        for i in range(3):  # honest use up to the cap
            ws = f"{i:032x}"
            assert (
                c.put(f"/v2/workspaces/{ws}/card", json={"card": card_for(ws)}).status_code == 200
            )
        ws = f"{9:032x}"
        # A bad signature is refused as such, never as the quota (authorize first).
        bad = card_for(ws)
        bad["sig"] = P.b64u(bytes(64))
        r = c.put(f"/v2/workspaces/{ws}/card", json={"card": bad})
        assert r.status_code in (400, 401) and r.json()["error"] != "quota_exceeded", r.text
        r = c.put(f"/v2/workspaces/{ws}/card", json={"card": card_for(ws)})
        assert (r.status_code, r.json()) == (429, {"error": "quota_exceeded"}), r.text
        assert int(r.headers["retry-after"]) >= 1
        # The refused card charged no creation window and wrote nothing.
        assert d.windows[("card-owner", PERSON, HOUR)][1] == 3
        assert d.windows[("card-address", "testclient", HOUR)][1] == 3
        with closing(db.connect(d.path)) as con:
            assert con.execute("SELECT count(*) FROM workspaces").fetchone()[0] == 3
        d.account_workspaces = 4
        assert c.put(f"/v2/workspaces/{ws}/card", json={"card": card_for(ws)}).status_code == 200


def test_the_workspace_cap_refuses_in_the_precheck_without_the_lock(tmp_path, monkeypatch):
    from directory_support import seed as dseed
    from test_directory_preauth import Spy

    with TestClient(create_app(tmp_path)) as c:
        d = c.app.state.directory
        dseed(d, card=False)
        d.account_workspaces = 0
        spy = Spy(d, monkeypatch)
        ws = f"{1:032x}"
        r = c.put(f"/v2/workspaces/{ws}/card", json={"card": card_for(ws)})
        assert (r.status_code, r.json()) == (429, {"error": "quota_exceeded"})
        assert (spy.locks, spy.writes) == (0, 0)


# --- G4: stored nodes per workspace ---------------------------------------------------------------


def test_node_quota_refuses_in_phase_a_before_phase_b_inserts(relay):
    stored = usage(relay.path)[0]
    body, _ = append(relay, 30, 10)
    before = published(relay.path)
    relay.cps.caps.nodes = stored + 29
    memos = []
    relay.cps.hooks["after_a"] = lambda **kw: memos.append(kw["memo"].accepted)
    r = relay.client.put(URL, content=P.cj(body), headers=HOST)
    assert (r.status_code, r.json()) == (429, {"error": "quota_exceeded"}), r.text
    assert int(r.headers["retry-after"]) >= 1
    assert memos == [False]  # phase A refused: no phase B
    assert node_count(relay.path) == stored and usage(relay.path) == (stored, 0)
    assert published(relay.path) == before
    # Uncharged like every 429; the fold work is recorded against the refused-heads budget.
    assert failures(relay.path) == 0
    assert sql(relay.path, "SELECT heads FROM checkpoint_refused_heads") == [(30,)]
    # Exactly at the quota is honest use: accepted.
    relay.cps.caps.nodes = stored + 30
    assert put(relay.client, body)["result"] == "accepted"
    assert usage(relay.path) == (stored + 30, 0)


def test_node_quota_is_rechecked_in_phase_c(relay):
    """Phase A's snapshot passed the quota; nodes stored before phase C (here: another writer)
    make phase C refuse before anything is inserted for this publication."""
    stored = usage(relay.path)[0]
    body, _ = append(relay, 30, 10)
    relay.cps.caps.nodes = stored + 30

    def grow(**kw):
        sql(
            relay.path, "UPDATE checkpoint_node_usage SET nodes=nodes+1 WHERE workspace_id=?", (WS,)
        )

    relay.cps.hooks["after_a"] = lambda **kw: setattr(kw["memo"], "accepted", False) or grow()
    r = relay.client.put(URL, content=P.cj(body), headers=HOST)
    assert (r.status_code, r.json()) == (429, {"error": "quota_exceeded"}), r.text
    assert node_count(relay.path) == stored


def test_orphans_count_toward_the_node_quota(relay):
    """`nodes` includes orphans (phase B rows of a publication phase C refused); `orphaned` is
    only their cumulative count and is not what the quota reads."""
    body, _ = append(relay, 40, 20)

    def drop(**kw):
        sql(relay.path, "DELETE FROM checkpoint_staging WHERE workspace_id=?", (WS,))

    relay.cps.hooks["before_c"] = drop
    assert put(relay.client, body) == {"status": 409, "error": "staging_incomplete"}
    del relay.cps.hooks["before_c"]
    nodes, orphaned = usage(relay.path)
    assert orphaned == 40
    relay.cps.caps.nodes = nodes + 5
    other, _ = append(relay, 10, 10, "other")
    assert put(relay.client, other) == {"status": 429, "error": "quota_exceeded"}
    # A publication whose nodes are all stored adds nothing and is never refused by the quota,
    # even with the workspace at or over it.
    relay.cps.caps.nodes = nodes - 1
    sql(relay.path, "DELETE FROM checkpoint_staging WHERE workspace_id=?", (WS,))
    again, _ = append(relay, 40, 20)
    assert put(relay.client, again)["result"] == "accepted"


def test_node_quota_counts_live_inserts_once(relay):
    """Without phase A (the live path: no memo, e.g. a lazy retry whose receipt was evicted), the
    nodes are inserted and counted in the transaction before the commit-point check; they are
    this publication's new nodes, not stored ones."""
    stored = usage(relay.path)[0]
    body, _ = append(relay, 30, 10)
    caps = checkpoints.Caps()
    caps.nodes = stored + 30
    with closing(db.connect(relay.path)) as con, con:
        result = checkpoints.Relay(relay.d, con, WS, NOW, caps=caps).publish(P.cj(body), 1)
    assert result["result"] == "accepted"
    assert usage(relay.path) == (stored + 30, 0) == (node_count(relay.path), 0)


def test_node_quota_refuses_only_after_authorization(relay):
    body, _ = append(relay, 30, 10)
    relay.cps.caps.nodes = 0
    assert put(relay.client, body, {**HOST, "Orch-Holder": "0"}) == {
        "status": 409,
        "error": "fenced",
    }
    assert put(relay.client, body, {**HOST, "Authorization": "Bearer FAKE-nobody"}) == {
        "status": 401,
        "error": "unauthenticated",
    }
    assert sql(relay.path, "SELECT count(*) FROM checkpoint_refused_heads")[0][0] == 0
    assert put(relay.client, body) == {"status": 429, "error": "quota_exceeded"}


def test_node_quota_holds_under_concurrent_publications(relay):
    """Two targets from the same H, sent at once: the per-workspace mutex serializes them; one is
    accepted within the quota and the other never adds nodes past it."""
    stored = usage(relay.path)[0]
    one, _ = append(relay, 30, 10, "one")
    two, _ = append(relay, 30, 10, "two", at="2026-09-21T13:46:41Z")
    relay.cps.caps.nodes = stored + 30
    barrier, results = threading.Barrier(2), []

    def send(body):
        barrier.wait()
        results.append(put(relay.client, body))

    threads = [threading.Thread(target=send, args=(b,)) for b in (one, two)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    assert sorted(r["status"] for r in results) == [200, 409], results
    assert usage(relay.path)[0] <= stored + 30


# --- G4: receipts and checkpoint_gone are bounded per workspace -----------------------------------


def chain(relay, count):
    """`count` accepted appends after r.first, one head each; the bodies in order."""
    bodies, held, tip, o = [], relay.first, relay.tip, relay.o
    for k in range(count):
        head = C.digest(f"FAKE chain {k}".encode())
        nxt = entry([head], tip["acc"], tip["seq"])
        o = {**o, "n": o["n"] + 1, "workspace_log": nxt}
        target = R.sign_object(S, WSK, o)
        body = stage(relay.path, held, target, [page("workspace", tip, [head])])
        assert put(relay.client, body)["result"] == "accepted"
        bodies.append(body)
        held, tip = target, nxt
    return bodies


def test_receipts_keep_the_newest_per_workspace(relay, monkeypatch):
    monkeypatch.setattr(checkpoints, "RECEIPTS_KEPT", 3)
    bodies = chain(relay, 5)
    kept = {d for (d,) in sql(relay.path, "SELECT digest FROM checkpoint_receipts")}
    assert kept == {digest(P.cj(b)) for b in bodies[-3:]}
    # The held publication's exact retry is still served from its receipt.
    last = bodies[-1]
    expect = {"status": 200, "result": "accepted", "n": last["checkpoint"]["o"]["n"]}
    expect["hash"] = C.checkpoint_hash(last["checkpoint"])
    assert put(relay.client, last) == expect
    # An evicted one is judged live: a lower n with consistent entries is `ignored`, uncharged.
    assert put(relay.client, bodies[0])["result"] == "ignored"
    assert failures(relay.path) == 0


def test_checkpoint_gone_keeps_the_newest_per_workspace(relay, monkeypatch):
    monkeypatch.setattr(checkpoints, "GONE_KEPT", 2)
    bodies = chain(relay, 5)
    old = [C.checkpoint_hash(relay.first)] + [C.checkpoint_hash(b["checkpoint"]) for b in bodies]
    relay.d.clock = lambda: NOW + checkpoints.DAY + 1
    relay.cps.sweep()
    gone = [h for (h,) in sql(relay.path, "SELECT hash FROM checkpoint_gone ORDER BY rowid")]
    assert len(gone) == 2 and set(gone) <= set(old[:-1])

    def get(h):
        r = relay.client.get(f"/v2/workspaces/{WS}/checkpoint", params={"hash": h}, headers=HOST)
        return r.status_code, r.json().get("error")

    assert get(gone[-1]) == (410, "checkpoint_gone")
    evicted = next(h for h in old[:-1] if h not in gone)
    assert get(evicted) == (404, "not_found")  # a refusal either way; never served
    assert get(old[-1])[0] == 200


# --- self-certified restore evidence per owner person ---------------------------------------------

B1 = "B1_unknown_device_self_certifying"


@pytest.fixture
def b1(tmp_path):
    """A workspace restore staged whose single evidence entry is self-certified and new to the
    global table (orch-core #397); the publication itself is not sent."""
    c = case(B1)
    with TestClient(create_app(tmp_path)) as client:
        path = tmp_path / db.DB_NAME
        replay(client, path, c, upto=2)
        body = c["steps"][2]["input"]["body"]
        (item,) = body["restore"]["line"]["revocations"]
        pair = (item["revocation"]["o"]["device_id"], item["revocation"]["o"]["person_id"])
        owner = c["state"]["delegation"]["o"]["owner_person_id"]
        yield client, path, client.app.state.checkpoints, body, pair, owner


def evidence_used(path, person):
    rows = sql(path, "SELECT pairs FROM account_evidence_pairs WHERE person_id=?", (person,))
    return rows[0][0] if rows else 0


def test_evidence_quota_refuses_new_self_certified_pairs_over_the_cap(b1):
    client, path, cps, body, pair, owner = b1
    cps.caps.evidence = 0
    memos = []
    cps.hooks["after_a"] = lambda **kw: memos.append(kw["memo"].accepted)
    before = published(path)
    r = client.put(URL, content=P.cj(body), headers=HOST)
    assert (r.status_code, r.json()) == (429, {"error": "quota_exceeded"}), r.text
    assert memos == [False]  # refused in phase A too: no phase B
    assert published(path) == before and failures(path) == 0
    assert not sql(path, "SELECT 1 FROM revocations WHERE device_id=? AND person_id=?", pair)
    assert evidence_used(path, owner) == 0
    # Exactly at the cap is honest use: accepted, and the pair is charged to the owner.
    cps.caps.evidence = 1
    assert put(client, body)["result"] == "accepted"
    assert evidence_used(path, owner) == 1
    assert evidence_used(path, pair[1]) == 0


def test_evidence_quota_never_counts_an_existing_pair(b1):
    """Re-carrying a pair the global table already holds (a victim's required carriage) is not
    charged and not refused, even with the carrier's quota spent."""
    client, path, cps, body, pair, owner = b1
    (item,) = body["restore"]["line"]["revocations"]
    record = item["revocation"]
    sql(
        path,
        "INSERT INTO revocations VALUES (?,?,?,?,0,(SELECT coalesce(max(cursor),0)+1 FROM "
        "revocations))",
        (*pair, P.cj(record), record["o"]["reason"]),
    )
    cps.caps.evidence = 0
    assert put(client, body)["result"] == "accepted"
    assert evidence_used(path, owner) == 0


def test_evidence_quota_is_per_owner_person(b1):
    client, path, cps, body, pair, owner = b1
    cps.caps.evidence = 5
    sql(path, "INSERT INTO account_evidence_pairs VALUES (?,?)", (pair[1], 5))  # another person
    assert put(client, body)["result"] == "accepted"
    assert evidence_used(path, owner) == 1 and evidence_used(path, pair[1]) == 5


def test_evidence_quota_is_rechecked_live_in_phase_c(b1):
    client, path, cps, body, pair, owner = b1
    cps.caps.evidence = 1
    memos = []

    def spend(**kw):
        memos.append(kw["memo"].accepted)
        sql(path, "INSERT INTO account_evidence_pairs VALUES (?,1)", (owner,))

    cps.hooks["before_c"] = spend
    r = client.put(URL, content=P.cj(body), headers=HOST)
    assert (r.status_code, r.json()) == (429, {"error": "quota_exceeded"}), r.text
    assert memos == [True] and failures(path) == 0
    assert not sql(path, "SELECT 1 FROM revocations WHERE device_id=? AND person_id=?", pair)


def test_evidence_quota_refuses_only_after_authorization(b1):
    client, _path, cps, body, _pair, _owner = b1
    cps.caps.evidence = 0
    assert put(client, body, {**HOST, "Orch-Holder": "0"}) == {"status": 409, "error": "fenced"}
    assert put(client, body) == {"status": 429, "error": "quota_exceeded"}


def test_migration_0015_backfills_evidence_pairs_per_owner(tmp_path):
    import shutil
    from importlib import resources

    mdir = tmp_path / "m"
    mdir.mkdir()
    src = resources.files("orch_relay").joinpath("migrations")
    for e in src.iterdir():
        if e.name.endswith(".sql") and e.name < "0015":
            shutil.copy(str(e), mdir / e.name)
    path = tmp_path / "r.sqlite3"
    db.migrate(path, mdir)
    with closing(db.connect(path)) as con, con:
        con.execute("INSERT INTO accounts VALUES ('aa','pk',0)")
        con.execute("INSERT INTO accounts VALUES ('bb','pk',0)")
        con.execute("INSERT INTO devices VALUES ('d1','bb',x'00','k','k',x'00',NULL)")
        for ws in ("w1", "w2"):
            con.execute("INSERT INTO workspaces VALUES (?,'aa','k',x'00',x'00',1,1,0)", (ws,))
        rows = [
            ("w1", "x1", "p1"),  # self-certified (no association)
            ("w2", "x1", "p1"),  # the same pair in another of aa's workspaces: counted once
            ("w2", "x2", "p2"),
            ("w1", "d1", "bb"),  # an associated (registered) device: not self-certified
        ]
        for ws, d, p in rows:
            con.execute(
                "INSERT INTO checkpoint_revocations VALUES (?,?,?,'lost',x'00',x'00','k','r','t')",
                (ws, d, p),
            )
    for e in src.iterdir():
        if e.name.endswith(".sql") and e.name >= "0015":
            shutil.copy(str(e), mdir / e.name)
    assert db.migrate(path, mdir)[0].startswith("0015")
    assert sql(path, "SELECT person_id, pairs FROM account_evidence_pairs") == [("aa", 2)]
