"""P3-D33 (G1 pre-public-deploy gate): a final publication is verified outside Directory.lock.

Phase A folds and checks on a WAL read snapshot under a per-workspace mutex and a global
semaphore; phase B inserts the new log_nodes in short chunks, each its own short transaction
under the lock; phase C re-runs the publication under the lock against live state, reusing
phase A's folds. These tests pin the lock-hold bound, the races at the phase boundaries, crash
safety, orphan accounting, the refused-heads budget and that light requests are served while a
big publication is in phase A or B. FAKE keys only.
"""

import asyncio
import threading
import time
from contextlib import closing
from types import SimpleNamespace

import pytest
from checkpoint_support import CORPUS, WS, replay, seed
from directory_support import issue_login
from fastapi.testclient import TestClient

from orch_relay import checkpoints, db
from orch_relay import proto as P
from orch_relay.app import create_app
from orch_relay.checkpoints import ZERO, Relay
from ref import checkpoints as C
from ref import orch_protocol_ref as R

NOW = 1790000000000
V = CORPUS["suites"]["2"]
S = R.SUITES[2]
WSK = S.sig_key(bytes.fromhex(V["keys"]["wsk_a.sig"]["seed"]))
HOST = {"Authorization": "Bearer FAKE-workspace", "Orch-Holder": "1"}
HOST |= {"Content-Type": "application/json"}
LOWER = {k.lower(): v for k, v in HOST.items()}
URL = f"/v2/workspaces/{WS}/checkpoint"


def case(name):
    return next(c for c in V["checkpoints"]["cases"] if c["name"] == name)


def entry(heads, acc=ZERO, seq=0):
    for h in heads:
        acc = C.log_acc(acc, h)
    return {"seq": seq + len(heads), "head": heads[-1], "acc": acc}


def page(log, start, heads):
    p = {"kind": "appended", "log": log, "after_seq": start["seq"], "from_acc": start["acc"]}
    p["heads"] = heads
    p["digest"] = C.page_digest(p)
    return p


def stage(path, held, target, pages):
    source = C.checkpoint_hash(held) if held else None
    h = C.checkpoint_hash(target)
    pages = sorted(pages, key=lambda p: (p["kind"], p["log"], p["after_seq"]))
    with closing(db.connect(path)) as con, con:
        relay = Relay(None, con, WS, NOW)
        for i, p in enumerate(pages):
            relay.put_staging(source, h, i, p, P.cj(p), 1 << 40)
        manifest = {"pages": [C.descriptor(i, p) for i, p in enumerate(pages)]}
        relay.put_staging(source, h, None, manifest, P.cj(manifest), 1 << 40)
    return {"checkpoint": target, "source_hash": source}


def put(client, body, headers=HOST):
    r = client.put(URL, content=P.cj(body), headers=headers)
    return {"status": r.status_code, **r.json()}


def sql(path, query, args=()):
    with closing(db.connect(path)) as con, con:
        return con.execute(query, args).fetchall()


@pytest.fixture
def relay(tmp_path):
    """The pinned genesis and a first accepted checkpoint (4 workspace heads), over HTTP."""
    pinned = case("first_checkpoint_full_proof")
    root = pinned["state"]["genesis"]["pin"]["o"]["genesis"]
    with TestClient(create_app(tmp_path)) as client:
        path = tmp_path / db.DB_NAME
        seed(path, pinned["state"], pinned)
        client.app.state.directory.clock = lambda: NOW
        heads = [root] + [C.digest(f"FAKE ws {i}".encode()) for i in range(1, 4)]
        o = {
            "v": 2,
            "suite": 2,
            "kind": "workspace_checkpoint",
            "workspace_id": WS,
            "genesis": root,
            "n": 1,
            "at": "2026-09-21T13:46:40Z",
            "workspace_log": entry(heads),
            "tickets": {},
        }
        first = R.sign_object(S, WSK, o)
        body = stage(path, None, first, [page("workspace", C.EMPTY, heads)])
        assert put(client, body)["result"] == "accepted"
        yield SimpleNamespace(
            client=client,
            path=path,
            first=first,
            o=o,
            tip=entry(heads),
            cps=client.app.state.checkpoints,
            d=client.app.state.directory,
        )


def append(r, count, per_page, tag="a", wrong=False):
    """Stage an append of `count` heads to the workspace log after r.first; the body and heads.
    `wrong`: the signed entry disagrees with the proof (refused after every fold)."""
    heads = [C.digest(f"FAKE {tag} {i}".encode()) for i in range(count)]
    pages, cursor = [], r.tip
    for k in range(0, count, per_page):
        chunk = heads[k : k + per_page]
        pages.append(page("workspace", cursor, chunk))
        cursor = entry(chunk, cursor["acc"], cursor["seq"])
    signed = {**cursor, "acc": C.digest(b"FAKE wrong")} if wrong else cursor
    target = R.sign_object(S, WSK, {**r.o, "n": 2, "workspace_log": signed})
    return stage(r.path, r.first, target, pages), heads


def proof(r, body):
    """Every head after r.tip on the published workspace log, through GET .../proof."""
    acc, out = r.tip["acc"], []
    to = C.checkpoint_hash(body["checkpoint"])
    while acc is not None:
        got = r.client.get(
            f"/v2/workspaces/{WS}/proof",
            params={"log": "workspace", "from": acc, "to": to},
            headers=HOST,
        )
        assert got.status_code == 200, got.text
        out += got.json()["heads"]
        acc = got.json()["next"]
    return out


def usage(path):
    rows = sql(
        path, "SELECT nodes, orphaned FROM checkpoint_node_usage WHERE workspace_id=?", (WS,)
    )
    return tuple(rows[0]) if rows else (0, 0)


def node_count(path):
    return sql(path, "SELECT count(*) FROM log_nodes WHERE workspace_id=?", (WS,))[0][0]


def published(path):
    return {
        "checkpoints": sql(path, "SELECT hash FROM checkpoints ORDER BY hash"),
        "heads": sql(path, "SELECT hash FROM checkpoint_heads"),
        "receipts": sql(path, "SELECT digest FROM checkpoint_receipts ORDER BY digest"),
        "transitions": sql(path, "SELECT restore_id FROM checkpoint_transitions"),
    }


def failures(path):
    return sql(path, "SELECT count(*) FROM checkpoint_failures")[0][0]


class Recorder:
    """Directory.lock recording each outermost hold and the folds (log_acc) made while held."""

    def __init__(self, lock):
        self.lock, self.depth, self.since, self.holds, self.folds = lock, 0, 0.0, [], 0

    def __enter__(self):
        self.lock.acquire()
        if self.depth == 0:
            self.since = time.perf_counter()
        self.depth += 1
        return self

    def __exit__(self, *exc):
        self.depth -= 1
        if self.depth == 0:
            self.holds.append(time.perf_counter() - self.since)
        self.lock.release()

    def _is_owned(self):
        return self.lock._is_owned()


# --- the lock-hold bound -------------------------------------------------------------------------


def test_no_head_is_folded_under_the_lock_and_each_hold_inserts_one_chunk(relay, monkeypatch):
    """60,000 heads with 10,000-row chunks: 6 short phase B holds and one phase C hold, no fold
    (log_acc) while the publishing thread holds Directory.lock, and every head is served after."""
    monkeypatch.setattr(checkpoints, "NODE_CHUNK", 10_000)
    body, heads = append(relay, 60_000, 30_000)
    recorder = Recorder(relay.d.lock)
    real = checkpoints.log_acc

    def counted(acc, head):
        if recorder.lock._is_owned():
            recorder.folds += 1
        return real(acc, head)

    monkeypatch.setattr(checkpoints, "log_acc", counted)
    relay.d.lock = recorder
    began = time.perf_counter()
    result = put(relay.client, body)
    wall = time.perf_counter() - began
    relay.d.lock = recorder.lock
    assert result["result"] == "accepted", result
    assert recorder.folds == 0
    assert len(recorder.holds) == 6 + 1, recorder.holds
    assert max(recorder.holds) <= 0.25 * wall, (recorder.holds, wall)
    assert proof(relay, body) == heads


# --- the per-workspace mutex and the global semaphore --------------------------------------------


def test_gate_serializes_one_workspace_and_admits_at_most_width_across_workspaces():
    gate = checkpoints.Gate(2)
    inside, order = [], []

    async def run():
        release = asyncio.Event()

        async def one(ws, tag):
            async with gate.enter(ws):
                inside.append(tag)
                order.append(("in", tag))
                await release.wait()
                inside.remove(tag)
                order.append(("out", tag))

        tasks = [asyncio.create_task(one(f"ws{k}", k)) for k in range(5)]
        tasks.append(asyncio.create_task(one("ws0", "same")))
        for _ in range(20):
            await asyncio.sleep(0)
        assert len(inside) == 2 and gate.active == 2  # the semaphore
        assert "same" not in inside
        release.set()
        await asyncio.gather(*tasks)

    asyncio.run(run())
    assert gate.peak == 2 and gate.active == 0
    # The second publication to ws0 entered only after the first one left (the mutex).
    assert order.index(("in", "same")) > order.index(("out", 0))
    assert not gate.loops or not next(iter(gate.loops.values()))[0]  # no per-workspace residue


def test_publication_runs_its_phases_inside_the_gate(relay):
    seen = []
    relay.cps.hooks["phase_a"] = lambda **kw: seen.append(("a", relay.cps.gate.active))
    relay.cps.hooks["before_c"] = lambda **kw: seen.append(("c", relay.cps.gate.active))
    body, _ = append(relay, 50, 25)
    assert put(relay.client, body)["result"] == "accepted"
    assert seen == [("a", 1), ("c", 1)], seen


def test_same_workspace_publications_serialize_and_exactly_one_wins(relay):
    """Two publications from H: the second's phase A starts only after the first committed, so it
    sees the new H and is refused; exactly one is accepted."""
    one, _ = append(relay, 40, 20, "one")
    two, _ = append(relay, 40, 20, "two")
    entered, release, results = [], threading.Event(), {}

    def phase_a(**kw):
        entered.append(kw["ws"])

    def before_c(**kw):
        if len(entered) == 1:
            assert release.wait(30)

    relay.cps.hooks.update(phase_a=phase_a, before_c=before_c)
    first = threading.Thread(target=lambda: results.update(one=put(relay.client, one)))
    first.start()
    while not entered:
        time.sleep(0.01)
    second = threading.Thread(target=lambda: results.update(two=put(relay.client, two)))
    second.start()
    time.sleep(0.3)
    assert len(entered) == 1  # the second waits on the workspace mutex, not in phase A
    release.set()
    first.join(30)
    second.join(30)
    assert results["one"]["result"] == "accepted", results
    assert (results["two"]["status"], results["two"]["error"]) == (409, "chain_diverged"), results
    head = sql(relay.path, "SELECT hash FROM checkpoint_heads")[0][0]
    assert head == C.checkpoint_hash(one["checkpoint"])


def test_racing_publications_on_h_without_the_mutex_still_accept_once(relay):
    """Phase C re-reads H live: A1, A2, B1, C1, B2, C2 accepts the first and refuses the second,
    whose phase B nodes are counted as orphans."""
    cps = relay.cps
    one, _ = append(relay, 30, 10, "one")
    two, _ = append(relay, 30, 10, "two")
    params = {"ws": WS}
    prepared, memos = {}, {}
    for name, body in (("one", one), ("two", two)):
        raw = P.cj(body)
        wsk = cps.preauthorize("checkpoint_put", WS, LOWER)
        prepared[name] = (raw, cps.prepare("checkpoint_put", WS, raw, wsk))
        memos[name] = cps.phase_a(WS, LOWER, raw, prepared[name][1])
        assert memos[name].accepted
    before = usage(relay.path)
    cps.phase_b(WS, LOWER, memos["one"])
    result, _ = cps.phase_c(params, LOWER, *prepared["one"], memos["one"])
    assert result["result"] == "accepted"
    cps.phase_b(WS, LOWER, memos["two"])
    with pytest.raises(checkpoints.Refusal) as refused:
        cps.phase_c(params, LOWER, *prepared["two"], memos["two"])
    cps.settle(WS, memos["two"], accepted=False)
    assert refused.value.code == "chain_diverged"
    assert sql(relay.path, "SELECT hash FROM checkpoint_heads")[0][0] == result["hash"]
    after = usage(relay.path)
    assert after == (before[0] + 60, before[1] + 30), (before, after)
    assert after[0] == node_count(relay.path)  # every node this relay inserted is counted


# --- changes between phase A and phase C ---------------------------------------------------------


@pytest.mark.parametrize("where", ["before_c", "chunk"])
def test_takeover_between_a_and_c_refuses_fenced_uncharged(relay, monkeypatch, where):
    monkeypatch.setattr(checkpoints, "NODE_CHUNK", 10)
    body, _ = append(relay, 40, 20)
    before = published(relay.path)
    calls = []

    def takeover(**kw):
        calls.append(1)
        if len(calls) == 2 or where == "before_c":
            sql(relay.path, "UPDATE holders SET gen=2 WHERE workspace_id=?", (WS,))

    relay.cps.hooks[where] = takeover
    assert put(relay.client, body) == {"status": 409, "error": "fenced"}
    assert published(relay.path) == before and failures(relay.path) == 0
    if where == "chunk":  # phase B stops at the first chunk after the takeover
        assert usage(relay.path)[1] == 10


def test_staging_deleted_between_a_and_c_is_refused_and_counts_orphans(relay):
    body, heads = append(relay, 40, 20)
    before, nodes = published(relay.path), usage(relay.path)

    def drop(**kw):
        sql(relay.path, "DELETE FROM checkpoint_staging WHERE workspace_id=?", (WS,))

    relay.cps.hooks["before_c"] = drop
    assert put(relay.client, body) == {"status": 409, "error": "staging_incomplete"}
    assert published(relay.path) == before and failures(relay.path) == 1
    assert usage(relay.path) == (nodes[0] + 40, nodes[1] + 40)
    # Re-staged, the same publication is accepted; its nodes exist already (idempotent).
    del relay.cps.hooks["before_c"]
    body, _ = append(relay, 40, 20)
    assert put(relay.client, body)["result"] == "accepted"
    assert usage(relay.path) == (nodes[0] + 40, nodes[1] + 40)
    assert proof(relay, body) == heads


RESTORE = "workspace_restore_and_exact_retry"


def restore_change(path, change):
    from test_checkpoints import held_row, signer_of

    with closing(db.connect(path)) as con, con:
        if change == "signer_revoked":
            device, owner = signer_of()
            held_row(con, device, owner, "person_alice.sig")
        elif change == "chain_pair_added":
            device = con.execute(
                "SELECT device_id FROM ever_devices WHERE workspace_id=?", (WS,)
            ).fetchone()[0]
            person = con.execute(
                "SELECT person_id FROM devices WHERE device_id=?", (device,)
            ).fetchone()[0]
            con.execute(
                "INSERT INTO checkpoint_revocations VALUES (?,?,?,'compromised',x'7b7d',x'7b7d',"
                "'FAKE','FAKE','FAKE')",
                (WS, device, person),
            )
        elif change == "delegation_changed":
            row = con.execute("SELECT delegation FROM workspaces WHERE workspace_id=?", (WS,))
            delegation = P.parse_json(row.fetchone()[0])
            delegation["o"] = {**delegation["o"], "FAKE": 1}
            con.execute(
                "UPDATE workspaces SET delegation=? WHERE workspace_id=?", (P.cj(delegation), WS)
            )
        else:
            other = P.b64u(bytes.fromhex(V["keys"]["wsk_b.sig"]["pub"]))
            con.execute("UPDATE workspaces SET wsk_pub=? WHERE workspace_id=?", (other, WS))


@pytest.mark.parametrize(
    "change,expect",
    [
        ("signer_revoked", (409, "restore_not_owner")),
        ("chain_pair_added", (409, "restore_missing_revocation")),
        ("delegation_changed", (409, "restore_not_owner")),
        ("wsk_changed", (401, "bad_signature")),
        (None, (200, None)),
    ],
)
def test_evidence_and_policy_changes_between_a_and_c_are_caught_live(tmp_path, change, expect):
    restore = case(RESTORE)
    with TestClient(create_app(tmp_path)) as client:
        path = tmp_path / db.DB_NAME
        replay(client, path, restore, upto=2)  # staged; the restore publication not yet sent
        step = restore["steps"][2]
        cps, memos = client.app.state.checkpoints, []
        cps.hooks["after_a"] = lambda **kw: memos.append(kw["memo"].accepted)
        if change:
            cps.hooks["before_c"] = lambda **kw: restore_change(path, change)
        before = published(path)
        r = client.put(URL, content=P.cj(step["input"]["body"]), headers=HOST)
        assert memos == [True]  # phase A accepted against its snapshot
        assert (r.status_code, r.json().get("error")) == expect, r.text
        if change:
            assert published(path) == before and failures(path) == 1
        else:
            assert r.json() == {k: v for k, v in step["expect"].items() if k != "status"}


# --- crashes and restarts ------------------------------------------------------------------------


class Crash(Exception):
    pass


def test_crash_between_b_and_c_leaves_no_checkpoint_and_a_retry_is_accepted(relay):
    cps = relay.cps
    body, heads = append(relay, 30, 10)
    before = published(relay.path)
    raw = P.cj(body)
    pre = cps.prepare("checkpoint_put", WS, raw, cps.preauthorize("checkpoint_put", WS, LOWER))
    memo = cps.phase_a(WS, LOWER, raw, pre[1])
    cps.phase_b(WS, LOWER, memo)  # the process dies here: phase C never runs
    assert published(relay.path) == before
    assert node_count(relay.path) >= 30
    assert put(relay.client, body)["result"] == "accepted"
    assert proof(relay, body) == heads


def test_crash_in_phase_b_leaves_a_prefix_and_a_retry_is_accepted(relay, monkeypatch):
    monkeypatch.setattr(checkpoints, "NODE_CHUNK", 7)
    body, heads = append(relay, 30, 10)
    before, nodes = published(relay.path), node_count(relay.path)
    calls = []

    def crash(**kw):
        calls.append(1)
        if len(calls) == 3:
            raise Crash

    relay.cps.hooks["chunk"] = crash
    with pytest.raises(Crash):
        put(relay.client, body)
    assert published(relay.path) == before and node_count(relay.path) == nodes + 14
    del relay.cps.hooks["chunk"]
    assert put(relay.client, body)["result"] == "accepted"
    assert proof(relay, body) == heads


def test_phase_c_never_accepts_on_folds_whose_nodes_phase_b_did_not_insert(relay):
    """Defence in depth: if phase A did not accept (so phase B inserted nothing), phase C may not
    commit an acceptance resting on phase A's folds; it re-runs the publication live."""
    body, heads = append(relay, 30, 10)

    def forget(**kw):
        kw["memo"].accepted = False

    relay.cps.hooks["after_a"] = forget
    assert put(relay.client, body)["result"] == "accepted"
    assert proof(relay, body) == heads


# --- budget by work ------------------------------------------------------------------------------


def test_refused_heads_budget_stops_folding_work(relay, monkeypatch):
    monkeypatch.setattr(checkpoints, "REFUSED_HEADS", 100)
    wrong, _ = append(relay, 60, 30, "w", wrong=True)
    for _ in range(2):  # 0, then 60 heads spent: both still folded and refused
        assert put(relay.client, wrong) == {"status": 409, "error": "chain_diverged"}
    spent = sql(
        relay.path, "SELECT heads FROM checkpoint_refused_heads WHERE workspace_id=?", (WS,)
    )
    assert sorted(h for (h,) in spent) == [60, 60]
    folds = []
    real = checkpoints.log_acc
    monkeypatch.setattr(checkpoints, "log_acc", lambda a, h: folds.append(1) or real(a, h))
    good, _ = append(relay, 60, 30, "g")
    r = relay.client.put(URL, content=P.cj(good), headers=HOST)
    assert (r.status_code, r.json()) == (429, {"error": "quota_exceeded"})
    assert r.headers["retry-after"] == "1" and folds == []
    assert failures(relay.path) == 2  # 429 is never charged
    with closing(db.connect(relay.path)) as con, con:
        con.execute("UPDATE checkpoint_refused_heads SET at_ms=at_ms-? ", (checkpoints.HOUR,))
    assert put(relay.client, good)["result"] == "accepted"


def test_a_refusal_before_the_staged_set_is_loaded_charges_no_heads(relay):
    body, _ = append(relay, 20, 10)
    body = {**body, "source_hash": C.digest(b"FAKE other source")}
    assert put(relay.client, body) == {"status": 409, "error": "restore_source_mismatch"}
    assert sql(relay.path, "SELECT count(*) FROM checkpoint_refused_heads")[0][0] == 0
    assert failures(relay.path) == 1


# --- light requests are served while a big publication is in phase A or B ------------------------


@pytest.mark.parametrize("where", ["phase_a", "chunk"])
def test_healthz_login_and_bridge_are_served_during_phase_a_and_b(relay, monkeypatch, where):
    monkeypatch.setattr(checkpoints, "NODE_CHUNK", 500)
    body, _ = append(relay, 2_000, 1_000)
    paused, release, results = threading.Event(), threading.Event(), {}

    def pause(**kw):
        if not paused.is_set():
            paused.set()
            assert release.wait(30)

    relay.cps.hooks[where] = pause
    publication = threading.Thread(target=lambda: results.update(put=put(relay.client, body)))
    publication.start()
    assert paused.wait(30)

    def light():
        results["healthz"] = relay.client.get("/healthz").status_code
        results["login"] = issue_login(relay.client).status_code
        results["poll"] = relay.client.get(
            f"/v2/workspaces/{WS}/host/poll", params={"after": "0"}, headers=HOST
        ).status_code

    worker = threading.Thread(target=light)
    worker.start()
    worker.join(10)
    served = not worker.is_alive()
    release.set()
    publication.join(30)
    worker.join(30)
    assert served, results
    assert (results["healthz"], results["login"], results["poll"]) == (200, 200, 200), results
    assert results["put"]["result"] == "accepted"
