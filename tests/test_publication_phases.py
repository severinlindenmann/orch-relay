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


def append(r, count, per_page, tag="a", wrong=False, at=None, tickets=None):
    """Stage an append of `count` heads to the workspace log after r.first; the body and heads.
    `wrong`: the signed entry disagrees with the proof (refused after every fold). `at`: another
    checkpoint time (another target over the same pages). `tickets`: {log: (heads, entry)}, new
    ticket logs with one page each and the signed entry."""
    heads = [C.digest(f"FAKE {tag} {i}".encode()) for i in range(count)]
    pages, cursor = [], r.tip
    for k in range(0, count, per_page):
        chunk = heads[k : k + per_page]
        pages.append(page("workspace", cursor, chunk))
        cursor = entry(chunk, cursor["acc"], cursor["seq"])
    signed = {**cursor, "acc": C.digest(b"FAKE wrong")} if wrong else cursor
    o = {**r.o, "n": 2, "workspace_log": signed}
    if at:
        o["at"] = at
    for log, (ticket_heads, signed_entry) in (tickets or {}).items():
        o["tickets"] = {**o["tickets"], log: signed_entry}
        pages.append(page(log, C.EMPTY, ticket_heads))
    target = R.sign_object(S, WSK, o)
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
    """Directory.lock recording each outermost hold (by thread) and the folds (log_acc) made while
    held."""

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
            self.holds.append((threading.get_ident(), time.perf_counter() - self.since))
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
    pages, real_page = [], checkpoints.Relay.page_body

    def page_body(self, stage, d):
        if recorder.lock._is_owned():
            pages.append(d["i"])  # phase C reads no staged page: phase A recorded what it needs
        return real_page(self, stage, d)

    monkeypatch.setattr(checkpoints.Relay, "page_body", page_body)
    publisher = []
    relay.cps.hooks["phase_a"] = lambda **kw: publisher.append(threading.get_ident())
    relay.d.lock = recorder
    began = time.perf_counter()
    result = put(relay.client, body)
    wall = time.perf_counter() - began
    relay.d.lock = recorder.lock
    assert result["result"] == "accepted", result
    assert recorder.folds == 0 and pages == []
    holds = [held for thread, held in recorder.holds if thread == publisher[0]]
    assert len(holds) == 6 + 1, recorder.holds  # the background sweeps hold it too, briefly
    assert max(holds) <= 0.25 * wall, (holds, wall)
    assert proof(relay, body) == heads
    assert usage(relay.path) == (node_count(relay.path), 0)  # counted, none orphaned


def test_lock_order_gate_then_lock_and_no_pooled_read_connection_held_while_locking(
    relay, monkeypatch
):
    """Lock order (P3-D33): the workspace mutex and the semaphore (the gate) are held whenever the
    publishing thread takes Directory.lock, and it never waits for the lock while it holds a
    pooled read connection (phase A's snapshot is returned before phase B)."""
    from contextlib import contextmanager

    monkeypatch.setattr(checkpoints, "NODE_CHUNK", 10)
    body, _ = append(relay, 40, 20)
    pool, borrowed, taken = relay.d.pool, {}, []
    real_borrow = pool.borrow

    @contextmanager
    def borrow(purpose="read"):
        me = threading.get_ident()
        borrowed[me] = borrowed.get(me, 0) + 1
        try:
            with real_borrow(purpose) as con:
                yield con
        finally:
            borrowed[me] -= 1

    monkeypatch.setattr(pool, "borrow", borrow)
    publisher = []
    relay.cps.hooks["phase_a"] = lambda **kw: publisher.append(threading.get_ident())

    class Ordered(Recorder):
        def __enter__(self):
            me = threading.get_ident()
            if publisher and me == publisher[0] and self.depth == 0:
                taken.append((relay.cps.gate.active, borrowed.get(me, 0)))
            return super().__enter__()

    recorder = Ordered(relay.d.lock)
    relay.d.lock = recorder
    result = put(relay.client, body)
    relay.d.lock = recorder.lock
    assert result["result"] == "accepted", result
    assert taken == [(1, 0)] * (4 + 1), taken  # 4 chunks and phase C, all inside the gate


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


def test_gate_takes_the_workspace_mutex_before_a_semaphore_slot():
    """Review O10: two publications to one workspace queued first must not hold both slots (the
    second waits on its mutex without a slot), so another workspace still gets in."""
    gate = checkpoints.Gate(2)
    inside = []

    async def run():
        release = asyncio.Event()

        async def one(ws, tag):
            async with gate.enter(ws):
                inside.append(tag)
                await release.wait()

        tasks = [asyncio.create_task(one(ws, tag)) for ws, tag in [("a", 1), ("a", 2), ("b", 3)]]
        for _ in range(20):
            await asyncio.sleep(0)
        assert sorted(inside) == [1, 3], inside
        release.set()
        await asyncio.gather(*tasks)

    asyncio.run(run())


def test_gate_admits_by_heads_in_flight_in_arrival_order():
    """F4: besides the width, the sum of reserved heads stays under the cap; a publication larger
    than the cap runs alone; admission is first come, first served (a big waiter is not starved)."""
    gate = checkpoints.Gate(2, heads=10)
    inside = []

    async def run():
        events = {}

        async def one(ws, weight):
            events[ws] = asyncio.Event()
            async with gate.enter(ws, weight):
                inside.append(ws)
                await events[ws].wait()
                inside.remove(ws)

        async def settle():
            for _ in range(20):
                await asyncio.sleep(0)

        tasks = [asyncio.create_task(one("a", 6))]
        await settle()
        tasks.append(asyncio.create_task(one("b", 6)))  # 12 > 10: waits
        await settle()
        tasks.append(asyncio.create_task(one("c", 1)))  # would fit, but b came first
        await settle()
        assert inside == ["a"] and gate.heads == 6
        events["a"].set()
        await settle()
        assert sorted(inside) == ["b", "c"] and gate.heads == 7
        tasks.append(asyncio.create_task(one("d", 50)))  # above the cap: alone
        await settle()
        events["b"].set()
        events["c"].set()
        await settle()
        assert inside == ["d"] and gate.heads == 50
        events["d"].set()
        await asyncio.gather(*tasks)

    asyncio.run(run())
    assert gate.heads == 0 and gate.active == 0


def test_publication_width_and_heads_cap_come_from_the_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("ORCH_RELAY_PUBLISH_WIDTH", "1")
    monkeypatch.setenv("ORCH_RELAY_PUBLISH_HEADS", "1234")
    with TestClient(create_app(tmp_path)) as client:
        gate = client.app.state.checkpoints.gate
        assert (gate.width, gate.cap) == (1, 1234)


def test_publication_reserves_its_staged_heads_and_reweighs_an_underestimate(relay, monkeypatch):
    body, _ = append(relay, 300, 100)
    seen = []
    relay.cps.hooks["phase_a"] = lambda **kw: seen.append(relay.cps.gate.heads)
    assert put(relay.client, body)["result"] == "accepted"
    assert len(seen) == 1 and 300 <= seen[0] < 400, seen  # estimated from the staged bytes


def test_an_underestimated_publication_reweighs_before_folding(relay, monkeypatch):
    seen = []
    relay.cps.hooks["phase_a"] = lambda **kw: seen.append(relay.cps.gate.heads)
    body, _ = append(relay, 200, 100, "u")
    monkeypatch.setattr(checkpoints.Checkpoints, "weigh", lambda self, ws, pre: 0)
    assert put(relay.client, body)["result"] == "accepted"
    assert seen == [0, 200], seen  # phase A stopped at the manifest and re-entered with 200


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
    waited = len(entered) == 1  # the second waits on the workspace mutex, not in phase A
    release.set()
    assert waited, entered
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
    cps.settle(WS, memos["two"])
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
    # F2: phase A's fold work is recorded even though `fenced` is never charged.
    assert sql(relay.path, "SELECT heads FROM checkpoint_refused_heads") == [(40,)]
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


def test_staging_replaced_between_a_and_c_is_judged_on_the_live_set(relay):
    """Phase A's folds are keyed by page digest: a set re-staged under the same key with other
    pages misses them, and phase C folds the live pages (here: refused, as the live path is)."""
    body, _ = append(relay, 40, 20)

    def replace(**kw):
        sql(relay.path, "DELETE FROM checkpoint_staging WHERE workspace_id=?", (WS,))
        bad = [C.digest(f"FAKE bad {i}".encode()) for i in range(40)]
        stage(relay.path, relay.first, body["checkpoint"], [page("workspace", relay.tip, bad)])

    relay.cps.hooks["before_c"] = replace
    assert put(relay.client, body) == {"status": 409, "error": "chain_diverged"}
    assert failures(relay.path) == 1
    spent = sql(relay.path, "SELECT heads FROM checkpoint_refused_heads")
    assert spent == [(80,)]  # phase A's 40 and phase C's live 40


def test_an_unused_page_staged_between_a_and_c_is_refused(relay):
    """Review O13: the set is re-staged with the same pages plus one unused page (of a log the
    target does not name): phase C reuses every fold and still refuses the unused page."""
    body, _ = append(relay, 40, 20)
    pages = []
    cursor = relay.tip
    heads = [C.digest(f"FAKE a {i}".encode()) for i in range(40)]
    for k in (0, 20):
        pages.append(page("workspace", cursor, heads[k : k + 20]))
        cursor = entry(heads[k : k + 20], cursor["acc"], cursor["seq"])
    pages.append(page("01" + "1" * 24, C.EMPTY, [C.digest(b"FAKE unused")]))
    folds = []

    def restage(**kw):
        sql(relay.path, "DELETE FROM checkpoint_staging WHERE workspace_id=?", (WS,))
        stage(relay.path, relay.first, body["checkpoint"], pages)

    relay.cps.hooks["before_c"] = restage
    relay.cps.hooks["restart"] = lambda **kw: folds.append("restart")
    assert put(relay.client, body) == {"status": 409, "error": "chain_diverged"}
    assert folds == []


def test_a_refusal_after_folds_is_answered_by_phase_c_as_by_the_live_path(relay):
    """The workspace log folds and passes its genesis root check on phase A's new nodes, then a
    new ticket's signed entry disagrees with its proof. Phase C (no phase B ran) answers the
    same chain_diverged: it reads phase A's nodes for the root check."""
    ticket = "01" + "0" * 24
    heads = [C.digest(f"FAKE ticket {i}".encode()) for i in range(3)]
    body, _ = append(relay, 30, 30, tickets={ticket: (heads, entry(heads[:2]))})
    memos = []
    relay.cps.hooks["after_a"] = lambda **kw: memos.append(kw["memo"].accepted)
    assert put(relay.client, body) == {"status": 409, "error": "chain_diverged"}
    assert memos == [False] and node_count(relay.path) == 4  # nothing inserted


def test_phase_b_skips_nodes_another_publication_stored(relay):
    """Two targets over the same pages, phases interleaved without the mutex: the second's phase
    B finds every node stored (idempotent inserts) and orphans nothing."""
    cps = relay.cps
    one, _ = append(relay, 30, 10, "same")
    two, _ = append(relay, 30, 10, "same", at="2026-09-21T13:46:41Z")
    params, runs = {"ws": WS}, []
    for body in (one, two):
        raw = P.cj(body)
        prepared = cps.prepare(
            "checkpoint_put", WS, raw, cps.preauthorize("checkpoint_put", WS, LOWER)
        )
        runs.append((raw, prepared, cps.phase_a(WS, LOWER, raw, prepared)))
    before = usage(relay.path)
    for k, (raw, prepared, memo) in enumerate(runs):
        cps.phase_b(WS, LOWER, memo)
        assert memo.inserted == (30 if k == 0 else 0)
        try:
            cps.phase_c(params, LOWER, raw, prepared, memo)
        except checkpoints.Refusal as exc:
            assert k == 1 and exc.code == "chain_diverged"
        cps.settle(WS, memo)
    assert usage(relay.path) == (before[0] + 30, before[1])


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
        elif change == "member_removed":
            device, _ = signer_of()
            con.execute("DELETE FROM members WHERE workspace_id=? AND device_id=?", (WS, device))
        else:
            other = P.b64u(bytes.fromhex(V["keys"]["wsk_b.sig"]["pub"]))
            con.execute("UPDATE workspaces SET wsk_pub=? WHERE workspace_id=?", (other, WS))


@pytest.mark.parametrize(
    "change,expect",
    [
        ("signer_revoked", (409, "restore_not_owner")),
        ("chain_pair_added", (409, "restore_missing_revocation")),
        ("delegation_changed", (409, "restore_not_owner")),
        ("member_removed", (409, "restore_not_owner")),
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
    memo = cps.phase_a(WS, LOWER, raw, pre)
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
    commit an acceptance resting on phase A's folds; it restarts from phase A (round 2)."""
    body, heads = append(relay, 30, 10)
    rounds = []

    def forget(**kw):
        rounds.append(kw["memo"].accepted)
        if len(rounds) == 1:
            kw["memo"].accepted = False

    relay.cps.hooks["after_a"] = forget
    assert put(relay.client, body)["result"] == "accepted"
    assert rounds == [True, True]
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


# --- review round 2: F1 restarts, F2 work on every refusal, F3 snapshots, F6 settle -------------


def publisher_lock(relay, monkeypatch):
    """Record Directory.lock holds and log_acc calls made under it by the publishing thread."""
    recorder = Recorder(relay.d.lock)
    real = checkpoints.log_acc

    def counted(acc, head):
        if recorder.lock._is_owned():
            recorder.folds += 1
        return real(acc, head)

    monkeypatch.setattr(checkpoints, "log_acc", counted)
    relay.d.lock = recorder
    return recorder


def at_after(ms):
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(ms // 1000 + 1)) + "Z"


@pytest.mark.parametrize("trigger", ["clock_edge", "staging_completed"])
def test_phase_c_restarts_instead_of_folding_a_set_under_the_lock(relay, monkeypatch, trigger):
    """F1: phase A refuses before any fold (checkpoint_time, staging_incomplete), live state then
    lets the publication through: phase C must not fold the set under the lock (above
    LIVE_FOLD_LIMIT); it restarts from phase A, which folds outside the lock."""
    count = checkpoints.LIVE_FOLD_LIMIT + 1_000
    clock = {"now": NOW}
    relay.d.clock = lambda: clock["now"]
    at = at_after(NOW + 300_000) if trigger == "clock_edge" else None
    body, heads = append(relay, count, count // 2, at=at)
    rounds, hold = [], {}
    if trigger == "clock_edge":

        def after_a(**kw):
            rounds.append(kw["memo"].accepted)
            clock["now"] = NOW + 2_000  # the A -> C window: `at` is now within five minutes

    else:
        h = C.checkpoint_hash(body["checkpoint"])
        hold["page"] = sql(
            relay.path,
            "SELECT i, body FROM checkpoint_staging_pages WHERE target=? ORDER BY i DESC",
            (h,),
        )[0]
        sql(
            relay.path,
            "DELETE FROM checkpoint_staging_pages WHERE target=? AND i=?",
            (h, hold["page"][0]),
        )

        def after_a(**kw):
            rounds.append(kw["memo"].accepted)
            if len(rounds) == 1:  # the last page lands between phase A and phase C
                sql(
                    relay.path,
                    "INSERT INTO checkpoint_staging_pages SELECT workspace_id,source,target,?,? "
                    "FROM checkpoint_staging WHERE target=?",
                    (*hold["page"], h),
                )

    relay.cps.hooks["after_a"] = after_a
    recorder = publisher_lock(relay, monkeypatch)
    began = time.perf_counter()
    result = put(relay.client, body)
    wall = time.perf_counter() - began
    relay.d.lock = recorder.lock
    assert result["result"] == "accepted", result
    assert rounds == [False, True], rounds
    assert recorder.folds <= checkpoints.LIVE_FOLD_LIMIT
    assert max(held for _, held in recorder.holds) <= 0.5 * wall, (recorder.holds, wall)
    assert proof(relay, body) == heads


def test_phase_c_restarts_after_an_owner_policy_change_between_a_and_c(tmp_path, monkeypatch):
    """F1, owner policy: phase A refuses restore_not_owner (the signer is not a list member), the
    member row is back before phase C. With LIVE_FOLD_LIMIT 0 no live fold is allowed under the
    lock: phase C restarts and round 2 is accepted on phase A's folds."""
    from test_checkpoints import signer_of

    monkeypatch.setattr(checkpoints, "LIVE_FOLD_LIMIT", 0)
    restore = case(RESTORE)
    with TestClient(create_app(tmp_path)) as client:
        path = tmp_path / db.DB_NAME
        replay(client, path, restore, upto=2)
        step = restore["steps"][2]
        device, _ = signer_of()
        row = sql(path, "SELECT * FROM members WHERE workspace_id=? AND device_id=?", (WS, device))
        sql(path, "DELETE FROM members WHERE workspace_id=? AND device_id=?", (WS, device))
        cps, rounds = client.app.state.checkpoints, []

        def after_a(**kw):
            rounds.append(kw["memo"].accepted)
            if len(rounds) == 1:
                sql(path, "INSERT INTO members VALUES (?,?,?,?)", tuple(row[0]))

        cps.hooks["after_a"] = after_a
        d = client.app.state.directory
        recorder = Recorder(d.lock)
        real = checkpoints.log_acc

        def counted(acc, head):
            if recorder.lock._is_owned():
                recorder.folds += 1
            return real(acc, head)

        monkeypatch.setattr(checkpoints, "log_acc", counted)
        d.lock = recorder
        r = client.put(URL, content=P.cj(step["input"]["body"]), headers=HOST)
        d.lock = recorder.lock
        assert r.json() == {k: v for k, v in step["expect"].items() if k != "status"}, r.text
        assert rounds == [False, True] and recorder.folds == 0


def test_restarts_end_in_a_retryable_uncharged_503(relay, monkeypatch):
    """F1: a publication whose phase C keeps needing live folds restarts at most twice, then is
    answered 503 overloaded with Retry-After, uncharged, nothing published."""
    count = checkpoints.LIVE_FOLD_LIMIT + 1_000
    body, _ = append(relay, count, count // 2)
    h = C.checkpoint_hash(body["checkpoint"])
    last = sql(
        relay.path,
        "SELECT i, body FROM checkpoint_staging_pages WHERE target=? ORDER BY i DESC",
        (h,),
    )[0]

    def drop(**kw):
        sql(relay.path, "DELETE FROM checkpoint_staging_pages WHERE target=? AND i=?", (h, last[0]))

    def add(**kw):
        sql(
            relay.path,
            "INSERT INTO checkpoint_staging_pages SELECT workspace_id,source,target,?,? "
            "FROM checkpoint_staging WHERE target=?",
            (*last, h),
        )

    drop()
    restarts = []
    relay.cps.hooks.update(after_a=add, restart=lambda **kw: restarts.append(1) or drop())
    before = published(relay.path)
    recorder = publisher_lock(relay, monkeypatch)
    r = relay.client.put(URL, content=P.cj(body), headers=HOST)
    relay.d.lock = recorder.lock
    assert (r.status_code, r.json()) == (503, {"error": "overloaded"}), r.text
    assert r.headers["retry-after"] == "1"
    assert len(restarts) == 2
    assert recorder.folds <= checkpoints.PUBLISH_ROUNDS * checkpoints.LIVE_FOLD_LIMIT
    assert published(relay.path) == before and failures(relay.path) == 0


def test_a_database_error_in_phase_a_retries_phase_a(relay, monkeypatch):
    """F1: an sqlite3.Error in phase A never falls back to folding under the lock."""
    import sqlite3

    body, heads = append(relay, 3_000, 1_500)
    real, calls = checkpoints.Checkpoints.phase_a, []

    def flaky(self, *args, **kwargs):
        calls.append(1)
        if len(calls) == 1:
            raise sqlite3.OperationalError("FAKE database is locked")
        return real(self, *args, **kwargs)

    monkeypatch.setattr(checkpoints.Checkpoints, "phase_a", flaky)
    recorder = publisher_lock(relay, monkeypatch)
    result = put(relay.client, body)
    relay.d.lock = recorder.lock
    assert result["result"] == "accepted" and len(calls) == 2 and recorder.folds == 0
    assert proof(relay, body) == heads


def test_self_takeover_records_phase_a_work_every_round(relay):
    """F2: a holder taking over its own workspace while its publication is in phase A is answered
    `fenced` (uncharged), but the heads phase A folded are recorded every round."""
    body, _ = append(relay, 2_000, 1_000, wrong=True)
    gen = [1]

    def after_a(**kw):
        r = relay.client.post(
            f"/v2/workspaces/{WS}/host/hold", json={"gen": None, "take_over": True}, headers=HOST
        )
        assert r.status_code == 200, r.text
        gen[0] = r.json()["gen"]

    relay.cps.hooks["after_a"] = after_a
    for _ in range(4):
        assert put(relay.client, body, {**HOST, "Orch-Holder": str(gen[0])}) == {
            "status": 409,
            "error": "fenced",
        }
    spent = sql(relay.path, "SELECT coalesce(sum(heads),0) FROM checkpoint_refused_heads")
    assert spent[0][0] == 8_000 and failures(relay.path) == 0


def test_phase_a_ends_its_read_snapshot_between_folds(relay, monkeypatch):
    """F3: phase A re-opens its WAL read snapshot every A_SNAPSHOT_HEADS folded heads, so a full
    checkpoint (TRUNCATE) can complete while it runs (no long reader starves the WAL)."""
    import sqlite3

    monkeypatch.setattr(checkpoints, "A_SNAPSHOT_HEADS", 10)
    body, _ = append(relay, 40, 10)
    results = []

    def refresh(**kw):
        sql(
            relay.path,
            "UPDATE holders SET lease_until_ms=lease_until_ms WHERE workspace_id=?",
            (WS,),
        )
        con = sqlite3.connect(relay.path, timeout=0)
        try:
            results.append(con.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0])
        finally:
            con.close()

    relay.cps.hooks["refresh"] = refresh
    assert put(relay.client, body)["result"] == "accepted"
    assert len(results) >= 3 and results == [0] * len(results), results  # busy == 0 every time


def test_a_settle_error_does_not_replace_the_refusal(relay, monkeypatch):
    """F6: accounting after the answer is best effort; a database error there is logged."""
    import sqlite3

    body, _ = append(relay, 40, 20)
    relay.cps.hooks["before_c"] = lambda **kw: sql(
        relay.path, "DELETE FROM checkpoint_staging WHERE workspace_id=?", (WS,)
    )

    def broken(*args, **kwargs):
        raise sqlite3.OperationalError("FAKE disk I/O error")

    monkeypatch.setattr(checkpoints.Checkpoints, "account", broken)
    assert put(relay.client, body) == {"status": 409, "error": "staging_incomplete"}


def test_every_rounds_work_and_nodes_are_recorded_when_restarts_end_in_503(relay):
    """Security re-check of the budgets: each round's phase A folds the whole set and phase B
    stores it; phase C restarts every time (the set is swapped for a larger, different one just
    before phase C). The final 503 records the heads of all three rounds and the round-1 nodes
    as orphans: restarts never make fold work or node inserts free."""
    count = checkpoints.LIVE_FOLD_LIMIT + 1_000
    body, _ = append(relay, count, count)
    h = C.checkpoint_hash(body["checkpoint"])
    original = sql(relay.path, "SELECT i, body FROM checkpoint_staging_pages WHERE target=?", (h,))
    other = [C.digest(f"FAKE swap {i}".encode()) for i in range(count)]
    swapped = P.cj(page("workspace", relay.tip, other))
    before = usage(relay.path)

    def swap(body_bytes):
        sql(
            relay.path, "UPDATE checkpoint_staging_pages SET body=? WHERE target=?", (body_bytes, h)
        )
        d = P.parse_json(body_bytes)
        slot = {k: d[k] for k in ("kind", "log", "after_seq", "digest")} | {"i": 0, "count": count}
        sql(
            relay.path,
            "UPDATE checkpoint_staging SET manifest=? WHERE target=?",
            (P.cj({"pages": [slot]}), h),
        )

    relay.cps.hooks.update(
        before_c=lambda **kw: swap(swapped), restart=lambda **kw: swap(original[0][1])
    )
    r = relay.client.put(URL, content=P.cj(body), headers=HOST)
    assert (r.status_code, r.json()) == (503, {"error": "overloaded"}), r.text
    spent = sql(relay.path, "SELECT coalesce(sum(heads),0) FROM checkpoint_refused_heads")
    assert spent[0][0] == 3 * count and failures(relay.path) == 0
    assert usage(relay.path) == (before[0] + count, before[1] + count)
