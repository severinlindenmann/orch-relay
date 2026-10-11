"""G4 production checkpoint relay: costs, isolation and budgets beyond the shared vectors."""

import time
from contextlib import closing

import pytest

from orch_relay import db
from orch_relay.checkpoints import EMPTY, ZERO, Nodes, digest

WS = "705d40abbb8c1c90354a1acaa94c935c"
HISTORY = 20_000


@pytest.fixture(scope="module")
def history(tmp_path_factory):
    """One workspace log of HISTORY nodes, built through the production insert path."""
    path = tmp_path_factory.mktemp("history") / db.DB_NAME
    db.migrate(path)
    heads = [digest(f"FAKE history head {i}".encode()) for i in range(HISTORY)]
    with closing(db.connect(path)) as con, con:
        end = Nodes(con, WS, "workspace").extend(EMPTY, heads)
    accs = [ZERO]
    with closing(db.connect(path)) as con:
        nodes = Nodes(con, WS, "workspace")
        acc = end["acc"]
        while acc != ZERO:  # the test's own O(N) oracle walk, once
            node = nodes.get(acc)
            accs.append(acc)
            acc = node["prev_acc"]
    accs = [ZERO] + accs[1:][::-1]  # accs[s] is the acc at seq s
    return path, heads, end, accs


def vm_steps(path, fn):
    """SQLite virtual-machine steps (in units of 64) spent by fn on a fresh, cold-cache reader."""
    with closing(db.connect(path)) as con:
        steps = [0]

        def tick():
            steps[0] += 1
            return 0

        con.set_progress_handler(tick, 64)
        fn(Nodes(con, WS, "workspace"))
        con.set_progress_handler(None, 0)
        return steps[0]


def test_proof_page_cost_is_independent_of_position(history):
    # G4 precondition (a), protocol-v2 §19.8 detail 6: a page costs O(limit + log N), so a page
    # near the end of a long history costs what a page near the start costs.
    path, heads, end, accs = history
    limit = 64
    pages = {}
    for start in (10, HISTORY // 2, HISTORY - 200):

        def page(nodes, start=start):
            pages[start] = nodes.page(accs[start], end["acc"], limit)

        cost = vm_steps(path, page)
        assert pages[start] == (heads[start : start + limit], accs[start + limit])
        pages[start] = cost
    cheapest = min(pages.values())
    # Tight: a prev_acc walk from E costs about 20 000 node lookups for the first page.
    assert max(pages.values()) <= 2 * cheapest + 50, pages
    assert max(pages.values()) <= 1500, pages


def test_full_device_walk_from_acc_zero_is_linear(history):
    # The device walk reads a restored log from acc_0 (§19.8 step 3): paging the whole history
    # must cost O(N) overall, not O(N^2 / limit).
    path, heads, end, accs = history
    limit = 1000
    out = []

    def walk(nodes):
        start = ZERO
        while True:
            got, nxt = nodes.page(start, end["acc"], limit)
            out.extend(got)
            if nxt is None:
                return
            start = nxt

    total = vm_steps(path, walk)
    first = vm_steps(path, lambda nodes: nodes.page(ZERO, end["acc"], limit))
    last = vm_steps(path, lambda nodes: nodes.page(accs[HISTORY - limit], end["acc"], limit))
    assert out == heads
    assert last <= 2 * first + 50, (first, last)
    assert total <= (HISTORY // limit) * 2 * max(first, last), (total, first, last)


def test_proof_page_wall_clock_near_end_matches_near_start(history):
    path, _heads, end, accs = history
    with closing(db.connect(path)) as con:
        timings = []
        for start in (1, HISTORY - 100):
            began = time.perf_counter()
            for _ in range(20):
                Nodes(con, WS, "workspace").page(accs[start], end["acc"], 16)
            timings.append(time.perf_counter() - began)
    assert timings[1] < 0.5 and timings[0] < 0.5, timings


def test_proof_source_must_be_on_the_endpoint_branch(history, tmp_path):
    path, heads, end, accs = history
    with closing(db.connect(path)) as con, con:
        nodes = Nodes(con, WS, "workspace")
        fork = nodes.extend(
            {"seq": 100, "head": heads[99], "acc": accs[100]}, [digest(b"FAKE fork")]
        )
        from orch_relay.directory import Refusal

        with pytest.raises(Refusal) as refused:
            nodes.page(fork["acc"], end["acc"], 10)
        assert refused.value.code == "not_found"
        with pytest.raises(Refusal):
            nodes.page(accs[200], fork["acc"], 10)
        con.rollback()
