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


# --- P3-D29: a person first known from self-certified restore evidence gains no account powers ---


def publish_self_certified_restore(client, path):
    """Accepted H(n=1); a workspace restore whose evidence revokes a device of a person the relay
    has no account for (the intruder key, review A/B); returns that person's id."""
    from checkpoint_support import CORPUS, http, seed

    from ref import checkpoints as C

    cs = {c["name"]: c for c in CORPUS["suites"]["2"]["checkpoints"]["cases"]}
    accepted = cs["B1_unknown_device_self_certifying"]["state"]
    after = cs["B1_self_certified_registers_globally"]["state"]
    t = after["transitions"][0]
    target = after["checkpoints"][t["target_hash"]]["checkpoint"]
    nodes = accepted["nodes"]["workspace"]
    by_seq = {n["seq"]: n for n in nodes.values()}
    page = {
        "kind": "abandoned",
        "log": "workspace",
        "after_seq": 2,
        "from_acc": by_seq[2]["acc"],
        "heads": [by_seq[3]["head"], by_seq[4]["head"]],
    }
    page["digest"] = C.page_digest(page)
    seed(path, accepted, cs["B1_self_certified_registers_globally"])
    client.app.state.directory.clock = lambda: 1790000000000
    host = {"Authorization": "Bearer FAKE-workspace", "Orch-Holder": "1"}
    base = f"/v2/workspaces/{WS}/staging/{t['source_hash']}/{t['target_hash']}"
    assert http(client, "PUT", base + "/pages/0", host, body=page)["status"] == 200
    manifest = {"pages": [C.descriptor(0, page)]}
    assert http(client, "PUT", base + "/manifest", host, body=manifest)["complete"] is True
    bundle = {k: t[k] for k in ("line", "cert", "authz", "log")}
    body = {"checkpoint": target, "source_hash": t["source_hash"], "restore": bundle}
    result = http(client, "PUT", f"/v2/workspaces/{WS}/checkpoint", host, body=body)
    assert result["result"] == "accepted", result
    return t["line"]["revocations"][0]["revocation"]["o"]["person_id"]


def test_evidence_only_person_cannot_register_devices_or_cards(tmp_path):
    from directory_support import V, sign, signed
    from fastapi.testclient import TestClient

    from orch_relay import proto as P
    from orch_relay.app import create_app

    with TestClient(create_app(tmp_path)) as client:
        path = tmp_path / db.DB_NAME
        person = publish_self_certified_restore(client, path)
        with closing(db.connect(path)) as con:
            assert con.execute(
                "SELECT 1 FROM evidence_persons WHERE person_id=?", (person,)
            ).fetchone()
            assert con.execute(
                "SELECT reason FROM revocations WHERE person_id=?", (person,)
            ).fetchone()
        # A fresh device certified by the intruder's PK: without the guard this registers a live
        # device for a person who never redeemed an invite.
        fresh = signed(
            {**V["certs"]["signed"]["primary"]["o"], "person_id": person}, "intruder.sig"
        )
        r = client.put(f"/v2/devices/{fresh['o']['device_id']}", json={"cert": fresh})
        assert (r.status_code, r.json()) == (403, {"error": "other_person"}), r.text
        # Redeeming an invite turns the evidence-only row into the person's account.
        from orch_relay.directory import digest as hexdigest

        with closing(db.connect(path)) as con, con:
            con.execute(
                "INSERT INTO invites(code_hash,expires_ms) VALUES (?,?)",
                (hexdigest(b"FAKE-invite-q"), 1790000100000),
            )
        client.app.state.directory.origin = "https://relay.example"
        challenge = client.post("/v2/session/challenge", json={}).json()["challenge"]
        pk = P.b64u(bytes.fromhex(V["keys"]["intruder.sig"]["pub"]))
        sig = sign(
            "primary.sig",
            P.auth_bytes(
                "https://relay.example", P.unb64u(challenge), "device", fresh["o"]["device_id"]
            ),
        )
        r = client.post(
            "/v2/accounts",
            json={
                "invite": "FAKE-invite-q",
                "pk_pub": pk,
                "device_cert": fresh,
                "challenge": challenge,
                "sig": sig,
            },
        )
        assert (r.status_code, r.json()) == (200, {"person_id": person}), r.text
        with closing(db.connect(path)) as con:
            assert not con.execute("SELECT 1 FROM evidence_persons").fetchone()


@pytest.mark.parametrize("manifest_first", [False, True])
def test_staging_page_put_cost_does_not_grow_with_staged_pages(tmp_path, manifest_first):
    # Many small pages must not make each PUT re-read the whole set or the manifest (O(n^2)).
    from orch_relay import proto as P
    from orch_relay.checkpoints import Relay, descriptor, page_digest

    path = tmp_path / db.DB_NAME
    db.migrate(path)
    target = digest(b"FAKE target")
    costs = {}
    with closing(db.connect(path)) as con, con:
        relay = Relay(None, con, WS, 1790000000000)
        pages = []
        for i in range(1200):
            page = {
                "kind": "appended",
                "log": "workspace",
                "after_seq": i,
                "from_acc": ZERO,
                "heads": [digest(f"FAKE staged {i}".encode())],
            }
            page["digest"] = page_digest(page)
            pages.append(page)
        if manifest_first:
            manifest = {"pages": [descriptor(i, p) for i, p in enumerate(pages)]}
            relay.put_staging(None, target, None, manifest, P.cj(manifest), 1 << 40)
        for i, page in enumerate(pages):
            wire = P.cj(page)
            steps = [0]

            def tick(steps=steps):
                steps[0] += 1
                return 0

            con.set_progress_handler(tick, 16)
            relay.put_staging(None, target, i, page, wire, 1 << 40)
            con.set_progress_handler(None, 0)
            costs[i] = steps[0]
    assert costs[1199] <= 2 * costs[5] + 20, (costs[5], costs[1199])


# --- G4 precondition (c): the deployment-wide staged-bytes ceiling ------------------------------


def stage_page(relay, target, i, cap):
    from orch_relay import proto as P
    from orch_relay.checkpoints import page_digest

    page = {
        "kind": "appended",
        "log": "workspace",
        "after_seq": 0,
        "from_acc": ZERO,
        "heads": [digest(f"FAKE global {i}".encode())],
    }
    page["digest"] = page_digest(page)
    wire = P.cj(page)
    return relay.put_staging(None, target, 0, page, wire, cap), len(wire)


def test_global_staging_ceiling_refuses_across_workspaces_without_eviction(tmp_path):
    from orch_relay.checkpoints import HOUR, Relay
    from orch_relay.directory import Refusal

    path = tmp_path / db.DB_NAME
    db.migrate(path)
    now = 1790000000000
    other = "282193f85af5b8d07610fbb3a8448857"
    with closing(db.connect(path)) as con, con:
        _, size = stage_page(Relay(None, con, WS, now), digest(b"FAKE a"), 0, 1 << 40)
        cap = 2 * size
        stage_page(Relay(None, con, other, now), digest(b"FAKE b"), 1, cap)
        # A third workspace-scoped quota would allow it; the deployment ceiling does not.
        with pytest.raises(Refusal) as refused:
            stage_page(Relay(None, con, other, now), digest(b"FAKE c"), 2, cap)
        assert (refused.value.code, refused.value.status) == ("overloaded", 503)
        rows = con.execute("SELECT workspace_id, bytes FROM checkpoint_staging").fetchall()
    with closing(db.connect(path)) as con, con:
        # Nothing was evicted, and an expired set no longer counts against the ceiling.
        assert sorted(rows) == sorted(
            con.execute("SELECT workspace_id, bytes FROM checkpoint_staging")
        )
        later = Relay(None, con, other, now + HOUR)
        later.purge()
        Relay(None, con, WS, now + HOUR).purge()
        stage_page(Relay(None, con, other, now + HOUR), digest(b"FAKE c"), 2, cap)


def test_global_staging_ceiling_over_http_is_503_with_retry_after(tmp_path):
    from checkpoint_support import CORPUS, seed
    from fastapi.testclient import TestClient

    from orch_relay.app import create_app
    from orch_relay.checkpoints import page_digest

    case = next(
        c
        for c in CORPUS["suites"]["2"]["checkpoints"]["cases"]
        if c["name"] == "staging_immutable_page_and_manifest"
    )
    with TestClient(create_app(tmp_path)) as client:
        path = tmp_path / db.DB_NAME
        seed(path, case["state"], case)
        client.app.state.directory.clock = lambda: 1790000000000
        client.app.state.checkpoints.global_stage_cap = 10
        page = {
            "kind": "appended",
            "log": "workspace",
            "after_seq": 0,
            "from_acc": ZERO,
            "heads": [digest(b"FAKE over the ceiling")],
        }
        page["digest"] = page_digest(page)
        url = f"/v2/workspaces/{WS}/staging/null/{digest(b'FAKE t')}/pages/0"
        r = client.put(
            url,
            content=__import__("json").dumps(page),
            headers={
                "Authorization": "Bearer FAKE-workspace",
                "Orch-Holder": "1",
                "Content-Type": "application/json",
            },
        )
        assert (r.status_code, r.json()) == (503, {"error": "overloaded"}), r.text
        assert int(r.headers["retry-after"]) >= 1
        with closing(db.connect(path)) as con:
            assert not con.execute("SELECT 1 FROM checkpoint_staging").fetchone()


# --- G4 precondition (b): cross-workspace isolation side effects -------------------------------


def test_workspace_b_cannot_touch_workspace_a_objects(tmp_path):
    from checkpoint_support import WS_B, find, http, replay, seed, step
    from fastapi.testclient import TestClient

    from orch_relay.app import create_app

    a = find({"section": "checkpoints_g4", "name": "isolation_workspace_a"})
    b = find({"section": "checkpoints_g4", "name": "isolation_workspace_b"})
    with TestClient(create_app(tmp_path)) as client:
        path = tmp_path / db.DB_NAME
        replay(client, path, a)
        seed(path, b["state"], b, ws=WS_B)

        def rows(con):
            return {
                t: sorted(con.execute(f"SELECT * FROM {t} WHERE workspace_id=?", (WS,)))
                for t in (
                    "checkpoint_baselines",
                    "checkpoint_staging",
                    "checkpoint_staging_pages",
                    "checkpoints",
                    "log_nodes",
                )
            }

        with closing(db.connect(path)) as con:
            before = rows(con)
        for s in b["steps"]:
            assert step(client, path, s["input"], b, ws=WS_B) == s["expect"]
        with closing(db.connect(path)) as con:
            assert rows(con) == before  # B's no-op DELETE and its own staging set left A as it was
            assert (
                con.execute(
                    "SELECT count(*) FROM checkpoint_staging WHERE workspace_id=?", (WS_B,)
                ).fetchone()[0]
                == 1
            )
        # B's W token is not eligible for A even with A's current holder generation.
        h = a["steps"][0]["input"]["body"]["hash"]
        r = http(
            client,
            "DELETE",
            f"/v2/workspaces/{WS}/baselines/{h}",
            {"Authorization": "Bearer FAKE-workspace-b", "Orch-Holder": "1"},
        )
        assert r == {"status": 403, "error": "not_eligible"}


# --- W(g) is the workspace session only; quotas count real bytes -----------------------------------


@pytest.mark.parametrize(
    "fixture", ["genesis", "staging_page", "staging_manifest", "baseline_post", "checkpoint_put"]
)
def test_member_device_cannot_use_w_routes_even_with_the_holder_generation(tmp_path, fixture):
    import json
    from pathlib import Path

    from checkpoint_support import prepare_fixture
    from fastapi.testclient import TestClient

    from orch_relay import proto as P
    from orch_relay.app import create_app

    cases = json.loads(Path(f"tests/http_fixtures/{fixture}.json").read_text())["cases"]
    success = cases[0]
    with TestClient(create_app(tmp_path)) as client:
        path = tmp_path / db.DB_NAME
        prepare_fixture(client, path, success, success)
        with closing(db.connect(path)) as con, con:  # the phone is a member with operate
            con.execute(
                "UPDATE members SET scopes=? WHERE device_id=?",
                (P.cj(["look", "decide", "operate"]), "4177b27d8e4ac182e8d388b247d2b136"),
            )
        request = success["request"]
        headers = {**request["headers"], "Authorization": "Bearer FAKE-device"}
        r = client.request(
            request["method"],
            request["path"],
            params=request["query"],
            headers=headers,
            content=P.cj(request["json"]),
        )
        assert (r.status_code, r.json()) == (403, {"error": "not_eligible"}), r.text


def test_staging_byte_quota_counts_pages_and_manifest_and_retries_are_free(tmp_path, monkeypatch):
    from orch_relay import checkpoints
    from orch_relay import proto as P
    from orch_relay.checkpoints import Relay, descriptor, page_digest
    from orch_relay.directory import Refusal

    path = tmp_path / db.DB_NAME
    db.migrate(path)
    page = {
        "kind": "appended",
        "log": "workspace",
        "after_seq": 0,
        "from_acc": ZERO,
        "heads": [digest(b"FAKE quota")],
    }
    page["digest"] = page_digest(page)
    wire = P.cj(page)
    manifest = {"pages": [descriptor(0, page)]}
    target = digest(b"FAKE quota target")
    monkeypatch.setattr(checkpoints, "STAGE_CAP", len(wire) + len(P.cj(manifest)) - 1)
    with closing(db.connect(path)) as con, con:
        relay = Relay(None, con, WS, 1790000000000)
        relay.put_staging(None, target, 0, page, wire, 1 << 40)
        relay.put_staging(None, target, 0, page, wire, 1 << 40)  # identical retry: not charged
        with pytest.raises(Refusal) as refused:
            relay.put_staging(None, target, None, manifest, P.cj(manifest), 1 << 40)
        assert (refused.value.code, refused.value.status) == ("quota_exceeded", 429)
        assert con.execute("SELECT bytes, manifest FROM checkpoint_staging").fetchone() == (
            len(wire),
            None,
        )
        other = digest(b"FAKE quota other")
        with pytest.raises(Refusal):  # a second set shares the same workspace bytes
            relay.put_staging(None, other, 0, page, wire, 1 << 40)


# --- review R1: a many-ticket publication folds each staged descriptor once ---------------------


def many_ticket_publication(tmp_path, tickets, refused):
    """Seed the pinned state, stage a first publication of `tickets` ticket logs (one page each)
    through the production staging code, and run the publication; returns (relay, seconds)."""
    from checkpoint_support import CORPUS, seed
    from directory_support import V

    from orch_relay import proto as P
    from orch_relay.checkpoints import EMPTY as E
    from orch_relay.checkpoints import Relay, checkpoint_hash, descriptor, log_acc, page_digest
    from orch_relay.directory import Refusal
    from ref import orch_protocol_ref as R

    case = next(
        c
        for c in CORPUS["suites"]["2"]["checkpoints"]["cases"]
        if c["name"] == "first_checkpoint_full_proof"
    )
    path = tmp_path / db.DB_NAME
    db.migrate(path)
    seed(path, case["state"], case)
    root = case["state"]["genesis"]["pin"]["o"]["genesis"]

    def entry(head):
        return {"seq": 1, "head": head, "acc": log_acc(ZERO, head)}

    pages = []
    o = {
        "v": 2,
        "suite": 2,
        "kind": "workspace_checkpoint",
        "workspace_id": WS,
        "genesis": root,
        "n": 1,
        "at": "2026-09-21T13:46:40Z",
        "workspace_log": entry(root),
        "tickets": {},
    }
    for log, head in [("workspace", root)] + [
        (f"01{t:024d}", digest(f"FAKE r1 {t}".encode())) for t in range(tickets)
    ]:
        if log != "workspace":
            o["tickets"][log] = entry(head)
        page = {"kind": "appended", "log": log, "after_seq": 0, "from_acc": ZERO, "heads": [head]}
        page["digest"] = page_digest(page)
        pages.append(page)
    if refused:  # the last ticket's signed entry disagrees with its proof: refused after all work
        o["tickets"][log] = entry(digest(b"FAKE wrong"))
    target = R.sign_object(
        R.SUITES[2], R.SUITES[2].sig_key(bytes.fromhex(V["keys"]["wsk_a.sig"]["seed"])), o
    )
    h = checkpoint_hash(target)
    pages.sort(key=lambda p: (p["kind"], p["log"], p["after_seq"]))
    with closing(db.connect(path)) as con, con:
        relay = Relay(None, con, WS, 1790000000000)
        for i, page in enumerate(pages):
            relay.put_staging(None, h, i, page, P.cj(page), 1 << 40)
        manifest = {"pages": [descriptor(i, p) for i, p in enumerate(pages)]}
        relay.put_staging(None, h, None, manifest, P.cj(manifest), 1 << 40)
        relay = Relay(None, con, WS, 1790000000000)
        began = time.perf_counter()
        try:
            result = relay.publish({"checkpoint": target, "source_hash": None}, 1)
            assert result["result"] == "accepted"
            assert not refused
        except Refusal as exc:
            assert refused and exc.code == "chain_diverged"
        took = time.perf_counter() - began
        con.rollback()
    assert E["seq"] == 0
    return relay, took, len(pages)


@pytest.mark.parametrize("refused", [False, True])
def test_many_ticket_publication_work_is_linear_in_staged_pages(tmp_path, refused):
    small, small_s, small_pages = many_ticket_publication(tmp_path / "s", 250, refused)
    large, large_s, large_pages = many_ticket_publication(tmp_path / "l", 2000, refused)
    # Each staged descriptor is folded at most once; scanning the manifest per log costs
    # tickets x pages (2000 tickets: ~4M visits, seconds under the global lock).
    assert small.visits <= small_pages and large.visits <= large_pages, (small.visits, large.visits)
    # 8x the tickets: linear is ~8x the time, the quadratic scan ~64x.
    assert large_s <= 24 * small_s + 0.05, (small_s, large_s)
