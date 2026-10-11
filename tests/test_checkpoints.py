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
    assert timings[1] < 2 and timings[0] < 2, timings  # coarse; VM-step tests are exact


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


def evidence_person_card(person):
    """A valid first card for a new workspace whose owner is `person` (the intruder key)."""
    import hashlib

    from directory_support import CARD, V, signed

    from orch_relay import proto as P
    from ref import orch_protocol_ref as R

    ws = "00" * 15 + "07"
    delegation = signed(
        {**CARD["delegation"]["o"], "workspace_id": ws, "owner_person_id": person}, "intruder.sig"
    )
    o = {**CARD["o"], "workspace_id": ws, "owner_person_id": person}
    o["sealed_hash"] = P.b64u(hashlib.sha256(P.unb64u(CARD["sealed"])).digest())
    wsk = R.SUITES[2].sig_key(bytes.fromhex(V["keys"]["wsk_a.sig"]["seed"]))
    sig = R.b64u(R.SUITES[2].sign(wsk, P.L["sig_card_wsk"] + P.cj(o)))
    return {"o": o, "sig": sig, "delegation": delegation, "sealed": CARD["sealed"]}


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
        # Nor may it own a workspace: a first card whose delegation and owner are the intruder.
        card = evidence_person_card(person)
        r = client.put(f"/v2/workspaces/{card['o']['workspace_id']}/card", json={"card": card})
        assert (r.status_code, r.json()) == (403, {"error": "other_person"}), r.text
        # Nor join a list: a live device of the person (stored directly, as no route stores one)
        # is refused by membership's certificate check before any grant is sealed to it.
        from orch_relay.directory import Refusal
        from orch_relay.members import certificate

        with closing(db.connect(path)) as con:
            con.row_factory = __import__("sqlite3").Row
            client.app.state.directory.store_device(con, fresh)
            member = {"device_id": fresh["o"]["device_id"], "person_id": person, "scopes": ["look"]}
            with pytest.raises(Refusal) as refused:
                certificate(con, member, person, [], 1790000000000)
            assert refused.value.code == "other_person"
            con.rollback()
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
    # Coarse (timing on a shared machine); the visit count above is the exact bound.
    assert large_s <= 24 * max(small_s, 0.05), (small_s, large_s)


# --- transport refusals of PUT checkpoint: charged after W(g), capped by the window (review L1) ---


def test_transport_refusals_are_charged_only_after_auth_and_stop_at_the_budget(tmp_path):
    from checkpoint_support import CORPUS, seed
    from fastapi.testclient import TestClient

    from orch_relay.app import create_app
    from orch_relay.checkpoints import REQUEST_CAP

    case = next(
        c
        for c in CORPUS["suites"]["2"]["checkpoints"]["cases"]
        if c["name"] == "checkpoint_gone_all_endpoint_routes"
    )
    url = f"/v2/workspaces/{WS}/checkpoint"
    host = {
        "Authorization": "Bearer FAKE-workspace",
        "Orch-Holder": "1",
        "Content-Type": "application/json",
    }
    with TestClient(create_app(tmp_path)) as client:
        path = tmp_path / db.DB_NAME
        seed(path, case["state"], case)
        client.app.state.directory.clock = lambda: 1790000000000

        def failures():
            with closing(db.connect(path)) as con:
                return con.execute("SELECT count(*) FROM checkpoint_failures").fetchone()[0]

        big = b" " * (REQUEST_CAP + 1)
        for headers, charged in [
            (host, 1),
            ({k: v for k, v in host.items() if k != "Authorization"}, 1),  # 401: never charged
            ({**host, "Orch-Holder": "0"}, 1),  # fenced: never charged
            ({**host, "Content-Type": "text/plain"}, 2),  # malformed transport, authorized
        ]:
            r = client.put(
                url, content=big if headers is not host or charged == 1 else b"{}", headers=headers
            )
            assert r.status_code == 400, r.text
            assert failures() == charged, headers
        with closing(db.connect(path)) as con, con:
            con.executemany(
                "INSERT INTO checkpoint_failures VALUES (?,1,?)",
                [(WS, 1790000000000) for _ in range(14)],
            )
        for _ in range(3):  # the window is full: refused, but no further rows (L1)
            assert client.put(url, content=big, headers=host).status_code == 400
        assert failures() == 16


# --- review G2: stateless parsing and checks happen before the global lock ----------------------


class TimedLock:
    """directory.lock with the time it is held recorded (re-entrant like the real one)."""

    def __init__(self, lock):
        self.lock, self.depth, self.held, self.since = lock, 0, 0.0, 0.0

    def __enter__(self):
        self.lock.acquire()
        if self.depth == 0:
            self.since = time.perf_counter()
        self.depth += 1
        return self

    def __exit__(self, *exc):
        self.depth -= 1
        if self.depth == 0:
            self.held += time.perf_counter() - self.since
        self.lock.release()

    def _is_owned(self):
        return self.lock._is_owned()


@pytest.mark.parametrize("kind", ["page_bad_digest", "checkpoint_bad_signature"])
def test_large_stateless_refusals_do_not_hold_the_lock(tmp_path, kind):
    import json

    from checkpoint_support import CORPUS, seed
    from fastapi.testclient import TestClient

    from orch_relay import proto as P
    from orch_relay.app import create_app

    case = next(
        c
        for c in CORPUS["suites"]["2"]["checkpoints"]["cases"]
        if c["name"] == "checkpoint_gone_all_endpoint_routes"
    )
    host = {
        "Authorization": "Bearer FAKE-workspace",
        "Orch-Holder": "1",
        "Content-Type": "application/json",
    }
    with TestClient(create_app(tmp_path)) as client:
        path = tmp_path / db.DB_NAME
        seed(path, case["state"], case)
        d = client.app.state.directory
        d.clock = lambda: 1790000000000
        timed = TimedLock(d.lock)
        d.lock = timed
        if kind == "page_bad_digest":
            heads = [digest(f"FAKE g2 {i}".encode()) for i in range(55_000)]
            body = {
                "kind": "appended",
                "log": "workspace",
                "after_seq": 0,
                "from_acc": ZERO,
                "heads": heads,
                "digest": ZERO,
            }
            url = f"/v2/workspaces/{WS}/staging/null/{digest(b'FAKE g2')}/pages/0"
            expected = (400, {"error": "malformed"})
        else:
            held = case["state"]["held"]
            tickets = {f"01{t:024d}": held["o"]["workspace_log"] for t in range(9000)}
            cp = {"o": {**held["o"], "n": 2, "tickets": tickets}, "sig": held["sig"]}
            body = {"checkpoint": cp, "source_hash": None}
            url = f"/v2/workspaces/{WS}/checkpoint"
            expected = (401, {"error": "bad_signature"})
        raw = P.cj(body)
        began = time.perf_counter()
        r = client.put(url, content=raw, headers=host)
        wall = time.perf_counter() - began
        assert (r.status_code, r.json()) == expected, r.text
        assert len(raw) > 1_000_000 and json.loads(raw)
        # Parsing and validating megabytes happens outside; the transaction only looks up state.
        assert timed.held <= 0.25 * wall, (timed.held, wall)
        if kind == "checkpoint_bad_signature":  # still charged, inside the transaction
            with closing(db.connect(path)) as con:
                assert con.execute("SELECT count(*) FROM checkpoint_failures").fetchone()[0] == 1


def test_owner_check_fails_closed_when_the_revocation_lookup_errors(tmp_path, monkeypatch):
    # Review L2: a database error must not turn into "not revoked".
    import sqlite3

    from checkpoint_support import CORPUS, seed

    from orch_relay.checkpoints import Relay

    case = next(
        c
        for c in CORPUS["suites"]["2"]["checkpoints"]["cases"]
        if c["name"] == "workspace_restore_and_exact_retry"
    )
    path = tmp_path / db.DB_NAME
    db.migrate(path)
    seed(path, case["state"], case)
    bundle = case["steps"][2]["input"]["body"]["restore"]

    def broken(self, device):
        raise sqlite3.OperationalError("FAKE disk I/O error")

    monkeypatch.setattr(Relay, "revoked", broken)
    with closing(db.connect(path)) as con:
        relay = Relay(None, con, WS, 1790000000000)
        with pytest.raises(sqlite3.OperationalError):
            relay.owner(relay.workspace(), bundle["cert"], 1790000000000)


# --- per-workspace chain revocations and revocation.unpublished (F1 #387, orch-52; provisional) ---

LAPTOP = "146f7f5f8b446934e01b8bdee16426fa"
ALICE = "5c0574d08d9b869beaa7b630cc83893d"
BOB = "42f83168aabd846982483297b14e7301"


def revocation_of(person, reason, key, ms=1789990000000):
    from directory_support import signed

    return signed(
        {
            "v": 2,
            "suite": 2,
            "kind": "revocation",
            "person_id": person,
            "device_id": LAPTOP,
            "revoked_ms": ms,
            "reason": reason,
        },
        key,
    )


def run_case(tmp_path, name, prepare):
    """Seed a vector case, apply `prepare(con)` and replay its steps; the last step's result."""
    from checkpoint_support import CORPUS, seed, step
    from fastapi.testclient import TestClient

    from orch_relay.app import create_app

    case = next(c for c in CORPUS["suites"]["2"]["checkpoints"]["cases"] if c["name"] == name)
    with TestClient(create_app(tmp_path)) as client:
        path = tmp_path / db.DB_NAME
        seed(path, case["state"], case)
        with closing(db.connect(path)) as con, con:
            prepare(con)
        for s in case["steps"]:
            result = step(client, path, s["input"], case)
        with closing(db.connect(path)) as con:
            tables = {
                t: sorted(con.execute(f"SELECT * FROM {t}"))
                for t in ("checkpoint_revocations", "checkpoint_unpublished")
            }
        return result, tables


def global_revocation(con, person, reason, key, cert=None):
    from orch_relay import proto as P

    if cert is not None:
        o = cert["o"]
        con.execute(
            "INSERT OR IGNORE INTO devices VALUES (?,?,?,?,?,?,?)",
            (
                LAPTOP,
                person,
                P.cj(cert),
                o["dk_sig_pub"],
                o["dk_kx_pub"],
                P.cj(o["scopes_max"]),
                o["expires_ms"],
            ),
        )
    rev = revocation_of(person, reason, key)
    con.execute(
        "INSERT INTO revocations VALUES (?,?,?,?,?,"
        "(SELECT coalesce(max(cursor),0)+1 FROM revocations))",
        (LAPTOP, person, P.cj(rev), reason, 0),
    )


@pytest.mark.parametrize("where", ["g2_ever", "checkpoint_ever", "unknown"])
def test_out_of_band_revocation_is_never_demanded_and_reported_unpublished(tmp_path, where):
    # A revocation the relay holds globally (another workspace's restore, the §19.5 feed) is out of
    # band for this workspace: the restore that omits it is accepted, never restore_missing_revocation,
    # and a device this workspace knows is reported in `unpublished` with a reference.
    from directory_support import V

    def prepare(con):
        global_revocation(
            con, ALICE, "compromised", "person_alice.sig", V["certs"]["signed"]["laptop"]
        )
        if where == "g2_ever":  # a revoked former list member
            con.execute("INSERT INTO ever_devices VALUES (?,?,1)", (WS, LAPTOP))
        elif where == "checkpoint_ever":
            con.execute("INSERT INTO checkpoint_ever_devices VALUES (?,?)", (WS, LAPTOP))

    result, tables = run_case(tmp_path, "workspace_restore_and_exact_retry", prepare)
    assert result["status"] == 200 and result["result"] == "accepted", result
    if where == "unknown":  # unknown-device evidence is not forwarded
        assert "unpublished" not in result and tables["checkpoint_unpublished"] == []
    else:
        assert result["unpublished"] == ["d_" + LAPTOP]
        (ref,) = result["unpublished_refs"]
        assert (ref["device_id"], ref["person_id"], ref["reason"]) == (LAPTOP, ALICE, "compromised")
        (row,) = tables["checkpoint_unpublished"]
        assert row[3:6] == (LAPTOP, ALICE, "compromised") and row[6] == ref["cursor"]
    assert tables["checkpoint_revocations"] == []  # out of band never becomes a chain pair


def test_listed_weaker_than_held_out_of_band_is_unpublished(tmp_path):
    # A carried entry weaker than the relay's global revocation of that pair is accepted (it is not
    # this workspace's chain) and reported; the global row is not downgraded.
    from directory_support import V

    result, tables = run_case(
        tmp_path,
        "B1_evidence_sorted_pair",
        lambda con: global_revocation(
            con, ALICE, "compromised", "person_alice.sig", V["certs"]["signed"]["laptop"]
        ),
    )
    assert result["result"] == "accepted" and result["unpublished"] == ["d_" + LAPTOP], result
    chain = {(r[1], r[2]): r[3] for r in tables["checkpoint_revocations"]}
    assert chain[(LAPTOP, ALICE)] == "lost"


def test_completeness_is_per_device_and_person_pair(tmp_path):
    # Two chain pairs for one device: carrying alice's entry does not satisfy bob's pair.
    from directory_support import V, signed

    from orch_relay import proto as P

    bob_cert = signed({**V["certs"]["signed"]["laptop"]["o"], "person_id": BOB}, "person_bob.sig")
    bob_pk = P.b64u(bytes.fromhex(V["keys"]["person_bob.sig"]["pub"]))

    def prepare(con):
        con.execute(
            "INSERT INTO checkpoint_revocations VALUES (?,?,?,?,?,?,?,?,?)",
            (
                WS,
                LAPTOP,
                BOB,
                "lost",
                P.cj(revocation_of(BOB, "lost", "person_bob.sig")),
                P.cj(bob_cert),
                bob_pk,
                "seed",
                "seed",
            ),
        )

    result, _ = run_case(tmp_path, "B1_stronger", prepare)
    assert result == {"status": 409, "error": "restore_missing_revocation", "devices": [LAPTOP]}


def test_chain_pairs_are_monotonic_and_keep_their_first_evidence(tmp_path):
    from orch_relay import proto as P

    before = {}

    def prepare(con):
        before.update(
            {(r[1], r[2]): r for r in con.execute("SELECT * FROM checkpoint_revocations")}
        )

    # Same strength, other bytes: the stored pair keeps its reason, record and provenance.
    result, tables = run_case(tmp_path / "same", "B1_same_strength_other_bytes", prepare)
    assert result["result"] == "accepted"
    after = {(r[1], r[2]): r for r in tables["checkpoint_revocations"]}
    assert after[(LAPTOP, ALICE)] == before[(LAPTOP, ALICE)]
    # Stronger: upgraded, with the carrying restore as provenance; never deleted either way.
    result, tables = run_case(tmp_path / "stronger", "B1_stronger", lambda con: None)
    row = {(r[1], r[2]): r for r in tables["checkpoint_revocations"]}[(LAPTOP, ALICE)]
    assert row[3] == "compromised" and row[7] != "seed"
    assert P.parse_json(row[4])["o"]["reason"] == "compromised"


def test_ticket_restores_report_nothing_unpublished(tmp_path):
    from directory_support import V

    def prepare(con):
        global_revocation(
            con, ALICE, "compromised", "person_alice.sig", V["certs"]["signed"]["laptop"]
        )
        con.execute("INSERT INTO checkpoint_ever_devices VALUES (?,?)", (WS, LAPTOP))

    result, tables = run_case(tmp_path, "ticket_restore", prepare)
    assert result["result"] == "accepted" and "unpublished" not in result
    assert tables["checkpoint_unpublished"] == []


def test_unknown_device_cannot_be_self_certified_under_two_persons_in_one_restore(tmp_path):
    # With entries unique per (device, person), one restore could carry two self-certifying
    # entries for one unknown device: bob's own and alice's (her PK certifying bob's phone id).
    # Both would bind; the global row would then name bob with alice's record. Refused.
    import copy

    from checkpoint_support import CORPUS, http, seed
    from directory_support import V, signed
    from fastapi.testclient import TestClient

    from orch_relay import proto as P
    from orch_relay.app import create_app
    from ref import checkpoints as C
    from ref import orch_protocol_ref as R

    S = R.SUITES[2]

    def key(name):
        return S.sig_key(bytes.fromhex(V["keys"][name]["seed"]))

    case = next(
        c
        for c in CORPUS["suites"]["2"]["checkpoints"]["cases"]
        if c["name"] == "B1_unknown_device_self_certifying"
    )
    page = case["steps"][0]["input"]["body"]
    body = copy.deepcopy(case["steps"][2]["input"]["body"])
    line = body["restore"]["line"]
    (bob_item,) = line["revocations"]
    phone = bob_item["device_cert"]["o"]["device_id"]
    alice_cert = signed({**bob_item["device_cert"]["o"], "person_id": ALICE})
    alice_rev = signed({**bob_item["revocation"]["o"], "person_id": ALICE, "reason": "compromised"})
    alice_item = {
        "revocation": alice_rev,
        "device_cert": alice_cert,
        "pk_pub": P.b64u(bytes.fromhex(V["keys"]["person_alice.sig"]["pub"])),
    }
    line["revocations"] = sorted(
        [bob_item, alice_item], key=lambda e: (phone, e["revocation"]["o"]["person_id"])
    )
    ws = WS
    line["sig"] = R.b64u(S.sign(key("phone.sig"), C.event_bytes(S, line, ws, "workspace")))
    line["host_sig"] = R.b64u(
        S.sign(key("wsk_a.sig"), C.event_bytes(S, line, ws, "workspace", True))
    )
    t = body["checkpoint"]
    entry = t["o"]["workspace_log"]
    head = C.event_head(line)
    prev_acc = case["state"]["nodes"]["workspace"]
    acc2 = next(n["acc"] for n in prev_acc.values() if n["seq"] == 2)
    body["checkpoint"] = R.sign_object(
        S,
        key("wsk_a.sig"),
        {**t["o"], "workspace_log": {**entry, "head": head, "acc": C.log_acc(acc2, head)}},
    )
    target = C.checkpoint_hash(body["checkpoint"])
    host = {"Authorization": "Bearer FAKE-workspace", "Orch-Holder": "1"}
    with TestClient(create_app(tmp_path)) as client:
        path = tmp_path / db.DB_NAME
        seed(path, case["state"], case)
        client.app.state.directory.clock = lambda: 1790000000000
        base = f"/v2/workspaces/{WS}/staging/{body['source_hash']}/{target}"
        assert http(client, "PUT", base + "/pages/0", host, body=page)["status"] == 200
        manifest = {"pages": [C.descriptor(0, page)]}
        assert http(client, "PUT", base + "/manifest", host, body=manifest)["complete"]
        result = http(client, "PUT", f"/v2/workspaces/{WS}/checkpoint", host, body=body)
        assert result == {"status": 409, "error": "restore_invalid"}, result
        with closing(db.connect(path)) as con:
            assert not con.execute("SELECT 1 FROM devices WHERE device_id=?", (phone,)).fetchone()
