"""P3-D31 production pins beyond the shared vectors: authorization first, budgets, snapshots,
wakeups, page cost and the publication hints (tests/test_checkpoint_vectors.py replays the group)."""

import os
import threading
from contextlib import closing

import pytest
from checkpoint_support import WS, WS_B, cases, http, replay, seed
from fastapi.testclient import TestClient

from orch_relay import db
from orch_relay import proto as P
from orch_relay import unpublished as U
from orch_relay.app import create_app
from orch_relay.directory import token_hash

NOW = 1790000000000
CASE = {c["name"]: c for c in cases("unpublished")}
GET = f"/v2/workspaces/{WS}/unpublished"
ACK = GET + "/ack"


def host(gen=1):
    return {"Authorization": "Bearer FAKE-workspace", "Orch-Holder": str(gen)}


@pytest.fixture
def relay(tmp_path):
    """Workspace A with two items: (laptop, alice, lost) at cursor 1, (bob_phone, bob, lost) at 2."""
    case = CASE["ack_is_not_publication"]
    with TestClient(create_app(tmp_path)) as client:
        seed(tmp_path / db.DB_NAME, case["state"], case)
        client.app.state.directory.clock = lambda: NOW
        yield client


def sql(client, statement, args=()):
    with closing(db.connect(client.app.state.directory.path)) as con, con:
        return con.execute(statement, args).fetchall()


def ack(client, c, headers=None):
    headers = host() if headers is None else headers
    return http(client, "POST", ACK, headers, body={"cursor": U.token(WS, c)})


# --- authorization first: no lock, no write transaction, no window, no oracle --------------------


class Spy:
    """Counts directory.lock acquisitions and write-connection requests (BEGIN IMMEDIATE)."""

    def __init__(self, client, monkeypatch):
        self.locks, self.writes = 0, 0
        d, bridge = client.app.state.directory, client.app.state.bridge
        real_lock, real_connection = d.lock, bridge.connection
        spy = self

        class Lock:
            def __enter__(self):
                spy.locks += 1
                return real_lock.__enter__()

            def __exit__(self, *exc):
                return real_lock.__exit__(*exc)

            def __getattr__(self, name):
                return getattr(real_lock, name)

        def connection(purpose):
            if purpose == "write":
                spy.writes += 1
            return real_connection(purpose)

        monkeypatch.setattr(d, "lock", Lock())
        monkeypatch.setattr(bridge, "connection", connection)


REFUSED = [
    ("unauthenticated", {}, 401, "unauthenticated"),
    ("device_session", {"Authorization": "Bearer FAKE-device", "Orch-Holder": "1"}, 403, None),
    (
        "other_workspace_host",
        {"Authorization": "Bearer FAKE-workspace-b", "Orch-Holder": "1"},
        403,
        None,
    ),
    ("missing_holder", {"Authorization": "Bearer FAKE-workspace"}, 409, "fenced"),
    ("stale_holder", host(0), 409, "fenced"),
    ("expired_lease", host(1), 409, "fenced"),
]


@pytest.mark.parametrize("method", ["GET", "POST"])
@pytest.mark.parametrize("name,headers,status,code", REFUSED, ids=[r[0] for r in REFUSED])
def test_refusals_before_authorization_take_no_lock_write_or_window(
    relay, monkeypatch, method, name, headers, status, code
):
    if name == "other_workspace_host":
        sql(
            relay,
            "INSERT INTO workspaces SELECT ?,owner_person_id,wsk_pub,delegation,card,card_seq,"
            "wxk_version,client_hosted FROM workspaces WHERE workspace_id=?",
            (WS_B, WS),
        )
        sql(relay, "INSERT INTO holders VALUES (?,1,?,0,NULL)", (WS_B, NOW + 40_000))
        sql(
            relay,
            "INSERT INTO sessions VALUES (?,?,?,?)",
            (token_hash("FAKE-workspace-b"), "workspace", WS_B, NOW + 900_000),
        )
    if name == "expired_lease":
        sql(relay, "UPDATE holders SET lease_until_ms=? WHERE workspace_id=?", (NOW, WS))
    # The bridge sweep runs every second on its own task and takes the lock and a write transaction: on a slow CI
    # runner the 200 requests below outlast a tick and the spy would count it (orch-relay#91).
    monkeypatch.setattr(relay.app.state.bridge, "sweep", lambda: None)
    spy = Spy(relay, monkeypatch)
    budget = relay.app.state.checkpoints.budget
    for _ in range(200):  # far beyond every window: refusals are never charged
        if method == "GET":
            result = http(relay, "GET", GET, headers, {"cursor": U.token(WS, 0)})
        else:
            result = ack(relay, 2, headers)
        assert result == {"status": status, "error": code or "not_eligible"}
    assert (spy.locks, spy.writes) == (0, 0)
    assert budget.windows == {}
    assert sql(relay, "SELECT * FROM unpublished_acks") == []


@pytest.mark.parametrize("method", ["GET", "POST"])
def test_no_oracle_for_unknown_workspaces(relay, method):
    """403 for a W session of another workspace and 401 without a session, identical whether the
    path's workspace exists or not: nothing on the route answers 404."""
    sql(
        relay,
        "INSERT INTO workspaces SELECT ?,owner_person_id,wsk_pub,delegation,card,card_seq,"
        "wxk_version,client_hosted FROM workspaces WHERE workspace_id=?",
        (WS_B, WS),
    )
    sql(
        relay,
        "INSERT INTO sessions VALUES (?,?,?,?)",
        (token_hash("FAKE-workspace-b"), "workspace", WS_B, NOW + 900_000),
    )
    other = {"Authorization": "Bearer FAKE-workspace-b", "Orch-Holder": "1"}
    for ws in (WS, "ab" * 16):
        path = f"/v2/workspaces/{ws}/unpublished" + ("/ack" if method == "POST" else "")
        body = {"cursor": U.token(ws, 0)} if method == "POST" else None
        assert http(relay, method, path, other, body=body) == {
            "status": 403,
            "error": "not_eligible",
        }
        assert http(relay, method, path, {}, body=body) == {
            "status": 401,
            "error": "unauthenticated",
        }


# --- budgets -----------------------------------------------------------------------------------


def test_fetch_minute_window(relay):
    for _ in range(120):
        assert http(relay, "GET", GET, host())["status"] == 200
    r = relay.get(GET, headers=host())
    assert (r.status_code, r.json()) == (429, {"error": "rate_limited"})
    assert int(r.headers["retry-after"]) >= 1
    assert ack(relay, 2)["status"] == 200  # the ack has its own window


def test_fetch_hour_window(relay):
    budget = relay.app.state.checkpoints.budget
    end = (NOW // U.HOUR + 1) * U.HOUR
    budget.windows[("unpublished-get", WS, U.HOUR)] = (end, 2000)
    assert http(relay, "GET", GET, host()) == {"status": 429, "error": "rate_limited"}
    budget.windows[("unpublished-get", WS, U.HOUR)] = (end, 1999)
    assert http(relay, "GET", GET, host())["status"] == 200


def test_ack_window(relay):
    for _ in range(30):
        assert ack(relay, 1)["status"] == 200
    assert ack(relay, 1) == {"status": 429, "error": "rate_limited"}
    assert http(relay, "GET", GET, host())["status"] == 200


def test_malformed_requests_are_charged(relay):
    for _ in range(120):
        assert http(relay, "GET", GET, host(), {"limit": "0"})["status"] == 400
    assert http(relay, "GET", GET, host()) == {"status": 429, "error": "rate_limited"}


# --- reads are reads -----------------------------------------------------------------------------


def dump(client):
    with closing(db.connect(client.app.state.directory.path)) as con:
        return list(con.iterdump())


def test_fetch_is_query_only_and_writes_nothing(relay, monkeypatch):
    seen = []
    real = U.page

    def page(con, ws, query):
        seen.append(con.execute("PRAGMA query_only").fetchone()[0])
        return real(con, ws, query)

    monkeypatch.setattr(U, "page", page)
    before = dump(relay)
    first = http(relay, "GET", GET, host(), {"limit": "1"})
    http(relay, "GET", GET, host(), {"cursor": first["cursor"]})
    http(relay, "GET", GET, host(), {"cursor": U.token(WS, 99)})
    assert seen == [1, 1, 1] and dump(relay) == before


def test_a_page_is_one_snapshot(relay, monkeypatch):
    """A restore or intake committing while a page is read is not half-visible: the page is the
    state before it, and the next read sees it at its new cursor."""
    real = U.rows
    path = relay.app.state.directory.path

    def rows(con, ws, after, limit):
        # A concurrent commit between the position check and the item read.
        with closing(db.connect(path)) as other, other:
            other.execute("UPDATE revocations SET cursor=3 WHERE cursor=1")
        return real(con, ws, after, limit)

    monkeypatch.setattr(U, "rows", rows)
    page = http(relay, "GET", GET, host())
    assert [i["provenance"]["cursor"] for i in page["items"]] == [1, 2]
    monkeypatch.setattr(U, "rows", real)
    assert [i["provenance"]["cursor"] for i in http(relay, "GET", GET, host())["items"]] == [2, 3]


# --- page cost: the view reads this workspace's ever-devices, never the relay-wide table ----------


def test_page_cost_does_not_grow_with_the_global_revocation_table(tmp_path):
    path = tmp_path / db.DB_NAME
    db.migrate(path)
    person = "11" * 16
    with closing(db.connect(path)) as con, con:
        con.execute("INSERT INTO accounts VALUES (?,?,0)", (person, "pk"))
        for i in range(U.MAX_EVER_DEVICES):
            device = f"{i:032x}"
            con.execute(
                "INSERT INTO devices VALUES (?,?,?,?,?,?,?)",
                (device, person, b"{}", "s", "k", b"[]", None),
            )
            con.execute("INSERT INTO ever_devices VALUES (?,?,1)", (WS, device))
        con.execute(
            "INSERT INTO revocations VALUES (?,?,?,?,0,1)",
            (f"{7:032x}", person, b'{"o":{}}', "lost"),
        )

    def cost():
        with closing(db.connect(path)) as con:
            steps = [0]

            def tick():
                steps[0] += 1
                return 0

            con.set_progress_handler(tick, 64)
            assert len(U.page(con, WS, {})["items"]) == 1
            U.notice(con, WS)
            return steps[0]

    small = cost()
    with closing(db.connect(path)) as con, con:
        con.executemany(
            "INSERT INTO revocations VALUES (?,?,?,?,?,?)",
            (
                (os.urandom(16).hex(), os.urandom(16).hex(), os.urandom(300), "lost", 0, i)
                for i in range(2, 20_002)
            ),
        )
    large = cost()
    assert large <= small * 1.1 + 50, (small, large)


# --- wakeups and the notice --------------------------------------------------------------------


def poll(client, first=True, token="FAKE-poll"):
    bridge = client.app.state.bridge
    headers = {k.lower(): v for k, v in host().items()}
    return bridge.transaction(
        "host_poll", {"ws": WS}, "GET", b"", {"after": "0"}, headers, "testclient", token, first
    )


def test_notice_wakes_once_per_intake_and_once_after_the_ack(relay):
    woken = []
    relay.app.state.directory.changed = lambda *keys: woken.append(keys)
    result, ready = poll(relay)
    assert ready and result["notices"]["unpublished"] == U.token(WS, 2)
    assert poll(relay)[1] is False  # delivered: never repeated
    assert ack(relay, 2)["status"] == 200 and woken == [(("ws", WS),)]
    result, ready = poll(relay)
    assert ready and result["notices"]["unpublished"] is None
    assert ack(relay, 1)["acked"] == U.token(WS, 2) and woken == [(("ws", WS),)]  # a no-op
    assert poll(relay)[1] is False
    record = CASE["ack_is_not_publication"]["steps"][5]["input"]["body"]
    assert http(relay, "POST", "/v2/revocations", {}, body=record)["status"] == 200
    assert ("ws", WS) in woken[-1]
    result, ready = poll(relay)
    assert ready and result["notices"]["unpublished"] == U.token(WS, 3)
    assert poll(relay)[1] is False


# --- the publication's hints ----------------------------------------------------------------------


def test_every_publication_ref_is_served_and_nothing_is_stored(tmp_path):
    """U10/I3: each unpublished_refs entry of an accepted publication is an item of the next
    fetch from the start; checkpoint_unpublished is no longer written."""
    checked = 0
    for name, case in CASE.items():
        publishes = [i for i, s in enumerate(case["steps"]) if s["input"]["op"] == "publish"]
        for index in publishes:
            with TestClient(create_app(tmp_path / name / str(index))) as client:
                path = tmp_path / name / str(index) / db.DB_NAME
                result = replay(client, path, case, upto=index + 1)[-1]
                page = http(client, "GET", GET, host())
                served = {(i["device_id"], i["person_id"]): i["provenance"] for i in page["items"]}
                for ref in result.get("unpublished_refs", []):
                    key = (ref["device_id"], ref["person_id"])
                    assert served[key] == {"cursor": ref["cursor"], "digest": ref["digest"]}
                    checked += 1
                with closing(db.connect(path)) as con:
                    assert con.execute(
                        "SELECT count(*) FROM checkpoint_unpublished"
                    ).fetchone() == (0,)
    assert checked >= 5


def test_a_registry_row_of_an_evidence_only_person_is_not_eligible(relay):
    """Pre-0010 residue (P3-D29): a G2 ever-device whose registry person is evidence-only is no
    association. Its pair is neither served nor noticed nor reported."""
    laptop = CASE["ack_is_not_publication"]["steps"][0]["expect"]["items"][0]
    sql(relay, "INSERT INTO evidence_persons VALUES (?)", (laptop["person_id"],))
    page = http(relay, "GET", GET, host())
    assert laptop["device_id"] not in {i["device_id"] for i in page["items"]}
    assert len(page["items"]) == 1
    with closing(db.connect(relay.app.state.directory.path)) as con:
        assert U.notice(con, WS) == U.token(WS, 2)
    sql(relay, "DELETE FROM revocations WHERE person_id<>?", (laptop["person_id"],))
    with closing(db.connect(relay.app.state.directory.path)) as con:
        assert U.notice(con, WS) is None


def test_ack_raises_are_serialized(relay):
    """Concurrent acks leave the maximum (monotonic under the lock)."""
    results = []
    checkpoints = relay.app.state.checkpoints
    headers = {k.lower(): v for k, v in host().items()}

    def send(c):
        results.append(checkpoints.unpublished_ack(WS, headers, P.cj({"cursor": U.token(WS, c)})))

    threads = [threading.Thread(target=send, args=(c,)) for c in (2, 1, 0, 2, 1)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert len(results) == 5
    assert sql(relay, "SELECT cursor, gen FROM unpublished_acks") == [(2, 1)]


def test_ack_is_bound_to_the_workspace_not_the_generation(relay):
    assert ack(relay, 1)["acked"] == U.token(WS, 1)
    sql(relay, "UPDATE holders SET gen=2 WHERE workspace_id=?", (WS,))
    assert ack(relay, 1, host(1)) == {"status": 409, "error": "fenced"}
    assert ack(relay, 0, host(2))["acked"] == U.token(WS, 1)  # a new holder inherits the mark
    page = http(relay, "GET", GET, host(2), {"cursor": U.token(WS, 1)})
    assert [i["provenance"]["cursor"] for i in page["items"]] == [2]


def test_the_ack_body_cap_is_one_kibibyte(relay):
    body = P.cj({"cursor": "A" * (U.ACK_CAP - 13)})
    assert len(body) == U.ACK_CAP
    r = relay.post(ACK, content=body + b" ", headers={**host(), "Content-Type": "application/json"})
    assert (r.status_code, r.json()) == (413, {"error": "too_large"})
    r = relay.post(ACK, content=body, headers={**host(), "Content-Type": "application/json"})
    assert (r.status_code, r.json()) == (400, {"error": "malformed"})


def test_membership_publication_bounds_ever_devices(tmp_path):
    """U13: at most 4096 ever-devices per workspace (a page costs O(|ever_devices|)); a list that
    would add the 4097th is refused 429 quota_exceeded and changes nothing."""
    from members_support import BODY, HEADERS, load_state, snapshot

    members = [m["device_id"] for m in BODY["member_list"]["o"]["members"]]
    for spare, status in ((0, 200), (-1, 429)):  # spare -1: one ever-device too many
        with TestClient(create_app(tmp_path / str(status))) as client:
            d = client.app.state.directory
            load_state(d)
            with closing(db.connect(d.path)) as con, con:
                known = {r[0] for r in con.execute("SELECT device_id FROM ever_devices")}
                fresh = len(set(members) - known)
                room = U.MAX_EVER_DEVICES - len(known) - fresh - spare
                con.executemany(
                    "INSERT INTO ever_devices VALUES (?,?,1)",
                    [(WS, f"{i:032x}") for i in range(room)],
                )
            before = snapshot(d)
            r = client.put(f"/v2/workspaces/{WS}/membership", content=P.cj(BODY), headers=HEADERS)
            assert r.status_code == status, r.text
            if status == 429:
                assert r.json() == {"error": "quota_exceeded"} and snapshot(d) == before
            else:
                assert len(sql(client, "SELECT * FROM ever_devices")) == U.MAX_EVER_DEVICES


def test_the_first_item_is_always_served(relay, monkeypatch):
    """A page never comes back empty while items exist after the position, even when one item
    alone exceeds the byte bound (the host's walk would otherwise never advance)."""
    monkeypatch.setattr(U, "PAGE_BYTES", 100)
    first = http(relay, "GET", GET, host())
    assert len(first["items"]) == 1 and first["more"]
    rest = http(relay, "GET", GET, host(), {"cursor": first["cursor"]})
    assert len(rest["items"]) == 1 and not rest["more"]


# --- review of PR #55: cross-workspace isolation (RC1), retired chain (S1), in-lock auth (S2),
# --- per-workspace windows and the quota's fresh-device count (S3) ------------------------------


def items(client):
    return {(i["device_id"], i["person_id"]): i for i in http(client, "GET", GET, host())["items"]}


def test_another_workspaces_chain_never_retires_an_item(relay):
    before = items(relay)
    (d, p) = next(iter(before))
    sql(
        relay,
        "INSERT INTO checkpoint_revocations VALUES (?,?,?,?,?,?,?,?,?)",
        (WS_B, d, p, "compromised", b"{}", b"{}", "pk", "r", "t"),
    )
    assert items(relay) == before


def test_another_workspaces_ever_device_is_never_served(relay):
    before = items(relay)
    (d, p) = next(iter(before))
    # Move the ever-device to workspace B only: A must stop serving it.
    sql(
        relay,
        "UPDATE ever_devices SET workspace_id=? WHERE workspace_id=? AND device_id=?",
        (WS_B, WS, d),
    )
    after = items(relay)
    assert (d, p) not in after and len(after) == len(before) - 1
    with closing(db.connect(relay.app.state.directory.path)) as con:
        assert U.notice(con, WS) is not None


def test_retired_chain_upgraded_to_compromised_is_an_item(relay):
    before = items(relay)
    (d, p) = next(iter(before))
    sql(
        relay,
        "INSERT INTO checkpoint_revocations VALUES (?,?,?,?,?,?,?,?,?)",
        (WS, d, p, "retired", b"{}", b"{}", "pk", "r", "t"),
    )
    assert (d, p) not in items(relay)  # global lost == chain retired: equal strength
    sql(
        relay,
        "UPDATE revocations SET reason='compromised' WHERE device_id=? AND person_id=?",
        (d, p),
    )
    assert items(relay)[(d, p)]["chain_reason"] == "retired"


def workspace_b(client):
    sql(
        client,
        "INSERT INTO workspaces SELECT ?,owner_person_id,wsk_pub,delegation,card,card_seq,"
        "wxk_version,client_hosted FROM workspaces WHERE workspace_id=?",
        (WS_B, WS),
    )
    sql(client, "INSERT INTO holders VALUES (?,1,?,0,NULL)", (WS_B, NOW + 40_000))
    sql(
        client,
        "INSERT INTO sessions VALUES (?,?,?,?)",
        (token_hash("FAKE-workspace-b"), "workspace", WS_B, NOW + 900_000),
    )
    return {"Authorization": "Bearer FAKE-workspace-b", "Orch-Holder": "1"}


@pytest.mark.parametrize("name,headers,status,code", REFUSED, ids=[r[0] for r in REFUSED])
def test_ack_authorizes_under_the_lock_when_the_pre_check_is_unavailable(
    relay, monkeypatch, name, headers, status, code
):
    """On the sqlite3.Error fallback the transaction's re-authorization is the only one: every
    refusal still holds and writes nothing; an authorized ack then succeeds."""
    import sqlite3

    from orch_relay import checkpoints

    if name == "other_workspace_host":
        workspace_b(relay)
    if name == "expired_lease":
        sql(relay, "UPDATE holders SET lease_until_ms=? WHERE workspace_id=?", (NOW, WS))

    def unavailable(self, route, ws, headers):
        raise sqlite3.OperationalError("FAKE database is locked")

    monkeypatch.setattr(checkpoints.Checkpoints, "preauthorize", unavailable)
    assert ack(relay, 2, headers) == {"status": status, "error": code or "not_eligible"}
    assert sql(relay, "SELECT * FROM unpublished_acks") == []
    assert relay.app.state.checkpoints.budget.windows == {}
    if name != "expired_lease":
        assert ack(relay, 2)["acked"] == U.token(WS, 2)


def test_one_workspaces_fetch_window_never_spends_anothers(relay):
    other = workspace_b(relay)
    path = f"/v2/workspaces/{WS_B}/unpublished"
    for _ in range(120):
        assert http(relay, "GET", path, other)["status"] == 200
    assert http(relay, "GET", path, other) == {"status": 429, "error": "rate_limited"}
    assert http(relay, "GET", GET, host())["status"] == 200


def test_the_quota_counts_only_devices_new_to_the_workspace(tmp_path):
    """A list re-naming devices that are already ever-devices adds nothing to the count: at exactly
    4096 ever-devices, republishing the same members is accepted."""
    from members_support import BODY, HEADERS, load_state

    members = {m["device_id"] for m in BODY["member_list"]["o"]["members"]}
    with TestClient(create_app(tmp_path)) as client:
        d = client.app.state.directory
        load_state(d)
        with closing(db.connect(d.path)) as con, con:
            for did in members:
                con.execute("INSERT OR IGNORE INTO ever_devices VALUES (?,?,1)", (WS, did))
            known = con.execute("SELECT count(*) FROM ever_devices").fetchone()[0]
            con.executemany(
                "INSERT INTO ever_devices VALUES (?,?,1)",
                [(WS, f"{i:032x}") for i in range(U.MAX_EVER_DEVICES - known)],
            )
        r = client.put(f"/v2/workspaces/{WS}/membership", content=P.cj(BODY), headers=HEADERS)
        assert r.status_code == 200, r.text
        assert len(sql(client, "SELECT * FROM ever_devices")) == U.MAX_EVER_DEVICES
