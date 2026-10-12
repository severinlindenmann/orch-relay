"""P3-D32 (G3 re-review D4): every directory route authorizes first, outside Directory.lock.

A refused request takes no Directory.lock and no write transaction (BEGIN IMMEDIATE), and is
charged only the windows today's order charges before refusing it. The transaction alone still
refuses everything with the same status and body (the pre-check is never load-bearing).
"""

import copy
import json
import threading
from contextlib import closing
from pathlib import Path

import pytest
from directory_support import (
    CARD,
    CERT,
    DEVICE,
    NOW,
    ORIGIN,
    PERSON,
    PK,
    PRIMARY,
    RECORD,
    WS,
    prepare_case,
    seed,
    sign,
    signed,
)
from fastapi.testclient import TestClient
from members_support import prepare_fixture

from orch_relay import db
from orch_relay import proto as P
from orch_relay.app import create_app
from orch_relay.directory import HOUR, MINUTE, token_hash

OTHER = "ab" * 16
STRANGER = "cd" * 16
UNKNOWN = "ef" * 16
DEV = {"Authorization": "Bearer FAKE-device"}
HOST = {"Authorization": "Bearer FAKE-workspace"}
BAD = {"Authorization": "Bearer nope"}
CHALLENGE = P.b64u(bytes(range(32)))


class Spy:
    """Counts Directory.lock acquisitions and write-connection requests (BEGIN IMMEDIATE)."""

    def __init__(self, d, monkeypatch):
        self.locks, self.writes = 0, 0
        real_lock, real_connection = d.lock, d.connection
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
        monkeypatch.setattr(d, "connection", connection)


def sql(d, statement, args=()):
    with closing(db.connect(d.path)) as con, con:
        con.execute(statement, args)


def card_for(ws, owner=None):
    card = copy.deepcopy(CARD)
    card["o"]["workspace_id"] = ws
    if owner:
        card["o"]["owner_person_id"] = owner
    card["delegation"] = signed({**card["delegation"]["o"], "workspace_id": ws})
    card["sig"] = sign("wsk_a.sig", P.L["sig_card_wsk"] + P.cj(card["o"]))
    return card


def login_body(key="phone.sig", origin=None):
    return {
        "challenge": CHALLENGE,
        "kind": "device",
        "id": DEVICE,
        "sig": sign(key, P.auth_bytes(origin, P.unb64u(CHALLENGE), "device", DEVICE))
        if origin
        else P.b64u(bytes(64)),
    }


def setup(d, name):
    """Scenario state on top of seed(d)."""
    d.add_challenge(CHALLENGE, NOW + MINUTE, "testclient", None)
    if name == "expired_session":
        sql(d, "UPDATE sessions SET expires_ms=?", (NOW,))
    if name in ("revoked", "login_revoked"):
        sql(
            d,
            "INSERT INTO revocations VALUES (?,?,?,?,?,?)",
            (DEVICE, PERSON, P.cj(RECORD), "lost", NOW, 1),
        )
    if name == "cert_expired":
        sql(d, "UPDATE devices SET expires_ms=?", (NOW,))
    if name == "card_window_full":
        d.windows[("card-address", "testclient", HOUR)] = (NOW + HOUR, 10)
    if name == "recovery_window_full":
        d.windows[("revocation-address", "testclient", MINUTE)] = (NOW + MINUTE, 10)


# (id, method, path, headers, body, status, error, windows charged by design)
REFUSED = [
    # Device or workspace session (members routes; W(g) writes are fenced).
    ("members_no_session", "GET", f"/v2/workspaces/{WS}/members", {}, None, 401, None, ()),
    ("members_bad_token", "GET", f"/v2/workspaces/{WS}/members", BAD, None, 401, None, ()),
    ("expired_session", "GET", f"/v2/workspaces/{WS}/members", DEV, None, 401, None, ()),
    ("revoked", "GET", f"/v2/workspaces/{WS}/members", DEV, None, 403, "revoked", ()),
    ("cert_expired", "GET", f"/v2/workspaces/{WS}/members", DEV, None, 400, "cert_expired", ()),
    ("members_other_host", "GET", f"/v2/workspaces/{OTHER}/members", HOST, None, 403, None, ()),
    ("members_non_member", "GET", f"/v2/workspaces/{OTHER}/members", DEV, None, 403, None, ()),
    ("members_bad_ident", "GET", "/v2/workspaces/zz/members", DEV, None, 400, "malformed", ()),
    ("members_query", "GET", f"/v2/workspaces/{WS}/members?x=1", DEV, None, 400, "malformed", ()),
    ("grants_host", "GET", f"/v2/workspaces/{WS}/grants", HOST, None, 403, None, ()),
    ("card_key_host", "GET", f"/v2/workspaces/{WS}/card-key?card_seq=1", HOST, None, 403, None, ()),
    ("membership_device", "PUT", f"/v2/workspaces/{WS}/membership", DEV, {}, 403, None, ()),
    ("membership_unfenced", "PUT", f"/v2/workspaces/{WS}/membership", HOST, {}, 409, "fenced", ()),
    (
        "membership_bad_holder",
        "PUT",
        f"/v2/workspaces/{WS}/membership",
        {**HOST, "Orch-Holder": "x"},
        {},
        400,
        "malformed",
        (),
    ),
    (
        "card_keys_stale",
        "PUT",
        f"/v2/workspaces/{WS}/card-keys",
        {**HOST, "Orch-Holder": "7"},
        {},
        409,
        "fenced",
        (),
    ),
    (
        "membership_content_type",
        "PUT",
        f"/v2/workspaces/{WS}/membership",
        {**HOST, "Content-Type": "text/plain"},
        "{}",
        400,
        "malformed",
        (),
    ),
    (
        "membership_bad_token_bad_body",  # the body is checked before authentication
        "PUT",
        f"/v2/workspaces/{WS}/membership",
        {**BAD, "Content-Type": "text/plain"},
        "{}",
        400,
        "malformed",
        (),
    ),
    # Person session (feed) and device reads.
    ("feed_no_session", "GET", f"/v2/persons/{PERSON}/revocations", {}, None, 401, None, ()),
    ("feed_other_person", "GET", f"/v2/persons/{STRANGER}/revocations", DEV, None, 403, None, ()),
    ("device_no_session", "GET", f"/v2/devices/{DEVICE}", {}, None, 401, None, ()),
    ("device_unknown", "GET", f"/v2/devices/{UNKNOWN}", DEV, None, 404, "not_found", ()),
    ("device_not_ever", "GET", f"/v2/devices/{PRIMARY}", HOST, None, 403, None, ()),
    ("card_no_session", "GET", f"/v2/workspaces/{WS}/card", {}, None, 401, None, ()),
    ("card_unknown", "GET", f"/v2/workspaces/{OTHER}/card", DEV, None, 404, "not_found", ()),
    # Card PUT: W(g) for a stored workspace, the owner's PK and windows for a new one.
    ("card_put_no_session", "PUT", f"/v2/workspaces/{WS}/card", {}, {"card": CARD}, 401, None, ()),
    (
        "card_put_unfenced",
        "PUT",
        f"/v2/workspaces/{WS}/card",
        HOST,
        {"card": CARD},
        409,
        "fenced",
        (),
    ),
    (
        "card_put_stranger_owner",
        "PUT",
        f"/v2/workspaces/{OTHER}/card",
        {},
        {"card": card_for(OTHER, STRANGER)},
        403,
        "other_person",
        (),
    ),
    (
        "card_window_full",
        "PUT",
        f"/v2/workspaces/{OTHER}/card",
        {},
        {"card": card_for(OTHER)},
        429,
        "rate_limited",
        (),
    ),
    # Unauthenticated by design: logout of nothing, login, accounts, recovery, public reads.
    ("logout_unknown", "POST", "/v2/session/logout", BAD, {}, 200, None, ()),
    ("logout_no_session", "POST", "/v2/session/logout", {}, {}, 200, None, ()),
    ("logout_malformed", "POST", "/v2/session/logout", BAD, {"x": 1}, 400, "malformed", ()),
    (
        "login_unknown_challenge",
        "POST",
        "/v2/session/login",
        {},
        {**login_body(), "challenge": P.b64u(bytes(32))},
        401,
        "unknown_challenge",
        (),
    ),
    ("login_malformed", "POST", "/v2/session/login", {}, [], 400, "malformed", ()),
    (
        "login_bad_signature",
        "POST",
        "/v2/session/login",
        {},
        login_body(),
        401,
        "bad_signature",
        (),
    ),
    (
        "login_revoked",
        "POST",
        "/v2/session/login",
        {},
        login_body("phone.sig", ORIGIN),
        403,
        "revoked",
        (),
    ),
    (
        "accounts_unknown_invite_and_challenge",
        "POST",
        "/v2/accounts",
        {},
        {
            "invite": "x",
            "pk_pub": "",
            "device_cert": {},
            "challenge": P.b64u(bytes(32)),
            "sig": "",
        },
        401,
        "unknown_challenge",
        (),
    ),
    (
        "accounts_unknown_invite",
        "POST",
        "/v2/accounts",
        {},
        {"invite": "x", "pk_pub": "", "device_cert": {}, "challenge": CHALLENGE, "sig": ""},
        403,
        "not_eligible",
        (),
    ),
    (
        "revocations_malformed",
        "POST",
        "/v2/revocations",
        {},
        {"x": 1},
        400,
        "malformed",
        ("revocation-address",),
    ),
    (
        "revocations_stranger",
        "POST",
        "/v2/revocations",
        {},
        {"record": {**RECORD, "o": {**RECORD["o"], "person_id": STRANGER}}},
        403,
        "other_person",
        ("revocation-address",),
    ),
    (
        "recovery_window_full",
        "POST",
        "/v2/revocations",
        {},
        {"record": RECORD},
        429,
        "rate_limited",
        (),
    ),
    (
        "device_put_bad_signature",
        "PUT",
        f"/v2/devices/{DEVICE}",
        {},
        {"cert": {**CERT, "sig": P.b64u(bytes(64))}},
        400,
        "cert_invalid",
        ("certificate-address",),
    ),
    (
        "revocation_read_unknown",
        "GET",
        f"/v2/devices/{UNKNOWN}/revocation",
        {},
        None,
        404,
        "not_found",
        ("revocation-read",),
    ),
    ("challenge", "POST", "/v2/session/challenge", {}, {}, 200, None, ("challenge",)),
    ("challenge_malformed", "POST", "/v2/session/challenge", {}, {"x": 1}, 400, "malformed", ()),
]


def send(c, method, path, headers, body):
    headers = dict(headers)
    if isinstance(body, str):
        return c.request(method, path, content=body, headers=headers)
    if body is not None:
        headers.setdefault("Content-Type", "application/json")
        return c.request(method, path, content=P.cj(body), headers=headers)
    return c.request(method, path, headers=headers)


def run(tmp_path, monkeypatch, case, precheck=True):
    name, method, path, headers, body, *_ = case
    with TestClient(create_app(tmp_path)) as c:
        d = c.app.state.directory
        seed(d)
        d.random = lambda n: bytes(n)
        setup(d, name)
        if not precheck:
            monkeypatch.setattr(d, "preauthorize", lambda *args: None)
        spy = Spy(d, monkeypatch)
        windows = dict(d.windows)
        r = send(c, method, path, headers, body)
        challenged = CHALLENGE in d.challenges
        return r, spy, windows, dict(d.windows), challenged


@pytest.mark.parametrize("case", REFUSED, ids=[c[0] for c in REFUSED])
def test_refused_directory_requests_take_no_lock_or_write(tmp_path, monkeypatch, case):
    _, _, _, _, _, status, error, charged = case
    r, spy, before, after, _ = run(tmp_path, monkeypatch, case)
    assert r.status_code == status, r.text
    if error or status != 200:
        assert r.json()["error"] == (error or {401: "unauthenticated", 403: "not_eligible"}[status])
    assert (spy.locks, spy.writes) == (0, 0)
    # Only the windows today's order charges before refusing (recovery, public reads, challenges).
    assert {k[0] for k in after if after[k] != before.get(k)} == set(charged)
    for key in after:
        if after[key] != before.get(key):
            assert after[key][1] == before.get(key, (0, 0))[1] + 1


@pytest.mark.parametrize("case", REFUSED, ids=[c[0] for c in REFUSED])
def test_transaction_alone_answers_the_same(tmp_path, monkeypatch, case):
    """The pre-check is never load-bearing: without it the transaction gives the same bytes, the
    same windows and the same challenge state."""
    first, _, _, windows, challenged = run(tmp_path / "pre", monkeypatch, case)
    monkeypatch.undo()
    second, spy, _, windows_alone, challenged_alone = run(
        tmp_path / "alone", monkeypatch, case, precheck=False
    )
    assert spy.locks >= 1 or case[0].startswith("challenge")  # nothing else answers early
    assert (first.status_code, first.content) == (second.status_code, second.content)
    assert first.headers.get("retry-after") == second.headers.get("retry-after")
    assert windows == windows_alone and challenged == challenged_alone


def test_refused_login_consumes_its_challenge(tmp_path, monkeypatch):
    case = next(c for c in REFUSED if c[0] == "login_bad_signature")
    _, _, _, _, challenged = run(tmp_path, monkeypatch, case)
    assert not challenged  # one guess per challenge, as in the transaction (§19.4)


def test_authorized_requests_still_take_the_lock(tmp_path, monkeypatch):
    with TestClient(create_app(tmp_path)) as c:
        d = c.app.state.directory
        seed(d)
        spy = Spy(d, monkeypatch)
        assert c.get(f"/v2/workspaces/{WS}/members", headers=DEV).status_code == 200
        assert (spy.locks, spy.writes) == (1, 1)
        assert c.post("/v2/session/logout", json={}, headers=DEV).json() == {}
        assert (spy.locks, spy.writes) == (2, 2)
        assert c.get(f"/v2/workspaces/{WS}/members", headers=DEV).status_code == 401


def test_precheck_passes_but_transaction_refuses(tmp_path, monkeypatch):
    """TOCTOU: a session revoked between the pre-check and the lock is refused by the
    transaction, with the transaction's code."""
    with TestClient(create_app(tmp_path)) as c:
        d = c.app.state.directory
        seed(d)
        real = d.preauthorize

        def preauthorize(*args):
            result = real(*args)
            sql(d, "DELETE FROM sessions WHERE token_hash=?", (token_hash("FAKE-device"),))
            return result

        monkeypatch.setattr(d, "preauthorize", preauthorize)
        r = c.get(f"/v2/workspaces/{WS}/members", headers=DEV)
        assert r.status_code == 401 and r.json() == {"error": "unauthenticated"}


def test_database_errors_fall_back_to_the_transaction(tmp_path, monkeypatch):
    import sqlite3

    with TestClient(create_app(tmp_path)) as c:
        d = c.app.state.directory
        seed(d)

        def broken(*args):
            raise sqlite3.OperationalError("database is locked")

        monkeypatch.setattr(d, "preauthorize", broken)
        assert c.get(f"/v2/workspaces/{WS}/members", headers=BAD).status_code == 401
        assert c.get(f"/v2/workspaces/{WS}/members", headers=DEV).status_code == 200


def test_precheck_read_failure_after_consuming_keeps_the_challenge_consumed(tmp_path, monkeypatch):
    """A pre-check that consumed the challenge and then hit sqlite3.Error hands the consumed
    challenge to the transaction, which logs in with it (it is not consumed twice)."""
    import sqlite3

    with TestClient(create_app(tmp_path)) as c:
        d = c.app.state.directory
        seed(d)
        sql(d, "DELETE FROM sessions")
        d.add_challenge(CHALLENGE, NOW + MINUTE, "testclient", None)
        real = d.connection
        failed = []

        class Broken:
            def __init__(self, con):
                self.con = con

            def execute(self, statement, *args):
                if statement.startswith("SELECT * FROM devices") and not failed:
                    failed.append(statement)
                    raise sqlite3.OperationalError("database is locked")
                return self.con.execute(statement, *args)

            def __getattr__(self, name):
                return getattr(self.con, name)

        monkeypatch.setattr(
            d,
            "connection",
            lambda purpose: Broken(real(purpose)) if purpose == "read" else real(purpose),
        )
        r = c.post("/v2/session/login", json=login_body("phone.sig", d.origin))
        assert failed and r.status_code == 200, r.text
        assert CHALLENGE not in d.challenges


def test_concurrent_identical_account_retries_both_succeed(tmp_path):
    """An existing invite is never decided by the pre-check: the retry sees the replay."""
    from concurrent.futures import ThreadPoolExecutor

    from orch_relay.directory import create_invite

    invite = create_invite(tmp_path / db.DB_NAME, 7 * 86_400_000)
    with TestClient(create_app(tmp_path)) as c:
        d = c.app.state.directory
        seed(d, accounts=False, devices=False, card=False)
        d.add_challenge(CHALLENGE, NOW + MINUTE, "testclient", None)
        body = {
            "invite": invite,
            "pk_pub": PK,
            "device_cert": CERT,
            "challenge": CHALLENGE,
            "sig": sign("phone.sig", P.auth_bytes(d.origin, P.unb64u(CHALLENGE), "device", DEVICE)),
        }
        raw = P.cj(body)
        barrier = threading.Barrier(4)

        def post(_):
            barrier.wait()
            return c.post("/v2/accounts", content=raw, headers={"Content-Type": "application/json"})

        with ThreadPoolExecutor(max_workers=4) as pool:
            responses = list(pool.map(post, range(4)))
        assert [r.status_code for r in responses] == [200] * 4


def test_connections_are_per_thread_and_reused(tmp_path):
    with TestClient(create_app(tmp_path)) as c:
        d = c.app.state.directory
        seen = {}

        def grab(name):
            seen[name] = (d.connection("read"), d.connection("read"), d.connection("write"))

        threads = [threading.Thread(target=grab, args=(n,)) for n in ("a", "b")]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        (a1, a2, aw), (b1, _, bw) = seen["a"], seen["b"]
        assert a1 is a2 and a1 is not aw  # reused within a thread, one per purpose
        assert a1 is not b1 and aw is not bw  # never shared between threads
        assert a1.execute("PRAGMA query_only").fetchone()[0] == 1
        assert a1.execute("PRAGMA busy_timeout").fetchone()[0] == 0
        assert aw.execute("PRAGMA query_only").fetchone()[0] == 0


# --- the shared HTTP fixtures, byte for byte with and without the pre-check ----------------------

G1 = {
    "accounts",
    "session_challenge",
    "session_login",
    "session_logout",
    "device_get",
    "device_put",
    "revocations_post",
    "revocation_get",
    "revocation_feed",
    "card_put",
    "card_get",
}
G2 = {"membership", "members", "grants", "card_keys", "card_key"}
FIXTURES = [
    (p.stem, c)
    for p in sorted(Path("tests/http_fixtures").glob("*.json"))
    if p.stem in G1 | G2
    for c in json.loads(p.read_text())["cases"]
]


def replay(tmp_path, monkeypatch, name, case, precheck):
    with TestClient(create_app(tmp_path)) as c:
        d = c.app.state.directory
        (prepare_fixture if name in G2 else prepare_case)(d, name, case)
        d.random = lambda n: bytes(n)
        if not precheck:
            monkeypatch.setattr(d, "preauthorize", lambda *args: None)
        request = case["request"]
        kwargs = {"headers": request["headers"], "params": request["query"]}
        if "body_b64u" in request:
            kwargs["content"] = P.unb64u(request["body_b64u"])
        if "json" in request:
            kwargs["content"] = P.cj(request["json"])
        if "body_recipe" in request:
            recipe = request["body_recipe"]
            kwargs["content"] = (
                P.unb64u(recipe["prefix_b64u"])
                + bytes([recipe["byte"]]) * recipe["count"]
                + P.unb64u(recipe["suffix_b64u"])
            )
        out = []
        if case["given"].get("scenario") == "exact_bytes_already_committed":
            out.append(client_bytes(c.request(request["method"], request["path"], **kwargs)))
        out.append(client_bytes(c.request(request["method"], request["path"], **kwargs)))
        return out, dict(d.windows), sorted(d.challenges)


def client_bytes(r):
    return r.status_code, r.content, r.headers.get("retry-after")


@pytest.mark.parametrize("name,case", FIXTURES, ids=[f"{n}-{c['name']}" for n, c in FIXTURES])
def test_fixture_bytes_identical_without_precheck(tmp_path, monkeypatch, name, case):
    pre = replay(tmp_path / "pre", monkeypatch, name, case, True)
    monkeypatch.undo()
    alone = replay(tmp_path / "alone", monkeypatch, name, case, False)
    assert pre == alone
    assert pre[0][-1][0] == case["response"]["status"]


def test_reused_connection_never_carries_an_open_transaction(tmp_path):
    """A connection handed out again is rolled back first: a pre-check never reads an old snapshot
    and the transaction never inherits an open one."""
    with TestClient(create_app(tmp_path)) as c:
        d = c.app.state.directory
        for purpose in ("read", "write"):
            con = d.connection(purpose)
            con.execute("BEGIN")
            con.execute("SELECT count(*) FROM sessions").fetchone()
            assert con.in_transaction
            assert d.connection(purpose) is con and not con.in_transaction


def test_windows_and_challenges_are_guarded_by_the_budget_mutex(tmp_path):
    """Pre-checks touch windows and challenges without Directory.lock, so every access takes the
    budget mutex (and only that)."""
    from orch_relay.directory import Directory

    d = Directory(tmp_path / "unused", "https://relay.example")
    real, held = d.budget, []

    class Budget:
        def __enter__(self):
            held.append(True)
            return real.__enter__()

        def __exit__(self, *exc):
            return real.__exit__(*exc)

    d.budget = Budget()
    d.rate("x", "a", MINUTE, 5, NOW, False)
    d.rate("x", "a", MINUTE, 5, NOW)
    assert len(held) == 2
    challenge = d.issue("198.51.100.1", NOW)["challenge"]
    assert len(held) > 2
    count = len(held)
    d.consume(challenge, NOW)
    assert len(held) > count
