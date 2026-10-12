"""P3-D36: the audited per-account override of the workspaces-per-account cap (review F2).

An operator command (`orch-relay account-cap`), never an HTTP route: it writes the override row
and an append-only audit row in one write transaction on the relay's database, with the relay
running or stopped. The first-card check reads the override in its read-only pre-check (no lock)
and again in the transaction. FAKE keys only.
"""

import json
import sqlite3
from contextlib import closing

import pytest
from directory_support import NOW, PERSON
from directory_support import seed as dseed
from fastapi.testclient import TestClient
from test_caps import card_for
from test_directory_preauth import Spy

from orch_relay import cli, db
from orch_relay import directory as D
from orch_relay.app import create_app

OTHER = "ab" * 16


def rows(path, query, args=()):
    with closing(db.connect(path)) as con:
        return con.execute(query, args).fetchall()


def own(path, person, count, start=100):
    """`count` workspaces owned by `person` (rows only; the cap counts rows)."""
    with closing(db.connect(path)) as con, con:
        if not con.execute("SELECT 1 FROM accounts WHERE person_id=?", (person,)).fetchone():
            con.execute("INSERT INTO accounts VALUES (?,?,?)", (person, "FAKE-pk", NOW))
        for i in range(count):
            con.execute(
                "INSERT INTO workspaces VALUES (?,?,'k',x'00',x'00',1,1,0)",
                (f"{start + i:032x}", person),
            )


@pytest.fixture
def app(tmp_path):
    with TestClient(create_app(tmp_path)) as c:
        d = c.app.state.directory
        dseed(d, card=False)
        yield c, d


def first_card(c, n):
    ws = f"{n:032x}"
    return c.put(f"/v2/workspaces/{ws}/card", json={"card": card_for(ws)})


def test_override_raises_the_cap_for_one_account_only(app):
    c, d = app
    d.account_workspaces = 1
    own(d.path, OTHER, 1)
    assert first_card(c, 0).status_code == 200
    assert first_card(c, 1).status_code == 429  # PERSON at the global cap
    D.set_account_cap(d.path, OTHER, 50, "FAKE-operator")  # another account's override
    assert first_card(c, 1).json() == {"error": "quota_exceeded"}
    D.set_account_cap(d.path, PERSON, 2, "FAKE-operator", "migrating twice")
    assert first_card(c, 1).status_code == 200
    r = first_card(c, 2)
    assert (r.status_code, r.json()) == (429, {"error": "quota_exceeded"})
    # A lower override binds too (it never removes workspaces; it refuses new ones).
    d.account_workspaces = 32
    D.set_account_cap(d.path, PERSON, 2, "FAKE-operator")
    assert first_card(c, 2).status_code == 429
    # Accounts without an override keep the global cap.
    with closing(db.connect(d.path)) as con:
        assert d.workspace_cap(con, OTHER) == 50
        assert d.workspace_cap(con, "cd" * 16) == 32


def test_override_is_read_in_the_precheck_without_the_lock(app, monkeypatch):
    c, d = app
    d.account_workspaces = 5
    own(d.path, PERSON, 1)
    D.set_account_cap(d.path, PERSON, 1, "FAKE-operator")
    spy = Spy(d, monkeypatch)
    r = first_card(c, 0)
    assert (r.status_code, r.json()) == (429, {"error": "quota_exceeded"})
    assert (spy.locks, spy.writes) == (0, 0)


def test_override_is_rechecked_in_the_transaction(app, monkeypatch):
    """The pre-check passes on its snapshot; an override written before the transaction (the
    operator, concurrently) is read again under the lock."""
    c, d = app
    d.account_workspaces = 5
    own(d.path, PERSON, 1)
    real = d.preauthorize

    def then_lower(*args, **kwargs):
        result = real(*args, **kwargs)
        D.set_account_cap(d.path, PERSON, 1, "FAKE-operator")
        return result

    monkeypatch.setattr(d, "preauthorize", then_lower)
    r = first_card(c, 0)
    assert (r.status_code, r.json()) == (429, {"error": "quota_exceeded"})


def test_override_and_audit_are_written_together(app):
    _c, d = app
    assert D.set_account_cap(d.path, PERSON, 40, "FAKE-op-1", "first", now_ms=NOW) == (None, 40)
    assert D.set_account_cap(d.path, PERSON, 64, "FAKE-op-2", now_ms=NOW + 1) == (40, 64)
    assert rows(d.path, "SELECT * FROM account_workspace_override") == [
        (PERSON, 64, "FAKE-op-2", NOW + 1, None)
    ]
    assert rows(
        d.path,
        "SELECT person_id, old_cap, new_cap, set_by, set_at_ms, note "
        "FROM account_workspace_override_audit ORDER BY seq",
    ) == [
        (PERSON, None, 40, "FAKE-op-1", NOW, "first"),
        (PERSON, 40, 64, "FAKE-op-2", NOW + 1, None),
    ]
    # Atomic: an audit row that cannot be written leaves the override unchanged.
    with closing(db.connect(d.path)) as con, con:
        con.execute(
            "CREATE TRIGGER fake_fail BEFORE INSERT ON account_workspace_override_audit "
            "BEGIN SELECT RAISE(ABORT, 'FAKE audit failure'); END"
        )
    with pytest.raises(sqlite3.DatabaseError):
        D.set_account_cap(d.path, PERSON, 99, "FAKE-op-3")
    assert rows(d.path, "SELECT cap FROM account_workspace_override") == [(64,)]
    # Append-only: the audit cannot be changed or deleted.
    for statement in (
        "UPDATE account_workspace_override_audit SET new_cap=1",
        "DELETE FROM account_workspace_override_audit",
    ):
        with pytest.raises(sqlite3.DatabaseError), closing(db.connect(d.path)) as con, con:
            con.execute(statement)
    assert len(rows(d.path, "SELECT * FROM account_workspace_override_audit")) == 2


@pytest.mark.parametrize("cap", [-1, 0, 10_001, 2**63, True, 5.0, "5", None])
def test_bad_caps_are_rejected(app, cap):
    _c, d = app
    with pytest.raises(ValueError):
        D.set_account_cap(d.path, PERSON, cap, "FAKE-operator")
    assert rows(d.path, "SELECT count(*) FROM account_workspace_override_audit") == [(0,)]


def test_bounds_and_inputs():
    assert D.MAX_ACCOUNT_WORKSPACES == 10_000


@pytest.mark.parametrize(
    "person,by,note",
    [
        ("AB" * 16, "op", None),  # not lower-case hex
        ("ab" * 15, "op", None),
        ("cd" * 16, "op", None),  # no such account
        (PERSON, "", None),
        (PERSON, "o" * 129, None),
        (PERSON, "op\n", None),
        (PERSON, "op", "n" * 1025),
        (PERSON, "op", "a\x00b"),
    ],
)
def test_bad_inputs_are_rejected(app, person, by, note):
    _c, d = app
    with pytest.raises(ValueError):
        D.set_account_cap(d.path, person, 5, by, note)
    assert rows(d.path, "SELECT count(*) FROM account_workspace_override") == [(0,)]


def test_the_schema_refuses_bad_caps_written_directly(app):
    _c, d = app
    for cap in (0, 10_001):
        with pytest.raises(sqlite3.IntegrityError), closing(db.connect(d.path)) as con, con:
            con.execute(
                "INSERT INTO account_workspace_override VALUES (?,?,?,?,NULL)",
                (PERSON, cap, "op", NOW),
            )


@pytest.fixture
def stopped(tmp_path):
    """A relay database with no relay running (the operator's other case)."""
    path = tmp_path / db.DB_NAME
    db.migrate(path)
    own(path, PERSON, 0)
    return path


def test_a_busy_database_writes_nothing(stopped):
    """With the relay (or anyone) holding the write lock past the busy timeout, the command
    fails with sqlite3.OperationalError and writes neither row."""
    with closing(db.connect(stopped)) as holder:
        holder.isolation_level = None
        holder.execute("BEGIN IMMEDIATE")
        with pytest.raises(sqlite3.OperationalError):
            D.set_account_cap(stopped, PERSON, 5, "FAKE-operator", timeout_ms=50)
        holder.execute("ROLLBACK")
    assert rows(stopped, "SELECT count(*) FROM account_workspace_override") == [(0,)]
    assert rows(stopped, "SELECT count(*) FROM account_workspace_override_audit") == [(0,)]
    assert D.set_account_cap(stopped, PERSON, 5, "FAKE-operator") == (None, 5)  # stopped relay


def test_cli_set_show_and_audit(app, monkeypatch, capsys):
    _c, d = app
    monkeypatch.setenv("ORCH_RELAY_DATA", str(d.path.parent))
    monkeypatch.setenv("ORCH_RELAY_ACCOUNT_WORKSPACES", "32")
    own(d.path, PERSON, 3)
    assert cli.main(["account-cap", "show", PERSON]) == 0
    shown = json.loads(capsys.readouterr().out)
    assert shown == {"person_id": PERSON, "owned": 3, "cap": 32, "override": None}
    assert cli.main(["account-cap", "set", PERSON, "48", "--by", "FAKE-op", "--note", "x"]) == 0
    assert json.loads(capsys.readouterr().out) == {
        "person_id": PERSON,
        "old_cap": None,
        "new_cap": 48,
    }
    assert cli.main(["account-cap", "show", PERSON]) == 0
    shown = json.loads(capsys.readouterr().out)
    assert (shown["cap"], shown["override"]["cap"], shown["override"]["set_by"]) == (
        48,
        48,
        "FAKE-op",
    )
    assert cli.main(["account-cap", "audit"]) == 0
    (line,) = capsys.readouterr().out.splitlines()
    audit = json.loads(line)
    assert (audit["person_id"], audit["old_cap"], audit["new_cap"], audit["note"]) == (
        PERSON,
        None,
        48,
        "x",
    )
    assert cli.main(["account-cap", "audit", OTHER]) == 0
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize(
    "argv",
    [
        ["account-cap", "set", PERSON, "0", "--by", "op"],
        ["account-cap", "set", PERSON, "-3", "--by", "op"],
        ["account-cap", "set", PERSON, "10001", "--by", "op"],
        ["account-cap", "set", PERSON, "x", "--by", "op"],
        ["account-cap", "set", PERSON, "5"],  # --by is required
        ["account-cap", "set", "cd" * 16, "5", "--by", "op"],  # no such account
        ["account-cap", "show", "nope"],
    ],
)
def test_cli_refuses_bad_input(app, monkeypatch, capsys, argv):
    _c, d = app
    monkeypatch.setenv("ORCH_RELAY_DATA", str(d.path.parent))
    with pytest.raises(SystemExit) as exited:
        cli.main(argv)
    assert exited.value.code == 2
    assert rows(d.path, "SELECT count(*) FROM account_workspace_override_audit") == [(0,)]


def test_cli_reports_a_busy_database(stopped, monkeypatch, capsys):
    monkeypatch.setenv("ORCH_RELAY_DATA", str(stopped.parent))
    monkeypatch.setenv("ORCH_RELAY_ADMIN_BUSY_MS", "50")
    with closing(db.connect(stopped)) as holder:
        holder.isolation_level = None
        holder.execute("BEGIN IMMEDIATE")
        assert cli.main(["account-cap", "set", PERSON, "5", "--by", "op"]) == 1
        holder.execute("ROLLBACK")
    assert "nothing was written" in capsys.readouterr().err
