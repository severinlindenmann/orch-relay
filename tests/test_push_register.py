"""P3-D40a: push registration and unregistration (protocol §19.10, P3 design §14.3 items 1-3, 8, 9)."""

import os
import stat
from contextlib import closing
from pathlib import Path

import pytest
from directory_support import DEVICE, NOW, PERSON, RECORD, WS, V
from drop_support import AGENT, LAPTOP, PRIMARY
from fastapi.testclient import TestClient
from push_support import (
    BOB,
    HEAD,
    TOKEN_A,
    TOKEN_B,
    TOPIC,
    auth,
    clear,
    configure,
    long_sessions,
    push_env,
    register,
    rid,
    rows,
    seed_push,
    token_b64,
    unregister,
)

from orch_relay import cli, db
from orch_relay import proto as P
from orch_relay.app import create_app
from orch_relay.push_config import PushConfigError, derive, load

HOUR = 3_600_000
DAY = 24 * HOUR


@pytest.fixture
def c(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    with TestClient(create_app(tmp_path / "data")) as client:
        d = client.app.state.directory
        seed_push(d)
        client.d = d
        yield client


# --- disabled push (item 9) -------------------------------------------------------------------


def test_disabled_push_is_404_on_every_route_before_authentication(tmp_path, monkeypatch):
    clear(monkeypatch)
    with TestClient(create_app(tmp_path)) as client:
        assert not client.app.state.push.enabled
        for path in ("/v2/push/register", "/v2/push/unregister"):
            r = client.post(path, json={})
            assert (r.status_code, r.json()) == (404, {"error": "not_found"}), path
            r = client.post(path, json={}, headers=auth("FAKE-device", "1"))
            assert r.status_code == 404, path


# --- register: shape, idempotency, retirement (item 1) -----------------------------------------


def test_register_answers_and_stores_the_sealed_token(c):
    r = register(c)
    assert (r.status_code, r.json()) == (200, {"registration_id": rid(1), "registered": True})
    (row,) = rows(c.d)
    assert (row["device_id"], row["workspace_id"], row["env"], row["topic"]) == (
        DEVICE,
        WS,
        "sandbox",
        TOPIC,
    )
    assert row["created_ms"] == row["last_seen_ms"] == NOW
    assert TOKEN_A not in bytes(row["token_sealed"])
    assert c.app.state.push.unseal(rid(1), row["token_sealed"]) == TOKEN_A


def test_token_bytes_are_not_in_the_database_files(c):
    secrets_ = [TOKEN_A, TOKEN_B]
    assert register(c, TOKEN_A, 1).status_code == 200
    assert register(c, TOKEN_B, 2, env="production").status_code == 200
    # a sealed row also survives a checkpoint of the WAL into the main file
    with closing(db.connect(c.d.path)) as con:
        con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    blobs = b"".join(p.read_bytes() for p in c.d.path.parent.glob("relay.sqlite3*") if p.is_file())
    for raw in secrets_:
        assert raw not in blobs
        assert raw.hex().encode() not in blobs
        assert token_b64(raw).encode() not in blobs
    # nor is any key
    cfg = c.app.state.push.config
    assert cfg.k_tok not in blobs and cfg.k_mac not in blobs


def test_exact_retry_refreshes_and_is_free_of_rate_windows(c):
    assert register(c).status_code == 200
    for step in range(40):  # more than the 30 per hour: refreshes are free
        c.d.clock = lambda step=step: NOW + 1000 * (step + 1)
        assert register(c).status_code == 200
    assert rows(c.d)[0]["last_seen_ms"] == NOW + 40_000
    assert len(rows(c.d)) == 1


def test_a_new_id_retires_the_old_one_for_the_tuple(c):
    register(c, TOKEN_A, 1)
    assert register(c, TOKEN_A, 2).status_code == 200
    assert [r["registration_id"] for r in rows(c.d)] == [rid(2)]
    # another env, workspace or token-holder is another tuple
    assert register(c, TOKEN_B, 3, env="production").status_code == 200
    assert sorted(r["registration_id"] for r in rows(c.d)) == [rid(2), rid(3)]
    # the retired id is gone: a replay of it is a new registration, not a refresh
    assert register(c, TOKEN_A, 1).status_code == 200
    assert [r["registration_id"] for r in rows(c.d, "env='sandbox'")] == [rid(1)]


def test_same_id_with_another_body_is_409(c):
    register(c, TOKEN_A, 1)
    for patch in ({"token": token_b64(TOKEN_B)}, {"env": "production"}):
        r = register(c, TOKEN_A, 1, **patch)
        assert (r.status_code, r.json()) == (409, {"error": "registration_conflict"}), patch
    assert len(rows(c.d)) == 1 and rows(c.d)[0]["env"] == "sandbox"


def test_another_devices_id_is_409_and_not_refreshed(c):
    register(c, TOKEN_A, 1)
    c.d.clock = lambda: NOW + 5000
    # the laptop (same person) replaying the phone's exact body must not refresh the phone's row
    r = register(c, TOKEN_A, 1, session="FAKE-laptop")
    assert (r.status_code, r.json()) == (409, {"error": "registration_conflict"})
    assert rows(c.d)[0]["last_seen_ms"] == NOW and rows(c.d)[0]["device_id"] == DEVICE


@pytest.mark.parametrize(
    "patch",
    [
        {"env": "demo"},
        {"topic": "io.example.other"},
        {"token": token_b64(bytes(31))},
        {"token": token_b64(bytes(101))},
        {"token": "AA=="},  # non-canonical (padded)
        {"token": 7},
        {"registration_id": "ab" * 15},
        {"registration_id": "AB" * 16},
        {"workspace_id": "nothex"},
        {"extra": 1},
    ],
)
def test_malformed_bodies(c, patch):
    r = register(c, **patch)
    assert (r.status_code, r.json()) == (400, {"error": "malformed"})
    assert rows(c.d) == []


def test_token_length_bounds_are_inclusive(c):
    assert register(c, bytes(32), 1).status_code == 200
    assert register(c, bytes(100), 2, env="production").status_code == 200


def test_missing_field_array_and_content_type_are_malformed(c):
    body = {"workspace_id": WS, "registration_id": rid(1), "env": "sandbox", "topic": TOPIC}
    assert c.post("/v2/push/register", json=body, headers=auth("FAKE-device")).status_code == 400
    assert c.post("/v2/push/register", json=[], headers=auth("FAKE-device")).status_code == 400
    r = c.post("/v2/push/register", content=b"{}", headers={"Authorization": "Bearer FAKE-device"})
    assert r.status_code == 400
    assert (
        c.post("/v2/push/register?x=1", json=body, headers=auth("FAKE-device")).status_code == 400
    )


def test_body_cap_is_16_kib(c):
    r = c.post("/v2/push/register", content=b" " * (16 * 1024 + 1), headers=auth("FAKE-device"))
    assert (r.status_code, r.json()) == (413, {"error": "too_large"})
    r = c.post("/v2/push/unregister", content=b" " * (16 * 1024 + 1), headers=auth("FAKE-device"))
    assert r.status_code == 413


def test_an_env_without_a_configured_key_is_malformed(tmp_path, monkeypatch):
    clear(monkeypatch)
    configure(monkeypatch, tmp_path, envs=("sandbox",))
    with TestClient(create_app(tmp_path / "data")) as client:
        seed_push(client.app.state.directory)
        assert register(client, env="sandbox").status_code == 200
        r = register(client, TOKEN_B, 2, env="production")
        assert (r.status_code, r.json()) == (400, {"error": "malformed"})


# --- register: who may (D(m), not_eligible, revoked) -------------------------------------------


def test_who_may_register(c):
    assert register(c, session="nope").status_code == 401
    no_auth = c.post("/v2/push/register", json={}, headers=HEAD)
    assert no_auth.status_code == 401
    for session in ("FAKE-agent", "FAKE-workspace"):  # a drop: device; a W session
        r = register(c, session=session)
        assert (r.status_code, r.json()) == (403, {"error": "not_eligible"}), session
    # a registered device that is not a member of the workspace, and one of another person
    with closing(db.connect(c.d.path)) as con, con:
        from orch_relay.directory import token_hash

        con.execute(
            "INSERT INTO sessions VALUES (?,?,?,?)",
            (token_hash("FAKE-primary"), "device", PRIMARY, NOW + 900_000),
        )
    for session in ("FAKE-primary", "FAKE-bob"):
        r = register(c, session=session)
        assert (r.status_code, r.json()) == (403, {"error": "not_eligible"}), session
    assert rows(c.d) == []


def test_a_revoked_device_is_refused(c):
    with closing(db.connect(c.d.path)) as con, con:
        con.execute(
            "INSERT INTO revocations VALUES (?,?,?,?,?,?)",
            (DEVICE, PERSON, b"x", "lost", NOW, 1),
        )
    r = register(c)
    assert (r.status_code, r.json()) == (403, {"error": "revoked"})
    assert unregister(c).status_code == 403


# --- same-person move (item 1) -----------------------------------------------------------------


def test_the_token_moves_from_the_persons_other_devices(c):
    register(c, TOKEN_A, 1, session="FAKE-device")
    register(c, TOKEN_B, 2, session="FAKE-device", env="production")
    # the same token on the person's other device: the phone's registrations with it are deleted
    assert register(c, TOKEN_A, 3, session="FAKE-laptop").status_code == 200
    assert sorted((r["device_id"], r["registration_id"]) for r in rows(c.d)) == sorted(
        [(DEVICE, rid(2)), (LAPTOP, rid(3))]
    )


def test_the_same_device_in_another_workspace_keeps_both(c):
    other = "cd" * 16
    with closing(db.connect(c.d.path)) as con, con:
        con.execute("INSERT INTO members VALUES (?,?,?,?)", (other, DEVICE, PERSON, "[]"))
    register(c, TOKEN_A, 1)
    assert register(c, TOKEN_A, 2, ws=other).status_code == 200
    assert len(rows(c.d)) == 2


def test_another_persons_registration_of_the_token_is_not_touched(c):
    with closing(db.connect(c.d.path)) as con, con:
        con.execute("INSERT INTO members VALUES (?,?,?,?)", (WS, BOB, V["ids"]["person_bob"], "[]"))
    register(c, TOKEN_A, 1, session="FAKE-bob")
    assert register(c, TOKEN_A, 2, session="FAKE-device").status_code == 200
    assert sorted(r["device_id"] for r in rows(c.d)) == sorted([BOB, DEVICE])


# --- limits (item 7) ---------------------------------------------------------------------------


def test_thirty_state_changes_per_device_per_hour(c):
    long_sessions(c.d)
    for n in range(1, 31):
        assert register(c, bytes([n]) * 32, n).status_code == 200, n
    r = register(c, bytes([99]) * 32, 99)
    assert (r.status_code, r.json()) == (429, {"error": "rate_limited"})
    assert int(r.headers["Retry-After"]) >= 1
    c.d.clock = lambda: NOW + HOUR  # the next window
    assert register(c, bytes([99]) * 32, 99).status_code == 200


def test_at_most_128_registrations_per_device(c):
    long_sessions(c.d)
    members = [f"{n:032x}" for n in range(1000, 1130)]
    with closing(db.connect(c.d.path)) as con, con:
        for ws in members:
            con.execute("INSERT INTO members VALUES (?,?,?,?)", (ws, DEVICE, PERSON, "[]"))
    for n, ws in enumerate(members[:128]):
        c.d.clock = lambda n=n: NOW + (n // 30) * HOUR
        assert register(c, bytes([n % 250 + 1]) * 32, n + 1, ws=ws).status_code == 200, n
    c.d.clock = lambda: NOW + 9 * HOUR
    r = register(c, TOKEN_B, 500, ws=members[128])
    assert (r.status_code, r.json()) == (429, {"error": "quota_exceeded"})
    assert len(rows(c.d)) == 128
    # replacing an existing tuple stays within the quota
    assert register(c, TOKEN_B, 501, ws=members[0]).status_code == 200


# --- unregister (item 2) -----------------------------------------------------------------------


def test_unregister_by_id_by_null_and_absent(c):
    register(c, TOKEN_A, 1)
    register(c, TOKEN_B, 2, env="production")
    r = unregister(c, 1)
    assert (r.status_code, r.json()) == (200, {"registration_id": rid(1), "registered": False})
    assert [r["registration_id"] for r in rows(c.d)] == [rid(2)]
    assert unregister(c, 1).json() == {"registration_id": rid(1), "registered": False}  # absent
    r = unregister(c, None)
    assert (r.status_code, r.json()) == (200, {"registration_id": None, "registered": False})
    assert rows(c.d) == []
    assert unregister(c, None).status_code == 200  # nothing to delete


def test_unregister_another_devices_id_is_403_and_leaves_it(c):
    register(c, TOKEN_A, 1)
    r = unregister(c, 1, session="FAKE-laptop")
    assert (r.status_code, r.json()) == (403, {"error": "not_for_this_device"})
    assert len(rows(c.d)) == 1
    # null deletes only the caller's own
    assert unregister(c, None, session="FAKE-laptop").status_code == 200
    assert len(rows(c.d)) == 1


def test_unregister_needs_no_membership_and_refuses_other_principals(c):
    register(c, TOKEN_A, 1)
    with closing(db.connect(c.d.path)) as con, con:
        con.execute("DELETE FROM members WHERE device_id=?", (DEVICE,))  # removed, not revoked
    assert unregister(c, 1).status_code == 200 and rows(c.d) == []
    assert unregister(c, 1, session="nope").status_code == 401
    r = unregister(c, 1, session="FAKE-workspace")
    assert (r.status_code, r.json()) == (403, {"error": "not_eligible"})


@pytest.mark.parametrize(
    "body",
    [
        {"workspace_id": WS},
        {"workspace_id": WS, "registration_id": "x"},
        {"workspace_id": WS, "registration_id": 5},
        {"workspace_id": "zz", "registration_id": None},
        {"workspace_id": WS, "registration_id": None, "x": 1},
    ],
)
def test_unregister_malformed(c, body):
    r = c.post("/v2/push/unregister", json=body, headers=auth("FAKE-device"))
    assert (r.status_code, r.json()) == (400, {"error": "malformed"})


# --- lifecycle (item 3) ------------------------------------------------------------------------


def test_prune_on_revocation_and_removal(c):
    register(c, TOKEN_A, 1, session="FAKE-device")
    register(c, TOKEN_B, 2, session="FAKE-laptop")
    from orch_relay.members import prune_device

    with c.d.lock:
        con = c.d.connection("write")
        con.execute("BEGIN IMMEDIATE")
        with con:
            prune_device(con, LAPTOP, WS)  # removal from the workspace's list
    assert [r["device_id"] for r in rows(c.d)] == [DEVICE]
    with c.d.lock:
        con = c.d.connection("write")
        con.execute("BEGIN IMMEDIATE")
        with con:
            c.d.revoke(con, RECORD, NOW)  # the phone's verified revocation (prunes everywhere)
    assert rows(c.d) == []


def test_the_sweep_deletes_stale_and_expired_certificate_registrations(c):
    push = c.app.state.push
    register(c, TOKEN_A, 1, session="FAKE-device")
    register(c, TOKEN_B, 2, session="FAKE-laptop")
    assert push.sweep(NOW + 59 * DAY) == 0
    with closing(db.connect(c.d.path)) as con, con:
        con.execute("UPDATE sessions SET expires_ms=?", (NOW + 90 * DAY,))
    c.d.clock = lambda: NOW + 30 * DAY
    register(c, TOKEN_B, 2, session="FAKE-laptop")  # a refresh keeps it
    assert push.sweep(NOW + 61 * DAY) == 1
    assert [r["registration_id"] for r in rows(c.d)] == [rid(2)]
    with closing(db.connect(c.d.path)) as con, con:
        con.execute("UPDATE devices SET expires_ms=? WHERE device_id=?", (NOW + 100, LAPTOP))
    assert push.sweep(NOW + 99) == 0
    assert push.sweep(NOW + 100) == 1 and rows(c.d) == []


def test_the_background_sweep_runs_at_start(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    with TestClient(create_app(tmp_path / "data")) as client:
        assert client.app.state.push.enabled  # the task exists only for an enabled push


# --- sealing (item 8) --------------------------------------------------------------------------


def test_seal_is_bound_to_the_registration_id_and_random(c):
    push = c.app.state.push
    one, two = push.seal(rid(1), TOKEN_A), push.seal(rid(1), TOKEN_A)
    assert one != two and push.unseal(rid(1), one) == TOKEN_A
    from cryptography.exceptions import InvalidTag

    with pytest.raises(InvalidTag):
        push.unseal(rid(2), one)
    assert push.token_mac(TOKEN_A) == push.token_mac(TOKEN_A) != push.token_mac(TOKEN_B)
    assert len(push.token_mac(TOKEN_A)) == 32


def test_keys_derive_from_the_secret_and_differ(tmp_path):
    a, b = derive(bytes(32)), derive(bytes(range(32)))
    assert a[0] != a[1] and a != b and all(len(k) == 32 for k in a)


# --- configuration (item 9, §14.7) -------------------------------------------------------------


@pytest.mark.parametrize(
    "drop",
    [
        ["ORCH_RELAY_APNS_TEAM_ID"],
        ["ORCH_RELAY_APNS_TOPIC"],
        ["ORCH_RELAY_PUSH_TOKEN_KEY_FILE"],  # a key without the token secret
        ["ORCH_RELAY_APNS_SANDBOX_KEY_ID", "ORCH_RELAY_APNS_PRODUCTION_KEY_ID"],  # a key, no id
        [
            "ORCH_RELAY_APNS_SANDBOX_KEY_FILE",
            "ORCH_RELAY_APNS_PRODUCTION_KEY_FILE",
        ],  # an id, no key
        ["ORCH_RELAY_APNS_SANDBOX_KEY_ID"],  # one environment half-configured
        ["ORCH_RELAY_APNS_PRODUCTION_KEY_FILE"],
    ],
)
def test_partial_configuration_refuses_to_start(tmp_path, monkeypatch, drop):
    env, _ = push_env(tmp_path)
    for name in drop:
        env.pop(name)
    clear(monkeypatch)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    with pytest.raises(PushConfigError, match="partial push configuration"):
        create_app(tmp_path / "data")


def test_only_the_team_or_only_a_file_is_partial_not_disabled(tmp_path, monkeypatch):
    clear(monkeypatch)
    monkeypatch.setenv("ORCH_RELAY_APNS_TEAM_ID", "TEAM123456")
    with pytest.raises(PushConfigError):
        create_app(tmp_path)


def test_the_cli_exits_2_on_a_partial_configuration(tmp_path, monkeypatch, capsys):
    clear(monkeypatch)
    monkeypatch.setenv("ORCH_RELAY_DATA", str(tmp_path))
    monkeypatch.setenv("ORCH_RELAY_APNS_TOPIC", TOPIC)
    assert cli.main(["serve", "--port", "1"]) == 2
    assert "refusing to start" in capsys.readouterr().err


def test_a_single_environment_is_enough(tmp_path):
    env, _ = push_env(tmp_path, envs=("production",))
    config = load(env)
    assert config.envs == ("production",)


def test_one_key_for_both_environments_is_parsed_once(tmp_path):
    env, _ = push_env(tmp_path, same_key=True)
    config = load(env)
    assert config.keys["sandbox"][1] is config.keys["production"][1]
    assert config.keys["sandbox"][0] == config.keys["production"][0]


@pytest.mark.parametrize("mode", [0o640, 0o604, 0o660, 0o644])
def test_a_group_or_world_accessible_key_file_is_refused(tmp_path, mode):
    env, _ = push_env(tmp_path, envs=("sandbox",))
    os.chmod(env["ORCH_RELAY_APNS_SANDBOX_KEY_FILE"], mode)
    with pytest.raises(PushConfigError, match="accessible to others"):
        load(env)


def test_the_token_secret_file_is_held_to_the_same_rule_and_length(tmp_path):
    env, _ = push_env(tmp_path, envs=("sandbox",))
    secret = env["ORCH_RELAY_PUSH_TOKEN_KEY_FILE"]
    os.chmod(secret, 0o644)
    with pytest.raises(PushConfigError, match="push token secret"):
        load(env)
    os.chmod(secret, 0o600)
    Path(secret).write_bytes(b"short")
    with pytest.raises(PushConfigError, match="exactly 32 bytes"):
        load(env)


def test_a_credentials_directory_file_is_accepted_as_is(tmp_path, monkeypatch):
    env, _ = push_env(tmp_path, envs=("sandbox",))
    creds = tmp_path / "creds"
    creds.mkdir()
    for name in ("ORCH_RELAY_APNS_SANDBOX_KEY_FILE", "ORCH_RELAY_PUSH_TOKEN_KEY_FILE"):
        target = creds / os.path.basename(env[name])
        target.write_bytes(Path(env[name]).read_bytes())
        os.chmod(target, 0o644)  # systemd sets the mode there; the relay accepts it
        env[name] = str(target)
    with pytest.raises(PushConfigError):
        load(env)  # outside $CREDENTIALS_DIRECTORY the same files are refused
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(creds))
    assert load(env).envs == ("sandbox",)


def test_key_errors_name_the_environment_and_leak_nothing(tmp_path):
    env, _ = push_env(tmp_path, envs=("sandbox",))
    path = env["ORCH_RELAY_APNS_SANDBOX_KEY_FILE"]
    with open(path, "wb") as handle:
        handle.write(b"-----BEGIN PRIVATE KEY-----\nSECRETBYTES\n-----END PRIVATE KEY-----\n")
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    with pytest.raises(PushConfigError) as caught:
        load(env)
    assert str(caught.value) == "apns key unreadable (sandbox)"
    env["ORCH_RELAY_APNS_SANDBOX_KEY_FILE"] = str(tmp_path / "missing.p8")
    with pytest.raises(PushConfigError) as caught:
        load(env)
    assert "missing.p8" not in str(caught.value) and "(sandbox)" in str(caught.value)


def test_an_rsa_key_is_not_an_apns_key(tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    env, _ = push_env(tmp_path, envs=("sandbox",))
    path = env["ORCH_RELAY_APNS_SANDBOX_KEY_FILE"]
    other = ec.generate_private_key(ec.SECP384R1())
    with open(path, "wb") as handle:
        handle.write(
            other.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
    with pytest.raises(PushConfigError, match="apns key unreadable"):
        load(env)


def test_malformed_ids_are_refused(tmp_path):
    env, _ = push_env(tmp_path, envs=("sandbox",))
    for name, bad in (
        ("ORCH_RELAY_APNS_TEAM_ID", "short"),
        ("ORCH_RELAY_APNS_SANDBOX_KEY_ID", "bad id!"),
        ("ORCH_RELAY_APNS_TOPIC", "bad topic"),
    ):
        with pytest.raises(PushConfigError):
            load({**env, name: bad})


def test_migration_0018_creates_the_table(tmp_path):
    path = tmp_path / "relay.sqlite3"
    assert "0018_push" in db.migrate(path)
    with closing(db.connect(path)) as con:
        cols = [r[1] for r in con.execute("PRAGMA table_info(push_subscriptions)")]
    assert cols == [
        "registration_id",
        "device_id",
        "workspace_id",
        "env",
        "topic",
        "token_sealed",
        "token_mac",
        "created_ms",
        "last_seen_ms",
    ]
    assert P and AGENT  # (imports kept for the shared fixtures)
