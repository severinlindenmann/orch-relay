"""P3-D40 test material: a throwaway P-256 APNs key and token secret (never a real key), the push
environment, and a seeded workspace with registered tokens. Public FAKE data only."""

import os
import sqlite3
from contextlib import closing

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from directory_support import NOW, WS, V
from drop_support import setup

from orch_relay import db
from orch_relay import proto as P
from orch_relay.directory import token_hash

TEAM = "TEAM123456"
TOPIC = "io.severin.orch"
KID = {"sandbox": "SBXKEY1234", "production": "PRDKEY5678"}
BOB = V["ids"]["device_bob_phone"]
HEAD = {"Content-Type": "application/json"}
TOKEN_A = bytes(range(32))
TOKEN_B = bytes(range(100, 132))
TOKEN_C = bytes(range(200, 232))


def rid(n):
    return f"{n:032x}"


def token_b64(raw):
    return P.b64u(raw)


def auth(name, holder=None):
    h = {"Authorization": "Bearer " + name, **HEAD}
    if holder is not None:
        h["Orch-Holder"] = holder
    return h


def make_key(path):
    """A throwaway P-256 key as PKCS8 PEM (the .p8 shape), mode 0600. Returns the private key."""
    private = ec.generate_private_key(ec.SECP256R1())
    path.write_bytes(
        private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    os.chmod(path, 0o600)
    return private


def push_env(tmp_path, envs=("sandbox", "production"), same_key=False):
    """Environment variables of a complete configuration; returns (env, {env name: private key})."""
    secret = tmp_path / "push-token.key"
    secret.write_bytes(bytes(range(7, 39)))
    os.chmod(secret, 0o600)
    env = {
        "ORCH_RELAY_APNS_TEAM_ID": TEAM,
        "ORCH_RELAY_APNS_TOPIC": TOPIC,
        "ORCH_RELAY_PUSH_TOKEN_KEY_FILE": str(secret),
    }
    keys, shared = {}, None
    for name in envs:
        path = tmp_path / f"AuthKey_{name}.p8"
        if same_key and shared is not None:
            path, key = shared
        else:
            key = make_key(path)
            shared = (path, key)
        keys[name] = key
        env[f"ORCH_RELAY_APNS_{name.upper()}_KEY_ID"] = KID["sandbox" if same_key else name]
        env[f"ORCH_RELAY_APNS_{name.upper()}_KEY_FILE"] = str(path)
    return env, keys


def configure(monkeypatch, tmp_path, **options):
    env, keys = push_env(tmp_path, **options)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    return keys


def clear(monkeypatch):
    from orch_relay.push_config import ALL_NAMES

    for name in ALL_NAMES:
        monkeypatch.delenv(name, raising=False)


def seed_push(d, now=NOW):
    """Drop's seeded workspace (phone and laptop members of one person, W session, the `drop:` agent)
    plus bob's phone (another person; a member of nothing) with a session."""
    setup(d, now)
    with closing(db.connect(d.path)) as con, con:
        con.execute("PRAGMA foreign_keys=OFF")
        con.execute("INSERT INTO accounts VALUES (?,?,?)", (V["ids"]["person_bob"], "AA", now))
        d.store_device(con, V["certs"]["signed"]["bob_phone"])
        con.execute(
            "INSERT INTO sessions VALUES (?,?,?,?)",
            (token_hash("FAKE-bob"), "device", BOB, now + 900_000),
        )


def register(c, tok=TOKEN_A, registration=1, session="FAKE-device", ws=WS, env="sandbox", **over):
    body = {
        "workspace_id": ws,
        "registration_id": rid(registration),
        "env": env,
        "topic": TOPIC,
        "token": token_b64(tok),
    }
    body.update(over)
    return c.post("/v2/push/register", json=body, headers=auth(session))


def unregister(c, registration=1, session="FAKE-device", ws=WS):
    body = {
        "workspace_id": ws,
        "registration_id": None if registration is None else rid(registration),
    }
    return c.post("/v2/push/unregister", json=body, headers=auth(session))


def rows(d, where="1", args=()):
    with closing(db.connect(d.path)) as con:
        con.row_factory = sqlite3.Row
        return [
            dict(r) for r in con.execute(f"SELECT * FROM push_subscriptions WHERE {where}", args)
        ]


def long_sessions(d):
    """Sessions and the holder lease that outlive a test's clock jumps."""
    with closing(db.connect(d.path)) as con, con:
        con.execute("UPDATE sessions SET expires_ms=?", (NOW + 10 * 86_400_000,))
        con.execute("UPDATE holders SET lease_until_ms=?", (NOW + 10 * 86_400_000,))


def outer(n=1, ws=WS, epoch=1, size=24):
    return {"v": 2, "ws": ws, "epoch": epoch, "c": P.b64u(bytes([n % 250 + 1]) * size)}


def send(
    c,
    targets,
    o=None,
    priority="high",
    ttl_s=600,
    holder="1",
    session="FAKE-workspace",
    ws=WS,
    **over,
):
    body = {"targets": targets, "outer": o or outer(), "priority": priority, "ttl_s": ttl_s}
    body.update(over)
    return c.post(f"/v2/workspaces/{ws}/push", json=body, headers=auth(session, holder))
