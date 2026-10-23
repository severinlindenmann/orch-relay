"""Push test material: a throwaway P-256 APNs key and token secret (never a real key) and the push
environment. Public FAKE data only."""

import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from orch_relay import proto as P

TEAM = "TEAM123456"
TOPIC = "io.severin.orch"
KID = {"sandbox": "SBXKEY1234", "production": "PRDKEY5678"}
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
