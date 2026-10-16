"""Push configuration (P3-D40 item 9, P3 design §14.7): environment, key files, secret derivation.

Push is enabled only by a complete configuration: the team id, the topic, the token secret file and at
least one environment's key id and key file. No push variable at all means disabled (the three push
routes answer 404 `not_found`). Anything in between is partial and `load` raises `PushConfigError`,
so the relay refuses to start (a misconfiguration is loud). Key material is parsed once at start-up;
errors name the environment, never a path's contents or any key byte.

Variables (not secret; in /etc/orch/relay.local.env of the public unit only):
  ORCH_RELAY_APNS_TEAM_ID  ORCH_RELAY_APNS_TOPIC  ORCH_RELAY_PUSH_TOKEN_KEY_FILE
  ORCH_RELAY_APNS_SANDBOX_KEY_ID  ORCH_RELAY_APNS_SANDBOX_KEY_FILE
  ORCH_RELAY_APNS_PRODUCTION_KEY_ID  ORCH_RELAY_APNS_PRODUCTION_KEY_FILE
"""

import hashlib
import hmac
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ENVS = ("sandbox", "production")
TEAM = "ORCH_RELAY_APNS_TEAM_ID"
TOPIC = "ORCH_RELAY_APNS_TOPIC"
TOKEN_KEY = "ORCH_RELAY_PUSH_TOKEN_KEY_FILE"
KEY_ID = "ORCH_RELAY_APNS_{}_KEY_ID"
KEY_FILE = "ORCH_RELAY_APNS_{}_KEY_FILE"
ALL_NAMES = (
    TEAM,
    TOPIC,
    TOKEN_KEY,
    *(pattern.format(env.upper()) for env in ENVS for pattern in (KEY_ID, KEY_FILE)),
)
IDENT = re.compile(r"[A-Za-z0-9]{10}")  # Apple's key ids and team ids
TOPIC_SHAPE = re.compile(r"[A-Za-z0-9.-]{1,255}")


class PushConfigError(RuntimeError):
    """A partial or unusable push configuration: the relay refuses to start."""


@dataclass
class PushConfig:
    team_id: str
    topic: str
    k_tok: bytes = field(repr=False)
    k_mac: bytes = field(repr=False)
    keys: dict = field(repr=False)  # env -> (kid, private key object)

    @property
    def envs(self):
        return tuple(self.keys)


def derive(secret):
    """K_tok and K_mac by HKDF-SHA-256 from the 32-byte instance secret (P3-D40 item 8)."""
    out = []
    for info in (b"orch-relay/push/k_tok", b"orch-relay/push/k_mac"):
        out.append(HKDF(hashes.SHA256(), 32, None, info).derive(secret))
    return out[0], out[1]


def mac(k_mac, token):
    return hmac.new(k_mac, token, hashlib.sha256).digest()


def read_secret_file(path, what):
    """The file's bytes, refusing one that is group- or world-accessible or owned by another uid than
    this process, except under $CREDENTIALS_DIRECTORY (systemd sets owner and mode there)."""
    p = Path(path)
    try:
        fd = os.open(p, os.O_RDONLY)
    except OSError:
        raise PushConfigError(f"{what} unreadable") from None
    try:
        info = os.fstat(fd)
        credentials = os.environ.get("CREDENTIALS_DIRECTORY")
        under = False
        if credentials:
            try:
                under = p.resolve().is_relative_to(Path(credentials).resolve())
            except OSError:
                under = False
        if not stat.S_ISREG(info.st_mode):
            raise PushConfigError(f"{what} unreadable")
        if not under and (info.st_mode & 0o077 or info.st_uid != os.geteuid()):
            raise PushConfigError(f"{what} is accessible to others or owned by another user")
        with os.fdopen(fd, "rb", closefd=False) as handle:
            return handle.read(64 * 1024)
    finally:
        os.close(fd)


def load(env=None):
    """None when push is not configured at all; a PushConfig when complete; else PushConfigError."""
    env = os.environ if env is None else env
    given = {name for name in ALL_NAMES if env.get(name, "").strip()}
    if not given:
        return None
    team, topic, token_file = (env.get(n, "").strip() for n in (TEAM, TOPIC, TOKEN_KEY))
    problems = [n for n, v in ((TEAM, team), (TOPIC, topic), (TOKEN_KEY, token_file)) if not v]
    enabled = {}
    for name in ENVS:
        kid_name, file_name = KEY_ID.format(name.upper()), KEY_FILE.format(name.upper())
        kid, path = env.get(kid_name, "").strip(), env.get(file_name, "").strip()
        if bool(kid) != bool(path):
            problems.append(file_name if kid else kid_name)
        elif kid:
            enabled[name] = (kid, path)
    if not enabled:
        problems.append("one environment's key id and key file")
    if problems:
        raise PushConfigError("partial push configuration, missing: " + ", ".join(problems))
    if not IDENT.fullmatch(team):
        raise PushConfigError(f"{TEAM} is not a 10-character Apple team id")
    if not TOPIC_SHAPE.fullmatch(topic):
        raise PushConfigError(f"{TOPIC} is not a bundle id")
    secret = read_secret_file(token_file, "push token secret")
    if len(secret) != 32:
        raise PushConfigError("push token secret must be exactly 32 bytes")
    keys, cache = {}, {}
    for name, (kid, path) in enabled.items():
        if not IDENT.fullmatch(kid):
            raise PushConfigError(f"apns key id ({name}) is not a 10-character Apple key id")
        if (kid, path) not in cache:  # one key serving both gateways is parsed once
            try:
                private = serialization.load_pem_private_key(
                    read_secret_file(path, f"apns key ({name})"), password=None
                )
            except PushConfigError:
                raise
            except (ValueError, TypeError, UnsupportedAlgorithm):
                raise PushConfigError(f"apns key unreadable ({name})") from None
            if not isinstance(private, ec.EllipticCurvePrivateKey) or not isinstance(
                private.curve, ec.SECP256R1
            ):
                raise PushConfigError(f"apns key unreadable ({name})")
            cache[(kid, path)] = private
        keys[name] = (kid, cache[(kid, path)])
    k_tok, k_mac = derive(secret)
    return PushConfig(team, topic, k_tok, k_mac, keys)
