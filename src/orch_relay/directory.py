"""Directory transactions and shared authorization for protocol-v2 §19.

All entry points run in the thread pool. The process lock serializes ephemeral budgets
with SQLite transactions; BEGIN IMMEDIATE also serializes the admin CLI and later groups.
"""

import hashlib
import heapq
import ipaddress
import logging
import math
import os
import re
import secrets
import sqlite3
import threading
import time
from collections import Counter, OrderedDict
from contextlib import closing

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from . import db
from . import proto as P

MINUTE, HOUR, DAY = 60_000, 3_600_000, 86_400_000
# P3-D34 (G3): workspaces one account (owner person) may own; a first card beyond it is 429
# quota_exceeded. Bounds per-account staging fairness and storage (x the per-workspace node quota).
ACCOUNT_WORKSPACES = 32
MAX_RESPONSE = 4 * 1024 * 1024
# P3-D35 (pre-public-deploy blocker 4): token buckets for authenticated requests, as (burst,
# refill per minute). Every request with a valid session on a directory, bridge or checkpoint route
# takes one token of its session's bucket, and of its workspace's for a W session (W sessions are
# not capped in number; device sessions are, 8 per device), after authentication and before any
# lock, slot or write; proof and transition pages also take one of the page buckets. Refusals
# after authentication are charged the same, so a valid session spamming refused requests is
# throttled too. Honest clients long-poll (up to 25 s) or poll at most every few seconds, and a
# sync reads a handful of directory objects: 600/min sustained (10/s) and a 600 burst is two
# orders of magnitude above that. A device walks at most a few dozen proof pages (a full 64 MiB
# set is about 16 pages of 56,680 heads, plus one page per small log), so the page burst is 256 and
# the refill 2/s. Overrides: ORCH_RELAY_THROTTLE_<NAME>="burst/per-minute". In memory, reset on
# restart (accepted, like every rate window).
THROTTLES = {
    "session": (600, 600),
    "workspace": (1200, 1200),
    "page-session": (256, 120),
    "page-workspace": (512, 240),
}
# Buckets kept (LRU-evicted beyond it; ORCH_RELAY_THROTTLE_TABLE). Only authenticated sessions and
# their workspaces create entries, so a flood of bad tokens adds none; about 390 B per entry
# (measured), ~25 MB when full.
THROTTLE_TABLE = 65_536
# P3-D35 item 4: the unauthenticated revocation-pair read per IPv6 /56 (as challenges and pairing).
REVOCATION_READ_PARENT = 960
BODY_CAPS = {"accounts": 65536, "card": 65536, "card_keys": 65536, "membership": 2097152}


def body_cap(route):
    return BODY_CAPS.get(route, 16384)


STATUS = {
    **dict.fromkeys(
        (
            "stale_list",
            "stale_epoch",
            "bad_epoch",
            "rotation_required",
            "wk_commit_changed",
            "missing_grant",
            "grant_conflict",
            "wrap_conflict",
        ),
        409,
    ),
    "scope_exceeded": 403,
    "not_for_this_device": 403,
    "unknown_challenge": 401,
    "expired": 401,
    "bad_signature": 401,
    "unauthenticated": 401,
    "revoked": 403,
    "not_eligible": 403,
    "other_person": 403,
    "account_exists": 409,
    "cert_conflict": 409,
    "fenced": 409,
    "other_workspace": 409,
    "wsk_changed": 409,
    "delegation_changed": 409,
    "stale_card": 409,
    "wxk_changed_without_version": 409,
    "bad_wxk_version": 409,
    "not_found": 404,
    "rate_limited": 429,
    "quota_exceeded": 429,
    "too_large": 413,
}


class Refusal(Exception):
    def __init__(self, code, retry=None):
        self.code, self.status, self.retry = code, STATUS.get(code, 400), retry


def fail(code, retry=None):
    raise Refusal(code, retry)


def checked(result):
    if "refuse" in result:
        fail(result["refuse"])
    return result["ok"]


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def token_hash(token):
    # Tokens are opaque to callers; only their hash is persisted.
    try:
        raw = P.unb64u(token, 32)
    except ValueError:
        raw = token.encode("utf-8")
    return digest(raw)


def fields(body, expected):
    if not isinstance(body, dict) or set(body) != set(expected.split()):
        fail("malformed")


def integer(text, maximum=P.MAX_SAFE_INT):
    if not isinstance(text, str) or not re.fullmatch(r"[0-9]+", text):
        fail("malformed")
    value = int(text)
    if value > maximum:
        fail("malformed")
    return value


def check_suite(signed):
    if isinstance(signed, dict) and isinstance(signed.get("o"), dict):
        suite = signed["o"].get("suite")
        if type(suite) is int and suite != 2:
            fail("wrong_suite")


def canonical_address(peer, forwarded, trusted_proxy):
    """Trust a single proxy hop only; ignore caller-supplied XFF otherwise."""
    try:
        address = ipaddress.ip_address(peer)
        if address.version == 6 and address.ipv4_mapped:
            address = address.ipv4_mapped
        proxy = ipaddress.ip_address(trusted_proxy) if trusted_proxy else None
        if proxy and proxy.version == 6 and proxy.ipv4_mapped:
            proxy = proxy.ipv4_mapped
        if address == proxy and not forwarded:
            logging.getLogger(__name__).warning("Trusted proxy sent no X-Forwarded-For")
        if address == proxy and forwarded:
            # Caddy appends its immediate peer; never trust an attacker-chosen leftmost hop.
            address = ipaddress.ip_address(forwarded.split(",")[-1].strip())
            if address.version == 6 and address.ipv4_mapped:
                address = address.ipv4_mapped
        return (
            str(ipaddress.ip_network(f"{address}/64", strict=False))
            if address.version == 6
            else str(address)
        )
    except ValueError:
        return peer  # A malformed forwarded header never creates a fresh budget identity.


def ipv6_parent(address):
    try:
        network = ipaddress.ip_network(address, strict=False)
        return str(network.supernet(new_prefix=56)) if network.version == 6 else None
    except ValueError:
        return None


def check_response_budget(device_bytes, workspace_bytes, incoming_bytes):
    """G3 calls under its queue transaction using persisted undelivered byte totals.

    Totals span all sessions; call before insertion, release on delivery/expiry/revocation.
    This checks capacity without evicting or mutating queues.
    """
    if min(device_bytes, workspace_bytes, incoming_bytes) < 0:
        raise ValueError("negative response byte count")
    if (
        device_bytes + incoming_bytes > 2 * 1024 * 1024
        or workspace_bytes + incoming_bytes > 16 * 1024 * 1024
    ):
        fail("quota_exceeded")


def usable_account(con, person):
    """The person's account row, or None while it exists only from restore evidence (P3-D29):
    such a person registers no device and owns no card until it redeems an invite."""
    return con.execute(
        "SELECT pk_pub FROM accounts a WHERE person_id=? AND NOT EXISTS ("
        "SELECT 1 FROM evidence_persons e WHERE e.person_id=a.person_id)",
        (person,),
    ).fetchone()


def pair_revoked(con, device_id, person_id):
    """Does the relay hold a revocation of the (device_id, person_id) pair (global §19.5 table)?

    P3-D30 (orch-52 ruling 2): the device-auth cutoff (sessions, login, member and stored
    certificates) is per pair, the device plus the person of the registry row it authenticates
    under. Callers pass `devices.person_id`, never a person named by the request, so a stranger's
    self-certified pair for the same device id never cuts off the registered person's device."""
    return (
        con.execute(
            "SELECT 1 FROM revocations WHERE device_id=? AND person_id=?", (device_id, person_id)
        ).fetchone()
        is not None
    )


def chain_revoked(con, device_id):
    """Does any workspace's chain hold a revocation of this device id, whatever the person?

    Chain-learned (P3-D30) = recorded in `checkpoint_revocations` by an accepted restore, the only
    authenticated-history source this relay has. Out-of-band rows (the global table alone) are not
    chain-learned. Served by migration 0011's index."""
    return (
        con.execute(
            "SELECT 1 FROM checkpoint_revocations WHERE device_id=? LIMIT 1", (device_id,)
        ).fetchone()
        is not None
    )


def registration_refused(con, device_id, person_id):
    """P3-D30: a NEW registration of `device_id` for `person_id` (the person of the verified
    certificate, who becomes the registry person) is refused (403 `revoked`) when any chain-learned
    revocation of the id exists, of any person, or when the new pair itself is revoked. Out-of-band
    evidence of another person alone never refuses it.

    Refusing on any chain pair keeps the F1 §5.10 limit unreachable: a registry person that
    contradicts a chain pair would strand every workspace whose chain holds that pair."""
    return chain_revoked(con, device_id) or pair_revoked(con, device_id, person_id)


def window_rate(state, purpose, identity, duration, cap, now, charge=True):
    """Fixed-window budget on `state.windows`/`state.window_expiry` (the caller holds its mutex).

    A check (charge=False) has no side effects at all, not even the lazy cleanup: pre-checks run it
    outside Directory.lock (P3-D32). Refusal: 429 `rate_limited` with Retry-After to the window end.
    """
    if charge:
        # Bounded lazy cleanup avoids scanning all live windows or a restart-sized backlog.
        for _ in range(64):
            if not state.window_expiry or state.window_expiry[0][0] > now:
                break
            old_end, old_key = heapq.heappop(state.window_expiry)
            if state.windows.get(old_key, (None,))[0] == old_end:
                del state.windows[old_key]
    key = (purpose, identity, duration)
    end, count = state.windows.get(key, ((now // duration + 1) * duration, 0))
    if now >= end:
        end, count = (now // duration + 1) * duration, 0
    if count >= cap:
        fail("rate_limited", max(1, math.ceil((end - now) / 1000)))
    if charge:
        if key not in state.windows or state.windows[key][0] != end:
            heapq.heappush(state.window_expiry, (end, key))
        state.windows[key] = (end, count + 1)


class Buckets:
    """Token buckets with a bounded table (P3-D35); the caller holds Directory.budget.

    Levels are integers in 1/60,000 of a token, so a refill of `rate` tokens per minute adds
    exactly `rate` units per millisecond and every count is deterministic under an injected clock.
    A missing entry is a full bucket, so evicting the least recently charged entry beyond `limit`
    can only make that identity's next request more permissive, never refuse anyone else."""

    UNIT = 60_000

    def __init__(self, limit=THROTTLE_TABLE):
        self.limit = limit
        self.table = OrderedDict()  # key -> (level, ms of the level)

    def take(self, key, burst, rate, now, charge=True):
        """Refuse 429 `rate_limited` (Retry-After to the next whole token) when less than one token
        is left; else, with charge, take it. A check (charge=False) has no side effects at all."""
        full = burst * self.UNIT
        level, at = self.table.get(key, (full, now))
        level = min(full, level + max(0, now - at) * rate)
        if level < self.UNIT:
            fail("rate_limited", max(1, math.ceil((self.UNIT - level) / rate / 1000)))
        if charge:
            self.table[key] = (level - self.UNIT, max(now, at))
            self.table.move_to_end(key)
            while len(self.table) > self.limit:
                self.table.popitem(last=False)


def throttle_settings(env):
    """THROTTLES and THROTTLE_TABLE with ORCH_RELAY_THROTTLE_* overrides (positive integers)."""
    settings = dict(THROTTLES)
    for name in THROTTLES:
        text = env.get("ORCH_RELAY_THROTTLE_" + name.upper().replace("-", "_"))
        if text is not None:
            burst, rate = (int(part) for part in text.split("/"))
            if burst <= 0 or rate <= 0:
                raise ValueError(f"throttle {name} needs a positive burst/per-minute")
            settings[name] = (burst, rate)
    table = int(env.get("ORCH_RELAY_THROTTLE_TABLE", THROTTLE_TABLE))
    if table <= 0:
        raise ValueError("ORCH_RELAY_THROTTLE_TABLE must be positive")
    return settings, table


class Proceed(Exception):
    """A pre-check reached the route's authorization point: the transaction decides the rest."""


# Pre-check steps that are the whole, read-only answer (P3-D32): a challenge (no database), a logout
# of no stored session, a revocation receipt replay and the public revocation-pair read.
FINAL = "final"


class Directory:
    def __init__(self, path, origin, trusted_proxy=None):
        self.path, self.origin, self.trusted_proxy = path, origin, trusted_proxy
        self.account_workspaces = ACCOUNT_WORKSPACES  # P3-D34; ORCH_RELAY_ACCOUNT_WORKSPACES
        origin.encode("ascii")
        self.lock = threading.RLock()
        # In-memory challenges and rate windows. Taken alone by pre-checks (P3-D32) and inside
        # self.lock by transactions, never the other way round; held only for dict/heap updates.
        self.budget = threading.RLock()
        self.challenges = {}  # challenge -> (expires_ms, canonical address, /56 parent)
        self.challenge_expiry = []
        self.challenge_addresses = Counter()
        self.challenge_parents = Counter()
        self.window_expiry = []
        self.windows = {}  # (purpose, identity, duration) -> (window end, count)
        self.throttles = dict(THROTTLES)  # P3-D35; ORCH_RELAY_THROTTLE_*
        self.buckets = Buckets()  # under self.budget
        self.proxy_warned = False
        self.clock = lambda: time.time_ns() // 1_000_000
        self.changed = None  # event-loop callback(*keys) after committed writes (wakes polls)
        self.random = secrets.token_bytes
        self.dummy_pub = (
            ec.generate_private_key(ec.SECP256R1())
            .public_key()
            .public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        )
        # Shared with the bridge and checkpoints (P3-D32 round 2): one write connection and a
        # bounded read pool, owned by no worker thread.
        self.pool = db.Connections(path)

    def connection(self, purpose):
        """The shared write connection, only under self.lock with BEGIN IMMEDIATE."""
        assert purpose == "write" and self.lock._is_owned(), "write connection outside the lock"
        return self.pool.write()

    def reader(self, purpose="read"):
        """Borrow a pooled read connection for one use (context manager). "read" is query-only
        with busy_timeout=0: a pre-check never waits (WAL readers do not block on writers; on any
        sqlite3.Error the transaction decides alone); its snapshot ends when it is returned."""
        return self.pool.borrow(purpose)

    def close(self):
        self.pool.close()

    @staticmethod
    def authorized(state):
        """A route's authorization point: everything before it is read-only (no write, no window
        charge, no in-memory change but the once-only steps in `state`). A pre-check stops here."""
        if state and state.get("pre"):
            raise Proceed

    @staticmethod
    def final(state):
        """The pre-check's result is the whole answer (read-only routes only, see FINAL)."""
        if state is not None:
            state[FINAL] = True

    def consume_once(self, challenge, now, state):
        """Consume the request's challenge exactly once: a pre-check consumes it (it is removed
        whatever follows, §19.4) and the transaction reuses the consumed bytes."""
        if state is None:
            return self.consume(challenge, now)
        if "challenge" not in state:
            state["challenge"] = self.consume(challenge, now)
        return state["challenge"]

    def assert_can_wait(self):
        """G3 must call before a long-poll wait, outside its database transaction."""
        assert not self.lock._is_owned(), "long poll cannot wait while holding directory.lock"

    def rate(self, purpose, identity, duration, cap, now, charge=True):
        with self.budget:
            window_rate(self, purpose, identity, duration, cap, now, charge)

    def throttle(self, session, now, page=False):
        """P3-D35: take one token of an authenticated request's buckets, or refuse 429. Callers
        charge only after authentication (a request without a valid session charges nothing) and
        before any lock, slot or write; refusals after authentication are charged too. All
        buckets are checked before any is charged, under the budget mutex."""
        keys = [("session", session["token_hash"])]
        if session["kind"] == "workspace":
            keys.append(("workspace", session["subject_id"]))
        if page:
            keys += [("page-" + purpose, identity) for purpose, identity in keys]
        with self.budget:
            for charge in (False, True):
                for key in keys:
                    self.buckets.take(key, *self.throttles[key[0]], now, charge)

    def client_address(self, peer, headers):
        """canonical_address(), warning once (N4) when a proxy forwards but none is trusted."""
        forwarded = headers.get("x-forwarded-for")
        if forwarded and not self.trusted_proxy and not self.proxy_warned:
            self.proxy_warned = True
            logging.getLogger(__name__).warning(
                "X-Forwarded-For received but ORCH_RELAY_TRUSTED_PROXY is unset: behind a reverse "
                "proxy every client shares the proxy's address (pair polls, address windows); set "
                "it to the proxy's IP address"
            )
        return canonical_address(peer, forwarded, self.trusted_proxy)

    def consume(self, challenge, now):
        P.unb64u(challenge, 32)
        with self.budget:
            state = self.remove_challenge(challenge)
        if state is None:
            fail("unknown_challenge")
        if now >= state[0]:
            fail("expired")
        return P.unb64u(challenge, 32)

    def add_challenge(self, challenge, expires, address, parent):
        with self.budget:
            self.challenges[challenge] = (expires, address, parent)
            self.challenge_addresses[address] += 1
            if parent:
                self.challenge_parents[parent] += 1
            heapq.heappush(self.challenge_expiry, (expires, challenge))

    def remove_challenge(self, challenge):
        with self.budget:
            state = self.challenges.pop(challenge, None)
            if state is not None:
                for counts, key in (
                    (self.challenge_addresses, state[1]),
                    (self.challenge_parents, state[2]),
                ):
                    if key is not None:
                        counts[key] -= 1
                        if not counts[key]:
                            del counts[key]
            return state

    def issue(self, address, now):
        # No database state: runs under the budget mutex alone, never Directory.lock (P3-D32).
        with self.budget:
            return self.issue_unguarded(address, now)

    def issue_unguarded(self, address, now):
        # Bound cleanup after clock jumps; stale counts conservatively retain capacity.
        for _ in range(64):
            if not self.challenge_expiry or self.challenge_expiry[0][0] > now:
                break
            expires, challenge = heapq.heappop(self.challenge_expiry)
            if self.challenges.get(challenge, (None,))[0] == expires:
                self.remove_challenge(challenge)
        parent = ipv6_parent(address)
        # dict length is the incrementally maintained global outstanding count.
        if (
            len(self.challenges) >= 65_536
            or self.challenge_addresses[address] >= 16
            or (parent and self.challenge_parents[parent] >= 256)
        ):
            fail("rate_limited", 60)
        self.rate("challenge", address, MINUTE, 60, now, False)
        if parent:
            self.rate("challenge-parent", parent, MINUTE, 960, now)
        self.rate("challenge", address, MINUTE, 60, now)
        challenge = P.b64u(self.random(32))
        while challenge in self.challenges:
            challenge = P.b64u(self.random(32))
        self.add_challenge(challenge, now + MINUTE, address, parent)
        return {"challenge": challenge, "expires_ms": now + MINUTE}

    def device_status(self, con, device, now):
        # Device-auth cutoff per pair (P3-D30): `device` is the registry row, so the person is the
        # one this device id authenticates as (sessions, login, stored-certificate retries, bridge).
        if pair_revoked(con, device["device_id"], device["person_id"]):
            fail("revoked")
        if device["expires_ms"] is not None and now >= device["expires_ms"]:
            fail("cert_expired")

    def authenticate(self, con, headers, now, state=None):
        authorization = headers.get("authorization", "")
        if not authorization.startswith("Bearer "):
            fail("unauthenticated")
        session = con.execute(
            "SELECT * FROM sessions WHERE token_hash=?", (token_hash(authorization[7:]),)
        ).fetchone()
        if session is None or now >= session["expires_ms"]:
            fail("unauthenticated")
        session = dict(session)
        if session["kind"] == "device":
            device = con.execute(
                "SELECT * FROM devices WHERE device_id=?", (session["subject_id"],)
            ).fetchone()
            if device is None:
                fail("unauthenticated")
            self.device_status(con, device, now)
            session["person_id"] = device["person_id"]
            session["scopes_max"] = P.parse_json(device["scopes_max"])
        elif not con.execute(
            "SELECT 1 FROM workspaces WHERE workspace_id=?", (session["subject_id"],)
        ).fetchone():
            fail("unauthenticated")
        if state is not None:
            state["session"] = session  # handle() charges its buckets (P3-D35)
        return session

    def person_access(self, con, session, person):
        if session["kind"] == "device":
            allowed = session["person_id"] == person and not session["scopes_max"][0].startswith(
                "drop:"
            )
        else:
            allowed = con.execute(
                "SELECT 1 FROM ever_persons p WHERE p.workspace_id=? AND p.person_id=? "
                "AND EXISTS (SELECT 1 FROM ever_devices e JOIN devices d ON d.device_id=e.device_id "
                "WHERE e.workspace_id=p.workspace_id AND d.person_id=p.person_id)",
                (session["subject_id"], person),
            ).fetchone()
        if not allowed:
            fail("not_eligible")

    def workspace_access(self, con, session, ws, write=False):
        if session["kind"] == "workspace":
            allowed = session["subject_id"] == ws
        else:
            allowed = (
                not write
                and not session["scopes_max"][0].startswith("drop:")
                and con.execute(
                    "SELECT 1 FROM members WHERE workspace_id=? AND device_id=?",
                    (ws, session["subject_id"]),
                ).fetchone()
            )
        if not allowed:
            fail("not_eligible")

    def fence(self, con, headers, ws, now):
        text = headers.get("orch-holder")
        if text is None:
            fail("fenced")
        gen = integer(text)
        holder = con.execute("SELECT * FROM holders WHERE workspace_id=?", (ws,)).fetchone()
        if holder is None or holder["gen"] != gen or holder["lease_until_ms"] <= now:
            fail("fenced")

    def wake_keys(self, con, route, ident, body, logout):
        """Long polls a committed directory write can end or make ready (bridge keys)."""
        if route == "revocations":
            did = body["record"]["o"]["device_id"]
            return [("subject", did)] + [
                ("ws", row[0])
                for row in con.execute(
                    "SELECT workspace_id FROM ever_devices WHERE device_id=?", (did,)
                )
            ]
        if route == "device":
            # Certificate completion changes cert_requests notices of the person's hosts.
            return [("subject", ident)] + [
                ("ws", row[0])
                for row in con.execute(
                    "SELECT DISTINCT workspace_id FROM cert_requests WHERE person_id="
                    "(SELECT person_id FROM devices WHERE device_id=?)",
                    (ident,),
                )
            ]
        if route == "membership":
            return [("ws", ident), ("members", ident)]
        if route == "logout" and logout:
            return [("subject", logout[0])]
        return []

    def store_device(self, con, cert):
        o = cert["o"]
        try:
            con.execute(
                "INSERT INTO devices VALUES (?,?,?,?,?,?,?)",
                (
                    o["device_id"],
                    o["person_id"],
                    P.cj(cert),
                    o["dk_sig_pub"],
                    o["dk_kx_pub"],
                    P.cj(o["scopes_max"]),
                    o["expires_ms"],
                ),
            )
        except sqlite3.IntegrityError:
            fail("cert_conflict")

    def account(self, con, body, raw, now, state=None):
        fields(body, "invite pk_pub device_cert challenge sig")
        if not isinstance(body["invite"], str) or not body["invite"]:
            fail("malformed")
        invite_hash = digest(body["invite"].encode())
        invite = con.execute("SELECT * FROM invites WHERE code_hash=?", (invite_hash,)).fetchone()
        if invite and invite["request_digest"] == digest(raw):
            return {"person_id": invite["used_by"]}
        if invite and invite["used_ms"] is None and now < invite["expires_ms"] + MINUTE:
            # P3-D32: an unused invite may be being redeemed by a concurrent identical request,
            # whose retry must see the replay, not a challenge this pre-check consumed: only the
            # transaction consumes it. A used invite never becomes unused and its replay was
            # answered above, and a request on an invite expired for over a minute cannot race a
            # redemption still in flight (review F2): those, and requests without an invite, are
            # refused below in the pre-check, after consuming the challenge.
            self.authorized(state)
        challenge = self.consume_once(body["challenge"], now, state)
        if invite is None or invite["used_ms"] is not None or now >= invite["expires_ms"]:
            fail("not_eligible")
        check_suite(body["device_cert"])
        pub = P.unb64u(body["pk_pub"], 65)
        if not P.SUITE.pub_ok(pub):
            fail("cert_invalid")
        check_suite(body["device_cert"])
        # As PUT /v2/devices (recovery): a new registration is refused for a device id with any
        # chain-learned revocation, or a revocation of the new pair itself (P3-D30). Since 0010
        # such an id can exist without a registry row (restore evidence registers nothing).
        cert_o = body["device_cert"].get("o") if isinstance(body["device_cert"], dict) else None
        did, person = (
            (cert_o.get("device_id"), cert_o.get("person_id"))
            if isinstance(cert_o, dict)
            else (None, None)
        )
        prior = (
            isinstance(did, str)
            and isinstance(person, str)
            and registration_refused(con, did, person)
        )
        o = checked(P.verify_cert(body["device_cert"], pub, now, {did} if prior else set()))
        if not P.SUITE.verify(
            P.unb64u(o["dk_sig_pub"]),
            P.unb64u(body["sig"]),
            P.auth_bytes(self.origin, challenge, "device", o["device_id"]),
        ):
            fail("bad_signature")
        if usable_account(con, o["person_id"]):
            fail("account_exists")
        self.authorized(state)
        # P3-D29: redeeming an invite turns an evidence-only row (same person_id, so the same
        # pk_pub) into the account; its revocations stay. P3-D30 round 2 (review R1): its device
        # rows, written by pre-0010 restore evidence, are deleted first. Restores create no
        # association (ruling 1), and keeping them would make each one an association the moment
        # the person stops being evidence-only, contradicting any other workspace's chain pair for
        # that id (the F1 §5.10 strand). Each such device is cut off by its own revoked pair and
        # its re-registration is refused by its chain pair. Nothing else can reference it: no
        # session (its pair is revoked), member row, grant, wrap or queue (all need a usable
        # account); sessions and queues are cleared anyway.
        if con.execute(
            "SELECT 1 FROM evidence_persons WHERE person_id=?", (o["person_id"],)
        ).fetchone():
            self.drop_evidence_devices(con, o["person_id"])
        con.execute("DELETE FROM evidence_persons WHERE person_id=?", (o["person_id"],))
        con.execute(
            "INSERT INTO accounts VALUES (?,?,?) ON CONFLICT(person_id) DO UPDATE SET "
            "created_ms=excluded.created_ms",
            (o["person_id"], body["pk_pub"], now),
        )
        self.store_device(con, body["device_cert"])
        con.execute(
            "UPDATE invites SET used_ms=?, used_by=?, request_digest=? WHERE code_hash=?",
            (now, o["person_id"], digest(raw), invite_hash),
        )
        return {"person_id": o["person_id"]}

    def drop_evidence_devices(self, con, person):
        """Delete an evidence-only person's device rows (P3-D30 round 2; migration 0012 did the
        same once for every evidence-only person)."""
        from .members import prune_device

        for (did,) in con.execute(
            "SELECT device_id FROM devices WHERE person_id=?", (person,)
        ).fetchall():
            con.execute("DELETE FROM sessions WHERE kind='device' AND subject_id=?", (did,))
            prune_device(con, did)
        con.execute("DELETE FROM devices WHERE person_id=?", (person,))

    def login(self, con, body, now, state=None):
        # Consume a recognizable challenge even if other fields are malformed.
        if not isinstance(body, dict) or "challenge" not in body:
            fail("malformed")
        challenge = self.consume_once(body["challenge"], now, state)
        fields(body, "challenge kind id sig")
        kind, ident = body["kind"], body["id"]
        if kind not in ("device", "workspace"):
            fail("malformed")
        P.unhex(ident)
        if kind == "device":
            subject = con.execute("SELECT * FROM devices WHERE device_id=?", (ident,)).fetchone()
            pub = P.unb64u(subject["dk_sig_pub"]) if subject else self.dummy_pub
        else:
            subject = con.execute(
                "SELECT * FROM workspaces WHERE workspace_id=?", (ident,)
            ).fetchone()
            pub = P.unb64u(subject["wsk_pub"]) if subject else self.dummy_pub
        try:
            sig = P.unb64u(body["sig"])
        except ValueError:
            sig = b""
        valid = P.SUITE.verify(pub, sig, P.auth_bytes(self.origin, challenge, kind, ident))
        if not valid or subject is None:
            fail("bad_signature")
        if kind == "device":
            self.device_status(con, subject, now)
            account = con.execute(
                "SELECT pk_pub FROM accounts WHERE person_id=?", (subject["person_id"],)
            ).fetchone()
            checked(P.verify_cert(P.parse_json(subject["cert"]), P.unb64u(account["pk_pub"]), now))
        if kind == "device":
            live = con.execute(
                "SELECT COUNT(*), MIN(expires_ms) FROM sessions "
                "WHERE kind='device' AND subject_id=? AND expires_ms>?",
                (ident, now),
            ).fetchone()
            if live[0] >= 8:
                fail("quota_exceeded", max(1, math.ceil((live[1] - now) / 1000)))
        self.authorized(state)
        token = P.b64u(self.random(32))
        con.execute("DELETE FROM sessions WHERE expires_ms<=?", (now,))
        con.execute(
            "INSERT INTO sessions VALUES (?,?,?,?)", (token_hash(token), kind, ident, now + 900_000)
        )
        return {"token": token, "expires_ms": now + 900_000}

    def recovery(self, con, body, raw, address, now, device=None, state=None):
        """Verify and apply recovery; handle() has already enforced the address budget."""
        from .cert_queue import complete

        revocation = device is None
        kind = "revocation" if revocation else "certificate"
        field = "record" if revocation else "cert"
        fields(body, field)
        signed = body[field]
        check_suite(signed)
        if not isinstance(signed, dict) or not isinstance(signed.get("o"), dict):
            fail("malformed" if revocation else "cert_invalid")
        o = signed["o"]
        person, did = o.get("person_id"), o.get("device_id")
        P.unhex(person)
        P.unhex(did)
        if device is not None and did != device:
            fail("cert_invalid")
        receipt = con.execute(
            "SELECT subject_id FROM recovery_receipts WHERE kind=? AND request_digest=?",
            (kind, digest(raw)),
        ).fetchone()
        if receipt:
            if revocation:
                self.final(state)  # a read-only replay: answered from the pre-check's snapshot
                return {"device_id": did}
            self.authorized(state)
            stored = con.execute("SELECT * FROM devices WHERE device_id=?", (did,)).fetchone()
            self.device_status(con, stored, now)
            complete(con, P.parse_json(stored["cert"]), now)
            return {"device_id": did}
        account = con.execute("SELECT pk_pub FROM accounts WHERE person_id=?", (person,)).fetchone()
        if account is None or (not revocation and usable_account(con, person) is None):
            fail("other_person")
        pub = P.unb64u(account["pk_pub"])
        stored = con.execute("SELECT * FROM devices WHERE device_id=?", (did,)).fetchone()
        # A revocation is held per (device, person) pair (orch-core #397). A certificate (P3-D30):
        # the stored device is cut off per pair, under its registry person (never the request's);
        # a new registration is refused on any chain-learned revocation of the id, or its own pair.
        if revocation:
            prior = con.execute(
                "SELECT * FROM revocations WHERE device_id=? AND person_id=?", (did, person)
            ).fetchone()
        elif stored:
            prior = pair_revoked(con, did, stored["person_id"])
        else:
            prior = registration_refused(con, did, person)
        if revocation:
            checked(
                P.verify_revocation(
                    signed, pub, P.parse_json(stored["cert"])["o"] if stored else None
                )
            )
        else:
            checked(P.verify_cert(signed, pub, now, {did} if prior else set()))
            if stored and P.cj(P.parse_json(stored["cert"])["o"]) != P.cj(signed["o"]):
                fail("cert_conflict")
        if (not revocation and stored) or (
            revocation
            and prior
            and (prior["reason"] == "compromised" or o["reason"] != "compromised")
        ):
            self.authorized(state)
            # Cache accepted no-ops too: a byte-identical retry must bypass address budgets.
            con.execute("INSERT INTO recovery_receipts VALUES (?,?,?)", (kind, digest(raw), did))
            if not revocation:
                complete(con, signed, now)
            return {"device_id": did}
        self.rate(kind + "-person", person, DAY, 32 if revocation else 64, now, False)
        if revocation and prior:
            self.rate("revocation-repeat", person, DAY, 24, now, False)
        self.authorized(state)
        self.rate(kind + "-person", person, DAY, 32 if revocation else 64, now)
        if revocation and prior:
            self.rate("revocation-repeat", person, DAY, 24, now)
        if revocation:
            self.revoke(con, signed, now)
        elif stored is None:
            self.store_device(con, signed)
        if not revocation:
            complete(con, signed, now)
        con.execute("INSERT INTO recovery_receipts VALUES (?,?,?)", (kind, digest(raw), did))
        return {"device_id": did}

    def revoke(self, con, record, now):
        """Called only after PK verification; caller owns the write transaction (also G4).

        Retained per (device_id, person_id) pair (orch-core #397, migration 0010): another person's
        revocation of the same device id is another row, never dropped and never replacing this
        one; a pair only upgrades (§6.2 "no un-revoke").

        The cutoff below (sessions, prune_device's queues, grants and wraps, rotation_due) is per pair
        (P3-D30): it runs only when the record's person is the device's registry person
        (`devices.person_id`), the only person the device id authenticates as. Any other pair, and
        any revocation of an unregistered id, has nothing to cut off: no session, member row or
        grant can exist without a registry row of that person. Such a pair is still stored."""
        o = record["o"]
        did = o["device_id"]
        prior = con.execute(
            "SELECT * FROM revocations WHERE device_id=? AND person_id=?", (did, o["person_id"])
        ).fetchone()
        cursor = prior["cursor"] if prior else None
        if prior is None or (prior["reason"] != "compromised" and o["reason"] == "compromised"):
            cursor = con.execute("SELECT COALESCE(MAX(cursor),0)+1 FROM revocations").fetchone()[0]
            con.execute(
                "INSERT INTO revocations VALUES (?,?,?,?,?,?) ON CONFLICT(device_id,person_id) "
                "DO UPDATE SET record=excluded.record, reason=excluded.reason, "
                "received_ms=excluded.received_ms, cursor=excluded.cursor",
                (did, o["person_id"], P.cj(record), o["reason"], now, cursor),
            )
        registered = con.execute(
            "SELECT person_id FROM devices WHERE device_id=?", (did,)
        ).fetchone()
        if registered is None or registered[0] != o["person_id"]:
            return
        con.execute("DELETE FROM sessions WHERE kind='device' AND subject_id=?", (did,))
        from .members import prune_device

        prune_device(con, did)
        con.execute(
            """INSERT INTO rotation_due(workspace_id, device_id, revocation_cursor, epoch)
            SELECT m.workspace_id, m.device_id, ?, COALESCE((SELECT epoch FROM member_lists l
                WHERE l.workspace_id=m.workspace_id ORDER BY list_seq DESC LIMIT 1),0)
            FROM members m WHERE m.device_id=?
            ON CONFLICT(workspace_id,device_id) DO UPDATE SET
                revocation_cursor=excluded.revocation_cursor, epoch=excluded.epoch""",
            (cursor, did),
        )

    PAIR_PAGE = 32

    def revocation_pairs(self, con, device, query):
        """GET /v2/devices/{device}/revocation?after=&limit= (P3-D30, orch-52 ruling 3; paginated
        in round 2, review S1): every held pair of the device id, at most 32 per page, as
        `{pairs, next}`. The registered person's pair is first on page 1; the others follow
        chain before feed, then by §19.5 cursor (earliest first), never by person_id, which an
        attacker chooses (minted keys) to push genuine pairs off page 1. `next` is opaque and
        passed back as `after`. A walk is not a snapshot: a pair whose label or cursor changes
        during it (upgraded, a feed pair carried by a restore, a registry pair created after page 1)
        may be MISSED or repeated; a client restarts from page 1 for a consistent view. A valid
        `after` past the last pair is an empty 200 page, also for a device with no pairs.
        Intake is not capped (that would let an attacker block restores).

        provenance: 'registry' when the pair's person is the device's association (its registry row,
        excluding P3-D29 evidence-only rows, which restores created); 'chain' when an accepted
        restore of some workspace carried the pair (`checkpoint_revocations`: carried by some
        workspace host, NOT authenticated by the device's person); 'feed' otherwise (the §19.5
        table alone). The labels are relay claims; no client decision may rest on this route.

        The route is unauthenticated, so each entry is only the public signed record (the strongest
        held, the §19.5 row) and its label. Security review of P3-D30: no device certificate (the
        registry one is gated by GET /v2/devices/{device}; a chain one came from another
        workspace's restore, readable only through that workspace's routes) and no account key."""
        limit = integer(query.get("limit", str(self.PAIR_PAGE)), self.PAIR_PAGE)
        if limit == 0:
            fail("malformed")
        rank, cursor = -1, 0
        if "after" in query:
            continuation = P.parse_json(P.unb64u(query["after"]))
            fields(continuation, "device rank cursor")
            rank, cursor = continuation["rank"], continuation["cursor"]
            if (
                continuation["device"] != device
                or type(rank) is not int
                or rank not in (0, 1, 2)
                or type(cursor) is not int
            ):
                fail("malformed")
        rows = con.execute(
            "SELECT * FROM (SELECT r.person_id, r.reason, r.record, r.cursor, CASE "
            "WHEN d.device_id IS NOT NULL THEN 0 WHEN EXISTS (SELECT 1 FROM checkpoint_revocations "
            "c WHERE c.device_id=r.device_id AND c.person_id=r.person_id) THEN 1 ELSE 2 END rank "
            "FROM revocations r LEFT JOIN devices d ON d.device_id=r.device_id "
            "AND d.person_id=r.person_id "
            "AND NOT EXISTS (SELECT 1 FROM evidence_persons e WHERE e.person_id=d.person_id) "
            "WHERE r.device_id=?) WHERE (rank, cursor) > (?, ?) ORDER BY rank, cursor LIMIT ?",
            (device, rank, cursor, limit + 1),
        ).fetchall()
        if not rows and "after" not in query:
            fail("not_found")
        page = rows[:limit]
        last = page[-1] if page else None
        return {
            "pairs": [
                {
                    "person_id": person,
                    "reason": reason,
                    "revocation": P.parse_json(record),
                    "provenance": ("registry", "chain", "feed")[rank_],
                }
                for person, reason, record, _, rank_ in page
            ],
            "next": P.b64u(P.cj({"device": device, "rank": last[4], "cursor": last[3]}))
            if len(rows) > limit
            else None,
        }

    def card_put(self, con, ws, body, headers, address, now, state=None):
        fields(body, "card")
        card = body["card"]
        check_suite(card)
        if isinstance(card, dict):
            check_suite(card.get("delegation"))
        stored = con.execute("SELECT * FROM workspaces WHERE workspace_id=?", (ws,)).fetchone()
        if stored:
            session = self.authenticate(con, headers, now, state)
            self.workspace_access(con, session, ws, write=True)
            self.fence(con, headers, ws, now)
        if not isinstance(card, dict) or not isinstance(card.get("o"), dict):
            fail("malformed")
        owner = card["o"].get("owner_person_id")
        P.unhex(owner)
        account = usable_account(con, owner)
        if account is None:
            fail("other_person")
        old_card = P.parse_json(stored["card"]) if stored else None
        previous = (
            {"o": old_card["o"], "delegation": old_card["delegation"]["o"]} if old_card else None
        )
        o = checked(P.relay_accept_card(previous, card, P.unb64u(account["pk_pub"])))
        if o["workspace_id"] != ws:
            fail("other_workspace")
        # The normative contract requires the complete canonical delegation to remain unchanged.
        if old_card and P.cj(old_card["delegation"]) != P.cj(card["delegation"]):
            fail("delegation_changed")
        if old_card and old_card["o"] == o:
            self.authorized(state)
            return {"card_seq": o["card_seq"]}
        if not stored:
            self.rate("card-address", address, HOUR, 10, now, False)
            self.rate("card-owner", owner, HOUR, 10, now, False)
            # P3-D34 (G3): live workspaces per account. Workspaces are never deleted, so this is
            # every workspace the person owns; read-only, so the pre-check refuses it unlocked.
            owned = con.execute(
                "SELECT count(*) FROM workspaces WHERE owner_person_id=?", (owner,)
            ).fetchone()[0]
            if owned >= self.account_workspaces:
                fail("quota_exceeded")
        self.authorized(state)
        if not stored:
            self.rate("card-address", address, HOUR, 10, now)
            self.rate("card-owner", owner, HOUR, 10, now)
        con.execute(
            """INSERT INTO workspaces VALUES (?,?,?,?,?,?,?,?)
            ON CONFLICT(workspace_id) DO UPDATE SET card=excluded.card,
            card_seq=excluded.card_seq, wxk_version=excluded.wxk_version""",
            (
                ws,
                owner,
                o["wsk_pub"],
                P.cj(card["delegation"]),
                P.cj(card),
                o["card_seq"],
                o["wxk_version"],
                card["delegation"]["o"]["client_hosted"],
            ),
        )
        return {"card_seq": o["card_seq"]}

    def dispatch(
        self, con, route, ident, method, body, raw, query, headers, address, now, state=None
    ):
        """Route dispatch. With state["pre"] it is the read-only pre-check: it stops at the route's
        authorization point (Proceed) or, for FINAL steps, is the whole answer (P3-D32)."""
        from . import members

        if route in members.ROUTES:
            P.unhex(ident)
            return members.dispatch(self, con, route, ident, body, raw, query, headers, now, state)
        allowed = {
            "feed": {"after", "limit", "next"},
            "revocation": {"after", "limit"},
        }.get(route, set())
        if any(k not in allowed for k in query) or len(query) != len(set(query.keys())):
            fail("malformed")
        if ident is not None:
            P.unhex(ident)
        if route == "challenge":
            fields(body, "")
            self.final(state)  # no database state; the budget mutex guards the windows
            return self.issue(address, now)
        if route == "login":
            return self.login(con, body, now, state)
        if route == "logout":
            fields(body, "")
            auth = headers.get("authorization", "")
            if auth.startswith("Bearer "):
                hashed = token_hash(auth[7:])
                if not (state and state.get("pre")):
                    con.execute("DELETE FROM sessions WHERE token_hash=?", (hashed,))
                elif con.execute("SELECT 1 FROM sessions WHERE token_hash=?", (hashed,)).fetchone():
                    raise Proceed
            self.final(state)  # nothing stored under this token: nothing to delete or wake
            return {}
        if route == "accounts":
            return self.account(con, body, raw, now, state)
        if route == "revocations":
            return self.recovery(con, body, raw, address, now, state=state)
        if route == "device" and method == "PUT":
            return self.recovery(con, body, raw, address, now, ident, state)
        if route == "revocation":
            # Public and read-only after its address windows (charged once per request).
            if not (state and "revocation-read" in state):
                windows = [("revocation-read", address, 60)]
                parent = ipv6_parent(address)
                if parent:
                    windows.append(("revocation-read-parent", parent, REVOCATION_READ_PARENT))
                with self.budget:
                    for charge in (False, True):
                        for purpose, identity, cap in windows:
                            self.rate(purpose, identity, MINUTE, cap, now, charge)
            if state is not None:
                state["revocation-read"] = True
            result = self.revocation_pairs(con, ident, query)
            self.final(state)
            return result
        if route == "card" and method == "PUT":
            return self.card_put(con, ident, body, headers, address, now, state)
        session = self.authenticate(con, headers, now, state)
        if route == "device":
            row = con.execute("SELECT * FROM devices WHERE device_id=?", (ident,)).fetchone()
            if row is None:
                fail("not_found")
            self.person_access(con, session, row["person_id"])
            if (
                session["kind"] == "workspace"
                and not con.execute(
                    "SELECT 1 FROM ever_devices WHERE workspace_id=? AND device_id=?",
                    (session["subject_id"], ident),
                ).fetchone()
            ):
                fail("not_eligible")
            self.authorized(state)
            return {"cert": P.parse_json(row["cert"])}
        if route == "card":
            row = con.execute(
                "SELECT card FROM workspaces WHERE workspace_id=?", (ident,)
            ).fetchone()
            if row is None:
                fail("not_found")
            self.workspace_access(con, session, ident)
            self.authorized(state)
            return {"card": P.parse_json(row["card"])}
        self.person_access(con, session, ident)
        self.authorized(state)
        after, limit = integer(query.get("after", "0")), integer(query.get("limit", "256"), 256)
        if limit == 0:
            fail("malformed")
        if "next" in query:
            # Opaque to clients, tied to the requested person and original after position.
            continuation = P.parse_json(P.unb64u(query["next"]))
            fields(continuation, "person after cursor")
            if continuation["person"] != ident or continuation["after"] != after:
                fail("malformed")
            after = integer(str(continuation["cursor"]))
        workspace = session["subject_id"] if session["kind"] == "workspace" else None
        rows = con.execute(
            "SELECT cursor,record FROM revocations r WHERE person_id=? AND cursor>? "
            "AND (? IS NULL OR EXISTS (SELECT 1 FROM ever_devices e "
            "WHERE e.workspace_id=? AND e.device_id=r.device_id)) ORDER BY cursor LIMIT ?",
            (ident, after, workspace, workspace, limit + 1),
        ).fetchall()
        entries, size = [], 0
        for row in rows[:limit]:
            item = {"cursor": row["cursor"], "record": P.parse_json(row["record"])}
            item_size = len(P.cj(item)) + 1
            if size + item_size > MAX_RESPONSE - 1024:
                break
            entries.append(item)
            size += item_size
        more = len(entries) < len(rows)
        next_value = (
            P.b64u(
                P.cj(
                    {
                        "person": ident,
                        "after": integer(query.get("after", "0")),
                        "cursor": entries[-1]["cursor"],
                    }
                )
            )
            if more and entries
            else None
        )
        return {"revocations": entries, "next": next_value}

    def steps(self, con, route, ident, method, raw, query, headers, address, now, state):
        """The request in order: the recovery address budget, the body, then dispatch. Shared by the
        pre-check (read connection, state["pre"]) and the transaction, so both refuse in the same
        order with the same codes. Returns (result, body, logout subject row)."""
        if route == "revocations" or (route == "device" and method == "PUT"):
            # Charged before authentication by design (throttles guessing).
            revocation = route == "revocations"
            kind = "revocation" if revocation else "certificate"
            receipt = con.execute(
                "SELECT subject_id FROM recovery_receipts WHERE kind=? AND request_digest=?",
                (kind, digest(raw)),
            ).fetchone()
            if not receipt or (not revocation and receipt["subject_id"] != ident):
                duration, cap = (MINUTE, 10) if revocation else (HOUR, 30)
                window = (kind + "-address", address, duration, cap, now)
                if state.get("pre"):
                    # Checked here, charged only if the pre-check refuses (preauthorize): a request
                    # that proceeds is charged by the transaction, which re-reads the receipt, so a
                    # concurrent identical retry stays free as before.
                    self.rate(*window, False)
                    state["deferred"] = window
                else:
                    self.rate(*window)
        if method == "GET":
            if raw:
                fail("malformed")
            body = None
        else:
            if headers.get("content-type", "").split(";")[0].strip() != "application/json":
                fail("malformed")
            body = P.parse_json(raw)
        logout = (
            con.execute(
                "SELECT subject_id FROM sessions WHERE token_hash=?",
                (token_hash(headers.get("authorization", "")[7:]),),
            ).fetchone()
            if route == "logout"
            else None
        )
        result = self.dispatch(
            con, route, ident, method, body, raw, query, headers, address, now, state
        )
        return result, body, logout

    def preauthorize(self, route, ident, method, raw, query, headers, address, state):
        """Read-only pre-check before Directory.lock and any write transaction (P3-D32, G3
        re-review D4): the same steps on a query-only WAL snapshot, up to the route's
        authorization point. Raises the refusal the transaction would raise, in the same order;
        returns the whole answer for FINAL steps, else None (the transaction re-checks everything).
        sqlite3.Error propagates: the caller falls back to the transaction alone."""
        with self.reader() as con:
            state["pre"] = True
            try:
                con.execute("BEGIN")
                result = self.steps(
                    con, route, ident, method, raw, query, headers, address, self.clock(), state
                )[0]
                return result if state.get(FINAL) else None
            except Proceed:
                return None
            except (Refusal, ValueError, TypeError, KeyError, AttributeError):
                if "deferred" in state:
                    # The recovery address window precedes every other check (charged even when
                    # the request is refused): charge it now, atomically re-checked, as the
                    # transaction would have before refusing. A full window answers 429 instead.
                    self.rate(*state.pop("deferred"))
                raise
            finally:
                state["pre"] = False
                con.rollback()

    def handle(self, route, ident, method, raw, query, headers, peer):
        try:
            if len(raw) > body_cap(route):
                fail("too_large")
            address = self.client_address(peer, headers)
            # Authorize first: a refused request takes no lock and no write transaction, and is
            # charged only what the transaction would charge before refusing it, plus (P3-D35) its
            # session's buckets once the session is authenticated.
            state = {}
            try:
                result = self.preauthorize(
                    route, ident, method, raw, query, headers, address, state
                )
            except sqlite3.Error:
                result = None  # the transaction authorizes on its own
            except (Refusal, ValueError, TypeError, KeyError, AttributeError):
                if "session" in state:
                    self.throttle(state["session"], self.clock())
                raise
            if "session" in state:
                self.throttle(state["session"], self.clock())
            if result is not None:
                response = JSONResponse(result)
                response.wake = []  # FINAL steps change no row
                return response
            with self.lock:
                con = self.connection("write")
                now = self.clock()
                con.execute("BEGIN IMMEDIATE")
                with con:
                    changes = con.total_changes
                    result, body, logout = self.steps(
                        con, route, ident, method, raw, query, headers, address, now, state
                    )
                    # Any row change (incl. triggers) on this connection since BEGIN came from this
                    # commit. Unthrottled receipt replays change nothing and so wake nothing.
                    wake = (
                        self.wake_keys(con, route, ident, body, logout)
                        if con.total_changes > changes and method != "GET"
                        else []
                    )
            response = JSONResponse(result)
            response.wake = wake
            return response
        except Refusal as e:
            return JSONResponse(
                {"error": e.code, **getattr(e, "details", {})},
                status_code=e.status,
                headers={"Retry-After": str(e.retry or 1)} if e.status == 429 else None,
            )
        except (ValueError, TypeError, KeyError, AttributeError):
            return JSONResponse({"error": "malformed"}, status_code=400)


def install(app, data):
    directory = Directory(
        data / db.DB_NAME,
        os.environ.get("ORCH_RELAY_ORIGIN", "http://localhost:8101"),
        os.environ.get("ORCH_RELAY_TRUSTED_PROXY"),
    )
    directory.account_workspaces = int(
        os.environ.get("ORCH_RELAY_ACCOUNT_WORKSPACES", ACCOUNT_WORKSPACES)
    )
    directory.throttles, directory.buckets.limit = throttle_settings(os.environ)
    behind = os.environ.get("ORCH_RELAY_BEHIND_PROXY", "").strip().lower()
    if behind not in ("", "0", "false", "no") and not directory.trusted_proxy:
        # N4: behind Caddy without a trusted proxy every client has the proxy's address.
        logging.getLogger(__name__).warning(
            "ORCH_RELAY_BEHIND_PROXY is set but ORCH_RELAY_TRUSTED_PROXY is unset: every client "
            "shares the proxy's address (4 pair polls relay-wide, shared address windows)"
        )
    app.state.directory = directory

    def endpoint(route):
        async def handle(request: Request):
            raw = bytearray()
            cap = body_cap(route)
            declared = request.headers.get("content-length")
            if declared and declared.isdecimal() and int(declared) > cap:
                return JSONResponse({"error": "too_large"}, status_code=413)
            async for chunk in request.stream():
                if len(raw) + len(chunk) > cap:
                    return JSONResponse({"error": "too_large"}, status_code=413)
                raw.extend(chunk)
            if len(request.query_params.multi_items()) != len(request.query_params):
                return JSONResponse({"error": "malformed"}, status_code=400)
            response = await run_in_threadpool(
                directory.handle,
                route,
                request.path_params.get("ident"),
                request.method,
                bytes(raw),
                dict(request.query_params),
                dict(request.headers),
                request.client.host if request.client else "unknown",
            )
            # Revocations, membership, logout and certificates can end or ready a long poll.
            # Only commits that changed rows notify, and only the affected polls' keys.
            if directory.changed and getattr(response, "wake", None):
                directory.changed(*response.wake)
            return response

        return handle

    for path, methods, route in (
        ("workspaces/{ident}/membership", ["PUT"], "membership"),
        ("workspaces/{ident}/members", ["GET"], "members"),
        ("workspaces/{ident}/grants", ["GET"], "grants"),
        ("workspaces/{ident}/card-keys", ["PUT"], "card_keys"),
        ("workspaces/{ident}/card-key", ["GET"], "card_key"),
        ("session/challenge", ["POST"], "challenge"),
        ("session/login", ["POST"], "login"),
        ("session/logout", ["POST"], "logout"),
        ("accounts", ["POST"], "accounts"),
        ("devices/{ident}", ["PUT", "GET"], "device"),
        ("revocations", ["POST"], "revocations"),
        ("devices/{ident}/revocation", ["GET"], "revocation"),
        ("persons/{ident}/revocations", ["GET"], "feed"),
        ("workspaces/{ident}/card", ["PUT", "GET"], "card"),
    ):
        app.add_api_route("/v2/" + path, endpoint(route), methods=methods)


def create_invite(path, ttl_ms):
    if type(ttl_ms) is not int or ttl_ms <= 0:
        raise ValueError("positive invite TTL required")
    db.migrate(path)
    code = P.b64u(secrets.token_bytes(32))
    with closing(db.connect(path)) as con, con:
        con.execute(
            "INSERT INTO invites(code_hash,expires_ms) VALUES (?,?)",
            (digest(code.encode()), time.time_ns() // 1_000_000 + ttl_ms),
        )
    return code
