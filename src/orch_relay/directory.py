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
from collections import Counter
from contextlib import closing

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from . import db
from . import proto as P

MINUTE, HOUR, DAY = 60_000, 3_600_000, 86_400_000
MAX_RESPONSE = 4 * 1024 * 1024
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


class Directory:
    def __init__(self, path, origin, trusted_proxy=None):
        self.path, self.origin, self.trusted_proxy = path, origin, trusted_proxy
        origin.encode("ascii")
        self.lock = threading.RLock()
        self.challenges = {}  # challenge -> (expires_ms, canonical address, /56 parent)
        self.challenge_expiry = []
        self.challenge_addresses = Counter()
        self.challenge_parents = Counter()
        self.window_expiry = []
        self.windows = {}  # (purpose, identity, duration) -> (window end, count)
        self.clock = lambda: time.time_ns() // 1_000_000
        self.changed = None  # event-loop callback(*keys) after committed writes (wakes polls)
        self.random = secrets.token_bytes
        self.dummy_pub = (
            ec.generate_private_key(ec.SECP256R1())
            .public_key()
            .public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        )

    def assert_can_wait(self):
        """G3 must call before a long-poll wait, outside its database transaction."""
        assert not self.lock._is_owned(), "long poll cannot wait while holding directory.lock"

    def rate(self, purpose, identity, duration, cap, now, charge=True):
        # Bounded lazy cleanup avoids scanning all live windows or a restart-sized backlog.
        for _ in range(64):
            if not self.window_expiry or self.window_expiry[0][0] > now:
                break
            old_end, old_key = heapq.heappop(self.window_expiry)
            if self.windows.get(old_key, (None,))[0] == old_end:
                del self.windows[old_key]
        key = (purpose, identity, duration)
        end, count = self.windows.get(key, ((now // duration + 1) * duration, 0))
        if now >= end:
            end, count = (now // duration + 1) * duration, 0
        if count >= cap:
            fail("rate_limited", max(1, math.ceil((end - now) / 1000)))
        if charge:
            if key not in self.windows or self.windows[key][0] != end:
                heapq.heappush(self.window_expiry, (end, key))
            self.windows[key] = (end, count + 1)

    def consume(self, challenge, now):
        P.unb64u(challenge, 32)
        state = self.remove_challenge(challenge)
        if state is None:
            fail("unknown_challenge")
        if now >= state[0]:
            fail("expired")
        return P.unb64u(challenge, 32)

    def add_challenge(self, challenge, expires, address, parent):
        self.challenges[challenge] = (expires, address, parent)
        self.challenge_addresses[address] += 1
        if parent:
            self.challenge_parents[parent] += 1
        heapq.heappush(self.challenge_expiry, (expires, challenge))

    def remove_challenge(self, challenge):
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
        if con.execute(
            "SELECT 1 FROM revocations WHERE device_id=?", (device["device_id"],)
        ).fetchone():
            fail("revoked")
        if device["expires_ms"] is not None and now >= device["expires_ms"]:
            fail("cert_expired")

    def authenticate(self, con, headers, now):
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

    def account(self, con, body, raw, now):
        fields(body, "invite pk_pub device_cert challenge sig")
        if not isinstance(body["invite"], str) or not body["invite"]:
            fail("malformed")
        invite_hash = digest(body["invite"].encode())
        invite = con.execute("SELECT * FROM invites WHERE code_hash=?", (invite_hash,)).fetchone()
        if invite and invite["request_digest"] == digest(raw):
            return {"person_id": invite["used_by"]}
        challenge = self.consume(body["challenge"], now)
        if invite is None or invite["used_ms"] is not None or now >= invite["expires_ms"]:
            fail("not_eligible")
        check_suite(body["device_cert"])
        pub = P.unb64u(body["pk_pub"], 65)
        if not P.SUITE.pub_ok(pub):
            fail("cert_invalid")
        check_suite(body["device_cert"])
        o = checked(P.verify_cert(body["device_cert"], pub, now))
        if not P.SUITE.verify(
            P.unb64u(o["dk_sig_pub"]),
            P.unb64u(body["sig"]),
            P.auth_bytes(self.origin, challenge, "device", o["device_id"]),
        ):
            fail("bad_signature")
        if usable_account(con, o["person_id"]):
            fail("account_exists")
        # P3-D29: redeeming an invite turns an evidence-only row (same person_id, so the same
        # pk_pub) into the account; its revoked devices stay revoked.
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

    def login(self, con, body, now):
        # Consume a recognizable challenge even if other fields are malformed.
        if not isinstance(body, dict) or "challenge" not in body:
            fail("malformed")
        challenge = self.consume(body["challenge"], now)
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
        token = P.b64u(self.random(32))
        con.execute("DELETE FROM sessions WHERE expires_ms<=?", (now,))
        con.execute(
            "INSERT INTO sessions VALUES (?,?,?,?)", (token_hash(token), kind, ident, now + 900_000)
        )
        return {"token": token, "expires_ms": now + 900_000}

    def recovery(self, con, body, raw, address, now, device=None):
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
            if not revocation:
                stored = con.execute("SELECT * FROM devices WHERE device_id=?", (did,)).fetchone()
                self.device_status(con, stored, now)
                complete(con, P.parse_json(stored["cert"]), now)
            return {"device_id": did}
        account = con.execute("SELECT pk_pub FROM accounts WHERE person_id=?", (person,)).fetchone()
        if account is None or (not revocation and usable_account(con, person) is None):
            fail("other_person")
        pub = P.unb64u(account["pk_pub"])
        stored = con.execute("SELECT * FROM devices WHERE device_id=?", (did,)).fetchone()
        prior = con.execute("SELECT * FROM revocations WHERE device_id=?", (did,)).fetchone()
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
            # Cache accepted no-ops too: a byte-identical retry must bypass address budgets.
            con.execute("INSERT INTO recovery_receipts VALUES (?,?,?)", (kind, digest(raw), did))
            if not revocation:
                complete(con, signed, now)
            return {"device_id": did}
        self.rate(kind + "-person", person, DAY, 32 if revocation else 64, now, False)
        if revocation and prior:
            self.rate("revocation-repeat", person, DAY, 24, now, False)
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
        """Called only after PK verification; caller owns the write transaction (also G4)."""
        o = record["o"]
        did = o["device_id"]
        prior = con.execute("SELECT * FROM revocations WHERE device_id=?", (did,)).fetchone()
        cursor = prior["cursor"] if prior else None
        if prior is None or (prior["reason"] != "compromised" and o["reason"] == "compromised"):
            cursor = con.execute("SELECT COALESCE(MAX(cursor),0)+1 FROM revocations").fetchone()[0]
            con.execute(
                "INSERT INTO revocations VALUES (?,?,?,?,?,?) ON CONFLICT(device_id) DO UPDATE SET record=excluded.record, reason=excluded.reason, received_ms=excluded.received_ms, cursor=excluded.cursor",
                (did, o["person_id"], P.cj(record), o["reason"], now, cursor),
            )
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

    def card_put(self, con, ws, body, headers, address, now):
        fields(body, "card")
        card = body["card"]
        check_suite(card)
        if isinstance(card, dict):
            check_suite(card.get("delegation"))
        stored = con.execute("SELECT * FROM workspaces WHERE workspace_id=?", (ws,)).fetchone()
        if stored:
            session = self.authenticate(con, headers, now)
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
            return {"card_seq": o["card_seq"]}
        if not stored:
            self.rate("card-address", address, HOUR, 10, now, False)
            self.rate("card-owner", owner, HOUR, 10, now, False)
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

    def dispatch(self, con, route, ident, method, body, raw, query, headers, address, now):
        from . import members

        if route in members.ROUTES:
            P.unhex(ident)
            return members.dispatch(self, con, route, ident, body, raw, query, headers, now)
        allowed = {"after", "limit", "next"} if route == "feed" else set()
        if any(k not in allowed for k in query) or len(query) != len(set(query.keys())):
            fail("malformed")
        if ident is not None:
            P.unhex(ident)
        if route == "challenge":
            fields(body, "")
            return self.issue(address, now)
        if route == "login":
            return self.login(con, body, now)
        if route == "logout":
            fields(body, "")
            auth = headers.get("authorization", "")
            if auth.startswith("Bearer "):
                con.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash(auth[7:]),))
            return {}
        if route == "accounts":
            return self.account(con, body, raw, now)
        if route == "revocations":
            return self.recovery(con, body, raw, address, now)
        if route == "device" and method == "PUT":
            return self.recovery(con, body, raw, address, now, ident)
        if route == "revocation":
            self.rate("revocation-read", address, MINUTE, 60, now)
            row = con.execute(
                "SELECT record FROM revocations WHERE device_id=?", (ident,)
            ).fetchone()
            if row is None:
                fail("not_found")
            return {"record": P.parse_json(row["record"])}
        if route == "card" and method == "PUT":
            return self.card_put(con, ident, body, headers, address, now)
        session = self.authenticate(con, headers, now)
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
            return {"cert": P.parse_json(row["cert"])}
        if route == "card":
            row = con.execute(
                "SELECT card FROM workspaces WHERE workspace_id=?", (ident,)
            ).fetchone()
            if row is None:
                fail("not_found")
            self.workspace_access(con, session, ident)
            return {"card": P.parse_json(row["card"])}
        self.person_access(con, session, ident)
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

    def handle(self, route, ident, method, raw, query, headers, peer):
        try:
            if len(raw) > body_cap(route):
                fail("too_large")
            address = canonical_address(peer, headers.get("x-forwarded-for"), self.trusted_proxy)
            with self.lock, closing(db.connect(self.path)) as con:
                con.row_factory = sqlite3.Row
                now = self.clock()
                con.execute("BEGIN IMMEDIATE")
                with con:
                    if route == "revocations" or (route == "device" and method == "PUT"):
                        revocation = route == "revocations"
                        kind = "revocation" if revocation else "certificate"
                        receipt = con.execute(
                            "SELECT subject_id FROM recovery_receipts "
                            "WHERE kind=? AND request_digest=?",
                            (kind, digest(raw)),
                        ).fetchone()
                        if not receipt or (not revocation and receipt["subject_id"] != ident):
                            duration, cap = (MINUTE, 10) if revocation else (HOUR, 30)
                            self.rate(kind + "-address", address, duration, cap, now)
                    if method == "GET":
                        if raw:
                            fail("malformed")
                        body = None
                    else:
                        if (
                            headers.get("content-type", "").split(";")[0].strip()
                            != "application/json"
                        ):
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
                        con, route, ident, method, body, raw, query, headers, address, now
                    )
                    # Fresh connection: any row change (incl. triggers) came from this commit.
                    # Unthrottled receipt replays change nothing and so wake nothing.
                    wake = (
                        self.wake_keys(con, route, ident, body, logout)
                        if con.total_changes > 0 and method != "GET"
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
