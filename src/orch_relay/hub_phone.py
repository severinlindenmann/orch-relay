"""Hub -> relay push targets, push sends and channel mailboxes (orch-relay E2; orch-hub contract §10.8.1, §10.8.2).

Every route below `/v2/hubs/{hub_id}/` starts with `app.state.hub_request_auth` (E1: the §10.8 check order, nonce
recorded last), so a route and its body are only looked at for a request the hub's `HK_op` signed.

  PUT    /v2/hubs/{hub}/push/{ch}                  {v, env, topic, token}       one APNs target per (hub, channel)
  DELETE /v2/hubs/{hub}/push/{ch}                  empty                        idempotent
  POST   /v2/hubs/{hub}/push/{ch}/send             {v, outer, priority, ttl_s}  the sealed payload to APNs, unchanged
  PUT    /v2/hubs/{hub}/mailbox/{ch}/{id}          {v, c, ttl_s}                idempotent by id
  GET    /v2/hubs/{hub}/mailbox/{ch}/{id}          empty
  DELETE /v2/hubs/{hub}/mailbox/{ch}/{id}          empty                        idempotent
  DELETE /v2/hubs/{hub}/mailbox/{ch}               empty                        purge a channel + mark it revoked (permanent, E5)

The relay never learns what a push or a mailbox message says (ciphertext only) and does not know which channels
exist: that is the hub's business. A relay without a complete push configuration answers 404 `not_found` on every
route (after authentication), as for v2 push. Tokens are sealed at rest like the per-workspace ones (push.py); the
send hands a `push_send.Send` to the existing outbox/sender, with the hub as workspace/account and the channel as
device, so budgets, the 24 h dedup LRU, queue admission and APNs delivery are the v2 ones.

Quotas (§10.8.1): ORCH_RELAY_HUB_PUSH_TARGETS (the spec's relay config `max_push_targets_per_hub`) targets per hub (default 4096), 256 messages and 4 MiB per (hub, channel) mailbox, 16 KiB per message.
"""

import hashlib
import os
import re
import secrets
import sqlite3

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from . import proto as P
from .apns import apns_body
from .bridge import refuse
from .directory import Refusal, fail
from .push import error_response
from .push_send import MAX_OUTER, MAX_TTL_S, WAIT_MAX_S, WAIT_MIN_S, Send

MAX_TARGETS_PER_HUB = 4096  # default of ORCH_RELAY_HUB_PUSH_TARGETS, which is the spec's `max_push_targets_per_hub` (§10.8.1)
MAX_MESSAGES = 256
MAX_MAILBOX_BYTES = 4 * 1024 * 1024
MAX_MESSAGE = 16 * 1024
MAILBOX_TTL = (60, 7 * 86_400)
PRIORITIES = ("high", "normal")
_TOPIC = re.compile(r"[A-Za-z0-9.-]{1,155}")
_HEX32 = re.compile(r"[0-9a-f]{32}")
RETRY_S = 60


def sealing_id(hub, channel):
    """What the token seal is bound to (AAD) and what logs show the first 8 characters of."""
    return f"hub:{hub}:{channel}"


def _obj(raw, fields):
    try:
        o = P.parse_json(raw)
    except ValueError:
        fail("malformed")
    if type(o) is not dict or set(o) != fields or type(o["v"]) is not int or o["v"] != 2:
        fail("malformed")
    return o


def _empty(raw):
    if raw != b"":
        fail("malformed")


def _hex32(text):
    if not _HEX32.fullmatch(text):
        fail("malformed")
    return text


def outer_check(outer, hub, channel):
    """The APNs `o` field (§10.8.1): exactly {v, hub, ch, id, c} naming this hub and channel, at most 3072 bytes."""
    if type(outer) is not dict or set(outer) != {"v", "hub", "ch", "id", "c"}:
        fail("malformed")
    if (
        type(outer["v"]) is not int
        or outer["v"] != 2
        or outer["hub"] != hub
        or outer["ch"] != channel
    ):
        fail("malformed")
    if type(outer["id"]) is not str or not _HEX32.fullmatch(outer["id"]):
        fail("malformed")
    if type(outer["c"]) is not str or not outer["c"]:
        fail("malformed")
    try:
        P.unb64u(outer["c"])
    except ValueError:
        fail("malformed")
    raw = P.cj(outer)
    if len(raw) > MAX_OUTER:
        fail("too_large")
    return raw


def match(method, path, query, hub, raw):
    """Match an authenticated, canonical request and check its body. Returns (route, channel, id, parsed body).
    An unknown path or method is `not_found`; a body that is not exactly the route's shape `malformed`
    (`too_large` for an oversize message). `path` is the full path, `/v2/hubs/<hub>/...`."""
    if query:
        fail("malformed")  # none of these routes takes a query
    segs = path.split("/")[4:]
    kind = segs[0] if segs else ""
    if kind == "push" and len(segs) in (2, 3):
        ch = segs[1]
        if len(segs) == 2 and method == "PUT":
            o = _obj(raw, {"v", "env", "topic", "token"})
            try:
                token = P.unb64u(o["token"])
            except ValueError:
                fail("malformed")
            if o["env"] not in ("sandbox", "production") or type(o["topic"]) is not str:
                fail("malformed")
            if not _TOPIC.fullmatch(o["topic"]) or not 32 <= len(token) <= 100:
                fail("malformed")
            return (
                "push_put",
                _hex32(ch),
                None,
                {"env": o["env"], "topic": o["topic"], "token": token},
            )
        if len(segs) == 2 and method == "DELETE":
            _empty(raw)
            return "push_delete", _hex32(ch), None, None
        if len(segs) == 3 and segs[2] == "send" and method == "POST":
            o = _obj(raw, {"v", "outer", "priority", "ttl_s"})
            if o["priority"] not in PRIORITIES or type(o["ttl_s"]) is not int:
                fail("malformed")
            if not 0 <= o["ttl_s"] <= MAX_TTL_S:
                fail("malformed")
            outer_raw = outer_check(o["outer"], hub, _hex32(ch))
            return (
                "push_send",
                ch,
                o["outer"]["id"],
                {
                    "outer": outer_raw,
                    "priority": o["priority"],
                    "ttl_s": o["ttl_s"],
                },
            )
    if kind == "mailbox" and len(segs) in (2, 3):
        ch = _hex32(segs[1])
        if len(segs) == 2 and method == "DELETE":
            _empty(raw)
            return "mailbox_purge", ch, None, None
        if len(segs) == 3 and _HEX32.fullmatch(segs[2]):
            mid = segs[2]
            if method == "PUT":
                o = _obj(raw, {"v", "c", "ttl_s"})
                if (
                    type(o["ttl_s"]) is not int
                    or not MAILBOX_TTL[0] <= o["ttl_s"] <= MAILBOX_TTL[1]
                ):
                    fail("malformed")
                try:
                    c = P.unb64u(o["c"])
                except ValueError:
                    fail("malformed")
                if not c:
                    fail("malformed")
                if len(c) > MAX_MESSAGE:
                    fail("too_large")
                return "mailbox_put", ch, mid, {"c": c, "ttl_s": o["ttl_s"]}
            if method in ("GET", "DELETE"):
                _empty(raw)
                return ("mailbox_get" if method == "GET" else "mailbox_delete"), ch, mid, None
    fail("not_found")


class HubPhone:
    def __init__(self, directory, push, max_targets=None):
        self.d, self.push = directory, push
        self.max_targets = max_targets or MAX_TARGETS_PER_HUB

    def handle(self, hub, method, path, query, raw):
        route, ch, mid, body = match(method, path, query, hub, raw)
        return getattr(self, route)(hub, ch, mid, body)

    # --- push target ----------------------------------------------------------------------

    def push_put(self, hub, ch, _mid, body):
        push, d = self.push, self.d
        cfg = push.config
        if body["env"] not in cfg.keys or body["topic"] != cfg.topic:
            fail("malformed")  # an env or topic this relay is not configured for, as v2
        mac = push.token_mac(body["token"])
        with d.lock:
            con = d.connection("write")
            con.execute("BEGIN IMMEDIATE")
            with con:
                now = d.clock()
                held = con.execute(
                    "SELECT env, topic, token_mac FROM hub_push_targets WHERE hub_id=? AND channel_id=?",
                    (hub, ch),
                ).fetchone()
                if (
                    held is not None
                    and held["env"] == body["env"]
                    and held["topic"] == body["topic"]
                    and secrets.compare_digest(bytes(held["token_mac"]), mac)
                ):
                    return {"channel_id": ch, "registered": True}  # an exact repeat changes nothing
                if held is None:
                    (count,) = con.execute(
                        "SELECT count(*) FROM hub_push_targets WHERE hub_id=?", (hub,)
                    ).fetchone()
                    if count >= self.max_targets:
                        refuse("quota_exceeded", 429, RETRY_S)
                con.execute(
                    "INSERT INTO hub_push_targets VALUES (?,?,?,?,?,?,?,?) ON CONFLICT (hub_id, channel_id) DO "
                    "UPDATE SET env=excluded.env, topic=excluded.topic, token_sealed=excluded.token_sealed, "
                    "token_mac=excluded.token_mac, updated_ms=excluded.updated_ms",
                    (
                        hub,
                        ch,
                        body["env"],
                        body["topic"],
                        push.seal(sealing_id(hub, ch), body["token"]),
                        mac,
                        now,
                        now,
                    ),
                )
        return {"channel_id": ch, "registered": True}

    def push_delete(self, hub, ch, _mid, _body):
        d = self.d
        with d.lock:
            con = d.connection("write")
            con.execute("BEGIN IMMEDIATE")
            with con:
                con.execute(
                    "DELETE FROM hub_push_targets WHERE hub_id=? AND channel_id=?", (hub, ch)
                )
        return {"channel_id": ch, "registered": False}

    # --- send -----------------------------------------------------------------------------

    def push_send(self, hub, ch, mid, body):
        push, d = self.push, self.d
        with d.reader("query") as con:
            con.execute("BEGIN")
            now = d.clock()
            row = con.execute(
                "SELECT env, topic, token_sealed, token_mac FROM hub_push_targets "
                "WHERE hub_id=? AND channel_id=?",
                (hub, ch),
            ).fetchone()
        ttl, priority = body["ttl_s"], body["priority"]
        sends = []
        if row is not None and row["env"] in push.config.keys and row["topic"] == push.config.topic:
            wait_s = WAIT_MIN_S if ttl == 0 else min(ttl, WAIT_MAX_S)
            sends.append(
                Send(
                    sealing_id(hub, ch),
                    bytes(row["token_sealed"]),
                    bytes(row["token_mac"]),
                    row["env"],
                    hub,  # the budgets and queue caps of v2 push, with the hub as workspace and account
                    hub,
                    ch,
                    apns_body(body["outer"]),
                    10 if priority == "high" else 5,
                    0 if ttl == 0 else now // 1000 + ttl,
                    now + 1000 * wait_s,
                )
            )
        # The dedup key is (hub, channel, message id): a retry reaches the phone once whatever its `c`.
        key = hashlib.sha256(b"orch-relay/hub-push|" + bytes.fromhex(mid)).digest()
        with d.lock:
            try:
                queued = push.outbox.commit(hub, hub, key, [(ch, sends)], d.clock())
            except Refusal as error:
                if error.code != "rate_limited":
                    raise
                refuse(
                    "quota_exceeded", 429, error.retry or RETRY_S
                )  # the hub's request budget (§10.8.1)
        if queued:
            push.sender.notify()
        return {"accepted": 1 if queued else 0}

    # --- mailbox --------------------------------------------------------------------------

    def mailbox_put(self, hub, ch, mid, body):
        d, c = self.d, body["c"]
        with d.lock:
            con = d.connection("write")
            con.execute("BEGIN IMMEDIATE")
            with con:
                now = d.clock()
                con.execute("DELETE FROM hub_mailbox WHERE expires_ms<=?", (now,))
                held = con.execute(
                    "SELECT c, expires_ms FROM hub_mailbox WHERE hub_id=? AND channel_id=? AND msg_id=?",
                    (hub, ch, mid),
                ).fetchone()
                if held is not None:
                    if not secrets.compare_digest(bytes(held["c"]), c):
                        refuse("message_conflict", 409)
                    return {"id": mid, "stored": True, "expires_ms": held["expires_ms"]}
                count, size = con.execute(
                    "SELECT count(*), coalesce(sum(length(c)), 0) FROM hub_mailbox "
                    "WHERE hub_id=? AND channel_id=?",
                    (hub, ch),
                ).fetchone()
                if count >= MAX_MESSAGES or size + len(c) > MAX_MAILBOX_BYTES:
                    refuse("quota_exceeded", 429, RETRY_S)
                expires = now + 1000 * body["ttl_s"]
                con.execute(
                    "INSERT INTO hub_mailbox VALUES (?,?,?,?,?,?)", (hub, ch, mid, c, expires, now)
                )
        return {"id": mid, "stored": True, "expires_ms": expires}

    def mailbox_get(self, hub, ch, mid, _body):
        d = self.d
        with d.reader("query") as con:
            con.execute("BEGIN")
            row = con.execute(
                "SELECT c, expires_ms FROM hub_mailbox WHERE hub_id=? AND channel_id=? AND msg_id=? "
                "AND expires_ms>?",
                (hub, ch, mid, d.clock()),
            ).fetchone()
        if row is None:
            fail("not_found")
        return {"id": mid, "c": P.b64u(bytes(row["c"])), "expires_ms": row["expires_ms"]}

    def mailbox_delete(self, hub, ch, mid, _body):
        d = self.d
        with d.lock:
            con = d.connection("write")
            con.execute("BEGIN IMMEDIATE")
            with con:
                con.execute(
                    "DELETE FROM hub_mailbox WHERE hub_id=? AND channel_id=? AND msg_id=?",
                    (hub, ch, mid),
                )
        return {"id": mid, "deleted": True}

    def mailbox_purge(self, hub, ch, _mid, _body):
        d = self.d
        with d.lock:
            con = d.connection("write")
            con.execute("BEGIN IMMEDIATE")
            with con:
                # The hub's signed revocation notice (§10.8.1, §10.8.4): permanent, in the same transaction as the purge.
                con.execute(
                    "INSERT OR IGNORE INTO hub_revoked_channels VALUES (?,?,?)",
                    (hub, ch, d.clock()),
                )
                con.execute(
                    "DELETE FROM hub_mailbox WHERE hub_id=? AND channel_id=? AND expires_ms<=?",
                    (hub, ch, d.clock()),
                )  # expired messages are already gone, they are not counted
                n = con.execute(
                    "DELETE FROM hub_mailbox WHERE hub_id=? AND channel_id=?", (hub, ch)
                ).rowcount
        return {"channel_id": ch, "deleted": n}

    def sweep(self, now):
        """Expired mailbox messages (also dropped lazily on write and read)."""
        d = self.d
        with d.lock:
            con = d.connection("write")
            con.execute("BEGIN IMMEDIATE")
            with con:
                return con.execute("DELETE FROM hub_mailbox WHERE expires_ms<=?", (now,)).rowcount


def install(app):
    d, push = app.state.directory, app.state.push
    # ORCH_RELAY_HUB_PUSH_TARGETS is the spec's relay config `max_push_targets_per_hub` (§10.8.1, default 4096).
    phone = HubPhone(
        d, push, int(os.environ.get("ORCH_RELAY_HUB_PUSH_TARGETS", MAX_TARGETS_PER_HUB))
    )
    app.state.hub_phone = phone

    async def route(hub_id_text: str, tail: str, request: Request):
        try:
            hub, raw = await app.state.hub_request_auth(request)
            if not push.enabled:
                fail("not_found")
            path = (request.scope.get("raw_path") or request.url.path.encode()).decode(
                "ascii", "replace"
            )
            query = request.scope.get("query_string", b"").decode("ascii", "replace")
            result = await run_in_threadpool(phone.handle, hub, request.method, path, query, raw)
        except Refusal as error:
            return error_response(error)
        except (ValueError, TypeError, KeyError, sqlite3.DataError):
            return JSONResponse({"error": "malformed"}, status_code=400)
        return JSONResponse(result, headers={"Cache-Control": "no-store"})

    app.add_api_route(
        "/v2/hubs/{hub_id_text}/{tail:path}", route, methods=["GET", "PUT", "POST", "DELETE"]
    )
    return phone


__all__ = ["HubPhone", "install", "match"]
