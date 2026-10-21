"""Webhook doorbells (orch-relay #81; orch follow-up design FU11-FU13).

A hook is an unguessable id (`hk_` + 128 random bits) that a workspace host registers as its hash
`H(id) = SHA-256("orch/v2/hook|" || id)`. The relay never sees or stores the id except transiently in
the URL of a ring; it stores `H(id)`, the workspace, the expiry and the time of the first ring.

Host routes (W session of the workspace, fenced: the push send pattern):
  POST /v2/workspaces/{ws}/hooks         {"hooks": [{"hook_hash", "expires_ms"}, ...]}  register
  POST /v2/workspaces/{ws}/hooks/revoke  {"hook_hashes": [...]}                         revoke
  POST /v2/workspaces/{ws}/hooks/fetch   {"ack": [hook_hash, ...]}                      rings

Public route: `POST /h/{id}` answers 204 with no body, always the same headers, whatever the id or
the state of the hook: the handler never touches the database. It only hashes the id, charges the
limits, and queues the hash; `drain()` (a background task, or a test) records the first ring of a
registered, unexpired hook. Body: never read (a declared length over 64 KiB is refused 413 from the
header alone, the same for every id). Limits: per source address (429, independent of the id), per
hook hash and per workspace (a ring over a limit is dropped, still 204). One row per hook and 256
per workspace.
"""

import asyncio
import hashlib
import logging
import re
import sqlite3
import threading
from collections import deque

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from . import proto as P
from .directory import DAY, HOUR, Buckets, Refusal, fail
from .push import error_response, read_body

log = logging.getLogger(__name__)

LABEL = b"orch/v2/hook|"
HEX64 = re.compile(r"[0-9a-f]{64}")
REQUEST_CAP = 32 * 1024  # host request bodies
RING_BODY_CAP = 64 * 1024
MAX_ID_BYTES = 128  # longer ids cannot be registered ids; they are hashed truncated, never refused
MAX_LIFE_MS = 14 * DAY
BODY_TIMEOUT_S = 10  # a chunked ring body that dawdles is answered like an oversized one
PER_WORKSPACE = 256
PER_REQUEST = 64
REGISTER_PER_HOUR = 240
SWEEP_EVERY_S = 3600
QUEUE_MAX = 4096
RINGS_MAX = 256
# (burst, per minute) token buckets; ORCH_RELAY_THROTTLE_* does not apply (fixed, like push-ws).
LIMITS = {"hook-ip": (30, 30), "hook": (3, 1), "hook-ws": (64, 30)}


def hook_hash(hook_id: str) -> str:
    """H(id), lower-case hex. Any text is hashed (an invalid id simply matches nothing)."""
    raw = hook_id.encode("utf-8", "surrogatepass")[:MAX_ID_BYTES]
    return hashlib.sha256(LABEL + raw).hexdigest()


def hex64(value):
    if not isinstance(value, str) or not HEX64.fullmatch(value):
        raise ValueError("hex")
    return value


class Hooks:
    def __init__(self, directory):
        self.d = directory
        self.mutex = (
            threading.Lock()
        )  # buckets and queue; ring() never takes Directory.lock, drain() takes this inside it
        self.buckets = Buckets(directory.buckets.limit)
        self.queue = deque()
        self.dropped = 0
        self.wake = None
        self.loop = None

    # --- the public doorbell ------------------------------------------------------------------

    def ring(self, hook_id, address):
        """Called on the event loop for `POST /h/{id}`. No database access, no branch on the id."""
        digest = hook_hash(hook_id)
        now = self.d.clock()
        with self.mutex:
            self.take(("hook-ip", address), now)  # 429: id independent
            try:
                self.take(("hook", digest), now)
            except Refusal:
                return  # over this hook's limit: still the same answer
            if len(self.queue) < QUEUE_MAX:
                self.queue.append((digest, now))
            else:
                self.dropped += 1
        self.notify()

    def take(self, key, now):
        self.buckets.take(key, *LIMITS[key[0]], now)

    def notify(self):
        loop, wake = self.loop, self.wake
        if loop is not None and wake is not None:
            loop.call_soon_threadsafe(wake.set)

    def drain(self):
        """Record queued rings: the first ring of a registered, unexpired hook (one row per hook).
        Returns how many rows were set. Safe to call from any thread, any number of times."""
        with self.mutex:
            batch = list(self.queue)
            self.queue.clear()
        if not batch:
            return 0
        d, rung = self.d, 0
        with d.lock:
            con = d.connection("write")
            con.execute("BEGIN IMMEDIATE")
            with con:
                for digest, at in batch:
                    row = con.execute(
                        "SELECT workspace_id FROM hooks WHERE hook_hash=? AND rung_ms IS NULL "
                        "AND created_ms<=? AND expires_ms>?",
                        (digest, at, at),
                    ).fetchone()
                    if row is None:
                        continue
                    try:
                        with self.mutex:
                            self.take(("hook-ws", row[0]), at)
                    except Refusal:
                        continue  # over the workspace's limit: dropped, never reported to the sender
                    rung += con.execute(
                        "UPDATE hooks SET rung_ms=? WHERE hook_hash=? AND rung_ms IS NULL",
                        (at, digest),
                    ).rowcount
        return rung

    # --- the host routes ----------------------------------------------------------------------

    def admit(self, headers, ws):
        """Step 1 of the push send route: W session of this workspace, the fence, the bucket."""
        d = self.d
        try:
            P.unhex(ws)
        except ValueError:
            fail("malformed")
        with d.reader("query") as con:
            con.execute("BEGIN")
            now = d.clock()
            session = d.authenticate(con, headers, now)
            try:
                if session["kind"] != "workspace" or session["subject_id"] != ws:
                    fail("not_eligible")
                d.fence(con, headers, ws, now)
            except Refusal:
                d.throttle(session, now)
                raise
            d.throttle(session, now)

    @staticmethod
    def body(raw, expected):
        try:
            body = P.parse_json(raw)
        except ValueError:
            fail("malformed")
        if not isinstance(body, dict) or set(body) != set(expected):
            fail("malformed")
        return body

    def locked(self, headers, ws):
        """Open the write transaction and re-check session and fence inside it."""
        d = self.d
        con = d.connection("write")
        con.execute("BEGIN IMMEDIATE")
        now = d.clock()
        session = d.authenticate(con, headers, now)
        if session["kind"] != "workspace" or session["subject_id"] != ws:
            fail("not_eligible")
        d.fence(con, headers, ws, now)
        return con, now

    def register(self, headers, ws, raw):
        d = self.d
        self.admit(headers, ws)
        body = self.body(raw, ("hooks",))
        items = body["hooks"]
        if not isinstance(items, list) or not 1 <= len(items) <= PER_REQUEST:
            fail("malformed")
        parsed = {}
        for item in items:
            if not isinstance(item, dict) or set(item) != {"hook_hash", "expires_ms"}:
                fail("malformed")
            expires = item["expires_ms"]
            if type(expires) is not int:
                fail("malformed")
            parsed[hex64(item["hook_hash"])] = expires
        with d.lock:
            con, now = self.locked(headers, ws)
            with con:
                for expires in parsed.values():
                    if not now < expires <= now + MAX_LIFE_MS:
                        fail("malformed")
                d.rate("hook-register", ws, HOUR, REGISTER_PER_HOUR, now)
                con.execute("DELETE FROM hooks WHERE expires_ms<=?", (now,))
                held = {
                    r[0]: r[1]
                    for r in con.execute(
                        f"SELECT hook_hash, workspace_id FROM hooks WHERE hook_hash IN "
                        f"({','.join('?' * len(parsed))})",
                        tuple(parsed),
                    )
                }
                # A hash held by another workspace is skipped and answered like a new one: the
                # register route must not tell a host whether someone else's hook exists.
                parsed = {k: v for k, v in parsed.items() if held.get(k, ws) == ws}
                (count,) = con.execute(
                    "SELECT count(*) FROM hooks WHERE workspace_id=?", (ws,)
                ).fetchone()
                held = {k: v for k, v in held.items() if v == ws}
                if count + len(parsed) - len(held) > PER_WORKSPACE:
                    fail("quota_exceeded", 60)
                for digest, expires in parsed.items():
                    if digest in held:
                        # an exact retry or an extension; a ring already recorded stays recorded
                        con.execute(
                            "UPDATE hooks SET expires_ms=min(?, created_ms+?) WHERE hook_hash=?",
                            (expires, MAX_LIFE_MS, digest),
                        )
                    else:
                        con.execute(
                            "INSERT INTO hooks VALUES (?,?,?,?,NULL)", (digest, ws, now, expires)
                        )
        return {"registered": len(items)}

    def revoke(self, headers, ws, raw):
        d = self.d
        self.admit(headers, ws)
        body = self.body(raw, ("hook_hashes",))
        items = body["hook_hashes"]
        if not isinstance(items, list) or not 1 <= len(items) <= PER_REQUEST:
            fail("malformed")
        digests = [hex64(x) for x in items]
        with d.lock:
            con, _now = self.locked(headers, ws)
            with con:
                gone = 0
                for digest in digests:
                    gone += con.execute(
                        "DELETE FROM hooks WHERE hook_hash=? AND workspace_id=?", (digest, ws)
                    ).rowcount
        return {"revoked": gone}

    def fetch(self, headers, ws, raw):
        """The rings of this workspace's hooks (first ring only, oldest first). `ack` first clears
        the ring of the named hooks (the hook stays registered until revoked or expired)."""
        d = self.d
        self.admit(headers, ws)
        body = self.body(raw, ("ack",))
        items = body["ack"]
        if not isinstance(items, list) or len(items) > RINGS_MAX:
            fail("malformed")
        acks = [hex64(x) for x in items]
        with d.lock:
            con, now = self.locked(headers, ws)
            with con:
                for digest in acks:
                    con.execute(
                        "UPDATE hooks SET rung_ms=NULL WHERE hook_hash=? AND workspace_id=?",
                        (digest, ws),
                    )
                rings = [
                    {"hook_hash": r[0], "rung_ms": r[1]}
                    for r in con.execute(
                        "SELECT hook_hash, rung_ms FROM hooks WHERE workspace_id=? "
                        "AND rung_ms IS NOT NULL AND expires_ms>? ORDER BY rung_ms, hook_hash "
                        "LIMIT ?",
                        (ws, now, RINGS_MAX),
                    )
                ]
        return {"rings": rings}

    # --- lifecycle ----------------------------------------------------------------------------

    def sweep(self, now=None):
        """Delete expired hooks (a ring that was never fetched goes with its hook)."""
        d = self.d
        with d.lock:
            con = d.connection("write")
            con.execute("BEGIN IMMEDIATE")
            with con:
                now = d.clock() if now is None else now
                return con.execute("DELETE FROM hooks WHERE expires_ms<=?", (now,)).rowcount

    async def maintenance(self):
        self.loop = asyncio.get_running_loop()
        self.wake = asyncio.Event()
        next_sweep = self.loop.time() + SWEEP_EVERY_S  # no write at start-up
        while True:
            self.wake.clear()
            try:
                await run_in_threadpool(self.drain)
                if self.loop.time() >= next_sweep:
                    await run_in_threadpool(self.sweep)
                    next_sweep = self.loop.time() + SWEEP_EVERY_S
            except (sqlite3.Error, OSError):
                log.exception("hooks maintenance failed")
            try:
                await asyncio.wait_for(self.wake.wait(), 5)
            except TimeoutError:
                pass


async def drain_body(request):
    """True when the chunked body is within the cap; keeps nothing."""
    seen = 0
    async for chunk in request.stream():
        seen += len(chunk)
        if seen > RING_BODY_CAP:
            return False
    return True


class HideHookIds(logging.Filter):
    """uvicorn's access log would print `POST /h/<id>`: the id is a secret (FU12). Rewrite the path."""

    def filter(self, record):
        args = record.args
        if isinstance(args, tuple) and len(args) >= 3 and str(args[2]).startswith("/h/"):
            record.args = (*args[:2], "/h/…", *args[3:])
        return True


def install(app):
    hooks = Hooks(app.state.directory)
    access = logging.getLogger("uvicorn.access")
    if not any(isinstance(f, HideHookIds) for f in access.filters):
        access.addFilter(HideHookIds())
    app.state.hooks = hooks
    d = app.state.directory

    def endpoint(name):
        async def handle(request: Request):
            if request.query_params:
                return JSONResponse({"error": "malformed"}, status_code=400)
            raw = await read_body(request, REQUEST_CAP)
            if raw is None:
                return JSONResponse({"error": "too_large"}, status_code=413)
            if request.headers.get("content-type", "").split(";")[0].strip() != "application/json":
                return JSONResponse({"error": "malformed"}, status_code=400)
            try:
                result = await run_in_threadpool(
                    getattr(hooks, name), dict(request.headers), request.path_params["ws"], raw
                )
            except Refusal as error:
                return error_response(error)
            except (ValueError, TypeError, KeyError, AttributeError):
                return JSONResponse({"error": "malformed"}, status_code=400)
            return JSONResponse(result)

        return handle

    async def doorbell(hook_id: str, request: Request):
        # Decided from headers and the address alone: nothing here depends on the id or its state.
        declared = request.headers.get("content-length")
        if declared and declared.isdecimal() and int(declared) > RING_BODY_CAP:
            return Response(status_code=413)
        if declared is None and request.headers.get("transfer-encoding"):
            try:
                if not await asyncio.wait_for(drain_body(request), BODY_TIMEOUT_S):
                    return Response(status_code=413)
            except TimeoutError:
                return Response(status_code=413)  # a slow sender gets the oversize answer
        address = d.client_address(request.client.host if request.client else "", request.headers)
        try:
            hooks.ring(hook_id, address)
        except Refusal as error:
            return Response(status_code=429, headers={"Retry-After": str(error.retry or 1)})
        return Response(status_code=204)

    app.add_api_route("/v2/workspaces/{ws}/hooks", endpoint("register"), methods=["POST"])
    app.add_api_route("/v2/workspaces/{ws}/hooks/revoke", endpoint("revoke"), methods=["POST"])
    app.add_api_route("/v2/workspaces/{ws}/hooks/fetch", endpoint("fetch"), methods=["POST"])
    app.add_api_route("/h/{hook_id}", doorbell, methods=["POST"])
    return hooks
