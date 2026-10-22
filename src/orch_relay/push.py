"""Push registration (P3-D40a): protocol-v2 §19.10, P3 design §14.3 items 1-3, 8 and 9.

`POST /v2/push/register` (D(m) of `workspace_id`) and `POST /v2/push/unregister` (D). A relay without a
complete push configuration (push_config.py) answers 404 `not_found` on these routes and on the host's
send route before any authentication. Tokens are stored sealed (AES-256-GCM under K_tok, bound to the
registration id) with an HMAC for lookups (K_mac); both keys come from the instance secret
`push-token.key`, which is never in the database. The send route and APNs delivery are push_send.py.

Lock order: Directory.lock, then the in-memory budgets (Directory.budget). A pooled read connection is
never held while taking the lock.
"""

import asyncio
import logging
import os
import re
import secrets
import sqlite3

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from . import proto as P
from .bridge import refuse
from .cutover import gate as cutover_gate
from .directory import DAY, HOUR, Refusal, fail
from .push_config import load, mac
from .push_send import SEND_CAP, attach
from .push_send import send as send_route

log = logging.getLogger(__name__)

BODY_TIMEOUT_S = 10
REGISTER_CAP = 16 * 1024
STATE_CHANGES_PER_HOUR = 30
PER_DEVICE = 128
STALE_MS = 60 * DAY
SWEEP_EVERY_S = 6 * 3600
HEX32 = re.compile(r"[0-9a-f]{32}")
AAD = b"orch-relay/push-token|"


def hex32(value):
    if not isinstance(value, str) or not HEX32.fullmatch(value):
        raise ValueError("hex")
    return value


def error_response(error):
    headers = {"Retry-After": str(error.retry or 1)} if error.status in (429, 503) else None
    return JSONResponse(
        {"error": error.code, **getattr(error, "details", {})},
        status_code=error.status,
        headers=headers,
    )


async def read_body(request, cap):
    """The whole request body, or a 413 JSON response when it exceeds `cap`."""
    declared = request.headers.get("content-length")
    if declared and declared.isdecimal() and int(declared) > cap:
        return None
    raw = bytearray()

    async def collect():
        async for chunk in request.stream():
            if len(raw) + len(chunk) > cap:
                return False
            raw.extend(chunk)
        return True

    try:
        if not await asyncio.wait_for(collect(), BODY_TIMEOUT_S):
            return None
    except TimeoutError:
        return None  # a slow sender is refused like an oversized body
    return bytes(raw)


class Push:
    def __init__(self, directory, config):
        self.d, self.config = directory, config
        self.outbox = self.sender = self.apns = None  # push_send.attach, when enabled

    @property
    def enabled(self):
        return self.config is not None

    # --- token sealing (item 8) ---------------------------------------------------------------

    def seal(self, registration_id, token):
        nonce = secrets.token_bytes(12)
        aad = AAD + registration_id.encode("ascii")
        return nonce + AESGCM(self.config.k_tok).encrypt(nonce, token, aad)

    def unseal(self, registration_id, sealed):
        aad = AAD + registration_id.encode("ascii")
        return AESGCM(self.config.k_tok).decrypt(bytes(sealed[:12]), bytes(sealed[12:]), aad)

    def token_mac(self, token):
        return mac(self.config.k_mac, token)

    # --- shared steps -------------------------------------------------------------------------

    def admit(self, headers, device_only=True):
        """Session (401, 403 revoked, 400 cert_expired) and its read-class bucket, on a read snapshot."""
        d = self.d
        with d.reader("query") as con:
            con.execute("BEGIN")
            now = d.clock()
            session = d.authenticate(con, headers, now)
            d.throttle(session, now)
            if session["kind"] != "device":
                fail("not_eligible")
            return session

    @staticmethod
    def body(raw, expected):
        try:
            body = P.parse_json(raw)
        except ValueError:
            fail("malformed")
        if not isinstance(body, dict) or set(body) != set(expected):
            fail("malformed")
        return body

    # --- register (item 1) --------------------------------------------------------------------

    def register(self, headers, raw):
        d, cfg = self.d, self.config
        session = self.admit(headers)
        if session["scopes_max"][0].startswith("drop:"):
            fail("not_eligible")
        try:
            body = self.body(raw, ("workspace_id", "registration_id", "env", "topic", "token"))
            ws, rid = hex32(body["workspace_id"]), hex32(body["registration_id"])
            env, topic = body["env"], body["topic"]
            if env not in cfg.envs or topic != cfg.topic:
                fail("malformed")
            token = P.unb64u(body["token"])
            if not 32 <= len(token) <= 100:
                fail("malformed")
        except ValueError:
            fail("malformed")
        sealed_mac = self.token_mac(token)
        device = session["subject_id"]
        with d.lock:
            con = d.connection("write")
            con.execute("BEGIN IMMEDIATE")
            with con:
                now = d.clock()
                session = d.authenticate(con, headers, now)
                if session["kind"] != "device" or session["subject_id"] != device:
                    fail("not_eligible")
                if (
                    session["scopes_max"][0].startswith("drop:")
                    or not con.execute(
                        "SELECT 1 FROM members WHERE workspace_id=? AND device_id=?", (ws, device)
                    ).fetchone()
                ):
                    fail("not_eligible")
                cutover_gate(con, ws, now, write=True)  # E3: no new direct push registrations
                held = con.execute(
                    "SELECT * FROM push_subscriptions WHERE registration_id=?", (rid,)
                ).fetchone()
                if held is not None:
                    same = (
                        held["device_id"] == device
                        and held["workspace_id"] == ws
                        and held["env"] == env
                        and held["topic"] == topic
                        and secrets.compare_digest(bytes(held["token_mac"]), sealed_mac)
                    )
                    if not same:
                        refuse("registration_conflict", 409)
                    # An exact retry (the app registers at every launch): free of rate windows.
                    con.execute(
                        "UPDATE push_subscriptions SET last_seen_ms=? WHERE registration_id=?",
                        (now, rid),
                    )
                    return {"registration_id": rid, "registered": True}
                d.rate("push-register", device, HOUR, STATE_CHANGES_PER_HOUR, now, charge=False)
                con.execute(
                    "DELETE FROM push_subscriptions WHERE device_id=? AND workspace_id=? "
                    "AND env=? AND topic=?",
                    (device, ws, env, topic),
                )
                # A phone reset gives new device keys but keeps its token: the person's other
                # devices lose registrations with this token (another person's are untouched).
                con.execute(
                    "DELETE FROM push_subscriptions WHERE token_mac=? AND device_id<>? AND "
                    "device_id IN (SELECT device_id FROM devices WHERE person_id=?)",
                    (sealed_mac, device, session["person_id"]),
                )
                (count,) = con.execute(
                    "SELECT count(*) FROM push_subscriptions WHERE device_id=?", (device,)
                ).fetchone()
                if count >= PER_DEVICE:
                    fail("quota_exceeded", 60)
                con.execute(
                    "INSERT INTO push_subscriptions VALUES (?,?,?,?,?,?,?,?,?)",
                    (rid, device, ws, env, topic, self.seal(rid, token), sealed_mac, now, now),
                )
                d.rate("push-register", device, HOUR, STATE_CHANGES_PER_HOUR, now)
                return {"registration_id": rid, "registered": True}

    # --- unregister (item 2) ------------------------------------------------------------------

    def unregister(self, headers, raw):
        d = self.d
        session = self.admit(headers)
        try:
            body = self.body(raw, ("workspace_id", "registration_id"))
            ws = hex32(body["workspace_id"])
            rid = body["registration_id"]
            if rid is not None:
                hex32(rid)
        except ValueError:
            fail("malformed")
        device = session["subject_id"]
        with d.lock:
            con = d.connection("write")
            con.execute("BEGIN IMMEDIATE")
            with con:
                now = d.clock()
                session = d.authenticate(con, headers, now)
                if session["kind"] != "device" or session["subject_id"] != device:
                    fail("not_eligible")
                if rid is None:
                    con.execute(
                        "DELETE FROM push_subscriptions WHERE device_id=? AND workspace_id=?",
                        (device, ws),
                    )
                else:
                    held = con.execute(
                        "SELECT device_id, workspace_id FROM push_subscriptions "
                        "WHERE registration_id=?",
                        (rid,),
                    ).fetchone()
                    if held is not None and held["device_id"] != device:
                        fail("not_for_this_device")
                    if held is not None and held["workspace_id"] == ws:
                        con.execute(
                            "DELETE FROM push_subscriptions WHERE registration_id=?", (rid,)
                        )
        return {"registration_id": rid, "registered": False}

    # --- the send route and delivery (push_send.py) ------------------------------------------

    def send(self, headers, ws, raw):
        return send_route(self, headers, ws, raw)

    def apply_result(self, send, result):
        """APNs 410 and 400 BadDeviceToken / DeviceTokenNotForTopic delete registrations (item 3):
        410 those with the token whose `last_seen_ms` is not after Apple's timestamp; 400 the token's
        in that environment. Runs in a worker thread; logs carry the id's first 8 digits only."""
        d = self.d
        with d.lock:
            con = d.connection("write")
            con.execute("BEGIN IMMEDIATE")
            with con:
                if result.kind == "unregistered":
                    stamp = result.timestamp_ms if result.timestamp_ms is not None else d.clock()
                    gone = con.execute(
                        "DELETE FROM push_subscriptions WHERE token_mac=? AND last_seen_ms<=?",
                        (send.mac, stamp),
                    ).rowcount
                else:
                    gone = con.execute(
                        "DELETE FROM push_subscriptions WHERE token_mac=? AND env=?",
                        (send.mac, send.env),
                    ).rowcount
        log.info(
            "apns %s: %s, removed %d registration(s)", send.registration_id[:8], result.reason, gone
        )

    # --- lifecycle (item 3) -------------------------------------------------------------------

    def sweep(self, now=None):
        """Registrations not refreshed for 60 days, and those of devices whose certificate expired."""
        d = self.d
        with d.lock:
            con = d.connection("write")
            con.execute("BEGIN IMMEDIATE")
            with con:
                now = d.clock() if now is None else now
                a = con.execute(
                    "DELETE FROM push_subscriptions WHERE last_seen_ms<=?", (now - STALE_MS,)
                ).rowcount
                b = con.execute(
                    "DELETE FROM push_subscriptions WHERE device_id IN (SELECT device_id FROM "
                    "devices WHERE expires_ms IS NOT NULL AND expires_ms<=?)",
                    (now,),
                ).rowcount
        return a + b

    async def maintenance(self):
        while True:
            try:
                await run_in_threadpool(self.sweep)
            except (sqlite3.Error, OSError):
                log.exception("push sweep failed")
            await asyncio.sleep(SWEEP_EVERY_S)


def not_found():
    return JSONResponse({"error": "not_found"}, status_code=404)


def install(app, env=None):
    """Load the push configuration (raises PushConfigError when partial) and register the routes.
    The routes always exist; without a configuration they answer 404 `not_found`."""
    config = load(os.environ if env is None else env)
    push = Push(app.state.directory, config)
    app.state.push = push

    def endpoint(name, cap):
        async def handle(request: Request):
            if not push.enabled:
                return not_found()
            if request.query_params:
                return JSONResponse({"error": "malformed"}, status_code=400)
            raw = await read_body(request, cap)
            if raw is None:
                return JSONResponse({"error": "too_large"}, status_code=413)
            if request.headers.get("content-type", "").split(";")[0].strip() != "application/json":
                return JSONResponse({"error": "malformed"}, status_code=400)
            headers = dict(request.headers)
            extra = (request.path_params["ws"],) if name == "send" else ()
            try:
                result = await run_in_threadpool(getattr(push, name), headers, *extra, raw)
            except Refusal as error:
                return error_response(error)
            except (ValueError, TypeError, KeyError, AttributeError):
                return JSONResponse({"error": "malformed"}, status_code=400)
            return JSONResponse(result)

        return handle

    if push.enabled:
        attach(app, push, env)
    app.add_api_route("/v2/push/register", endpoint("register", REGISTER_CAP), methods=["POST"])
    app.add_api_route("/v2/push/unregister", endpoint("unregister", REGISTER_CAP), methods=["POST"])
    app.add_api_route("/v2/workspaces/{ws}/push", endpoint("send", SEND_CAP), methods=["POST"])
    return push
