"""A channel's own mailbox read (orch-relay E5; orch-hub contract §10.8.4, reference `check_channel_request`).

  GET    /v2/hub-channels/{hub}/{ch}/mailbox        200 {messages: [{id, expires_ms}]}  (held messages, <= 256, by id)
  GET    /v2/hub-channels/{hub}/{ch}/mailbox/{id}   200 {id, c, expires_ms} | 404 not_found
  DELETE /v2/hub-channels/{hub}/{ch}/mailbox/{id}   200 {id, deleted: true}  (also when absent)

The phone signs with its channel key; the relay knows no channel keys, so the request carries the hub's
`hub.channel_cert` (header `Orch-Channel-Cert`), verified under the held card of the hub. Checks, in the contract's
order: 1 header syntax / method / canonical target, 2 clock window, 3 held card of the hub, 4 the certificate (and that it
names the target's channel), 5 the signature, 6 the channel is not revoked by its hub (the signed mailbox purge of
§10.8.1, kept in `hub_revoked_channels`), 7 the nonce (recorded last, same write transaction), 8 the route.
Every signature comes before the revoked check, so only the holder of the key learns `channel_revoked`.
"""

import hashlib
import re
import sqlite3
import struct

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from . import hub_accounts as H
from . import proto as P
from .common import Refusal, error_response, read_body

WINDOW_MS = 120_000
NONCE_RETENTION_MS = 240_000
METHODS = ("GET", "DELETE")
TARGET_MAX = 256
CERT_HEADER_MAX = 4096
LIST_MAX = 256  # the per-channel mailbox cap of §10.8.1
NONCES_PER_CHANNEL = (
    600  # relay-side read budget: nonces held for one (hub, channel) inside the retention window
)
BODY_CAP = 1024
RETRY_S = 60
L_CHANNEL_CERT = b"orch/v2/hub-channel-cert|"
L_CHANNEL_REQ = b"orch/v2/hub-channel-relay-req|"
L_CHANNEL_ID = b"orch/v2/id/channel|"
_SEG = re.compile(r"[A-Za-z0-9._~-]+")
_HEX32 = re.compile(r"[0-9a-f]{32}")
_HEADERS = ("orch-channel-cert", "orch-channel-ts", "orch-channel-nonce", "orch-channel-signature")

# HTTP status per code on this path (§10.8.4 table, §14): authentication failures are 401, a certificate naming another
# channel 403, a revoked channel 403.
STATUS = {
    "malformed": 400,
    "wrong_suite": 400,
    "other_user": 403,
    "channel_revoked": 403,
    "not_found": 404,
    "quota_exceeded": 429,
}


def refuse(code, retry=None, **details):
    error = Refusal(code, retry)
    error.status = STATUS.get(code, 401)
    error.details = details
    raise error


def _remap(error):
    """A refusal raised by the shared hub helpers, answered with this path's status."""
    error.status = STATUS.get(error.code, 401)
    error.details = getattr(error, "details", {})
    return error


def channel_id(key_pub):
    return hashlib.sha256(L_CHANNEL_ID + b"\x02" + key_pub).digest()[:16].hex()


def parse_target(target):
    """`/v2/hub-channels/<hub_id>/<channel_id>/...`: ASCII, at most 256 bytes, unreserved segments only, no query, no
    empty, `.` or `..` segment, no trailing `/`. Returns (hub_id, channel_id, rest); anything else is `malformed`."""
    if type(target) is not str or not target.isascii() or len(target) > TARGET_MAX or "?" in target:
        refuse("malformed")
    segs = target.split("/")
    if segs[0] != "" or len(segs) < 5 or segs[1:3] != ["v2", "hub-channels"]:
        refuse("malformed")
    for seg in segs[1:]:
        if not _SEG.fullmatch(seg) or seg in (".", ".."):
            refuse("malformed")
    if not _HEX32.fullmatch(segs[3]) or not _HEX32.fullmatch(segs[4]):
        refuse("malformed")
    return segs[3], segs[4], segs[5:]


def request_bytes(hub, ch, ts_ms, nonce, method, target, body):
    """`"orch/v2/hub-channel-relay-req|" || suite || hub_id || channel_id || u64(ts_ms) || nonce || lp16(METHOD) ||
    lp16(target) || H(body)` (§10.8.4)."""
    return (
        L_CHANNEL_REQ
        + b"\x02"
        + P.unhex(hub, 16)
        + P.unhex(ch, 16)
        + struct.pack(">Q", ts_ms)
        + nonce
        + H._lp16(method.encode("ascii"))
        + H._lp16(target.encode("ascii"))
        + hashlib.sha256(body).digest()
    )


def route(method, target, body):
    """The route of an authenticated request (§10.8.4 step 8): the list, a get, a delete. Another path or method is
    `not_found`; a body `malformed`. Returns {route, hub, channel_id[, id]}."""
    hub, ch, rest = parse_target(target)
    if rest == ["mailbox"] and method == "GET":
        found = {"route": "mailbox_list"}
    elif (
        len(rest) == 2 and rest[0] == "mailbox" and _HEX32.fullmatch(rest[1]) and method in METHODS
    ):
        found = {"route": "mailbox_get" if method == "GET" else "mailbox_delete", "id": rest[1]}
    else:
        refuse("not_found")
    if body != b"":
        refuse("malformed")
    return {"hub": hub, "channel_id": ch, **found}


def verify_channel_cert(signed, card, op, now, dev_mode):
    """§6.2 under the held, re-verified card: signature by its `HK_op`, fields, `hub_id`, the card's op cert, dev marker,
    `channel_id` of `key_pub`, time."""
    o = H._envelope(signed, "hub.channel_cert")
    H._signature(signed, L_CHANNEL_CERT, P.unb64u(op["hk_op_pub"], 65))
    H._fields(o, "hub.channel_cert")
    if o["hub_id"] != card["hub_id"]:
        refuse("other_hub")
    if o["op_cert_id"] != op["cert_id"]:
        refuse("stale_op_cert")
    H._dev(o, dev_mode)
    if o["channel_id"] != channel_id(P.unb64u(o["key_pub"], 65)):
        refuse("cert_invalid")
    if o["expires_ms"] <= o["issued_ms"] or o["issued_ms"] > now + H.CLOCK_SKEW_MS:
        refuse("cert_invalid")
    if now >= o["expires_ms"]:
        refuse("cert_expired")
    return o


def _headers(headers):
    """Lower-cased `Orch-Channel-*` headers; a repeated header in any spelling is `malformed` (L2B-9), never "the last
    one wins". `headers` is a mapping or a list of (name, value) pairs (the raw request headers)."""
    pairs = headers.items() if hasattr(headers, "items") else headers
    out = {}
    for name, value in pairs:
        name = name.decode("latin-1") if isinstance(name, bytes) else str(name)
        name = name.lower()
        if not name.startswith("orch-channel-"):
            continue
        if name in out:
            refuse("malformed")
        out[name] = value.decode("latin-1") if isinstance(value, bytes) else value
    return out


class HubChannels:
    def __init__(self, directory, dev_mode=False):
        self.d, self.dev_mode = directory, dev_mode

    def authenticate(self, method, target, headers, body):
        """§10.8.4 steps 1-7. Returns (hub, channel_id); the nonce is recorded last, after every signature and the
        revoked check, in the same write transaction."""
        h = _headers(headers)
        try:
            raw_cert = h["orch-channel-cert"]
            if type(raw_cert) is not str or len(raw_cert) > CERT_HEADER_MAX:
                raise ValueError("cert")
            cert = P.parse_json(P.unb64u(raw_cert))
            if not H._TS.fullmatch(h["orch-channel-ts"]):
                raise ValueError("ts")
            ts = int(h["orch-channel-ts"])
            nonce = P.unhex(h["orch-channel-nonce"], 16)
            sig = P.unb64u(h["orch-channel-signature"], 64)
            if method not in METHODS or type(body) is not bytes or ts >= 1 << 64:
                raise ValueError("request")
            hub, ch, _rest = parse_target(target)
        except (KeyError, ValueError, TypeError):
            refuse("malformed")
        message = request_bytes(hub, ch, ts, nonce, method, target, body)
        d = self.d
        try:
            with d.lock:
                con = d.connection("write")
                con.execute("BEGIN IMMEDIATE")
                with con:
                    now = d.clock()
                    if abs(now - ts) > WINDOW_MS:
                        refuse("stale_timestamp", server_ms=now)
                    row = con.execute(
                        "SELECT card FROM hub_accounts WHERE hub_id=?", (hub,)
                    ).fetchone()
                    if row is None:
                        refuse("unknown_hub")
                    try:
                        card, op, _root = H.verify_card(
                            P.parse_json(row[0].encode()),
                            now,
                            self.dev_mode,
                            frozenset(
                                r[0]
                                for r in con.execute(
                                    "SELECT cert_id FROM hub_op_revoked WHERE hub_id=?", (hub,)
                                )
                            ),
                        )
                    except (Refusal, ValueError):
                        refuse("unknown_hub")
                    cert_o = verify_channel_cert(cert, card, op, now, self.dev_mode)
                    if cert_o["channel_id"] != ch:
                        refuse("other_user")
                    if not P.SUITE.verify(P.unb64u(cert_o["key_pub"], 65), sig, message):
                        refuse("bad_channel_signature")
                    if con.execute(
                        "SELECT 1 FROM hub_revoked_channels WHERE hub_id=? AND channel_id=?",
                        (hub, ch),
                    ).fetchone():
                        refuse("channel_revoked")
                    con.execute(
                        "DELETE FROM hub_channel_nonces WHERE ts_ms <= ?",
                        (now - NONCE_RETENTION_MS,),
                    )
                    (held,) = con.execute(
                        "SELECT count(*) FROM hub_channel_nonces WHERE hub_id=? AND channel_id=?",
                        (hub, ch),
                    ).fetchone()
                    try:
                        con.execute(
                            "INSERT INTO hub_channel_nonces VALUES (?,?,?,?)",
                            (hub, ch, nonce.hex(), ts),
                        )
                    except sqlite3.IntegrityError:
                        refuse("replay")
                    if held >= NONCES_PER_CHANNEL:
                        refuse(
                            "quota_exceeded", RETRY_S
                        )  # raised inside the transaction: the nonce is not kept
        except Refusal as error:
            raise _remap(error) from None
        return hub, ch

    # --- the routes -----------------------------------------------------------------------

    def handle(self, found):
        return getattr(self, found["route"])(found["hub"], found["channel_id"], found.get("id"))

    def mailbox_list(self, hub, ch, _mid):
        d = self.d
        with d.reader("query") as con:
            con.execute("BEGIN")
            rows = con.execute(
                "SELECT msg_id, expires_ms FROM hub_mailbox WHERE hub_id=? AND channel_id=? AND expires_ms>? "
                "ORDER BY msg_id LIMIT ?",
                (hub, ch, d.clock(), LIST_MAX),
            ).fetchall()
        return {"messages": [{"id": r["msg_id"], "expires_ms": r["expires_ms"]} for r in rows]}

    def mailbox_get(self, hub, ch, mid):
        d = self.d
        with d.reader("query") as con:
            con.execute("BEGIN")
            row = con.execute(
                "SELECT c, expires_ms FROM hub_mailbox WHERE hub_id=? AND channel_id=? AND msg_id=? AND expires_ms>?",
                (hub, ch, mid, d.clock()),
            ).fetchone()
        if row is None:
            refuse("not_found")
        return {"id": mid, "c": P.b64u(bytes(row["c"])), "expires_ms": row["expires_ms"]}

    def mailbox_delete(self, hub, ch, mid):
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


def install(app):
    chans = HubChannels(app.state.core, app.state.hub_accounts.dev_mode)
    app.state.hub_channels = chans

    async def read(hub_id_text: str, channel_text: str, request: Request, tail: str = ""):
        try:
            body = await read_body(request, BODY_CAP)
            if body is None:
                refuse("malformed")
            target = (request.scope.get("raw_path") or request.url.path.encode()).decode(
                "ascii", "replace"
            )
            if request.scope.get("query_string"):
                target += "?" + request.scope["query_string"].decode("ascii", "replace")
            await run_in_threadpool(
                chans.authenticate, request.method, target, request.headers.raw, body
            )
            found = route(request.method, target, body)
            result = await run_in_threadpool(chans.handle, found)
        except Refusal as error:
            return error_response(error)
        except (ValueError, TypeError, KeyError, sqlite3.DataError):
            return JSONResponse({"error": "malformed"}, status_code=400)
        return JSONResponse(result, headers={"Cache-Control": "no-store"})

    for path in (
        "/v2/hub-channels/{hub_id_text}/{channel_text}",
        "/v2/hub-channels/{hub_id_text}/{channel_text}/{tail:path}",
    ):
        app.add_api_route(path, read, methods=["GET", "DELETE"])
    return chans


__all__ = ["HubChannels", "install", "request_bytes", "route", "verify_channel_cert"]
