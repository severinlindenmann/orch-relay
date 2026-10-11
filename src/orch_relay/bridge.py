"""Durable ORB2 mailboxes and holder transactions (protocol §19.3–19.6)."""

import asyncio
import math
import secrets
import sqlite3
import struct
import time
from contextlib import closing

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from . import db
from . import proto as P
from .directory import (
    Refusal,
    canonical_address,
    check_response_budget,
    digest,
    fail,
    fields,
    integer,
    ipv6_parent,
)

MIB = 1024 * 1024
HEADER = struct.Struct(">4sBBBB16s16s16s16sQQI16s")


def refuse(code, status, retry=None, **details):
    error = Refusal(code, retry)
    error.status, error.details = status, details
    raise error


def envelope(raw, ws, rid, direction, device=None, offer=None):
    limit = 65536 if offer else MIB if direction == 1 else 256 * 1024
    if len(raw) > limit:
        refuse("too_large", 400)
    if len(raw) < 188:
        fail("malformed")
    magic, version, dr, flags, suite, workspace, dev, request, stream, idx, _ts, epoch, _salt = (
        HEADER.unpack(raw[:108])
    )
    if suite != 2:
        fail("wrong_suite")
    if (
        magic != b"ORB2"
        or version != 2
        or dr != direction
        or workspace.hex() != ws
        or request.hex() != rid
        or idx > P.MAX_SAFE_INT
        or flags & ~(2 if direction == 1 else 7)
        or flags & 4
        and not flags & 1
        or (epoch != 0 or stream.hex() != offer if offer else epoch == 0)
    ):
        fail("malformed")
    if device and dev.hex() != device:
        fail("not_for_this_device")
    return {"device": dev.hex(), "idx": idx, "flags": flags, "epoch": epoch, "stream": stream.hex()}


def collect(con, now):
    con.execute("DELETE FROM bridge_msgs WHERE expires_ms<=?", (now,))
    con.execute("DELETE FROM request_mailboxes WHERE expires_ms<=?", (now,))
    con.execute("DELETE FROM rid_seen WHERE keep_until_ms<=?", (now,))
    con.execute(
        "UPDATE cert_requests SET state='expired' WHERE state IN ('open','challenged') AND expires_ms<=?",
        (now,),
    )
    con.execute("DELETE FROM cert_requests WHERE expires_ms+60000<=?", (now,))


def notices(con, ws):
    cursor = con.execute(
        "SELECT coalesce(max(r.cursor),0) FROM revocations r JOIN ever_devices e ON e.device_id=r.device_id WHERE e.workspace_id=?",
        (ws,),
    ).fetchone()[0]
    return {
        "revocations_cursor": cursor,
        "cert_requests": [
            r[0]
            for r in con.execute(
                "SELECT request_id FROM cert_requests WHERE workspace_id=? AND (challenge IS NOT NULL OR cert IS NOT NULL OR rejection IS NOT NULL) ORDER BY request_id",
                (ws,),
            )
        ],
        "rotation_due": [
            dict(r)
            for r in con.execute(
                "SELECT device_id,revocation_cursor,epoch FROM rotation_due WHERE workspace_id=? ORDER BY device_id",
                (ws,),
            )
        ],
    }


class Bridge:
    def __init__(self, directory):
        self.d = directory
        self.polls = {}

    def sweep(self):
        with self.d.lock, closing(db.connect(self.d.path)) as con, con:
            con.execute("BEGIN IMMEDIATE")
            collect(con, self.d.clock())

    async def maintenance(self):
        while True:
            await asyncio.sleep(1)
            await run_in_threadpool(self.sweep)

    def budget(self, con, ws, device, direction, size):
        total = con.execute("SELECT coalesce(sum(bodies),0) FROM queue_totals").fetchone()[0]
        if total + size > 256 * MIB:
            refuse("overloaded", 503, 1)
        rows = con.execute("SELECT * FROM queue_totals WHERE direction=?", (direction,)).fetchall()
        device_bytes = sum(r["pending"] for r in rows if r["device_id"] == device)
        ws_bytes = sum(r["pending"] for r in rows if r["workspace_id"] == ws)
        if direction == 2:
            check_response_budget(device_bytes, ws_bytes, size)
        elif (
            device_bytes + size > 8 * MIB
            or ws_bytes + size > 16 * MIB
            or sum(r["count"] for r in rows if r["workspace_id"] == ws) >= 1024
        ):
            fail("quota_exceeded")

    def eligible(self, con, ws, device, now):
        row = con.execute("SELECT * FROM devices WHERE device_id=?", (device,)).fetchone()
        if row is None:
            fail("not_eligible")
        self.d.device_status(con, row, now)
        if not con.execute(
            "SELECT 1 FROM members WHERE workspace_id=? AND device_id=?", (ws, device)
        ).fetchone():
            fail("not_eligible")

    def hold(self, con, ws, body, now):
        fields(body, "gen take_over")
        gen = body["gen"]
        if type(body["take_over"]) is not bool or (
            gen is not None and (type(gen) is not int or gen < 0)
        ):
            fail("malformed")
        row = con.execute("SELECT * FROM holders WHERE workspace_id=?", (ws,)).fetchone()
        if gen is not None:
            if row is None or row["gen"] != gen or row["lease_until_ms"] <= now:
                fail("fenced")
        elif row and row["lease_until_ms"] > now and not body["take_over"]:
            refuse("holder_conflict", 409)
        else:
            gen = row["gen"] + 1 if row else 1
        cursor = row["cursor"] if row else 0
        con.execute(
            "INSERT INTO holders VALUES (?,?,?,?,?) ON CONFLICT(workspace_id) DO UPDATE SET gen=excluded.gen,lease_until_ms=excluded.lease_until_ms,poll_token=CASE WHEN holders.gen=excluded.gen THEN holders.poll_token ELSE NULL END",
            (ws, gen, now + 40000, cursor, None),
        )
        if row is None or gen != row["gen"]:
            con.execute(
                "INSERT INTO holder_delivery VALUES (?,?) ON CONFLICT(workspace_id) DO UPDATE SET delivered=excluded.delivered",
                (ws, cursor),
            )
        return {"gen": gen, "lease_s": 40, "cursor": cursor}

    def post(self, con, ws, rid, offer, raw, session, now):
        direction = 2 if session and session["kind"] == "workspace" else 1
        h = envelope(
            raw,
            ws,
            rid,
            direction,
            session["subject_id"] if session and direction == 1 else None,
            offer,
        )
        device = h["device"]
        if offer is None:
            self.eligible(con, ws, device, now)
        key = (ws, device, rid)
        seen = con.execute(
            "SELECT * FROM rid_seen WHERE workspace_id=? AND device_id=? AND rid=?", key
        ).fetchone()
        current = con.execute(
            "SELECT epoch FROM member_lists WHERE workspace_id=? ORDER BY list_seq DESC LIMIT 1",
            (ws,),
        ).fetchone()
        epoch = current[0] if current else 0
        hashed = digest(raw)
        self.d.rate("bridge-post", device, 1000, 20, now)
        if direction == 1:
            if seen:
                if seen["req_digest"] != hashed or seen["offer"] != offer:
                    refuse("rid_conflict", 409)
                live = con.execute(
                    "SELECT 1 FROM bridge_msgs WHERE workspace_id=? AND device_id=? AND rid=? AND direction=1 AND n>coalesce((SELECT cursor FROM holders WHERE workspace_id=?),0)",
                    (*key, ws),
                ).fetchone()
                if live:
                    return {}
                if seen["requeues"] >= 8:
                    refuse("retry_exhausted", 409)
                if now < seen["last_requeue_ms"] + 10000:
                    fail("rate_limited", math.ceil((seen["last_requeue_ms"] + 10000 - now) / 1000))
            else:
                if offer is None and h["epoch"] != epoch:
                    refuse("stale_epoch", 409, epoch=epoch)
                if (
                    con.execute(
                        "SELECT count(*) FROM rid_seen WHERE device_id=?", (device,)
                    ).fetchone()[0]
                    >= 4096
                ):
                    fail("quota_exceeded")
            exists = con.execute(
                "SELECT 1 FROM request_mailboxes WHERE workspace_id=? AND device_id=? AND rid=?",
                key,
            ).fetchone()
            if (
                not exists
                and con.execute(
                    "SELECT count(*) FROM request_mailboxes WHERE workspace_id=? AND device_id=?",
                    (ws, device),
                ).fetchone()[0]
                >= 128
            ):
                fail("quota_exceeded")
            self.budget(con, ws, device, 1, len(raw))
            if seen:
                con.execute(
                    "UPDATE rid_seen SET requeues=requeues+1,last_requeue_ms=?,keep_until_ms=max(keep_until_ms,?) WHERE workspace_id=? AND device_id=? AND rid=?",
                    (now, now + 60000, *key),
                )
            else:
                con.execute(
                    "INSERT INTO rid_seen VALUES (?,?,?,?,?,?,0,?,?,?)",
                    (*key, hashed, h["epoch"], now, now, now + 900000, offer),
                )
            con.execute(
                "INSERT INTO request_mailboxes VALUES (?,?,?,?) ON CONFLICT DO UPDATE SET expires_ms=excluded.expires_ms",
                (*key, now + 60000),
            )
        else:
            if seen is None or seen["offer"] != offer:
                refuse("expired", 410)
            chunk = con.execute(
                "SELECT digest FROM rid_chunks WHERE workspace_id=? AND device_id=? AND rid=? AND idx=?",
                (*key, h["idx"]),
            ).fetchone()
            if chunk:
                if chunk[0] != hashed:
                    refuse("chunk_conflict", 409)
                return {}
            if h["epoch"] != seen["req_epoch"] or (
                offer is None and epoch != h["epoch"] and h["flags"] & 5 != 5
            ):
                refuse("stale_epoch", 409, epoch=epoch)
            if (
                con.execute(
                    "SELECT count(*) FROM rid_chunks WHERE workspace_id=? AND device_id=? AND rid=?",
                    key,
                ).fetchone()[0]
                >= 64
            ):
                fail("quota_exceeded")
            self.budget(con, ws, device, 2, len(raw))
            con.execute("INSERT INTO rid_chunks VALUES (?,?,?,?,?)", (*key, h["idx"], hashed))
            con.execute(
                "UPDATE rid_seen SET keep_until_ms=max(keep_until_ms,?) WHERE workspace_id=? AND device_id=? AND rid=?",
                (now + 60000, *key),
            )
        con.execute(
            "INSERT INTO bridge_msgs(workspace_id,device_id,rid,direction,offer,idx,flags,stream,body,expires_ms) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (*key, direction, offer, h["idx"], h["flags"], h["stream"], raw, now + 60000),
        )
        return {}

    def host_poll(self, con, ws, query, token, first, now):
        holder = con.execute("SELECT * FROM holders WHERE workspace_id=?", (ws,)).fetchone()
        after = integer(query.get("after", "0"))
        delivered = con.execute(
            "SELECT delivered FROM holder_delivery WHERE workspace_id=?", (ws,)
        ).fetchone()
        if after > (delivered[0] if delivered else 0):
            fail("malformed")
        if first:
            con.execute(
                "UPDATE holders SET cursor=max(cursor,?),poll_token=?,lease_until_ms=? WHERE workspace_id=?",
                (after, token, now + 40000, ws),
            )
        elif holder["poll_token"] != token:
            return {"items": [], "notices": notices(con, ws), "next": None}, True
        cursor = max(holder["cursor"], after)
        position = cursor
        if "next" in query:
            page = P.parse_json(P.unb64u(query["next"]))
            if (
                set(page) != {"ws", "after", "n"}
                or page["ws"] != ws
                or page["after"] != after
                or type(page["n"]) is not int
                or page["n"] < 0
                or page["n"] > (delivered[0] if delivered else 0)
            ):
                fail("malformed")
            position = max(position, page["n"])
        con.execute(
            "UPDATE bridge_msgs SET delivered=1 WHERE workspace_id=? AND direction=1 AND n<=?",
            (ws, cursor),
        )
        rows = con.execute(
            "SELECT * FROM bridge_msgs WHERE workspace_id=? AND direction=1 AND n>? ORDER BY n",
            (ws, position),
        ).fetchall()
        updates = notices(con, ws)
        items, size, more = [], len(P.cj(updates)) + 512, False
        for row in rows:
            if row["offer"] is None:
                try:
                    self.eligible(con, ws, row["device_id"], now)
                except Refusal:
                    continue
            item = {
                "n": row["n"],
                "route": "pair" if row["offer"] else "bridge",
                "device": row["device_id"],
                "rid": row["rid"],
                "offer": row["offer"],
                "envelope": P.b64u(row["body"]),
            }
            item_size = len(P.cj(item)) + 1
            if len(items) == 16 or size + item_size > 4 * MIB:
                more = True
                break
            items.append(item)
            size += item_size
        if items:
            con.execute(
                "INSERT INTO holder_delivery VALUES (?,?) ON CONFLICT(workspace_id) DO UPDATE SET delivered=max(delivered,excluded.delivered)",
                (ws, items[-1]["n"]),
            )
        nxt = P.b64u(P.cj({"ws": ws, "after": after, "n": items[-1]["n"]})) if more else None
        return {"items": items, "notices": updates, "next": nxt}, bool(
            items or any(updates.values())
        )

    def transaction(self, route, params, method, raw, query, headers, peer, token, first):
        d = self.d
        with d.lock, closing(db.connect(d.path)) as con:
            con.row_factory = sqlite3.Row
            con.execute("BEGIN IMMEDIATE")
            with con:
                now = d.clock()
                collect(con, now)
                ws, rid, offer = params.get("ws"), params.get("rid"), params.get("offer")
                for value in params.values():
                    P.unhex(value)
                if route.startswith("cert"):
                    from .cert_queue import dispatch

                    result = dispatch(d, con, route, params, method, raw, headers, now)
                    return result, bool(
                        result.get("requests")
                    ) or method != "GET" or route == "cert_request"
                if (
                    route == "pair"
                    and not con.execute(
                        "SELECT 1 FROM workspaces WHERE workspace_id=?", (ws,)
                    ).fetchone()
                ):
                    refuse("unknown_workspace", 401)
                session = None
                if route != "pair" or method == "POST" and len(raw) >= 6 and raw[5] == 2:
                    session = d.authenticate(con, headers, now)
                    d.workspace_access(
                        con, session, ws, write=route in ("hold", "host_poll") or route == "pair"
                    )
                    if (
                        session["kind"] == "workspace"
                        and route != "hold"
                        and (method == "POST" or route == "host_poll")
                    ):
                        d.fence(con, headers, ws, now)
                if route == "pair":
                    if not con.execute(
                        "SELECT 1 FROM workspaces WHERE workspace_id=?", (ws,)
                    ).fetchone():
                        refuse("unknown_workspace", 401)
                    if first:
                        address = canonical_address(
                            peer, headers.get("x-forwarded-for"), d.trusted_proxy
                        )
                        limits = [
                            (address, 60 if method == "POST" else 120),
                            ("global", 6000 if method == "POST" else 12000),
                        ]
                        parent = ipv6_parent(address)
                        if parent:
                            limits.append((parent, 480 if method == "POST" else 960))
                        if method == "POST":
                            limits.append((ws, 60))
                        for charge in (False, True):
                            for identity, cap in limits:
                                d.rate("pair-" + method, identity, 60000, cap, now, charge)
                if route == "hold":
                    return self.hold(con, ws, P.parse_json(raw), now), True
                if method == "POST":
                    return self.post(con, ws, rid, offer, raw, session, now), True
                if route == "host_poll":
                    return self.host_poll(con, ws, query, token, first, now)
                if session and session["kind"] != "device":
                    fail("not_eligible")
                after = integer(query["after"]) if "after" in query else -1
                rows = con.execute(
                    "SELECT * FROM bridge_msgs WHERE workspace_id=? AND rid=? AND direction=2 AND idx>? AND offer IS ? ORDER BY idx",
                    (ws, rid, after, offer),
                ).fetchall()
                chunks = []
                for row in rows:
                    if session and row["device_id"] != session["subject_id"]:
                        continue
                    chunks.append(
                        {
                            "id": row["rid"],
                            "idx": row["idx"],
                            "last": bool(row["flags"] & 1),
                            "stream": bool(row["flags"] & 2),
                            "envelope": P.b64u(row["body"]),
                        }
                    )
                    con.execute("UPDATE bridge_msgs SET delivered=1 WHERE n=?", (row["n"],))
                return {"chunks": chunks}, bool(chunks)

    async def handle(self, request, route):
        binary = route in ("bridge", "pair") and request.method == "POST"
        cap = (
            (65536 if route == "pair" else MIB)
            if binary
            else (65536 if route == "cert_requests" else 16384)
        )
        key = None
        admitted = False
        try:
            if len(request.query_params.multi_items()) != len(request.query_params):
                fail("malformed")
            query = dict(request.query_params)
            allowed = (
                {"after", "wait", "next"}
                if route == "host_poll"
                else {"wait"}
                if route.startswith("cert")
                else {"after", "wait"}
            )
            if request.method != "GET" or route == "cert_request":
                allowed = set()
            if set(query) - allowed:
                fail("malformed")
            wait = integer(query.get("wait", "0"), 25)
            raw = bytearray()
            declared = request.headers.get("content-length")
            if declared and declared.isdecimal() and int(declared) > cap:
                refuse("too_large", 400 if binary else 413)
            async for chunk in request.stream():
                raw.extend(chunk)
                if len(raw) > cap:
                    refuse("too_large", 400 if binary else 413)
            if request.method == "GET" and raw:
                fail("malformed")
            if request.method != "GET" and request.headers.get("content-type", "").split(";")[
                0
            ].strip() != ("application/octet-stream" if binary else "application/json"):
                fail("malformed")
            if wait:
                with self.d.lock, closing(db.connect(self.d.path)) as con:
                    con.row_factory = sqlite3.Row
                    if route != "pair":
                        session = self.d.authenticate(con, request.headers, self.d.clock())
                        key = (session["kind"], session["subject_id"])
                    else:
                        key = ("pair", request.client.host if request.client else "unknown")
                    if sum(self.polls.values()) >= 4096:
                        refuse("overloaded", 503, 1)
                    if key[0] == "device" and self.polls.get(key, 0) >= 6:
                        fail("quota_exceeded")
                    self.polls[key] = self.polls.get(key, 0) + 1
                    admitted = True
            token, first, deadline = secrets.token_hex(16), True, time.monotonic() + wait
            while True:
                result, ready = await run_in_threadpool(
                    self.transaction,
                    route,
                    dict(request.path_params),
                    request.method,
                    bytes(raw),
                    query,
                    dict(request.headers),
                    request.client.host if request.client else "unknown",
                    token,
                    first,
                )
                if ready or not wait or time.monotonic() >= deadline:
                    return JSONResponse(result, status_code=202 if binary else 200)
                first = False
                self.d.assert_can_wait()
                await asyncio.sleep(min(0.05, max(0, deadline - time.monotonic())))
        except Refusal as error:
            return JSONResponse(
                {"error": error.code, **getattr(error, "details", {})},
                status_code=error.status,
                headers={"Retry-After": str(error.retry or 1)}
                if error.status in (429, 503)
                else None,
            )
        except (ValueError, TypeError, KeyError, AttributeError):
            return JSONResponse({"error": "malformed"}, status_code=400)
        finally:
            if admitted:
                self.polls[key] -= 1
                if not self.polls[key]:
                    del self.polls[key]


def install(app):
    bridge = Bridge(app.state.directory)
    app.state.bridge = bridge

    def endpoint(route):
        async def handle(request: Request):
            return await bridge.handle(request, route)

        return handle

    for path, methods, route in (
        ("workspaces/{ws}/bridge/{rid}", ["GET", "POST"], "bridge"),
        ("workspaces/{ws}/pair/{offer}/{rid}", ["GET", "POST"], "pair"),
        ("workspaces/{ws}/host/hold", ["POST"], "hold"),
        ("workspaces/{ws}/host/poll", ["GET"], "host_poll"),
        ("persons/{person}/cert-requests", ["GET", "POST"], "cert_requests"),
        ("cert-requests/{ident}", ["GET"], "cert_request"),
        ("cert-requests/{ident}/challenge", ["POST"], "cert_challenge"),
        ("cert-requests/{ident}/rejection", ["POST"], "cert_rejection"),
    ):
        app.add_api_route("/v2/" + path, endpoint(route), methods=methods)
