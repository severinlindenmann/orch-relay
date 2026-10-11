"""Durable ORB2 mailboxes and holder transactions (protocol §19.3–19.6)."""

import asyncio
import ipaddress
import math
import random
import secrets
import sqlite3
import struct
import threading
import time

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
    token_hash,
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


EMPTY_NOTICES = {"revocations_cursor": 0, "cert_requests": [], "rotation_due": []}


def notices_stamp(updates):
    return digest(P.cj(updates))


def last_stamp(delivered):
    """Digest of the notices last delivered in this holder generation."""
    return (delivered["notices"] if delivered else None) or notices_stamp(EMPTY_NOTICES)


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


POLL_CEILING = 4096  # all concurrent long polls (protocol §19, P3-D17)
PAIR_POLL_CEILING = 512  # anonymous pair polls, a separate share of POLL_CEILING
PAIR_POLLS_PER_ADDRESS = 4  # per canonical client address (IPv4 or IPv6 /64)
# Per allocation, so one cheap prefix cannot fill the pair pool: IPv4 /24, IPv6 /56 and /48.
PAIR_POLL_GROUPS = ((4, 24, 32), (6, 56, 32), (6, 48, 64))
DEVICE_POLLS = 6
RID_POLLS = 16  # waiting polls per (workspace, rid): bounds one response's wake fan-out
# Waiting polls re-check authorization at their earliest known expiry (session or
# certificate) and otherwise on a jittered slow tick; commits wake them by key.
POLL_TICK = (5.0, 7.0)


def pair_group_caps(address):
    try:
        network = ipaddress.ip_network(address, strict=False)
    except ValueError:
        return []
    return [
        (str(network.supernet(new_prefix=prefix)), cap)
        for version, prefix, cap in PAIR_POLL_GROUPS
        if network.version == version and network.prefixlen >= prefix
    ]


class Bridge:
    """Long polls wait on in-memory wakeups, never on the directory lock.

    The first step of a poll is the full write transaction. While waiting, a poll is
    woken by commits that may make it ready (see committed() and the directory's wake
    keys), at its earliest session/certificate expiry, or by the jittered slow tick. It
    then runs probe() on the event loop: a read-only snapshot without collect() that
    re-checks authorization, fencing and whether anything is ready. Only a ready probe
    re-runs the full transaction, which re-checks everything again before handing data
    over; the deadline also re-runs it, so a timed-out poll returns a fresh response.
    """

    def __init__(self, directory):
        self.d = directory
        self.polls = {}
        self.waiters = {}  # wake key -> set of asyncio.Event; touched on the event loop only
        self.pair_groups = {}  # address group -> admitted pair polls
        self.local = threading.local()
        self.connections = []
        self.connections_lock = threading.Lock()

    def connection(self, purpose):
        """A per-thread connection reused across transactions ("read" is query-only)."""
        cache = self.local.__dict__.setdefault("connections", {})
        con = cache.get(purpose)
        if con is None:
            con = db.connect(self.d.path, check_same_thread=False)
            con.row_factory = sqlite3.Row
            if purpose == "read":
                con.execute("PRAGMA query_only=ON")
            with self.connections_lock:
                self.connections.append(con)
            cache[purpose] = con
        if con.in_transaction:
            con.rollback()
        return con

    def close(self):
        with self.connections_lock:
            for con in self.connections:
                con.close()
            self.connections.clear()
        self.local = threading.local()

    def wake(self, *keys):
        for key in keys:
            for event in self.waiters.get(key, ()):
                event.set()

    def sweep(self):
        with self.d.lock:
            con = self.connection("write")
            con.execute("BEGIN IMMEDIATE")
            with con:
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
                "INSERT INTO holder_delivery(workspace_id,delivered) VALUES (?,?) ON CONFLICT(workspace_id) DO UPDATE SET delivered=excluded.delivered,notices=NULL",
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

        def charge():
            # Charged only after replay/coalescing checks, so identical resends are free.
            # Pairing headers name an unproven device; transaction() charges
            # pairing address/workspace/global limits, never device quotas.
            if offer is None:
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
                    return {}, False  # coalesced: nothing new to wake for
                if seen["requeues"] >= 8:
                    refuse("retry_exhausted", 409)
                if now < seen["last_requeue_ms"] + 10000:
                    fail("rate_limited", math.ceil((seen["last_requeue_ms"] + 10000 - now) / 1000))
                charge()
            else:
                charge()
                if offer is None and h["epoch"] != epoch:
                    refuse("stale_epoch", 409, epoch=epoch)
                if (
                    con.execute(
                        "SELECT count(*) FROM rid_seen WHERE device_id=? AND offer IS NULL"
                        if offer is None
                        else "SELECT count(*) FROM rid_seen WHERE workspace_id=? AND offer IS NOT NULL",
                        (device if offer is None else ws,),
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
                    "SELECT count(*) FROM request_mailboxes m WHERE workspace_id=? AND device_id=? "
                    "AND NOT EXISTS (SELECT 1 FROM rid_seen s WHERE s.workspace_id=m.workspace_id "
                    "AND s.device_id=m.device_id AND s.rid=m.rid AND s.offer IS NOT NULL)"
                    if offer is None
                    else "SELECT count(*) FROM request_mailboxes m WHERE workspace_id=? "
                    "AND EXISTS (SELECT 1 FROM rid_seen s WHERE s.workspace_id=m.workspace_id "
                    "AND s.device_id=m.device_id AND s.rid=m.rid AND s.offer IS NOT NULL)",
                    (ws, device) if offer is None else (ws,),
                ).fetchone()[0]
                >= 128
            ):
                fail("quota_exceeded")
            self.budget(con, ws, device if offer is None else None, 1, len(raw))
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
                return {}, False  # stored replay
            charge()
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
            self.budget(con, ws, device if offer is None else None, 2, len(raw))
            con.execute("INSERT INTO rid_chunks VALUES (?,?,?,?,?)", (*key, h["idx"], hashed))
            con.execute(
                "UPDATE rid_seen SET keep_until_ms=max(keep_until_ms,?) WHERE workspace_id=? AND device_id=? AND rid=?",
                (now + 60000, *key),
            )
        con.execute(
            "INSERT INTO bridge_msgs(workspace_id,device_id,rid,direction,offer,idx,flags,stream,body,expires_ms) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (*key, direction, offer, h["idx"], h["flags"], h["stream"], raw, now + 60000),
        )
        return {}, True

    def host_poll(self, con, ws, query, token, first, now):
        holder = con.execute("SELECT * FROM holders WHERE workspace_id=?", (ws,)).fetchone()
        after = integer(query.get("after", "0"))
        delivered = con.execute(
            "SELECT delivered,notices FROM holder_delivery WHERE workspace_id=?", (ws,)
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
                "INSERT INTO holder_delivery(workspace_id,delivered) VALUES (?,?) ON CONFLICT(workspace_id) DO UPDATE SET delivered=max(delivered,excluded.delivered)",
                (ws, items[-1]["n"]),
            )
        # Durable notices (a past revocation cursor, rotation_due, cert request states)
        # make a poll ready only when they changed since the last delivered response.
        stamp = notices_stamp(updates)
        ready = bool(items) or stamp != last_stamp(delivered)
        if ready:
            con.execute(
                "INSERT INTO holder_delivery(workspace_id,notices) VALUES (?,?) ON CONFLICT(workspace_id) DO UPDATE SET notices=excluded.notices",
                (ws, stamp),
            )
        nxt = P.b64u(P.cj({"ws": ws, "after": after, "n": items[-1]["n"]})) if more else None
        return {"items": items, "notices": updates, "next": nxt}, ready

    def transaction(self, route, params, method, raw, query, headers, peer, token, first):
        d = self.d
        with d.lock:
            con = self.connection("write")
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
                    # For posts the flag means "inserted": only new bodies wake polls.
                    return self.post(con, ws, rid, offer, raw, session, now)
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

    def ready(self, con, route, params, query, headers, token, now):
        """Read-only mirror of a waiting poll step: may the full transaction hand over data?

        Expired rows are filtered rather than collected; the maintenance sweep deletes them.
        """
        d = self.d
        ws, rid, offer = params.get("ws"), params.get("rid"), params.get("offer")
        after = integer(query["after"]) if "after" in query else -1
        if route == "pair":
            if not con.execute("SELECT 1 FROM workspaces WHERE workspace_id=?", (ws,)).fetchone():
                return True
            return bool(
                con.execute(
                    "SELECT 1 FROM bridge_msgs WHERE workspace_id=? AND rid=? AND direction=2 "
                    "AND idx>? AND offer=? AND expires_ms>? LIMIT 1",
                    (ws, rid, after, offer, now),
                ).fetchone()
            )
        session = d.authenticate(con, headers, now)
        if route == "cert_requests":
            if session["kind"] != "device" or session["person_id"] != params["person"]:
                return True
            return bool(
                con.execute(
                    "SELECT 1 FROM cert_requests WHERE person_id=? AND primary_device_id=? "
                    "AND state='open' AND expires_ms>? LIMIT 1",
                    (params["person"], session["subject_id"], now),
                ).fetchone()
            )
        d.workspace_access(con, session, ws, write=route == "host_poll")
        if route == "bridge":
            if session["kind"] != "device":
                return True
            return bool(
                con.execute(
                    "SELECT 1 FROM bridge_msgs WHERE workspace_id=? AND rid=? AND direction=2 "
                    "AND idx>? AND offer IS NULL AND device_id=? AND expires_ms>? LIMIT 1",
                    (ws, rid, after, session["subject_id"], now),
                ).fetchone()
            )
        d.fence(con, headers, ws, now)
        holder = con.execute("SELECT * FROM holders WHERE workspace_id=?", (ws,)).fetchone()
        if holder["poll_token"] != token:
            return True  # replaced: the full step answers empty
        position = max(holder["cursor"], integer(query.get("after", "0")))
        if "next" in query:
            position = max(position, P.parse_json(P.unb64u(query["next"]))["n"])
        for row in con.execute(
            "SELECT device_id,offer FROM bridge_msgs WHERE workspace_id=? AND direction=1 "
            "AND n>? AND expires_ms>? ORDER BY n",
            (ws, position, now),
        ):
            if row["offer"] is not None:
                return True
            try:
                self.eligible(con, ws, row["device_id"], now)
                return True
            except Refusal:
                continue
        delivered = con.execute(
            "SELECT delivered,notices FROM holder_delivery WHERE workspace_id=?", (ws,)
        ).fetchone()
        return notices_stamp(notices(con, ws)) != last_stamp(delivered)

    def expiry(self, con, headers):
        """Earliest time (ms) the poll's authorization lapses without any commit."""
        session = con.execute(
            "SELECT s.expires_ms,d.expires_ms FROM sessions s LEFT JOIN devices d "
            "ON s.kind='device' AND d.device_id=s.subject_id WHERE s.token_hash=?",
            (token_hash(headers.get("authorization", "")[7:]),),
        ).fetchone()
        return min(x for x in session if x is not None) if session else None

    def probe(self, route, params, query, headers, token):
        """Runs on the event loop: a 10-30 µs read, cheaper than a thread-pool hop.

        Returns (ready, expiry_ms). WAL readers never wait for writers.
        """
        con = self.connection("read")
        try:
            con.execute("BEGIN")
            ready = self.ready(con, route, params, query, headers, token, self.d.clock())
            return ready, None if ready or route == "pair" else self.expiry(con, headers)
        except (Refusal, sqlite3.Error):
            return True, None  # the full transaction gives the authoritative answer
        finally:
            con.rollback()

    def admission_session(self, headers):
        con = self.connection("read")
        con.execute("BEGIN")
        try:
            return self.d.authenticate(con, headers, self.d.clock()), self.expiry(con, headers)
        finally:
            con.rollback()

    def admit(self, key):
        """Concurrency caps; callers run on the event loop, so no lock is needed."""
        if sum(self.polls.values()) >= POLL_CEILING:
            refuse("overloaded", 503, 1)
        groups = pair_group_caps(key[1]) if key[0] == "pair" else []
        if key[0] == "pair":
            if sum(v for k, v in self.polls.items() if k[0] == "pair") >= PAIR_POLL_CEILING:
                refuse("overloaded", 503, 1)
            if self.polls.get(key, 0) >= PAIR_POLLS_PER_ADDRESS or any(
                self.pair_groups.get(group, 0) >= cap for group, cap in groups
            ):
                fail("quota_exceeded")
            for group, _cap in groups:
                self.pair_groups[group] = self.pair_groups.get(group, 0) + 1
        if key[0] == "device" and self.polls.get(key, 0) >= DEVICE_POLLS:
            fail("quota_exceeded")
        self.polls[key] = self.polls.get(key, 0) + 1

    def release(self, key):
        self.polls[key] -= 1
        if not self.polls[key]:
            del self.polls[key]
        for group, _cap in pair_group_caps(key[1]) if key[0] == "pair" else []:
            self.pair_groups[group] -= 1
            if not self.pair_groups[group]:
                del self.pair_groups[group]

    def committed(self, route, params, method, raw, ready):
        """Wake waiting polls a successful transaction may have made ready.

        Each key wakes only polls the commit can ready: requests (direction 1, possibly
        anonymous pairing) wake the workspace's host polls; responses (direction 2, from
        the fenced holder only) wake device and pair polls on that rid. Cert challenges
        and rejections change the requesting workspace's host notices.
        """
        ws, rid = params.get("ws"), params.get("rid")
        if route in ("bridge", "pair") and method == "POST":
            if ready:  # identical resends and replays insert nothing and wake nothing
                self.wake(("rid", ws, rid) if raw[5] == 2 else ("ws", ws))
        elif route in ("hold", "host_poll"):
            self.wake(("ws", ws))  # new generation fences; a new poll replaces the old one
        elif route == "cert_requests" and method == "POST":
            self.wake(("person", params["person"]))
        elif route in ("cert_challenge", "cert_rejection"):
            con = self.connection("read")
            try:
                row = con.execute(
                    "SELECT workspace_id FROM cert_requests WHERE request_id=?", (params["ident"],)
                ).fetchone()
            finally:
                con.rollback()
            if row:
                self.wake(("ws", row[0]))

    @staticmethod
    def wait_keys(route, params, subject):
        if route == "host_poll":
            return [("ws", params["ws"])]
        if route == "cert_requests":
            return [("person", params["person"]), ("subject", subject)]
        keys = [("rid", params["ws"], params["rid"])]
        if route == "bridge":
            keys += [("subject", subject), ("members", params["ws"])]
        return keys

    async def handle(self, request, route):
        binary = route in ("bridge", "pair") and request.method == "POST"
        cap = (
            (65536 if route == "pair" else MIB)
            if binary
            else (65536 if route == "cert_requests" else 16384)
        )
        key = None
        event = None
        wake_keys = []
        expiry = None
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
            params, headers = dict(request.path_params), dict(request.headers)
            peer = request.client.host if request.client else "unknown"
            if wait:
                subject = None
                if route == "pair":
                    address = canonical_address(
                        peer, headers.get("x-forwarded-for"), self.d.trusted_proxy
                    )
                    candidate = ("pair", address)
                else:
                    session, expiry = self.admission_session(headers)
                    subject = session["subject_id"]
                    candidate = (session["kind"], subject)
                keys = self.wait_keys(route, params, subject)
                if len(self.waiters.get(keys[0], ())) >= RID_POLLS and route in (
                    "bridge",
                    "pair",
                ):
                    fail("quota_exceeded")
                self.admit(candidate)
                key = candidate
                # Register before the first step so a commit racing it still wakes us.
                event = asyncio.Event()
                wake_keys = keys
                for wake_key in wake_keys:
                    self.waiters.setdefault(wake_key, set()).add(event)
            token, deadline = secrets.token_hex(16), time.monotonic() + wait
            step = (route, params, request.method, bytes(raw), query, headers, peer, token)
            result, ready = await run_in_threadpool(self.transaction, *step, True)
            self.committed(route, params, request.method, raw, ready)
            while wait and not ready:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    # Rebuild (and re-authorize) rather than return the first step's result.
                    result, ready = await run_in_threadpool(self.transaction, *step, False)
                    break
                timeout = min(remaining, random.uniform(*POLL_TICK))
                if expiry is not None:
                    timeout = min(timeout, max(0.01, (expiry - self.d.clock()) / 1000 + 0.01))
                self.d.assert_can_wait()
                try:
                    await asyncio.wait_for(event.wait(), timeout)
                except TimeoutError:
                    pass
                event.clear()
                probed, expiry = self.probe(route, params, query, headers, token)
                if probed:
                    result, ready = await run_in_threadpool(self.transaction, *step, False)
            return JSONResponse(result, status_code=202 if binary else 200)
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
            for wake_key in wake_keys:
                events = self.waiters[wake_key]
                events.discard(event)
                if not events:
                    del self.waiters[wake_key]
            if key is not None:
                self.release(key)


def install(app):
    bridge = Bridge(app.state.directory)
    app.state.bridge = bridge
    app.state.directory.changed = bridge.wake

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
