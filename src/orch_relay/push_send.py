"""The host's push send route and APNs delivery (P3-D40b): protocol-v2 §19.10, P3 design §14.3 items 4-7.

`POST /v2/workspaces/{ws}/push` (W(g), fenced) accepts sealed outer objects for member devices; the relay
queues one APNs send per registration of each accepted, unbudgeted, not-yet-sent target and delivers them
best effort (no durable queue, no receipts). Check order, each refusal stopping the request:

 1 session (401), W session of this workspace (403 `not_eligible`), the fence (409 `fenced`), then the
   session's read-class bucket; nothing below has run, so a stale holder spends nobody's budget
 2 body (400 `malformed`), the request bucket (429), the list epoch (409 `stale_epoch`)
 3 targets: current members with an unrevoked, unexpired certificate; others are skipped, not refused
 4 under Directory.lock: the live holders row again (409 `fenced`), then, under the outbox mutex: the
   dedup LRU, the per-device budgets, the all-or-nothing queue admission (503 `overloaded`), and only
   then the charges, the LRU entries and the enqueue

Lock order: Directory.lock, then the outbox mutex (which also guards the budgets and the LRU; the
event loop takes only the mutex, briefly). Delivery runs on the event loop: apns.py.
"""

import asyncio
import hashlib
import logging
import os
import threading
import time
from collections import Counter, OrderedDict, deque
from dataclasses import dataclass, field
from itertools import pairwise

from cryptography.exceptions import InvalidTag
from starlette.concurrency import run_in_threadpool

from . import proto as P
from .apns import MAX_STREAMS, Apns, HttpxTransport, apns_body
from .bridge import refuse
from .directory import Buckets, Refusal, fail, revoked_sql

log = logging.getLogger(__name__)

SEND_CAP = 64 * 1024
MAX_TARGETS = 1024
MAX_OUTER = 3072
MAX_TTL_S = 86_400
LRU_ENTRIES = 65_536
LRU_MS = 24 * 3_600_000
QUEUE_TOTAL, QUEUE_WORKSPACE, QUEUE_ACCOUNT = 4096, 1024, 2048
WAIT_MAX_S = 600  # a send waiting longer than min(ttl_s, 600 s) is dropped
WAIT_MIN_S = 5  # ... but ttl_s 0 ("once, then drop" at APNs) still waits this long in our queue
SENDS_PER_SECOND = 50
OVERLOADED_RETRY_S = 5
# P3-D40 item 7: (burst, per minute); ORCH_RELAY_THROTTLE_PUSH_* override as for the P3-D35 classes.
THROTTLES = {"push-ws-device": (20, 2), "push-device": (60, 6), "push-ws": (120, 20)}
OUTER_FIELDS = {"v", "ws", "epoch", "c"}
EPOCH_MAX = 2**32 - 1


def throttle_settings(env):
    out = dict(THROTTLES)
    for name in THROTTLES:
        text = env.get("ORCH_RELAY_THROTTLE_" + name.upper().replace("-", "_"))
        if text is not None:
            burst, rate = (int(part) for part in text.split("/"))
            if burst <= 0 or rate <= 0:
                raise ValueError(f"throttle {name} needs a positive burst/per-minute")
            out[name] = (burst, rate)
    return out


@dataclass
class Send:
    registration_id: str
    sealed: bytes
    mac: bytes
    env: str
    ws: str
    account: str
    device: str
    body: bytes
    priority: int
    expiration: int
    deadline_ms: int
    token: bytes = field(default=b"", repr=False)


class Outbox:
    """Budgets, the dedup LRU and the in-memory queue, all under one mutex."""

    def __init__(self, envs, throttles, table_limit):
        self.mutex = threading.Lock()
        self.throttles = throttles
        self.buckets = Buckets(table_limit)
        self.lru = OrderedDict()  # 32-byte digest -> expiry ms
        self.queues = {env: deque() for env in envs}
        self.total = 0
        self.per_ws, self.per_account = Counter(), Counter()
        self.caps = (QUEUE_TOTAL, QUEUE_WORKSPACE, QUEUE_ACCOUNT)

    def take(self, key, now, charge):
        self.buckets.take(key, *self.throttles[key[0]], now, charge)

    def request_ok(self, ws, now):
        """Per-workspace send requests: burst 120, refill 20 per minute (429 for the request)."""
        with self.mutex:
            self.take(("push-ws", ws), now, False)

    @staticmethod
    def digest(ws, outer_hash, device):
        return hashlib.sha256(ws.encode() + b"|" + outer_hash + b"|" + device.encode()).digest()

    def fresh(self, key, now):
        expiry = self.lru.get(key)
        if expiry is None:
            return True
        if expiry <= now:
            del self.lru[key]
            return True
        return False

    def commit(self, ws, account, outer_hash, targets, now):
        """targets: [(device, [Send, ...])] sorted by device. Returns the sends queued. 429 for the
        request bucket, 503 when the sends do not all fit; otherwise charges and enqueues."""
        with self.mutex:
            self.take(("push-ws", ws), now, False)
            selected = []
            for device, sends in targets:
                key = self.digest(ws, outer_hash, device)
                if not sends or not self.fresh(key, now):
                    continue  # an exact retry reaches no device twice
                keys = [("push-ws-device", ws, device), ("push-device", device)]
                try:
                    for k in keys:
                        self.take(k, now, False)
                except Refusal:
                    continue  # over budget: skipped, still `accepted`
                selected.append((device, key, keys, sends))
            queued = [s for *_, sends in selected for s in sends]
            total, in_ws, in_account = self.caps
            if (
                self.total + len(queued) > total
                or self.per_ws[ws] + len(queued) > in_ws
                or self.per_account[account] + len(queued) > in_account
            ):
                refuse("overloaded", 503, OVERLOADED_RETRY_S)
            self.take(("push-ws", ws), now, True)
            for _device, key, keys, sends in selected:
                for k in keys:
                    self.take(k, now, True)
                self.lru[key] = now + LRU_MS
                self.lru.move_to_end(key)
            while len(self.lru) > LRU_ENTRIES:
                self.lru.popitem(last=False)
            for s in queued:
                self.queues[s.env].append(s)
            self.total += len(queued)
            self.per_ws[ws] += len(queued)
            self.per_account[account] += len(queued)
            return queued

    def release(self, send):
        self.total -= 1
        self.per_ws[send.ws] -= 1
        self.per_account[send.account] -= 1
        if not self.per_ws[send.ws]:
            del self.per_ws[send.ws]
        if not self.per_account[send.account]:
            del self.per_account[send.account]

    def pop_ready(self, env, now, active_limit, active):
        """The next send of `env` to start (None when none is due); expired ones are dropped."""
        with self.mutex:
            queue = self.queues[env]
            while queue and active < active_limit:
                send = queue.popleft()
                self.release(send)
                if send.deadline_ms > now:
                    return send
                log.info(
                    "apns %s: dropped after waiting too long (%s)", send.registration_id[:8], env
                )
            return None

    def expire(self, env, now):
        with self.mutex:
            keep = deque()
            for send in self.queues[env]:
                if send.deadline_ms > now:
                    keep.append(send)
                else:
                    self.release(send)
            self.queues[env] = keep

    def queued(self, env=None):
        with self.mutex:
            return self.total if env is None else len(self.queues[env])


class Sender:
    """Delivery: per-environment queues drained by one pump on the event loop at most 50 sends a
    second, at most 16 concurrent streams per environment (one HTTP/2 connection)."""

    def __init__(self, push, outbox, apns):
        self.push, self.outbox, self.apns = push, outbox, apns
        self.rate_per_s = SENDS_PER_SECOND
        self.active = Counter()
        self.tasks = set()
        self.next_start = 0.0
        self.loop = None
        self.wake = None
        self.results = []  # delivery results, newest last (bounded; for tests and diagnostics)

    def notify(self):
        """Thread-safe: new sends were queued."""
        loop, wake = self.loop, self.wake
        if loop is not None and wake is not None:
            loop.call_soon_threadsafe(wake.set)

    async def run(self):
        self.loop = asyncio.get_running_loop()
        self.wake = asyncio.Event()
        try:
            while True:
                self.wake.clear()
                delay = self.dispatch()
                try:
                    await asyncio.wait_for(self.wake.wait(), delay)
                except TimeoutError:
                    pass
        finally:
            for task in list(self.tasks):
                task.cancel()
            if self.apns.transport is not None:
                await self.apns.transport.aclose()

    def dispatch(self):
        """Start every due send; returns how long to sleep before looking again."""
        d = self.push.d
        delay = 1.0
        for env in self.outbox.queues:
            now = d.clock()
            if self.apns.paused(env, now / 1000):
                self.outbox.expire(env, now)
                continue
            while True:
                spacing = time.monotonic() - self.next_start
                if spacing < 0:
                    delay = min(delay, -spacing)
                    break
                send = self.outbox.pop_ready(env, d.clock(), MAX_STREAMS, self.active[env])
                if send is None:
                    break
                self.next_start = max(time.monotonic(), self.next_start) + 1 / self.rate_per_s
                self.active[env] += 1
                task = asyncio.create_task(self.deliver(send))
                self.tasks.add(task)
                task.add_done_callback(self.finished)
        return delay

    def finished(self, task):
        self.tasks.discard(task)
        if self.wake is not None:
            self.wake.set()

    async def deliver(self, send):
        try:
            try:
                send.token = self.push.unseal(send.registration_id, send.sealed)
            except InvalidTag:
                log.error("push token unreadable for %s", send.registration_id[:8])
                return
            if self.apns.transport is None:
                self.apns.transport = HttpxTransport()
            result = await self.apns.deliver(send)
            send.token = b""
            self.results.append((send.registration_id, result.kind, result.status))
            del self.results[:-1024]
            if result.kind in ("unregistered", "bad_token"):
                await run_in_threadpool(self.push.apply_result, send, result)
        finally:
            send.token = b""
            self.active[send.env] -= 1


def outer_check(outer, ws):
    if not isinstance(outer, dict) or set(outer) != OUTER_FIELDS:
        fail("malformed")
    if type(outer["v"]) is not int or outer["v"] != 2 or outer["ws"] != ws:
        fail("malformed")
    if type(outer["epoch"]) is not int or not 0 <= outer["epoch"] <= EPOCH_MAX:
        fail("malformed")
    if not isinstance(outer["c"], str) or not outer["c"]:
        fail("malformed")
    try:
        P.unb64u(outer["c"])
    except ValueError:
        fail("malformed")
    raw = P.cj(outer)
    if len(raw) > MAX_OUTER:
        fail("malformed")
    return raw


def parse_send(raw, ws):
    try:
        body = P.parse_json(raw)
    except ValueError:
        fail("malformed")
    if not isinstance(body, dict) or set(body) != {"targets", "outer", "priority", "ttl_s"}:
        fail("malformed")
    targets = body["targets"]
    if not isinstance(targets, list) or not 1 <= len(targets) <= MAX_TARGETS:
        fail("malformed")
    try:
        for t in targets:
            P.unhex(t)
    except ValueError:
        fail("malformed")
    if any(a >= b for a, b in pairwise(targets)):  # sorted, unique
        fail("malformed")
    if body["priority"] not in ("high", "normal"):
        fail("malformed")
    ttl = body["ttl_s"]
    if type(ttl) is not int or not 0 <= ttl <= MAX_TTL_S:
        fail("malformed")
    return targets, body["outer"], outer_check(body["outer"], ws), body["priority"], ttl


def send(push, headers, ws, raw):
    """POST /v2/workspaces/{ws}/push; returns {"accepted": n}."""
    d, cfg, outbox = push.d, push.config, push.outbox
    try:
        P.unhex(ws)
    except ValueError:
        fail("malformed")
    with d.reader("query") as con:  # step 1
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
    targets, outer, outer_raw, priority, ttl = parse_send(raw, ws)  # step 2
    outbox.request_ok(ws, d.clock())
    with d.reader("query") as con:  # step 3
        con.execute("BEGIN")
        now = d.clock()
        row = con.execute(
            "SELECT epoch FROM member_lists WHERE workspace_id=? ORDER BY list_seq DESC LIMIT 1",
            (ws,),
        ).fetchone()
        if row is None or row[0] != outer["epoch"]:
            refuse("stale_epoch", 409, epoch=row[0] if row else 0)
        account = con.execute(
            "SELECT owner_person_id FROM workspaces WHERE workspace_id=?", (ws,)
        ).fetchone()
        account = account[0] if account else ws
        accepted = []
        for start in range(0, len(targets), 256):
            chunk = targets[start : start + 256]
            marks = ",".join("?" * len(chunk))
            accepted += [
                r[0]
                for r in con.execute(
                    "SELECT m.device_id FROM members m JOIN devices v ON v.device_id=m.device_id "
                    f"WHERE m.workspace_id=? AND m.device_id IN ({marks}) "
                    "AND (v.expires_ms IS NULL OR v.expires_ms>?) AND NOT "
                    + revoked_sql("m.device_id"),
                    (ws, *chunk, now),
                )
            ]
        accepted.sort()
        regs = {}
        for start in range(0, len(accepted), 256):
            chunk = accepted[start : start + 256]
            marks = ",".join("?" * len(chunk))
            for r in con.execute(
                "SELECT registration_id, device_id, env, topic, token_sealed, token_mac FROM "
                f"push_subscriptions WHERE workspace_id=? AND device_id IN ({marks}) "
                "ORDER BY registration_id",
                (ws, *chunk),
            ):
                if r["env"] in cfg.keys and r["topic"] == cfg.topic:
                    regs.setdefault(r["device_id"], []).append(r)
    body = apns_body(outer_raw)
    expiration = 0 if ttl == 0 else now // 1000 + ttl
    wait_s = WAIT_MIN_S if ttl == 0 else min(ttl, WAIT_MAX_S)
    deadline = now + 1000 * wait_s
    plan = [
        (
            device,
            [
                Send(
                    r["registration_id"],
                    bytes(r["token_sealed"]),
                    bytes(r["token_mac"]),
                    r["env"],
                    ws,
                    account,
                    device,
                    body,
                    10 if priority == "high" else 5,
                    expiration,
                    deadline,
                )
                for r in regs.get(device, ())
            ],
        )
        for device in accepted
    ]
    outer_hash = hashlib.sha256(outer_raw).digest()
    with d.lock:  # step 4
        con = d.connection("write")
        d.fence(con, headers, ws, d.clock())  # a read of the live holders row, no write transaction
        outbox.commit(ws, account, outer_hash, plan, d.clock())
    push.sender.notify()
    return {"accepted": len(accepted)}


def attach(app, push, env=None):
    """Create the outbox and the sender for an enabled push."""
    env = os.environ if env is None else env
    outbox = Outbox(push.config.envs, throttle_settings(env), push.d.buckets.limit)
    apns = Apns(push.config, clock_s=lambda: push.d.clock() / 1000)
    push.outbox, push.sender = outbox, Sender(push, outbox, apns)
    push.apns = apns
