"""APNs delivery of the hub's push sends (D77): the in-memory outbox (budgets, dedup LRU, queue caps) and the sender.

`hub_phone` hands `Send` objects (common.py) to `Outbox.commit`, with the hub as workspace and account and the channel
as device; the sender drains the per-environment queues to APNs best effort (no durable queue, no receipts).

Lock order: Core.lock, then the outbox mutex (which also guards the budgets and the LRU; the event loop takes only
the mutex, briefly). Delivery runs on the event loop: apns.py.
"""

import asyncio
import hashlib
import logging
import os
import threading
import time
from collections import Counter, OrderedDict, deque

from cryptography.exceptions import InvalidTag
from starlette.concurrency import run_in_threadpool

from .apns import MAX_STREAMS, Apns, HttpxTransport
from .common import Buckets, Refusal, refuse

log = logging.getLogger(__name__)

LRU_ENTRIES = 65_536
LRU_MS = 24 * 3_600_000
QUEUE_TOTAL, QUEUE_WORKSPACE, QUEUE_ACCOUNT = 4096, 1024, 2048
SENDS_PER_SECOND = 50
OVERLOADED_RETRY_S = 5
# P3-D40 item 7: (burst, per minute); ORCH_RELAY_THROTTLE_PUSH_* override as for the P3-D35 classes.
THROTTLES = {"push-ws-device": (20, 2), "push-device": (60, 6), "push-ws": (120, 20)}


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


def attach(app, push, env=None):
    """Create the outbox and the sender for an enabled push."""
    env = os.environ if env is None else env
    outbox = Outbox(push.config.envs, throttle_settings(env), push.d.table_limit)
    apns = Apns(push.config, clock_s=lambda: push.d.clock() / 1000)
    push.outbox, push.sender = outbox, Sender(push, outbox, apns)
    push.apns = apns
