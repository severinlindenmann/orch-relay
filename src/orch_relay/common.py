"""Shared plumbing of the hub-only relay (V3-D36; D68, D69, D76, D77).

The relay serves hub accounts (hub_accounts), hub channels (hub_channels) and the hub's phone push
and mailboxes (hub_phone, push). This module holds what those share: the refusal type, the request
body reader, the fixed-window and token-bucket budgets, the client-address rule and `Core`, the one
process lock plus the pooled SQLite connections (db.Connections) every route works on.

Lock order: Core.lock, then the in-memory budgets (Core.budget). A pooled read connection is never
held while taking the lock.
"""

import asyncio
import heapq
import ipaddress
import logging
import math
import os
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field

from fastapi.responses import JSONResponse

from . import db

MINUTE, HOUR, DAY = 60_000, 3_600_000, 86_400_000
# Buckets kept per key class (ORCH_RELAY_THROTTLE_TABLE), evicting full buckets first.
THROTTLE_TABLE = 16_384
BODY_TIMEOUT_S = 10

STATUS = {
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


def refuse(code, status, retry=None, **details):
    error = Refusal(code, retry)
    error.status, error.details = status, details
    raise error


def error_response(error):
    headers = {"Retry-After": str(error.retry or 1)} if error.status in (429, 503) else None
    return JSONResponse(
        {"error": error.code, **getattr(error, "details", {})},
        status_code=error.status,
        headers=headers,
    )


async def read_body(request, cap):
    """The whole request body, or None when it exceeds `cap` (or arrives too slowly)."""
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


# --- the push send shape (hub_phone builds these; push_send.py queues and delivers them) ---------

MAX_OUTER = 3072
MAX_TTL_S = 86_400
WAIT_MAX_S = 600  # a send waiting longer than min(ttl_s, 600 s) is dropped
WAIT_MIN_S = 5  # ... but ttl_s 0 ("once, then drop" at APNs) still waits this long in our queue


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
    """Token buckets with bounded tables (P3-D35); the caller holds Directory.budget.

    Levels are integers in 1/60,000 of a token, so a refill of `rate` tokens per minute adds
    exactly `rate` units per millisecond and every count is deterministic under an injected clock.
    A missing entry is a full bucket. Each key class (the key's first element: session, person,
    workspace, page-*, staging, host-answer) has its own table of at most `limit` entries, so keys
    of one class never evict another's. Beyond the limit the entry evicted is, among the EVICT_SCAN
    least recently charged, the first that has refilled completely (evicting it loses nothing),
    else the one closest to full: a depleted bucket is never reset by a flood of fresh identities
    while fuller entries remain (security review of round 2)."""

    UNIT = 60_000
    EVICT_SCAN = 64

    def __init__(self, limit=THROTTLE_TABLE):
        self.limit = limit
        self.tables = {}  # class -> OrderedDict key -> (level, ms of the level, burst, rate)

    @property
    def table(self):
        """Every entry (a read-only snapshot, for tests and diagnostics)."""
        return {key: entry for table in self.tables.values() for key, entry in table.items()}

    def clear(self):
        self.tables.clear()

    @staticmethod
    def kind(key):
        return key[0] if isinstance(key, tuple) else None

    def take(self, key, burst, rate, now, charge=True, cost=1, debt=False):
        """Refuse 429 `rate_limited` (Retry-After to when `cost` tokens are back, whole seconds)
        when fewer than `cost` tokens are left; else, with charge, take them. A check
        (charge=False) has no side effects at all. With `debt` it never refuses and the level may
        go below zero: work measured after it was done (a proof page's heads) delays the next."""
        need = cost * self.UNIT
        full = burst * self.UNIT
        table = self.tables.get(self.kind(key), {})
        level, at = table.get(key, (full, now))[:2]
        level = min(full, level + max(0, now - at) * rate)
        if level < need and not debt:
            fail("rate_limited", max(1, math.ceil((need - level) / rate / 1000)))
        if charge:
            table = self.tables.setdefault(self.kind(key), OrderedDict())
            table[key] = (level - need, max(now, at), burst, rate)
            table.move_to_end(key)
            while len(table) > self.limit:
                del table[self.victim(table, now)]

    def victim(self, table, now):
        best, best_fill = None, None
        for n, (key, (level, at, burst, rate)) in enumerate(table.items()):
            if n == self.EVICT_SCAN:
                break
            full = burst * self.UNIT
            fill = min(full, level + max(0, now - at) * rate) / full
            if fill >= 1:
                return key
            if best_fill is None or fill > best_fill:
                best, best_fill = key, fill
        return best


def throttle_table(env):
    """THROTTLE_TABLE with the ORCH_RELAY_THROTTLE_TABLE override (a positive integer)."""
    table = int(env.get("ORCH_RELAY_THROTTLE_TABLE", THROTTLE_TABLE))
    if table <= 0:
        raise ValueError("ORCH_RELAY_THROTTLE_TABLE must be positive")
    return table


class Core:
    """The process lock, the in-memory budgets and the pooled SQLite connections."""

    def __init__(self, path, trusted_proxy=None):
        self.path, self.trusted_proxy = path, trusted_proxy
        self.lock = threading.RLock()
        # In-memory rate windows. Taken alone by pre-checks and inside self.lock by transactions,
        # never the other way round; held only for dict/heap updates.
        self.budget = threading.RLock()
        self.window_expiry = []
        self.windows = {}  # (purpose, identity, duration) -> (window end, count)
        self.table_limit = THROTTLE_TABLE
        self.proxy_warned = False
        self.clock = lambda: time.time_ns() // 1_000_000
        # One write connection and a bounded read pool, owned by no worker thread.
        self.pool = db.Connections(path)

    def connection(self, purpose):
        """The shared write connection, only under self.lock with BEGIN IMMEDIATE."""
        assert purpose == "write" and self.lock._is_owned(), "write connection outside the lock"
        return self.pool.write()

    def reader(self, purpose="read"):
        """Borrow a pooled read connection for one use (context manager). "read" is query-only
        with busy_timeout=0; "query" waits; its snapshot ends when it is returned."""
        return self.pool.borrow(purpose)

    def close(self):
        # Under Core.lock: a cancelled maintenance task leaves its worker thread running, and the
        # sweep holds the lock for its whole run, so this waits for one still in BEGIN IMMEDIATE
        # instead of closing its connection under the running statement (SIGSEGV at shutdown, P3-D36 review F3).
        with self.lock:
            self.pool.close()

    def rate(self, purpose, identity, duration, cap, now, charge=True):
        with self.budget:
            window_rate(self, purpose, identity, duration, cap, now, charge)

    def client_address(self, peer, headers):
        """canonical_address(), warning once (N4) when a proxy forwards but none is trusted."""
        forwarded = headers.get("x-forwarded-for")
        if forwarded and not self.trusted_proxy and not self.proxy_warned:
            self.proxy_warned = True
            logging.getLogger(__name__).warning(
                "X-Forwarded-For received but ORCH_RELAY_TRUSTED_PROXY is unset: behind a reverse "
                "proxy every client shares the proxy's address (address windows); set "
                "it to the proxy's IP address"
            )
        return canonical_address(peer, forwarded, self.trusted_proxy)


def install(app, data):
    core = Core(data / db.DB_NAME, os.environ.get("ORCH_RELAY_TRUSTED_PROXY"))
    core.table_limit = throttle_table(os.environ)
    behind = os.environ.get("ORCH_RELAY_BEHIND_PROXY", "").strip().lower()
    if behind not in ("", "0", "false", "no") and not core.trusted_proxy:
        # N4: behind Caddy without a trusted proxy every client has the proxy's address.
        logging.getLogger(__name__).warning(
            "ORCH_RELAY_BEHIND_PROXY is set but ORCH_RELAY_TRUSTED_PROXY is unset: every client "
            "shares the proxy's address (shared address windows)"
        )
    app.state.core = core
    return core
