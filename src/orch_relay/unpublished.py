"""Retrieval of unpublished revocation evidence (protocol-v2 §19.8, P3-D31).

GET /v2/workspaces/{ws}/unpublished serves a derived view, never a materialized queue: an item exists
for workspace `ws` exactly while the global §19.5 table holds the pair (d, p), d is a G2 ever-device of
`ws` (a current or former list member; restore-only checkpoint_ever_devices never qualify), p is the
person the live registry associates with d (P3-D29 evidence-only persons excluded, as
checkpoints.Relay.association), and `ws`'s chain (checkpoint_revocations) holds (d, p) weaker or not
at all. Another person's pair of the device is never served, whatever its reason. An accepted workspace
restore carrying the pair at equal or greater strength retires the item; nothing else does.

POST .../unpublished/ack only raises a per-workspace high-water mark (unpublished_acks) that drives
the host-poll notice `notices.unpublished`. It is not publication and never hides an item.

The view is read from ever_devices outward (CROSS JOIN fixes SQLite's join order): a page costs
O(|ever_devices(ws)|) primary-key lookups whatever the relay-wide revocation table holds. ref/checkpoints.py
(`unpublished_items`, `unpublished_get`, `unpublished_ack`, `unpublished_notice`) is the executable model.
"""

import hashlib
import threading

from . import proto as P
from .directory import Refusal, fields, integer, window_rate

LIMIT = 64  # items per page (default and maximum)
PAGE_BYTES = 256 * 1024  # of cj(response), the first item always included
ACK_CAP = 1024  # JSON body cap of the ack
MAX_EVER_DEVICES = 4096  # per workspace (members.publish): bounds a page's cost
MINUTE, HOUR = 60_000, 3_600_000
# Per workspace, charged only after W(g) authorization (U12); in memory like Directory.rate.
FETCH_WINDOWS = ((MINUTE, 120), (HOUR, 2000))
ACK_WINDOWS = ((MINUTE, 30),)

COLUMNS = "r.device_id, r.person_id, r.reason, r.cursor, r.record, d.cert, a.pk_pub, c.reason"
VIEW = (
    "FROM ever_devices e CROSS JOIN devices d CROSS JOIN revocations r "
    "JOIN accounts a ON a.person_id = d.person_id "
    "LEFT JOIN checkpoint_revocations c ON c.workspace_id = e.workspace_id "
    "AND c.device_id = r.device_id AND c.person_id = r.person_id "
    "WHERE e.workspace_id = ? AND d.device_id = e.device_id "
    "AND r.device_id = d.device_id AND r.person_id = d.person_id "
    "AND NOT EXISTS (SELECT 1 FROM evidence_persons x WHERE x.person_id = d.person_id) "
    "AND (c.reason IS NULL OR (r.reason = 'compromised' AND c.reason <> 'compromised'))"
)


def refuse(code, status):
    error = Refusal(code)
    error.status = status
    raise error


def token(ws, c):
    """The opaque position b64u(cj({v: 1, ws, c})): bound to the workspace, not to the generation."""
    return P.b64u(P.cj({"v": 1, "ws": ws, "c": c}))


def newest_cursor(con):
    return con.execute("SELECT coalesce(max(cursor), 0) FROM revocations").fetchone()[0]


def position(ws, text):
    """Strict decoding (400 malformed): §2.3 JSON, exactly {v, ws, c}, v 1, this workspace, c a safe
    integer >= 0. Another workspace's position is malformed, never 403/404."""
    try:
        o = P.parse_json(P.unb64u(text))
    except (ValueError, TypeError):
        refuse("malformed", 400)
    fields(o, "v ws c")
    if type(o["v"]) is not int or o["v"] != 1 or o["ws"] != ws:
        refuse("malformed", 400)
    c = o["c"]
    if type(c) is not int or not 0 <= c <= P.MAX_SAFE_INT:
        refuse("malformed", 400)
    return c


def not_ahead(con, c):
    """A position above the relay's newest §19.5 cursor names state that does not exist (a bug, a
    forgery or a rolled-back relay): 409 cursor_ahead; the host restarts from the beginning."""
    if c > newest_cursor(con):
        refuse("cursor_ahead", 409)


def rows(con, ws, after, limit):
    return con.execute(
        f"SELECT {COLUMNS} {VIEW} AND r.cursor > ? ORDER BY r.cursor LIMIT ?", (ws, after, limit)
    )


def item(row):
    device, person, reason, cursor, record, cert, pk, chain = row
    return {
        "device_id": device,
        "person_id": person,
        "reason": reason,
        "revocation": P.parse_json(bytes(record)),
        "device_cert": P.parse_json(bytes(cert)),
        "pk_pub": pk,
        "provenance": {"cursor": cursor, "digest": digest(record)},
        "chain_reason": chain,
    }


def digest(record):
    """The stored record is cj(revocation): the digest of identical evidence never changes."""
    return "sha256:" + hashlib.sha256(bytes(record)).hexdigest()


def view(con, ws):
    """Every item, ascending §19.5 cursor (the publication's hints: checkpoints.Relay.restore)."""
    return [item(r) for r in rows(con, ws, 0, -1)]


def page(con, ws, query):
    """One page after the requested position (0 when absent): at most `limit` items and PAGE_BYTES of
    cj(response) as sent; `cursor` is never null, `more` says items exist after it."""
    limit = integer(query["limit"], LIMIT) if "limit" in query else LIMIT
    if limit < 1:
        refuse("malformed", 400)
    after = position(ws, query["cursor"]) if "cursor" in query else 0
    not_ahead(con, after)
    found = [item(r) for r in rows(con, ws, after, limit + 1)]
    out = []
    for k, candidate in enumerate(found[:limit]):
        framed = {
            "items": out + [candidate],
            "cursor": token(ws, candidate["provenance"]["cursor"]),
            "more": k + 1 < len(found),
        }
        if out and len(P.cj(framed)) > PAGE_BYTES:
            break
        out.append(candidate)
    last = out[-1]["provenance"]["cursor"] if out else after
    return {"items": out, "cursor": token(ws, last), "more": len(out) < len(found)}


def notice(con, ws):
    """notices.unpublished (host poll): the newest item's position while it is above the ack."""
    newest = con.execute(f"SELECT coalesce(max(r.cursor), 0) {VIEW}", (ws,)).fetchone()[0]
    acked = acked_cursor(con, ws)
    return token(ws, newest) if newest > acked else None


def acked_cursor(con, ws):
    row = con.execute("SELECT cursor FROM unpublished_acks WHERE workspace_id=?", (ws,)).fetchone()
    return row[0] if row else 0


def parse_ack(ws, raw):
    body = P.parse_json(raw)
    fields(body, "cursor")
    if not isinstance(body["cursor"], str):
        refuse("malformed", 400)
    return position(ws, body["cursor"])


def ack(con, ws, c, gen, now):
    """Monotonic max(): a lower or equal position is a no-op that returns the stored mark.
    Returns (response, changed)."""
    not_ahead(con, c)
    stored = acked_cursor(con, ws)
    if c > stored:
        con.execute(
            "INSERT INTO unpublished_acks VALUES (?,?,?,?) ON CONFLICT(workspace_id) DO UPDATE SET "
            "cursor=excluded.cursor, gen=excluded.gen, at_ms=excluded.at_ms",
            (ws, c, gen, now),
        )
    return {"acked": token(ws, max(stored, c))}, c > stored


class Budget:
    """Per-workspace rate windows under their own small mutex, never directory.lock, so a read never
    queues behind writes (U12). Same windows as Directory.rate (window_rate); reset on restart (accepted)."""

    def __init__(self):
        self.lock = threading.Lock()
        self.windows = {}
        self.window_expiry = []

    def charge(self, purpose, ws, windows, now):
        with self.lock:
            for charge in (False, True):
                for duration, cap in windows:
                    window_rate(self, purpose, ws, duration, cap, now, charge)
