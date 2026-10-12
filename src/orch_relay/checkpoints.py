"""Signed checkpoints, genesis pins, staging and restore transitions (protocol-v2 §19.8).

P3-D12/D13/D18-D25 on SQLite. ref/checkpoints.py is the executable model; the production
relay replays the same vectors (tests/test_checkpoint_vectors.py). Every request is authorized
read-only before it takes the directory lock or a write transaction (G3 review 3); reads never
take the lock at all. A refused write leaves the database unchanged; only a charged refusal of a
final publication records its failure row (protocol-v2 §19.8 failure budget).

A final publication runs in three phases (P3-D33, the G1 pre-public-deploy gate): phase A folds and
checks it on a WAL read snapshot without Directory.lock, phase B inserts its new log_nodes in short
chunks (each its own short transaction under the lock), and phase C re-runs the publication under
the lock against live state, reusing phase A's folds, and commits it. Lock order: the per-workspace
publication mutex, then the global publication semaphore (both awaited on the event loop), then
Directory.lock, then Directory.budget; a pooled read connection is never held while taking the lock.
"""

import asyncio
import collections
import hashlib
import logging
import os
import re
import sqlite3
import weakref
from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from . import proto as P
from . import unpublished as U
from .bridge import refuse
from .directory import Refusal, integer

log = logging.getLogger(__name__)

ZERO = "sha256:" + "0" * 64
EMPTY = {"seq": 0, "head": None, "acc": ZERO}
HOUR = 3_600_000
DAY = 24 * HOUR
CP_CAP = 2 * 1024 * 1024
LINE_CAP = 524_288
REQUEST_CAP = CP_CAP + LINE_CAP + 65536
PAGE_CAP = 4 * 1024 * 1024
STAGE_CAP = 64 * 1024 * 1024
GLOBAL_STAGE_CAP = 4 * 1024 * 1024 * 1024  # deployment-wide staged bytes (503 overloaded)
# P3-D34 (the G3 and G4 pre-public-deploy gates), each overridable from the environment (Caps):
# staged bytes per owner person across its workspaces (ORCH_RELAY_ACCOUNT_STAGE_BYTES; 512 MiB is
# eight full workspace quotas, so at least eight accounts are needed to fill the global ceiling),
ACCOUNT_STAGE_CAP = GLOBAL_STAGE_CAP // 8
# stored log_nodes per workspace, orphans included (ORCH_RELAY_WORKSPACE_NODES; ~1.2 GB at 293 B
# per node, about 4.4 full 64 MiB staging sets),
WORKSPACE_NODES = 4_000_000
# and distinct self-certified revocation pairs an owner person's restores may add to the global
# table (ORCH_RELAY_ACCOUNT_EVIDENCE). All three answer 429 quota_exceeded.
ACCOUNT_EVIDENCE = 50_000
# Retention bounds per workspace (newest kept): exact-retry receipts and 410 tombstones (P3-D34).
RECEIPTS_KEPT = 256
GONE_KEPT = 4096
STAGE_SETS = 2
BASELINES = 16
FAILURE_BUDGET = 16  # charged refusals per holder generation per rolling hour
WORKSPACE_FAILURE_CEILING = 48  # charged refusals per workspace per rolling hour
# P3-D33 (G1): budget by work. Heads folded by charged refusals per workspace per rolling hour:
# about two full 64 MiB staging sets (a head is 74 bytes on the wire).
REFUSED_HEADS = 2 * (STAGE_CAP // 74)
NODE_CHUNK = 20_000  # log_nodes rows per phase B transaction (one short hold of the lock each)
# Publications in phases A to C at once, across all workspaces (ORCH_RELAY_PUBLISH_WIDTH), and the
# staged heads they may reserve together (ORCH_RELAY_PUBLISH_HEADS; phase A needs roughly 1.3 KB
# per new node, so 1.5 million heads is about 2 GB). A larger publication runs alone.
PUBLISH_WIDTH = 2
PUBLISH_HEADS = 1_500_000
# P3-D33 round 2 (review F1): phase C may fold or parse at most this many heads live under the
# lock (work phase A did not record); beyond it, it restarts from phase A, at most
# PUBLISH_ROUNDS - 1 times, then answers 503 overloaded (retryable, uncharged).
LIVE_FOLD_LIMIT = 5_000
PUBLISH_ROUNDS = 3
A_SNAPSHOT_HEADS = 20_000  # phase A re-opens its read snapshot after folding this many (F3)
PROOF_LIMIT = 65536
TRANSITION_LIMIT = 16
# A head is 73 JSON bytes plus its comma; keep framing headroom inside the 4 MiB response.
PROOF_PAGE_HEADS = (PAGE_CAP - 128) // 74
STRENGTH = {"lost": 1, "retired": 1, "compromised": 2}
HASH = re.compile(r"sha256:[0-9a-f]{64}")
ULID = re.compile(r"[0-7][0-9A-HJKMNP-TV-Z]{25}")
TICKET_LOG = re.compile(r"[0-9A-HJKMNP-TV-Z]{26}")
LABEL = {
    "sig_checkpoint": b"orch/v2/sig/checkpoint|",
    "sig_genesis_pin": b"orch/v2/sig/genesis-pin|",
    "sig_ws_event": b"orch/v2/sig/ws-event|",
    "sig_ticket_event": b"orch/v2/sig/ticket-event|",
    "sig_host_event": b"orch/v2/sig/host-event|",
    "h_event": b"orch/v2/event|",
    "h_checkpoint": b"orch/v2/checkpoint-hash|",
    "h_log_acc": b"orch/v2/log-acc|",
}
RESTORE_FIELDS = {
    "v",
    "id",
    "seq",
    "at",
    "type",
    "actor",
    "based_on",
    "prev",
    "hash_v",
    "host_sig",
    "sig",
    "auth",
    "roster_v",
    "from_seq",
    "head",
    "abandoned",
    "abandoned_decisions",
    "reason",
    "source",
    "revocations",
}
AUTH_KINDS = ("passphrase", "secure-enclave", "secure-enclave-unlocked", "webauthn", "tpm")
AUTH_KINDS += ("windows-hello",)
CHECKPOINT_FIELDS = {"v", "suite", "kind", "workspace_id", "genesis", "n", "at"}
CHECKPOINT_FIELDS |= {"workspace_log", "tickets"}


def no(code, status=409, **details):
    refuse(code, status, 1 if status in (429, 503) else None, **details)


def record_failure(con, ws, gen, now, heads=0):
    """Charge one refusal, unless the window is already full (review L1): rows never grow with
    the request rate, and a full window refuses with 429 before any work either way. `heads` is
    the fold work the refused publication did (P3-D33 budget by work); a refusal before the
    staged set was folded did none."""
    con.execute(
        "DELETE FROM checkpoint_failures WHERE workspace_id=? AND at_ms<=?", (ws, now - HOUR)
    )
    con.execute(
        "DELETE FROM checkpoint_refused_heads WHERE workspace_id=? AND at_ms<=?", (ws, now - HOUR)
    )
    if heads:
        con.execute("INSERT INTO checkpoint_refused_heads VALUES (?,?,?)", (ws, now, heads))
    total, mine = con.execute(
        "SELECT count(*), coalesce(sum(gen=?),0) FROM checkpoint_failures WHERE workspace_id=?",
        (gen, ws),
    ).fetchone()
    if mine < FAILURE_BUDGET and total < WORKSPACE_FAILURE_CEILING:
        con.execute("INSERT INTO checkpoint_failures VALUES (?,?,?)", (ws, gen, now))


def refusal(code, status=409):
    error = Refusal(code)
    error.status = status
    return error


def count_nodes(con, ws, nodes, orphaned=0):
    """checkpoint_node_usage: stored log_nodes per workspace, and those orphaned (P3-D33)."""
    con.execute(
        "INSERT INTO checkpoint_node_usage VALUES (?,?,?) ON CONFLICT(workspace_id) DO UPDATE "
        "SET nodes=nodes+excluded.nodes, orphaned=orphaned+excluded.orphaned",
        (ws, nodes, orphaned),
    )


class Caps:
    """The P3-D34 deployment caps; Checkpoints reads them from the environment once."""

    def __init__(self, env=None):
        env = env if env is not None else {}
        self.account_stage = int(env.get("ORCH_RELAY_ACCOUNT_STAGE_BYTES", ACCOUNT_STAGE_CAP))
        self.nodes = int(env.get("ORCH_RELAY_WORKSPACE_NODES", WORKSPACE_NODES))
        self.evidence = int(env.get("ORCH_RELAY_ACCOUNT_EVIDENCE", ACCOUNT_EVIDENCE))


def evict_oldest(con, table, ws, kept):
    """Keep the newest `kept` rows of one workspace in `table` (rowid is insertion order: the
    newest row is never deleted, so SQLite never reuses a rowid here)."""
    con.execute(
        f"DELETE FROM {table} WHERE workspace_id=?1 AND rowid<=(SELECT rowid FROM {table} "
        "WHERE workspace_id=?1 ORDER BY rowid DESC LIMIT 1 OFFSET ?2)",
        (ws, kept),
    )


def need(ok, code="malformed", status=400, **details):
    if not ok:
        no(code, status, **details)


# --- encodings (F1 §5.3/5.6/5.10 at orch-core 4f00d9ce, P3-D19) -------------------------------------


def hash_bytes(value):
    need(isinstance(value, str) and HASH.fullmatch(value))
    return bytes.fromhex(value[7:])


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def checkpoint_hash(cp):
    return digest(LABEL["h_checkpoint"] + P.cj(cp["o"]))


def log_acc(acc, head):
    return digest(LABEL["h_log_acc"] + hash_bytes(acc) + hash_bytes(head))


def event_head(line):
    return digest(LABEL["h_event"] + P.cj(line))


def event_bytes(line, ws, log, host=False):
    omit = {"host_sig"} if host else {"seq", "at", "prev", "ws_seq", "sig", "host_sig"}
    label = (
        "sig_host_event" if host else "sig_ws_event" if log == "workspace" else "sig_ticket_event"
    )
    event = {k: v for k, v in line.items() if k not in omit}
    return LABEL[label] + P.cj(
        {"contract": 1, "suite": 2, "workspace_id": ws, "log": log, "event": event}
    )


def timestamp(at):
    need(isinstance(at, str) and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", at))
    try:
        return int(datetime.fromisoformat(at).timestamp() * 1000)
    except ValueError:
        no("malformed", 400)


def count(n, minimum=0):
    need(type(n) is int and minimum <= n <= P.MAX_SAFE_INT)


def verify_signed(signed, pub, kind, label):
    try:
        if not isinstance(signed, dict) or set(signed) != {"o", "sig"}:
            return None
        o = signed["o"]
        if (
            not isinstance(o, dict)
            or o.get("v") != 2
            or o.get("suite") != 2
            or o.get("kind") != kind
        ):
            return None
        if P.SUITE.verify(pub, P.unb64u(signed["sig"], 64), LABEL[label] + P.cj(o)):
            return o
    except (ValueError, TypeError):
        pass
    return None


def entries(cp):
    return {"workspace": cp["o"]["workspace_log"], **cp["o"]["tickets"]}


def reference(cp):
    return {"n": cp["o"]["n"], "hash": checkpoint_hash(cp)} if cp else None


def page_digest(page):
    # Transport convention (§19.8 detail 1), not an F1 hash domain.
    return digest(P.cj({k: v for k, v in page.items() if k != "digest"}))


def descriptor(i, page):
    out = {k: page[k] for k in ("kind", "log", "after_seq", "digest")}
    return out | {"i": i, "count": len(page["heads"])}


def stage_key(source, target):
    if source is not None:
        hash_bytes(source)
    hash_bytes(target)
    return ("null" if source is None else source, target)


# --- the node index (P3-D19; G4 precondition (a)) --------------------------------------------------


def skip_height(height):
    """Deterministic skip-list height (as Bitcoin's CBlockIndex::pskip): ancestors in O(log N)."""
    if height < 2:
        return 0
    if height & 1:
        h = height - 1
        h &= h - 1
        return (h & (h - 1)) + 1
    return height & (height - 1)


def raw(h):
    """log_nodes stores hashes as their 32 raw bytes (a third of the text row size)."""
    return bytes.fromhex(h[7:])


def text(b):
    return "sha256:" + b.hex()


class Nodes:
    """log_nodes of one workspace log, with a per-request cache of the nodes it touched. With a
    `sink` (phase A, P3-D33) new nodes are collected there instead of inserted; the cache serves
    them to the rest of the publication."""

    def __init__(self, con, ws, log, sink=None):
        self.con, self.ws, self.log, self.cache, self.sink = con, ws, log, {}, sink
        self.added = 0  # new nodes this object inserted or handed to the sink (P3-D34 quota)

    def get(self, acc):
        if acc == ZERO:
            return {**EMPTY, "prev_acc": None, "skip_acc": None}
        if acc in self.cache:
            return self.cache[acc]
        row = self.con.execute(
            "SELECT seq,head,prev_acc,skip_acc FROM log_nodes WHERE workspace_id=? AND log=? AND acc=?",
            (self.ws, self.log, raw(acc)),
        ).fetchone()
        if row is None:
            return None
        found = {"seq": row[0], "head": text(row[1]), "acc": acc}
        found |= {"prev_acc": text(row[2]), "skip_acc": text(row[3])}
        self.cache[acc] = found
        return found

    def ancestor(self, start, height):
        """The node at `height` on start's branch, or None (absent node or height above start)."""
        walk = start
        while walk is not None and walk["seq"] > height >= 0:
            here = walk["seq"]
            hs, hsp = skip_height(here), skip_height(here - 1)
            if hs == height or (hs > height and not (hsp < hs - 2 and hsp >= height)):
                walk = self.get(walk["skip_acc"])
            else:
                walk = self.get(walk["prev_acc"])
        return walk if walk is not None and walk["seq"] == height else None

    def at_seq(self, endpoint, seq):
        start = self.get(endpoint["acc"])
        found = self.ancestor(start, seq) if start is not None else None
        need(found is not None, "restore_invalid", 409)
        return {k: found[k] for k in ("seq", "head", "acc")}

    def extend(self, old, heads):
        """Insert every verified head (never cut back); the result entry, or chain_diverged.

        Folds in memory, checks which nodes exist in batches and inserts the rest with one
        executemany (or hands them to the sink, in fold order: a node's prev and skip ancestors
        always precede it)."""
        previous = self.get(old["acc"])
        need(previous is not None and previous["seq"] == old["seq"], "chain_diverged", 409)
        accs, acc = [], old["acc"]
        for head in heads:
            acc = log_acc(acc, head)
            accs.append(acc)
        stored = {}
        for k in range(0, len(accs), 500):
            batch = accs[k : k + 500]
            for row in self.con.execute(
                "SELECT acc,seq,head,prev_acc,skip_acc FROM log_nodes WHERE workspace_id=? AND log=? "
                f"AND acc IN ({','.join('?' * len(batch))})",
                (self.ws, self.log, *map(raw, batch)),
            ):
                found = {"acc": text(row[0]), "seq": row[1], "head": text(row[2])}
                found |= {"prev_acc": text(row[3]), "skip_acc": text(row[4])}
                stored[found["acc"]] = found
        rows, prev_acc, seq = [], old["acc"], old["seq"]
        for head, acc in zip(heads, accs):
            seq += 1
            found = self.cache.get(acc) or stored.get(acc)
            if found is not None:
                need(
                    (found["seq"], found["head"], found["prev_acc"]) == (seq, head, prev_acc),
                    "chain_diverged",
                    409,
                )
            else:
                skip = self.ancestor(previous, skip_height(seq))
                need(skip is not None, "chain_diverged", 409)
                found = {"seq": seq, "head": head, "acc": acc, "prev_acc": prev_acc}
                found["skip_acc"] = skip["acc"]
                rows.append(
                    (self.ws, self.log, raw(acc), seq, raw(head), raw(prev_acc), raw(skip["acc"]))
                )
            self.cache[acc] = found
            previous, prev_acc = found, acc
        self.added += len(rows)
        if self.sink is not None:
            self.sink.extend(rows)
        elif rows:
            self.con.executemany("INSERT INTO log_nodes VALUES (?,?,?,?,?,?,?)", rows)
            count_nodes(self.con, self.ws, len(rows))
        return (
            {"seq": seq, "head": heads[-1], "acc": prev_acc}
            if heads
            else {k: old[k] for k in ("seq", "head", "acc")}
        )

    def page(self, start_acc, endpoint_acc, limit):
        """Heads after start_acc on the endpoint's branch: O(limit + log N), never O(history)."""
        start, end = self.get(start_acc), self.get(endpoint_acc)
        need(start is not None and end is not None, "not_found", 404)
        on_branch = self.ancestor(end, start["seq"])
        need(on_branch is not None and on_branch["acc"] == start_acc, "not_found", 404)
        total = end["seq"] - start["seq"]
        size = min(limit, total, PROOF_PAGE_HEADS)
        if size == 0:
            return [], None
        last = self.ancestor(end, start["seq"] + size)
        need(last is not None, "not_found", 404)
        rows = self.con.execute(
            """WITH RECURSIVE w(acc, prev, head, seq, k) AS (
                SELECT acc, prev_acc, head, seq, 1 FROM log_nodes
                WHERE workspace_id=?1 AND log=?2 AND acc=?3
                UNION ALL
                SELECT n.acc, n.prev_acc, n.head, n.seq, w.k + 1 FROM w JOIN log_nodes n
                ON n.workspace_id=?1 AND n.log=?2 AND n.acc=w.prev WHERE w.k < ?4)
            SELECT head, seq, prev FROM w""",
            (self.ws, self.log, raw(last["acc"]), size),
        ).fetchall()
        need(
            len(rows) == size
            and all(r[1] == last["seq"] - k for k, r in enumerate(rows))
            and rows[-1][2] == raw(start_acc),
            "not_found",
            404,
        )
        return [text(r[0]) for r in reversed(rows)], last["acc"] if size < total else None


# --- stateless prechecks, run before the directory lock (review G2) ----------------------------------


def caught(check, *args):
    """A check's refusal (or the reference's generic malformed), returned instead of raised."""
    try:
        check(*args)
    except Refusal as exc:
        return exc
    except (KeyError, TypeError, ValueError, AttributeError, IndexError):
        return refusal("malformed", 400)
    return None


def precheck_publication(body, wsk_pub, stages=True):
    """Parse, size, shape, receipt digest, signature and entry shapes of a final publication.

    Nothing here reads mutable state (the card's WSK is fixed), so it runs before the lock; the
    refusals are raised inside the transaction at their reference position, after the exact
    retry and the budget check, and are charged there."""
    pre = {"wsk_pub": wsk_pub, "early": None, "stage1": None, "stage2": None}

    def parse():
        nonlocal body
        if isinstance(body, (bytes, bytearray)):
            body = P.parse_json(bytes(body))
        need(len(P.cj(body)) <= REQUEST_CAP, "too_large", 400)
        need(
            isinstance(body, dict)
            and set(body)
            in ({"checkpoint", "source_hash"}, {"checkpoint", "source_hash", "restore"})
        )

    pre["early"] = caught(parse)
    if pre["early"]:
        return pre
    pre["body"], pre["receipt"] = body, digest(P.cj(body))
    if not stages:
        pre["lazy"] = True  # an exact retry needs no validation (review N4)
        return pre
    cp = body["checkpoint"]

    def stage1():
        need(len(P.cj(cp)) <= CP_CAP, "too_large", 400)
        o = cp["o"]
        need(o.get("suite") == 2, "wrong_suite", 400)
        need(set(o) == CHECKPOINT_FIELDS)
        need(o["kind"] == "workspace_checkpoint" and o["v"] == 2)
        good = verify_signed(cp, P.unb64u(wsk_pub), "workspace_checkpoint", "sig_checkpoint")
        need(good is not None, "bad_signature", 401)

    def stage2():
        o = cp["o"]
        count(o["n"], 1)
        timestamp(o["at"])
        need(isinstance(o["tickets"], dict))
        for uid in o["tickets"]:
            need(ULID.fullmatch(uid))
        for entry in entries(cp).values():
            need(isinstance(entry, dict) and set(entry) == {"seq", "head", "acc"})
            count(entry["seq"], 1)
            hash_bytes(entry["head"])
            hash_bytes(entry["acc"])

    pre["stage1"] = caught(stage1)
    pre["stage2"] = None if pre["stage1"] else caught(stage2)
    if not (pre["stage1"] or pre["stage2"]):
        pre["hash"] = checkpoint_hash(cp)
    return pre


def precheck_page(body, wire):
    def check():
        need(len(wire) <= PAGE_CAP, "too_large", 413)
        need(isinstance(body, dict))
        need(set(body) == {"kind", "log", "after_seq", "from_acc", "heads", "digest"})
        need(body["kind"] in ("appended", "abandoned", "retained"))
        need(
            body["log"] == "workspace"
            or (isinstance(body["log"], str) and TICKET_LOG.fullmatch(body["log"]))
        )
        count(body["after_seq"])
        hash_bytes(body["from_acc"])
        need(isinstance(body["heads"], list) and bool(body["heads"]))
        for h in body["heads"]:
            hash_bytes(h)
        need(body["digest"] == page_digest(body))

    return {"refusal": caught(check)}


def precheck_manifest(body, wire):
    """{shape: refusal of the whole body, at: index of the first bad descriptor (or None),
    refusal: that descriptor's refusal, or the order refusal after the loop}."""
    pre = {"shape": None, "at": None, "refusal": None}

    def shape():
        need(isinstance(body, dict) and set(body) == {"pages"} and isinstance(body["pages"], list))
        need(len(wire) <= PAGE_CAP, "too_large", 413)

    pre["shape"] = caught(shape)
    if pre["shape"]:
        return pre
    previous, seen, order = {}, set(), []

    def descriptor_ok(d):
        need(isinstance(d, dict) and set(d) == {"i", "kind", "log", "after_seq", "count", "digest"})
        count(d["i"])
        count(d["after_seq"])
        count(d["count"], 1)
        hash_bytes(d["digest"])
        need(d["kind"] in ("appended", "abandoned", "retained"))
        need(d["i"] not in seen)
        seen.add(d["i"])
        group = (d["kind"], d["log"])
        need(group not in previous or previous[group] == d["after_seq"])
        previous[group] = d["after_seq"] + d["count"]
        order.append((*group, d["after_seq"]))

    for at, d in enumerate(body["pages"]):
        pre["refusal"] = caught(descriptor_ok, d)
        if pre["refusal"]:
            pre["at"] = at
            return pre
    pre["refusal"] = caught(need, order == sorted(order))
    return pre


# --- relay state -----------------------------------------------------------------------------------


class Restart(Exception):
    """Phase C needs work phase A did not do: roll back, release the lock, rerun phase A."""


class Reweigh(Exception):
    """Phase A found more staged heads than the publication reserved in the gate."""

    def __init__(self, heads):
        super().__init__(heads)
        self.heads = heads


def again(exc):
    """A fresh copy of a recorded refusal (same code, status, Retry-After and details)."""
    error = Refusal(exc[0], exc[2])
    error.status = exc[1]
    if exc[3] is not None:
        error.details = dict(exc[3])
    return error


class Memo:
    """What phase A of a publication hands to phases B and C (P3-D33).

    Every fold is recorded under what determines it: (log, key, start seq, start acc), where `key`
    is the page's manifest digest (which binds the page's bytes, P3-D20) or the restore line's
    head. A stored node is a function of its acc alone (nodes are immutable, hash-addressed and
    branch-agnostic, and a stored start's branch is stored), so a recorded fold is the result a
    live fold would give whenever phase C asks for the same key from the same start; phase C
    re-checks the start node live. Everything else phase C re-reads live."""

    def __init__(self):
        self.folds = {}  # (log, key, start seq, start acc) -> result entry, or refusal tuple
        self.fresh = {}  # the same key -> new nodes that fold produced (the P3-D34 node quota)
        self.pages = {}  # manifest digest -> {"after_seq", "from_acc"}
        self.manifest = None  # (manifest bytes, parsed manifest, descriptor groups)
        self.rows = []  # new log_nodes rows in fold order (phase B)
        self.overlay = {}  # log -> phase A's node cache (phase C reads it when phase B did not run)
        # Heads folded by this publication's phase A rounds so far, and live in phase C rounds
        # that restarted (recorded on any refusal: budget by work, review F2).
        self.heads = self.live = 0
        self.accepted = False  # phase A reached the commit point: phase B inserts every new node
        self.unsafe = False  # a staged page disagrees with its descriptor: restart
        self.committed = False  # phase C committed the publication
        self.charged = False  # phase C's charged refusal recorded the heads itself
        self.reserved = None  # heads reserved in the gate (phase A reweighs beyond it)
        self.carried = 0  # heads folded by earlier rounds of this request (budget check, N2)
        self.refresh = None  # phase A: end the read snapshot and start a new one (review F3)
        self.inserted = self.hits = 0


class Relay:
    """One workspace's checkpoint state inside a caller-owned transaction.

    With a memo and `dry` (phase A, P3-D33), on a read snapshot: folds are recorded, new nodes
    collected and nothing is written. With a memo and not `dry` (phase C), under the lock: the
    recorded folds replace the work they did, and everything else runs live."""

    def __init__(self, directory, con, ws, now, memo=None, dry=False, caps=None):
        self.d, self.con, self.ws, self.now = directory, con, ws, now
        self.memo, self.dry = memo, dry
        self.caps = caps if caps is not None else Caps()
        self.reused = 0  # phase C: new nodes of recorded folds that phase B did not store
        self.nodes = {}
        self.wake = set()
        self.visits = 0  # staged descriptors folded by this publication (work bound, review R1)
        self.folded = 0  # heads this Relay folded itself
        self.work = 0  # phase C: heads folded or parsed live (bounded by LIVE_FOLD_LIMIT)
        self.since = 0  # phase A: heads folded since the read snapshot began
        self.committed = False
        self.unpublished = []

    def log(self, name):
        if name not in self.nodes:
            nodes = Nodes(self.con, self.ws, name, self.memo.rows if self.dry else None)
            if self.memo is not None and not self.dry and name in self.memo.overlay:
                nodes.cache = self.memo.overlay[name]
            self.nodes[name] = nodes
        return self.nodes[name]

    def live(self, count):
        """Phase C's live work under the lock is bounded (review F1): beyond LIVE_FOLD_LIMIT
        heads, restart from phase A, which does the work outside the lock."""
        if self.memo is not None and not self.dry:
            self.work += count
            if self.work > LIVE_FOLD_LIMIT:
                raise Restart

    def fold(self, log, key, start, heads, count=1):
        """Nodes.extend(start, heads()) for one staged page or the restore line (P3-D33): phase A
        records the result or the refusal, phase C reuses it, so no head is folded under the
        lock. A fold phase A never reached, or whose start node phase C cannot see, is done live,
        within the live bound (`count` heads)."""
        nodes, memo = self.log(log), self.memo
        slot = (log, key, start["seq"], start["acc"])
        if memo is not None and not self.dry and slot in memo.folds:
            previous = nodes.get(start["acc"])
            if previous is not None and previous["seq"] == start["seq"]:
                memo.hits += 1
                done = memo.folds[slot]
                if isinstance(done, tuple):
                    raise again(done)
                if not memo.accepted:  # phase B did not run: these nodes are not stored
                    self.reused += memo.fresh.get(slot, 0)
                return dict(done)
        self.live(count)
        batch = heads()
        self.folded += len(batch)
        added = nodes.added
        try:
            result = nodes.extend(start, batch)
        except Refusal as exc:
            if self.dry:
                details = getattr(exc, "details", None)
                memo.folds[slot] = (exc.code, exc.status, exc.retry, details)
            raise
        if self.dry:
            memo.folds[slot] = dict(result)
            memo.fresh[slot] = nodes.added - added
            self.since += len(batch)
            if self.since >= A_SNAPSHOT_HEADS and memo.refresh is not None:
                # Folds read only immutable nodes from here on (every mutable input and the
                # staged pages were read already), so a newer snapshot is as good (review F3).
                self.since = 0
                memo.refresh()
        return result

    def workspace(self):
        row = self.con.execute(
            "SELECT w.wsk_pub,w.delegation,w.owner_person_id,a.pk_pub FROM workspaces w "
            "LEFT JOIN accounts a ON a.person_id=w.owner_person_id WHERE w.workspace_id=?",
            (self.ws,),
        ).fetchone()
        need(row is not None and row[3] is not None, "not_found", 404)
        return {
            "wsk_pub": row[0],
            "delegation": P.parse_json(row[1]),
            "owner": row[2],
            "owner_pk": row[3],
        }

    def genesis(self):
        row = self.con.execute(
            "SELECT body FROM checkpoint_genesis WHERE workspace_id=?", (self.ws,)
        ).fetchone()
        return P.parse_json(row[0]) if row else None

    def held(self):
        row = self.con.execute(
            "SELECT c.body FROM checkpoint_heads h JOIN checkpoints c "
            "ON c.workspace_id=h.workspace_id AND c.hash=h.hash WHERE h.workspace_id=?",
            (self.ws,),
        ).fetchone()
        return P.parse_json(row[0]) if row else None

    # Retention (P3-D13/D19/D20): evaluated at read time, so reads never write.
    def pinned(self, h):
        return self.con.execute(
            "SELECT 1 FROM checkpoint_baselines WHERE workspace_id=? AND hash=? AND until_ms>?",
            (self.ws, h, self.now),
        ).fetchone()

    def checkpoint(self, h):
        hash_bytes(h)
        need(
            not self.con.execute(
                "SELECT 1 FROM checkpoint_gone WHERE workspace_id=? AND hash=?", (self.ws, h)
            ).fetchone(),
            "checkpoint_gone",
            410,
        )
        row = self.con.execute(
            "SELECT body,superseded_ms,permanent FROM checkpoints WHERE workspace_id=? AND hash=?",
            (self.ws, h),
        ).fetchone()
        need(row is not None, "not_found", 404)
        expired = (
            not row[2] and row[1] is not None and self.now >= row[1] + DAY and not self.pinned(h)
        )
        need(not expired, "checkpoint_gone", 410)
        return P.parse_json(row[0])

    def purge(self):
        """Physically drop what retention already hides (writes and the maintenance sweep only)."""
        con, ws, now = self.con, self.ws, self.now
        con.execute(
            "DELETE FROM checkpoint_baselines WHERE workspace_id=? AND until_ms<=?", (ws, now)
        )
        con.execute(
            "DELETE FROM checkpoint_staging WHERE workspace_id=? AND expires_ms<=?", (ws, now)
        )
        gone = [
            r[0]
            for r in con.execute(
                "SELECT hash FROM checkpoints c WHERE workspace_id=? AND permanent=0 "
                "AND superseded_ms IS NOT NULL AND superseded_ms+?<=? AND NOT EXISTS ("
                "SELECT 1 FROM checkpoint_baselines b WHERE b.workspace_id=c.workspace_id "
                "AND b.hash=c.hash AND b.until_ms>?)",
                (ws, DAY, now, now),
            )
        ]
        for h in gone:
            con.execute("DELETE FROM checkpoints WHERE workspace_id=? AND hash=?", (ws, h))
            con.execute("INSERT OR IGNORE INTO checkpoint_gone VALUES (?,?)", (ws, h))
        if gone:  # P3-D34: an evicted tombstone answers 404 instead of 410, a refusal either way
            evict_oldest(con, "checkpoint_gone", ws, GONE_KEPT)

    # --- genesis (P3-D18) --------------------------------------------------------------------------

    def put_genesis(self, body):
        need(isinstance(body, dict) and set(body) == {"pin", "cert"})
        pin, stored = body["pin"], self.genesis()
        if stored:
            need(pin == stored["pin"], "genesis_mismatch", 409)
            return {}
        w = self.workspace()
        cert = self.owner(w, body["cert"], self.now)
        o = verify_signed(pin, P.unb64u(cert["dk_sig_pub"]), "genesis_pin", "sig_genesis_pin")
        need(o is not None, "bad_signature", 401)
        need(set(o) == {"v", "suite", "kind", "workspace_id", "wsk_pub", "genesis"})
        hash_bytes(o["genesis"])
        need(o["workspace_id"] == self.ws and o["wsk_pub"] == w["wsk_pub"], "genesis_mismatch", 409)
        self.con.execute("INSERT INTO checkpoint_genesis VALUES (?,?)", (self.ws, P.cj(body)))
        return {}

    # --- owner-device policy (P3-D23/D24, relay side) ------------------------------------------------

    def revoked(self, device, person):
        """A held revocation of the restore signer's (device, person) pair (orch-core #397): another
        person's revocation of the device id is another pair and never refuses the signer. (The
        device-auth cutoff is per pair too, under the registry person: directory, P3-D30.)"""
        return self.con.execute(
            "SELECT 1 FROM revocations WHERE device_id=? AND person_id=?", (device, person)
        ).fetchone()

    def owner(self, w, cert, at_ms, extra=()):
        # Every revocation the relay holds of the signer's pair, and any entry in this payload for
        # the signer's device id (self-revocation, any person), refuses the signer. A malformed
        # certificate fails verify_cert below; a database error propagates (fail closed, review
        # L2): the relay's revocation lookup is never skipped.
        try:
            device, person = cert["o"]["device_id"], cert["o"]["person_id"]
        except (TypeError, KeyError):
            device = person = None
        revoked = set()
        if isinstance(device, str) and (
            device in extra or (isinstance(person, str) and self.revoked(device, person))
        ):
            revoked = {device}
        checked = P.verify_cert(cert, P.unb64u(w["owner_pk"]), at_ms, revoked)
        need("ok" in checked, "restore_not_owner", 409)
        c = checked["ok"]
        need(
            c["person_id"] == w["owner"]
            and "operate" in c["scopes_max"]
            and not any(x.startswith("drop:") for x in c["scopes_max"]),
            "restore_not_owner",
            409,
        )
        return c

    def owner_policy(self, w, bundle, extra=()):
        line = bundle["line"]
        cert = self.owner(w, bundle["cert"], timestamp(line["at"]), extra)
        self.owner(w, bundle["cert"], self.now, extra)
        member = self.con.execute(
            "SELECT scopes FROM members WHERE workspace_id=? AND device_id=?",
            (self.ws, cert["device_id"]),
        ).fetchone()
        need(member is not None and "operate" in P.parse_json(member[0]), "restore_not_owner", 409)
        authz = bundle["authz"]
        need(isinstance(authz, dict) and set(authz) == {"delegation"}, "restore_not_owner", 409)
        delegation = authz["delegation"]
        need(
            isinstance(delegation, dict)
            and delegation.get("o") == w["delegation"]["o"]
            and "ok" in P.verify_delegation(delegation, P.unb64u(w["owner_pk"])),
            "restore_not_owner",
            409,
        )
        need(
            line["actor"]["id"] == "p_" + cert["person_id"]
            and line["actor"]["device"] == "d_" + cert["device_id"],
            "restore_not_owner",
            409,
        )
        return cert

    # --- staging (P3-D20) ----------------------------------------------------------------------------

    def staged_bytes(self):
        return self.con.execute(
            "SELECT coalesce(sum(bytes),0) FROM checkpoint_staging WHERE workspace_id=? AND expires_ms>?",
            (self.ws, self.now),
        ).fetchone()[0]

    def charge_stage(self, key, size, global_cap):
        need(self.staged_bytes() + size <= STAGE_CAP, "quota_exceeded", 429)
        # P3-D34 (G3): the owner person's live staged bytes across all of its workspaces, in this
        # write transaction (exact under concurrency, like the ceiling below); expired, deleted
        # and committed sets no longer count. Before the shared ceiling: the account's own cap.
        account = self.con.execute(
            "SELECT coalesce(sum(bytes),0) FROM checkpoint_staging WHERE expires_ms>?1 AND "
            "workspace_id IN (SELECT workspace_id FROM workspaces WHERE owner_person_id=("
            "SELECT owner_person_id FROM workspaces WHERE workspace_id=?2) UNION SELECT ?2)",
            (self.now, self.ws),
        ).fetchone()[0]
        need(account + size <= self.caps.account_stage, "quota_exceeded", 429)
        # The deployment ceiling across workspaces: a refusal, never an eviction (§19.8, P3-D17).
        total = self.con.execute(
            "SELECT coalesce(sum(bytes),0) FROM checkpoint_staging WHERE expires_ms>?", (self.now,)
        ).fetchone()[0]
        need(total + size <= global_cap, "overloaded", 503)
        self.con.execute(
            "UPDATE checkpoint_staging SET bytes=bytes+? WHERE workspace_id=? AND source=? AND target=?",
            (size, self.ws, *key),
        )

    def stage(self, key):
        """The set's metadata only: page PUTs never re-read the set (no O(n^2) staging)."""
        row = self.con.execute(
            "SELECT expires_ms,manifest IS NOT NULL FROM checkpoint_staging "
            "WHERE workspace_id=? AND source=? AND target=?",
            (self.ws, *key),
        ).fetchone()
        return {"expires_ms": row[0], "manifest": bool(row[1])} if row else None

    def staged(self, sql, key, *args):
        return self.con.execute(
            sql
            + " WHERE workspace_id=? AND source=? AND target=?"
            + "".join(f" AND {a}=?" for a in args[::2]),
            (self.ws, *key, *args[1::2]),
        )

    def completeness(self, key):
        if not self.stage(key)["manifest"]:
            return {"complete": False, "missing": []}
        missing = [
            r[0]
            for r in self.con.execute(
                "SELECT s.i FROM checkpoint_staging_slots s WHERE s.workspace_id=? AND s.source=? "
                "AND s.target=? AND NOT EXISTS (SELECT 1 FROM checkpoint_staging_pages p WHERE "
                "p.workspace_id=s.workspace_id AND p.source=s.source AND p.target=s.target AND p.i=s.i) "
                "ORDER BY s.pos",
                (self.ws, *key),
            )
        ]
        return {"complete": not missing, "missing": missing}

    def put_staging(self, source, target, i, body, wire, global_cap, pre=None):
        """Stateless validation comes precomputed from before the lock (review G2); its refusal
        is raised here, after the stateful steps that precede it in the reference."""
        if pre is None:
            pre = precheck_page(body, wire) if i is not None else precheck_manifest(body, wire)
        key = stage_key(source, target)
        self.con.execute(
            "DELETE FROM checkpoint_staging WHERE workspace_id=? AND expires_ms<=?",
            (self.ws, self.now),
        )
        stage = self.stage(key)
        if stage is None:
            live = self.con.execute(
                "SELECT count(*) FROM checkpoint_staging WHERE workspace_id=?", (self.ws,)
            ).fetchone()[0]
            need(live < STAGE_SETS, "quota_exceeded", 429)
            self.con.execute(
                "INSERT INTO checkpoint_staging VALUES (?,?,?,?,NULL,0)",
                (self.ws, *key, self.now + HOUR),
            )
            stage = {"expires_ms": self.now + HOUR, "manifest": False}
        if i is not None:
            if pre["refusal"]:
                raise pre["refusal"]
            existing = self.staged(
                "SELECT body FROM checkpoint_staging_pages", key, "i", i
            ).fetchone()
            if existing is not None:
                need(existing[0] == wire, "staging_conflict", 409)
                return {}
            if stage["manifest"]:
                slot = self.staged(
                    "SELECT descriptor FROM checkpoint_staging_slots", key, "i", i
                ).fetchone()
                need(
                    slot is not None and P.parse_json(slot[0]) == descriptor(i, body),
                    "staging_conflict",
                    409,
                )
            self.charge_stage(key, len(wire), global_cap)
            self.con.execute(
                "INSERT INTO checkpoint_staging_pages VALUES (?,?,?,?,?)", (self.ws, *key, i, wire)
            )
            return {}
        if pre["shape"]:
            raise pre["shape"]
        if stage["manifest"]:
            stored = self.staged("SELECT manifest FROM checkpoint_staging", key).fetchone()[0]
            need(stored == wire, "staging_conflict", 409)
            return self.completeness(key)
        staged = {r[0] for r in self.staged("SELECT i FROM checkpoint_staging_pages", key)}
        pages = body["pages"] if pre["at"] is None else body["pages"][: pre["at"]]
        for d in pages:
            if d["i"] in staged:
                raw = self.staged("SELECT body FROM checkpoint_staging_pages", key, "i", d["i"])
                need(
                    descriptor(d["i"], P.parse_json(raw.fetchone()[0])) == d,
                    "staging_conflict",
                    409,
                )
        if pre["refusal"]:
            raise pre["refusal"]
        need(staged <= {d["i"] for d in pages}, "staging_conflict", 409)
        self.charge_stage(key, len(wire), global_cap)
        self.con.execute(
            "UPDATE checkpoint_staging SET manifest=? WHERE workspace_id=? AND source=? AND target=?",
            (wire, self.ws, *key),
        )
        self.con.executemany(
            "INSERT INTO checkpoint_staging_slots VALUES (?,?,?,?,?,?)",
            [(self.ws, *key, d["i"], pos, P.cj(d)) for pos, d in enumerate(body["pages"])],
        )
        return self.completeness(key)

    # --- publication (P3-D13/D20/D24/D25) ------------------------------------------------------------

    def validate_checkpoint(self, cp, pre):
        """The stateful checkpoint checks, between the two stateless stages computed by
        precheck_publication (before the lock), in the reference's order."""
        if pre["stage1"]:
            raise pre["stage1"]
        o = cp["o"]
        genesis = self.genesis()
        need(genesis is not None, "no_genesis", 409)
        need(
            o["workspace_id"] == self.ws and o["genesis"] == genesis["pin"]["o"]["genesis"],
            "genesis_mismatch",
            409,
        )
        if pre["stage2"]:
            raise pre["stage2"]
        return genesis

    def load_stage(self, key):
        """The staged set's manifest, grouped by (kind, log) once per publication (review R1).
        Pages are read when a fold needs them (phase C: only if phase A did not fold them)."""
        wire = self.staged("SELECT manifest FROM checkpoint_staging", key).fetchone()[0]
        memo = self.memo
        if memo is not None and memo.manifest is not None and memo.manifest[0] == wire:
            manifest, groups = memo.manifest[1], memo.manifest[2]
        else:
            manifest, groups = P.parse_json(wire), {}
            for d in manifest["pages"]:
                groups.setdefault((d["kind"], d["log"]), []).append(d)  # manifest order
            if self.dry:
                memo.manifest = (wire, manifest, groups)
        stage = {"key": key, "manifest": manifest, "groups": groups, "wire": None}
        if self.dry:
            heads = sum(d["count"] for d in manifest["pages"])
            if memo.reserved is not None and heads > memo.reserved:
                raise Reweigh(heads)
            self.page_body(stage, None)  # every page in this snapshot (it is refreshed later)
        return stage

    def page_body(self, stage, d):
        if self.memo is not None and not self.dry:  # phase C: one page, within the live bound
            row = self.staged(
                "SELECT body FROM checkpoint_staging_pages", stage["key"], "i", d["i"]
            )
            return P.parse_json(row.fetchone()[0])
        if stage["wire"] is None:
            stage["wire"] = dict(
                self.staged("SELECT i,body FROM checkpoint_staging_pages", stage["key"])
            )
        return P.parse_json(stage["wire"][d["i"]]) if d is not None else None

    def staged_page(self, stage, d):
        """A staged page (phase C: its after_seq and from_acc, recorded by phase A)."""
        memo = self.memo
        if memo is not None and not self.dry and d["digest"] in memo.pages:
            return memo.pages[d["digest"]]
        self.live(d["count"])
        p = self.page_body(stage, d)
        if self.dry:
            if p.get("digest") == d["digest"]:
                memo.pages[d["digest"]] = {"after_seq": p["after_seq"], "from_acc": p["from_acc"]}
            else:
                memo.unsafe = True
        return p

    def proof_pages(self, stage, kind, log, start, used):
        # Descriptors are grouped by (kind, log) once per publication (review R1): scanning the
        # manifest per log cost tickets x pages under the global lock.
        current = {k: start[k] for k in ("seq", "head", "acc")}
        for d in stage["groups"].get((kind, log), ()):
            self.visits += 1
            p = self.staged_page(stage, d)
            need(
                p["after_seq"] == current["seq"] and p["from_acc"] == current["acc"],
                "chain_diverged",
                409,
            )
            heads = lambda p=p, d=d: p.get("heads") or self.page_body(stage, d)["heads"]
            current = self.fold(log, d["digest"], current, heads, d["count"])
            used.add(d["i"])
        return current

    def publish(self, body, gen, pre=None):
        w = self.workspace()
        if pre is None or pre["wsk_pub"] != w["wsk_pub"]:  # the card's WSK never changes
            pre = precheck_publication(body, w["wsk_pub"])
        if pre["early"]:
            raise pre["early"]
        body = pre["body"]
        stored = self.con.execute(
            "SELECT result FROM checkpoint_receipts WHERE workspace_id=? AND digest=?",
            (self.ws, pre["receipt"]),
        ).fetchone()
        if stored:
            return P.parse_json(stored[0])  # served even with the budget spent (review N5)
        if pre.get("lazy"):  # its receipt was seen before the lock, then evicted (P3-D34)
            pre = precheck_publication(body, w["wsk_pub"])
        window = self.con.execute(
            "SELECT count(*), coalesce(sum(gen=?),0) FROM checkpoint_failures "
            "WHERE workspace_id=? AND at_ms>?",
            (gen, self.ws, self.now - HOUR),
        ).fetchone()
        spent = self.con.execute(
            "SELECT coalesce(sum(heads),0) FROM checkpoint_refused_heads "
            "WHERE workspace_id=? AND at_ms>?",
            (self.ws, self.now - HOUR),
        ).fetchone()[0]
        if self.memo is not None:  # earlier rounds of this request, recorded only after it (N2)
            spent += self.memo.carried
        need(
            window[1] < FAILURE_BUDGET
            and window[0] < WORKSPACE_FAILURE_CEILING
            and spent < REFUSED_HEADS,
            "quota_exceeded",
            429,
        )
        target = body["checkpoint"]
        genesis = self.validate_checkpoint(target, pre)
        h = pre["hash"]
        held = self.held()
        o = target["o"]
        result = {"result": "accepted", "n": o["n"], "hash": h}
        if held and o["n"] <= held["o"]["n"]:
            if o == held["o"] and "restore" not in body:
                return result
            if o["n"] == held["o"]["n"] or "restore" in body:
                no("restore_source_mismatch" if "restore" in body else "chain_diverged")
            old = entries(held)
            need(
                all(
                    k in old and (e["seq"] < old[k]["seq"] or e == old[k])
                    for k, e in entries(target).items()
                ),
                "chain_diverged",
                409,
            )
            return {**result, "result": "ignored"}
        held_hash = checkpoint_hash(held) if held else None
        need(body["source_hash"] == held_hash, "restore_source_mismatch", 409)
        need(
            timestamp(o["at"]) <= self.now + 300_000
            and (not held or timestamp(o["at"]) >= timestamp(held["o"]["at"])),
            "checkpoint_time",
            409,
        )
        key = stage_key(body["source_hash"], h)
        meta = self.stage(key)
        need(
            meta is not None
            and meta["expires_ms"] > self.now
            and self.completeness(key)["complete"],
            "staging_incomplete",
            409,
        )
        stage = self.load_stage(key)
        used = set()
        old = entries(held) if held else {}
        offered = entries(target)
        need(not old.keys() - offered.keys(), "chain_diverged", 409)
        restored = None
        if "restore" in body:
            try:
                restored = self.restore(w, genesis, body, target, held, stage, used)
            except (KeyError, TypeError, ValueError, AttributeError, IndexError) as exc:
                raise refusal("restore_invalid") from exc
        for log, entry in offered.items():
            if log == restored:
                continue
            calculated = self.proof_pages(stage, "appended", log, old.get(log, EMPTY), used)
            need(calculated == entry, "chain_diverged", 409)
            if log == "workspace":
                root = self.log(log).at_seq(entry, 1)
                need(root["head"] == o["genesis"], "genesis_mismatch", 409)
        need(used == {d["i"] for d in stage["manifest"]["pages"]}, "chain_diverged", 409)
        self.node_quota()
        if self.dry:  # phase A ends at the commit point: phase B inserts the nodes, C commits
            self.memo.accepted = True
            return result
        self.committed = True
        if self.unpublished:
            # Hints (P3-D31 U10): GET .../unpublished is authoritative and serves every ref.
            result["unpublished"] = sorted({"d_" + u["device_id"] for u in self.unpublished})
            result["unpublished_refs"] = self.unpublished
        con = self.con
        if held:
            con.execute(
                "UPDATE checkpoints SET superseded_ms=? WHERE workspace_id=? AND hash=?",
                (self.now, self.ws, held_hash),
            )
        con.execute(
            "INSERT INTO checkpoints VALUES (?,?,?,?,NULL,?)",
            (self.ws, h, o["n"], P.cj(target), int(restored is not None)),
        )
        con.execute(
            "INSERT INTO checkpoint_heads VALUES (?,?) ON CONFLICT(workspace_id) DO UPDATE SET hash=excluded.hash",
            (self.ws, h),
        )
        con.execute(
            "INSERT INTO checkpoint_receipts VALUES (?,?,?)",
            (self.ws, pre["receipt"], P.cj(result)),
        )
        evict_oldest(con, "checkpoint_receipts", self.ws, RECEIPTS_KEPT)  # P3-D34
        con.execute(
            "DELETE FROM checkpoint_staging WHERE workspace_id=? AND source=? AND target=?",
            (self.ws, *key),
        )
        return result

    def node_quota(self):
        """P3-D34 (G4): at the commit point of phase A (before phase B inserts anything) and of
        phase C, the workspace's stored nodes (orphans included: `nodes`, never `orphaned`) plus
        the new nodes this publication adds must stay within the quota. A publication that adds
        no node is never refused by it."""
        added = sum(n.added for n in self.nodes.values())
        pending = added + self.reused
        if pending:
            row = self.con.execute(
                "SELECT nodes FROM checkpoint_node_usage WHERE workspace_id=?", (self.ws,)
            ).fetchone()
            # Live inserts (phase C, or no memo) are counted in this transaction already.
            stored = (row[0] if row else 0) - (0 if self.dry else added)
            need(stored + pending <= self.caps.nodes, "quota_exceeded", 429)

    def fresh_evidence(self, listed):
        """The self-certified pairs (device without association) this restore would add to the
        global table: a pair the table already holds is never counted (P3-D34)."""
        return [
            pair
            for pair in listed
            if self.association(pair[0]) is None
            and not self.con.execute(
                "SELECT 1 FROM revocations WHERE device_id=? AND person_id=?", pair
            ).fetchone()
        ]

    def evidence_used(self, person):
        row = self.con.execute(
            "SELECT pairs FROM account_evidence_pairs WHERE person_id=?", (person,)
        ).fetchone()
        return row[0] if row else 0

    # --- restores (R0-R5) --------------------------------------------------------------------------

    @staticmethod
    def restore_shape(line):
        need(
            isinstance(line, dict)
            and RESTORE_FIELDS <= set(line) <= RESTORE_FIELDS | {"note", "ws_seq"}
        )
        need(
            type(line["hash_v"]) is int
            and line["v"] == 2
            and line["hash_v"] == 1
            and line["type"] == "restore"
        )
        need(set(line["actor"]) == {"kind", "id", "device"} and line["actor"]["kind"] == "person")
        need(
            re.fullmatch(r"p_[0-9a-f]{32}", line["actor"]["id"])
            and re.fullmatch(r"d_[0-9a-f]{32}", line["actor"]["device"])
        )
        need(ULID.fullmatch(line["id"]))
        count(line["seq"], 1)
        count(line["from_seq"], 1)
        count(line["roster_v"])
        if "ws_seq" in line:
            count(line["ws_seq"], 1)
        for k in ("based_on", "prev", "head"):
            hash_bytes(line[k])
        timestamp(line["at"])
        need(line["seq"] == line["from_seq"] + 1 and line["prev"] == line["head"])
        need(line["auth"] in AUTH_KINDS)
        need(line["reason"] in ("rollback", "diverged", "broken", "other"))
        decisions = line["abandoned_decisions"]
        need(isinstance(decisions, list) and len(set(decisions)) == len(decisions))
        for ident in decisions:
            need(ULID.fullmatch(ident))
        if "note" in line:
            note = line["note"]
            need(
                isinstance(note, str)
                and len(note.encode()) <= 280
                and not any(ord(c) < 32 or ord(c) == 127 for c in note)
            )
        if line["source"] is not None:
            need(set(line["source"]) == {"n", "hash"})
            count(line["source"]["n"], 1)
            hash_bytes(line["source"]["hash"])
        if line["abandoned"] is not None:
            need(set(line["abandoned"]) == {"seq", "head"})
            count(line["abandoned"]["seq"], line["from_seq"] + 1)
            hash_bytes(line["abandoned"]["head"])
        P.unb64u(line["sig"], 64)
        P.unb64u(line["host_sig"], 64)
        need(isinstance(line["revocations"], list))

    def association(self, device):
        """(person, account key or None) the relay associates with `device`, or None: the live
        device registry (§19.1, written by PUT /v2/devices or account creation under the person's
        account key; a restore signer is a list member and so a registered device, review L3).

        orch-core #397: only associations bind a carried entry's identity. Held revocations bind
        nothing: neither this workspace's chain pairs nor the global table (a tombstone is evidence,
        not an association). Restore evidence never registers a device (apply_evidence), and a
        registry row of an evidence-only person (P3-D29, created by restore evidence before
        migration 0010) is not an association either."""
        row = self.con.execute(
            "SELECT d.person_id, a.pk_pub FROM devices d LEFT JOIN accounts a "
            "ON a.person_id=d.person_id WHERE d.device_id=? AND NOT EXISTS "
            "(SELECT 1 FROM evidence_persons e WHERE e.person_id=d.person_id)",
            (device,),
        ).fetchone()
        return (row[0], row[1]) if row else None

    def evidence(self, line, log):
        """Verified entries keyed by (device, person): a restore carries one entry per pair, sorted
        by (device_id, person_id) (orch-core #397). An entry for an associated device must be of its
        person and key; a device without association is self-certified by each pair, so two
        persons' entries for one such device are two pairs, both accepted."""
        need(log == "workspace" or line["revocations"] == [], "restore_invalid", 409)
        listed, order = {}, []
        for item in line["revocations"]:
            need(
                isinstance(item, dict) and set(item) == {"revocation", "device_cert", "pk_pub"},
                "restore_invalid",
                409,
            )
            pk = P.unb64u(item["pk_pub"])
            c = item["device_cert"]["o"]
            checked = P.verify_cert(item["device_cert"], pk, c["created_ms"])
            need("ok" in checked, "restore_invalid", 409)
            rev = P.verify_revocation(item["revocation"], pk, checked["ok"])
            need("ok" in rev, "restore_invalid", 409)
            pair = (rev["ok"]["device_id"], rev["ok"]["person_id"])
            holder = self.association(pair[0])
            need(
                holder is None or (pair[1] == holder[0] and holder[1] in (None, item["pk_pub"])),
                "restore_invalid",
                409,
            )
            need(pair not in listed, "restore_invalid", 409)
            order.append(pair)
            listed[pair] = item
        need(order == sorted(order), "restore_invalid", 409)
        return listed

    def coverage(self, listed, signer, log):
        """R4 completeness, per (device, person) pair, from this workspace's own chain only
        (F1 #387): each chain pair of a device in ever_devices (G2 and checkpoint) or in this
        restore needs a carried entry of the same pair at the same or a stronger reason. The
        `unpublished` hints are the P3-D31 view after the restore (unpublished_refs)."""
        if log != "workspace":
            return
        carried = {
            pair: STRENGTH[item["revocation"]["o"]["reason"]] for pair, item in listed.items()
        }
        devices = {d for d, _ in listed} | {signer}
        known = {
            r[0]
            for r in self.con.execute(
                "SELECT device_id FROM ever_devices WHERE workspace_id=?1 UNION "
                "SELECT device_id FROM checkpoint_ever_devices WHERE workspace_id=?1",
                (self.ws,),
            )
        } | devices
        chain = {
            (d, p): reason
            for d, p, reason in self.con.execute(
                "SELECT device_id,person_id,reason FROM checkpoint_revocations WHERE workspace_id=?",
                (self.ws,),
            )
            if d in known
        }
        missing = sorted(
            {d for (d, p), reason in chain.items() if carried.get((d, p), 0) < STRENGTH[reason]}
        )
        need(not missing, "restore_missing_revocation", 409, devices=missing)

    def unpublished_refs(self, signer):
        """revocation.unpublished hints of an accepted workspace restore (P3-D31 U10): exactly the
        items of the unpublished view after this restore's evidence is applied, minus the signer's
        device, so every reference is retrievable through GET .../unpublished in the next
        snapshot. The view reads only this workspace's G2 ever-devices (review N2), each device's
        registry pair only (a device without association, or another person's pair, is never
        reported: F1 keeps it pending), and includes a chain pair whose global row is stronger
        (review N1). Not authoritative: the route is."""
        return [
            {
                "device_id": i["device_id"],
                "person_id": i["person_id"],
                "reason": i["reason"],
                **i["provenance"],
            }
            for i in U.view(self.con, self.ws)
            if i["device_id"] != signer
        ]

    def restore(self, w, genesis, body, target, held, stage, used):
        bundle = body["restore"]
        try:
            need(isinstance(bundle, dict) and set(bundle) == {"line", "cert", "authz", "log"})
            line = bundle["line"]
            self.restore_shape(line)
            log = bundle["log"]
            need((log == "workspace") == ("ws_seq" not in line))
            need(len(P.cj(line)) + 1 <= LINE_CAP, "too_large", 400)
        except (KeyError, TypeError, ValueError, Refusal) as exc:
            if isinstance(exc, Refusal) and exc.code == "too_large":
                raise
            raise refusal("restore_invalid") from exc
        need(line["source"] == reference(held), "restore_source_mismatch", 409)
        need(
            not self.con.execute(
                "SELECT 1 FROM checkpoint_transitions WHERE workspace_id=? AND restore_id=?",
                (self.ws, line["id"]),
            ).fetchone(),
            "restore_reused",
            409,
        )
        pub = P.unb64u(bundle["cert"]["o"]["dk_sig_pub"])
        need(
            P.SUITE.verify(pub, P.unb64u(line["sig"]), event_bytes(line, self.ws, log))
            and P.SUITE.verify(
                P.unb64u(w["wsk_pub"]),
                P.unb64u(line["host_sig"]),
                event_bytes(line, self.ws, log, True),
            ),
            "restore_invalid",
            409,
        )
        listed = self.evidence(line, log)
        cert = self.owner_policy(w, bundle, {d for d, _ in listed})
        self.coverage(listed, cert["device_id"], log)
        # P3-D34: new self-certified pairs are charged to the owner person (the signer, by
        # owner_policy), in phase A (before any fold) and live in phase C.
        fresh = self.fresh_evidence(listed)
        need(
            not fresh or self.evidence_used(w["owner"]) + len(fresh) <= self.caps.evidence,
            "quota_exceeded",
            429,
        )
        at = timestamp(line["at"])
        need(
            (not held or timestamp(held["o"]["at"]) <= at) and at <= timestamp(target["o"]["at"]),
            "restore_invalid",
            409,
        )
        if "ws_seq" in line:
            need(line["ws_seq"] <= target["o"]["workspace_log"]["seq"], "restore_invalid", 409)
        nodes = self.log(log)
        old = entries(held).get(log, EMPTY) if held else EMPTY
        if line["from_seq"] < old["seq"]:
            retained = nodes.at_seq(old, line["from_seq"])
            # A stored path needs no retained page; a supplied one must bind to that branch.
            pages = stage["groups"].get(("retained", log), [])
            if pages:
                first = self.staged_page(stage, pages[0])
                start = nodes.get(first["from_acc"])
                need(
                    start is not None and start["seq"] == first["after_seq"], "restore_invalid", 409
                )
                tip = nodes.get(old["acc"])
                on = nodes.ancestor(tip, start["seq"]) if tip is not None else None
                need(on is not None and on["acc"] == first["from_acc"], "chain_diverged", 409)
                proved = self.proof_pages(stage, "retained", log, start, used)
                need(proved == retained, "restore_invalid", 409)
            abandoned = self.proof_pages(stage, "abandoned", log, retained, used)
            need(abandoned == old, "restore_invalid", 409)
            ab = line["abandoned"]
            need(
                ab is not None
                and ab["seq"] >= old["seq"]
                and (ab["seq"] != old["seq"] or ab["head"] == old["head"]),
                "restore_invalid",
                409,
            )
        else:
            retained = self.proof_pages(stage, "retained", log, old, used)
        need(
            retained["seq"] == line["from_seq"] and retained["head"] == line["head"],
            "restore_invalid",
            409,
        )
        if log == "workspace":
            root = nodes.at_seq(retained, 1)
            need(root["head"] == genesis["pin"]["o"]["genesis"], "restore_invalid", 409)
        head = event_head(line)
        result = self.fold(log, ("line", head), retained, lambda: [head])
        need(entries(target).get(log) == result, "restore_invalid", 409)
        if self.dry:  # phase A writes nothing; phase C applies the evidence live
            return log
        target_hash = checkpoint_hash(target)
        self.apply_evidence(listed, line["id"], target_hash)
        con, ws = self.con, self.ws
        if fresh:
            con.execute(
                "INSERT INTO account_evidence_pairs VALUES (?,?) ON CONFLICT(person_id) "
                "DO UPDATE SET pairs=pairs+excluded.pairs",
                (w["owner"], len(fresh)),
            )
        if log == "workspace":
            # checkpoint_unpublished is no longer written (P3-D31): the view replaces it.
            self.unpublished = self.unpublished_refs(cert["device_id"])
        for device in {d for d, _ in listed} | {cert["device_id"]}:
            con.execute("INSERT OR IGNORE INTO checkpoint_ever_devices VALUES (?,?)", (ws, device))
        transition = {
            "restore_id": line["id"],
            "source_hash": body["source_hash"],
            "target_hash": target_hash,
            "target_n": target["o"]["n"],
            **bundle,
        }
        con.execute(
            "INSERT INTO checkpoint_transitions VALUES (?,?,?,?)",
            (ws, line["id"], target["o"]["n"], P.cj(transition)),
        )
        if held:
            con.execute(
                "UPDATE checkpoints SET permanent=1 WHERE workspace_id=? AND hash=?",
                (ws, checkpoint_hash(held)),
            )
        return log

    def apply_evidence(self, listed, restore_id, target_hash):
        """§19.5 intake and this workspace's chain pairs, in this transaction, per (device,
        person) pair. Restore evidence never registers its device or creates an account (orch-core
        #397: no first-come association; the round-4 rule is reverted). Neither table ever loses a
        revocation: the global one only upgrades per pair (§6.2 "no un-revoke"), a chain pair keeps
        its first evidence and provenance until a stronger reason replaces them (monotonic,
        sticky: only an accepted restore writes a chain pair, never out-of-band evidence)."""
        con = self.con
        for (device, person), item in listed.items():
            reason = item["revocation"]["o"]["reason"]
            row = con.execute(
                "SELECT reason FROM checkpoint_revocations WHERE workspace_id=? AND device_id=? "
                "AND person_id=?",
                (self.ws, device, person),
            ).fetchone()
            if row is None or STRENGTH[reason] > STRENGTH[row[0]]:
                con.execute(
                    "INSERT INTO checkpoint_revocations VALUES (?,?,?,?,?,?,?,?,?) "
                    "ON CONFLICT(workspace_id,device_id,person_id) DO UPDATE SET "
                    "reason=excluded.reason,record=excluded.record,device_cert=excluded.device_cert,"
                    "pk_pub=excluded.pk_pub,restore_id=excluded.restore_id,"
                    "target_hash=excluded.target_hash",
                    (
                        self.ws,
                        device,
                        person,
                        reason,
                        P.cj(item["revocation"]),
                        P.cj(item["device_cert"]),
                        item["pk_pub"],
                        restore_id,
                        target_hash,
                    ),
                )
            self.d.revoke(con, item["revocation"], self.now)
            self.wake.add(("subject", device))
            self.wake.update(
                ("ws", r[0])
                for r in con.execute(
                    "SELECT workspace_id FROM ever_devices WHERE device_id=?", (device,)
                )
            )

    # --- baselines (P3-D13/D20) ----------------------------------------------------------------------

    def baseline_post(self, body):
        need(isinstance(body, dict))
        h = body["hash"]
        hash_bytes(h)
        self.purge()
        need(set(body) == {"hash", "offer_id"})
        P.unhex(body["offer_id"], 16)
        self.checkpoint(h)
        pin = self.con.execute(
            "SELECT until_ms FROM checkpoint_baselines WHERE workspace_id=? AND hash=?",
            (self.ws, h),
        ).fetchone()
        if pin:
            return {"until_ms": pin[0]}  # retries never extend the pin
        live = self.con.execute(
            "SELECT count(*) FROM checkpoint_baselines WHERE workspace_id=?", (self.ws,)
        ).fetchone()[0]
        need(live < BASELINES, "quota_exceeded", 429)
        self.con.execute(
            "INSERT INTO checkpoint_baselines VALUES (?,?,?,?)",
            (self.ws, h, body["offer_id"], self.now + 7 * DAY),
        )
        return {"until_ms": self.now + 7 * DAY}

    def baseline_delete(self, h, role, offer_id):
        hash_bytes(h)
        self.purge()
        pin = self.con.execute(
            "SELECT offer_id FROM checkpoint_baselines WHERE workspace_id=? AND hash=?",
            (self.ws, h),
        ).fetchone()
        # W(g) releases any pin; a member only the pin whose offer_id it names (review 10).
        if pin and (role == "host" or offer_id == pin[0]):
            self.con.execute(
                "DELETE FROM checkpoint_baselines WHERE workspace_id=? AND hash=?", (self.ws, h)
            )
        return {}

    # --- reads (P3-D13/D19) --------------------------------------------------------------------------

    def read(self, route, query):
        h = query.get("hash") if route == "checkpoint_get" else query.get("to")
        if h is None:
            need(route == "checkpoint_get")
            row = self.con.execute(
                "SELECT hash FROM checkpoint_heads WHERE workspace_id=?", (self.ws,)
            ).fetchone()
            need(row is not None, "not_found", 404)
            h = row[0]
        cp = self.checkpoint(h)
        if route == "checkpoint_get":
            head = self.con.execute(
                "SELECT coalesce(max(target_n),0) FROM checkpoint_transitions "
                "WHERE workspace_id=? AND target_n<=?",
                (self.ws, cp["o"]["n"]),
            ).fetchone()[0]
            return {"genesis": self.genesis(), "checkpoint": cp, "transitions_head": head}
        cap = TRANSITION_LIMIT if route == "transitions" else PROOF_LIMIT
        limit = integer(query.get("limit", str(cap)))
        need(1 <= limit <= cap)
        if route == "transitions":
            after = integer(query.get("after_n", "0"))
            rows = self.con.execute(
                "SELECT bundle FROM checkpoint_transitions WHERE workspace_id=? AND target_n>? "
                "AND target_n<=? ORDER BY target_n LIMIT ?",
                (self.ws, after, cp["o"]["n"], limit + 1),
            ).fetchall()
            items = [P.parse_json(r[0]) for r in rows]
            page = []
            for item in items[:limit]:
                framed = {"transitions": page + [item], "next": str(item["target_n"])}
                if len(P.cj(framed)) > PAGE_CAP:
                    break
                page.append(item)
            more = len(page) < len(items)
            return {"transitions": page, "next": str(page[-1]["target_n"]) if more else None}
        log, start = query.get("log"), query.get("from")
        hash_bytes(start)
        need(log in entries(cp), "not_found", 404)
        heads, nxt = self.log(log).page(start, entries(cp)[log]["acc"], limit)
        return {"heads": heads, "next": nxt}


# --- HTTP -------------------------------------------------------------------------------------------

# route -> (method, path, auth, JSON body cap). W: W(g), fenced; R: D(m) or W; WD: W(g) or D(m).
ROUTES = {
    "genesis": ("PUT", "workspaces/{ws}/genesis", "W", 65536),
    "staging_page": ("PUT", "workspaces/{ws}/staging/{source}/{target}/pages/{i}", "W", PAGE_CAP),
    "staging_manifest": (
        "PUT",
        "workspaces/{ws}/staging/{source}/{target}/manifest",
        "W",
        PAGE_CAP,
    ),
    "baseline_post": ("POST", "workspaces/{ws}/baselines", "W", 16384),
    "baseline_delete": ("DELETE", "workspaces/{ws}/baselines/{hash}", "WD", 0),
    "checkpoint_put": ("PUT", "workspaces/{ws}/checkpoint", "W", REQUEST_CAP),
    "checkpoint_get": ("GET", "workspaces/{ws}/checkpoint", "R", 0),
    "transitions": ("GET", "workspaces/{ws}/transitions", "R", 0),
    "proof": ("GET", "workspaces/{ws}/proof", "R", 0),
    "unpublished_get": ("GET", "workspaces/{ws}/unpublished", "W", 0),
    "unpublished_ack": ("POST", "workspaces/{ws}/unpublished/ack", "W", U.ACK_CAP),
}
QUERY = {
    "checkpoint_get": {"hash"},
    "transitions": {"after_n", "to", "limit"},
    "proof": {"log", "from", "to", "limit"},
    "baseline_delete": {"offer_id"},
    "unpublished_get": {"cursor", "limit"},
}


class Gate:
    """The per-workspace publication mutex, then admission (P3-D33).

    Admission is first come, first served and bounded twice: at most `width` publications at
    once, and their reserved staged heads together at most `cap` (review F4: phase A's memory is
    about linear in heads); a publication above the cap is admitted only alone. Everything is
    awaited on the event loop, so a publication that waits pins no worker thread (a blocked
    worker would stall reads and /healthz). The mutex is taken first, so two publications to one
    workspace never hold two slots. One set per running loop; a workspace's mutex is dropped
    when nothing holds or awaits it."""

    def __init__(self, width, heads=None):
        self.width, self.cap = width, heads
        self.loops = weakref.WeakKeyDictionary()  # loop -> ({ws: [lock, users]}, waiters)
        self.active = self.peak = self.heads = 0

    def fits(self, weight):
        if self.active >= self.width:
            return False
        return self.active == 0 or self.cap is None or self.heads + weight <= self.cap

    def admit(self, weight):
        self.active += 1
        self.heads += weight
        self.peak = max(self.peak, self.active)

    def release(self, weight, waiters):
        self.active -= 1
        self.heads -= weight
        self.wake(waiters)

    def wake(self, waiters):
        while waiters and (waiters[0][1].done() or self.fits(waiters[0][0])):
            weight, future = waiters.popleft()
            if future.done():  # cancelled while queued (review N1): it gives up its place
                continue
            self.admit(weight)
            future.set_result(None)

    @asynccontextmanager
    async def enter(self, ws, weight=0):
        loop = asyncio.get_running_loop()
        if loop not in self.loops:
            self.loops[loop] = ({}, collections.deque())
        mutexes, waiters = self.loops[loop]
        mutex = mutexes.setdefault(ws, [asyncio.Lock(), 0])
        mutex[1] += 1
        try:
            async with mutex[0]:
                if not waiters and self.fits(weight):
                    self.admit(weight)
                else:
                    waiter = (weight, loop.create_future())
                    waiters.append(waiter)
                    try:
                        await waiter[1]
                    except asyncio.CancelledError:
                        if waiter[1].done() and not waiter[1].cancelled():
                            self.release(weight, waiters)  # admitted, then cancelled
                        else:  # never admitted; a leave may have dropped it already (N1)
                            if waiter in waiters:
                                waiters.remove(waiter)
                            self.wake(waiters)
                        raise
                try:
                    yield
                finally:
                    self.release(weight, waiters)
        finally:
            mutex[1] -= 1
            if mutex[1] == 0:
                del mutexes[ws]


class Checkpoints:
    def __init__(self, directory, bridge):
        self.d, self.bridge = directory, bridge
        self.global_stage_cap = int(
            os.environ.get("ORCH_RELAY_GLOBAL_STAGE_BYTES", GLOBAL_STAGE_CAP)
        )
        self.caps = Caps(os.environ)  # P3-D34
        self.budget = U.Budget()  # P3-D31 rate windows, after authorization only
        self.gate = Gate(
            int(os.environ.get("ORCH_RELAY_PUBLISH_WIDTH", PUBLISH_WIDTH)),
            int(os.environ.get("ORCH_RELAY_PUBLISH_HEADS", PUBLISH_HEADS)),
        )
        # Tests: phase_a, refresh, after_a, chunk, before_c, restart (P3-D33 phase boundaries).
        self.hooks = {}

    def hook(self, name, **info):
        if name in self.hooks:
            self.hooks[name](**info)

    def authorize(self, con, route, ws, headers, now, charge=False):
        """The route's principal: authenticated, authorized for this workspace, fenced.

        With `charge` (once per request, at its first authorization) the session's buckets are
        charged after authentication (P3-D35), refused or not; proof and transition pages also
        take a page token."""
        session = self.d.authenticate(con, headers, now)
        try:
            self.authorize_session(con, session, route, ws, headers, now)
        except Refusal:
            if charge:
                self.d.throttle(session, now)
            raise
        if charge:
            self.d.throttle(session, now, page=route in ("proof", "transitions"))
        return session

    def authorize_session(self, con, session, route, ws, headers, now):
        d = self.d
        auth = ROUTES[route][2]
        if auth == "R" or (auth == "WD" and session["kind"] == "device"):
            d.workspace_access(con, session, ws)
            return session
        d.workspace_access(con, session, ws, write=True)
        if route == "checkpoint_put" and "orch-holder" not in headers:
            no("malformed", 400)  # the generation is required; no failure is recorded
        d.fence(con, headers, ws, now)
        return session

    def preauthorize(self, route, ws, headers):
        """Read-only, before any lock, write transaction or failure window (G3 review 3)."""
        with self.bridge.reading() as con:
            con.execute("BEGIN")
            self.authorize(con, route, ws, headers, self.d.clock(), charge=True)
            row = con.execute(
                "SELECT wsk_pub FROM workspaces WHERE workspace_id=?", (ws,)
            ).fetchone()
            return row[0] if row else None

    def prepare(self, route, ws, raw, wsk_pub):
        """Parse and validate what needs no database state, after authorization and before the
        lock (review G2). A body that does not parse is refused here, except a final
        publication's, which is charged in the transaction like every refusal after W(g).

        An exact retry of an accepted publication (its receipt in a read snapshot) skips the
        signature and entry checks entirely (review N4). Only receipts older than the newest
        RECEIPTS_KEPT of the workspace are evicted (P3-D34); the transaction re-validates a
        retry whose receipt is gone by then."""
        if route == "checkpoint_put":
            pre = precheck_publication(raw, wsk_pub, stages=False)
            if pre["early"]:
                return None, pre
            with self.bridge.reading("query") as con:
                con.execute("BEGIN")
                hit = con.execute(
                    "SELECT 1 FROM checkpoint_receipts WHERE workspace_id=? AND digest=?",
                    (ws, pre["receipt"]),
                ).fetchone()
            return None, pre if hit else precheck_publication(pre["body"], wsk_pub)
        body = P.parse_json(raw) if raw else None
        if route == "staging_page":
            return body, precheck_page(body, raw)
        if route == "staging_manifest":
            return body, precheck_manifest(body, raw)
        return body, None

    def read(self, route, params, query, headers):
        with self.bridge.reading("query") as con:
            con.execute("BEGIN")
            now = self.d.clock()
            self.authorize(con, route, params["ws"], headers, now, charge=True)
            return Relay(self.d, con, params["ws"], now).read(route, query)

    def unpublished_read(self, ws, query, headers):
        """GET .../unpublished (P3-D31): one query-only snapshot, no lock, no write. W(g) is checked
        first (401, then 403 for any other principal, never 404, then 409 fenced); only then is the
        workspace's fetch window charged; then the query and the position are parsed."""
        with self.bridge.reading("query") as con:
            con.execute("BEGIN")
            now = self.d.clock()
            self.authorize(con, "unpublished_get", ws, headers, now, charge=True)
            self.budget.charge("unpublished-get", ws, U.FETCH_WINDOWS, now)
            return U.page(con, ws, query)

    def unpublished_ack(self, ws, headers, raw):
        """POST .../unpublished/ack (P3-D31): authorized read-only first, then the ack window, then
        the body; the raise itself runs under the lock, re-authorized and re-checked."""
        try:
            self.preauthorize("unpublished_ack", ws, headers)
            early = True
        except sqlite3.Error:
            early = False  # the transaction authorizes on its own before anything is charged
        if early:
            self.budget.charge("unpublished-ack", ws, U.ACK_WINDOWS, self.d.clock())
            c = U.parse_ack(ws, raw)
        d = self.d
        with d.lock:
            con = self.bridge.connection("write")
            con.execute("BEGIN IMMEDIATE")
            with con:
                now = d.clock()
                self.authorize(con, "unpublished_ack", ws, headers, now)
                if not early:
                    self.budget.charge("unpublished-ack", ws, U.ACK_WINDOWS, now)
                    c = U.parse_ack(ws, raw)
                result, changed = U.ack(con, ws, c, integer(headers["orch-holder"]), now)
        return result, [("ws", ws)] if changed else []

    # --- final publication in three phases (P3-D33, G1) ------------------------------------------

    def weigh(self, ws, pre):
        """The heads a publication will fold, estimated from its staged set's bytes (a head is 74
        bytes on the wire), for its reservation in the gate; phase A reweighs (F4)."""
        if pre is None or "hash" not in pre:
            return 0
        try:
            key = stage_key(pre["body"]["source_hash"], pre["hash"])
        except (Refusal, KeyError, TypeError, ValueError):
            return 0
        with self.bridge.reading("query") as con:
            row = con.execute(
                "SELECT bytes FROM checkpoint_staging WHERE workspace_id=? AND source=? "
                "AND target=?",
                (ws, *key),
            ).fetchone()
        return row[0] // 74 if row else 0

    def publication(self, params, headers, raw, prepared, reserved=None):
        """PUT checkpoint after authorization; the caller holds the gate for the workspace.

        An exact retry and a body that does not parse need no fold and go straight to the
        transaction, as before. Otherwise rounds of phase A, phase B (if phase A reached the
        commit point) and phase C. A round restarts when phase C would do more than
        LIVE_FOLD_LIMIT heads of work under the lock, would commit on folds phase B did not
        store, or phase A hit a database error or an inconsistent page (review F1); after
        PUBLISH_ROUNDS rounds the answer is 503 overloaded (retryable, never charged)."""
        ws = params["ws"]
        pre = prepared[1] if prepared is not None else None
        if pre is not None and (pre.get("lazy") or pre["early"]):
            return self.write("checkpoint_put", params, {}, headers, raw, prepared)
        memo, refused = None, True
        try:
            for attempt in range(PUBLISH_ROUNDS):
                if attempt:
                    self.hook("restart", ws=ws, round=attempt)
                try:
                    carried = memo.heads + memo.live if memo is not None else 0
                    fresh = self.phase_a(ws, headers, raw, prepared, reserved, carried)
                except sqlite3.Error:
                    continue
                if memo is not None:  # the work and the nodes of earlier rounds
                    fresh.heads += memo.heads + memo.live
                    fresh.inserted += memo.inserted
                memo = fresh
                self.hook("after_a", ws=ws, memo=memo)
                if memo.unsafe:
                    continue
                try:
                    if memo.accepted:
                        self.phase_b(ws, headers, memo)
                    self.hook("before_c", ws=ws, memo=memo)
                    answer = self.phase_c(params, headers, raw, prepared, memo)
                except Restart:
                    continue
                refused = False
                return answer
            no("overloaded", 503)
        finally:
            if memo is not None:
                self.settle(ws, memo, refused)

    def phase_a(self, ws, headers, raw, prepared, reserved=None, carried=0):
        """Authorize, then run the whole publication on WAL read snapshots, without the lock:
        every fold, R0-R5 and the checks in their reference order. Nothing is written; the
        outcome only prepares phase C, which answers (a refusal here is re-derived there). The
        snapshot is renewed every A_SNAPSHOT_HEADS folded heads (review F3)."""
        assert not self.d.lock._is_owned(), "phase A runs outside Directory.lock"
        pre = prepared[1] if prepared is not None else None
        memo = Memo()
        memo.reserved, memo.carried = reserved, carried
        with self.bridge.reading("query") as con:
            con.execute("BEGIN")
            now = self.d.clock()
            self.authorize(con, "checkpoint_put", ws, headers, now)
            self.hook("phase_a", ws=ws, memo=memo)

            def refresh():
                con.execute("ROLLBACK")
                self.hook("refresh", ws=ws)
                con.execute("BEGIN")

            memo.refresh = refresh
            relay = Relay(self.d, con, ws, now, memo, dry=True, caps=self.caps)
            try:
                relay.publish(raw, integer(headers["orch-holder"]), pre)
            except (Refusal, KeyError, TypeError, ValueError, AttributeError, IndexError):
                pass
            finally:
                memo.refresh = None
            memo.heads = relay.folded
            memo.overlay = {log: nodes.cache for log, nodes in relay.nodes.items()}
        return memo

    def phase_b(self, ws, headers, memo):
        """Insert phase A's new nodes, NODE_CHUNK rows per short transaction under the lock, each
        re-authorized (a takeover stops it). Nodes are immutable and nothing references them yet,
        so a refusal or a crash after any chunk leaves only orphans (counted), and the inserts are
        idempotent on a retry. Chunks follow fold order, so every committed prefix is also
        branch-closed (not load-bearing: a later fold reaches a stored node only along a branch it
        holds in its own cache or that is stored in full)."""
        rows, memo.rows = memo.rows, []
        d = self.d
        for k in range(0, len(rows), NODE_CHUNK):
            # Key order inside a chunk (it commits atomically) keeps the B-tree inserts local.
            chunk = sorted(rows[k : k + NODE_CHUNK], key=lambda row: (row[1], row[2]))
            self.hook("chunk", ws=ws, memo=memo, rows=len(chunk))
            with d.lock:
                con = self.bridge.connection("write")
                con.execute("BEGIN IMMEDIATE")
                with con:
                    self.authorize(con, "checkpoint_put", ws, headers, d.clock())
                    before = con.total_changes
                    con.executemany("INSERT OR IGNORE INTO log_nodes VALUES (?,?,?,?,?,?,?)", chunk)
                    added = con.total_changes - before
                    if added:
                        count_nodes(con, ws, added)
            memo.inserted += added
        memo.overlay = {}  # every node phase A made is stored now

    def phase_c(self, params, headers, raw, prepared, memo):
        """The publication under the lock against live state, with phase A's folds (write)."""
        return self.write("checkpoint_put", params, {}, headers, raw, prepared, memo)

    def settle(self, ws, memo, refused=True):
        """After the answer: on a refusal not charged in phase C (fenced, 429, 503, a refusal in
        phase B), record the fold work of every round (review F2: a takeover must not make phase
        A free); count the nodes phase B inserted for a publication phase C did not commit
        (`orphaned` only grows, also when a later publication commits on those nodes). Best
        effort: a database error here is logged and never replaces the answer (review F6)."""
        heads = memo.heads + memo.live if refused and not memo.charged else 0
        orphans = 0 if memo.committed else memo.inserted
        if heads or orphans:
            try:
                self.account(ws, heads, orphans)
            except sqlite3.Error:
                log.exception("publication accounting failed for workspace %s", ws)

    def account(self, ws, heads, orphans):
        with self.d.lock:
            con = self.bridge.connection("write")
            con.execute("BEGIN IMMEDIATE")
            with con:
                if heads:
                    con.execute(
                        "INSERT INTO checkpoint_refused_heads VALUES (?,?,?)",
                        (ws, self.d.clock(), heads),
                    )
                if orphans:
                    count_nodes(con, ws, 0, orphans)

    def write(self, route, params, query, headers, raw, prepared=None, memo=None):
        body, pre = prepared if prepared is not None else (None, None)
        d = self.d
        with d.lock:
            con = self.bridge.connection("write")
            con.execute("BEGIN IMMEDIATE")
            refused = None
            with con:
                now = d.clock()
                ws = params["ws"]
                session = self.authorize(con, route, ws, headers, now)
                if prepared is None and route != "checkpoint_put":
                    body = P.parse_json(raw) if raw else None  # only after authorization (N5)
                relay = Relay(
                    d, con, ws, now, memo if route == "checkpoint_put" else None, caps=self.caps
                )
                if route == "checkpoint_put":
                    gen = integer(headers["orch-holder"])
                    con.execute("SAVEPOINT publication")
                    try:
                        try:
                            result = relay.publish(raw, gen, pre)
                            if (
                                memo is not None
                                and relay.committed
                                and not memo.accepted
                                and memo.folds
                            ):
                                # Phase B did not store phase A's folds (or its overlay nodes):
                                # never commit on them; restart from phase A (review F1).
                                raise Restart
                        except (KeyError, TypeError, ValueError, AttributeError, IndexError) as exc:
                            raise refusal("malformed", 400) from exc
                        con.execute("RELEASE publication")
                    except Restart:
                        memo.live += relay.folded
                        raise
                    except Refusal as exc:
                        con.execute("ROLLBACK TO publication")
                        con.execute("RELEASE publication")
                        relay.wake.clear()
                        relay.committed = False
                        if exc.code != "quota_exceeded":
                            # After W(g) and fencing (review 3), with the fold work (P3-D33).
                            heads = relay.folded
                            if memo is not None:
                                heads += memo.heads + memo.live
                                memo.charged = True
                            record_failure(con, ws, gen, now, heads)
                        elif memo is not None:
                            memo.live += relay.folded
                        refused = exc
                else:
                    if route == "genesis":
                        result = relay.put_genesis(body)
                    elif route in ("staging_page", "staging_manifest"):
                        source = None if params["source"] == "null" else params["source"]
                        i = None
                        if route == "staging_page":
                            i = integer(params["i"])
                        result = relay.put_staging(
                            source, params["target"], i, body, raw, self.global_stage_cap, pre
                        )
                    elif route == "baseline_post":
                        result = relay.baseline_post(body)
                    else:
                        role = "host" if session["kind"] == "workspace" else "member"
                        result = relay.baseline_delete(params["hash"], role, query.get("offer_id"))
            if memo is not None:
                memo.committed = relay.committed  # after the commit
            if refused is not None:
                raise refused
            return result, sorted(relay.wake)

    def sweep(self):
        """Drop expired staging sets, baselines and checkpoints across workspaces."""
        with self.d.lock:
            con = self.bridge.connection("write")
            con.execute("BEGIN IMMEDIATE")
            with con:
                now = self.d.clock()
                for (ws,) in con.execute(
                    "SELECT workspace_id FROM checkpoint_heads UNION "
                    "SELECT workspace_id FROM checkpoint_staging"
                ).fetchall():
                    Relay(self.d, con, ws, now).purge()

    async def maintenance(self, interval=60):
        while True:
            await asyncio.sleep(interval)
            await run_in_threadpool(self.sweep)

    async def transport(self, request, route):
        """Size cap, strict query and content type: refused before any parsing or lock."""
        method, _path, _auth, cap = ROUTES[route]
        raw = bytearray()
        status = 400 if route == "checkpoint_put" else 413
        declared = request.headers.get("content-length")
        if declared and declared.isdecimal() and int(declared) > cap:
            no("too_large", status)
        async for chunk in request.stream():
            raw.extend(chunk)
            if len(raw) > cap:
                no("too_large", status)
        if len(request.query_params.multi_items()) != len(request.query_params):
            no("malformed", 400)
        query = dict(request.query_params)
        need(not set(query) - QUERY.get(route, set()))
        if method in ("GET", "DELETE"):
            need(not raw)
        elif request.headers.get("content-type", "").split(";")[0].strip() != "application/json":
            no("malformed", 400)
        return bytes(raw), query

    def charge(self, ws, headers):
        """A final publication refused at the transport is charged like any other refusal,
        but only once it passes W(g) authentication and the holder-generation check."""
        with self.d.lock:
            con = self.bridge.connection("write")
            con.execute("BEGIN IMMEDIATE")
            with con:
                now = self.d.clock()
                self.authorize(con, "checkpoint_put", ws, headers, now)
                record_failure(con, ws, integer(headers["orch-holder"]), now)

    async def handle(self, request, route):
        method = ROUTES[route][0]
        params, headers = dict(request.path_params), dict(request.headers)
        try:
            try:
                raw, query = await self.transport(request, route)
            except (Refusal, ValueError, TypeError, KeyError, AttributeError):
                if route == "checkpoint_put":
                    try:
                        P.unhex(params["ws"])
                        await run_in_threadpool(self.preauthorize, route, params["ws"], headers)
                        await run_in_threadpool(self.charge, params["ws"], headers)
                    except (Refusal, sqlite3.Error, ValueError, KeyError):
                        pass  # not authorized or fenced: never charged
                raise
            P.unhex(params["ws"])
            if route == "unpublished_get":
                result = await run_in_threadpool(
                    self.unpublished_read, params["ws"], query, headers
                )
                return JSONResponse(result)
            if route == "unpublished_ack":
                result, wake = await run_in_threadpool(
                    self.unpublished_ack, params["ws"], headers, raw
                )
                if wake and self.d.changed:
                    self.d.changed(*wake)  # notices.unpublished may have changed
                return JSONResponse(result)
            if method == "GET":
                result = await run_in_threadpool(self.read, route, params, query, headers)
                return JSONResponse(result)
            try:
                wsk = await run_in_threadpool(self.preauthorize, route, params["ws"], headers)
                prepared = await run_in_threadpool(self.prepare, route, params["ws"], raw, wsk)
            except sqlite3.Error:
                # Not pre-authorized: nothing is parsed or validated before the transaction's own
                # authorization (review N5).
                prepared = None
            if route == "checkpoint_put":
                pre = prepared[1] if prepared is not None else None
                weight = await run_in_threadpool(self.weigh, params["ws"], pre)
                for attempt in range(3):
                    async with self.gate.enter(params["ws"], weight):
                        try:
                            result, wake = await run_in_threadpool(
                                self.publication,
                                params,
                                headers,
                                raw,
                                prepared,
                                weight if attempt < 2 else None,
                            )
                            break
                        except Reweigh as exc:
                            weight = exc.heads
            else:
                result, wake = await run_in_threadpool(
                    self.write, route, params, query, headers, raw, prepared
                )
            if wake and self.d.changed:
                self.d.changed(*wake)
            return JSONResponse(result)
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


def install(app):
    checkpoints = Checkpoints(app.state.directory, app.state.bridge)
    app.state.checkpoints = checkpoints

    def endpoint(route):
        async def handle(request: Request):
            return await checkpoints.handle(request, route)

        return handle

    for route, (method, path, _auth, _cap) in ROUTES.items():
        app.add_api_route("/v2/" + path, endpoint(route), methods=[method])
