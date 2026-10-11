"""Signed checkpoints, genesis pins, staging and restore transitions (protocol-v2 §19.8).

P3-D12/D13/D18-D25 on SQLite. ref/checkpoints.py is the executable model; the production
relay replays the same vectors (tests/test_checkpoint_vectors.py). Every request is authorized
read-only before it takes the directory lock or a write transaction (G3 review 3); reads never
take the lock at all. A refused write leaves the database unchanged; only a charged refusal of a
final publication records its failure row (protocol-v2 §19.8 failure budget).
"""

import asyncio
import hashlib
import os
import re
import sqlite3
from datetime import datetime

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from . import proto as P
from .bridge import refuse
from .directory import Refusal, integer

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
STAGE_SETS = 2
BASELINES = 16
FAILURE_BUDGET = 16  # charged refusals per holder generation per rolling hour
WORKSPACE_FAILURE_CEILING = 48  # charged refusals per workspace per rolling hour
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


def record_failure(con, ws, gen, now):
    """Charge one refusal, unless the window is already full (review L1): rows never grow with
    the request rate, and a full window refuses with 429 before any work either way."""
    con.execute(
        "DELETE FROM checkpoint_failures WHERE workspace_id=? AND at_ms<=?", (ws, now - HOUR)
    )
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
    """log_nodes of one workspace log, with a per-request cache of the nodes it touched."""

    def __init__(self, con, ws, log):
        self.con, self.ws, self.log, self.cache = con, ws, log, {}

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
        executemany: the directory lock is held for O(heads) work with few SQL round trips."""
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
        self.con.executemany("INSERT INTO log_nodes VALUES (?,?,?,?,?,?,?)", rows)
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


def precheck_publication(body, wsk_pub):
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


class Relay:
    """One workspace's checkpoint state inside a caller-owned transaction."""

    def __init__(self, directory, con, ws, now):
        self.d, self.con, self.ws, self.now = directory, con, ws, now
        self.nodes = {}
        self.wake = set()
        self.visits = 0  # staged descriptors folded by this publication (work bound, review R1)

    def log(self, name):
        if name not in self.nodes:
            self.nodes[name] = Nodes(self.con, self.ws, name)
        return self.nodes[name]

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

    def revoked(self, device):
        return self.con.execute("SELECT 1 FROM revocations WHERE device_id=?", (device,)).fetchone()

    def owner(self, w, cert, at_ms, extra=()):
        # Every revocation the relay holds, and evidence in this payload, refuses the signer.
        # A malformed certificate fails verify_cert below; a database error propagates (fail
        # closed, review L2): the relay's revocation lookup is never skipped.
        try:
            device = cert["o"]["device_id"]
        except (TypeError, KeyError):
            device = None
        revoked = set()
        if isinstance(device, str) and (device in extra or self.revoked(device)):
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

    def proof_pages(self, stage, kind, log, start, used):
        # Descriptors are grouped by (kind, log) once per publication (review R1): scanning the
        # manifest per log cost tickets x pages under the global lock.
        current = {k: start[k] for k in ("seq", "head", "acc")}
        for d in stage["groups"].get((kind, log), ()):
            self.visits += 1
            p = stage["pages"][d["i"]]
            need(
                p["after_seq"] == current["seq"] and p["from_acc"] == current["acc"],
                "chain_diverged",
                409,
            )
            current = self.log(log).extend(current, p["heads"])
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
        window = self.con.execute(
            "SELECT count(*), coalesce(sum(gen=?),0) FROM checkpoint_failures "
            "WHERE workspace_id=? AND at_ms>?",
            (gen, self.ws, self.now - HOUR),
        ).fetchone()
        need(
            window[1] < FAILURE_BUDGET and window[0] < WORKSPACE_FAILURE_CEILING,
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
        stage = {
            "manifest": P.parse_json(
                self.staged("SELECT manifest FROM checkpoint_staging", key).fetchone()[0]
            ),
            "pages": {
                i: P.parse_json(b)
                for i, b in self.staged("SELECT i,body FROM checkpoint_staging_pages", key)
            },
            "groups": {},
        }
        for d in stage["manifest"]["pages"]:
            stage["groups"].setdefault((d["kind"], d["log"]), []).append(d)  # manifest order
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
        con.execute(
            "DELETE FROM checkpoint_staging WHERE workspace_id=? AND source=? AND target=?",
            (self.ws, *key),
        )
        return result

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

    def known_holder(self, device):
        """(person, key or None) the relay binds to a device; None for a wholly unknown device.

        The first accepted binding wins: a held revocation's person comes before the live
        registry (§19.8 R4, review A/B). The reference's verified-signer binding needs no table
        here: a restore signer is a current list member, list members are registered devices,
        and devices are never deleted (review L3)."""
        row = self.con.execute(
            "SELECT person_id FROM revocations WHERE device_id=?", (device,)
        ).fetchone()
        if row is None:
            row = self.con.execute(
                "SELECT person_id FROM devices WHERE device_id=?", (device,)
            ).fetchone()
        if row is None:
            return None
        key = self.con.execute(
            "SELECT pk_pub FROM accounts WHERE person_id=?", (row[0],)
        ).fetchone()
        return row[0], key[0] if key else None

    def evidence(self, line, log):
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
            device = rev["ok"]["device_id"]
            holder = self.known_holder(device)
            need(
                holder is None
                or (rev["ok"]["person_id"] == holder[0] and holder[1] in (None, item["pk_pub"])),
                "restore_invalid",
                409,
            )
            need(device not in listed, "restore_invalid", 409)
            order.append(device)
            listed[device] = item
        need(order == sorted(order), "restore_invalid", 409)
        return listed

    def coverage(self, listed, signer, log):
        if log != "workspace":
            return
        held = {
            r[0]: r[1]
            for r in self.con.execute(
                "SELECT device_id,reason FROM revocations WHERE device_id IN ("
                "SELECT device_id FROM ever_devices WHERE workspace_id=?1 UNION "
                "SELECT device_id FROM checkpoint_ever_devices WHERE workspace_id=?1)",
                (self.ws,),
            )
        }
        for device in {*listed, signer} - set(held):
            row = self.con.execute(
                "SELECT reason FROM revocations WHERE device_id=?", (device,)
            ).fetchone()
            if row:
                held[device] = row[0]
        missing = sorted(
            d
            for d, reason in held.items()
            if d not in listed
            or STRENGTH[listed[d]["revocation"]["o"]["reason"]] < STRENGTH[reason]
        )
        need(not missing, "restore_missing_revocation", 409, devices=missing)

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
        cert = self.owner_policy(w, bundle, listed)
        self.coverage(listed, cert["device_id"], log)
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
                first = stage["pages"][pages[0]["i"]]
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
        result = nodes.extend(retained, [event_head(line)])
        need(entries(target).get(log) == result, "restore_invalid", 409)
        self.apply_evidence(listed)
        con, ws = self.con, self.ws
        for device in {*listed, cert["device_id"]}:
            con.execute("INSERT OR IGNORE INTO checkpoint_ever_devices VALUES (?,?)", (ws, device))
        transition = {
            "restore_id": line["id"],
            "source_hash": body["source_hash"],
            "target_hash": checkpoint_hash(target),
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

    def apply_evidence(self, listed):
        """§19.5 intake in this transaction. A wholly unknown device is registered from its
        self-certified evidence first, so the registry never contradicts the binding (review
        A/B); a held revocation is never deleted, only upgraded (§6.2 "no un-revoke")."""
        con = self.con
        for device, item in listed.items():
            rev, cert = item["revocation"], item["device_cert"]
            if not con.execute("SELECT 1 FROM devices WHERE device_id=?", (device,)).fetchone():
                person = cert["o"]["person_id"]
                if not con.execute(
                    "SELECT 1 FROM accounts WHERE person_id=?", (person,)
                ).fetchone():
                    con.execute(
                        "INSERT INTO accounts VALUES (?,?,?)", (person, item["pk_pub"], self.now)
                    )
                    con.execute("INSERT INTO evidence_persons VALUES (?)", (person,))
                self.d.store_device(con, cert)
            self.d.revoke(con, rev, self.now)
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
}
QUERY = {
    "checkpoint_get": {"hash"},
    "transitions": {"after_n", "to", "limit"},
    "proof": {"log", "from", "to", "limit"},
    "baseline_delete": {"offer_id"},
}


class Checkpoints:
    def __init__(self, directory, bridge):
        self.d, self.bridge = directory, bridge
        self.global_stage_cap = int(
            os.environ.get("ORCH_RELAY_GLOBAL_STAGE_BYTES", GLOBAL_STAGE_CAP)
        )

    def authorize(self, con, route, ws, headers, now):
        """The route's principal: authenticated, authorized for this workspace, fenced."""
        d = self.d
        session = d.authenticate(con, headers, now)
        auth = ROUTES[route][2]
        if auth == "R" or (auth == "WD" and session["kind"] == "device"):
            d.workspace_access(con, session, ws)
            return session
        d.workspace_access(con, session, ws, write=True)
        if route == "checkpoint_put" and "orch-holder" not in headers:
            no("malformed", 400)  # the generation is required; never charged
        d.fence(con, headers, ws, now)
        return session

    def preauthorize(self, route, ws, headers):
        """Read-only, before any lock, write transaction or failure window (G3 review 3)."""
        con = self.bridge.connection("read")
        con.execute("BEGIN")
        try:
            self.authorize(con, route, ws, headers, self.d.clock())
            row = con.execute(
                "SELECT wsk_pub FROM workspaces WHERE workspace_id=?", (ws,)
            ).fetchone()
            return row[0] if row else None
        finally:
            con.rollback()

    @staticmethod
    def prepare(route, raw, wsk_pub):
        """Parse and validate what needs no database state, after authorization and before the
        lock (review G2). A body that does not parse is refused here, except a final
        publication's, which is charged in the transaction like every refusal after W(g)."""
        if route == "checkpoint_put":
            return None, precheck_publication(raw, wsk_pub) if wsk_pub else None
        body = P.parse_json(raw) if raw else None
        if route == "staging_page":
            return body, precheck_page(body, raw)
        if route == "staging_manifest":
            return body, precheck_manifest(body, raw)
        return body, None

    def read(self, route, params, query, headers):
        con = self.bridge.connection("query")
        con.execute("PRAGMA query_only=ON")
        con.execute("BEGIN")
        try:
            now = self.d.clock()
            self.authorize(con, route, params["ws"], headers, now)
            return Relay(self.d, con, params["ws"], now).read(route, query)
        finally:
            con.rollback()

    def write(self, route, params, query, headers, raw, prepared=None):
        body, pre = prepared if prepared is not None else (None, None)
        if prepared is None and route != "checkpoint_put":
            body = P.parse_json(raw) if raw else None
        d = self.d
        with d.lock:
            con = self.bridge.connection("write")
            con.execute("BEGIN IMMEDIATE")
            refused = None
            with con:
                now = d.clock()
                ws = params["ws"]
                session = self.authorize(con, route, ws, headers, now)
                relay = Relay(d, con, ws, now)
                if route == "checkpoint_put":
                    gen = integer(headers["orch-holder"])
                    con.execute("SAVEPOINT publication")
                    try:
                        try:
                            result = relay.publish(raw, gen, pre)
                        except (KeyError, TypeError, ValueError, AttributeError, IndexError) as exc:
                            raise refusal("malformed", 400) from exc
                        con.execute("RELEASE publication")
                    except Refusal as exc:
                        con.execute("ROLLBACK TO publication")
                        con.execute("RELEASE publication")
                        relay.wake.clear()
                        if exc.code != "quota_exceeded":
                            record_failure(con, ws, gen, now)  # after W(g) and fencing (review 3)
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
            if method == "GET":
                result = await run_in_threadpool(self.read, route, params, query, headers)
                return JSONResponse(result)
            try:
                wsk = await run_in_threadpool(self.preauthorize, route, params["ws"], headers)
            except sqlite3.Error:
                wsk = None  # the transaction authorizes and validates on its own
            prepared = await run_in_threadpool(self.prepare, route, raw, wsk)
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
