"""Per-workspace cut-over to a hub (orch-relay E3, orch-core#896; spec orch-v2-hub.md, core side C10 #878).

Until the H5 cut-over a workspace keeps its direct (v2) relay path untouched. A workspace that joined a hub is
switched with one row in `workspace_cutover`:

  pending    the workspace said (workspace session = its WSK, the owner-delegated key) which hub it joins
  cut_over   the direct path is closed; the mailbox drains for DRAIN_S (default 7 days), then is purged

Routes (PROPOSED here, they need a contract entry; see the PR):
  PUT    /v2/workspaces/{ws}/cutover          workspace session, {v: 2, hub_id, state: "pending" | "cut_over"}
  DELETE /v2/workspaces/{ws}/cutover          workspace session only: back to the direct path (reversal)
  GET    /v2/workspaces/{ws}/cutover          workspace session or a member device: the state
  PUT    /v2/hubs/{hub}/workspaces/{ws}/cutover   hub (§10.8 signed, empty body): `pending` -> `cut_over`, only when the
                                                  workspace named exactly this hub
  GET    /v2/hubs/{hub}/workspaces/{ws}/cutover   the state, only for a workspace that named this hub
  DELETE /v2/hubs/{hub}/workspaces/{ws}/cutover   always 403 `not_allowed`: a hub never reverses

A hub can never create, redirect or reverse a cut-over by itself: it can only confirm what the workspace named. A
workspace that is unknown, not named, or named for another hub all answer the hub `other_hub` (indistinguishable).

After `cut_over` ONE gate (`guard`, one policy table `CLASS`, every route named in `NAMES`) refuses with 403 `cut_over`
(details: `drain_until_ms`, `drained`) EVERY per-workspace direct route, except an explicit allow-list: the mailbox
reads (bridge GET, pair GET, host hold/poll) until `drain_until_ms`, push unregistration, and the cut-over routes
themselves. At the end of the drain the direct data (mailbox, replay records, push registrations, hooks, cert
requests, Drop objects and blobs) is purged. Fail closed: an unnamed route refuses. A guard test lists every
registered route and requires each to be named. Anonymous pair requests are answered as for an unknown workspace.
"""

import os
import re
import sqlite3

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from . import proto as P
from .directory import Refusal

DAY_MS = 86_400_000
DRAIN_S = 7 * 86_400
BODY_CAP = 1024
_HEX32 = re.compile(r"[0-9a-f]{32}")
STATES = ("pending", "cut_over")
PENDING_TTL_MS = DAY_MS  # a `pending` naming that the hub does not confirm within 24 h lapses
STATUS = {
    "unknown_hub": 403,
    "cut_over": 403,
    "other_hub": 403,
    "not_allowed": 403,
    "not_eligible": 403,
}


def refuse(code, **details):
    error = Refusal(code)
    error.status = STATUS.get(code, error.status)
    error.details = details
    raise error


def drain_ms(env=os.environ):
    try:
        seconds = int(env.get("ORCH_RELAY_CUTOVER_DRAIN_S", DRAIN_S))
    except ValueError:
        return DRAIN_S * 1000
    return max(0, seconds) * 1000


def held(con, ws):
    return con.execute("SELECT * FROM workspace_cutover WHERE workspace_id=?", (ws,)).fetchone()


def lapsed(row, now):
    """A `pending` naming the hub never confirmed within PENDING_TTL_MS is as good as absent."""
    return row["state"] == "pending" and now >= row["requested_ms"] + PENDING_TTL_MS


def live(con, ws, now):
    row = held(con, ws)
    return None if row is None or lapsed(row, now) else row


# --- the one policy table ----------------------------------------------------------------------------------------------
# closed: refused from the cut-over on. drain: allowed until the drain window ends. open: never refused.
# exempt: not a per-workspace route (no workspace to cut over); listed so a new route cannot slip past the guard test.
CLASS = {
    "bridge_get": "drain",
    "bridge_post": "closed",
    "pair_get": "drain",
    "pair_post": "closed",
    "host_hold": "drain",
    "host_poll": "drain",
    "cert_requests": "closed",
    "cert_request": "closed",
    "cert_challenge": "closed",
    "cert_rejection": "closed",
    "hooks_register": "closed",
    "hooks_revoke": "closed",
    "hooks_fetch": "closed",
    "push_register": "closed",
    "push_unregister": "open",
    "push_send": "closed",
    "membership": "closed",
    "members": "closed",
    "grants": "closed",
    "card_keys": "closed",
    "card_key": "closed",
    "card_put": "closed",
    "card_get": "closed",
    "checkpoint": "closed",  # every checkpoint route (genesis, staging, baselines, checkpoint, transitions, proof, unpublished)
    "drop": "closed",  # every Drop route (put, list, descriptors, descriptor, wraps, blob, retire)
    "cutover": "open",
    "cutover_hub": "open",
    "exempt": "exempt",
}
NAMES = {
    ("GET", "/v2/workspaces/{ws}/bridge/{rid}"): "bridge_get",
    ("POST", "/v2/workspaces/{ws}/bridge/{rid}"): "bridge_post",
    ("GET", "/v2/workspaces/{ws}/pair/{offer}/{rid}"): "pair_get",
    ("POST", "/v2/workspaces/{ws}/pair/{offer}/{rid}"): "pair_post",
    ("POST", "/v2/workspaces/{ws}/host/hold"): "host_hold",
    ("GET", "/v2/workspaces/{ws}/host/poll"): "host_poll",
    ("GET", "/v2/persons/{person}/cert-requests"): "cert_requests",
    ("POST", "/v2/persons/{person}/cert-requests"): "cert_requests",
    ("GET", "/v2/cert-requests/{ident}"): "cert_request",
    ("POST", "/v2/cert-requests/{ident}/challenge"): "cert_challenge",
    ("POST", "/v2/cert-requests/{ident}/rejection"): "cert_rejection",
    ("POST", "/v2/workspaces/{ws}/hooks"): "hooks_register",
    ("POST", "/v2/workspaces/{ws}/hooks/revoke"): "hooks_revoke",
    ("POST", "/v2/workspaces/{ws}/hooks/fetch"): "hooks_fetch",
    (
        "POST",
        "/h/{hook_id}",
    ): "exempt",  # anonymous doorbell: no workspace known; inert once fetch is closed and purged
    ("POST", "/v2/push/register"): "push_register",
    ("POST", "/v2/push/unregister"): "push_unregister",
    ("POST", "/v2/workspaces/{ws}/push"): "push_send",
    ("PUT", "/v2/workspaces/{ident}/membership"): "membership",
    ("GET", "/v2/workspaces/{ident}/members"): "members",
    ("GET", "/v2/workspaces/{ident}/grants"): "grants",
    ("PUT", "/v2/workspaces/{ident}/card-keys"): "card_keys",
    ("GET", "/v2/workspaces/{ident}/card-key"): "card_key",
    ("PUT", "/v2/workspaces/{ident}/card"): "card_put",
    ("GET", "/v2/workspaces/{ident}/card"): "card_get",
    ("GET", "/v2/workspaces/{ws}/cutover"): "cutover",
    ("PUT", "/v2/workspaces/{ws}/cutover"): "cutover",
    ("DELETE", "/v2/workspaces/{ws}/cutover"): "cutover",
}
for _m in ("GET", "PUT", "DELETE"):
    NAMES[(_m, "/v2/hubs/{hub_id_text}/workspaces/{ws}/cutover")] = "cutover_hub"
# checkpoints (checkpoints.ROUTES) and Drop (drop.ROUTES) are named by prefix in `name_of`.
EXEMPT_PREFIXES = (
    "/healthz",
    "/v2/relay-info",
    "/v2/hubs",  # hub accounts, E2 hub-phone routes: per hub, not per workspace
    "/v2/hub-channels",  # E5: a channel's own mailbox read, per hub and channel
    "/v2/session/",
    "/v2/accounts",
    "/v2/devices/",
    "/v2/revocations",
    "/v2/persons/{ident}/revocations",
    "/docs",
    "/redoc",
    "/openapi.json",
)


def name_of(method, path):
    """The policy name of a registered route, or None when it is unnamed (the guard test fails on None)."""
    if (method, path) in NAMES:
        return NAMES[(method, path)]
    if path.startswith("/v2/workspaces/{ws}/") and method in ("GET", "PUT", "POST", "DELETE"):
        tail = path.split("/")[4:]
        if tail and tail[0] in (
            "genesis",
            "staging",
            "baselines",
            "checkpoint",
            "transitions",
            "proof",
            "unpublished",
        ):
            return "checkpoint"
    if path.startswith("/v2/drop/"):
        return "drop"
    if any(path == p or path.startswith(p) for p in EXEMPT_PREFIXES):
        return "exempt"
    return None


def guard(con, ws, now, name, anonymous=False):
    """THE gate. Every per-workspace handler calls it with its policy name once it knows the workspace (inside its own
    transaction, after authentication). An unknown name refuses (fail closed). `anonymous`: the caller is not
    authenticated (a first pair POST or GET): answer as for a workspace that does not exist, so nothing leaks."""
    cls = CLASS.get(name)
    if cls is None:
        refuse("cut_over")
    row = held(con, ws)
    if row is None or row["state"] != "cut_over" or cls in ("open", "exempt"):
        return
    drained = row["purged_ms"] is not None or now >= row["drain_until_ms"]
    if cls == "closed" or drained:
        if anonymous:
            error = Refusal("unknown_workspace")
            error.status = 401
            raise error
        refuse("cut_over", drain_until_ms=row["drain_until_ms"], drained=drained)


def gate(con, ws, now, write):  # kept for callers that only know read or write
    guard(con, ws, now, "bridge_post" if write else "bridge_get")


def purge_due(con, now):
    """Delete the direct-path data of every workspace whose drain window ended (idempotent; called from the bridge
    sweep). Returns the number of workspaces purged."""
    due = con.execute(
        "SELECT workspace_id FROM workspace_cutover WHERE state='cut_over' AND purged_ms IS NULL "
        "AND drain_until_ms<=?",
        (now,),
    ).fetchall()
    for (ws,) in due:
        con.execute("DELETE FROM bridge_msgs WHERE workspace_id=?", (ws,))
        con.execute(
            "DELETE FROM rid_seen WHERE workspace_id=?", (ws,)
        )  # rid_chunks follows (cascade)
        con.execute("DELETE FROM request_mailboxes WHERE workspace_id=?", (ws,))
        con.execute("DELETE FROM push_subscriptions WHERE workspace_id=?", (ws,))
        con.execute("DELETE FROM hooks WHERE workspace_id=?", (ws,))
        con.execute("DELETE FROM cert_requests WHERE workspace_id=?", (ws,))
        # Drop objects and blobs are released by the Drop sweep (drop_life.sweep_cutover), which owns the usage books.
        con.execute("UPDATE workspace_cutover SET purged_ms=? WHERE workspace_id=?", (now, ws))
    return len(due)


def view(row):
    if row is None:
        return {"state": "direct"}
    return {
        "state": row["state"],
        "hub_id": row["hub_id"],
        "cut_over_ms": row["cut_over_ms"],
        "drain_until_ms": row["drain_until_ms"],
        "purged": row["purged_ms"] is not None,
    }


def _body(raw):
    try:
        o = P.parse_json(raw)
    except ValueError:
        refuse("malformed")
    if type(o) is not dict or set(o) != {"v", "hub_id", "state"} or o["v"] != 2:
        refuse("malformed")
    if (
        type(o["hub_id"]) is not str
        or not _HEX32.fullmatch(o["hub_id"])
        or o["state"] not in STATES
    ):
        refuse("malformed")
    return o["hub_id"], o["state"]


def _promote(con, ws, hub, by, now, window):
    """pending/cut_over -> cut_over for `hub`. An existing cut-over keeps its times (idempotent)."""
    row = held(con, ws)
    if row is not None and row["state"] == "cut_over":
        con.execute(
            "UPDATE workspace_cutover SET hub_id=?, set_by=? WHERE workspace_id=?", (hub, by, ws)
        )
    else:
        con.execute(
            "INSERT INTO workspace_cutover(workspace_id, hub_id, state, set_by, requested_ms, cut_over_ms, "
            "drain_until_ms) VALUES (?,?, 'cut_over', ?, ?, ?, ?) ON CONFLICT(workspace_id) DO UPDATE SET "
            "hub_id=excluded.hub_id, state='cut_over', set_by=excluded.set_by, cut_over_ms=excluded.cut_over_ms, "
            "drain_until_ms=excluded.drain_until_ms",
            (ws, hub, by, now, now, now + window),
        )


class Cutover:
    def __init__(self, directory, window_ms):
        self.d = directory
        self.window_ms = window_ms

    # --- the workspace's own requests -------------------------------------------------------------

    def workspace(self, method, ws, headers, raw):
        d = self.d
        with d.lock:
            con = d.connection("write")
            con.execute("BEGIN IMMEDIATE")
            with con:
                now = d.clock()
                session = d.authenticate(con, headers, now)
                d.throttle(session, now)
                if method == "GET":
                    _empty(raw)
                    d.workspace_access(con, session, ws)
                    guard(con, ws, now, "cutover")
                    return view(live(con, ws, now))
                # A change is the workspace's own act: its session (WSK), never a device or a hub.
                if session["kind"] != "workspace" or session["subject_id"] != ws:
                    refuse("not_eligible")
                if not con.execute(
                    "SELECT 1 FROM workspaces WHERE workspace_id=?", (ws,)
                ).fetchone():
                    refuse("not_eligible")
                # L2-E3-1: the same holder fence as every other durable workspace write (409 `fenced`).
                d.fence(con, headers, ws, now)
                if method == "DELETE":
                    _empty(raw)
                    con.execute("DELETE FROM workspace_cutover WHERE workspace_id=?", (ws,))
                    return {"state": "direct"}
                hub, state = _body(raw)
                if not con.execute("SELECT 1 FROM hub_accounts WHERE hub_id=?", (hub,)).fetchone():
                    refuse(
                        "unknown_hub"
                    )  # L2-E3-4: only a hub registered with this relay can be named
                row = held(con, ws)
                if state == "cut_over":
                    _promote(con, ws, hub, "workspace", now, self.window_ms)
                elif row is not None and row["state"] == "cut_over":
                    # Naming a hub never weakens a cut-over; only DELETE reverses it (contract §10.8.3).
                    refuse("cut_over", drain_until_ms=row["drain_until_ms"], drained=False)
                else:
                    con.execute(
                        "INSERT INTO workspace_cutover(workspace_id, hub_id, state, set_by, requested_ms) "
                        "VALUES (?,?, 'pending', 'workspace', ?) ON CONFLICT(workspace_id) DO UPDATE SET "
                        "hub_id=excluded.hub_id, requested_ms=excluded.requested_ms",
                        (ws, hub, now),
                    )
                return view(held(con, ws))

    # --- the hub's requests (already authenticated by hub_request_auth) ----------------------------

    def hub(self, hub, method, ws, raw):
        d = self.d
        if method == "PUT":
            _hub_body(
                raw
            )  # {v: 2, state: "cut_over"} exactly (contract §10.8.3); the hub is the signer
        else:
            _empty(raw)
        if method == "DELETE":
            refuse("not_allowed")  # a hub never reverses a cut-over
        with d.lock:
            con = d.connection("write")
            con.execute("BEGIN IMMEDIATE")
            with con:
                now = d.clock()
                row = live(con, ws, now)
                if row is None or row["hub_id"] != hub:
                    refuse("other_hub")
                if method == "PUT":
                    _promote(con, ws, hub, "hub", now, self.window_ms)
                    row = held(con, ws)
                return view(row)


def _hub_body(raw):
    try:
        o = P.parse_json(raw)
    except ValueError:
        refuse("malformed")
    if type(o) is not dict or o != {"v": 2, "state": "cut_over"} or type(o["v"]) is not int:
        refuse("malformed")


def match(method, path, raw):
    """The hub-side route table of contract §10.8.3, for the shared vectors: (route, workspace) or a Refusal."""
    m = re.fullmatch(r"/v2/hubs/[^/]*/workspaces/([^/]*)/cutover", path)
    if m is None:
        refuse("not_found")
    if method not in ("GET", "PUT", "DELETE"):
        refuse("not_found")
    if not _HEX32.fullmatch(m.group(1)):
        refuse("malformed")
    if method == "DELETE":
        _empty(raw)
        refuse("not_allowed")
    if method == "PUT":
        _hub_body(raw)
    else:
        _empty(raw)
    return ("cutover_put" if method == "PUT" else "cutover_get"), m.group(1)


def _empty(raw):
    if raw != b"":
        refuse("malformed")


def install(app):
    from .push import error_response, read_body

    d = app.state.directory
    state = Cutover(d, drain_ms())
    app.state.cutover = state

    async def workspace_route(ws: str, request: Request):
        try:
            if not _HEX32.fullmatch(ws) or request.query_params:
                refuse("malformed")
            raw = await read_body(request, BODY_CAP)
            if raw is None:
                refuse("too_large")
            result = await run_in_threadpool(
                state.workspace, request.method, ws, dict(request.headers), bytes(raw)
            )
        except Refusal as error:
            return error_response(error)
        except (ValueError, TypeError, KeyError, sqlite3.DataError):
            return JSONResponse({"error": "malformed"}, status_code=400)
        return JSONResponse(result, headers={"Cache-Control": "no-store"})

    async def hub_route(hub_id_text: str, ws: str, request: Request):
        try:
            hub, raw = await app.state.hub_request_auth(
                request
            )  # §10.8, before anything else is looked at
            if not _HEX32.fullmatch(ws):
                refuse("malformed")
            result = await run_in_threadpool(state.hub, hub, request.method, ws, raw)
        except Refusal as error:
            return error_response(error)
        except (ValueError, TypeError, KeyError, sqlite3.DataError):
            return JSONResponse({"error": "malformed"}, status_code=400)
        return JSONResponse(result, headers={"Cache-Control": "no-store"})

    app.add_api_route(
        "/v2/workspaces/{ws}/cutover", workspace_route, methods=["GET", "PUT", "DELETE"]
    )
    # Registered before E2's `/v2/hubs/{hub}/{tail:path}` catch-all (first match wins).
    app.add_api_route(
        "/v2/hubs/{hub_id_text}/workspaces/{ws}/cutover",
        hub_route,
        methods=["GET", "PUT", "DELETE"],
    )
    return state


__all__ = ["Cutover", "gate", "guard", "install", "match", "purge_due"]
