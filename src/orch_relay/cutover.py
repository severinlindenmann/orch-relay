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

After `cut_over` the gate refuses with 403 `cut_over` (details: `drain_until_ms`, `drained`): bridge and pairing POSTs,
push registration and push sends at once; reads of the bridge mailbox and the host hold/poll until `drain_until_ms`;
everything once purged. Push unregistration stays allowed (cleanup). Fail closed: a row that does not parse refuses.
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
STATUS = {"cut_over": 403, "other_hub": 403, "not_allowed": 403, "not_eligible": 403}


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


def gate(con, ws, now, write):
    """Refuse a direct-path use of a cut-over workspace (called inside the caller's transaction). `write` is True for
    anything that adds to the mailbox or registers a push target; reads pass until the drain window ends."""
    row = held(con, ws)
    if row is None or row["state"] != "cut_over":
        return
    drained = row["purged_ms"] is not None or now >= row["drain_until_ms"]
    if write or drained:
        refuse("cut_over", drain_until_ms=row["drain_until_ms"], drained=drained)


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
                    return view(held(con, ws))
                # A change is the workspace's own act: its session (WSK), never a device or a hub.
                if session["kind"] != "workspace" or session["subject_id"] != ws:
                    refuse("not_eligible")
                if not con.execute(
                    "SELECT 1 FROM workspaces WHERE workspace_id=?", (ws,)
                ).fetchone():
                    refuse("not_eligible")
                if method == "DELETE":
                    _empty(raw)
                    con.execute("DELETE FROM workspace_cutover WHERE workspace_id=?", (ws,))
                    return {"state": "direct"}
                hub, state = _body(raw)
                row = held(con, ws)
                if state == "cut_over":
                    _promote(con, ws, hub, "workspace", now, self.window_ms)
                elif row is not None and row["state"] == "cut_over":
                    # Naming a hub never weakens a cut-over; only DELETE reverses it.
                    refuse("malformed")
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
        _empty(raw)
        if method == "DELETE":
            refuse("not_allowed")  # a hub never reverses a cut-over
        with d.lock:
            con = d.connection("write")
            con.execute("BEGIN IMMEDIATE")
            with con:
                now = d.clock()
                row = held(con, ws)
                if row is None or row["hub_id"] != hub:
                    refuse("other_hub")
                if method == "PUT":
                    _promote(con, ws, hub, "hub", now, self.window_ms)
                    row = held(con, ws)
                return view(row)


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


__all__ = ["Cutover", "gate", "install", "purge_due"]
