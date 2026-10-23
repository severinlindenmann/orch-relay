"""GET /v2/relay-info (H12d, P3-D38; protocol §19.1, orch-core orch-v2-host §9.8).

The relay software's reader level for the reader-version handshake, and its maximum publication size.
An **honest-operator statement**, authenticated only by TLS to the origin the host stored: it is never a
security control (a hostile relay can claim any level; its worst case is a refused restore publication,
which the host alarms and which stays held, blocking later publications of that workspace until the operator
resolves it: availability only). A relay without this route answers 404, which a host reads as level 0.

Unauthenticated and the same for every caller: no workspace, person or device data. Throttled per
client address like the public revocation-pair read (§19.4: 60/min per address, 960/min per IPv6 /56),
charged before the answer and never against a session bucket. `Cache-Control: no-store`, so a cache
never serves an old level after a deploy.
"""

import os
import re

from fastapi import Request
from fastapi.responses import JSONResponse

from .common import MINUTE, Refusal, ipv6_parent

# A code constant, deliberately not a setting: an operator cannot misreport it.
RELAY_READER_LEVEL = 1
MAX_PUBLICATION = 16 * 1024 * 1024
STAGE_CAP = 64 * 1024 * 1024


def max_publication(env):
    """ORCH_RELAY_MAX_PUBLICATION_BYTES: a decimal integer in 1..STAGE_CAP, validated at start-up."""
    raw = env.get("ORCH_RELAY_MAX_PUBLICATION_BYTES", MAX_PUBLICATION)
    if not (type(raw) is int or (isinstance(raw, str) and re.fullmatch(r"[0-9]+", raw))):
        raise ValueError("ORCH_RELAY_MAX_PUBLICATION_BYTES must be a decimal integer")
    value = int(raw)
    if not 1 <= value <= STAGE_CAP:
        raise ValueError(f"ORCH_RELAY_MAX_PUBLICATION_BYTES must be in 1..{STAGE_CAP}")
    return value


RELAY_INFO_READ = 60  # per canonical client address (/64 for IPv6) per minute
RELAY_INFO_READ_PARENT = 960  # per IPv6 /56 per minute
NO_STORE = {"Cache-Control": "no-store"}


def answer(max_bytes):
    return {"v": 1, "reader": RELAY_READER_LEVEL, "max_publication_bytes": max_bytes}


def install(app):
    directory = app.state.core
    max_bytes = max_publication(os.environ)

    def relay_info(request: Request):  # sync: FastAPI runs it in the thread pool (Directory.budget)
        if request.query_params:
            return JSONResponse({"error": "malformed"}, status_code=400, headers=NO_STORE)
        address = directory.client_address(
            request.client.host if request.client else "unknown", dict(request.headers)
        )
        windows = [("relay-info", address, RELAY_INFO_READ)]
        parent = ipv6_parent(address)
        if parent:
            windows.append(("relay-info-parent", parent, RELAY_INFO_READ_PARENT))
        now = directory.clock()
        try:
            with directory.budget:  # check every window, then charge every window
                for charge in (False, True):
                    for purpose, identity, cap in windows:
                        directory.rate(purpose, identity, MINUTE, cap, now, charge)
        except Refusal as e:
            return JSONResponse(
                {"error": e.code},
                status_code=e.status,
                headers={**NO_STORE, "Retry-After": str(e.retry or 1)},
            )
        return JSONResponse(answer(max_bytes), headers=NO_STORE)

    app.add_api_route("/v2/relay-info", relay_info, methods=["GET"])
