"""GET /v2/relay-info (H12d, P3-D38; protocol §19.1, orch-core orch-v2-host §9.8).

The relay software's reader level for the reader-version handshake, and its maximum publication size.
An **honest-operator statement**, authenticated only by TLS to the origin the host stored: it is never a
security control (a hostile relay can claim any level; its worst case is a refused restore publication,
which the host alarms). A relay without this route answers 404, which a host reads as level 0.

Unauthenticated and the same for every caller: no workspace, person or device data. Throttled per
client address like the public revocation-pair read (§19.4: 60/min per address, 960/min per IPv6 /56),
charged before the answer and never against a session bucket. `Cache-Control: no-store`, so a cache
never serves an old level after a deploy.
"""

from fastapi import Request
from fastapi.responses import JSONResponse

from .checkpoints import AUTH_KINDS
from .directory import MINUTE, Refusal, ipv6_parent

# Level 1 = the restore-evidence parser (AUTH_KINDS) holds "convenience" (F1 §11.4 with the H5c amendment)
# and refuses every unknown `auth` kind. A code constant, deliberately not a setting: an operator cannot
# misreport it, and it changes only with the parser change it names.
RELAY_READER_LEVEL = 1
if RELAY_READER_LEVEL >= 1 and "convenience" not in AUTH_KINDS:
    raise RuntimeError("RELAY_READER_LEVEL 1 requires 'convenience' in checkpoints.AUTH_KINDS")
RELAY_INFO_READ = 60  # per canonical client address (/64 for IPv6) per minute
RELAY_INFO_READ_PARENT = 960  # per IPv6 /56 per minute
NO_STORE = {"Cache-Control": "no-store"}


def answer(caps):
    return {"v": 1, "reader": RELAY_READER_LEVEL, "max_publication_bytes": caps.max_publication}


def install(app):
    directory, checkpoints = app.state.directory, app.state.checkpoints

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
        return JSONResponse(answer(checkpoints.caps), headers=NO_STORE)

    app.add_api_route("/v2/relay-info", relay_info, methods=["GET"])
