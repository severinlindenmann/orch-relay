"""Relay accounts of kind `hub` (orch-relay E1; orch-hub contract H0 `docs/protocol.md` §4, §5, §14).

A hub registers one account by presenting its hub card (`hub.card`, signed by `HK_op`, carrying the
`hub.op_cert` signed by `HK_root`). The relay verifies it exactly as the contract's §5 says and keeps it
under `hub_id`, which is derived from `HK_root` and therefore cannot be claimed without that key.

  POST /v2/hubs              the hub card              register, or rotate to a newer card
  POST /v2/hubs/op-revoked   {hk_root_pub, revocation} a root-signed `hub.op_revoked`
  GET  /v2/hubs/{hub_id}     public: the stored card and whether its op cert is revoked

Rules (all fail closed, no secret is stored or logged, ciphertext-only relay rule untouched):
- The relay is real (default) or dev (`ORCH_RELAY_DEV=1`). A real relay refuses `dev: true` objects
  (`dev_refused`); a dev relay refuses `dev: false` (`dev_mismatch`). The marker is the relay's own
  configuration, never a field of the card. An op-cert revocation is never refused for their marker (L2-8).
- Order between cards is the root-signed `op_seq` first (a lower one, or the same one under another
  `cert_id`, is `stale_op_cert` whatever its `card_seq`), `card_seq` only within one op cert (`stale_card`).
  Another `hk_root_pub` under a held `hub_id` cannot occur (the id is derived from the root); it is
  `other_hub` if it ever does. A higher `op_seq` replaces the held card.
- A revocation is permanent. A card whose op cert is revoked is refused (`revoked`); `current()` hides a
  stored card whose op cert was revoked afterwards, so a later authentication step never relies on
  having re-verified the card.

Hub -> relay request authentication is NOT here: the contract has no signing label for it (reported as a
contract gap in the E1 PR). This module only registers, rotates and revokes.

The verification is an independent port of the contract's reference verifier (`orch_hub.contract.hub`),
checked against the shared vectors (`tests/vectors/vectors_hub.json`, V3-D8).
"""

import hashlib
import os
import re
import sqlite3
import threading
from pathlib import Path

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from . import proto as P
from .directory import HOUR, Refusal
from .push import error_response, read_body

HV = 0
CLOCK_SKEW_MS = 300_000
REQUEST_CAP = 16 * 1024
L_OP_CERT = b"orch/v2/hub-op-cert|"
L_OP_REVOKED = b"orch/v2/hub-op-revoked|"
L_CARD = b"orch/v2/hub-card|"
L_HUB_ID = b"orch/v2/id/hub|"
REGISTER_PER_HOUR = 60  # per canonical client address
READ_PER_HOUR = 600
MAX_ACCOUNTS = 1000  # ORCH_RELAY_HUB_ACCOUNTS
MAX_REVOCATIONS_PER_HUB = 64

STATUS = {
    "bad_signature": 401,
    "revoked": 403,
    "dev_refused": 403,
    "dev_mismatch": 403,
    "other_hub": 409,
    "stale_op_cert": 409,
    "stale_card": 409,
    "unknown_hub": 404,
    "not_allowed": 403,
    "quota_exceeded": 429,
}

_URL = re.compile(
    r"https://[a-z0-9.-]{1,253}(:[0-9]{1,5})?|http://(localhost|127\.0\.0\.1|\[::1\])(:[0-9]{1,5})?"
)


def refuse(code, retry=None):
    error = Refusal(code, retry)
    error.status = STATUS.get(code, error.status)
    raise error


def hub_id(root_pub):
    return hashlib.sha256(L_HUB_ID + b"\x02" + root_pub).digest()[:16].hex()


# --- field checks (contract §4.1, §4.2, §5) -------------------------------------------------------


def _hex16(x):
    try:
        P.unhex(x, 16)
        return True
    except ValueError:
        return False


def _pub(x):
    try:
        return P.SUITE.pub_ok(P.unb64u(x, 65))
    except ValueError:
        return False


def _b64u32(x):
    try:
        P.unb64u(x, 32)
        return True
    except ValueError:
        return False


def _int_min(lo):
    return lambda x: type(x) is int and x >= lo


def _bool(x):
    return type(x) is bool


def _relay_url(x):
    return x is None or (type(x) is str and _URL.fullmatch(x) is not None)


FIELDS = {
    "hub.op_cert": {
        "hub_id": _hex16,
        "cert_id": _hex16,
        "op_seq": _int_min(1),
        "hk_op_pub": _pub,
        "issued_ms": _int_min(0),
        "expires_ms": _int_min(1),
        "dev": _bool,
    },
    "hub.op_revoked": {
        "hub_id": _hex16,
        "cert_id": _hex16,
        "revoked_ms": _int_min(0),
        "dev": _bool,
    },
    "hub.card": {
        "hub_id": _hex16,
        "hk_root_pub": _pub,
        "hxk_pub": _pub,
        "relay_url": _relay_url,
        "tls_spki_sha256": _b64u32,
        "card_seq": _int_min(1),
        "issued_ms": _int_min(0),
        "dev": _bool,
    },
}


def _envelope(signed, kind, extra=()):
    if type(signed) is not dict or set(signed) != {"o", "sig", *extra}:
        refuse("malformed")
    o = signed["o"]
    if type(o) is not dict or o.get("kind") != kind:
        refuse("malformed")
    if type(o.get("suite")) is not int or o["suite"] != 2:
        refuse("wrong_suite")
    if type(o.get("v")) is not int or o["v"] != 2 or type(o.get("hv")) is not int or o["hv"] != HV:
        refuse("malformed")
    try:
        P.cj(signed)
    except ValueError:
        refuse("malformed")
    return o


def _signature(signed, label, pub):
    try:
        sig = P.unb64u(signed["sig"], 64)
        message = label + P.cj(signed["o"])
    except ValueError:
        refuse("malformed")
    if not P.SUITE.verify(pub, sig, message):
        refuse("bad_signature")


def _fields(o, kind):
    spec = FIELDS[kind]
    if set(o) != {"v", "suite", "kind", "hv", *spec}:
        refuse("malformed")
    for name, ok in spec.items():
        if not ok(o[name]):
            refuse("malformed")


def _dev(o, dev_mode):
    if o["dev"] is True and not dev_mode:
        refuse("dev_refused")
    if o["dev"] is False and dev_mode:
        refuse("dev_mismatch")


def _root_key(root_text):
    if not _pub(root_text):
        refuse("malformed")
    return P.unb64u(root_text, 65)


def verify_op_cert(signed, root, now, dev_mode, revoked):
    o = _envelope(signed, "hub.op_cert")
    _signature(signed, L_OP_CERT, root)
    _fields(o, "hub.op_cert")
    if o["hub_id"] != hub_id(root):
        refuse("other_hub")
    _dev(o, dev_mode)
    if o["expires_ms"] <= o["issued_ms"] or o["issued_ms"] > now + CLOCK_SKEW_MS:
        refuse("cert_invalid")
    if now >= o["expires_ms"]:
        refuse("cert_expired")
    if o["cert_id"] in revoked:
        refuse("revoked")
    return o


def verify_op_revoked(signed, root):
    """No dev-marker check (L2-8): a revocation only removes authority."""
    o = _envelope(signed, "hub.op_revoked")
    _signature(signed, L_OP_REVOKED, root)
    _fields(o, "hub.op_revoked")
    if o["hub_id"] != hub_id(root):
        refuse("other_hub")
    return o


def verify_card(card, now, dev_mode, revoked=frozenset(), held=None):
    """Contract §5 steps 1-7. `held` is the stored card (a signed card dict) or None. Returns
    (card object, op cert object, root key bytes)."""
    o = _envelope(card, "hub.card", ("op_cert",))
    root = _root_key(o.get("hk_root_pub"))
    if o.get("hub_id") != hub_id(root):
        refuse("hub_id_mismatch")
    op = verify_op_cert(card["op_cert"], root, now, dev_mode, revoked)
    _signature(card, L_CARD, P.unb64u(op["hk_op_pub"], 65))
    _fields(o, "hub.card")
    _dev(o, dev_mode)
    if o["issued_ms"] > now + CLOCK_SKEW_MS:
        refuse("cert_invalid")
    if held is not None:
        ho, hop = held["o"], held["op_cert"]["o"]
        if o["hk_root_pub"] != ho["hk_root_pub"]:
            refuse("other_hub")
        if op["op_seq"] < hop["op_seq"] or (
            op["op_seq"] == hop["op_seq"] and op["cert_id"] != hop["cert_id"]
        ):
            refuse("stale_op_cert")
        if op["op_seq"] == hop["op_seq"]:
            if o["card_seq"] < ho["card_seq"]:
                refuse("stale_card")
            if o["card_seq"] == ho["card_seq"] and P.cj(card) != P.cj(held):
                refuse("stale_card")
    return o, op, root


# --- the account store ------------------------------------------------------------------------------


class HubAccounts:
    def __init__(self, directory, dev_mode=False, max_accounts=MAX_ACCOUNTS, allowlist=None):
        self.d = directory
        # Operator allowlist of hk_root_pub (one b64u key per line, `#` comments): the only roots that
        # may CREATE an account. Unset or unreadable = nobody (fail closed). Rotation of an existing
        # account needs no entry.
        self.allowlist = allowlist
        self.dev_mode = dev_mode
        self.max_accounts = max_accounts
        self.mutex = threading.Lock()

    def revoked_set(self, con, hid):
        return frozenset(
            r[0] for r in con.execute("SELECT cert_id FROM hub_op_revoked WHERE hub_id=?", (hid,))
        )

    def allowed(self, root_text):
        try:
            lines = Path(self.allowlist).read_text().splitlines() if self.allowlist else []
        except (OSError, UnicodeError):
            return False
        return any(line.split("#")[0].strip() == root_text for line in lines)

    def charge(self, purpose, address, cap):
        now = self.d.clock()
        self.d.rate(purpose, address, HOUR, cap, now)

    def register(self, raw, address):
        """Register or rotate. The cheap parse comes first; everything that reads state runs in
        the write transaction on re-read state."""
        self.charge("hub-register", address, REGISTER_PER_HOUR)
        card = parse(raw)
        d = self.d
        with d.lock:
            con = d.connection("write")
            con.execute("BEGIN IMMEDIATE")
            with con:
                now = d.clock()
                # The id is read only to find the held card; the verifier below proves it.
                hid = card.get("o", {}).get("hub_id") if isinstance(card, dict) else None
                row = None
                if isinstance(hid, str) and len(hid) == 32:
                    row = con.execute(
                        "SELECT card FROM hub_accounts WHERE hub_id=?", (hid,)
                    ).fetchone()
                held = P.parse_json(row[0].encode()) if row else None
                revoked = self.revoked_set(con, hid) if isinstance(hid, str) else frozenset()
                o, op, _root = verify_card(card, now, self.dev_mode, revoked, held)
                hid = o["hub_id"]
                text = P.cj(card).decode()
                if row is None:
                    if not self.allowed(o["hk_root_pub"]):
                        refuse("not_allowed")
                    (count,) = con.execute("SELECT count(*) FROM hub_accounts").fetchone()
                    if count >= self.max_accounts:
                        refuse("quota_exceeded", 60)
                    con.execute(
                        "INSERT INTO hub_accounts VALUES (?,?,?,?,?,?,?,?,?,?)",
                        (
                            hid,
                            o["hk_root_pub"],
                            op["cert_id"],
                            op["op_seq"],
                            op["expires_ms"],
                            o["card_seq"],
                            int(o["dev"]),
                            text,
                            now,
                            now,
                        ),
                    )
                    created = True
                else:
                    con.execute(
                        "UPDATE hub_accounts SET op_cert_id=?, op_seq=?, expires_ms=?, card_seq=?, dev=?, "
                        "card=?, updated_ms=? WHERE hub_id=?",
                        (
                            op["cert_id"],
                            op["op_seq"],
                            op["expires_ms"],
                            o["card_seq"],
                            int(o["dev"]),
                            text,
                            now,
                            hid,
                        ),
                    )
                    created = False
        return {
            "hub_id": hid,
            "op_cert_id": op["cert_id"],
            "op_seq": op["op_seq"],
            "card_seq": o["card_seq"],
            "created": created,
        }

    def revoke(self, raw, address):
        self.charge("hub-revoke", address, REGISTER_PER_HOUR)
        body = parse(raw)
        if not isinstance(body, dict) or set(body) != {"hk_root_pub", "revocation"}:
            refuse("malformed")
        root = _root_key(body["hk_root_pub"])
        o = verify_op_revoked(body["revocation"], root)
        d = self.d
        with d.lock:
            con = d.connection("write")
            con.execute("BEGIN IMMEDIATE")
            with con:
                now = d.clock()
                known = con.execute(
                    "SELECT 1 FROM hub_accounts WHERE hub_id=?", (o["hub_id"],)
                ).fetchone()
                have = con.execute(
                    "SELECT 1 FROM hub_op_revoked WHERE hub_id=? AND cert_id=?",
                    (o["hub_id"], o["cert_id"]),
                ).fetchone()
                if known is None and not self.allowed(body["hk_root_pub"]):
                    # accepted and ignored: stores nothing for a root the operator never admitted
                    return {
                        "hub_id": o["hub_id"],
                        "cert_id": o["cert_id"],
                        "revoked": False,
                        "ignored": "unknown_hub",
                    }
                if have is None:  # permanent: a repeated revocation changes nothing
                    (per_hub,) = con.execute(
                        "SELECT count(*) FROM hub_op_revoked WHERE hub_id=?", (o["hub_id"],)
                    ).fetchone()
                    if per_hub >= MAX_REVOCATIONS_PER_HUB:
                        refuse("quota_exceeded", 60)
                    con.execute(
                        "INSERT INTO hub_op_revoked VALUES (?,?,?,?)",
                        (o["hub_id"], o["cert_id"], o["revoked_ms"], now),
                    )
        return {"hub_id": o["hub_id"], "cert_id": o["cert_id"], "revoked": True}

    def current(self, con, hid):
        """The stored card of a hub, only if it may be used now (check at use, contract §5): the op cert
        is not revoked, not expired (`now >= expires_ms`), and the card's dev marker matches this
        relay. Else None. The caller supplies a connection (read or write)."""
        row = con.execute(
            "SELECT card, op_cert_id, dev, expires_ms FROM hub_accounts WHERE hub_id=?", (hid,)
        ).fetchone()
        if row is None or row[1] in self.revoked_set(con, hid):
            return None
        if self.d.clock() >= row[3] or bool(row[2]) != self.dev_mode:
            return None
        return P.parse_json(row[0].encode())

    def show(self, hid, address):
        P.unhex(hid, 16)
        self.charge("hub-read", address, READ_PER_HOUR)
        with self.d.reader("query") as con:
            con.execute("BEGIN")
            row = con.execute(
                "SELECT card, op_cert_id FROM hub_accounts WHERE hub_id=?", (hid,)
            ).fetchone()
            if row is None:
                refuse("unknown_hub")
            revoked = row[1] in self.revoked_set(con, hid)
        return {"card": P.parse_json(row[0].encode()), "revoked": revoked}


def parse(raw):
    try:
        return P.parse_json(raw)
    except ValueError:
        refuse("malformed")


def dev_from_env(env=os.environ):
    return env.get("ORCH_RELAY_DEV", "").strip().lower() in ("1", "true", "yes")


def install(app):
    d = app.state.directory
    cap = int(os.environ.get("ORCH_RELAY_HUB_ACCOUNTS", MAX_ACCOUNTS))
    hubs = HubAccounts(d, dev_from_env(), cap, os.environ.get("ORCH_RELAY_HUB_ALLOWLIST"))
    app.state.hub_accounts = hubs

    def address_of(request):
        return d.client_address(request.client.host if request.client else "", request.headers)

    def endpoint(name):
        async def handle(request: Request):
            if request.query_params:
                return JSONResponse({"error": "malformed"}, status_code=400)
            raw = await read_body(request, REQUEST_CAP)
            if raw is None:
                return JSONResponse({"error": "too_large"}, status_code=413)
            if request.headers.get("content-type", "").split(";")[0].strip() != "application/json":
                return JSONResponse({"error": "malformed"}, status_code=400)
            try:
                result = await run_in_threadpool(getattr(hubs, name), raw, address_of(request))
            except Refusal as error:
                return error_response(error)
            except (ValueError, TypeError, KeyError, AttributeError, sqlite3.DataError):
                return JSONResponse({"error": "malformed"}, status_code=400)
            return JSONResponse(result, headers={"Cache-Control": "no-store"})

        return handle

    async def show(hub_id_text: str, request: Request):
        if request.query_params:
            return JSONResponse({"error": "malformed"}, status_code=400)
        try:
            result = await run_in_threadpool(hubs.show, hub_id_text, address_of(request))
        except Refusal as error:
            return error_response(error)
        except (ValueError, TypeError):
            return JSONResponse({"error": "malformed"}, status_code=400)
        return JSONResponse(result, headers={"Cache-Control": "no-store"})

    app.add_api_route("/v2/hubs", endpoint("register"), methods=["POST"])
    app.add_api_route("/v2/hubs/op-revoked", endpoint("revoke"), methods=["POST"])
    app.add_api_route("/v2/hubs/{hub_id_text}", show, methods=["GET"])
    return hubs


__all__ = ["HubAccounts", "install", "verify_card", "verify_op_cert", "verify_op_revoked"]
