"""Push configuration and token custody for the hub's push targets (D77; hub_phone.py has the routes).

A relay without a complete push configuration (push_config.py) answers 404 `not_found` on the hub push routes.
Tokens are stored sealed (AES-256-GCM under K_tok, bound to the sealing id) with an HMAC for lookups (K_mac);
both keys come from the instance secret `push-token.key`, which is never in the database. APNs delivery is
push_send.py. Lock order: Core.lock, then the in-memory budgets (Core.budget).
"""

import asyncio
import logging
import os
import secrets
import sqlite3

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from starlette.concurrency import run_in_threadpool

from .push_config import load, mac
from .push_send import attach

log = logging.getLogger(__name__)

SWEEP_EVERY_S = 6 * 3600
AAD = b"orch-relay/push-token|"


class Push:
    def __init__(self, directory, config):
        self.d, self.config = directory, config
        self.outbox = self.sender = self.apns = None  # push_send.attach, when enabled

    @property
    def enabled(self):
        return self.config is not None

    # --- token sealing (item 8) ---------------------------------------------------------------

    def seal(self, registration_id, token):
        nonce = secrets.token_bytes(12)
        aad = AAD + registration_id.encode("ascii")
        return nonce + AESGCM(self.config.k_tok).encrypt(nonce, token, aad)

    def unseal(self, registration_id, sealed):
        aad = AAD + registration_id.encode("ascii")
        return AESGCM(self.config.k_tok).decrypt(bytes(sealed[:12]), bytes(sealed[12:]), aad)

    def token_mac(self, token):
        return mac(self.config.k_mac, token)

    def apply_result(self, send, result):
        """APNs 410 and 400 BadDeviceToken / DeviceTokenNotForTopic delete registrations (item 3):
        410 those with the token whose `last_seen_ms` is not after Apple's timestamp; 400 the token's
        in that environment. Runs in a worker thread; logs carry the id's first 8 digits only."""
        d = self.d
        with d.lock:
            con = d.connection("write")
            con.execute("BEGIN IMMEDIATE")
            with con:
                if result.kind == "unregistered":
                    stamp = result.timestamp_ms if result.timestamp_ms is not None else d.clock()
                    gone = con.execute(
                        "DELETE FROM hub_push_targets WHERE token_mac=? AND updated_ms<=?",
                        (send.mac, stamp),
                    ).rowcount
                else:
                    gone = con.execute(
                        "DELETE FROM hub_push_targets WHERE token_mac=? AND env=?",
                        (send.mac, send.env),
                    ).rowcount
        log.info(
            "apns %s: %s, removed %d registration(s)", send.registration_id[:8], result.reason, gone
        )

    # --- lifecycle (item 3) -------------------------------------------------------------------

    def sweep(self, now=None):
        """Expired hub mailbox messages (hub push targets are kept until the hub deletes them or APNs reports
        the token gone: a hub does not re-register a stable target)."""
        d = self.d
        with d.lock:
            con = d.connection("write")
            con.execute("BEGIN IMMEDIATE")
            with con:
                now = d.clock() if now is None else now
                return con.execute("DELETE FROM hub_mailbox WHERE expires_ms<=?", (now,)).rowcount

    async def maintenance(self):
        while True:
            try:
                await run_in_threadpool(self.sweep)
            except (sqlite3.Error, OSError):
                log.exception("push sweep failed")
            await asyncio.sleep(SWEEP_EVERY_S)


def install(app, env=None):
    """Load the push configuration (raises PushConfigError when partial) and attach the outbox and sender."""
    config = load(os.environ if env is None else env)
    push = Push(app.state.core, config)
    app.state.push = push
    if push.enabled:
        attach(app, push, env)
    return push
