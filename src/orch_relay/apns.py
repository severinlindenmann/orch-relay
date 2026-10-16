"""The APNs provider client (P3-D40b): protocol-v2 §19.10 "APNs request", P3 design §14.3 items 5-6.

Pure delivery logic over a transport: the exact request, the ES256 provider JWT cached per key, the
answer table (done / delete the registration / renew and retry / pause the environment with a backoff /
retry / drop) and per-environment pauses. The queue and the budgets are push_send.py. The transport is
one HTTP/2 connection per enabled environment (httpx, no HTTP/1.1 fallback); tests inject a fake with
the same two methods.

Logs carry the registration id's first 8 hex digits and the reason, never a token, payload, JWT or key.
"""

import asyncio
import json
import logging
from dataclasses import dataclass, field

import httpx
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from . import proto as P

log = logging.getLogger(__name__)

# httpx logs every request line (the URL carries the device token) at INFO, and httpcore, h2 and hpack log header
# values (`authorization: bearer <JWT>`) at DEBUG: they stay at WARNING whatever the operator sets on the root logger.
for _name in ("httpx", "httpcore", "h2", "hpack"):
    logging.getLogger(_name).setLevel(logging.WARNING)

GATEWAYS = {
    "production": "https://api.push.apple.com",
    "sandbox": "https://api.sandbox.push.apple.com",
}
ALERT = b'{"aps":{"alert":{"title":"orch","body":"New activity in orch"},"mutable-content":1},"o":'
JWT_MAX_AGE_S = 40 * 60  # renewed every 40 minutes (Apple refuses > 1 h and throttles < 20 min)
BACKOFF_MIN_S = 20 * 60  # Apple's renewal floor
BACKOFF_MAX_S = 2 * 3600
MAX_STREAMS = 16
RETRY_DELAYS_S = (0.5, 2.0)  # at most two retries of a 500, 503 or connection error
AUTH_REASONS = {"ExpiredProviderToken", "InvalidProviderToken"}
CONFIG_REASONS = {"TopicDisallowed", "BadTopic"}
BAD_TOKEN_REASONS = {"BadDeviceToken", "DeviceTokenNotForTopic"}


def apns_body(outer_cj: bytes) -> bytes:
    """The exact APNs body: `o` is a JSON string holding cj(outer) (the NSE reads userInfo["o"])."""
    return ALERT + json.dumps(outer_cj.decode("utf-8")).encode("ascii") + b"}"


def request_headers(topic, priority, expiration, jwt):
    """Exactly these headers: no apns-collapse-id (the id is sealed), no apns-id, nothing derived from content."""
    return {
        "authorization": "bearer " + jwt,
        "apns-topic": topic,
        "apns-push-type": "alert",
        "apns-priority": str(priority),
        "apns-expiration": str(expiration),
    }


def provider_jwt(kid, team_id, private, iat):
    """ES256: header {alg, kid}, claims {iss, iat}, raw 64-byte r||s signature."""
    head = P.b64u(json.dumps({"alg": "ES256", "kid": kid}, separators=(",", ":")).encode())
    claims = P.b64u(json.dumps({"iss": team_id, "iat": iat}, separators=(",", ":")).encode())
    signing_input = f"{head}.{claims}".encode("ascii")
    r, s = decode_dss_signature(private.sign(signing_input, ec.ECDSA(hashes.SHA256())))
    return f"{head}.{claims}.{P.b64u(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"


class JwtCache:
    """One provider JWT per key (a provider token does not bind the environment, so one key mapped
    to both gateways uses one token), renewed at 40 minutes or on demand."""

    def __init__(self, team_id, keys):
        self.team_id = team_id
        self.ident = {}  # env -> (kid, key object): the cache key is the key's identity
        for env, (kid, private) in keys.items():
            self.ident[env] = (kid, id(private)), private
        self.tokens = {}  # (kid, id) -> (jwt, iat)
        self.signed = 0

    def get(self, env, now_s, renew=False):
        now_s = int(now_s)
        key, private = self.ident[env]
        jwt, iat = self.tokens.get(key, (None, 0))
        if renew or jwt is None or now_s - iat >= JWT_MAX_AGE_S or now_s < iat:
            iat = now_s
            jwt = provider_jwt(key[0], self.team_id, private, iat)
            self.tokens[key] = (jwt, iat)
            self.signed += 1
        return jwt


@dataclass
class Result:
    """What delivering one send led to: `kind` is one of ok, unregistered (`timestamp_ms`), bad_token,
    auth_paused, config_paused, dropped (a 429, a 413, an unexpected answer), failed (retries spent)."""

    kind: str
    status: int | None = None
    reason: str | None = None
    timestamp_ms: int | None = None


@dataclass
class EnvState:
    paused_until_s: float = 0.0
    backoff_s: float = BACKOFF_MIN_S
    renew_next: bool = False  # the first send after a pause renews the JWT
    forced_at_s: float | None = (
        None  # when a 403 last forced a renewal (at most one per BACKOFF_MIN_S)
    )


@dataclass
class Apns:
    config: object  # PushConfig
    transport: object = None  # post(env, path, headers, body) -> (status, body bytes); aclose()
    clock_s: object = None  # () -> seconds; the relay's injectable clock
    sleep: object = asyncio.sleep
    retry_delays: tuple = RETRY_DELAYS_S
    states: dict = field(default_factory=dict)

    def __post_init__(self):
        self.jwt = JwtCache(self.config.team_id, self.config.keys)
        self.states = {env: EnvState() for env in self.config.keys}

    def paused(self, env, now_s):
        return self.states[env].paused_until_s > now_s

    def pause(self, env, now_s, why):
        state = self.states[env]
        state.paused_until_s = now_s + state.backoff_s
        log.error("apns %s: pausing %s for %d s", why, env, state.backoff_s)
        state.backoff_s = min(state.backoff_s * 2, BACKOFF_MAX_S)
        state.renew_next = True

    def recovered(self, env):
        state = self.states[env]
        state.backoff_s, state.renew_next = BACKOFF_MIN_S, False

    @staticmethod
    def reason_of(raw):
        try:
            data = json.loads(raw) if raw else {}
        except ValueError:
            return None, None
        if not isinstance(data, dict):
            return None, None
        reason, stamp = data.get("reason"), data.get("timestamp")
        return (reason if isinstance(reason, str) else None), (
            stamp if type(stamp) is int else None
        )

    async def post(self, send, now_s, renew=False):
        state = self.states[send.env]
        renew = renew or state.renew_next
        state.renew_next = False
        jwt = self.jwt.get(send.env, now_s, renew)
        headers = request_headers(self.config.topic, send.priority, send.expiration, jwt)
        return await self.transport.post(
            send.env, "/3/device/" + send.token.hex(), headers, send.body
        )

    async def deliver(self, send):
        """One send through the answer table. Never raises for an APNs or network failure."""
        env, tag = send.env, send.registration_id[:8]
        attempts = 0
        renewed = force = False
        while True:
            now_s = self.clock_s()
            try:
                status, raw = await self.post(send, now_s, renew=force)
                force = False
            except (TimeoutError, httpx.HTTPError, OSError) as exc:
                status, raw = None, b""
                log.warning("apns %s: connection error %s (%s)", tag, type(exc).__name__, env)
            reason, stamp = self.reason_of(raw)
            if status == 200:
                self.recovered(env)
                return Result("ok", 200)
            if status == 410:
                return Result("unregistered", 410, reason, stamp)
            if status == 400 and reason in BAD_TOKEN_REASONS:
                return Result("bad_token", 400, reason)
            if status == 403:
                state = self.states[env]
                last = state.forced_at_s
                if not renewed and (last is None or now_s - last >= BACKOFF_MIN_S):
                    # renew the JWT once and retry once; a 403 storm renews at most once per 20 minutes per
                    # environment (Apple throttles provider tokens renewed more often)
                    renewed = force = True
                    state.forced_at_s = now_s
                    continue
                log.error("apns_auth %s: %s (%s)", tag, reason or status, env)
                self.pause(env, now_s, "apns_auth")
                return Result("auth_paused", 403, reason)
            if status == 400 and reason in CONFIG_REASONS:
                log.error("apns config %s: %s (%s)", tag, reason, env)
                self.pause(env, now_s, "apns_config")
                return Result("config_paused", 400, reason)
            if status is None or status in (500, 503):
                if attempts < len(self.retry_delays) and now_s + self.retry_delays[attempts] < (
                    send.deadline_ms / 1000
                ):
                    await self.sleep(self.retry_delays[attempts])
                    attempts += 1
                    continue
                return Result("failed", status, reason)
            if status == 429:
                return Result("dropped", 429, reason)  # per device: drop the send
            log.error(
                "apns %s: unexpected %s %s (%s)", tag, status, reason, env
            )  # 413: a relay bug
            return Result("dropped", status, reason)


class HttpxTransport:
    """One HTTP/2 connection per environment (httpx with http1 off: Apple speaks h2 over TLS only).
    `gateways` maps env to a base URL; a test points it at a local h2c server."""

    def __init__(self, gateways=None):
        self.gateways = dict(gateways or GATEWAYS)
        self.clients = {}

    def client(self, env):
        client = self.clients.get(env)
        if client is None:
            client = self.clients[env] = httpx.AsyncClient(
                base_url=self.gateways[env],
                http1=False,
                http2=True,
                timeout=httpx.Timeout(10.0),
                limits=httpx.Limits(max_connections=1, max_keepalive_connections=1),
            )
        return client

    async def post(self, env, path, headers, body):
        response = await self.client(env).post(path, headers=headers, content=body)
        return response.status_code, response.content

    async def aclose(self):
        for client in self.clients.values():
            await client.aclose()
