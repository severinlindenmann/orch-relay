"""A scripted HTTP/2-shaped fake APNs transport (P3 design §14.3 "Pinned by"): it records every request
and verifies, for each, the path, the exact header set, the provider JWT under the public half of the key
mapped to the request's environment, and the exact body bytes. Verification failures are collected in
`errors` (a failure inside the relay's event loop would otherwise only look like a failed send)."""

import json
import time

import httpx
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from orch_relay import proto as P

HEADERS = {
    "authorization",
    "apns-topic",
    "apns-push-type",
    "apns-priority",
    "apns-expiration",
}


class Request:
    def __init__(self, env, path, headers, body):
        self.env, self.path, self.headers, self.body = env, path, dict(headers), body
        self.jwt = headers["authorization"].removeprefix("bearer ")
        self.token_hex = path.removeprefix("/3/device/")

    @property
    def outer(self):
        return json.loads(self.body)["o"]


class FakeApns:
    def __init__(self, keys, team, topic, kids):
        self.public = {env: key.public_key() for env, key in keys.items()}
        self.team, self.topic, self.kids = team, topic, kids
        self.requests, self.errors = [], []
        self.script = []  # answers consumed in order: (status, body dict | None) or an exception
        self.default = (200, None)
        self.closed = False

    def check_jwt(self, env, jwt):
        head, claims, sig = jwt.split(".")
        h, c = json.loads(P.unb64u(head)), json.loads(P.unb64u(claims))
        if h != {"alg": "ES256", "kid": self.kids[env]}:
            self.errors.append(f"jwt header {h} for {env}")
        if set(c) != {"iss", "iat"} or c["iss"] != self.team or type(c["iat"]) is not int:
            self.errors.append(f"jwt claims {c}")
        raw = P.unb64u(sig, 64)
        der = encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
        try:
            self.public[env].verify(der, f"{head}.{claims}".encode(), ec.ECDSA(hashes.SHA256()))
        except Exception as exc:  # noqa: BLE001
            self.errors.append(f"jwt signature for {env}: {type(exc).__name__}")
        return c["iat"]

    async def post(self, env, path, headers, body):
        request = Request(env, path, headers, body)
        self.requests.append(request)
        if not path.startswith("/3/device/") or len(request.token_hex) not in range(64, 201, 2):
            self.errors.append(f"path {path}")
        if set(headers) != HEADERS:
            self.errors.append(f"headers {sorted(headers)}")
        if headers.get("apns-topic") != self.topic or headers.get("apns-push-type") != "alert":
            self.errors.append("topic or push type")
        if headers.get("apns-priority") not in ("10", "5"):
            self.errors.append("priority")
        if not headers.get("apns-expiration", "x").isdigit():
            self.errors.append("expiration")
        self.check_jwt(env, request.jwt)
        o = json.loads(body)
        if list(o) != ["aps", "o"] or o["aps"] != {
            "alert": {"title": "orch", "body": "New activity in orch"},
            "mutable-content": 1,
        }:
            self.errors.append("body shape")
        answer = self.script.pop(0) if self.script else self.default
        if isinstance(answer, Exception):
            raise answer
        status, payload = answer
        return status, json.dumps(payload).encode() if payload is not None else b""

    async def aclose(self):
        self.closed = True

    def reply(self, *answers):
        self.script.extend(answers)
        return self


def refuse_connection():
    return httpx.ConnectError("scripted connection error")


def wait_for(predicate, seconds=5.0):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if predicate():
            return True
        time.sleep(0.005)
    return predicate()
