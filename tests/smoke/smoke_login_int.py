"""Login-origin smoke test for a deployed DEV relay instance (deploy-day runbook V5, gate G6).

Usage, from the orch-relay repository root on the laptop:

    uv run python tests/smoke/smoke_login_int.py BASE_URL ORIGIN [--public]

BASE_URL is the instance to test, ORIGIN the exact ORCH_RELAY_ORIGIN string it was started with
(for the internal dev instance both are https://relay-internal.dev.severin.io). The single-use
invite (from `orch-relay invite create` on that instance) is read from standard input, never from
the command line (argv shows up in `ps` and shell history); on a terminal it is prompted for
without echo.

What it does: GET /v2/relay-info; generates FRESH test keys in memory (person key, device signing
and key-exchange keys; never real keys, never written anywhere); POST /v2/accounts with the
invite and a device certificate (account + first device); one login whose challenge signature is
bound to a WRONG origin (must be 401 bad_signature); one login bound to ORIGIN (must be 200);
GET /v2/devices/<id> with that session (the authenticated read); logout; the same read again (must
be 401). Output is PASS/FAIL lines only; tokens, keys and the invite are never printed. Exit 0
when every check passed, 1 on any failure, 2 on a refused target or bad arguments.

It leaves exactly ONE test account behind in the instance's database (its person_id is printed):
a person with one device, scopes ["look"], certificate expiring after 7 days. Its keys existed
only in this process, so nobody can log in as it afterwards; it owns no workspace.

Target allow-list (checked before any network access): the internal dev instance and loopback;
the public dev instance only with --public; tix.severin.io and every other host are refused, and
plain http only for loopback. ORIGIN must name an allowed host too. HTTP is http.client only:
no proxies from the environment, no redirects.
"""

import argparse
import getpass
import http.client
import ipaddress
import json
import secrets
import ssl
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(ROOT / "src")]

from orch_relay import proto as P  # the relay's own wire encoding
from ref import orch_protocol_ref as R  # the reference suite-2 signer

INTERNAL_HOSTS = {"relay-internal.dev.severin.io"}
PUBLIC_HOSTS = {"relay.dev.severin.io"}  # only with --public
DENIED_HOSTS = {"tix.severin.io"}  # never, whatever the flags
LOOPBACK_NAMES = {"localhost"}
WRONG_ORIGINS = ("http://localhost:8101", "https://wrong-origin.invalid")
CERT_DAYS = 7
TIMEOUT_S = 20

SUITE = R.SUITES[2]


class Refused(Exception):
    """The target or the arguments are not allowed; nothing was sent."""


def is_loopback(host):
    if host in LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def check_target(url, public):
    """(scheme, host, port) of an allowed base URL or origin, else Refused."""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if parts.scheme not in ("http", "https") or not host:
        raise Refused("not an http(s) URL")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise Refused("URL must not carry credentials, a query or a fragment")
    if parts.path not in ("", "/"):
        raise Refused("URL must not carry a path")
    if any(host == d or host.endswith("." + d) for d in DENIED_HOSTS):
        raise Refused(f"host {host} is never a smoke-test target")
    loopback = is_loopback(host)
    if not (loopback or host in INTERNAL_HOSTS or (public and host in PUBLIC_HOSTS)):
        hint = " (needs --public)" if host in PUBLIC_HOSTS else ""
        raise Refused(f"host {host} is not on the allow-list{hint}")
    if parts.scheme != "https" and not loopback:
        raise Refused("plain http is allowed for loopback only")
    try:
        port = parts.port
    except ValueError as exc:
        raise Refused("bad port") from exc
    return parts.scheme, host, port or (443 if parts.scheme == "https" else 80)


class Relay:
    """One relay over http.client: no environment proxies, no redirects, verified TLS."""

    def __init__(self, scheme, host, port):
        self.scheme, self.host, self.port = scheme, host, port

    def call(self, method, path, body=None, token=None):
        if self.scheme == "https":
            con = http.client.HTTPSConnection(
                self.host, self.port, timeout=TIMEOUT_S, context=ssl.create_default_context()
            )
        else:
            con = http.client.HTTPConnection(self.host, self.port, timeout=TIMEOUT_S)
        headers = {"Accept": "application/json", "User-Agent": "orch-relay-smoke/1"}
        raw = None
        if body is not None:
            raw = P.cj(body)
            headers["Content-Type"] = "application/json"
        if token is not None:
            headers["Authorization"] = "Bearer " + token
        try:
            con.request(method, path, body=raw, headers=headers)
            response = con.getresponse()
            data = response.read()
            try:
                parsed = json.loads(data) if data else None
            except ValueError:
                parsed = None
            return response.status, parsed, response.getheader("Cache-Control")
        finally:
            con.close()


class Smoke:
    def __init__(self):
        self.failed = 0

    def check(self, name, ok, detail=""):
        """Print one PASS/FAIL line. `detail` must never contain a secret."""
        print(f"{'PASS' if ok else 'FAIL'} {name}{': ' + detail if detail else ''}", flush=True)
        if not ok:
            self.failed += 1
        return ok


def outcome(status, parsed):
    """A printable outcome: the status and the relay's error code, nothing else."""
    code = parsed.get("error") if isinstance(parsed, dict) else None
    return f"{status}" + (f" {code}" if isinstance(code, str) and len(code) < 40 else "")


def b64(raw):
    return P.b64u(raw)


def fresh_identity(now_ms):
    """Fresh in-memory test keys and a device certificate signed by the fresh person key."""
    person = SUITE.sig_key(secrets.token_bytes(32))
    device = SUITE.sig_key(secrets.token_bytes(32))
    kx = SUITE.kx_key(secrets.token_bytes(32))
    pk_pub, dk_sig_pub = SUITE.sig_pub(person), SUITE.sig_pub(device)
    o = {
        "v": 2,
        "suite": 2,
        "kind": "device_cert",
        "device_id": P.identifier("device", dk_sig_pub),
        "person_id": P.identifier("person", pk_pub),
        "dk_sig_pub": b64(dk_sig_pub),
        "dk_kx_pub": b64(SUITE.kx_pub(kx)),
        "label_sealed": b64(b"FAKE smoke-test device " + secrets.token_bytes(8)),
        "created_ms": now_ms,
        "expires_ms": now_ms + CERT_DAYS * 86_400_000,
        "scopes_max": ["look"],
    }
    cert = {"o": o, "sig": b64(SUITE.sign(person, P.L["sig_device_cert"] + P.cj(o)))}
    return device, b64(pk_pub), cert


def auth_sig(device, origin, challenge, device_id):
    return b64(SUITE.sign(device, P.auth_bytes(origin, P.unb64u(challenge), "device", device_id)))


def challenge(relay):
    status, parsed, _ = relay.call("POST", "/v2/session/challenge", {})
    if status != 200 or not isinstance(parsed, dict) or "challenge" not in parsed:
        return None, outcome(status, parsed)
    return parsed["challenge"], None


def run(relay, origin, wrong_origin, invite, expect_max):
    s = Smoke()
    status, parsed, cache = relay.call("GET", "/v2/relay-info")
    info_ok = (
        status == 200
        and isinstance(parsed, dict)
        and parsed.get("v") == 1
        and isinstance(parsed.get("reader"), int)
        and isinstance(parsed.get("max_publication_bytes"), int)
        and (cache or "").lower() == "no-store"
    )
    detail = outcome(status, parsed)
    if info_ok:
        detail = (
            f"reader {parsed['reader']}, max_publication_bytes {parsed['max_publication_bytes']}"
        )
    s.check("relay-info", info_ok, detail)
    if expect_max is not None and info_ok:
        s.check(
            "relay-info max_publication_bytes",
            parsed["max_publication_bytes"] == expect_max,
            f"want {expect_max}",
        )

    device, pk_pub, cert = fresh_identity(int(time.time() * 1000))
    device_id, person_id = cert["o"]["device_id"], cert["o"]["person_id"]
    ch, err = challenge(relay)
    if not s.check("challenge for account", ch is not None, err or ""):
        return s.failed
    body = {
        "invite": invite,
        "pk_pub": pk_pub,
        "device_cert": cert,
        "challenge": ch,
        "sig": auth_sig(device, origin, ch, device_id),
    }
    status, parsed, _ = relay.call("POST", "/v2/accounts", body)
    created = status == 200 and isinstance(parsed, dict) and parsed.get("person_id") == person_id
    s.check(
        "account + device registered",
        created,
        f"person_id {person_id} device_id {device_id}" if created else outcome(status, parsed),
    )
    if not created:
        return s.failed

    ch, err = challenge(relay)
    if s.check("challenge for wrong-origin login", ch is not None, err or ""):
        body = {"challenge": ch, "kind": "device", "id": device_id}
        body["sig"] = auth_sig(device, wrong_origin, ch, device_id)
        status, parsed, _ = relay.call("POST", "/v2/session/login", body)
        s.check(
            "login bound to a wrong origin refused",
            status == 401 and isinstance(parsed, dict) and parsed.get("error") == "bad_signature",
            outcome(status, parsed),
        )

    ch, err = challenge(relay)
    if not s.check("challenge for login", ch is not None, err or ""):
        return s.failed
    body = {"challenge": ch, "kind": "device", "id": device_id}
    body["sig"] = auth_sig(device, origin, ch, device_id)
    status, parsed, _ = relay.call("POST", "/v2/session/login", body)
    token = parsed.get("token") if status == 200 and isinstance(parsed, dict) else None
    if not s.check("login bound to the configured origin", isinstance(token, str), str(status)):
        return s.failed

    status, parsed, _ = relay.call("GET", f"/v2/devices/{device_id}", token=token)
    s.check(
        "authenticated read GET /v2/devices/<id>",
        status == 200 and isinstance(parsed, dict) and parsed.get("cert") == cert,
        outcome(status, parsed),
    )
    status, parsed, _ = relay.call("POST", "/v2/session/logout", {}, token=token)
    s.check("logout", status == 200, outcome(status, parsed))
    status, parsed, _ = relay.call("GET", f"/v2/devices/{device_id}", token=token)
    s.check("session gone after logout", status == 401, outcome(status, parsed))
    return s.failed


def read_invite():
    if sys.stdin.isatty():
        invite = getpass.getpass("invite (not echoed): ")
    else:
        invite = sys.stdin.readline()
    invite = invite.strip()
    if not invite or len(invite) > 200 or not invite.isascii():
        raise Refused("no usable invite on standard input")
    return invite


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("base_url", help="the instance, e.g. https://relay-internal.dev.severin.io")
    p.add_argument("origin", help="its exact ORCH_RELAY_ORIGIN string")
    p.add_argument("--public", action="store_true", help="also allow the PUBLIC dev instance")
    p.add_argument(
        "--expect-max-publication", type=int, default=None, help="relay-info value to require"
    )
    args = p.parse_args(argv)
    try:
        scheme, host, port = check_target(args.base_url, args.public)
        o_scheme, o_host, o_port = check_target(args.origin, args.public)
        if args.origin != f"{o_scheme}://{urlsplit(args.origin).netloc}":
            raise Refused("ORIGIN must be exactly scheme://host[:port], no trailing slash")
        if (o_scheme, o_host, o_port) != (scheme, host, port) and not is_loopback(host):
            raise Refused("ORIGIN must name the same host as BASE_URL")
        invite = read_invite()
    except Refused as exc:
        print(f"FAIL refused: {exc}", flush=True)
        return 2
    wrong = next(w for w in WRONG_ORIGINS if w != args.origin)
    try:
        failed = run(
            Relay(scheme, host, port), args.origin, wrong, invite, args.expect_max_publication
        )
    except (OSError, http.client.HTTPException) as exc:
        print(f"FAIL connection: {type(exc).__name__}", flush=True)
        return 1
    print("PASS all checks" if not failed else f"FAIL {failed} check(s)", flush=True)
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
