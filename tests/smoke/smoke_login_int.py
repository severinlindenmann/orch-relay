"""Login-origin smoke test for a deployed DEV relay instance (deploy-day runbook V5, gate G6).

Usage, from the orch-relay repository root on the laptop (--frozen --offline: `uv run` must not
sync from PyPI, the only network peer of this run is the target):

    uv run --frozen --offline python tests/smoke/smoke_login_int.py BASE_URL ORIGIN [--public]

BASE_URL is the instance to test, ORIGIN the exact ORCH_RELAY_ORIGIN string it was started with
(for the internal dev instance both are https://relay-internal.dev.severin.io). The single-use
invite (from `orch-relay invite create` on that instance) is read from the terminal without echo,
never from the command line (argv shows up in `ps` and shell history). A non-terminal standard
input (a pipe) is refused unless --invite-stdin is given; if getpass cannot switch echo off, the
run is refused instead of falling back to an echoing read.

What it does: GET /v2/relay-info; generates FRESH test keys in memory (person key, device signing
and key-exchange keys; never real keys, never written anywhere) and prints the test person_id and
device_id; POST /v2/accounts with the invite and a device certificate (account + first device);
one login whose challenge signature is bound to a WRONG origin (must be 401 bad_signature; a
wrongly accepted session is logged out again); one login bound to ORIGIN (must be 200);
GET /v2/devices/<id> with that session (the authenticated read); logout; the same read again (must
be 401). Exit 0 when every check passed, 1 on any failure, 2 on a refused target or bad arguments.

Output is PASS/FAIL lines of printable ASCII only. Tokens, keys and the invite are never printed:
a relay `error` code is shown only if it matches ^[a-z][a-z0-9_]{0,39}$ and contains no secret
(else <unprintable>), nothing else from a response body is ever shown, and an unexpected
exception is reported by its type name only (no message, no traceback). Session tokens must look
like base64url before they are used. Responses are capped at 1 MiB; every call has a deadline
(--call-timeout, default 20 s) and the whole run one more (--total-timeout, default 120 s), so a
slow-dripping server cannot keep the script alive.

It leaves ONE test account behind in the instance's database: a person with one device, scopes
["look"], certificate expiring after 7 days. Its keys existed only in this process, so nobody can
log in as it afterwards; it owns no workspace. The person_id is printed BEFORE the account POST:
if that POST commits but its response is lost (timeout, connection drop), the invite is used up
and the account exists anyway. Record every printed person_id; a rerun needs a fresh invite and
leaves one more inert account.

Target allow-list (checked before any network access): the internal dev instance and loopback;
the public dev instance only with --public; tix.severin.io and every other host are refused,
plain http only for loopback, non-loopback hosts on port 443 only, and URLs must be in canonical
form (no credentials, path, query or fragment). ORIGIN must be exactly scheme://host[:port] (as
the relay compares it, lowercase) and name the same host and port as BASE_URL, except when
BASE_URL is loopback (local tests, or an SSH tunnel to a relay: accepted by design). HTTP is
http.client only: no proxies from the environment, no redirects, verified TLS.
"""

import argparse
import contextlib
import getpass
import http.client
import ipaddress
import json
import re
import secrets
import signal
import ssl
import sys
import time
import warnings
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
CALL_TIMEOUT_S = 20.0
TOTAL_TIMEOUT_S = 120.0
MAX_TIMEOUT_S = 600.0
MAX_BODY = 1024 * 1024
ERROR_CODE = re.compile(r"[a-z][a-z0-9_]{0,39}")
TOKEN = re.compile(r"[A-Za-z0-9_-]{16,512}")
INVITE = re.compile(r"[A-Za-z0-9_-]{16,200}")
UNPRINTABLE = "<unprintable>"

SUITE = R.SUITES[2]

# Values that must never reach the output (the invite, session tokens), registered once known.
SECRETS = []


class Refused(Exception):
    """The target or the arguments are not allowed; nothing was sent."""


class Deadline(Exception):
    """A call or the whole run took longer than its deadline."""


class BodyTooLarge(Exception):
    """A response body above MAX_BODY."""


def has_secret(text):
    return any(s in text for s in SECRETS)


def say(line):
    """The only output path: printable ASCII, and never a registered secret."""
    line = re.sub(r"[^ -~]", "?", line)
    if has_secret(line):
        line = f"{'PASS' if line.startswith('PASS') else 'FAIL'} {UNPRINTABLE}"
    print(line, flush=True)


def is_loopback(host):
    if host in LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def check_target(url, public):
    """(scheme, host, port, canonical) of an allowed base URL or origin, else Refused."""
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        explicit_port = parts.port
    except ValueError:
        raise Refused("malformed URL") from None
    if parts.scheme not in ("http", "https") or not host:
        raise Refused("not an http(s) URL")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise Refused("URL must not carry credentials")
    if parts.query or parts.fragment or "?" in url or "#" in url:
        raise Refused("URL must not carry a query or a fragment")
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
    if explicit_port == 0:
        raise Refused("bad port")
    port = explicit_port or (443 if parts.scheme == "https" else 80)
    if not loopback and port != 443:
        raise Refused("non-loopback hosts are reached on port 443 only")
    netloc = (f"[{host}]" if ":" in host else host) + (
        f":{explicit_port}" if explicit_port is not None else ""
    )
    if parts.netloc.lower() != netloc:
        raise Refused("URL is not in canonical form")
    return parts.scheme, host, port, f"{parts.scheme}://{netloc}"


@contextlib.contextmanager
def alarm(seconds):
    """Raise Deadline in this (main) thread after `seconds`, whatever the socket is doing."""

    def fire(signum, frame):
        raise Deadline()

    old = signal.signal(signal.SIGALRM, fire)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)


class Relay:
    """One relay over http.client: no environment proxies, no redirects, verified TLS."""

    def __init__(self, scheme, host, port, call_s=CALL_TIMEOUT_S, total_s=TOTAL_TIMEOUT_S):
        self.scheme, self.host, self.port = scheme, host, port
        self.call_s = call_s
        self.run_deadline = time.monotonic() + total_s

    def connection(self, timeout):
        if self.scheme == "https":
            return http.client.HTTPSConnection(
                self.host, self.port, timeout=timeout, context=ssl.create_default_context()
            )
        return http.client.HTTPConnection(self.host, self.port, timeout=timeout)

    def call(self, method, path, body=None, token=None):
        limit = min(self.call_s, self.run_deadline - time.monotonic())
        if limit <= 0:
            raise Deadline()
        headers = {"Accept": "application/json", "User-Agent": "orch-relay-smoke/1"}
        raw = None
        if body is not None:
            raw = P.cj(body)
            headers["Content-Type"] = "application/json"
        if token is not None:
            if not isinstance(token, str) or not TOKEN.fullmatch(token):
                raise ValueError("malformed session credential")
            headers["Authorization"] = "Bearer " + token
        with alarm(limit):
            con = self.connection(limit)
            try:
                con.request(method, path, body=raw, headers=headers)
                response = con.getresponse()
                length = response.getheader("Content-Length")
                if length is not None and (not length.isdigit() or int(length) > MAX_BODY):
                    raise BodyTooLarge()
                data = response.read(MAX_BODY + 1)
                if len(data) > MAX_BODY:
                    raise BodyTooLarge()
                try:
                    parsed = json.loads(data) if data else None
                except Exception:  # noqa: BLE001 - ValueError, RecursionError (deep nesting), ...
                    parsed = None
                return response.status, parsed, response.getheader("Cache-Control")
            finally:
                con.close()


class Smoke:
    def __init__(self):
        self.failed = 0

    def check(self, name, ok, detail=""):
        """Print one PASS/FAIL line. `detail` must never contain a secret (say() enforces it)."""
        say(f"{'PASS' if ok else 'FAIL'} {name}{': ' + detail if detail else ''}")
        if not ok:
            self.failed += 1
        return ok


def outcome(status, parsed):
    """A printable outcome: the status and the relay's error code, nothing else."""
    code = parsed.get("error") if isinstance(parsed, dict) else None
    if code is None:
        return f"{int(status)}"
    printable = (
        isinstance(code, str)
        and ERROR_CODE.fullmatch(code) is not None
        and not has_secret(code)
        and not (len(code) >= 8 and any(code in s for s in SECRETS))
    )
    return f"{int(status)} {code if printable else UNPRINTABLE}"


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
    ch = parsed.get("challenge") if status == 200 and isinstance(parsed, dict) else None
    if not isinstance(ch, str) or not TOKEN.fullmatch(ch):
        return None, outcome(status, parsed)
    return ch, None


def session_token(status, parsed):
    """The session token of a 200 login, registered as a secret, or None if absent/malformed."""
    token = parsed.get("token") if status == 200 and isinstance(parsed, dict) else None
    if isinstance(token, str) and TOKEN.fullmatch(token):
        SECRETS.append(token)
        return token
    return None


def login_detail(status, parsed, token):
    if status == 200 and token is None:
        return "200 credential missing or malformed (not used)"
    return outcome(status, parsed)


def run(relay, origin, wrong_origin, invite, expect_max):
    s = Smoke()
    status, parsed, cache = relay.call("GET", "/v2/relay-info")
    info_ok = (
        status == 200
        and isinstance(parsed, dict)
        and parsed.get("v") == 1
        and type(parsed.get("reader")) is int
        and type(parsed.get("max_publication_bytes")) is int
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
    # Printed BEFORE the account POST: if it commits but the response is lost, this is the record.
    s.check("test identity generated", True, f"person_id {person_id} device_id {device_id}")
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
        f"person_id {person_id}" if created else outcome(status, parsed),
    )
    if not created:
        return s.failed

    ch, err = challenge(relay)
    if s.check("challenge for wrong-origin login", ch is not None, err or ""):
        body = {"challenge": ch, "kind": "device", "id": device_id}
        body["sig"] = auth_sig(device, wrong_origin, ch, device_id)
        status, parsed, _ = relay.call("POST", "/v2/session/login", body)
        refused = (
            status == 401 and isinstance(parsed, dict) and parsed.get("error") == "bad_signature"
        )
        stray = None if refused else session_token(status, parsed)
        s.check("login bound to a wrong origin refused", refused, outcome(status, parsed))
        if stray is not None:
            status, parsed, _ = relay.call("POST", "/v2/session/logout", {}, token=stray)
            s.check(
                "logout of the wrongly accepted session", status == 200, outcome(status, parsed)
            )

    ch, err = challenge(relay)
    if not s.check("challenge for login", ch is not None, err or ""):
        return s.failed
    body = {"challenge": ch, "kind": "device", "id": device_id}
    body["sig"] = auth_sig(device, origin, ch, device_id)
    status, parsed, _ = relay.call("POST", "/v2/session/login", body)
    token = session_token(status, parsed)
    if not s.check(
        "login bound to the configured origin",
        token is not None,
        login_detail(status, parsed, token),
    ):
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


def read_invite(invite_stdin):
    if sys.stdin.isatty():
        with warnings.catch_warnings():
            # getpass falls back to an ECHOING read when it cannot control the terminal: refuse.
            warnings.simplefilter("error", getpass.GetPassWarning)
            invite = getpass.getpass("invite (not echoed): ")
    elif invite_stdin:
        invite = sys.stdin.readline(256)
    else:
        raise Refused("standard input is not a terminal (pass --invite-stdin to read a pipe)")
    invite = invite.strip()
    if not INVITE.fullmatch(invite):
        raise Refused("no usable invite on standard input")
    return invite


def seconds(text):
    value = float(text)
    if not 0 < value <= MAX_TIMEOUT_S:
        raise argparse.ArgumentTypeError(f"must be in (0, {MAX_TIMEOUT_S:g}]")
    return value


def parse_args(argv):
    p = argparse.ArgumentParser(
        description=__doc__.split("\n\n")[0],
        epilog="The test person_id is printed before the account POST; record it even if a later "
        "step fails (a lost response still leaves the account). Run via "
        "`uv run --frozen --offline` so uv does not reach PyPI.",
    )
    p.add_argument("base_url", help="the instance, e.g. https://relay-internal.dev.severin.io")
    p.add_argument("origin", help="its exact ORCH_RELAY_ORIGIN string")
    p.add_argument("--public", action="store_true", help="also allow the PUBLIC dev instance")
    p.add_argument(
        "--expect-max-publication", type=int, default=None, help="relay-info value to require"
    )
    p.add_argument(
        "--invite-stdin",
        action="store_true",
        help="read the invite from a non-terminal standard input (tests); default: prompt only",
    )
    p.add_argument("--call-timeout", type=seconds, default=CALL_TIMEOUT_S, help="per call, s")
    p.add_argument("--total-timeout", type=seconds, default=TOTAL_TIMEOUT_S, help="whole run, s")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    SECRETS.clear()
    try:
        scheme, host, port, _ = check_target(args.base_url, args.public)
        o_scheme, o_host, o_port, o_canonical = check_target(args.origin, args.public)
        if args.origin != o_canonical:
            raise Refused("ORIGIN must be exactly scheme://host[:port], lowercase, no slash")
        if (o_scheme, o_host, o_port) != (scheme, host, port) and not is_loopback(host):
            raise Refused("ORIGIN must name the same host and port as BASE_URL")
        invite = read_invite(args.invite_stdin)
    except Refused as exc:
        say(f"FAIL refused: {exc}")
        return 2
    except Exception as exc:  # noqa: BLE001 - never the message: it may carry input
        say(f"FAIL refused: {type(exc).__name__}")
        return 2
    SECRETS.append(invite)
    wrong = next(w for w in WRONG_ORIGINS if w != args.origin)
    relay = Relay(scheme, host, port, args.call_timeout, args.total_timeout)
    try:
        failed = run(relay, args.origin, wrong, invite, args.expect_max_publication)
    except Deadline:
        say("FAIL timeout: a call or the run exceeded its deadline")
        return 1
    except BodyTooLarge:
        say(f"FAIL response larger than {MAX_BODY} bytes")
        return 1
    except KeyboardInterrupt:
        say("FAIL interrupted")
        return 130
    except Exception as exc:  # noqa: BLE001 - type name only: messages may carry secrets
        say(f"FAIL error: {type(exc).__name__}")
        return 1
    say("PASS all checks" if not failed else f"FAIL {failed} check(s)")
    return 0 if not failed else 1


def excepthook(exc_type, exc, tb):
    """Last resort: the type name only, never a message or traceback."""
    print(f"FAIL internal: {exc_type.__name__}", flush=True)


if __name__ == "__main__":
    sys.tracebacklimit = 0
    sys.excepthook = excepthook
    sys.exit(main())
