"""The deploy-day login-origin smoke script (tests/smoke/smoke_login_int.py).

- against a real local `orch-relay serve` on 127.0.0.1 (a free port, a temp data dir,
  ORCH_RELAY_ORIGIN set exactly): it passes against the configured origin and fails when given
  another origin;
- against hostile fake relays on 127.0.0.1 (stdlib http.server threads): redirects, proxies from
  the environment, echoed secrets, malformed tokens, oversized and nested bodies, slow drips;
- in-process: the target allow-list, the invite prompt, the TLS context.

Nothing here leaves the loopback interface: in this process `socket.socket.connect` and
`socket.getaddrinfo` refuse anything but loopback (refusal tests refuse even loopback and assert
that nothing was attempted), and every script subprocess runs under the same guard, so a broken
allow-list fails a test instead of sending a request to a real host."""

import http.server
import importlib.util
import io
import json
import os
import re
import secrets
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.request
import warnings
from pathlib import Path

import pytest

from orch_relay import proto as P

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tests" / "smoke" / "smoke_login_int.py"
SECRET_MARKERS = ("Bearer", "token", 'invite":', 'sig":')
LOOPBACK_ADDRS = ("127.0.0.1", "::1")
LOOPBACK_NAMES = ("127.0.0.1", "::1", "localhost")
LINE = re.compile(r"(PASS|FAIL) [ -~]*")

# Installed in every script subprocess before the script runs: loopback only.
GUARD = r"""
import runpy, socket, sys
_connect, _gai = socket.socket.connect, socket.getaddrinfo
def connect(self, address):
    if not (isinstance(address, tuple) and address[0] in ("127.0.0.1", "::1")):
        raise PermissionError("test guard: network blocked")
    return _connect(self, address)
def getaddrinfo(host, *a, **k):
    if host not in ("127.0.0.1", "::1", "localhost"):
        raise PermissionError("test guard: network blocked")
    return _gai(host, *a, **k)
socket.socket.connect, socket.getaddrinfo = connect, getaddrinfo
sys.argv = sys.argv[1:]
runpy.run_path(sys.argv[0], run_name="__main__")
"""


def load_script():
    spec = importlib.util.spec_from_file_location("smoke_login_int", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SM = load_script()


def _guard(monkeypatch, allow):
    attempts = []
    real_connect, real_gai = socket.socket.connect, socket.getaddrinfo

    def connect(self, address):
        attempts.append(address)
        if not (allow and isinstance(address, tuple) and address[0] in LOOPBACK_ADDRS):
            raise PermissionError("test guard: network blocked")
        return real_connect(self, address)

    def getaddrinfo(host, *args, **kwargs):
        attempts.append(host)
        if not (allow and host in LOOPBACK_NAMES):
            raise PermissionError("test guard: network blocked")
        return real_gai(host, *args, **kwargs)

    monkeypatch.setattr(socket.socket, "connect", connect)
    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    return attempts


@pytest.fixture(autouse=True)
def loopback_only(monkeypatch):
    return _guard(monkeypatch, allow=True)


@pytest.fixture
def no_network(monkeypatch):
    """Every connect/resolve refused, even loopback; the list records each attempt."""
    return _guard(monkeypatch, allow=False)


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def cli(env, *args):
    return subprocess.run(
        [sys.executable, "-m", "orch_relay.cli", *args],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    ).stdout


@pytest.fixture
def relay(tmp_path):
    port = free_port()
    base = f"http://127.0.0.1:{port}"
    env = {
        **os.environ,
        "ORCH_RELAY_DATA": str(tmp_path / "data"),
        "ORCH_RELAY_ORIGIN": base,
        "PYTHONPATH": str(ROOT / "src"),
    }
    env.pop("ORCH_RELAY_TRUSTED_PROXY", None)
    server = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "orch_relay.cli",
            "serve",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        cwd=ROOT,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        deadline = time.monotonic() + 30
        while True:
            try:
                with opener.open(base + "/healthz", timeout=1) as r:
                    if r.status == 200:
                        break
            except OSError:
                if time.monotonic() > deadline or server.poll() is not None:
                    raise
                time.sleep(0.2)
        yield base, env
    finally:
        server.terminate()
        try:
            server.wait(timeout=15)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait()


def smoke(*args, invite="", env=None, timeout=60):
    """The script as a subprocess, under the loopback-only guard, invite on a pipe."""
    return subprocess.run(
        [sys.executable, "-c", GUARD, str(SCRIPT), *args, "--invite-stdin"],
        cwd=ROOT,
        env=env,
        input=invite + "\n",
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def assert_quiet(r, *secret_values):
    """Only PASS/FAIL lines of printable ASCII, nothing on stderr, and no secret anywhere."""
    lines = r.stdout.splitlines()
    assert lines and all(LINE.fullmatch(line) for line in lines), r.stdout
    assert r.stderr == "", r.stderr[-2000:]
    for stream in (r.stdout, r.stderr):
        for value in secret_values:
            assert value not in stream
        assert not any(marker in stream for marker in SECRET_MARKERS), stream


def new_invite():
    # Lowercase, so it also matches the error-code pattern: only the secret check can hide it.
    return "smokeinvite_" + secrets.token_hex(10)


# --- the real relay ---------------------------------------------------------------------------


def test_passes_against_the_configured_origin(relay):
    base, env = relay
    invite = cli(env, "invite", "create", "--ttl", "1h").strip()
    r = smoke(base, base, "--expect-max-publication", str(16 * 1024 * 1024), invite=invite)
    assert r.returncode == 0, r.stdout + r.stderr[-2000:]
    assert_quiet(r, invite)
    lines = r.stdout.splitlines()
    ident = next(i for i, line in enumerate(lines) if "test identity generated" in line)
    account = next(i for i, line in enumerate(lines) if "account + device registered" in line)
    assert ident < account
    assert "PASS login bound to a wrong origin refused: 401 bad_signature" in r.stdout
    assert "PASS login bound to the configured origin" in r.stdout
    assert lines[-1] == "PASS all checks"
    # The invite is single-use: a second run cannot create another account.
    again = smoke(base, base, invite=invite)
    assert again.returncode == 1
    assert "FAIL account + device registered: 403 not_eligible" in again.stdout


def test_fails_when_the_relay_has_another_origin(relay):
    base, env = relay
    invite = cli(env, "invite", "create", "--ttl", "1h").strip()
    # The relay was started with ORCH_RELAY_ORIGIN = http://127.0.0.1:<port>; "localhost" is a
    # different origin string, so every signature the script makes is bound to the wrong one.
    other = base.replace("127.0.0.1", "localhost")
    r = smoke(base, other, invite=invite)
    assert r.returncode == 1, r.stdout
    assert_quiet(r, invite)
    assert "FAIL account + device registered: 401 bad_signature" in r.stdout


# --- hostile fake relays on 127.0.0.1 -----------------------------------------------------------


class FakeRelay(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, mode):
        super().__init__(("127.0.0.1", 0), Handler)
        self.mode = mode
        self.base = f"http://127.0.0.1:{self.server_address[1]}"
        self.log, self.issued, self.logouts = [], [], []
        self.certs, self.live = {}, set()
        self.sink = None
        self.stopped = threading.Event()

    def new_token(self):
        if self.mode == "token_crlf":
            token = "SMOKETOKMARK" + secrets.token_hex(8) + "\r\nX-Evil: 1"
        else:  # lowercase, <= 40 chars: matches the error-code pattern too
            token = "smoketok_" + secrets.token_hex(12)
        self.issued.append(token)
        self.live.add(token)
        return token


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def log_message(self, *args):
        pass

    def do_GET(self):
        self.serve("GET")

    def do_POST(self):
        self.serve("POST")

    def reply(self, status, obj=None, headers=None):
        data = json.dumps(obj).encode() if obj is not None else b""
        self.send_response(status)
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def drip(self):
        self.send_response(200)
        self.send_header("Content-Length", "100000")
        self.end_headers()
        try:
            while not self.server.stopped.is_set():
                self.wfile.write(b" ")
                self.wfile.flush()
                time.sleep(0.2)
        except OSError:
            pass

    def raw(self, data, length=True):
        self.send_response(200)
        if length:
            self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def serve(self, method):
        srv, path = self.server, self.path
        n = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(n)) if n else None
        auth = self.headers.get("Authorization")
        srv.log.append((method, path, body, auth))
        bearer = auth[len("Bearer ") :] if auth else None
        mode = srv.mode
        if mode == "sink":
            return self.reply(200, {})
        if mode == "redirect":
            return self.reply(302, headers={"Location": f"{srv.sink.base}{path}"})
        if path == "/v2/relay-info":
            if mode == "slow":
                return self.drip()
            if mode == "big_length":
                return self.raw(b" " * (2 * SM.MAX_BODY))
            if mode == "big_stream":
                return self.raw(b" " * (2 * SM.MAX_BODY), length=False)
            if mode == "deep_json":
                return self.raw(b"[" * 200_000)
            info = {"v": 1, "reader": 1, "max_publication_bytes": 4194304}
            return self.reply(200, info, {"Cache-Control": "no-store"})
        if path == "/v2/session/challenge":
            return self.reply(200, {"challenge": P.b64u(secrets.token_bytes(32))})
        if path == "/v2/accounts":
            if mode == "echo_invite":
                return self.reply(400, {"error": body["invite"]})
            if mode == "echo_long":
                return self.reply(400, {"error": "a" * 100})
            if mode == "echo_escape":
                return self.reply(400, {"error": "\x1b[2J\x1b[31m\nPASS all checks"})
            cert = body["device_cert"]
            srv.certs[cert["o"]["device_id"]] = cert
            if mode == "account_drop":  # committed, but the response is lost
                self.close_connection = True
                return None
            return self.reply(200, {"person_id": cert["o"]["person_id"]})
        if path == "/v2/session/login":
            cert = srv.certs[body["id"]]
            signed = P.auth_bytes(srv.base, P.unb64u(body["challenge"]), "device", body["id"])
            ok = P.SUITE.verify(P.unb64u(cert["o"]["dk_sig_pub"]), P.unb64u(body["sig"]), signed)
            if not ok and mode != "accept_any_login":
                return self.reply(401, {"error": "bad_signature"})
            return self.reply(200, {"token": srv.new_token(), "expires_ms": 1})
        if path.startswith("/v2/devices/"):
            if mode == "token_error":
                return self.reply(401, {"error": bearer})
            if mode == "token_drop":
                self.close_connection = True
                return None
            if bearer in srv.live:
                return self.reply(200, {"cert": srv.certs[path.rsplit("/", 1)[1]]})
            return self.reply(401, {"error": "unauthorized"})
        if path == "/v2/session/logout":
            srv.logouts.append(bearer)
            srv.live.discard(bearer)
            return self.reply(200, {})
        return self.reply(404, {"error": "not_found"})


@pytest.fixture
def fake():
    servers = []

    def start(mode="honest"):
        srv = FakeRelay(mode)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
        return srv

    yield start
    for srv in servers:
        srv.stopped.set()
        srv.shutdown()
        srv.server_close()


def fake_run(srv, invite, *extra, env=None, timeout=60):
    return smoke(srv.base, srv.base, *extra, invite=invite, env=env, timeout=timeout)


def test_fake_relay_success_never_prints_the_token(fake):
    srv, invite = fake(), new_invite()
    r = fake_run(srv, invite)
    assert r.returncode == 0, r.stdout + r.stderr
    assert_quiet(r, invite, *srv.issued)
    assert srv.issued and srv.logouts == [srv.issued[-1]]
    # The wrong-origin login is really signed for the wrong origin: the fake verifies against its
    # own origin and accepts only the configured-origin login.
    assert "PASS login bound to a wrong origin refused: 401 bad_signature" in r.stdout
    assert len(srv.issued) == 1
    # The account POST carried the invite; the logins never did.
    accounts = [b for m, p, b, a in srv.log if p == "/v2/accounts"]
    assert len(accounts) == 1 and accounts[0]["invite"] == invite


def test_redirect_and_environment_proxy_are_never_followed(fake):
    sink = fake("sink")
    srv = fake("redirect")
    srv.sink = sink
    env = {**os.environ, "NO_PROXY": "", "no_proxy": ""}
    for name in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY"):
        env[name] = sink.base
    invite = new_invite()
    r = fake_run(srv, invite, env=env)
    assert r.returncode == 1, r.stdout + r.stderr
    assert_quiet(r, invite)
    assert "FAIL relay-info: 302" in r.stdout
    assert sink.log == []


@pytest.mark.parametrize("mode", ["echo_invite", "echo_long", "echo_escape"])
def test_error_strings_from_the_relay_are_filtered(fake, mode):
    srv, invite = fake(mode), new_invite()
    r = fake_run(srv, invite)
    assert r.returncode == 1, r.stdout + r.stderr
    assert_quiet(r, invite, "a" * 41, "\x1b")
    assert "FAIL account + device registered: 400 <unprintable>" in r.stdout
    assert r.stdout.count("PASS all checks") == 0


@pytest.mark.parametrize("mode", ["token_error", "token_drop", "token_crlf"])
def test_the_session_token_is_never_printed(fake, mode):
    srv, invite = fake(mode), new_invite()
    r = fake_run(srv, invite)
    assert r.returncode == 1, r.stdout + r.stderr
    assert srv.issued
    assert_quiet(r, invite, *srv.issued, *(t.split("\r")[0] for t in srv.issued), "X-Evil")
    if mode == "token_error":
        assert "FAIL authenticated read GET /v2/devices/<id>: 401 <unprintable>" in r.stdout
    if mode == "token_drop":
        assert r.stdout.splitlines()[-1] == "FAIL error: RemoteDisconnected"
    if mode == "token_crlf":
        assert (
            "FAIL login bound to the configured origin: 200 credential missing or malformed"
            in r.stdout
        )
        assert all(a is None for m, p, b, a in srv.log)


def test_wrongly_accepted_wrong_origin_login_is_logged_out(fake):
    srv, invite = fake("accept_any_login"), new_invite()
    r = fake_run(srv, invite)
    assert r.returncode == 1, r.stdout + r.stderr
    assert_quiet(r, invite, *srv.issued)
    assert "FAIL login bound to a wrong origin refused: 200" in r.stdout
    assert "PASS logout of the wrongly accepted session" in r.stdout
    assert len(srv.issued) == 2 and srv.logouts == srv.issued


def test_person_id_is_printed_before_the_account_post(fake):
    srv, invite = fake("account_drop"), new_invite()
    r = fake_run(srv, invite)
    assert r.returncode == 1, r.stdout + r.stderr
    assert_quiet(r, invite)
    (cert,) = srv.certs.values()
    person_id = cert["o"]["person_id"]
    lines = r.stdout.splitlines()
    assert f"person_id {person_id}" in lines[1] and lines[1].startswith("PASS test identity")
    assert lines[-1] == "FAIL error: RemoteDisconnected"


@pytest.mark.parametrize(
    "mode, last",
    [
        ("big_length", f"FAIL response larger than {SM.MAX_BODY} bytes"),
        ("big_stream", f"FAIL response larger than {SM.MAX_BODY} bytes"),
        ("deep_json", "PASS all checks"),
    ],
)
def test_oversized_and_nested_bodies(fake, mode, last):
    srv, invite = fake(mode), new_invite()
    r = fake_run(srv, invite)
    assert_quiet(r, invite, *srv.issued)
    if mode == "deep_json":
        assert r.returncode == 1 and r.stdout.splitlines()[0] == "FAIL relay-info: 200"
        assert r.stdout.splitlines()[-1] == "FAIL 1 check(s)"
    else:
        assert r.returncode == 1 and r.stdout.splitlines() == [last]


@pytest.mark.parametrize("call, total", [("30", "2"), ("1.5", "30")])
def test_slowloris_relay_cannot_outlive_the_deadlines(fake, call, total):
    srv, invite = fake("slow"), new_invite()
    started = time.monotonic()
    r = fake_run(srv, invite, "--call-timeout", call, "--total-timeout", total, timeout=20)
    assert time.monotonic() - started < 12
    assert r.returncode == 1, r.stdout + r.stderr
    assert_quiet(r, invite)
    assert r.stdout.splitlines() == ["FAIL timeout: a call or the run exceeded its deadline"]


def test_piped_invite_needs_the_explicit_flag(fake):
    srv = fake()
    r = subprocess.run(
        [sys.executable, "-c", GUARD, str(SCRIPT), srv.base, srv.base],
        cwd=ROOT,
        input=new_invite() + "\n",
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert r.returncode == 2
    assert r.stdout.startswith("FAIL refused: standard input is not a terminal")
    assert srv.log == []


# --- in process: allow-list, invite prompt, TLS, exception reporting ----------------------------


@pytest.mark.parametrize(
    "url",
    [
        "https://tix.severin.io",
        "https://api.tix.severin.io",
        "https://relay.dev.severin.io",
        "https://example.com",
        "http://relay-internal.dev.severin.io",
        "https://relay-internal.dev.severin.io/v2",
        "https://relay-internal.dev.severin.io?x=1",
        "https://relay-internal.dev.severin.io#x",
        "https://user@relay-internal.dev.severin.io",
        "https://user:pw@relay-internal.dev.severin.io",
        "https://relay-internal.dev.severin.io@evil.com",
        "https://relay-internal.dev.severin.io.evil.com",
        "https://xrelay-internal.dev.severin.io",
        "https://a.relay-internal.dev.severin.io",
        "https://relay-internal.dev.severin.io.",
        "https://relay-internal.dev.severin.io:8443",
        "https://relay-internal.dev.severin.io:0443",
        "https://relay-internal.dev.severin.io:",
        "http://localhost.evil.com",
        "http://2130706433",
        "http://0x7f.0.0.1",
        "http://127.1",
        "http://0.0.0.0",
        "http://[::]",
        "http://[::1",
        "http://[::1]x",
        "http://127.0.0.1:0",
        "ftp://127.0.0.1",
        "//relay-internal.dev.severin.io",
    ],
)
def test_check_target_refuses(no_network, url):
    with pytest.raises(SM.Refused):
        SM.check_target(url, public=False)
    assert no_network == []


@pytest.mark.parametrize(
    "url, public, want",
    [
        ("https://relay-internal.dev.severin.io", False, 443),
        ("https://relay-internal.dev.severin.io:443", False, 443),
        ("https://relay-internal.dev.severin.io/", False, 443),
        ("https://relay.dev.severin.io", True, 443),
        ("http://127.0.0.1:8080", False, 8080),
        ("http://[::1]:9", False, 9),
        ("http://localhost", False, 80),
    ],
)
def test_check_target_allows(no_network, url, public, want):
    assert SM.check_target(url, public)[2] == want


def test_tix_is_denied_even_if_it_slips_into_the_allow_list(monkeypatch, no_network):
    monkeypatch.setattr(SM, "INTERNAL_HOSTS", {"tix.severin.io", "api.tix.severin.io"})
    monkeypatch.setattr(SM, "PUBLIC_HOSTS", {"tix.severin.io"})
    for url in ("https://tix.severin.io", "https://api.tix.severin.io"):
        with pytest.raises(SM.Refused, match="never"):
            SM.check_target(url, public=True)


def run_main(monkeypatch, capsys, argv, stdin="FAKE-not-an-invite\n"):
    monkeypatch.setattr(SM.sys, "stdin", io.StringIO(stdin))
    rc = SM.main(argv)
    return rc, capsys.readouterr()


INTERNAL = "https://relay-internal.dev.severin.io"


@pytest.mark.parametrize(
    "target, origin, extra",
    [
        ("https://tix.severin.io", "https://tix.severin.io", []),
        ("https://tix.severin.io", "https://tix.severin.io", ["--public"]),
        ("https://api.tix.severin.io", "https://api.tix.severin.io", ["--public"]),
        ("https://relay.dev.severin.io", "https://relay.dev.severin.io", []),
        ("https://example.com", "https://example.com", ["--public"]),
        ("http://relay-internal.dev.severin.io", "http://relay-internal.dev.severin.io", []),
        (INTERNAL, INTERNAL + "/", []),
        (INTERNAL, "https://RELAY-INTERNAL.dev.severin.io", []),
        (INTERNAL, INTERNAL + ":443", []),
        (INTERNAL, "https://relay.dev.severin.io", ["--public"]),
        (INTERNAL + "/v2", INTERNAL, []),
        (INTERNAL + ":8443", INTERNAL + ":8443", []),
        ("http://[::1", "http://[::1", []),
        ("http://127.0.0.1:1", "http://[::1", []),
        (INTERNAL, INTERNAL, []),  # stdin is a pipe and there is no --invite-stdin
        ("http://127.0.0.1:1", "http://127.0.0.1:1", ["--invite-stdin"]),  # "x" is no invite
    ],
)
def test_main_refuses_before_any_network_access(
    monkeypatch, capsys, no_network, target, origin, extra
):
    stdin = "x\n" if "--invite-stdin" in extra else "FAKE-not-an-invite\n"
    rc, out = run_main(monkeypatch, capsys, [target, origin, *extra], stdin)
    assert rc == 2, out.out
    assert out.out.startswith("FAIL refused: ") and len(out.out.splitlines()) == 1, out.out
    assert out.err == ""
    assert no_network == []


def test_invite_prompt_uses_getpass_and_never_echoes(monkeypatch):
    prompts = []

    def fake_getpass(prompt):
        prompts.append(prompt)
        return "FAKE-not-an-invite"

    def echoing_input(*args):
        raise AssertionError("input() echoes the invite")

    monkeypatch.setattr(SM.sys, "stdin", Tty())
    monkeypatch.setattr(SM.getpass, "getpass", fake_getpass)
    monkeypatch.setattr("builtins.input", echoing_input)
    assert SM.read_invite(False) == "FAKE-not-an-invite"
    assert prompts == ["invite (not echoed): "]


class Tty(io.StringIO):
    def isatty(self):
        return True


def test_echoing_getpass_fallback_is_refused(monkeypatch, capsys, no_network):
    def fallback(prompt):
        warnings.warn("Can not control echo on the terminal.", SM.getpass.GetPassWarning)
        return "FAKE-not-an-invite"

    monkeypatch.setattr(SM.getpass, "getpass", fallback)
    monkeypatch.setattr(SM.sys, "stdin", Tty())
    rc = SM.main(["http://127.0.0.1:1", "http://127.0.0.1:1"])
    out = capsys.readouterr()
    assert rc == 2 and out.out == "FAIL refused: GetPassWarning\n"
    assert no_network == []


def test_tls_is_verified_with_the_default_context(monkeypatch, no_network):
    seen = {}

    class Stop(Exception):
        pass

    class Recorder:
        def __init__(self, host, port, timeout=None, context=None):
            seen.update(host=host, port=port, context=context, timeout=timeout)

        def request(self, *args, **kwargs):
            raise Stop()

        def close(self):
            pass

    monkeypatch.setattr(SM.http.client, "HTTPSConnection", Recorder)
    with pytest.raises(Stop):
        SM.Relay("https", "relay-internal.dev.severin.io", 443).call("GET", "/v2/relay-info")
    ctx = seen["context"]
    assert isinstance(ctx, ssl.SSLContext)
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname
    assert seen["host"] == "relay-internal.dev.severin.io" and seen["port"] == 443
    assert 0 < seen["timeout"] <= SM.CALL_TIMEOUT_S


def test_exceptions_are_reported_by_type_name_only(monkeypatch, capsys, no_network):
    def boom(*args):
        raise ValueError("Bearer SMOKETOKMARK123\r\nX-Evil: 1 FAKE-not-an-invite")

    monkeypatch.setattr(SM, "run", boom)
    rc, out = run_main(
        monkeypatch, capsys, ["http://127.0.0.1:1", "http://127.0.0.1:1", "--invite-stdin"]
    )
    assert rc == 1
    assert out.out == "FAIL error: ValueError\n" and out.err == ""


def test_excepthook_prints_the_type_name_only(capsys):
    SM.excepthook(RecursionError, RecursionError("SMOKETOKMARK"), None)
    assert capsys.readouterr().out == "FAIL internal: RecursionError\n"


def test_a_malformed_token_is_never_sent(no_network):
    relay = SM.Relay("http", "127.0.0.1", 1)
    with pytest.raises(ValueError):
        relay.call("GET", "/v2/devices/x", token="SMOKETOKMARK0123456789\r\nX-Evil: 1")
    assert no_network == []
