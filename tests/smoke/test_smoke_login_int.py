"""The deploy-day login-origin smoke script (tests/smoke/smoke_login_int.py) against a real local
`orch-relay serve` on 127.0.0.1 (a free port, a temp data dir, ORCH_RELAY_ORIGIN set exactly):
it passes against the configured origin, fails when given another origin, and refuses targets off
its allow-list before sending anything. Nothing here leaves the loopback interface."""

import os
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tests" / "smoke" / "smoke_login_int.py"
SECRET_MARKERS = ("Bearer", "token", 'invite":', 'sig":')


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
    try:
        deadline = time.monotonic() + 30
        while True:
            try:
                with urllib.request.urlopen(base + "/healthz", timeout=1) as r:
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


def smoke(*args, invite="", env=None):
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        cwd=ROOT,
        env=env,
        input=invite + "\n",
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


def assert_quiet(r, invite):
    """Only PASS/FAIL lines, and no secret on any stream."""
    lines = r.stdout.splitlines()
    assert lines and all(line.startswith(("PASS ", "FAIL ")) for line in lines), r.stdout
    for stream in (r.stdout, r.stderr):
        assert invite not in stream
        assert not any(marker in stream for marker in SECRET_MARKERS), stream


def test_passes_against_the_configured_origin(relay):
    base, env = relay
    invite = cli(env, "invite", "create", "--ttl", "1h").strip()
    r = smoke(base, base, "--expect-max-publication", str(16 * 1024 * 1024), invite=invite)
    assert r.returncode == 0, r.stdout + r.stderr[-2000:]
    assert_quiet(r, invite)
    assert "PASS login bound to a wrong origin refused: 401 bad_signature" in r.stdout
    assert "PASS login bound to the configured origin" in r.stdout
    assert r.stdout.splitlines()[-1] == "PASS all checks"
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


@pytest.mark.parametrize(
    "target, origin, extra",
    [
        ("https://tix.severin.io", "https://tix.severin.io", []),
        ("https://tix.severin.io", "https://tix.severin.io", ["--public"]),
        ("https://api.tix.severin.io", "https://api.tix.severin.io", ["--public"]),
        ("https://relay.dev.severin.io", "https://relay.dev.severin.io", []),
        ("https://example.com", "https://example.com", ["--public"]),
        ("http://relay-internal.dev.severin.io", "http://relay-internal.dev.severin.io", []),
        (
            "https://relay-internal.dev.severin.io",
            "https://relay-internal.dev.severin.io/",
            [],
        ),
        ("https://relay-internal.dev.severin.io", "https://relay.dev.severin.io", ["--public"]),
        ("https://relay-internal.dev.severin.io/v2", "https://relay-internal.dev.severin.io", []),
    ],
)
def test_refuses_targets_off_the_allow_list(target, origin, extra):
    r = smoke(target, origin, *extra, invite="FAKE-not-an-invite")
    assert r.returncode == 2, r.stdout
    assert r.stdout.startswith("FAIL refused: "), r.stdout
    assert len(r.stdout.splitlines()) == 1
