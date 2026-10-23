"""P3-D36 round 2 (review F3): shutting the relay down while a maintenance sweep waits on a
write lock held by another process must not crash (it closed the sweep's connection under the
running statement: SIGSEGV), and a busy sweep must not end the maintenance loop.

The app runs in a subprocess (a crash would take pytest down) with a timeout; the test asserts
its exit code, not timings."""

import asyncio
import os
import sqlite3
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest
from push_support import configure, push_env

from orch_relay import db
from orch_relay.app import create_app

ROOT = Path(__file__).resolve().parents[1]

SCRIPT = textwrap.dedent(
    """
    import sqlite3, sys, threading, time
    from fastapi.testclient import TestClient
    from orch_relay import db
    from orch_relay.app import create_app

    data = sys.argv[1]
    app = create_app(data)
    entered = threading.Event()
    real = app.state.push.sweep

    def sweep():
        entered.set()
        real()

    app.state.push.sweep = sweep
    with TestClient(app):
        holder = sqlite3.connect(
            data + "/" + db.DB_NAME, isolation_level=None, check_same_thread=False
        )
        holder.execute("BEGIN IMMEDIATE")  # another process (the operator CLI) holds the lock
        assert entered.wait(30)
        time.sleep(0.3)  # the sweep is now waiting in BEGIN IMMEDIATE (busy timeout 5 s)
        threading.Timer(1.0, holder.rollback).start()
    print("clean exit", flush=True)
    """
)


def test_shutdown_while_a_sweep_waits_on_the_lock_does_not_crash(tmp_path):
    db.init_schema(tmp_path / db.DB_NAME)
    env, _keys = push_env(tmp_path)  # the sweep runs only on a relay with push configured
    r = subprocess.run(
        [sys.executable, "-X", "faulthandler", "-c", SCRIPT, str(tmp_path)],
        env={**os.environ, **env},
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert r.returncode == 0, (r.returncode, r.stdout, r.stderr[-2000:])
    assert "clean exit" in r.stdout


def test_a_busy_sweep_does_not_end_the_maintenance_loop(tmp_path, caplog, monkeypatch):
    configure(monkeypatch, tmp_path)
    app = create_app(tmp_path / "data")
    real_sleep = asyncio.sleep

    async def no_wait(_seconds):
        await real_sleep(0)

    monkeypatch.setattr(asyncio, "sleep", no_wait)
    owner = app.state.push
    calls = []

    def sweep(calls=calls):
        calls.append(1)
        if len(calls) == 1:
            raise sqlite3.OperationalError("FAKE database is locked")
        raise asyncio.CancelledError  # ends the loop after its second round

    owner.sweep = sweep
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(owner.maintenance())
    assert len(calls) == 2
    assert caplog.text.count("sweep failed") == 1
