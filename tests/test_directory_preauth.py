"""P3-D32 (G3 re-review D4): every directory route authorizes first, outside Directory.lock."""

import threading

from fastapi.testclient import TestClient

from orch_relay.app import create_app


def test_connections_are_per_thread_and_reused(tmp_path):
    with TestClient(create_app(tmp_path)) as c:
        d = c.app.state.directory
        seen = {}

        def grab(name):
            seen[name] = (d.connection("read"), d.connection("read"), d.connection("write"))

        threads = [threading.Thread(target=grab, args=(n,)) for n in ("a", "b")]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        (a1, a2, aw), (b1, _, bw) = seen["a"], seen["b"]
        assert a1 is a2 and a1 is not aw  # reused within a thread, one per purpose
        assert a1 is not b1 and aw is not bw  # never shared between threads
        assert a1.execute("PRAGMA query_only").fetchone()[0] == 1
        assert a1.execute("PRAGMA busy_timeout").fetchone()[0] == 0
        assert aw.execute("PRAGMA query_only").fetchone()[0] == 0
