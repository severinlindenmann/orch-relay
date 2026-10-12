"""G1 (P3-D33) measurement: how long a final publication holds Directory.lock. Not collected by
pytest; run on demand:

    uv run python tests/bench_publication_lockhold.py

Two scenarios, each in its own process (so peak RSS is per scenario), over HTTP (TestClient)
against a SQLite file (WAL, synchronous=FULL). Staging is seeded with the production staging code
on a direct connection; only the final PUT checkpoint is measured.

- append_200k: an accepted 200,000-head append to the workspace log (4 pages at the 4 MiB cap).
- tickets_10k_refused: a refused first publication of 10,000 ticket logs x 2 pages each (the
  last ticket's signed entry disagrees with its proof, so it is refused after every fold).

Reported: wall time of the PUT, the longest single hold of Directory.lock, the total time it was
held, the number of holds, and the process's peak RSS. FAKE keys only.
"""

import json
import platform
import resource
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import closing
from pathlib import Path

sys.path[:0] = [str(Path(__file__).parent), str(Path(__file__).parents[1])]

from checkpoint_support import CORPUS, WS, seed
from directory_support import unthrottled
from fastapi.testclient import TestClient

from orch_relay import db
from orch_relay import proto as P
from orch_relay.app import create_app
from orch_relay.checkpoints import PAGE_CAP, ZERO, Relay
from ref import checkpoints as C
from ref import orch_protocol_ref as R

NOW = 1790000000000
V = CORPUS["suites"]["2"]
S = R.SUITES[2]
WSK = S.sig_key(bytes.fromhex(V["keys"]["wsk_a.sig"]["seed"]))
HOST = {"Authorization": "Bearer FAKE-workspace", "Orch-Holder": "1"}
HOST |= {"Content-Type": "application/json"}


class HoldRecorder:
    """Directory.lock, recording every outermost hold (re-entrant like the real RLock)."""

    def __init__(self, lock):
        self.lock, self.depth, self.since, self.holds = lock, 0, 0.0, []
        self.local = threading.local()

    def __enter__(self):
        self.lock.acquire()
        if self.depth == 0:
            self.since = time.perf_counter()
        self.depth += 1
        return self

    def __exit__(self, *exc):
        self.depth -= 1
        if self.depth == 0:
            self.holds.append(time.perf_counter() - self.since)
        self.lock.release()

    def acquire(self, *a, **k):
        return self.__enter__()

    def release(self):
        self.__exit__()

    def _is_owned(self):
        return self.lock._is_owned()


def entry(heads, acc=ZERO, seq=0):
    for h in heads:
        acc = C.log_acc(acc, h)
    return {"seq": seq + len(heads), "head": heads[-1], "acc": acc}


def page(kind, log, start, heads):
    p = {"kind": kind, "log": log, "after_seq": start["seq"], "from_acc": start["acc"]}
    p["heads"] = heads
    p["digest"] = C.page_digest(p)
    return p


def stage(path, held, target, pages):
    source = C.checkpoint_hash(held) if held else None
    h = C.checkpoint_hash(target)
    pages = sorted(pages, key=lambda p: (p["kind"], p["log"], p["after_seq"]))
    with closing(db.connect(path)) as con, con:
        relay = Relay(None, con, WS, NOW)
        for i, p in enumerate(pages):
            relay.put_staging(source, h, i, p, P.cj(p), 1 << 40)
        manifest = {"pages": [C.descriptor(i, p) for i, p in enumerate(pages)]}
        relay.put_staging(source, h, None, manifest, P.cj(manifest), 1 << 40)
    return {"checkpoint": target, "source_hash": source}


def base_object(root, ws_entry):
    return {
        "v": 2,
        "suite": 2,
        "kind": "workspace_checkpoint",
        "workspace_id": WS,
        "genesis": root,
        "n": 1,
        "at": "2026-09-21T13:46:40Z",
        "workspace_log": ws_entry,
        "tickets": {},
    }


def publish(client, body):
    d = client.app.state.directory
    recorder = HoldRecorder(d.lock)
    d.lock = recorder
    began = time.perf_counter()
    r = client.put(f"/v2/workspaces/{WS}/checkpoint", content=P.cj(body), headers=HOST)
    wall = time.perf_counter() - began
    d.lock = recorder.lock
    return r, wall, recorder.holds


def scenario(name):
    tmp = Path(tempfile.mkdtemp())
    pinned = next(
        c for c in V["checkpoints"]["cases"] if c["name"] == "first_checkpoint_full_proof"
    )
    root = pinned["state"]["genesis"]["pin"]["o"]["genesis"]
    with TestClient(create_app(tmp)) as client:
        path = tmp / db.DB_NAME
        seed(path, pinned["state"], pinned)
        client.app.state.directory.clock = lambda: NOW
        unthrottled(client.app.state.directory)  # benchmark, not the P3-D35 buckets
        ws_heads = [root] + [C.digest(f"FAKE ws {i}".encode()) for i in range(1, 4)]
        if name == "append_200k":
            o = base_object(root, entry(ws_heads))
            first = R.sign_object(S, WSK, o)
            body = stage(path, None, first, [page("appended", "workspace", C.EMPTY, ws_heads)])
            r = client.put(f"/v2/workspaces/{WS}/checkpoint", content=P.cj(body), headers=HOST)
            assert r.json()["result"] == "accepted", r.text
            per_page = (PAGE_CAP - 512) // 74
            cursor = entry(ws_heads)
            heads = [C.digest(f"FAKE long {i}".encode()) for i in range(200_000)]
            pages = []
            for k in range(0, len(heads), per_page):
                chunk = heads[k : k + per_page]
                pages.append(page("appended", "workspace", cursor, chunk))
                cursor = entry(chunk, cursor["acc"], cursor["seq"])
            second = R.sign_object(S, WSK, {**o, "n": 2, "workspace_log": cursor})
            body = stage(path, first, second, pages)
            expect = "accepted"
        else:
            o = base_object(root, entry([root]))
            pages = [page("appended", "workspace", C.EMPTY, [root])]
            for t in range(10_000):
                uid = f"01{t:024d}"
                hs = [C.digest(f"FAKE t{t} h{i}".encode()) for i in range(2)]
                o["tickets"][uid] = entry(hs)
                pages.append(page("appended", uid, C.EMPTY, hs[:1]))
                pages.append(page("appended", uid, entry(hs[:1]), hs[1:]))
            o["tickets"][uid] = entry([C.digest(b"FAKE wrong")])  # refused after every fold
            body = stage(path, None, R.sign_object(S, WSK, o), pages)
            expect = "chain_diverged"
        r, wall, holds = publish(client, body)
        got = r.json().get("result") or r.json().get("error")
        assert got == expect, r.text
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return {
        "result": got,
        "wall_s": round(wall, 3),
        "longest_hold_s": round(max(holds), 4),
        "total_hold_s": round(sum(holds), 4),
        "holds": len(holds),
        "peak_rss_mb": round(rss / (1 if sys.platform == "darwin" else 1 / 1024) / 1e6, 1),
    }


if __name__ == "__main__":
    if len(sys.argv) > 1:
        print(json.dumps(scenario(sys.argv[1])))
        sys.exit(0)
    out = {"python": platform.python_version(), "platform": platform.platform()}
    for name in ("append_200k", "tickets_10k_refused"):
        run = subprocess.run(
            [sys.executable, __file__, name], capture_output=True, text=True, check=True
        )
        out[name] = json.loads(run.stdout.strip().splitlines()[-1])
    print(json.dumps(out, indent=2))
