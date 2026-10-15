"""Directory authorize-first measurement (P3-D32, G3 re-review D4). Not collected by pytest; run on
demand, alone (no test suite in parallel):

    uv run python tests/bench_directory_preauth.py [seconds]

1. For each class of refused directory request: wall time, `Directory.lock` acquisitions and lock
   hold time per request (in process, through `Directory.handle`, as the HTTP endpoint calls it).
2. Throughput of an authenticated directory route (GET members, device session) and of an
   authenticated bridge transaction (both share `Directory.lock`), idle and while threads flood
   bad-token directory requests: unpaced 1, 4 and 16 threads, and a paced 750/s and 3000/s
   flood over 16 threads (the G3 re-review measured ~750/s saturating the lock).

Unpaced in-process flooders also compete for the GIL, so they depress throughput even without
any lock; the paced rows show the cost of a given flood rate. FAKE keys only.
"""

import logging
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path[:0] = [str(Path(__file__).parent), str(Path(__file__).parents[1])]
logging.disable(logging.WARNING)

from bridge_support import RID
from directory_support import DEVICE, PERSON, WS, seed, unthrottled

from orch_relay import db
from orch_relay import proto as P
from orch_relay.app import create_app

SECONDS = float(sys.argv[1]) if len(sys.argv) > 1 else 2.0
BAD = {"authorization": "Bearer nope"}
GOOD = {"authorization": "Bearer FAKE-device"}
JSON = {"content-type": "application/json"}
ADDRESS = "203.0.113.9"

tmp = tempfile.mkdtemp()
app = create_app(tmp)
db.migrate(app.state.data_dir / db.DB_NAME)
d, bridge = app.state.directory, app.state.bridge
seed(d)
unthrottled(d)  # measures the lock path, not the P3-D35 buckets


class TimedLock:
    """Counts acquisitions and hold time of Directory.lock (re-entrant like the real RLock)."""

    def __init__(self, real):
        self.real, self.count, self.held, self.depth, self.start = real, 0, [], {}, {}

    def __enter__(self):
        self.real.acquire()
        me = threading.get_ident()
        self.depth[me] = self.depth.get(me, 0) + 1
        if self.depth[me] == 1:
            self.count += 1
            self.start[me] = time.perf_counter()
        return self

    def __exit__(self, *exc):
        me = threading.get_ident()
        self.depth[me] -= 1
        if not self.depth[me]:
            self.held.append(time.perf_counter() - self.start[me])
        self.real.release()

    def __getattr__(self, name):
        return getattr(self.real, name)


REFUSED = {
    "members, bad token (401)": ("members", WS, "GET", b"", {}, BAD, 401),
    "feed, bad token (401)": ("feed", PERSON, "GET", b"", {}, BAD, 401),
    "card GET, bad token (401)": ("card", WS, "GET", b"", {}, BAD, 401),
    "device GET, bad token (401)": ("device", DEVICE, "GET", b"", {}, BAD, 401),
    "membership PUT, bad token (401)": ("membership", WS, "PUT", b"{}", {}, {**BAD, **JSON}, 401),
    "logout, unknown token (200)": ("logout", None, "POST", b"{}", {}, {**BAD, **JSON}, 200),
    "login, unknown challenge (401)": (
        "login",
        None,
        "POST",
        P.cj({"challenge": P.b64u(bytes(32)), "kind": "device", "id": DEVICE, "sig": ""}),
        {},
        JSON,
        401,
    ),
    "accounts, unknown invite + challenge (401)": (
        "accounts",
        None,
        "POST",
        P.cj(
            {
                "invite": "x",
                "pk_pub": "",
                "device_cert": {},
                "challenge": P.b64u(bytes(32)),
                "sig": "",
            }
        ),
        {},
        JSON,
        401,
    ),
}


def call(spec):
    route, ident, method, raw, query, headers, status = spec
    r = d.handle(route, ident, method, raw, query, headers, ADDRESS)
    assert r.status_code == status, (route, r.status_code, r.body)


def per_request(spec, n=2000):
    real = d.lock
    d.lock = timed = TimedLock(real)
    try:
        start = time.perf_counter()
        for _ in range(n):
            call(spec)
        wall = (time.perf_counter() - start) / n * 1e6
    finally:
        d.lock = real
    held = sorted(timed.held) or [0.0]
    return wall, timed.count / n, held[len(held) // 2] * 1e6, held[int(len(held) * 0.9)] * 1e6


def members_good():
    call(("members", WS, "GET", b"", {}, GOOD, 200))


def bridge_good():
    bridge.transaction("bridge", {"ws": WS, "rid": RID}, "GET", b"", {}, GOOD, "x", "t", True)


def throughput(fn):
    count, end = 0, time.perf_counter() + SECONDS
    while time.perf_counter() < end:
        fn()
        count += 1
    return count / SECONDS


def flooded(fn, threads, rate=None):
    """Throughput of fn while `threads` threads send bad-token directory requests: unpaced
    (as fast as the GIL allows), or paced at `rate` requests/s in total. Returns (fn/s, flood/s)."""
    stop = threading.Event()
    spec = REFUSED["members, bad token (401)"]
    sent = [0] * threads

    def flood(i):
        interval = threads / rate if rate else 0
        due = time.perf_counter()
        while not stop.is_set():
            if interval:
                due += interval
                pause = due - time.perf_counter()
                if pause > 0:
                    time.sleep(pause)
            call(spec)
            sent[i] += 1

    workers = [threading.Thread(target=flood, args=(i,)) for i in range(threads)]
    for w in workers:
        w.start()
    try:
        time.sleep(0.2)
        before = sum(sent)
        result = throughput(fn)
        return result, (sum(sent) - before) / SECONDS
    finally:
        stop.set()
        for w in workers:
            w.join()


def main():
    print(f"python {sys.version.split()[0]}, {SECONDS:.1f} s per throughput sample")
    print(f"{'refused request':45} {'wall µs':>8} {'locks':>6} {'held p50 µs':>12} {'p90 µs':>8}")
    for name, spec in REFUSED.items():
        wall, locks, p50, p90 = per_request(spec)
        print(f"{name:45} {wall:8.1f} {locks:6.2f} {p50:12.1f} {p90:8.1f}")
    routes = (("directory GET members", members_good), ("bridge GET transaction", bridge_good))
    print()
    print("Unpaced flooder threads (in process; with no lock left they still compete for the GIL):")
    print(
        f"{'authenticated route':28} {'idle/s':>8} "
        + " ".join(f"{f'{n} thr':>9}" for n in (1, 4, 16))
    )
    for name, fn in routes:
        idle = throughput(fn)
        loaded = [flooded(fn, n)[0] for n in (1, 4, 16)]
        print(f"{name:28} {idle:8.0f} " + " ".join(f"{x:9.0f}" for x in loaded))
    print()
    print("Paced flood over 16 threads (route/s, flood requests actually served/s):")
    rates = (750, 3000)
    print(
        f"{'authenticated route':28} {'idle/s':>8} "
        + " ".join(f"{f'{r}/s flood':>20}" for r in rates)
    )
    for name, fn in routes:
        idle = throughput(fn)
        cells = []
        for rate in rates:
            got, flood = flooded(fn, 16, rate)
            cells.append(f"{got:9.0f} ({flood:6.0f}/s)")
        print(f"{name:28} {idle:8.0f} " + " ".join(f"{c:>20}" for c in cells))
    bridge.close()


if __name__ == "__main__":
    main()
