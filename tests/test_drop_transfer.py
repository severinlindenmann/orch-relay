"""P3-D39 (D39a1): early answers, the drain pool and its bounds, upload/read/download slots,
transfer bounds and concurrent writers, driven at the ASGI level (one event loop per test)."""

import asyncio
import json
import time

import pytest
from directory_support import DEVICE, NOW, WS
from drop_support import LAPTOP, TOKENS, object_id, rows, setup, upload, usage

from orch_relay import db
from orch_relay.app import create_app


class Harness:
    def __init__(self, tmp_path):
        self.app = create_app(tmp_path)
        self.drop = self.app.state.drop
        self.d = self.app.state.directory
        db.migrate(self.d.path)
        self.drop.startup_sweep()
        setup(self.d)
        lim = self.drop.limits
        lim.idle, lim.drain_idle, lim.drain_total, lim.brief_s = 2.0, 0.3, 1.0, 0.3


@pytest.fixture
def h(tmp_path):
    return Harness(tmp_path)


def scope(method, path, params, author=DEVICE, length=None, if_match="0", holder=None, extra=()):
    headers = [(b"authorization", ("Bearer " + TOKENS[author]).encode())]
    if length is not None:
        headers.append((b"content-length", str(length).encode()))
    if if_match is not None:
        headers.append((b"if-match", if_match.encode()))
    if holder is not None:
        headers.append((b"orch-holder", holder.encode()))
    headers += list(extra)
    return {
        "type": "http",
        "method": method,
        "path": path,
        "headers": headers,
        "query_string": b"",
        "path_params": params,
    }


class Peer:
    """A client: `receive` hands out `chunks` (with optional pauses), then stalls or disconnects;
    `send` records the messages."""

    def __init__(self, chunks, pause=0.0, then="stall", hold=None):
        self.chunks, self.pause, self.then = list(chunks), pause, then
        self.sent, self.read, self.calls = [], 0, 0
        self.hold = hold  # an asyncio.Event the body send waits on

    async def receive(self):
        self.calls += 1
        if self.chunks:
            if self.pause:
                await asyncio.sleep(self.pause)
            data = self.chunks.pop(0)
            self.read += len(data)
            return {
                "type": "http.request",
                "body": data,
                "more_body": bool(self.chunks) or self.then != "end",
            }
        if self.then == "disconnect":
            return {"type": "http.disconnect"}
        if self.then == "trickle":
            await asyncio.sleep(0.05)
            self.read += 1
            return {"type": "http.request", "body": b"x", "more_body": True}
        await asyncio.sleep(3600)

    async def send(self, message):
        if self.hold is not None and message["type"] == "http.response.body" and message["body"]:
            await self.hold.wait()
        self.sent.append(message)

    @property
    def status(self):
        return next(m["status"] for m in self.sent if m["type"] == "http.response.start")

    @property
    def json(self):
        return json.loads(
            b"".join(m.get("body", b"") for m in self.sent if m["type"] == "http.response.body")
        )

    def header(self, name):
        start = next(m for m in self.sent if m["type"] == "http.response.start")
        return dict(start["headers"]).get(name)

    @property
    def complete(self):
        return any(m["type"] == "http.response.body" and not m.get("more_body") for m in self.sent)


def split(body, size=65536):
    return [body[i : i + size] for i in range(0, len(body), size)]


async def put(h, body, signed=None, chunks=None, author=None, **kw):
    o_id = signed["o"]["object_id"] if signed else object_id("x")
    author = author or (signed["o"]["author_id"] if signed else DEVICE)
    kw.setdefault("then", "end" if chunks is None else "stall")
    peer = kw.pop("peer", None) or Peer(
        chunks if chunks is not None else split(body),
        **{k: kw.pop(k) for k in ("pause", "then") if k in kw},
    )
    s = scope(
        "PUT",
        f"/v2/drop/{o_id}/versions",
        {"o": o_id},
        author=author,
        length=kw.pop("length", len(body)),
        **kw,
    )
    await h.drop.endpoint(s, peer.receive, peer.send, "put")
    return peer


def big_upload(label, size=26 * 1024 * 1024 - 4096, **kw):
    return upload(label, content=b"\0" * size, chunk=1 << 20, **kw)


def test_early_409_drains_after_freeing_the_upload_slot(h):
    async def run():
        seen = {}
        signed, _, body = upload("early", content=b"\0" * 300_000)

        async def drain():
            seen["slots"] = h.drop.uploads.count
            seen["drains"] = h.drop.drains.count

        h.drop.hooks["drain"] = drain
        peer = await put(h, body, signed, if_match="5")  # 409 version_conflict before the blob
        assert (peer.status, peer.json) == (409, {"error": "version_conflict", "current": 0})
        assert peer.header(b"connection") == b"close"
        assert seen == {"slots": 0, "drains": 1}
        assert peer.read == len(body) and peer.complete  # the declared remainder was drained
        assert h.drop.drains.count == 0 and h.drop.uploads.count == 0

    asyncio.run(run())


def test_early_200_exact_retry_does_not_read_the_blob(h):
    async def run():
        signed, _, body = upload("retry", content=b"\0" * 300_000)
        first = await put(h, body, signed)
        assert first.status == 201
        reads = []
        h.drop.hooks["drain"] = lambda: reads.append(h.drop.uploads.count)
        peer = await put(h, body, signed, then="stall")
        assert (peer.status, peer.json, peer.header(b"etag")) == (200, {"version": 1}, b'"1"')
        assert reads == [0]
        assert len(rows(h.d.path, "drop_versions")) == 1

    asyncio.run(run())


def test_drain_stops_at_idle_and_at_total(h):
    async def run():
        signed, _, body = upload("idle", content=b"\0" * 300_000)
        head = body[: len(body) - signed["o"]["content_len"]]
        t = time.monotonic()
        peer = await put(h, body, signed, chunks=[head], then="stall", if_match="3")
        assert peer.status == 409 and peer.complete
        assert 0.25 < time.monotonic() - t < 1.5  # drain_idle 0.3 s
        t = time.monotonic()
        peer = await put(h, body, signed, chunks=[head], then="trickle", if_match="3")
        assert peer.status == 409 and peer.complete
        assert 0.9 < time.monotonic() - t < 2.0  # drain_total 1.0 s
        assert peer.read < len(body)  # at most the declared remainder, here cut by time

    asyncio.run(run())


def test_full_drain_pool_closes_without_draining(h):
    async def run():
        signed, _, body = upload("pool", content=b"\0" * 300_000)
        head = body[: len(body) - signed["o"]["content_len"]]
        called = []
        h.drop.hooks["drain"] = lambda: called.append(1)
        h.drop.drains.count = h.drop.drains.total  # 32 drains in flight
        t = time.monotonic()
        peer = await put(h, body, signed, chunks=[head], then="stall", if_match="3")
        assert peer.status == 409 and peer.complete and called == []
        assert time.monotonic() - t < 0.25
        h.drop.drains.count = 0
        h.drop.drains.used[("device", DEVICE)] = 2  # the device's 2 drains
        peer = await put(h, body, signed, chunks=[head], then="stall", if_match="3")
        assert peer.complete and called == []

    asyncio.run(run())


def test_refusals_before_a_slot_never_drain(h):
    async def run():
        signed, _, body = upload("noslot", content=b"\0" * 300_000)
        drained = []
        h.drop.hooks["drain"] = lambda: drained.append(1)
        peer = Peer(split(body, 16384), then="stall")
        s = scope(
            "PUT",
            f"/v2/drop/{signed['o']['object_id']}/versions",
            {"o": signed["o"]["object_id"]},
            length=len(body),
        )
        s["headers"][0] = (b"authorization", b"Bearer nobody")
        t = time.monotonic()
        await h.drop.endpoint(s, peer.receive, peer.send, "put")
        assert (peer.status, peer.json) == (401, {"error": "unauthenticated"})
        assert peer.read <= 64 * 1024 + 16384 and drained == []  # at most 64 KiB (or 1 s)
        assert time.monotonic() - t < 1.0
        # a 413 for a declared length reads nothing at all
        peer = Peer([body], then="stall")
        s = scope("PUT", s["path"], s["path_params"], length=h.drop.max_body + 1)
        await h.drop.endpoint(s, peer.receive, peer.send, "put")
        assert (peer.status, peer.calls) == (413, 0) and peer.complete

    asyncio.run(run())


def test_upload_slot_caps(h):
    async def run():
        gate = asyncio.Event()
        arrived = []

        async def head():
            arrived.append(1)
            await gate.wait()

        h.drop.hooks["head"] = head

        async def start(author, label):
            signed, _, body = upload(label, author=author)
            return asyncio.create_task(put(h, body, signed))

        a = [await start(DEVICE, f"p{i}") for i in range(2)]
        while len(arrived) < 2:
            await asyncio.sleep(0.01)
        third = await put(h, upload("p3")[2], upload("p3")[0])
        assert (third.status, third.json) == (429, {"error": "quota_exceeded", "quota": "slot"})
        assert third.header(b"retry-after") == b"1"
        b = await start(LAPTOP, "l1")
        while len(arrived) < 3:
            await asyncio.sleep(0.01)
        fourth = await put(h, upload("l2", author=LAPTOP)[2], upload("l2", author=LAPTOP)[0])
        assert fourth.json == {"error": "quota_exceeded", "quota": "slot"}  # 3 per person
        h.drop.uploads.total = 3
        w = await put(h, upload("w", author=WS)[2], upload("w", author=WS)[0], holder="1")
        assert (w.status, w.json) == (503, {"error": "overloaded"})  # relay-wide
        gate.set()
        for task in [*a, b]:
            assert (await task).status == 201
        assert h.drop.uploads.count == 0 and not h.drop.uploads.used

    asyncio.run(run())


def test_workspace_upload_slots(h):
    async def run():
        gate = asyncio.Event()
        h.drop.hooks["before_commit"] = lambda plan: gate.wait()
        tasks = []
        for i in range(4):
            s, _, b = upload(f"w{i}", author=WS)
            tasks.append(asyncio.create_task(put(h, b, s, holder="1")))
        while h.drop.uploads.count < 4:
            await asyncio.sleep(0.01)
        s, _, b = upload("w5", author=WS)
        fifth = await put(h, b, s, holder="1")
        assert fifth.json == {"error": "quota_exceeded", "quota": "slot"}
        # a device's upload counts against the same workspace share once its head names it
        s, _, b = upload("dev")
        dev = await put(h, b, s)
        assert dev.json == {"error": "quota_exceeded", "quota": "slot"}
        gate.set()
        assert [(await t).status for t in tasks] == [201] * 4
        assert h.drop.uploads.count == 0

    asyncio.run(run())


def test_minimum_rate_and_idle_close_and_clean_up(h):
    async def run():
        h.drop.limits.grace, h.drop.limits.min_rate = 0.2, 10**9
        signed, _, body = upload("slow", content=b"\0" * 300_000)
        peer = await put(h, body, signed, chunks=split(body, 4096), pause=0.05, then="end")
        assert (peer.status, peer.json) == (400, {"error": "malformed"})
        assert peer.read < len(body)
        h.drop.limits.grace, h.drop.limits.min_rate, h.drop.limits.idle = 30, 1, 0.3
        head = body[: len(body) - signed["o"]["content_len"] + 1000]
        peer = await put(h, body, signed, chunks=[head], then="stall")
        assert (peer.status, peer.json) == (400, {"error": "malformed"})
        assert rows(h.d.path, "drop_objects") == [] and usage(h.d.path) == {}
        assert list(h.drop.tmp.iterdir()) == [] and h.drop.uploads.count == 0

    asyncio.run(run())


def test_killed_upload_mid_blob_leaves_nothing(h):
    async def run():
        signed, _, body = upload("killed", content=b"\0" * 300_000)
        peer = await put(h, body, signed, chunks=split(body)[:2], then="disconnect")
        assert peer.read < len(body)
        assert peer.sent == []  # nothing to answer
        assert rows(h.d.path, "drop_objects") == [] and usage(h.d.path) == {}
        assert list(h.drop.tmp.iterdir()) == [] and list(h.drop.blobs.iterdir()) == []
        assert h.drop.uploads.count == 0

    asyncio.run(run())


def test_two_concurrent_writers_of_the_next_version(h):
    async def run():
        o_id = object_id("race")
        v1, _, b1 = upload(o_id, kind="document")
        assert (await put(h, b1, v1)).status == 201
        arrived, gate = [], asyncio.Event()

        async def before(plan):
            arrived.append(plan.o["author_id"])
            if len(arrived) == 2:
                gate.set()
            await gate.wait()

        h.drop.hooks["before_commit"] = before
        a, _, ab = upload(o_id, kind="document", version=2, parent=v1["o"])
        b, _, bb = upload(o_id, kind="document", version=2, parent=v1["o"], author=LAPTOP)
        pa, pb = await asyncio.gather(put(h, ab, a, if_match="1"), put(h, bb, b, if_match="1"))
        assert sorted([pa.status, pb.status]) == [201, 409]
        loser = pa if pa.status == 409 else pb
        assert loser.json == {"error": "version_conflict", "current": 2}
        blobs = [p for p in h.drop.blobs.rglob("*") if p.is_file()]
        assert len(blobs) == 2  # version 1 and the winner's version 2
        assert list(h.drop.tmp.iterdir()) == []
        assert usage(h.d.path)[("workspace", WS)][2] == 2

    asyncio.run(run())


def test_concurrent_identical_uploads_store_one_file(h):
    async def run():
        signed, _, body = upload("same")
        arrived, gate = [], asyncio.Event()

        async def before(plan):
            arrived.append(1)
            if len(arrived) == 2:
                gate.set()
            await gate.wait()

        h.drop.hooks["before_commit"] = before
        p1, p2 = await asyncio.gather(put(h, body, signed), put(h, body, signed))
        assert sorted([p1.status, p2.status]) == [200, 201]
        assert len([p for p in h.drop.blobs.rglob("*") if p.is_file()]) == 1

    asyncio.run(run())


def test_takeover_versus_put_race(h):
    """A host/hold takeover committed while the host's PUT streams: 409 fenced at the commit;
    the reverse order: the PUT commits and the new holder lists it."""

    async def run():
        signed, _, body = upload("race", author=WS)

        async def take(plan):
            h.drop.hooks.pop("before_commit")
            from contextlib import closing

            with h.d.lock, closing(db.connect(h.d.path)) as con, con:
                con.row_factory = __import__("sqlite3").Row
                h.app.state.bridge.hold(con, WS, {"gen": None, "take_over": True}, NOW)

        h.drop.hooks["before_commit"] = take
        peer = await put(h, body, signed, holder="1")
        assert (peer.status, peer.json) == (409, {"error": "fenced"})
        assert rows(h.d.path, "drop_objects") == [] and list(h.drop.tmp.iterdir()) == []
        assert [p for p in h.drop.blobs.rglob("*") if p.is_file()] == []
        peer = await put(h, body, signed, holder="2")
        assert peer.status == 201

    asyncio.run(run())


def test_read_slot_held_until_the_body_is_sent(h):
    async def run():
        signed, _, body = upload("list")
        assert (await put(h, body, signed)).status == 201
        holds = []

        async def listing(author=DEVICE, held=True):
            hold = asyncio.Event() if held else None
            payload = json.dumps({"workspace_id": WS, "direction": "sending"}).encode()
            peer = Peer([payload], hold=hold, then="end")
            s = scope(
                "POST", "/v2/drop/list", {}, author=author, length=len(payload), if_match=None
            )
            task = asyncio.create_task(h.drop.endpoint(s, peer.receive, peer.send, "list"))
            if held:
                holds.append(hold)
            return peer, task

        p1, t1 = await listing()
        p2, t2 = await listing()
        while h.drop.reads.count < 2 or len([m for m in p2.sent]) < 1:
            await asyncio.sleep(0.01)
        assert h.drop.reads.count == 2  # serialized, but the slot is still held
        p3, t3 = await listing(held=False)
        await asyncio.sleep(0.05)
        await t3
        assert (p3.status, p3.json) == (429, {"error": "quota_exceeded", "quota": "slot"})
        _p4, t4 = await listing(LAPTOP)
        _p5, t5 = await listing(LAPTOP)
        while h.drop.reads.count < 4:
            await asyncio.sleep(0.01)
        p6, t6 = await listing(LAPTOP, held=False)
        await t6
        assert p6.json == {"error": "quota_exceeded", "quota": "slot"}  # 4 per person
        for hold in holds:
            hold.set()
        await asyncio.gather(t1, t2, t4, t5)
        assert p1.status == 200 and h.drop.reads.count == 0
        h.drop.reads.count = h.drop.reads.total
        p7, t7 = await listing(WS, held=False)
        await t7
        assert (p7.status, p7.json) == (503, {"error": "overloaded"})

    asyncio.run(run())


def test_download_slots_and_rate(h):
    async def run():
        signed, _, body = upload("dl", content=b"\0" * 600_000)
        assert (await put(h, body, signed)).status == 201
        o_id = signed["o"]["object_id"]

        async def download(author=DEVICE, hold=None):
            peer = Peer([], hold=hold)
            s = scope(
                "GET",
                f"/v2/drop/{o_id}/versions/1/blob",
                {"o": o_id, "v": "1"},
                author=author,
                if_match=None,
            )
            return peer, asyncio.create_task(h.drop.endpoint(s, peer.receive, peer.send, "blob"))

        gate = asyncio.Event()
        held = [await download(hold=gate) for _ in range(4)]
        while h.drop.downloads.count < 4:
            await asyncio.sleep(0.01)
        p, t = await download()
        await t
        assert p.json == {"error": "quota_exceeded", "quota": "slot"}
        gate.set()
        for peer, task in held:
            await task
            assert peer.status == 200
            assert sum(len(m.get("body", b"")) for m in peer.sent[1:]) == signed["o"]["content_len"]
        assert h.drop.downloads.count == 0
        # a reader slower than the minimum rate is cut off and frees its slot
        h.drop.limits.grace, h.drop.limits.min_rate = 0.1, 10**9

        class Slow(Peer):
            async def send(self, message):
                await asyncio.sleep(0.06)
                self.sent.append(message)

        peer = Slow([])
        s = scope("GET", f"/v2/drop/{o_id}/versions/1/blob", {"o": o_id, "v": "1"}, if_match=None)
        await h.drop.endpoint(s, peer.receive, peer.send, "blob")
        assert not peer.complete and h.drop.downloads.count == 0

    asyncio.run(run())
