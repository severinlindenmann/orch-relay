"""P3-D39 item 2 (D39a1): early answers over a REAL socket (uvicorn, HTTP/1.1, 127.0.0.1 only).

An early 409 and an early exact-retry 200 with an unread 26 MiB body must reach the client intact:
the relay drains the declared remainder after answering, so the kernel never answers unread
upload bytes with a RST that would destroy the response. Also a drain that stalls (the client
stops sending) and a full drain pool (the relay closes without draining; the answer is sent
first). Nothing here contacts any host but the loopback interface.

The same cases through a real Caddy (HTTP/2 to the client, HTTP/1.1 to uvicorn) are the manual /
CI-only test tests/e2e/test_drop_caddy.py (skipped: Caddy is not available locally).
"""

import json
import socket
import threading
import time

import pytest
import uvicorn
from directory_support import NOW
from drop_support import TOKENS, setup, upload

from orch_relay.app import create_app

pytestmark = pytest.mark.slow
SIZE = 26 * 1024 * 1024 - 64 * 1024  # an ORD2 blob near the 26 MiB cap


@pytest.fixture(scope="module")
def big():
    return upload("socket", content=b"\0" * SIZE, chunk=1 << 20)


@pytest.fixture
def relay(tmp_path):
    app = create_app(tmp_path)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    config = uvicorn.Config(app, log_level="warning", lifespan="on", timeout_keep_alive=5)
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started:
        assert time.monotonic() < deadline, "uvicorn did not start"
        time.sleep(0.01)
    setup(app.state.directory, now=NOW)
    app.state.drop.limits.drain_idle = 1.0
    yield app, sock.getsockname()[1]
    server.should_exit = True
    thread.join(10)


def request_head(o_id, length, if_match):
    return (
        f"PUT /v2/drop/{o_id}/versions HTTP/1.1\r\nHost: 127.0.0.1\r\n"
        f"Authorization: Bearer {TOKENS[next(iter(TOKENS))]}\r\n"
        f"Content-Type: application/octet-stream\r\nContent-Length: {length}\r\n"
        f"If-Match: {if_match}\r\n\r\n"
    ).encode()


def exchange(port, body, o_id, if_match, send_all=True, stop_after=None):
    """Send the request (in a thread, as fast as the socket takes it) while reading the answer;
    returns (status, json, bytes the client managed to send, error while sending)."""
    conn = socket.create_connection(("127.0.0.1", port), timeout=60)
    sent = {"n": 0, "error": None}

    def writer():
        try:
            conn.sendall(request_head(o_id, len(body), if_match))
            view = memoryview(body)
            limit = len(body) if stop_after is None else stop_after
            while sent["n"] < limit:
                n = conn.send(view[sent["n"] : min(limit, sent["n"] + 256 * 1024)])
                sent["n"] += n
        except OSError as exc:  # the relay may close after its bounded drain
            sent["error"] = exc

    thread = threading.Thread(target=writer, daemon=True)
    thread.start()
    raw = b""
    try:
        while b"\r\n\r\n" not in raw:
            chunk = conn.recv(65536)
            assert chunk, f"connection closed before an answer: {raw!r}"
            raw += chunk
        head, rest = raw.split(b"\r\n\r\n", 1)
        lines = head.decode().split("\r\n")
        status = int(lines[0].split()[1])
        headers = {k.lower(): v.strip() for k, v in (h.split(":", 1) for h in lines[1:])}
        length = int(headers["content-length"])
        while len(rest) < length:
            chunk = conn.recv(65536)
            assert chunk, "the answer was cut off"
            rest += chunk
        thread.join(60)
        return status, json.loads(rest[:length]), sent, headers
    finally:
        conn.close()


def test_upload_then_early_200_and_early_409_with_an_unread_26_mib_body(relay, big):
    app, port = relay
    signed, _, body = big
    o_id = signed["o"]["object_id"]
    status, answer, _, _ = exchange(port, body, o_id, "0")
    assert (status, answer) == (201, {"version": 1})  # the full 26 MiB streamed and stored
    status, answer, sent, headers = exchange(port, body, o_id, "0")
    assert (status, answer) == (200, {"version": 1})  # the exact retry, answered early
    assert headers.get("connection") == "close" and headers["etag"] == '"1"'
    assert sent["error"] is None and sent["n"] == len(body)  # drained, never reset
    other, _, other_body = upload("socket-b", content=b"\1" * SIZE, chunk=1 << 20)
    status, answer, sent, _ = exchange(port, other_body, other["o"]["object_id"], "4")
    assert (status, answer) == (409, {"error": "version_conflict", "current": 0})
    assert sent["error"] is None and sent["n"] == len(other_body)
    deadline = time.monotonic() + 10  # the relay ends its drain once the last byte arrived
    while app.state.drop.drains.count and time.monotonic() < deadline:
        time.sleep(0.01)
    assert app.state.drop.uploads.count == 0 and app.state.drop.drains.count == 0


def test_stalled_client_still_gets_the_answer(relay, big):
    _app, port = relay
    signed, _, body = big
    head_len = len(body) - signed["o"]["content_len"]
    t = time.monotonic()
    status, answer, _, _ = exchange(
        port, body, signed["o"]["object_id"], "9", stop_after=head_len + 1000
    )
    assert (status, answer) == (409, {"error": "version_conflict", "current": 0})
    assert time.monotonic() - t < 10


def test_full_drain_pool_answers_then_closes(relay, big):
    app, port = relay
    signed, _, body = big
    app.state.drop.drains.count = app.state.drop.drains.total
    head_len = len(body) - signed["o"]["content_len"]
    # the client sends the head and a little more, then waits for the answer (as the phone
    # does once it has one): the answer arrives although the relay does not drain
    status, answer, _, _ = exchange(
        port, body, signed["o"]["object_id"], "9", stop_after=head_len + 1000
    )
    assert (status, answer) == (409, {"error": "version_conflict", "current": 0})
    app.state.drop.drains.count = 0
