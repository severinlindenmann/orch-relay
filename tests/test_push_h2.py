"""P3-D40b: the real HTTP/2 client path (httpx, no HTTP/1.1 fallback) against a local h2 server."""

import asyncio

import pytest
from directory_support import DEVICE, WS
from drop_support import LAPTOP
from fake_apns import FakeApns, wait_for
from fastapi.testclient import TestClient
from h2_server import H2Server
from push_support import (
    KID,
    TEAM,
    TOKEN_A,
    TOPIC,
    configure,
    outer,
    push_env,
    register,
    rid,
    seed_push,
    send,
)

from orch_relay import proto as P
from orch_relay import push_send as PS
from orch_relay.apns import Apns, HttpxTransport, apns_body
from orch_relay.app import create_app
from orch_relay.push_config import load


@pytest.fixture
def server():
    s = H2Server().start()
    yield s
    s.close()


def make_send(n=1, env="sandbox"):
    send_ = PS.Send(
        rid(n), b"", b"", env, WS, "A", DEVICE, apns_body(P.cj(outer(n))), 10, 123, 10**15
    )
    send_.token = TOKEN_A
    return send_


def apns_for(tmp_path, server, **options):
    env, keys = push_env(tmp_path, envs=("sandbox", "production"), **options)
    transport = HttpxTransport({"sandbox": server.url, "production": server.url})
    return (
        Apns(load(env), transport=transport, clock_s=lambda: 1_790_000_000.0, retry_delays=(0, 0)),
        keys,
        transport,
    )


def test_the_request_goes_out_as_exact_http2(tmp_path, server):
    apns, keys, transport = apns_for(tmp_path, server)

    async def run():
        try:
            return await apns.deliver(make_send())
        finally:
            await transport.aclose()

    assert asyncio.run(run()).kind == "ok"
    (request,) = server.requests
    assert (request["method"], request["path"]) == ("POST", "/3/device/" + TOKEN_A.hex())
    h = request["headers"]
    jwt = h["authorization"].removeprefix("bearer ")
    assert {k: v for k, v in h.items() if k.startswith("apns-")} == {
        "apns-topic": TOPIC,
        "apns-push-type": "alert",
        "apns-priority": "10",
        "apns-expiration": "123",
    }
    assert "apns-collapse-id" not in h and "apns-id" not in h
    assert request["body"] == apns_body(P.cj(outer(1)))
    fake = FakeApns(keys, TEAM, TOPIC, KID)
    assert fake.check_jwt("sandbox", jwt) == 1_790_000_000 and fake.errors == []


def test_answers_travel_back_and_one_connection_serves_many_sends(tmp_path, server):
    server.answer = lambda r: (
        (410, {"reason": "Unregistered", "timestamp": 99})
        if r["path"].endswith("ff")
        else (200, None)
    )
    apns, _keys, transport = apns_for(tmp_path, server)

    async def run():
        try:
            first = await asyncio.gather(*(apns.deliver(make_send(n)) for n in range(1, 21)))
            other = make_send(30)
            other.token = b"\xff" * 32
            return first, await apns.deliver(other)
        finally:
            await transport.aclose()

    first, gone = asyncio.run(run())
    assert {r.kind for r in first} == {"ok"}
    assert (gone.kind, gone.status, gone.timestamp_ms) == ("unregistered", 410, 99)
    assert server.connections == 1  # multiplexed over one HTTP/2 connection
    assert len(server.requests) == 21


def test_streams_are_multiplexed_concurrently(tmp_path, server):
    apns, _keys, transport = apns_for(tmp_path, server)

    async def run():
        # the server's loop is another thread: release it through its own loop
        server.loop.call_soon_threadsafe(lambda: setattr(server, "hold", asyncio.Event()))
        await asyncio.sleep(0.05)
        tasks = [asyncio.create_task(apns.deliver(make_send(n))) for n in range(1, 9)]
        for _ in range(200):
            await asyncio.sleep(0.01)
            if server.peak >= 8:
                break
        peak = server.peak
        server.loop.call_soon_threadsafe(server.hold.set)
        results = await asyncio.gather(*tasks)
        await transport.aclose()
        return peak, results

    peak, results = asyncio.run(run())
    assert peak == 8 and {r.kind for r in results} == {"ok"}
    assert server.connections == 1


def test_a_connection_error_is_retried_then_fails(tmp_path):
    env, _ = push_env(tmp_path, envs=("sandbox",))
    transport = HttpxTransport({"sandbox": "http://127.0.0.1:1"})  # nothing listens
    apns = Apns(
        load(env), transport=transport, clock_s=lambda: 1_790_000_000.0, retry_delays=(0, 0)
    )

    async def run():
        try:
            return await apns.deliver(make_send())
        finally:
            await transport.aclose()

    assert asyncio.run(run()).kind == "failed"


def test_the_whole_relay_delivers_over_real_http2(tmp_path, monkeypatch, server):
    keys = configure(monkeypatch, tmp_path)
    with TestClient(create_app(tmp_path / "data")) as client:
        seed_push(client.app.state.directory)
        push = client.app.state.push
        push.apns.transport = HttpxTransport({"sandbox": server.url, "production": server.url})
        assert register(client, TOKEN_A, 1).status_code == 200
        assert (
            register(client, b"\x09" * 32, 2, session="FAKE-laptop", env="production").status_code
            == 200
        )
        assert send(client, sorted([DEVICE, LAPTOP])).json() == {"accepted": 2}
        assert wait_for(lambda: len(server.requests) == 2)
        fake = FakeApns(keys, TEAM, TOPIC, KID)
        for request in server.requests:
            assert request["body"] == apns_body(P.cj(outer(1)))
            env = "sandbox" if request["path"].endswith(TOKEN_A.hex()) else "production"
            fake.check_jwt(env, request["headers"]["authorization"].removeprefix("bearer "))
        assert fake.errors == []
        assert wait_for(lambda: [r[1] for r in push.sender.results] == ["ok", "ok"])
