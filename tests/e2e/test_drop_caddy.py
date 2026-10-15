"""P3-D39 item 2 (D39a1): early answers through a real Caddy (HTTP/2 to the client, HTTP/1.1 to
uvicorn). MANUAL / CI-only: skipped unless ORCH_RELAY_CADDY_E2E is set, because Caddy is not
installed on the development laptop and this test must never contact a deployed relay.

Exact steps (all on one machine, loopback only, no deployed host):

1. Start a relay with a scratch data directory, seeded like tests/drop_support.setup (the test
   seeds it itself through ORCH_RELAY_DATA when it starts the relay in-process on 127.0.0.1:8401):
       ORCH_RELAY_CADDY_E2E=1 uv run pytest -q tests/e2e/test_drop_caddy.py
   The test starts uvicorn on 127.0.0.1:8401 itself.
2. Before step 1, run Caddy (>= 2.7) with this Caddyfile (a local CA, HTTP/2 on 127.0.0.1:8443,
   the upload-path body cap and timeouts of P3 design §14.8 / D40c):
       {
           local_certs
           auto_https disable_redirects
       }
       https://127.0.0.1:8443 {
           tls internal
           @drop path_regexp drop ^/v2/drop/[0-9a-f]{32}/versions$
           request_body @drop {
               max_size 28000000
           }
           reverse_proxy 127.0.0.1:8401 {
               transport http {
                   read_timeout 11m
                   write_timeout 11m
               }
           }
       }
   and export ORCH_RELAY_CADDY_URL=https://127.0.0.1:8443 and ORCH_RELAY_CADDY_CA=<path of
   Caddy's local root certificate, `caddy trust` prints it, usually
   ~/.local/share/caddy/pki/authorities/local/root.crt>.
3. The test needs `httpx[http2]` (`uv pip install 'httpx[http2]'`, not a project dependency). It
   sends a 26 MiB ODU2 upload over HTTP/2 (expects 201), resends it (expects the early exact-retry
   200 while the body is still being sent), sends another object with a stale If-Match (expects
   the early 409 version_conflict), each time asserting the JSON answer arrives and the stream is
   not reset (no `RemoteProtocolError` / `ReadError`).
4. Record the Caddy version and the result in the PR before the D40c Caddy change is deployed.
"""

import os
import socket
import threading
import time

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("ORCH_RELAY_CADDY_E2E"),
    reason="manual/CI-only: needs a local Caddy (HTTP/2) in front of the relay (see docstring)",
)

SIZE = 26 * 1024 * 1024 - 64 * 1024


def test_early_answers_through_caddy_http2(tmp_path):
    httpx = pytest.importorskip("httpx")
    pytest.importorskip("h2")
    import uvicorn
    from directory_support import NOW
    from drop_support import TOKENS, setup, upload

    from orch_relay.app import create_app

    url, ca = os.environ["ORCH_RELAY_CADDY_URL"], os.environ["ORCH_RELAY_CADDY_CA"]
    assert url.startswith("https://127.0.0.1"), "loopback only: never a deployed relay"
    app = create_app(tmp_path)
    sock = socket.socket()
    sock.bind(("127.0.0.1", 8401))
    server = uvicorn.Server(uvicorn.Config(app, log_level="warning"))
    threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True).start()
    while not server.started:
        time.sleep(0.01)
    setup(app.state.directory, now=NOW)
    try:
        signed, _, body = upload("caddy", content=b"\0" * SIZE, chunk=1 << 20)
        other, _, other_body = upload("caddy-b", content=b"\1" * SIZE, chunk=1 << 20)
        headers = {
            "Authorization": "Bearer " + next(iter(TOKENS.values())),
            "Content-Type": "application/octet-stream",
        }
        with httpx.Client(http2=True, verify=ca, timeout=120) as client:

            def put(s, b, if_match):
                return client.put(
                    f"{url}/v2/drop/{s['o']['object_id']}/versions",
                    content=b,
                    headers={**headers, "If-Match": if_match},
                )

            r = put(signed, body, "0")
            assert (r.http_version, r.status_code, r.json()) == ("HTTP/2", 201, {"version": 1})
            r = put(signed, body, "0")
            assert (r.status_code, r.json()) == (200, {"version": 1})
            r = put(other, other_body, "4")
            assert (r.status_code, r.json()) == (409, {"error": "version_conflict", "current": 0})
    finally:
        server.should_exit = True
