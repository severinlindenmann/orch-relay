"""Device ↔ real ASGI relay ↔ suite-2 host stub; no socket is required."""

from contextlib import closing

from clients import DeviceClient, HostStub
from directory_support import NOW, seed
from fastapi.testclient import TestClient

from orch_relay import db
from orch_relay.app import create_app


def test_pair_bridge_lost_response_restart_and_revoke(tmp_path):
    with TestClient(create_app(tmp_path)) as relay:
        seed(relay.app.state.directory)
        with closing(db.connect(relay.app.state.directory.path)) as con, con:
            for table in ("members", "member_lists", "ever_devices", "ever_persons"):
                con.execute(f"DELETE FROM {table}")
        device, host = DeviceClient(relay), HostStub(relay)
        path = device.pair_request()
        host.process(host.poll()[0])
        pending = device.pair_answer(path)
        assert pending["state"] == "pending"
        host.approve(pending["sas"])
        path = device.pair_status()
        host.process(host.poll()[0])
        device.finish_pair(path)
        rid, raw = device.request()
        assert device.send(rid, raw).status_code == 202
        # Simulate losing the accepted HTTP response. Persist exactly the same bytes.
        assert device.send(rid, raw).status_code == 202
    # Restart before the host receives the operation; SQLite retains all mailboxes.
    with TestClient(create_app(tmp_path)) as relay:
        relay.app.state.directory.clock = lambda: NOW
        device.client = host.client = relay
        items = host.poll()
        assert len(items) == 1
        assert host.process(items[0]) == {"status": "ready"}
        assert device.response(rid) == {"status": "ready"}
        assert device.response(rid) == {"status": "ready"}
        host.revoke()
        assert device.send(rid, raw).status_code == 401
