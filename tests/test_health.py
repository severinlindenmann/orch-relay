import sqlite3

from fastapi.testclient import TestClient

import orch_relay
from orch_relay.app import create_app


def test_healthz(tmp_path):
    with TestClient(create_app(data_dir=tmp_path, instance="public")) as c:
        r = c.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"ok": True, "version": orch_relay.__version__, "instance": "public"}


def test_env_config(tmp_path, monkeypatch):
    monkeypatch.setenv("ORCH_RELAY_DATA", str(tmp_path))
    monkeypatch.setenv("ORCH_RELAY_INSTANCE", "int")
    with TestClient(create_app()) as c:
        assert c.get("/healthz").json()["instance"] == "int"
    assert (tmp_path / "relay.sqlite3").exists()


def test_default_instance(tmp_path, monkeypatch):
    monkeypatch.delenv("ORCH_RELAY_INSTANCE", raising=False)
    with TestClient(create_app(data_dir=tmp_path)) as c:
        assert c.get("/healthz").json()["instance"] == "public"


def test_two_instances_have_separate_dbs(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    with (
        TestClient(create_app(data_dir=a, instance="public")) as ca,
        TestClient(create_app(data_dir=b, instance="int")) as cb,
    ):
        assert ca.get("/healthz").json()["instance"] == "public"
        assert cb.get("/healthz").json()["instance"] == "int"
    for d in (a, b):
        assert (d / "relay.sqlite3").exists()
    con = sqlite3.connect(a / "relay.sqlite3")
    con.execute("INSERT INTO meta(key, value) VALUES ('x', '1')")
    con.commit()
    other = sqlite3.connect(b / "relay.sqlite3")
    assert other.execute("SELECT count(*) FROM meta WHERE key='x'").fetchone()[0] == 0
