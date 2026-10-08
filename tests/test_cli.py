from unittest import mock

from orch_relay import cli


def test_serve_args_and_instance(tmp_path, monkeypatch):
    monkeypatch.setenv("ORCH_RELAY_DATA", str(tmp_path))
    monkeypatch.setenv("ORCH_RELAY_INSTANCE", "int")
    with mock.patch("uvicorn.run") as run:
        assert cli.main(["serve", "--host", "127.0.0.1", "--port", "8102"]) == 0
    app = run.call_args.args[0]
    assert run.call_args.kwargs == {"host": "127.0.0.1", "port": 8102}
    assert app.state.instance == "int"


def test_serve_port_does_not_change_instance(tmp_path, monkeypatch):
    monkeypatch.setenv("ORCH_RELAY_DATA", str(tmp_path))
    monkeypatch.delenv("ORCH_RELAY_INSTANCE", raising=False)
    with mock.patch("uvicorn.run") as run:
        cli.main(["serve", "--port", "8102"])
    assert run.call_args.args[0].state.instance == "public"


def test_serve_port_from_env(tmp_path, monkeypatch):
    monkeypatch.setenv("ORCH_RELAY_DATA", str(tmp_path))
    monkeypatch.setenv("ORCH_RELAY_PORT", "9000")
    with mock.patch("uvicorn.run") as run:
        cli.main(["serve"])
    assert run.call_args.kwargs["port"] == 9000


def test_migrate_command(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("ORCH_RELAY_DATA", str(tmp_path))
    assert cli.main(["migrate"]) == 0
    assert "0001_init" in capsys.readouterr().out
    assert cli.main(["migrate"]) == 0
    assert "(none)" in capsys.readouterr().out
    assert (tmp_path / "relay.sqlite3").exists()
