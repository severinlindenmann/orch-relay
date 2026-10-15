"""The production relay replays the same checkpoint vectors as ref/checkpoints.py (G4)."""

import pytest
from checkpoint_support import cases, cursors, project_db, project_state, registry, replay
from fastapi.testclient import TestClient

from orch_relay import db
from orch_relay.app import create_app

ALL = [c for section in ("checkpoints", "checkpoints_g4", "unpublished") for c in cases(section)]


@pytest.mark.parametrize("case", ALL, ids=lambda c: c["name"])
def test_production_replays_checkpoint_vector(tmp_path, case):
    with TestClient(create_app(tmp_path)) as client:
        path = tmp_path / db.DB_NAME
        replay(client, path, case)
        now = case["steps"][-1]["input"]["now_ms"]
        assert project_db(path, now) == project_state(case["expect"]["state"], now)
        stored = registry(path)
        expected = case["expect"]["state"]
        # The reference's verified-signer bindings are registered devices in production (L3).
        for device, person in {**expected["bound"], **expected["registry"]}.items():
            assert stored[device] == person, device
        if "cursors" in expected:  # P3-D31: the §19.5 cursor of every global pair
            assert cursors(path) == {tuple(k.split(":")): c for k, c in expected["cursors"].items()}
