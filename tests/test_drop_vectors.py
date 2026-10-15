"""P3-D39 (D39a1): the `drop.upload_frame` and `drop.relay_put` vectors, replayed by the reference
model (ref/drop_relay.py) and by the production relay over HTTP."""

import copy
import json
from contextlib import closing
from pathlib import Path

import pytest
from drop_support import apply_op, send_step, setup
from fastapi.testclient import TestClient

from orch_relay import db
from orch_relay.app import create_app
from ref import drop_relay as M

DROP = json.loads(Path("tests/vectors_v2.json").read_text())["suites"]["2"]["drop"]
CASES = DROP["relay_put"]
FRAMES = DROP["upload_frame"]["cases"]


def body_of(step):
    if "body_recipe" in step:
        r = step["body_recipe"]
        return (
            bytes.fromhex(r["prefix_hex"])
            + bytes([r["byte"]]) * r["count"]
            + bytes.fromhex(r["suffix_hex"])
        )
    return bytes.fromhex(step["body_hex"])


def model_replay(state, steps):
    for step in steps:
        if step["op"] == "put":
            got = M.put(
                state,
                step["principal"],
                step["object_id"],
                body_of(step).hex(),
                step["if_match"],
                step.get("holder"),
                step.get("content_length"),
            )
            assert got == step["expect"], step
        else:
            M.apply(state, step)


@pytest.mark.parametrize("case", CASES, ids=lambda c: c["name"])
def test_reference_model_replays_relay_put(case):
    state = copy.deepcopy(case["state"])
    model_replay(state, case["steps"])
    after = {k: {f: x[f] for f in case["after"].get(k, {})} for k, x in state["objects"].items()}
    assert after == case["after"]


def production(tmp_path, case_state, steps):
    with TestClient(create_app(tmp_path)) as client:
        d = client.app.state.directory
        setup(d, now=case_state["now_ms"])
        epoch = case_state["workspaces"][next(iter(case_state["workspaces"]))]["epoch"]
        if epoch != 1:
            apply_op(d, {"op": "epoch", "epoch": epoch})
        for step in steps:
            if step["op"] != "put":
                apply_op(d, step)
                continue
            r = send_step(client, step)
            assert (r.status_code, r.json()) == (
                step["expect"]["status"],
                step["expect"]["json"],
            ), (step.get("name"), r.text)
        with closing(db.connect(d.path)) as con:
            con.row_factory = __import__("sqlite3").Row
            return {
                r["object_id"]: {
                    "current": r["current"],
                    "n": r["n"],
                    "audience": r["audience"],
                    "head_hash": r["head_hash"],
                    "tombstone_kind": r["tombstone_kind"],
                    "claimed_by": r["claimed_by"],
                }
                for r in con.execute("SELECT * FROM drop_objects")
            }


@pytest.mark.parametrize("case", CASES, ids=lambda c: c["name"])
def test_production_replays_relay_put(tmp_path, case):
    assert production(tmp_path, case["state"], case["steps"]) == case["after"]


@pytest.mark.parametrize("case", FRAMES, ids=lambda c: c["name"])
def test_upload_frame(tmp_path, case):
    model_replay(copy.deepcopy(DROP["upload_frame"]["state"]), [case])
    production(tmp_path, DROP["upload_frame"]["state"], [case])
