"""G4 production capacity measurement (P3-D20). Not collected by pytest; run on demand:

    uv run python tests/bench_checkpoint_capacity.py

Drives the real app over HTTP against a SQLite file (WAL, synchronous=FULL): staging and the
final publication of a 5,000-ticket checkpoint, a long single-log append, the global/per-workspace
staging capacity in heads, log_nodes bytes per node, and proof page cost near the start and end of
the resulting history. FAKE keys only.
"""

import json
import os
import platform
import sys
import tempfile
import time
from contextlib import closing
from pathlib import Path

sys.path[:0] = [str(Path(__file__).parent), str(Path(__file__).parents[1])]

from checkpoint_support import CORPUS, WS, find, seed
from fastapi.testclient import TestClient

from orch_relay import db
from orch_relay import proto as P
from orch_relay.app import create_app
from orch_relay.checkpoints import PAGE_CAP, STAGE_CAP, ZERO, Nodes
from ref import checkpoints as C
from ref import orch_protocol_ref as R

NOW = 1790000000000
V = CORPUS["suites"]["2"]
S = R.SUITES[2]
WSK = S.sig_key(bytes.fromhex(V["keys"]["wsk_a.sig"]["seed"]))
HOST = {
    "Authorization": "Bearer FAKE-workspace",
    "Orch-Holder": "1",
    "Content-Type": "application/json",
}


def entry(heads, acc=ZERO, seq=0):
    for h in heads:
        acc = C.log_acc(acc, h)
    return {"seq": seq + len(heads), "head": heads[-1], "acc": acc}


def page(kind, log, start, heads):
    p = {
        "kind": kind,
        "log": log,
        "after_seq": start["seq"],
        "from_acc": start["acc"],
        "heads": heads,
    }
    p["digest"] = C.page_digest(p)
    return p


def stage_and_publish(client, held, target, pages):
    source = C.checkpoint_hash(held) if held else None
    base = f"/v2/workspaces/{WS}/staging/{source or 'null'}/{C.checkpoint_hash(target)}"
    pages = sorted(pages, key=lambda p: (p["kind"], p["log"], p["after_seq"]))
    began = time.perf_counter()
    for i, p in enumerate(pages):
        r = client.put(f"{base}/pages/{i}", content=P.cj(p), headers=HOST)
        assert r.status_code == 200, r.text
    manifest = {"pages": [C.descriptor(i, p) for i, p in enumerate(pages)]}
    r = client.put(base + "/manifest", content=P.cj(manifest), headers=HOST)
    assert r.json()["complete"], r.text
    staged = time.perf_counter() - began
    began = time.perf_counter()
    body = {"checkpoint": target, "source_hash": source}
    r = client.put(f"/v2/workspaces/{WS}/checkpoint", content=P.cj(body), headers=HOST)
    assert r.json().get("result") == "accepted", r.text
    return staged, time.perf_counter() - began, len(P.cj(manifest))


def measure():
    tmp = Path(tempfile.mkdtemp())
    out = {"python": platform.python_version(), "platform": platform.platform()}
    pinned = find({"section": "checkpoints", "name": "first_checkpoint_full_proof"})
    root = pinned["state"]["genesis"]["pin"]["o"]["genesis"]
    with TestClient(create_app(tmp)) as client:
        path = tmp / db.DB_NAME
        seed(path, pinned["state"], pinned)
        client.app.state.directory.clock = lambda: NOW
        # 1. First publication of a 5,000-ticket checkpoint, each ticket with four heads.
        tickets, pages = {}, []
        ws_heads = [root] + [C.digest(f"FAKE ws {i}".encode()) for i in range(1, 4)]
        pages.append(page("appended", "workspace", C.EMPTY, ws_heads))
        for t in range(5000):
            uid = f"01{t:024d}"
            hs = [C.digest(f"FAKE t{t} h{i}".encode()) for i in range(4)]
            tickets[uid] = entry(hs)
            pages.append(page("appended", uid, C.EMPTY, hs))
        o = {
            "v": 2,
            "suite": 2,
            "kind": "workspace_checkpoint",
            "workspace_id": WS,
            "genesis": root,
            "n": 1,
            "at": "2026-09-21T13:46:40Z",
            "workspace_log": entry(ws_heads),
            "tickets": tickets,
        }
        first = R.sign_object(S, WSK, o)
        staged, published, manifest_bytes = stage_and_publish(client, None, first, pages)
        out["tickets_5000"] = {
            "checkpoint_cj_bytes": len(P.cj(first)),
            "pages": len(pages),
            "manifest_bytes": manifest_bytes,
            "staging_seconds": round(staged, 3),
            "publish_seconds": round(published, 3),
        }
        # 2. A long append on the workspace log: 200,000 heads in pages at the 4 MiB cap.
        per_page = (PAGE_CAP - 512) // 74
        start = entry(ws_heads)
        heads = [C.digest(f"FAKE long {i}".encode()) for i in range(200_000)]
        pages, cursor = [], start
        for k in range(0, len(heads), per_page):
            chunk = heads[k : k + per_page]
            pages.append(page("appended", "workspace", cursor, chunk))
            cursor = entry(chunk, cursor["acc"], cursor["seq"])
        second = R.sign_object(S, WSK, {**o, "n": 2, "workspace_log": cursor})
        staged, published, _ = stage_and_publish(client, first, second, pages)
        out["append_200000_heads"] = {
            "pages": len(pages),
            "heads_per_page": per_page,
            "staging_seconds": round(staged, 3),
            "publish_seconds": round(published, 3),
        }
        with closing(db.connect(path)) as con:
            nodes = con.execute("SELECT count(*) FROM log_nodes").fetchone()[0]
            con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        out["log_nodes"] = nodes
        out["db_bytes_per_node"] = round(os.path.getsize(path) / nodes, 1)
        out["staging_quota_heads"] = {
            "per_workspace_64_mib": STAGE_CAP // 74,
            "per_page_4_mib": per_page,
        }
        # 3. Proof pages near the start and the end of the 200,004-node workspace history.
        with closing(db.connect(path)) as con:
            index = Nodes(con, WS, "workspace")
            for label, start_acc in (
                ("start", ZERO),
                ("end", entry(heads[:-64], start["acc"], 4)["acc"]),
            ):
                began = time.perf_counter()
                for _ in range(100):
                    Nodes(con, WS, "workspace").page(start_acc, cursor["acc"], 64)
                out[f"proof_page_64_ms_near_{label}"] = round((time.perf_counter() - began) * 10, 3)
            began = time.perf_counter()
            acc, total = ZERO, 0
            while acc is not None:
                got, acc = index.page(acc, cursor["acc"], 65536)
                total += len(got)
            out["full_walk_from_acc0_seconds"] = round(time.perf_counter() - began, 3)
            out["full_walk_heads"] = total
    return out


if __name__ == "__main__":
    print(json.dumps(measure(), indent=2))
