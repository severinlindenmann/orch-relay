"""Explicit database preconditions for membership vectors and HTTP fixtures."""

import copy
from contextlib import closing

from directory_support import DEVICE, NOW, PERSON, PK, RECORD, WS, V, seed, signed

from orch_relay import db
from orch_relay import proto as P
from orch_relay.directory import token_hash

BASE = next(c for c in V["p3"]["cases"] if c["name"] == "second_person_and_grants_in_one_commit")
BODY = BASE["args"]["body"]
HEADERS = {
    "Authorization": "Bearer FAKE-workspace",
    "Orch-Holder": "1",
    "Content-Type": "application/json",
}


def holder(con, now=NOW, gen=1):
    con.execute(
        "INSERT OR REPLACE INTO holders VALUES (?,?,?,?,?)", (WS, gen, now + 40_000, 0, None)
    )


def load_state(d, state=None, directory=None, now=NOW):
    state = copy.deepcopy(BASE["state"] if state is None else state)
    directory = BASE["args"]["directory"] if directory is None else directory
    seed(d)
    d.clock = lambda: now
    with closing(db.connect(d.path)) as con, con:
        con.execute("PRAGMA foreign_keys=OFF")  # Abstract vectors include a missing account.
        for table in ("members", "member_lists", "ever_persons", "ever_devices"):
            con.execute(f"DELETE FROM {table}")
        con.execute("UPDATE sessions SET expires_ms=?", (now + 900_000,))
        holder(con, now)
        con.execute("DELETE FROM devices")
        for person, pub in directory["persons"].items():
            con.execute(
                "INSERT OR IGNORE INTO accounts VALUES (?,?,?)",
                (person, P.b64u(bytes.fromhex(pub)), NOW),
            )
        for cert in directory["certs"].values():
            d.store_device(con, cert)
        for did in directory["revoked"]:
            con.execute(
                "INSERT INTO revocations VALUES (?,?,?,?,?,?)",
                (did, PERSON, P.cj(RECORD), "lost", NOW, 1),
            )
        for person in state.get("ever_persons", []):
            con.execute("INSERT INTO ever_persons VALUES (?,?)", (WS, person))
        for did in state.get("ever_devices", []):
            con.execute("INSERT INTO ever_devices VALUES (?,?,?)", (WS, did, 1))
        if state["list"]:
            o = state["list"]
            con.execute(
                "INSERT INTO member_lists VALUES (?,?,?,?)",
                (WS, o["list_seq"], o["epoch"], P.cj(signed(o, "wsk_a.sig"))),
            )
            for m in o["members"]:
                con.execute(
                    "INSERT INTO members VALUES (?,?,?,?)",
                    (WS, m["device_id"], m["person_id"], P.cj(m["scopes"])),
                )
        for key, g in state["grants"].items():
            did, epoch = key.split("/")
            con.execute("INSERT INTO wk_grants VALUES (?,?,?,?)", (WS, did, int(epoch), P.cj(g)))
        for did, w in state["wraps"].items():
            con.execute(
                "INSERT INTO card_key_wraps VALUES (?,?,?,?)", (WS, did, w["card_seq"], w["sealed"])
            )
        for did, obligation in state["rotation_due"].items():
            con.execute(
                "INSERT INTO rotation_due VALUES (?,?,?,?)",
                (WS, did, obligation["revocation_cursor"], obligation["epoch"]),
            )
        for h, result in state["publications"].items():
            # The abstract vectors have no retention timestamp; seed still-live receipts.
            con.execute(
                "INSERT INTO membership_receipts VALUES (?,?,?,?,?)",
                (WS, h, now, result["ok"]["list_seq"], result["ok"]["epoch"]),
            )
        con.execute("UPDATE workspaces SET card_seq=?", (state["card_seq"],))


def snapshot(d):
    with closing(db.connect(d.path)) as con:
        return {
            t: [tuple(r) for r in con.execute(f"SELECT * FROM {t} ORDER BY rowid")]
            for t in (
                "members",
                "member_lists",
                "wk_grants",
                "card_key_wraps",
                "rotation_due",
                "ever_persons",
                "ever_devices",
                "membership_receipts",
            )
        }


def prepare_fixture(d, name, case):
    scenario = case["given"].get("scenario", case["name"])
    committed = copy.deepcopy(BASE["expect"]["state"])
    committed["publications"] = {}
    load_state(d, None if name == "membership" else committed)
    with closing(db.connect(d.path)) as con, con:
        if name == "members":
            con.execute("UPDATE member_lists SET list=?", (P.cj(BODY["member_list"]),))
        if scenario == "cert_invalid":
            con.execute("UPDATE devices SET cert=? WHERE device_id=?", (b"{}", DEVICE))
        elif scenario == "bad_signature":
            con.execute("UPDATE workspaces SET wsk_pub=?", (PK,))
        elif scenario == "cert_expired":
            cert = signed({**V["certs"]["signed"]["phone"]["o"], "expires_ms": NOW})
            con.execute(
                "UPDATE devices SET cert=?,expires_ms=? WHERE device_id=?",
                (P.cj(cert), NOW, DEVICE),
            )
        elif scenario == "not_eligible":
            con.execute(
                "UPDATE sessions SET kind='device',subject_id=? WHERE token_hash=?",
                (V["ids"]["device_primary"], token_hash("FAKE-workspace")),
            )
            con.execute("DELETE FROM members")
        elif scenario == "revoked":
            con.execute(
                "INSERT INTO revocations VALUES (?,?,?,?,?,?)",
                (DEVICE, PERSON, P.cj(RECORD), "lost", NOW, 1),
            )
        elif scenario == "other_person":
            # Stored certificate bound to a different person than the proposed entry.
            con.execute(
                "UPDATE devices SET cert=? WHERE device_id=?",
                (P.cj(V["certs"]["signed"]["bob_phone"]), DEVICE),
            )
        elif scenario == "scope_exceeded":
            cert = signed(
                {
                    **V["certs"]["signed"]["phone"]["o"],
                    "scopes_max": ["drop:" + WS],
                    "expires_ms": NOW + 10000,
                }
            )
            con.execute("UPDATE devices SET cert=? WHERE device_id=?", (P.cj(cert), DEVICE))
        elif scenario in {
            "stale_epoch",
            "bad_epoch",
            "rotation_required",
            "stale_list",
            "wk_commit_changed",
        }:
            # bad_epoch: the held epoch 2 is above the fixture's epoch 1 (epochs never fall).
            # wk_commit_changed: the held epoch-1 list carries the base publication's wk_commit A;
            # the fixture body keeps epoch 1 with wk_commit B.
            o = copy.deepcopy(BODY["member_list"]["o"])
            o["list_seq"] = 1
            o["epoch"] = 2 if scenario in {"stale_epoch", "bad_epoch"} else 1
            con.execute(
                "INSERT INTO member_lists VALUES (?,?,?,?)",
                (WS, o["list_seq"], o["epoch"], P.cj(signed(o, "wsk_a.sig"))),
            )
            if scenario == "rotation_required":
                con.execute(
                    "INSERT INTO members VALUES (?,?,?,?)",
                    (WS, V["ids"]["device_laptop"], PERSON, P.cj(["look"])),
                )
        elif scenario == "not_for_this_device" and name == "card_keys":
            o = copy.deepcopy(BODY["member_list"]["o"])
            o["members"] = [m for m in o["members"] if m["device_id"] != DEVICE]
            con.execute("UPDATE member_lists SET list=?", (P.cj(signed(o, "wsk_a.sig")),))
            con.execute("DELETE FROM members WHERE device_id=?", (DEVICE,))
        elif scenario == "quota_exceeded":
            # P3-D31: 4096 ever-devices, none of them in this list.
            con.executemany(
                "INSERT INTO ever_devices VALUES (?,?,1)",
                [(WS, f"{i:032x}") for i in range(4096)],
            )
        elif scenario == "grant_conflict":
            con.execute("INSERT INTO wk_grants VALUES (?,?,?,?)", (WS, DEVICE, 1, b"{}"))
        elif scenario == "stale_card":
            con.execute("UPDATE workspaces SET card_seq=2")
        elif scenario == "wrap_conflict":
            con.execute(
                "INSERT OR REPLACE INTO card_key_wraps VALUES (?,?,?,?)", (WS, DEVICE, 1, "other")
            )
        elif scenario == "not_found":
            table = {
                "members": "member_lists",
                "grants": "wk_grants",
                "card_key": "card_key_wraps",
            }[name]
            con.execute(f"DELETE FROM {table}")
