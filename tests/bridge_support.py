"""G3 fixture and vector database preconditions; no production checks are mocked."""

import json
from contextlib import closing
from pathlib import Path

from directory_support import DEVICE, NOW, PERSON, PK, PRIMARY, RECORD, WS, V, seed

from orch_relay import db
from orch_relay import proto as P
from orch_relay.bridge import HEADER
from orch_relay.directory import token_hash

OBJECTS = V["p3"]["objects"]
RID = "fde154f24ef24b8eccff1cb87c930438"
CRID = OBJECTS["request"]["o"]["request_id"]
HOST = {"Authorization": "Bearer FAKE-workspace", "Orch-Holder": "1"}


def request(name):
    return json.loads(Path(f"tests/http_fixtures/{name}.json").read_text())["cases"][0]["request"]


def binary(name):
    return P.unb64u(request(name)["body_b64u"])


def insert_queue(con, entry):
    o = entry["request"]["o"]
    con.execute(
        "INSERT OR REPLACE INTO cert_requests VALUES (?,?,?,?,?,?,?,?,?,?)",
        (
            o["request_id"],
            o["workspace_id"],
            o["person_id"],
            o["primary_device_id"],
            P.cj(entry["request"]),
            o["expires_ms"],
            entry["state"],
            *[P.cj(entry[k]) if entry.get(k) else None for k in ("challenge", "cert", "rejection")],
        ),
    )


def queue_entry(state="open"):
    return {
        "request": OBJECTS["request"],
        "state": state,
        "challenge": OBJECTS["challenge"] if state in ("challenged", "signed") else None,
        "cert": OBJECTS["cert"] if state == "signed" else None,
        "rejection": OBJECTS["cert_rejection"] if state == "rejected" else None,
    }


def queue_body(con, raw, n=None):
    h = HEADER.unpack(raw[:108])
    ws, device, rid, offer = h[5].hex(), h[6].hex(), h[7].hex(), h[8].hex() if h[11] == 0 else None
    con.execute(
        "INSERT INTO bridge_msgs(n,workspace_id,device_id,rid,direction,offer,idx,flags,stream,body,expires_ms) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (n, ws, device, rid, h[2], offer, h[9], h[3], h[8].hex(), raw, NOW + 60000),
    )


def seen(con, raw=None):
    from orch_relay.directory import digest

    raw = raw or binary("bridge_device_post")
    h = HEADER.unpack(raw[:108])
    con.execute(
        "INSERT OR IGNORE INTO rid_seen VALUES (?,?,?,?,?,?,0,?,?,?)",
        (
            h[5].hex(),
            h[6].hex(),
            h[7].hex(),
            digest(raw),
            h[11],
            NOW,
            NOW,
            NOW + 900000,
            h[8].hex() if h[11] == 0 else None,
        ),
    )


def prepare_fixture(client, name, case):
    d, bridge = client.app.state.directory, client.app.state.bridge
    seed(d)
    scenario = case["given"].get("scenario")
    with closing(db.connect(d.path)) as con, con:
        con.execute(
            "INSERT INTO sessions VALUES (?,?,?,?)",
            (token_hash("FAKE-primary"), "device", PRIMARY, NOW + 900000),
        )
        if name.startswith("cert_"):
            if name != "cert_requests_post":
                state = (
                    case["name"]
                    if case["name"] in ("open", "signed", "rejected", "expired")
                    else "challenged"
                    if name == "cert_request_get"
                    else "open"
                )
                insert_queue(con, queue_entry(state))
            if case["name"] == "resigned_identical":
                field = "challenge" if name == "cert_challenge" else "rejection"
                con.execute(
                    f"UPDATE cert_requests SET state=?,{field}=?",
                    (
                        "challenged" if field == "challenge" else "rejected",
                        P.cj(OBJECTS[field if field == "challenge" else "cert_rejection"]),
                    ),
                )
        if name == "host_hold":
            if case["name"] == "success":
                con.execute("DELETE FROM holders")
            elif case["name"] == "explicit_takeover":
                con.execute("UPDATE holders SET cursor=1")
        if name in ("bridge_host_post", "bridge_device_poll"):
            seen(con)
        if name in ("pair_host_post", "pair_poll"):
            seen(con, binary("pair_device_post"))
        if name in ("bridge_device_poll", "pair_poll"):
            queue_body(
                con,
                binary("bridge_host_post" if name == "bridge_device_poll" else "pair_host_post"),
            )
        if name == "host_poll":
            if case["name"] == "pair_item":
                queue_body(con, binary("pair_device_post"), 2)
            elif case["name"] != "durable_notices":
                queue_body(con, binary("bridge_device_post"), 1)
            else:
                con.execute(
                    "INSERT INTO revocations VALUES (?,?,?,?,?,?)",
                    (DEVICE, PERSON, P.cj(RECORD), "lost", NOW, 1),
                )
                con.execute("INSERT INTO rotation_due VALUES (?,?,?,?)", (WS, DEVICE, 1, 1))
                insert_queue(con, queue_entry("challenged"))
        if scenario == "cert_expired":
            con.execute("UPDATE devices SET expires_ms=?", (NOW,))
        elif scenario == "revoked":
            did = PRIMARY if name.startswith("cert_") else DEVICE
            con.execute(
                "INSERT INTO revocations VALUES (?,?,?,?,?,?)",
                (did, PERSON, P.cj(RECORD), "lost", NOW, 1),
            )
        elif scenario == "not_eligible":
            con.execute("DELETE FROM members")
            con.execute(
                "UPDATE sessions SET subject_id=? WHERE kind='workspace'",
                (V["ids"]["workspace_b"],),
            )
            # A real other workspace keeps session authentication valid.
            con.execute(
                "INSERT INTO workspaces SELECT ?,owner_person_id,wsk_pub,delegation,card,card_seq,wxk_version,client_hosted FROM workspaces WHERE workspace_id=?",
                (V["ids"]["workspace_b"], WS),
            )
            if name.startswith("cert_"):
                con.execute(
                    "UPDATE sessions SET subject_id=? WHERE token_hash=?",
                    (DEVICE, token_hash("FAKE-primary")),
                )
                if name == "cert_requests_poll":
                    con.execute(
                        "UPDATE devices SET person_id=? WHERE device_id=?", (PERSON, DEVICE)
                    )
                    con.execute(
                        "UPDATE sessions SET kind='workspace',subject_id=? WHERE token_hash=?",
                        (WS, token_hash("FAKE-primary")),
                    )
                if name == "cert_requests_post":
                    con.execute(
                        "UPDATE sessions SET kind='device',subject_id=? WHERE token_hash=?",
                        (DEVICE, token_hash("FAKE-workspace")),
                    )
        elif scenario == "unknown_workspace":
            con.execute("DELETE FROM workspaces")
        elif scenario == "stale_epoch":
            con.execute("UPDATE member_lists SET epoch=2")
        elif scenario == "rid_conflict":
            seen(con)
            con.execute("UPDATE rid_seen SET req_digest='different'")
        elif scenario == "retry_exhausted":
            seen(con)
            con.execute("UPDATE rid_seen SET requeues=8")
        elif scenario == "chunk_conflict":
            con.execute("INSERT INTO rid_chunks VALUES (?,?,?,0,'different')", (WS, DEVICE, RID))
        elif scenario == "expired":
            if name == "bridge_host_post":
                con.execute("DELETE FROM rid_seen")
            elif name.startswith("cert_"):
                d.clock = lambda: NOW + 600001
                con.execute("UPDATE holders SET lease_until_ms=?", (NOW + 700000,))
        elif scenario == "not_found":
            con.execute("DELETE FROM cert_requests")
        elif scenario == "bad_signature":
            if name == "cert_requests_post":
                con.execute("UPDATE workspaces SET wsk_pub=?", (PK,))
            else:
                con.execute("UPDATE accounts SET pk_pub=?", (V["card"]["card"]["o"]["wsk_pub"],))
        elif scenario in ("other_person", "other_workspace", "not_for_this_device"):
            if name == "bridge_device_post":
                con.execute(
                    "UPDATE sessions SET subject_id=? WHERE token_hash=?",
                    (PRIMARY, token_hash("FAKE-device")),
                )
                con.execute(
                    "INSERT INTO members VALUES (?,?,?,?)", (WS, PRIMARY, PERSON, P.cj(["look"]))
                )
            elif name == "cert_requests_post":
                if scenario == "other_person":
                    con.execute(
                        "INSERT INTO accounts VALUES (?,?,?)", (V["ids"]["person_bob"], PK, NOW)
                    )
                    con.execute(
                        "UPDATE workspaces SET owner_person_id=?", (V["ids"]["person_bob"],)
                    )
                elif scenario == "not_for_this_device":
                    con.execute("DELETE FROM devices WHERE device_id=?", (PRIMARY,))
                elif scenario == "other_workspace":
                    other = V["ids"]["workspace_b"]
                    con.execute(
                        "INSERT INTO workspaces SELECT ?,owner_person_id,wsk_pub,delegation,card,card_seq,wxk_version,client_hosted FROM workspaces",
                        (other,),
                    )
                    con.execute("INSERT INTO holders VALUES (?,1,?,0,NULL)", (other, NOW + 40000))
                    con.execute("UPDATE sessions SET subject_id=? WHERE kind='workspace'", (other,))
            elif name in ("cert_challenge", "cert_rejection"):
                req = json.loads(P.cj(OBJECTS["request"]))
                key = {
                    "other_person": "person_id",
                    "other_workspace": "workspace_id",
                    "not_for_this_device": "request_id",
                }[scenario]
                req["o"][key] = "ab" * 16
                con.execute("UPDATE cert_requests SET request=?", (P.cj(req),))
        elif scenario in ("already_signed", "replayed", "request_open"):
            if name == "cert_requests_post":
                entry = queue_entry()
                if scenario == "request_open":
                    entry = json.loads(P.cj(entry))
                    entry["request"]["o"]["request_id"] = "ab" * 16
                insert_queue(con, entry)
                if scenario == "replayed":
                    con.execute("UPDATE cert_requests SET request=?", (b"{}",))
            else:
                con.execute(
                    "UPDATE cert_requests SET state=?",
                    ("signed" if scenario == "already_signed" else "rejected",),
                )
        elif scenario == "rate_limited":
            pair = "pair-host-" if name == "pair_host_post" else "pair-"
            d.windows[(pair + case["request"]["method"], "testclient", 60000)] = (
                NOW + 60000,
                12000,
            )
            d.windows[("bridge-post", DEVICE, 1000)] = (NOW + 1000, 20)
            d.windows[("bridge-host-post", (WS, DEVICE), 1000)] = (NOW + 1000, 20)
        elif scenario in ("overloaded", "quota_exceeded"):
            if case["request"]["method"] == "GET":
                key = ("device", PRIMARY if name == "cert_requests_poll" else DEVICE)
                bridge.polls[key] = 4096 if scenario == "overloaded" else 6
            elif name == "cert_requests_post":
                for i in range(64):
                    entry = json.loads(P.cj(queue_entry()))
                    entry["request"]["o"].update(request_id=f"{i:032x}", workspace_id=f"{i:032x}")
                    insert_queue(con, entry)
            else:
                direction = 2 if "host" in name else 1
                size = 256 * 1024 * 1024 if scenario == "overloaded" else 16 * 1024 * 1024
                con.execute(
                    "INSERT INTO queue_totals VALUES (?,?,?,?,?,?)",
                    (WS, DEVICE, direction, size, size, 1),
                )
