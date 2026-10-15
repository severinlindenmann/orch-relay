"""Atomic membership and key publication, protocol-v2 §19.2 and §19.7."""

from . import proto as P
from .directory import (
    DAY,
    Refusal,
    check_suite,
    checked,
    digest,
    fail,
    fields,
    integer,
    pair_revoked,
    usable_account,
)
from .unpublished import MAX_EVER_DEVICES

ROUTES = {"membership", "members", "grants", "card_keys", "card_key"}
MAX_EPOCH = 2**32 - 1  # §7.2 check 2: epochs are u32 (bridge header, commitments)
EPOCH_STEP = 2**16  # §7.2 checks 4 and 6: the largest first epoch and forward skip


def positive(value, maximum=P.MAX_SAFE_INT):
    if type(value) is not int or not 1 <= value <= maximum:
        fail("malformed")


def stored_wk_commit(raw):
    """wk_commit of a stored list. A pre-G2b dev row has none, so 7b refuses a same-epoch list over it
    (the host recovers by rotating to a higher epoch; wipe such dev databases)."""
    signed = P.parse_json(raw)
    o = signed.get("o") if isinstance(signed, dict) else None
    return o.get("wk_commit") if isinstance(o, dict) else None


def sealed(value):
    raw = P.unb64u(value, 65 + 32 + 16)
    if not P.SUITE.pub_ok(raw[:65]):
        fail("malformed")


def verify(obj, pub, kind):
    check_suite(obj)
    result = P.verify_object(obj, pub, kind)
    if result is None:
        fail("bad_signature")
    return result


def certificate(con, member, owner, persons, now):
    did = member["device_id"]
    row = con.execute("SELECT * FROM devices WHERE device_id=?", (did,)).fetchone()
    if row is None:
        fail("cert_invalid")
    # P3-D30: the cutoff is per pair, under the registry person (never the list's member person,
    # which is checked against it below): another person's pair for this id never refuses it.
    if pair_revoked(con, did, row["person_id"]):
        fail("revoked")
    cert = P.parse_json(row["cert"])
    if not isinstance(cert, dict) or not isinstance(cert.get("o"), dict):
        fail("cert_invalid")
    person = cert["o"].get("person_id")
    if (
        person != member["person_id"]
        or person != row["person_id"]
        or person not in {owner, *persons}
    ):
        fail("other_person")
    account = usable_account(con, person)
    if account is None:
        fail("other_person")
    try:
        result = checked(P.verify_cert(cert, P.unb64u(account[0]), now))
    except Refusal as error:
        if error.code == "cert_expired":
            error.status = 403
        raise
    if result["device_id"] != did:
        fail("cert_invalid")
    scopes = member["scopes"]
    maximum = result["scopes_max"]
    if (
        maximum[0].startswith("drop:")
        or not P.scopes_ok(scopes)
        or scopes != maximum[: len(scopes)]
    ):
        fail("scope_exceeded")


def wraps_put(con, ws, body, workspace, members, persons, now):
    fields(body, "card_seq wraps")
    positive(body["card_seq"])
    if body["card_seq"] != workspace["card_seq"]:
        fail("stale_card")
    if not isinstance(body["wraps"], list):
        fail("malformed")
    seen = set()
    for wrap in body["wraps"]:
        fields(wrap, "device_id sealed")
        did = wrap["device_id"]
        P.unhex(did)
        if did in seen:
            fail("malformed")
        seen.add(did)
        if did not in members:
            fail("not_for_this_device")
        certificate(con, members[did], workspace["owner_person_id"], persons, now)
        sealed(wrap["sealed"])
        old = con.execute(
            "SELECT sealed FROM card_key_wraps WHERE workspace_id=? AND device_id=? AND card_seq=?",
            (ws, did, body["card_seq"]),
        ).fetchone()
        if old and old[0] != wrap["sealed"]:
            fail("wrap_conflict")
        con.execute(
            "INSERT OR IGNORE INTO card_key_wraps VALUES (?,?,?,?)",
            (ws, did, body["card_seq"], wrap["sealed"]),
        )
    return {"stored": len(seen)}


def publish(con, ws, body, raw, workspace, now):
    receipt = con.execute(
        "SELECT list_seq,epoch FROM membership_receipts WHERE workspace_id=? "
        "AND request_digest=? AND accepted_ms>?",
        (ws, digest(raw), now - 7 * DAY),
    ).fetchone()
    if receipt:
        return dict(receipt)
    if not isinstance(body, dict) or set(body) not in (
        {"member_list", "grants"},
        {"member_list", "grants", "card_key_wraps"},
    ):
        fail("malformed")
    pub = P.unb64u(workspace["wsk_pub"])
    o = verify(body["member_list"], pub, "member_list")
    fields(o, "v suite kind workspace_id epoch list_seq issued_ms wk_commit persons members")
    positive(o["epoch"], MAX_EPOCH)
    positive(o["list_seq"])
    P.unb64u(o["wk_commit"], 32)
    if (
        type(o["issued_ms"]) is not int
        or not isinstance(o["members"], list)
        or len(o["members"]) > 1024
    ):
        fail("malformed")
    if not isinstance(o["persons"], list):
        fail("malformed")
    for person in o["persons"]:
        P.unhex(person)
    if o["persons"] != sorted(set(o["persons"])):
        fail("malformed")
    members = {}
    for m in o["members"]:
        fields(m, "device_id person_id scopes")
        P.unhex(m["device_id"])
        P.unhex(m["person_id"])
        members[m["device_id"]] = m
    if [m["device_id"] for m in o["members"]] != sorted(members):
        fail("malformed")
    if o["workspace_id"] != ws:
        fail("other_workspace")
    previous = con.execute(
        "SELECT * FROM member_lists WHERE workspace_id=? ORDER BY list_seq DESC LIMIT 1", (ws,)
    ).fetchone()
    # Checks 4-7b: epochs may skip (a refused publication burns its epoch), never fall.
    epoch = previous["epoch"] if previous else 0
    if previous and o["list_seq"] <= previous["list_seq"]:
        fail("stale_list")
    if not (epoch if previous else 1) <= o["epoch"] <= epoch + EPOCH_STEP:
        fail("bad_epoch")
    old_ids = {
        r[0] for r in con.execute("SELECT device_id FROM members WHERE workspace_id=?", (ws,))
    }
    if old_ids - members.keys() and o["epoch"] <= epoch:
        fail("rotation_required")
    if previous and o["epoch"] == epoch and stored_wk_commit(previous["list"]) != o["wk_commit"]:
        fail("wk_commit_changed")
    if not isinstance(body["grants"], list):
        fail("malformed")
    grants = {}
    for grant in body["grants"]:
        g = verify(grant, pub, "wk_grant")
        fields(g, "v suite kind workspace_id device_id epoch sealed")
        positive(g["epoch"], MAX_EPOCH)
        P.unhex(g["device_id"])
        if g["workspace_id"] != ws:
            fail("other_workspace")
        if g["device_id"] not in members or g["epoch"] != o["epoch"]:
            fail("not_for_this_device")
        if g["device_id"] in grants:
            fail("malformed")
        sealed(g["sealed"])
        old = con.execute(
            "SELECT grant FROM wk_grants WHERE workspace_id=? AND device_id=? AND epoch=?",
            (ws, g["device_id"], g["epoch"]),
        ).fetchone()
        if old and bytes(old[0]) != P.cj(grant):
            fail("grant_conflict")
        grants[g["device_id"]] = grant
    for m in members.values():
        certificate(con, m, workspace["owner_person_id"], o["persons"], now)
        if m["device_id"] not in grants:
            fail("missing_grant")
    bound_persons = {m["person_id"] for m in members.values()}
    if not set(o["persons"]) <= bound_persons:
        fail("other_person")
    if not previous and workspace["owner_person_id"] not in bound_persons:
        fail("other_person")
    # P3-D31: at most MAX_EVER_DEVICES ever-devices per workspace, so an unpublished page costs
    # O(|ever_devices|) bounded (the G4 storage gate's per-workspace quota for this route).
    known = con.execute("SELECT count(*) FROM ever_devices WHERE workspace_id=?", (ws,)).fetchone()[
        0
    ]
    fresh = sum(
        1
        for did in members
        if not con.execute(
            "SELECT 1 FROM ever_devices WHERE workspace_id=? AND device_id=?", (ws, did)
        ).fetchone()
    )
    if known + fresh > MAX_EVER_DEVICES:
        fail("quota_exceeded")
    if "card_key_wraps" in body:
        wraps_put(con, ws, body["card_key_wraps"], workspace, members, o["persons"], now)
    for did in old_ids - members.keys():
        prune_device(con, did, ws)
    con.execute("DELETE FROM members WHERE workspace_id=?", (ws,))
    for did, m in members.items():
        con.execute(
            "INSERT INTO members VALUES (?,?,?,?)", (ws, did, m["person_id"], P.cj(m["scopes"]))
        )
        con.execute("INSERT OR IGNORE INTO ever_devices VALUES (?,?,?)", (ws, did, o["epoch"]))
        con.execute("INSERT OR IGNORE INTO ever_persons VALUES (?,?)", (ws, m["person_id"]))
        con.execute(
            "INSERT OR IGNORE INTO wk_grants VALUES (?,?,?,?)",
            (ws, did, o["epoch"], P.cj(grants[did])),
        )
    con.execute(
        "INSERT INTO member_lists VALUES (?,?,?,?)",
        (ws, o["list_seq"], o["epoch"], P.cj(body["member_list"])),
    )
    con.execute(
        "DELETE FROM rotation_due WHERE workspace_id=? AND epoch<? AND device_id NOT IN (SELECT device_id FROM members WHERE workspace_id=?)",
        (ws, o["epoch"], ws),
    )
    con.execute(
        "DELETE FROM membership_receipts WHERE workspace_id=? AND accepted_ms<=?",
        (ws, now - 7 * DAY),
    )
    con.execute(
        "INSERT INTO membership_receipts VALUES (?,?,?,?,?)",
        (ws, digest(raw), now, o["list_seq"], o["epoch"]),
    )
    return {"list_seq": o["list_seq"], "epoch": o["epoch"]}


def prune_device(con, did, ws=None):
    """G3 queues use device_id/workspace_id; replay metadata is deliberately retained.

    Its chunk records are exhausted instead (P3-D27), so nothing is restored after a re-add.
    """
    for table in (
        "wk_grants",
        "card_key_wraps",
        "bridge_msgs",
        "request_mailboxes",
        "sk_grants",
        "push_subscriptions",
    ):
        if con.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
        ).fetchone():
            clause, args = ("", (did,)) if ws is None else (" AND workspace_id=?", (did, ws))
            con.execute(f"DELETE FROM {table} WHERE device_id=?" + clause, args)
    # P3-D27: a removed (or revoked) device's chunks are never stored again, even after a
    # re-add. Exhaust the cap rather than delete: the digests keep chunk_conflict in force.
    from .bridge import MAX_RESTORES

    clause, args = ("", (did,)) if ws is None else (" AND workspace_id=?", (did, ws))
    con.execute(
        "UPDATE rid_chunks SET restores=? WHERE device_id=?" + clause, (MAX_RESTORES, *args)
    )


def dispatch(directory, con, route, ws, body, raw, query, headers, now, state=None):
    allowed = {"epoch"} if route == "grants" else {"card_seq"} if route == "card_key" else set()
    if set(query) - allowed:
        fail("malformed")
    session = directory.authenticate(con, headers, now, state)
    write = route in {"membership", "card_keys"}
    directory.workspace_access(con, session, ws, write=write)
    if write:
        directory.fence(con, headers, ws, now)
    if route in {"grants", "card_key"} and session["kind"] != "device":
        fail("not_eligible")
    directory.authorized(state)  # P3-D32: a pre-check stops here
    workspace = con.execute("SELECT * FROM workspaces WHERE workspace_id=?", (ws,)).fetchone()
    if workspace is None:
        fail("not_found")
    if route == "membership":
        return publish(con, ws, body, raw, workspace, now)
    current = con.execute(
        "SELECT list FROM member_lists WHERE workspace_id=? ORDER BY list_seq DESC LIMIT 1", (ws,)
    ).fetchone()
    if route in {"members", "card_keys"}:
        if current is None:
            fail("not_found")
        signed = P.parse_json(current[0])
        if route == "members":
            return {"member_list": signed}
        return wraps_put(
            con,
            ws,
            body,
            workspace,
            {m["device_id"]: m for m in signed["o"]["members"]},
            signed["o"]["persons"],
            now,
        )
    did = session["subject_id"]
    if route == "card_key":
        seq = integer(query.get("card_seq"))
        if seq == 0:
            fail("malformed")
        row = con.execute(
            "SELECT sealed FROM card_key_wraps WHERE workspace_id=? AND device_id=? AND card_seq=?",
            (ws, did, seq),
        ).fetchone()
        if row is None:
            fail("not_found")
        return {"workspace_id": ws, "device_id": did, "card_seq": seq, "sealed": row[0]}
    epoch = integer(query["epoch"], MAX_EPOCH) if "epoch" in query else None
    if epoch == 0:
        fail("malformed")
    rows = con.execute(
        "SELECT grant FROM wk_grants g JOIN ever_devices e USING(workspace_id,device_id) WHERE workspace_id=? AND device_id=? AND epoch>=first_epoch AND (? IS NULL OR epoch=?) ORDER BY epoch",
        (ws, did, epoch, epoch),
    ).fetchall()
    if not rows:
        fail("not_found")
    return {"grants": [P.parse_json(r[0]) for r in rows]}
