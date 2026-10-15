"""P3-D39 (D39a1): the Drop PUT check order, storage, reads and lists over HTTP (TestClient)."""

import os
import stat
from contextlib import closing

import pytest
from directory_support import DEVICE, NOW, WS
from drop_support import (
    AGENT,
    DAY,
    LAPTOP,
    PRIMARY,
    WS_B,
    default_wraps,
    descriptor,
    frame,
    headers,
    object_id,
    put,
    rows,
    setup,
    upload,
    usage,
    wrap,
)
from fastapi.testclient import TestClient

from orch_relay import db
from orch_relay import drop as DR
from orch_relay import proto as P
from orch_relay.app import create_app


@pytest.fixture
def client(tmp_path):
    with TestClient(create_app(tmp_path)) as c:
        setup(c.app.state.directory)
        yield c


def path_of(c):
    return c.app.state.directory.path


def files(c):
    drop = c.app.state.drop
    blobs = sorted(p for p in drop.blobs.rglob("*") if p.is_file())
    return blobs, sorted(drop.tmp.iterdir())


def nothing_stored(c):
    assert rows(path_of(c), "drop_objects") == []
    assert rows(path_of(c), "drop_versions") == []
    assert rows(path_of(c), "drop_wraps") == []
    assert rows(path_of(c), "drop_usage") == []
    assert files(c) == ([], [])
    assert c.app.state.drop.uploads.count == 0


def sql(c, statement, *args):
    with closing(db.connect(path_of(c))) as con, con:
        con.execute(statement, args)


def get(c, o_id, what, author=DEVICE, version=1):
    from drop_support import TOKENS

    return c.get(
        f"/v2/drop/{o_id}/versions/{version}/{what}",
        headers={"Authorization": "Bearer " + TOKENS[author]},
    )


def listing(c, author=DEVICE, direction="received", **extra):
    from drop_support import TOKENS

    return c.post(
        "/v2/drop/list",
        json={"workspace_id": WS, "direction": direction, **extra},
        headers={"Authorization": "Bearer " + TOKENS[author]},
    )


# --- the write path --------------------------------------------------------------------------------


def test_put_stores_rows_files_usage_and_etag(client):
    signed, wraps, body = upload("a")
    r = put(client, signed, body)
    assert (r.status_code, r.json(), r.headers["etag"]) == (201, {"version": 1}, '"1"')
    o = signed["o"]
    (version,) = rows(path_of(client), "drop_versions")
    assert version["descriptor"] == P.cj(signed).decode()
    assert version["descriptor_len"] == len(P.cj(signed))
    assert version["parent_hash_next"] == DR.parent_hash(o)
    assert version["blob"] == "stored" and version["head_len"] == len(body) - 8 - o["content_len"]
    (obj,) = rows(path_of(client), "drop_objects")
    assert (obj["audience"], obj["inbox"], obj["n"], obj["head_author_id"]) == (
        "space",
        0,
        1,
        DEVICE,
    )
    assert obj["head_hash"] == DR.parent_hash(o) and obj["owner_person_id"]
    blobs, tmp = files(client)
    assert tmp == [] and len(blobs) == 1
    assert blobs[0].read_bytes() == body[-o["content_len"] :]
    assert stat.S_IMODE(os.stat(blobs[0]).st_mode) == 0o600
    for folder in (client.app.state.drop.root, client.app.state.drop.tmp, blobs[0].parent):
        assert stat.S_IMODE(os.stat(folder).st_mode) == 0o700
    head = len(P.cj(signed)) + len(P.cj(wraps[0]))
    u = usage(path_of(client))
    assert u[("workspace", WS)] == (o["content_len"], head, 1, 0)
    assert u[("device", f"{WS}:{DEVICE}")] == (o["content_len"], head, 1, 0)
    assert u[("global", "")] == (o["content_len"], head, 1, 0)
    assert client.app.state.drop.uploads.count == 0


def test_exact_retry_is_200_before_the_cas_even_resigned(client):
    signed, wraps, body = upload("a")
    assert put(client, signed, body).status_code == 201
    r = put(client, signed, body, if_match="7")  # a stale If-Match: the retry still wins
    assert (r.status_code, r.json(), r.headers["etag"]) == (200, {"version": 1}, '"1"')
    resigned = {
        "o": signed["o"],
        "sig": __import__("directory_support").sign(
            "phone.sig", P.L["sig_drop_object"] + P.cj(signed["o"])
        ),
    }
    data = body[-signed["o"]["content_len"] :]
    assert put(client, resigned, frame(resigned, wraps, data)).status_code == 200
    assert len(rows(path_of(client), "drop_versions")) == 1
    assert len(files(client)[0]) == 1


@pytest.mark.parametrize("value", [None, "03", "*", 'W/"0"', "0,0", "-1", " 0", "", '"01"'])
def test_if_match_missing_or_malformed_is_428(client, value):
    signed, _, body = upload("a")
    r = put(client, signed, body, if_match=value)
    assert (r.status_code, r.json()) == (428, {"error": "precondition_required"})
    nothing_stored(client)


def test_if_match_quoted_form_is_accepted(client):
    signed, _, body = upload("a")
    assert put(client, signed, body, if_match='"0"').status_code == 201


def test_document_chain_cas_and_fork(client):
    o_id = object_id("doc")
    v1, _w1, b1 = upload(o_id, kind="document")
    assert put(client, v1, b1).status_code == 201
    v2, _, b2 = upload(o_id, kind="document", version=2, parent=v1["o"], author=LAPTOP)
    stale = put(client, v2, b2, if_match="0")
    assert (stale.status_code, stale.json()) == (409, {"error": "version_conflict", "current": 1})
    assert put(client, v2, b2, if_match="1").status_code == 201
    # a fork: version 3 whose parent_hash names version 1
    fork, _, bf = upload(o_id, kind="document", version=3, parent=v1["o"])
    assert put(client, fork, bf, if_match="2").json() == {"error": "version_conflict", "current": 2}
    skip, _, bs = upload(o_id, kind="document", version=4, parent=v2["o"], parent_hash=None)
    assert put(client, skip, bs, if_match="2").status_code == 400  # parent != version - 1
    v3, _, b3 = upload(o_id, kind="document", version=3, parent=v2["o"])
    assert put(client, v3, b3, if_match="2").status_code == 201
    (obj,) = rows(path_of(client), "drop_objects")
    assert (obj["current"], obj["n"], obj["head_author_id"]) == (3, 3, DEVICE)
    assert usage(path_of(client))[("workspace", WS)][2:] == (3, 1)  # versions, documents
    # a lost 201 of version 2 resent after the head moved: still the exact retry
    assert put(client, v2, b2, if_match="1").status_code == 200


def test_file_rules(client):
    o_id = object_id("file")
    v1, _, b1 = upload(o_id)
    assert put(client, v1, b1).status_code == 201
    v2, _, b2 = upload(o_id, version=2, parent=v1["o"])
    assert put(client, v2, b2, if_match="1").json() == {"error": "malformed"}  # version 2 file
    late, _, bl = upload("late", expires=NOW + 7 * DAY + 300_001)
    assert put(client, late, bl).status_code == 400
    edge, _, be = upload("edge", expires=NOW + 7 * DAY + 300_000)
    assert put(client, edge, be).status_code == 201
    gone, _, bg = upload("gone", expires=NOW)
    assert (put(client, gone, bg).status_code, put(client, gone, bg).json()) == (
        410,
        {"error": "expired"},
    )
    short, _, bsh = upload("short", expires=NOW + 59_999)
    assert put(client, short, bsh).status_code == 400  # the 60 s floor (A1)
    floor, _, bfl = upload("floor", expires=NOW + 60_000)
    assert put(client, floor, bfl).status_code == 201
    # an exact retry 59 s before the expiry is still 200 (the floor is checked after the retry)
    client.app.state.directory.clock = lambda: NOW + 1_000
    assert put(client, floor, bfl).status_code == 200


def test_descriptor_shape_refusals_store_nothing(client):
    cases = [
        {"kind": "document", "expires": NOW + DAY},  # a document with an expiry
        {"recipients": "inbox", "kind": "document"},  # an inbox document
        {"recipients": []},  # amendment A1, R2
        {"recipients": sorted([WS, DEVICE], reverse=True)},  # unsorted
        {"recipients": [WS, WS]},
        {"recipients": [WS_B]},  # a foreign workspace id
        {"recipients": [PRIMARY]},  # not a member device
        {"space_kind": "shared"},
        {"origin": "robot"},
        {"meta": P.b64u(b"m" * (DR.MAX_META + 1))},
        {"content_hash": P.b64u(b"short")},
        {"parent_hash": P.b64u(bytes(32))},
        {"suite": 1},
    ]
    for over in cases:
        signed, _, body = upload("shape", **over)
        r = put(client, signed, body)
        assert (r.status_code, r.json()) == (400, {"error": "malformed"}), over
    nothing_stored(client)


def test_descriptor_cap(client, monkeypatch):
    signed, _, body = upload("cap")
    monkeypatch.setattr(DR, "MAX_DESCRIPTOR", len(P.cj(signed)) - 1)
    assert put(client, signed, body).json() == {"error": "malformed"}
    monkeypatch.setattr(DR, "MAX_DESCRIPTOR", len(P.cj(signed)))
    assert put(client, signed, body).status_code == 201


def test_meta_at_its_cap(client):
    signed, _, body = upload("meta", meta=P.b64u(b"m" * DR.MAX_META))
    assert put(client, signed, body).status_code == 201
    signed, _, body = upload("meta2", meta=P.b64u(b"m" * (DR.MAX_META + 1)))
    assert put(client, signed, body).status_code == 400


def test_object_id_and_author_and_signature(client):
    signed, _, body = upload("a")
    r = client.put(f"/v2/drop/{object_id('other')}/versions", content=body, headers=headers())
    assert r.status_code == 400  # object_id is not the path
    r = put(client, signed, body, author=LAPTOP)  # the laptop's session, the phone's descriptor
    assert (r.status_code, r.json()) == (403, {"error": "not_eligible"})
    forged, _, fb = upload("forged")
    forged = {"o": forged["o"], "sig": upload("forged", author=LAPTOP)[0]["sig"]}
    r = put(
        client, forged, frame(forged, default_wraps(forged["o"]), fb[-forged["o"]["content_len"] :])
    )
    assert (r.status_code, r.json()) == (401, {"error": "bad_signature"})
    nothing_stored(client)


def test_write_scope_and_drop_scoped_device(tmp_path):
    with TestClient(create_app(tmp_path)) as c:
        setup(c.app.state.directory, laptop_scopes=["look", "decide"])
        signed, _, body = upload("a", author=LAPTOP)
        assert put(c, signed, body).json() == {"error": "not_eligible"}  # no `operate`
        r = c.put(
            f"/v2/drop/{signed['o']['object_id']}/versions", content=body, headers=headers(AGENT)
        )
        assert (r.status_code, r.json()) == (403, {"error": "not_eligible"})
        r = c.post(
            "/v2/drop/list",
            json={"workspace_id": WS, "direction": "received"},
            headers={"Authorization": "Bearer FAKE-agent"},
        )
        assert r.status_code == 403
        nothing_stored(c)


def test_wraps_refusals(client):
    def try_(label, wraps, status, error, **kw):
        signed, _, _ = upload(label, **kw)
        data = __import__("drop_support").blob(signed["o"]["object_id"], 1)[0]
        r = put(client, signed, frame(signed, wraps(signed["o"]), data))
        assert (r.status_code, r.json()) == (status, error), label

    m = {"error": "malformed"}
    try_(
        "stale", lambda o: [wrap(o, "wk", key_version=2)], 409, {"error": "stale_epoch", "epoch": 1}
    )
    try_(
        "wxkv",
        lambda o: [wrap(o, "wk"), wrap(o, "wxk", key_version=2)],
        409,
        {"error": "bad_wxk_version"},
    )
    try_("wxkforeign", lambda o: [wrap(o, "wk"), wrap(o, "wxk", target=WS_B)], 400, m)
    try_("wkforeign", lambda o: [wrap(o, "wk", target=WS_B)], 400, m)
    try_("inboxwk", lambda o: [wrap(o, "wxk"), wrap(o, "wk")], 400, m, recipients="inbox")
    try_("inboxnone", lambda o: [], 400, m, recipients="inbox")
    try_(
        "inboxtwo",
        lambda o: [wrap(o, "wxk"), wrap(o, "device", LAPTOP)],
        400,
        m,
        recipients="inbox",
    )
    try_("nowk", lambda o: [wrap(o, "device", DEVICE)], 400, m)
    try_("dup", lambda o: [wrap(o, "wk"), wrap(o, "wk")], 400, m)
    try_("sk", lambda o: [wrap(o, "wk"), {**wrap(o, "wk"), "target_kind": "sk"}], 400, m)
    try_("kv", lambda o: [wrap(o, "wk"), wrap(o, "device", LAPTOP, key_version=1)], 400, m)
    try_(
        "big",
        lambda o: [wrap(o, "wk"), {**wrap(o, "device", LAPTOP), "wrap": P.b64u(b"x" * 513)}],
        400,
        m,
    )
    try_("frame", lambda o: [{**wrap(o, "wk"), "wrap": P.b64u(b"x" * 63)}], 400, m)
    try_("ver", lambda o: [{**wrap(o, "wk"), "version": 2}], 400, m)
    try_("extra", lambda o: [{**wrap(o, "wk"), "x": 1}], 400, m)
    try_(
        "nonmember",
        lambda o: [wrap(o, "wk"), wrap(o, "device", PRIMARY)],
        403,
        {"error": "not_eligible"},
    )
    nothing_stored(client)


def test_stale_epoch_then_same_dek_rewrap_succeeds(client):
    sql(client, "INSERT INTO member_lists VALUES (?,2,2,'{}')", WS)
    signed, _, _ = upload("epoch")
    data = __import__("drop_support").blob(signed["o"]["object_id"], 1)[0]
    old = put(client, signed, frame(signed, [wrap(signed["o"], "wk", key_version=1)], data))
    assert old.json() == {"error": "stale_epoch", "epoch": 2}
    new = put(client, signed, frame(signed, [wrap(signed["o"], "wk", key_version=2)], data))
    assert new.status_code == 201  # same descriptor and blob, the same DEK under WK_2


def test_inbox_and_device_only_uploads(client):
    inbox, _, b = upload("inbox", recipients="inbox", wraps=None)
    data = b[-inbox["o"]["content_len"] :]
    body = frame(inbox, [wrap(inbox["o"], "wxk"), wrap(inbox["o"], "device", DEVICE)], data)
    assert put(client, inbox, body).status_code == 201
    host_only, _, hb = upload("hostonly", author=WS, recipients=[LAPTOP])
    assert put(client, host_only, hb).status_code == 201  # a W author may omit wk for devices
    host_space, _, hs = upload("hostspace", author=WS, recipients=[WS], wraps=[])
    assert put(client, host_space, hs).status_code == 400  # but not when addressed to the space
    objs = {r["object_id"]: r for r in rows(path_of(client), "drop_objects")}
    assert objs[inbox["o"]["object_id"]]["audience"] == "inbox"
    assert objs[host_only["o"]["object_id"]]["audience"] == "devices"
    aud = rows(path_of(client), "drop_audience")
    assert [(r["object_id"], r["device_id"]) for r in aud] == [
        (host_only["o"]["object_id"], LAPTOP)
    ]
    # device-only audience rows are charged 65 B each; a device author is in its own audience
    dev, _, db_ = upload("devonly", recipients=[LAPTOP], wraps=None)
    data = db_[-dev["o"]["content_len"] :]
    assert put(client, dev, frame(dev, [wrap(dev["o"], "wk")], data)).status_code == 201
    aud = {(r["object_id"], r["device_id"]) for r in rows(path_of(client), "drop_audience")}
    assert {(dev["o"]["object_id"], DEVICE), (dev["o"]["object_id"], LAPTOP)} <= aud


def test_audience_403_precedes_410_retry_cas_and_file_version(client):
    """Opus delta R1: a device outside a device-only audience learns no state through a PUT."""
    o_id = object_id("restricted")
    signed, _, body = upload(o_id, author=WS, recipients=[LAPTOP])
    assert put(client, signed, body).status_code == 201
    mine, _, mb = upload(o_id)  # the phone, outside the audience
    assert put(client, mine, mb).json() == {"error": "not_eligible"}
    two, _, tb = upload(o_id, version=2, parent=signed["o"])
    assert put(client, two, tb, if_match="1").json() == {"error": "not_eligible"}
    sql(client, "UPDATE drop_objects SET tombstone_ms=?, tombstone_kind='retired'", NOW)
    assert put(client, mine, mb).json() == {"error": "not_eligible"}  # retired, still 403
    lap, _, lb = upload(o_id, author=LAPTOP, recipients=[LAPTOP])
    assert put(client, lap, lb).json() == {"error": "expired"}  # the audience gets the 410


def test_author_of_device_only_file_keeps_its_retry_until_the_sweep(client):
    o_id = object_id("own")
    signed, _, body = upload(o_id, recipients=[LAPTOP], expires=NOW + 120_000)
    assert put(client, signed, body).status_code == 201
    assert put(client, signed, body).status_code == 200  # the author is in its audience
    client.app.state.directory.clock = lambda: NOW + 120_000
    assert put(client, signed, body).json() == {"error": "expired"}  # before the sweep: 410
    # the expiry sweep (D39a2) deletes the audience rows: every device then gets 403
    sql(client, "DELETE FROM drop_audience")
    sql(client, "UPDATE drop_objects SET tombstone_ms=expires_ms, tombstone_kind='expired'")
    assert put(client, signed, body).json() == {"error": "not_eligible"}
    assert get(client, o_id, "descriptor").status_code == 403
    assert get(client, o_id, "descriptor", author=WS).status_code == 410


def test_other_space_tombstone_and_claimed(client):
    o_id = object_id("foreign")
    sql(
        client,
        "INSERT INTO drop_objects VALUES (?,?,?, 'file',1,0,NULL,?,NULL,NULL,?,?,'space',1,?)",
        o_id,
        WS_B,
        "x",
        NOW + DAY,
        PRIMARY,
        "h",
        NOW,
    )
    signed, _, body = upload(o_id)
    assert put(client, signed, body).json() == {"error": "not_eligible"}
    assert get(client, o_id, "descriptor").json() == {"error": "not_eligible"}
    t_id = object_id("tomb")
    signed, _, body = upload(t_id)
    assert put(client, signed, body).status_code == 201
    sql(
        client,
        "UPDATE drop_objects SET tombstone_ms=?, tombstone_kind='retired' WHERE object_id=?",
        NOW,
        t_id,
    )
    assert put(client, signed, body).json() == {"error": "expired"}  # a retry of a tombstone: 410
    c_id = object_id("claimed")
    claimed, _, cb = upload(c_id, recipients="inbox")
    assert put(client, claimed, cb).status_code == 201
    sql(client, "UPDATE drop_objects SET claimed_by=? WHERE object_id=?", WS, c_id)
    other, _, ob = upload(c_id, recipients="inbox", content=b"another")
    assert put(client, other, ob).json() == {"error": "not_eligible"}


def test_frame_transport_refusals(client):
    signed, _wraps, body = upload("frame")
    o_path = f"/v2/drop/{signed['o']['object_id']}/versions"
    bad = b"ODU1" + body[4:]
    assert client.put(o_path, content=bad, headers=headers()).status_code == 400
    r = client.put(o_path, content=body, headers=headers(**{"Content-Length": str(len(body) - 1)}))
    assert r.status_code == 400  # Content-Length does not match the frame (or a short body)
    long = body + b"x"
    r = client.put(o_path, content=long, headers=headers(**{"Content-Length": str(len(body))}))
    assert r.status_code == 400  # a long body
    chunked = client.put(o_path, content=iter([body]), headers=headers())
    assert chunked.status_code == 400  # no Content-Length: a chunked body
    head = (DR.MAX_HEAD + 1).to_bytes(4, "big")
    r = client.put(o_path, content=b"ODU2" + head + b"x" * 64, headers=headers())
    assert (r.status_code, r.json()) == (413, {"error": "too_large"})
    r = client.put(
        o_path,
        content=b"x",
        headers=headers(**{"Content-Length": str(client.app.state.drop.max_body + 1)}),
    )
    assert (r.status_code, r.json()) == (413, {"error": "too_large"})
    r = client.put(o_path + "?x=1", content=body, headers=headers())
    assert r.status_code == 400
    nothing_stored(client)


def test_blob_refusals_store_nothing(client):
    import drop_support as S

    def attempt(label, mutate, **kw):
        signed, data, _ = descriptor(object_id(label), **kw)
        data = mutate(data)
        o = dict(signed["o"])
        o["content_len"] = len(data)
        signed = (
            S.signed(o, "phone.sig")
            if False
            else __import__("directory_support").signed(o, "phone.sig")
        )
        r = put(client, signed, frame(signed, default_wraps(o), data))
        return r

    wrong = attempt("hash", lambda d: d[:-1] + bytes([d[-1] ^ 1]))  # content_hash mismatch
    assert wrong.json() == {"error": "malformed"}

    def not_ord2(d):
        return b"ORD3" + d[4:]

    def rehash(label, mutate):
        signed, data, _ = descriptor(object_id(label), content=b"x" * 512)
        data = mutate(data)
        o = {
            **signed["o"],
            "content_len": len(data),
            "content_hash": P.b64u(__import__("hashlib").sha256(data).digest()),
        }
        signed = __import__("directory_support").signed(o, "phone.sig")
        return put(client, signed, frame(signed, default_wraps(o), data))

    assert rehash("magic", not_ord2).status_code == 400
    assert rehash("objid", lambda d: d[:8] + bytes(16) + d[24:]).status_code == 400
    assert rehash("ver", lambda d: d[:24] + (2).to_bytes(4, "big") + d[28:]).status_code == 400
    assert rehash("chunk", lambda d: d[:28] + (500).to_bytes(4, "big") + d[32:]).status_code == 400
    assert rehash("suite", lambda d: d[:5] + b"\x01" + d[6:]).status_code == 400
    assert rehash("tail", lambda d: d + b"x" * 5).status_code == 400  # last chunk below a tag
    nothing_stored(client)


def test_w_session_fenced_before_any_slot(client):
    signed, _, body = upload("host", author=WS)
    calls = []
    client.app.state.drop.hooks["head"] = lambda: calls.append(1)
    r = put(client, signed, body, holder="0")
    assert (r.status_code, r.json()) == (409, {"error": "fenced"})
    r = put(client, signed, body, holder=None)
    assert (r.status_code, r.json()) == (409, {"error": "fenced"})
    assert calls == [] and client.app.state.drop.uploads.count == 0
    assert put(client, signed, body).status_code == 201


def test_takeover_during_transfer_is_fenced_at_the_commit(client):
    """orch-52 change 0: a takeover committed during the blob transfer fails the commit."""
    signed, _, body = upload("takeover", author=WS)

    def takeover(plan):
        sql(client, "UPDATE holders SET gen=2")

    client.app.state.drop.hooks["before_commit"] = takeover
    r = put(client, signed, body)
    assert (r.status_code, r.json()) == (409, {"error": "fenced"})
    nothing_stored(client)


def test_lapsed_lease_during_transfer_is_fenced(client):
    signed, _, body = upload("lapse", author=WS)

    def lapse(plan):
        client.app.state.directory.clock = lambda: NOW + 40_000

    client.app.state.drop.hooks["before_commit"] = lapse
    assert put(client, signed, body).json() == {"error": "fenced"}
    nothing_stored(client)


def test_membership_lost_during_transfer_refuses_at_commit(client):
    signed, _, body = upload("member")
    client.app.state.drop.hooks["before_commit"] = lambda plan: sql(
        client, "DELETE FROM members WHERE device_id=?", DEVICE
    )
    assert put(client, signed, body).json() == {"error": "not_eligible"}
    nothing_stored(client)


def test_epoch_moved_during_transfer_is_stale_at_commit(client):
    signed, _, body = upload("moved")
    client.app.state.drop.hooks["before_commit"] = lambda plan: sql(
        client, "INSERT INTO member_lists VALUES (?,2,2,'{}')", WS
    )
    assert put(client, signed, body).json() == {"error": "stale_epoch", "epoch": 2}
    nothing_stored(client)


# --- reads ------------------------------------------------------------------------------------------


def test_read_answer_order(client):
    absent = object_id("absent")
    assert get(client, absent, "descriptor").status_code == 404
    o_id = object_id("doc")
    v1, _, b1 = upload(o_id, kind="document")
    assert put(client, v1, b1).status_code == 201
    assert get(client, o_id, "descriptor", version=2).status_code == 404  # version absent
    r = get(client, o_id, "descriptor")
    assert (r.status_code, r.headers["etag"], r.json()) == (200, '"1"', {"descriptor": v1})
    hidden, _, hb = upload("hidden", author=WS, recipients=[LAPTOP])
    assert put(client, hidden, hb).status_code == 201
    h_id = hidden["o"]["object_id"]
    for what in ("descriptor", "wraps", "blob"):
        assert get(client, h_id, what).status_code == 403
        assert get(client, h_id, what, version=9).status_code == 403  # 403 for every version
    assert client.get(f"/v2/drop/{h_id}/descriptors", headers=headers()).status_code == 403
    assert get(client, h_id, "descriptor", author=LAPTOP).status_code == 200
    sql(
        client,
        "UPDATE drop_objects SET tombstone_ms=?, tombstone_kind='retired' WHERE object_id=?",
        NOW,
        h_id,
    )
    assert get(client, h_id, "descriptor").status_code == 403  # tombstones included
    assert get(client, h_id, "descriptor", author=LAPTOP).status_code == 410
    assert get(client, h_id, "descriptor", author=LAPTOP, version=9).status_code == 410  # 410 first
    sql(client, "UPDATE sessions SET expires_ms=?", NOW + 60 * DAY)
    client.app.state.directory.clock = lambda: NOW + 30 * DAY
    assert get(client, h_id, "descriptor", author=LAPTOP).status_code == 404  # the tombstone ended
    assert get(client, h_id, "descriptor").status_code == 404


def test_expired_file_reads_410_at_once(client):
    signed, _, body = upload("exp", expires=NOW + 120_000)
    assert put(client, signed, body).status_code == 201
    o_id = signed["o"]["object_id"]
    client.app.state.directory.clock = lambda: NOW + 120_000
    for what in ("descriptor", "wraps", "blob"):
        assert get(client, o_id, what).json() == {"error": "expired"}


def test_wraps_filtered_per_caller(client):
    o_id = object_id("wraps")
    signed, _, _ = upload(o_id)
    o = signed["o"]
    data = __import__("drop_support").blob(o_id, 1)[0]
    ws = [wrap(o, "wk"), wrap(o, "wxk"), wrap(o, "device", DEVICE), wrap(o, "device", LAPTOP)]
    ws.sort(key=lambda w: (w["target_kind"], w["target_id"]))
    assert put(client, signed, frame(signed, ws, data)).status_code == 201
    kinds = {
        who: [
            (w["target_kind"], w["target_id"])
            for w in get(client, o_id, "wraps", who).json()["wraps"]
        ]
        for who in (DEVICE, LAPTOP, WS)
    }
    assert kinds[DEVICE] == [("device", DEVICE), ("wk", WS)]
    assert kinds[LAPTOP] == [("device", LAPTOP), ("wk", WS)]
    assert kinds[WS] == [("wk", WS), ("wxk", WS)]  # never another device's wrap
    assert get(client, o_id, "wraps").json()["claimed_by"] is None


def test_unclaimed_inbox_is_listed_but_its_blob_waits(client):
    signed, _, body = upload("inbox", recipients="inbox")
    assert put(client, signed, body).status_code == 201
    o_id = signed["o"]["object_id"]
    assert get(client, o_id, "descriptor", LAPTOP).status_code == 200
    assert get(client, o_id, "blob", LAPTOP).json() == {"error": "not_eligible"}
    assert get(client, o_id, "wraps", LAPTOP).json() == {"claimed_by": None, "wraps": []}
    entries = listing(client, LAPTOP).json()["objects"]
    assert [e["object_id"] for e in entries] == [o_id]
    assert entries[0]["wraps"] == []  # no wxk to a device
    sql(client, "UPDATE drop_objects SET claimed_by=?", WS)
    assert get(client, o_id, "blob", LAPTOP).status_code == 200


def test_blob_get_streams_with_headers(client):
    signed, _, body = upload("blob", content=os.urandom(300_000))
    assert put(client, signed, body).status_code == 201
    r = get(client, signed["o"]["object_id"], "blob", LAPTOP)
    assert r.status_code == 200
    assert r.content == body[-signed["o"]["content_len"] :]
    assert r.headers["content-type"] == "application/octet-stream"
    assert r.headers["content-length"] == str(signed["o"]["content_len"])
    assert (r.headers["etag"], r.headers["cache-control"]) == ('"1"', "no-store")
    assert client.app.state.drop.downloads.count == 0


def test_descriptor_pages(client, monkeypatch):
    o_id = object_id("pages")
    parent = None
    for v in range(1, 6):
        s, _, b = upload(o_id, kind="document", version=v, parent=parent)
        assert put(client, s, b, if_match=str(v - 1)).status_code == 201
        parent = s["o"]
    url = f"/v2/drop/{o_id}/descriptors"
    page = client.get(url, params={"limit": "2"}, headers=headers()).json()
    assert [d["o"]["version"] for d in page["descriptors"]] == [1, 2] and page["next"] == 2
    page = client.get(url, params={"after": "2", "limit": "2"}, headers=headers()).json()
    assert [d["o"]["version"] for d in page["descriptors"]] == [3, 4] and page["next"] == 4
    page = client.get(url, params={"after": "4"}, headers=headers()).json()
    assert [d["o"]["version"] for d in page["descriptors"]] == [5] and page["next"] is None
    for bad in ({"limit": "257"}, {"limit": "0"}, {"after": "-1"}, {"x": "1"}, {"after": "01"}):
        assert client.get(url, params=bad, headers=headers()).status_code == 400
    lens = sorted(
        (r["version"], r["descriptor_len"]) for r in rows(path_of(client), "drop_versions")
    )
    cap = DR.NEXT_RESERVE + 11 + lens[0][1] + lens[1][1] + 2
    monkeypatch.setattr(DR, "PAGE_BYTES", cap)
    page = client.get(url, headers=headers()).json()
    assert len(page["descriptors"]) == 2 and page["next"] == 2  # the byte cut
    monkeypatch.setattr(DR, "PAGE_BYTES", 10)
    page = client.get(url, headers=headers()).json()
    assert len(page["descriptors"]) == 1 and page["next"] == 1  # at least one entry


def test_list_positions_direction_states_and_cut(client, monkeypatch):
    a, _, ab = upload("a")
    b, _, bb = upload("b", author=LAPTOP)
    c_, _, cb = upload("c", author=WS, recipients=[LAPTOP])
    d, _, dbody = upload("d", recipients="inbox")
    for s, body in ((a, ab), (b, bb), (c_, cb), (d, dbody)):
        assert put(client, s, body).status_code == 201
    mine = listing(client, DEVICE, "sending").json()
    assert [e["object_id"] for e in mine["objects"]] == [a["o"]["object_id"], d["o"]["object_id"]]
    assert mine["next"] is None
    got = listing(client, DEVICE).json()["objects"]
    assert [e["object_id"] for e in got] == [b["o"]["object_id"]]  # c is hidden from the phone
    lap = listing(client, LAPTOP).json()["objects"]
    assert [e["n"] for e in lap] == [1, 3, 4]
    for e in lap:
        assert set(e) == {
            "n",
            "object_id",
            "version",
            "state",
            "tombstone_until_ms",
            "descriptor",
            "wraps",
            "claimed_by",
        }
        assert e["state"] == "live" and e["tombstone_until_ms"] is None and e["claimed_by"] is None
    assert all(w["target_kind"] != "wxk" for e in lap for w in e["wraps"])
    host = listing(client, WS).json()["objects"]
    assert [e["n"] for e in host] == [1, 2, 4]  # W: received = authored by anyone else
    page = listing(client, LAPTOP, limit=2).json()
    assert [e["n"] for e in page["objects"]] == [1, 3] and page["next"] == 3
    page = listing(client, LAPTOP, after=3).json()
    assert [e["n"] for e in page["objects"]] == [4] and page["next"] is None
    # a new version moves an object to the end
    # states: retired and expired tombstones, pruned
    sql(
        client,
        "UPDATE drop_objects SET tombstone_ms=?, tombstone_kind='retired', n=10 WHERE object_id=?",
        NOW,
        a["o"]["object_id"],
    )
    sql(client, "UPDATE sessions SET expires_ms=?", NOW + 60 * DAY)
    client.app.state.directory.clock = lambda: NOW + 7 * DAY
    entries = {e["object_id"]: e for e in listing(client, LAPTOP).json()["objects"]}
    retired = entries[a["o"]["object_id"]]
    assert (retired["state"], retired["descriptor"], retired["wraps"]) == ("retired", None, [])
    assert retired["tombstone_until_ms"] == NOW + 30 * DAY and retired["version"] == 1
    expired = entries[d["o"]["object_id"]]
    assert (expired["state"], expired["descriptor"]) == ("expired", None)
    assert expired["tombstone_until_ms"] == d["o"]["expires_ms"] + 30 * DAY
    assert listing(client, LAPTOP, after=4).json()["objects"][0]["n"] == 10  # an after list sees it
    for bad in ({"limit": 65}, {"limit": 0}, {"after": -1}, {"x": 1}, {"after": True}):
        assert listing(client, LAPTOP, **bad).status_code == 400
    r = client.post(
        "/v2/drop/list",
        content=b"{" + b" " * 16384 + b"}",
        headers={"Authorization": "Bearer FAKE-laptop"},
    )
    assert (r.status_code, r.json()) == (413, {"error": "too_large"})
    client.app.state.directory.clock = lambda: NOW
    monkeypatch.setattr(DR, "LIST_BYTES", 10)
    page = listing(client, LAPTOP).json()
    assert len(page["objects"]) == 1 and page["next"] == page["objects"][0]["n"]


def test_list_other_workspace_and_non_member(client):
    r = client.post(
        "/v2/drop/list", json={"workspace_id": WS_B, "direction": "received"}, headers=headers()
    )
    assert r.status_code == 403
    sql(client, "DELETE FROM members WHERE device_id=?", LAPTOP)
    assert listing(client, LAPTOP).status_code == 403


def test_startup_sweep_prunes_missing_and_deletes_orphans(tmp_path):
    with TestClient(create_app(tmp_path)) as c:
        setup(c.app.state.directory)
        s, _, b = upload("a")
        assert put(c, s, b).status_code == 201
        s2, _, b2 = upload("b")
        assert put(c, s2, b2).status_code == 201
        _blobs, _ = files(c)
        drop = c.app.state.drop
        (drop.tmp / "orphan").write_bytes(b"x")
        stray = drop.blobs / s["o"]["object_id"] / "1.dead"
        stray.write_bytes(b"x")
        (drop.blobs / "zz").mkdir()
        path_a = drop.blobs / rows(c.app.state.directory.path, "drop_versions")[0]["blob_path"]
        path_a.unlink()  # a restore without data/drop/ for this one
        before = usage(c.app.state.directory.path)[("workspace", WS)]
    with TestClient(create_app(tmp_path)) as c:
        c.app.state.directory.clock = lambda: NOW
        drop = c.app.state.drop
        assert sorted(drop.tmp.iterdir()) == [] and not stray.exists()
        assert not (drop.blobs / "zz").exists()
        versions = {r["object_id"]: r for r in rows(c.app.state.directory.path, "drop_versions")}
        assert versions[s["o"]["object_id"]]["blob"] == "pruned"
        assert versions[s["o"]["object_id"]]["blob_path"] is None
        assert versions[s2["o"]["object_id"]]["blob"] == "stored"
        after = usage(c.app.state.directory.path)[("workspace", WS)]
        assert after[0] == before[0] - s["o"]["content_len"] and after[2] == before[2] - 1
        objs = {r["object_id"]: r["n"] for r in rows(c.app.state.directory.path, "drop_objects")}
        assert objs[s["o"]["object_id"]] == 3  # a new change position
        e = {
            x["object_id"]: x
            for x in c.post(
                "/v2/drop/list",
                json={"workspace_id": WS, "direction": "sending"},
                headers=headers(),
            ).json()["objects"]
        }
        assert (e[s["o"]["object_id"]]["state"], e[s["o"]["object_id"]]["wraps"]) == ("pruned", [])
        assert e[s["o"]["object_id"]]["descriptor"] == s
        r = c.get(f"/v2/drop/{s['o']['object_id']}/versions/1/blob", headers=headers())
        assert (r.status_code, r.json()) == (410, {"error": "expired"})
        assert (
            c.get(
                f"/v2/drop/{s['o']['object_id']}/versions/1/descriptor", headers=headers()
            ).status_code
            == 200
        )


def test_immutable_versions_trigger(client):
    s, _, b = upload("a")
    assert put(client, s, b).status_code == 201
    import sqlite3

    with pytest.raises(sqlite3.IntegrityError):
        sql(client, "UPDATE drop_versions SET descriptor='x'")
    with pytest.raises(sqlite3.IntegrityError):
        sql(client, "INSERT OR REPLACE INTO drop_versions SELECT * FROM drop_versions")
    sql(client, "UPDATE drop_versions SET blob='pruned', blob_path=NULL")  # the only mutable ones


def test_host_drop_notice_behind_its_switch(client):
    s, _, b = upload("a")
    assert put(client, s, b).status_code == 201
    q = {"after": "0", "wait": "0"}
    h = {"Authorization": "Bearer FAKE-workspace", "Orch-Holder": "1"}
    notices = client.get(f"/v2/workspaces/{WS}/host/poll", params=q, headers=h).json()["notices"]
    assert "drop" not in notices  # off until hosts accept the key (Q-H1)
    client.app.state.bridge.drop_notice = True
    notices = client.get(f"/v2/workspaces/{WS}/host/poll", params=q, headers=h).json()["notices"]
    assert notices["drop"] == 1
    s2, _, b2 = upload("b", author=LAPTOP)
    assert put(client, s2, b2).status_code == 201
    notices = client.get(f"/v2/workspaces/{WS}/host/poll", params=q, headers=h).json()["notices"]
    assert notices["drop"] == 2


def test_relay_never_stores_name_mime_or_plaintext(client):
    """§14.2 item 11: only ciphertext reaches the database and the blob files."""
    secret = b"PLAINTEXT-MARKER-orch-drop-7f3a" * 8
    signed, _, body = upload("secret", content=secret)
    assert put(client, signed, body).status_code == 201
    data = path_of(client).read_bytes()
    for wal in path_of(client).parent.glob("*.sqlite3-wal"):
        data += wal.read_bytes()
    for blob in files(client)[0]:
        data += blob.read_bytes()
    for needle in (b"PLAINTEXT-MARKER", b"f.txt", b"text/plain"):
        assert needle not in data


# --- review round 2: F1, F4, F5 and the test gaps A04, A23, A26, A42, A43 ---------------------------


def test_drop_routes_are_off_unless_enabled(tmp_path, monkeypatch):
    """F1: without ORCH_RELAY_DROP=1 every Drop route answers 404 as an absent route."""
    monkeypatch.setenv("ORCH_RELAY_DROP", "0")
    o_id = object_id("off")
    with TestClient(create_app(tmp_path)) as c:
        setup(c.app.state.directory)
        signed, _, body = upload("off")
        assert put(c, signed, body).status_code == 404
        h = {"Authorization": "Bearer FAKE-device"}
        assert (
            c.post(
                "/v2/drop/list", json={"workspace_id": WS, "direction": "received"}, headers=h
            ).status_code
            == 404
        )
        for what in ("descriptor", "wraps", "blob"):
            assert c.get(f"/v2/drop/{o_id}/versions/1/{what}", headers=h).status_code == 404
        assert c.get(f"/v2/drop/{o_id}/descriptors", headers=h).status_code == 404
        assert rows(path_of(c), "drop_objects") == []  # migration 0017 still applied
    monkeypatch.setenv("ORCH_RELAY_DROP", "1")
    assert DR.enabled() and not DR.enabled({}) and not DR.enabled({"ORCH_RELAY_DROP": "yes"})


def seed_versions(c, o_id, count, size):
    """`count` document versions with descriptors of `size` bytes, written directly."""
    text = '{"o":{"pad":"' + "x" * (size - 20) + '"},"sig":""}'
    with closing(db.connect(path_of(c))) as con, con:
        con.execute(
            "INSERT INTO drop_objects VALUES (?,?,?,'document',?,0,NULL,NULL,NULL,NULL,?,?,'space',1,?)",
            (o_id, WS, "p", count, DEVICE, "h", NOW),
        )
        for v in range(1, count + 1):
            con.execute(
                "INSERT INTO drop_versions VALUES (?,?,'device',?,?,'h','c',100,1,?,'stored',?,?)",
                (o_id, v, DEVICE, text, len(text), f"{o_id}/{v}.x", NOW),
            )
    return text


def test_descriptor_page_reads_only_what_fits(client):
    """F4: a 1 MiB page over 257 maximal descriptors stays near its own size in memory."""
    import tracemalloc

    o_id = object_id("big pages")
    text = seed_versions(client, o_id, 257, 96 * 1024)
    session = client.app.state.drop.admit({"authorization": "Bearer FAKE-device"})
    tracemalloc.start()
    page = client.app.state.drop.descriptors_page(session, o_id, {})
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    assert len(page) <= DR.PAGE_BYTES and page.count(text.encode()) == 10
    assert page.endswith(b',"next":10}')
    assert peak < 5 * 1024 * 1024, peak  # was ~25 MB: every descriptor fetched before the cut


def test_startup_sweep_never_loads_descriptors(client):
    """F5: the sweep reads stored versions in batches without their descriptor text."""
    import tracemalloc

    drop = client.app.state.drop
    o_id = object_id("sweep many")
    seed_versions(client, o_id, 300, 90 * 1024)
    (drop.blobs / o_id).mkdir()
    for v in range(1, 301):
        (drop.blobs / o_id / f"{v}.x").write_bytes(b"x")
    tracemalloc.start()
    drop.startup_sweep()
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    assert peak < 5 * 1024 * 1024, peak  # was ~27 MB
    assert {r["blob"] for r in rows(path_of(client), "drop_versions")} == {"stored"}


def test_a_device_in_two_workspaces_cannot_move_an_object(client):
    """A04: another space's object id is 403 even for a member of both workspaces."""
    from directory_support import CARD

    with closing(db.connect(path_of(client))) as con, con:
        con.execute(
            "INSERT INTO workspaces SELECT ?,owner_person_id,wsk_pub,delegation,card,card_seq,"
            "wxk_version,client_hosted FROM workspaces WHERE workspace_id=?",
            (WS_B, WS),
        )
        con.execute(
            "INSERT INTO members VALUES (?,?,?,?)",
            (WS_B, DEVICE, CARD["o"]["owner_person_id"], P.cj(["look", "decide", "operate"])),
        )
        con.execute("INSERT INTO member_lists VALUES (?,1,1,'{}')", (WS_B,))
    o_id = object_id("two spaces")
    v1, _, b1 = upload(o_id, kind="document", space=WS_B, recipients=[WS_B])
    assert put(client, v1, b1).status_code == 201
    v2, _, b2 = upload(o_id, kind="document", version=2, parent=v1["o"])  # says space A
    assert put(client, v2, b2, if_match="1").json() == {"error": "not_eligible"}
    (obj,) = rows(path_of(client), "drop_objects")
    assert (obj["workspace_id"], obj["current"]) == (WS_B, 1)


def test_device_wrap_to_a_revoked_or_expired_target(client):
    """A23: a device wrap to a revoked or expired member certificate is 403."""
    from directory_support import PERSON, RECORD

    def attempt(label):
        s, _, _ = upload(label)
        data = __import__("drop_support").blob(s["o"]["object_id"], 1)[0]
        return put(client, s, frame(s, [wrap(s["o"], "wk"), wrap(s["o"], "device", LAPTOP)], data))

    sql(client, "UPDATE devices SET expires_ms=? WHERE device_id=?", NOW, LAPTOP)
    assert attempt("expired target").json() == {"error": "not_eligible"}
    sql(client, "UPDATE devices SET expires_ms=NULL WHERE device_id=?", LAPTOP)
    assert attempt("fine target").status_code == 201
    sql(
        client,
        "INSERT INTO revocations VALUES (?,?,?,?,?,?)",
        LAPTOP,
        PERSON,
        P.cj(RECORD),
        "lost",
        NOW,
        7,
    )
    assert attempt("revoked target").json() == {"error": "not_eligible"}


def test_tombstone_leaves_the_list_after_30_days(client):
    """A26: listed until tombstone_until_ms, then gone without a new position."""
    s, _, b = upload("ends")
    assert put(client, s, b).status_code == 201
    sql(client, "UPDATE drop_objects SET tombstone_ms=?, tombstone_kind='retired'", NOW)
    sql(client, "UPDATE sessions SET expires_ms=?", NOW + 60 * DAY)
    client.app.state.directory.clock = lambda: NOW + 30 * DAY - 1
    assert [e["state"] for e in listing(client, LAPTOP).json()["objects"]] == ["retired"]
    client.app.state.directory.clock = lambda: NOW + 30 * DAY
    assert listing(client, LAPTOP).json() == {"objects": [], "next": None}


def test_commit_rechecks_the_object_state(client):
    """A42: a retire or an expiry between the head checks and the commit is 410 at the commit."""
    o_id = object_id("recheck")
    v1, _, b1 = upload(o_id, kind="document")
    assert put(client, v1, b1).status_code == 201
    v2, _, b2 = upload(o_id, kind="document", version=2, parent=v1["o"])
    client.app.state.drop.hooks["before_commit"] = lambda plan: sql(
        client, "UPDATE drop_objects SET tombstone_ms=?, tombstone_kind='retired'", NOW
    )
    assert put(client, v2, b2, if_match="1").json() == {"error": "expired"}
    assert len(rows(path_of(client), "drop_versions")) == 1
    f, _, fb = upload("expires in transfer", expires=NOW + 120_000)

    def late(plan):
        client.app.state.directory.clock = lambda: NOW + 120_000

    client.app.state.drop.hooks["before_commit"] = late
    assert put(client, f, fb).json() == {"error": "expired"}
    assert len(files(client)[0]) == 1


def test_commit_uses_the_request_now_for_the_60_s_floor(client):
    """A43 (Opus delta 2, L-c): a slow upload that met the floor at admission is not refused."""
    f, _, fb = upload("floor at commit", expires=NOW + 60_000)

    def slow(plan):
        client.app.state.directory.clock = lambda: NOW + 30_000

    client.app.state.drop.hooks["before_commit"] = slow
    assert put(client, f, fb).status_code == 201


def test_startup_sweep_batches_cover_every_row_in_key_order(client):
    """F5: the keyset batches advance and miss nothing."""
    o_id = object_id("batches")
    seed_versions(client, o_id, 23, 100)
    with closing(db.connect(path_of(client))) as con:
        con.row_factory = __import__("sqlite3").Row
        got = [(r["object_id"], r["version"]) for r in DR.Drop.stored_rows(con, batch=7)]
    assert got == [(o_id, v) for v in range(1, 24)]
