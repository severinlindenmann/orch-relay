"""P3-D39 (D39a2 part 1): stored-bytes quotas, in-flight reservations, the commit's authority, the
daily version-1 creation counters and the MiB upload and download buckets."""

import asyncio
from contextlib import closing

import pytest
from directory_support import DEVICE, NOW, WS
from drop_support import DAY, LAPTOP, TOKENS, descriptor, frame, object_id, put, rows, setup, upload
from fastapi.testclient import TestClient
from test_drop_transfer import Harness, Peer, split
from test_drop_transfer import put as aput
from test_drop_transfer import scope as tscope

from orch_relay import db
from orch_relay import drop_quota as Q
from orch_relay import proto as P
from orch_relay.app import create_app
from orch_relay.directory import Refusal, throttle_settings

OWNER = "owner"


@pytest.fixture
def client(tmp_path):
    with TestClient(create_app(tmp_path)) as c:
        setup(c.app.state.directory)
        yield c


def path_of(c):
    return c.app.state.directory.path


def seed(c, scope, ident, blob=0, head=0, versions=0, documents=0):
    with closing(db.connect(path_of(c))) as con, con:
        con.execute(
            "INSERT INTO drop_usage VALUES (?,?,?,?,?,?) ON CONFLICT(scope,id) DO UPDATE SET "
            "blob_bytes=excluded.blob_bytes, head_bytes=excluded.head_bytes, "
            "versions=excluded.versions, documents=excluded.documents",
            (scope, ident, blob, head, versions, documents),
        )


def usage_row(c, scope, ident):
    with closing(db.connect(path_of(c))) as con:
        return con.execute(
            "SELECT blob_bytes, head_bytes, versions, documents FROM drop_usage "
            "WHERE scope=? AND id=?",
            (scope, ident),
        ).fetchone()


def nothing_new(c, before=0):
    assert len(rows(path_of(c), "drop_objects")) == before
    assert c.app.state.drop.reserved.view() == {}
    assert c.app.state.drop.uploads.count == 0
    drop = c.app.state.drop
    assert [p for p in drop.tmp.iterdir()] == []
    assert len([p for p in drop.blobs.rglob("*") if p.is_file()]) == before


def owner_of(c):
    with closing(db.connect(path_of(c))) as con:
        return con.execute("SELECT owner_person_id FROM workspaces").fetchone()[0]


def need_of(signed, wraps):
    class Plan:  # the parts Need.of reads
        o = signed["o"]
        descriptor = P.cj(signed).decode()
        wrap_texts = tuple(P.cj(w).decode() for w in wraps)
        devices = ()

    return Q.Need.of(Plan, False)


# --- the pure checks ------------------------------------------------------------------------------


def blank(keys):
    return {key: dict.fromkeys(Q.FIELDS, 0) for key in keys}


def test_need_mirrors_what_the_commit_charges(client):
    signed, wraps, _body = upload("a")
    need = need_of(signed, wraps)
    head = len(P.cj(signed)) + sum(len(P.cj(w)) for w in wraps)
    assert (need.blob, need.head, need.versions, need.documents) == (
        signed["o"]["content_len"],
        head,
        1,
        0,
    )
    assert put(client, signed, _body).status_code == 201
    assert usage_row(client, "workspace", WS) == (need.blob, need.head, 1, 0)  # exactly the need


CAPS = [
    # (scope key, field, attribute, name, status)
    ("device", "blob", "dev_blob", "drop_device", 429),
    ("device", "head", "dev_head", "drop_device_head", 429),
    ("device", "versions", "dev_versions", "drop_device_versions", 429),
    ("device", "documents", "dev_documents", "drop_device_documents", 429),
    ("workspace", "blob", "ws_blob", "drop_ws", 429),
    ("workspace", "head", "ws_head", "drop_head_ws", 429),
    ("workspace", "versions", "ws_versions", "drop_versions", 429),
    ("workspace", "documents", "ws_documents", "drop_documents", 429),
    ("account", "blob", "account_blob", "drop_account", 429),
    ("global", "blob", "global_blob", None, 503),
    ("global", "head", "global_head", None, 503),
]


@pytest.mark.parametrize(("scope", "field", "attr", "name", "status"), CAPS)
def test_each_cap_passes_exactly_at_the_cap_and_refuses_one_over(scope, field, attr, name, status):
    quotas = Q.Quotas({})
    ws, owner, device = "w" * 32, "p" * 32, "d" * 32
    ident = {"device": f"{ws}:{device}", "workspace": ws, "account": owner, "global": ""}[scope]
    keys = Q.usage_keys(ws, owner, device)
    o = {"object_kind": "file", "version": 1}
    cap = getattr(quotas, attr)
    need = Q.Need(0, 0, 0, 0)
    setattr(need, field, 1)
    usage = blank(keys)
    usage[(scope, ident)][field] = cap - 1
    Q.check(quotas, usage, {}, need, ws, owner, device, o)  # lands exactly on the cap
    usage[(scope, ident)][field] = cap
    with pytest.raises(Refusal) as caught:
        Q.check(quotas, usage, {}, need, ws, owner, device, o)
    error = caught.value
    assert error.status == status and error.retry == Q.SWEEP
    if name is None:
        assert (error.code, getattr(error, "details", {})) == ("overloaded", {})
    else:
        assert (error.code, error.details) == ("quota_exceeded", {"quota": name})
    # the reservations of uploads in flight count against the cap too
    usage[(scope, ident)][field] = cap - 1
    with pytest.raises(Refusal):
        Q.check(quotas, usage, {(scope, ident): {field: 1}}, need, ws, owner, device, o)


def test_a_field_the_upload_does_not_add_to_is_not_checked():
    quotas = Q.Quotas({})
    keys = Q.usage_keys("w", "p", "d")
    usage = blank(keys)
    usage[("device", "w:d")]["head"] = quotas.dev_head + 10  # a lowered cap, an over-full share
    o = {"object_kind": "file", "version": 1}
    Q.check(quotas, usage, {}, Q.Need(5, 0, 1, 0), "w", "p", "d", o)
    with pytest.raises(Refusal):
        Q.check(quotas, usage, {}, Q.Need(5, 1, 1, 0), "w", "p", "d", o)


def test_the_authors_share_is_named_before_the_workspace_and_the_global_ceiling_last():
    quotas = Q.Quotas({})
    keys = Q.usage_keys("w", "p", "d")
    usage = blank(keys)
    for key in keys:
        usage[key]["blob"] = 10**12  # everything is over
    o = {"object_kind": "file", "version": 1}
    with pytest.raises(Refusal) as caught:
        Q.check(quotas, usage, {}, Q.Need(1, 0), "w", "p", "d", o)
    assert caught.value.details == {"quota": "drop_device"}
    with pytest.raises(Refusal) as caught:  # a W author has no device share
        Q.check(quotas, usage, {}, Q.Need(1, 0), "w", "p", None, o)
    assert caught.value.details == {"quota": "drop_ws"}
    usage = blank(keys)
    usage[("global", "")]["blob"] = 10**12
    with pytest.raises(Refusal) as caught:
        Q.check(quotas, usage, {}, Q.Need(1, 0), "w", "p", "d", o)
    assert caught.value.code == "overloaded"


def test_document_chain_cap_is_the_1025th_version():
    quotas = Q.Quotas({})
    keys = Q.usage_keys("w", "p", None)
    Q.check(
        quotas,
        blank(keys),
        {},
        Q.Need(1, 1),
        "w",
        "p",
        None,
        {"object_kind": "document", "version": 1024},
    )
    with pytest.raises(Refusal) as caught:
        Q.check(
            quotas,
            blank(keys),
            {},
            Q.Need(1, 1),
            "w",
            "p",
            None,
            {"object_kind": "document", "version": 1025},
        )
    assert (caught.value.status, caught.value.details) == (429, {"quota": "drop_doc_versions"})
    # a file is never version 1025 (CAS), and the cap has no per-member share
    Q.check(
        quotas, blank(keys), {}, Q.Need(1, 1), "w", "p", None, {"object_kind": "file", "version": 1}
    )


def test_reservations_add_up_and_release_exactly():
    r = Q.Reservations()
    keys = Q.usage_keys("w", "p", "d")
    one, two = r.take(keys, Q.Need(100, 10)), r.take(keys, Q.Need(50, 5, 1, 1))
    assert r.view()[("workspace", "w")] == {"blob": 150, "head": 15, "versions": 2, "documents": 1}
    r.release(one)
    assert r.view()[("device", "w:d")]["blob"] == 50
    r.release(two)
    assert r.view() == {}


def test_seconds_to_midnight_is_whole_seconds_between_1_and_86400():
    midnight = 5 * Q.DAY_MS
    assert Q.seconds_to_midnight(midnight - 500) == 1  # 23:59:59.500
    assert Q.seconds_to_midnight(midnight - 1000) == 1
    assert Q.seconds_to_midnight(midnight - 1001) == 2
    assert Q.seconds_to_midnight(midnight) == 86_400  # at 00:00:00.000 a full day remains
    assert Q.seconds_to_midnight(midnight + 1) == 86_400
    assert Q.seconds_to_midnight(midnight + 86_399_999) == 1


def test_creation_counter_upsert_refuses_at_the_cap_and_is_per_day(tmp_path):
    path = tmp_path / "r.sqlite3"
    db.migrate(path)
    con = db.connect(path)
    quotas = Q.Quotas({})
    quotas.ws_creations, quotas.dev_creations = 3, 2
    assert Q.creations_left(con, quotas, "w", "d", 1)
    with con:
        assert Q.charge_creation(con, quotas, "w", "d", 1)
        assert Q.charge_creation(con, quotas, "w", "d", 1)
    assert not Q.creations_left(con, quotas, "w", "d", 1)  # the device share: 2 of 2
    assert Q.creations_left(con, quotas, "w", "other", 1)
    assert Q.creations_left(con, quotas, "w", "d", 2)  # a new UTC day
    with con:
        assert not Q.charge_creation(con, quotas, "w", "d", 1)
        assert Q.charge_creation(con, quotas, "w", None, 1)  # a W author: the workspace only
    assert not Q.creations_left(con, quotas, "w", "other", 1)  # workspace 3 of 3
    con.close()


def test_global_ceilings_come_from_the_environment():
    assert Q.Quotas({}).global_blob == 4 * 1024**3 and Q.Quotas({}).global_head == 512 * 1024**2
    quotas = Q.Quotas(
        {
            "ORCH_RELAY_DROP_GLOBAL_BYTES": "1073741824",
            "ORCH_RELAY_DROP_GLOBAL_HEAD_BYTES": "134217728",
        }
    )
    assert (quotas.global_blob, quotas.global_head) == (1024**3, 128 * 1024**2)
    for bad in ("0", "-1", "1.5", "x", ""):
        with pytest.raises(ValueError):
            Q.Quotas({"ORCH_RELAY_DROP_GLOBAL_BYTES": bad})


# --- over HTTP ------------------------------------------------------------------------------------


def refused(r, quota, status=429):
    assert r.status_code == status, r.text
    body = r.json()
    if status == 429:
        assert body == {"error": "quota_exceeded", "quota": quota}
    else:
        assert body == {"error": "overloaded"}
    assert r.headers["retry-after"] == "600"


HTTP_CAPS = [
    # (usage scope, id template, row fields, expected quota or None for the global 503)
    ("device", f"{WS}:{DEVICE}", {"blob": 1}, "drop_device"),
    ("device", f"{WS}:{DEVICE}", {"head": 1}, "drop_device_head"),
    ("device", f"{WS}:{DEVICE}", {"versions": 1}, "drop_device_versions"),
    ("workspace", WS, {"blob": 1}, "drop_ws"),
    ("workspace", WS, {"head": 1}, "drop_head_ws"),
    ("workspace", WS, {"versions": 1}, "drop_versions"),
    ("account", OWNER, {"blob": 1}, "drop_account"),
    ("global", "", {"blob": 1}, None),
    ("global", "", {"head": 1}, None),
]


@pytest.mark.parametrize(("scope", "ident", "fields", "quota"), HTTP_CAPS)
def test_a_full_scope_refuses_the_put_and_stores_nothing(client, scope, ident, fields, quota):
    quotas = client.app.state.drop.quotas
    ident = owner_of(client) if scope == "account" else ident
    (field,) = fields
    signed, wraps, body = upload("a")
    need = need_of(signed, wraps)
    attr = {
        ("device", "blob"): "dev_blob",
        ("device", "head"): "dev_head",
        ("device", "versions"): "dev_versions",
        ("workspace", "blob"): "ws_blob",
        ("workspace", "head"): "ws_head",
        ("workspace", "versions"): "ws_versions",
        ("account", "blob"): "account_blob",
        ("global", "blob"): "global_blob",
        ("global", "head"): "global_head",
    }[(scope, field)]
    cap = getattr(quotas, attr)
    amount = {"blob": need.blob, "head": need.head, "versions": 1}[field]
    # exactly at the cap after this upload: it passes (the boundary, over HTTP)
    seed(client, scope, ident, **{field: cap - amount})
    ok = put(client, signed, body)
    assert ok.status_code == 201, ok.text
    # one byte (or version) over: refused, nothing more stored
    other, _w, other_body = upload("b")
    r = put(client, other, other_body)
    refused(r, quota, 429 if quota else 503)
    nothing_new(client, before=1)
    assert client.app.state.drop.uploads.count == 0


def test_documents_and_the_document_chain_have_their_caps(client):
    drop = client.app.state.drop
    drop.quotas.dev_documents = 1
    one = upload("d1", kind="document")
    assert put(client, one[0], one[2]).status_code == 201
    two = upload("d2", kind="document")
    refused(put(client, two[0], two[2]), "drop_device_documents")
    drop.quotas.dev_documents, drop.quotas.ws_documents = 64, 1
    refused(put(client, two[0], two[2]), "drop_documents")
    drop.quotas.ws_documents, drop.quotas.doc_versions = 256, 2
    parent = one[0]["o"]
    for version, expected in ((2, 201), (3, 429)):
        signed, data, _dek = descriptor(
            parent["object_id"], version=version, kind="document", parent=parent
        )
        parent = signed["o"]
        r = put(client, signed, frame(signed, [_wrap(signed)], data), if_match=str(version - 1))
        assert r.status_code == expected, r.text
        if expected == 429:
            assert r.json() == {"error": "quota_exceeded", "quota": "drop_doc_versions"}
            assert r.headers["retry-after"] == "600"


def _wrap(signed):
    from drop_support import wrap

    return wrap(signed["o"], "wk")


def test_the_commit_is_the_authority_when_usage_moves_after_the_reservation(client):
    """Another upload's commit lands between this one's reservation and its own commit: the
    reservation saw room, the live rows do not. Nothing is stored, the file is unlinked, the
    reservation released, and the cap holds."""
    drop = client.app.state.drop
    signed, wraps, body = upload("a")
    need = need_of(signed, wraps)
    drop.quotas.ws_blob = need.blob + 100

    def hook(plan):
        seed(client, "workspace", WS, blob=drop.quotas.ws_blob)  # a rival commit filled the cap

    drop.hooks["before_commit"] = hook
    r = put(client, signed, body)
    refused(r, "drop_ws")
    assert rows(path_of(client), "drop_versions") == []
    nothing_new(client)
    assert usage_row(client, "workspace", WS)[0] == drop.quotas.ws_blob  # untouched


def test_a_commit_refusal_charges_no_creation(client):
    drop = client.app.state.drop
    signed, _wraps, body = upload("a")
    drop.quotas.ws_blob = 1
    assert put(client, signed, body).status_code == 429
    assert rows(path_of(client), "drop_creations") == []  # rolled back with the transaction


def test_creation_counters_per_device_and_workspace_per_utc_day(client):
    d, drop = client.app.state.directory, client.app.state.drop
    drop.quotas.dev_creations, drop.quotas.ws_creations = 2, 3
    for label in "ab":
        s, _w, b = upload(label)
        assert put(client, s, b).status_code == 201
    s, _w, b = upload("c")
    r = put(client, s, b)  # the device's third in this UTC day
    assert (r.status_code, r.json()) == (429, {"error": "rate_limited", "quota": "drop_creations"})
    to_midnight = Q.seconds_to_midnight(NOW)
    assert r.headers["retry-after"] == str(to_midnight) and 1 <= to_midnight <= 86_400
    nothing_new(client, before=2)
    # the exact retry is a 200 before any charge; a 409 charges nothing either
    first, _w, first_body = upload("a")
    assert put(client, first, first_body).status_code == 200
    assert rows(path_of(client), "drop_creations")[0]["creations"] == 2
    # the workspace cap (3) binds a second device that still has room: the laptop
    s, _w, b = upload("c", author=LAPTOP)
    assert put(client, s, b, author=LAPTOP).status_code == 201
    s, _w, b = upload("d", author=LAPTOP)
    r = put(client, s, b, author=LAPTOP)
    assert (r.status_code, r.json()) == (429, {"error": "rate_limited", "quota": "drop_creations"})
    # a new UTC day opens new counters (and the old rows stay for the sweep, PR 2)
    d.clock = lambda: NOW + DAY
    with closing(db.connect(path_of(client))) as con, con:  # sessions and certificates outlive it
        con.execute("UPDATE sessions SET expires_ms=?", (NOW + 2 * DAY,))
        con.execute("UPDATE devices SET expires_ms=?", (NOW + 30 * DAY,))
        con.execute("UPDATE holders SET lease_until_ms=?", (NOW + 2 * DAY,))
    s, _w, b = upload("e", expires=NOW + DAY + 7 * DAY, now=NOW + DAY)
    assert put(client, s, b).status_code == 201
    days = {r["day"] for r in rows(path_of(client), "drop_creations")}
    assert days == {NOW // DAY, NOW // DAY + 1}


def test_a_new_document_version_is_not_a_creation(client):
    client.app.state.drop.quotas.dev_creations = 1
    one = upload("d1", kind="document")
    assert put(client, one[0], one[2]).status_code == 201
    o1 = one[0]["o"]
    signed, data, _dek = descriptor(o1["object_id"], version=2, kind="document", parent=o1)
    r = put(client, signed, frame(signed, [_wrap(signed)], data), if_match="1")
    assert r.status_code == 201, r.text
    assert rows(path_of(client), "drop_creations")[0]["creations"] == 1


def test_w_session_uploads_charge_the_workspace_and_not_a_device_share(client):
    s, _w, b = upload("h", author=WS)
    assert put(client, s, b, author=WS).status_code == 201
    assert usage_row(client, "workspace", WS)[0] == s["o"]["content_len"]
    assert [r["scope"] for r in rows(path_of(client), "drop_creations")] == ["workspace"]
    assert usage_row(client, "device", f"{WS}:{WS}") is None


# --- reservations across concurrent uploads -------------------------------------------------------


@pytest.fixture
def h(tmp_path):
    return Harness(tmp_path)


def test_concurrent_uploads_cannot_both_take_the_last_free_slice(h):
    """Each upload fits alone, not together: the first holds its reservation while it waits at
    the commit; the second is refused 429 at step 9, before it reads a blob byte."""
    first, _w1, body1 = upload("a")
    second, _w2, body2 = upload("b", author=LAPTOP)
    h.drop.quotas.ws_blob = first["o"]["content_len"] + 10  # room for one, not two

    async def go():
        gate = asyncio.Event()
        reached = asyncio.Event()

        async def hold(plan):
            reached.set()
            await gate.wait()

        h.drop.hooks["before_commit"] = hold
        one = asyncio.create_task(aput(h, body1, first))
        await reached.wait()
        assert h.drop.reserved.view()[("workspace", WS)]["blob"] == first["o"]["content_len"]
        # a chunks=[] second body: a refusal must come before any blob byte is read
        refusal = await aput(h, body2, second, author=LAPTOP)
        gate.set()
        win = await one
        return refusal, win

    refusal, win = asyncio.run(go())
    assert win.status == 201
    assert refusal.status == 429
    assert refusal.json == {"error": "quota_exceeded", "quota": "drop_ws"}
    assert refusal.header(b"retry-after") == b"600"
    assert h.drop.reserved.view() == {}
    assert len(rows(h.d.path, "drop_objects")) == 1


def test_reservations_are_released_on_a_disconnect_and_on_a_short_body(h):
    signed, _w, body = upload("a")
    h.drop.quotas.ws_blob = signed["o"]["content_len"] + 100
    asyncio.run(aput(h, body, signed, chunks=[body[: len(body) // 2]], then="disconnect"))
    assert h.drop.reserved.view() == {}
    peer = asyncio.run(aput(h, body, signed))  # the same upload now fits again
    assert peer.status == 201


# --- buckets --------------------------------------------------------------------------------------


def exhaust(client, **buckets):
    d = client.app.state.directory
    d.throttles = {**d.throttles, **buckets}


def test_upload_bucket_costs_one_token_per_started_mib(client):
    exhaust(client, **{"drop-up": (3, 1)})  # NOW is frozen: no refill
    big = upload("big", content=b"\0" * (1024 * 1024 + 1), chunk=1 << 20)  # two started MiB
    assert put(client, big[0], big[2]).status_code == 201  # 2 of 3 tokens
    small = upload("s1")
    assert put(client, small[0], small[2]).status_code == 201  # 1 of 3
    last = upload("s2")
    r = put(client, last[0], last[2])  # the bucket is empty
    assert (r.status_code, r.json()) == (429, {"error": "rate_limited"})
    assert int(r.headers["retry-after"]) >= 1
    nothing_new(client, before=2)  # refused before any slot or reservation


def test_upload_bucket_is_taken_at_admission_before_the_head_is_read(client):
    exhaust(client, **{"drop-up": (1, 1)})
    one = upload("a")
    assert put(client, one[0], one[2]).status_code == 201
    r = client.put(  # garbage that would be 400: the empty bucket answers first
        f"/v2/drop/{object_id('zz')}/versions",
        content=b"garbage",
        headers={"Authorization": "Bearer " + TOKENS[DEVICE], "If-Match": "0"},
    )
    assert r.status_code == 429


def test_a_devices_workspace_bucket_is_charged_when_the_head_names_the_workspace(client):
    exhaust(client, **{"drop-up-workspace": (2, 1)})
    for label, author in (("a", DEVICE), ("b", LAPTOP)):
        s, _w, b = upload(label, author=author)
        assert put(client, s, b, author=author).status_code == 201
    s, _w, b = upload("c")
    r = put(client, s, b)
    assert (r.status_code, r.json()) == (429, {"error": "rate_limited"})
    assert 1 <= int(r.headers["retry-after"])
    nothing_new(client, before=2)


def test_a_host_upload_spends_the_workspace_bucket(client):
    exhaust(client, **{"drop-up-workspace": (1, 1)})
    one = upload("h1", author=WS)
    assert put(client, one[0], one[2], author=WS).status_code == 201
    two = upload("h2", author=WS)
    assert put(client, two[0], two[2], author=WS).status_code == 429


def test_the_upload_bucket_refills_with_the_clock(client):
    d = client.app.state.directory
    exhaust(client, **{"drop-up": (1, 1)})  # one token a minute
    one = upload("a")
    assert put(client, one[0], one[2]).status_code == 201
    two = upload("b")
    r = put(client, two[0], two[2])
    assert (r.status_code, r.headers["retry-after"]) == (429, "60")
    d.clock = lambda: NOW + 60_000
    assert put(client, two[0], two[2]).status_code == 201


def test_download_bucket_is_taken_before_the_blob_is_read(client):
    s, _w, b = upload("a")
    assert put(client, s, b).status_code == 201
    exhaust(client, **{"drop-down": (1, 1)})
    url = f"/v2/drop/{s['o']['object_id']}/versions/1/blob"
    auth = {"Authorization": "Bearer " + TOKENS[DEVICE]}
    first = client.get(url, headers=auth)
    assert first.status_code == 200 and first.content == b[-s["o"]["content_len"] :]
    second = client.get(url, headers=auth)
    assert (second.status_code, second.json()) == (429, {"error": "rate_limited"})
    assert int(second.headers["retry-after"]) >= 1
    assert client.app.state.drop.downloads.count == 0  # the slot was freed too
    # metadata reads take no download tokens
    assert client.get(url.replace("blob", "descriptor"), headers=auth).status_code == 200


def test_download_person_bucket_spans_a_persons_devices(client):
    s, _w, b = upload("a")
    assert put(client, s, b).status_code == 201
    exhaust(client, **{"drop-down-person": (1, 1)})
    url = f"/v2/drop/{s['o']['object_id']}/versions/1/blob"
    assert client.get(url, headers={"Authorization": "Bearer " + TOKENS[DEVICE]}).status_code == 200
    r = client.get(url, headers={"Authorization": "Bearer " + TOKENS[LAPTOP]})  # same person
    assert r.status_code == 429


def test_bucket_defaults_and_environment_overrides():
    settings, _table = throttle_settings({})
    assert settings["drop-up"] == (64, 32) and settings["drop-up-workspace"] == (256, 128)
    assert settings["drop-down"] == (256, 256) and settings["drop-down-person"] == (512, 512)
    settings, _table = throttle_settings(
        {"ORCH_RELAY_THROTTLE_DROP_UP": "10/5", "ORCH_RELAY_THROTTLE_DROP_DOWN_PERSON": "7/3"}
    )
    assert settings["drop-up"] == (10, 5) and settings["drop-down-person"] == (7, 3)
    with pytest.raises(ValueError):
        throttle_settings({"ORCH_RELAY_THROTTLE_DROP_UP": "0/5"})
    # a 5-attachment, 25 MiB compose costs about 27 tokens against a burst of 64: no 429
    assert 5 * 5 + 2 <= 64


def test_a_put_adds_a_session_bucket_entry(client):
    d = client.app.state.directory
    s, _w, b = upload("a")
    before = d.buckets.table
    assert put(client, s, b).status_code == 201
    assert len(d.buckets.table) > len(before)


def test_the_drop_notice_is_absent_with_drop_off(monkeypatch):
    from orch_relay.bridge import Bridge

    class D:  # the bridge only stores the directory here
        pass

    monkeypatch.setenv("ORCH_RELAY_DROP_NOTICE", "1")
    monkeypatch.setenv("ORCH_RELAY_DROP", "0")
    assert Bridge(D()).drop_notice is False
    monkeypatch.setenv("ORCH_RELAY_DROP", "1")
    assert Bridge(D()).drop_notice is True
    monkeypatch.setenv("ORCH_RELAY_DROP_NOTICE", "0")
    assert Bridge(D()).drop_notice is False


# --- Opus review round 2 ----------------------------------------------------------------------------


def revive(client, now):
    """Move the clock and keep sessions, certificates and the holder lease alive."""
    d = client.app.state.directory
    d.clock = lambda: now
    with closing(db.connect(path_of(client))) as con, con:
        con.execute("UPDATE sessions SET expires_ms=?", (now + 900_000,))
        con.execute("UPDATE devices SET expires_ms=?", (now + 30 * DAY,))
        con.execute("UPDATE holders SET lease_until_ms=?", (now + 40_000,))


def ws_bucket(client, ident=WS):
    return client.app.state.directory.buckets.table.get(("drop-up-workspace", ident))


def test_r1_every_eligible_request_spends_the_workspace_bucket(client):
    """Exact retries, step 6-9 refusals and the creations 429 cost the device's workspace bucket
    as soon as step 5 passed; nothing is refunded (R-D12's per-workspace bound)."""
    s, _w, b = upload("a")
    assert put(client, s, b).status_code == 201
    exhaust(client, **{"drop-up-workspace": (4, 1), "drop-up": (1000, 1000)})
    client.app.state.directory.buckets.clear()
    assert put(client, s, b).status_code == 200  # the exact retry: 1
    c, _w, cb = upload("c")
    assert put(client, c, cb, if_match="3").status_code == 409  # step 8 refusal: 2
    client.app.state.drop.quotas.dev_creations = 1  # the device already created "a" today
    assert put(client, c, cb).status_code == 429  # the creations 429 (step 9): 3
    assert put(client, s, b).status_code == 200  # 4
    r = put(client, s, b)  # the bucket is empty: even a retry that stores nothing is refused
    assert (r.status_code, r.json()) == (429, {"error": "rate_limited"})
    other, _w, ob = upload("o", author=LAPTOP)  # and so is another member's upload
    assert put(client, other, ob, author=LAPTOP).status_code == 429


def test_r1_an_ineligible_device_cannot_drain_a_workspace_bucket(client):
    from drop_support import WS_B

    exhaust(client, **{"drop-up-workspace": (4, 1)})
    foreign, _w, body = upload("f", space=WS_B)
    for _ in range(6):
        assert put(client, foreign, body).status_code == 403  # no write scope in WS_B
    assert ws_bucket(client, WS_B) is None and ws_bucket(client) is None


def test_r2_the_reservation_is_released_when_the_commit_returns(tmp_path):
    """A's commit landed but its response send is slow: B fits on the committed rows alone and
    must not get a false, non-transient quota_exceeded."""
    h = Harness(tmp_path)
    first, _w1, body1 = upload("a")
    second, _w2, body2 = upload("b", author=LAPTOP)
    h.drop.quotas.ws_blob = first["o"]["content_len"] + second["o"]["content_len"] + 10

    async def go():
        gate, reached = asyncio.Event(), asyncio.Event()

        class Slow(Peer):
            async def send(self, message):
                if message["type"] == "http.response.start":
                    reached.set()
                    await gate.wait()
                await super().send(message)

        peer = Slow(split(body1), then="end")
        o_id = first["o"]["object_id"]
        sc = tscope(
            "PUT", f"/v2/drop/{o_id}/versions", {"o": o_id}, author=DEVICE, length=len(body1)
        )
        one = asyncio.create_task(h.drop.endpoint(sc, peer.receive, peer.send, "put"))
        await asyncio.wait_for(reached.wait(), 10)
        assert h.drop.reserved.view() == {}  # committed, so no longer reserved
        b = await aput(h, body2, second, author=LAPTOP)
        gate.set()
        await one
        return b

    assert asyncio.run(go()).status == 201


@pytest.mark.parametrize(
    ("attr", "status", "who"),
    [("dev_blob", 429, DEVICE), ("account_blob", 429, LAPTOP), ("global_blob", 503, LAPTOP)],
)
def test_concurrent_uploads_are_bounded_on_the_device_account_and_global_keys(h, attr, status, who):
    """Reservations sit on every key a version charges, not only the workspace's."""
    first, _w1, body1 = upload("a")
    second, _w2, body2 = upload("b", author=who)
    setattr(h.drop.quotas, attr, first["o"]["content_len"] + 10)  # room for one, not two

    async def go():
        gate, reached = asyncio.Event(), asyncio.Event()

        async def hold(plan):
            reached.set()
            await gate.wait()

        h.drop.hooks["before_commit"] = hold
        one = asyncio.create_task(aput(h, body1, first))
        await reached.wait()
        refusal = await aput(h, body2, second, author=who)
        gate.set()
        return refusal, await one

    refusal, win = asyncio.run(go())
    assert (win.status, refusal.status) == (201, status)


def test_a_creations_refusal_comes_before_any_blob_byte(h):
    h.drop.quotas.dev_creations = 1
    first, _w, body1 = upload("a")
    assert asyncio.run(aput(h, body1, first)).status == 201
    second, _w, body2 = upload("b")
    head_end = 8 + int.from_bytes(body2[4:8], "big")
    # only the head arrives, then the client stalls: the refusal must not wait for the blob
    peer = asyncio.run(aput(h, body2, second, chunks=[body2[:head_end]], length=len(body2)))
    assert (peer.status, peer.json) == (429, {"error": "rate_limited", "quota": "drop_creations"})
    assert peer.read == head_end


def test_a_device_only_audience_counts_in_the_head_need():
    class Plan:
        o = {"content_len": 100}  # noqa: RUF012
        descriptor = "x" * 10
        wrap_texts = ("y" * 5,)

    Plan.devices = ()
    base = Q.Need.of(Plan, False).head
    Plan.devices = ("a", "b", "c")
    assert Q.Need.of(Plan, False).head == base + 3 * Q.AUDIENCE_ROW


def test_creations_follow_the_utc_midnight_boundary(client):
    drop = client.app.state.drop
    drop.quotas.dev_creations = 1
    midnight = (NOW // DAY + 1) * DAY
    revive(client, midnight - 1)
    s, _w, b = upload("a", now=midnight - 1)
    assert put(client, s, b).status_code == 201
    s, _w, b = upload("b", now=midnight - 1)
    assert put(client, s, b).status_code == 429  # still the old day
    revive(client, midnight)
    s, _w, b = upload("c", now=midnight)
    assert put(client, s, b).status_code == 201  # 00:00:00.000 is the new day
    days = sorted(
        r["day"] for r in rows(path_of(client), "drop_creations") if r["scope"] == "device"
    )
    assert days == [midnight // DAY - 1, midnight // DAY]


def test_creations_retry_after_and_day_come_from_the_requests_now(client):
    drop = client.app.state.drop
    drop.quotas.dev_creations = 1
    midnight = (NOW // DAY + 1) * DAY
    start = midnight - 5000
    revive(client, start)
    s, _w, b = upload("a", now=start)

    def hook(plan):  # a rival fills the request's day, and the commit runs after midnight
        with closing(db.connect(path_of(client))) as con, con:
            con.execute(
                "INSERT INTO drop_creations VALUES ('device',?,?,1)",
                (f"{WS}:{DEVICE}", start // DAY),
            )
        revive(client, midnight + 1000)

    drop.hooks["before_commit"] = hook
    r = put(client, s, b)
    assert r.status_code == 429 and r.json()["quota"] == "drop_creations"
    assert r.headers["retry-after"] == "5"  # from the request's now, not ~86,400 from the commit's


def test_r3_a_cost_above_the_burst_is_413_not_a_retry_after_that_never_comes(client):
    exhaust(client, **{"drop-up": (2, 1)})
    big = upload("big", content=b"\0" * (2 * 1024 * 1024 + 1), chunk=1 << 20)  # 3 started MiB
    r = put(client, big[0], big[2])
    assert (r.status_code, r.json()) == (413, {"error": "too_large"})
    assert "retry-after" not in r.headers


def test_r3_a_download_cost_is_clamped_to_the_burst(client):
    s, _w, b = upload("big", content=b"\0" * (2 * 1024 * 1024 + 1), chunk=1 << 20)
    assert put(client, s, b).status_code == 201
    exhaust(client, **{"drop-down": (2, 1), "drop-down-person": (2, 1)})  # the blob costs 3
    url = f"/v2/drop/{s['o']['object_id']}/versions/1/blob"
    assert client.get(url, headers={"Authorization": "Bearer " + TOKENS[DEVICE]}).status_code == 200


def test_r3_start_up_refuses_a_burst_below_a_maximal_body(client):
    drop = client.app.state.drop
    drop.check_buckets()  # the defaults hold the default 26 MiB cap
    d = client.app.state.directory
    for name, env in (
        ("drop-up", "ORCH_RELAY_THROTTLE_DROP_UP"),
        ("drop-up-workspace", "ORCH_RELAY_THROTTLE_DROP_UP_WORKSPACE"),
        ("drop-down", "ORCH_RELAY_THROTTLE_DROP_DOWN"),
        ("drop-down-person", "ORCH_RELAY_THROTTLE_DROP_DOWN_PERSON"),
    ):
        saved = d.throttles
        d.throttles = {**saved, name: (20, 20)}  # a 26 MiB blob needs 26 tokens (27 with the frame)
        with pytest.raises(ValueError, match=env):
            drop.check_buckets()
        d.throttles = saved
    drop.max_blob = 100 * 1024 * 1024  # a larger blob cap than drop-up's 64 burst allows
    drop.max_body = 8 + 512 * 1024 + drop.max_blob
    with pytest.raises(ValueError, match="ORCH_RELAY_THROTTLE_DROP_UP"):
        drop.check_buckets()


def test_start_up_checks_the_buckets_only_with_drop_on(tmp_path, monkeypatch):
    monkeypatch.setenv("ORCH_RELAY_THROTTLE_DROP_UP", "10/10")
    monkeypatch.setenv("ORCH_RELAY_DROP", "0")
    create_app(tmp_path / "off")  # off: nothing of Drop runs
    monkeypatch.setenv("ORCH_RELAY_DROP", "1")
    with pytest.raises(ValueError, match="ORCH_RELAY_THROTTLE_DROP_UP"):
        create_app(tmp_path / "on")


def test_the_global_cap_variables_are_parsed_only_with_drop_on(client):
    from orch_relay.drop import Drop

    app = client.app
    bad = {"ORCH_RELAY_DROP_GLOBAL_BYTES": "x"}
    Drop(
        app.state.directory,
        app.state.bridge,
        app.state.data_dir,
        env={**bad, "ORCH_RELAY_DROP": "0"},
    )
    with pytest.raises(ValueError):
        Drop(
            app.state.directory,
            app.state.bridge,
            app.state.data_dir,
            env={**bad, "ORCH_RELAY_DROP": "1"},
        )


def test_a_download_over_one_mib_costs_two_tokens(client):
    s, _w, b = upload("big", content=b"\0" * (1024 * 1024 + 1), chunk=1 << 20)
    assert put(client, s, b).status_code == 201
    exhaust(client, **{"drop-down": (3, 1)})
    client.app.state.directory.buckets.clear()
    url = f"/v2/drop/{s['o']['object_id']}/versions/1/blob"
    auth = {"Authorization": "Bearer " + TOKENS[DEVICE]}
    assert (
        client.get(url, headers=auth).status_code == 200
    )  # 2 of 3 tokens (a 1 MiB + 1 B blob + header)
    assert client.get(url, headers=auth).status_code == 429  # 1 left: a floored cost would pass
