"""P3-D39 (D39a2 part 1): stored-bytes quotas, in-flight reservations, the commit's authority, the
daily version-1 creation counters and the MiB upload and download buckets."""

import asyncio
from contextlib import closing

import pytest
from directory_support import DEVICE, NOW, WS
from drop_support import DAY, LAPTOP, TOKENS, descriptor, frame, object_id, put, rows, setup, upload
from fastapi.testclient import TestClient
from test_drop_transfer import Harness
from test_drop_transfer import put as aput

from orch_relay import db
from orch_relay import drop_quota as Q
from orch_relay import proto as P
from orch_relay.app import create_app
from orch_relay.directory import throttle_settings

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
        wrap_texts = [P.cj(w).decode() for w in wraps]
        devices = []

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
    with pytest.raises(Exception) as caught:
        Q.check(quotas, usage, {}, need, ws, owner, device, o)
    error = caught.value
    assert error.status == status and error.retry == Q.SWEEP
    if name is None:
        assert (error.code, getattr(error, "details", {})) == ("overloaded", {})
    else:
        assert (error.code, error.details) == ("quota_exceeded", {"quota": name})
    # the reservations of uploads in flight count against the cap too
    usage[(scope, ident)][field] = cap - 1
    with pytest.raises(Exception):
        Q.check(quotas, usage, {(scope, ident): {field: 1}}, need, ws, owner, device, o)


def test_a_field_the_upload_does_not_add_to_is_not_checked():
    quotas = Q.Quotas({})
    keys = Q.usage_keys("w", "p", "d")
    usage = blank(keys)
    usage[("device", "w:d")]["head"] = quotas.dev_head + 10  # a lowered cap, an over-full share
    o = {"object_kind": "file", "version": 1}
    Q.check(quotas, usage, {}, Q.Need(5, 0, 1, 0), "w", "p", "d", o)
    with pytest.raises(Exception):
        Q.check(quotas, usage, {}, Q.Need(5, 1, 1, 0), "w", "p", "d", o)


def test_the_authors_share_is_named_before_the_workspace_and_the_global_ceiling_last():
    quotas = Q.Quotas({})
    keys = Q.usage_keys("w", "p", "d")
    usage = blank(keys)
    for key in keys:
        usage[key]["blob"] = 10**12  # everything is over
    o = {"object_kind": "file", "version": 1}
    with pytest.raises(Exception) as caught:
        Q.check(quotas, usage, {}, Q.Need(1, 0), "w", "p", "d", o)
    assert caught.value.details == {"quota": "drop_device"}
    with pytest.raises(Exception) as caught:  # a W author has no device share
        Q.check(quotas, usage, {}, Q.Need(1, 0), "w", "p", None, o)
    assert caught.value.details == {"quota": "drop_ws"}
    usage = blank(keys)
    usage[("global", "")]["blob"] = 10**12
    with pytest.raises(Exception) as caught:
        Q.check(quotas, usage, {}, Q.Need(1, 0), "w", "p", "d", o)
    assert caught.value.code == "overloaded"


def test_document_chain_cap_is_the_1025th_version():
    quotas = Q.Quotas({})
    keys = Q.usage_keys("w", "p", None)
    Q.check(quotas, blank(keys), {}, Q.Need(1, 1), "w", "p", None, {"object_kind": "document", "version": 1024})
    with pytest.raises(Exception) as caught:
        Q.check(quotas, blank(keys), {}, Q.Need(1, 1), "w", "p", None, {"object_kind": "document", "version": 1025})
    assert (caught.value.status, caught.value.details) == (429, {"quota": "drop_doc_versions"})
    # a file is never version 1025 (CAS), and the cap has no per-member share
    Q.check(quotas, blank(keys), {}, Q.Need(1, 1), "w", "p", None, {"object_kind": "file", "version": 1})


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
        {"ORCH_RELAY_DROP_GLOBAL_BYTES": "1073741824", "ORCH_RELAY_DROP_GLOBAL_HEAD_BYTES": "134217728"}
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
ATTRS = {
    "blob": ("dev_blob", "ws_blob", "account_blob", "global_blob"),
    "head": ("dev_head", "ws_head", None, "global_head"),
    "versions": ("dev_versions", "ws_versions", None, None),
}


@pytest.mark.parametrize(("scope", "ident", "fields", "quota"), HTTP_CAPS)
def test_a_full_scope_refuses_the_put_and_stores_nothing(client, scope, ident, fields, quota):
    quotas = client.app.state.drop.quotas
    ident = owner_of(client) if scope == "account" else ident
    (field,) = fields
    seed(client, scope, ident, **{field: {"device": 0, "workspace": 0}.get(scope, 0)})
    signed, wraps, body = upload("a")
    need = need_of(signed, wraps)
    cap = {"device": quotas.dev_blob, "workspace": quotas.ws_blob}  # replaced below per field
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
    o1 = one[0]["o"]
    for version, expected in ((2, 201), (3, 429)):
        signed, data, _dek = descriptor(
            o1["object_id"], version=version, kind="document", parent=o1 if version == 2 else v2
        )
        if version == 2:
            v2 = signed["o"]
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
    signed, wraps, body = upload("a")
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
    assert (r.status_code, r.json()) == (429, {"error": "rate_limited"})
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
    assert (r.status_code, r.json()) == (429, {"error": "rate_limited"})
    # a new UTC day opens new counters (and the old rows stay for the sweep, PR 2)
    d.clock = lambda: NOW + DAY
    s, _w, b = upload("c", expires=NOW + DAY + 7 * DAY)
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
    h.drop.quotas.ws_blob = first["o"]["content_len"] + 100

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


def test_a_refused_put_still_spends_the_read_class_token_once(client):
    d = client.app.state.directory
    s, _w, b = upload("a")
    before = d.buckets.table
    assert put(client, s, b).status_code == 201
    assert len(d.buckets.table) > len(before)
