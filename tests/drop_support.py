"""P3-D39 (D39a1) test material: signed descriptors, real wraps and ORD2 blobs from the reference,
the ODU2 frame, and the seeded workspace (vector keys and ids, public FAKE material only)."""

from contextlib import closing

from directory_support import DEVICE, NOW, PERSON, WS, V, seed, signed

from orch_relay import db
from orch_relay import proto as P
from orch_relay.directory import token_hash
from ref.drop_relay import GENERATION
from ref import orch_protocol_ref as R

S = R.SUITES[2]
LAPTOP = V["ids"]["device_laptop"]
PRIMARY = V["ids"]["device_primary"]
AGENT = V["ids"]["device_agent"]
WS_B = V["ids"]["workspace_b"]
WK = {1: R.fake("drop test WK epoch 1"), 2: R.fake("drop test WK epoch 2")}
KX = {
    "wxk": bytes.fromhex(V["keys"]["wxk_a_1.kx"]["pub"]),
    DEVICE: bytes.fromhex(V["keys"]["phone.kx"]["pub"]),
    LAPTOP: bytes.fromhex(V["keys"]["laptop.kx"]["pub"]),
}
SIGNERS = {DEVICE: "phone.sig", LAPTOP: "laptop.sig", WS: "wsk_a.sig", PRIMARY: "primary.sig"}
TOKENS = {DEVICE: "FAKE-device", LAPTOP: "FAKE-laptop", WS: "FAKE-workspace", AGENT: "FAKE-agent"}
FULL = ["look", "decide", "operate", "type"]
DAY = 86_400_000


def sync_counter(con):
    """A position is never above the counter: tests that set `drop_objects.n` by hand keep the
    relay-wide counter at or above the newest one (D39a2 part 4: lists are cut at the counter)."""
    con.execute("UPDATE drop_counter SET n=max(n, (SELECT coalesce(max(n), 0) FROM drop_objects))")


def object_id(label):
    return R.fake("drop object " + label)[:16].hex()


def setup(d, now=NOW, laptop_scopes=FULL):
    """The vector workspace: the phone and the laptop members with `operate`, list epoch 1,
    card wxk_version 1, holder generation 1; sessions for both devices, the W session and the
    `drop:` scoped agent (registered, never a member)."""
    seed(d)
    d.clock = lambda: now
    with closing(db.connect(d.path)) as con, con:
        con.execute("UPDATE members SET scopes=?", (P.cj(FULL),))
        con.execute(
            "INSERT INTO members VALUES (?,?,?,?)", (WS, LAPTOP, PERSON, P.cj(laptop_scopes))
        )
        con.execute("INSERT INTO ever_devices VALUES (?,?,?)", (WS, LAPTOP, 1))
        d.store_device(con, V["certs"]["signed"]["agent"])
        con.execute("UPDATE holders SET lease_until_ms=?", (now + 40_000,))
        con.execute("UPDATE sessions SET expires_ms=?", (now + 900_000,))
        for ident in (LAPTOP, AGENT):
            con.execute(
                "INSERT INTO sessions VALUES (?,?,?,?)",
                (token_hash(TOKENS[ident]), "device", ident, now + 900_000),
            )


def blob(o_id, version, content=b"orch drop test content", chunk=512, dek=None):
    dek = dek or R.fake(f"dek {o_id} {version}")
    prefix = R.fake(f"prefix {o_id} {version}")[:8]
    return R.drop_encrypt(S, dek, bytes.fromhex(o_id), version, content, prefix, chunk), dek


def descriptor(
    o_id,
    author=DEVICE,
    version=1,
    kind="file",
    recipients=None,
    parent=None,
    content=b"orch drop test content",
    now=NOW,
    expires=None,
    space=WS,
    chunk=512,
    **over,
):
    """A signed descriptor and its blob. `parent` is the parent version's descriptor o."""
    data, dek = blob(o_id, version, content, chunk)
    meta = R.drop_meta_seal(S, dek, bytes.fromhex(o_id), version, {"name": "f.txt"})
    if expires is None:
        expires = now + 7 * DAY if kind == "file" else None
    o = {
        "v": 2,
        "suite": 2,
        "kind": "drop_object",
        "object_id": o_id,
        "space_id": space,
        "space_kind": "workspace",
        "object_kind": kind,
        "version": version,
        "parent": version - 1,
        "parent_hash": None if parent is None else R.b64u(R.drop_parent_hash(parent)),
        "author_kind": "workspace" if author == WS else "device",
        "author_id": author,
        "content_hash": R.b64u(R.H(data)),
        "content_len": len(data),
        "dek_commit": R.b64u(R.dek_commit(bytes.fromhex(o_id), version, dek)),
        "meta": R.b64u(meta),
        "recipients": [space] if recipients is None else recipients,
        "origin": "human",
        "created_ms": now,
        "expires_ms": expires,
    }
    o.update(over)
    return signed(o, SIGNERS.get(author, "phone.sig")), data, dek


def wrap(o, kind, target=None, key_version=None, dek=None):
    o_id, version = bytes.fromhex(o["object_id"]), o["version"]
    dek = dek or R.fake(f"dek {o['object_id']} {version}")
    if kind == "wk":
        kv = 1 if key_version is None else key_version
        return R.wrap_dek(
            S,
            "wk",
            bytes.fromhex(target or o["space_id"]),
            kv,
            o_id,
            version,
            dek,
            wk=WK.get(kv, WK[1]),
            salt=R.fake(f"salt {o['object_id']} {kv}")[:16],
        )
    if kind == "wxk":
        kv = 1 if key_version is None else key_version
        return R.wrap_dek(
            S,
            "wxk",
            bytes.fromhex(target or o["space_id"]),
            kv,
            o_id,
            version,
            dek,
            kx_pub=KX["wxk"],
            eph_seed=R.fake(f"eph wxk {o['object_id']}"),
        )
    target = target or o["author_id"]
    return R.wrap_dek(
        S,
        "device",
        bytes.fromhex(target),
        0 if key_version is None else key_version,
        o_id,
        version,
        dek,
        kx_pub=KX.get(target, KX[DEVICE]),
        eph_seed=R.fake(f"eph device {o['object_id']} {target}"),
    )


def default_wraps(o):
    if o["recipients"] == "inbox":
        return [wrap(o, "wxk")]
    if o["author_kind"] == "device" or o["space_id"] in o["recipients"]:
        return [wrap(o, "wk")]
    return [wrap(o, "device", target) for target in o["recipients"]]


def frame(signed_, wraps, data):
    head = P.cj({"descriptor": signed_, "wraps": wraps})
    return b"ODU2" + len(head).to_bytes(4, "big") + head + data


def upload(o_id="a", **kw):
    """(signed, wraps, body) for one upload; `wraps` may be passed explicitly."""
    wraps = kw.pop("wraps", None)
    signed_, data, _dek = descriptor(object_id(o_id) if len(o_id) != 32 else o_id, **kw)
    wraps = default_wraps(signed_["o"]) if wraps is None else wraps
    return signed_, wraps, frame(signed_, wraps, data)


def headers(author=DEVICE, if_match="0", holder="1", **extra):
    h = {"Authorization": "Bearer " + TOKENS[author], "Content-Type": "application/octet-stream"}
    if if_match is not None:
        h["If-Match"] = if_match
    if author == WS and holder is not None:
        h["Orch-Holder"] = holder
    h.update(extra)
    return h


def put(client, signed_, body, author=None, **kw):
    author = author or signed_["o"]["author_id"]
    return client.put(
        f"/v2/drop/{signed_['o']['object_id']}/versions",
        content=body,
        headers=headers(author, **kw),
    )


def rows(path, table):
    with closing(db.connect(path)) as con:
        con.row_factory = __import__("sqlite3").Row
        return con.execute(f"SELECT * FROM {table}").fetchall()


def usage(path):
    with closing(db.connect(path)) as con:
        return {
            (r[0], r[1]): tuple(r[2:]) for r in con.execute("SELECT * FROM drop_usage").fetchall()
        }


def apply_op(d, op):
    """The production side of ref/drop_relay.apply: state changes without a D39a1 route (the
    D39a2 retire and sweeps, the D39b claim), a clock move and a new member-list epoch."""
    kind = op["op"]
    if kind == "clock":
        d.clock = lambda: op["now_ms"]
        return
    with closing(db.connect(d.path)) as con, con:
        if kind == "epoch":
            seq = con.execute("SELECT coalesce(max(list_seq),0)+1 FROM member_lists").fetchone()[0]
            con.execute("INSERT INTO member_lists VALUES (?,?,?,'{}')", (WS, seq, op["epoch"]))
            return
        if kind == "scopes":  # a member device's scopes change (a phone: look and decide)
            con.execute(
                "UPDATE members SET scopes=? WHERE device_id=?",
                (P.cj(op["scopes"]), op["device"]),
            )
            return
        if kind == "rotation_due":  # a revocation's rotation is open: wk wraps are refused
            con.execute("INSERT INTO rotation_due VALUES (?,?,?,?)", (WS, LAPTOP, 5, 1))
            return
        o_id = op["object_id"]
        con.execute("UPDATE drop_counter SET n=n+1")
        n = con.execute("SELECT n FROM drop_counter").fetchone()[0]
        if kind == "foreign_object":
            con.execute(
                "INSERT INTO drop_objects VALUES (?,?,?,'file',1,0,NULL,?,NULL,NULL,?,?,'space',?,?,NULL)",
                (
                    o_id,
                    op["workspace_id"],
                    PERSON,
                    d.clock() + DAY,
                    op["workspace_id"],
                    "x" * 43,
                    n,
                    d.clock(),
                ),
            )
            return
        con.execute("UPDATE drop_objects SET n=? WHERE object_id=?", (n, o_id))
        if kind in ("retire", "expire_sweep"):
            if kind == "retire":
                con.execute(
                    "UPDATE drop_objects SET tombstone_ms=?, tombstone_kind='retired' "
                    "WHERE object_id=?",
                    (d.clock(), o_id),
                )
            else:
                con.execute(
                    "UPDATE drop_objects SET tombstone_ms=expires_ms, tombstone_kind='expired' "
                    "WHERE object_id=?",
                    (o_id,),
                )
                con.execute("DELETE FROM drop_audience WHERE object_id=?", (o_id,))
            con.execute("DELETE FROM drop_versions WHERE object_id=?", (o_id,))
        elif kind == "claim":
            con.execute(
                "UPDATE drop_objects SET claimed_by=?, claimed_ms=? WHERE object_id=?",
                (op["workspace_id"], d.clock(), o_id),
            )
        elif kind == "prune":
            con.execute(
                "DELETE FROM drop_wraps WHERE object_id=? AND version=(SELECT current FROM "
                "drop_objects WHERE object_id=?)",
                (o_id, o_id),
            )
            con.execute(
                "UPDATE drop_versions SET blob='pruned', blob_path=NULL WHERE object_id=? AND "
                "version=(SELECT current FROM drop_objects WHERE object_id=?)",
                (o_id, o_id),
            )
        else:
            raise ValueError(kind)


def token_for(principal):
    return TOKENS[principal["id"]]


def send_step(client, step):
    """One `put` step of a `drop` vector over HTTP."""
    if "body_recipe" in step:
        r = step["body_recipe"]
        body = (
            bytes.fromhex(r["prefix_hex"])
            + bytes([r["byte"]]) * r["count"]
            + bytes.fromhex(r["suffix_hex"])
        )
    else:
        body = bytes.fromhex(step["body_hex"])
    h = {"Authorization": "Bearer " + token_for(step["principal"])}
    if step["if_match"] is not None:
        h["If-Match"] = step["if_match"]
    if step.get("holder") is not None:
        h["Orch-Holder"] = step["holder"]
    if "content_length" in step:
        h["Content-Length"] = str(step["content_length"])
    return client.put(f"/v2/drop/{step['object_id']}/versions", content=body, headers=h)


def send_request(client, request):
    kwargs = {"headers": request["headers"], "params": request["query"]}
    if "body_hex" in request:
        kwargs["content"] = bytes.fromhex(request["body_hex"])
    if "json" in request:
        kwargs["content"] = P.cj(request["json"])
    return client.request(request["method"], request["path"], **kwargs)


def prepare_fixture(client, case):
    """A Drop HTTP fixture's preconditions (tests/http_fixtures/README.md): the seeded workspace,
    `given.prior` requests, `given.ops` and `given.relay` conditions."""
    d, drop = client.app.state.directory, client.app.state.drop
    setup(d)
    drop.state.generation = GENERATION  # the fixtures' relay generation (a real one is random)
    given = case["given"]
    for prior in given.get("prior", []):
        r = send_request(client, prior)
        assert r.status_code in (200, 201), (prior["path"], r.text)
    for op in given.get("ops", []):
        apply_op(d, op)
    relay = given.get("relay", {})
    token = case["request"]["headers"].get("Authorization", "")[7:]
    ident = next((k for k, t in TOKENS.items() if t == token), None)
    with closing(db.connect(d.path)) as con, con:
        if relay.get("device") == "drop_scoped":
            con.execute(
                "UPDATE devices SET scopes_max=? WHERE device_id=?", (P.cj([f"drop:{WS}"]), ident)
            )
        elif relay.get("device") == "cert_expired":
            con.execute("UPDATE devices SET expires_ms=? WHERE device_id=?", (d.clock(), ident))
        elif relay.get("device") == "revoked":
            con.execute(
                "INSERT INTO revocations VALUES (?,?,?,?,?,?)",
                (ident, PERSON, P.cj(V["revocations"][0]["signed"]), "lost", d.clock(), 1),
            )
    for kind, slots in (
        ("upload_slots", drop.uploads),
        ("read_slots", drop.reads),
        ("download_slots", drop.downloads),
    ):
        if relay.get(kind) == "device":
            slots.used[("device", ident)] = slots.caps["device"]
        elif relay.get(kind) == "relay":
            slots.count = slots.total
    if (
        "usage" in relay
        or "creations" in relay
        or "decide_budget" in relay
        or relay.get("bucket") == "drop_up_empty"
    ):
        production_conditions(client, relay, ident)
    if relay.get("bucket") == "empty":
        d.throttles = {**d.throttles, "session": (1, 1)}
        d.buckets.take(("session", ("device", ident)), 1, 1, d.clock())


def production_conditions(client, relay, ident):
    """D39a2 relay conditions: a usage scope at its cap, a full daily creation counter, an empty
    upload bucket (the fixture README names them)."""
    d, drop = client.app.state.directory, client.app.state.drop
    q = drop.quotas
    if relay.get("bucket") == "drop_up_empty":
        d.throttles = {**d.throttles, "drop-up": (1, 1)}
        d.buckets.take(("drop-up", ident), 1, 1, d.clock())
    with closing(db.connect(d.path)) as con, con:
        if "usage" in relay:
            scope, field = relay["usage"]["scope"], relay["usage"]["field"]
            owner = con.execute("SELECT owner_person_id FROM workspaces").fetchone()[0]
            key = {"device": f"{WS}:{ident}", "workspace": WS, "account": owner, "global": ""}[
                scope
            ]
            cap = {
                ("device", "blob"): q.dev_blob,
                ("workspace", "blob"): q.ws_blob,
                ("workspace", "head"): q.ws_head,
                ("account", "blob"): q.account_blob,
                ("global", "blob"): q.global_blob,
            }[(scope, field)]
            values = {"blob": 0, "head": 0}
            values[field] = cap
            con.execute(
                "INSERT INTO drop_usage VALUES (?,?,?,?,0,0) ON CONFLICT(scope,id) DO UPDATE SET "
                "blob_bytes=excluded.blob_bytes, head_bytes=excluded.head_bytes",
                (scope, key, values["blob"], values["head"]),
            )
        if relay.get("decide_budget") in ("creations_full", "bytes_full"):
            full = relay["decide_budget"] == "creations_full"
            con.execute(
                "INSERT INTO drop_decide_budget VALUES (?,?,?,?,?)",
                (
                    WS,
                    ident,
                    d.clock() // DAY,
                    q.decide_creations if full else 0,
                    0 if full else q.decide_bytes,
                ),
            )
        if relay.get("creations") == "device_full":
            con.execute(
                "INSERT INTO drop_creations VALUES ('device', ?, ?, ?)",
                (f"{WS}:{ident}", d.clock() // DAY, q.dev_creations),
            )
