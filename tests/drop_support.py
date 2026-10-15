"""P3-D39 (D39a1) test material: signed descriptors, real wraps and ORD2 blobs from the reference,
the ODU2 frame, and the seeded workspace (vector keys and ids, public FAKE material only)."""

from contextlib import closing

from directory_support import DEVICE, NOW, PERSON, WS, V, seed, signed

from orch_relay import db
from orch_relay import proto as P
from orch_relay.directory import token_hash
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
SIGNERS = {DEVICE: "phone.sig", LAPTOP: "laptop.sig", WS: "wsk_a.sig"}
TOKENS = {DEVICE: "FAKE-device", LAPTOP: "FAKE-laptop", WS: "FAKE-workspace", AGENT: "FAKE-agent"}
FULL = ["look", "decide", "operate", "type"]
DAY = 86_400_000


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
    **over,
):
    """A signed descriptor and its blob. `parent` is the parent version's descriptor o."""
    data, dek = blob(o_id, version, content)
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
