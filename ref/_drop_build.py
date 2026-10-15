"""P3-D39 (D39a1) builders shared by the `drop.upload_frame`/`drop.relay_put` vectors and the Drop HTTP
fixtures: signed descriptors, real wraps and ORD2 blobs from the vector keys (public FAKE material)."""
from ref import drop_relay as M
from ref import orch_protocol_ref as R

S = R.SUITES[2]
NOW = 1790000000000
DAY = M.DAY
WK = {1: R.fake("drop test WK epoch 1"), 2: R.fake("drop test WK epoch 2")}


class Builder:
    def __init__(self, v):
        self.v = v
        ids = v["ids"]
        self.ws, self.phone, self.laptop = ids["workspace_a"], ids["device_phone"], ids["device_laptop"]
        self.primary, self.agent, self.ws_b = ids["device_primary"], ids["device_agent"], ids["workspace_b"]
        self.signers = {self.phone: "phone", self.laptop: "laptop", self.ws: "wsk_a", self.primary: "primary"}
        self.kx = {self.phone: "phone", self.laptop: "laptop"}

    def key(self, name):
        return S.sig_key(bytes.fromhex(self.v["keys"][name + ".sig"]["seed"]))

    def kx_pub(self, name):
        return bytes.fromhex(self.v["keys"][name]["pub"])

    @staticmethod
    def oid(label):
        return R.fake("drop object " + label)[:16].hex()

    @staticmethod
    def blob(o_id, version, content, chunk=512):
        dek = R.fake(f"dek {o_id} {version}")
        prefix = R.fake(f"prefix {o_id} {version}")[:8]
        return R.drop_encrypt(S, dek, bytes.fromhex(o_id), version, content, prefix, chunk), dek

    def descriptor(self, o_id, author=None, version=1, kind="file", recipients=None, parent=None,
                   content=b"orch drop test content", expires=None, space=None, now=NOW, sign_as=None,
                   **over):
        author = author or self.phone
        space = space or self.ws
        data, dek = self.blob(o_id, version, content)
        meta = R.drop_meta_seal(S, dek, bytes.fromhex(o_id), version, {"name": "f.txt"})
        if expires is None and kind == "file":
            expires = now + 7 * DAY
        o = {"v": 2, "suite": 2, "kind": "drop_object", "object_id": o_id, "space_id": space,
             "space_kind": "workspace", "object_kind": kind, "version": version, "parent": version - 1,
             "parent_hash": None if parent is None else R.b64u(R.drop_parent_hash(parent)),
             "author_kind": "workspace" if author == self.ws else "device", "author_id": author,
             "content_hash": R.b64u(R.H(data)), "content_len": len(data),
             "dek_commit": R.b64u(R.dek_commit(bytes.fromhex(o_id), version, dek)), "meta": R.b64u(meta),
             "recipients": [space] if recipients is None else recipients, "origin": "human",
             "created_ms": now, "expires_ms": expires}
        o.update(over)
        return R.sign_object(S, self.key(sign_as or self.signers.get(author, "phone")), o), data

    def wrap(self, o, kind, target=None, key_version=None):
        o_id, ver = bytes.fromhex(o["object_id"]), o["version"]
        dek = R.fake(f"dek {o['object_id']} {ver}")
        if kind == "wk":
            kv = 1 if key_version is None else key_version
            return R.wrap_dek(S, "wk", bytes.fromhex(target or o["space_id"]), kv, o_id, ver, dek, wk=WK.get(kv, WK[1]),
                              salt=R.fake(f"salt {o['object_id']} {kv}")[:16])
        if kind == "wxk":
            kv = 1 if key_version is None else key_version
            return R.wrap_dek(S, "wxk", bytes.fromhex(target or o["space_id"]), kv, o_id, ver, dek,
                              kx_pub=self.kx_pub("wxk_a_1.kx"), eph_seed=R.fake(f"eph wxk {o['object_id']}"))
        target = target or o["author_id"]
        return R.wrap_dek(S, "device", bytes.fromhex(target), 0 if key_version is None else key_version, o_id, ver,
                          dek, kx_pub=self.kx_pub(self.kx.get(target, "phone") + ".kx"),
                          eph_seed=R.fake(f"eph device {o['object_id']} {target}"))

    def default_wraps(self, o):
        if o["recipients"] == "inbox":
            return [self.wrap(o, "wxk")]
        if o["author_kind"] == "device" or o["space_id"] in o["recipients"]:
            return [self.wrap(o, "wk")]
        return [self.wrap(o, "device", t) for t in o["recipients"]]

    def upload(self, label, wraps=None, data=None, **kw):
        """(signed, frame bytes) for one upload."""
        o_id = label if len(label) == 32 else self.oid(label)
        signed, blob = self.descriptor(o_id, **kw)
        wraps = self.default_wraps(signed["o"]) if wraps is None else wraps(signed["o"])
        return signed, M.frame({"descriptor": signed, "wraps": wraps}, blob if data is None else data(blob))

    def principal(self, who):
        return {"kind": "workspace" if who == self.ws else "device", "id": who}
