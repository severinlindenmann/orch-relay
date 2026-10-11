"""Small suite-2 clients. All bridge bodies are signed and AEAD encrypted.

The stub implements known-certificate pairing and a status operation; it is not an
orch host. The shared offer secret and signing keys model out-of-band provisioning.
"""

import secrets

from bridge_support import HOST
from directory_support import CERT, DEVICE, NOW, PERSON, PK, RECORD, WS, V, issue_login, signed

from orch_relay import proto as P
from ref import orch_protocol_ref as R

SUITE = R.SUITES[2]
WS_BYTES, DEVICE_BYTES = bytes.fromhex(WS), bytes.fromhex(DEVICE)
OFFER = bytes.fromhex("32" * 16)
SECRET = bytes.fromhex("43" * 32)
WK = bytes.fromhex("54" * 32)
SAS_NONCE = bytes.fromhex("65" * 32)
WSK = P.b64u(bytes.fromhex(V["keys"]["wsk_a.sig"]["pub"]))


def private(name):
    return SUITE.sig_key(bytes.fromhex(V["keys"][name]["seed"]))


def seal(direction, rid, key, meta, *, pair=False):
    h = R.Header(
        direction,
        0 if direction == 1 else R.F_LAST,
        2,
        WS_BYTES,
        DEVICE_BYTES,
        rid,
        OFFER if pair else bytes(16),
        0,
        NOW,
        0 if pair else 1,
        secrets.token_bytes(16),
    )
    return R.envelope(
        SUITE, key, private("phone.sig" if direction == 1 else "wsk_a.sig"), h, R.frame(meta)
    )


def open_message(raw, key, from_host=False):
    header, body, signature = R.split(raw)
    pub = bytes.fromhex(V["keys"]["wsk_a.sig" if from_host else "phone.sig"]["pub"])
    assert SUITE.verify(pub, signature, R.bridge_signed(header, body))
    meta, data = R.unframe(R.open_body(key, header, body))
    assert not data
    return meta


class DeviceClient:
    def __init__(self, client):
        self.client = client
        self.headers = {}
        self.bridge_key = None

    def pair_request(self):
        self.pair_rid = secrets.token_bytes(16)
        self.pair_key = R.k_pair(SECRET, WS_BYTES, OFFER)
        raw = seal(
            1,
            self.pair_rid,
            self.pair_key,
            {
                "op": "pair",
                "cert": CERT,
                "dk_sig_pub": CERT["o"]["dk_sig_pub"],
                "dk_kx_pub": CERT["o"]["dk_kx_pub"],
                "label": "Test phone",
            },
            pair=True,
        )
        path = f"/v2/workspaces/{WS}/pair/{OFFER.hex()}/{self.pair_rid.hex()}"
        assert (
            self.client.post(
                path, content=raw, headers={"Content-Type": "application/octet-stream"}
            ).status_code
            == 202
        )
        return path

    def pair_answer(self, path):
        raw = P.unb64u(self.client.get(path).json()["chunks"][0]["envelope"])
        ctx = {
            "suite": 2,
            "workspace": WS,
            "device": DEVICE,
            "offer": OFFER.hex(),
            "secret": SECRET.hex(),
            "wsk_pin": R.wsk_pin(SUITE, P.unb64u(WSK)).hex(),
            "pk_pin": R.pk_pin(SUITE, P.unb64u(PK)).hex(),
            "dk_sig_pub": CERT["o"]["dk_sig_pub"],
            "dk_kx_pub": CERT["o"]["dk_kx_pub"],
            "pending": {self.pair_rid.hex(): {"next": 0}},
            "offset_ms": 0,
        }
        answer = R.open_pair_answer(raw, ctx, NOW)
        assert answer["result"] == "accept", answer
        return answer

    def pair_status(self):
        self.pair_rid = secrets.token_bytes(16)
        raw = seal(1, self.pair_rid, self.pair_key, {"op": "pair_status"}, pair=True)
        path = f"/v2/workspaces/{WS}/pair/{OFFER.hex()}/{self.pair_rid.hex()}"
        assert (
            self.client.post(
                path, content=raw, headers={"Content-Type": "application/octet-stream"}
            ).status_code
            == 202
        )
        return path

    def finish_pair(self, path):
        assert self.pair_answer(path)["state"] == "approved"
        login = issue_login(self.client)
        assert login.status_code == 200
        self.headers = {
            "Authorization": "Bearer " + login.json()["token"],
            "Content-Type": "application/octet-stream",
        }
        grants = self.client.get(f"/v2/workspaces/{WS}/grants", headers=self.headers).json()[
            "grants"
        ]
        private_kx = SUITE.kx_key(bytes.fromhex(V["keys"]["phone.kx"]["seed"]))
        opened = R.open_wk_grant(
            SUITE, P.unb64u(WSK), grants[0], WS_BYTES, DEVICE_BYTES, private_kx
        )
        assert "ok" in opened, opened
        self.bridge_key = R.k_bridge(
            bytes.fromhex(opened["ok"]["wk"]), WS_BYTES, opened["ok"]["epoch"]
        )

    def request(self):
        rid = secrets.token_bytes(16)
        return rid, seal(1, rid, self.bridge_key, {"op": "status"})

    def send(self, rid, raw):
        return self.client.post(
            f"/v2/workspaces/{WS}/bridge/{rid.hex()}", content=raw, headers=self.headers
        )

    def response(self, rid):
        r = self.client.get(f"/v2/workspaces/{WS}/bridge/{rid.hex()}", headers=self.headers)
        assert r.status_code == 200
        return open_message(P.unb64u(r.json()["chunks"][0]["envelope"]), self.bridge_key, True)


class HostStub:
    def __init__(self, client):
        self.client, self.cursor, self.results = client, 0, {}

    def poll(self):
        r = self.client.get(
            f"/v2/workspaces/{WS}/host/poll", headers=HOST, params={"after": self.cursor}
        )
        assert r.status_code == 200, r.text
        return r.json()["items"]

    def process(self, item):
        raw = P.unb64u(item["envelope"])
        pair = item["route"] == "pair"
        key = R.k_pair(SECRET, WS_BYTES, OFFER) if pair else R.k_bridge(WK, WS_BYTES, 1)
        message = open_message(raw, key)
        if pair:
            if message["op"] == "pair":
                assert message["cert"] == CERT
                assert P.verify_cert(CERT, P.unb64u(PK), NOW).get("ok")
                answer = {
                    "state": "pending",
                    "wsk_pub": WSK,
                    "sas_nonce": P.b64u(SAS_NONCE),
                    "dk_sig_pub": CERT["o"]["dk_sig_pub"],
                    "dk_kx_pub": CERT["o"]["dk_kx_pub"],
                }
            else:
                assert message == {"op": "pair_status"}
                answer = {
                    "state": "approved",
                    "scopes": ["look"],
                    "cert": CERT,
                    "pk_pub": PK,
                    "epoch": 1,
                    "wsk_pub": WSK,
                }
        else:
            assert message == {"op": "status"}
            answer = {"status": "ready"}
        rid = item["rid"]
        if rid not in self.results:
            self.results[rid] = seal(2, bytes.fromhex(rid), key, answer, pair=pair)
        route = f"pair/{OFFER.hex()}" if pair else "bridge"
        response = self.client.post(
            f"/v2/workspaces/{WS}/{route}/{rid}",
            content=self.results[rid],
            headers={**HOST, "Content-Type": "application/octet-stream"},
        )
        assert response.status_code == 202, response.text
        self.cursor = item["n"]
        return answer

    def approve(self, displayed_code):
        expected = R.sas(
            SUITE,
            WS_BYTES,
            OFFER,
            P.unb64u(CERT["o"]["dk_sig_pub"]),
            P.unb64u(CERT["o"]["dk_kx_pub"]),
            P.unb64u(WSK),
            SAS_NONCE,
        )
        assert displayed_code == expected
        assert self.client.put(f"/v2/devices/{DEVICE}", json={"cert": CERT}).status_code == 200
        grant = R.make_wk_grant(
            SUITE,
            private("wsk_a.sig"),
            WS_BYTES,
            DEVICE_BYTES,
            P.unb64u(CERT["o"]["dk_kx_pub"]),
            1,
            WK,
            secrets.token_bytes(32),
        )
        member_list = signed(
            {
                "v": 2,
                "suite": 2,
                "kind": "member_list",
                "workspace_id": WS,
                "epoch": 1,
                "list_seq": 1,
                "issued_ms": NOW,
                "persons": [],
                "members": [{"device_id": DEVICE, "person_id": PERSON, "scopes": ["look"]}],
            },
            "wsk_a.sig",
        )
        r = self.client.put(
            f"/v2/workspaces/{WS}/membership",
            json={"member_list": member_list, "grants": [grant]},
            headers=HOST,
        )
        assert r.status_code == 200, r.text

    def revoke(self):
        assert self.client.post("/v2/revocations", json={"record": RECORD}).status_code == 200
