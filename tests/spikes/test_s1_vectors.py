"""S1: verify what Apple CryptoKit / the Secure Enclave produced (spikes/s1/fixtures/se-mac.json) with Python
`cryptography` and the reference in ref/. Regenerate the fixture with `cd spikes/s1 && swift run s1-fixtures`."""
import json
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

from ref import orch_protocol_ref as ref

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "spikes/s1/fixtures/se-mac.json"
VECTORS = ROOT / "tests/vectors_v2.json"

S = ref.SUITES[2]
N = ref.P256_N

fx = json.loads(FIXTURE.read_text())
vec = json.loads(VECTORS.read_text())["suites"]["2"]


def vkey(name):
    return S.kx_key(bytes.fromhex(vec["keys"][name]["seed"]))


def _sig_cases():
    for who in ("secure_enclave", "software"):
        for i, c in enumerate(fx[who]["sig"]):
            yield pytest.param(who, c, id=f"{who}-{i}")


SIG_CASES = list(_sig_cases())


def test_fixture_metadata():
    assert fx["suite"] == 2
    assert fx["host"]["secure_enclave_available"] is True


@pytest.mark.parametrize("who", ["secure_enclave", "software"])
def test_public_key_is_suite2_format(who):
    pub = bytes.fromhex(fx[who]["sig_pub"])
    assert len(pub) == 65 and pub[0] == 4
    assert S.sig_pub_ok(pub)


@pytest.mark.parametrize("who,case", SIG_CASES)
def test_signature_verifies_raw_and_der(who, case):
    pub, msg = bytes.fromhex(fx[who]["sig_pub"]), bytes.fromhex(case["msg"])
    raw, der = bytes.fromhex(case["sig_raw"]), bytes.fromhex(case["sig_der"])
    assert len(raw) == 64
    assert S.verify(pub, raw, msg)                       # protocol path: raw r||s through the reference
    r, s = decode_dss_signature(der)                     # DER <-> raw conversion
    assert raw == r.to_bytes(32, "big") + s.to_bytes(32, "big")
    assert encode_dss_signature(r, s) == der
    ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub).verify(der, msg, ec.ECDSA(hashes.SHA256()))
    assert not S.verify(pub, raw, msg + b"x")


@pytest.mark.parametrize("who,case", SIG_CASES)
def test_signature_s_malleability(who, case):
    """Apple does not normalise s (it may be high or low); the twin (r, n-s) verifies too, so never use a signature as an id."""
    pub, msg, raw = bytes.fromhex(fx[who]["sig_pub"]), bytes.fromhex(case["msg"]), bytes.fromhex(case["sig_raw"])
    r, s = int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")
    assert 0 < r < N and 0 < s < N
    twin = r.to_bytes(32, "big") + (N - s).to_bytes(32, "big")
    assert S.verify(pub, twin, msg)


def test_se_ecdh_matches_python():
    e = fx["secure_enclave"]["ecdh"]
    se_pub = bytes.fromhex(e["se_kx_pub"])
    assert len(se_pub) == 65 and S.kx_pub_ok(se_pub)
    ss = S.kx(vkey(e["peer_vector_key"]), se_pub)         # Python private vector key x SE public key
    assert len(ss) == 32 and ss.hex() == e["shared_secret"]


@pytest.mark.parametrize("path", [("secure_enclave", "seal_with_se_ephemeral"), ("software", "seal")])
def test_python_opens_apple_seal(path):
    c = fx[path[0]][path[1]]
    blob = bytes.fromhex(c["sealed"])
    assert blob[:65] == bytes.fromhex(c["eph_pub"])
    pt = ref.open_sealed(S, vkey(c["recipient_vector_key"]), bytes.fromhex(c["recipient_id"]), c["purpose"],
                         bytes.fromhex(c["object_id"]), c["epoch"], blob)
    assert pt.hex() == c["plaintext"]


def test_tampered_seal_fails():
    c = fx["secure_enclave"]["seal_with_se_ephemeral"]
    blob = bytearray.fromhex(c["sealed"])
    blob[-1] ^= 1
    with pytest.raises(InvalidTag):
        ref.open_sealed(S, vkey(c["recipient_vector_key"]), bytes.fromhex(c["recipient_id"]), c["purpose"],
                        bytes.fromhex(c["object_id"]), c["epoch"], bytes(blob))


# --- negative cases (same list as SoftwareP256Tests.testMalformedSignaturesRejected / ...EncodingsRejected)

_valid = next(c for c in vec["sign"] if c["name"] == "valid")
_PUB, _MSG, _SIG = (bytes.fromhex(_valid[k]) for k in ("pub", "msg", "sig"))
_R, _S = _SIG[:32], _SIG[32:]
_N = N.to_bytes(32, "big")
_ONES = b"\xff" * 32
BAD_SIGS = {
    "s=0": _R + bytes(32), "r=0": bytes(32) + _S, "r=n": _N + _S, "s=n": _R + _N,
    "r=2^256-1": _ONES + _S, "s=2^256-1": _R + _ONES,
    "63 bytes": _SIG[:-1], "65 bytes": _SIG + b"\0", "empty": b"",
}


def test_valid_baseline():
    assert S.verify(_PUB, _SIG, _MSG)


@pytest.mark.parametrize("name", list(BAD_SIGS))
def test_malformed_signature_rejected_by_ref_and_cryptography(name):
    bad = BAD_SIGS[name]
    assert not S.verify(_PUB, bad, _MSG)                       # reference: explicit length and range checks
    if len(bad) == 64:                                         # cryptography alone, via DER, must also refuse
        r, s = int.from_bytes(bad[:32], "big"), int.from_bytes(bad[32:], "big")
        pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), _PUB)
        try:
            der = encode_dss_signature(r, s)
        except ValueError:
            return                                             # not even encodable
        with pytest.raises(InvalidSignature):
            pub.verify(der, _MSG, ec.ECDSA(hashes.SHA256()))


def _compressed(pub: bytes) -> bytes:
    return bytes([2 + (pub[64] & 1)]) + pub[1:33]


BAD_PUBS = {
    "compressed": _compressed(_PUB), "hybrid": bytes([6 + (_PUB[64] & 1)]) + _PUB[1:],
    "identity": b"\x04" + bytes(64), "single 00": b"\x00", "no prefix": _PUB[1:], "66 bytes": _PUB + b"\0",
    "prefix 05": b"\x05" + _PUB[1:], "empty": b"",
}


@pytest.mark.parametrize("name", list(BAD_PUBS))
def test_malformed_public_key_rejected(name):
    assert not S.sig_pub_ok(BAD_PUBS[name])
    assert not S.verify(BAD_PUBS[name], _SIG, _MSG)
