"""Reference implementation of the orch v2 wire protocol (docs/protocol-v2.md). TEST SUPPORT ONLY.

Nothing that ships (orch-relay, orch-core, orch mobile) imports this file. It exists so that
tests/vectors_v2.json is reproducible and so that every implementation can check its own code against
the same vectors. Section numbers (§n) refer to docs/protocol-v2.md. Where this file and the document
disagree, the document wins and this file has a bug.

Only the Python `cryptography` package and the standard library are used.

Regenerate the vectors:  uv run python -m ref.orch_protocol_ref
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import struct
import unicodedata
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, x25519
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# =====================================================================================================
# §2 Encodings
# =====================================================================================================

MAX_SAFE_INT = (1 << 53) - 1
ZERO_NONCE = bytes(12)
ZERO_ID = bytes(16)


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


_B64U = re.compile(r"[A-Za-z0-9_-]*")


def unb64u(s, n: int | None = None) -> bytes:
    """Canonical unpadded base64url only (§2.2). `n`: the exact decoded length, if fixed."""
    if not isinstance(s, str) or not _B64U.fullmatch(s) or len(s) % 4 == 1:
        raise ValueError("not b64u")
    b = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    if b64u(b) != s:
        raise ValueError("non-canonical b64u")
    if n is not None and len(b) != n:
        raise ValueError("wrong length")
    return b


_HEX = re.compile(r"(?:[0-9a-f]{2})*")


def unhex(s, n: int) -> bytes:
    """Lower-case hex of exactly n bytes (§2.2)."""
    if not isinstance(s, str) or len(s) != 2 * n or not _HEX.fullmatch(s):
        raise ValueError("not lower-case hex of the right length")
    return bytes.fromhex(s)


def _check_json(v, depth=0):
    """The JSON subset every signed or sealed object uses (§2.3)."""
    if depth > 16:
        raise ValueError("too deep")
    if v is None or isinstance(v, bool):
        return
    if isinstance(v, int):
        if not -MAX_SAFE_INT <= v <= MAX_SAFE_INT:
            raise ValueError("integer out of range")
        return
    if isinstance(v, str):
        if any(0xD800 <= ord(c) <= 0xDFFF for c in v):
            raise ValueError("lone surrogate")
        return
    if isinstance(v, list):
        for x in v:
            _check_json(x, depth + 1)
        return
    if isinstance(v, dict):
        for k, x in v.items():
            if not isinstance(k, str) or not k.isascii() or not k:
                raise ValueError("keys are non-empty ASCII")
            _check_json(x, depth + 1)
        return
    raise ValueError(f"{type(v).__name__} is not allowed (no floats)")


def cj(obj) -> bytes:
    """Canonical JSON (§2.3): TIX's canonicalJson restricted to the §2.3 subset."""
    _check_json(obj)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _no_dupes(pairs):
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate key")
    return dict(pairs)


def _no_constant(name):
    raise ValueError(f"{name} is not JSON")


def _no_float(s):
    raise ValueError("floats are not allowed")


def parse_json(raw: bytes):
    """Strict parse (§2.3): UTF-8, no duplicate key, no NaN/Infinity, no float, the subset only."""
    if not isinstance(raw, (bytes, bytearray)):
        raise ValueError("bytes expected")
    v = json.loads(bytes(raw).decode("utf-8"), object_pairs_hook=_no_dupes, parse_constant=_no_constant,
                   parse_float=_no_float)
    _check_json(v)
    return v


def lp16(b: bytes) -> bytes:
    assert len(b) < 1 << 16
    return struct.pack(">H", len(b)) + b


def u32(i: int) -> bytes:
    return struct.pack(">I", i)


def u64(i: int) -> bytes:
    return struct.pack(">Q", i)


def H(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """RFC 5869 HKDF-SHA-256; an empty salt is HashLen zero bytes (as WebCrypto does)."""
    return HKDF(hashes.SHA256(), length, salt or None, info).derive(ikm)


def ctx(label: str, *fields) -> bytes:
    """An HKDF info string (§3.1): the label, then each field after a '|'. Fields are 32-hex ids, decimal
    integers without leading zeros, or ASCII purpose names from a closed list."""
    out = label
    for f in fields:
        if isinstance(f, bytes):
            f = f.hex()
        out += "|" + str(f)
    return out.encode("ascii")


# =====================================================================================================
# §3 Labels: every domain-separation string in one place (the vector file lists them; a test checks that
# they are distinct and that no signature label is a prefix of another)
# =====================================================================================================

LABELS = {
    # HKDF info (key derivation)
    "kdf_bridge": "orch/v2/bridge",
    "kdf_bridge_msg": "orch/v2/bridge-msg",
    "kdf_push": "orch/v2/push",
    "kdf_push_msg": "orch/v2/push-msg",
    "kdf_wrap_wk": "orch/v2/wrap-wk",
    "kdf_wrap_sk": "orch/v2/wrap-sk",
    "kdf_wrap_msg": "orch/v2/wrap-msg",
    "kdf_pair": "orch/v2/pair",
    "kdf_seal": "orch/v2/seal",
    "kdf_card": "orch/v2/card",
    "kdf_drop_content": "orch/v2/drop-content",
    "kdf_drop_meta": "orch/v2/drop-meta",
    "kdf_label": "orch/v2/label",
    "kdf_label_msg": "orch/v2/label-msg",
    # AEAD associated-data prefixes
    "aad_seal": "orch/v2/seal-aad|",
    "aad_push": "orch/v2/push-aad|",
    "aad_wrap": "orch/v2/wrap-aad|",
    "aad_card": "orch/v2/card-aad|",
    "aad_label": "orch/v2/label-aad|",
    "aad_drop_meta": "orch/v2/drop-meta-aad|",
    # signature domains
    "sig_device_cert": "orch/v2/sig/device-cert|",
    "sig_revocation": "orch/v2/sig/revocation|",
    "sig_card_wsk": "orch/v2/sig/card-wsk|",
    "sig_ws_delegation": "orch/v2/sig/ws-delegation|",
    "sig_cert_challenge": "orch/v2/sig/cert-challenge|",
    "sig_push": "orch/v2/sig/push|",
    "sig_decision": "orch/v2/sig/decision|",
    "sig_member_list": "orch/v2/sig/member-list|",
    "sig_wk_grant": "orch/v2/sig/wk-grant|",
    "sig_sk_grant": "orch/v2/sig/sk-grant|",
    "sig_bridge": "orch/v2/sig/bridge|",
    "sig_cert_request": "orch/v2/sig/cert-request|",
    "sig_enroll_request": "orch/v2/sig/enroll-request|",
    "sig_drop_object": "orch/v2/sig/drop-object|",
    "sig_drop_claim": "orch/v2/sig/drop-claim|",
    "sig_ws_envelope": "orch/v2/ws-envelope|",
    "sig_ws_cosign": "orch/v2/sig/ws-cosign|",
    "sig_webauthn_bind": "orch/v2/sig/webauthn-bind|",
    "sig_relay_auth": "orch/v2/sig/relay-auth|",
    "sig_publish": "orch/v2/publish|",
    # hashes (ids, pins, commitments, challenges)
    "h_device_id": "orch/v2/id/device|",
    "h_person_id": "orch/v2/id/person|",
    "h_pin_person": "orch/v2/pin/person|",
    "h_pin_workspace": "orch/v2/pin/workspace|",
    "h_sas": "orch/v2/sas|",
    "h_sas_cert": "orch/v2/sas-cert|",
    "h_dek_commit": "orch/v2/dek-commit|",
    "h_card_key_commit": "orch/v2/card-key-commit|",
    "h_drop_parent": "orch/v2/drop-parent|",
    "h_ws_envelope": "orch/v2/ws-envelope-hash|",
    "h_question": "orch/v2/question|",
    "h_assert": "orch/v2/assert|",
    "h_webauthn_reg": "orch/v2/webauthn-reg|",
    # MAC
    "mac_enroll": "orch/v2/enroll|",
}
L = {k: v.encode("ascii") for k, v in LABELS.items()}

# =====================================================================================================
# §1 Suites
# =====================================================================================================

ED_P = 2 ** 255 - 19
ED_L = 2 ** 252 + 27742317777372353535851937790883648493
ED_D = -121665 * pow(121666, ED_P - 2, ED_P) % ED_P
ED_I = pow(2, (ED_P - 1) // 4, ED_P)
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def _ed_decode(enc: bytes):
    """RFC 8032 §5.1.3, strictly: None for a non-canonical or non-decodable encoding."""
    if len(enc) != 32:
        return None
    n = int.from_bytes(enc, "little")
    sign, y = n >> 255, n & ((1 << 255) - 1)
    if y >= ED_P:
        return None
    x2 = (y * y - 1) * pow(ED_D * y * y + 1, ED_P - 2, ED_P) % ED_P
    x = pow(x2, (ED_P + 3) // 8, ED_P)
    if (x * x - x2) % ED_P:
        x = x * ED_I % ED_P
    if (x * x - x2) % ED_P:
        return None
    if x == 0 and sign:
        return None
    if x & 1 != sign:
        x = ED_P - x
    return x, y


def _ed_encode(pt) -> bytes:
    x, y = pt
    return (y | (x & 1) << 255).to_bytes(32, "little")


def _ed_add(a, b):
    (x1, y1), (x2, y2) = a, b
    t = ED_D * x1 * x2 * y1 * y2 % ED_P
    return ((x1 * y2 + x2 * y1) * pow(1 + t, ED_P - 2, ED_P) % ED_P,
            (y1 * y2 + x1 * x2) * pow(1 - t, ED_P - 2, ED_P) % ED_P)


def _ed_mul(k: int, pt):
    acc, add = (0, 1), pt
    while k:
        if k & 1:
            acc = _ed_add(acc, add)
        add = _ed_add(add, add)
        k >>= 1
    return acc


def ed25519_small_order_encodings() -> list[str]:
    """Every canonical encoding of a point of order dividing 8 (§1.2), computed, not copied."""
    y = 2
    while True:
        pt = _ed_decode(y.to_bytes(32, "little"))
        y += 1
        if pt is None:
            continue
        t = _ed_mul(ED_L, pt)                   # kill the prime-order part: t is a torsion point
        if _ed_mul(4, t) != (0, 1):             # order exactly 8: a generator of the torsion group
            break
    pts, acc = [], (0, 1)
    for _ in range(8):
        pts.append(_ed_encode(acc).hex())
        acc = _ed_add(acc, t)
    return sorted(pts)


def ed25519_pub_ok(pub: bytes) -> bool:
    """§1.2: canonical, decodable and not of small order."""
    pt = _ed_decode(pub)
    return pt is not None and _ed_mul(8, pt) != (0, 1)


class Suite:
    id: int
    name: str
    sig_pub_len: int
    kx_pub_len: int
    sig_len = 64


class SuiteX(Suite):
    """Suite 1: Ed25519 + X25519 (D22 primary)."""
    id, name, sig_pub_len, kx_pub_len = 1, "ed25519-x25519", 32, 32

    def sig_key(self, seed):
        return ed25519.Ed25519PrivateKey.from_private_bytes(seed)

    def sig_pub(self, priv) -> bytes:
        return priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def sign(self, priv, msg: bytes) -> bytes:
        return priv.sign(msg)

    def sig_pub_ok(self, pub: bytes) -> bool:
        return isinstance(pub, bytes) and len(pub) == 32 and ed25519_pub_ok(pub)

    def verify(self, pub: bytes, sig: bytes, msg: bytes) -> bool:
        if not self.sig_pub_ok(pub) or not isinstance(sig, bytes) or len(sig) != 64:
            return False
        if int.from_bytes(sig[32:], "little") >= ED_L:          # S must be canonical (§1.2)
            return False
        try:
            ed25519.Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg)
            return True
        except InvalidSignature:
            return False

    def kx_key(self, seed):
        return x25519.X25519PrivateKey.from_private_bytes(seed)

    def kx_pub(self, priv) -> bytes:
        return priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def kx_pub_ok(self, pub: bytes) -> bool:
        return isinstance(pub, bytes) and len(pub) == 32

    def kx(self, priv, pub: bytes) -> bytes:
        if not self.kx_pub_ok(pub):
            raise ValueError("bad kx public key")
        ss = priv.exchange(x25519.X25519PublicKey.from_public_bytes(pub))   # raises on all-zero
        if ss == bytes(32):
            raise ValueError("all-zero shared secret")
        return ss


class SuiteP(Suite):
    """Suite 2: ECDSA P-256 / ECDH P-256 (D22 fallback). Never mixed with suite 1."""
    id, name, sig_pub_len, kx_pub_len = 2, "p256", 65, 65

    def _priv(self, seed):
        return ec.derive_private_key(int.from_bytes(seed, "big") % (P256_N - 1) + 1, ec.SECP256R1())

    def _pub(self, priv) -> bytes:
        return priv.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)

    def _load(self, pub: bytes):
        if not isinstance(pub, bytes) or len(pub) != 65 or pub[0] != 4:
            raise ValueError("not an uncompressed P-256 point")
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub)     # on-curve check

    sig_key = kx_key = _priv
    sig_pub = kx_pub = _pub

    def sign(self, priv, msg: bytes) -> bytes:
        # RFC 6979 only so the vectors are reproducible; real signers may randomise
        r, s = decode_dss_signature(priv.sign(msg, ec.ECDSA(hashes.SHA256(), deterministic_signing=True)))
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    def sig_pub_ok(self, pub: bytes) -> bool:
        try:
            self._load(pub)
            return True
        except ValueError:
            return False

    kx_pub_ok = sig_pub_ok

    def verify(self, pub: bytes, sig: bytes, msg: bytes) -> bool:
        if not isinstance(sig, bytes) or len(sig) != 64:
            return False
        r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
        if not (0 < r < P256_N and 0 < s < P256_N):
            return False
        try:
            self._load(pub).verify(encode_dss_signature(r, s), msg, ec.ECDSA(hashes.SHA256()))
            return True
        except (InvalidSignature, ValueError):
            return False

    def kx(self, priv, pub: bytes) -> bytes:
        return priv.exchange(ec.ECDH(), self._load(pub))


SUITES = {1: SuiteX(), 2: SuiteP()}

# =====================================================================================================
# §4 Identifiers, pins, short authentication string
# =====================================================================================================


def device_id(suite: Suite, dk_sig_pub: bytes) -> bytes:
    return H(L["h_device_id"] + bytes([suite.id]) + dk_sig_pub)[:16]


def person_id(suite: Suite, pk_pub: bytes) -> bytes:
    return H(L["h_person_id"] + bytes([suite.id]) + pk_pub)[:16]


def pk_pin(suite: Suite, pk_pub: bytes) -> bytes:
    return H(L["h_pin_person"] + bytes([suite.id]) + pk_pub)


def wsk_pin(suite: Suite, wsk_pub: bytes) -> bytes:
    return H(L["h_pin_workspace"] + bytes([suite.id]) + wsk_pub)


B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def sas(suite: Suite, ws: bytes, offer: bytes, dk_sig_pub: bytes, dk_kx_pub: bytes, wsk_pub: bytes,
        sas_nonce: bytes) -> str:
    """The 6-character pairing code (§8.3): 30 bits, bound to a host nonce chosen after the device key."""
    d = H(L["h_sas"] + bytes([suite.id]) + ws + offer + lp16(dk_sig_pub) + lp16(dk_kx_pub) + lp16(wsk_pub)
          + sas_nonce)
    return base64.b32encode(d).decode()[:6]


# =====================================================================================================
# §5 Symmetric constructions
# =====================================================================================================


def salted_seal(k_base: bytes, msg_label: bytes, aad: bytes, pt: bytes, salt: bytes) -> bytes:
    """SALTED-AEAD (§5.1): salt || AES-256-GCM(HKDF(k_base, salt, msg_label), zero nonce, pt, aad)."""
    assert len(salt) == 16
    return salt + AESGCM(hkdf(k_base, salt, msg_label)).encrypt(ZERO_NONCE, pt, aad)


def salted_open(k_base: bytes, msg_label: bytes, aad: bytes, blob: bytes) -> bytes:
    if len(blob) < 32:
        raise InvalidTag()
    return AESGCM(hkdf(k_base, blob[:16], msg_label)).decrypt(ZERO_NONCE, blob[16:], aad)


def k_bridge(wk: bytes, ws: bytes, epoch: int) -> bytes:
    return hkdf(wk, b"", ctx(LABELS["kdf_bridge"], ws, epoch))


def k_push(wk: bytes, ws: bytes, epoch: int) -> bytes:
    return hkdf(wk, b"", ctx(LABELS["kdf_push"], ws, epoch))


def k_wrap_wk(wk: bytes, ws: bytes, epoch: int) -> bytes:
    return hkdf(wk, b"", ctx(LABELS["kdf_wrap_wk"], ws, epoch))


def k_wrap_sk(sk: bytes, space: bytes, epoch: int) -> bytes:
    return hkdf(sk, b"", ctx(LABELS["kdf_wrap_sk"], space, epoch))


def k_pair(secret: bytes, ws: bytes, offer: bytes) -> bytes:
    return hkdf(secret, b"", ctx(LABELS["kdf_pair"], ws, offer))


def k_card(ck: bytes, ws: bytes, card_seq: int) -> bytes:
    return hkdf(ck, b"", ctx(LABELS["kdf_card"], ws, card_seq))


def k_label(pvk: bytes, person: bytes) -> bytes:
    return hkdf(pvk, b"", ctx(LABELS["kdf_label"], person))


# =====================================================================================================
# §5.3 Sealing to a device or to a workspace exchange key (HPKE-shaped)
# =====================================================================================================

SEAL_PURPOSES = ("wk", "sk", "card", "cert-request", "drop-dek", "ws-envelope", "vault")


def seal_aad(suite: Suite, purpose: str, object_id: bytes, epoch: int, extra: bytes = b"") -> bytes:
    p = purpose.encode("ascii")
    return L["aad_seal"] + bytes([suite.id, len(p)]) + p + object_id + u32(epoch) + extra


def seal_key(suite: Suite, ss: bytes, eph_pub: bytes, rcpt_pub: bytes, purpose: str, rcpt_id: bytes) -> bytes:
    return hkdf(ss, eph_pub + rcpt_pub, ctx(LABELS["kdf_seal"], purpose, rcpt_id))


def seal_to(suite: Suite, rcpt_kx_pub: bytes, rcpt_id: bytes, purpose: str, object_id: bytes, epoch: int,
            pt: bytes, eph_seed: bytes, extra_aad: bytes = b"") -> bytes:
    """eph_pub || AES-256-GCM(K, zero nonce, pt, AAD). `eph_seed` is fixed only for the vectors; a real
    sealer MUST draw a fresh ephemeral key for every seal."""
    assert purpose in SEAL_PURPOSES and len(object_id) == 16 and len(rcpt_id) == 16
    eph = suite.kx_key(eph_seed)
    eph_pub = suite.kx_pub(eph)
    k = seal_key(suite, suite.kx(eph, rcpt_kx_pub), eph_pub, rcpt_kx_pub, purpose, rcpt_id)
    return eph_pub + AESGCM(k).encrypt(ZERO_NONCE, pt, seal_aad(suite, purpose, object_id, epoch, extra_aad))


def open_sealed(suite: Suite, rcpt_kx_priv, rcpt_id: bytes, purpose: str, object_id: bytes, epoch: int,
                blob: bytes, extra_aad: bytes = b"") -> bytes:
    n = suite.kx_pub_len
    if len(blob) < n + 16:
        raise InvalidTag()
    eph_pub, ct = blob[:n], blob[n:]
    rcpt_pub = suite.kx_pub(rcpt_kx_priv)
    try:
        ss = suite.kx(rcpt_kx_priv, eph_pub)
    except ValueError:
        raise InvalidTag()
    k = seal_key(suite, ss, eph_pub, rcpt_pub, purpose, rcpt_id)
    return AESGCM(k).decrypt(ZERO_NONCE, ct, seal_aad(suite, purpose, object_id, epoch, extra_aad))


# =====================================================================================================
# §6 Signed objects
# =====================================================================================================

KIND_LABEL = {"device_cert": "sig_device_cert", "revocation": "sig_revocation", "member_list": "sig_member_list",
              "wk_grant": "sig_wk_grant", "sk_grant": "sig_sk_grant", "cert_request": "sig_cert_request",
              "ws_delegation": "sig_ws_delegation", "cert_challenge": "sig_cert_challenge",
              "enroll_request": "sig_enroll_request", "drop_object": "sig_drop_object",
              "drop_claim": "sig_drop_claim"}


def sign_object(suite: Suite, priv, o: dict) -> dict:
    assert o["v"] == 2 and o["suite"] == suite.id
    return {"o": o, "sig": b64u(suite.sign(priv, L[KIND_LABEL[o["kind"]]] + cj(o)))}


def verify_object(suite: Suite, pub: bytes, signed, kind: str) -> dict | None:
    """The object if `signed` is {"o": {...kind...}, "sig": b64u} and the signature verifies; else None."""
    try:
        if not isinstance(signed, dict) or set(signed) != {"o", "sig"}:
            return None
        o = signed["o"]
        if not isinstance(o, dict) or o.get("v") != 2 or o.get("suite") != suite.id or o.get("kind") != kind:
            return None
        sig = unb64u(signed["sig"], 64)
        return o if suite.verify(pub, sig, L[KIND_LABEL[kind]] + cj(o)) else None
    except (ValueError, TypeError):
        return None


SCOPE_ORDER = ["look", "decide", "operate", "type"]
_DROP_SCOPE = re.compile(r"drop:[0-9a-f]{32}")
REVOKE_REASONS = ("lost", "retired", "compromised")


def scopes_ok(scopes) -> bool:
    """§6.1: a non-empty prefix of look, decide, operate, type; or exactly one drop:<space>."""
    if not isinstance(scopes, list) or not scopes:
        return False
    if len(scopes) == 1 and isinstance(scopes[0], str) and _DROP_SCOPE.fullmatch(scopes[0]):
        return True
    return scopes == SCOPE_ORDER[:len(scopes)]


def verify_cert(suite: Suite, signed, pk_pub: bytes, now_ms: int, revoked: set[str] = frozenset()) -> dict:
    """§6.1. {"ok": cert} or {"refuse": code}."""
    o = verify_object(suite, pk_pub, signed, "device_cert")
    if o is None:
        return {"refuse": "cert_invalid"}
    try:
        if set(o) != {"v", "suite", "kind", "device_id", "person_id", "dk_sig_pub", "dk_kx_pub", "label_sealed",
                      "created_ms", "expires_ms", "scopes_max"}:
            return {"refuse": "cert_invalid"}
        sig_pub, kx_pub = unb64u(o["dk_sig_pub"], suite.sig_pub_len), unb64u(o["dk_kx_pub"], suite.kx_pub_len)
        unb64u(o["label_sealed"])
        if not suite.sig_pub_ok(sig_pub) or not suite.kx_pub_ok(kx_pub):
            return {"refuse": "cert_invalid"}
        if unhex(o["device_id"], 16) != device_id(suite, sig_pub) or unhex(o["person_id"], 16) != person_id(suite, pk_pub):
            return {"refuse": "cert_invalid"}
        if not scopes_ok(o["scopes_max"]) or type(o["created_ms"]) is not int:
            return {"refuse": "cert_invalid"}
        exp = o["expires_ms"]
        drop_scoped = o["scopes_max"][0].startswith("drop:")
        if exp is not None and (type(exp) is not int or exp <= o["created_ms"]):
            return {"refuse": "cert_invalid"}
        if drop_scoped and exp is None:                  # a scoped agent device always expires (D15)
            return {"refuse": "cert_invalid"}
    except (ValueError, TypeError, KeyError, AttributeError):
        return {"refuse": "cert_invalid"}
    if o["created_ms"] > now_ms + SKEW_MS:
        return {"refuse": "cert_invalid"}
    if exp is not None and now_ms >= exp:
        return {"refuse": "cert_expired"}
    if o["device_id"] in revoked:
        return {"refuse": "revoked"}
    return {"ok": o}


def verify_revocation(suite: Suite, signed, pk_pub: bytes, cert: dict | None) -> dict:
    o = verify_object(suite, pk_pub, signed, "revocation")
    if o is None or set(o) != {"v", "suite", "kind", "person_id", "device_id", "revoked_ms", "reason"}:
        return {"refuse": "bad_signature"}
    if o["person_id"] != person_id(suite, pk_pub).hex() or o["reason"] not in REVOKE_REASONS \
            or type(o["revoked_ms"]) is not int:
        return {"refuse": "malformed"}
    if cert is None or cert["person_id"] != o["person_id"] or cert["device_id"] != o["device_id"]:
        return {"refuse": "other_person"}
    return {"ok": o}


# =====================================================================================================
# §7 Workspace card, member list, WK grants
# =====================================================================================================

_RELAY_URL = re.compile(r"https://[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[1-9][0-9]{0,4})?|"
                        r"http://(localhost|127\.0\.0\.1|\[::1\])(:[1-9][0-9]{0,4})?")
CARD_FIELDS = {"v", "suite", "kind", "workspace_id", "wsk_pub", "wxk_pub", "wxk_version", "owner_person_id",
               "relay_url", "card_seq", "issued_ms", "sealed_hash", "ck_commit"}
SEALED_CARD_FIELDS = {"name", "description", "capabilities", "hosted_by"}
DELEGATION_FIELDS = {"v", "suite", "kind", "workspace_id", "wsk_pub", "owner_person_id", "client_hosted", "issued_ms"}


def ck_commit(ws: bytes, card_seq: int, ck: bytes) -> bytes:
    return H(L["h_card_key_commit"] + ws + u32(card_seq) + ck)


def make_delegation(suite: Suite, pk, ws: bytes, wsk_pub: bytes, owner: bytes, client_hosted: bool,
                    issued_ms: int) -> dict:
    """§7.1: signed once by the owner's PK when the workspace is created; it never changes."""
    return sign_object(suite, pk, {"v": 2, "suite": suite.id, "kind": "ws_delegation", "workspace_id": ws.hex(),
                                   "wsk_pub": b64u(wsk_pub), "owner_person_id": owner.hex(),
                                   "client_hosted": client_hosted, "issued_ms": issued_ms})


def verify_delegation(suite: Suite, signed, owner_pk_pub: bytes) -> dict:
    o = verify_object(suite, owner_pk_pub, signed, "ws_delegation")
    if o is None:
        return {"refuse": "bad_signature"}
    if set(o) != DELEGATION_FIELDS or type(o["client_hosted"]) is not bool or type(o["issued_ms"]) is not int:
        return {"refuse": "malformed"}
    if o["owner_person_id"] != person_id(suite, owner_pk_pub).hex():
        return {"refuse": "other_person"}
    return {"ok": o}


def card_sealed_part(suite: Suite, ck: bytes, ws: bytes, card_seq: int, part: dict) -> bytes:
    assert set(part) == SEALED_CARD_FIELDS
    return AESGCM(k_card(ck, ws, card_seq)).encrypt(ZERO_NONCE, cj(part),
                                                    L["aad_card"] + bytes([suite.id]) + ws + u32(card_seq))


def open_card_sealed_part(suite: Suite, card_o: dict, ck: bytes, sealed: bytes) -> dict:
    """§7.1: a reader that unwrapped CK first checks it against the signed ck_commit, then opens."""
    ws, seq = unhex(card_o["workspace_id"], 16), card_o["card_seq"]
    if not hmac.compare_digest(unb64u(card_o["ck_commit"], 32), ck_commit(ws, seq, ck)):
        raise ValueError("card key does not match ck_commit")
    return parse_json(AESGCM(k_card(ck, ws, seq)).decrypt(
        ZERO_NONCE, sealed, L["aad_card"] + bytes([suite.id]) + ws + u32(seq)))


def make_card(suite: Suite, wsk, delegation: dict, o: dict, sealed: bytes, ck: bytes) -> dict:
    """§7.1: the rotating card is signed by WSK alone; the owner's PK signed the delegation once."""
    ws = unhex(o["workspace_id"], 16)
    o = {**o, "sealed_hash": b64u(H(sealed)), "ck_commit": b64u(ck_commit(ws, o["card_seq"], ck))}
    return {"delegation": delegation, "o": o, "sig": b64u(suite.sign(wsk, L["sig_card_wsk"] + cj(o))),
            "sealed": b64u(sealed)}


def verify_card(suite: Suite, card, owner_pk_pub: bytes) -> dict:
    """§7.1, what the relay, orch-publish and a peer check: the delegation (owner PK), then the card (WSK)."""
    try:
        if not isinstance(card, dict) or set(card) != {"delegation", "o", "sig", "sealed"}:
            return {"refuse": "malformed"}
        o = card["o"]
        if not isinstance(o, dict) or set(o) != CARD_FIELDS or o["v"] != 2 or o["kind"] != "card":
            return {"refuse": "malformed"}
        if o["suite"] != suite.id:
            return {"refuse": "wrong_suite"}
        unhex(o["workspace_id"], 16)
        wsk_pub, wxk_pub = unb64u(o["wsk_pub"], suite.sig_pub_len), unb64u(o["wxk_pub"], suite.kx_pub_len)
        if not suite.sig_pub_ok(wsk_pub) or not suite.kx_pub_ok(wxk_pub):
            return {"refuse": "malformed"}
        if not isinstance(o["relay_url"], str) or not _RELAY_URL.fullmatch(o["relay_url"]):
            return {"refuse": "malformed"}
        for k in ("wxk_version", "card_seq", "issued_ms"):
            if type(o[k]) is not int or o[k] < (1 if k != "issued_ms" else 0):
                return {"refuse": "malformed"}
        unb64u(o["ck_commit"], 32)
        sealed = unb64u(card["sealed"])
        if o["owner_person_id"] != person_id(suite, owner_pk_pub).hex():
            return {"refuse": "other_person"}
        d = verify_delegation(suite, card["delegation"], owner_pk_pub)
        if "refuse" in d:
            return d
        d = d["ok"]
        if (d["workspace_id"], d["wsk_pub"], d["owner_person_id"]) != (o["workspace_id"], o["wsk_pub"],
                                                                        o["owner_person_id"]):
            return {"refuse": "delegation_mismatch"}
        if not suite.verify(wsk_pub, unb64u(card["sig"], 64), L["sig_card_wsk"] + cj(o)):
            return {"refuse": "bad_signature"}
        if unb64u(o["sealed_hash"], 32) != H(sealed):
            return {"refuse": "bad_signature"}
    except (ValueError, TypeError, KeyError, AttributeError):
        return {"refuse": "malformed"}
    return {"ok": o}


def relay_accept_card(suite: Suite, stored: dict | None, card, owner_pk_pub: bytes) -> dict:
    """§7.1 update rules, as the relay applies them. stored: {"o": card o, "delegation": delegation o} or None."""
    r = verify_card(suite, card, owner_pk_pub)
    if "refuse" in r:
        return r
    o = r["ok"]
    if stored is None:
        return {"ok": o}
    so = stored["o"]
    if o["workspace_id"] != so["workspace_id"] or o["owner_person_id"] != so["owner_person_id"]:
        return {"refuse": "other_workspace"}
    if o["wsk_pub"] != so["wsk_pub"]:
        return {"refuse": "wsk_changed"}
    if cj(card["delegation"]["o"]) != cj(stored["delegation"]):
        return {"refuse": "delegation_changed"}
    if o["card_seq"] <= so["card_seq"]:
        return {"refuse": "stale_card"}
    if o["wxk_version"] == so["wxk_version"]:
        if o["wxk_pub"] != so["wxk_pub"]:
            return {"refuse": "wxk_changed_without_version"}
    elif o["wxk_version"] != so["wxk_version"] + 1 or o["wxk_pub"] == so["wxk_pub"]:
        return {"refuse": "bad_wxk_version"}
    return {"ok": o}


def relay_accept_member_list(suite: Suite, wsk_pub: bytes, card_ws: str, prev: dict | None, signed,
                             dir_state: dict, now_ms: int) -> dict:
    """§7.2. card_ws: the workspace id of the card whose wsk_pub verifies. dir_state: {"owner_pk_pub": bytes,
    "certs": {device hex: signed cert}, "revoked": set, "grants": {(device hex, epoch)}}."""
    o = verify_object(suite, wsk_pub, signed, "member_list")
    if o is None:
        return {"refuse": "bad_signature"}
    try:
        if set(o) != {"v", "suite", "kind", "workspace_id", "epoch", "list_seq", "issued_ms", "members"}:
            return {"refuse": "malformed"}
        ids = [m["device_id"] for m in o["members"]]
        for m in o["members"]:
            if set(m) != {"device_id", "scopes"}:
                return {"refuse": "malformed"}
            unhex(m["device_id"], 16)
        if ids != sorted(set(ids)):
            return {"refuse": "malformed"}
        if type(o["epoch"]) is not int or o["epoch"] < 1 or type(o["list_seq"]) is not int:
            return {"refuse": "malformed"}
    except (ValueError, TypeError, KeyError, AttributeError):
        return {"refuse": "malformed"}
    if o["workspace_id"] != card_ws:
        return {"refuse": "other_workspace"}
    if prev is not None:
        if o["list_seq"] <= prev["list_seq"]:
            return {"refuse": "stale_list"}
        if o["epoch"] not in (prev["epoch"], prev["epoch"] + 1):
            return {"refuse": "bad_epoch"}
        removed = {m["device_id"] for m in prev["members"]} - set(ids)
        if removed and o["epoch"] != prev["epoch"] + 1:
            return {"refuse": "rotation_required"}
    elif o["epoch"] != 1 or o["list_seq"] != 1:
        return {"refuse": "bad_epoch"}
    for m in o["members"]:
        did = m["device_id"]
        if did in dir_state["revoked"]:
            return {"refuse": "revoked"}
        cert = dir_state["certs"].get(did)
        if cert is None:
            return {"refuse": "cert_invalid"}
        c = verify_cert(suite, cert, dir_state["owner_pk_pub"], now_ms, dir_state["revoked"])
        if "refuse" in c:
            return {"refuse": "other_person" if c["refuse"] == "cert_invalid"
                    and cert["o"].get("person_id") != person_id(suite, dir_state["owner_pk_pub"]).hex()
                    else c["refuse"]}
        cs = c["ok"]["scopes_max"]
        if cs[0].startswith("drop:") or not scopes_ok(m["scopes"]) or len(m["scopes"]) > len(cs):
            return {"refuse": "scope_exceeded"}
        if (did, o["epoch"]) not in dir_state["grants"]:
            return {"refuse": "missing_grant"}
    return {"ok": o}


def make_wk_grant(suite: Suite, wsk, ws: bytes, dev: bytes, dk_kx_pub: bytes, epoch: int, wk: bytes,
                  eph_seed: bytes) -> dict:
    sealed = seal_to(suite, dk_kx_pub, dev, "wk", ws, epoch, wk, eph_seed)
    return sign_object(suite, wsk, {"v": 2, "suite": suite.id, "kind": "wk_grant", "workspace_id": ws.hex(),
                                    "device_id": dev.hex(), "epoch": epoch, "sealed": b64u(sealed)})


def open_wk_grant(suite: Suite, wsk_pub: bytes, signed, ws: bytes, dev: bytes, dk_kx_priv) -> dict:
    o = verify_object(suite, wsk_pub, signed, "wk_grant")
    if o is None:
        return {"refuse": "bad_signature"}
    if o["workspace_id"] != ws.hex() or o["device_id"] != dev.hex():
        return {"refuse": "not_for_this_device"}
    try:
        wk = open_sealed(suite, dk_kx_priv, dev, "wk", ws, o["epoch"], unb64u(o["sealed"]))
    except (InvalidTag, ValueError):
        return {"refuse": "tag"}
    if len(wk) != 32:
        return {"refuse": "malformed"}
    return {"ok": {"epoch": o["epoch"], "wk": wk.hex()}}


# =====================================================================================================
# §8 Bridge v2
# =====================================================================================================

MAGIC = b"ORB2"
VERSION = 2
TO_HOST, TO_DEVICE = 1, 2
F_LAST, F_STREAM, F_REFUSAL = 0x01, 0x02, 0x04
HEADER_LEN = 108
TAG_LEN = 16
SIG_LEN = 64
OVERHEAD = HEADER_LEN + TAG_LEN + SIG_LEN            # 188
MAX_REQUEST = 1 << 20
MAX_CHUNK = 256 * 1024
MAX_META = 64 * 1024
WINDOW_MS = 300_000
SKEW_MS = 300_000
SEQ_WINDOW = 64
RID_RETENTION_MS = 900_000
PER_DEVICE = 1024
MAX_RECORDS = 16384
BUSY_ALLOWANCE = 64
BUDGET = 10
OFFER_BUDGET = 5
BUDGET_WINDOW_MS = 60_000
MAX_OFFSET_MS = 24 * 3600 * 1000
MAX_LABEL = 80
OFFER_TTL_MS = 600_000
CERT_PENDING_MS = 600_000
OFFER_RECORD_MS = 24 * 3600 * 1000

_HDR = struct.Struct(">4sBBBB16s16s16s16sQQI16s")
assert _HDR.size == HEADER_LEN


@dataclass(frozen=True)
class Header:
    direction: int
    flags: int
    suite: int
    workspace: bytes
    device: bytes
    rid: bytes
    stream: bytes
    seq: int
    ts_ms: int
    epoch: int
    salt: bytes
    version: int = VERSION
    magic: bytes = MAGIC

    def encode(self) -> bytes:
        return _HDR.pack(self.magic, self.version, self.direction, self.flags, self.suite, self.workspace,
                         self.device, self.rid, self.stream, self.seq, self.ts_ms, self.epoch, self.salt)

    @classmethod
    def decode(cls, b: bytes) -> "Header":
        m, v, d, f, s, ws, dev, rid, st, seq, ts, ep, salt = _HDR.unpack(b[:HEADER_LEN])
        return cls(d, f, s, ws, dev, rid, st, seq, ts, ep, salt, v, m)

    def as_json(self) -> dict:
        return {"magic": self.magic.decode("latin-1"), "version": self.version, "direction": self.direction,
                "flags": self.flags, "suite": self.suite, "workspace": self.workspace.hex(),
                "device": self.device.hex(), "rid": self.rid.hex(), "stream": self.stream.hex(), "seq": self.seq,
                "ts_ms": self.ts_ms, "epoch": self.epoch, "salt": self.salt.hex()}


def frame(meta: dict, data: bytes = b"") -> bytes:
    m = cj(meta)
    assert len(m) <= MAX_META
    return struct.pack(">I", len(m)) + m + data


def unframe(pt: bytes) -> tuple[dict, bytes]:
    if len(pt) < 4:
        raise ValueError("short plaintext")
    n = struct.unpack(">I", pt[:4])[0]
    if n > MAX_META or 4 + n > len(pt):
        raise ValueError("bad meta length")
    meta = parse_json(pt[4:4 + n])
    if not isinstance(meta, dict):
        raise ValueError("meta is not an object")
    return meta, pt[4 + n:]


def bridge_key(state_or_ctx: dict, h: Header) -> bytes | None:
    """The channel key for a header (§8.2): K_pair for epoch 0, K_bridge(epoch) otherwise; None if unknown."""
    ws = h.workspace
    if h.epoch == 0:
        offer = state_or_ctx.get("offers", {}).get(h.stream.hex())
        return None if offer is None else k_pair(bytes.fromhex(offer["secret"]), ws, h.stream)
    wk = state_or_ctx["wk"].get(str(h.epoch))
    return None if wk is None else k_bridge(bytes.fromhex(wk), ws, h.epoch)


def message_key(k_chan: bytes, salt: bytes) -> bytes:
    return hkdf(k_chan, salt, L["kdf_bridge_msg"])


def seal_body(k_chan: bytes, hb: bytes, pt: bytes) -> bytes:
    return AESGCM(message_key(k_chan, Header.decode(hb).salt)).encrypt(ZERO_NONCE, pt, hb)


def open_body(k_chan: bytes, hb: bytes, body: bytes) -> bytes:
    return AESGCM(message_key(k_chan, Header.decode(hb).salt)).decrypt(ZERO_NONCE, body, hb)


def bridge_signed(hb: bytes, body: bytes) -> bytes:
    return L["sig_bridge"] + hb + body


def envelope(suite: Suite, k_chan: bytes, signer, h: Header, pt: bytes) -> bytes:
    hb = h.encode()
    body = seal_body(k_chan, hb, pt)
    return hb + body + suite.sign(signer, bridge_signed(hb, body))


def split(env: bytes):
    return env[:HEADER_LEN], env[HEADER_LEN:-SIG_LEN], env[-SIG_LEN:]


def digest(env: bytes) -> bytes:
    hb, body, _ = split(env)
    return H(hb + body)


def _drop(why):
    return {"result": "drop", "why": why}


def _refuse(code, **extra):
    return {"result": "refuse", "code": code, **extra}


def _unverified(state, now_ms, code, bucket=None, limit=BUDGET, **extra):
    holder = state if bucket is None else bucket
    recent = [t for t in holder.get("unverified", []) if now_ms - t < BUDGET_WINDOW_MS]
    if len(recent) >= limit:
        holder["unverified"] = recent
        return _drop("budget")
    holder["unverified"] = recent + [now_ms]
    return _refuse(code, **extra)


class StoreFull(Exception):
    pass


class DeviceFull(Exception):
    pass


def _limits(state):
    return {"per_device": PER_DEVICE, "max_records": MAX_RECORDS, "busy_allowance": BUSY_ALLOWANCE,
            **state.get("limits", {})}


def _total(state, now_ms):
    return sum(1 for r in state["rids"].values() if now_ms < r["until"])


def _count_for(state, dev, now_ms):
    return sum(1 for r in state["rids"].values() if r["device"] == dev and now_ms < r["until"])


def _record(state, h, env, now_ms, outcome):
    lim = _limits(state)
    if _total(state, now_ms) >= lim["max_records"]:
        raise StoreFull()
    if _count_for(state, h.device.hex(), now_ms) >= lim["per_device"] + lim["busy_allowance"]:
        raise DeviceFull()
    state["rids"][h.rid.hex()] = {"device": h.device.hex(), "digest": digest(env).hex(), "outcome": outcome,
                                  "until": now_ms + RID_RETENTION_MS}


def _recorded_refusal(state, h, env, now_ms, code, **extra):
    _record(state, h, env, now_ms, {"refusal": code, **extra})
    return _refuse(code, **extra)


def seq_accept(dev: dict, seq: int) -> bool:
    high, bm = dev["high"], dev["bitmap"]
    if seq > high:
        shift = seq - high
        dev["bitmap"] = ((bm << shift) | 1) & ((1 << SEQ_WINDOW) - 1) if shift < SEQ_WINDOW else 1
        dev["high"] = seq
        return True
    i = high - seq
    if seq < 1 or i >= SEQ_WINDOW or bm >> i & 1:
        return False
    dev["bitmap"] = bm | 1 << i
    return True


def host_check(env: bytes, state: dict, now_ms: int, mailbox_id: str | None = None) -> dict:
    r = _host_check(env, state, now_ms, mailbox_id)
    if r["result"] == "refuse" and len(env) >= HEADER_LEN and Header.decode(env).flags & F_STREAM:
        r["stream"] = True
    return r


def _host_check(env: bytes, state: dict, now_ms: int, mailbox_id: str | None) -> dict:
    """§8.6: what the host does with one request envelope, in the normative order. `state` is mutated:
    {"suite", "workspace", "epoch", "wk": {epoch str: hex}, "members": {device hex: scopes},
     "certs": {device hex: {"dk_sig_pub": b64u}}, "revoked": [device hex], "seq": {device hex: {high, bitmap}},
     "rids", "streams", "unverified", "offers": {offer hex: {...}}, "pending_pairs", "wsk_pub", "owner_pk_pub",
     "owner_person_id"}."""
    suite = SUITES[state["suite"]]
    # 1. shape: nothing here needs a key, so nothing here may answer
    if not OVERHEAD <= len(env) <= MAX_REQUEST:
        return _drop("size")
    hb, body, sig = split(env)
    h = Header.decode(hb)
    if h.magic != MAGIC or h.version != VERSION:
        return _drop("version")
    if h.direction != TO_HOST or h.flags & ~F_STREAM:
        return _drop("direction_or_flags")
    if h.suite != suite.id:
        return _drop("suite")
    if h.workspace.hex() != state["workspace"]:
        return _drop("workspace")
    if mailbox_id is not None and mailbox_id != h.rid.hex():
        return _drop("mailbox_mismatch")
    # 2. the channel key: epoch 0 is pairing (K_pair of the offer named in `stream`), else K_bridge(epoch)
    if h.epoch > state["epoch"]:
        return _drop("future_epoch")
    k = bridge_key(state, h)
    if k is None:
        return _drop("no_key")
    # 3. the tag
    try:
        pt = open_body(k, hb, body)
    except InvalidTag:
        return _drop("tag")
    if h.epoch == 0:
        return _pairing(state, suite, h, hb, body, sig, pt, now_ms)
    # 4. who signed it
    did = h.device.hex()
    if did in state["revoked"]:
        return _unverified(state, now_ms, "revoked")
    if did not in state["members"]:
        return _unverified(state, now_ms, "not_member")
    pub = unb64u(state["certs"][did]["dk_sig_pub"])
    if not suite.verify(pub, sig, bridge_signed(hb, body)):
        return _unverified(state, now_ms, "bad_signature")
    dev = state["seq"].setdefault(did, {"high": 0, "bitmap": 0})
    # 5. a known request id
    rid = h.rid.hex()
    known = state["rids"].get(rid)
    if known is not None and now_ms < known["until"]:
        if known["device"] == did and known["digest"] == digest(env).hex():
            out = known["outcome"]
            if out is None:
                return _refuse("already_done", status="unknown")
            if "refusal" in out:
                extra = {k_: v for k_, v in out.items() if k_ != "refusal"}
                if "host_ms" in extra:
                    extra["host_ms"] = now_ms
                if "high" in extra:
                    extra["high"] = dev["high"]
                if "epoch" in extra:
                    extra["epoch"] = state["epoch"]
                return _refuse(out["refusal"], **extra)
            if out.get("body_stored") is False:
                return _refuse("already_done", status=out["status"])
            return {"result": "replay", "outcome": out}
        return _refuse("rid_conflict")
    try:
        return _record_and_run(state, h, env, pt, dev, did, rid, now_ms)
    except StoreFull:
        return _drop("store_full")
    except DeviceFull:
        return _drop("busy_unrecordable")


def _record_and_run(state, h, env, pt, dev, did, rid, now_ms):
    if _count_for(state, did, now_ms) >= _limits(state)["per_device"]:
        return _recorded_refusal(state, h, env, now_ms, "busy")
    try:
        meta, data = unframe(pt)
        if not isinstance(meta.get("op"), str):
            raise ValueError("no op")
    except (ValueError, UnicodeDecodeError):
        return _recorded_refusal(state, h, env, now_ms, "malformed")
    if not seq_accept(dev, h.seq):
        return _recorded_refusal(state, h, env, now_ms, "stale_sequence", high=dev["high"])
    if abs(now_ms - h.ts_ms) > WINDOW_MS:
        return _recorded_refusal(state, h, env, now_ms, "stale_timestamp", host_ms=now_ms)
    if h.epoch != state["epoch"]:                                   # §8.5: old epoch, never served
        return _recorded_refusal(state, h, env, now_ms, "stale_epoch", epoch=state["epoch"])
    streams = state.setdefault("streams", {})
    if h.stream != ZERO_ID and streams.get(h.stream.hex()) != did:
        return _recorded_refusal(state, h, env, now_ms, "forbidden_scope")
    _record(state, h, env, now_ms, None)
    if h.flags & F_STREAM:
        streams[rid] = did
    return {"result": "accept", "scopes": state["members"][did], "meta": meta, "data": data.hex()}


def clean_label(s: str) -> str:
    """Pairing labels and `shown` text (§8.7, carried over from bridge v1 §9.3)."""
    if any(0xD800 <= ord(c) <= 0xDFFF for c in s):
        raise ValueError("not Unicode scalar values")
    return "".join(c for c in s if c == "\n" or not (
        unicodedata.category(c) in {"Cc", "Cf", "Zl", "Zp", "Co", "Cn"} or _ignorable(ord(c))))[:MAX_LABEL]


_IGNORABLE = ((0x00AD, 0x00AD), (0x034F, 0x034F), (0x061C, 0x061C), (0x115F, 0x1160), (0x17B4, 0x17B5),
              (0x180B, 0x180F), (0x200B, 0x200F), (0x202A, 0x202E), (0x2060, 0x206F), (0x3164, 0x3164),
              (0xFE00, 0xFE0F), (0xFEFF, 0xFEFF), (0xFFA0, 0xFFA0), (0xFFF0, 0xFFF8), (0x1BCA0, 0x1BCA3),
              (0x1D173, 0x1D17A), (0xE0000, 0xE0FFF))


def _ignorable(o):
    return any(a <= o <= b for a, b in _IGNORABLE)


def _pairing(state, suite, h, hb, body, sig, pt, now_ms):
    """§8.3: an epoch-0 envelope; the tag under K_pair verified, so the sender holds the offer's secret."""
    offer = state["offers"][h.stream.hex()]
    wsk_pub = state["wsk_pub"]
    ob = {"bucket": offer, "limit": OFFER_BUDGET, "wsk_pub": wsk_pub}
    try:
        meta, _ = unframe(pt)
        op = meta.get("op")
    except (ValueError, UnicodeDecodeError):
        return _unverified(state, now_ms, "malformed", **ob)
    held = state.setdefault("pending_pairs", {}).get(h.device.hex())
    if op == "pair_status":
        if held is None or held["offer_id"] != h.stream.hex():
            return _unverified(state, now_ms, "pairing_closed", **ob)
        if not suite.verify(unb64u(held["dk_sig_pub"]), sig, bridge_signed(hb, body)):
            return _unverified(state, now_ms, "bad_signature", **ob)
        if abs(now_ms - h.ts_ms) > WINDOW_MS:
            return _unverified(state, now_ms, "stale_timestamp", host_ms=now_ms, **ob)
        return {"result": "pair_status", "answer": pair_status_answer(state, held, now_ms)}
    if op != "pair":
        return _unverified(state, now_ms, "malformed", **ob)
    try:
        if set(meta) != {"op", "dk_sig_pub", "dk_kx_pub", "label", "cert"}:
            raise ValueError("fields")
        sig_pub = unb64u(meta["dk_sig_pub"], suite.sig_pub_len)
        kx_pub = unb64u(meta["dk_kx_pub"], suite.kx_pub_len)
        if not suite.sig_pub_ok(sig_pub) or not suite.kx_pub_ok(kx_pub) or not isinstance(meta["label"], str):
            raise ValueError("keys")
        label = clean_label(meta["label"])
    except (ValueError, TypeError):
        return _unverified(state, now_ms, "malformed", **ob)
    resend = held is not None and held["offer_id"] == h.stream.hex() and held["dk_sig_pub"] == b64u(sig_pub) \
        and held["dk_kx_pub"] == b64u(kx_pub)
    if now_ms >= offer["expires_ms"] or (offer.get("used") and not resend):
        return _unverified(state, now_ms, "pairing_closed", **ob)
    if device_id(suite, sig_pub) != h.device or not suite.verify(sig_pub, sig, bridge_signed(hb, body)):
        return _unverified(state, now_ms, "bad_signature", **ob)
    if abs(now_ms - h.ts_ms) > WINDOW_MS:
        return _unverified(state, now_ms, "stale_timestamp", host_ms=now_ms, **ob)
    if resend:
        return {"result": "pair_pending", "answer": pending_answer(state, held)}
    cert_state = "needed"
    if meta["cert"] is not None:                               # a phone that is already one of the owner's devices
        o = meta["cert"].get("o") if isinstance(meta["cert"], dict) else None
        if isinstance(o, dict) and o.get("person_id") != state["owner_person_id"]:
            return _unverified(state, now_ms, "other_person", **ob)       # D1 C is out of scope (§8.3)
        c = verify_cert(suite, meta["cert"], unb64u(state["owner_pk_pub"]), now_ms, set(state["revoked"]))
        if "refuse" in c:
            return _unverified(state, now_ms, c["refuse"], **ob)
        if c["ok"]["dk_sig_pub"] != b64u(sig_pub) or c["ok"]["dk_kx_pub"] != b64u(kx_pub):
            return _unverified(state, now_ms, "cert_invalid", **ob)
        cert_state = "present"
    offer["used"] = True
    held = {"offer_id": h.stream.hex(), "dk_sig_pub": b64u(sig_pub), "dk_kx_pub": b64u(kx_pub), "label": label,
            "sas_nonce": offer["sas_nonce"], "state": "pending", "cert": meta["cert"], "cert_state": cert_state}
    state["pending_pairs"][h.device.hex()] = held
    return {"result": "pair_pending", "label": label, "cert_state": cert_state,
            "sas": sas(suite, h.workspace, h.stream, sig_pub, kx_pub, unb64u(wsk_pub), unb64u(offer["sas_nonce"])),
            "answer": pending_answer(state, held)}


def pending_answer(state, held) -> dict:
    """§8.3 step 3: exactly five fields."""
    return {"state": "pending", "wsk_pub": state["wsk_pub"], "sas_nonce": held["sas_nonce"],
            "dk_sig_pub": held["dk_sig_pub"], "dk_kx_pub": held["dk_kx_pub"]}


def pair_status_answer(state, held, now_ms) -> dict:
    """§8.3 step 5: one of six shapes; every one carries wsk_pub, so the device can check it against the
    link's pin before anything else (§8.3 step 4)."""
    s, w = held["state"], state["wsk_pub"]
    if s == "pending":
        return pending_answer(state, held)
    if s == "cert_pending" and now_ms >= held["cert_pending_since"] + CERT_PENDING_MS:
        return {"state": "expired", "wsk_pub": w}
    if s == "cert_pending":
        return {"state": "cert_pending", "primary_label": held["primary_label"], "pk_pub": state["owner_pk_pub"],
                "challenge": held.get("challenge"), "wsk_pub": w}
    if s == "approved":
        return {"state": "approved", "scopes": held["scopes"], "cert": held["cert"], "pk_pub": state["owner_pk_pub"],
                "epoch": state["epoch"], "wsk_pub": w}
    return {"state": s, "wsk_pub": w}                     # rejected, expired


# --- the device side ---------------------------------------------------------------------------------

def device_check(env: bytes, c: dict, mailbox: dict, now_ms: int) -> dict:
    """§8.8. c: {"suite", "workspace", "device", "wsk_pub", "wk": {epoch: hex}, "pending": {rid hex: {next,
    stream, epoch}}, "offset_ms"}."""
    suite = SUITES[c["suite"]]
    if not OVERHEAD <= len(env) <= MAX_CHUNK:
        return _drop("size")
    hb, body, sig = split(env)
    h = Header.decode(hb)
    if h.magic != MAGIC or h.version != VERSION or h.direction != TO_DEVICE or h.flags & ~(F_LAST | F_STREAM | F_REFUSAL):
        return _drop("version_direction_or_flags")
    if h.flags & F_REFUSAL and not h.flags & F_LAST:
        return _drop("flags")
    if h.suite != suite.id or h.workspace.hex() != c["workspace"] or h.device.hex() != c["device"]:
        return _drop("not_for_this_device")
    pend = c["pending"].get(h.rid.hex())
    if pend is None:
        return _drop("unknown_request")
    if h.epoch != pend["epoch"]:
        return _drop("epoch_mismatch")
    if (mailbox["id"], mailbox["idx"], mailbox["last"], mailbox["stream"]) != \
            (h.rid.hex(), h.seq, bool(h.flags & F_LAST), bool(h.flags & F_STREAM)) or pend["stream"] != mailbox["stream"]:
        return _drop("mailbox_mismatch")
    k = k_bridge(bytes.fromhex(c["wk"][str(h.epoch)]), h.workspace, h.epoch)
    if not suite.verify(unb64u(c["wsk_pub"]), sig, bridge_signed(hb, body)):
        try:
            open_body(k, hb, body)
            pin_failure = True
        except InvalidTag:
            pin_failure = False
        return {**_drop("host_signature"), "pin_failure": pin_failure}
    try:
        meta, data = unframe(open_body(k, hb, body))
    except (InvalidTag, ValueError, UnicodeDecodeError):
        return _drop("tag")
    if h.seq != pend["next"]:
        return _drop("out_of_order")
    res = {"result": "accept", "last": bool(h.flags & F_LAST), "refusal": bool(h.flags & F_REFUSAL), "meta": meta,
           "data": data.hex()}
    if h.flags & F_REFUSAL and meta.get("refusal") == "stale_timestamp" and type(meta.get("host_ms")) is int:
        if not pend.get("offset_adopted"):
            pend["offset_adopted"] = True
            off = meta["host_ms"] - now_ms
            if abs(off) <= MAX_OFFSET_MS:
                res["offset_ms"] = off
            else:
                res["clock_wrong"] = True
    elif abs(now_ms + c.get("offset_ms", 0) - h.ts_ms) > WINDOW_MS:
        return _drop("stale_timestamp")
    if h.flags & F_REFUSAL and meta.get("refusal") == "stale_epoch":
        # §8.5: only a strictly higher epoch sends the device to fetch grants; it never moves backwards
        if type(meta.get("epoch")) is not int or meta["epoch"] <= h.epoch:
            return _drop("stale_epoch_not_higher")
        res["fetch_grants"] = True
    pend["next"] += 1
    return res


def open_pair_answer(env: bytes, c: dict, now_ms: int) -> dict:
    """§8.3 step 4: every answer to an epoch-0 request, before the device has pinned anything but the link.
    c: {"suite", "workspace", "device", "offer", "secret", "wsk_pin", "pk_pin", "dk_sig_pub", "dk_kx_pub",
    "pending": {rid hex: {next}}, "offset_ms"}."""
    suite = SUITES[c["suite"]]
    if not OVERHEAD <= len(env) <= MAX_CHUNK:
        return _drop("size")
    hb, body, sig = split(env)
    h = Header.decode(hb)
    if h.magic != MAGIC or h.version != VERSION or h.direction != TO_DEVICE or h.flags not in (F_LAST, F_LAST | F_REFUSAL):
        return _drop("version_direction_or_flags")
    if h.suite != suite.id or h.workspace.hex() != c["workspace"] or h.device.hex() != c["device"] \
            or h.epoch != 0 or h.stream.hex() != c["offer"]:
        return _drop("not_for_this_device")
    pend = c["pending"].get(h.rid.hex())
    if pend is None:
        return _drop("unknown_request")
    k = k_pair(bytes.fromhex(c["secret"]), h.workspace, h.stream)
    try:
        meta, _ = unframe(open_body(k, hb, body))
        wsk_pub = unb64u(meta["wsk_pub"], suite.sig_pub_len)
    except (InvalidTag, ValueError, KeyError, TypeError, UnicodeDecodeError):
        return _drop("tag_or_meta")
    if not hmac.compare_digest(wsk_pin(suite, wsk_pub), bytes.fromhex(c["wsk_pin"])):
        return _drop("wsk_pin")
    if not suite.verify(wsk_pub, sig, bridge_signed(hb, body)):
        return _drop("host_signature")
    if h.seq != pend["next"]:
        return _drop("out_of_order")
    refusal = bool(h.flags & F_REFUSAL)
    if refusal and not isinstance(meta.get("refusal"), str):
        return _drop("not_a_pairing_answer")
    res = {"result": "accept", "wsk_pub": b64u(wsk_pub)}
    if refusal and meta["refusal"] == "stale_timestamp" and type(meta.get("host_ms")) is int:
        # the one answer exempt from the window: it says this device's clock is off (§5.1 of bridge v1)
        res["refusal"] = "stale_timestamp"
        if not pend.get("offset_adopted"):
            pend["offset_adopted"] = True
            off = meta["host_ms"] - now_ms
            if abs(off) <= MAX_OFFSET_MS:
                res["offset_ms"] = off
            else:
                res["clock_wrong"] = True
        pend["next"] += 1
        return res
    if abs(now_ms + c.get("offset_ms", 0) - h.ts_ms) > WINDOW_MS:   # every other answer, refusals included
        return _drop("stale_timestamp")
    if refusal:
        res["refusal"] = meta["refusal"]
        pend["next"] += 1
        return res
    st = meta.get("state")
    if st == "pending":
        if meta.get("dk_sig_pub") != c["dk_sig_pub"] or meta.get("dk_kx_pub") != c["dk_kx_pub"]:
            return {**_drop("not_my_key"), "alarm": True}           # the host is pairing someone else's key
        try:
            nonce = unb64u(meta.get("sas_nonce"), 32)
        except ValueError:
            return _drop("not_a_pairing_answer")
        res["state"] = "pending"
        res["sas"] = sas(suite, h.workspace, h.stream, unb64u(c["dk_sig_pub"]), unb64u(c["dk_kx_pub"]),
                         wsk_pub, nonce)
    elif st in ("cert_pending", "approved"):
        try:
            pk_pub = unb64u(meta["pk_pub"], suite.sig_pub_len)
        except (ValueError, KeyError):
            return _drop("not_a_pairing_answer")
        if not hmac.compare_digest(pk_pin(suite, pk_pub), bytes.fromhex(c["pk_pin"])):
            return _drop("pk_pin")
        if st == "cert_pending":
            res.update(state="cert_pending", primary_label=meta.get("primary_label"))
            if meta.get("challenge") is not None:
                v = check_cert_challenge(suite, meta["challenge"], pk_pub, c, now_ms + c.get("offset_ms", 0))
                if "drop" in v:
                    return {**_drop(v["drop"]), **({"alarm": True} if v["drop"] == "not_my_key" else {})}
                res["cert_code"] = v["cert_code"]
        else:
            v = verify_cert(suite, meta.get("cert"), pk_pub, now_ms + c.get("offset_ms", 0))
            if "refuse" in v or v["ok"]["dk_sig_pub"] != c["dk_sig_pub"] or v["ok"]["dk_kx_pub"] != c["dk_kx_pub"]:
                return _drop("cert")
            if not scopes_ok(meta.get("scopes")) or type(meta.get("epoch")) is not int:
                return _drop("not_a_pairing_answer")
            res.update(state="approved", scopes=meta["scopes"], epoch=meta["epoch"], device_id=v["ok"]["device_id"])
    elif st in ("rejected", "expired"):
        res["state"] = st
    else:
        return _drop("not_a_pairing_answer")
    pend["next"] += 1
    return res


_FRAGMENT = re.compile(r"#?v2\.([0-9a-f]{32})\.([0-9a-f]{32})\.([A-Za-z0-9_-]{43})\.([A-Za-z0-9_-]{43})\.([A-Za-z0-9_-]{43})")


def parse_pair_fragment(fragment):
    """§8.3 step 1, strictly."""
    m = _FRAGMENT.fullmatch(fragment) if isinstance(fragment, str) else None
    if not m:
        return None
    try:
        s, wp, pp = (unb64u(m.group(i), 32) for i in (3, 4, 5))
    except ValueError:
        return None
    return {"workspace": m.group(1), "offer": m.group(2), "secret": s.hex(), "wsk_pin": wp.hex(), "pk_pin": pp.hex()}


def make_cert_request(suite: Suite, wsk, ws: bytes, person: bytes, primary: bytes, primary_kx_pub: bytes,
                      request_id: bytes, inner: dict, created_ms: int, eph_seed: bytes) -> dict:
    """§8.4. inner = {device_id, dk_sig_pub, dk_kx_pub, label, scopes_max, offer_id}: no host nonce, so the
    host has nothing to grind the code with (R1)."""
    sealed = seal_to(suite, primary_kx_pub, primary, "cert-request", request_id, 0, cj(inner), eph_seed)
    return sign_object(suite, wsk, {"v": 2, "suite": suite.id, "kind": "cert_request", "request_id": request_id.hex(),
                                    "workspace_id": ws.hex(), "person_id": person.hex(), "primary_device_id": primary.hex(),
                                    "created_ms": created_ms, "expires_ms": created_ms + CERT_PENDING_MS,
                                    "sealed": b64u(sealed)})


def primary_open_cert_request(suite: Suite, signed, card: dict, my_person: bytes, me: bytes, my_kx_priv,
                              prim: dict, now_ms: int) -> dict:
    """§8.4: what the owner's primary device checks before it draws its nonce and signs a challenge.
    card: the workspace's verified card (with its delegation). prim (mutated on success): {"seen": [request
    ids], "open": {workspace hex: request id}}."""
    card_o, deleg = card["o"], card["delegation"]["o"]
    if card_o["owner_person_id"] != my_person.hex():
        return {"refuse": "other_person"}
    o = verify_object(suite, unb64u(card_o["wsk_pub"]), signed, "cert_request")
    if o is None or o["workspace_id"] != card_o["workspace_id"]:
        return {"refuse": "bad_signature"}
    if o["primary_device_id"] != me.hex() or o["person_id"] != my_person.hex():
        return {"refuse": "not_for_this_device"}
    if not o["created_ms"] - SKEW_MS <= now_ms < o["expires_ms"] or o["expires_ms"] - o["created_ms"] > CERT_PENDING_MS:
        return {"refuse": "expired"}
    if o["request_id"] in prim["seen"]:
        return {"refuse": "replayed"}
    if o["workspace_id"] in prim["open"]:
        return {"refuse": "request_open"}                # at most one open request per workspace
    try:
        inner = parse_json(open_sealed(suite, my_kx_priv, me, "cert-request", unhex(o["request_id"], 16), 0,
                                       unb64u(o["sealed"])))
        if set(inner) != {"device_id", "dk_sig_pub", "dk_kx_pub", "label", "scopes_max", "offer_id"}:
            raise ValueError("fields")
        sig_pub = unb64u(inner["dk_sig_pub"], suite.sig_pub_len)
        kx_pub = unb64u(inner["dk_kx_pub"], suite.kx_pub_len)
        unhex(inner["offer_id"], 16)
    except (InvalidTag, ValueError, KeyError, TypeError):
        return {"refuse": "malformed"}
    if inner["device_id"] != device_id(suite, sig_pub).hex() or not suite.sig_pub_ok(sig_pub) \
            or not suite.kx_pub_ok(kx_pub) or not scopes_ok(inner["scopes_max"]):
        return {"refuse": "malformed"}
    if inner["scopes_max"][0].startswith("drop:"):
        return {"refuse": "scope_exceeded"}              # scoped agents enrol through §6.4 only
    prim["seen"].append(o["request_id"])
    prim["open"][o["workspace_id"]] = o["request_id"]
    return {"ok": inner, "warning": "client_hosted" if deleg["client_hosted"] else None}


CHALLENGE_FIELDS = {"v", "suite", "kind", "request_id", "workspace_id", "person_id", "device_id", "dk_sig_pub",
                    "dk_kx_pub", "primary_nonce", "expires_ms"}


def cert_sas(suite: Suite, challenge_o: dict) -> str:
    """§8.4: the code the primary and the phone both show; the primary's nonce was drawn after the keys
    reached it, and only PK can sign the challenge, so nobody can grind it."""
    return base64.b32encode(H(L["h_sas_cert"] + bytes([suite.id]) + cj(challenge_o))).decode()[:6]


def make_cert_challenge(suite: Suite, pk, request_o: dict, inner: dict, primary_nonce: bytes) -> dict:
    assert len(primary_nonce) == 32
    return sign_object(suite, pk, {"v": 2, "suite": suite.id, "kind": "cert_challenge",
                                   "request_id": request_o["request_id"], "workspace_id": request_o["workspace_id"],
                                   "person_id": request_o["person_id"], "device_id": inner["device_id"],
                                   "dk_sig_pub": inner["dk_sig_pub"], "dk_kx_pub": inner["dk_kx_pub"],
                                   "primary_nonce": b64u(primary_nonce), "expires_ms": request_o["expires_ms"]})


def primary_issue_challenge(suite: Suite, pk, prim: dict, request_o: dict, inner: dict, primary_nonce: bytes) -> dict:
    """§8.4: the primary draws primary_nonce (32 CSPRNG bytes) only now, after the keys reached it, keeps the
    challenge as the only thing it will ever certify for this request, and posts it to (ws, request_id)."""
    ch = make_cert_challenge(suite, pk, request_o, inner, primary_nonce)
    prim.setdefault("challenges", {})[request_o["request_id"]] = ch["o"]
    return ch


def check_cert_challenge(suite: Suite, signed, pk_pub: bytes, c: dict, now_ms: int) -> dict:
    """§8.4, on the phone: the challenge the host relayed must be PK's, for this workspace, for this device's
    own two keys (else the alarm: someone asked the primary to certify another key), and unexpired."""
    o = verify_object(suite, pk_pub, signed, "cert_challenge")
    if o is None or set(o) != CHALLENGE_FIELDS:
        return {"drop": "challenge_signature"}
    if o["workspace_id"] != c["workspace"] or o["person_id"] != person_id(suite, pk_pub).hex():
        return {"drop": "not_for_this_workspace"}
    if o["dk_sig_pub"] != c["dk_sig_pub"] or o["dk_kx_pub"] != c["dk_kx_pub"] or o["device_id"] != c["device"]:
        return {"drop": "not_my_key"}
    if type(o["expires_ms"]) is not int or now_ms >= o["expires_ms"]:
        return {"drop": "challenge_expired"}
    return {"ok": o, "cert_code": cert_sas(suite, o)}


def primary_sign_cert(suite: Suite, pk, prim: dict, request_id: str, label_sealed: str, created_ms: int,
                      expires_ms, scopes_max: list) -> dict:
    """§8.4: after the human confirmed the code, the primary certifies exactly the keys of ITS OWN stored
    challenge for that request, once. prim: {"challenges": {request id: challenge o}, "signed": [ids], "open"}."""
    ch = prim["challenges"].get(request_id)
    if ch is None:
        return {"refuse": "unknown_request"}
    if request_id in prim.setdefault("signed", []):
        return {"refuse": "already_signed"}
    prim["signed"].append(request_id)
    prim["open"].pop(ch["workspace_id"], None)
    return {"ok": sign_object(suite, pk, {"v": 2, "suite": suite.id, "kind": "device_cert",
                                          "device_id": ch["device_id"], "person_id": ch["person_id"],
                                          "dk_sig_pub": ch["dk_sig_pub"], "dk_kx_pub": ch["dk_kx_pub"],
                                          "label_sealed": label_sealed, "created_ms": created_ms,
                                          "expires_ms": expires_ms, "scopes_max": scopes_max})}


def enroll_mac(code: bytes, suite: Suite, space: bytes, dk_sig_pub: bytes, dk_kx_pub: bytes) -> bytes:
    return hmac.new(code, L["mac_enroll"] + bytes([suite.id]) + space + lp16(dk_sig_pub) + lp16(dk_kx_pub),
                    hashlib.sha256).digest()


# --- WebAuthn challenges (§8.7, bridge v1 §9 with v2 labels) ------------------------------------------

SCOPES = {"look": 1, "decide": 2, "operate": 3, "type": 4}
PURPOSES = {"fresh": 1, "lease": 2}


def assertion_challenge(ws: bytes, dev: bytes, rid: bytes, epoch: int, purpose: str, scope: str, expires_ms: int,
                        nonce: bytes, subject: dict) -> bytes:
    return H(L["h_assert"] + ws + dev + rid + u32(epoch) + bytes([PURPOSES[purpose], SCOPES[scope]])
             + u64(expires_ms) + nonce + H(cj(subject)))


def registration_challenge(ws: bytes, dev: bytes, expires_ms: int, nonce: bytes) -> bytes:
    return H(L["h_webauthn_reg"] + ws + dev + u64(expires_ms) + nonce)


def question_hash(content: dict) -> bytes:
    return H(L["h_question"] + cj(content))


def decision_signed_bytes(ws_hex: str, d: dict) -> bytes:
    return L["sig_decision"] + cj({"workspace_id": ws_hex, "question_id": d["question_id"],
                                   "content_hash": d["content_hash"], "decision_id": d["decision_id"],
                                   "answer": d["answer"]})


def sign_decision(suite: Suite, dk, ws_hex: str, d: dict) -> dict:
    """§13: the decision op's meta, with a detached device signature that survives outside the bridge."""
    return {"op": "decision", **d, "sig": b64u(suite.sign(dk, decision_signed_bytes(ws_hex, d)))}


def host_check_decision(suite: Suite, meta: dict, ws_hex: str, dk_sig_pub: bytes) -> dict:
    try:
        if set(meta) != {"op", "decision_id", "question_id", "content_hash", "answer", "sig"}:
            return {"refuse": "malformed"}
        unhex(meta["decision_id"], 16), unhex(meta["question_id"], 16), unb64u(meta["content_hash"], 32)
        sig = unb64u(meta["sig"], 64)
    except (ValueError, TypeError):
        return {"refuse": "malformed"}
    if not suite.verify(dk_sig_pub, sig, decision_signed_bytes(ws_hex, meta)):
        return {"refuse": "bad_signature"}
    return {"ok": True}


def host_revocation(suite: Suite, state: dict, meta: dict) -> dict:
    """§6.2: the bridge op {"op": "revocation", "record": <signed revocation>}. Authority is PK's signature,
    whoever relays it. The host records it and rotates when the device was a member (mutates state)."""
    if not isinstance(meta, dict) or set(meta) != {"op", "record"}:
        return {"refuse": "malformed"}
    o = verify_object(suite, unb64u(state["owner_pk_pub"]), meta["record"], "revocation")
    if o is None:
        return {"refuse": "bad_signature"}
    if set(o) != {"v", "suite", "kind", "person_id", "device_id", "revoked_ms", "reason"} \
            or o["reason"] not in REVOKE_REASONS or type(o["revoked_ms"]) is not int:
        return {"refuse": "malformed"}
    if o["person_id"] != state["owner_person_id"]:
        return {"refuse": "other_person"}
    did = o["device_id"]
    if did not in state["revoked"]:
        state["revoked"].append(did)
    was_member = state["members"].pop(did, None) is not None
    return {"ok": did, "rotate": was_member}


# =====================================================================================================
# §9 Push
# =====================================================================================================

PUSH_KINDS = ("question", "question.closed", "ticket.update", "drop.new", "peer.ticket", "join")
MAX_PUSH = 3072
PUSH_MAX_AGE_MS = 24 * 3600 * 1000


def push_signed_bytes(suite, ws: bytes, epoch: int, payload: dict) -> bytes:
    return L["sig_push"] + bytes([suite.id]) + ws + u32(epoch) + cj(payload)


def push_aad(suite, ws, epoch):
    return L["aad_push"] + bytes([suite.id]) + ws + u32(epoch)


def seal_push(suite: Suite, wsk, wk: bytes, ws: bytes, epoch: int, payload: dict, salt: bytes) -> bytes:
    sig = suite.sign(wsk, push_signed_bytes(suite, ws, epoch, payload))
    pt = cj({"p": payload, "sig": b64u(sig)})
    c = salted_seal(k_push(wk, ws, epoch), L["kdf_push_msg"], push_aad(suite, ws, epoch), pt, salt)
    out = cj({"v": 2, "ws": ws.hex(), "epoch": epoch, "c": b64u(c)})
    assert len(out) <= MAX_PUSH
    return out


def sw_open_push(suite: Suite, raw: bytes, keys: dict, last: dict, now_ms: int) -> dict:
    """§9.2: what the service worker does. keys: {ws hex: {"wsk_pub": b64u, "wk": {epoch str: wk hex}}};
    last (mutated): {"<ws hex>/<id>": highest ts_ms shown}."""
    if len(raw) > MAX_PUSH:
        return _drop("size")
    try:
        m = parse_json(raw)
        if not isinstance(m, dict) or set(m) != {"v", "ws", "epoch", "c"} or m["v"] != 2:
            return _drop("shape")
        ws = unhex(m["ws"], 16)
        c = unb64u(m["c"])
    except (ValueError, UnicodeDecodeError):
        return _drop("shape")
    entry = keys.get(m["ws"])
    wk = None if entry is None else entry["wk"].get(str(m["epoch"]))
    if wk is None or type(m["epoch"]) is not int:
        return _drop("no_key")
    try:
        outer = parse_json(salted_open(k_push(bytes.fromhex(wk), ws, m["epoch"]), L["kdf_push_msg"],
                                       push_aad(suite, ws, m["epoch"]), c))
        if not isinstance(outer, dict) or set(outer) != {"p", "sig"} or not isinstance(outer["p"], dict):
            return _drop("payload")
        sig = unb64u(outer["sig"], 64)
    except (InvalidTag, ValueError, UnicodeDecodeError):
        return _drop("tag")
    p = outer["p"]
    if not suite.verify(unb64u(entry["wsk_pub"]), sig, push_signed_bytes(suite, ws, m["epoch"], p)):
        return _drop("signature")                        # a member device cannot speak for the host (R3)
    if set(p) != {"kind", "id", "label", "ts_ms"} or p["kind"] not in PUSH_KINDS:
        return _drop("payload")
    if not isinstance(p["label"], str) or len(p["label"]) > MAX_LABEL or not isinstance(p["id"], str) \
            or type(p["ts_ms"]) is not int:
        return _drop("payload")
    if not now_ms - PUSH_MAX_AGE_MS <= p["ts_ms"] <= now_ms + SKEW_MS:
        return _drop("stale")
    key = f"{m['ws']}/{p['id']}"
    if key in last and p["ts_ms"] <= last[key]:
        return _drop("replay")
    last[key] = p["ts_ms"]
    return {"result": "show", "tag": p["id"], **p}


# =====================================================================================================
# §10 Drop
# =====================================================================================================

DROP_MAGIC = b"ORD2"
DROP_HEADER_LEN = 40
DEFAULT_CHUNK = 1 << 20
MAX_CHUNK_SIZE = 64 << 20


def drop_content_key(dek, obj, ver):
    return hkdf(dek, b"", ctx(LABELS["kdf_drop_content"], obj, ver))


def drop_encrypt(suite: Suite, dek: bytes, obj: bytes, ver: int, pt: bytes, prefix: bytes,
                 chunk: int = DEFAULT_CHUNK) -> bytes:
    """SHR1's chunked layout (TIX crypto.js encryptBlob) under a v2 header and a derived content key."""
    assert len(prefix) == 8 and 0 < chunk <= MAX_CHUNK_SIZE
    hdr = DROP_MAGIC + bytes([2, suite.id, 0, 0]) + obj + u32(ver) + u32(chunk) + prefix
    a = AESGCM(drop_content_key(dek, obj, ver))
    n = max(1, -(-len(pt) // chunk))
    out = [hdr]
    for i in range(n):
        out.append(a.encrypt(prefix + u32(i), pt[i * chunk:(i + 1) * chunk], hdr + u32(i) + bytes([i == n - 1])))
    return b"".join(out)


def drop_decrypt(suite: Suite, dek: bytes, obj: bytes, ver: int, blob: bytes) -> bytes:
    if len(blob) < DROP_HEADER_LEN + 16:
        raise ValueError("truncated")
    hdr = blob[:DROP_HEADER_LEN]
    if hdr[:4] != DROP_MAGIC or hdr[4] != 2 or hdr[5] != suite.id or hdr[6:8] != b"\0\0" or hdr[8:24] != obj \
            or hdr[24:28] != u32(ver):
        raise ValueError("not this object")
    chunk = struct.unpack(">I", hdr[28:32])[0]
    if not 0 < chunk <= MAX_CHUNK_SIZE:
        raise ValueError("bad chunk size")
    body, step = blob[DROP_HEADER_LEN:], chunk + 16
    n = -(-len(body) // step)
    if len(body) - (n - 1) * step < 16:
        raise ValueError("truncated")
    a = AESGCM(drop_content_key(dek, obj, ver))
    return b"".join(a.decrypt(hdr[32:40] + u32(i), body[i * step:(i + 1) * step], hdr + u32(i) + bytes([i == n - 1]))
                    for i in range(n))


def drop_meta_seal(suite, dek, obj, ver, meta: dict) -> bytes:
    k = hkdf(dek, b"", ctx(LABELS["kdf_drop_meta"], obj, ver))
    return AESGCM(k).encrypt(ZERO_NONCE, cj(meta), L["aad_drop_meta"] + bytes([suite.id]) + obj + u32(ver))


def drop_meta_open(suite, dek, obj, ver, sealed: bytes) -> dict:
    k = hkdf(dek, b"", ctx(LABELS["kdf_drop_meta"], obj, ver))
    return parse_json(AESGCM(k).decrypt(ZERO_NONCE, sealed, L["aad_drop_meta"] + bytes([suite.id]) + obj + u32(ver)))


def drop_parent_hash(parent_o: dict) -> bytes:
    return H(L["h_drop_parent"] + cj(parent_o))


def verify_doc_chain(versions: list[dict]) -> dict:
    """§10.6, a reader: descriptor objects (already signature-checked) from version 1 up must chain."""
    for i, o in enumerate(versions):
        want = None if i == 0 else b64u(drop_parent_hash(versions[i - 1]))
        if o["version"] != i + 1 or o["parent_hash"] != want:
            return {"refuse": "fork", "at": o["version"]}
    return {"ok": len(versions)}


def dek_commit(obj: bytes, ver: int, dek: bytes) -> bytes:
    return H(L["h_dek_commit"] + obj + u32(ver) + dek)


def wrap_aad(suite, obj, ver, target_kind: str, target: bytes, key_version: int) -> bytes:
    t = target_kind.encode()
    return L["aad_wrap"] + bytes([suite.id, len(t)]) + t + target + obj + u32(ver) + u32(key_version)


def wrap_dek(suite: Suite, target_kind: str, target: bytes, key_version: int, obj: bytes, ver: int, dek: bytes, *,
             wk: bytes | None = None, sk: bytes | None = None, kx_pub: bytes | None = None,
             salt: bytes | None = None, eph_seed: bytes | None = None) -> dict:
    """§10.3: one wrap record. target_kind: wk (workspace member), sk (shared space), wxk (any workspace),
    device."""
    if target_kind == "wk":
        w = salted_seal(k_wrap_wk(wk, target, key_version), L["kdf_wrap_msg"],
                        wrap_aad(suite, obj, ver, "wk", target, key_version), dek, salt)
    elif target_kind == "sk":
        w = salted_seal(k_wrap_sk(sk, target, key_version), L["kdf_wrap_msg"],
                        wrap_aad(suite, obj, ver, "sk", target, key_version), dek, salt)
    elif target_kind in ("wxk", "device"):
        w = seal_to(suite, kx_pub, target, "drop-dek", obj, key_version, dek, eph_seed,
                    extra_aad=bytes([1 if target_kind == "wxk" else 2]) + u32(ver))
    else:
        raise ValueError(target_kind)
    return {"object_id": obj.hex(), "version": ver, "target_kind": target_kind, "target_id": target.hex(),
            "key_version": key_version, "wrap": b64u(w)}


def unwrap_dek(suite: Suite, rec: dict, *, wk=None, sk=None, kx_priv=None) -> bytes:
    obj, target, kv, ver = (unhex(rec["object_id"], 16), unhex(rec["target_id"], 16), rec["key_version"],
                            rec["version"])
    w = unb64u(rec["wrap"])
    tk = rec["target_kind"]
    if tk == "wk":
        return salted_open(k_wrap_wk(wk, target, kv), L["kdf_wrap_msg"], wrap_aad(suite, obj, ver, "wk", target, kv), w)
    if tk == "sk":
        return salted_open(k_wrap_sk(sk, target, kv), L["kdf_wrap_msg"], wrap_aad(suite, obj, ver, "sk", target, kv), w)
    return open_sealed(suite, kx_priv, target, "drop-dek", obj, kv, w,
                       extra_aad=bytes([1 if tk == "wxk" else 2]) + u32(ver))


DROP_OBJECT_FIELDS = {"v", "suite", "kind", "object_id", "space_id", "space_kind", "object_kind", "version", "parent",
                      "parent_hash", "author_kind", "author_id", "content_hash", "content_len", "dek_commit", "meta",
                      "recipients", "origin", "created_ms", "expires_ms"}


def verify_drop_object(suite: Suite, signed, author_pub: bytes) -> dict:
    o = verify_object(suite, author_pub, signed, "drop_object")
    if o is None:
        return {"refuse": "bad_signature"}
    if set(o) != DROP_OBJECT_FIELDS or o["object_kind"] not in ("file", "document") \
            or o["space_kind"] not in ("personal", "workspace", "shared") or o["origin"] not in ("human", "agent") \
            or o["author_kind"] not in ("device", "workspace"):
        return {"refuse": "malformed"}
    if o["version"] != o["parent"] + 1 or (o["object_kind"] == "file" and o["version"] != 1):
        return {"refuse": "malformed"}
    try:
        if (o["version"] == 1) != (o["parent_hash"] is None) or (o["parent_hash"] is not None
                                                                 and len(unb64u(o["parent_hash"])) != 32):
            return {"refuse": "malformed"}
    except ValueError:
        return {"refuse": "malformed"}
    r = o["recipients"]
    if r != "inbox" and (not isinstance(r, list) or r != sorted(set(r))):
        return {"refuse": "malformed"}
    return {"ok": o}


def relay_claim(suite: Suite, obj_state: dict, signed, cards: dict, epochs: dict) -> dict:
    """§10.5, one transaction. obj_state: {"object_id", "version", "state": "inbox"|"claimed", "claimed_by",
    "wraps": [records]}; cards: {ws hex: card o}; epochs: {ws hex: the workspace's current epoch, from its
    member list}. Mutated only on success."""
    o0 = signed.get("o", {}) if isinstance(signed, dict) else {}
    ws_hex = o0.get("workspace_id") if isinstance(o0, dict) else None
    card = cards.get(ws_hex) if isinstance(ws_hex, str) else None
    if card is None:
        return {"status": 403, "error": "not_eligible"}
    o = verify_object(suite, unb64u(card["wsk_pub"]), signed, "drop_claim")
    if o is None:
        return {"status": 401, "error": "bad_signature"}
    if o["object_id"] != obj_state["object_id"] or set(o) != {"v", "suite", "kind", "object_id", "workspace_id",
                                                               "wrap"}:
        return {"status": 400, "error": "malformed"}
    try:
        w = o["wrap"]
        if set(w) != {"object_id", "version", "target_kind", "target_id", "key_version", "wrap"} \
                or w["target_kind"] != "wk" or w["target_id"] != ws_hex or w["object_id"] != o["object_id"] \
                or w["version"] != obj_state["version"] or w["key_version"] != epochs.get(ws_hex):
            return {"status": 400, "error": "malformed"}
    except (TypeError, AttributeError):
        return {"status": 400, "error": "malformed"}
    if obj_state["state"] == "claimed":
        if obj_state["claimed_by"] == ws_hex:
            return {"status": 200, "claimed_by": ws_hex}          # idempotent
        return {"status": 409, "error": "already_claimed", "claimed_by": obj_state["claimed_by"]}
    if not any(r["target_kind"] == "wxk" and r["target_id"] == ws_hex for r in obj_state["wraps"]):
        return {"status": 403, "error": "not_eligible"}
    obj_state.update(state="claimed", claimed_by=ws_hex, wraps=[w])
    return {"status": 200, "claimed_by": ws_hex}


def relay_put_version(doc: dict, if_match, new_o: dict) -> dict:
    """§10.6: If-Match and the hash chain. doc: {"current": n, "head": descriptor o of version n, or None}.
    The descriptor's signature is checked before this."""
    if not isinstance(if_match, str) or not re.fullmatch(r"0|[1-9][0-9]{0,15}", if_match):
        return {"status": 428, "error": "precondition_required"}
    cur = doc["current"]
    want_parent = None if doc["head"] is None else b64u(drop_parent_hash(doc["head"]))
    if int(if_match) != cur or new_o["parent"] != cur or new_o["version"] != cur + 1 \
            or new_o["parent_hash"] != want_parent:
        return {"status": 409, "error": "version_conflict", "current": cur}
    doc["current"], doc["head"] = cur + 1, new_o
    return {"status": 201, "version": cur + 1}


# =====================================================================================================
# §11 ws→ws envelopes
# =====================================================================================================

WX_MAGIC = b"ORWX"
WX_HEADER = struct.Struct(">4sBBBB16s16s16sI")
WX_HEADER_LEN = WX_HEADER.size                     # 60
F_COSIGNED = 0x01
F_WS_REFUSAL = 0x02
FINAL_KINDS = ("result", "refusal")
MAX_WS_ENVELOPE = 1 << 20
MAX_DEADLINE_MS = 30 * 24 * 3600 * 1000
WXK_OVERLAP_MS = 14 * 24 * 3600 * 1000
SEEN_RETENTION_MS = 7 * 24 * 3600 * 1000
BODY_KINDS = ("ticket", "result", "refusal", "question.closed")
WS_REFUSALS = ("stale_wxk", "depth_exceeded", "deadline_passed", "bad_cosignature", "unknown_reply", "malformed")


def wx_header(suite: Suite, flags: int, env_id: bytes, from_ws: bytes, to_ws: bytes, wxk_version: int) -> bytes:
    return WX_HEADER.pack(WX_MAGIC, 2, suite.id, flags, 0, env_id, from_ws, to_ws, wxk_version)


def ws_envelope_hash(hb: bytes, body: bytes) -> bytes:
    return H(L["h_ws_envelope"] + hb + body)


def build_ws_envelope(suite: Suite, wsk, hb: bytes, body_pt: dict, to_wxk_pub: bytes, eph_seed: bytes,
                      cosig: dict | None = None) -> bytes:
    _, v, s, flags, _, env_id, _, to_ws, wxk_version = WX_HEADER.unpack(hb)
    body = seal_to(suite, to_wxk_pub, to_ws, "ws-envelope", env_id, wxk_version, cj(body_pt), eph_seed, extra_aad=hb)
    sig = suite.sign(wsk, L["sig_ws_envelope"] + hb + body)
    out = hb + u32(len(body)) + body + sig
    if flags & F_COSIGNED:
        c = cj(cosig)
        out += u32(len(c)) + c
    return out


def device_cosign(suite: Suite, dk, cert: dict, hb: bytes, body: bytes) -> dict:
    return {"type": "device", "cert": cert, "sig": b64u(suite.sign(dk, L["sig_ws_cosign"] + ws_envelope_hash(hb, body)))}


def build_ws_refusal(suite: Suite, wsk, me: bytes, refused_id: bytes, sender: bytes, sender_wxk_pub: bytes,
                     sender_wxk_version: int, code: str, env_id: bytes, eph_seed: bytes, now_ms: int, **fields) -> bytes:
    """§11.5: a refusal is an envelope back to the sender with the signed REFUSAL flag."""
    hb = wx_header(suite, F_WS_REFUSAL, env_id, me, sender, sender_wxk_version)
    body = {"kind": "refusal", "in_reply_to": refused_id.hex(), "depth": 0, "deadline_ms": now_ms, "ticket": None,
            "result": None, "refusal": {"code": code, **fields}, "attachments": []}
    return build_ws_envelope(suite, wsk, hb, body, sender_wxk_pub, eph_seed)


def split_ws_envelope(env: bytes):
    if not WX_HEADER_LEN + 4 + 16 + SIG_LEN <= len(env) <= MAX_WS_ENVELOPE:
        raise ValueError("size")
    hb = env[:WX_HEADER_LEN]
    n = struct.unpack(">I", env[WX_HEADER_LEN:WX_HEADER_LEN + 4])[0]
    p = WX_HEADER_LEN + 4
    if p + n + SIG_LEN > len(env):
        raise ValueError("body length")
    body, sig, rest = env[p:p + n], env[p + n:p + n + SIG_LEN], env[p + n + SIG_LEN:]
    return hb, body, sig, rest


def _verify_cosig(suite: Suite, cos: dict, peer: dict, hb: bytes, body: bytes, now_ms: int) -> bool:
    try:
        owner_pk = unb64u(peer["owner_pk_pub"])
        c = verify_cert(suite, cos["cert"], owner_pk, now_ms, set(peer.get("revoked", [])))
        if "refuse" in c or c["ok"]["scopes_max"][0].startswith("drop:"):
            return False
        dk_pub = unb64u(c["ok"]["dk_sig_pub"])
        eh = ws_envelope_hash(hb, body)
        if cos["type"] == "device":
            return set(cos) == {"type", "cert", "sig"} and suite.verify(dk_pub, unb64u(cos["sig"], 64),
                                                                          L["sig_ws_cosign"] + eh)
        if cos["type"] != "webauthn":
            return False
        if set(cos) != {"type", "cert", "credential_id", "credential_pub", "bind_sig", "rp_id", "origin",
                        "authenticator_data", "client_data_json", "signature"}:
            return False
        cred_id, cred_pub = unb64u(cos["credential_id"]), unb64u(cos["credential_pub"], 65)
        if not suite.verify(dk_pub, unb64u(cos["bind_sig"], 64), L["sig_webauthn_bind"] + lp16(cred_id) + cred_pub):
            return False
        rp = re.sub(r"^https?://", "", peer["relay_url"]).split(":")[0]
        if cos["rp_id"] != rp or cos["origin"] != peer["relay_url"]:
            return False
        ad, cdj = unb64u(cos["authenticator_data"]), unb64u(cos["client_data_json"])
        cd = json.loads(cdj)
        if cd.get("type") != "webauthn.get" or cd.get("origin") != cos["origin"] or cd.get("crossOrigin") \
                or unb64u(cd.get("challenge"), 32) != eh:
            return False
        if len(ad) < 37 or ad[:32] != H(cos["rp_id"].encode()) or ad[32] & 0x05 != 0x05:
            return False
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), cred_pub).verify(
            unb64u(cos["signature"]), ad + H(cdj), ec.ECDSA(hashes.SHA256()))
        return True
    except (ValueError, KeyError, TypeError, InvalidSignature, AttributeError):
        return False


def ws_receive(env: bytes, st: dict, now_ms: int) -> dict:
    """§11.4, the receiver's order. st: {"suite", "workspace", "wxk": {version str: {"seed", "retired_ms"}},
    "wxk_version", "peers": {ws hex: {wsk_pub, owner_pk_pub, relay_url, revoked}}, "seen": {"<from>/<id>":
    {digest, outcome, until}}, "sent": {id hex: {"to": ws hex, "consumed": [kinds]}}}."""
    suite = SUITES[st["suite"]]
    try:
        hb, body, sig, rest = split_ws_envelope(env)
    except ValueError:
        return _drop("size")
    magic, v, s, flags, res, env_id, from_ws, to_ws, wxk_version = WX_HEADER.unpack(hb)
    if magic != WX_MAGIC or v != 2 or res != 0 or flags & ~(F_COSIGNED | F_WS_REFUSAL):
        return _drop("shape")
    if s != suite.id:
        return _drop("suite")
    if to_ws.hex() != st["workspace"]:
        return _drop("not_for_us")
    peer = st["peers"].get(from_ws.hex())
    if peer is None:
        return _drop("not_pinned")
    if not suite.verify(unb64u(peer["wsk_pub"]), sig, L["sig_ws_envelope"] + hb + body):
        return _drop("signature")
    is_refusal = bool(flags & F_WS_REFUSAL)
    d = H(hb + body).hex()
    seen_key = f"{from_ws.hex()}/{env_id.hex()}"
    seen = st["seen"].get(seen_key)
    if seen is not None and now_ms < seen["until"]:
        if seen["digest"] != d:
            return _drop("id_conflict")
        return {"result": "duplicate", "outcome": seen["outcome"]}

    def done(r, deadline=None):
        if is_refusal and r["result"] == "refuse":       # §11.5: a refusal is never answered
            r = _drop(r["code"])
        st["seen"][seen_key] = {"digest": d, "outcome": r, "until": max(now_ms, deadline or 0) + SEEN_RETENTION_MS}
        return r

    if flags & F_COSIGNED:
        try:
            if len(rest) < 4 or struct.unpack(">I", rest[:4])[0] != len(rest) - 4:
                raise ValueError("cosig length")
            cos = parse_json(rest[4:])
            ok = isinstance(cos, dict) and _verify_cosig(suite, cos, peer, hb, body, now_ms)
        except (ValueError, UnicodeDecodeError):
            ok = False
        if not ok:
            return done(_refuse("bad_cosignature"))
    elif rest:
        return _drop("trailing_bytes")
    key = st["wxk"].get(str(wxk_version))
    if key is None or (key.get("retired_ms") is not None and now_ms >= key["retired_ms"] + WXK_OVERLAP_MS):
        return done(_refuse("stale_wxk", wxk_version=st["wxk_version"]))
    try:
        p = parse_json(open_sealed(suite, suite.kx_key(bytes.fromhex(key["seed"])), to_ws, "ws-envelope", env_id,
                                   wxk_version, body, extra_aad=hb))
        if not isinstance(p, dict) or set(p) != {"kind", "in_reply_to", "depth", "deadline_ms", "ticket", "result",
                                                 "refusal", "attachments"} or p["kind"] not in BODY_KINDS:
            raise ValueError("body")
        if type(p["depth"]) is not int or type(p["deadline_ms"]) is not int or not isinstance(p["attachments"], list):
            raise ValueError("body")
        if (p["kind"] == "refusal") != is_refusal:       # the signed flag and the sealed kind agree
            raise ValueError("refusal flag")
        if is_refusal and (not isinstance(p["refusal"], dict) or p["refusal"].get("code") not in WS_REFUSALS):
            raise ValueError("refusal body")
    except (InvalidTag, ValueError, UnicodeDecodeError):
        return done(_refuse("malformed"))
    if p["kind"] == "ticket":
        if p["ticket"] is None or p["depth"] < 0 or p["in_reply_to"] is not None:
            return done(_refuse("malformed"))
        if p["depth"] > 1:
            return done(_refuse("depth_exceeded"))
        if p["deadline_ms"] > now_ms + MAX_DEADLINE_MS:
            return done(_refuse("malformed"))
        if p["deadline_ms"] + SKEW_MS < now_ms:
            return done(_refuse("deadline_passed"))
        return done({"result": "inbox", "kind": "ticket", "from": from_ws.hex(), "depth": p["depth"]}, p["deadline_ms"])
    # a reply: it must answer an envelope we sent to this peer, and each kind of reply is taken once (§11.4)
    sent = st["sent"].get(p["in_reply_to"]) if isinstance(p["in_reply_to"], str) else None
    group = FINAL_KINDS if p["kind"] in FINAL_KINDS else (p["kind"],)
    if sent is None or sent["to"] != from_ws.hex() or any(k_ in sent["consumed"] for k_ in group):
        return done(_refuse("unknown_reply"))
    sent["consumed"].append(p["kind"])
    r = {"result": "deliver", "kind": p["kind"], "in_reply_to": p["in_reply_to"],
         "late": p["kind"] == "result" and p["deadline_ms"] + SKEW_MS < now_ms}
    if is_refusal:
        r["code"] = p["refusal"]["code"]
    return done(r, p["deadline_ms"])


# =====================================================================================================
# §12 Publish request signing, relay authentication
# =====================================================================================================

PUBLISH_WINDOW_MS = 120_000
NONCE_RETENTION_MS = 2 * PUBLISH_WINDOW_MS


def publish_signed_bytes(suite: Suite, ws: bytes, ts_ms: int, nonce: bytes, method: str, host: str, target: str,
                         body: bytes) -> bytes:
    return (L["sig_publish"] + bytes([suite.id]) + ws + u64(ts_ms) + nonce + lp16(method.encode("ascii"))
            + lp16(host.encode("ascii")) + lp16(target.encode("ascii")) + H(body))


def sign_publish(suite: Suite, wsk, ws: bytes, ts_ms: int, nonce: bytes, method, host, target, body) -> dict:
    sig = suite.sign(wsk, publish_signed_bytes(suite, ws, ts_ms, nonce, method, host, target, body))
    return {"Orch-Workspace": ws.hex(), "Orch-Ts": str(ts_ms), "Orch-Nonce": nonce.hex(), "Orch-Signature": b64u(sig)}


def publish_check(suite: Suite, headers: dict, method: str, host: str, target: str, body: bytes, cards: dict,
                  nonces: dict, now_ms: int) -> dict:
    """§12.1, orch-publish's order. nonces: {ws hex: {nonce hex: until_ms}} (mutated)."""
    try:
        ws = unhex(headers["Orch-Workspace"], 16)
        ts_s = headers["Orch-Ts"]
        if not re.fullmatch(r"0|[1-9][0-9]{0,15}", ts_s):
            raise ValueError("ts")
        ts = int(ts_s)
        nonce = unhex(headers["Orch-Nonce"], 16)
        sig = unb64u(headers["Orch-Signature"], 64)
    except (KeyError, ValueError, TypeError):
        return {"status": 400, "error": "malformed"}
    if abs(now_ms - ts) > PUBLISH_WINDOW_MS:
        return {"status": 401, "error": "stale_timestamp", "server_ms": now_ms}
    card = cards.get(ws.hex())
    if card is None:
        return {"status": 401, "error": "unknown_workspace"}
    if not suite.verify(unb64u(card["wsk_pub"]), sig,
                        publish_signed_bytes(suite, ws, ts, nonce, method, host, target, body)):
        return {"status": 401, "error": "bad_signature"}
    seen = nonces.setdefault(ws.hex(), {})
    for n_, until in list(seen.items()):
        if until <= now_ms:
            del seen[n_]
    if nonce.hex() in seen:
        return {"status": 401, "error": "replay"}
    seen[nonce.hex()] = now_ms + NONCE_RETENTION_MS
    return {"status": 200, "workspace": ws.hex()}


def relay_auth_signed_bytes(suite: Suite, origin: str, challenge: bytes, kind: str, ident: bytes) -> bytes:
    return (L["sig_relay_auth"] + bytes([suite.id]) + lp16(origin.encode("ascii")) + challenge
            + bytes([{"device": 1, "workspace": 2}[kind]]) + ident)


# =====================================================================================================
# The vector file
# =====================================================================================================

RELAY_CHALLENGE_MS = 60_000


def relay_auth_check(suite: Suite, st: dict, origin: str, challenge: bytes, kind: str, ident: bytes, sig: bytes,
                     pub: bytes, now_ms: int) -> dict:
    """§12.2, the relay. st: {"challenges": {hex: expires_ms}} (single use: removed whatever happens). `origin`
    is the relay's OWN origin, never one the client names; `pub` comes from the certificate or card of `ident`."""
    exp = st["challenges"].pop(challenge.hex(), None)
    if exp is None:
        return {"status": 401, "error": "unknown_challenge"}
    if now_ms >= exp:
        return {"status": 401, "error": "expired"}
    if kind not in ("device", "workspace"):
        return {"status": 400, "error": "malformed"}
    if not suite.verify(pub, sig, relay_auth_signed_bytes(suite, origin, challenge, kind, ident)):
        return {"status": 401, "error": "bad_signature"}
    return {"status": 200}


def make_enroll_request(suite: Suite, dk, person: bytes, space: bytes, code_id: bytes, dk_sig_pub: bytes,
                        dk_kx_pub: bytes, mac: bytes) -> dict:
    return sign_object(suite, dk, {"v": 2, "suite": suite.id, "kind": "enroll_request", "person_id": person.hex(),
                                   "space_id": space.hex(), "code_id": code_id.hex(), "dk_sig_pub": b64u(dk_sig_pub),
                                   "dk_kx_pub": b64u(dk_kx_pub), "mac": b64u(mac)})


def primary_check_enroll(suite: Suite, signed, me_person: bytes, codes: dict, now_ms: int) -> dict:
    """§6.4. codes (mutated): {code_id hex: {"code": hex, "space_id": hex, "expires_ms", "used": bool}}."""
    try:
        o = signed["o"]
        sig_pub, kx_pub = unb64u(o["dk_sig_pub"], suite.sig_pub_len), unb64u(o["dk_kx_pub"], suite.kx_pub_len)
    except (KeyError, TypeError, ValueError):
        return {"refuse": "malformed"}
    o = verify_object(suite, sig_pub, signed, "enroll_request")      # proof of possession
    if o is None or not suite.kx_pub_ok(kx_pub):
        return {"refuse": "bad_signature"}
    if set(o) != {"v", "suite", "kind", "person_id", "space_id", "code_id", "dk_sig_pub", "dk_kx_pub", "mac"} \
            or o["person_id"] != me_person.hex():
        return {"refuse": "malformed"}
    entry = codes.get(o["code_id"])
    if entry is None:
        return {"refuse": "unknown_code"}
    if entry["used"]:
        return {"refuse": "used"}
    if now_ms >= entry["expires_ms"]:
        return {"refuse": "expired"}
    want = enroll_mac(bytes.fromhex(entry["code"]), suite, bytes.fromhex(entry["space_id"]), sig_pub, kx_pub)
    if o["space_id"] != entry["space_id"] or not hmac.compare_digest(want, unb64u(o["mac"], 32)):
        return {"refuse": "bad_mac"}
    entry["used"] = True
    return {"ok": {"device_id": device_id(suite, sig_pub).hex(), "scopes_max": [f"drop:{entry['space_id']}"]}}


def host_respond(suite: Suite, wsk, state: dict, req_env: bytes, result: dict, now_ms: int, salt: bytes) -> bytes:
    """The host's answer envelope to one request (round-trip tests): a refusal chunk, a pairing answer, or a
    one-chunk 200. Sealed under the request's channel key and epoch, signed by WSK."""
    h = Header.decode(req_env)
    if result["result"] == "refuse":
        meta = {"refusal": result["code"], **{k_: v for k_, v in result.items()
                                             if k_ not in ("result", "code", "stream", "why")}}
        flags = F_LAST | F_REFUSAL
    elif result["result"] in ("pair_pending", "pair_status"):
        meta, flags = result["answer"], F_LAST
    else:
        meta, flags = {"status": 200, "headers": {}}, F_LAST
    if h.flags & F_STREAM:
        flags |= F_STREAM
    stream = h.stream if h.epoch == 0 else (h.rid if h.flags & F_STREAM else ZERO_ID)
    rh = Header(TO_DEVICE, flags, suite.id, h.workspace, h.device, h.rid, stream, 0, now_ms, h.epoch, salt)
    return envelope(suite, bridge_key(state, rh), wsk, rh, frame(meta))


VECTORS = Path(__file__).resolve().parents[1] / "tests" / "vectors_v2.json"


def fake(label: str) -> bytes:
    """Deterministic FAKE material: SHA-256 of a public label. Never a real key."""
    return H(b"FAKE orch v2 test vector: " + label.encode())


def render(v: dict) -> str:
    return json.dumps(v, indent=1, ensure_ascii=False, sort_keys=False) + "\n"


def build() -> dict:
    from ref import _vectors      # the builder lives beside this file, to keep this one readable
    return _vectors.build()


if __name__ == "__main__":
    VECTORS.write_text(render(build()), encoding="utf-8")
    print(f"wrote {VECTORS}")
