"""Suite-2 directory wire checks, independently shipped from the protocol test oracle."""

import base64
import hashlib
import json
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

MAX_SAFE_INT = 2**53 - 1
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
LABELS = {
    "sig_cert_request": "orch/v2/sig/cert-request|",
    "sig_cert_challenge": "orch/v2/sig/cert-challenge|",
    "sig_cert_rejection": "orch/v2/sig/cert-rejection|",
    "sig_member_list": "orch/v2/sig/member-list|",
    "sig_wk_grant": "orch/v2/sig/wk-grant|",
    "sig_device_cert": "orch/v2/sig/device-cert|",
    "sig_revocation": "orch/v2/sig/revocation|",
    "sig_ws_delegation": "orch/v2/sig/ws-delegation|",
    "sig_card_wsk": "orch/v2/sig/card-wsk|",
    "sig_relay_auth": "orch/v2/sig/relay-auth|",
    "h_device_id": "orch/v2/id/device|",
    "h_person_id": "orch/v2/id/person|",
    "h_dk_hash": "orch/v2/dk-hash|",
    "sig_drop_object": "orch/v2/sig/drop-object|",  # §10.4 (P3-D39)
    "h_drop_parent": "orch/v2/drop-parent|",  # §10.6
}
L = {k: v.encode("ascii") for k, v in LABELS.items()}


def check_json(value, depth=1):
    if isinstance(value, (dict, list)):
        if depth > 16:
            raise ValueError("nesting")
        if isinstance(value, dict):
            if any(not isinstance(k, str) or not k or not k.isascii() for k in value):
                raise ValueError("keys")
            value = value.values()
        for child in value:
            check_json(child, depth + 1)
    elif value is None or type(value) is bool:
        pass
    elif type(value) is int:
        if abs(value) > MAX_SAFE_INT:
            raise ValueError("integer")
    elif isinstance(value, str):
        value.encode("utf-8")
    else:
        raise ValueError("JSON type")


def cj(value):
    check_json(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def parse_json(raw):
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise ValueError("duplicate")
            out[key] = value
        return out

    def reject(_):
        raise ValueError("number")

    try:
        result = json.loads(
            raw.decode("utf-8"), object_pairs_hook=pairs, parse_float=reject, parse_constant=reject
        )
        check_json(result)
        return result
    except (RecursionError, UnicodeError) as e:
        raise ValueError("invalid JSON") from e


def b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def unb64u(value, length=None):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]*", value):
        raise ValueError("b64u")
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if b64u(raw) != value or (length is not None and len(raw) != length):
        raise ValueError("b64u length or canonical form")
    return raw


def unhex(value, length=16):
    if not isinstance(value, str) or not re.fullmatch(rf"[0-9a-f]{{{2 * length}}}", value):
        raise ValueError("hex")
    return bytes.fromhex(value)


class Suite2:
    id = 2

    def load(self, pub):
        if len(pub) != 65 or pub[0] != 4:
            raise ValueError("uncompressed point required")
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub)

    def pub_ok(self, pub):
        try:
            self.load(pub)
            return True
        except (ValueError, TypeError):
            return False

    def verify(self, pub, sig, message):
        if not isinstance(sig, bytes) or len(sig) != 64:
            return False
        r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
        if not 0 < r < P256_N or not 0 < s < P256_N:
            return False
        try:
            self.load(pub).verify(encode_dss_signature(r, s), message, ec.ECDSA(hashes.SHA256()))
            return True
        except (ValueError, TypeError, InvalidSignature):
            return False


SUITE = Suite2()


def identifier(kind, pub):
    return hashlib.sha256(L["h_" + kind + "_id"] + b"\x02" + pub).digest()[:16].hex()


def dk_hash(dk_sig_pub, dk_kx_pub):
    """G3b (P3-D28): both keys of one pairing attempt, as named by cert requests and rejections."""
    return b64u(
        hashlib.sha256(
            L["h_dk_hash"]
            + b"\x02"
            + len(dk_sig_pub).to_bytes(2, "big")
            + dk_sig_pub
            + len(dk_kx_pub).to_bytes(2, "big")
            + dk_kx_pub
        ).digest()
    )


def auth_bytes(origin, challenge, kind, ident):
    origin = origin.encode("ascii")
    return (
        L["sig_relay_auth"]
        + b"\x02"
        + len(origin).to_bytes(2, "big")
        + origin
        + challenge
        + bytes([{"device": 1, "workspace": 2}[kind]])
        + unhex(ident)
    )


def verify_object(signed, pub, kind):
    try:
        if not isinstance(signed, dict) or set(signed) != {"o", "sig"}:
            return None
        o = signed["o"]
        if o.get("v") != 2 or o.get("suite") != 2 or o.get("kind") != kind:
            return None
        if SUITE.verify(pub, unb64u(signed["sig"], 64), L["sig_" + kind] + cj(o)):
            return o
    except (ValueError, TypeError, AttributeError, KeyError):
        pass
    return None


def scopes_ok(scopes):
    return (
        isinstance(scopes, list)
        and bool(scopes)
        and (
            scopes == ["look", "decide", "operate", "type"][: len(scopes)]
            or (
                len(scopes) == 1
                and isinstance(scopes[0], str)
                and re.fullmatch(r"drop:[0-9a-f]{32}", scopes[0]) is not None
            )
        )
    )


def verify_cert(signed, pk_pub, now_ms, revoked=frozenset()):
    o = verify_object(signed, pk_pub, "device_cert")
    try:
        if o is None or set(o) != {
            "v",
            "suite",
            "kind",
            "device_id",
            "person_id",
            "dk_sig_pub",
            "dk_kx_pub",
            "label_sealed",
            "created_ms",
            "expires_ms",
            "scopes_max",
        }:
            raise ValueError()
        sig, kx = unb64u(o["dk_sig_pub"], 65), unb64u(o["dk_kx_pub"], 65)
        unb64u(o["label_sealed"])
        if (
            not SUITE.pub_ok(sig)
            or not SUITE.pub_ok(kx)
            or o["device_id"] != identifier("device", sig)
            or o["person_id"] != identifier("person", pk_pub)
        ):
            raise ValueError()
        if (
            not scopes_ok(o["scopes_max"])
            or type(o["created_ms"]) is not int
            or o["created_ms"] > now_ms + 300_000
        ):
            raise ValueError()
        exp = o["expires_ms"]
        if exp is not None and (type(exp) is not int or exp <= o["created_ms"]):
            raise ValueError()
        if o["scopes_max"][0].startswith("drop:") and exp is None:
            raise ValueError()
    except (ValueError, TypeError, KeyError):
        return {"refuse": "cert_invalid"}
    if exp is not None and now_ms >= exp:
        return {"refuse": "cert_expired"}
    if o["device_id"] in revoked:
        return {"refuse": "revoked"}
    return {"ok": o}


def verify_revocation(signed, pk_pub, cert):
    o = verify_object(signed, pk_pub, "revocation")
    if o is None or set(o) != {
        "v",
        "suite",
        "kind",
        "person_id",
        "device_id",
        "revoked_ms",
        "reason",
    }:
        return {"refuse": "bad_signature"}
    if (
        o["person_id"] != identifier("person", pk_pub)
        or o["reason"] not in ("lost", "retired", "compromised")
        or type(o["revoked_ms"]) is not int
    ):
        return {"refuse": "malformed"}
    if cert is None or cert["person_id"] != o["person_id"] or cert["device_id"] != o["device_id"]:
        return {"refuse": "other_person"}
    return {"ok": o}


def verify_delegation(signed, pk_pub):
    o = verify_object(signed, pk_pub, "ws_delegation")
    if o is None:
        return {"refuse": "bad_signature"}
    if (
        set(o)
        != {
            "v",
            "suite",
            "kind",
            "workspace_id",
            "wsk_pub",
            "owner_person_id",
            "client_hosted",
            "issued_ms",
        }
        or type(o["client_hosted"]) is not bool
        or type(o["issued_ms"]) is not int
    ):
        return {"refuse": "malformed"}
    if o["owner_person_id"] != identifier("person", pk_pub):
        return {"refuse": "other_person"}
    return {"ok": o}


def verify_card(card, pk_pub):
    try:
        if set(card) != {"delegation", "o", "sig", "sealed"}:
            raise ValueError()
        o = card["o"]
        if (
            set(o)
            != {
                "v",
                "suite",
                "kind",
                "workspace_id",
                "wsk_pub",
                "wxk_pub",
                "wxk_version",
                "owner_person_id",
                "relay_url",
                "card_seq",
                "issued_ms",
                "sealed_hash",
                "ck_commit",
            }
            or o["v"] != 2
            or o["kind"] != "card"
        ):
            raise ValueError()
        if o["suite"] != 2:
            return {"refuse": "wrong_suite"}
        unhex(o["workspace_id"])
        wsk, wxk = unb64u(o["wsk_pub"], 65), unb64u(o["wxk_pub"], 65)
        if not SUITE.pub_ok(wsk) or not SUITE.pub_ok(wxk):
            raise ValueError()
        if not re.fullmatch(
            r"https://[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[1-9][0-9]{0,4})?|http://(localhost|127\.0\.0\.1|\[::1\]|10\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])|172\.(?:1[6-9]|2[0-9]|3[01])\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])|192\.168\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])|100\.(?:6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9]))(:[1-9][0-9]{0,4})?",
            o["relay_url"],
        ):
            raise ValueError()
        for key in ("wxk_version", "card_seq", "issued_ms"):
            if (
                type(o[key]) is not int
                or not (0 if key == "issued_ms" else 1) <= o[key] <= MAX_SAFE_INT
            ):
                raise ValueError()
        unb64u(o["ck_commit"], 32)
        sealed = unb64u(card["sealed"])
        if o["owner_person_id"] != identifier("person", pk_pub):
            return {"refuse": "other_person"}
        result = verify_delegation(card["delegation"], pk_pub)
        if "refuse" in result:
            return result
        if any(result["ok"][k] != o[k] for k in ("workspace_id", "wsk_pub", "owner_person_id")):
            return {"refuse": "delegation_mismatch"}
        if (
            not SUITE.verify(wsk, unb64u(card["sig"], 64), L["sig_card_wsk"] + cj(o))
            or unb64u(o["sealed_hash"], 32) != hashlib.sha256(sealed).digest()
        ):
            return {"refuse": "bad_signature"}
        return {"ok": o}
    except (ValueError, TypeError, KeyError, AttributeError):
        return {"refuse": "malformed"}


def relay_accept_card(stored, card, pk_pub):
    result = verify_card(card, pk_pub)
    if "refuse" in result or stored is None:
        return result
    o, old = result["ok"], stored["o"]
    code = None
    if any(o[k] != old[k] for k in ("workspace_id", "owner_person_id")):
        code = "other_workspace"
    elif o["wsk_pub"] != old["wsk_pub"]:
        code = "wsk_changed"
    elif cj(card["delegation"]["o"]) != cj(stored["delegation"]):
        code = "delegation_changed"
    elif o == old:
        return result
    elif o["card_seq"] <= old["card_seq"]:
        code = "stale_card"
    elif o["wxk_version"] == old["wxk_version"]:
        if o["wxk_pub"] != old["wxk_pub"]:
            code = "wxk_changed_without_version"
    elif o["wxk_version"] != old["wxk_version"] + 1 or o["wxk_pub"] == old["wxk_pub"]:
        code = "bad_wxk_version"
    return {"refuse": code} if code else result
