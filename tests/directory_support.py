"""Test-only keys and explicit database preconditions for shared HTTP examples."""

import copy
import json
from contextlib import closing
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from orch_relay import db
from orch_relay import proto as P
from orch_relay.directory import digest, token_hash

V = json.loads(Path("tests/vectors_v2.json").read_text())["suites"]["2"]
NOW = 1790000000000
ORIGIN = V["relay_auth"]["origin"]
PERSON = V["ids"]["person_alice"]
DEVICE = V["ids"]["device_phone"]
PRIMARY = V["ids"]["device_primary"]
WS = V["ids"]["workspace_a"]
CERT = V["certs"]["signed"]["phone"]
CARD = V["card"]["card"]
RECORD = V["revocations"][0]["signed"]
PK = P.b64u(bytes.fromhex(V["keys"]["person_alice.sig"]["pub"]))
LOGIN = V["p3"]["objects"]["login"]


def sign(key, message):
    seed = int(V["keys"][key]["seed"], 16)
    private = ec.derive_private_key(seed % (P.P256_N - 1) + 1, ec.SECP256R1())
    r, s = decode_dss_signature(private.sign(message, ec.ECDSA(hashes.SHA256())))
    return P.b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def signed(o, key="person_alice.sig"):
    return {"o": o, "sig": sign(key, P.L["sig_" + o["kind"]] + P.cj(o))}


def unthrottled(directory):
    """Lift the P3-D35 session buckets for load tests that flood one session on purpose."""
    directory.throttles = {name: (10**9, 10**9) for name in directory.throttles}


def seed(directory, accounts=True, devices=True, card=True):
    directory.clock = lambda: NOW
    directory.origin = ORIGIN
    with closing(db.connect(directory.path)) as con, con:
        if accounts:
            con.execute("INSERT INTO accounts VALUES (?,?,?)", (PERSON, PK, NOW))
        if devices:
            for name in ("phone", "primary", "laptop"):
                directory.store_device(con, V["certs"]["signed"][name])
        if card:
            con.execute(
                "INSERT INTO workspaces VALUES (?,?,?,?,?,?,?,?)",
                (WS, PERSON, CARD["o"]["wsk_pub"], P.cj(CARD["delegation"]), P.cj(CARD), 1, 1, 0),
            )
            con.execute("INSERT INTO ever_persons VALUES (?,?)", (WS, PERSON))
            con.execute("INSERT INTO ever_devices VALUES (?,?,?)", (WS, DEVICE, 1))
            con.execute(
                "INSERT INTO members VALUES (?,?,?,?)", (WS, DEVICE, PERSON, P.cj(["look"]))
            )
            con.execute("INSERT INTO member_lists VALUES (?,?,?,?)", (WS, 1, 1, b"{}"))
            con.execute("INSERT INTO holders VALUES (?,?,?,?,?)", (WS, 1, NOW + 40_000, 0, None))
        for token, kind, ident in [
            ("FAKE-device", "device", DEVICE),
            ("FAKE-workspace", "workspace", WS),
        ]:
            con.execute(
                "INSERT INTO sessions VALUES (?,?,?,?)",
                (token_hash(token), kind, ident, NOW + 900_000),
            )


def issue_login(client, key="phone.sig", kind="device", ident=DEVICE):
    challenge = client.post("/v2/session/challenge", json={}).json()["challenge"]
    return client.post(
        "/v2/session/login",
        json={
            "challenge": challenge,
            "kind": kind,
            "id": ident,
            "sig": sign(
                key,
                P.auth_bytes(client.app.state.directory.origin, P.unb64u(challenge), kind, ident),
            ),
        },
    )


def prepare_case(directory, name, case):
    scenario = case["given"].get("scenario", case["name"])
    account_route = name == "accounts"
    seed(
        directory,
        accounts=not account_route,
        devices=not account_route,
        card=not account_route and name != "device_put",
    )
    directory.clock = lambda: case["given"].get("now_ms", NOW)
    request = case["request"]
    challenge = request.get("json", {}).get("challenge", LOGIN["challenge"])
    directory.add_challenge(challenge, NOW + 60_000, "testclient", None)
    with closing(db.connect(directory.path)) as con, con:
        con.execute(
            "INSERT INTO invites(code_hash,expires_ms) VALUES (?,?)",
            (digest(b"FAKE-single-use-invite"), NOW + 100_000),
        )
        if request["headers"].get("Authorization") == "Bearer FAKE-workspace-token":
            con.execute(
                "INSERT INTO sessions VALUES (?,?,?,?)",
                (token_hash("FAKE-workspace-token"), "workspace", WS, NOW + 900_000),
            )
        if name == "device_put" and case["name"] == "resigned_identical":
            original = next(
                c for c in V["p3"]["cases"] if c["name"] == "certificate_directory_resigned_retry"
            )["state"][DEVICE]
            con.execute("UPDATE devices SET cert=? WHERE device_id=?", (P.cj(original), DEVICE))
        if scenario == "other_workspace_person_refused":
            con.execute("DELETE FROM ever_persons")
        if name == "session_login" and scenario == "quota_exceeded":
            con.execute("DELETE FROM sessions")
            for i in range(8):
                con.execute(
                    "INSERT INTO sessions VALUES (?,?,?,?)",
                    (str(i), "device", DEVICE, NOW + 20_000),
                )
        if name == "device_put" and scenario == "rate_limited":
            con.execute("DELETE FROM devices WHERE device_id=?", (DEVICE,))
        if name == "revocation_feed" and case["name"] == "filtered_workspace_feed":
            record = signed({**RECORD["o"], "device_id": PRIMARY})
            con.execute(
                "INSERT INTO revocations VALUES (?,?,?,?,?,?)",
                (PRIMARY, PERSON, P.cj(record), "lost", NOW, 2),
            )
        if name == "revocation_feed":
            # The feed's target is revoked; its caller is another live device of the person.
            con.execute(
                "UPDATE sessions SET subject_id=? WHERE token_hash=?",
                (PRIMARY, token_hash("FAKE-device")),
            )
        if name in ("revocation_get", "revocation_feed") or scenario == "revoked":
            con.execute(
                "INSERT INTO revocations VALUES (?,?,?,?,?,?)",
                (DEVICE, PERSON, P.cj(RECORD), "lost", NOW, 1),
            )
            if name == "revocation_feed" and scenario == "revoked":
                con.execute(
                    "UPDATE sessions SET subject_id=? WHERE token_hash=?",
                    (DEVICE, token_hash("FAKE-device")),
                )
        if name == "revocation_get" and scenario == "every_pair":
            for pair in case["given"]["held_pairs"][1:]:
                record = pair["revocation"]
                con.execute(
                    "INSERT INTO revocations VALUES (?,?,?,?,?,"
                    "(SELECT coalesce(max(cursor),0)+1 FROM revocations))",
                    (DEVICE, pair["person_id"], P.cj(record), pair["reason"], NOW),
                )
                if pair["provenance"] == "chain":
                    con.execute(
                        "INSERT INTO checkpoint_revocations VALUES (?,?,?,?,?,?,?,?,?)",
                        (
                            WS,
                            DEVICE,
                            pair["person_id"],
                            pair["reason"],
                            P.cj(record),
                            b"{}",  # the carried evidence; the public route never serves it
                            "fixture",
                            "fixture",
                            "fixture",
                        ),
                    )
        if name == "card_put" and (
            case["name"] == "first_card_without_session"
            or scenario in ("rate_limited", "other_person")
        ):
            con.execute("DELETE FROM workspaces")
        if scenario == "unknown_challenge":
            directory.remove_challenge(challenge)
        elif scenario == "expired":
            directory.remove_challenge(challenge)
            directory.add_challenge(challenge, NOW, "testclient", None)
        elif scenario == "cert_expired" and name != "device_put":
            con.execute("UPDATE devices SET expires_ms=?", (NOW,))
        elif scenario == "cert_invalid" and not account_route:
            if name == "device_put":
                con.execute(
                    "UPDATE accounts SET pk_pub=?",
                    (P.b64u(bytes.fromhex(V["keys"]["person_bob.sig"]["pub"])),),
                )
            else:
                con.execute("UPDATE devices SET cert=?", (b"{}",))
        elif scenario == "bad_signature":
            if name in ("accounts", "session_login"):
                directory.origin = "https://different-origin.example"
            elif name != "card_put":
                con.execute(
                    "UPDATE accounts SET pk_pub=?",
                    (P.b64u(bytes.fromhex(V["keys"]["person_bob.sig"]["pub"])),),
                )
        elif scenario == "not_eligible":
            if account_route:
                con.execute("DELETE FROM invites")
            elif name in ("device_get", "revocation_feed"):
                con.execute("UPDATE devices SET person_id=?", (PERSON,))
                con.execute("UPDATE sessions SET kind=?,subject_id=?", ("workspace", WS))
                con.execute("DELETE FROM ever_persons")
            else:
                con.execute("DELETE FROM members")
                if name == "card_put":
                    con.execute("UPDATE sessions SET kind=?,subject_id=?", ("device", DEVICE))
        elif scenario == "other_person":
            if name == "revocations_post":
                con.execute("DELETE FROM devices WHERE device_id=?", (DEVICE,))
            elif name == "card_put":
                # A trusted account under this id contains another key.
                con.execute(
                    "UPDATE accounts SET pk_pub=?",
                    (P.b64u(bytes.fromhex(V["keys"]["person_bob.sig"]["pub"])),),
                )
            else:
                con.execute("DELETE FROM devices")
                con.execute("DELETE FROM accounts")
        elif scenario == "account_exists":
            con.execute("INSERT INTO accounts VALUES (?,?,?)", (PERSON, PK, NOW))
        elif scenario == "cert_conflict":
            other = copy.deepcopy(CERT)
            other["o"]["label_sealed"] = P.b64u(b"other")
            con.execute("UPDATE devices SET cert=? WHERE device_id=?", (P.cj(other), DEVICE))
        elif scenario == "not_found":
            if name == "device_get":
                con.execute("UPDATE sessions SET subject_id=?", (PRIMARY,))
                con.execute("DELETE FROM members")
                con.execute("DELETE FROM devices WHERE device_id=?", (DEVICE,))
            elif name == "card_get":
                con.execute("DELETE FROM workspaces")
            else:
                con.execute("DELETE FROM revocations")
        elif scenario == "rate_limited":
            purpose, duration, cap = {
                "session_challenge": ("challenge", 60_000, 60),
                "device_put": ("certificate-address", 3_600_000, 30),
                "revocations_post": ("revocation-address", 60_000, 10),
                "revocation_get": ("revocation-read", 60_000, 60),
                "relay_info": ("relay-info", 60_000, 60),
                "card_put": ("card-address", 3_600_000, 10),
            }[name]
            directory.windows[(purpose, "testclient", duration)] = (NOW + 60_000, cap)
        elif scenario == "token_expired_or_already_logged_out":
            con.execute("UPDATE sessions SET expires_ms=?", (NOW,))
        if name == "card_put":
            if scenario in ("cert_expired", "revoked"):
                con.execute("UPDATE sessions SET kind=?,subject_id=?", ("device", DEVICE))
            changes = {
                "bad_wxk_version": {"card_seq": 0, "wxk_version": 3},
                "stale_card": {"card_seq": 2},
                "wsk_changed": {"wsk_pub": PK},
                "wxk_changed_without_version": {"card_seq": 0, "wxk_pub": PK},
                "other_workspace": {"workspace_id": "00" * 16},
            }
            old = copy.deepcopy(CARD)
            if scenario in changes:
                old["o"].update(changes[scenario])
                con.execute("UPDATE workspaces SET card=?", (P.cj(old),))
            if scenario == "delegation_changed":
                old["delegation"]["o"]["client_hosted"] = True
                con.execute("UPDATE workspaces SET card=?", (P.cj(old),))
