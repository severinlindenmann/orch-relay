"""PK-authorized certificate request transitions, atomic with directory completion."""

from . import proto as P
from .bridge import refuse
from .directory import check_suite, fail, fields


def verify(signed, pub, kind):
    check_suite(signed)
    o = P.verify_object(signed, P.unb64u(pub), kind)
    if o is None:
        fail("bad_signature")
    return o


def context(o, req):
    for field, code in (
        ("person_id", "other_person"),
        ("workspace_id", "other_workspace"),
        ("request_id", "not_for_this_device"),
    ):
        if o[field] != req[field]:
            refuse(code, 409 if field == "workspace_id" else 403)


def binding(o, req):
    """G3b (P3-D28): a challenge or rejection names the stored request's attempt (offer, nonce) and device keys."""
    keys = (
        o["dk_hash"]
        if "dk_hash" in o
        else P.dk_hash(P.unb64u(o["dk_sig_pub"]), P.unb64u(o["dk_kx_pub"]))
    )
    if (o["offer_id"], o["attempt"], o["device_id"], keys) != (
        req["offer_id"],
        req["attempt"],
        req["device_id"],
        req["dk_hash"],
    ):
        fail("not_for_this_device")


def certificate_transition(con, row, cert, now, pk):
    """Verify a certificate and transition one queue entry without replacing terminal state."""
    if now >= row["expires_ms"] + 60000:
        fail("not_found")
    o = verify(cert, pk, "device_cert")
    if row["cert"] and P.cj(P.parse_json(row["cert"])["o"]) == P.cj(o):
        return row["state"]
    if (
        row["state"] == "expired"
        or row["state"] in ("open", "challenged")
        and now >= row["expires_ms"]
    ):
        refuse("expired", 410)
    from .directory import checked

    checked(P.verify_cert(cert, P.unb64u(pk), now))
    if row["state"] == "signed":
        refuse("already_signed", 409)
    if row["state"] == "rejected":
        refuse("replayed", 409)
    if row["state"] != "challenged":
        return "unmatched"
    challenged = P.parse_json(row["challenge"])["o"]
    if not all(
        o[k] == challenged[k] for k in ("person_id", "device_id", "dk_sig_pub", "dk_kx_pub")
    ):
        return "unmatched"
    con.execute(
        "UPDATE cert_requests SET state='signed',cert=? WHERE request_id=?",
        (P.cj(cert), row["request_id"]),
    )
    return "signed"


def complete(con, cert, now):
    """Called at every verified certificate exit, including stored canonical retries."""
    person = cert["o"]["person_id"]
    rows = con.execute(
        "SELECT * FROM cert_requests WHERE person_id=? AND state='challenged' AND expires_ms>?",
        (person, now),
    ).fetchall()
    if rows:
        pk = con.execute("SELECT pk_pub FROM accounts WHERE person_id=?", (person,)).fetchone()[0]
        for row in rows:
            certificate_transition(con, row, cert, now, pk)


def dispatch(d, con, route, params, method, raw, headers, now):
    session = d.authenticate(con, headers, now)
    if route == "cert_requests":
        person = params["person"]
        if method == "GET":
            if session["kind"] != "device" or session["person_id"] != person:
                fail("not_eligible")
            return {
                "requests": [
                    P.parse_json(row[0])
                    for row in con.execute(
                        "SELECT request FROM cert_requests WHERE person_id=? AND primary_device_id=? AND state='open' ORDER BY request_id",
                        (person, session["subject_id"]),
                    )
                ]
            }
        if session["kind"] != "workspace":
            fail("not_eligible")
        ws = session["subject_id"]
        d.fence(con, headers, ws, now)
        body = P.parse_json(raw)
        fields(body, "request")
        workspace = con.execute("SELECT * FROM workspaces WHERE workspace_id=?", (ws,)).fetchone()
        o = verify(body["request"], workspace["wsk_pub"], "cert_request")
        fields(
            o,
            "v suite kind request_id workspace_id person_id primary_device_id offer_id attempt device_id"
            " dk_hash created_ms expires_ms sealed",
        )
        for key in (
            "request_id",
            "workspace_id",
            "person_id",
            "primary_device_id",
            "offer_id",
            "attempt",
            "device_id",
        ):
            P.unhex(o[key])
        P.unb64u(o["dk_hash"], 32)
        if o["workspace_id"] != ws:
            refuse("other_workspace", 409)
        if o["person_id"] != person or workspace["owner_person_id"] != person:
            fail("other_person")
        primary = con.execute(
            "SELECT * FROM devices WHERE device_id=?", (o["primary_device_id"],)
        ).fetchone()
        if primary is None or primary["person_id"] != person:
            fail("not_for_this_device")
        d.device_status(con, primary, now)
        if P.parse_json(primary["scopes_max"])[0].startswith("drop:"):
            fail("not_for_this_device")
        sealed = P.unb64u(o["sealed"])
        if len(sealed) < 113 or not P.SUITE.pub_ok(sealed[:65]):
            fail("malformed")
        if any(type(o[k]) is not int for k in ("created_ms", "expires_ms")):
            fail("malformed")
        old = con.execute(
            "SELECT request FROM cert_requests WHERE request_id=?", (o["request_id"],)
        ).fetchone()
        if old:
            if P.cj(body["request"]) != old[0]:
                refuse("replayed", 409)
            return {"request_id": o["request_id"]}
        if (
            not o["created_ms"] - 300000 <= now < o["expires_ms"]
            or not 0 < o["expires_ms"] - o["created_ms"] <= 600000
        ):
            refuse("expired", 410)
        if con.execute(
            "SELECT 1 FROM cert_requests WHERE workspace_id=? AND state IN ('open','challenged')",
            (ws,),
        ).fetchone():
            refuse("request_open", 409)
        if (
            con.execute(
                "SELECT count(*) FROM cert_requests WHERE person_id=? AND state IN ('open','challenged')",
                (person,),
            ).fetchone()[0]
            >= 64
        ):
            fail("quota_exceeded")
        con.execute(
            "INSERT INTO cert_requests VALUES (?,?,?,?,?,?,'open',NULL,NULL,NULL)",
            (
                o["request_id"],
                ws,
                person,
                o["primary_device_id"],
                P.cj(body["request"]),
                o["expires_ms"],
            ),
        )
        return {"request_id": o["request_id"]}
    row = con.execute(
        "SELECT * FROM cert_requests WHERE request_id=?", (params["ident"],)
    ).fetchone()
    if row is None:
        fail("not_found")
    if route == "cert_request":
        if session["kind"] != "workspace" or session["subject_id"] != row["workspace_id"]:
            fail("not_eligible")
        return {
            "state": row["state"],
            **{
                k: P.parse_json(row[k]) if row[k] else None
                for k in ("challenge", "cert", "rejection")
            },
        }
    if (
        session["kind"] != "device"
        or session["person_id"] != row["person_id"]
        or session["subject_id"] != row["primary_device_id"]
    ):
        fail("not_eligible")
    field = "challenge" if route == "cert_challenge" else "rejection"
    body = P.parse_json(raw)
    fields(body, field)
    pk = con.execute(
        "SELECT pk_pub FROM accounts WHERE person_id=?", (row["person_id"],)
    ).fetchone()[0]
    o = verify(body[field], pk, "cert_" + field)
    required = (
        "v suite kind request_id workspace_id person_id offer_id attempt device_id expires_ms"
    )
    required += " dk_sig_pub dk_kx_pub primary_nonce" if field == "challenge" else " dk_hash"
    fields(o, required)
    for key in ("request_id", "workspace_id", "person_id", "offer_id", "attempt", "device_id"):
        P.unhex(o[key])
    if type(o["expires_ms"]) is not int:
        fail("malformed")
    request = P.parse_json(row["request"])["o"]
    context(o, request)
    if field == "rejection":
        P.unb64u(o["dk_hash"], 32)
        if o["expires_ms"] != row["expires_ms"]:
            fail("malformed")
    if field == "challenge":
        sig_pub = P.unb64u(o["dk_sig_pub"])
        if (
            not P.SUITE.pub_ok(sig_pub)
            or not P.SUITE.pub_ok(P.unb64u(o["dk_kx_pub"]))
            or P.identifier("device", sig_pub) != o["device_id"]
            or o["expires_ms"] != row["expires_ms"]
        ):
            fail("malformed")
        P.unb64u(o["primary_nonce"], 32)
    binding(o, request)
    if row["state"] == "expired":
        refuse("expired", 410)
    if row[field] and P.cj(P.parse_json(row[field])["o"]) == P.cj(o):
        return {}
    if row["state"] == "signed":
        refuse("already_signed", 409)
    if row["state"] == "rejected" or field == "challenge" and row["state"] != "open":
        refuse("replayed", 409)
    con.execute(
        f"UPDATE cert_requests SET {field}=?,state=? WHERE request_id=?",
        (
            P.cj(body[field]),
            "challenged" if field == "challenge" else "rejected",
            row["request_id"],
        ),
    )
    return {}
