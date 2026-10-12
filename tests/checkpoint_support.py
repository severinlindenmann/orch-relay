"""G4: seed a ref/checkpoints.py state into the production database and replay vector steps.

The reference state is JSON-portable; this module writes the same facts into the tables the
production relay reads (accounts, devices, members, revocations and the 0009 checkpoint tables),
then drives every relay operation over HTTP with explicit sessions and the Orch-Holder fence.
Nothing in the production checks is mocked. Device walks run ref.checkpoints.sync_walk with its
reads served by the production GET routes.
"""

import copy
import json
from contextlib import closing
from pathlib import Path

from orch_relay import db
from orch_relay import proto as P
from orch_relay.checkpoints import DAY, HOUR, Nodes, Relay, raw, skip_height, text
from orch_relay.directory import Refusal, token_hash
from ref import checkpoints as C
from ref import orch_protocol_ref as R

CORPUS = json.loads(Path("tests/vectors_v2.json").read_text())
V = CORPUS["suites"]["2"]
S = R.SUITES[2]
WS = V["ids"]["workspace_a"]
WS_B = V["ids"]["workspace_b"]
DEVICE = V["ids"]["device_phone"]
CARD = V["card"]["card"]
LEASE = 1 << 52
SECTIONS = ("checkpoints", "checkpoints_g4")
BOB_PHONE = V["ids"]["device_bob_phone"]
# Per workspace: its W token, a member device token and that device (§19.8 detail 6 (b)).
TOKENS = {
    WS: ("FAKE-workspace", "FAKE-device", DEVICE),
    WS_B: ("FAKE-workspace-b", "FAKE-device-b", BOB_PHONE),
}
W = {"Authorization": "Bearer FAKE-workspace"}
D = {"Authorization": "Bearer FAKE-device"}


def principals(ws):
    w, d, _ = TOKENS[ws]
    return {"Authorization": "Bearer " + w}, {"Authorization": "Bearer " + d}


STRENGTH = C.STRENGTH


def cases(section="checkpoints"):
    return V.get(section, {"cases": []})["cases"]


def find(binding):
    return next(c for c in cases(binding["section"]) if c["name"] == binding["name"])


def collect(value, out):
    """Every device certificate and pk_pub anywhere in a case (its evidence and bodies)."""
    if isinstance(value, dict):
        o = value.get("o")
        if isinstance(o, dict) and o.get("kind") == "device_cert" and set(value) == {"o", "sig"}:
            out["certs"].setdefault((o["device_id"], o["person_id"]), value)
        if isinstance(value.get("pk_pub"), str):
            try:
                pk = R.unb64u(value["pk_pub"])
                out["pks"][R.person_id(S, pk).hex()] = value["pk_pub"]
            except (ValueError, TypeError):
                pass
        for child in value.values():
            collect(child, out)
    elif isinstance(value, list):
        for child in value:
            collect(child, out)
    return out


def pools(case):
    out = {"certs": {}, "pks": {}}
    for cert in V["certs"]["signed"].values():
        out["certs"][(cert["o"]["device_id"], cert["o"]["person_id"])] = cert
    for name in ("person_alice", "person_bob", "intruder"):
        pub = bytes.fromhex(V["keys"][name + ".sig"]["pub"])
        out["pks"][R.person_id(S, pub).hex()] = R.b64u(pub)
    return collect(case, out)


def key_for(person):
    for name in ("person_alice", "person_bob", "intruder"):
        pub = bytes.fromhex(V["keys"][name + ".sig"]["pub"])
        if R.person_id(S, pub).hex() == person:
            return S.sig_key(bytes.fromhex(V["keys"][name + ".sig"]["seed"]))
    raise KeyError(person)


def certificate(pool, device, person):
    if (device, person) in pool["certs"]:
        return pool["certs"][(device, person)]
    base = next(c for (d, _), c in pool["certs"].items() if d == device)
    return R.sign_object(S, key_for(person), {**base["o"], "person_id": person})


def revocations(state):
    """Production holds revocations globally, per (device, person) pair (orch-core #397, migration
    0010): the strongest of the held and the global sets, keyed 'device:person' as in the reference."""
    out = {}
    for source in (state["revocations"], state.get("global_revocations", {})):
        for key, rev in source.items():
            if key not in out or STRENGTH[rev["o"]["reason"]] > STRENGTH[out[key]["o"]["reason"]]:
                out[key] = rev
    return out


def insert_node(con, ws, log, n, nodes):
    prev = nodes.get(n["prev_acc"])
    skip = nodes.ancestor(prev, skip_height(n["seq"]))
    con.execute(
        "INSERT INTO log_nodes VALUES (?,?,?,?,?,?,?)",
        (ws, log, raw(n["acc"]), n["seq"], raw(n["head"]), raw(n["prev_acc"]), raw(skip["acc"])),
    )
    nodes.cache[n["acc"]] = {**n, "skip_acc": skip["acc"]}


def seed(path, state, case, now=None, ws=WS):
    pool = pools(case)
    revs = revocations(state)
    with closing(db.connect(path)) as con, con:
        # Restore evidence registers no device (orch-core #397): the registry holds the
        # reference's registry, verified signers and the list members only.
        devices = dict(state["registry"])
        for d, person in state.get("bound", {}).items():
            devices.setdefault(d, person)
        for d in state["members"]:
            # Production members are registered devices (G2 membership verifies their certs).
            devices.setdefault(d, next(p for (dd, p) in pool["certs"] if dd == d))
        persons = dict(state["person_keys"])
        for person in set(devices.values()) - set(persons):
            persons[person] = pool["pks"][person]
        for person, pk in persons.items():
            con.execute("INSERT OR IGNORE INTO accounts VALUES (?,?,?)", (person, pk, 0))
        for d, person in devices.items():
            cert = certificate(pool, d, person)
            o = cert["o"]
            con.execute(
                "INSERT OR IGNORE INTO devices VALUES (?,?,?,?,?,?,?)",
                (
                    d,
                    person,
                    P.cj(cert),
                    o["dk_sig_pub"],
                    o["dk_kx_pub"],
                    P.cj(o["scopes_max"]),
                    o["expires_ms"],
                ),
            )
        delegation = state["delegation"]
        con.execute(
            "INSERT INTO workspaces VALUES (?,?,?,?,?,?,?,?)",
            (
                ws,
                delegation["o"]["owner_person_id"],
                state["wsk_pub"],
                P.cj(delegation),
                P.cj(CARD),
                1,
                1,
                0,
            ),
        )
        for d, scopes in state["members"].items():
            con.execute("INSERT INTO members VALUES (?,?,?,?)", (ws, d, devices[d], P.cj(scopes)))
            con.execute("INSERT OR IGNORE INTO ever_persons VALUES (?,?)", (ws, devices[d]))
            if d in state["ever_devices"]:
                con.execute("INSERT INTO ever_devices VALUES (?,?,1)", (ws, d))
        for d in state["ever_devices"]:
            # As in production: list members are G2 ever_devices only; restore evidence and
            # signers outside the list are checkpoint_ever_devices only (review R2).
            if d not in state["members"]:
                con.execute("INSERT INTO checkpoint_ever_devices VALUES (?,?)", (ws, d))
        for cursor, key in enumerate(sorted(revs), 1):
            rev = revs[key]
            con.execute(
                "INSERT INTO revocations VALUES (?,?,?,?,?,?)",
                (
                    rev["o"]["device_id"],
                    rev["o"]["person_id"],
                    P.cj(rev),
                    rev["o"]["reason"],
                    0,
                    cursor,
                ),
            )
        # The reference's held (workspace) revocations are this workspace's chain pairs.
        provenance = {}
        for t in state["transitions"]:
            for item in t["line"]["revocations"]:
                o = item["revocation"]["o"]
                provenance.setdefault(
                    (o["device_id"], o["person_id"]), (t["restore_id"], t["target_hash"])
                )
        for rev in state["revocations"].values():
            d, person = rev["o"]["device_id"], rev["o"]["person_id"]
            ref = provenance.get((d, person), ("seed", "seed"))
            con.execute(
                "INSERT INTO checkpoint_revocations VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    ws,
                    d,
                    person,
                    rev["o"]["reason"],
                    P.cj(rev),
                    P.cj(certificate(pool, d, person)),
                    pool["pks"][person],
                    *ref,
                ),
            )
        if state["genesis"]:
            con.execute("INSERT INTO checkpoint_genesis VALUES (?,?)", (ws, P.cj(state["genesis"])))
        for h, c in state["checkpoints"].items():
            con.execute(
                "INSERT INTO checkpoints VALUES (?,?,?,?,?,?)",
                (
                    ws,
                    h,
                    c["checkpoint"]["o"]["n"],
                    P.cj(c["checkpoint"]),
                    c["superseded_ms"],
                    int(c["permanent"]),
                ),
            )
        if state["held"]:
            con.execute(
                "INSERT INTO checkpoint_heads VALUES (?,?)", (ws, C.checkpoint_hash(state["held"]))
            )
        for h in state["gone"]:
            con.execute("INSERT OR IGNORE INTO checkpoint_gone VALUES (?,?)", (ws, h))
        for log, nodes in state["nodes"].items():
            index = Nodes(con, ws, log)
            for n in sorted(nodes.values(), key=lambda n: n["seq"]):
                insert_node(con, ws, log, n, index)
        for key, st in state["staging"].items():
            source, target = key.split("/")
            pages = {int(i): bytes.fromhex(w) for i, w in st["wire_pages"].items()}
            manifest = bytes.fromhex(st["wire_manifest"]) if st["wire_manifest"] else None
            size = sum(map(len, pages.values())) + len(manifest or b"")
            con.execute(
                "INSERT INTO checkpoint_staging VALUES (?,?,?,?,?,?)",
                (ws, source, target, st["expires_ms"], manifest, size),
            )
            if manifest:
                for pos, d in enumerate(P.parse_json(manifest)["pages"]):
                    con.execute(
                        "INSERT INTO checkpoint_staging_slots VALUES (?,?,?,?,?,?)",
                        (ws, source, target, d["i"], pos, P.cj(d)),
                    )
            for i, wire in pages.items():
                con.execute(
                    "INSERT INTO checkpoint_staging_pages VALUES (?,?,?,?,?)",
                    (ws, source, target, i, wire),
                )
        for t in state["transitions"]:
            con.execute(
                "INSERT INTO checkpoint_transitions VALUES (?,?,?,?)",
                (ws, t["restore_id"], t["target_n"], P.cj(t)),
            )
        for h, b in state["baselines"].items():
            con.execute(
                "INSERT INTO checkpoint_baselines VALUES (?,?,?,?)",
                (ws, h, b["offer_id"], b["until_ms"]),
            )
        for receipt, result in state["receipts"].items():
            con.execute(
                "INSERT INTO checkpoint_receipts VALUES (?,?,?)", (ws, receipt, P.cj(result))
            )
        for gen, at in state["failures"]:
            con.execute("INSERT INTO checkpoint_failures VALUES (?,?,?)", (ws, gen, at))
        con.execute(
            "INSERT INTO holders VALUES (?,?,?,?,?)", (ws, state["generation"], LEASE, 0, None)
        )
        w_token, d_token, member = TOKENS[ws]
        for token, kind, subject in ((w_token, "workspace", ws), (d_token, "device", member)):
            con.execute(
                "INSERT OR IGNORE INTO sessions VALUES (?,?,?,?)",
                (token_hash(token), kind, subject, LEASE),
            )


def holder_gen(path, ws=WS):
    with closing(db.connect(path)) as con:
        return con.execute("SELECT gen FROM holders WHERE workspace_id=?", (ws,)).fetchone()[0]


def http(client, method, path, headers, query=None, body=None):
    kwargs = {"headers": dict(headers), "params": query or {}}
    if body is not None:
        kwargs["content"] = (
            body
            if isinstance(body, bytes)
            else body.encode()
            if isinstance(body, str)
            else P.cj(body)
        )
        kwargs["headers"]["Content-Type"] = "application/json"
    response = client.request(method, path, **kwargs)
    return {"status": response.status_code, **response.json()}


def device_key(cert):
    """The vector device key whose public key the certificate names."""
    for name, key in V["keys"].items():
        if name.endswith(".sig") and R.b64u(bytes.fromhex(key["pub"])) == cert["o"]["dk_sig_pub"]:
            return S.sig_key(bytes.fromhex(key["seed"]))
    raise KeyError(cert["o"]["device_id"])


def create_account(client, path, cert, pk_pub, now):
    """POST /v2/accounts (P3-D3) for a register_device step with route 'account': a fresh invite and
    the device's login signature over a relay challenge, as a real first device sends it."""
    from orch_relay.directory import digest

    invite = "FAKE-vector-invite-" + cert["o"]["device_id"] + cert["o"]["person_id"]
    with closing(db.connect(path)) as con, con:
        con.execute(
            "INSERT OR IGNORE INTO invites(code_hash,expires_ms) VALUES (?,?)",
            (digest(invite.encode()), now + DAY),
        )
    challenge = http(client, "POST", "/v2/session/challenge", {}, body={})["challenge"]
    d = client.app.state.directory
    message = P.auth_bytes(d.origin, P.unb64u(challenge), "device", cert["o"]["device_id"])
    sig = R.b64u(S.sign(device_key(cert), message))
    return http(
        client,
        "POST",
        "/v2/accounts",
        {},
        body={
            "invite": invite,
            "pk_pub": pk_pub,
            "device_cert": cert,
            "challenge": challenge,
            "sig": sig,
        },
    )


SKIPPED = "skipped"


def step(client, path, inp, case, ws=WS):
    """One vector step against the production relay; SKIPPED for device-only operations."""
    d = client.app.state.directory
    op, now = inp["op"], inp["now_ms"]
    d.clock = lambda: now
    prefix = f"/v2/workspaces/{ws}"
    W, D = principals(ws)
    host = {**W, "Orch-Holder": str(holder_gen(path, ws))}
    body = inp.get("body")
    if op == "publish":
        gen = inp.get("generation")
        headers = dict(W)
        if gen is not None:
            if type(gen) is int and gen > holder_gen(path, ws):
                with closing(db.connect(path)) as con, con:  # an explicit takeover (P3-D10)
                    con.execute("UPDATE holders SET gen=? WHERE workspace_id=?", (gen, ws))
            headers["Orch-Holder"] = str(gen)
        return http(client, "PUT", prefix + "/checkpoint", headers, body=body)
    if op == "genesis":
        return http(client, "PUT", prefix + "/genesis", host, body=body)
    if op in ("page", "manifest"):
        tail = f"/pages/{inp['i']}" if op == "page" else "/manifest"
        url = f"{prefix}/staging/{inp['source'] or 'null'}/{inp['target']}{tail}"
        return http(client, "PUT", url, host, body=body)
    if op == "baseline":
        return http(client, "POST", prefix + "/baselines", host, body=body)
    if op == "baseline_delete":
        role = inp.get("role")
        if role is None:
            return SKIPPED  # HTTP always names its principal; the reference fails closed
        if role == "host":
            return http(client, "DELETE", f"{prefix}/baselines/{body['hash']}", host)
        query = {"offer_id": body["offer_id"]} if "offer_id" in body else {}
        return http(client, "DELETE", f"{prefix}/baselines/{body['hash']}", D, query)
    if op in ("get", "proof", "transitions"):
        route = {"get": "/checkpoint", "proof": "/proof", "transitions": "/transitions"}[op]
        query = {k: str(v) for k, v in inp.items() if k not in ("op", "now_ms") and v is not None}
        return http(client, "GET", prefix + route, W, query)
    if op == "register_device":
        pool = pools(case)
        cert = certificate(pool, body["device_id"], body["person_id"])
        if body.get("route") == "account":
            result = create_account(client, path, cert, body["pk_pub"], now)
        else:
            result = http(
                client, "PUT", f"/v2/devices/{body['device_id']}", {}, body={"cert": cert}
            )
        return {k: v for k, v in result.items() if k in ("status", "error")}
    if op == "owner_policy":
        if inp.get("historical"):
            return SKIPPED  # device-side judgement
        with closing(db.connect(path)) as con:
            relay = Relay(d, con, ws, now)
            try:
                relay.owner_policy(relay.workspace(), body)
                return {"status": 200}
            except Refusal as exc:
                return {"status": exc.status, "error": exc.code}
            except (KeyError, TypeError, ValueError, AttributeError):
                return {"status": 400, "error": "malformed"}
    if op == "device_sync":
        return device_sync(client, inp, ws)
    return SKIPPED  # device_learn: a device-only state change


def device_sync(client, inp, ws=WS):
    """The reference device walk, reading the production relay through its GET routes."""
    real = C.read
    route = {"get": "/checkpoint", "proof": "/proof", "transitions": "/transitions"}

    def read(_state, op, args, _now):
        query = {k: str(v) for k, v in args.items() if v is not None}
        result = http(client, "GET", f"/v2/workspaces/{ws}{route[op]}", W, query)
        if result["status"] != 200:
            raise C.Refusal(result["error"], result["status"])
        return {k: v for k, v in result.items() if k != "status"}

    C.read = read
    try:
        out = C.sync_walk(
            S,
            copy.deepcopy(inp["body"]),
            None,
            inp["now_ms"],
            inp.get("endpoint"),
            inp.get("script"),
            inp.get("max_heads"),
        )
        return {"status": 200, **out}
    except C.Refusal as exc:
        return exc.result
    except (KeyError, TypeError, ValueError, AttributeError, IndexError):
        return {"status": 400, "error": "malformed"}
    finally:
        C.read = real


# --- state projections: what a refusal must leave unchanged and what a case must end in -------------


def visible(now, checkpoints, baselines):
    """(stored, gone) after retention at `now`, from rows {hash: (superseded_ms, permanent)}."""
    pinned = {h for h, until in baselines.items() if until > now}
    stored, gone = {}, set()
    for h, (superseded, permanent) in checkpoints.items():
        if not permanent and superseded is not None and now >= superseded + DAY and h not in pinned:
            gone.add(h)
        else:
            stored[h] = (superseded, bool(permanent))
    return stored, gone


def project_state(state, now):
    revs = revocations(state)
    stored, gone = visible(
        now,
        {h: (c["superseded_ms"], c["permanent"]) for h, c in state["checkpoints"].items()},
        {h: b["until_ms"] for h, b in state["baselines"].items()},
    )
    return {
        "genesis": state["genesis"],
        "held": C.checkpoint_hash(state["held"]) if state["held"] else None,
        "checkpoints": stored,
        "gone": gone | set(state["gone"]),
        "nodes": {
            (log, acc): (n["seq"], n["head"], n["prev_acc"])
            for log, ns in state["nodes"].items()
            for acc, n in ns.items()
        },
        "transitions": sorted(
            (t["restore_id"], t["target_n"], P.cj(t)) for t in state["transitions"]
        ),
        "baselines": {
            h: (b["offer_id"], b["until_ms"])
            for h, b in state["baselines"].items()
            if b["until_ms"] > now
        },
        "revocations": {
            (r["o"]["device_id"], r["o"]["person_id"]): r["o"]["reason"] for r in revs.values()
        },
        "chain": {
            (r["o"]["device_id"], r["o"]["person_id"]): r["o"]["reason"]
            for r in state["revocations"].values()
        },
        "ever": set(state["ever_devices"]),
        "staging": {
            tuple(k.split("/")): (
                s["expires_ms"],
                sorted(int(i) for i in s["wire_pages"]),
                s["wire_manifest"] is not None,
            )
            for k, s in state["staging"].items()
            if s["expires_ms"] > now
        },
        "receipts": set(state["receipts"]),
        "failures": sorted(tuple(f) for f in state["failures"] if f[1] > now - HOUR),
    }


def project_db(path, now, ws=WS):
    with closing(db.connect(path)) as con:
        rows = {
            h: (s, p)
            for h, s, p in con.execute(
                "SELECT hash,superseded_ms,permanent FROM checkpoints WHERE workspace_id=?", (ws,)
            )
        }
        baselines = dict(
            con.execute(
                "SELECT hash,until_ms FROM checkpoint_baselines WHERE workspace_id=?", (ws,)
            )
        )
        stored, gone = visible(now, rows, baselines)
        genesis = con.execute(
            "SELECT body FROM checkpoint_genesis WHERE workspace_id=?", (ws,)
        ).fetchone()
        held = con.execute(
            "SELECT hash FROM checkpoint_heads WHERE workspace_id=?", (ws,)
        ).fetchone()
        staging = {}
        for source, target, expires, manifest in con.execute(
            "SELECT source,target,expires_ms,manifest FROM checkpoint_staging WHERE workspace_id=?",
            (ws,),
        ):
            if expires > now:
                pages = sorted(
                    r[0]
                    for r in con.execute(
                        "SELECT i FROM checkpoint_staging_pages WHERE workspace_id=? AND source=? AND target=?",
                        (ws, source, target),
                    )
                )
                staging[(source, target)] = (expires, pages, manifest is not None)
        return {
            "genesis": P.parse_json(genesis[0]) if genesis else None,
            "held": held[0] if held else None,
            "checkpoints": stored,
            "gone": gone
            | {
                r[0]
                for r in con.execute("SELECT hash FROM checkpoint_gone WHERE workspace_id=?", (ws,))
            },
            "nodes": {
                (log, text(acc)): (seq, text(head), text(prev))
                for log, acc, seq, head, prev in con.execute(
                    "SELECT log,acc,seq,head,prev_acc FROM log_nodes WHERE workspace_id=?", (ws,)
                )
            },
            "transitions": sorted(
                (r, n, bytes(b))
                for r, n, b in con.execute(
                    "SELECT restore_id,target_n,bundle FROM checkpoint_transitions WHERE workspace_id=?",
                    (ws,),
                )
            ),
            "baselines": {
                h: (o, u)
                for h, o, u in con.execute(
                    "SELECT hash,offer_id,until_ms FROM checkpoint_baselines WHERE workspace_id=? AND until_ms>?",
                    (ws, now),
                )
            },
            "revocations": {
                (d, p): r
                for d, p, r in con.execute("SELECT device_id,person_id,reason FROM revocations")
            },
            "chain": {
                (d, p): r
                for d, p, r in con.execute(
                    "SELECT device_id,person_id,reason FROM checkpoint_revocations WHERE workspace_id=?",
                    (ws,),
                )
            },
            "ever": {
                r[0]
                for r in con.execute(
                    "SELECT device_id FROM ever_devices WHERE workspace_id=?1 UNION "
                    "SELECT device_id FROM checkpoint_ever_devices WHERE workspace_id=?1",
                    (ws,),
                )
            },
            "staging": staging,
            "receipts": {
                r[0]
                for r in con.execute(
                    "SELECT digest FROM checkpoint_receipts WHERE workspace_id=?", (ws,)
                )
            },
            "failures": sorted(
                con.execute(
                    "SELECT gen,at_ms FROM checkpoint_failures WHERE workspace_id=? AND at_ms>?",
                    (ws, now - HOUR),
                )
            ),
        }


def registry(path):
    with closing(db.connect(path)) as con:
        return dict(con.execute("SELECT device_id,person_id FROM devices"))


def replay(client, path, case, upto=None):
    """Replay a case's steps (all, or the first `upto`) and check each production result."""
    seed(path, case["state"], case)
    results = []
    for index, s in enumerate(case["steps"][:upto]):
        now = s["input"]["now_ms"]
        before = project_db(path, now)
        result = step(client, path, s["input"], case)
        results.append(result)
        if result == SKIPPED:
            continue
        assert result == s["expect"], (case["name"], index, s["input"]["op"], result, s["expect"])
        if result["status"] >= 400 and s["input"]["op"] != "device_sync":
            after = project_db(path, now)
            before.pop("failures"), after.pop("failures")
            assert after == before, (case["name"], index, "a refusal changed state")
    return results


# --- HTTP fixture preconditions (tests/test_directory_fixtures.py) ----------------------------------

RECORD = V["revocations"][0]["signed"]


def prepare_fixture(client, path, case, success):
    """The state a checkpoint fixture runs in: its bound vector replayed through production up to
    the bound step, or (for transport/auth refusals) the success case's state plus the scenario."""
    given = case["given"]
    if "isolation" in given:
        replay(client, path, find(given["isolation"]["a"]))
        b = find(given["isolation"]["b"])
        seed(path, b["state"], b, ws=WS_B)
        for s in b["steps"][: given.get("vector", {}).get("step", 0)]:
            assert step(client, path, s["input"], b, ws=WS_B) == s["expect"]
    else:
        binding = given.get("vector") or success["given"]["vector"]
        replay(client, path, find(binding), upto=binding["step"])
        scenario = given.get("scenario")
        with closing(db.connect(path)) as con, con:
            if scenario == "not_eligible":
                if case["request"]["headers"].get("Authorization") == "Bearer FAKE-workspace":
                    con.execute(
                        "INSERT OR IGNORE INTO workspaces SELECT ?,owner_person_id,wsk_pub,"
                        "delegation,card,card_seq,wxk_version,client_hosted FROM workspaces "
                        "WHERE workspace_id=?",
                        (WS_B, WS),
                    )
                    con.execute(
                        "UPDATE sessions SET subject_id=? WHERE token_hash=?",
                        (WS_B, token_hash("FAKE-workspace")),
                    )
                else:
                    con.execute("DELETE FROM members WHERE device_id=?", (DEVICE,))
            elif scenario == "cert_expired":
                con.execute(
                    "UPDATE devices SET expires_ms=? WHERE device_id=?", (given["now_ms"], DEVICE)
                )
            elif scenario == "revoked":
                con.execute(
                    "INSERT OR IGNORE INTO revocations VALUES (?,?,?,?,?,"
                    "(SELECT coalesce(max(cursor),0)+1 FROM revocations))",
                    (DEVICE, RECORD["o"]["person_id"], P.cj(RECORD), RECORD["o"]["reason"], 0),
                )
    client.app.state.directory.clock = lambda: given["now_ms"]
