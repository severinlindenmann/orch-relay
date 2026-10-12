import argparse
import json
import os
import re
import sqlite3
import sys

from . import app as app_mod
from . import db


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="orch-relay")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve", help="run the relay (applies pending migrations at startup)")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=int(os.environ.get("ORCH_RELAY_PORT", "8101")))
    sub.add_parser("migrate", help="apply pending migrations and exit")
    invite = sub.add_parser("invite", help="admin invite management")
    invite_sub = invite.add_subparsers(dest="invite_cmd", required=True)
    create = invite_sub.add_parser("create", help="print a single-use invite once")
    create.add_argument("--ttl", default="7d", help="positive duration: s, m, h, d (default 7d)")
    acct = sub.add_parser(
        "account-cap",
        help="audited per-account override of the workspaces-per-account cap (P3-D36)",
    )
    acct_sub = acct.add_subparsers(dest="account_cmd", required=True)
    acct_set = acct_sub.add_parser("set", help="set an account's cap (1..10000), audited")
    acct_set.add_argument("person_id")
    acct_set.add_argument("cap", type=int)
    acct_set.add_argument("--by", required=True, help="the operator making the change")
    acct_set.add_argument("--note", default=None)
    acct_show = acct_sub.add_parser("show", help="owned workspaces, effective cap, override")
    acct_show.add_argument("person_id")
    acct_audit = acct_sub.add_parser("audit", help="the audit rows, oldest first, one per line")
    acct_audit.add_argument("person_id", nargs="?")
    args = p.parse_args(argv)
    if args.cmd == "account-cap":
        return account_cap(p, args)
    if args.cmd == "invite":
        from .directory import create_invite

        match = re.fullmatch(r"([1-9][0-9]*)([smhd])", args.ttl)
        if match is None:
            p.error("--ttl must be a positive duration, e.g. 7d")
        ttl = int(match[1]) * {"s": 1000, "m": 60_000, "h": 3_600_000, "d": 86_400_000}[match[2]]
        try:
            print(create_invite(app_mod.data_dir_from_env() / db.DB_NAME, ttl))
        except ValueError as exc:  # another user's database (P3-D36 review F2)
            p.error(str(exc))
        return 0

    if args.cmd == "migrate":
        applied = db.migrate(app_mod.data_dir_from_env() / db.DB_NAME)
        print("applied:", ", ".join(applied) if applied else "(none)")
        return 0

    import uvicorn

    uvicorn.run(
        app_mod.create_app(), host=args.host, port=args.port, workers=1, proxy_headers=False
    )
    return 0


def account_cap(parser, args):
    """P3-D36: the operator's account-cap commands on the relay's database (JSON on stdout).

    Safe while the relay runs: one SQLite write transaction (BEGIN IMMEDIATE) that waits up to
    ORCH_RELAY_ADMIN_BUSY_MS (default 5000) for the relay's write lock; if still busy, exit 1 with
    nothing written (retry). Bad input exits 2 (argparse) with nothing written."""
    from . import directory as D

    path = app_mod.data_dir_from_env() / db.DB_NAME
    try:
        if args.account_cmd == "set":
            busy = int(os.environ.get("ORCH_RELAY_ADMIN_BUSY_MS", "5000"))
            old, new = D.set_account_cap(
                path, args.person_id, args.cap, args.by, args.note, timeout_ms=busy
            )
            print(json.dumps({"person_id": args.person_id, "old_cap": old, "new_cap": new}))
        elif args.account_cmd == "show":
            cap = int(os.environ.get("ORCH_RELAY_ACCOUNT_WORKSPACES", D.ACCOUNT_WORKSPACES))
            print(json.dumps(D.show_account_cap(path, args.person_id, cap)))
        else:
            for row in D.account_cap_audit(path, args.person_id):
                print(json.dumps(row))
    except ValueError as exc:
        parser.error(str(exc))
    except sqlite3.OperationalError as exc:
        print(f"database busy or unavailable ({exc}); nothing was written", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
