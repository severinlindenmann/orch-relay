import argparse
import os
import re
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
    args = p.parse_args(argv)
    if args.cmd == "invite":
        from .directory import create_invite

        match = re.fullmatch(r"([1-9][0-9]*)([smhd])", args.ttl)
        if match is None:
            p.error("--ttl must be a positive duration, e.g. 7d")
        ttl = int(match[1]) * {"s": 1000, "m": 60_000, "h": 3_600_000, "d": 86_400_000}[match[2]]
        print(create_invite(app_mod.data_dir_from_env() / db.DB_NAME, ttl))
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


if __name__ == "__main__":
    sys.exit(main())
