import argparse
import os
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
    args = p.parse_args(argv)

    if args.cmd == "migrate":
        applied = db.migrate(app_mod.data_dir_from_env() / db.DB_NAME)
        print("applied:", ", ".join(applied) if applied else "(none)")
        return 0

    import uvicorn

    from .push_config import PushConfigError

    try:
        app = app_mod.create_app()
    except PushConfigError as exc:  # P3-D40 item 9: a partial push configuration is loud
        print(f"orch-relay: refusing to start: {exc}", file=sys.stderr)
        return 2
    uvicorn.run(app, host=args.host, port=args.port, workers=1, proxy_headers=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
