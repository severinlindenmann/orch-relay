import asyncio
import os
from contextlib import asynccontextmanager, suppress
from pathlib import Path

from fastapi import FastAPI
from starlette.concurrency import run_in_threadpool

from . import __version__, db
from .common import install as install_core

DEFAULT_DATA = "./data"


def data_dir_from_env() -> Path:
    return Path(os.environ.get("ORCH_RELAY_DATA", DEFAULT_DATA))


def create_app(data_dir: Path | str | None = None, instance: str | None = None) -> FastAPI:
    data = Path(data_dir) if data_dir is not None else data_dir_from_env()
    name = instance or os.environ.get("ORCH_RELAY_INSTANCE") or "public"

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await run_in_threadpool(db.init_schema, data / db.DB_NAME)
        tasks = []
        if app.state.push.enabled:  # the expired-mailbox sweep and APNs delivery
            tasks.append(asyncio.create_task(app.state.push.maintenance()))
            tasks.append(asyncio.create_task(app.state.push.sender.run()))
        try:
            yield
        finally:
            for task in tasks:
                task.cancel()
                with suppress(asyncio.CancelledError):
                    await task
            app.state.core.close()

    app = FastAPI(title="orch-relay", version=__version__, lifespan=lifespan)
    app.state.data_dir = data
    app.state.instance = name
    install_core(app, data)

    from .relay_info import install as install_relay_info

    install_relay_info(app)  # H12d (P3-D38)
    from .push import install as install_push

    install_push(app)  # D77: raises PushConfigError on a partial configuration

    from .hub_accounts import install as install_hub_accounts

    install_hub_accounts(app)  # E1: hub accounts by hub card (ORCH_RELAY_DEV = dev relay)

    from .hub_phone import install as install_hub_phone

    install_hub_phone(
        app
    )  # E2: hub push targets, push send and channel mailboxes (signed by HK_op)

    from .hub_channels import install as install_hub_channels

    install_hub_channels(app)  # E5: a phone reads its own channel mailbox (§10.8.4)

    @app.get("/healthz")
    def healthz() -> dict:
        return {"ok": True, "version": __version__, "instance": name}

    return app
