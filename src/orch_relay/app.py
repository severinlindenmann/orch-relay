import asyncio
import os
from contextlib import asynccontextmanager, suppress
from pathlib import Path

from fastapi import FastAPI
from starlette.concurrency import run_in_threadpool

from . import __version__, db
from .directory import install

DEFAULT_DATA = "./data"


def data_dir_from_env() -> Path:
    return Path(os.environ.get("ORCH_RELAY_DATA", DEFAULT_DATA))


def create_app(
    data_dir: Path | str | None = None, instance: str | None = None, serve: bool = False
) -> FastAPI:
    """`serve` is `orch-relay serve` only: that process takes the Drop state lock (D39a2 part 4)."""
    data = Path(data_dir) if data_dir is not None else data_dir_from_env()
    name = instance or os.environ.get("ORCH_RELAY_INSTANCE") or "public"

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await run_in_threadpool(db.migrate, data / db.DB_NAME)
        drop = app.state.drop
        # P3-D39 (D39a2 part 4), in this order: the state check, the lock, the generation check and
        # the start write, then the start-up sweep and the routes. A failed check never stops the
        # process: it only keeps the Drop routes and every `n`-assigning sweep off.
        await run_in_threadpool(drop.state.start)
        await run_in_threadpool(drop.startup_sweep)  # P3-D39, before serving
        tasks = [
            asyncio.create_task(app.state.bridge.maintenance()),
            asyncio.create_task(app.state.checkpoints.maintenance()),
        ]
        # The Drop sweeps assign change positions: they exist only with ORCH_RELAY_DROP=1.
        if (sweeper := app.state.drop.life.start()) is not None:
            tasks.append(sweeper)
        if drop.state.ok and drop.state.required:
            tasks.append(asyncio.create_task(drop.state.maintenance()))
        tasks.append(asyncio.create_task(app.state.hooks.maintenance()))  # #81: rings and expiry
        if app.state.push.enabled:  # P3-D40: the stale and expired-certificate sweep
            tasks.append(asyncio.create_task(app.state.push.maintenance()))
            tasks.append(asyncio.create_task(app.state.push.sender.run()))  # APNs delivery
        try:
            yield
        finally:
            for task in tasks:
                task.cancel()
                with suppress(asyncio.CancelledError):
                    await task
            await run_in_threadpool(drop.state.shutdown)  # the last high-water write, the lock
            app.state.bridge.close()

    app = FastAPI(title="orch-relay", version=__version__, lifespan=lifespan)
    app.state.data_dir = data
    app.state.instance = name
    install(app, data)
    from .bridge import install as install_bridge

    install_bridge(app)
    from .checkpoints import install as install_checkpoints

    install_checkpoints(app)
    from .relay_info import install as install_relay_info

    install_relay_info(app)  # H12d (P3-D38)
    from .drop import install as install_drop

    install_drop(app)  # P3-D39 (D39a1)
    app.state.drop.state.hold_lock = serve
    from .push import install as install_push

    install_push(app)  # P3-D40 (D40a): raises PushConfigError on a partial configuration

    from .hooks import install as install_hooks

    install_hooks(app)  # orch-relay #81: webhook doorbells for follow-ups

    from .hub_accounts import install as install_hub_accounts

    install_hub_accounts(app)  # E1: hub accounts by hub card (ORCH_RELAY_DEV = dev relay)

    from .cutover import install as install_cutover

    # E3: per-workspace cut-over to a hub. Before any `/v2/hubs/{hub}/{tail:path}` catch-all (first match wins).
    install_cutover(app)

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
