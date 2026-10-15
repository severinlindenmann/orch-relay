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


def create_app(data_dir: Path | str | None = None, instance: str | None = None) -> FastAPI:
    data = Path(data_dir) if data_dir is not None else data_dir_from_env()
    name = instance or os.environ.get("ORCH_RELAY_INSTANCE") or "public"

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await run_in_threadpool(db.migrate, data / db.DB_NAME)
        await run_in_threadpool(app.state.drop.startup_sweep)  # P3-D39, before serving
        tasks = [
            asyncio.create_task(app.state.bridge.maintenance()),
            asyncio.create_task(app.state.checkpoints.maintenance()),
        ]
        # The Drop sweeps assign change positions: they exist only with ORCH_RELAY_DROP=1.
        if (sweeper := app.state.drop.life.start()) is not None:
            tasks.append(sweeper)
        try:
            yield
        finally:
            for task in tasks:
                task.cancel()
                with suppress(asyncio.CancelledError):
                    await task
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

    @app.get("/healthz")
    def healthz() -> dict:
        return {"ok": True, "version": __version__, "instance": name}

    return app
