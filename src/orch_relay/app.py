import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI

from . import __version__, db

DEFAULT_DATA = "./data"


def data_dir_from_env() -> Path:
    return Path(os.environ.get("ORCH_RELAY_DATA", DEFAULT_DATA))


def create_app(data_dir: Path | str | None = None, instance: str | None = None) -> FastAPI:
    data = Path(data_dir) if data_dir is not None else data_dir_from_env()
    name = instance or os.environ.get("ORCH_RELAY_INSTANCE") or "public"

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        db.migrate(data / db.DB_NAME)
        yield

    app = FastAPI(title="orch-relay", version=__version__, lifespan=lifespan)
    app.state.data_dir = data
    app.state.instance = name

    @app.get("/healthz")
    def healthz() -> dict:
        return {"ok": True, "version": __version__, "instance": name}

    return app
