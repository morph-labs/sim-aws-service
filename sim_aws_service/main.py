from __future__ import annotations

from fastapi import FastAPI

from sim_aws_service.api.v1.router import router as v1_router
from sim_aws_service.config import get_settings
from sim_aws_service.db.db import Database
from sim_aws_service.db.migrate import apply_migrations
from sim_aws_service.integrations.morph import MorphClient
from sim_aws_service.integrations.services_sdk import ServicesSDKClient


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(title="sim-aws-service", version="0.1.0")

    db = Database(settings.db_url)
    apply_migrations(db)

    app.state.db = db
    app.state.morph_client = MorphClient()
    app.state.services_client = ServicesSDKClient()

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    app.include_router(v1_router)
    return app


app = create_app()
