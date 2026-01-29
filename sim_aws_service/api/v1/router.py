from __future__ import annotations

from fastapi import APIRouter

from sim_aws_service.api.v1 import env


router = APIRouter(prefix="/v1")
router.include_router(env.router)

