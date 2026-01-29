from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    db_url: str = "sqlite:///./simaws.db"
    max_envs_per_tenant: int = 3


def get_settings() -> Settings:
    import os

    db_url = os.environ.get("SIM_AWS_DB_URL", Settings.db_url)
    max_envs_per_tenant = int(os.environ.get("SIM_AWS_MAX_ENVS_PER_TENANT", "3"))
    return Settings(db_url=db_url, max_envs_per_tenant=max_envs_per_tenant)

