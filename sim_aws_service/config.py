from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    db_url: str = "sqlite:///./simaws.db"
    max_envs_per_tenant: int = 3
    default_env_ttl_seconds: int = 8 * 60 * 60


def get_settings() -> Settings:
    import os

    db_url = os.environ.get("SIM_AWS_DB_URL", Settings.db_url)
    max_envs_per_tenant = int(os.environ.get("SIM_AWS_MAX_ENVS_PER_TENANT", "3"))
    default_env_ttl_seconds = int(os.environ.get("SIM_AWS_DEFAULT_TTL_SECONDS", str(Settings.default_env_ttl_seconds)))
    return Settings(
        db_url=db_url,
        max_envs_per_tenant=max_envs_per_tenant,
        default_env_ttl_seconds=default_env_ttl_seconds,
    )
