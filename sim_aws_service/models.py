from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


EnvStatus = Literal["creating", "ready", "paused", "error", "deleting"]


class EnvCreateRequest(BaseModel):
    regions: list[str] = Field(min_length=1)
    services: list[str] = Field(min_length=1)
    ttl_seconds: int | None = Field(default=None, ge=60)
    name: str | None = None
    metadata: dict[str, Any] | None = None
    terraform_bundle: dict[str, Any] | None = None


class EnvRestoreRequest(BaseModel):
    snapshot_id: str = Field(min_length=1)


class Environment(BaseModel):
    env_id: str
    tenant_id: str
    instance_id: str
    status: EnvStatus
    region_set: list[str]
    cidr: str
    dns_ip: str
    aws_gateway_ip: str
    tunnel_url: str
    ca_cert_pem: str
    snapshots: list[dict[str, Any]] = []


class SnapshotResponse(BaseModel):
    snapshot_id: str
    env_id: str
    morph_snapshot_id: str | None = None
    note: str | None = None
    created_at: str


class ConnectBundle(BaseModel):
    version: Literal["v1"] = "v1"
    env_id: str
    instance_id: str
    tunnel_ws_url: str
    wg: dict[str, Any]
    dns: dict[str, Any]
    tls: dict[str, Any]
    aws: dict[str, Any]
    auth: dict[str, Any] | None = None
    notes: list[str] | None = None
