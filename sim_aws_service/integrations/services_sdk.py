from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Literal

import httpx


@dataclass(frozen=True)
class ServiceUser:
    tenant_id: str
    request_user_id: str


class ServicesSDKClient:
    def __init__(
        self,
        *,
        service_api_key: str | None = None,
        base_url: str | None = None,
        timeout_s: float = 15.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._service_api_key = service_api_key or os.environ.get("SERVICES_API_KEY")
        self._timeout_s = timeout_s
        self._transport = transport

        default_base = "https://service.svc.cloud.morph.so"
        raw_base = (base_url or os.environ.get("SERVICES_BASE_URL") or default_base).rstrip("/")
        self._base_url = raw_base if raw_base.endswith("/service") else f"{raw_base}/service"

    @property
    def mode(self) -> Literal["enabled", "quota_disabled"]:
        return "enabled" if self._service_api_key else "quota_disabled"

    @property
    def quota_blocked_reason(self) -> str | None:
        if self._service_api_key:
            return None
        return "SERVICES_API_KEY not set"

    def _service_headers(self) -> dict[str, str]:
        if not self._service_api_key:
            raise RuntimeError("ServicesSDKClient is not configured (missing SERVICES_API_KEY)")
        return {"Authorization": f"Bearer {self._service_api_key}", "Content-Type": "application/json"}

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=self._base_url,
            timeout=self._timeout_s,
            transport=self._transport,
        )

    @staticmethod
    def _parse_bearer(auth_header: str) -> str:
        prefix = "Bearer "
        if not auth_header.startswith(prefix) or len(auth_header) <= len(prefix):
            raise ValueError("Invalid auth_header; expected Bearer token")
        return auth_header[len(prefix) :].strip()

    async def _authenticate_user(self, *, user_api_key: str) -> dict[str, Any]:
        async with self._client() as client:
            r = await client.post("/auth/user", headers=self._service_headers(), json={"api_key": user_api_key})
            r.raise_for_status()
            return r.json()

    async def _resolve_actor(self, *, auth_header: str) -> ServiceUser:
        user_api_key = self._parse_bearer(auth_header)
        info = await self._authenticate_user(user_api_key=user_api_key)
        request_user_id = str(info["id"])
        tenant_id = str(info.get("organization_id") or request_user_id)
        return ServiceUser(tenant_id=tenant_id, request_user_id=request_user_id)

    async def ensure_service_user(self, *, tenant_id: str, auth_header: str) -> ServiceUser:
        _ = tenant_id
        if not self._service_api_key:
            return ServiceUser(tenant_id=tenant_id, request_user_id=tenant_id)

        actor = await self._resolve_actor(auth_header=auth_header)
        async with self._client() as client:
            r = await client.get(f"/user/{actor.request_user_id}", headers=self._service_headers())
            if r.status_code == 404:
                metadata: dict[str, str] = {
                    "morph:owner:user_id": actor.request_user_id,
                    "morph:owner:organization_id": actor.tenant_id,
                    "project": "sim-aws-service",
                }
                r = await client.post(
                    f"/user/{actor.request_user_id}",
                    headers=self._service_headers(),
                    json=metadata,
                )
            r.raise_for_status()
        return actor

    async def enforce_quota(
        self,
        *,
        tenant_id: str,
        auth_header: str,
        env_count: int,
        max_envs: int,
        env_id: str | None = None,
    ) -> None:
        _ = tenant_id
        if not self._service_api_key:
            return
        if env_id is None:
            return

        actor = await self._resolve_actor(auth_header=auth_header)
        payload: dict[str, Any] = {
            "user_id": actor.request_user_id,
            "resource_type": "sim-aws-env",
            "client_key": env_id,
            "quota_usages": [{"quota_code": "sim_aws_max_envs", "amount": 1}],
            "metadata": {
                "morph:owner:user_id": actor.request_user_id,
                "morph:owner:organization_id": actor.tenant_id,
                "sim_aws:env_id": env_id,
            },
        }
        async with self._client() as client:
            r = await client.post("/resource", headers=self._service_headers(), json=payload)
            if r.status_code >= 400:
                detail = None
                try:
                    detail = r.json()
                except Exception:
                    detail = r.text
                raise PermissionError(f"quota blocked by services api: status={r.status_code} detail={detail}")

        _ = env_count, max_envs

    async def release_env_resource(self, *, auth_header: str, env_id: str) -> None:
        if not self._service_api_key:
            return
        actor = await self._resolve_actor(auth_header=auth_header)
        payload = {"user_id": actor.request_user_id, "resource_type": "sim-aws-env", "client_key": env_id}
        async with self._client() as client:
            r = await client.request("DELETE", "/resource", headers=self._service_headers(), json=payload)
            if r.status_code in (404, 204, 200):
                return
            r.raise_for_status()

    async def record_env_resource(self, *, tenant_id: str, auth_header: str, env_id: str) -> None:
        await self.enforce_quota(tenant_id=tenant_id, auth_header=auth_header, env_count=0, max_envs=0, env_id=env_id)
