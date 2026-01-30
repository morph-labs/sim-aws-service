from __future__ import annotations

import asyncio
import json

import httpx

from sim_aws_service.integrations.morph import MorphClient
from sim_aws_service.integrations.services_sdk import ServicesSDKClient


def test_morph_client_request_paths_and_restore_url(monkeypatch):
    monkeypatch.setenv("SIM_AWS_MORPH_SNAPSHOT_ID", "snap_base")
    monkeypatch.setenv("SIM_AWS_TUNNEL_PORT", "8080")

    seen: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, request.url.path))
        assert request.headers.get("authorization") == "Bearer user-key"

        if request.method == "POST" and request.url.path == "/api/instance":
            assert request.url.params.get("snapshot_id") == "snap_base"
            body = json.loads(request.content.decode("utf-8"))
            assert body["metadata"]["project"] == "sim-aws-service"
            return httpx.Response(200, json={"id": "inst_1"})

        if request.method == "GET" and request.url.path == "/api/instance/inst_1":
            return httpx.Response(
                200,
                json={
                    "id": "inst_1",
                    "status": "ready",
                    "networking": {
                        "http_services": [{"name": "tunnel", "url": "https://tunnel-inst_1.http.cloud.morph.so"}]
                    },
                },
            )

        if request.method == "DELETE" and request.url.path == "/api/instance/inst_1/http/tunnel":
            return httpx.Response(404, json={})

        if request.method == "POST" and request.url.path == "/api/instance/inst_1/http":
            body = json.loads(request.content.decode("utf-8"))
            assert body == {"name": "tunnel", "port": 8080, "auth_mode": "api_key"}
            return httpx.Response(200, json={})

        if request.method == "POST" and request.url.path == "/api/instance/inst_1/wake-on":
            body = json.loads(request.content.decode("utf-8"))
            assert body == {"wake_on_http": True}
            return httpx.Response(200, json={})

        if request.method == "POST" and request.url.path == "/api/instance/inst_1/snapshot":
            return httpx.Response(200, json={"id": "snap_1"})

        if request.method == "GET" and request.url.path == "/api/snapshot/snap_1":
            return httpx.Response(200, json={"id": "snap_1", "status": "READY"})

        if request.method == "POST" and request.url.path == "/api/instance/inst_1/pause":
            return httpx.Response(200, json={})

        if request.method == "POST" and request.url.path == "/api/instance/inst_1/resume":
            return httpx.Response(200, json={})

        if request.method == "DELETE" and request.url.path == "/api/instance/inst_1":
            return httpx.Response(200, json={})

        return httpx.Response(500, json={"error": f"unexpected request {request.method} {request.url}"})

    transport = httpx.MockTransport(handler)
    morph = MorphClient(base_url="https://morph.example/api", transport=transport, ready_timeout_s=5.0, ready_poll_interval_s=0.0)

    async def run() -> None:
        created = await morph.create_instance(auth_header="Bearer user-key", name="test")
        assert created.instance_id == "inst_1"

        ws_url = await morph.ensure_http_service_tunnel(
            auth_header="Bearer user-key",
            instance_id="inst_1",
            service_name="tunnel",
            auth_mode="api_key",
            wake_on_http=True,
        )
        assert ws_url == "wss://tunnel-inst_1.http.cloud.morph.so"

        snap_id = await morph.snapshot_instance(auth_header="Bearer user-key", instance_id="inst_1")
        assert snap_id == "snap_1"

        await morph.pause_instance(auth_header="Bearer user-key", instance_id="inst_1")
        await morph.start_instance(auth_header="Bearer user-key", instance_id="inst_1")
        await morph.delete_instance(auth_header="Bearer user-key", instance_id="inst_1")

    asyncio.run(run())

    assert ("POST", "/api/instance") in seen
    assert ("GET", "/api/instance/inst_1") in seen
    assert ("POST", "/api/instance/inst_1/http") in seen
    assert ("POST", "/api/instance/inst_1/wake-on") in seen


def test_services_sdk_client_paths_and_headers():
    seen: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, request.url.path))
        assert request.headers.get("authorization") == "Bearer svc_123"

        if request.method == "POST" and request.url.path == "/service/auth/user":
            body = json.loads(request.content.decode("utf-8"))
            assert body == {"api_key": "user_key_abc"}
            return httpx.Response(
                200,
                json={
                    "id": "user_1",
                    "email": "user@example.com",
                    "account_type": "free",
                    "is_restricted": False,
                    "organization_id": "org_1",
                },
            )

        if request.method == "GET" and request.url.path == "/service/user/user_1":
            return httpx.Response(404, json={"detail": "not found"})

        if request.method == "POST" and request.url.path == "/service/user/user_1":
            body = json.loads(request.content.decode("utf-8"))
            assert body["morph:owner:user_id"] == "user_1"
            assert body["morph:owner:organization_id"] == "org_1"
            return httpx.Response(200, json={"id": "su_1", "user_id": "user_1", "service_id": "sim-aws", "metadata": body})

        if request.method == "POST" and request.url.path == "/service/resource":
            body = json.loads(request.content.decode("utf-8"))
            assert body["user_id"] == "user_1"
            assert body["resource_type"] == "sim-aws-env"
            assert body["client_key"] == "env_1"
            assert body["quota_usages"] == [{"quota_code": "sim_aws_max_envs", "amount": 1}]
            return httpx.Response(200, json={"resource_id": "res_1", "already_exists": False})

        return httpx.Response(500, json={"error": f"unexpected request {request.method} {request.url}"})

    transport = httpx.MockTransport(handler)
    client = ServicesSDKClient(service_api_key="svc_123", base_url="https://service.example", transport=transport)

    async def run() -> None:
        actor = await client.ensure_service_user(tenant_id="ignored", auth_header="Bearer user_key_abc")
        assert actor.tenant_id == "org_1"
        assert actor.request_user_id == "user_1"
        await client.enforce_quota(tenant_id="ignored", auth_header="Bearer user_key_abc", env_count=0, max_envs=0, env_id="env_1")

    asyncio.run(run())

    assert ("POST", "/service/auth/user") in seen
    assert ("POST", "/service/resource") in seen


def test_services_sdk_client_quota_disabled_mode():
    client = ServicesSDKClient(service_api_key=None, base_url="https://service.example")
    assert client.mode == "quota_disabled"
    assert client.quota_blocked_reason
