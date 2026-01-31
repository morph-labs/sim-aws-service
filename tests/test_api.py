from __future__ import annotations

import hashlib
import json
from pathlib import Path

import jsonschema


def test_requires_authorization_header(client):
    r = client.get("/v1/envs")
    assert r.status_code == 401


def test_create_and_connect_bundle_schema(client, monkeypatch):
    seen = {}

    async def fake_verify_user_api_key(*, auth_header: str) -> None:
        seen["verify_auth_header"] = auth_header
        return None

    async def fake_create_instance(*, auth_header: str, name=None, **_kwargs):
        seen["auth_header"] = auth_header
        return type("X", (), {"instance_id": "morphvm_test123"})()

    async def fake_ensure_http_service_tunnel(*, auth_header: str, instance_id: str, **kwargs):
        seen["tunnel_auth_header"] = auth_header
        assert instance_id == "morphvm_test123"
        return "wss://tunnel-morphvm_test123.http.cloud.morph.so"

    async def fake_provision_env_runtime(*, auth_header: str, instance_id: str, **_kwargs):
        seen["provision_auth_header"] = auth_header
        seen["provision_instance_id"] = instance_id
        return type(
            "X",
            (),
            {
                "wg_client_private_key": "wg_client_priv",
                "wg_server_public_key": "wg_server_pub",
                "ca_cert_pem": "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n",
                "ca_fingerprint_sha256": "deadbeef",
            },
        )()

    app = client.app
    monkeypatch.setattr(app.state.morph_client, "verify_user_api_key", fake_verify_user_api_key)
    monkeypatch.setattr(app.state.morph_client, "create_instance", fake_create_instance)
    monkeypatch.setattr(app.state.morph_client, "ensure_http_service_tunnel", fake_ensure_http_service_tunnel)
    monkeypatch.setattr(app.state.morph_client, "provision_env_runtime", fake_provision_env_runtime)

    headers = {
        "Authorization": "Bearer user-morph-key-abc",
        "X-Morph-Org-Id": "org_123",
        "X-Morph-User-Id": "user_456",
    }
    create = client.post(
        "/v1/envs",
        headers=headers,
        json={"regions": ["us-east-1"], "services": ["s3", "ec2"], "name": "test"},
    )
    assert create.status_code == 200, create.text
    assert create.headers["X-SimAWS-Quota-Mode"] == "quota_disabled"
    body = create.json()
    expect_tenant = "keysha256_" + hashlib.sha256(b"user-morph-key-abc").hexdigest()
    assert body["tenant_id"] == expect_tenant
    assert body["instance_id"] == "morphvm_test123"
    assert seen["verify_auth_header"] == "Bearer user-morph-key-abc"
    assert seen["auth_header"] == "Bearer svc_key_test"
    assert seen["tunnel_auth_header"] == "Bearer svc_key_test"
    assert seen["provision_auth_header"] == "Bearer svc_key_test"
    assert seen["provision_instance_id"] == "morphvm_test123"

    env_id = body["env_id"]
    connect = client.post(f"/v1/envs/{env_id}/connect", headers=headers)
    assert connect.status_code == 200, connect.text
    bundle = connect.json()
    assert bundle["version"] == "v1"
    assert bundle["auth"]["header_value_template"] == "Bearer ${MORPH_API_KEY}"
    assert "user-morph-key-abc" not in json.dumps(bundle)

    schema_path = Path(__file__).resolve().parents[1] / "contracts" / "connect_bundle_v1.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))["schema"]
    jsonschema.validate(instance=bundle, schema=schema)


def test_snapshot_and_restore_updates_instance_id(client, monkeypatch):
    seen = {}

    async def fake_verify_user_api_key(*, auth_header: str) -> None:
        seen["verify_auth_header"] = auth_header
        return None

    async def fake_create_instance(*, auth_header: str, name=None, **_kwargs):
        seen["create_auth_header"] = auth_header
        return type("X", (), {"instance_id": "morphvm_initial"})()

    async def fake_snapshot_instance(*, auth_header: str, instance_id: str):
        assert auth_header == "Bearer svc_key_test"
        assert instance_id == "morphvm_initial"
        return "morphsnap_abc"

    async def fake_create_instance_from_snapshot(*, auth_header: str, snapshot_id: str, name=None, **_kwargs):
        assert auth_header == "Bearer svc_key_test"
        assert snapshot_id == "morphsnap_abc"
        return type("X", (), {"instance_id": "morphvm_restored"})()

    async def fake_wait_snapshot_ready(*, auth_header: str, snapshot_id: str, **_kwargs):
        assert auth_header == "Bearer svc_key_test"
        assert snapshot_id == "morphsnap_abc"
        return None

    async def fake_ensure_http_service_tunnel(*, auth_header: str, instance_id: str, **kwargs):
        assert auth_header == "Bearer svc_key_test"
        assert instance_id in ("morphvm_initial", "morphvm_restored")
        return f"wss://tunnel-{instance_id}.http.cloud.morph.so"

    async def fake_delete_instance(*, auth_header: str, instance_id: str):
        seen["delete_auth_header"] = auth_header
        seen["deleted_instance_id"] = instance_id

    async def fake_provision_env_runtime(*, auth_header: str, instance_id: str, existing_wg_client_private_key=None, **_kwargs):
        assert auth_header == "Bearer svc_key_test"
        assert instance_id in ("morphvm_initial", "morphvm_restored")
        # Should be passed through on restore.
        if instance_id == "morphvm_restored":
            assert existing_wg_client_private_key == "wg_client_priv"
        return type(
            "X",
            (),
            {
                "wg_client_private_key": "wg_client_priv",
                "wg_server_public_key": "wg_server_pub",
                "ca_cert_pem": "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n",
                "ca_fingerprint_sha256": "deadbeef",
            },
        )()

    app = client.app
    monkeypatch.setattr(app.state.morph_client, "verify_user_api_key", fake_verify_user_api_key)
    monkeypatch.setattr(app.state.morph_client, "create_instance", fake_create_instance)
    monkeypatch.setattr(app.state.morph_client, "snapshot_instance", fake_snapshot_instance)
    monkeypatch.setattr(app.state.morph_client, "create_instance_from_snapshot", fake_create_instance_from_snapshot)
    monkeypatch.setattr(app.state.morph_client, "wait_snapshot_ready", fake_wait_snapshot_ready)
    monkeypatch.setattr(app.state.morph_client, "ensure_http_service_tunnel", fake_ensure_http_service_tunnel)
    monkeypatch.setattr(app.state.morph_client, "delete_instance", fake_delete_instance)
    monkeypatch.setattr(app.state.morph_client, "provision_env_runtime", fake_provision_env_runtime)

    headers = {
        "Authorization": "Bearer user-morph-key-abc",
        "X-Morph-Org-Id": "org_123",
    }
    create = client.post(
        "/v1/envs",
        headers=headers,
        json={"regions": ["us-east-1"], "services": ["s3"], "name": "test"},
    )
    assert create.status_code == 200, create.text
    env_id = create.json()["env_id"]

    snap = client.post(f"/v1/envs/{env_id}/snapshot", headers=headers)
    assert snap.status_code == 200, snap.text
    snapshot_id = snap.json()["snapshot_id"]

    restore = client.post(
        f"/v1/envs/{env_id}/restore",
        headers=headers,
        json={"snapshot_id": snapshot_id},
    )
    assert restore.status_code == 200, restore.text
    restored_env = restore.json()
    assert restored_env["instance_id"] == "morphvm_restored"
    assert seen["verify_auth_header"] == "Bearer user-morph-key-abc"
    assert seen["delete_auth_header"] == "Bearer svc_key_test"
    assert seen["deleted_instance_id"] == "morphvm_initial"
