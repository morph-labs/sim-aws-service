from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from sim_aws_service.auth import CallerContext, get_caller
from sim_aws_service.config import Settings, get_settings
from sim_aws_service.db.db import Database
from sim_aws_service.integrations.morph import MorphClient
from sim_aws_service.integrations.services_sdk import ServicesSDKClient
from sim_aws_service.models import ConnectBundle, EnvCreateRequest, Environment, EnvRestoreRequest, SnapshotResponse


router = APIRouter(prefix="/envs", tags=["envs"])


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _redact_secrets(text: str) -> str:
    text = text.replace("\n", " ").replace("\r", " ")
    text = re.sub(r"(?i)bearer\\s+[^\\s,;\\\"']+", "Bearer [REDACTED]", text)
    text = re.sub(r"(?i)(morph_api_key|api_key)\\s*[=:]\\s*[^\\s,;\\\"']+", r"\\1=[REDACTED]", text)
    return text


def _sanitize_morph_restore_error(e: Exception) -> str:
    base = f"restore failed calling morph: {type(e).__name__}"
    status_code = getattr(getattr(e, "response", None), "status_code", None)
    request = getattr(e, "request", None)
    method = getattr(request, "method", None)
    url = getattr(request, "url", None)

    parts: list[str] = [base]
    if status_code is not None:
        parts.append(f"status_code={status_code}")
    if method and url:
        parts.append(f"{method} {url}")
    else:
        parts.append(_redact_secrets(str(e))[:200])
    return ": ".join(parts)[:300]


def _allocate_cidr(db: Database) -> tuple[str, str, str, str]:
    rows = db.fetchall("SELECT cidr FROM envs WHERE deleted_at IS NULL;")
    used = set()
    for r in rows:
        cidr = str(r["cidr"])
        try:
            used.add(int(cidr.split(".")[2]))
        except Exception:
            continue
    for idx in range(1, 255):
        if idx not in used:
            cidr = f"10.250.{idx}.0/24"
            dns_ip = f"10.250.{idx}.1"
            aws_gateway_ip = f"10.250.{idx}.2"
            client_ip = f"10.250.{idx}.100/32"
            return cidr, dns_ip, aws_gateway_ip, client_ip
    raise RuntimeError("no free CIDR blocks available")


def get_db(request: Request) -> Database:
    return request.app.state.db


def get_morph_client(request: Request) -> MorphClient:
    return request.app.state.morph_client


def get_services_client(request: Request) -> ServicesSDKClient:
    return request.app.state.services_client


@router.post("", response_model=Environment)
async def create_env(
    body: EnvCreateRequest,
    caller: Annotated[CallerContext, Depends(get_caller)],
    db: Annotated[Database, Depends(get_db)],
    morph: Annotated[MorphClient, Depends(get_morph_client)],
    services: Annotated[ServicesSDKClient, Depends(get_services_client)],
    settings: Annotated[Settings, Depends(get_settings)],
    response: Response,
) -> Environment:
    existing_count = db.fetchone(
        "SELECT COUNT(*) AS c FROM envs WHERE tenant_id = ? AND deleted_at IS NULL;",
        (caller.tenant_id,),
    )["c"]

    env_id = f"awsenv_{uuid.uuid4().hex}"
    response.headers["X-SimAWS-Quota-Mode"] = services.mode
    if services.mode != "enabled":
        response.headers["X-SimAWS-Quota-Blocked"] = "true"
        if services.quota_blocked_reason:
            response.headers["X-SimAWS-Quota-Reason"] = services.quota_blocked_reason

    try:
        await services.ensure_service_user(tenant_id=caller.tenant_id, auth_header=caller.morph_authorization_header)
        await services.enforce_quota(
            tenant_id=caller.tenant_id,
            auth_header=caller.morph_authorization_header,
            env_count=int(existing_count),
            max_envs=settings.max_envs_per_tenant,
            env_id=env_id,
        )
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e)) from e

    cidr, dns_ip, aws_gateway_ip, wg_client_address = _allocate_cidr(db)

    effective_ttl = body.ttl_seconds if body.ttl_seconds is not None else settings.default_env_ttl_seconds
    ttl_action = "pause" if effective_ttl is not None else None

    try:
        instance = await morph.create_instance(
            auth_header=caller.morph_authorization_header,
            name=body.name,
            metadata=body.metadata,
            ttl_seconds=effective_ttl,
            env_id=env_id,
            ttl_action=ttl_action,
        )
        tunnel_ws_url = await morph.ensure_http_service_tunnel(
            auth_header=caller.morph_authorization_header,
            instance_id=instance.instance_id,
            service_name="tunnel",
            auth_mode=None,
            wake_on_http=True,
        )
        provision = await morph.provision_env_runtime(
            auth_header=caller.morph_authorization_header,
            instance_id=instance.instance_id,
            env_id=env_id,
            cidr=cidr,
            dns_ip=dns_ip,
            aws_gateway_ip=aws_gateway_ip,
            regions=body.regions,
            services=body.services,
            wg_client_address=wg_client_address,
            wg_allowed_ips=[cidr],
        )
    except Exception:
        try:
            if "instance" in locals() and getattr(instance, "instance_id", None):
                await morph.delete_instance(auth_header=caller.morph_authorization_header, instance_id=instance.instance_id)
        except Exception:
            pass
        try:
            await services.release_env_resource(auth_header=caller.morph_authorization_header, env_id=env_id)
        except Exception:
            pass
        raise

    ca_cert_pem = provision.ca_cert_pem
    ca_fingerprint = provision.ca_fingerprint_sha256

    wg_client_private_key = provision.wg_client_private_key
    wg_server_public_key = provision.wg_server_public_key
    wg_allowed_ips = [cidr]
    wg_endpoint_host = "127.0.0.1"
    wg_endpoint_port = 51820
    wg_mtu = 1280
    wg_keepalive = 25

    now = _now()
    db.execute(
        """
        INSERT INTO envs(
          env_id, tenant_id, user_id, org_id, name, status,
          regions_json, services_json,
          cidr, dns_ip, aws_gateway_ip, tunnel_ws_url,
          ca_cert_pem, ca_fingerprint_sha256,
          instance_id, created_at, updated_at, deleted_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL);
        """,
        (
            env_id,
            caller.tenant_id,
            caller.user_id,
            caller.org_id,
            body.name,
            "ready",
            json.dumps(body.regions),
            json.dumps(body.services),
            cidr,
            dns_ip,
            aws_gateway_ip,
            tunnel_ws_url,
            ca_cert_pem,
            ca_fingerprint,
            instance.instance_id,
            now,
            now,
        ),
    )
    db.execute(
        """
        INSERT INTO env_secrets(
          env_id, wg_client_address, wg_client_private_key, wg_server_public_key,
          wg_allowed_ips_json, wg_endpoint_host, wg_endpoint_port, wg_mtu, wg_persistent_keepalive
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
        """,
        (
            env_id,
            wg_client_address,
            wg_client_private_key,
            wg_server_public_key,
            json.dumps(wg_allowed_ips),
            wg_endpoint_host,
            wg_endpoint_port,
            wg_mtu,
            wg_keepalive,
        ),
    )
    await services.record_env_resource(tenant_id=caller.tenant_id, auth_header=caller.morph_authorization_header, env_id=env_id)

    return Environment(
        env_id=env_id,
        tenant_id=caller.tenant_id,
        instance_id=instance.instance_id,
        status="ready",
        region_set=body.regions,
        cidr=cidr,
        dns_ip=dns_ip,
        aws_gateway_ip=aws_gateway_ip,
        tunnel_url=tunnel_ws_url,
        ca_cert_pem=ca_cert_pem,
        snapshots=[],
    )


@router.get("", response_model=list[Environment])
async def list_envs(
    caller: Annotated[CallerContext, Depends(get_caller)],
    db: Annotated[Database, Depends(get_db)],
) -> list[Environment]:
    rows = db.fetchall(
        """
        SELECT * FROM envs
        WHERE tenant_id = ? AND deleted_at IS NULL
        ORDER BY created_at DESC;
        """,
        (caller.tenant_id,),
    )
    envs: list[Environment] = []
    for r in rows:
        envs.append(
            Environment(
                env_id=r["env_id"],
                tenant_id=r["tenant_id"],
                instance_id=r["instance_id"],
                status=r["status"],
                region_set=json.loads(r["regions_json"]),
                cidr=r["cidr"],
                dns_ip=r["dns_ip"],
                aws_gateway_ip=r["aws_gateway_ip"],
                tunnel_url=r["tunnel_ws_url"],
                ca_cert_pem=r["ca_cert_pem"],
                snapshots=[],
            )
        )
    return envs


def _get_env_row(db: Database, *, env_id: str, tenant_id: str) -> Any:
    row = db.fetchone(
        "SELECT * FROM envs WHERE env_id = ? AND tenant_id = ? AND deleted_at IS NULL;",
        (env_id, tenant_id),
    )
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="env not found")
    return row


@router.get("/{env_id}", response_model=Environment)
async def get_env(
    env_id: str,
    caller: Annotated[CallerContext, Depends(get_caller)],
    db: Annotated[Database, Depends(get_db)],
) -> Environment:
    r = _get_env_row(db, env_id=env_id, tenant_id=caller.tenant_id)
    return Environment(
        env_id=r["env_id"],
        tenant_id=r["tenant_id"],
        instance_id=r["instance_id"],
        status=r["status"],
        region_set=json.loads(r["regions_json"]),
        cidr=r["cidr"],
        dns_ip=r["dns_ip"],
        aws_gateway_ip=r["aws_gateway_ip"],
        tunnel_url=r["tunnel_ws_url"],
        ca_cert_pem=r["ca_cert_pem"],
        snapshots=[],
    )


@router.post("/{env_id}/start", response_model=Environment)
async def start_env(
    env_id: str,
    caller: Annotated[CallerContext, Depends(get_caller)],
    db: Annotated[Database, Depends(get_db)],
    morph: Annotated[MorphClient, Depends(get_morph_client)],
) -> Environment:
    r = _get_env_row(db, env_id=env_id, tenant_id=caller.tenant_id)
    await morph.start_instance(auth_header=caller.morph_authorization_header, instance_id=r["instance_id"])
    db.execute("UPDATE envs SET status = ?, updated_at = ? WHERE env_id = ?;", ("ready", _now(), env_id))
    return await get_env(env_id, caller, db)


@router.post("/{env_id}/pause", response_model=Environment)
async def pause_env(
    env_id: str,
    caller: Annotated[CallerContext, Depends(get_caller)],
    db: Annotated[Database, Depends(get_db)],
    morph: Annotated[MorphClient, Depends(get_morph_client)],
) -> Environment:
    r = _get_env_row(db, env_id=env_id, tenant_id=caller.tenant_id)
    await morph.pause_instance(auth_header=caller.morph_authorization_header, instance_id=r["instance_id"])
    db.execute("UPDATE envs SET status = ?, updated_at = ? WHERE env_id = ?;", ("paused", _now(), env_id))
    return await get_env(env_id, caller, db)


@router.post("/{env_id}/restore", response_model=Environment)
async def restore_env(
    env_id: str,
    body: EnvRestoreRequest,
    caller: Annotated[CallerContext, Depends(get_caller)],
    db: Annotated[Database, Depends(get_db)],
    morph: Annotated[MorphClient, Depends(get_morph_client)],
) -> Environment:
    env = _get_env_row(db, env_id=env_id, tenant_id=caller.tenant_id)
    secrets_row = db.fetchone("SELECT * FROM env_secrets WHERE env_id = ?;", (env_id,))
    if secrets_row is None:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="missing env secrets")
    snapshot_row = db.fetchone(
        "SELECT * FROM snapshots WHERE snapshot_id = ? AND env_id = ?;",
        (body.snapshot_id, env_id),
    )
    if snapshot_row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="snapshot not found")
    morph_snapshot_id = snapshot_row["morph_snapshot_id"]
    if not morph_snapshot_id:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="snapshot missing morph_snapshot_id")

    old_instance_id = env["instance_id"]
    try:
        await morph.wait_snapshot_ready(auth_header=caller.morph_authorization_header, snapshot_id=morph_snapshot_id)
        new_instance = await morph.create_instance_from_snapshot(
            auth_header=caller.morph_authorization_header,
            snapshot_id=morph_snapshot_id,
            name=env["name"],
            env_id=env_id,
        )
        tunnel_ws_url = await morph.ensure_http_service_tunnel(
            auth_header=caller.morph_authorization_header,
            instance_id=new_instance.instance_id,
            service_name="tunnel",
            auth_mode=None,
            wake_on_http=True,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=_sanitize_morph_restore_error(e),
        ) from None
    # NOTE: on restore, reuse env runtime state from the Morph snapshot; do not re-provision via /instance/exec.

    db.execute(
        "UPDATE envs SET status = ?, instance_id = ?, tunnel_ws_url = ?, ca_cert_pem = ?, ca_fingerprint_sha256 = ?, updated_at = ? WHERE env_id = ?;",
        ("ready", new_instance.instance_id, tunnel_ws_url, env["ca_cert_pem"], env["ca_fingerprint_sha256"], _now(), env_id),
    )
    try:
        await morph.delete_instance(auth_header=caller.morph_authorization_header, instance_id=old_instance_id)
    except Exception:
        pass

    return await get_env(env_id, caller, db)


@router.delete("/{env_id}")
async def delete_env(
    env_id: str,
    caller: Annotated[CallerContext, Depends(get_caller)],
    db: Annotated[Database, Depends(get_db)],
    morph: Annotated[MorphClient, Depends(get_morph_client)],
    services: Annotated[ServicesSDKClient, Depends(get_services_client)],
) -> dict[str, str]:
    r = _get_env_row(db, env_id=env_id, tenant_id=caller.tenant_id)
    await morph.delete_instance(auth_header=caller.morph_authorization_header, instance_id=r["instance_id"])
    try:
        await services.release_env_resource(auth_header=caller.morph_authorization_header, env_id=env_id)
    except Exception:
        pass
    now = _now()
    db.execute(
        "UPDATE envs SET status = ?, updated_at = ?, deleted_at = ? WHERE env_id = ?;",
        ("deleting", now, now, env_id),
    )
    return {"status": "deleted"}


@router.post("/{env_id}/snapshot", response_model=SnapshotResponse)
async def snapshot_env(
    env_id: str,
    caller: Annotated[CallerContext, Depends(get_caller)],
    db: Annotated[Database, Depends(get_db)],
    morph: Annotated[MorphClient, Depends(get_morph_client)],
) -> SnapshotResponse:
    r = _get_env_row(db, env_id=env_id, tenant_id=caller.tenant_id)
    morph_snapshot_id = await morph.snapshot_instance(auth_header=caller.morph_authorization_header, instance_id=r["instance_id"])
    snapshot_id = f"awssnap_{uuid.uuid4().hex}"
    now = _now()
    db.execute(
        """
        INSERT INTO snapshots(snapshot_id, env_id, morph_snapshot_id, note, created_at)
        VALUES (?, ?, ?, NULL, ?);
        """,
        (snapshot_id, env_id, morph_snapshot_id, now),
    )
    return SnapshotResponse(
        snapshot_id=snapshot_id,
        env_id=env_id,
        morph_snapshot_id=morph_snapshot_id,
        note=None,
        created_at=now,
    )


@router.post("/{env_id}/connect", response_model=ConnectBundle)
async def connect_env(
    env_id: str,
    caller: Annotated[CallerContext, Depends(get_caller)],
    db: Annotated[Database, Depends(get_db)],
    morph: Annotated[MorphClient, Depends(get_morph_client)],
) -> ConnectBundle:
    env = _get_env_row(db, env_id=env_id, tenant_id=caller.tenant_id)
    secrets_row = db.fetchone("SELECT * FROM env_secrets WHERE env_id = ?;", (env_id,))
    if secrets_row is None:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="missing env secrets")

    tunnel_ws_url = env["tunnel_ws_url"]
    try:
        tunnel_ws_url = await morph.ensure_http_service_tunnel(
            auth_header=caller.morph_authorization_header,
            instance_id=env["instance_id"],
            service_name="tunnel",
            auth_mode=None,
            wake_on_http=True,
        )
        healthy = await morph.ensure_env_runtime_healthy(auth_header=caller.morph_authorization_header, instance_id=env["instance_id"])
        if tunnel_ws_url != env["tunnel_ws_url"]:
            db.execute(
                "UPDATE envs SET tunnel_ws_url = ?, updated_at = ? WHERE env_id = ?;",
                (tunnel_ws_url, _now(), env_id),
            )
        _ = healthy
    except Exception:
        tunnel_ws_url = env["tunnel_ws_url"]

    wg_allowed_ips = json.loads(secrets_row["wg_allowed_ips_json"])
    return ConnectBundle(
        version="v1",
        env_id=env["env_id"],
        instance_id=env["instance_id"],
        tunnel_ws_url=tunnel_ws_url,
        wg={
            "client_address": secrets_row["wg_client_address"],
            "client_private_key": secrets_row["wg_client_private_key"],
            "server_public_key": secrets_row["wg_server_public_key"],
            "allowed_ips": wg_allowed_ips,
            "endpoint_host": secrets_row["wg_endpoint_host"],
            "endpoint_port": int(secrets_row["wg_endpoint_port"]),
            "mtu": int(secrets_row["wg_mtu"]),
            "persistent_keepalive": int(secrets_row["wg_persistent_keepalive"]),
        },
        dns={"nameserver": env["dns_ip"]},
        tls={
            "ca_cert_pem": env["ca_cert_pem"],
            "ca_fingerprint_sha256": env["ca_fingerprint_sha256"],
        },
        aws={"gateway_ip": env["aws_gateway_ip"], "regions": json.loads(env["regions_json"])},
        auth={
            "mode": "morph_api_key_bearer",
            "header_name": "Authorization",
            "header_value_template": "Bearer ${MORPH_API_KEY}",
        },
        notes=[
            "Do NOT embed MORPH_API_KEY in the connect bundle; provide it out-of-band (e.g., env var at runtime).",
            "The connect bundle is sensitive: it contains a WireGuard private key.",
        ],
    )
