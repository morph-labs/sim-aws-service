from __future__ import annotations

import asyncio
import base64
import json
import os
import shlex
import textwrap
from dataclasses import dataclass
from typing import Any

import httpx


@dataclass
class MorphCreateInstanceResult:
    instance_id: str


@dataclass
class MorphExecResult:
    exit_code: int
    stdout: str
    stderr: str


@dataclass
class MorphProvisionEnvRuntimeResult:
    wg_client_private_key: str
    wg_server_public_key: str
    ca_cert_pem: str
    ca_fingerprint_sha256: str


class MorphClient:
    def __init__(
        self,
        *,
        base_url: str | None = None,
        timeout_s: float = 30.0,
        ready_timeout_s: float = 180.0,
        ready_poll_interval_s: float = 1.0,
        tunnel_port: int = 8081,
        exec_timeout_s: float = 1200.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._base_url = (base_url or os.environ.get("MORPH_BASE_URL") or "https://cloud.morph.so/api").rstrip("/")
        self._exec_timeout_s = float(os.environ.get("SIM_AWS_MORPH_EXEC_TIMEOUT_S", str(exec_timeout_s)))
        # Ensure the client default timeout isn't smaller than exec timeout.
        self._timeout_s = max(float(timeout_s), self._exec_timeout_s)
        self._ready_timeout_s = ready_timeout_s
        self._ready_poll_interval_s = ready_poll_interval_s
        self._tunnel_port = int(os.environ.get("SIM_AWS_TUNNEL_PORT", str(tunnel_port)))
        self._transport = transport

    def _headers(self, auth_header: str) -> dict[str, str]:
        return {"Authorization": auth_header, "Content-Type": "application/json"}

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=self._base_url,
            timeout=self._timeout_s,
            transport=self._transport,
        )

    async def _get_instance(self, *, auth_header: str, instance_id: str) -> dict[str, Any]:
        async with self._client() as client:
            r = await client.get(f"/instance/{instance_id}", headers=self._headers(auth_header))
            r.raise_for_status()
            return r.json()

    async def _get_snapshot(self, *, auth_header: str, snapshot_id: str) -> dict[str, Any]:
        async with self._client() as client:
            r = await client.get(f"/snapshot/{snapshot_id}", headers=self._headers(auth_header))
            r.raise_for_status()
            data = r.json()
            if not isinstance(data, dict):
                raise TypeError("Morph snapshot response was not an object")
            return data

    async def _wait_until_ready(self, *, auth_header: str, instance_id: str) -> None:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self._ready_timeout_s
        while True:
            inst = await self._get_instance(auth_header=auth_header, instance_id=instance_id)
            status = str(inst.get("status") or "")
            if status == "ready":
                return
            if status == "error":
                raise RuntimeError(f"Morph instance entered error state: instance_id={instance_id}")
            if loop.time() >= deadline:
                raise TimeoutError(f"Timed out waiting for Morph instance ready: instance_id={instance_id} status={status}")
            await asyncio.sleep(self._ready_poll_interval_s)

    async def _wait_snapshot_ready(
        self,
        *,
        auth_header: str,
        snapshot_id: str,
        timeout_s: float = 900,
        poll_s: float = 1.0,
    ) -> None:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + float(timeout_s)
        while True:
            snap = await self._get_snapshot(auth_header=auth_header, snapshot_id=snapshot_id)
            status_raw = str(snap.get("status") or "")
            status = status_raw.lower()
            if status == "ready":
                return
            if status == "failed":
                raise RuntimeError(f"Morph snapshot entered failed state: snapshot_id={snapshot_id}")
            if loop.time() >= deadline:
                raise TimeoutError(
                    f"Timed out waiting for Morph snapshot ready: snapshot_id={snapshot_id} status={status_raw}"
                )
            await asyncio.sleep(float(poll_s))

    def _snapshot_id_from_env(self) -> str:
        snapshot_id = os.environ.get("SIM_AWS_MORPH_SNAPSHOT_ID") or os.environ.get("SIM_AWS_ENV_SNAPSHOT_ID")
        return snapshot_id or "snapshot_9m3k3prh"

    def _coerce_exit_code(self, data: dict[str, Any]) -> int:
        for k in ("exit_code", "code", "returncode"):
            if k in data:
                try:
                    return int(data[k])
                except Exception:
                    break
        return 0

    async def create_instance(
        self,
        *,
        auth_header: str,
        name: str | None = None,
        metadata: dict[str, Any] | None = None,
        ttl_seconds: int | None = None,
        env_id: str | None = None,
        ttl_action: str | None = "pause",
    ) -> MorphCreateInstanceResult:
        snapshot_id = self._snapshot_id_from_env()
        return await self.create_instance_from_snapshot(
            auth_header=auth_header,
            snapshot_id=snapshot_id,
            name=name,
            metadata=metadata,
            ttl_seconds=ttl_seconds,
            env_id=env_id,
            ttl_action=ttl_action,
        )

    async def create_instance_from_snapshot(
        self,
        *,
        auth_header: str,
        snapshot_id: str,
        name: str | None = None,
        metadata: dict[str, Any] | None = None,
        ttl_seconds: int | None = None,
        env_id: str | None = None,
        ttl_action: str | None = "pause",
    ) -> MorphCreateInstanceResult:
        merged_metadata: dict[str, Any] = {"project": "sim-aws-service"}
        if name:
            merged_metadata["name"] = name
        if env_id:
            merged_metadata["sim_aws:env_id"] = env_id
        if metadata:
            merged_metadata.update(metadata)

        payload: dict[str, Any] = {"metadata": merged_metadata}
        if ttl_seconds is not None:
            payload["ttl_seconds"] = int(ttl_seconds)
        if ttl_action is not None:
            payload["ttl_action"] = ttl_action

        async with self._client() as client:
            r = await client.post(
                "/instance",
                params={"snapshot_id": snapshot_id},
                headers=self._headers(auth_header),
                json=payload,
            )
            r.raise_for_status()
            inst = r.json()
            instance_id = str(inst["id"])
        await self._wait_until_ready(auth_header=auth_header, instance_id=instance_id)
        return MorphCreateInstanceResult(instance_id=instance_id)

    async def wait_snapshot_ready(
        self,
        *,
        auth_header: str,
        snapshot_id: str,
        timeout_s: float = 900,
        poll_s: float = 1.0,
    ) -> None:
        await self._wait_snapshot_ready(
            auth_header=auth_header,
            snapshot_id=snapshot_id,
            timeout_s=timeout_s,
            poll_s=poll_s,
        )

    async def start_instance(self, *, auth_header: str, instance_id: str) -> None:
        async with self._client() as client:
            r = await client.post(f"/instance/{instance_id}/resume", headers=self._headers(auth_header))
            if r.status_code in (404, 409):
                return
            r.raise_for_status()

    async def pause_instance(self, *, auth_header: str, instance_id: str) -> None:
        async with self._client() as client:
            r = await client.post(f"/instance/{instance_id}/pause", headers=self._headers(auth_header))
            if r.status_code in (404, 409):
                return
            r.raise_for_status()

    async def delete_instance(self, *, auth_header: str, instance_id: str) -> None:
        async with self._client() as client:
            r = await client.delete(f"/instance/{instance_id}", headers=self._headers(auth_header))
            if r.status_code == 404:
                return
            r.raise_for_status()

    async def snapshot_instance(self, *, auth_header: str, instance_id: str) -> str:
        async with self._client() as client:
            r = await client.post(
                f"/instance/{instance_id}/snapshot",
                headers=self._headers(auth_header),
                json={"metadata": {"project": "sim-aws-service"}},
            )
            r.raise_for_status()
            snap = r.json()
            snapshot_id = str(snap["id"])
        await self._wait_snapshot_ready(auth_header=auth_header, snapshot_id=snapshot_id)
        return snapshot_id

    async def exec(
        self,
        *,
        auth_header: str,
        instance_id: str,
        command: list[str],
    ) -> MorphExecResult:
        if not command:
            raise ValueError("command must be non-empty")

        # Morph instance exec runs the received command through a shell without quoting argv.
        # Send a single, shell-escaped command string to preserve arguments/newlines safely.
        command_str = " ".join(shlex.quote(part) for part in command)
        async with self._client() as client:
            r = await client.post(
                f"/instance/{instance_id}/exec",
                headers=self._headers(auth_header),
                json={"command": [command_str]},
                timeout=self._exec_timeout_s,
            )
            r.raise_for_status()
            data = r.json() if r.content else {}
            if not isinstance(data, dict):
                data = {}
            exit_code = self._coerce_exit_code(data)
            stdout = str(data.get("stdout") or data.get("out") or "")
            stderr = str(data.get("stderr") or data.get("err") or "")
            return MorphExecResult(exit_code=exit_code, stdout=stdout, stderr=stderr)

    async def provision_env_runtime(
        self,
        *,
        auth_header: str,
        instance_id: str,
        env_id: str,
        cidr: str,
        dns_ip: str,
        aws_gateway_ip: str,
        regions: list[str],
        services: list[str],
        wg_client_address: str,
        wg_allowed_ips: list[str],
        existing_wg_client_private_key: str | None = None,
        tunnel_port: int | None = None,
        wg_port: int = 51820,
        wg_mtu: int = 1280,
        wg_persistent_keepalive: int = 25,
    ) -> MorphProvisionEnvRuntimeResult:
        payload = {
            "env_id": env_id,
            "cidr": cidr,
            "dns_ip": dns_ip,
            "aws_gateway_ip": aws_gateway_ip,
            "regions": regions,
            "localstack_services": services,
            "wg_client_address": wg_client_address,
            "wg_allowed_ips": wg_allowed_ips,
            "wg_port": int(wg_port),
            "wg_mtu": int(wg_mtu),
            "wg_persistent_keepalive": int(wg_persistent_keepalive),
            "tunnel_port": int(tunnel_port or self._tunnel_port),
            "existing_wg_client_private_key": existing_wg_client_private_key,
        }
        payload_b64 = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")

        py = textwrap.dedent(
            """\
            import base64, json, os, subprocess, sys, hashlib, shutil, time, shlex

            payload = json.loads(base64.b64decode(sys.argv[1]).decode("utf-8"))

            SUPERVISOR_NAME = "env-" + "runtime-supervisor.sh"
            HEALTH_NAME = "env-" + "runtime-health.sh"
            WS_UDP_TUNNEL_NAME = "ws_" + "udp_tunnel.py"
            WSTUNNEL_NAME = "ws" + "tunnel"

            def _run(cmd, *, stdin=None, timeout_s=60):
                p = subprocess.run(cmd, input=stdin, text=True, capture_output=True, timeout=timeout_s)
                if p.returncode != 0:
                    raise RuntimeError(f"command failed: {cmd!r} rc={p.returncode} stderr={(p.stderr or '')[:200]!r}")
                return p.stdout

            def _ensure_wg():
                if shutil.which("wg"):
                    return
                # Best-effort install for keygen + interface config.
                _run(["apt-get", "update"], timeout_s=180)
                _run(["apt-get", "install", "-y", "wireguard-tools"], timeout_s=240)
                if not shutil.which("wg"):
                    raise RuntimeError("wg still missing after install")

            def _find_cloudsim_root():
                candidates = ["/opt/cloudsim", "/cloudsim", "/srv/cloudsim", "/root/cloudsim"]
                for r in candidates:
                    if os.path.isfile(os.path.join(r, "bin", SUPERVISOR_NAME)):
                        return r
                # Fallback: bounded find (best-effort).
                try:
                    find_cmd = f"find / -maxdepth 6 -type f -name {shlex.quote(SUPERVISOR_NAME)} 2>/dev/null | head -n 1"
                    out = _run(
                        [
                            "bash",
                            "-lc",
                            find_cmd,
                        ],
                        timeout_s=30,
                    ).strip()
                except Exception:
                    out = ""
                if out:
                    return os.path.abspath(os.path.join(os.path.dirname(out), os.pardir))
                return None

            def _walk_find_first(root: str, max_depth: int, names: set[str]) -> str | None:
                root = os.path.abspath(root)
                root_depth = root.rstrip("/").count("/")
                for dirpath, dirnames, filenames in os.walk(root):
                    depth = dirpath.rstrip("/").count("/") - root_depth
                    if depth >= max_depth:
                        dirnames[:] = []
                    for fn in filenames:
                        if fn in names:
                            return os.path.join(dirpath, fn)
                return None

            cloudsim_root = _find_cloudsim_root()
            state_dir = os.environ.get("CLOUDSIM_STATE_DIR") or ("/var/lib/cloudsim" if os.path.isdir("/var/lib") else None)
            if not state_dir:
                state_dir = os.path.join(cloudsim_root or "/tmp", "cloudsim-state")
            os.makedirs(state_dir, exist_ok=True)

            config_path = os.environ.get("ENV_RUNTIME_CONFIG") or "/etc/cloudsim/env_runtime_config.json"
            os.makedirs(os.path.dirname(config_path), exist_ok=True)
            log_path = os.path.join(state_dir, "env-runtime-supervisor.log")

            existing_cfg = {}
            if os.path.isfile(config_path):
                try:
                    existing_cfg = json.loads(open(config_path, "r", encoding="utf-8").read())
                    if not isinstance(existing_cfg, dict):
                        existing_cfg = {}
                except Exception:
                    existing_cfg = {}

            _ensure_wg()

            client_priv = payload.get("existing_wg_client_private_key") or ""
            if client_priv:
                client_priv = str(client_priv).strip()
            if not client_priv:
                client_priv = _run(["wg", "genkey"], timeout_s=10).strip()
            client_pub = _run(["wg", "pubkey"], stdin=client_priv + "\\n", timeout_s=10).strip()

            server_priv = str(existing_cfg.get("wg_server_private_key") or "").strip()
            if not server_priv:
                server_priv = _run(["wg", "genkey"], timeout_s=10).strip()
            server_pub = _run(["wg", "pubkey"], stdin=server_priv + "\\n", timeout_s=10).strip()

            prefix = "24"
            try:
                prefix = str(int(str(payload["cidr"]).split("/", 1)[1]))
            except Exception:
                prefix = "24"

            cfg = {
                "version": "v1",
                "env_id": payload["env_id"],
                "cidr": payload["cidr"],
                "dns_ip": payload["dns_ip"],
                "aws_gateway_ip": payload["aws_gateway_ip"],
                "regions": payload["regions"],
                "localstack_services": payload["localstack_services"],
                "wg_server_private_key": server_priv,
                "wg_server_listen_udp": f'127.0.0.1:{int(payload.get(\"wg_port\") or 51820)}',
                "tunnel_listen_port": int(payload.get("tunnel_port") or 8081),
                "wg_peers": [{"public_key": client_pub, "allowed_ips": [payload["wg_client_address"]]}],
            }

            open(config_path, "w", encoding="utf-8").write(json.dumps(cfg, indent=2, sort_keys=True) + "\\n")

            sup = os.path.join(cloudsim_root, "bin", SUPERVISOR_NAME) if cloudsim_root else None
            if sup and os.path.isfile(sup):
                env = dict(os.environ)
                env["CLOUDSIM_STATE_DIR"] = state_dir
                env["ENV_RUNTIME_CONFIG"] = config_path
                # Best-effort cleanup of stale processes from the base snapshot.
                def _pkill_f(pat: str) -> None:
                    try:
                        subprocess.run(["pkill", "-f", pat], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    except Exception:
                        pass

                _pkill_f(SUPERVISOR_NAME)
                _pkill_f(WS_UDP_TUNNEL_NAME)
                _pkill_f(WSTUNNEL_NAME)
                time.sleep(1)
                # Detach the supervisor so it survives the /instance/exec lifecycle.
                cmd = f"nohup {shlex.quote(sup)} >>{shlex.quote(log_path)} 2>&1 &"
                subprocess.run(["bash", "-lc", cmd], env=env, cwd=cloudsim_root, check=True)

            health = os.path.join(cloudsim_root, "bin", HEALTH_NAME) if cloudsim_root else None
            if health and os.path.isfile(health):
                env = dict(os.environ)
                env["CLOUDSIM_STATE_DIR"] = state_dir
                env["ENV_RUNTIME_CONFIG"] = config_path

                # Give the supervisor time to start tunnel/DNS/LocalStack.
                deadline_s = 240.0
                interval_s = 2.0
                attempts = int(deadline_s // interval_s)
                last_rc = None
                last_first = ""
                for _ in range(attempts):
                    p = subprocess.run([health], cwd=cloudsim_root, text=True, capture_output=True, env=env, timeout=180)
                    if p.returncode == 0:
                        break
                    last_rc = p.returncode
                    err_lines = (p.stderr or "").strip().splitlines()
                    out_lines = (p.stdout or "").strip().splitlines()
                    last_first = err_lines[0] if err_lines else (out_lines[0] if out_lines else "")
                    time.sleep(interval_s)
                else:
                    sup_tail = ""
                    try:
                        if os.path.isfile(log_path):
                            sup_tail = _run(["bash", "-lc", f"tail -n 40 {shlex.quote(log_path)}"], timeout_s=10).strip()
                    except Exception:
                        sup_tail = ""
                    if sup_tail:
                        raise RuntimeError(f"env runtime health failed: rc={last_rc} first_line={last_first} supervisor_log_tail={sup_tail[:200]}")
                    raise RuntimeError(f"env runtime health failed: rc={last_rc} first_line={last_first}")

            ca_candidates = [
                os.path.join(state_dir, "ca.crt.pem"),
                os.path.join(state_dir, "certs", f"simaws-{payload['env_id']}-ca.crt.pem"),
                os.path.join(state_dir, "certs", "ca.crt.pem"),
                os.path.join(state_dir, "certs", "ca.pem"),
                os.path.join(state_dir, "certs", "ca.crt"),
                os.path.join(state_dir, "tls", "ca.pem"),
            ]
            ca_path = None
            for p in ca_candidates:
                if os.path.isfile(p):
                    ca_path = p
                    break
            if not ca_path:
                ca_path = _walk_find_first(state_dir, max_depth=4, names={"ca.pem", "ca.crt"})

            if not ca_path:
                raise RuntimeError("unable to locate CA certificate (ca.pem/ca.crt)")

            ca_pem = open(ca_path, "r", encoding="utf-8", errors="replace").read()
            if "BEGIN CERTIFICATE" not in ca_pem:
                raise RuntimeError("CA certificate file did not look like PEM")

            fp = hashlib.sha256(ca_pem.encode("utf-8")).hexdigest()

            print(
                json.dumps(
                    {
                        "wg_client_private_key": client_priv,
                        "wg_server_public_key": server_pub,
                        "ca_cert_pem": ca_pem,
                        "ca_fingerprint_sha256": fp,
                    }
                )
            )
            """
        )

        exec_res = await self.exec(auth_header=auth_header, instance_id=instance_id, command=["python3", "-c", py, payload_b64])
        if exec_res.exit_code != 0:
            # Never include stdout: it may contain secrets (e.g. generated keys).
            raise RuntimeError(
                f"failed to provision env runtime in instance: instance_id={instance_id} exit_code={exec_res.exit_code} stderr={exec_res.stderr[:200]}"
            )

        try:
            data = json.loads(exec_res.stdout)
        except Exception as e:
            raise RuntimeError(f"invalid provision result from instance: instance_id={instance_id}") from e

        return MorphProvisionEnvRuntimeResult(
            wg_client_private_key=str(data["wg_client_private_key"]),
            wg_server_public_key=str(data["wg_server_public_key"]),
            ca_cert_pem=str(data["ca_cert_pem"]),
            ca_fingerprint_sha256=str(data["ca_fingerprint_sha256"]),
        )

    async def ensure_http_service_tunnel(
        self,
        *,
        auth_header: str,
        instance_id: str,
        service_name: str = "tunnel",
        auth_mode: str | None = None,
        wake_on_http: bool = True,
    ) -> str:
        payload: dict[str, Any] = {"name": service_name, "port": self._tunnel_port}
        if auth_mode is not None:
            payload["auth_mode"] = auth_mode
        async with self._client() as client:
            r = await client.post(
                f"/instance/{instance_id}/http",
                headers=self._headers(auth_header),
                json=payload,
            )
            r.raise_for_status()
            if wake_on_http:
                r = await client.post(
                    f"/instance/{instance_id}/wake-on",
                    headers=self._headers(auth_header),
                    json={"wake_on_http": True},
                )
                r.raise_for_status()

        inst = await self._get_instance(auth_header=auth_header, instance_id=instance_id)
        url: str | None = None
        for svc in (inst.get("networking") or {}).get("http_services") or []:
            if svc.get("name") == service_name and svc.get("url"):
                url = str(svc["url"])
                break
        if not url:
            url = f"https://{service_name}-{instance_id}.http.cloud.morph.so"

        if url.startswith("https://"):
            return "wss://" + url[len("https://") :]
        if url.startswith("http://"):
            return "ws://" + url[len("http://") :]
        return url
