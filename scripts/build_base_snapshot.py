#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shlex
import sys
import time
from typing import Any

import httpx


def _get_required_env(name: str) -> str:
    v = (os.environ.get(name) or "").strip()
    if not v:
        raise SystemExit(f"missing required env var: {name}")
    return v


def _unwrap(resp_json: Any) -> Any:
    """
    Morph endpoints vary between returning a plain object and returning {object,data}.
    Normalize to the most useful payload.
    """
    if isinstance(resp_json, dict) and "data" in resp_json:
        return resp_json["data"]
    return resp_json


def _coerce_instance_id(data: Any) -> str:
    if isinstance(data, dict):
        for k in ("id", "instance_id"):
            v = data.get(k)
            if isinstance(v, str) and v:
                return v
    raise RuntimeError("could not parse instance id from response")


def _coerce_snapshot_id(data: Any) -> str:
    if isinstance(data, dict):
        for k in ("id", "snapshot_id"):
            v = data.get(k)
            if isinstance(v, str) and v:
                return v
    raise RuntimeError("could not parse snapshot id from response")


def _coerce_status(data: Any) -> str:
    if isinstance(data, dict):
        v = data.get("status")
        if isinstance(v, str):
            return v
    return ""


def _shell(cmd: str) -> str:
    return cmd if cmd.endswith("\n") else cmd + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description="Build a Sim-AWS base snapshot (service-account owned).")
    ap.add_argument("--base-snapshot-id", required=True, help="Base Morph snapshot to start from (e.g. snapshot_mkuvgj72).")
    ap.add_argument(
        "--cloudsim-ref",
        default="magi/simaws-env-runtime-handoff-20260126",
        help="cloudsim git ref to bake into /opt/cloudsim (default: %(default)s).",
    )
    ap.add_argument(
        "--cloudsim-repo",
        default="https://github.com/morph-labs/cloudsim.git",
        help="cloudsim repo URL (default: %(default)s).",
    )
    ap.add_argument("--name", default="simaws-env-runtime", help="Metadata name for the builder instance.")
    ap.add_argument("--timeout-s", type=float, default=900.0, help="Timeout for instance/snapshot readiness.")
    ap.add_argument("--poll-s", type=float, default=2.0, help="Poll interval.")
    ap.add_argument("--keep-instance", action="store_true", help="Do not delete the builder instance after snapshotting.")
    args = ap.parse_args()

    base_url = (os.environ.get("MORPH_BASE_URL") or "https://cloud.morph.so/api").rstrip("/")
    api_key = _get_required_env("MORPH_API_KEY")

    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}

    def req(method: str, path: str, **kwargs: Any) -> Any:
        with httpx.Client(base_url=base_url, headers=headers, timeout=60.0) as c:
            r = c.request(method, path, **kwargs)
        r.raise_for_status()
        return _unwrap(r.json() if r.content else {})

    def wait_instance_ready(instance_id: str) -> None:
        deadline = time.time() + float(args.timeout_s)
        while True:
            inst = req("GET", f"/instance/{instance_id}")
            status = _coerce_status(inst)
            if status == "ready":
                return
            if status == "error":
                raise RuntimeError(f"instance entered error state: {instance_id}")
            if time.time() >= deadline:
                raise TimeoutError(f"timed out waiting for instance ready: {instance_id} status={status!r}")
            time.sleep(float(args.poll_s))

    def wait_snapshot_ready(snapshot_id: str) -> None:
        deadline = time.time() + float(args.timeout_s)
        while True:
            snap = req("GET", f"/snapshot/{snapshot_id}")
            status = _coerce_status(snap).lower()
            if status == "ready":
                return
            if status == "failed":
                raise RuntimeError(f"snapshot entered failed state: {snapshot_id}")
            if time.time() >= deadline:
                raise TimeoutError(f"timed out waiting for snapshot ready: {snapshot_id} status={status!r}")
            time.sleep(float(args.poll_s))

    def exec_cmd(instance_id: str, cmd: str, *, timeout_s: float = 1200.0) -> dict[str, Any]:
        payload = {"command": [cmd]}
        with httpx.Client(base_url=base_url, headers=headers, timeout=timeout_s) as c:
            r = c.post(f"/instance/{instance_id}/exec", json=payload)
        r.raise_for_status()
        data = _unwrap(r.json() if r.content else {})
        if not isinstance(data, dict):
            data = {}
        return data

    create = req(
        "POST",
        "/instance",
        params={"snapshot_id": args.base_snapshot_id},
        json={"metadata": {"project": "sim-aws", "name": args.name}},
    )
    instance_id = _coerce_instance_id(create)
    wait_instance_ready(instance_id)

    # Bake cloudsim into the snapshot (used by env runtime supervisor).
    # Avoid printing command output: it may include env/runtime secrets.
    cloudsim_repo = args.cloudsim_repo
    cloudsim_ref = args.cloudsim_ref
    cmd = _shell(
        "set -euo pipefail\n"
        "if command -v apt-get >/dev/null 2>&1; then\n"
        "  apt-get update >/dev/null 2>&1 || true\n"
        "  if ! command -v python3 >/dev/null 2>&1; then apt-get install -y python3 >/dev/null 2>&1 || true; fi\n"
        "  if ! command -v git >/dev/null 2>&1; then apt-get install -y git >/dev/null 2>&1 || true; fi\n"
        "  if ! command -v jq >/dev/null 2>&1; then apt-get install -y jq >/dev/null 2>&1 || true; fi\n"
        "  if ! command -v openssl >/dev/null 2>&1; then apt-get install -y openssl ca-certificates >/dev/null 2>&1 || true; fi\n"
        "  if ! command -v ip >/dev/null 2>&1; then apt-get install -y iproute2 >/dev/null 2>&1 || true; fi\n"
        "  if ! command -v iptables >/dev/null 2>&1; then apt-get install -y iptables >/dev/null 2>&1 || true; fi\n"
        "  if ! command -v wg >/dev/null 2>&1; then apt-get install -y wireguard-tools >/dev/null 2>&1 || true; fi\n"
        "  if ! command -v wireguard-go >/dev/null 2>&1; then apt-get install -y wireguard-go >/dev/null 2>&1 || true; fi\n"
        "fi\n"
        "if ! command -v docker >/dev/null 2>&1; then\n"
        "  if command -v curl >/dev/null 2>&1; then\n"
        "    (curl -fsSL https://get.docker.com | sh) >/dev/null 2>&1 || true\n"
        "  fi\n"
        "fi\n"
        "if command -v systemctl >/dev/null 2>&1; then\n"
        "  systemctl enable docker >/dev/null 2>&1 || true\n"
        "  systemctl start docker >/dev/null 2>&1 || true\n"
        "fi\n"
        "mkdir -p /opt\n"
        "if [ -d /opt/cloudsim/.git ]; then\n"
        "  cd /opt/cloudsim\n"
        f"  git remote set-url origin {shlex.quote(cloudsim_repo)} || true\n"
        "  git fetch --all --prune >/dev/null 2>&1 || true\n"
        f"  git checkout -f {shlex.quote(cloudsim_ref)} >/dev/null 2>&1 || true\n"
        f"  git reset --hard origin/{shlex.quote(cloudsim_ref)} >/dev/null 2>&1 || true\n"
        "elif [ -d /opt/cloudsim ]; then\n"
        "  ts=\"$(date +%s 2>/dev/null || echo 0)\"\n"
        "  mv /opt/cloudsim \"/opt/cloudsim.bak.${ts}\" >/dev/null 2>&1 || true\n"
        f"  git clone --depth 1 --branch {shlex.quote(cloudsim_ref)} {shlex.quote(cloudsim_repo)} /opt/cloudsim >/dev/null 2>&1\n"
        "else\n"
        f"  git clone --depth 1 --branch {shlex.quote(cloudsim_ref)} {shlex.quote(cloudsim_repo)} /opt/cloudsim >/dev/null 2>&1\n"
        "fi\n"
        "chmod +x /opt/cloudsim/bin/env-runtime-supervisor.sh /opt/cloudsim/bin/env-runtime-health.sh || true\n"
        # Pre-pull the LocalStack/CoreDNS images used by the env runtime to reduce first-boot latency.
        "if command -v docker >/dev/null 2>&1; then\n"
        "  docker info >/dev/null 2>&1 || true\n"
        "  docker pull localstack/localstack:latest >/dev/null 2>&1 || true\n"
        "  docker pull coredns/coredns:1.11.1 >/dev/null 2>&1 || true\n"
        "fi\n"
    )
    exec_cmd(instance_id, cmd)

    snap = req("POST", f"/instance/{instance_id}/snapshot", json={"metadata": {"project": "sim-aws", "name": "simaws-env-runtime"}})
    snapshot_id = _coerce_snapshot_id(snap)
    wait_snapshot_ready(snapshot_id)

    if not args.keep_instance:
        try:
            req("DELETE", f"/instance/{instance_id}")
        except Exception:
            pass

    sys.stdout.write(json.dumps({"instance_id": instance_id, "snapshot_id": snapshot_id}, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
