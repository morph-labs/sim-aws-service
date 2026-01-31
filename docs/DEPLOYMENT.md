# Sim-AWS service deployment

This repo is the **Sim-AWS control-plane** service that should be deployed as a standard Morph “service VM” behind `sim-aws.svc.cloud.morph.so`.

## Runtime configuration

Required/important env vars:

- `MORPH_API_KEY` (required): Morph API key used by the Morph service deployment tooling. In the current deployment workflow, this is also the key that will be available inside the running service container.
  - Recommendation: set this to the **Sim-AWS service account** Morph API key so all Sim-AWS instances/snapshots are owned by the service account.
- `MORPH_SIM_AWS_SNAPSHOT_ID` (recommended): base Morph snapshot to boot each Sim-AWS environment from. Default is `snapshot_9m3k3prh` (from the Magi E2E PASS run).
- `SIM_AWS_SERVICE_MORPH_API_KEY` (optional): explicit service account key override. Useful for local dev. Note: the standard `morphcloud service deploy` workflow only passes through `MORPH*` env vars to the container.
- `MORPH_BASE_URL` (optional): Morph API base (default: `https://cloud.morph.so/api`).
- `SERVICES_API_KEY` (optional but recommended): enables quota/resource tracking via Morph “service APIs”. If unset, quotas are disabled (service still works; it sets `X-SimAWS-Quota-Mode: quota_disabled`).
- `SERVICES_BASE_URL` (optional): base URL for services API (default: `https://service.svc.cloud.morph.so/service`).
- `SIM_AWS_DB_URL` (optional): state DB (default: `sqlite:///./simaws.db`).
- `SIM_AWS_TUNNEL_PORT` (optional): port for the instance tunnel listener (default: `8081`).
- `SIM_AWS_MORPH_EXEC_TIMEOUT_S` (optional): Morph `/instance/{id}/exec` timeout seconds (default: `1200`).
- `SIM_AWS_DEFAULT_TTL_SECONDS` (optional): default TTL applied when the client does not specify `--ttl-seconds`. Set `0` or leave unset to disable TTL (run until stopped).

## Tunnel auth mode

This branch exposes the per-environment instance HTTP service `tunnel` **without auth** (equivalent to `auth_mode=none`) to avoid connector authorization issues during early rollout.

Security note: this means anyone who can guess the tunnel URL can connect to the environment tunnel. Re-enable auth before broader rollout.

## Ownership model

- End users call `sim-aws-service` using their **personal** Morph API key in `Authorization: Bearer ...`.
- The service validates that key and uses it for tenant scoping (and optionally quota enforcement).
- All Morph instances/snapshots created for Sim-AWS are created using the service’s configured Morph API key, so they are owned by the Sim-AWS service account.

## Deploy (recommended)

### 0) Register the service name (one-time)

`<service>.svc.cloud.morph.so` routing requires that the service name exists in the control plane.
If you have not registered `sim-aws` yet, create it (admin permissions required):

```bash
morphcloud admin service create sim-aws
```

If you want quota/resource tracking enabled in the Sim-AWS service, create a service API key and use it as `SERVICES_API_KEY` when deploying:

```bash
morphcloud admin service create-api-key sim-aws --json
```

### 1) Deploy the service VM

Use the Morph “service deploy” workflow from `services-sdk` (or its packaged CLI integration):

```bash
morphcloud service deploy --service-name sim-aws --version <tag-or-sha>
```

Service requirements (this repo satisfies them):
- `Dockerfile` at repo root
- listens on port `8000`
- `/healthz` returns HTTP 200

## Quick smoke checks

Once deployed:

```bash
curl -fsS https://sim-aws.svc.cloud.morph.so/healthz
curl -fsS https://sim-aws.svc.cloud.morph.so/openapi.json | head
```
