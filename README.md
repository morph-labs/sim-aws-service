# Sim-AWS Service (MVP skeleton)

FastAPI control plane skeleton for Sim-AWS environments on Morph Cloud.

## Docs

- Deployment: `docs/DEPLOYMENT.md`
- End-user usage (CLI + connector): `docs/END_USER.md`

## Local dev

1) Create a venv and install deps:

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
```

2) Run:

```bash
uvicorn sim_aws_service.main:app --reload
```

3) Visit:

- `http://127.0.0.1:8000/healthz`
- `http://127.0.0.1:8000/docs`

## Auth / tenancy

- Caller provides `Authorization: Bearer <MORPH_API_KEY>`.
- Tenant scope is derived from headers:
  - `X-Morph-Org-Id` (preferred)
  - else `X-Morph-User-Id`

In production, those IDs should be resolved/verified via Morph “service APIs” (services-sdk); this repo contains stubs for that integration.
