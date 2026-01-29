CREATE TABLE IF NOT EXISTS envs (
  env_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  user_id TEXT,
  org_id TEXT,
  name TEXT,
  status TEXT NOT NULL,
  regions_json TEXT NOT NULL,
  services_json TEXT NOT NULL,
  cidr TEXT NOT NULL,
  dns_ip TEXT NOT NULL,
  aws_gateway_ip TEXT NOT NULL,
  tunnel_ws_url TEXT NOT NULL,
  ca_cert_pem TEXT NOT NULL,
  ca_fingerprint_sha256 TEXT NOT NULL,
  instance_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  deleted_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_envs_tenant_created_at ON envs(tenant_id, created_at);

CREATE TABLE IF NOT EXISTS env_secrets (
  env_id TEXT PRIMARY KEY REFERENCES envs(env_id) ON DELETE CASCADE,
  wg_client_address TEXT NOT NULL,
  wg_client_private_key TEXT NOT NULL,
  wg_server_public_key TEXT NOT NULL,
  wg_allowed_ips_json TEXT NOT NULL,
  wg_endpoint_host TEXT NOT NULL,
  wg_endpoint_port INTEGER NOT NULL,
  wg_mtu INTEGER NOT NULL,
  wg_persistent_keepalive INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS snapshots (
  snapshot_id TEXT PRIMARY KEY,
  env_id TEXT NOT NULL REFERENCES envs(env_id) ON DELETE CASCADE,
  morph_snapshot_id TEXT,
  note TEXT,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_snapshots_env_created_at ON snapshots(env_id, created_at);

