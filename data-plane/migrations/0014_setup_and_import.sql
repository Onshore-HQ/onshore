-- Machine keys that can only move setup between environments, and a record of data imports.
CREATE TABLE control.api_keys (
  id           text PRIMARY KEY,
  tenant_id    text NOT NULL REFERENCES control.tenants(id),
  name         text NOT NULL,
  key_hash     text NOT NULL UNIQUE,
  scopes       text[] NOT NULL,
  created_by   text NOT NULL REFERENCES control.principals(id),
  created_at   timestamptz NOT NULL DEFAULT now(),
  expires_at   timestamptz,
  last_used_at timestamptz,
  revoked_at   timestamptz
);

-- Counts and column names only. The file itself never reaches the server, and neither do its rows.
CREATE TABLE control.import_jobs (
  id            text PRIMARY KEY,
  tenant_id     text NOT NULL REFERENCES control.tenants(id),
  vault_id      text NOT NULL REFERENCES control.vaults(id),
  file_name     text NOT NULL,
  mapping       jsonb NOT NULL,
  ref_column    text,
  status        text NOT NULL DEFAULT 'running' CHECK (status IN ('running','paused','done','cancelled')),
  rows_done     bigint NOT NULL DEFAULT 0,
  rows_failed   bigint NOT NULL DEFAULT 0,
  values_new    bigint NOT NULL DEFAULT 0,
  values_existing bigint NOT NULL DEFAULT 0,
  created_by    text NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now(),
  finished_at   timestamptz
);
CREATE INDEX import_jobs_vault ON control.import_jobs(vault_id, created_at DESC);

GRANT SELECT, INSERT, UPDATE ON control.api_keys, control.import_jobs TO rv_control;
