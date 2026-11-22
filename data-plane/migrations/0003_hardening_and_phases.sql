-- Findings from the first penetration test, and tables for phases 2 and 3.
ALTER TABLE control.principals
  ADD COLUMN must_change_password boolean NOT NULL DEFAULT false,
  ADD COLUMN sessions_valid_after timestamptz;

ALTER TABLE control.tenants ADD COLUMN kek_rotation_days integer;

ALTER TABLE control.vault_fields DROP CONSTRAINT vault_fields_data_type_check;
ALTER TABLE control.vault_fields ADD CONSTRAINT vault_fields_data_type_check
  CHECK (data_type IN ('bvn','nin','vnin','ng_11_digit_id','nuban','phone_ng','email','person_name','amount_ngn','payment_ref','address','date','free_text'));

-- NDPA Part VIII: the ground relied on for each flow that leaves the country.
ALTER TABLE control.log_pipelines ADD COLUMN transfer_basis text NOT NULL DEFAULT 'not_assessed'
  CHECK (transfer_basis IN ('not_assessed','adequacy','approved_instrument','section_43','tokens_only'));

CREATE TABLE control.ai_routes (
  id text PRIMARY KEY,
  vault_id text NOT NULL REFERENCES control.vaults(id),
  name text NOT NULL,
  upstream_base_url text NOT NULL,
  provider text NOT NULL,
  allowed_models text[] NOT NULL DEFAULT '{}',
  entity_types text[] NOT NULL DEFAULT '{}',
  restore_in_response boolean NOT NULL DEFAULT false,
  mode text NOT NULL DEFAULT 'shadow' CHECK (mode IN ('shadow','enforcing')),
  transfer_basis text NOT NULL DEFAULT 'not_assessed' CHECK (transfer_basis IN ('not_assessed','adequacy','approved_instrument','section_43','tokens_only')),
  route_key_hash text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (vault_id, name)
);

CREATE TABLE control.proxy_routes (
  id text PRIMARY KEY,
  vault_id text NOT NULL REFERENCES control.vaults(id),
  name text NOT NULL,
  direction text NOT NULL DEFAULT 'inbound' CHECK (direction IN ('inbound','outbound')),
  method text NOT NULL,
  path_pattern text NOT NULL,
  upstream_url text NOT NULL,
  mode text NOT NULL DEFAULT 'process_and_store' CHECK (mode IN ('process_and_store','process_only')),
  redact_paths jsonb NOT NULL DEFAULT '[]',
  unredact_paths jsonb NOT NULL DEFAULT '[]',
  response_redact_paths jsonb NOT NULL DEFAULT '[]',
  response_unredact_paths jsonb NOT NULL DEFAULT '[]',
  redact_query jsonb NOT NULL DEFAULT '[]',
  dlp boolean NOT NULL DEFAULT true,
  dlp_excluded_paths text[] NOT NULL DEFAULT '{}',
  transfer_basis text NOT NULL DEFAULT 'not_assessed' CHECK (transfer_basis IN ('not_assessed','adequacy','approved_instrument','section_43','tokens_only')),
  route_key_hash text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (vault_id, name)
);

-- Results only: counts and locations. Sampled values never leave the scanner.
CREATE TABLE control.discovery_runs (
  id text PRIMARY KEY,
  tenant_id text NOT NULL REFERENCES control.tenants(id),
  source_name text NOT NULL,
  source_type text NOT NULL,
  rows_sampled bigint NOT NULL DEFAULT 0,
  findings jsonb NOT NULL,
  uploaded_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

GRANT SELECT ON control.ai_routes, control.proxy_routes, control.discovery_runs TO rv_vault;
GRANT SELECT, INSERT, UPDATE, DELETE ON control.ai_routes, control.proxy_routes, control.discovery_runs TO rv_control;
