-- Three schemas with different trust levels. Roles created in 0002 enforce that
-- the control plane can never read data.* (ciphertext, keys).
CREATE SCHEMA IF NOT EXISTS control;
CREATE SCHEMA IF NOT EXISTS data;
CREATE SCHEMA IF NOT EXISTS events;

---------------------------------------------------------------- control plane
CREATE TABLE control.tenants (
  id text PRIMARY KEY,
  name text NOT NULL,
  plan text NOT NULL DEFAULT 'growth',
  deployment text NOT NULL DEFAULT 'self_hosted' CHECK (deployment IN ('hosted','self_hosted')),
  hosting_facility text,
  hosting_country text NOT NULL DEFAULT 'NG',
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE control.vaults (
  id text PRIMARY KEY,
  tenant_id text NOT NULL REFERENCES control.tenants(id),
  name text NOT NULL,
  environment text NOT NULL CHECK (environment IN ('sandbox','production')),
  status text NOT NULL DEFAULT 'active',
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, name)
);

CREATE TABLE control.column_groups (
  id text PRIMARY KEY,
  vault_id text NOT NULL REFERENCES control.vaults(id),
  name text NOT NULL,
  token_kind text NOT NULL,
  token_format text NOT NULL,
  UNIQUE (vault_id, name)
);

CREATE TABLE control.vault_fields (
  id text PRIMARY KEY,
  vault_id text NOT NULL REFERENCES control.vaults(id),
  name text NOT NULL,
  data_type text NOT NULL CHECK (data_type IN ('bvn','nin','ng_11_digit_id','nuban','phone_ng','email','person_name','amount_ngn','address','date','free_text')),
  token_kind text NOT NULL DEFAULT 'deterministic' CHECK (token_kind IN ('deterministic','cell','transient')),
  token_format text NOT NULL DEFAULT 'opaque' CHECK (token_format IN ('opaque','format_preserving')),
  column_group_id text REFERENCES control.column_groups(id),
  ttl_days integer,
  ttl_seconds integer,
  searchable boolean NOT NULL DEFAULT true,
  unique_values boolean NOT NULL DEFAULT false,
  mask_rule text NOT NULL DEFAULT 'default',
  in_payment_scope boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (vault_id, name)
);

CREATE TABLE control.principals (
  id text PRIMARY KEY,
  tenant_id text NOT NULL REFERENCES control.tenants(id),
  kind text NOT NULL CHECK (kind IN ('user','service_account')),
  display_name text NOT NULL,
  email text UNIQUE,
  password_hash text,
  totp_secret_enc text,
  totp_last_step bigint,
  mfa_enabled boolean NOT NULL DEFAULT false,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended')),
  approved_network text,
  last_active_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE control.service_account_keys (
  id text PRIMARY KEY,
  principal_id text NOT NULL REFERENCES control.principals(id),
  public_key text NOT NULL,
  fingerprint text NOT NULL,
  ip_allowlist text[] NOT NULL DEFAULT '{}',
  expires_at timestamptz,
  last_used_at timestamptz,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE control.roles (
  id text PRIMARY KEY,
  tenant_id text NOT NULL REFERENCES control.tenants(id),
  name text NOT NULL,
  UNIQUE (tenant_id, name)
);

CREATE TABLE control.role_assignments (
  role_id text NOT NULL REFERENCES control.roles(id),
  principal_id text NOT NULL REFERENCES control.principals(id),
  PRIMARY KEY (role_id, principal_id)
);

CREATE TABLE control.approved_networks (
  id text PRIMARY KEY,
  tenant_id text NOT NULL REFERENCES control.tenants(id),
  name text NOT NULL,
  cidrs text[] NOT NULL,
  UNIQUE (tenant_id, name)
);

CREATE TABLE control.policies (
  id text PRIMARY KEY,
  tenant_id text NOT NULL REFERENCES control.tenants(id),
  name text NOT NULL,
  version integer NOT NULL,
  source jsonb NOT NULL,
  compiled_cel jsonb,
  status text NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','active','archived')),
  created_by text NOT NULL,
  approved_by text,
  created_at timestamptz NOT NULL DEFAULT now(),
  published_at timestamptz,
  UNIQUE (tenant_id, name, version),
  CHECK (status <> 'active' OR (approved_by IS NOT NULL AND approved_by <> created_by))
);
CREATE UNIQUE INDEX policies_one_active ON control.policies (tenant_id, name) WHERE status = 'active';

CREATE TABLE control.break_glass_grants (
  id text PRIMARY KEY,
  tenant_id text NOT NULL REFERENCES control.tenants(id),
  principal_id text NOT NULL REFERENCES control.principals(id),
  vault_id text NOT NULL REFERENCES control.vaults(id),
  reason text NOT NULL,
  requested_by text NOT NULL,
  approved_by text,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','active','denied','revoked')),
  duration_minutes integer NOT NULL,
  expires_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK (approved_by IS NULL OR approved_by <> requested_by)
);

CREATE TABLE control.log_pipelines (
  id text PRIMARY KEY,
  vault_id text NOT NULL REFERENCES control.vaults(id),
  name text NOT NULL,
  source_type text NOT NULL CHECK (source_type IN ('otlp','fluentbit','vector')),
  destination text NOT NULL,
  upstream_url text NOT NULL,
  entity_types text[] NOT NULL,
  action_per_type jsonb NOT NULL DEFAULT '{}',
  sensitive_paths text[] NOT NULL DEFAULT '{}',
  sample_rate real NOT NULL DEFAULT 1,
  mode text NOT NULL DEFAULT 'shadow' CHECK (mode IN ('shadow','enforcing')),
  failure_mode text NOT NULL DEFAULT 'buffer' CHECK (failure_mode IN ('buffer','drop')),
  ingest_key_hash text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (vault_id, name)
);

CREATE TABLE control.scope_definitions (
  id text PRIMARY KEY,
  tenant_id text NOT NULL REFERENCES control.tenants(id),
  version integer NOT NULL,
  body text NOT NULL,
  created_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, version)
);

CREATE TABLE control.licences (
  id text PRIMARY KEY,
  tenant_id text NOT NULL REFERENCES control.tenants(id),
  signed_blob text NOT NULL,
  features text[] NOT NULL DEFAULT '{}',
  seats integer,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

------------------------------------------------------------------- data plane
CREATE TABLE data.data_keys (
  id text PRIMARY KEY,
  vault_id text NOT NULL,
  wrapped_dek bytea NOT NULL,
  kek_ref text NOT NULL,
  algorithm text NOT NULL DEFAULT 'AES-256-GCM',
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','decrypt_only','retired')),
  created_at timestamptz NOT NULL DEFAULT now(),
  rotated_at timestamptz
);
CREATE UNIQUE INDEX data_keys_one_active ON data.data_keys (vault_id) WHERE status = 'active';

CREATE TABLE data.blind_index_keys (
  id text PRIMARY KEY,
  vault_id text NOT NULL UNIQUE,
  wrapped_key bytea NOT NULL,
  kek_ref text NOT NULL,
  version integer NOT NULL DEFAULT 1
);

-- Subject references are customer IDs; they are encrypted and looked up by HMAC.
CREATE TABLE data.subjects (
  id uuid PRIMARY KEY,
  vault_id text NOT NULL,
  ref_index bytea NOT NULL,
  ref_ciphertext bytea NOT NULL,
  ref_nonce bytea NOT NULL,
  dek_id text NOT NULL REFERENCES data.data_keys(id),
  restricted boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (vault_id, ref_index)
);

CREATE TABLE data.records (
  id uuid PRIMARY KEY,
  vault_id text NOT NULL,
  field_id text NOT NULL,
  record_group uuid,
  dedup_scope text NOT NULL,
  deterministic boolean NOT NULL,
  ciphertext bytea NOT NULL,
  nonce bytea NOT NULL,
  dek_id text NOT NULL REFERENCES data.data_keys(id),
  blind_index bytea,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz
);
CREATE UNIQUE INDEX records_deterministic ON data.records (vault_id, dedup_scope, blind_index) WHERE deterministic;
CREATE INDEX records_lookup ON data.records (vault_id, field_id, blind_index);
CREATE INDEX records_expiry ON data.records (expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX records_dek ON data.records (dek_id);
CREATE INDEX records_group ON data.records (record_group);

-- One deterministic record can belong to several people (a shared phone line),
-- so erasing one subject must not destroy another subject's value.
CREATE TABLE data.record_subjects (
  record_id uuid NOT NULL REFERENCES data.records(id) ON DELETE CASCADE,
  subject_id uuid NOT NULL REFERENCES data.subjects(id) ON DELETE CASCADE,
  PRIMARY KEY (record_id, subject_id)
);
CREATE INDEX record_subjects_subject ON data.record_subjects (subject_id);

CREATE TABLE data.tokens (
  token text PRIMARY KEY,
  vault_id text NOT NULL,
  record_id uuid NOT NULL REFERENCES data.records(id) ON DELETE CASCADE,
  field_id text NOT NULL,
  kind text NOT NULL CHECK (kind IN ('deterministic','cell','transient')),
  format text NOT NULL CHECK (format IN ('opaque','format_preserving')),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz
);
CREATE INDEX tokens_record ON data.tokens (record_id);

-- Audit signing key, wrapped by the KEK.
CREATE TABLE data.audit_keys (
  tenant_id text PRIMARY KEY,
  wrapped_private_key bytea NOT NULL,
  public_key text NOT NULL,
  kek_ref text NOT NULL
);

-- Single-use JWT assertions (replay protection).
CREATE TABLE data.used_assertions (
  jti text PRIMARY KEY,
  expires_at timestamptz NOT NULL
);

-- Shared reveal and lookup counters so limits hold across replicas.
CREATE TABLE data.rate_counters (
  bucket text NOT NULL,
  window_start timestamptz NOT NULL,
  count integer NOT NULL DEFAULT 0,
  PRIMARY KEY (bucket, window_start)
);

---------------------------------------------------------------- event layer
CREATE TABLE events.audit_events (
  seq bigserial PRIMARY KEY,
  event_id uuid NOT NULL UNIQUE,
  occurred_at timestamptz NOT NULL,
  tenant_id text NOT NULL,
  vault_id text,
  principal_id text,
  principal_kind text,
  source_ip text,
  geo_country text,
  network text,
  module text NOT NULL,
  action text NOT NULL,
  field_id text,
  record_id uuid,
  token_hash text,
  purpose text,
  decision text,
  policy_id text,
  policy_version integer,
  break_glass boolean NOT NULL DEFAULT false,
  request_id text,
  latency_ms integer,
  detail text,
  prev_hash text NOT NULL,
  hash text NOT NULL
);
CREATE INDEX audit_tenant_seq ON events.audit_events (tenant_id, seq);
CREATE INDEX audit_tenant_time ON events.audit_events (tenant_id, occurred_at DESC);
CREATE INDEX audit_principal ON events.audit_events (principal_id, occurred_at DESC);
CREATE INDEX audit_record ON events.audit_events (record_id);

-- The audit log is append-only even for the application's own database role.
CREATE FUNCTION events.reject_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'audit_events is append-only'; END $$;
CREATE TRIGGER audit_append_only BEFORE UPDATE OR DELETE ON events.audit_events
  FOR EACH ROW EXECUTE FUNCTION events.reject_change();
CREATE TRIGGER audit_no_truncate BEFORE TRUNCATE ON events.audit_events
  FOR EACH STATEMENT EXECUTE FUNCTION events.reject_change();

-- Serialises chain appends per tenant.
CREATE TABLE events.audit_heads (
  tenant_id text PRIMARY KEY,
  head_hash text NOT NULL,
  head_seq bigint NOT NULL DEFAULT 0
);

CREATE TABLE events.audit_checkpoints (
  tenant_id text NOT NULL,
  day date NOT NULL,
  seq bigint NOT NULL,
  hash text NOT NULL,
  signature text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, day)
);

CREATE TABLE events.detection_events (
  occurred_at timestamptz NOT NULL,
  vault_id text NOT NULL,
  module text NOT NULL,
  source_id text NOT NULL,
  destination text NOT NULL DEFAULT '',
  entity_type text NOT NULL,
  action text NOT NULL CHECK (action IN ('tokenized','masked','dropped','passed')),
  count bigint NOT NULL,
  PRIMARY KEY (occurred_at, vault_id, module, source_id, destination, entity_type, action)
);

CREATE TABLE events.usage_daily (
  vault_id text NOT NULL,
  date date NOT NULL,
  tokenize_count bigint NOT NULL DEFAULT 0,
  detokenize_count bigint NOT NULL DEFAULT 0,
  denied_count bigint NOT NULL DEFAULT 0,
  detections_by_type jsonb NOT NULL DEFAULT '{}',
  p95_latency_ms integer,
  PRIMARY KEY (vault_id, date)
);

CREATE TABLE events.alerts (
  id uuid PRIMARY KEY,
  tenant_id text NOT NULL,
  kind text NOT NULL,
  principal_id text,
  detail jsonb NOT NULL,
  event_at timestamptz NOT NULL,
  raised_at timestamptz NOT NULL DEFAULT now(),
  acknowledged_at timestamptz
);
CREATE INDEX alerts_tenant ON events.alerts (tenant_id, raised_at DESC);
