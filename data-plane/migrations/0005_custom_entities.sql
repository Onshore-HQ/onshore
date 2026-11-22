-- Update Spec 01: customer-defined detection entities. Additive only.
-- The spec's SQL is written against uuid keys and enum types. This schema uses text
-- ids and CHECK constraints, so it follows those instead.

ALTER TABLE control.vaults
  ADD COLUMN custom_entities_enabled boolean NOT NULL DEFAULT false,
  ADD COLUMN detection_thresholds jsonb NOT NULL DEFAULT '{}';

CREATE TABLE control.custom_entities (
  id text PRIMARY KEY,
  tenant_id text NOT NULL REFERENCES control.tenants(id),
  vault_id text NOT NULL REFERENCES control.vaults(id),
  name text NOT NULL,
  slug text NOT NULL CHECK (slug ~ '^c_[a-z0-9_]{2,40}$'),
  kind text NOT NULL CHECK (kind IN ('keyword_list','pattern','after_keyword','value_list','json_path')),
  definition jsonb NOT NULL,
  validator jsonb,
  context_positive text[] NOT NULL DEFAULT '{}',
  context_negative text[] NOT NULL DEFAULT '{}',
  threshold numeric(3,2) NOT NULL DEFAULT 0.70 CHECK (threshold >= 0 AND threshold <= 1),
  token_kind text NOT NULL DEFAULT 'deterministic' CHECK (token_kind IN ('deterministic','cell','transient')),
  token_format text NOT NULL DEFAULT 'opaque' CHECK (token_format IN ('opaque','format_preserving')),
  mask_rule jsonb NOT NULL DEFAULT '{"type":"last_n","n":4}',
  actions jsonb NOT NULL,
  status text NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','shadow','enforcing','archived')),
  version integer NOT NULL DEFAULT 0, -- 0 means never published
  draft jsonb, -- an edit waiting beside the live version, or the draft itself
  list_version integer NOT NULL DEFAULT 0, -- the value list in force
  staged_list_version integer, -- an uploaded list waiting for approval
  created_by text NOT NULL,
  approved_by text,
  edited_by text NOT NULL,
  published_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (vault_id, slug)
);
CREATE INDEX custom_entities_vault ON control.custom_entities (vault_id, status);

CREATE TABLE control.custom_entity_versions (
  entity_id text NOT NULL REFERENCES control.custom_entities(id),
  version integer NOT NULL,
  snapshot jsonb NOT NULL,
  published_by text NOT NULL,
  approved_by text NOT NULL,
  published_at timestamptz NOT NULL DEFAULT now(),
  benchmark jsonb,
  PRIMARY KEY (entity_id, version),
  CHECK (approved_by <> published_by)
);

-- Keyed hashes of value-list members, never plaintext.
CREATE TABLE control.custom_entity_values (
  entity_id text NOT NULL REFERENCES control.custom_entities(id) ON DELETE CASCADE,
  list_version integer NOT NULL,
  index_key_version integer NOT NULL DEFAULT 1,
  value_hmac bytea NOT NULL,
  PRIMARY KEY (entity_id, list_version, value_hmac)
);

-- An upload goes live only through approval, so lists are versioned like definitions.
CREATE TABLE control.custom_entity_lists (
  entity_id text NOT NULL REFERENCES control.custom_entities(id) ON DELETE CASCADE,
  list_version integer NOT NULL,
  value_count integer NOT NULL,
  max_words integer NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (entity_id, list_version)
);

-- People paste real-looking data here, so samples are encrypted with the vault's DEK.
CREATE TABLE control.custom_entity_tests (
  id text PRIMARY KEY,
  entity_id text NOT NULL REFERENCES control.custom_entities(id) ON DELETE CASCADE,
  sample_ciphertext bytea NOT NULL,
  sample_nonce bytea NOT NULL,
  dek_id text NOT NULL,
  expect_match boolean NOT NULL,
  created_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX custom_entity_tests_entity ON control.custom_entity_tests (entity_id);

-- The original upload, encrypted and kept 30 days so a list can be re-hashed.
CREATE TABLE control.custom_entity_uploads (
  id text PRIMARY KEY,
  entity_id text NOT NULL REFERENCES control.custom_entities(id) ON DELETE CASCADE,
  ciphertext bytea NOT NULL,
  nonce bytea NOT NULL,
  dek_id text NOT NULL,
  expires_at timestamptz NOT NULL
);

-- Not in the spec's table list, but its publish-requests endpoints need somewhere to live.
CREATE TABLE control.custom_entity_publish_requests (
  id text PRIMARY KEY,
  tenant_id text NOT NULL REFERENCES control.tenants(id),
  vault_id text NOT NULL REFERENCES control.vaults(id),
  entity_id text NOT NULL REFERENCES control.custom_entities(id),
  version integer NOT NULL,
  snapshot jsonb NOT NULL,
  benchmark jsonb NOT NULL,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','rejected','superseded')),
  requested_by text NOT NULL,
  decided_by text,
  created_at timestamptz NOT NULL DEFAULT now(),
  decided_at timestamptz,
  CHECK (decided_by IS NULL OR decided_by <> requested_by OR status <> 'approved')
);
CREATE UNIQUE INDEX custom_entity_one_pending ON control.custom_entity_publish_requests (entity_id) WHERE status = 'pending';

CREATE TABLE control.ruleset_versions (
  vault_id text PRIMARY KEY REFERENCES control.vaults(id),
  version bigint NOT NULL
);

-- Fields can be declared as a custom type.
ALTER TABLE control.vault_fields DROP CONSTRAINT vault_fields_data_type_check;
ALTER TABLE control.vault_fields
  ADD CONSTRAINT vault_fields_data_type_check CHECK (data_type IN ('bvn','nin','vnin','ng_11_digit_id','nuban','phone_ng','email','person_name','amount_ngn','payment_ref','address','date','free_text','custom')),
  ADD COLUMN custom_entity_id text REFERENCES control.custom_entities(id),
  ADD CONSTRAINT vault_fields_custom_ck CHECK ((data_type = 'custom') = (custom_entity_id IS NOT NULL));

-- Detection counts record which version and rule set matched. Rows now differ by
-- version, so the key moves to a unique index that treats built-ins as version 0.
ALTER TABLE events.detection_events
  ADD COLUMN entity_version integer,
  ADD COLUMN ruleset_version bigint,
  DROP CONSTRAINT detection_events_pkey,
  DROP CONSTRAINT detection_events_action_check,
  ADD CONSTRAINT detection_events_action_check CHECK (action IN ('tokenized','masked','dropped','passed','shadow'));
CREATE UNIQUE INDEX detection_events_key ON events.detection_events
  (occurred_at, vault_id, module, source_id, destination, entity_type, action, coalesce(entity_version, 0), coalesce(ruleset_version, 0));

-- The control plane holds no keys, so everything keyed goes through the vault role.
GRANT SELECT ON control.custom_entities, control.custom_entity_versions, control.ruleset_versions TO rv_vault;
GRANT SELECT, INSERT, DELETE ON control.custom_entity_values, control.custom_entity_tests, control.custom_entity_uploads TO rv_vault;
GRANT SELECT, INSERT, DELETE ON control.custom_entity_lists TO rv_vault;
GRANT UPDATE (staged_list_version) ON control.custom_entities TO rv_vault;
GRANT SELECT ON control.custom_entity_publish_requests TO rv_vault;

GRANT SELECT, INSERT, UPDATE ON control.custom_entities, control.custom_entity_publish_requests TO rv_control;
GRANT SELECT, INSERT ON control.custom_entity_versions TO rv_control;
GRANT SELECT ON control.custom_entity_lists TO rv_control;
GRANT SELECT, INSERT, UPDATE ON control.ruleset_versions TO rv_control;
-- Which samples exist, but never their contents.
GRANT SELECT (id, entity_id, expect_match, created_by, created_at) ON control.custom_entity_tests TO rv_control;

-- New permissions, as roles: this product's access model is role names.
INSERT INTO control.roles(id, tenant_id, name)
  SELECT t.id || ':' || r, t.id, r FROM control.tenants t, unnest(ARRAY['detection_manager','detection_approver']) r
  ON CONFLICT DO NOTHING;
