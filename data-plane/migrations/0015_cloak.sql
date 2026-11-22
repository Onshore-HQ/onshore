-- Cloak settings: what happens to each kind of data before text leaves the
-- country (a placeholder, a stand-in name or a less specific value). Reusable
-- across a vault's AI routes and the cloak API.
CREATE TABLE control.cloak_profiles (
  id text PRIMARY KEY,
  vault_id text NOT NULL REFERENCES control.vaults(id),
  name text NOT NULL,
  options jsonb NOT NULL DEFAULT '{}',
  created_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (vault_id, name)
);
ALTER TABLE control.ai_routes ADD COLUMN cloak_profile_id text REFERENCES control.cloak_profiles(id);
ALTER TABLE control.ai_routes ADD COLUMN twin_days integer NOT NULL DEFAULT 0 CHECK (twin_days BETWEEN 0 AND 365);
GRANT SELECT ON control.cloak_profiles TO rv_vault;
GRANT SELECT, INSERT, UPDATE, DELETE ON control.cloak_profiles TO rv_control;

-- Digital twins: the sealed map from what a provider saw back to the real
-- values, so an app can swap them back later as far as policy allows.
CREATE TABLE data.cloak_twins (
  id uuid PRIMARY KEY,
  vault_id text NOT NULL,
  route_id text,
  dek_id text NOT NULL REFERENCES data.data_keys(id),
  ciphertext bytea NOT NULL,
  nonce bytea NOT NULL,
  entities jsonb NOT NULL,
  created_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL
);
CREATE INDEX cloak_twins_expiry ON data.cloak_twins (expires_at);
CREATE INDEX cloak_twins_dek ON data.cloak_twins (dek_id);
CREATE INDEX cloak_twins_vault ON data.cloak_twins (vault_id, created_at DESC);
GRANT SELECT, INSERT, UPDATE, DELETE ON data.cloak_twins TO rv_vault;
