-- An organisation's own country pack: data types and laws for a country without a
-- built-in pack (or extra ones for a country with one). Applying a pack to a vault
-- creates its data types there as drafts, which publish through the usual tests and
-- second-person approval. A pack can be exported as a signed file and imported.

CREATE TABLE control.custom_packs (
  id text PRIMARY KEY,
  tenant_id text NOT NULL REFERENCES control.tenants(id),
  country text NOT NULL CHECK (country ~ '^[A-Z]{2}$'),
  name text NOT NULL CHECK (length(name) BETWEEN 2 AND 80),
  description text NOT NULL DEFAULT '',
  version int NOT NULL DEFAULT 1 CHECK (version >= 1),
  data_types jsonb NOT NULL DEFAULT '[]',
  laws jsonb NOT NULL DEFAULT '[]',
  origin text NOT NULL DEFAULT 'own' CHECK (origin IN ('own','imported')),
  imported_from jsonb,
  created_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  archived_at timestamptz
);
CREATE UNIQUE INDEX custom_packs_name ON control.custom_packs (tenant_id, lower(name)) WHERE archived_at IS NULL;

-- A data type that came from a pack, and from which version of it.
ALTER TABLE control.custom_entities
  ADD COLUMN pack_id text REFERENCES control.custom_packs(id),
  ADD COLUMN pack_version int;

-- The key an organisation signs exported packs with. Only the public half leaves.
CREATE TABLE control.pack_signing_keys (
  tenant_id text PRIMARY KEY REFERENCES control.tenants(id),
  public_key text NOT NULL,
  private_key_enc text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

GRANT SELECT, INSERT, UPDATE, DELETE ON control.custom_packs, control.pack_signing_keys TO rv_control;
GRANT SELECT ON control.custom_packs TO rv_vault;
