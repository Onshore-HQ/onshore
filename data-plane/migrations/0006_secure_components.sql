-- Embeddable collect and reveal components.
-- Which sites may frame a vault's components. Empty, the default, means none.
ALTER TABLE control.vaults ADD COLUMN embed_origins text[] NOT NULL DEFAULT '{}';

-- Single-use capabilities the customer's backend hands to a browser. Only a hash is kept.
CREATE TABLE data.client_tokens (
  hash text PRIMARY KEY,
  id text NOT NULL UNIQUE,
  tenant_id text NOT NULL,
  vault_id text NOT NULL,
  principal_id text NOT NULL,
  kind text NOT NULL CHECK (kind IN ('collect','reveal')),
  fields text[] NOT NULL DEFAULT '{}',
  tokens text[] NOT NULL DEFAULT '{}',
  origin text NOT NULL,
  purpose text NOT NULL DEFAULT '',
  subject_ref text NOT NULL DEFAULT '',
  bind_ip text NOT NULL DEFAULT '',
  expires_at timestamptz NOT NULL,
  used_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX client_tokens_expiry ON data.client_tokens (expires_at);
GRANT SELECT, INSERT, UPDATE, DELETE ON data.client_tokens TO rv_vault;
