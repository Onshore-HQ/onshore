-- A vault can have its own time zone; it inherits the organisation's when unset.
-- An organisation spanning several countries then counts each vault's days locally,
-- while the tenant-wide audit chain keeps the organisation's zone.
ALTER TABLE control.vaults ADD COLUMN time_zone text;
CREATE FUNCTION control.check_vault_time_zone() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.time_zone IS NOT NULL AND NOT EXISTS (SELECT 1 FROM pg_timezone_names WHERE name = NEW.time_zone) THEN
    RAISE EXCEPTION 'unknown time zone %', NEW.time_zone USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER vaults_time_zone BEFORE INSERT OR UPDATE OF time_zone ON control.vaults
  FOR EACH ROW EXECUTE FUNCTION control.check_vault_time_zone();
CREATE OR REPLACE FUNCTION control.vault_tz(v text) RETURNS text LANGUAGE sql STABLE AS
  $$ SELECT coalesce((SELECT coalesce(x.time_zone, t.time_zone) FROM control.vaults x JOIN control.tenants t ON t.id = x.tenant_id WHERE x.id = v), 'UTC') $$;

-- Enterprise: installs in other countries linked to this one. Each member install
-- keeps its own vaults, keys and customer data in its country; it sends this install
-- only names, settings and counts, signed with a secret agreed when it joined.
CREATE TABLE control.linked_installs (
  id text PRIMARY KEY,
  tenant_id text NOT NULL REFERENCES control.tenants(id),
  country text NOT NULL CHECK (country ~ '^[A-Z]{2}$'),
  name text NOT NULL,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','active','revoked')),
  join_code_hash text UNIQUE,
  join_expires_at timestamptz,
  secret_enc text,
  base_url text,
  version text,
  summary jsonb NOT NULL DEFAULT '{}',
  last_seen_at timestamptz,
  created_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  joined_at timestamptz,
  revoked_at timestamptz
);
CREATE INDEX linked_installs_tenant ON control.linked_installs (tenant_id);

-- On a member install: the primary it reports to.
CREATE TABLE control.federation (
  id boolean PRIMARY KEY DEFAULT true CHECK (id),
  primary_url text NOT NULL,
  install_id text NOT NULL,
  secret_enc text NOT NULL,
  joined_at timestamptz NOT NULL DEFAULT now(),
  last_report_at timestamptz,
  last_error text
);

-- Onshore Cloud: countries an organisation is waiting for.
CREATE TABLE control.region_waitlist (
  tenant_id text NOT NULL REFERENCES control.tenants(id),
  country text NOT NULL CHECK (country ~ '^[A-Z]{2}$'),
  requested_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  notified_at timestamptz,
  PRIMARY KEY (tenant_id, country)
);

GRANT SELECT, INSERT, UPDATE, DELETE ON control.linked_installs, control.federation, control.region_waitlist TO rv_control;
GRANT SELECT ON control.linked_installs TO rv_vault;
GRANT EXECUTE ON FUNCTION control.vault_tz(text) TO rv_vault, rv_control;
