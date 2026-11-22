-- Each organisation has its own time zone, which decides where a "day" ends for
-- usage, audit checkpoints, residency-map history and exception expiry. Existing
-- organisations were set up in Nigeria, so they keep West Africa Time.
ALTER TABLE control.tenants ADD COLUMN time_zone text NOT NULL DEFAULT 'UTC';
UPDATE control.tenants SET time_zone = 'Africa/Lagos' WHERE hosting_country = 'NG';

-- Only a zone PostgreSQL knows is accepted.
CREATE FUNCTION control.check_time_zone() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_timezone_names WHERE name = NEW.time_zone) THEN
    RAISE EXCEPTION 'unknown time zone %', NEW.time_zone USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER tenants_time_zone BEFORE INSERT OR UPDATE OF time_zone ON control.tenants
  FOR EACH ROW EXECUTE FUNCTION control.check_time_zone();

CREATE FUNCTION control.tenant_tz(t text) RETURNS text LANGUAGE sql STABLE AS
  $$ SELECT coalesce((SELECT time_zone FROM control.tenants WHERE id = t), 'UTC') $$;
CREATE FUNCTION control.vault_tz(v text) RETURNS text LANGUAGE sql STABLE AS
  $$ SELECT coalesce((SELECT t.time_zone FROM control.vaults x JOIN control.tenants t ON t.id = x.tenant_id WHERE x.id = v), 'UTC') $$;
GRANT EXECUTE ON FUNCTION control.tenant_tz(text), control.vault_tz(text) TO rv_vault, rv_control;
GRANT UPDATE (time_zone) ON control.tenants TO rv_control;

-- A flow's scope is the organisation's own definition of data that must stay in
-- the country, whichever law it comes from; it was named after one regulator.
ALTER TABLE control.data_flows RENAME COLUMN in_cbn_scope TO in_scope;
