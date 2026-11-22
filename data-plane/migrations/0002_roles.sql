-- Least-privilege runtime roles. Passwords are set by the migrator from the
-- environment (see store.Migrate) because SQL files must not hold secrets.
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rv_vault') THEN CREATE ROLE rv_vault LOGIN; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rv_control') THEN CREATE ROLE rv_control LOGIN; END IF;
END $$;

GRANT USAGE ON SCHEMA control, data, events TO rv_vault;
GRANT SELECT ON ALL TABLES IN SCHEMA control TO rv_vault;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA data TO rv_vault;
GRANT SELECT, INSERT ON events.audit_events, events.audit_checkpoints TO rv_vault;
GRANT SELECT, INSERT, UPDATE ON events.audit_heads, events.detection_events, events.usage_daily, events.alerts TO rv_vault;
GRANT DELETE ON events.detection_events TO rv_vault;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA events TO rv_vault;
GRANT UPDATE (last_used_at) ON control.service_account_keys TO rv_vault;
GRANT UPDATE (last_active_at) ON control.principals TO rv_vault;

-- The control plane has no access to the data schema at all, and only reads events.
GRANT USAGE ON SCHEMA control, events TO rv_control;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA control TO rv_control;
GRANT SELECT ON ALL TABLES IN SCHEMA events TO rv_control;
GRANT UPDATE (acknowledged_at) ON events.alerts TO rv_control;
