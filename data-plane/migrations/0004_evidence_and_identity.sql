-- Audit retention, SIEM export, SSO and support adapters.
ALTER TABLE control.tenants
  ADD COLUMN audit_retention_days integer NOT NULL DEFAULT 2557 CHECK (audit_retention_days >= 365),
  ADD COLUMN siem_url text,
  ADD COLUMN siem_secret_enc text,
  ADD COLUMN siem_cursor bigint NOT NULL DEFAULT 0;

-- Where a purged chain resumes. The purge keeps the hash of its last removed event,
-- so that verification still proves nothing later was altered.
CREATE TABLE events.audit_anchors (
  tenant_id text PRIMARY KEY,
  seq bigint NOT NULL,
  hash text NOT NULL,
  events_removed bigint NOT NULL DEFAULT 0,
  purged_at timestamptz NOT NULL DEFAULT now()
);

CREATE OR REPLACE FUNCTION events.reject_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' AND current_setting('rv.audit_purge', true) = 'on' THEN RETURN OLD; END IF;
  RAISE EXCEPTION 'audit_events is append-only';
END $$;

-- The only way to remove audit events: a whole prefix older than the tenant's
-- retention and already covered by a signed checkpoint. Definer rights, because the
-- application role holds no DELETE on this table.
CREATE FUNCTION events.purge_audit(p_tenant text) RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER SET search_path = events, control, pg_temp AS $$
DECLARE
  v_days integer; v_seq bigint; v_hash text; v_removed bigint;
BEGIN
  SELECT audit_retention_days INTO v_days FROM control.tenants WHERE id = p_tenant;
  IF v_days IS NULL THEN RETURN 0; END IF;
  SELECT c.seq, c.hash INTO v_seq, v_hash FROM events.audit_checkpoints c
    JOIN events.audit_events e ON e.seq = c.seq
    WHERE c.tenant_id = p_tenant AND e.occurred_at < now() - make_interval(days => v_days)
    ORDER BY c.seq DESC LIMIT 1;
  IF v_seq IS NULL THEN RETURN 0; END IF;
  PERFORM set_config('rv.audit_purge', 'on', true);
  DELETE FROM events.audit_events WHERE tenant_id = p_tenant AND seq <= v_seq;
  GET DIAGNOSTICS v_removed = ROW_COUNT;
  PERFORM set_config('rv.audit_purge', 'off', true);
  IF v_removed = 0 THEN RETURN 0; END IF;
  INSERT INTO events.audit_anchors(tenant_id, seq, hash, events_removed) VALUES (p_tenant, v_seq, v_hash, v_removed)
    ON CONFLICT (tenant_id) DO UPDATE SET seq = EXCLUDED.seq, hash = EXCLUDED.hash, events_removed = audit_anchors.events_removed + EXCLUDED.events_removed, purged_at = now();
  RETURN v_removed;
END $$;
REVOKE ALL ON FUNCTION events.purge_audit(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION events.purge_audit(text) TO rv_vault;
GRANT SELECT ON events.audit_anchors TO rv_vault, rv_control;
GRANT UPDATE (siem_cursor) ON control.tenants TO rv_control;

CREATE TABLE control.sso_configs (
  tenant_id text PRIMARY KEY REFERENCES control.tenants(id),
  kind text NOT NULL CHECK (kind IN ('oidc','saml')),
  email_domains text[] NOT NULL,
  -- OIDC
  issuer text,
  client_id text,
  client_secret_enc text,
  -- SAML
  idp_sso_url text,
  idp_cert text,
  sp_entity_id text,
  -- Consoles require MFA. An IdP session counts only if the admin says it enforces MFA.
  idp_enforces_mfa boolean NOT NULL DEFAULT false,
  sso_only boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE control.sso_states (
  state_hash text PRIMARY KEY,
  tenant_id text NOT NULL,
  nonce text NOT NULL,
  verifier text NOT NULL,
  expires_at timestamptz NOT NULL
);

CREATE TABLE control.adapters (
  id text PRIMARY KEY,
  vault_id text NOT NULL REFERENCES control.vaults(id),
  name text NOT NULL,
  kind text NOT NULL CHECK (kind IN ('freshdesk','intercom','zoho_desk','salesforce')),
  base_url text NOT NULL,
  api_credential_enc text NOT NULL,
  webhook_secret_hash text NOT NULL,
  webhook_secret_enc text NOT NULL,
  mode text NOT NULL DEFAULT 'shadow' CHECK (mode IN ('shadow','enforcing')),
  transfer_basis text NOT NULL DEFAULT 'not_assessed' CHECK (transfer_basis IN ('not_assessed','adequacy','approved_instrument','section_43','tokens_only')),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (vault_id, name)
);

GRANT SELECT ON control.sso_configs, control.adapters TO rv_vault;
GRANT SELECT, INSERT, UPDATE, DELETE ON control.sso_configs, control.sso_states, control.adapters TO rv_control;
