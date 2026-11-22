-- Identity: groups from an identity provider decide roles; accounts can be created
-- on first single sign-on, kept in step by SCIM, or checked against LDAP; and
-- passkeys can stand in for the authenticator code.

-- Where an account came from, and its id at the identity provider.
ALTER TABLE control.principals
  ADD COLUMN source text NOT NULL DEFAULT 'local' CHECK (source IN ('local','sso','scim','ldap')),
  ADD COLUMN external_id text;
-- Removed by an identity provider: kept for the audit trail, never signs in.
ALTER TABLE control.principals DROP CONSTRAINT principals_status_check;
ALTER TABLE control.principals ADD CONSTRAINT principals_status_check CHECK (status IN ('active','suspended','deprovisioned'));
CREATE UNIQUE INDEX principals_external_id ON control.principals (tenant_id, source, external_id) WHERE external_id IS NOT NULL;

-- A group at the identity provider (by name, or by id for Entra) gives these roles.
-- Shared by single sign-on, SCIM and LDAP. With no mappings, roles are set by hand.
CREATE TABLE control.group_role_mappings (
  tenant_id text NOT NULL REFERENCES control.tenants(id),
  group_name text NOT NULL CHECK (group_name = lower(group_name) AND length(group_name) BETWEEN 1 AND 256),
  roles text[] NOT NULL CHECK (cardinality(roles) BETWEEN 1 AND 20),
  created_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, group_name)
);

ALTER TABLE control.sso_configs
  ADD COLUMN jit_provisioning boolean NOT NULL DEFAULT false,
  ADD COLUMN groups_attribute text,
  ADD COLUMN scopes text NOT NULL DEFAULT 'openid email profile',
  ADD COLUMN provider text;

-- SCIM: bearer tokens an identity provider uses to push users and groups.
CREATE TABLE control.scim_tokens (
  id text PRIMARY KEY,
  tenant_id text NOT NULL REFERENCES control.tenants(id),
  name text NOT NULL,
  token_hash text NOT NULL UNIQUE,
  created_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz,
  revoked_at timestamptz
);
CREATE TABLE control.scim_groups (
  id text PRIMARY KEY,
  tenant_id text NOT NULL REFERENCES control.tenants(id),
  display_name text NOT NULL,
  external_id text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX scim_groups_name ON control.scim_groups (tenant_id, lower(display_name));
CREATE TABLE control.scim_group_members (
  group_id text NOT NULL REFERENCES control.scim_groups(id) ON DELETE CASCADE,
  principal_id text NOT NULL REFERENCES control.principals(id),
  PRIMARY KEY (group_id, principal_id)
);

-- LDAP: the directory people's passwords are checked against. Onshore's own second
-- factor still applies, since a directory has none.
CREATE TABLE control.ldap_configs (
  tenant_id text PRIMARY KEY REFERENCES control.tenants(id),
  url text NOT NULL CHECK (url ~ '^ldaps?://'),
  start_tls boolean NOT NULL DEFAULT false,
  ca_cert text,
  bind_dn text NOT NULL,
  bind_password_enc text NOT NULL,
  base_dn text NOT NULL,
  user_filter text NOT NULL DEFAULT '(&(objectClass=person)(mail={email}))',
  group_base_dn text,
  group_filter text NOT NULL DEFAULT '(&(objectClass=groupOfNames)(member={dn}))',
  email_domains text[] NOT NULL,
  jit_provisioning boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK (url ~ '^ldaps://' OR start_tls)
);

-- Passkeys and security keys (WebAuthn), as a second factor.
CREATE TABLE control.webauthn_credentials (
  id text PRIMARY KEY,
  principal_id text NOT NULL REFERENCES control.principals(id),
  public_key bytea NOT NULL,
  counter bigint NOT NULL DEFAULT 0,
  transports text[] NOT NULL DEFAULT '{}',
  name text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz
);
CREATE INDEX webauthn_credentials_principal ON control.webauthn_credentials (principal_id);
CREATE TABLE control.auth_challenges (
  id text PRIMARY KEY,
  principal_id text NOT NULL REFERENCES control.principals(id),
  kind text NOT NULL CHECK (kind IN ('passkey_register','passkey_login')),
  challenge text NOT NULL,
  expires_at timestamptz NOT NULL
);
CREATE INDEX auth_challenges_principal ON control.auth_challenges (principal_id, kind);

GRANT SELECT, INSERT, UPDATE, DELETE ON control.group_role_mappings, control.scim_tokens, control.scim_groups, control.scim_group_members, control.ldap_configs, control.webauthn_credentials, control.auth_challenges TO rv_control;
