-- Email through the customer's own mail server, and ways back into an account.
CREATE TABLE control.mail_settings (
  tenant_id      text PRIMARY KEY REFERENCES control.tenants(id),
  host           text NOT NULL,
  port           integer NOT NULL,
  tls_mode       text NOT NULL CHECK (tls_mode IN ('starttls','tls','none')),
  username       text,
  password_enc   text,
  from_address   text NOT NULL,
  from_name      text NOT NULL DEFAULT 'Onshore',
  console_url    text NOT NULL,
  alerts_enabled boolean NOT NULL DEFAULT true,
  verified_at    timestamptz,
  updated_at     timestamptz NOT NULL DEFAULT now()
);

-- Single-use links. Only a hash is stored, so a database copy cannot sign anyone in.
CREATE TABLE control.account_tokens (
  id           text PRIMARY KEY,
  tenant_id    text NOT NULL REFERENCES control.tenants(id),
  principal_id text NOT NULL REFERENCES control.principals(id) ON DELETE CASCADE,
  kind         text NOT NULL CHECK (kind IN ('invite','password_reset','admin_recovery')),
  token_hash   text NOT NULL UNIQUE,
  created_by   text,
  created_at   timestamptz NOT NULL DEFAULT now(),
  expires_at   timestamptz NOT NULL,
  used_at      timestamptz,
  revoked_at   timestamptz
);
CREATE INDEX account_tokens_principal ON control.account_tokens(principal_id);

CREATE TABLE control.recovery_codes (
  id           text PRIMARY KEY,
  principal_id text NOT NULL REFERENCES control.principals(id) ON DELETE CASCADE,
  code_hash    text NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  used_at      timestamptz
);
CREATE INDEX recovery_codes_principal ON control.recovery_codes(principal_id);

-- A replacement authenticator, held until it is proven with a valid code.
ALTER TABLE control.principals ADD COLUMN totp_pending_enc text;
ALTER TABLE events.alerts ADD COLUMN emailed_at timestamptz;

GRANT SELECT, INSERT, UPDATE, DELETE ON control.mail_settings TO rv_control;
GRANT SELECT, INSERT, UPDATE ON control.account_tokens TO rv_control;
GRANT SELECT, INSERT, UPDATE, DELETE ON control.recovery_codes TO rv_control;
GRANT UPDATE (emailed_at) ON events.alerts TO rv_control;
