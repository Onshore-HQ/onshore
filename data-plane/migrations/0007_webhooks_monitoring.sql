-- Outbound webhooks and monitoring. Control-plane state: no values, keys or data.
CREATE TABLE control.webhook_endpoints (
  id text PRIMARY KEY,
  tenant_id text NOT NULL REFERENCES control.tenants(id),
  url text NOT NULL,
  description text NOT NULL DEFAULT '',
  event_types text[] NOT NULL,
  secret_enc text NOT NULL,
  secret_prev_enc text,
  secret_prev_until timestamptz,
  enabled boolean NOT NULL DEFAULT true,
  disabled_reason text,
  audit_cursor bigint NOT NULL DEFAULT 0,
  alert_cursor timestamptz NOT NULL DEFAULT now(),
  consecutive_failures integer NOT NULL DEFAULT 0,
  last_success_at timestamptz,
  last_failure_at timestamptz,
  created_by text,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX webhook_endpoints_tenant ON control.webhook_endpoints (tenant_id);

-- One row per event per endpoint: the unique key is what makes enqueueing idempotent.
CREATE TABLE control.webhook_deliveries (
  id uuid PRIMARY KEY,
  endpoint_id text NOT NULL REFERENCES control.webhook_endpoints(id) ON DELETE CASCADE,
  tenant_id text NOT NULL,
  event_id text NOT NULL,
  event_type text NOT NULL,
  payload jsonb NOT NULL,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'delivered', 'dead')),
  attempts integer NOT NULL DEFAULT 0,
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  last_status integer,
  last_error text,
  created_at timestamptz NOT NULL DEFAULT now(),
  delivered_at timestamptz,
  UNIQUE (endpoint_id, event_id)
);
CREATE INDEX webhook_deliveries_due ON control.webhook_deliveries (next_attempt_at) WHERE status = 'pending';
CREATE INDEX webhook_deliveries_recent ON control.webhook_deliveries (endpoint_id, created_at DESC);
CREATE INDEX webhook_deliveries_age ON control.webhook_deliveries (created_at);

-- Whether each service last answered. Install-wide, so that a restart does not re-announce.
CREATE TABLE control.monitor_state (
  component text PRIMARY KEY,
  status text NOT NULL,
  failures integer NOT NULL DEFAULT 0,
  since timestamptz NOT NULL DEFAULT now(),
  checked_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE control.tenants ADD COLUMN metrics_key_hash text;
CREATE UNIQUE INDEX tenants_metrics_key ON control.tenants (metrics_key_hash) WHERE metrics_key_hash IS NOT NULL;

GRANT SELECT, INSERT, UPDATE, DELETE ON control.webhook_endpoints, control.webhook_deliveries, control.monitor_state TO rv_control;
GRANT UPDATE (metrics_key_hash) ON control.tenants TO rv_control;
GRANT INSERT ON events.alerts TO rv_control;
