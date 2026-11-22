-- Update Spec 02: the residency map. Additive only. The spec's SQL is written against
-- uuid keys and enum types; this schema uses text ids and CHECK constraints instead.

ALTER TABLE control.vaults ADD COLUMN residency_map_enabled boolean NOT NULL DEFAULT false;
ALTER TABLE control.tenants ADD COLUMN map_exception_max_days integer NOT NULL DEFAULT 180 CHECK (map_exception_max_days BETWEEN 1 AND 730);

-- Global rows have a null tenant. Regions: [{"code":"us1","name":"US1","country":"US","hosts":["..."]}].
-- An empty list means the vendor publishes no region we can state, so the customer declares it.
CREATE TABLE control.vendors (
  id text PRIMARY KEY,
  tenant_id text REFERENCES control.tenants(id),
  name text NOT NULL,
  category text NOT NULL,
  hostnames text[] NOT NULL,
  regions jsonb NOT NULL DEFAULT '[]',
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX vendors_name ON control.vendors (coalesce(tenant_id, ''), lower(name));

CREATE TABLE control.systems (
  id text PRIMARY KEY,
  tenant_id text NOT NULL REFERENCES control.tenants(id),
  vault_id text NOT NULL REFERENCES control.vaults(id),
  name text NOT NULL,
  kind text NOT NULL CHECK (kind IN ('database','service','warehouse','saas_account','log_pipeline','ai_route','proxy_route','file_store','other')),
  vendor_id text REFERENCES control.vendors(id),
  vendor_region text,                 -- confirmed region code; null means not confirmed
  hosting_country text CHECK (hosting_country ~ '^[A-Z]{2}$'),
  hosting_facility text,
  host text,                          -- for a destination known only by its address
  owner_id text REFERENCES control.principals(id),
  entity_types text[] NOT NULL DEFAULT '{}',
  managed_by_onshore boolean NOT NULL DEFAULT false,
  source_ref jsonb,                   -- {"type":"log_pipeline","id":"..."}
  route_mode text CHECK (route_mode IN ('shadow','enforcing')),
  route_mode_since timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  retired_at timestamptz
);
CREATE INDEX systems_vault ON control.systems (vault_id, kind);
CREATE UNIQUE INDEX systems_source ON control.systems ((source_ref->>'id')) WHERE source_ref IS NOT NULL;
CREATE UNIQUE INDEX systems_vendor_account ON control.systems (vault_id, vendor_id) WHERE kind = 'saas_account' AND vendor_id IS NOT NULL AND retired_at IS NULL;
CREATE UNIQUE INDEX systems_host ON control.systems (vault_id, host) WHERE host IS NOT NULL AND retired_at IS NULL;

-- Declaration changes and route mode changes, for the system page and a flow's evidence.
CREATE TABLE control.system_history (
  seq bigserial PRIMARY KEY,
  system_id text NOT NULL REFERENCES control.systems(id),
  occurred_at timestamptz NOT NULL DEFAULT now(),
  kind text NOT NULL CHECK (kind IN ('declared','declaration_changed','region_confirmed','route_mode')),
  detail jsonb NOT NULL,
  actor_id text REFERENCES control.principals(id)
);
CREATE INDEX system_history_system ON control.system_history (system_id, occurred_at);

CREATE TABLE control.data_flows (
  id text PRIMARY KEY,
  tenant_id text NOT NULL REFERENCES control.tenants(id),
  vault_id text NOT NULL REFERENCES control.vaults(id),
  source_system_id text NOT NULL REFERENCES control.systems(id),
  dest_system_id text REFERENCES control.systems(id),
  dest_vendor_id text REFERENCES control.vendors(id),
  dest_region text,
  dest_host text,
  dest_country text CHECK (dest_country ~ '^[A-Z]{2}$'),
  dest_country_source text NOT NULL DEFAULT 'unconfirmed' CHECK (dest_country_source IN ('vendor_region','declared','unconfirmed')),
  dest_ip_hint text,                  -- from an IP lookup: shown beside the declared value, never used as it
  entity_types text[] NOT NULL DEFAULT '{}',
  in_cbn_scope boolean NOT NULL DEFAULT true,
  origin text NOT NULL CHECK (origin IN ('observed','manual')),
  via_system_id text REFERENCES control.systems(id), -- the Onshore route this flow passes through
  route_source_id text,               -- that route's id, as detection events name it
  status text NOT NULL DEFAULT 'unverified' CHECK (status IN ('unverified','leaking','shadow','protected','verified','in_country','exception','retired')),
  status_since timestamptz NOT NULL DEFAULT now(),
  owner_id text REFERENCES control.principals(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  retired_at timestamptz,
  CHECK (dest_system_id IS NOT NULL OR dest_vendor_id IS NOT NULL OR dest_host IS NOT NULL)
);
CREATE INDEX data_flows_status ON control.data_flows (tenant_id, status);
CREATE INDEX data_flows_vault ON control.data_flows (vault_id, status);
CREATE INDEX data_flows_route ON control.data_flows (route_source_id, dest_host) WHERE route_source_id IS NOT NULL;
CREATE UNIQUE INDEX data_flows_path ON control.data_flows
  (source_system_id, coalesce(dest_vendor_id, dest_system_id, dest_host), coalesce(dest_region, ''), coalesce(dest_host, ''))
  WHERE retired_at IS NULL;

-- Append-only: the control role can insert and read, never change. Kept like audit events.
CREATE TABLE control.flow_status_events (
  seq bigserial PRIMARY KEY,
  flow_id text NOT NULL REFERENCES control.data_flows(id),
  occurred_at timestamptz NOT NULL DEFAULT now(),
  from_status text,
  to_status text NOT NULL,
  cause text NOT NULL,
  evidence jsonb,
  actor_id text REFERENCES control.principals(id) -- null when set by the engine
);
CREATE INDEX flow_status_events_flow ON control.flow_status_events (flow_id, occurred_at);

CREATE TABLE control.flow_observations_daily (
  flow_id text NOT NULL REFERENCES control.data_flows(id),
  day date NOT NULL,
  entity_type text NOT NULL,
  protected_count bigint NOT NULL DEFAULT 0,
  passed_count bigint NOT NULL DEFAULT 0,
  ruleset_version bigint,
  PRIMARY KEY (flow_id, day, entity_type)
);
CREATE INDEX flow_observations_day ON control.flow_observations_daily (day);

CREATE TABLE control.flow_exceptions (
  id text PRIMARY KEY,
  flow_id text NOT NULL REFERENCES control.data_flows(id),
  reason text NOT NULL,
  compensating_controls text,
  requested_by text NOT NULL REFERENCES control.principals(id),
  requested_at timestamptz NOT NULL DEFAULT now(),
  approved_by text REFERENCES control.principals(id),
  approved_at timestamptz,
  revoked_by text REFERENCES control.principals(id),
  revoked_at timestamptz,
  expires_at date NOT NULL,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','active','expired','revoked')),
  expiry_warned boolean NOT NULL DEFAULT false,
  CHECK (approved_by IS NULL OR approved_by <> requested_by)
);
CREATE INDEX flow_exceptions_flow ON control.flow_exceptions (flow_id, status);
CREATE UNIQUE INDEX flow_exceptions_one_live ON control.flow_exceptions (flow_id) WHERE status IN ('pending','active');

CREATE TABLE control.remediation_actions (
  id text PRIMARY KEY,
  flow_id text NOT NULL REFERENCES control.data_flows(id),
  plan text NOT NULL CHECK (plan IN ('move_in_country','route_via_proxy','tokenize_at_source','delete_data','other')),
  description text,
  owner_id text NOT NULL REFERENCES control.principals(id),
  due_date date NOT NULL,
  status text NOT NULL DEFAULT 'open' CHECK (status IN ('open','in_progress','done','cancelled')),
  evidence jsonb,                     -- the linked change
  evidence_files jsonb,               -- proof, encrypted with the control secret
  created_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz,
  completed_by text REFERENCES control.principals(id),
  overdue_warned boolean NOT NULL DEFAULT false
);
CREATE INDEX remediation_actions_flow ON control.remediation_actions (flow_id, status);

-- Scores over time. Recomputed through the day; the last value of a day stands.
CREATE TABLE control.map_scores_daily (
  vault_id text NOT NULL REFERENCES control.vaults(id),
  day date NOT NULL,
  flow_score numeric(5,2),
  flow_score_without_exceptions numeric(5,2),
  volume_score numeric(5,2),
  counts jsonb NOT NULL DEFAULT '{}',
  PRIMARY KEY (vault_id, day)
);

-- Where each detection was headed. `destination` stays the human label it always was.
ALTER TABLE events.detection_events
  ADD COLUMN dest_host text,
  ADD COLUMN flow_id text;
DROP INDEX events.detection_events_key;
CREATE UNIQUE INDEX detection_events_key ON events.detection_events
  (occurred_at, vault_id, module, source_id, destination, coalesce(dest_host, ''), entity_type, action, coalesce(entity_version, 0), coalesce(ruleset_version, 0));
CREATE INDEX detection_events_flow ON events.detection_events (flow_id, occurred_at);
CREATE INDEX detection_events_host ON events.detection_events (source_id, dest_host, occurred_at) WHERE dest_host IS NOT NULL;

-- Every Onshore pipeline and route is also a system on the map.
ALTER TABLE control.log_pipelines
  ADD COLUMN system_id text REFERENCES control.systems(id),
  ADD COLUMN upstream_host text GENERATED ALWAYS AS (lower(substring(upstream_url from '^[a-zA-Z]+://(?:[^/@]*@)?([^/:?#]+)'))) STORED;
ALTER TABLE control.ai_routes ADD COLUMN system_id text REFERENCES control.systems(id);
ALTER TABLE control.proxy_routes ADD COLUMN system_id text REFERENCES control.systems(id);

GRANT SELECT, INSERT, UPDATE ON control.vendors, control.systems, control.data_flows, control.flow_observations_daily, control.flow_exceptions, control.remediation_actions, control.map_scores_daily TO rv_control;
GRANT SELECT, INSERT ON control.flow_status_events, control.system_history TO rv_control;
GRANT USAGE ON SEQUENCE control.flow_status_events_seq_seq, control.system_history_seq_seq TO rv_control;
GRANT UPDATE (flow_id) ON events.detection_events TO rv_control;
GRANT UPDATE (residency_map_enabled) ON control.vaults TO rv_control;
GRANT UPDATE (map_exception_max_days) ON control.tenants TO rv_control;

INSERT INTO control.roles(id, tenant_id, name)
  SELECT t.id || ':' || r, t.id, r FROM control.tenants t, unnest(ARRAY['map_editor','exception_approver']) r
  ON CONFLICT DO NOTHING;

-- The seeded catalogue. Hostnames and regions come from general knowledge of each vendor's
-- public documentation and were not checked vendor by vendor. An empty region list means no
-- hosting location is stated: the customer declares it. Nothing here is treated as confirmed
-- until the customer confirms it for their own account.
INSERT INTO control.vendors(id, name, category, hostnames, regions) VALUES
  ('ven_datadog', 'Datadog', 'logging', ARRAY['*.datadoghq.com','*.datadoghq.eu','*.ddog-gov.com'], '[{"code":"us1","name":"US1","country":"US","hosts":["datadoghq.com"]},{"code":"us3","name":"US3","country":"US","hosts":["us3.datadoghq.com"]},{"code":"us5","name":"US5","country":"US","hosts":["us5.datadoghq.com"]},{"code":"eu1","name":"EU1","country":"DE","hosts":["datadoghq.eu"]},{"code":"ap1","name":"AP1","country":"JP","hosts":["ap1.datadoghq.com"]},{"code":"ap2","name":"AP2","country":"AU","hosts":["ap2.datadoghq.com"]}]'::jsonb),
  ('ven_sentry', 'Sentry', 'apm', ARRAY['sentry.io','*.sentry.io'], '[{"code":"us","name":"US","country":"US","hosts":["*.ingest.us.sentry.io"]},{"code":"de","name":"EU (Germany)","country":"DE","hosts":["*.ingest.de.sentry.io"]}]'::jsonb),
  ('ven_newrelic', 'New Relic', 'apm', ARRAY['*.newrelic.com','*.nr-data.net'], '[{"code":"us","name":"US","country":"US","hosts":[]},{"code":"eu","name":"EU","country":"DE","hosts":["*.eu01.nr-data.net","*.eu.newrelic.com"]}]'::jsonb),
  ('ven_grafanacloud', 'Grafana Cloud', 'logging', ARRAY['*.grafana.net'], '[{"code":"us","name":"US","country":"US","hosts":[]},{"code":"eu","name":"EU","country":"EU","hosts":[]},{"code":"other","name":"Another region","country":null,"hosts":[]}]'::jsonb),
  ('ven_elasticcloud', 'Elastic Cloud', 'logging', ARRAY['*.elastic-cloud.com','*.es.io'], '[{"code":"us","name":"US","country":"US","hosts":[]},{"code":"eu","name":"EU","country":"EU","hosts":[]},{"code":"af-south-1","name":"AWS Cape Town","country":"ZA","hosts":[]}]'::jsonb),
  ('ven_splunkcloud', 'Splunk Cloud', 'logging', ARRAY['*.splunkcloud.com'], '[{"code":"us","name":"US","country":"US","hosts":[]},{"code":"eu","name":"EU","country":"EU","hosts":[]}]'::jsonb),
  ('ven_logzio', 'Logz.io', 'logging', ARRAY['*.logz.io'], '[{"code":"us","name":"US","country":"US","hosts":[]},{"code":"eu","name":"EU","country":"EU","hosts":[]}]'::jsonb),
  ('ven_solarwindspapertrail', 'SolarWinds Papertrail', 'logging', ARRAY['*.papertrailapp.com'], '[{"code":"us","name":"US","country":"US","hosts":[]}]'::jsonb),
  ('ven_betterstack', 'Better Stack', 'logging', ARRAY['*.betterstackdata.com','*.logs.betterstack.com'], '[{"code":"us","name":"US","country":"US","hosts":[]},{"code":"eu","name":"EU","country":"EU","hosts":[]}]'::jsonb),
  ('ven_honeycomb', 'Honeycomb', 'apm', ARRAY['*.honeycomb.io'], '[{"code":"us","name":"US","country":"US","hosts":["api.honeycomb.io"]},{"code":"eu","name":"EU","country":"EU","hosts":["api.eu1.honeycomb.io"]}]'::jsonb),
  ('ven_dynatrace', 'Dynatrace', 'apm', ARRAY['*.live.dynatrace.com'], '[{"code":"us","name":"US","country":"US","hosts":[]},{"code":"eu","name":"EU","country":"EU","hosts":[]}]'::jsonb),
  ('ven_rollbar', 'Rollbar', 'apm', ARRAY['*.rollbar.com'], '[{"code":"us","name":"US","country":"US","hosts":[]}]'::jsonb),
  ('ven_bugsnag', 'Bugsnag', 'apm', ARRAY['*.bugsnag.com'], '[{"code":"us","name":"US","country":"US","hosts":[]}]'::jsonb),
  ('ven_openai', 'OpenAI', 'ai', ARRAY['api.openai.com'], '[{"code":"us","name":"US","country":"US","hosts":[]}]'::jsonb),
  ('ven_anthropic', 'Anthropic', 'ai', ARRAY['api.anthropic.com'], '[{"code":"us","name":"US","country":"US","hosts":[]}]'::jsonb),
  ('ven_googlegemini', 'Google Gemini', 'ai', ARRAY['generativelanguage.googleapis.com'], '[{"code":"global","name":"Google global","country":"US","hosts":[]}]'::jsonb),
  ('ven_azureopenai', 'Azure OpenAI', 'ai', ARRAY['*.openai.azure.com'], '[{"code":"southafricanorth","name":"South Africa North","country":"ZA","hosts":[]},{"code":"westeurope","name":"West Europe","country":"NL","hosts":[]},{"code":"eastus","name":"East US","country":"US","hosts":[]}]'::jsonb),
  ('ven_amazonbedrock', 'Amazon Bedrock', 'ai', ARRAY['bedrock-runtime.*.amazonaws.com'], '[{"code":"us-east-1","name":"N. Virginia","country":"US","hosts":[]},{"code":"eu-central-1","name":"Frankfurt","country":"DE","hosts":[]}]'::jsonb),
  ('ven_cohere', 'Cohere', 'ai', ARRAY['api.cohere.com','api.cohere.ai'], '[{"code":"us","name":"US","country":"US","hosts":[]}]'::jsonb),
  ('ven_mistralai', 'Mistral AI', 'ai', ARRAY['api.mistral.ai'], '[{"code":"eu","name":"EU","country":"EU","hosts":[]}]'::jsonb),
  ('ven_groq', 'Groq', 'ai', ARRAY['api.groq.com'], '[{"code":"us","name":"US","country":"US","hosts":[]}]'::jsonb),
  ('ven_freshdesk', 'Freshdesk', 'support', ARRAY['*.freshdesk.com'], '[{"code":"us","name":"US","country":"US","hosts":[]},{"code":"eu","name":"EU","country":"DE","hosts":[]},{"code":"in","name":"India","country":"IN","hosts":[]},{"code":"au","name":"Australia","country":"AU","hosts":[]}]'::jsonb),
  ('ven_zendesk', 'Zendesk', 'support', ARRAY['*.zendesk.com'], '[{"code":"us","name":"US","country":"US","hosts":[]},{"code":"eu","name":"EU","country":"EU","hosts":[]}]'::jsonb),
  ('ven_intercom', 'Intercom', 'support', ARRAY['*.intercom.io','*.intercom.com'], '[{"code":"us","name":"US","country":"US","hosts":["api.intercom.io"]},{"code":"eu","name":"EU","country":"IE","hosts":["api.eu.intercom.io"]},{"code":"au","name":"Australia","country":"AU","hosts":["api.au.intercom.io"]}]'::jsonb),
  ('ven_zohodesk', 'Zoho Desk', 'support', ARRAY['desk.zoho.com','desk.zoho.eu','desk.zoho.in'], '[{"code":"us","name":"US","country":"US","hosts":["desk.zoho.com"]},{"code":"eu","name":"EU","country":"EU","hosts":["desk.zoho.eu"]},{"code":"in","name":"India","country":"IN","hosts":["desk.zoho.in"]}]'::jsonb),
  ('ven_salesforce', 'Salesforce', 'support', ARRAY['*.salesforce.com','*.force.com'], '[{"code":"us","name":"US","country":"US","hosts":[]},{"code":"eu","name":"EU","country":"EU","hosts":[]}]'::jsonb),
  ('ven_hubspot', 'HubSpot', 'support', ARRAY['*.hubapi.com'], '[{"code":"us","name":"US","country":"US","hosts":[]},{"code":"eu","name":"EU","country":"DE","hosts":[]}]'::jsonb),
  ('ven_segment', 'Segment', 'analytics', ARRAY['*.segment.io','*.segmentapis.com'], '[{"code":"us","name":"US","country":"US","hosts":["api.segment.io"]},{"code":"eu","name":"EU","country":"IE","hosts":["events.eu1.segmentapis.com"]}]'::jsonb),
  ('ven_mixpanel', 'Mixpanel', 'analytics', ARRAY['*.mixpanel.com'], '[{"code":"us","name":"US","country":"US","hosts":["api.mixpanel.com"]},{"code":"eu","name":"EU","country":"EU","hosts":["api-eu.mixpanel.com"]}]'::jsonb),
  ('ven_amplitude', 'Amplitude', 'analytics', ARRAY['*.amplitude.com'], '[{"code":"us","name":"US","country":"US","hosts":["api.amplitude.com"]},{"code":"eu","name":"EU","country":"EU","hosts":["api.eu.amplitude.com"]}]'::jsonb),
  ('ven_posthog', 'PostHog', 'analytics', ARRAY['*.posthog.com'], '[{"code":"us","name":"US","country":"US","hosts":["us.i.posthog.com"]},{"code":"eu","name":"EU","country":"EU","hosts":["eu.i.posthog.com"]}]'::jsonb),
  ('ven_googleanalytics', 'Google Analytics', 'analytics', ARRAY['*.google-analytics.com'], '[{"code":"global","name":"Google global","country":"US","hosts":[]}]'::jsonb),
  ('ven_snowflake', 'Snowflake', 'cloud', ARRAY['*.snowflakecomputing.com'], '[{"code":"aws-eu-west-1","name":"AWS Ireland","country":"IE","hosts":[]},{"code":"aws-us-east-1","name":"AWS N. Virginia","country":"US","hosts":[]},{"code":"aws-af-south-1","name":"AWS Cape Town","country":"ZA","hosts":[]}]'::jsonb),
  ('ven_googlebigquery', 'Google BigQuery', 'cloud', ARRAY['bigquery.googleapis.com'], '[{"code":"africa-south1","name":"Johannesburg","country":"ZA","hosts":[]},{"code":"eu","name":"EU","country":"EU","hosts":[]},{"code":"us","name":"US","country":"US","hosts":[]}]'::jsonb),
  ('ven_amazonwebservices', 'Amazon Web Services', 'cloud', ARRAY['*.amazonaws.com'], '[{"code":"af-south-1-los-1","name":"Lagos Local Zone","country":"NG","hosts":[]},{"code":"af-south-1","name":"Cape Town","country":"ZA","hosts":[]},{"code":"eu-west-1","name":"Ireland","country":"IE","hosts":[]},{"code":"eu-central-1","name":"Frankfurt","country":"DE","hosts":[]},{"code":"us-east-1","name":"N. Virginia","country":"US","hosts":[]}]'::jsonb),
  ('ven_microsoftazure', 'Microsoft Azure', 'cloud', ARRAY['*.windows.net','*.azure.com'], '[{"code":"southafricanorth","name":"South Africa North","country":"ZA","hosts":[]},{"code":"westeurope","name":"West Europe","country":"NL","hosts":[]},{"code":"eastus","name":"East US","country":"US","hosts":[]}]'::jsonb),
  ('ven_googlecloud', 'Google Cloud', 'cloud', ARRAY['*.googleapis.com'], '[{"code":"africa-south1","name":"Johannesburg","country":"ZA","hosts":[]},{"code":"europe-west1","name":"Belgium","country":"BE","hosts":[]},{"code":"us-central1","name":"Iowa","country":"US","hosts":[]}]'::jsonb),
  ('ven_cloudflare', 'Cloudflare', 'cloud', ARRAY['*.cloudflare.com'], '[]'::jsonb),
  ('ven_layer3cloud', 'Layer3Cloud', 'cloud', ARRAY['*.layer3.cloud'], '[{"code":"lagos","name":"Lagos","country":"NG","hosts":[]},{"code":"abuja","name":"Abuja","country":"NG","hosts":[]}]'::jsonb),
  ('ven_nobuscloud', 'Nobus Cloud', 'cloud', ARRAY['*.nobus.io'], '[{"code":"lagos","name":"Lagos","country":"NG","hosts":[]}]'::jsonb),
  ('ven_galaxybackbone', 'Galaxy Backbone', 'cloud', ARRAY['*.galaxybackbone.com.ng'], '[{"code":"abuja","name":"Abuja","country":"NG","hosts":[]}]'::jsonb),
  ('ven_mtncloud', 'MTN Cloud', 'cloud', ARRAY['*.mtn.com'], '[{"code":"lagos","name":"Lagos","country":"NG","hosts":[]}]'::jsonb),
  ('ven_smileid', 'Smile ID', 'kyc', ARRAY['*.smileidentity.com','*.usesmileid.com'], '[]'::jsonb),
  ('ven_dojah', 'Dojah', 'kyc', ARRAY['*.dojah.io'], '[]'::jsonb),
  ('ven_prembly', 'Prembly', 'kyc', ARRAY['*.prembly.com','*.myidentitypass.com'], '[]'::jsonb),
  ('ven_youverify', 'Youverify', 'kyc', ARRAY['*.youverify.co'], '[]'::jsonb),
  ('ven_verifyme', 'VerifyMe', 'kyc', ARRAY['*.verifyme.ng'], '[]'::jsonb),
  ('ven_mono', 'Mono', 'kyc', ARRAY['*.withmono.com'], '[]'::jsonb),
  ('ven_paystack', 'Paystack', 'payments', ARRAY['*.paystack.co'], '[]'::jsonb),
  ('ven_flutterwave', 'Flutterwave', 'payments', ARRAY['*.flutterwave.com'], '[]'::jsonb),
  ('ven_termii', 'Termii', 'messaging', ARRAY['*.termii.com'], '[]'::jsonb),
  ('ven_twilio', 'Twilio', 'messaging', ARRAY['*.twilio.com'], '[{"code":"us","name":"US","country":"US","hosts":[]}]'::jsonb);
