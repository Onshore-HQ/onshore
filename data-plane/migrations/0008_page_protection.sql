-- Page protection: which scripts run on the customer's sensitive pages.
CREATE TABLE control.protected_pages (
  id text PRIMARY KEY,
  tenant_id text NOT NULL REFERENCES control.tenants(id),
  name text NOT NULL,
  page_url text NOT NULL,
  origin text NOT NULL,
  report_key text NOT NULL UNIQUE,
  created_by text,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_report_at timestamptz,
  last_scan_at timestamptz,
  last_scan_error text,
  flood_alerted_at timestamptz
);
CREATE INDEX protected_pages_tenant ON control.protected_pages (tenant_id);

CREATE TABLE control.page_scripts (
  id text PRIMARY KEY,
  page_id text NOT NULL REFERENCES control.protected_pages(id) ON DELETE CASCADE,
  tenant_id text NOT NULL,
  script_url text NOT NULL,
  source text NOT NULL CHECK (source IN ('csp', 'watcher', 'scan')),
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected', 'changed')),
  justification text,
  decided_by text,
  decided_at timestamptz,
  first_seen timestamptz NOT NULL DEFAULT now(),
  last_seen timestamptz NOT NULL DEFAULT now(),
  seen_count bigint NOT NULL DEFAULT 1,
  content_hash text,
  hash_checked_at timestamptz,
  hash_changed_at timestamptz,
  hash_error text,
  notified_at timestamptz,
  UNIQUE (page_id, script_url)
);
CREATE INDEX page_scripts_recent ON control.page_scripts (page_id, first_seen);

GRANT SELECT, INSERT, UPDATE, DELETE ON control.protected_pages, control.page_scripts TO rv_control;
