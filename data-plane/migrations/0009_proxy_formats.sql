-- The HTTP proxy reads forms, XML, multipart and files, and applies rules to headers.
ALTER TABLE control.proxy_routes
  ADD COLUMN redact_headers jsonb NOT NULL DEFAULT '[]',
  ADD COLUMN unredact_headers jsonb NOT NULL DEFAULT '[]',
  ADD COLUMN response_redact_headers jsonb NOT NULL DEFAULT '[]',
  ADD COLUMN response_unredact_headers jsonb NOT NULL DEFAULT '[]',
  ADD COLUMN dlp_excluded_headers text[] NOT NULL DEFAULT '{}',
  ADD COLUMN dlp_excluded_params text[] NOT NULL DEFAULT '{}',
  ADD COLUMN file_policy text NOT NULL DEFAULT 'refuse' CHECK (file_policy IN ('refuse', 'redact', 'pass'));
