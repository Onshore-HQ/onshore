-- Flow checks: a job Onshore cannot sit in front of sends each batch to be checked before it
-- leaves, and those counts are the flow's evidence. Plus marks for a demo tenant's seeded history.
ALTER TABLE control.tenants ADD COLUMN demo_mode boolean NOT NULL DEFAULT false;
ALTER TABLE events.detection_events ADD COLUMN seeded boolean NOT NULL DEFAULT false;
ALTER TABLE control.map_scores_daily ADD COLUMN seeded boolean NOT NULL DEFAULT false;
GRANT SELECT (id, vault_id, dest_host, retired_at) ON control.data_flows TO rv_vault;
INSERT INTO control.roles(id, tenant_id, name)
  SELECT t.id || ':' || r, t.id, r FROM control.tenants t, unnest(ARRAY['ops_lead','contractor']) r
  ON CONFLICT DO NOTHING;
