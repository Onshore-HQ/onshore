-- The AI gateway is community edition. Each AI route keeps its own cloak settings
-- (how each kind of data is hidden), so it needs no shared profile, which stays a
-- Business feature. A route on a profile uses the profile's settings.

ALTER TABLE control.ai_routes
  ADD COLUMN cloak_options jsonb NOT NULL DEFAULT '{}'::jsonb
  CHECK (jsonb_typeof(cloak_options) = 'object');
