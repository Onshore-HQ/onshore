-- Going global: each organisation records where it is, its sector, the laws it
-- has confirmed and the places its customers live; each vault records the
-- country its data stays in and the country packs that detect its data.

ALTER TABLE control.tenants
  ADD COLUMN home_country text CHECK (home_country ~ '^[A-Z]{2}$'),
  ADD COLUMN sector text CHECK (sector IN ('banking','insurance','health','telecoms','retail','other')),
  ADD COLUMN console_language text NOT NULL DEFAULT 'en' CHECK (console_language IN ('en','fr')),
  ADD COLUMN console_format text CHECK (console_format ~ '^[A-Z]{2}$'),
  ADD COLUMN laws text[] NOT NULL DEFAULT '{}',
  ADD COLUMN markets text[] NOT NULL DEFAULT '{}',
  -- Countries chosen at setup that need another install or a cloud region.
  ADD COLUMN planned_countries text[] NOT NULL DEFAULT '{}',
  ADD COLUMN setup_completed_at timestamptz;

-- Organisations that already exist have been set up for Nigeria.
UPDATE control.tenants SET home_country = COALESCE(home_country, hosting_country), console_format = COALESCE(console_format, hosting_country),
  laws = CASE WHEN hosting_country = 'NG' THEN ARRAY['ndpa'] ELSE laws END, setup_completed_at = COALESCE(setup_completed_at, created_at);

ALTER TABLE control.vaults
  ADD COLUMN country text NOT NULL DEFAULT 'NG' CHECK (country ~ '^[A-Z]{2}$'),
  ADD COLUMN packs text[] NOT NULL DEFAULT '{everywhere,ng}';

-- A vault's country is where its data lives. Changing it would misstate every
-- record already in it, so it is fixed once set.
CREATE FUNCTION control.vault_country_fixed() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.country IS DISTINCT FROM OLD.country THEN
    RAISE EXCEPTION 'a vault''s country cannot change' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER vault_country_fixed BEFORE UPDATE OF country ON control.vaults
  FOR EACH ROW EXECUTE FUNCTION control.vault_country_fixed();

GRANT UPDATE (home_country, sector, console_language, console_format, laws, markets, planned_countries, setup_completed_at, name) ON control.tenants TO rv_control;
