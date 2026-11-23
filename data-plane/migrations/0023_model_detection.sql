-- Language-model detection (spaCy, transformers or Stanza) on top of the patterns,
-- checksums and name lists: the modules of each vault where it runs. Empty means off.
-- A paid feature: the setting is ignored on a Community install, except sandbox vaults.

ALTER TABLE control.vaults
  ADD COLUMN model_modules text[] NOT NULL DEFAULT '{}'
  CHECK (model_modules <@ ARRAY['ai','api','logs','proxy']::text[]);
