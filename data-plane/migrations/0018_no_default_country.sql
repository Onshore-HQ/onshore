-- No country is assumed. A vault names its country; a new vault starts with only
-- the "everywhere" pack until its country's pack is added; an install records its
-- country when it is installed or set up. Existing rows keep what they have.
ALTER TABLE control.vaults ALTER COLUMN country DROP DEFAULT;
ALTER TABLE control.vaults ALTER COLUMN packs SET DEFAULT '{everywhere}';
ALTER TABLE control.tenants ALTER COLUMN hosting_country DROP DEFAULT;
ALTER TABLE control.tenants ALTER COLUMN hosting_country DROP NOT NULL;
ALTER TABLE control.tenants ADD CONSTRAINT tenants_hosting_country_code CHECK (hosting_country IS NULL OR hosting_country ~ '^[A-Z]{2}$');

-- Amounts in any currency can be stored in a vault field.
ALTER TABLE control.vault_fields DROP CONSTRAINT vault_fields_data_type_check;
ALTER TABLE control.vault_fields ADD CONSTRAINT vault_fields_data_type_check CHECK (data_type IN (
  'bvn','nin','vnin','ng_11_digit_id','nuban','phone_ng','email','person_name','amount_ngn','amount','payment_ref','address','date','free_text','custom',
  'ghana_card','ke_national_id','ke_kra_pin','za_id','eg_national_id','emirates_id','sa_national_id','qa_id',
  'uk_nino','uk_nhs','uk_bank_account','iban','eu_vat','de_tax_id','fr_nir','us_ssn','us_itin','us_routing',
  'ca_sin','br_cpf','in_aadhaar','in_pan','sg_nric','phone'));
