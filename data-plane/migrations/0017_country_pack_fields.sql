-- Vault fields can hold the identifiers the country packs find, so detected values
-- outside Nigeria can be tokenised rather than only masked.
ALTER TABLE control.vault_fields DROP CONSTRAINT vault_fields_data_type_check;
ALTER TABLE control.vault_fields ADD CONSTRAINT vault_fields_data_type_check CHECK (data_type IN (
  'bvn','nin','vnin','ng_11_digit_id','nuban','phone_ng','email','person_name','amount_ngn','payment_ref','address','date','free_text','custom',
  'ghana_card','ke_national_id','ke_kra_pin','za_id','eg_national_id','emirates_id','sa_national_id','qa_id',
  'uk_nino','uk_nhs','uk_bank_account','iban','eu_vat','de_tax_id','fr_nir','us_ssn','us_itin','us_routing',
  'ca_sin','br_cpf','in_aadhaar','in_pan','sg_nric','phone'));
