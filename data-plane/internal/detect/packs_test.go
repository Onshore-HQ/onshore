package detect

import (
	"strings"
	"testing"
)

func scanPack(pack, text string) []Entity { return New(Config{}).ScanPacks(text, []string{pack}) }

func typeList(es []Entity) string {
	var s []string
	for _, e := range es {
		s = append(s, string(e.Type))
	}
	return strings.Join(s, ",")
}

func TestPacksFind(t *testing.T) {
	cases := []struct{ pack, text, want string }{
		{"gh", "Ghana Card GHA-123456789-1 and MoMo 024 123 4567", "ghana_card,phone"},
		{"gh", "call +233 24 123 4567", "phone"},
		{"ke", "KRA PIN A123456789Z, national ID 12345678, M-Pesa 0712 345 678", "ke_kra_pin,ke_national_id,phone"},
		{"za", "ID number 8001015009087", "za_id"},
		{"eg", "الرقم القومي 29001011234567", "eg_national_id"},
		{"ae", "Emirates ID 784-1990-1234567-6 IBAN AE07 0331 2345 6789 0123 456", "emirates_id,iban"},
		{"sa", "Iqama 2012345670 and IBAN SA03 8000 0000 6080 1016 7519", "sa_national_id,iban"},
		{"qa", "QID 28763412345, phone +974 5512 3456", "qa_id,phone"},
		{"gb", "NI number AB 12 34 56 C, NHS number 943 476 5919, sort code 12-34-56 12345678", "uk_nino,uk_nhs,uk_bank_account"},
		{"gb", "IBAN GB82 WEST 1234 5698 7654 32 mobile 07700 900123", "iban,phone"},
		{"eu", "IBAN DE89 3704 0044 0532 0130 00, VAT DE123456789", "iban,eu_vat"},
		{"eu", "Steuer-ID 36 574 261 809", "de_tax_id"},
		{"eu", "numéro de sécurité sociale 2 95 10 99 126 111 93", "fr_nir"},
		{"us", "SSN 078-05-1120, routing number 021000021", "us_ssn,us_routing"},
		{"us", "ITIN 912-70-1234", "us_itin"},
		{"ca", "SIN 046 454 286", "ca_sin"},
		{"br", "CPF 123.456.789-09", "br_cpf"},
		{"in", "Aadhaar 2345 6789 0124 and PAN ABCPE1234F", "in_aadhaar,in_pan"},
		{"sg", "NRIC S1234567D", "sg_nric"},
	}
	for _, c := range cases {
		if got := typeList(scanPack(c.pack, c.text)); got != c.want {
			t.Errorf("%s %q: got %q, want %q", c.pack, c.text, got, c.want)
		}
	}
}

func TestPacksRefuse(t *testing.T) {
	cases := []struct{ pack, text string }{
		{"za", "ID number 8001015009088"},              // bad Luhn
		{"ae", "Emirates ID 784-1990-1234567-9"},       // bad Luhn
		{"gb", "NHS number 943 476 5918"},              // bad mod 11
		{"gb", "NI number GB 12 34 56 C"},              // never issued
		{"gb", "NI number QQ 12 34 56 C"},              // HMRC's example prefix, never issued
		{"eu", "IBAN DE89 3704 0044 0532 0130 01"},     // bad mod 97
		{"eu", "Steuer-ID 36 574 261 808"},             // bad check
		{"us", "SSN 666-12-3456"},                      // never issued
		{"us", "order 021000021"},                      // routing shape, no cue
		{"br", "CPF 123.456.789-00"},                   // bad check digits
		{"in", "Aadhaar 2345 6789 0123"},               // bad Verhoeff
		{"sg", "NRIC S1234567A"},                       // bad check letter
		{"ke", "invoice 12345678"},                     // 8 digits, no cue
		{"qa", "order 28763412345"},                    // 11 digits, no cue
		{"sa", "ref 2012345670"},                       // 10 digits, no cue
	}
	for _, c := range cases {
		if got := scanPack(c.pack, c.text); len(got) != 0 {
			t.Errorf("%s %q: want nothing, got %v", c.pack, c.text, got)
		}
	}
}

func TestPackOnlyForItsVault(t *testing.T) {
	text := "SSN 078-05-1120 and BVN 22123456789"
	ng := BaseRuleSet(New(Config{})).WithPacks("NG", []string{"everywhere", "ng"}).ScanFor("ai", "", text, "")
	us := BaseRuleSet(New(Config{})).WithPacks("US", []string{"everywhere", "us"}).ScanFor("ai", "", text, "")
	legacy := BaseRuleSet(New(Config{})).ScanFor("ai", "", text, "")
	if typeList(ng) != "bvn" || typeList(legacy) != "bvn" {
		t.Fatalf("Nigerian and legacy vaults must not run other packs: ng=%v legacy=%v", ng, legacy)
	}
	if typeList(us) != "us_ssn" {
		t.Fatalf("a US vault finds SSNs, not BVNs: %v", us)
	}
}

func TestValidatePackValue(t *testing.T) {
	for _, c := range []struct {
		t    EntityType
		in   string
		want string
		ok   bool
	}{
		{IBAN, "de89 3704 0044 0532 0130 00", "DE89370400440532013000", true},
		{UKNHS, "943-476-5919", "9434765919", true},
		{BrazilCPF, "123.456.789-09", "12345678909", true},
		{BrazilCPF, "123.456.789-00", "12345678900", false},
		{PhoneIntl, "+44 7700 900123", "+447700900123", true},
	} {
		got, ok := ValidatePackValue(c.t, c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("%s %q: got %q %v", c.t, c.in, got, c.ok)
		}
	}
}

// The examples shown in setup and Settings (control-api/src/catalog.ts), each with
// the words a real message would carry. Every one must be found by its own pack.
func TestCatalogExamplesAreFound(t *testing.T) {
	for _, c := range []struct{ pack, text string }{
		{"gh", "Ghana Card GHA-123456789-1"}, {"gh", "phone 024 123 4567"},
		{"ke", "KRA PIN A123456789Z"}, {"ke", "national ID 12345678"}, {"ke", "M-Pesa 0712 345 678"},
		{"za", "ID 8001015009087"}, {"za", "mobile 082 123 4567"},
		{"eg", "national ID 29001011234567"}, {"eg", "mobile +20 100 123 4567"},
		{"ae", "Emirates ID 784-1990-1234567-6"}, {"ae", "IBAN AE07 0331 2345 6789 0123 456"}, {"ae", "mobile 050 123 4567"},
		{"sa", "national ID 1012345672"}, {"sa", "Iqama 2012345670"}, {"sa", "IBAN SA03 8000 0000 6080 1016 7519"}, {"sa", "mobile 050 123 4567"},
		{"qa", "QID 28763412345"}, {"qa", "IBAN QA58 DOHB 0000 1234 5678 90AB CDEF G"}, {"qa", "mobile +974 5512 3456"},
		{"gb", "NI AB 12 34 56 C"}, {"gb", "NHS 943 476 5919"}, {"gb", "sort code 12-34-56 12345678"}, {"gb", "IBAN GB82 WEST 1234 5698 7654 32"}, {"gb", "mobile 07700 900123"},
		{"eu", "IBAN DE89 3704 0044 0532 0130 00"}, {"eu", "VAT DE123456789"}, {"eu", "tax ID 36 574 261 809"}, {"eu", "NIR 2 95 10 99 126 111 93"}, {"eu", "phone +49 30 1234 5678"},
		{"us", "SSN 123-45-6789"}, {"us", "ITIN 912-70-1234"}, {"us", "routing 021000021"}, {"us", "phone +1 212 555 0100"},
		{"ca", "SIN 046 454 286"}, {"ca", "phone +1 416 555 0100"},
		{"br", "CPF 123.456.789-09"}, {"br", "celular +55 11 91234 5678"},
		{"in", "Aadhaar 2345 6789 0124"}, {"in", "PAN ABCPE1234F"}, {"in", "mobile +91 98765 43210"},
		{"sg", "NRIC S1234567D"}, {"sg", "mobile +65 9123 4567"},
	} {
		if got := scanPack(c.pack, c.text); len(got) != 1 {
			t.Errorf("%s %q: got %v", c.pack, c.text, got)
		}
	}
}

func TestAmountsInAnyCurrency(t *testing.T) {
	for _, text := range []string{"refund of $8,500.00", "paid €1.250,50 today", "balance £12,000", "fee 4,500 AED", "salary KSh 85,000", "cost R$ 1.200,00", "₹45,000 transfer", "USD 2.5m deal", "250 euros"} {
		if got := typeList(scanPack("everywhere", text)); got != "amount" {
			t.Errorf("%q: got %q", text, got)
		}
	}
	if got := scanPack("everywhere", "paid ₦850,000"); len(got) != 0 {
		t.Errorf("naira belongs to Nigeria's pack: %v", got)
	}
}

func TestPhonesIncludingLandlines(t *testing.T) {
	cases := []struct{ pack, text string }{
		{"everywhere", "call +44 20 7946 0958"}, {"everywhere", "WhatsApp +971 4 123 4567"}, {"everywhere", "tel +49 30 12345678"},
		{"gb", "office phone 020 7946 0958"}, {"gb", "call 0161 496 0000"},
		{"ke", "office phone 020 123 4567"}, {"za", "call 011 123 4567"}, {"ae", "office tel 04 123 4567"},
		{"sa", "phone 011 234 5678"}, {"qa", "office phone 4412 3456"}, {"eg", "call 02 2345 6789"},
		{"in", "landline 022 26543210"}, {"sg", "call 6123 4567"}, {"br", "telefone (11) 3456-7890"},
		{"eu", "Telefon 030 12345678"}, {"ng", "office line 01 234 5678"},
	}
	for _, c := range cases {
		if got := scanPack(c.pack, c.text); len(got) != 1 {
			t.Errorf("%s %q: got %v", c.pack, c.text, got)
		}
	}
	// National landline shapes need a phone word nearby.
	for _, c := range []struct{ pack, text string }{{"gb", "ref 020 7946 0958"}, {"qa", "order 4412 3456"}, {"sg", "invoice 6123 4567"}} {
		if got := scanPack(c.pack, c.text); len(got) != 0 {
			t.Errorf("%s %q: want nothing, got %v", c.pack, c.text, got)
		}
	}
}

func TestNamesFromEveryRegion(t *testing.T) {
	e := New(Config{})
	for _, text := range []string{"Customer Sarah Johnson called", "Kunde Lukas Müller hat angerufen", "client Pierre Dubois", "customer Fatima Al Harbi", "customer Priya Sharma", "Kofi Mensah paid", "Wanjiru Kamau wrote", "Thabo Nkosi wrote", "cliente João Santos"} {
		found := false
		for _, x := range e.Scan(text) {
			found = found || x.Type == PersonName
		}
		if !found {
			t.Errorf("%q: no name found in %v", text, e.Scan(text))
		}
	}
	// Everyday words that are also names are not names on their own.
	for _, text := range []string{"I will mark the rose", "The King hotel", "Price list for May"} {
		for _, x := range e.Scan(text) {
			if x.Type == PersonName {
				t.Errorf("%q: %q is not a name", text, text[x.Start:x.End])
			}
		}
	}
}

func TestStructureChecksWithoutPublishedCheckDigits(t *testing.T) {
	if !ValidQatarID("28763412345") || ValidQatarID("28799912345") || ValidQatarID("19963412345") {
		t.Fatal("Qatar ID: century, birth year and ISO nationality code")
	}
	if ValidEgyptID("39901011234567") { // born in 2099
		t.Fatal("Egyptian ID: a future birth date is refused")
	}
	if got := typeList(scanPack("gh", "Ghana Card NGA-123456789-1")); got != "ghana_card" {
		t.Fatalf("non-citizen Ghana Card: %q", got)
	}
	if got := scanPack("gh", "ref XYZ-123456789-1"); len(got) != 0 {
		t.Fatalf("not an ISO code: %v", got)
	}
}

func TestGlobalRuleSetAssumesNoCountry(t *testing.T) {
	rs := GlobalRuleSet(New(Config{}))
	text := "SSN 123-45-6789, IBAN DE89 3704 0044 0532 0130 00, BVN 22123456789, NHS number 943 476 5919"
	if got := typeList(rs.ScanFor("ai", "", text, "")); got != "us_ssn,iban,bvn,uk_nhs" {
		t.Fatalf("got %q", got)
	}
}

// Sandbox values must pass the same checks the detectors and vault fields apply.
func TestSamplesPassTheirOwnChecks(t *testing.T) {
	for _, country := range []string{"US", "GB", "DE", "AE", "IN", "BR", "SG", "ZA", "NG", "KE"} {
		s := NewSamples(42, country)
		for _, dt := range []string{"ghana_card", "ke_kra_pin", "uk_bank_account", "za_id", "eg_national_id", "emirates_id", "sa_national_id", "qa_id", "uk_nino", "uk_nhs", "iban", "de_tax_id", "fr_nir", "us_ssn", "us_routing", "ca_sin", "br_cpf", "in_aadhaar", "in_pan", "sg_nric", "phone"} {
			for i := 0; i < 20; i++ {
				v := s.Value(dt)
				if _, ok := ValidatePackValue(EntityType(dt), v); !ok {
					t.Fatalf("%s %s: %q does not validate", country, dt, v)
				}
			}
		}
		if n := s.Value("person_name"); !strings.Contains(n, " ") {
			t.Fatalf("%s name %q", country, n)
		}
	}
	if !strings.HasPrefix(NewSamples(1, "GB").Value("amount"), "£") || !strings.HasPrefix(NewSamples(1, "DE").Value("amount"), "€") {
		t.Fatal("amounts follow the country's currency")
	}
}
