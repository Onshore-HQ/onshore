package vault

import (
	"regexp"
	"strings"
	"unicode/utf8"

	"onshore/data-plane/internal/detect"
)

var emailShape = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)

func onlyDigits(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

func stripSeparators(s string) string {
	return strings.NewReplacer(" ", "", "-", "").Replace(s)
}

// Normalize returns the canonical form of a value and validates its format.
// ok=false maps to 422 validation_failed. Error text never echoes the value.
func Normalize(dataType, v string) (string, bool) {
	if !utf8.ValidString(v) || v == "" || len(v) > 64*1024 {
		return "", false
	}
	switch dataType {
	case "bvn", "nin", "ng_11_digit_id":
		n := stripSeparators(v)
		return n, len(n) == 11 && onlyDigits(n) == n
	case "nuban":
		n := stripSeparators(v)
		return n, len(n) == 10 && onlyDigits(n) == n
	case "phone_ng":
		n := strings.NewReplacer(" ", "", "-", "", "(", "", ")", "").Replace(v)
		switch {
		case strings.HasPrefix(n, "+234"):
			n = n[4:]
		case strings.HasPrefix(n, "234") && len(n) == 13:
			n = n[3:]
		case strings.HasPrefix(n, "0") && len(n) == 11:
			n = n[1:]
		}
		n = strings.TrimPrefix(n, "0") // +234(0)803...
		return "+234" + n, len(n) == 10 && onlyDigits(n) == n
	case "email":
		n := strings.ToLower(strings.TrimSpace(v))
		return n, emailShape.MatchString(n)
	case "person_name":
		n := strings.ToLower(strings.Join(strings.Fields(v), " "))
		return n, n != ""
	case "amount_ngn":
		n := strings.NewReplacer("₦", "", "NGN", "", "ngn", "", ",", "", " ", "").Replace(v)
		return n, n != ""
	case "amount":
		n := strings.Join(strings.Fields(v), " ")
		return n, n != "" && strings.ContainsAny(n, "0123456789")
	case "date", "address":
		n := strings.Join(strings.Fields(v), " ")
		return n, n != ""
	case "ghana_card", "ke_national_id", "ke_kra_pin", "za_id", "eg_national_id", "emirates_id", "sa_national_id", "qa_id",
		"uk_nino", "uk_nhs", "uk_bank_account", "iban", "eu_vat", "de_tax_id", "fr_nir", "us_ssn", "us_itin", "us_routing",
		"ca_sin", "br_cpf", "in_aadhaar", "in_pan", "sg_nric", "phone":
		return detect.ValidatePackValue(detect.EntityType(dataType), v)
	case "free_text":
		// Full card numbers must not enter the vault; that would pull in PCI DSS.
		for _, e := range cardCheck.Scan(v) {
			if e.Type == detect.CardPAN {
				return "", false
			}
		}
		return v, true
	}
	return "", false
}

var cardCheck = detect.New(detect.Config{})
