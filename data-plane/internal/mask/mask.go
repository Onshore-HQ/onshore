// Package mask renders the default masked form per data type.
package mask

import (
	"strconv"
	"strings"
	"unicode/utf8"
)

func lastN(s string, n int) string {
	if len(s) <= n {
		return strings.Repeat("*", len(s))
	}
	return strings.Repeat("*", len(s)-n) + s[len(s)-n:]
}

func keepFirst(word string, n int) string {
	if utf8.RuneCountInString(word) <= n {
		return strings.Repeat("*", utf8.RuneCountInString(word))
	}
	r := []rune(word)
	return string(r[:n]) + strings.Repeat("*", len(r)-n)
}

// Value masks a normalised value. rule "full" hides everything; "default" and
// "last4" use the per-type form from the spec.
func Value(dataType, rule, v string) string {
	if rule == "full" {
		return "********"
	}
	if strings.HasPrefix(dataType, "c_") {
		return customValue(rule, v)
	}
	if packTypes[dataType] {
		return lastN(alnum(v), 4)
	}
	switch dataType {
	case "bvn", "nin", "ng_11_digit_id", "nuban":
		return lastN(digits(v), 4)
	case "card_pan":
		return lastN(digits(v), 4)
	case "phone_ng":
		d := digits(v)
		if len(d) < 4 {
			return "+234 *** *** ****"
		}
		return "+234 *** *** " + d[len(d)-4:]
	case "person_name":
		parts := strings.Fields(v)
		for i, p := range parts {
			n := 1
			if i == 0 {
				n = 2
			}
			parts[i] = keepFirst(p, n)
		}
		return strings.Join(parts, " ")
	case "email":
		at := strings.LastIndexByte(v, '@')
		if at < 0 {
			return "********"
		}
		return keepFirst(v[:at], 2) + v[at:]
	case "amount_ngn":
		return "₦**,***"
	case "amount":
		return "**,***"
	case "date":
		return "**/**/****"
	}
	return "********"
}

func digits(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// customValue applies a custom entity's rule: last_n:N, first_n:N or fixed:TEXT. A rule
// that cannot be read shows the last 4, and a value no longer than N is fully masked.
func customValue(rule, v string) string {
	kind, arg, _ := strings.Cut(rule, ":")
	n := 4
	if d, err := strconv.Atoi(arg); err == nil && d >= 0 {
		n = d
	}
	r := []rune(v)
	switch kind {
	case "fixed":
		return arg
	case "first_n":
		if n >= len(r) {
			return strings.Repeat("*", len(r))
		}
		return string(r[:n]) + strings.Repeat("*", len(r)-n)
	}
	if n >= len(r) {
		return strings.Repeat("*", len(r))
	}
	return strings.Repeat("*", len(r)-n) + string(r[len(r)-n:])
}

// packTypes are the country packs' identifiers beyond Nigeria; each masks to its last four characters.
var packTypes = map[string]bool{
	"ghana_card": true, "ke_national_id": true, "ke_kra_pin": true, "za_id": true, "eg_national_id": true, "emirates_id": true,
	"sa_national_id": true, "qa_id": true, "uk_nino": true, "uk_nhs": true, "uk_bank_account": true, "iban": true, "eu_vat": true,
	"de_tax_id": true, "fr_nir": true, "us_ssn": true, "us_itin": true, "us_routing": true, "ca_sin": true, "br_cpf": true,
	"in_aadhaar": true, "in_pan": true, "sg_nric": true, "phone": true,
}

func alnum(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' {
			b.WriteRune(r)
		}
	}
	return strings.ToUpper(b.String())
}
