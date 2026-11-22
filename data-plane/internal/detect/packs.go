package detect

import (
	"math/big"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Country packs beyond Nigeria. Each pack is a list of rules: a pattern, a check
// where the issuer publishes one, and the words that make a match believable.
// A rule with no check needs one of its words nearby, since a bare number of the
// right length is too common to flag on shape alone.
//
// Packs only run for vaults that switch them on (RuleSet.WithPacks), so a
// Nigerian vault's detection is exactly what it was before packs existed.

// Entity types from the country packs.
const (
	GhanaCard     EntityType = "ghana_card"
	KenyaID       EntityType = "ke_national_id"
	KenyaKRAPIN   EntityType = "ke_kra_pin"
	SouthAfricaID EntityType = "za_id"
	EgyptID       EntityType = "eg_national_id"
	EmiratesID    EntityType = "emirates_id"
	SaudiID       EntityType = "sa_national_id"
	QatarID       EntityType = "qa_id"
	UKNINO        EntityType = "uk_nino"
	UKNHS         EntityType = "uk_nhs"
	UKBankAccount EntityType = "uk_bank_account"
	IBAN          EntityType = "iban"
	EUVAT         EntityType = "eu_vat"
	GermanTaxID   EntityType = "de_tax_id"
	FrenchNIR     EntityType = "fr_nir"
	USSSN         EntityType = "us_ssn"
	USITIN        EntityType = "us_itin"
	USRouting     EntityType = "us_routing"
	CanadaSIN     EntityType = "ca_sin"
	BrazilCPF     EntityType = "br_cpf"
	IndiaAadhaar  EntityType = "in_aadhaar"
	IndiaPAN      EntityType = "in_pan"
	SingaporeNRIC EntityType = "sg_nric"
	PhoneIntl     EntityType = "phone"
	// AmountMoney is an amount in any currency but naira, which Nigeria's pack reads as amount_ngn.
	AmountMoney EntityType = "amount"
)

type packRule struct {
	t     EntityType
	re    *regexp.Regexp
	valid func(raw string) bool
	// base is the score on shape and check alone; 0 means it needs a cue word.
	base, cued float64
	cues       []string
}

var (
	idCues    = []string{"id", "identity", "identification", "national", "card", "number", "no.", "no:", "nr"}
	phoneCues = []string{"phone", "mobile", "tel", "call", "whatsapp", "number", "cell", "sms"}
	taxCues   = []string{"tax", "tin", "steuer", "idnr", "identifikationsnummer"}
	acctCues  = []string{"account", "acct", "bank", "iban", "pay", "transfer", "sort code"}
	vatCues   = []string{"vat", "tva", "ust", "btw", "iva", "mwst", "moms", "alv", "nip"}
)

func rx(s string) *regexp.Regexp { return regexp.MustCompile(s) }

var ibanRule = packRule{IBAN, rx(`\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?\b`), ValidIBAN, 0.95, 0.99, acctCues}

// currencyRe reads an amount with a currency symbol or code before or after it.
// Naira is left to Nigeria's pack, whose rules know "N250,000" and "50k naira".
const currencyBefore = `(?:US\$|C\$|CA\$|A\$|S\$|SG\$|R\$|GH₵|GH¢|KSh|E£|\$|€|£|₹|₵|﷼|(?:USD|EUR|GBP|CAD|AUD|SGD|BRL|INR|GHS|KES|ZAR|EGP|AED|SAR|QAR|CHF|JPY|CNY)\b)`
const currencyAfter = `(?:€|USD|EUR|GBP|CAD|AUD|SGD|BRL|INR|GHS|KES|ZAR|EGP|AED|SAR|QAR|CHF|dollars?|euros?|pounds?|dirhams?|riyals?|rands?|rupees?|reais|shillings?|cedis?)`
const amountNumber = `\d{1,3}(?:[,. \x{00A0}]\d{3})*(?:[.,]\d{1,2})?|\d+(?:[.,]\d{1,2})?`

var amountRule = packRule{AmountMoney, rx(`(?i)` + currencyBefore + `\s?(?:` + amountNumber + `)(?:\s?(?:k|m|bn|million|billion|thousand)\b)?|\b(?:` + amountNumber + `)\s?` + currencyAfter + `\b`), nil, 0.85, 0.95, []string{"paid", "pay", "amount", "balance", "transfer", "debited", "credited", "salary", "price", "cost", "fee", "refund", "owe"}}

// E.164: a plus, a country code and the rest. Any country, so it sits in "everywhere".
var intlPhoneRule = packRule{PhoneIntl, rx(`\+[1-9]\d{0,2}[ -]?\(?\d{1,4}\)?(?:[ -]?\d){5,11}\b`), func(r string) bool { n := digitsOnly(r); return len(n) >= 8 && len(n) <= 15 }, 0.75, 0.95, phoneCues}

// PackRules are each pack's rules, beside the engine's built-in Nigerian and
// "everywhere" detectors.
var PackRules = map[string][]packRule{
	"everywhere": {amountRule, intlPhoneRule},
	// Nigerian landlines: Lagos 01, Abuja 09 and the state codes, which the mobile detector skips.
	"ng": {
		{PhoneNG, rx(`(?:\+234[ -]?(?:\(0\))?|\b0)(?:1|9|[2-8]\d)[ -]?\d{3}[ -]?\d{3,4}\b`), func(r string) bool {
			n := strings.TrimPrefix(digitsOnly(r), "234")
			return len(n) >= 7 && len(n) <= 11 && !strings.HasPrefix(strings.TrimPrefix(n, "0"), "7") && !strings.HasPrefix(strings.TrimPrefix(n, "0"), "8")
		}, 0, 0.9, append([]string{"landline", "office", "line"}, phoneCues...)},
	},
	"gh": {
		{PhoneIntl, rx(`\b03\d[ -]?\d{3}[ -]?\d{4}\b`), nil, 0, 0.9, append([]string{"landline", "office"}, phoneCues...)},
		{GhanaCard, rx(`\bGHA-?\d{9}-?\d\b`), nil, 0.95, 0.99, idCues},
		// Non-citizens' cards carry their nationality's ISO code instead of GHA.
		{GhanaCard, rx(`\b[A-Z]{3}-\d{9}-\d\b`), func(r string) bool { return isoAlpha3[r[:3]] }, 0, 0.93, []string{"ghana card", "ghanacard", "nia", "card", "pin", "non-citizen"}},
		{PhoneIntl, rx(`(?:\+233[ -]?|\b0)(?:2[03-8]|5[0-79])(?:[ -]?\d){7}\b`), nil, 0.75, 0.95, phoneCues},
	},
	"ke": {
		{PhoneIntl, rx(`\b0(?:20|4[0-9]|5[0-9]|6[0-9])[ -]?\d{3}[ -]?\d{3,4}\b`), nil, 0, 0.9, append([]string{"landline", "office"}, phoneCues...)},
		{KenyaKRAPIN, rx(`\b[AP]\d{9}[A-Z]\b`), nil, 0.9, 0.98, append([]string{"kra", "pin"}, taxCues...)},
		{KenyaID, rx(`\b\d{7,8}\b`), nil, 0, 0.85, []string{"national id", "id no", "id number", "id:", "kitambulisho", "huduma"}},
		{PhoneIntl, rx(`(?:\+254[ -]?|\b0)(?:7\d|1[01])\d(?:[ -]?\d){6}\b`), nil, 0.75, 0.95, append([]string{"m-pesa", "mpesa"}, phoneCues...)},
	},
	"za": {
		{PhoneIntl, rx(`\b0[1-5]\d[ -]?\d{3}[ -]?\d{4}\b`), nil, 0, 0.9, append([]string{"landline", "office"}, phoneCues...)},
		{SouthAfricaID, rx(`\b\d{13}\b`), ValidSouthAfricaID, 0.85, 0.97, idCues},
		{PhoneIntl, rx(`(?:\+27[ -]?|\b0)[6-8]\d(?:[ -]?\d){7}\b`), nil, 0.7, 0.95, phoneCues},
	},
	"eg": {
		{PhoneIntl, rx(`\b0(?:2|3|[4-9]\d)[ -]?\d{3,4}[ -]?\d{4}\b`), nil, 0, 0.9, append([]string{"landline", "office", "هاتف"}, phoneCues...)},
		{EgyptID, rx(`\b[23]\d{13}\b`), ValidEgyptID, 0.85, 0.97, append([]string{"رقم قومي", "national"}, idCues...)},
		{PhoneIntl, rx(`(?:\+20[ -]?|\b0)1[0125](?:[ -]?\d){8}\b`), nil, 0.75, 0.95, phoneCues},
	},
	"ae": {
		{PhoneIntl, rx(`\b0[2-79][ -]?\d{3}[ -]?\d{4}\b`), nil, 0, 0.9, append([]string{"landline", "office"}, phoneCues...)},
		{EmiratesID, rx(`\b784-?\d{4}-?\d{7}-?\d\b`), func(r string) bool { return ValidLuhn(digitsOnly(r)) }, 0.95, 0.99, append([]string{"emirates id", "eid"}, idCues...)},
		ibanRule,
		{PhoneIntl, rx(`(?:\+971[ -]?|\b0)5[024568](?:[ -]?\d){7}\b`), nil, 0.75, 0.95, phoneCues},
	},
	"sa": {
		{PhoneIntl, rx(`\b01[1-7][ -]?\d{3}[ -]?\d{4}\b`), nil, 0, 0.9, append([]string{"landline", "office"}, phoneCues...)},
		{SaudiID, rx(`\b[12]\d{9}\b`), func(r string) bool { return ValidLuhn(r) }, 0, 0.9, append([]string{"iqama", "هوية", "اقامة", "إقامة"}, idCues...)},
		ibanRule,
		{PhoneIntl, rx(`(?:\+966[ -]?|\b0)5\d(?:[ -]?\d){7}\b`), nil, 0.75, 0.95, phoneCues},
	},
	"qa": {
		{PhoneIntl, rx(`\b[34567]\d{3}[ -]?\d{4}\b`), nil, 0, 0.88, append([]string{"landline", "office"}, phoneCues...)},
		{QatarID, rx(`\b[23]\d{10}\b`), ValidQatarID, 0, 0.92, append([]string{"qid", "qatar id"}, idCues...)},
		ibanRule,
		{PhoneIntl, rx(`\+974[ -]?[3567]\d{3}[ -]?\d{4}\b`), nil, 0.85, 0.95, phoneCues},
	},
	"gb": {
		{PhoneIntl, rx(`\b0(?:1\d{2,4}|2\d|3\d{2})[ -]?\d{3,4}[ -]?\d{3,4}\b`), func(r string) bool { n := digitsOnly(r); return len(n) == 10 || len(n) == 11 }, 0, 0.92, append([]string{"landline", "office"}, phoneCues...)},
		{UKNINO, rx(`\b[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z] ?\d{2} ?\d{2} ?\d{2} ?[A-D]\b`), ValidNINO, 0.85, 0.97, []string{"national insurance", "nino", "ni number", "ni no"}},
		{UKNHS, rx(`\b\d{3}[ -]?\d{3}[ -]?\d{4}\b`), ValidNHS, 0, 0.95, []string{"nhs", "health", "patient"}},
		{UKBankAccount, rx(`\b\d{2}-\d{2}-\d{2}[ ,/]+\d{8}\b`), nil, 0.85, 0.97, acctCues},
		ibanRule,
		{PhoneIntl, rx(`(?:\+44[ -]?7|\b07)\d{3}[ -]?\d{3}[ -]?\d{3}\b`), nil, 0.75, 0.95, phoneCues},
	},
	"eu": {
		{PhoneIntl, rx(`\b0\d{1,4}[ /-]?\d{3,4}[ -]?\d{2,5}\b`), func(r string) bool { n := digitsOnly(r); return len(n) >= 9 && len(n) <= 12 }, 0, 0.88, append([]string{"telefon", "téléphone", "telefono", "teléfono", "tel.", "landline"}, phoneCues...)},
		ibanRule,
		{EUVAT, rx(`\b(?:DE\d{9}|FR[0-9A-HJ-NP-Z]{2}\d{9}|NL\d{9}B\d{2}|IE\d{7}[A-W][A-IW]?|BE[01]\d{9}|ES[A-Z0-9]\d{7}[A-Z0-9]|IT\d{11}|ATU\d{8}|PL\d{10}|SE\d{12}|PT\d{9}|DK\d{8}|FI\d{8}|LU\d{8})\b`), nil, 0.7, 0.97, vatCues},
		{GermanTaxID, rx(`\b\d{2} ?\d{3} ?\d{3} ?\d{3}\b`), ValidGermanTaxID, 0, 0.95, taxCues},
		{FrenchNIR, rx(`\b[12] ?\d{2} ?(?:0[1-9]|1[0-2]|[2-9]\d) ?(?:\d{2}|2[AB]) ?\d{3} ?\d{3} ?\d{2}\b`), ValidFrenchNIR, 0.9, 0.98, []string{"sécurité sociale", "securite sociale", "nir", "insee", "social security"}},
		{PhoneIntl, rx(`\+(?:49|33|353|31|34|39|32|43|48|46|351|45|358|352)[ -]?\d(?:[ -]?\d){6,12}\b`), nil, 0.85, 0.95, phoneCues},
	},
	"us": {
		{USITIN, rx(`\b9\d{2}-?(?:5\d|6[0-5]|7\d|8[0-8]|9[0-24-9])-?\d{4}\b`), nil, 0.8, 0.97, []string{"itin", "taxpayer", "tin"}},
		{USSSN, rx(`\b\d{3}-\d{2}-\d{4}\b`), ValidSSN, 0.85, 0.98, []string{"ssn", "social security", "soc sec"}},
		{USSSN, rx(`\b\d{9}\b`), ValidSSN, 0, 0.9, []string{"ssn", "social security", "soc sec"}},
		{USRouting, rx(`\b\d{9}\b`), ValidABA, 0, 0.92, []string{"routing", "aba", "rtn", "transit"}},
		{PhoneIntl, rx(`\+1[ -]?\(?[2-9]\d{2}\)?[ .-]?\d{3}[ .-]?\d{4}\b`), nil, 0.85, 0.95, phoneCues},
		{PhoneIntl, rx(`\(?\b[2-9]\d{2}\)?[ .-]\d{3}[ .-]\d{4}\b`), nil, 0, 0.9, phoneCues},
	},
	"ca": {
		{CanadaSIN, rx(`\b\d{3}[ -]\d{3}[ -]\d{3}\b`), func(r string) bool { return ValidLuhn(digitsOnly(r)) }, 0.75, 0.97, []string{"sin", "social insurance", "nas", "assurance sociale"}},
		{CanadaSIN, rx(`\b\d{9}\b`), ValidLuhn, 0, 0.92, []string{"sin", "social insurance", "nas", "assurance sociale"}},
		{PhoneIntl, rx(`\+1[ -]?\(?[2-9]\d{2}\)?[ .-]?\d{3}[ .-]?\d{4}\b`), nil, 0.85, 0.95, phoneCues},
	},
	"br": {
		{PhoneIntl, rx(`\(?\b\d{2}\)?[ -]?[2-5]\d{3}[ -]?\d{4}\b`), nil, 0, 0.9, append([]string{"telefone", "fixo"}, phoneCues...)},
		{BrazilCPF, rx(`\b\d{3}\.\d{3}\.\d{3}-\d{2}\b`), ValidCPF, 0.95, 0.99, []string{"cpf"}},
		{BrazilCPF, rx(`\b\d{11}\b`), ValidCPF, 0, 0.93, []string{"cpf"}},
		{PhoneIntl, rx(`\+55[ -]?\(?\d{2}\)?[ -]?9?\d{4}[ -]?\d{4}\b`), nil, 0.85, 0.95, append([]string{"celular", "telefone"}, phoneCues...)},
	},
	"in": {
		{PhoneIntl, rx(`\b0\d{2,4}[ -]?\d{6,8}\b`), func(r string) bool { n := digitsOnly(r); return len(n) == 11 }, 0, 0.9, append([]string{"landline", "office", "std"}, phoneCues...)},
		{PhoneIntl, rx(`\b[6-9]\d{4}[ -]?\d{5}\b`), nil, 0, 0.9, phoneCues},
		{IndiaAadhaar, rx(`\b[2-9]\d{3} \d{4} \d{4}\b`), func(r string) bool { return ValidVerhoeff(digitsOnly(r)) }, 0.85, 0.98, []string{"aadhaar", "aadhar", "uid", "आधार"}},
		{IndiaAadhaar, rx(`\b[2-9]\d{11}\b`), ValidVerhoeff, 0, 0.93, []string{"aadhaar", "aadhar", "uid", "आधार"}},
		{IndiaPAN, rx(`\b[A-Z]{3}[ABCFGHJLPT][A-Z]\d{4}[A-Z]\b`), nil, 0.9, 0.98, []string{"pan", "permanent account"}},
		{PhoneIntl, rx(`(?:\+91[ -]?)[6-9]\d{4}[ -]?\d{5}\b`), nil, 0.85, 0.95, phoneCues},
	},
	"sg": {
		{PhoneIntl, rx(`\b[689]\d{3}[ -]?\d{4}\b`), nil, 0, 0.9, phoneCues},
		{SingaporeNRIC, rx(`\b[STFGM]\d{7}[A-Z]\b`), ValidNRIC, 0.95, 0.99, []string{"nric", "fin", "ic"}},
		{PhoneIntl, rx(`\+65[ -]?[689]\d{3}[ -]?\d{4}\b`), nil, 0.85, 0.95, phoneCues},
	},
}

// PackTypesOf lists the entity types a pack can find.
func PackTypesOf(pack string) []EntityType {
	seen := map[EntityType]bool{}
	var out []EntityType
	for _, r := range PackRules[pack] {
		if !seen[r.t] {
			seen[r.t] = true
			out = append(out, r.t)
		}
	}
	return out
}

var packTypeSet = func() map[EntityType]bool {
	m := map[EntityType]bool{}
	for _, rules := range PackRules {
		for _, r := range rules {
			m[r.t] = true
		}
	}
	return m
}()

// IsPackType reports whether t comes from a country pack outside Nigeria. Pipelines
// and routes made before packs existed list only Nigerian types; pack types pass
// their filters, since a vault only finds them after switching a pack on.
func IsPackType(t EntityType) bool { return packTypeSet[t] }

func hasCue(lower string, start, end int, cues []string) bool {
	lo, hi := max(0, start-48), min(len(lower), end+16)
	window := lower[lo:start] + " " + lower[end:hi]
	for _, c := range cues {
		if strings.Contains(window, c) {
			return true
		}
	}
	return false
}

// ScanPacks finds the given packs' entities. Overlaps keep the longest, then the
// highest-scoring match.
func (e *Engine) ScanPacks(text string, packs []string) []Entity {
	if len(packs) == 0 || text == "" {
		return nil
	}
	lower := strings.ToLower(text)
	var found []Entity
	done := map[string]bool{}
	for _, p := range packs {
		for _, r := range PackRules[p] {
			key := string(r.t) + r.re.String()
			if done[key] {
				continue // IBAN and +1 phones sit in several packs
			}
			done[key] = true
			for _, m := range r.re.FindAllStringIndex(text, -1) {
				end := m[1]
				if !isolated(text, m[0], end) {
					continue
				}
				raw := text[m[0]:end]
				if r.valid != nil && !r.valid(compact(raw)) {
					continue
				}
				score := r.base
				if hasCue(lower, m[0], end, r.cues) {
					score = r.cued
				}
				if score < e.threshold(r.t) || score == 0 {
					continue
				}
				found = append(found, Entity{Type: r.t, Start: m[0], End: end, Score: score})
			}
		}
	}
	sort.SliceStable(found, func(i, j int) bool {
		a, b := found[i], found[j]
		if al, bl := a.End-a.Start, b.End-b.Start; al != bl {
			return al > bl
		}
		return a.Score > b.Score
	})
	var kept []Entity
	for _, f := range found {
		overlap := false
		for _, k := range kept {
			overlap = overlap || (f.Start < k.End && k.Start < f.End)
		}
		if !overlap {
			kept = append(kept, f)
		}
	}
	sort.Slice(kept, func(i, j int) bool { return kept[i].Start < kept[j].Start })
	return kept
}

// compact drops spaces, dashes and dots, for checks.
func compact(s string) string {
	return strings.NewReplacer(" ", "", "-", "", ".", "", "(", "", ")", "", "/", "", ",", "").Replace(s)
}

// ValidatePackValue normalises a value for a pack type and checks it, for vault fields.
func ValidatePackValue(t EntityType, v string) (string, bool) {
	n := strings.ToUpper(compact(strings.TrimSpace(v)))
	if t == PhoneIntl {
		n = strings.TrimPrefix(n, "+")
		return "+" + n, len(n) >= 8 && len(n) <= 15 && digitsOnly(n) == n
	}
	if t == UKBankAccount { // sort code and account, stored as 14 digits
		return n, len(n) == 14 && digitsOnly(n) == n
	}
	for _, rules := range PackRules {
		for _, r := range rules {
			if r.t != t {
				continue
			}
			if loc := r.re.FindStringIndex(n); loc != nil && loc[0] == 0 && loc[1] == len(n) && (r.valid == nil || r.valid(n)) {
				return n, true
			}
		}
	}
	return n, false
}

// ---- checks ---------------------------------------------------------------------

// ValidIBAN checks the country length and the ISO 13616 mod-97 check.
func ValidIBAN(s string) bool {
	s = strings.ToUpper(compact(s))
	if len(s) < 15 || len(s) > 34 {
		return false
	}
	if want, ok := ibanLengths[s[:2]]; ok && len(s) != want {
		return false
	} else if !ok {
		return false
	}
	var b strings.Builder
	for _, c := range s[4:] + s[:4] {
		switch {
		case c >= '0' && c <= '9':
			b.WriteRune(c)
		case c >= 'A' && c <= 'Z':
			b.WriteString(strconv.Itoa(int(c-'A') + 10))
		default:
			return false
		}
	}
	n, ok := new(big.Int).SetString(b.String(), 10)
	return ok && new(big.Int).Mod(n, big.NewInt(97)).Int64() == 1
}

var ibanLengths = map[string]int{
	"AE": 23, "AT": 20, "BE": 16, "BH": 22, "CH": 21, "CY": 28, "CZ": 24, "DE": 22, "DK": 18, "EE": 20, "EG": 29, "ES": 24,
	"FI": 18, "FR": 27, "GB": 22, "GR": 27, "HR": 21, "HU": 28, "IE": 22, "IT": 27, "JO": 30, "KW": 30, "LT": 20, "LU": 20,
	"LV": 21, "MT": 31, "NL": 18, "NO": 15, "OM": 23, "PL": 28, "PT": 25, "QA": 29, "RO": 24, "SA": 24, "SE": 24, "SI": 19,
	"SK": 24, "TR": 26, "BR": 29,
}

// ValidSouthAfricaID checks the date of birth (YYMMDD), the citizenship digit and Luhn.
func ValidSouthAfricaID(s string) bool {
	if len(s) != 13 || digitsOnly(s) != s || !ValidLuhn(s) {
		return false
	}
	if _, err := time.Parse("060102", s[:6]); err != nil {
		return false
	}
	return s[10] == '0' || s[10] == '1' || s[10] == '2'
}

// egyptGovernorates are the birth-place codes in an Egyptian national ID.
var egyptGovernorates = map[string]bool{"01": true, "02": true, "03": true, "04": true, "11": true, "12": true, "13": true, "14": true, "15": true, "16": true, "17": true, "18": true, "19": true, "21": true, "22": true, "23": true, "24": true, "25": true, "26": true, "27": true, "28": true, "29": true, "31": true, "32": true, "33": true, "34": true, "35": true, "88": true}

// ValidEgyptID checks the century digit, the date of birth and the governorate code.
// Egypt does not publish its check-digit algorithm.
func ValidEgyptID(s string) bool {
	if len(s) != 14 || digitsOnly(s) != s {
		return false
	}
	century := map[byte]string{'2': "19", '3': "20"}[s[0]]
	if century == "" {
		return false
	}
	born, err := time.Parse("20060102", century+s[1:7])
	if err != nil || born.After(time.Now()) {
		return false
	}
	return egyptGovernorates[s[7:9]]
}

// ValidNINO refuses the prefixes HMRC never issues and the administrative ones.
func ValidNINO(s string) bool {
	s = strings.ToUpper(compact(s))
	if len(s) != 9 {
		return false
	}
	switch s[:2] {
	case "BG", "GB", "NK", "KN", "TN", "NT", "ZZ":
		return false
	}
	return true
}

// ValidNHS is the NHS number's modulus 11 check.
func ValidNHS(s string) bool {
	s = compact(s)
	if len(s) != 10 || digitsOnly(s) != s {
		return false
	}
	sum := 0
	for i := 0; i < 9; i++ {
		sum += int(s[i]-'0') * (10 - i)
	}
	check := 11 - sum%11
	if check == 11 {
		check = 0
	}
	return check != 10 && check == int(s[9]-'0')
}

// ValidGermanTaxID is the Steuer-ID's ISO 7064 MOD 11,10 check; it never starts with 0.
func ValidGermanTaxID(s string) bool {
	s = compact(s)
	if len(s) != 11 || digitsOnly(s) != s || s[0] == '0' {
		return false
	}
	product := 10
	for i := 0; i < 10; i++ {
		sum := (int(s[i]-'0') + product) % 10
		if sum == 0 {
			sum = 10
		}
		product = (sum * 2) % 11
	}
	check := 11 - product
	if check == 10 {
		check = 0
	}
	return check == int(s[10]-'0')
}

// ValidFrenchNIR checks the 2-digit key: 97 minus the first 13 digits mod 97.
// Corsica's departments 2A and 2B count as 19 and 18.
func ValidFrenchNIR(s string) bool {
	s = strings.ToUpper(compact(s))
	if len(s) != 15 {
		return false
	}
	body := s[:13]
	switch {
	case strings.Contains(body[5:7], "2A"):
		body = body[:5] + "19" + body[7:]
	case strings.Contains(body[5:7], "2B"):
		body = body[:5] + "18" + body[7:]
	}
	if digitsOnly(body) != body || digitsOnly(s[13:]) != s[13:] {
		return false
	}
	n, _ := new(big.Int).SetString(body, 10)
	key, _ := strconv.Atoi(s[13:])
	return 97-new(big.Int).Mod(n, big.NewInt(97)).Int64() == int64(key)
}

// ValidSSN applies the Social Security Administration's never-issued rules.
func ValidSSN(s string) bool {
	s = compact(s)
	if len(s) != 9 || digitsOnly(s) != s {
		return false
	}
	area, group, serial := s[:3], s[3:5], s[5:]
	return area != "000" && area != "666" && area[0] != '9' && group != "00" && serial != "0000"
}

// ValidABA is the routing number's 3-7-1 weighted check.
func ValidABA(s string) bool {
	if len(s) != 9 || digitsOnly(s) != s {
		return false
	}
	w := []int{3, 7, 1, 3, 7, 1, 3, 7, 1}
	sum := 0
	for i := range s {
		sum += int(s[i]-'0') * w[i]
	}
	return sum%10 == 0 && s != "000000000"
}

// ValidCPF checks both of the CPF's check digits and refuses repeated digits.
func ValidCPF(s string) bool {
	s = compact(s)
	if len(s) != 11 || digitsOnly(s) != s || strings.Count(s, s[:1]) == 11 {
		return false
	}
	digit := func(n int) int {
		sum := 0
		for i := 0; i < n; i++ {
			sum += int(s[i]-'0') * (n + 1 - i)
		}
		d := sum * 10 % 11
		if d == 10 {
			d = 0
		}
		return d
	}
	return digit(9) == int(s[9]-'0') && digit(10) == int(s[10]-'0')
}

var (
	verhoeffD = [10][10]int{{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, {1, 2, 3, 4, 0, 6, 7, 8, 9, 5}, {2, 3, 4, 0, 1, 7, 8, 9, 5, 6}, {3, 4, 0, 1, 2, 8, 9, 5, 6, 7}, {4, 0, 1, 2, 3, 9, 5, 6, 7, 8}, {5, 9, 8, 7, 6, 0, 4, 3, 2, 1}, {6, 5, 9, 8, 7, 1, 0, 4, 3, 2}, {7, 6, 5, 9, 8, 2, 1, 0, 4, 3}, {8, 7, 6, 5, 9, 3, 2, 1, 0, 4}, {9, 8, 7, 6, 5, 4, 3, 2, 1, 0}}
	verhoeffP = [8][10]int{{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, {1, 5, 7, 6, 2, 8, 3, 0, 9, 4}, {5, 8, 0, 3, 7, 9, 6, 1, 4, 2}, {8, 9, 1, 6, 0, 4, 3, 5, 2, 7}, {9, 4, 5, 3, 1, 2, 6, 8, 7, 0}, {4, 2, 8, 6, 5, 7, 3, 9, 0, 1}, {2, 7, 9, 3, 8, 0, 6, 4, 1, 5}, {7, 0, 4, 6, 9, 1, 3, 2, 5, 8}}
)

// ValidVerhoeff is Aadhaar's check.
func ValidVerhoeff(s string) bool {
	if len(s) == 0 || digitsOnly(s) != s {
		return false
	}
	c := 0
	for i := 0; i < len(s); i++ {
		c = verhoeffD[c][verhoeffP[i%8][int(s[len(s)-1-i]-'0')]]
	}
	return c == 0
}

// ValidNRIC checks a Singapore NRIC or FIN check letter.
func ValidNRIC(s string) bool {
	s = strings.ToUpper(s)
	if len(s) != 9 {
		return false
	}
	w := []int{2, 7, 6, 5, 4, 3, 2}
	sum := 0
	for i := 0; i < 7; i++ {
		d := s[1+i]
		if d < '0' || d > '9' {
			return false
		}
		sum += int(d-'0') * w[i]
	}
	var letters string
	switch s[0] {
	case 'S', 'F':
		letters = map[byte]string{'S': "JZIHGFEDCBA", 'F': "XWUTRQPNMLK"}[s[0]]
	case 'T', 'G':
		sum += 4
		letters = map[byte]string{'T': "JZIHGFEDCBA", 'G': "XWUTRQPNMLK"}[s[0]]
	case 'M':
		sum += 3
		letters = "KLJNPQRTUWX"
	default:
		return false
	}
	if s[0] == 'M' {
		return letters[10-sum%11] == s[8]
	}
	return letters[sum%11] == s[8]
}

// ValidQatarID checks what a Qatar ID's structure allows; Qatar publishes no check
// digit. The first digit is the century of birth (2 for 1900s, 3 for 2000s), the
// next two the year of birth, the next three the holder's ISO 3166 numeric
// nationality code (634 for Qatari citizens), then a serial number.
func ValidQatarID(s string) bool {
	if len(s) != 11 || digitsOnly(s) != s {
		return false
	}
	century := map[byte]int{'2': 1900, '3': 2000}[s[0]]
	if century == 0 {
		return false
	}
	yy, _ := strconv.Atoi(s[1:3])
	year, now := century+yy, time.Now().Year()
	if year > now || year < now-110 {
		return false
	}
	return isoNumeric[s[3:6]]
}

// isoNumeric are the ISO 3166-1 numeric country codes.
var isoNumeric = func() map[string]bool {
	m := map[string]bool{}
	for _, c := range strings.Fields(`004 008 010 012 016 020 024 028 031 032 036 040 044 048 050 051 052 056 060 064 068 070 072 074 076 084 086 090 092 096
100 104 108 112 116 120 124 132 136 140 144 148 152 156 158 162 166 170 174 175 178 180 184 188 191 192 196 203 204 208 212 214 218 222 226 231 232
233 234 238 239 242 246 248 250 254 258 260 262 266 268 270 275 276 288 292 296 300 304 308 312 316 320 324 328 332 334 336 340 344 348 352 356 360
364 368 372 376 380 384 388 392 398 400 404 408 410 414 417 418 422 426 428 430 434 438 440 442 446 450 454 458 462 466 470 474 478 480 484 492 496
498 499 500 504 508 512 516 520 524 528 531 533 534 535 540 548 554 558 562 566 570 574 578 580 581 583 584 585 586 591 598 600 604 608 612 616 620
624 626 630 634 638 642 643 646 652 654 659 660 662 663 666 670 674 678 682 686 688 690 694 702 703 704 705 706 710 716 724 728 729 732 740 744 748
752 756 760 762 764 768 772 776 780 784 788 792 795 796 798 800 804 807 818 826 831 832 833 834 840 850 854 858 860 862 876 882 887 894`) {
		m[c] = true
	}
	return m
}()

// isoAlpha3 are ISO 3166-1 alpha-3 codes, as printed on non-citizens' Ghana Cards.
var isoAlpha3 = func() map[string]bool {
	m := map[string]bool{}
	for _, c := range strings.Fields(`AFG ALB DZA AGO ARG ARM AUS AUT AZE BHR BGD BLR BEL BEN BTN BOL BIH BWA BRA BGR BFA BDI KHM CMR CAN CPV CAF TCD CHL CHN
COL COM COG COD CRI CIV HRV CUB CYP CZE DNK DJI DOM ECU EGY SLV GNQ ERI EST SWZ ETH FJI FIN FRA GAB GMB GEO DEU GHA GRC GTM GIN GNB GUY HTI HND HKG HUN ISL
IND IDN IRN IRQ IRL ISR ITA JAM JPN JOR KAZ KEN KOR KWT KGZ LAO LVA LBN LSO LBR LBY LTU LUX MDG MWI MYS MDV MLI MLT MRT MUS MEX MDA MNG MNE MAR MOZ MMR NAM
NPL NLD NZL NIC NER NGA MKD NOR OMN PAK PSE PAN PNG PRY PER PHL POL PRT QAT ROU RUS RWA SAU SEN SRB SYC SLE SGP SVK SVN SOM ZAF SSD ESP LKA SDN SUR SWE CHE
SYR TWN TJK TZA THA TGO TTO TUN TUR TKM UGA UKR ARE GBR USA URY UZB VEN VNM YEM ZMB ZWE`) {
		m[c] = true
	}
	return m
}()

// AllPacks are every pack, for contexts with no vault: a preview, a scan from the
// command line. No country is assumed; overlaps keep the longest, best match.
func AllPacks() []string {
	out := []string{"everywhere", "ng"}
	for p := range PackRules {
		if p != "everywhere" && p != "ng" {
			out = append(out, p)
		}
	}
	sort.Strings(out[2:])
	return out
}

// GlobalRuleSet is the rule set for a context with no vault.
func GlobalRuleSet(e *Engine) *RuleSet { return BaseRuleSet(e).WithPacks("", AllPacks()) }
