// Package cloak decides how each kind of personal data is hidden before text
// leaves the country: a placeholder, a realistic stand-in name, or a less
// specific value such as an amount band, an age band or a state.
//
// Placeholders and stand-in names can be swapped back. Less specific values
// cannot: "₦1m–₦5m" stands for many amounts, so it stays as it is.
package cloak

import (
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// Options say what happens to each kind of data. Keys are entity types; a
// missing key means that kind's default.
type Options map[string]string

// The option values.
const (
	Placeholder = "placeholder" // [NAME_1]; restored in replies for callers allowed to see it
	Synthetic   = "synthetic"   // a realistic stand-in name; also restored
	Keep        = "keep"        // sent as it is
	Last4       = "last4"       // ****6789
	Band        = "band"        // ₦1m–₦5m
	AgeBand     = "age_band"    // aged 35–44
	Year        = "year"        // 1988
	Network     = "network"     // an MTN number
	Domain      = "domain"      // a gmail.com address
	State       = "state"       // Lagos
	Region      = "region"      // South-West Nigeria
)

// Choice is one option in the console's grid.
type Choice struct {
	Value   string `json:"value"`
	Label   string `json:"label"`
	Example string `json:"example"`
}

// Category is one row of the grid.
type Category struct {
	Key     string   `json:"key"`
	Label   string   `json:"label"`
	Default string   `json:"default"`
	Choices []Choice `json:"choices"`
	// Packs are the country packs that find this kind; none means every vault.
	Packs []string `json:"packs,omitempty"`
}

var placeholderChoice = func(ex string) Choice { return Choice{Placeholder, "Placeholder", ex} }

// Categories lists every kind of data with its choices, in display order.
var Categories = []Category{
	// Every vault.
	{"person_name", "Names", Placeholder, []Choice{placeholderChoice("[NAME_1]"), {Synthetic, "Stand-in name", "Sarah Johnson → Emily Carter"}, {Keep, "Send as it is", "Sarah Johnson"}}, nil},
	{"amount", "Amounts", Placeholder, []Choice{placeholderChoice("[AMOUNT_1]"), {Band, "Range, in the same currency", "$8,500 → $5k–$10k"}, {Keep, "Send as it is", "$8,500"}}, nil},
	{"date", "Dates of birth", Placeholder, []Choice{placeholderChoice("[DATE_1]"), {AgeBand, "Age range", "1988-03-14 → aged 35–44"}, {Year, "Year only", "1988-03-14 → 1988"}, {Keep, "Send as it is", "1988-03-14"}}, nil},
	{"address", "Places", Keep, []Choice{{Keep, "Send as it is", "Brooklyn"}, {State, "State or province", "Brooklyn → New York"}, {Region, "Country", "Brooklyn → United States"}, placeholderChoice("[PLACE_1]")}, nil},
	{"phone", "Phone numbers", Placeholder, []Choice{placeholderChoice("[PHONE_1]"), {Last4, "Last four digits", "****0958"}}, nil},
	{"email", "Email addresses", Placeholder, []Choice{placeholderChoice("[EMAIL_1]"), {Domain, "Domain only", "a gmail.com address"}}, nil},
	{"card_pan", "Card numbers", Placeholder, []Choice{placeholderChoice("[CARD_1]"), {Last4, "Last four digits", "****1234"}}, nil},
	{"payment_ref", "Payment references", Placeholder, []Choice{placeholderChoice("[REF_1]"), {Last4, "Last four characters", "****A1B2"}}, nil},
	// Country packs.
	{"bvn", "Nigerian BVNs", Placeholder, []Choice{placeholderChoice("[BVN_1]"), {Last4, "Last four digits", "****6789"}}, []string{"ng"}},
	{"nin", "Nigerian NINs", Placeholder, []Choice{placeholderChoice("[NIN_1]"), {Last4, "Last four digits", "****6789"}}, []string{"ng"}},
	{"vnin", "Nigerian virtual NINs", Placeholder, []Choice{placeholderChoice("[VNIN_1]"), {Last4, "Last four characters", "****WXYZ"}}, []string{"ng"}},
	{"ng_11_digit_id", "Nigerian 11-digit IDs, type unclear", Placeholder, []Choice{placeholderChoice("[ID_1]"), {Last4, "Last four digits", "****6789"}}, []string{"ng"}},
	{"nuban", "Nigerian bank accounts (NUBAN)", Placeholder, []Choice{placeholderChoice("[ACCOUNT_1]"), {Last4, "Last four digits", "****6789"}}, []string{"ng"}},
	{"phone_ng", "Nigerian phone numbers", Placeholder, []Choice{placeholderChoice("[PHONE_1]"), {Network, "Network only", "0803 123 4567 → an MTN number"}, {Last4, "Last four digits", "****4567"}}, []string{"ng"}},
	{"ghana_card", "Ghana Card numbers", Placeholder, []Choice{placeholderChoice("[GHANA_CARD_1]"), {Last4, "Last four characters", "****1234"}}, []string{"gh"}},
	{"ke_national_id", "Kenyan national IDs", Placeholder, []Choice{placeholderChoice("[KE_NATIONAL_ID_1]"), {Last4, "Last four characters", "****1234"}}, []string{"ke"}},
	{"ke_kra_pin", "KRA PINs", Placeholder, []Choice{placeholderChoice("[KE_KRA_PIN_1]"), {Last4, "Last four characters", "****1234"}}, []string{"ke"}},
	{"za_id", "South African ID numbers", Placeholder, []Choice{placeholderChoice("[ZA_ID_1]"), {Last4, "Last four characters", "****1234"}}, []string{"za"}},
	{"eg_national_id", "Egyptian national IDs", Placeholder, []Choice{placeholderChoice("[EG_NATIONAL_ID_1]"), {Last4, "Last four characters", "****1234"}}, []string{"eg"}},
	{"emirates_id", "Emirates IDs", Placeholder, []Choice{placeholderChoice("[EMIRATES_ID_1]"), {Last4, "Last four characters", "****1234"}}, []string{"ae"}},
	{"sa_national_id", "Saudi IDs and Iqamas", Placeholder, []Choice{placeholderChoice("[SA_NATIONAL_ID_1]"), {Last4, "Last four characters", "****1234"}}, []string{"sa"}},
	{"qa_id", "Qatar IDs", Placeholder, []Choice{placeholderChoice("[QA_ID_1]"), {Last4, "Last four characters", "****1234"}}, []string{"qa"}},
	{"uk_nino", "National Insurance numbers", Placeholder, []Choice{placeholderChoice("[UK_NINO_1]"), {Last4, "Last four characters", "****1234"}}, []string{"gb"}},
	{"uk_nhs", "NHS numbers", Placeholder, []Choice{placeholderChoice("[UK_NHS_1]"), {Last4, "Last four characters", "****1234"}}, []string{"gb"}},
	{"uk_bank_account", "UK sort codes and accounts", Placeholder, []Choice{placeholderChoice("[UK_BANK_ACCOUNT_1]"), {Last4, "Last four characters", "****1234"}}, []string{"gb"}},
	{"iban", "IBANs", Placeholder, []Choice{placeholderChoice("[IBAN_1]"), {Last4, "Last four characters", "****1234"}}, []string{"ae", "sa", "qa", "gb", "eu"}},
	{"eu_vat", "EU VAT numbers", Placeholder, []Choice{placeholderChoice("[EU_VAT_1]"), {Last4, "Last four characters", "****1234"}}, []string{"eu"}},
	{"de_tax_id", "German tax IDs", Placeholder, []Choice{placeholderChoice("[DE_TAX_ID_1]"), {Last4, "Last four characters", "****1234"}}, []string{"eu"}},
	{"fr_nir", "French social security numbers", Placeholder, []Choice{placeholderChoice("[FR_NIR_1]"), {Last4, "Last four characters", "****1234"}}, []string{"eu"}},
	{"us_ssn", "US Social Security numbers", Placeholder, []Choice{placeholderChoice("[US_SSN_1]"), {Last4, "Last four characters", "****1234"}}, []string{"us"}},
	{"us_itin", "US ITINs", Placeholder, []Choice{placeholderChoice("[US_ITIN_1]"), {Last4, "Last four characters", "****1234"}}, []string{"us"}},
	{"us_routing", "US routing numbers", Placeholder, []Choice{placeholderChoice("[US_ROUTING_1]"), {Last4, "Last four characters", "****1234"}}, []string{"us"}},
	{"ca_sin", "Canadian SINs", Placeholder, []Choice{placeholderChoice("[CA_SIN_1]"), {Last4, "Last four characters", "****1234"}}, []string{"ca"}},
	{"br_cpf", "Brazilian CPFs", Placeholder, []Choice{placeholderChoice("[BR_CPF_1]"), {Last4, "Last four characters", "****1234"}}, []string{"br"}},
	{"in_aadhaar", "Aadhaar numbers", Placeholder, []Choice{placeholderChoice("[IN_AADHAAR_1]"), {Last4, "Last four characters", "****1234"}}, []string{"in"}},
	{"in_pan", "Indian PANs", Placeholder, []Choice{placeholderChoice("[IN_PAN_1]"), {Last4, "Last four characters", "****1234"}}, []string{"in"}},
	{"sg_nric", "Singapore NRICs and FINs", Placeholder, []Choice{placeholderChoice("[SG_NRIC_1]"), {Last4, "Last four characters", "****1234"}}, []string{"sg"}},
}

var categoryByKey = func() map[string]*Category {
	m := map[string]*Category{}
	for i := range Categories {
		m[Categories[i].Key] = &Categories[i]
	}
	m["amount_ngn"] = m["amount"] // the key settings used before amounts went global
	return m
}()

// Validate refuses unknown kinds and options a kind does not offer.
func Validate(o Options) error {
	for k, v := range o {
		c := categoryByKey[k]
		if c == nil {
			return fmt.Errorf("unknown kind of data %q", k)
		}
		ok := false
		for _, ch := range c.Choices {
			ok = ok || ch.Value == v
		}
		if !ok {
			return fmt.Errorf("%s cannot use %q", c.Label, v)
		}
	}
	return nil
}

// For returns the option for an entity type. Custom entities and anything not
// listed get a placeholder, which is today's behaviour.
func (o Options) For(entity string) string {
	if v, ok := o[entity]; ok && v != "" {
		return v
	}
	// One "Amounts" row covers naira and every other currency; settings saved
	// before then used "amount_ngn".
	if entity == "amount_ngn" || entity == "amount" {
		for _, k := range []string{"amount", "amount_ngn"} {
			if v, ok := o[k]; ok && v != "" {
				return v
			}
		}
	}
	if c := categoryByKey[entity]; c != nil {
		return c.Default
	}
	return Placeholder
}

// Restorable reports whether an option's output can be swapped back.
func Restorable(option string) bool { return option == Placeholder || option == Synthetic }

// Generalize makes a value less specific. It returns false when the value
// cannot be read for that option; the caller then uses a placeholder, so
// nothing is ever sent as it is by mistake.
func Generalize(entity, option, value string, now time.Time) (string, bool) {
	return GeneralizeIn("", entity, option, value, now)
}

// GeneralizeIn is Generalize for a vault in a country, which decides how dates
// are read: month first in the United States, day first elsewhere.
func GeneralizeIn(country, entity, option, value string, now time.Time) (string, bool) {
	monthFirst := country == "US"
	switch option {
	case Last4:
		return last4(value)
	case Band:
		if entity == "amount_ngn" {
			return amountBand(value)
		}
		if entity == "amount" {
			return moneyBand(value)
		}
	case AgeBand:
		if entity == "date" {
			return ageBand(value, now, monthFirst)
		}
	case Year:
		if entity == "date" {
			if y := yearOf(value); y > 0 {
				return strconv.Itoa(y), true
			}
		}
	case Network:
		if entity == "phone_ng" {
			if n := phoneNetwork(value); n != "" {
				article := "a "
				if n == "MTN" || n == "Airtel" {
					article = "an "
				}
				return article + n + " number", true
			}
		}
	case Domain:
		if entity == "email" {
			at := strings.LastIndexByte(value, '@')
			if at > 0 && at < len(value)-1 {
				return "a " + strings.ToLower(value[at+1:]) + " address", true
			}
		}
	case State, Region:
		if entity == "address" {
			if p, ok := lookupPlace(value); ok {
				if option == State {
					return p.state, true
				}
				return p.region(), true
			}
		}
	}
	return "", false
}

func last4(v string) (string, bool) {
	var keep []rune
	for _, r := range v {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			keep = append(keep, r)
		}
	}
	if len(keep) < 8 {
		return "", false
	}
	return "****" + strings.ToUpper(string(keep[len(keep)-4:])), true
}

// amountBand reads "₦850,000", "NGN 1.2m", "N50k" or "250000 naira".
func amountBand(v string) (string, bool) {
	s := strings.ToLower(strings.TrimSpace(v))
	for _, p := range []string{"₦", "ngn", "n"} {
		s = strings.TrimPrefix(s, p)
	}
	s = strings.TrimSpace(strings.TrimSuffix(s, "naira"))
	s = strings.ReplaceAll(strings.ReplaceAll(s, ",", ""), " ", "")
	mult := 1.0
	switch {
	case strings.HasSuffix(s, "bn"):
		mult, s = 1e9, strings.TrimSuffix(s, "bn")
	case strings.HasSuffix(s, "b"):
		mult, s = 1e9, strings.TrimSuffix(s, "b")
	case strings.HasSuffix(s, "m"):
		mult, s = 1e6, strings.TrimSuffix(s, "m")
	case strings.HasSuffix(s, "k"):
		mult, s = 1e3, strings.TrimSuffix(s, "k")
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || f < 0 {
		return "", false
	}
	n := f * mult
	edges := []float64{1e4, 5e4, 1e5, 5e5, 1e6, 5e6, 1e7, 5e7, 1e8}
	if n < edges[0] {
		return "under ₦10k", true
	}
	for i := 1; i < len(edges); i++ {
		if n < edges[i] {
			return naira(edges[i-1]) + "–" + naira(edges[i]), true
		}
	}
	return "over ₦100m", true
}

func naira(n float64) string {
	if n >= 1e6 {
		return "₦" + strconv.FormatFloat(n/1e6, 'f', -1, 64) + "m"
	}
	return "₦" + strconv.FormatFloat(n/1e3, 'f', -1, 64) + "k"
}

// yearOf finds a four-digit year from 1900 to 2099.
func yearOf(v string) int {
	for i := 0; i+4 <= len(v); i++ {
		if (i > 0 && isDigit(v[i-1])) || (i+4 < len(v) && isDigit(v[i+4])) {
			continue
		}
		if y, err := strconv.Atoi(v[i : i+4]); err == nil && y >= 1900 && y <= 2099 {
			return y
		}
	}
	return 0
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

// birthDate reads 1988-03-14, 14/03/1988 and 14-03-1988: day first, as most of the
// world writes them, or month first (03/14/1988) for a vault in the United States.
func birthDate(v string, monthFirst bool) (time.Time, bool) {
	v = strings.TrimSpace(v)
	layouts := []string{"2006-01-02", "02/01/2006", "2/1/2006", "02-01-2006", "2-1-2006", "02.01.2006", "2 January 2006", "2 Jan 2006", "January 2, 2006"}
	if monthFirst {
		layouts = []string{"2006-01-02", "01/02/2006", "1/2/2006", "01-02-2006", "1-2-2006", "January 2, 2006", "Jan 2, 2006", "2 January 2006"}
	}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, v); err == nil {
			return t, true
		}
	}
	if y := yearOf(v); y > 0 {
		return time.Date(y, 7, 1, 0, 0, 0, 0, time.UTC), true // mid-year when only the year is readable
	}
	return time.Time{}, false
}

func ageBand(v string, now time.Time, monthFirst bool) (string, bool) {
	b, ok := birthDate(v, monthFirst)
	if !ok || b.After(now) {
		return "", false
	}
	age := now.Year() - b.Year()
	if now.YearDay() < b.YearDay() {
		age--
	}
	switch {
	case age < 18:
		return "under 18", true
	case age < 25:
		return "aged 18–24", true
	case age >= 65:
		return "aged 65 or over", true
	}
	lo := 25 + (age-25)/10*10
	return fmt.Sprintf("aged %d–%d", lo, lo+9), true
}

// phonePrefixes are the network operators' allocated prefixes, by first four digits.
var phonePrefixes = map[string]string{
	"0803": "MTN", "0806": "MTN", "0703": "MTN", "0706": "MTN", "0810": "MTN", "0813": "MTN", "0814": "MTN", "0816": "MTN", "0903": "MTN", "0906": "MTN", "0913": "MTN", "0916": "MTN", "0704": "MTN",
	"0805": "Glo", "0807": "Glo", "0705": "Glo", "0815": "Glo", "0811": "Glo", "0905": "Glo", "0915": "Glo",
	"0802": "Airtel", "0808": "Airtel", "0708": "Airtel", "0812": "Airtel", "0701": "Airtel", "0902": "Airtel", "0901": "Airtel", "0904": "Airtel", "0907": "Airtel", "0912": "Airtel",
	"0809": "9mobile", "0818": "9mobile", "0817": "9mobile", "0909": "9mobile", "0908": "9mobile",
}

func phoneNetwork(v string) string {
	var d strings.Builder
	for _, r := range v {
		if r >= '0' && r <= '9' {
			d.WriteRune(r)
		}
	}
	s := d.String()
	if strings.HasPrefix(s, "234") {
		s = "0" + s[3:]
	}
	if len(s) != 11 {
		return ""
	}
	return phonePrefixes[s[:4]]
}

// ---- stand-in names ------------------------------------------------------------

// Namer hands out stand-in names for one request. The same real name gets the
// same stand-in; no stand-in repeats, or appears anywhere in the original text.
type Namer struct {
	avoid string
	pick  func(n int) int
	used  map[string]bool
	byRe  map[string]string
	pool  namePool
}

// NewNamer avoids any name already in text. pick returns a random index below n.
// Stand-ins come from an international pool; NewNamerFor picks a country's.
func NewNamer(text string, pick func(n int) int) *Namer { return NewNamerFor(text, pick, "") }

// NewNamerFor uses the stand-in names of a vault's country, so a reply reads
// naturally where the customer lives.
func NewNamerFor(text string, pick func(n int) int, country string) *Namer {
	return &Namer{avoid: strings.ToLower(text), pick: pick, used: map[string]bool{}, byRe: map[string]string{}, pool: poolFor(country)}
}

// Part pairs a stand-in word with the real word it replaces.
type Part struct{ Fake, Real string }

// Fake returns the stand-in for a real name, and the parts a reply might use on
// their own ("Dear Adaeze"). It returns "" when the pools are used up.
func (n *Namer) Fake(real string) (string, []Part) {
	words := strings.Fields(real)
	if len(words) == 0 {
		return "", nil
	}
	if f, ok := n.byRe[real]; ok {
		return f, partsOf(f, words)
	}
	choose := func(pool []string) string {
		start := n.pick(len(pool))
		for k := 0; k < len(pool); k++ {
			c := pool[(start+k)%len(pool)]
			if !n.used[c] && !strings.Contains(n.avoid, strings.ToLower(c)) {
				return c
			}
		}
		return ""
	}
	first := choose(n.pool.first)
	if first == "" {
		return "", nil
	}
	fake := first
	if len(words) > 1 {
		last := choose(n.pool.last)
		if last == "" {
			return "", nil
		}
		fake = first + " " + last
		n.used[last] = true
	}
	n.used[first] = true
	n.byRe[real] = fake
	return fake, partsOf(fake, words)
}

func partsOf(fake string, real []string) []Part {
	f := strings.Fields(fake)
	if len(f) == 1 {
		return []Part{{f[0], strings.Join(real, " ")}}
	}
	return []Part{{f[0], real[0]}, {f[1], real[len(real)-1]}}
}
