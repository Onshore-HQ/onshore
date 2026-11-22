// Package detect finds Nigerian identifiers in free text, logs and JSON.
//
// Candidates come from RE2 regular expressions (linear time on hostile input)
// and an Aho-Corasick scan for context keywords; each is validated, scored from
// the words around it, and resolved against overlapping matches.
package detect

import (
	"math/bits"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

type EntityType string

const (
	BVN        EntityType = "bvn"
	NIN        EntityType = "nin"
	NG11Digit  EntityType = "ng_11_digit_id"
	NUBAN      EntityType = "nuban"
	PhoneNG    EntityType = "phone_ng"
	CardPAN    EntityType = "card_pan"
	Email      EntityType = "email"
	PersonName EntityType = "person_name"
	AmountNGN  EntityType = "amount_ngn"
	DOB        EntityType = "date"
	// VNIN is NIMC's 16-character virtual NIN: 2 letters, 12 digits, 2 letters.
	VNIN EntityType = "vnin"
	// PaymentRef is opt-in per pipeline. Law firms read "payment transaction
	// data" as including payment references; the CBN has not ruled on it.
	PaymentRef EntityType = "payment_ref"
)

// AllTypes lists every entity the engine can emit.
var AllTypes = []EntityType{BVN, NIN, NG11Digit, NUBAN, PhoneNG, CardPAN, Email, PersonName, AmountNGN, DOB, VNIN, PaymentRef}

// Entity is one detected span; Start and End are byte offsets.
type Entity struct {
	Type  EntityType `json:"type"`
	Start int        `json:"start"`
	End   int        `json:"end"`
	Score float64    `json:"score"`
	// Custom marks a customer-defined entity, with the version that matched it.
	Custom        bool `json:"custom"`
	EntityVersion int  `json:"entity_version,omitempty"`
	Shadow        bool `json:"shadow,omitempty"`
	// Observe marks a match only counted in this module: shadow, or action "pass".
	// It overlaps active spans freely and must never reach Replace.
	Observe bool `json:"-"`
}

// Config tunes an Engine. The zero value uses defaults.
type Config struct {
	// Thresholds overrides the minimum score per entity type (default 0.5).
	Thresholds map[EntityType]float64
	// AllowedEmailDomains are never reported (for example your own support domain).
	AllowedEmailDomains []string
	// IsOwnToken confirms that a format-preserving lookalike is one of our
	// tokens. Unconfirmed lookalikes stay sensitive, so a real value that happens
	// to fall in a reserved range is never passed through.
	IsOwnToken func(string) bool
	// FormatPreservingPrefixes are the reserved leading digits sent to IsOwnToken.
	FormatPreservingPrefixes []string
	// PaymentRefs turns on payment reference detection, which is opt-in.
	PaymentRefs bool
}

type cue uint16

const (
	cueBVN cue = 1 << iota
	cueNIN
	cueAcct
	cuePhone
	cueCard
	cueName
	cueHonorific
	cueAmount
	cueDOB
	cueNeg
	cueVNIN
	cuePayRef
)

var keywords = []struct {
	word string
	c    cue
}{
	{"bvn", cueBVN}, {"bank verification", cueBVN}, {"verification number", cueBVN}, {"verification no", cueBVN},
	{"nin", cueNIN}, {"national identity", cueNIN}, {"national id", cueNIN}, {"nimc", cueNIN}, {"slip", cueNIN},
	{"account", cueAcct}, {"acct", cueAcct}, {"acc", cueAcct}, {"a/c", cueAcct}, {"nuban", cueAcct}, {"beneficiary", cueAcct}, {"transfer", cueAcct}, {"transferred", cueAcct}, {"sent to", cueAcct}, {"enter", cueAcct}, {"send to", cueAcct}, {"send am", cueAcct}, {"pay into", cueAcct}, {"credited", cueAcct},
	{"bank", cueAcct},
	{"vnin", cueVNIN}, {"virtual nin", cueVNIN},
	{"rrn", cuePayRef}, {"payment ref", cuePayRef}, {"payment reference", cuePayRef}, {"transaction ref", cuePayRef}, {"transaction reference", cuePayRef}, {"txn ref", cuePayRef}, {"session id", cuePayRef}, {"nip session", cuePayRef},
	{"phone", cuePhone}, {"tel", cuePhone}, {"call", cuePhone}, {"whatsapp", cuePhone}, {"line", cuePhone}, {"mobile", cuePhone}, {"msisdn", cuePhone}, {"sms", cuePhone}, {"recharge", cuePhone},
	{"card", cueCard}, {"pan", cueCard}, {"debit card", cueCard}, {"verve", cueCard}, {"mastercard", cueCard}, {"visa", cueCard},
	{"name", cueName}, {"customer", cueName}, {"beneficiary", cueName}, {"holder", cueName},
	{"mr", cueHonorific}, {"mrs", cueHonorific}, {"miss", cueHonorific}, {"ms", cueHonorific}, {"dr", cueHonorific}, {"chief", cueHonorific}, {"alhaji", cueHonorific}, {"alhaja", cueHonorific}, {"engr", cueHonorific}, {"prof", cueHonorific}, {"mallam", cueHonorific}, {"madam", cueHonorific}, {"oga", cueHonorific},
	{"paid", cueAmount}, {"transfer", cueAmount}, {"transferred", cueAmount}, {"debit", cueAmount}, {"debited", cueAmount}, {"credit", cueAmount}, {"credited", cueAmount}, {"balance", cueAmount}, {"amount", cueAmount}, {"send", cueAmount}, {"loan", cueAmount}, {"withdraw", cueAmount}, {"deposit", cueAmount},
	{"dob", cueDOB}, {"date of birth", cueDOB}, {"born", cueDOB}, {"birth date", cueDOB}, {"birthdate", cueDOB}, {"birthday", cueDOB},
	{"ref", cueNeg}, {"reference", cueNeg}, {"session", cueNeg}, {"sessionid", cueNeg}, {"order", cueNeg}, {"orderid", cueNeg}, {"timestamp", cueNeg}, {"ts", cueNeg}, {"epoch", cueNeg}, {"trace", cueNeg}, {"traceid", cueNeg}, {"span", cueNeg}, {"spanid", cueNeg}, {"uuid", cueNeg}, {"request", cueNeg}, {"req", cueNeg}, {"pid", cueNeg}, {"thread", cueNeg}, {"invoice", cueNeg}, {"ticket", cueNeg}, {"latency", cueNeg}, {"duration", cueNeg}, {"bytes", cueNeg}, {"sku", cueNeg}, {"build", cueNeg}, {"version", cueNeg},
}

// bankCues name institutions, so that the check digit can be tested against the
// one code that matters. Codes are from the embedded list.
var bankCues = map[string]string{
	"access bank": "044", "gtb": "058", "gtbank": "058", "guaranty trust": "058", "zenith": "057", "uba": "033", "first bank": "011", "firstbank": "011",
	"fcmb": "214", "fidelity": "070", "sterling": "232", "wema": "035", "alat": "035", "union bank": "032", "stanbic": "221", "polaris": "076", "ecobank": "050",
	"keystone": "082", "providus": "101", "kuda": "50211", "moniepoint": "50515", "opay": "999992", "palmpay": "999991",
}

var (
	bankWords = func() []string {
		out := make([]string, 0, len(bankCues))
		for w := range bankCues {
			out = append(out, w)
		}
		return out
	}()
	keywordMatcher = func() *matcher {
		ws := make([]string, 0, len(keywords)+len(bankWords))
		for _, k := range keywords {
			ws = append(ws, k.word)
		}
		return newMatcher(append(ws, bankWords...))
	}()
	mobileRe = regexp.MustCompile(`^(?:(?:702[0-24-9]|819[01])\d{6}|(?:7(?:0[13-9]|[12]\d)|8(?:0[1-9]|1[0-8])|9(?:0[1-9]|1[0-6]))\d{7})$`)
	vninRe   = regexp.MustCompile(`\b[A-Za-z]{2}\d{12}[A-Za-z]{2}\b`)
	payRefRe = regexp.MustCompile(`[A-Za-z0-9][A-Za-z0-9_-]{9,63}`)

	ownTokenRe = regexp.MustCompile(`tok_[a-z0-9_]+_[A-Za-z0-9]{8,}`)
	// Candidate shape only; mobileRe holds the numbering rule (libphonenumber's NG
	// mobile pattern, consistent with the NCC's allocation table of December 2023).
	phoneRe    = regexp.MustCompile(`(?:\+?234[ -]?(?:\(0\)[ -]?)?|0)[789]\d(?:[ -]?\d){8}`)
	digits11Re = regexp.MustCompile(`\d{11}|\d{3}[ -]\d{4}[ -]\d{4}|\d{2}[ -]\d{4}[ -]\d{5}`)
	digits10Re = regexp.MustCompile(`\d{10}|\d{3}[ -]\d{3}[ -]\d{4}`)
	cardRe     = regexp.MustCompile(`\d{13,19}|\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{1,7}|\d{4}[ -]\d{6}[ -]\d{4,5}`)
	emailRe    = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}`)
	amountRe   = regexp.MustCompile(`(?i)(₦|NGN)\s?\d[\d,]*(?:\.\d{1,2})?(?:\s?(?:k|m|bn|million|thousand|billion)\b)?|\bN\s?\d[\d,]*(?:\.\d{1,2})?(?:\s?(?:k|m|bn)\b)?|\d[\d,]*(?:\.\d{1,2})?\s?(?:k|m)?\s?naira\b`)
	shortAmtRe = regexp.MustCompile(`(?i)\b\d+(?:\.\d+)?\s?(?:k|m)\b`)
	dateRe     = regexp.MustCompile(`(?i)\b\d{4}-\d{2}-\d{2}\b|\b\d{1,2}[/-]\d{1,2}[/-]\d{4}\b|\b\d{1,2}(?:st|nd|rd|th)?[ -](?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\.?,?[ -]\d{4}\b|\b(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\.? \d{1,2},? \d{4}\b`)

	nameSet = func() map[string]bool {
		m := make(map[string]bool, len(commonNames))
		for _, n := range commonNames {
			m[n] = true
		}
		return m
	}()
)

const contextWindow = 40

type hit struct {
	pos, end int
	c        cue
	bank     string
}

// Engine is safe for concurrent use.
type Engine struct {
	cfg        Config
	emailAllow map[string]bool
}

// New builds an Engine.
// WithThresholds returns the config with a vault's tuned thresholds applied.
func (c Config) WithThresholds(t map[string]float64) Config {
	if len(t) == 0 {
		return c
	}
	merged := make(map[EntityType]float64, len(c.Thresholds)+len(t))
	for k, v := range c.Thresholds {
		merged[k] = v
	}
	for k, v := range t {
		merged[EntityType(k)] = v
	}
	c.Thresholds = merged
	return c
}

func New(cfg Config) *Engine {
	allow := map[string]bool{}
	for _, d := range cfg.AllowedEmailDomains {
		allow[strings.ToLower(d)] = true
	}
	return &Engine{cfg: cfg, emailAllow: allow}
}

func (e *Engine) threshold(t EntityType) float64 {
	if v, ok := e.cfg.Thresholds[t]; ok {
		return v
	}
	return 0.5
}

func isWordByte(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

func lowerASCII(s string) []byte {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return b
}

// contextBytes lower-cases text and folds "_" and "-" to spaces, keeping byte
// offsets, so date_of_birth and account-number match their keywords.
func contextBytes(s string) []byte {
	b := lowerASCII(s)
	for i, c := range b {
		if c == '_' || c == '-' {
			b[i] = ' '
		}
	}
	return b
}

func contextHits(lower []byte) []hit {
	var hits []hit
	keywordMatcher.scan(lower, func(idx, start, end int) {
		// Keywords must sit on word boundaries ("nin" not in "running").
		if start > 0 && isWordByte(lower[start-1]) {
			return
		}
		if end < len(lower) && isWordByte(lower[end]) {
			// allow plural/compound forms only for digits-free suffix "s"
			if !(lower[end] == 's' && (end+1 == len(lower) || !isWordByte(lower[end+1]))) {
				return
			}
		}
		if idx >= len(keywords) {
			hits = append(hits, hit{start, end, cueAcct, bankCues[bankWords[idx-len(keywords)]]})
			return
		}
		hits = append(hits, hit{start, end, keywords[idx].c, ""})
	})
	sort.Slice(hits, func(i, j int) bool { return hits[i].pos < hits[j].pos })
	return hits
}

// cueSet holds the effective distance to the nearest cue of each class; -1 is none.
type cueSet [16]int32

func (d *cueSet) get(c cue) (int, bool) {
	v := d[bits.TrailingZeros16(uint16(c))]
	return int(v), v >= 0
}

func (d *cueSet) has(c cue) bool { return d[bits.TrailingZeros16(uint16(c))] >= 0 }

// cueDistances finds each class's nearest cue. A cue after the value counts
// double: people write "BVN 221…" far more often than "221… is my BVN", and in
// "BVN 221… NIN 331…" the NIN cue must not claim the first number.
func cueDistances(hits []hit, start, end int) *cueSet {
	d := &cueSet{}
	for i := range d {
		d[i] = -1
	}
	lo := sort.Search(len(hits), func(i int) bool { return hits[i].end >= start-contextWindow })
	for i := lo; i < len(hits); i++ {
		h := hits[i]
		if h.pos > end+contextWindow {
			break
		}
		var dist int
		switch {
		case h.end <= start:
			dist = start - h.end
		case h.pos >= end:
			dist = (h.pos-end)*2 + 1
		default:
			continue
		}
		slot := bits.TrailingZeros16(uint16(h.c))
		if d[slot] < 0 || int32(dist) < d[slot] {
			d[slot] = int32(dist)
		}
	}
	return d
}

// nearestBank finds the closest named institution around a span.
func nearestBank(hits []hit, start, end int) string {
	best, code := contextWindow*3, ""
	lo := sort.Search(len(hits), func(i int) bool { return hits[i].end >= start-contextWindow })
	for i := lo; i < len(hits) && hits[i].pos <= end+contextWindow; i++ {
		if hits[i].bank == "" {
			continue
		}
		d := start - hits[i].end
		if hits[i].pos >= end {
			d = hits[i].pos - end
		}
		if d >= 0 && d < best {
			best, code = d, hits[i].bank
		}
	}
	return code
}

func nearer(d *cueSet, a cue, others ...cue) bool {
	da, ok := d.get(a)
	if !ok {
		return false
	}
	for _, o := range others {
		if do, ok := d.get(o); ok && do < da {
			return false
		}
	}
	return true
}

func digitsOnly(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// isolated reports whether a numeric span stands alone: not glued to another
// digit or letter, and not part of a decimal or a longer dashed/dotted number.
func isolated(text string, start, end int) bool {
	if start > 0 {
		c := text[start-1]
		if isWordByte(c) {
			return false
		}
		if c == '.' && start > 1 && text[start-2] >= '0' && text[start-2] <= '9' {
			return false
		}
		if c == '-' && hexSegmentBefore(text, start-1) {
			return false
		}
	}
	if end < len(text) {
		c := text[end]
		if isWordByte(c) {
			return false
		}
		if (c == '.' || c == '-') && end+1 < len(text) && text[end+1] >= '0' && text[end+1] <= '9' {
			return false
		}
	}
	return true
}

// hexSegmentBefore reports whether the segment ending at dash is all hex digits, as in
// a UUID or a longer dashed number. A real word does not count, so the number in
// "bvn-22333444558" or "customer-22333444558" still stands alone.
func hexSegmentBefore(text string, dash int) bool {
	i := dash
	for i > 0 && isWordByte(text[i-1]) {
		c := text[i-1]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
		i--
	}
	return i < dash
}

func clamp(f float64) float64 {
	if f > 0.99 {
		return 0.99
	}
	if f < 0 {
		return 0
	}
	return f
}

// Scan returns the entities in text that clear their threshold, sorted by
// position with overlaps resolved.
func (e *Engine) Scan(text string) []Entity {
	return e.ScanWithHint(text, "")
}

// ScanWithHint scans text as if hint (for example a JSON key) preceded it.
func (e *Engine) ScanWithHint(text, hint string) []Entity {
	if len(text) == 0 {
		return nil
	}
	hits := contextHits(contextBytes(text))
	if hint != "" {
		for _, h := range contextHits(contextBytes(strings.ReplaceAll(hint, ".", " "))) {
			hits = append(hits, hit{pos: -1, end: 0, c: h.c, bank: h.bank})
		}
		sort.SliceStable(hits, func(i, j int) bool { return hits[i].pos < hits[j].pos })
	}

	var skip [][2]int
	for _, m := range ownTokenRe.FindAllStringIndex(text, -1) {
		skip = append(skip, [2]int{m[0], m[1]})
	}
	// FindAll returns matches in order, so skip is sorted and disjoint.
	inSkip := func(s, t int) bool {
		i := sort.Search(len(skip), func(i int) bool { return skip[i][1] > s })
		return i < len(skip) && skip[i][0] < t
	}

	var out []Entity
	add := func(t EntityType, s, n int, score float64) {
		if inSkip(s, n) {
			return
		}
		if score = clamp(score); score >= e.threshold(t) {
			out = append(out, Entity{Type: t, Start: s, End: n, Score: score})
		}
	}

	hasDigit := false
	for i := 0; i < len(text); i++ {
		if text[i] >= '0' && text[i] <= '9' {
			hasDigit = true
			break
		}
	}

	if hasDigit {
		e.scanCards(text, hits, add)
		e.scanPhones(text, hits, add)
		e.scan11(text, hits, add)
		e.scan10(text, hits, add)
		e.scanAmounts(text, hits, add)
		e.scanDates(text, hits, add)
	}
	if strings.IndexByte(text, '@') >= 0 {
		for _, m := range emailRe.FindAllStringIndex(text, -1) {
			domain := strings.ToLower(text[m[0]:m[1]])
			domain = domain[strings.IndexByte(domain, '@')+1:]
			if !e.emailAllow[domain] {
				add(Email, m[0], m[1], 0.99)
			}
		}
	}
	e.scanNames(text, hits, add)
	e.scanRefs(text, hits, add, e.cfg.PaymentRefs)
	return resolveOverlaps(out)
}

type addFn func(t EntityType, start, end int, score float64)

func (e *Engine) scanCards(text string, hits []hit, add addFn) {
	for _, m := range cardRe.FindAllStringIndex(text, -1) {
		if !isolated(text, m[0], m[1]) {
			continue
		}
		n := digitsOnly(text[m[0]:m[1]])
		luhn := ValidLuhn(n)
		if len(n) < 13 || len(n) > 19 || (!luhn && !isVerve(n)) {
			continue
		}
		d := cueDistances(hits, m[0], m[1])
		score := 0.55
		switch {
		case luhn && knownCardBIN(n):
			score = 0.95
		case !luhn: // Verve-shaped, and Verve is not reliably Luhn-valid
			score = 0.6
		}
		if d.has(cueCard) {
			score += 0.1
		}
		if nearer(d, cueNeg, cueCard) {
			// A word like "order" does not excuse a number that passes Luhn on a real
			// card range: such a number is treated as a card, and is costly to miss.
			if luhn && knownCardBIN(n) {
				score -= 0.2
			} else {
				score -= 0.5
			}
		}
		add(CardPAN, m[0], m[1], score)
	}
}

func (e *Engine) scanPhones(text string, hits []hit, add addFn) {
	for _, m := range phoneRe.FindAllStringIndex(text, -1) {
		s := m[0]
		if !isolated(text, s, m[1]) {
			continue
		}
		d := cueDistances(hits, s, m[1])
		raw := text[s:m[1]]
		national := strings.TrimPrefix(digitsOnly(raw), "234")
		if strings.HasPrefix(national, "0") {
			national = national[1:]
		}
		if !mobileRe.MatchString(national) {
			continue
		}
		score := 0.75
		if raw[0] == '+' || strings.HasPrefix(raw, "234") {
			score = 0.97
		}
		if d.has(cuePhone) {
			score += 0.2
		}
		if nearer(d, cueNeg, cuePhone) {
			score -= 0.3
		}
		// A BVN or NIN can begin 080…; an explicit nearer cue beats the shape. A number
		// written in phone groups ("0803 123 4567") is never a BVN or NIN, so it stays.
		if raw == digitsOnly(raw) && len(raw) == 11 && (nearer(d, cueBVN, cuePhone, cueNIN) || nearer(d, cueNIN, cuePhone, cueBVN)) {
			continue
		}
		add(PhoneNG, s, m[1], score)
	}
}

func (e *Engine) scan11(text string, hits []hit, add addFn) {
	for _, m := range digits11Re.FindAllStringIndex(text, -1) {
		if !isolated(text, m[0], m[1]) {
			continue
		}
		n := digitsOnly(text[m[0]:m[1]])
		if e.isOwnFormatToken(n) {
			continue
		}
		d := cueDistances(hits, m[0], m[1])
		switch {
		case nearer(d, cueBVN, cueNIN, cueNeg, cuePhone):
			add(BVN, m[0], m[1], 0.97)
		case nearer(d, cueNIN, cueBVN, cueNeg, cuePhone):
			add(NIN, m[0], m[1], 0.95)
		case nearer(d, cueNeg, cueBVN, cueNIN):
			add(NG11Digit, m[0], m[1], 0.3)
		default:
			add(NG11Digit, m[0], m[1], 0.65)
		}
	}
}

func (e *Engine) isOwnFormatToken(n string) bool {
	if e.cfg.IsOwnToken == nil {
		return false
	}
	for _, p := range e.cfg.FormatPreservingPrefixes {
		if strings.HasPrefix(n, p) {
			return e.cfg.IsOwnToken(n)
		}
	}
	return false
}

func (e *Engine) scan10(text string, hits []hit, add addFn) {
	for _, m := range digits10Re.FindAllStringIndex(text, -1) {
		if !isolated(text, m[0], m[1]) {
			continue
		}
		n := digitsOnly(text[m[0]:m[1]])
		if e.isOwnFormatToken(n) {
			continue
		}
		d := cueDistances(hits, m[0], m[1])
		// A 10-digit phone without the leading 0, but only with a phone cue.
		if mobileRe.MatchString(n) && nearer(d, cuePhone, cueAcct, cueNeg) {
			add(PhoneNG, m[0], m[1], 0.85)
			continue
		}
		// With 300+ institution codes nearly any number passes for some bank, so the
		// check digit only carries weight against an institution named nearby.
		var score float64
		bank := nearestBank(hits, m[0], m[1])
		switch {
		case nearer(d, cueAcct, cueNeg) && bank != "":
			score = 0.8 // a named bank, but the check digit fails: possibly non-standard
			if ValidNUBANFor(bank, n) {
				score = 0.97
			}
		case nearer(d, cueAcct, cueNeg):
			score = 0.91
		case nearer(d, cueNeg, cueAcct):
			score = 0.1
		case n[0] == '1': // the usual shape of a Unix timestamp
			score = 0.2
		default:
			score = 0.55
		}
		add(NUBAN, m[0], m[1], score)
	}
}

func (e *Engine) scanAmounts(text string, hits []hit, add addFn) {
	for _, m := range amountRe.FindAllStringIndex(text, -1) {
		raw := text[m[0]:m[1]]
		d := cueDistances(hits, m[0], m[1])
		cued := d.has(cueAmount)
		score := 0.85
		if raw[0] == 'N' || raw[0] == 'n' {
			if strings.HasPrefix(strings.ToLower(raw), "ngn") {
				score = 0.9
			} else if len(digitsOnly(raw)) < 3 && !cued {
				continue // "N95", "N2": too ambiguous without a money cue
			} else {
				score = 0.75
			}
		}
		if cued {
			score += 0.1
		}
		add(AmountNGN, m[0], m[1], score)
	}
	// Shorthand such as "50k" and "2.5m" counts only next to a money word.
	for _, m := range shortAmtRe.FindAllStringIndex(text, -1) {
		d := cueDistances(hits, m[0], m[1])
		if d.has(cueAmount) {
			add(AmountNGN, m[0], m[1], 0.7)
		}
	}
}

func (e *Engine) scanDates(text string, hits []hit, add addFn) {
	for _, m := range dateRe.FindAllStringIndex(text, -1) {
		d := cueDistances(hits, m[0], m[1])
		if !d.has(cueDOB) {
			continue
		}
		year := yearOf(text[m[0]:m[1]])
		now := time.Now().Year()
		if year < now-120 || year > now-5 {
			continue
		}
		add(DOB, m[0], m[1], 0.92)
	}
}

func yearOf(s string) int {
	run, year := 0, 0
	for i := 0; i <= len(s); i++ {
		if i < len(s) && s[i] >= '0' && s[i] <= '9' {
			run++
			continue
		}
		if run == 4 {
			for _, c := range s[i-4 : i] {
				year = year*10 + int(c-'0')
			}
			return year
		}
		run = 0
	}
	return 0
}

// scanRefs finds virtual NINs and payment references, both of which need a cue.
func (e *Engine) scanRefs(text string, hits []hit, add addFn, refs bool) {
	hasVNIN, hasRef := false, false
	for _, h := range hits {
		hasVNIN = hasVNIN || h.c == cueVNIN
		hasRef = hasRef || h.c == cuePayRef
	}
	if hasVNIN {
		for _, m := range vninRe.FindAllStringIndex(text, -1) {
			if d := cueDistances(hits, m[0], m[1]); d.has(cueVNIN) {
				add(VNIN, m[0], m[1], 0.95)
			}
		}
	}
	if hasRef && refs {
		for _, m := range payRefRe.FindAllStringIndex(text, -1) {
			v := text[m[0]:m[1]]
			if digitsOnly(v) == "" {
				continue // a reference holds at least one digit; plain words do not count
			}
			d := cueDistances(hits, m[0], m[1])
			if dist, ok := d.get(cuePayRef); ok && dist <= 12 {
				add(PaymentRef, m[0], m[1], 0.6)
			}
		}
	}
}

type word struct {
	start, end int
	lower      string
	capital    bool
}

func (e *Engine) scanNames(text string, hits []hit, add addFn) {
	var words []word
	for i := 0; i < len(text); {
		r, size := utf8.DecodeRuneInString(text[i:])
		if !unicode.IsLetter(r) {
			i += size
			continue
		}
		start, first := i, r
		for i < len(text) {
			r, size = utf8.DecodeRuneInString(text[i:])
			if !unicode.IsLetter(r) && !(r == '\'' && i+1 < len(text) && text[i+1] != ' ') {
				break
			}
			i += size
		}
		// Words glued to digits or underscores are identifiers, not names.
		if start > 0 && (isWordByte(text[start-1]) || text[start-1] == '_') {
			continue
		}
		if i < len(text) && (text[i] >= '0' && text[i] <= '9' || text[i] == '_') {
			continue
		}
		words = append(words, word{start, i, strings.ToLower(text[start:i]), unicode.IsUpper(first)})
	}

	for i := 0; i < len(words); {
		w := words[i]
		if nameStopwords[w.lower] || !(w.capital || nameSet[w.lower]) {
			i++
			continue
		}
		// Grow a run of adjacent name-like words on the same line.
		j := i + 1
		for j < len(words) && j-i < 4 {
			nw := words[j]
			gap := text[words[j-1].end:nw.start]
			if !(gap == " " || gap == "-") || nameStopwords[nw.lower] {
				break
			}
			if !nw.capital && !nameSet[nw.lower] {
				break
			}
			if w.capital != nw.capital && !nameSet[nw.lower] {
				break
			}
			j++
		}
		start, end := w.start, words[j-1].end

		strong, weak := 0, 0
		for _, x := range words[i:j] {
			if nameSet[x.lower] {
				if ambiguousNames[x.lower] {
					weak++
				} else {
					strong++
				}
			}
		}
		d := cueDistances(hits, start, end)
		nameDist, hasName := d.get(cueName)
		hon, hasHon := d.get(cueHonorific)
		honAdjacent := hasHon && hon <= 2
		allCap := true
		for _, x := range words[i:j] {
			allCap = allCap && x.capital
		}
		count := j - i

		var score float64
		switch {
		case strong >= 2:
			score = 0.92
		case strong+weak >= 2 && strong >= 1:
			score = 0.85
		case honAdjacent && allCap:
			score = 0.85
		case strong == 1 && hasName:
			score = 0.8
		case hasName && allCap && count >= 2 && nameDist <= 12:
			score = 0.7
		case allCap && count >= 2 && strong == 0 && nameLike(words[i:j]) && hasName:
			score = 0.7
		case allCap && count >= 2 && strong == 1:
			score = 0.65 // one known name beside another capitalised word
		case strong == 1 && count == 1 && w.capital:
			score = 0.4
		default:
			score = 0
		}
		if score > 0 {
			add(PersonName, start, end, score)
		}
		i = j
	}
}

// namePrefixes and nameSuffixes are common Yoruba, Igbo, Hausa and Edo name parts.
// They stand in for a named-entity model, which would need training data that the
// spec rightly forbids taking from customers.
var (
	namePrefixes = []string{"ade", "ola", "olu", "oluwa", "ayo", "ife", "chi", "chukwu", "nwa", "obi", "uche", "oke", "abu", "ibra", "muham", "aba", "oghene", "ese", "eka", "ini"}
	nameSuffixes = []string{"chukwu", "dimma", "nna", "nwa", "yemi", "tunde", "wale", "bayo", "kunle", "seun", "ola", "ade", "ike", "emeka", "ndu", "ullahi", "arin", "anmi"}
)

func nameLike(ws []word) bool {
	for _, w := range ws {
		for _, p := range namePrefixes {
			if strings.HasPrefix(w.lower, p) && len(w.lower) > len(p)+1 {
				return true
			}
		}
		for _, p := range nameSuffixes {
			if strings.HasSuffix(w.lower, p) && len(w.lower) > len(p)+1 {
				return true
			}
		}
	}
	return false
}

// priority breaks ties between overlapping entities of equal score: the more
// specific interpretation wins.
var priority = map[EntityType]int{
	VNIN: 10, CardPAN: 9, Email: 8, BVN: 7, NIN: 7, PhoneNG: 6, NUBAN: 5, NG11Digit: 4, DOB: 3, AmountNGN: 2, PersonName: 1, PaymentRef: 0,
}

func resolveOverlaps(in []Entity) []Entity {
	if len(in) < 2 {
		return in
	}
	sort.SliceStable(in, func(i, j int) bool {
		a, b := in[i], in[j]
		if a.Score != b.Score {
			return a.Score > b.Score
		}
		if al, bl := a.End-a.Start, b.End-b.Start; al != bl {
			return al > bl
		}
		return priority[a.Type] > priority[b.Type]
	})
	// Kept spans stay sorted and disjoint, so overlap is a binary search. Quadratic
	// scanning let a 1 MiB line of numbers stall the engine for seconds.
	var kept []Entity
	for _, c := range in {
		i := sort.Search(len(kept), func(i int) bool { return kept[i].End > c.Start })
		if i < len(kept) && kept[i].Start < c.End {
			continue
		}
		kept = append(kept, Entity{})
		copy(kept[i+1:], kept[i:])
		kept[i] = c
	}
	return kept
}

// Replace rewrites text, substituting repl(e) for each entity. Entities must be
// sorted and non-overlapping, as Scan returns them.
func Replace(text string, entities []Entity, repl func(Entity, string) string) string {
	if len(entities) == 0 {
		return text
	}
	var b strings.Builder
	last := 0
	for _, e := range entities {
		b.WriteString(text[last:e.Start])
		b.WriteString(repl(e, text[e.Start:e.End]))
		last = e.End
	}
	b.WriteString(text[last:])
	return b.String()
}
