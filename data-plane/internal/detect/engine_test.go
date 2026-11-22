package detect

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func types(es []Entity, text string) map[string]EntityType {
	m := map[string]EntityType{}
	for _, e := range es {
		m[text[e.Start:e.End]] = e.Type
	}
	return m
}

func TestSpecExample(t *testing.T) {
	text := "Transfer of N250,000 to 0123456789 failed. My BVN na 22123456789"
	es := New(Config{}).Scan(text)
	if len(es) != 3 {
		t.Fatalf("want 3 entities, got %+v", es)
	}
	want := []struct {
		typ        EntityType
		start, end int
	}{{AmountNGN, 12, 20}, {NUBAN, 24, 34}, {BVN, 53, 64}}
	for i, w := range want {
		if es[i].Type != w.typ || es[i].Start != w.start || es[i].End != w.end {
			t.Errorf("entity %d = %+v, want %+v", i, es[i], w)
		}
	}
}

func TestTable(t *testing.T) {
	cases := []struct {
		text string
		want map[string]EntityType
	}{
		{"BVN 22123456789 NIN 31234567890", map[string]EntityType{"22123456789": BVN, "31234567890": NIN}},
		{"bvn_number=22123456789", map[string]EntityType{"22123456789": BVN}},
		{"call +234 803 123 4567 now", map[string]EntityType{"+234 803 123 4567": PhoneNG}},
		{"phone 08031234567", map[string]EntityType{"08031234567": PhoneNG}},
		{"My BVN is 08031234567", map[string]EntityType{"08031234567": BVN}},
		{"id 41234567890 on file", map[string]EntityType{"41234567890": NG11Digit}},
		{"pan 4111 1111 1111 1111", map[string]EntityType{"4111 1111 1111 1111": CardPAN}},
		{"my acct no be 0123456789", map[string]EntityType{"0123456789": NUBAN}},
		{"ts=1730000000 ok", map[string]EntityType{}},
		{"order 2345678901 shipped", map[string]EntityType{}},
		{"tok_bvn_7Hq2xP9LmA4cRt5YzX0a1b leaked? no", map[string]EntityType{}},
		{"N95 masks", map[string]EntityType{}},
		{"balance 50k", map[string]EntityType{"50k": AmountNGN}},
		{"running 22123456789 km", map[string]EntityType{"22123456789": NG11Digit}},
		{"dob: 14/03/1990", map[string]EntityType{"14/03/1990": DOB}},
		{"meeting on 14/03/1990", map[string]EntityType{}},
		{"Mrs Ngozi Okafor called", map[string]EntityType{"Ngozi Okafor": PersonName}},
		{"email ada@example.ng", map[string]EntityType{"ada@example.ng": Email}},
		{"uuid 550e8400-e29b-41d4-a716-446655440000", map[string]EntityType{}},
		{"bvn-22333444558", map[string]EntityType{"22333444558": BVN}},
		{"nin-33444555666", map[string]EntityType{"33444555666": NIN}},
		{"customer-22333444558 failed", map[string]EntityType{"22333444558": NG11Digit}},
		{"phone-08035551111", map[string]EntityType{"08035551111": PhoneNG}},
		{"id e29b-22333444558", map[string]EntityType{}},
		{"id 123-22333444558", map[string]EntityType{}},
	}
	e := New(Config{})
	for _, c := range cases {
		got := types(e.Scan(c.text), c.text)
		if len(got) != len(c.want) {
			t.Errorf("%q: got %v, want %v", c.text, got, c.want)
			continue
		}
		for k, v := range c.want {
			if got[k] != v {
				t.Errorf("%q: %q = %q, want %q", c.text, k, got[k], v)
			}
		}
	}
}

func TestOwnFormatTokenRequiresConfirmation(t *testing.T) {
	text := "bvn 99483120577"
	unconfirmed := New(Config{FormatPreservingPrefixes: []string{"99"}, IsOwnToken: func(string) bool { return false }})
	if len(unconfirmed.Scan(text)) != 1 {
		t.Fatal("an unconfirmed lookalike must stay sensitive")
	}
	confirmed := New(Config{FormatPreservingPrefixes: []string{"99"}, IsOwnToken: func(string) bool { return true }})
	if es := confirmed.Scan(text); len(es) != 0 {
		t.Fatalf("a confirmed token must be skipped, got %+v", es)
	}
}

func TestAllowedEmailDomain(t *testing.T) {
	e := New(Config{AllowedEmailDomains: []string{"support.example.ng"}})
	if es := e.Scan("from help@support.example.ng"); len(es) != 0 {
		t.Fatalf("got %+v", es)
	}
}

func TestReplace(t *testing.T) {
	text := "bvn 22123456789 end"
	got := Replace(text, New(Config{}).Scan(text), func(e Entity, _ string) string { return "[" + string(e.Type) + "]" })
	if got != "bvn [bvn] end" {
		t.Fatal(got)
	}
}

// Both worked examples in the CBN's Revised NUBAN Standards.
func TestNUBANOfficialExamples(t *testing.T) {
	if d := NUBANCheckDigit("011", "000001457"); d != 9 {
		t.Fatalf("DMB illustration: got %d, want 9", d)
	}
	if !ValidNUBANFor("011", "0000014579") {
		t.Fatal("DMB illustration account")
	}
	if d := NUBANCheckDigit("50547", "000021457"); d != 9 {
		t.Fatalf("OFI illustration: got %d, want 9", d)
	}
	if !ValidNUBANFor("50547", "0000214579") {
		t.Fatal("OFI illustration account")
	}
}

func TestInstitutionListLoaded(t *testing.T) {
	want := map[string]bool{"058": true, "50515": true, "999992": true, "999991": true, "50211": true}
	for _, i := range Institutions {
		delete(want, i.Code)
	}
	if len(want) != 0 || len(Institutions) < 200 {
		t.Fatalf("missing %v of %d", want, len(Institutions))
	}
}

func TestResearchedRules(t *testing.T) {
	gtb := "000000001" // a serial, completed with its GTB check digit
	account := gtb + string(rune('0'+NUBANCheckDigit("058", gtb)))
	cases := []struct {
		text string
		want map[string]EntityType
	}{
		{"call 07121234567", map[string]EntityType{"07121234567": PhoneNG}},               // 7[12]x, libphonenumber
		{"+234(0)8031234567", map[string]EntityType{"+234(0)8031234567": PhoneNG}},        // written with the trunk digit
		{"call 08001234567", map[string]EntityType{"08001234567": NG11Digit}},             // 0800 is VAS, not a mobile range
		{"verve 5061234567890123", map[string]EntityType{"5061234567890123": CardPAN}},    // no Luhn on Verve
		{"vNIN AB123456789012CD issued", map[string]EntityType{"AB123456789012CD": VNIN}}, // virtual NIN
		{"AB123456789012CD issued", map[string]EntityType{}},                              // shape alone is too weak
		{"rrn=000123456789 ok", map[string]EntityType{"000123456789": PaymentRef}},        // payment reference
		{"GTB account " + account, map[string]EntityType{account: NUBAN}},
	}
	e := New(Config{PaymentRefs: true})
	for _, c := range cases {
		got := types(e.Scan(c.text), c.text)
		if len(got) != len(c.want) {
			t.Errorf("%q: got %v, want %v", c.text, got, c.want)
			continue
		}
		for k, v := range c.want {
			if got[k] != v {
				t.Errorf("%q: %q = %q, want %q", c.text, k, got[k], v)
			}
		}
	}
	// Off by default: whether references are in scope is undecided.
	if es := New(Config{}).Scan("rrn=000123456789 ok"); len(es) != 0 {
		t.Errorf("payment references must be opt-in: %+v", es)
	}
	// A named bank raises confidence when its own check digit passes.
	pass, fail := e.Scan("GTB account "+account), e.Scan("GTB account 0000000000")
	if pass[0].Score <= fail[0].Score {
		t.Errorf("check digit should separate: %v %v", pass[0].Score, fail[0].Score)
	}
}

// family collapses types that are acceptable answers for a label: an unlabelled
// 11-digit id is still treated as sensitive when BVN or NIN cannot be told apart.
func family(t EntityType) EntityType {
	if t == NG11Digit {
		return BVN
	}
	return t
}

type tally struct{ tp, fp, fn int }

func (c tally) precision() float64 {
	if c.tp+c.fp == 0 {
		return 1
	}
	return float64(c.tp) / float64(c.tp+c.fp)
}
func (c tally) recall() float64 {
	if c.tp+c.fn == 0 {
		return 1
	}
	return float64(c.tp) / float64(c.tp+c.fn)
}

func measure(seed int64, n int) map[EntityType]*tally {
	stats := map[EntityType]*tally{}
	get := func(t EntityType) *tally {
		if stats[t] == nil {
			stats[t] = &tally{}
		}
		return stats[t]
	}
	engine, corpus := New(Config{}), NewCorpus(seed)
	for i := 0; i < n; i++ {
		s := corpus.Sample()
		found := engine.Scan(s.Text)
		used := make([]bool, len(found))
		for _, l := range s.Labels {
			matched := false
			for j, f := range found {
				if !used[j] && f.Start == l.Start && f.End == l.End && (f.Type == l.Type || (f.Type == NG11Digit && (l.Type == BVN || l.Type == NIN))) {
					used[j], matched = true, true
					break
				}
			}
			if matched {
				get(l.Type).tp++
			} else {
				get(l.Type).fn++
			}
		}
		for j, f := range found {
			if !used[j] {
				get(family(f.Type)).fp++
			}
		}
	}
	return stats
}

// TestQualityTargets enforces the spec's recall and precision targets on the
// synthetic corpus. The corpus is written by the same hands as the rules, so
// passing it is necessary, not sufficient; design-partner samples are the real test.
func TestQualityTargets(t *testing.T) {
	targets := map[EntityType][2]float64{
		CardPAN: {.99, .98}, NUBAN: {.97, .95}, BVN: {.97, .95}, NIN: {.97, .95}, PhoneNG: {.97, .95}, Email: {.99, .99}, PersonName: {.85, .85},
	}
	stats := measure(42, 20000)
	var report strings.Builder
	for typ, c := range stats {
		fmt.Fprintf(&report, "%-14s recall %.4f precision %.4f (tp=%d fp=%d fn=%d)\n", typ, c.recall(), c.precision(), c.tp, c.fp, c.fn)
	}
	t.Log("\n" + report.String())
	for typ, want := range targets {
		c := stats[typ]
		if c == nil {
			t.Errorf("%s: no samples", typ)
			continue
		}
		if c.recall() < want[0] {
			t.Errorf("%s recall %.4f < %.2f", typ, c.recall(), want[0])
		}
		if c.precision() < want[1] {
			t.Errorf("%s precision %.4f < %.2f", typ, c.precision(), want[1])
		}
	}
}

func FuzzScanNeverPanics(f *testing.F) {
	f.Add("bvn 22123456789 ₦50,000 +2348031234567 a@b.co")
	f.Add(strings.Repeat("0 ", 5000))
	f.Fuzz(func(t *testing.T, s string) {
		for _, e := range New(Config{}).Scan(s) {
			if e.Start < 0 || e.End > len(s) || e.Start >= e.End {
				t.Fatalf("bad span %+v", e)
			}
		}
	})
}

func BenchmarkScan1KB(b *testing.B) {
	corpus := NewCorpus(7)
	var sb strings.Builder
	for sb.Len() < 1024 {
		sb.WriteString(corpus.Sample().Text + " ")
	}
	text := sb.String()[:1024]
	e := New(Config{})
	b.SetBytes(int64(len(text)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.Scan(text)
	}
}

// Regression for penetration test finding D2: flooding must stay near linear.
func TestFloodsStayFast(t *testing.T) {
	e := New(Config{})
	for name, text := range map[string]string{
		"digits":  strings.Repeat("0123456789 ", 95000),
		"cued":    strings.Repeat("acct 0123456789 ", 65000),
		"tokens":  strings.Repeat("tok_a_AAAAAAAA 0123456789 ", 40000),
		"cues":    strings.Repeat("ref bvn nin ", 87000) + "22123456789",
		"amounts": strings.Repeat("N250,000 ", 110000),
	} {
		start := time.Now()
		e.Scan(text)
		if d := time.Since(start); d > 3*time.Second {
			t.Errorf("%s took %s", name, d)
		}
	}
}

// A negative cue must not excuse a real card number; a shape that only resembles one still may.
func TestNegativeCueDoesNotExcuseACard(t *testing.T) {
	e := New(Config{})
	for _, cue := range []string{"order", "ticket", "ref", "invoice", "session"} {
		found := false
		for _, x := range e.Scan(cue + " 4111111111111111") {
			found = found || x.Type == CardPAN
		}
		if !found {
			t.Errorf("%s: card missed", cue)
		}
	}
}

// A phone written in groups next to a BVN is still a phone; bare 11 digits next to
// "BVN" stay a BVN, never a phone.
func TestGroupedPhoneNextToBVN(t *testing.T) {
	e := New(Config{})
	got := e.Scan("Her BVN is 22123456789 and her number is 0803 123 4567.")
	if len(got) != 2 || got[0].Type != BVN || got[1].Type != PhoneNG {
		t.Fatalf("got %v", got)
	}
	for _, ent := range e.Scan("BVN: 08031234567") {
		if ent.Type == PhoneNG {
			t.Fatalf("bare digits after BVN must not be a phone: %v", ent)
		}
	}
}
