package detect

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"
)

var listKey = []byte("0123456789abcdef0123456789abcdef")

func rs(t testing.TB, defs ...CustomDef) *RuleSet {
	t.Helper()
	for i := range defs {
		if defs[i].Status == "" {
			defs[i].Status = "enforcing"
		}
		if defs[i].Version == 0 {
			defs[i].Version = 3
		}
		if defs[i].Threshold == 0 {
			defs[i].Threshold = 0.7
		}
	}
	r, err := NewRuleSet(New(Config{}), 9, defs, listKey)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func hashes(values ...string) (out [][]byte, words int) {
	for _, v := range values {
		n := NormalizeListValue(v)
		out = append(out, ListHMAC(listKey, n))
		if w := len(strings.Fields(n)); w > words {
			words = w
		}
	}
	return out, words
}

func got(text string, ents []Entity) map[string]string {
	m := map[string]string{}
	for _, e := range ents {
		m[text[e.Start:e.End]] = string(e.Type)
	}
	return m
}

func wantHit(t *testing.T, r *RuleSet, text, value, slug string) Entity {
	t.Helper()
	for _, e := range r.Scan(text) {
		if text[e.Start:e.End] == value && string(e.Type) == slug {
			return e
		}
	}
	t.Fatalf("%q: wanted %q as %s, got %v", text, value, slug, got(text, r.Scan(text)))
	return Entity{}
}

func wantNone(t *testing.T, r *RuleSet, text, slug string) {
	t.Helper()
	for _, e := range r.Scan(text) {
		if string(e.Type) == slug {
			t.Fatalf("%q: did not want %s, found %q", text, slug, text[e.Start:e.End])
		}
	}
}

func TestKeywordList(t *testing.T) {
	off := false
	r := rs(t,
		CustomDef{Slug: "c_project", Kind: KindKeywordList, Definition: Definition{Terms: []string{"Project Ember", "PLAT-X"}}},
		CustomDef{Slug: "c_exact", Kind: KindKeywordList, Definition: Definition{Terms: []string{"Kobo"}, CaseSensitive: true}},
		CustomDef{Slug: "c_part", Kind: KindKeywordList, Definition: Definition{Terms: []string{"zeb"}, WholeWord: &off}},
	)
	wantHit(t, r, "status of project ember is green", "project ember", "c_project")
	wantHit(t, r, "tier PLAT-X customer", "PLAT-X", "c_project")
	wantNone(t, r, "tier XPLAT-X1 customer", "c_project")
	wantHit(t, r, "pay Kobo now", "Kobo", "c_exact")
	wantNone(t, r, "pay kobo now", "c_exact")
	wantHit(t, r, "a zebra", "zeb", "c_part")
	if e := wantHit(t, r, "pay Kobo now", "Kobo", "c_exact"); e.Score < 0.89 || !e.Custom || e.EntityVersion != 3 {
		t.Fatalf("%+v", e)
	}
}

func TestPatternScoring(t *testing.T) {
	loan := CustomDef{Slug: "c_loan_id", Kind: KindPattern, Definition: Definition{Regex: `LN-\d{8}`}, Validator: &Validator{Type: "length", Value: 11}, ContextPositive: []string{"loan", "repayment"}, ContextNegative: []string{"invoice"}}
	r := rs(t, loan)
	if e := wantHit(t, r, "see LN-00412873 today", "LN-00412873", "c_loan_id"); e.Score < 0.89 || e.Score > 0.91 {
		t.Fatalf("base plus validator: %v", e.Score)
	}
	if e := wantHit(t, r, "repayment on LN-00412873 is late", "LN-00412873", "c_loan_id"); e.Score < 0.99 {
		t.Fatalf("with context: %v", e.Score)
	}
	// The spec's own must-not-match sample.
	wantNone(t, r, "invoice INV-00412873 paid", "c_loan_id")
	// Without a validator, a bare pattern sits at 0.6, under the default threshold.
	bare := rs(t, CustomDef{Slug: "c_bare", Kind: KindPattern, Definition: Definition{Regex: `ZZ\d{4}`}, ContextPositive: []string{"ref"}})
	wantNone(t, bare, "ZZ1234", "c_bare")
	wantHit(t, bare, "ref ZZ1234", "ZZ1234", "c_bare")
	// A negative word takes a validated match below the line only when it has to.
	neg := rs(t, CustomDef{Slug: "c_neg", Kind: KindPattern, Threshold: 0.8, Definition: Definition{Regex: `AB\d{4}`}, Validator: &Validator{Type: "length", Value: 6}, ContextNegative: []string{"sample"}})
	wantHit(t, neg, "real AB1234", "AB1234", "c_neg")
	wantNone(t, neg, "sample AB1234", "c_neg")
}

func TestValidators(t *testing.T) {
	for _, c := range []struct {
		v     Validator
		value string
		want  bool
	}{
		{Validator{Type: "length", Value: 3}, "abc", true},
		{Validator{Type: "length", Value: 3}, "abcd", false},
		{Validator{Type: "prefix_list", Values: []string{"LN", "AC"}}, "AC12", true},
		{Validator{Type: "prefix_list", Values: []string{"LN"}}, "XX12", false},
		{Validator{Type: "luhn"}, "4111111111111111", true},
		{Validator{Type: "luhn"}, "4111111111111112", false},
		{Validator{Type: "mod11"}, "123456785", true},
		{Validator{Type: "mod11"}, "123456782", false},
		// Weights 3,7,3 repeating: the body 000001457 sums to 71, so the check digit is 9.
		{Validator{Type: "custom_checksum", Weights: []int{3, 7, 3, 3, 7, 3, 3, 7, 3}, Modulus: 10, CheckPosition: -1}, "0000014579", true},
		{Validator{Type: "custom_checksum", Weights: []int{3, 7, 3, 3, 7, 3, 3, 7, 3}, Modulus: 10, CheckPosition: -1}, "0000014578", false},
		{Validator{Type: "custom_checksum", Weights: []int{1}, Modulus: 10}, "1236", false},
		{Validator{Type: "custom_checksum", Weights: []int{1}, Modulus: 10}, "1234", true},
	} {
		if RunValidator(&c.v, c.value) != c.want {
			t.Errorf("%+v on %q: wanted %v", c.v, c.value, c.want)
		}
	}
}

func TestAfterKeyword(t *testing.T) {
	r := rs(t, CustomDef{Slug: "c_pin", Kind: KindAfterKeyword, Definition: Definition{Cues: []string{"PIN", "password"}, MaxLength: 8}})
	wantHit(t, r, "my PIN: 1234 ok", "1234", "c_pin")
	wantHit(t, r, "password=hunter2&x=1", "hunter2", "c_pin")
	wantHit(t, r, "pin 123456789012", "12345678", "c_pin")
	wantNone(t, r, "spinning wheel", "c_pin")
	wantNone(t, r, "the PIN:", "c_pin")
	// A multi-byte character must not be split at the length limit.
	e := wantHit(t, r, "PIN: ₦₦₦₦₦₦₦₦₦₦", "₦₦₦₦₦₦₦₦", "c_pin")
	if e.End-e.Start != 24 {
		t.Fatal(e)
	}
}

func TestValueList(t *testing.T) {
	vals, words := hashes("Chidi Benson Okoro", "ACME01", "Ada")
	r := rs(t, CustomDef{Slug: "c_vip", Kind: KindValueList, Values: vals, MaxWords: words})
	e := wantHit(t, r, "called CHIDI  benson okoro, today", "CHIDI  benson okoro", "c_vip")
	if e.Score != 1 {
		t.Fatal(e)
	}
	wantHit(t, r, "merchant:ACME01 paid", "ACME01", "c_vip")
	wantHit(t, r, "(acme01)", "acme01", "c_vip")
	wantNone(t, r, "chidi benson", "c_vip")
	wantNone(t, r, "ACME011 and ACME0", "c_vip")
	if !r.Validate("c_vip", "acme01") || r.Validate("c_vip", "nope") {
		t.Fatal("validate")
	}
}

func TestJSONPath(t *testing.T) {
	r := rs(t, CustomDef{Slug: "c_staff", Kind: KindJSONPath, Definition: Definition{Paths: []string{"$.loan.collateral_ref", "$..staffId", "$.items[*].sku"}}})
	for path, want := range map[string]bool{"$.loan.collateral_ref": true, "$.a.b.staffId": true, "$.staffId": true, "$.items.sku": true, "$.loan.other": false, "$.x.loan.collateral_ref": false, "": false} {
		ents := r.ScanLeaf(path, "value-1", "")
		if (len(ents) == 1) != want {
			t.Errorf("%q: %v", path, ents)
		}
	}
	if len(r.Scan("staffId value-1")) != 0 {
		t.Fatal("a path applies only to structured payloads")
	}
	for _, bad := range []string{"x.y", "$", "$.", "$.a[0", "$.a..", "$a"} {
		if err := CheckDefinition(&CustomDef{Slug: "c_x", Kind: KindJSONPath, Definition: Definition{Paths: []string{bad}}}); err == nil {
			t.Errorf("%q should be refused", bad)
		}
	}
}

func TestOverlapRules(t *testing.T) {
	// The longer span wins: the custom one swallows a built-in 11-digit id.
	r := rs(t, CustomDef{Slug: "c_ref", Kind: KindPattern, Threshold: 0.5, Definition: Definition{Regex: `REF-\d{11}`}})
	wantHit(t, r, "see REF-22333444558", "REF-22333444558", "c_ref")
	// Same span, same score: the custom entity wins.
	k := rs(t, CustomDef{Slug: "c_mail", Kind: KindKeywordList, Threshold: 0.5, Definition: Definition{Terms: []string{"a.b@example.ng"}}})
	base := New(Config{}).Scan("mail a.b@example.ng")
	if len(base) != 1 {
		t.Fatal(base)
	}
	ents := mergeOverlaps(base, []Entity{{Type: "c_mail", Start: base[0].Start, End: base[0].End, Score: base[0].Score, Custom: true}})
	if len(ents) != 1 || !ents[0].Custom {
		t.Fatal(ents)
	}
	_ = k
	// A shorter custom span loses to a longer built-in.
	s := rs(t, CustomDef{Slug: "c_short", Kind: KindKeywordList, Definition: Definition{Terms: []string{"example"}}})
	if m := got("a.b@example.ng", s.Scan("a.b@example.ng")); m["a.b@example.ng"] != "email" {
		t.Fatal(m)
	}
}

func TestOwnTokensAreSkipped(t *testing.T) {
	r := rs(t, CustomDef{Slug: "c_any", Kind: KindKeywordList, Threshold: 0.1, Definition: Definition{Terms: []string{"abcdefgh"}, WholeWord: new(bool)}})
	for _, tok := range []string{"tok_c_loan_id_abcdefghABCDEFGH1234", "tok_bvn_abcdefghABCDEFGH1234"} {
		if ents := r.Scan("value " + tok); len(ents) != 0 {
			t.Errorf("%s: %+v", tok, ents)
		}
	}
	if e := New(Config{}).Scan("tok_c_loan_id_22333444558aaaaaaa"); len(e) != 0 {
		t.Errorf("built-ins must skip custom tokens too: %+v", e)
	}
}

func TestShadowAndModuleActions(t *testing.T) {
	r := rs(t,
		CustomDef{Slug: "c_s", Kind: KindKeywordList, Status: "shadow", Definition: Definition{Terms: []string{"shade"}}},
		CustomDef{Slug: "c_e", Kind: KindKeywordList, Definition: Definition{Terms: []string{"live"}}, Actions: map[string]string{"logs": "drop"}},
	)
	active, shadow := r.Split(r.Scan("shade live bvn 22123456789"))
	if len(shadow) != 1 || string(shadow[0].Type) != "c_s" || len(active) != 2 {
		t.Fatalf("%v %v", active, shadow)
	}
	live := Entity{Type: "c_e"}
	if r.ModuleAction(live, "logs") != "drop" || r.ModuleAction(live, "api") != "tokenize" || r.ModuleAction(Entity{Type: BVN}, "logs") != "" {
		t.Fatal("actions")
	}
}

func TestDefinitionsRefused(t *testing.T) {
	for name, c := range map[string]struct {
		d    CustomDef
		code string
	}{
		"bad regex":   {CustomDef{Kind: KindPattern, Definition: Definition{Regex: `(`}}, "invalid_regex"},
		"not RE2":     {CustomDef{Kind: KindPattern, Definition: Definition{Regex: `(?=x)y`}}, "invalid_regex"},
		"backref":     {CustomDef{Kind: KindPattern, Definition: Definition{Regex: `(a)\1`}}, "invalid_regex"},
		"empty match": {CustomDef{Kind: KindPattern, Definition: Definition{Regex: `\d*`}}, "entity_too_broad"},
		"empty term":  {CustomDef{Kind: KindKeywordList, Definition: Definition{Terms: []string{" "}}}, "entity_too_broad"},
		"no cues":     {CustomDef{Kind: KindAfterKeyword}, "invalid_request"},
	} {
		err := CheckDefinition(&c.d)
		de, ok := err.(*DefinitionError)
		if !ok || de.Code != c.code {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// Whatever a customer writes and whatever arrives, the engine must finish and return
// sorted, disjoint spans inside the text.
func FuzzRuleSet(f *testing.F) {
	for _, s := range []string{"PIN: 1234", "LN-00412873", "tok_c_x_abcdefgh", "₦₦₦ \xff\xfe", "", "a.b@example.ng", strings.Repeat("9", 500)} {
		f.Add(s, `LN-\d+`)
	}
	f.Fuzz(func(t *testing.T, text, regex string) {
		vals, words := hashes("ada", "chidi okoro")
		defs := []CustomDef{
			{Slug: "c_kw", Kind: KindKeywordList, Threshold: 0.1, Status: "enforcing", Definition: Definition{Terms: []string{"pin", "a"}}},
			{Slug: "c_after", Kind: KindAfterKeyword, Threshold: 0.1, Status: "enforcing", Definition: Definition{Cues: []string{"pin"}}},
			{Slug: "c_vals", Kind: KindValueList, Status: "enforcing", Values: vals, MaxWords: words},
		}
		if err := CheckDefinition(&CustomDef{Kind: KindPattern, Definition: Definition{Regex: regex}}); err == nil {
			defs = append(defs, CustomDef{Slug: "c_re", Kind: KindPattern, Threshold: 0.1, Status: "enforcing", Definition: Definition{Regex: regex}})
		}
		r, err := NewRuleSet(New(Config{}), 1, defs, listKey)
		if err != nil {
			t.Fatal(err)
		}
		last := 0
		for _, e := range r.ScanLeaf("$.a", text, "") {
			if e.Start < last || e.End > len(text) || e.Start >= e.End {
				t.Fatalf("bad span %+v of %d, last %d", e, len(text), last)
			}
			last = e.End
		}
	})
}

// Random regexes over random text: nothing hangs, nothing crashes. RE2 guarantees the
// first; this confirms the code around it.
func TestRandomRegexesFinish(t *testing.T) {
	src := rand.New(rand.NewSource(1))
	atoms := []string{"a", "b", `\d`, `\w`, ".", "(a|b)", "[A-Z]", "x*", "y+", "(z?)", "^", "$", `\b`, "-"}
	text := strings.Repeat("aXb-12 zy LN-00412873 \n", 2000)
	start := time.Now()
	compiled := 0
	for i := 0; i < 300; i++ {
		var b strings.Builder
		for j := 0; j <= src.Intn(8); j++ {
			b.WriteString(atoms[src.Intn(len(atoms))])
		}
		if CheckDefinition(&CustomDef{Kind: KindPattern, Definition: Definition{Regex: b.String()}}) != nil {
			continue
		}
		compiled++
		r := rs(t, CustomDef{Slug: "c_re", Kind: KindPattern, Threshold: 0.1, Definition: Definition{Regex: b.String()}})
		r.Scan(text)
	}
	if compiled < 100 {
		t.Fatal(compiled)
	}
	t.Logf("%d regexes in %v", compiled, time.Since(start))
}

func entities200(t testing.TB) []CustomDef {
	vals, words := hashes("chidi okoro", "ada obi", "merchant one")
	var defs []CustomDef
	for i := 0; i < 200; i++ {
		d := CustomDef{Slug: fmt.Sprintf("c_e%03d", i), Status: "enforcing", Version: 1, Threshold: 0.7}
		switch {
		case i < 50:
			d.Kind, d.Definition = KindPattern, Definition{Regex: fmt.Sprintf(`X%02d-\d{6}`, i)}
		case i < 100:
			d.Kind, d.Definition = KindKeywordList, Definition{Terms: []string{fmt.Sprintf("codename%d", i)}}
		case i < 150:
			d.Kind, d.Definition = KindAfterKeyword, Definition{Cues: []string{fmt.Sprintf("secret%d", i)}}
		case i < 180:
			d.Kind, d.Values, d.MaxWords = KindValueList, vals, words
		default:
			d.Kind, d.Definition = KindJSONPath, Definition{Paths: []string{fmt.Sprintf("$..f%d", i)}}
		}
		defs = append(defs, d)
	}
	return defs
}

// Acceptance criterion 9: with 200 custom entities active, added latency per line stays
// under 2 ms at p95. This runs on the engine alone, on one core.
func TestTwoHundredEntitiesStayUnderTwoMillisecondsPerLine(t *testing.T) {
	if testing.Short() {
		t.Skip("timing")
	}
	r, err := NewRuleSet(New(Config{}), 1, entities200(t), listKey)
	if err != nil {
		t.Fatal(err)
	}
	gen := NewCorpus(7)
	lat := make([]time.Duration, 0, 5000)
	for i := 0; i < 5000; i++ {
		line := gen.Sample().Text
		s := time.Now()
		r.ScanLeaf("$.log.message", line, "message")
		lat = append(lat, time.Since(s))
	}
	sortDur(lat)
	p95 := lat[len(lat)*95/100]
	t.Logf("p50 %v, p95 %v, p99 %v", lat[len(lat)/2], p95, lat[len(lat)*99/100])
	if p95 > 2*time.Millisecond {
		t.Fatalf("p95 %v", p95)
	}
}

func sortDur(d []time.Duration) {
	for i := 1; i < len(d); i++ {
		for j := i; j > 0 && d[j] < d[j-1]; j-- {
			d[j], d[j-1] = d[j-1], d[j]
		}
	}
}

// The stored hash is of NormalizeListValue, so the fast path must agree exactly, or a
// list member would silently stop matching.
func TestFastNormalizeAgrees(t *testing.T) {
	src := rand.New(rand.NewSource(3))
	alphabet := " \t\n\r\v\fAbZz09.,-_'\"$+<=>^`|~()[]{}!?:;@#%&*/\\\x01\x7f"
	for i := 0; i < 200000; i++ {
		b := make([]byte, src.Intn(24))
		for j := range b {
			b[j] = alphabet[src.Intn(len(alphabet))]
		}
		got, ok := appendNormalizedASCII(nil, string(b))
		if !ok {
			t.Fatalf("%q should be handled", b)
		}
		if want := NormalizeListValue(string(b)); string(got) != want {
			t.Fatalf("%q: fast %q, slow %q", b, got, want)
		}
	}
	if _, ok := appendNormalizedASCII(nil, "caf\u00e9"); ok {
		t.Fatal("non-ASCII must fall back")
	}
}

func BenchmarkValueListScan(b *testing.B) {
	for _, size := range []int{1000, 100000} {
		values := make([]string, size)
		for i := range values {
			values[i] = fmt.Sprintf("Customer Number %d", i)
		}
		vals, words := hashes(values...)
		r := rs(b, CustomDef{Slug: "c_v", Kind: KindValueList, Values: vals, MaxWords: words})
		line := strings.Repeat("transfer failed for account holder with reference abc123 at the lagos branch today ", 13)[:1024]
		b.Run(fmt.Sprintf("%d values, 1 KB", size), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				r.scanCustom(line, "", "")
			}
		})
	}
}

// A bare 11-digit number after "order", "ref", "ticket" or "invoice" passes the built-in
// detectors on purpose. docs/custom-entities.md tells a customer who wants it caught to
// use this rule, so the recipe itself is what is tested here.
func TestBareNumberAfterBusinessWordRecipe(t *testing.T) {
	r := rs(t, CustomDef{
		Slug:            "c_bare_ref",
		Kind:            "pattern",
		Definition:      Definition{Regex: `\b\d{11}\b`},
		ContextPositive: []string{"order", "ref", "ticket", "invoice"},
	})
	const v = "22555566671"
	for _, text := range []string{
		"order " + v,
		"support ticket " + v,
		"invoice: " + v,
		`{"ref": "` + v + `"}`,
		`<payment ref="` + v + `"/>`,
		"https://x.test/pay?ref=" + v,
	} {
		wantHit(t, r, text, v, "c_bare_ref")
	}
	for _, text := range []string{
		"the balance was " + v,
		"order 2255556667",
		"order 225555666712",
	} {
		wantNone(t, r, text, "c_bare_ref")
	}
}

func TestPacksLimitBuiltIns(t *testing.T) {
	text := "BVN 22123456789, email ada@example.com, acct 0123456789"
	all := BaseRuleSet(New(Config{})).ScanFor("ai", "", text, "")
	de := BaseRuleSet(New(Config{})).WithPacks("DE", []string{"everywhere", "eu"}).ScanFor("ai", "", text, "")
	ng := BaseRuleSet(New(Config{})).WithPacks("NG", []string{"everywhere", "ng"}).ScanFor("ai", "", text, "")
	if len(all) != 3 || len(ng) != 3 {
		t.Fatalf("all %v ng %v", all, ng)
	}
	if len(de) != 1 || de[0].Type != Email {
		t.Fatalf("a German vault without the Nigeria pack must not flag BVNs or NUBANs: %v", de)
	}
	if BaseRuleSet(New(Config{})).WithPacks("", nil).allowed != nil {
		t.Fatal("nil packs keep every type")
	}
}
