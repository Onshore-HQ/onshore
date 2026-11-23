package detect

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"onshore/data-plane/internal/mask"
)

// Entity kinds a customer can define.
const (
	KindKeywordList  = "keyword_list"
	KindPattern      = "pattern"
	KindAfterKeyword = "after_keyword"
	KindValueList    = "value_list"
	KindJSONPath     = "json_path"
)

// Limits that keep a single definition from becoming expensive to hold or compile.
const (
	maxRegexLen    = 2000
	maxTerms       = 5000
	maxTermLen     = 200
	maxPaths       = 100
	customContext  = 40 // characters either side
	defaultCapture = 64
	maxCapture     = 512
	// ValueListKeyLabel derives the list key, so that services which match lists never
	// hold the vault's blind-index key itself.
	ValueListKeyLabel = "rv-custom-value-list-v1"
	// MaxValueLength is the longest accepted value-list member, in characters.
	MaxValueLength = 200
)

// Definition holds what a custom entity matches. Which fields apply depends on the kind.
type Definition struct {
	Terms         []string `json:"terms,omitempty"`
	CaseSensitive bool     `json:"case_sensitive,omitempty"`
	WholeWord     *bool    `json:"whole_word,omitempty"`
	Regex         string   `json:"regex,omitempty"`
	Cues          []string `json:"cues,omitempty"`
	MaxLength     int      `json:"max_length,omitempty"`
	StopChars     string   `json:"stop_chars,omitempty"`
	Paths         []string `json:"paths,omitempty"`
}

// Validator is a fixed menu. Customers cannot supply executable logic.
type Validator struct {
	Type          string   `json:"type"`
	Value         int      `json:"value,omitempty"`
	Values        []string `json:"values,omitempty"`
	Weights       []int    `json:"weights,omitempty"`
	Modulus       int      `json:"modulus,omitempty"`
	CheckPosition int      `json:"check_position,omitempty"`
}

// MaskRule says how a custom value is shown when it is masked.
type MaskRule struct {
	Type string `json:"type"`
	N    int    `json:"n,omitempty"`
	Text string `json:"text,omitempty"`
}

// String is the form kept in vault_fields.mask_rule.
func (m MaskRule) String() string {
	switch m.Type {
	case "last_n", "first_n":
		return fmt.Sprintf("%s:%d", m.Type, m.N)
	case "fixed":
		return "fixed:" + m.Text
	case "full":
		return "full"
	}
	return "last_n:4"
}

// CustomDef is one custom entity as a rule set sees it.
type CustomDef struct {
	ID              string            `json:"id"`
	Slug            string            `json:"slug"`
	Name            string            `json:"name"`
	Kind            string            `json:"kind"`
	Definition      Definition        `json:"definition"`
	Validator       *Validator        `json:"validator,omitempty"`
	ContextPositive []string          `json:"context_positive,omitempty"`
	ContextNegative []string          `json:"context_negative,omitempty"`
	Threshold       float64           `json:"threshold"`
	TokenKind       string            `json:"token_kind,omitempty"`
	TokenFormat     string            `json:"token_format,omitempty"`
	MaskRule        MaskRule          `json:"mask_rule"`
	Actions         map[string]string `json:"actions,omitempty"`
	Status          string            `json:"status"`
	Version         int               `json:"version"`
	// Values are keyed hashes of list members, for value_list only.
	Values [][]byte `json:"-"`
	// MaxWords is the word count of the longest list member.
	MaxWords int `json:"max_words,omitempty"`
}

// DefinitionError names the spec's error code for a definition that cannot compile.
type DefinitionError struct {
	Code    string
	Message string
}

func (e *DefinitionError) Error() string { return e.Message }

func badDef(code, format string, a ...any) error {
	return &DefinitionError{Code: code, Message: fmt.Sprintf(format, a...)}
}

type compiled struct {
	def       *CustomDef
	re        *regexp.Regexp
	prefix    string
	wholeWord bool
	stop      string
	maxLen    int
	paths     [][]string
	pos, neg  []string
}

func wholeWord(d *Definition) bool { return d.WholeWord == nil || *d.WholeWord }

// compileCustom validates a definition. Regexes are RE2, so none can backtrack badly.
func compileCustom(d *CustomDef) (*compiled, error) {
	c := &compiled{def: d, wholeWord: wholeWord(&d.Definition)}
	for _, w := range d.ContextPositive {
		c.pos = append(c.pos, strings.ToLower(w))
	}
	for _, w := range d.ContextNegative {
		c.neg = append(c.neg, strings.ToLower(w))
	}
	switch d.Kind {
	case KindKeywordList:
		if len(d.Definition.Terms) == 0 || len(d.Definition.Terms) > maxTerms {
			return nil, badDef("invalid_request", "a keyword list needs between 1 and %d terms", maxTerms)
		}
		for _, t := range d.Definition.Terms {
			if strings.TrimSpace(t) == "" || len(t) > maxTermLen {
				return nil, badDef("entity_too_broad", "a term is empty or longer than %d characters", maxTermLen)
			}
		}
	case KindPattern:
		if d.Definition.Regex == "" || len(d.Definition.Regex) > maxRegexLen {
			return nil, badDef("invalid_regex", "the pattern must be between 1 and %d characters", maxRegexLen)
		}
		re, err := regexp.Compile(d.Definition.Regex)
		if err != nil {
			return nil, badDef("invalid_regex", "not valid RE2 syntax")
		}
		if re.MatchString("") {
			return nil, badDef("entity_too_broad", "the pattern matches an empty string")
		}
		c.re = re
		if p, _ := re.LiteralPrefix(); p != "" {
			c.prefix = p
		}
		if d.Validator != nil {
			if err := checkValidator(d.Validator); err != nil {
				return nil, err
			}
		}
	case KindAfterKeyword:
		if len(d.Definition.Cues) == 0 || len(d.Definition.Cues) > maxTerms {
			return nil, badDef("invalid_request", "an after-keyword entity needs at least one cue word")
		}
		for _, t := range d.Definition.Cues {
			if strings.TrimSpace(t) == "" || len(t) > maxTermLen {
				return nil, badDef("entity_too_broad", "a cue is empty or longer than %d characters", maxTermLen)
			}
		}
		c.maxLen = d.Definition.MaxLength
		if c.maxLen <= 0 {
			c.maxLen = defaultCapture
		}
		if c.maxLen > maxCapture {
			return nil, badDef("invalid_request", "the maximum length is %d", maxCapture)
		}
		c.stop = d.Definition.StopChars
		if c.stop == "" {
			c.stop = " \t\r\n,;&\"'"
		}
	case KindValueList:
		// Membership is checked against keyed hashes; nothing to compile here.
	case KindJSONPath:
		if len(d.Definition.Paths) == 0 || len(d.Definition.Paths) > maxPaths {
			return nil, badDef("invalid_request", "a JSON path entity needs between 1 and %d paths", maxPaths)
		}
		for _, p := range d.Definition.Paths {
			parts, err := parsePath(p)
			if err != nil {
				return nil, err
			}
			c.paths = append(c.paths, parts)
		}
	default:
		return nil, badDef("invalid_request", "unknown entity kind")
	}
	return c, nil
}

func checkValidator(v *Validator) error {
	switch v.Type {
	case "length":
		if v.Value <= 0 {
			return badDef("invalid_request", "a length validator needs a positive value")
		}
	case "prefix_list":
		if len(v.Values) == 0 {
			return badDef("invalid_request", "a prefix validator needs at least one prefix")
		}
	case "luhn", "mod11":
	case "custom_checksum":
		if len(v.Weights) == 0 || v.Modulus < 2 {
			return badDef("invalid_request", "a custom checksum needs weights and a modulus of at least 2")
		}
	case "mod11_weighted":
		if len(v.Weights) == 0 || len(v.Weights) > 40 {
			return badDef("invalid_request", "a weighted mod 11 needs between 1 and 40 weights")
		}
	case "mod97":
		if v.Value < 0 || v.Value > 10 {
			return badDef("invalid_request", "mod 97 can move between 0 and 10 leading characters to the end")
		}
	case "letter_check":
		if len(v.Values) != 1 || len(v.Values[0]) < 2 || len(v.Values[0]) > 40 || len(v.Weights) == 0 || len(v.Weights) > 40 {
			return badDef("invalid_request", "a letter check needs one alphabet of 2 to 40 letters and between 1 and 40 weights")
		}
	case "date_embedded":
		if len(v.Values) != 1 || !validLayout(v.Values[0]) || v.Value < 0 || v.Value > 40 {
			return badDef("invalid_request", "a date check needs a layout (YYMMDD, YYYYMMDD, DDMMYY, DDMMYYYY or MMDDYY) and a start position")
		}
	default:
		return badDef("invalid_request", "unknown validator")
	}
	return nil
}

// RunValidator applies a validator to a matched value.
func RunValidator(v *Validator, value string) bool {
	switch v.Type {
	case "length":
		return utf8.RuneCountInString(value) == v.Value
	case "prefix_list":
		for _, p := range v.Values {
			if strings.HasPrefix(value, p) {
				return true
			}
		}
		return false
	case "luhn":
		d := digitsOnly(value)
		return len(d) > 1 && luhnValid(d)
	case "mod11":
		d := digitsOnly(value)
		if len(d) < 2 {
			return false
		}
		// Weights 2,3,...,7 repeating from the right of the body; the last digit checks it.
		sum, w := 0, 2
		for i := len(d) - 2; i >= 0; i-- {
			sum += int(d[i]-'0') * w
			if w++; w > 7 {
				w = 2
			}
		}
		check := (11 - sum%11) % 11
		return check < 10 && check == int(d[len(d)-1]-'0')
	case "custom_checksum":
		return customChecksum(v, digitsOnly(value))
	case "mod11_weighted":
		return mod11Weighted(v, alnumUpper(value))
	case "mod97":
		return mod97(v, alnumUpper(value))
	case "letter_check":
		return letterCheck(v, alnumUpper(value))
	case "date_embedded":
		return dateEmbedded(v, digitsOnly(value))
	}
	return false
}

// definitive says a failed check rules a match out, rather than only lowering its score.
// The older validators keep their soft behaviour, so existing data types don't change.
func definitive(v *Validator) bool {
	switch v.Type {
	case "mod11_weighted", "mod97", "letter_check", "date_embedded":
		return true
	}
	return false
}

// alnumUpper keeps letters and digits, upper-cased: spaces, dashes and dots are layout.
func alnumUpper(s string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(s) {
		if (r >= '0' && r <= '9') || (r >= 'A' && r <= 'Z') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// checkIndex turns a 1-based position (0 = last, negative = from the end) into an index.
func checkIndex(pos, n int) int {
	switch {
	case pos == 0:
		return n - 1
	case pos < 0:
		return n + pos
	default:
		return pos - 1
	}
}

// mod11Weighted: the body's digits times weights, summed. The check is 11 - sum mod 11
// (Value 0), or sum mod 11 itself (Value 1). A result of 10 is written X; 11 is 0.
func mod11Weighted(v *Validator, s string) bool {
	pos := checkIndex(v.CheckPosition, len(s))
	if pos < 0 || pos >= len(s) {
		return false
	}
	sum, w := 0, 0
	for i := 0; i < len(s); i++ {
		if i == pos {
			continue
		}
		c := s[i]
		if c < '0' || c > '9' {
			return false
		}
		sum += int(c-'0') * v.Weights[w%len(v.Weights)]
		w++
	}
	check := sum % 11
	if v.Value == 0 {
		check = (11 - check) % 11
	}
	want := byte('0' + check)
	if check == 10 {
		want = 'X'
	}
	return s[pos] == want
}

// mod97 (ISO 7064 MOD 97-10, as IBANs use): move Value leading characters to the end,
// turn letters into numbers (A=10 … Z=35), and the whole must leave 1 when divided by 97.
func mod97(v *Validator, s string) bool {
	if len(s) < 5 || v.Value >= len(s) {
		return false
	}
	s = s[v.Value:] + s[:v.Value]
	rem := 0
	for _, r := range s {
		if r >= 'A' && r <= 'Z' {
			n := int(r-'A') + 10
			rem = (rem*100 + n) % 97
		} else {
			rem = (rem*10 + int(r-'0')) % 97
		}
	}
	return rem == 1
}

// letterCheck: the digits times weights, plus Value, modulo the alphabet's length, picks
// the letter at CheckPosition (as Singapore's NRIC or Spain's DNI do).
func letterCheck(v *Validator, s string) bool {
	pos := checkIndex(v.CheckPosition, len(s))
	if pos < 0 || pos >= len(s) {
		return false
	}
	alphabet := strings.ToUpper(v.Values[0])
	sum, w := v.Value, 0
	for i := 0; i < len(s); i++ {
		if i == pos || s[i] < '0' || s[i] > '9' {
			continue
		}
		sum += int(s[i]-'0') * v.Weights[w%len(v.Weights)]
		w++
	}
	if w == 0 {
		return false
	}
	return s[pos] == alphabet[sum%len(alphabet)]
}

func validLayout(l string) bool {
	switch l {
	case "YYMMDD", "YYYYMMDD", "DDMMYY", "DDMMYYYY", "MMDDYY":
		return true
	}
	return false
}

// dateEmbedded: the digits from position Value (1-based) hold a real calendar date in
// the layout given, such as a birth date inside a national ID.
func dateEmbedded(v *Validator, d string) bool {
	layout := v.Values[0]
	start := v.Value - 1
	if v.Value == 0 {
		start = 0
	}
	if start < 0 || start+len(layout) > len(d) {
		return false
	}
	part := d[start : start+len(layout)]
	num := func(from, n int) int { x, _ := strconv.Atoi(part[from : from+n]); return x }
	var y, m, day int
	switch layout {
	case "YYMMDD":
		y, m, day = num(0, 2), num(2, 2), num(4, 2)
	case "YYYYMMDD":
		y, m, day = num(0, 4), num(4, 2), num(6, 2)
	case "DDMMYY":
		day, m, y = num(0, 2), num(2, 2), num(4, 2)
	case "DDMMYYYY":
		day, m, y = num(0, 2), num(2, 2), num(4, 4)
	case "MMDDYY":
		m, day, y = num(0, 2), num(2, 2), num(4, 2)
	}
	if len(layout) == 6 {
		y += 2000 // only February 29th depends on the century, and 2000 was a leap year
	}
	if m < 1 || m > 12 || day < 1 {
		return false
	}
	return day <= time.Date(y, time.Month(m)+1, 0, 0, 0, 0, 0, time.UTC).Day()
}

func luhnValid(d string) bool {
	sum, double := 0, false
	for i := len(d) - 1; i >= 0; i-- {
		n := int(d[i] - '0')
		if double {
			if n *= 2; n > 9 {
				n -= 9
			}
		}
		sum += n
		double = !double
	}
	return sum%10 == 0
}

// customChecksum covers NUBAN-style schemes: body digits are multiplied by weights, and
// the check digit at CheckPosition equals (modulus - sum%modulus) % modulus.
func customChecksum(v *Validator, d string) bool {
	pos := v.CheckPosition
	if pos < 0 {
		pos = len(d) + pos
	} else if pos == 0 {
		pos = len(d) - 1
	} else {
		pos--
	}
	if pos < 0 || pos >= len(d) || len(d) == 0 {
		return false
	}
	sum, w := 0, 0
	for i := 0; i < len(d); i++ {
		if i == pos {
			continue
		}
		sum += int(d[i]-'0') * v.Weights[w%len(v.Weights)]
		w++
	}
	return (v.Modulus-sum%v.Modulus)%v.Modulus == int(d[pos]-'0')
}

// parsePath accepts $.a.b, $..b, $.a[*].b and $.a[0].b. Array positions are ignored,
// because payload walkers report a path without them.
func parsePath(p string) ([]string, error) {
	if !strings.HasPrefix(p, "$") || len(p) < 3 || len(p) > 300 {
		return nil, badDef("invalid_request", "a JSON path must start with $ and name a field")
	}
	var out []string
	rest := p[1:]
	for rest != "" {
		if rest[0] != '.' {
			return nil, badDef("invalid_request", "this JSON path is not supported")
		}
		rest = rest[1:]
		if strings.HasPrefix(rest, ".") {
			out = append(out, "..")
			rest = rest[1:]
		}
		i := strings.IndexByte(rest, '.')
		seg := rest
		if i >= 0 {
			seg, rest = rest[:i], rest[i:]
		} else {
			rest = ""
		}
		if j := strings.IndexByte(seg, '['); j >= 0 {
			if !strings.HasSuffix(seg, "]") {
				return nil, badDef("invalid_request", "this JSON path is not supported")
			}
			seg = seg[:j]
		}
		if seg == "" {
			return nil, badDef("invalid_request", "a JSON path segment is empty")
		}
		out = append(out, seg)
	}
	return out, nil
}

func pathMatches(pattern, path []string) bool {
	if len(pattern) == 0 {
		return len(path) == 0
	}
	if pattern[0] == ".." {
		for i := 0; i <= len(path); i++ {
			if pathMatches(pattern[1:], path[i:]) {
				return true
			}
		}
		return false
	}
	if len(path) == 0 || (pattern[0] != "*" && pattern[0] != path[0]) {
		return false
	}
	return pathMatches(pattern[1:], path[1:])
}

func splitLeafPath(p string) []string {
	p = strings.TrimPrefix(p, "$")
	p = strings.TrimPrefix(p, ".")
	if p == "" {
		return nil
	}
	return strings.Split(p, ".")
}

// NormalizeListValue is the canonical form hashed for a value list: lower case, single
// spaces, no surrounding punctuation.
func NormalizeListValue(s string) string {
	f := strings.Fields(strings.ToLower(s))
	for i, w := range f {
		f[i] = strings.TrimFunc(w, func(r rune) bool { return unicode.IsPunct(r) || unicode.IsSymbol(r) })
	}
	kept := f[:0]
	for _, w := range f {
		if w != "" {
			kept = append(kept, w)
		}
	}
	return strings.Join(kept, " ")
}

// appendNormalizedASCII is NormalizeListValue without allocating, for ASCII input. It
// reports false for anything else, and the caller falls back. A test holds the two equal.
func appendNormalizedASCII(dst []byte, s string) ([]byte, bool) {
	i := 0
	for i < len(s) {
		for i < len(s) && asciiSpace(s[i]) {
			i++
		}
		start := i
		for i < len(s) && !asciiSpace(s[i]) {
			if s[i] >= 0x80 {
				return dst, false
			}
			i++
		}
		w := s[start:i]
		for len(w) > 0 && asciiPunct(w[0]) {
			w = w[1:]
		}
		for len(w) > 0 && asciiPunct(w[len(w)-1]) {
			w = w[:len(w)-1]
		}
		if len(w) == 0 {
			continue
		}
		if len(dst) > 0 {
			dst = append(dst, ' ')
		}
		for j := 0; j < len(w); j++ {
			c := w[j]
			if c >= 'A' && c <= 'Z' {
				c += 32
			}
			dst = append(dst, c)
		}
	}
	return dst, true
}

func asciiSpace(c byte) bool { return c == ' ' || (c >= '\t' && c <= '\r') }

// asciiPunct matches unicode.IsPunct or IsSymbol over ASCII.
func asciiPunct(c byte) bool {
	return c > ' ' && c < 0x7f && !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z')
}

// ListHMAC is the keyed hash stored for a list member.
func ListHMAC(key []byte, normalized string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(normalized))
	return m.Sum(nil)
}

// DeriveListKey produces the value-list key from a vault's blind-index key.
func DeriveListKey(indexKey []byte) []byte {
	m := hmac.New(sha256.New, indexKey)
	m.Write([]byte(ValueListKeyLabel))
	return m.Sum(nil)
}

// RuleSet is the immutable, compiled detection configuration of one vault: the built-in
// catalogue plus every live custom entity. Hot reload swaps a whole RuleSet, so requests
// in flight finish on the version they started with.
type RuleSet struct {
	Version int64
	// Country is the vault's country (ISO 3166 alpha-2), empty when unknown.
	Country string
	// allowed limits the built-in types to the vault's country packs; nil allows all.
	allowed map[EntityType]bool
	// foreign are the switched-on packs with their own rules, scanned with ScanPacks.
	foreign []string
	packs   []string
	engine  *Engine
	customs []*compiled
	bySlug  map[string]*compiled

	termMatch *matcher
	termOwner []termRef
	listKey   []byte
	lists     map[[32]byte][]*compiled
	maxWords  int
	hasPaths  bool

	// model is a language-model finder (spaCy, transformers or Stanza), used on top of
	// the patterns for the modules in modelModules. Nil when not switched on.
	model        ModelFinder
	modelModules map[string]bool
}

// ModelFinder finds values with a language model. The finder is a paid feature in
// ee/nlp; detection works without it.
type ModelFinder interface {
	// Find returns entities with byte offsets into text. An error means the model
	// could not be asked, and the patterns' result stands on its own.
	Find(text string) ([]Entity, error)
}

// WithModel adds a language-model finder for the given modules ("ai", "api", "logs",
// "proxy").
func (r *RuleSet) WithModel(f ModelFinder, modules []string) *RuleSet {
	r.model = f
	r.modelModules = map[string]bool{}
	for _, m := range modules {
		r.modelModules[m] = true
	}
	return r
}

// ModelModules lists the modules where the language model runs, for reporting.
func (r *RuleSet) ModelModules() []string {
	if r.model == nil {
		return nil
	}
	out := make([]string, 0, len(r.modelModules))
	for m := range r.modelModules {
		out = append(out, m)
	}
	sort.Strings(out)
	return out
}

type termRef struct {
	c     *compiled
	raw   string
	isCue bool
}

// PackTypes are the built-in types each country pack turns on. A pack that is not
// listed has no detectors yet; its vaults still get the "everywhere" types.
var PackTypes = map[string][]EntityType{
	"everywhere": {Email, CardPAN, DOB, PaymentRef, PersonName},
	"ng":         {BVN, NIN, VNIN, NG11Digit, NUBAN, PhoneNG, AmountNGN},
}

// WithPacks limits built-in detection to the given country packs, for a vault in
// country. A nil packs list keeps every built-in type, as before packs existed.
func (r *RuleSet) WithPacks(country string, packs []string) *RuleSet {
	r.Country = country
	r.packs = packs
	r.foreign = nil
	for _, p := range packs {
		if len(PackRules[p]) > 0 {
			r.foreign = append(r.foreign, p)
		}
	}
	if packs == nil {
		r.allowed = nil
		return r
	}
	r.allowed = map[EntityType]bool{}
	for _, t := range PackTypes["everywhere"] {
		r.allowed[t] = true
	}
	for _, p := range packs {
		for _, t := range PackTypes[p] {
			r.allowed[t] = true
		}
	}
	return r
}

// Packs are the vault's country packs; nil when the rule set predates packs.
func (r *RuleSet) Packs() []string { return r.packs }

// BaseRuleSet is the built-in catalogue alone.
func BaseRuleSet(e *Engine) *RuleSet { return &RuleSet{engine: e, bySlug: map[string]*compiled{}} }

// NewRuleSet compiles a rule set. An error means nothing changes: the caller keeps
// whatever it was running.
func NewRuleSet(e *Engine, version int64, defs []CustomDef, listKey []byte) (*RuleSet, error) {
	r := &RuleSet{Version: version, engine: e, bySlug: map[string]*compiled{}, listKey: listKey, lists: map[[32]byte][]*compiled{}}
	var words []string
	for i := range defs {
		d := &defs[i]
		c, err := compileCustom(d)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", d.Slug, err)
		}
		r.customs = append(r.customs, c)
		r.bySlug[d.Slug] = c
		switch d.Kind {
		case KindKeywordList:
			for _, t := range d.Definition.Terms {
				words = append(words, string(lowerASCII(t)))
				r.termOwner = append(r.termOwner, termRef{c: c, raw: t})
			}
		case KindAfterKeyword:
			for _, t := range d.Definition.Cues {
				words = append(words, string(lowerASCII(t)))
				r.termOwner = append(r.termOwner, termRef{c: c, raw: t, isCue: true})
			}
		case KindValueList:
			for _, v := range d.Values {
				if len(v) != sha256.Size {
					return nil, fmt.Errorf("%s: a stored hash has the wrong length", d.Slug)
				}
				var k [32]byte
				copy(k[:], v)
				r.lists[k] = append(r.lists[k], c)
			}
			if d.MaxWords > r.maxWords {
				r.maxWords = d.MaxWords
			}
		case KindJSONPath:
			r.hasPaths = true
		}
	}
	if len(r.lists) > 0 {
		if len(listKey) == 0 {
			return nil, errors.New("value lists need a list key")
		}
		if r.maxWords < 1 {
			r.maxWords = 1
		}
	}
	if len(words) > 0 {
		r.termMatch = newMatcher(words)
	}
	return r, nil
}

// Engine returns the built-in engine behind this rule set.
func (r *RuleSet) Engine() *Engine { return r.engine }

// Custom returns a live entity by slug, or nil.
func (r *RuleSet) Custom(slug string) *CustomDef {
	if c := r.bySlug[slug]; c != nil {
		return c.def
	}
	return nil
}

// Customs lists the live entities.
func (r *RuleSet) Customs() []*CustomDef {
	out := make([]*CustomDef, len(r.customs))
	for i, c := range r.customs {
		out[i] = c.def
	}
	return out
}

// Scan finds every entity an action would apply to, for callers with no module.
func (r *RuleSet) Scan(text string) []Entity { return r.ScanFor("", "", text, "") }

// ScanWithHint is Scan with extra context, as Engine.ScanWithHint has.
func (r *RuleSet) ScanWithHint(text, hint string) []Entity { return r.ScanFor("", "", text, hint) }

// ScanLeaf scans one value of a structured payload, which is where JSON paths apply.
func (r *RuleSet) ScanLeaf(path, text, hint string) []Entity { return r.ScanFor("", path, text, hint) }

// ScanFor scans on behalf of a module ("api", "logs", "ai", "proxy"). A shadow entity, or
// one whose action here is "pass", changes nothing about the traffic, so it can never
// suppress a built-in match: the longer-span rule would otherwise let it hide a BVN from
// redaction. Such matches come back flagged Observe. Use Split before Replace.
func (r *RuleSet) ScanFor(module, path, text, hint string) []Entity {
	base := r.engine.ScanWithHint(text, hint)
	if r.allowed != nil {
		kept := base[:0]
		for _, e := range base {
			if r.allowed[e.Type] {
				kept = append(kept, e)
			}
		}
		base = kept
	}
	if len(r.foreign) > 0 {
		if extra := r.engine.ScanPacks(text, r.foreign); len(extra) > 0 {
			base = mergeOverlaps(base, extra)
		}
	}
	if r.model != nil && r.modelModules[module] && strings.TrimSpace(text) != "" {
		if extra, err := r.model.Find(text); err == nil && len(extra) > 0 {
			base = mergeOverlaps(base, extra)
		}
	}
	if len(r.customs) == 0 || text == "" {
		return base
	}
	found := r.scanCustom(text, hint, path)
	if len(found) == 0 {
		return base
	}
	var acting, observed []Entity
	for _, e := range found {
		if e.Shadow || (module != "" && r.ModuleAction(e, module) == "pass") {
			e.Observe = true
			observed = append(observed, e)
		} else {
			acting = append(acting, e)
		}
	}
	merged := mergeOverlaps(base, acting)
	return append(merged, observed...)
}

// mergeOverlaps applies the custom rule: the longer span wins, then the higher score,
// then the custom entity, because the customer defined it deliberately.
func mergeOverlaps(base, custom []Entity) []Entity {
	all := append(append(make([]Entity, 0, len(base)+len(custom)), base...), custom...)
	sort.SliceStable(all, func(i, j int) bool {
		a, b := all[i], all[j]
		if al, bl := a.End-a.Start, b.End-b.Start; al != bl {
			return al > bl
		}
		if a.Score != b.Score {
			return a.Score > b.Score
		}
		return a.Custom && !b.Custom
	})
	var kept []Entity
	for _, c := range all {
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

func (r *RuleSet) scanCustom(text, hint, path string) []Entity {
	var skip [][2]int
	for _, m := range ownTokenRe.FindAllStringIndex(text, -1) {
		skip = append(skip, [2]int{m[0], m[1]})
	}
	inSkip := func(s, e int) bool {
		i := sort.Search(len(skip), func(i int) bool { return skip[i][1] > s })
		return i < len(skip) && skip[i][0] < e
	}
	var lower string
	lowerText := func() string {
		if lower == "" {
			lower = string(lowerASCII(text)) // ASCII folding keeps byte offsets aligned
		}
		return lower
	}
	var out []Entity
	add := func(c *compiled, start, end int, score float64) {
		if start >= end || inSkip(start, end) {
			return
		}
		if c.def.TokenFormat == "format_preserving" && r.engine.cfg.IsOwnToken != nil && r.engine.cfg.IsOwnToken(text[start:end]) {
			return
		}
		switch c.def.Kind {
		case KindValueList, KindJSONPath:
			score = 1
		default:
			score = clamp(score + contextDelta(c, lowerText(), hint, start, end))
			if score < c.def.Threshold {
				return
			}
		}
		out = append(out, Entity{Type: EntityType(c.def.Slug), Start: start, End: end, Score: score, Custom: true, EntityVersion: c.def.Version, Shadow: c.def.Status == "shadow"})
	}

	if r.termMatch != nil {
		r.termMatch.scan(lowerASCII(text), func(idx, s, e int) {
			t := r.termOwner[idx]
			if !t.isCue {
				if t.c.def.Definition.CaseSensitive && text[s:e] != t.raw {
					return
				}
				if t.c.wholeWord && !wordBounded(text, s, e) {
					return
				}
				add(t.c, s, e, 0.9)
				return
			}
			if !wordBounded(text, s, e) {
				return
			}
			if cs, ce := capture(text, e, t.c); ce > cs {
				add(t.c, cs, ce, 0.8)
			}
		})
	}
	for _, c := range r.customs {
		switch c.def.Kind {
		case KindPattern:
			if c.prefix != "" && !strings.Contains(text, c.prefix) {
				continue
			}
			for _, m := range c.re.FindAllStringIndex(text, -1) {
				score := 0.6
				if c.def.Validator != nil {
					if RunValidator(c.def.Validator, text[m[0]:m[1]]) {
						score += 0.3
					} else if definitive(c.def.Validator) {
						// A wrong check letter or digit, or an impossible date: not this ID, whatever words are nearby.
						continue
					}
				}
				add(c, m[0], m[1], score)
			}
		case KindJSONPath:
			if path == "" {
				continue
			}
			leaf := splitLeafPath(path)
			for _, p := range c.paths {
				if pathMatches(p, leaf) {
					add(c, 0, len(text), 1)
					break
				}
			}
		}
	}
	if len(r.lists) > 0 {
		r.scanLists(text, func(c *compiled, s, e int) { add(c, s, e, 1) })
	}
	return out
}

// capture returns what follows a cue: separators are skipped, then characters run up to
// the maximum length or a stop character. The span never ends mid-character.
func capture(text string, from int, c *compiled) (int, int) {
	s := from
	for s < len(text) && strings.IndexByte(" \t:=\"'", text[s]) >= 0 {
		s++
	}
	e, n := s, 0
	for e < len(text) && n < c.maxLen {
		r, size := utf8.DecodeRuneInString(text[e:])
		if strings.ContainsRune(c.stop, r) {
			break
		}
		e += size
		n++
	}
	return s, e
}

func wordBounded(text string, s, e int) bool {
	if s > 0 {
		r, _ := utf8.DecodeLastRuneInString(text[:s])
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' {
			return false
		}
	}
	if e < len(text) {
		r, _ := utf8.DecodeRuneInString(text[e:])
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' {
			return false
		}
	}
	return true
}

// contextDelta applies the spec's window: positive words add up to 0.2, negative words
// subtract up to 0.3.
func contextDelta(c *compiled, lower, hint string, start, end int) float64 {
	if len(c.pos) == 0 && len(c.neg) == 0 {
		return 0
	}
	from, to := start-customContext, end+customContext
	if from < 0 {
		from = 0
	}
	if to > len(lower) {
		to = len(lower)
	}
	before, after := lower[from:start], lower[end:to]
	h := strings.ToLower(hint)
	has := func(w string) bool {
		return strings.Contains(before, w) || strings.Contains(after, w) || (h != "" && strings.Contains(h, w))
	}
	d := 0.0
	gain := 0.0
	for _, w := range c.pos {
		if has(w) {
			gain += 0.1
		}
	}
	if gain > 0.2 {
		gain = 0.2
	}
	d += gain
	loss := 0.0
	for _, w := range c.neg {
		if has(w) {
			loss += 0.15
		}
	}
	if loss > 0.3 {
		loss = 0.3
	}
	return d - loss
}

// scanLists hashes each candidate once: whitespace-separated word runs up to the longest
// entry's word count, and alphanumeric runs inside each word.
func (r *RuleSet) scanLists(text string, emit func(c *compiled, s, e int)) {
	type span struct{ s, e int }
	var words []span
	i := 0
	for i < len(text) {
		rn, size := utf8.DecodeRuneInString(text[i:])
		if unicode.IsSpace(rn) {
			i += size
			continue
		}
		s := i
		for i < len(text) {
			rn, size = utf8.DecodeRuneInString(text[i:])
			if unicode.IsSpace(rn) {
				break
			}
			i += size
		}
		// Surrounding punctuation is not part of the value.
		for s < i {
			rn, size = utf8.DecodeRuneInString(text[s:])
			if !unicode.IsPunct(rn) && !unicode.IsSymbol(rn) {
				break
			}
			s += size
		}
		e := i
		for e > s {
			rn, size = utf8.DecodeLastRuneInString(text[s:e])
			if !unicode.IsPunct(rn) && !unicode.IsSymbol(rn) {
				break
			}
			e -= size
		}
		if e > s {
			words = append(words, span{s, e})
		}
	}
	// One keyed hash per candidate is the bulk of this matcher's cost, so the hash state
	// and the normalising buffer are reused. A scan is single-threaded; a RuleSet is not,
	// which is why these live here and not on it.
	mac := hmac.New(sha256.New, r.listKey)
	var buf []byte
	var sum [32]byte
	check := func(s, e int) {
		var ok bool
		if buf, ok = appendNormalizedASCII(buf[:0], text[s:e]); !ok {
			buf = append(buf[:0], NormalizeListValue(text[s:e])...)
		}
		if len(buf) == 0 {
			return
		}
		mac.Reset()
		mac.Write(buf)
		mac.Sum(sum[:0])
		for _, c := range r.lists[sum] {
			emit(c, s, e)
		}
	}
	for a := range words {
		for n := 1; n <= r.maxWords && a+n <= len(words); n++ {
			check(words[a].s, words[a+n-1].e)
		}
		// Alphanumeric runs catch a member joined to something, as in "merchant:ACME01".
		w := words[a]
		run := -1
		for p := w.s; p <= w.e; {
			var rn rune
			size := 1
			if p < w.e {
				rn, size = utf8.DecodeRuneInString(text[p:])
			}
			alnum := p < w.e && (unicode.IsLetter(rn) || unicode.IsDigit(rn))
			if alnum && run < 0 {
				run = p
			} else if !alnum && run >= 0 {
				if run != w.s || p != w.e {
					check(run, p)
				}
				run = -1
			}
			p += size
		}
	}
}

// Split separates the entities a module acts on, sorted and disjoint, from those it only
// counts.
func (r *RuleSet) Split(ents []Entity) (active, observed []Entity) {
	if len(r.customs) == 0 {
		return ents, nil
	}
	active = ents[:0:0]
	for _, e := range ents {
		if e.Observe {
			observed = append(observed, e)
		} else {
			active = append(active, e)
		}
	}
	return active, observed
}

// CountLabel is how an observed match is recorded.
func CountLabel(e Entity) string {
	if e.Shadow {
		return "shadow"
	}
	return "passed"
}

// MaskValue masks a matched value by the entity's own rule.
func (r *RuleSet) MaskValue(t EntityType, v string) string {
	if c := r.bySlug[string(t)]; c != nil {
		return mask.Value(string(t), c.def.MaskRule.String(), v)
	}
	return mask.Value(string(t), "default", v)
}

// RuleSets gives a module its vault's rule set. Nil means not ready: fail safe.
type RuleSets interface {
	For(vault string) *RuleSet
}

// SetFor resolves a rule set, with built-ins alone when no store is configured.
func SetFor(src RuleSets, e *Engine, vault string) *RuleSet {
	if src == nil {
		return BaseRuleSet(e)
	}
	return src.For(vault)
}

// ErrRulesNotReady means a service has not yet loaded its rule sets.
var ErrRulesNotReady = errors.New("detection rules are not loaded yet")

// WalkJSON calls f for each string or number leaf of a JSON document, with paths in the
// form payload walkers use. It reports whether text was JSON at all.
func WalkJSON(text string, f func(path, value string)) bool {
	dec := json.NewDecoder(strings.NewReader(text))
	dec.UseNumber()
	var v any
	if dec.Decode(&v) != nil {
		return false
	}
	var walk func(path string, v any)
	walk = func(path string, v any) {
		switch t := v.(type) {
		case map[string]any:
			for k, c := range t {
				walk(path+"."+k, c)
			}
		case []any:
			for _, c := range t {
				walk(path, c)
			}
		case string:
			f(path, t)
		case json.Number:
			f(path, t.String())
		}
	}
	walk("$", v)
	return true
}

// MatchesSample reports whether an entity matches a test sample, reading the sample as a
// payload when it is JSON.
func (r *RuleSet) MatchesSample(slug, text string) []Entity {
	var out []Entity
	keep := func(ents []Entity) {
		for _, e := range ents {
			if string(e.Type) == slug {
				out = append(out, e)
			}
		}
	}
	if c := r.bySlug[slug]; c != nil && c.def.Kind == KindJSONPath {
		WalkJSON(text, func(path, value string) { keep(r.scanCustom(value, "", path)) })
		return out
	}
	keep(r.scanCustom(text, "", ""))
	return out
}

// ModuleAction returns a custom entity's action for a module, or "" for a built-in.
func (r *RuleSet) ModuleAction(e Entity, module string) string {
	c := r.bySlug[string(e.Type)]
	if c == nil {
		return ""
	}
	if a := c.def.Actions[module]; a != "" {
		return a
	}
	return "tokenize"
}

// Validate reports whether a value may be stored in a custom-typed field.
func (r *RuleSet) Validate(slug, value string) bool {
	c := r.bySlug[slug]
	if c == nil {
		return false
	}
	switch c.def.Kind {
	case KindPattern:
		m := c.re.FindStringIndex(value)
		if m == nil || m[0] != 0 || m[1] != len(value) {
			return false
		}
		return c.def.Validator == nil || RunValidator(c.def.Validator, value)
	case KindKeywordList:
		for _, t := range c.def.Definition.Terms {
			if t == value || (!c.def.Definition.CaseSensitive && strings.EqualFold(t, value)) {
				return true
			}
		}
		return false
	case KindValueList:
		var k [32]byte
		copy(k[:], ListHMAC(r.listKey, NormalizeListValue(value)))
		for _, o := range r.lists[k] {
			if o == c {
				return true
			}
		}
		return false
	}
	return true
}

// CheckDefinition compiles a definition without using it.
func CheckDefinition(d *CustomDef) error {
	_, err := compileCustom(d)
	return err
}

// ParseDefinition reads a stored JSON snapshot.
func ParseDefinition(raw []byte, into *CustomDef) error { return json.Unmarshal(raw, into) }

// Publish-time limits from the spec.
const (
	MaxAddedMsPerKB     = 0.3
	MaxMatchedLineShare = 0.05
)

// BenchResult is the outcome of the publish-time benchmark.
type BenchResult struct {
	Bytes        int64   `json:"bytes"`
	Lines        int64   `json:"lines"`
	MatchedLines int64   `json:"matched_lines"`
	MatchedShare float64 `json:"matched_share"`
	MsPerKB      float64 `json:"ms_per_kb"`
}

// Benchmark runs one entity's matcher over a synthetic corpus, timing only the matcher.
// The corpus seed is fixed, so results are comparable between entities and runs.
func (r *RuleSet) Benchmark(ctx context.Context, slug string, size int64) (*BenchResult, error) {
	c := r.bySlug[slug]
	if c == nil {
		return nil, errors.New("unknown entity")
	}
	gen := NewCorpus(20261103)
	res := &BenchResult{}
	var spent time.Duration
	for res.Bytes < size {
		if res.Lines%4096 == 0 && ctx.Err() != nil {
			return nil, ctx.Err()
		}
		line := gen.Sample().Text
		start := time.Now()
		matched := r.scanCustom(line, "", "")
		spent += time.Since(start)
		res.Lines++
		res.Bytes += int64(len(line))
		if len(matched) > 0 {
			res.MatchedLines++
		}
	}
	res.MatchedShare = float64(res.MatchedLines) / float64(res.Lines)
	res.MsPerKB = spent.Seconds() * 1000 / (float64(res.Bytes) / 1024)
	return res, nil
}

// AddPathMatches adds JSON path entities for a JSON document scanned as whole text.
func (r *RuleSet) AddPathMatches(text string, ents []Entity) []Entity {
	if !r.hasPaths {
		return ents
	}
	var found []Entity
	pos := 0
	WalkJSON(text, func(path, value string) {
		if value == "" {
			return
		}
		for _, e := range r.scanCustom(value, "", path) {
			if r.bySlug[string(e.Type)].def.Kind != KindJSONPath || e.Shadow {
				continue
			}
			i := strings.Index(text[pos:], value)
			if i < 0 {
				pos = 0
				if i = strings.Index(text, value); i < 0 {
					continue
				}
			}
			e.Start, e.End = pos+i, pos+i+len(value)
			found = append(found, e)
		}
	})
	if len(found) == 0 {
		return ents
	}
	return mergeOverlaps(ents, found)
}
