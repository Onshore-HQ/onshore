package gateway

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"onshore/data-plane/ee/cloak"
	"onshore/data-plane/ee/logproc"
	"onshore/data-plane/internal/detect"
)

var placeholderRe = regexp.MustCompile(`\[([A-Z][A-Z0-9_]*)_([0-9]+)\]`)

// labels are the readable placeholder names, so the model can still reason.
var labels = map[detect.EntityType]string{detect.BVN: "BVN", detect.NIN: "NIN", detect.VNIN: "VNIN", detect.NG11Digit: "ID", detect.NUBAN: "ACCOUNT", detect.PhoneNG: "PHONE", detect.CardPAN: "CARD", detect.Email: "EMAIL", detect.PersonName: "NAME", detect.AmountNGN: "AMOUNT", detect.DOB: "DATE", detect.PaymentRef: "REF", Place: "PLACE"}

// Place is a Nigerian state, city or neighbourhood. The detection engine does
// not look for places; only a cloak setting other than "keep" does.
const Place detect.EntityType = "address"

// session holds one request's map from what the provider saw back to the real
// values. It lives in memory for that request, unless the route keeps a digital
// twin, in which case it is sealed in the vault.
type session struct {
	byPlaceholder map[string]entry // placeholder or stand-in word → real value
	byValue       map[string]string
	counters      map[string]int
	floor         int

	opts    cloak.Options
	namer   *cloak.Namer
	now     time.Time
	country string   // the vault's country: how dates are read, which stand-in names fit
	text    string   // the original request, which stand-in names must avoid
	namerOf string   // the country the namer was made for
	synth   []string // stand-in names and their parts, longest first
	synRe   *regexp.Regexp
}

type entry struct {
	entity detect.EntityType
	value  string
	part   bool // one word of a stand-in name; not counted as a separate value
}

func randIndex(n int) int {
	var b [8]byte
	rand.Read(b[:])
	return int(binary.BigEndian.Uint64(b[:]) % uint64(n))
}

func newSession(body []byte, opts cloak.Options) *session {
	s := &session{byPlaceholder: map[string]entry{}, byValue: map[string]string{}, counters: map[string]int{}, opts: opts, now: time.Now()}
	// Numbering starts above anything already in the prompt, so text that merely
	// looks like a placeholder can never restore someone's value.
	for _, m := range placeholderRe.FindAllSubmatch(body, -1) {
		if n, err := strconv.Atoi(string(m[2])); err == nil && n > s.floor && n < 1<<30 {
			s.floor = n
		}
	}
	s.text = string(body)
	s.namer = cloak.NewNamer(s.text, randIndex)
	return s
}

func (s *session) placeholder(e detect.EntityType, v string) string {
	key := string(e) + "\x00" + v
	if p, ok := s.byValue[key]; ok {
		return p
	}
	label := labels[e]
	if label == "" && (strings.HasPrefix(string(e), "c_") || detect.IsPackType(e)) {
		label = strings.ToUpper(string(e))
	}
	if label == "" {
		label = "VALUE"
	}
	s.counters[label]++
	p := fmt.Sprintf("[%s_%d]", label, s.floor+s.counters[label])
	s.byValue[key] = p
	s.byPlaceholder[p] = entry{entity: e, value: v}
	return p
}

func (s *session) addSynth(word string, en entry) {
	if _, ok := s.byPlaceholder[word]; ok {
		return
	}
	s.byPlaceholder[word] = en
	s.synth = append(s.synth, word)
	sort.Slice(s.synth, func(i, j int) bool { return len(s.synth[i]) > len(s.synth[j]) })
	s.synRe = nil
}

// cloakValue applies the route's setting for one detected value, and says what
// happened to it for the detection counts.
func (s *session) cloakValue(e detect.EntityType, v string) (string, string) {
	switch opt := s.opts.For(string(e)); opt {
	case cloak.Keep:
		return v, "passed"
	case cloak.Placeholder:
	case cloak.Synthetic:
		if fake, parts := s.namer.Fake(v); fake != "" {
			s.addSynth(fake, entry{entity: e, value: v})
			for _, p := range parts {
				s.addSynth(p.Fake, entry{entity: e, value: p.Real, part: true})
			}
			return fake, "tokenized"
		}
	default:
		if g, ok := cloak.GeneralizeIn(s.country, string(e), opt, v, s.now); ok {
			return g, "masked"
		}
	}
	return s.placeholder(e, v), "tokenized"
}

// withPlaces adds the places in text that no detected value already covers.
func withPlaces(text string, ents []detect.Entity, packs []string) []detect.Entity {
	places := cloak.FindPlacesIn(text, placePacks(packs))
	if len(places) == 0 {
		return ents
	}
	out := append([]detect.Entity(nil), ents...)
	for _, p := range places {
		overlaps := false
		for _, e := range ents {
			overlaps = overlaps || (p.Start < e.End && e.Start < p.End)
		}
		if !overlaps {
			out = append(out, detect.Entity{Type: Place, Start: p.Start, End: p.End, Score: 0.9})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Start < out[j].Start })
	return out
}

// cloakText runs detection and the route's settings over one piece of text.
// entities, when not empty, limits which built-in types are protected.
func cloakText(rules *detect.RuleSet, s *session, text, path, hint string, entities map[string]bool, enforcing bool, counts logproc.Counts) (string, bool) {
	s.country = rules.Country
	if s.namerOf != s.country && len(s.synth) == 0 {
		// Stand-in names come from the vault's own country, so replies read naturally there.
		s.namer, s.namerOf = cloak.NewNamerFor(s.text, randIndex, s.country), s.country
	}
	ents, observed := rules.Split(rules.ScanFor("ai", path, text, hint))
	for _, e := range observed {
		counts[[2]string{string(e.Type), detect.CountLabel(e)}]++
	}
	if len(entities) > 0 {
		kept := ents[:0]
		for _, e := range ents {
			if e.Custom || detect.IsPackType(e.Type) || entities[string(e.Type)] {
				kept = append(kept, e)
			}
		}
		ents = kept
	}
	if s.opts.For(string(Place)) != cloak.Keep {
		ents = withPlaces(text, ents, rules.Packs())
	}
	if len(ents) == 0 {
		return text, false
	}
	if !enforcing {
		for _, e := range ents {
			counts[[2]string{string(e.Type), "passed"}]++
		}
		return text, false
	}
	return detect.Replace(text, ents, func(e detect.Entity, v string) string {
		switch rules.ModuleAction(e, "ai") {
		case "mask":
			counts[[2]string{string(e.Type), "masked"}]++
			return rules.MaskValue(e.Type, v)
		case "drop":
			counts[[2]string{string(e.Type), "dropped"}]++
			return "[rv:dropped]"
		}
		out, action := s.cloakValue(e.Type, v)
		counts[[2]string{string(e.Type), action}]++
		return out
	}), true
}

// synthRe matches any stand-in word as a whole word.
func (s *session) synthRe() *regexp.Regexp {
	if len(s.synth) == 0 {
		return nil
	}
	if s.synRe == nil {
		q := make([]string, len(s.synth))
		for i, w := range s.synth {
			q[i] = regexp.QuoteMeta(w)
		}
		s.synRe = regexp.MustCompile(`\b(?:` + strings.Join(q, "|") + `)\b`)
	}
	return s.synRe
}

// nameHold finds where text could be the start of a stand-in name split across
// streamed chunks. A complete name at the very end is held too, since the next
// chunk may show it was part of a longer word.
func (s *session) nameHold(text string) int {
	if len(s.synth) == 0 {
		return len(text)
	}
	longest := len(s.synth[0])
	for i := max(0, len(text)-longest); i < len(text); i++ {
		if !utf8.RuneStart(text[i]) {
			continue
		}
		if i > 0 {
			prev, _ := utf8.DecodeLastRuneInString(text[:i])
			if unicode.IsLetter(prev) || unicode.IsDigit(prev) {
				continue
			}
		}
		tail := text[i:]
		for _, w := range s.synth {
			if len(tail) <= len(w) && strings.HasPrefix(w, tail) {
				return i
			}
		}
	}
	return len(text)
}

// ---- digital twin --------------------------------------------------------------

// TwinItem is one entry of a saved twin: what the provider saw, and the real value.
type TwinItem struct {
	Shown  string `json:"s"`
	Entity string `json:"e"`
	Value  string `json:"v"`
	Part   bool   `json:"p,omitempty"`
}

func (s *session) twin() []TwinItem {
	out := make([]TwinItem, 0, len(s.byPlaceholder))
	for k, e := range s.byPlaceholder {
		out = append(out, TwinItem{k, string(e.entity), e.value, e.part})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Shown < out[j].Shown })
	return out
}

func sessionFromTwin(items []TwinItem) *session {
	s := &session{byPlaceholder: map[string]entry{}, byValue: map[string]string{}, counters: map[string]int{}}
	for _, it := range items {
		en := entry{entity: detect.EntityType(it.Entity), value: it.Value, part: it.Part}
		if placeholderRe.MatchString(it.Shown) && placeholderRe.FindString(it.Shown) == it.Shown {
			s.byPlaceholder[it.Shown] = en
		} else {
			s.addSynth(it.Shown, en)
		}
	}
	return s
}

// Cloaked is the result of cloaking text outside the AI gateway.
type Cloaked struct {
	Text   string
	Twin   []TwinItem
	Counts map[string]int // entity type → values changed
}

// CloakText cloaks one text with the given settings, for the cloak API.
func CloakText(rules *detect.RuleSet, opts cloak.Options, text string) Cloaked {
	s := newSession([]byte(text), opts)
	counts := logproc.Counts{}
	out, _ := cloakText(rules, s, text, "", "", nil, true, counts)
	byType := map[string]int{}
	for k, n := range counts {
		if k[1] != "passed" && k[1] != "shadow" && k[1] != "observed" {
			byType[k[0]] += int(n)
		}
	}
	return Cloaked{out, s.twin(), byType}
}

// TwinEntities counts the distinct real values in a twin, by type, for the
// permission decision. Cards are left out: they never come back in full.
func TwinEntities(items []TwinItem) map[string]int {
	want := map[string]int{}
	for _, it := range items {
		if !it.Part && it.Entity != string(detect.CardPAN) {
			want[it.Entity]++
		}
	}
	return want
}

// Uncloak swaps placeholders and stand-in names in text back, as far as
// decisions allow: "plaintext" gives the real value, anything else a masked one.
func Uncloak(rules *detect.RuleSet, items []TwinItem, decisions map[string]string, text string) string {
	rs := &restorer{rules: rules, s: sessionFromTwin(items), rt: &AIRoute{}, decided: true, decisions: decisions}
	return rs.replace(text)
}

// placePacks are the gazetteers to search: the vault's packs, or every country's
// when the rule set has none (a preview with no vault).
func placePacks(packs []string) []string {
	if len(packs) == 0 {
		return nil
	}
	out := []string{}
	for _, p := range packs {
		if p != "everywhere" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
