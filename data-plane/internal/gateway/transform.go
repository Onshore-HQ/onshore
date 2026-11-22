// Package gateway holds the AI gateway and the HTTP proxy: one vault and one
// detection engine wrapped around two more leaks.
package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"onshore/data-plane/internal/detect"
	"onshore/data-plane/internal/logproc"
	"onshore/data-plane/internal/mask"
	"onshore/data-plane/internal/vault"
)

// PathRule names a JSON path and, when tokenizing into a chosen column, its field.
type PathRule struct {
	Path  string `json:"path"`
	Field string `json:"field,omitempty"`
}

// QueryRule redacts one query parameter.
type QueryRule struct {
	Param string `json:"param"`
	Field string `json:"field,omitempty"`
}

// ProxyRoute follows InCountry's Web Services: a route matches method and path;
// redact rules name JSON paths to tokenize and unredact rules name paths to restore.
type ProxyRoute struct {
	ID               string      `json:"id"`
	VaultID          string      `json:"vault_id"`
	Name             string      `json:"name"`
	Direction        string      `json:"direction"`
	Method           string      `json:"method"`
	PathPattern      string      `json:"path_pattern"`
	UpstreamURL      string      `json:"upstream_url"`
	Mode             string      `json:"mode"`
	Redact           []PathRule  `json:"redact_paths"`
	Unredact         []PathRule  `json:"unredact_paths"`
	ResponseRedact   []PathRule  `json:"response_redact_paths"`
	ResponseUnredact []PathRule  `json:"response_unredact_paths"`
	Query            []QueryRule `json:"redact_query"`
	DLP              bool        `json:"dlp"`
	DLPExcludedPaths []string    `json:"dlp_excluded_paths"`

	RedactHeaders           []HeaderRule `json:"redact_headers"`
	UnredactHeaders         []HeaderRule `json:"unredact_headers"`
	ResponseRedactHeaders   []HeaderRule `json:"response_redact_headers"`
	ResponseUnredactHeaders []HeaderRule `json:"response_unredact_headers"`
	DLPExcludedHeaders      []string     `json:"dlp_excluded_headers"`
	DLPExcludedParams       []string     `json:"dlp_excluded_params"`
	FilePolicy              string       `json:"file_policy"`
	KeyHash                 string       `json:"-"`
}

// Transformer applies route rules to JSON bodies.
type Transformer struct {
	Engine *detect.Engine
	Rules  detect.RuleSets
	// Tokenize issues tokens; process-only routes never call it.
	Tokenize func(ctx context.Context, route *ProxyRoute, items []logproc.Item) ([]string, error)
	// Reveal restores tokens as the end user; nil or no caller leaves them in place.
	Reveal func(ctx context.Context, route *ProxyRoute, caller string, tokens []string) (map[string]string, error)
	// RedactFile sends a PDF or image to the file redactor. Nil means files cannot be redacted.
	RedactFile func(ctx context.Context, route *ProxyRoute, body []byte) (out []byte, contentType string, found map[string]int, lowConfidence bool, err error)
}

// ErrNotJSON means rules apply but the body cannot be read, so it does not pass.
var ErrNotJSON = errors.New("this route has field rules, and the body is not JSON")

// ExampleTokens stands in for the vault in previews.
func ExampleTokens(_ context.Context, _ *ProxyRoute, items []logproc.Item) ([]string, error) {
	out := make([]string, len(items))
	for i, it := range items {
		t := it.Entity
		if t == "" {
			t = "free_text"
		}
		out[i] = vault.NewToken(t, "opaque")
	}
	return out, nil
}

var pathSegment = regexp.MustCompile(`^@?[A-Za-z0-9_-]+(\[\*\])?$`)

// ValidPath accepts the supported subset: $.a.b, $.items[*].id and $ itself, and for XML, $.a.@id.
func ValidPath(p string) bool {
	if p == "$" {
		return true
	}
	if !strings.HasPrefix(p, "$.") {
		return false
	}
	for _, seg := range strings.Split(p[2:], ".") {
		if !pathSegment.MatchString(seg) {
			return false
		}
	}
	return true
}

type setter struct {
	get func() any
	set func(any)
}

// resolve finds every location a path selects.
func resolve(doc *any, path string) []setter {
	cur := []setter{{func() any { return *doc }, func(v any) { *doc = v }}}
	if path == "$" {
		return cur
	}
	for _, seg := range strings.Split(strings.TrimPrefix(path, "$."), ".") {
		name, each := strings.CutSuffix(seg, "[*]")
		var next []setter
		for _, s := range cur {
			obj, ok := s.get().(map[string]any)
			if !ok {
				continue
			}
			if _, ok := obj[name]; !ok {
				continue
			}
			name := name
			field := setter{func() any { return obj[name] }, func(v any) { obj[name] = v }}
			if !each {
				next = append(next, field)
				continue
			}
			if arr, ok := field.get().([]any); ok {
				for i := range arr {
					i := i
					next = append(next, setter{func() any { return arr[i] }, func(v any) { arr[i] = v }})
				}
			}
		}
		cur = next
	}
	return cur
}

func scalar(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		return t, t != ""
	case json.Number:
		return t.String(), true
	}
	return "", false
}

func decodeJSON(b []byte) (any, error) {
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	if d.More() {
		return nil, ErrNotJSON
	}
	return v, nil
}

func encodeJSON(v any) ([]byte, error) {
	var b strings.Builder
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if err := e.Encode(v); err != nil {
		return nil, err
	}
	return []byte(strings.TrimRight(b.String(), "\n")), nil
}

func (t *Transformer) apply(ctx context.Context, r *ProxyRoute, body []byte, redact, unredact []PathRule, caller string, dlp bool) ([]byte, logproc.Counts, error) {
	counts := logproc.Counts{}
	if len(redact)+len(unredact) == 0 && !dlp {
		return body, counts, nil
	}
	if len(strings.TrimSpace(string(body))) == 0 {
		return body, counts, nil
	}
	doc, err := decodeJSON(body)
	if err != nil {
		return nil, nil, ErrNotJSON
	}
	processOnly := r.Mode == "process_only"

	var locs []setter
	var items []logproc.Item
	for _, rule := range redact {
		for _, s := range resolve(&doc, rule.Path) {
			if v, ok := scalar(s.get()); ok {
				locs = append(locs, s)
				items = append(items, logproc.Item{Field: rule.Field, Entity: "free_text", Value: v})
			}
		}
	}
	tokens := make([]string, len(items))
	if processOnly {
		// Nothing is stored, so these tokens can never be restored: one-way flows.
		for i := range items {
			tokens[i] = vault.NewToken("free_text", "opaque")
		}
	} else if len(items) > 0 {
		if tokens, err = t.Tokenize(ctx, r, items); err != nil {
			return nil, nil, err
		}
	}
	for i, s := range locs {
		tok := tokens[i]
		if tok == "" {
			// No such field in the vault: the value still does not pass.
			tok = mask.Value("", "full", items[i].Value)
		}
		s.set(tok)
		counts[[2]string{"path_rule", "tokenized"}]++
	}

	if len(unredact) > 0 && t.Reveal != nil && caller != "" && !processOnly {
		var ulocs []setter
		var want []string
		for _, rule := range unredact {
			for _, s := range resolve(&doc, rule.Path) {
				if v, ok := scalar(s.get()); ok {
					ulocs = append(ulocs, s)
					want = append(want, v)
				}
			}
		}
		if len(want) > 0 {
			vals, err := t.Reveal(ctx, r, caller, want)
			if err != nil {
				return nil, nil, err
			}
			for i, s := range ulocs {
				if v, ok := vals[want[i]]; ok {
					s.set(v)
				}
			}
		}
	}

	if dlp {
		c, err := t.dlp(ctx, r, &doc)
		if err != nil {
			return nil, nil, err
		}
		for k, n := range c {
			counts[k] += n
		}
	}
	out, err := encodeJSON(doc)
	return out, counts, err
}

// dlp catches identifiers no rule named, as InCountry's auto-detection does.
func (t *Transformer) dlp(ctx context.Context, r *ProxyRoute, doc *any) (logproc.Counts, error) {
	body, err := encodeJSON(*doc)
	if err != nil {
		return nil, err
	}
	pl := logproc.ParseBody(body)
	counts, changed, err := t.dlpLeaves(ctx, r, pl.Leaves)
	if err != nil || !changed {
		return counts, err
	}
	out, err := pl.Encode(nil)
	if err != nil {
		return nil, err
	}
	if *doc, err = decodeJSON(out); err != nil {
		return nil, fmt.Errorf("re-reading redacted body: %w", err)
	}
	return counts, nil
}

// dlpLeaves finds identifiers in values however they were parsed, and replaces them through
// each leaf's Set. It reports whether anything changed.
func (t *Transformer) dlpLeaves(ctx context.Context, r *ProxyRoute, leaves []logproc.Leaf) (logproc.Counts, bool, error) {
	excluded := map[string]bool{}
	for _, p := range r.DLPExcludedPaths {
		excluded[p] = true
	}
	for _, h := range r.DLPExcludedHeaders {
		excluded[headerPath(h)] = true
	}
	for _, q := range r.DLPExcludedParams {
		excluded["query:"+q] = true
	}
	rules := detect.SetFor(t.Rules, t.Engine, r.VaultID)
	if rules == nil {
		return nil, false, detect.ErrRulesNotReady
	}
	counts := logproc.Counts{}
	type hit struct {
		leaf int
		e    detect.Entity
	}
	var hits []hit
	var items []logproc.Item
	var err error
	for i, l := range leaves {
		if excluded[l.Path] {
			continue
		}
		active, observed := rules.Split(rules.ScanFor("proxy", l.Path, l.Value, l.Hint))
		for _, e := range observed {
			counts[[2]string{string(e.Type), detect.CountLabel(e)}]++
		}
		for _, e := range active {
			hits = append(hits, hit{i, e})
			if r.Mode != "process_only" && e.Type != detect.CardPAN && !customNoToken(rules, e) {
				items = append(items, logproc.Item{Entity: string(e.Type), Value: l.Value[e.Start:e.End]})
			}
		}
	}
	if len(hits) == 0 {
		return counts, false, nil
	}
	tokens := []string{}
	if len(items) > 0 {
		if tokens, err = t.Tokenize(ctx, r, items); err != nil {
			return nil, false, err
		}
	}
	perLeaf := map[int][]detect.Entity{}
	for _, h := range hits {
		perLeaf[h.leaf] = append(perLeaf[h.leaf], h.e)
	}
	next := 0
	for i := range leaves {
		ents := perLeaf[i]
		if len(ents) == 0 {
			continue
		}
		l := leaves[i]
		l.Set(detect.Replace(l.Value, ents, func(e detect.Entity, v string) string {
			if rules.ModuleAction(e, "proxy") == "drop" {
				counts[[2]string{string(e.Type), "dropped"}]++
				return "[rv:dropped]"
			}
			if r.Mode == "process_only" || customNoToken(rules, e) {
				counts[[2]string{string(e.Type), "masked"}]++
				return rules.MaskValue(e.Type, v)
			}
			if e.Type == detect.CardPAN {
				counts[[2]string{string(e.Type), "masked"}]++
				return mask.Value(string(e.Type), "default", v)
			}
			tok := ""
			if next < len(tokens) {
				tok = tokens[next]
			}
			next++
			if tok == "" {
				counts[[2]string{string(e.Type), "masked"}]++
				return rules.MaskValue(e.Type, v)
			}
			counts[[2]string{string(e.Type), "tokenized"}]++
			return tok
		}))
	}
	return counts, true, nil
}

// customNoToken reports a custom entity whose action here is anything but tokenize.
func customNoToken(rs *detect.RuleSet, e detect.Entity) bool {
	a := rs.ModuleAction(e, "proxy")
	return a != "" && a != "tokenize"
}

// Request transforms a body going to the upstream.
func (t *Transformer) Request(ctx context.Context, r *ProxyRoute, body []byte) ([]byte, logproc.Counts, error) {
	return t.apply(ctx, r, body, r.Redact, nil, "", r.DLP)
}

// Response transforms a body coming back.
func (t *Transformer) Response(ctx context.Context, r *ProxyRoute, body []byte, caller string) ([]byte, logproc.Counts, error) {
	return t.apply(ctx, r, body, r.ResponseRedact, r.ResponseUnredact, caller, false)
}
