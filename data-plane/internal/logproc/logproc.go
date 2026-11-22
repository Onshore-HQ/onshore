// Package logproc redacts logs before they leave. One engine, three front-ends:
// OTLP/HTTP, and JSON or text over HTTP for Fluent Bit and Vector.
package logproc

import (
	"context"
	"crypto/sha256"
	"strings"
	"sync"
	"time"

	"onshore/data-plane/internal/detect"
)

// Pipeline is a configured log route.
type Pipeline struct {
	ID, VaultID, Name, SourceType, Destination, UpstreamURL string
	EntityTypes                                             map[string]bool
	Actions                                                 map[string]string // per entity: tokenize, mask, drop, pass
	SensitivePaths                                          map[string]string // $.customer.bvn -> bvn
	SampleRate                                              float64
	Mode, FailureMode, KeyHash                              string
}

// MaxLeafBytes bounds a single scanned value. Larger values are replaced when
// enforcing rather than forwarded unread.
const MaxLeafBytes = 1 << 20

const oversizedMarker = "[rv:oversized-value-removed]"

// Item asks for a token.
type Item struct {
	Entity string `json:"entity,omitempty"`
	Field  string `json:"field,omitempty"` // a named vault field, for gateway path rules
	Value  string `json:"value"`
}

// Tokenizer issues deterministic tokens. An empty token means no suitable vault
// field exists, in which case the value is masked rather than passed through.
type Tokenizer interface {
	Tokenize(ctx context.Context, vaultID, pipelineID string, items []Item) ([]string, error)
}

// Leaf is one scannable string in a payload.
type Leaf struct {
	Value  string
	Hint   string // key path, supplies context
	Path   string // $.a.b, matched against SensitivePaths
	Record int    // which line or record it belongs to
	Set    func(string)
}

// Counts tallies detections per entity and action.
type Counts map[[2]string]int64

// Outcome is the result of processing one payload.
type Outcome struct {
	Counts  Counts
	Dropped map[int]bool
	Changed bool
}

// Processor applies a pipeline's rules. It keeps a bounded token cache so that
// repeated identifiers do not call the vault; keys are hashes, never values.
type Processor struct {
	Engine    *detect.Engine
	Rules     detect.RuleSets
	Tokenizer Tokenizer

	mu    sync.Mutex
	cache map[[32]byte]cacheEntry
}

type cacheEntry struct {
	token   string
	expires time.Time
}

const (
	maxCache = 200_000
	cacheTTL = 10 * time.Minute
)

func cacheKey(vaultID, entity, value string) [32]byte {
	return sha256.Sum256([]byte(vaultID + "\x00" + entity + "\x00" + value))
}

type span struct {
	entity detect.Entity
	action string
	token  string
}

// actionFor resolves the action for an entity. Card numbers are never vaulted:
// tokenize becomes mask (spec: non-goal, it would pull in PCI DSS).
func actionFor(p *Pipeline, rs *detect.RuleSet, e detect.Entity) string {
	t := e.Type
	a := p.Actions[string(t)]
	if a == "" {
		a = rs.ModuleAction(e, "logs")
	}
	if a == "" {
		a = "tokenize"
	}
	if t == detect.CardPAN && a == "tokenize" {
		a = "mask"
	}
	return a
}

// Process scans leaves and, when enforcing, rewrites them. In shadow mode it
// only counts and changes nothing; a tokenizer failure returns an error so the
// caller can fail safe, and nothing is ever forwarded half-redacted.
func (pr *Processor) Process(ctx context.Context, p *Pipeline, leaves []Leaf) (Outcome, error) {
	rs := detect.SetFor(pr.Rules, pr.Engine, p.VaultID)
	if rs == nil {
		return Outcome{}, detect.ErrRulesNotReady
	}
	out := Outcome{Counts: Counts{}, Dropped: map[int]bool{}}
	enforcing := p.Mode == "enforcing"
	plans := make([][]span, len(leaves))
	need := map[[2]string]struct{}{}

	for i := range leaves {
		l := &leaves[i]
		if len(l.Value) > MaxLeafBytes {
			if enforcing {
				l.Set(oversizedMarker)
				out.Changed = true
			}
			out.Counts[[2]string{"oversized", actionLabel(enforcing, "dropped")}]++
			continue
		}
		var ents []detect.Entity
		if t, ok := p.SensitivePaths[l.Path]; ok && l.Path != "" {
			ents = []detect.Entity{{Type: detect.EntityType(t), Start: 0, End: len(l.Value), Score: 1}}
		} else {
			ents = rs.ScanFor("logs", l.Path, l.Value, l.Hint)
		}
		for _, e := range ents {
			if e.Observe {
				out.Counts[[2]string{string(e.Type), detect.CountLabel(e)}]++
				continue
			}
			// A pipeline's type list predates any custom entity and the country packs, so it
			// narrows the Nigerian built-ins only; a pack's types run once the vault turns it on.
			if !e.Custom && !detect.IsPackType(e.Type) && len(p.EntityTypes) > 0 && !p.EntityTypes[string(e.Type)] {
				continue
			}
			a := actionFor(p, rs, e)
			if !enforcing {
				out.Counts[[2]string{string(e.Type), "passed"}]++
				continue
			}
			plans[i] = append(plans[i], span{entity: e, action: a})
			out.Counts[[2]string{string(e.Type), countLabel(a)}]++
			switch a {
			case "drop":
				out.Dropped[l.Record] = true
			case "tokenize":
				need[[2]string{string(e.Type), l.Value[e.Start:e.End]}] = struct{}{}
			}
		}
	}
	if !enforcing {
		return out, nil
	}
	tokens, err := pr.tokens(ctx, p, need)
	if err != nil {
		return Outcome{}, err
	}
	for i := range leaves {
		if len(plans[i]) == 0 {
			continue
		}
		l := &leaves[i]
		ents := make([]detect.Entity, len(plans[i]))
		act := map[int]string{}
		for j, s := range plans[i] {
			ents[j] = s.entity
			act[s.entity.Start] = s.action
		}
		changed := detect.Replace(l.Value, ents, func(e detect.Entity, v string) string {
			switch act[e.Start] {
			case "pass":
				return v
			case "drop":
				return "[rv:dropped]"
			case "tokenize":
				if t := tokens[[2]string{string(e.Type), v}]; t != "" {
					return t
				}
			}
			return rs.MaskValue(e.Type, v)
		})
		if changed != l.Value {
			l.Set(changed)
			out.Changed = true
		}
	}
	return out, nil
}

func actionLabel(enforcing bool, a string) string {
	if !enforcing {
		return "passed"
	}
	return a
}

func countLabel(a string) string {
	switch a {
	case "tokenize":
		return "tokenized"
	case "mask":
		return "masked"
	case "drop":
		return "dropped"
	}
	return "passed"
}

func (pr *Processor) tokens(ctx context.Context, p *Pipeline, need map[[2]string]struct{}) (map[[2]string]string, error) {
	out := make(map[[2]string]string, len(need))
	var missing []Item
	now := time.Now()
	pr.mu.Lock()
	if pr.cache == nil {
		pr.cache = map[[32]byte]cacheEntry{}
	}
	for k := range need {
		if c, ok := pr.cache[cacheKey(p.VaultID, k[0], k[1])]; ok && now.Before(c.expires) {
			out[k] = c.token
		} else {
			missing = append(missing, Item{Entity: k[0], Value: k[1]})
		}
	}
	pr.mu.Unlock()
	for start := 0; start < len(missing); start += 500 {
		end := start + 500
		if end > len(missing) {
			end = len(missing)
		}
		chunk := missing[start:end]
		toks, err := pr.Tokenizer.Tokenize(ctx, p.VaultID, p.ID, chunk)
		if err != nil {
			return nil, err
		}
		pr.mu.Lock()
		if len(pr.cache)+len(chunk) > maxCache {
			pr.cache = map[[32]byte]cacheEntry{}
		}
		for i, it := range chunk {
			out[[2]string{it.Entity, it.Value}] = toks[i]
			if toks[i] != "" {
				pr.cache[cacheKey(p.VaultID, it.Entity, it.Value)] = cacheEntry{toks[i], now.Add(cacheTTL)}
			}
		}
		pr.mu.Unlock()
	}
	return out, nil
}

// HintFromPath reduces a key path to its last segments for context scoring.
func HintFromPath(path string) string {
	parts := strings.Split(strings.TrimPrefix(path, "$."), ".")
	if len(parts) > 2 {
		parts = parts[len(parts)-2:]
	}
	return strings.Join(parts, " ")
}

// ParseSensitivePaths reads "$.customer.bvn:bvn" entries.
func ParseSensitivePaths(entries []string) map[string]string {
	out := map[string]string{}
	for _, e := range entries {
		if i := strings.LastIndexByte(e, ':'); i > 0 {
			out[e[:i]] = e[i+1:]
		}
	}
	return out
}
