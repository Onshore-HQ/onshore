// Package rules keeps each vault's compiled rule set current in a running service.
//
// A publish bumps the vault's ruleset version and sends NOTIFY. Services hear it, or
// notice within the poll interval, then compile the new set in the background and swap
// it in atomically. Requests in flight finish on the set they started with. A set that
// will not fetch or compile changes nothing: the last good one stays in force.
package rules

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"onshore/data-plane/internal/detect"
	"onshore/data-plane/internal/license"
)

// Channel is the PostgreSQL NOTIFY channel; the payload is a vault id.
const Channel = "rv_rulesets"

// PollEvery is the fallback for when a notification is missed.
const PollEvery = 10 * time.Second

// Snapshot is everything needed to compile one vault's rule set.
type Snapshot struct {
	Version    int64              `json:"version"`
	Thresholds map[string]float64 `json:"thresholds,omitempty"`
	Entities   []detect.CustomDef `json:"entities"`
	ListKey    []byte             `json:"list_key,omitempty"`
	// Values holds each value_list entity's hashes, concatenated, by slug.
	Values map[string][]byte `json:"values,omitempty"`
	// Country and Packs say which built-in detectors apply. Nil Packs means all.
	Country string   `json:"country,omitempty"`
	Packs   []string `json:"packs,omitempty"`
	// Models lists the modules where language models add to the patterns (paid).
	Models []string `json:"models,omitempty"`
	// Sandbox vaults may use paid features for development and testing.
	Sandbox bool `json:"sandbox,omitempty"`
}

// NewModelFinder returns the install's language-model finder, or nil. The ee/nlp
// package sets it when a service imports it; without that, models are never used.
var NewModelFinder func() detect.ModelFinder

// Source supplies versions and snapshots.
type Source interface {
	Versions(ctx context.Context) (map[string]int64, error)
	Snapshot(ctx context.Context, vault string) (*Snapshot, error)
}

// Store holds the current rule sets of a service.
type Store struct {
	Source Source
	// NewEngine builds the service's engine with a vault's tuned thresholds.
	NewEngine func(thresholds map[string]float64) *detect.Engine

	base   atomic.Pointer[detect.RuleSet]
	sets   atomic.Pointer[map[string]*detect.RuleSet]
	synced atomic.Bool
	mu     sync.Mutex
	wake   chan struct{}
}

func (st *Store) baseSet() *detect.RuleSet {
	if b := st.base.Load(); b != nil {
		return b
	}
	b := detect.BaseRuleSet(st.NewEngine(nil))
	st.base.CompareAndSwap(nil, b)
	return st.base.Load()
}

// For returns a vault's rule set, or nil before the first successful sync. Callers must
// treat nil as "not ready" and fail safe: answering with built-ins alone would forward
// the customer's own identifiers during a restart.
func (st *Store) For(vault string) *detect.RuleSet {
	if !st.synced.Load() {
		return nil
	}
	if m := st.sets.Load(); m != nil {
		if r, ok := (*m)[vault]; ok {
			return r // nil while a vault has never compiled: not ready, not unprotected
		}
	}
	return st.baseSet()
}

// Sync brings every vault up to date once.
func (st *Store) Sync(ctx context.Context) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	versions, err := st.Source.Versions(ctx)
	if err != nil {
		return err
	}
	cur := map[string]*detect.RuleSet{}
	if m := st.sets.Load(); m != nil {
		cur = *m
	}
	next := make(map[string]*detect.RuleSet, len(versions))
	changed := len(versions) != len(cur)
	var firstErr error
	for vault, v := range versions {
		if r, ok := cur[vault]; ok && r != nil && r.Version == v {
			next[vault] = r
			continue
		}
		r, err := st.compile(ctx, vault)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			// Keep the last good set. With none yet, this vault is not ready.
			next[vault] = cur[vault]
			continue
		}
		next[vault] = r
		changed = true
	}
	if changed || st.sets.Load() == nil {
		st.sets.Store(&next)
	}
	st.synced.Store(true)
	return firstErr
}

func (st *Store) compile(ctx context.Context, vault string) (*detect.RuleSet, error) {
	snap, err := st.Source.Snapshot(ctx, vault)
	if err != nil {
		return nil, err
	}
	return Compile(snap, st.NewEngine)
}

// Compile turns a snapshot into a rule set.
func Compile(snap *Snapshot, newEngine func(map[string]float64) *detect.Engine) (*detect.RuleSet, error) {
	for i := range snap.Entities {
		e := &snap.Entities[i]
		if e.Kind != detect.KindValueList {
			continue
		}
		raw := snap.Values[e.Slug]
		if len(raw)%32 != 0 {
			return nil, errors.New("a value list has a damaged hash")
		}
		e.Values = make([][]byte, 0, len(raw)/32)
		for p := 0; p < len(raw); p += 32 {
			e.Values = append(e.Values, raw[p:p+32])
		}
	}
	rs, err := detect.NewRuleSet(newEngine(snap.Thresholds), snap.Version, snap.Entities, snap.ListKey)
	if err != nil {
		return nil, err
	}
	rs = rs.WithPacks(snap.Country, snap.Packs)
	if len(snap.Models) > 0 && NewModelFinder != nil && (snap.Sandbox || license.Current().Has(license.Business)) {
		if f := NewModelFinder(); f != nil {
			rs = rs.WithModel(f, snap.Models)
		}
	}
	return rs, nil
}

// Notify asks the run loop to sync now. It never blocks.
func (st *Store) Notify() {
	st.mu.Lock()
	w := st.wake
	st.mu.Unlock()
	if w != nil {
		select {
		case w <- struct{}{}:
		default:
		}
	}
}

// Run keeps the store current until ctx ends. Pool may be nil for a service with no
// database, such as the file redactor, which then relies on the poll alone.
func (st *Store) Run(ctx context.Context, pool *pgxpool.Pool) {
	wake := make(chan struct{}, 1)
	st.mu.Lock()
	st.wake = wake
	st.mu.Unlock()
	if pool != nil {
		go st.listen(ctx, pool, wake)
	}
	t := time.NewTicker(PollEvery)
	defer t.Stop()
	sync := func() {
		c, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		if err := st.Sync(c); err != nil && ctx.Err() == nil {
			var de *detect.DefinitionError
			if errors.As(err, &de) {
				log.Printf("rule set not applied: %s", de.Code)
			} else {
				log.Printf("rule set not applied")
			}
		}
	}
	if !st.synced.Load() {
		sync()
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-wake:
		}
		sync()
	}
}

func (st *Store) listen(ctx context.Context, pool *pgxpool.Pool, wake chan<- struct{}) {
	for ctx.Err() == nil {
		func() {
			conn, err := pool.Acquire(ctx)
			if err != nil {
				return
			}
			defer conn.Release()
			if _, err := conn.Exec(ctx, "LISTEN "+Channel); err != nil {
				return
			}
			defer func() {
				c, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				conn.Exec(c, "UNLISTEN "+Channel)
			}()
			for {
				if _, err := conn.Conn().WaitForNotification(ctx); err != nil {
					return
				}
				select {
				case wake <- struct{}{}:
				default:
				}
			}
		}()
		select {
		case <-ctx.Done():
		case <-time.After(2 * time.Second):
		}
	}
}

// HTTPSource reads rule sets from the vault API. Only the vault holds keys, so this is
// how other services get a vault's list key, and how the file redactor, which has no
// database access, gets anything at all.
type HTTPSource struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

func (h *HTTPSource) post(ctx context.Context, path string, in, out any) error {
	b, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.BaseURL+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+h.Token)
	req.Header.Set("Content-Type", "application/json")
	res, err := h.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return errors.New("rule set request refused")
	}
	return json.NewDecoder(res.Body).Decode(out)
}

// Versions implements Source.
func (h *HTTPSource) Versions(ctx context.Context) (map[string]int64, error) {
	var out struct {
		Versions map[string]int64 `json:"versions"`
	}
	err := h.post(ctx, "/internal/rulesets/versions", struct{}{}, &out)
	return out.Versions, err
}

// Snapshot implements Source.
func (h *HTTPSource) Snapshot(ctx context.Context, vault string) (*Snapshot, error) {
	var out Snapshot
	err := h.post(ctx, "/internal/rulesets/snapshot", map[string]string{"vault": vault}, &out)
	return &out, err
}
