package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"onshore/data-plane/internal/detect"
	"onshore/data-plane/internal/rules"
)

// Limits from the update spec. They are starting points, and live here so that the
// control plane and the vault cannot disagree.
const (
	MaxValuesPerList  = 100_000
	MaxValuesPerVault = 1_000_000
	uploadKeepDays    = 30
)

// customAAD binds a stored sample or upload to its entity, so a ciphertext copied onto
// another row fails to decrypt.
func customAAD(kind, entityID, rowID string) []byte {
	return []byte("rv-custom|" + kind + "|" + entityID + "|" + rowID)
}

// entitySnapshot is the JSON stored in custom_entity_versions.snapshot.
type entitySnapshot = detect.CustomDef

// DBSource builds snapshots from the database. It runs only in the vault API, the one
// service that can unwrap keys.
type DBSource struct{ S *Service }

// Versions implements rules.Source. A vault appears here once it has anything to apply.
func (d *DBSource) Versions(ctx context.Context) (map[string]int64, error) {
	rows, err := d.S.Pool.Query(ctx, `SELECT v.id,coalesce(r.version,0) FROM control.vaults v LEFT JOIN control.ruleset_versions r ON r.vault_id=v.id
		WHERE v.status='active'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var id string
		var v int64
		if err := rows.Scan(&id, &v); err != nil {
			return nil, err
		}
		out[id] = v
	}
	return out, rows.Err()
}

// Snapshot implements rules.Source: published definitions only, never a pending edit.
func (d *DBSource) Snapshot(ctx context.Context, vault string) (*rules.Snapshot, error) {
	s := d.S
	out := &rules.Snapshot{Values: map[string][]byte{}}
	var thresholds []byte
	var enabled bool
	err := s.Pool.QueryRow(ctx, `SELECT coalesce(r.version,0),v.detection_thresholds,v.custom_entities_enabled,v.country,v.packs,v.model_modules,v.environment='sandbox' FROM control.vaults v LEFT JOIN control.ruleset_versions r ON r.vault_id=v.id WHERE v.id=$1`, vault).Scan(&out.Version, &thresholds, &enabled, &out.Country, &out.Packs, &out.Models, &out.Sandbox)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(thresholds, &out.Thresholds); err != nil {
		return nil, err
	}
	if !enabled {
		return out, nil
	}
	rows, err := s.Pool.Query(ctx, `SELECT e.id,e.status,e.version,e.list_version,x.snapshot,coalesce(l.max_words,1)
		FROM control.custom_entities e JOIN control.custom_entity_versions x ON x.entity_id=e.id AND x.version=e.version
		LEFT JOIN control.custom_entity_lists l ON l.entity_id=e.id AND l.list_version=e.list_version
		WHERE e.vault_id=$1 AND e.status IN ('shadow','enforcing') ORDER BY e.slug`, vault)
	if err != nil {
		return nil, err
	}
	type listRef struct {
		id, slug string
		version  int
	}
	var lists []listRef
	for rows.Next() {
		var def entitySnapshot
		var raw []byte
		var id, status string
		var version, listVersion, maxWords int
		if err := rows.Scan(&id, &status, &version, &listVersion, &raw, &maxWords); err != nil {
			rows.Close()
			return nil, err
		}
		if err := json.Unmarshal(raw, &def); err != nil {
			rows.Close()
			return nil, err
		}
		def.ID, def.Status, def.Version, def.MaxWords = id, status, version, maxWords
		out.Entities = append(out.Entities, def)
		if def.Kind == detect.KindValueList {
			lists = append(lists, listRef{id, def.Slug, listVersion})
		}
	}
	rows.Close()
	if rows.Err() != nil {
		return nil, rows.Err()
	}
	if len(lists) == 0 {
		return out, nil
	}
	if out.ListKey, err = s.listKey(ctx, vault); err != nil {
		return nil, err
	}
	for _, l := range lists {
		if out.Values[l.slug], err = s.listHashes(ctx, l.id, l.version); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (s *Service) listHashes(ctx context.Context, entityID string, listVersion int) ([]byte, error) {
	rows, err := s.Pool.Query(ctx, `SELECT value_hmac FROM control.custom_entity_values WHERE entity_id=$1 AND list_version=$2`, entityID, listVersion)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []byte
	for rows.Next() {
		var h []byte
		if err := rows.Scan(&h); err != nil {
			return nil, err
		}
		out = append(out, h...)
	}
	return out, rows.Err()
}

func (s *Service) listKey(ctx context.Context, vault string) ([]byte, error) {
	k, err := s.blindKey(ctx, vault)
	if err != nil {
		return nil, err
	}
	return detect.DeriveListKey(k), nil
}

// rulesFor returns a vault's rule set in the vault API. Before the store exists, as in
// some tests, built-ins apply.
func (s *Service) rulesFor(vault string) *detect.RuleSet {
	if s.Rules == nil {
		return detect.BaseRuleSet(s.Engine)
	}
	return s.Rules.For(vault)
}

// RulesFor is rulesFor for the HTTP layer.
func (s *Service) RulesFor(vault string) *detect.RuleSet { return s.rulesFor(vault) }

// StartRules loads rule sets once and keeps them current. A first failure leaves the
// store unsynced, so callers keep failing safe until it recovers.
func (s *Service) StartRules(ctx context.Context) {
	st := &rules.Store{Source: &DBSource{S: s}, NewEngine: func(t map[string]float64) *detect.Engine { return detect.New(s.engineConfig().WithThresholds(t)) }}
	s.Rules = st
	c, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	st.Sync(c) // best effort; Run retries
	go st.Run(ctx, s.Pool)
}

func (s *Service) engineConfig() detect.Config {
	return detect.Config{FormatPreservingPrefixes: []string{FPPrefixID, FPPrefixPhone}, IsOwnToken: s.isOwnToken}
}

// normalize is Normalize, extended to custom-typed fields. Those are checked against
// their entity, and a card number is refused as it is for free text.
func (s *Service) normalize(vault, dataType, v string) (string, bool) {
	if !strings.HasPrefix(dataType, "c_") {
		return Normalize(dataType, v)
	}
	n := strings.TrimSpace(v)
	if n == "" || !utf8.ValidString(n) || len(n) > 64*1024 {
		return "", false
	}
	for _, e := range cardCheck.Scan(n) {
		if e.Type == detect.CardPAN {
			return "", false
		}
	}
	rs := s.rulesFor(vault)
	if rs == nil || rs.Custom(dataType) == nil || !rs.Validate(dataType, n) {
		return "", false
	}
	return n, true
}

// cleanPurposeIn also removes the vault's own custom entities from free text.
func (s *Service) cleanPurposeIn(vault, p string) string {
	rs := s.rulesFor(vault)
	if rs == nil {
		rs = detect.BaseRuleSet(s.Engine)
	}
	active, observed := rs.Split(rs.Scan(p))
	// A shadow entity changes nothing in traffic, but the audit log is exported, so it
	// gets the stricter treatment: nothing recognised stays in it.
	clean := detect.Replace(p, active, func(e detect.Entity, _ string) string { return "[" + string(e.Type) + " removed]" })
	for _, e := range observed {
		if v := p[e.Start:e.End]; v != "" {
			clean = strings.ReplaceAll(clean, v, "["+string(e.Type)+" removed]")
		}
	}
	return stripLongNumbers(clean)
}

// draftSet compiles a test rule set: the built-in catalogue plus one definition, whatever
// its status, with its staged list if it has one.
func (s *Service) draftSet(ctx context.Context, vault, entityID string, def *detect.CustomDef) (*detect.RuleSet, error) {
	d := *def
	d.Status = "enforcing"
	var key []byte
	if d.Kind == detect.KindValueList {
		var live int
		var staged *int
		err := s.Pool.QueryRow(ctx, `SELECT list_version,staged_list_version FROM control.custom_entities WHERE id=$1 AND vault_id=$2`, entityID, vault).Scan(&live, &staged)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
		v := live
		if staged != nil {
			v = *staged
		}
		raw, err := s.listHashes(ctx, entityID, v)
		if err != nil {
			return nil, err
		}
		for p := 0; p+32 <= len(raw); p += 32 {
			d.Values = append(d.Values, raw[p:p+32])
		}
		if err := s.Pool.QueryRow(ctx, `SELECT coalesce(max(max_words),1) FROM control.custom_entity_lists WHERE entity_id=$1 AND list_version=$2`, entityID, v).Scan(&d.MaxWords); err != nil {
			return nil, err
		}
		if key, err = s.listKey(ctx, vault); err != nil {
			return nil, err
		}
	}
	base := s.rulesFor(vault)
	engine := s.Engine
	if base != nil {
		engine = base.Engine()
	}
	return detect.NewRuleSet(engine, 0, []detect.CustomDef{d}, key)
}

// BenchMatch is one highlighted match in the test bench.
type BenchMatch struct {
	Type   string  `json:"type"`
	Start  int     `json:"start"`
	End    int     `json:"end"`
	Score  float64 `json:"score"`
	Custom bool    `json:"custom"`
}

// TestBench scans ad-hoc text with a draft and the built-ins. A draft matches nothing
// anywhere else. The text is never stored or logged.
func (s *Service) TestBench(ctx context.Context, vault, entityID string, def *detect.CustomDef, text string) ([]BenchMatch, error) {
	if err := detect.CheckDefinition(def); err != nil {
		return nil, err
	}
	rs, err := s.draftSet(ctx, vault, entityID, def)
	if err != nil {
		return nil, err
	}
	out := []BenchMatch{}
	emit := func(ents []detect.Entity, shift int) {
		for _, e := range ents {
			out = append(out, BenchMatch{string(e.Type), e.Start + shift, e.End + shift, e.Score, e.Custom})
		}
	}
	if def.Kind == detect.KindJSONPath {
		pos := 0
		ok := detect.WalkJSON(text, func(path, value string) {
			i := strings.Index(text[pos:], value)
			if i < 0 {
				pos = 0
				if i = strings.Index(text, value); i < 0 {
					return
				}
			}
			shift := pos + i
			emit(rs.ScanLeaf(path, value, ""), shift)
			pos = shift
		})
		if ok {
			return out, nil
		}
	}
	emit(rs.Scan(text), 0)
	return out, nil
}

// SampleResult is one stored sample's outcome.
type SampleResult struct {
	ID          string `json:"id"`
	Sample      string `json:"sample"`
	ExpectMatch bool   `json:"expect_match"`
	Matched     bool   `json:"matched"`
	Passed      bool   `json:"passed"`
}

// TrySamples runs inline samples against one definition on its own, for a country pack
// that belongs to no vault yet. Nothing is stored. Value lists can't be in a pack: their
// values are the organisation's own data.
func (s *Service) TrySamples(def *detect.CustomDef, samples []SampleResult) ([]SampleResult, error) {
	if err := detect.CheckDefinition(def); err != nil {
		return nil, err
	}
	if def.Kind == detect.KindValueList {
		return nil, &detect.DefinitionError{Code: "invalid_request", Message: "a country pack can't hold a value list"}
	}
	d := *def
	d.Status = "enforcing"
	rs, err := detect.NewRuleSet(s.Engine, 0, []detect.CustomDef{d}, nil)
	if err != nil {
		return nil, err
	}
	out := make([]SampleResult, 0, len(samples))
	for i, smp := range samples {
		matched := len(rs.MatchesSample(d.Slug, smp.Sample)) > 0
		out = append(out, SampleResult{ID: strconv.Itoa(i), Sample: smp.Sample, ExpectMatch: smp.ExpectMatch, Matched: matched, Passed: matched == smp.ExpectMatch})
	}
	return out, nil
}

// AddSamples encrypts test samples and stores them.
func (s *Service) AddSamples(ctx context.Context, vault, entityID, by string, samples []struct {
	Sample      string `json:"sample"`
	ExpectMatch bool   `json:"expect_match"`
}) error {
	dekID, dek, err := s.activeDEK(ctx, vault)
	if err != nil {
		return err
	}
	for _, sm := range samples {
		id := "cet_" + newUUID()
		ct, nonce, err := Seal(dek, []byte(sm.Sample), customAAD("sample", entityID, id))
		if err != nil {
			return err
		}
		if _, err := s.Pool.Exec(ctx, `INSERT INTO control.custom_entity_tests(id,entity_id,sample_ciphertext,sample_nonce,dek_id,expect_match,created_by) VALUES ($1,$2,$3,$4,$5,$6,$7)`, id, entityID, ct, nonce, dekID, sm.ExpectMatch, by); err != nil {
			return err
		}
	}
	return nil
}

// DeleteSample removes one sample.
func (s *Service) DeleteSample(ctx context.Context, entityID, id string) error {
	_, err := s.Pool.Exec(ctx, `DELETE FROM control.custom_entity_tests WHERE id=$1 AND entity_id=$2`, id, entityID)
	return err
}

// RunSamples decrypts an entity's samples and runs them against a definition.
func (s *Service) RunSamples(ctx context.Context, vault, entityID string, def *detect.CustomDef) ([]SampleResult, error) {
	if err := detect.CheckDefinition(def); err != nil {
		return nil, err
	}
	rs, err := s.draftSet(ctx, vault, entityID, def)
	if err != nil {
		return nil, err
	}
	rows, err := s.Pool.Query(ctx, `SELECT id,sample_ciphertext,sample_nonce,dek_id,expect_match FROM control.custom_entity_tests WHERE entity_id=$1 ORDER BY created_at,id`, entityID)
	if err != nil {
		return nil, err
	}
	type row struct {
		id, dek   string
		ct, nonce []byte
		expect    bool
	}
	var list []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.ct, &r.nonce, &r.dek, &r.expect); err != nil {
			rows.Close()
			return nil, err
		}
		list = append(list, r)
	}
	rows.Close()
	if rows.Err() != nil {
		return nil, rows.Err()
	}
	out := make([]SampleResult, 0, len(list))
	for _, r := range list {
		var wrapped []byte
		if err := s.Pool.QueryRow(ctx, `SELECT wrapped_dek FROM data.data_keys WHERE id=$1 AND vault_id=$2`, r.dek, vault).Scan(&wrapped); err != nil {
			return nil, err
		}
		key, err := s.dekByID(ctx, vault, r.dek, wrapped)
		if err != nil {
			return nil, err
		}
		pt, err := Open(key, r.ct, r.nonce, customAAD("sample", entityID, r.id))
		if err != nil {
			return nil, err
		}
		matched := len(rs.MatchesSample(def.Slug, string(pt))) > 0
		out = append(out, SampleResult{r.id, string(pt), r.expect, matched, matched == r.expect})
	}
	return out, nil
}

// RejectedRow says why a list row was refused, without the row's contents.
type RejectedRow struct {
	Row    int    `json:"row"`
	Reason string `json:"reason"`
}

// UploadResult is the spec's count summary.
type UploadResult struct {
	Received     int           `json:"received"`
	Hashed       int           `json:"hashed"`
	Duplicates   int           `json:"duplicates"`
	Rejected     int           `json:"rejected"`
	RejectedRows []RejectedRow `json:"rejected_rows"`
	ListVersion  int           `json:"list_version"`
}

// ErrListTooLarge maps to 413 value_list_too_large.
var ErrListTooLarge = &Error{Status: 413, Code: "value_list_too_large", Message: "this list exceeds the per-list or per-vault value limit"}

// UploadValues hashes a list and stages it. It goes live only through approval. The
// values are kept for 30 days encrypted, so the list can be re-hashed; nothing else
// stores them, and they are never logged.
func (s *Service) UploadValues(ctx context.Context, vault, entityID string, values []string) (*UploadResult, error) {
	if len(values) > MaxValuesPerList {
		return nil, ErrListTooLarge
	}
	key, err := s.listKey(ctx, vault)
	if err != nil {
		return nil, err
	}
	res := &UploadResult{Received: len(values), RejectedRows: []RejectedRow{}}
	seen := make(map[string]struct{}, len(values))
	hashes := make([][]byte, 0, len(values))
	maxWords := 1
	for i, raw := range values {
		row := i + 1
		n := detect.NormalizeListValue(raw)
		switch {
		case n == "":
			res.RejectedRows = append(res.RejectedRows, RejectedRow{row, "empty"})
			continue
		case utf8.RuneCountInString(raw) > detect.MaxValueLength:
			res.RejectedRows = append(res.RejectedRows, RejectedRow{row, fmt.Sprintf("over %d characters", detect.MaxValueLength)})
			continue
		}
		if _, dup := seen[n]; dup {
			res.Duplicates++
			continue
		}
		seen[n] = struct{}{}
		hashes = append(hashes, detect.ListHMAC(key, n))
		if w := len(strings.Fields(n)); w > maxWords {
			maxWords = w
		}
	}
	res.Rejected = len(res.RejectedRows)
	res.Hashed = len(hashes)
	if len(res.RejectedRows) > 100 {
		res.RejectedRows = res.RejectedRows[:100]
	}
	dekID, dek, err := s.activeDEK(ctx, vault)
	if err != nil {
		return nil, err
	}
	blob, err := json.Marshal(values)
	if err != nil {
		return nil, err
	}
	uploadID := "ceu_" + newUUID()
	ct, nonce, err := Seal(dek, blob, customAAD("upload", entityID, uploadID))
	if err != nil {
		return nil, err
	}
	err = pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		// One upload at a time per entity, and a consistent view of the vault total.
		var live int
		var staged *int
		if err := tx.QueryRow(ctx, `SELECT list_version,staged_list_version FROM control.custom_entities WHERE id=$1 AND vault_id=$2 FOR SHARE`, entityID, vault).Scan(&live, &staged); err != nil {
			return err
		}
		var others int64
		if err := tx.QueryRow(ctx, `SELECT coalesce(sum(l.value_count),0) FROM control.custom_entity_lists l JOIN control.custom_entities e ON e.id=l.entity_id
			WHERE e.vault_id=$1 AND e.id<>$2 AND e.status<>'archived' AND l.list_version=coalesce(e.staged_list_version,e.list_version)`, vault, entityID).Scan(&others); err != nil {
			return err
		}
		if others+int64(len(hashes)) > MaxValuesPerVault {
			return ErrListTooLarge
		}
		var top int
		if err := tx.QueryRow(ctx, `SELECT coalesce(max(list_version),0) FROM control.custom_entity_lists WHERE entity_id=$1`, entityID).Scan(&top); err != nil {
			return err
		}
		res.ListVersion = top + 1
		if staged != nil { // a newer upload replaces one still waiting
			if _, err := tx.Exec(ctx, `DELETE FROM control.custom_entity_values WHERE entity_id=$1 AND list_version=$2`, entityID, *staged); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `DELETE FROM control.custom_entity_lists WHERE entity_id=$1 AND list_version=$2`, entityID, *staged); err != nil {
				return err
			}
		}
		rows := make([][]any, len(hashes))
		for i, h := range hashes {
			rows[i] = []any{entityID, res.ListVersion, h}
		}
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"control", "custom_entity_values"}, []string{"entity_id", "list_version", "value_hmac"}, pgx.CopyFromRows(rows)); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO control.custom_entity_lists(entity_id,list_version,value_count,max_words) VALUES ($1,$2,$3,$4)`, entityID, res.ListVersion, len(hashes), maxWords); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE control.custom_entities SET staged_list_version=$2 WHERE id=$1`, entityID, res.ListVersion); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO control.custom_entity_uploads(id,entity_id,ciphertext,nonce,dek_id,expires_at) VALUES ($1,$2,$3,$4,$5,now()+make_interval(days=>$6))`, uploadID, entityID, ct, nonce, dekID, uploadKeepDays)
		return err
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

// purgeCustom removes expired uploads and lists nothing points at any more.
func (s *Service) purgeCustom(ctx context.Context) error {
	if _, err := s.Pool.Exec(ctx, `DELETE FROM control.custom_entity_uploads WHERE expires_at<now()`); err != nil {
		return err
	}
	if _, err := s.Pool.Exec(ctx, `DELETE FROM control.custom_entity_values v USING control.custom_entities e WHERE e.id=v.entity_id AND v.list_version<>e.list_version AND v.list_version IS DISTINCT FROM e.staged_list_version`); err != nil {
		return err
	}
	_, err := s.Pool.Exec(ctx, `DELETE FROM control.custom_entity_lists l USING control.custom_entities e WHERE e.id=l.entity_id AND l.list_version<>e.list_version AND l.list_version IS DISTINCT FROM e.staged_list_version`)
	return err
}

// BenchmarkBytes is the corpus size for the publish check. Tests may lower it.
var BenchmarkBytes atomic.Int64

func init() { BenchmarkBytes.Store(50 << 20) }

// benchSlot allows one benchmark at a time: each reads a large corpus.
var benchSlot = make(chan struct{}, 1)

// BenchmarkDraft runs a draft over the synthetic corpus.
func (s *Service) BenchmarkDraft(ctx context.Context, vault, entityID string, def *detect.CustomDef) (*detect.BenchResult, error) {
	return s.BenchmarkDraftSize(ctx, vault, entityID, def, BenchmarkBytes.Load())
}

// BenchmarkDraftSize is BenchmarkDraft with a chosen corpus size.
func (s *Service) BenchmarkDraftSize(ctx context.Context, vault, entityID string, def *detect.CustomDef, size int64) (*detect.BenchResult, error) {
	if err := detect.CheckDefinition(def); err != nil {
		return nil, err
	}
	select {
	case benchSlot <- struct{}{}:
		defer func() { <-benchSlot }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	rs, err := s.draftSet(ctx, vault, entityID, def)
	if err != nil {
		return nil, err
	}
	return rs.Benchmark(ctx, def.Slug, size)
}
