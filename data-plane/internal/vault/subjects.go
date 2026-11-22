package vault

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"

	"onshore/data-plane/internal/audit"
	"onshore/data-plane/internal/mask"
	"onshore/data-plane/internal/policy"
)

// SubjectSummary is one row of the records explorer.
type SubjectSummary struct {
	ID           string     `json:"id"`
	Ref          string     `json:"ref"`
	FieldCount   int        `json:"field_count"`
	CreatedAt    time.Time  `json:"created_at"`
	LastAccessed *time.Time `json:"last_accessed"`
	Reveals30d   int        `json:"reveals_30d"`
	Restricted   bool       `json:"restricted"`
}

func (s *Service) allowSearch(ctx context.Context, c Caller, vaultID string) (*VaultMeta, error) {
	v, err := s.ownVault(ctx, c, vaultID)
	if err != nil {
		return nil, err
	}
	d, nets, err := s.decide(ctx, c, "search", nil, "")
	if err != nil {
		return nil, err
	}
	if !d.Allowed() {
		e := withDecision(s.event(c, vaultID, "search", s.Now()), d, nets)
		e.Decision = policy.Deny
		if err := s.writeEvents(ctx, c.TenantID, []audit.Event{e}); err != nil {
			return nil, err
		}
		return nil, errDenied(d)
	}
	return v, nil
}

func (s *Service) subjectRef(ctx context.Context, vaultID, id, dekID string, ct, nonce []byte) (string, error) {
	dek, err := s.dekByID(ctx, vaultID, dekID, nil)
	if err != nil {
		return "", err
	}
	pt, err := Open(dek, ct, nonce, []byte(vaultID+"|subject|"+id))
	if err != nil {
		return "", errors.New("subject reference failed to decrypt")
	}
	return string(pt), nil
}

// SubjectQuery filters the explorer. Query is a subject ref, token or exact value.
type SubjectQuery struct {
	Query         string `json:"query"`
	FieldType     string `json:"field_type"`
	HasReveals    bool   `json:"has_reveals"`
	Flagged       bool   `json:"flagged"`
	CreatedAfter  string `json:"created_after"`
	CreatedBefore string `json:"created_before"`
	Sort          string `json:"sort"`
	Dir           string `json:"dir"`
	Limit         int    `json:"limit"`
	Offset        int    `json:"offset"`
}

// subjectOrder maps a requested sort to fixed SQL; the request's text never reaches the query.
// The reference is not sortable: it is stored encrypted. Never-accessed people sort last either way,
// and created_at then id keep paging stable when values tie.
func subjectOrder(sortBy, dir string) (string, error) {
	cols := map[string]string{"": "s.created_at", "created_at": "s.created_at", "field_count": "field_count", "last_accessed": "last_accessed", "reveals_30d": "reveals_30d"}
	col, ok := cols[sortBy]
	if !ok {
		return "", errInvalid("sort must be created_at, field_count, last_accessed or reveals_30d")
	}
	d := "DESC"
	switch dir {
	case "", "desc":
	case "asc":
		d = "ASC"
	default:
		return "", errInvalid("dir must be asc or desc")
	}
	return col + " " + d + " NULLS LAST, s.created_at DESC, s.id", nil
}

// ListSubjects powers the explorer. A typed value goes through the blind index;
// it is never stored or logged. Reveal counts come from the audit log, and count only real values
// shown: opening a person's page reads masked values, which is access but not a reveal.
func (s *Service) ListSubjects(ctx context.Context, c Caller, vaultID string, q SubjectQuery) ([]SubjectSummary, int, error) {
	order, err := subjectOrder(q.Sort, q.Dir)
	if err != nil {
		return nil, 0, err
	}
	v, err := s.allowSearch(ctx, c, vaultID)
	if err != nil {
		return nil, 0, err
	}
	if q.Limit <= 0 || q.Limit > 200 {
		q.Limit = 50
	}
	if q.Query != "" {
		// A typed value can confirm that someone exists, so it counts like a lookup.
		over, err := s.overLookupLimit(ctx, c)
		if err != nil {
			return nil, 0, err
		}
		if over {
			return nil, 0, errRateLimited
		}
	}
	for _, t := range []string{q.CreatedAfter, q.CreatedBefore} {
		if t != "" {
			if _, err := time.Parse(time.RFC3339, t); err != nil {
				return nil, 0, errInvalid("dates must be RFC 3339")
			}
		}
	}
	idxKey, err := s.blindKey(ctx, vaultID)
	if err != nil {
		return nil, 0, err
	}

	where := `s.vault_id=$1`
	args := []any{vaultID}
	arg := func(a any) string {
		args = append(args, a)
		return "$" + itoa(len(args))
	}
	if q.Query != "" {
		// Token, then subject ref, then every field's blind index for this value.
		idxes := [][]byte{}
		for _, f := range v.Fields {
			if n, ok := s.normalize(vaultID, f.DataType, q.Query); ok {
				idxes = append(idxes, blindIndex(idxKey, f.Scope(), n))
			}
		}
		where += ` AND (s.ref_index=` + arg(blindIndex(idxKey, "subject", q.Query)) +
			` OR EXISTS (SELECT 1 FROM data.record_subjects rs JOIN data.tokens t ON t.record_id=rs.record_id WHERE rs.subject_id=s.id AND t.token=` + arg(q.Query) + `)` +
			` OR EXISTS (SELECT 1 FROM data.record_subjects rs JOIN data.records r ON r.id=rs.record_id WHERE rs.subject_id=s.id AND r.blind_index=ANY(` + arg(idxes) + `)))`
	}
	if q.FieldType != "" {
		ids := []string{}
		for _, f := range v.Fields {
			if f.DataType == q.FieldType {
				ids = append(ids, f.ID)
			}
		}
		where += ` AND EXISTS (SELECT 1 FROM data.record_subjects rs JOIN data.records r ON r.id=rs.record_id WHERE rs.subject_id=s.id AND r.field_id=ANY(` + arg(ids) + `))`
	}
	if q.Flagged {
		where += ` AND s.restricted`
	}
	if q.CreatedAfter != "" {
		where += ` AND s.created_at>=` + arg(q.CreatedAfter) + `::timestamptz`
	}
	if q.CreatedBefore != "" {
		where += ` AND s.created_at<=` + arg(q.CreatedBefore) + `::timestamptz`
	}
	revealExpr := `(SELECT count(*) FROM events.audit_events a JOIN data.record_subjects rs ON rs.record_id=a.record_id WHERE rs.subject_id=s.id AND a.action='detokenize' AND a.decision='plaintext' AND a.occurred_at>now()-interval '30 days')`
	if q.HasReveals {
		where += ` AND ` + revealExpr + `>0`
	}
	var total int
	if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM data.subjects s WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	limit, offset := arg(q.Limit), arg(q.Offset)
	rows, err := s.Pool.Query(ctx, `SELECT s.id::text,s.dek_id,s.ref_ciphertext,s.ref_nonce,s.created_at,s.restricted,
			(SELECT count(*) FROM data.record_subjects rs WHERE rs.subject_id=s.id) AS field_count,
			(SELECT max(a.occurred_at) FROM events.audit_events a JOIN data.record_subjects rs ON rs.record_id=a.record_id WHERE rs.subject_id=s.id AND a.action='detokenize') AS last_accessed,
			`+revealExpr+` AS reveals_30d
		FROM data.subjects s WHERE `+where+` ORDER BY `+order+` LIMIT `+limit+` OFFSET `+offset, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []SubjectSummary{}
	type enc struct {
		dek       string
		ct, nonce []byte
	}
	var encs []enc
	for rows.Next() {
		var r SubjectSummary
		var e enc
		if err := rows.Scan(&r.ID, &e.dek, &e.ct, &e.nonce, &r.CreatedAt, &r.Restricted, &r.FieldCount, &r.LastAccessed, &r.Reveals30d); err != nil {
			return nil, 0, err
		}
		out = append(out, r)
		encs = append(encs, e)
	}
	if rows.Err() != nil {
		return nil, 0, rows.Err()
	}
	for i := range out {
		if out[i].Ref, err = s.subjectRef(ctx, vaultID, out[i].ID, encs[i].dek, encs[i].ct, encs[i].nonce); err != nil {
			return nil, 0, err
		}
	}
	return out, total, nil
}

func itoa(i int) string {
	if i < 10 {
		return string(rune('0' + i))
	}
	return itoa(i/10) + string(rune('0'+i%10))
}

// SubjectField is one value on the subject page. Value is masked or absent:
// plaintext requires a separate reveal with a stated purpose.
type SubjectField struct {
	Field    string `json:"field"`
	DataType string `json:"data_type"`
	Token    string `json:"token"`
	Masked   string `json:"masked,omitempty"`
	Decision string `json:"decision"`
	RecordID string `json:"record_id"`
}

// SubjectDetail is the drill-down page.
type SubjectDetail struct {
	SubjectSummary
	Fields []SubjectField `json:"fields"`
}

func (s *Service) subjectRows(ctx context.Context, vaultID, subjectID string) ([]*tokenRow, error) {
	rows, err := s.Pool.Query(ctx, `SELECT DISTINCT ON (r.id) t.token,r.id::text,r.field_id,r.dek_id,r.ciphertext,r.nonce
		FROM data.record_subjects rs JOIN data.records r ON r.id=rs.record_id JOIN data.tokens t ON t.record_id=r.id
		WHERE rs.subject_id=$1::uuid AND r.vault_id=$2 ORDER BY r.id,t.created_at DESC`, subjectID, vaultID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*tokenRow
	for rows.Next() {
		r := &tokenRow{}
		if err := rows.Scan(&r.token, &r.recordID, &r.fieldID, &r.dekID, &r.ciphertext, &r.nonce); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetSubject shows one person's fields. Opening the page is itself audited,
// because it displays masked values.
func (s *Service) GetSubject(ctx context.Context, c Caller, vaultID, subjectID string) (*SubjectDetail, error) {
	started := s.Now()
	v, err := s.allowSearch(ctx, c, vaultID)
	if err != nil {
		return nil, err
	}
	d := &SubjectDetail{}
	var dek string
	var ct, nonce []byte
	err = s.Pool.QueryRow(ctx, `SELECT id::text,dek_id,ref_ciphertext,ref_nonce,created_at,restricted FROM data.subjects WHERE id=$1::uuid AND vault_id=$2`, subjectID, vaultID).Scan(&d.ID, &dek, &ct, &nonce, &d.CreatedAt, &d.Restricted)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errNoRecord
	}
	if err != nil {
		return nil, err
	}
	if d.Ref, err = s.subjectRef(ctx, vaultID, d.ID, dek, ct, nonce); err != nil {
		return nil, err
	}
	recs, err := s.subjectRows(ctx, vaultID, subjectID)
	if err != nil {
		return nil, err
	}
	d.FieldCount = len(recs)
	events := []audit.Event{}
	d.Fields = []SubjectField{}
	for _, r := range recs {
		f := v.ByID[r.fieldID]
		if f == nil {
			continue
		}
		dec, nets, err := s.decide(ctx, c, "detokenize", f, "subject page view")
		if err != nil {
			return nil, err
		}
		sf := SubjectField{Field: f.Name, DataType: f.DataType, Token: r.token, RecordID: r.recordID, Decision: dec.Effect}
		// The page never shows plaintext, even when a reveal would be allowed.
		if (dec.Effect == policy.Plaintext || dec.Effect == policy.Masked) && !d.Restricted {
			over, err := s.overRevealLimit(ctx, c, dec)
			if err != nil {
				return nil, err
			}
			if over {
				sf.Decision = policy.TokenOnly // the hourly limit is spent; show the token only
				d.Fields = append(d.Fields, sf)
				continue
			}
			pt, err := s.decrypt(ctx, vaultID, r)
			if err != nil {
				return nil, err
			}
			sf.Masked = mask.Value(f.DataType, f.MaskRule, pt)
			e := withDecision(s.event(c, vaultID, "detokenize", started), dec, nets)
			e.Module, e.FieldID, e.RecordID, e.TokenHash, e.Purpose, e.Decision = "console", f.ID, r.recordID, HashToken(r.token), "subject page view", policy.Masked
			events = append(events, e)
		}
		d.Fields = append(d.Fields, sf)
	}
	sort.Slice(d.Fields, func(i, j int) bool { return d.Fields[i].Field < d.Fields[j].Field })
	if err := s.writeEvents(ctx, c.TenantID, events); err != nil {
		return nil, err
	}
	return d, nil
}

// ExportSubject returns one person's data for an NDPA access request. Each field
// follows policy for the export action; a policy may return plaintext or masked.
func (s *Service) ExportSubject(ctx context.Context, c Caller, vaultID, subjectID, purpose string) ([]map[string]string, error) {
	purpose = s.cleanPurposeIn(vaultID, purpose)
	started := s.Now()
	v, err := s.ownVault(ctx, c, vaultID)
	if err != nil {
		return nil, err
	}
	recs, err := s.subjectRows(ctx, vaultID, subjectID)
	if err != nil {
		return nil, err
	}
	if len(recs) == 0 {
		return nil, errNoRecord
	}
	out := []map[string]string{}
	events := []audit.Event{}
	var denied *Error
	for _, r := range recs {
		f := v.ByID[r.fieldID]
		if f == nil {
			continue
		}
		dec, nets, err := s.decide(ctx, c, "export", f, purpose)
		if err != nil {
			return nil, err
		}
		e := withDecision(s.event(c, vaultID, "export", started), dec, nets)
		e.FieldID, e.RecordID, e.Purpose = f.ID, r.recordID, purpose
		events = append(events, e)
		if !dec.Allowed() {
			denied = errDenied(dec)
			continue
		}
		over, err := s.overRevealLimit(ctx, c, dec)
		if err != nil {
			return nil, err
		}
		if over {
			e.Decision, e.Detail = policy.Deny, `{"reason":"rate_limited"}`
			events[len(events)-1] = e
			denied = errRateLimited
			continue
		}
		pt, err := s.decrypt(ctx, vaultID, r)
		if err != nil {
			return nil, err
		}
		val := pt
		if dec.Effect == policy.Masked {
			val = mask.Value(f.DataType, f.MaskRule, pt)
		}
		out = append(out, map[string]string{"field": f.Name, "data_type": f.DataType, "value": val, "token": r.token, "decision": dec.Effect})
	}
	if err := s.writeEvents(ctx, c.TenantID, events); err != nil {
		return nil, err
	}
	if denied != nil {
		return nil, denied
	}
	return out, nil
}

// EraseSubject deletes a person's data. A deterministic value shared with
// another subject survives until its last owner is erased.
func (s *Service) EraseSubject(ctx context.Context, c Caller, vaultID, subjectID, purpose string) (int, error) {
	purpose = s.cleanPurposeIn(vaultID, purpose)
	started := s.Now()
	if _, err := s.ownVault(ctx, c, vaultID); err != nil {
		return 0, err
	}
	d, nets, err := s.decide(ctx, c, "delete", nil, purpose)
	if err != nil {
		return 0, err
	}
	base := withDecision(s.event(c, vaultID, "delete", started), d, nets)
	base.Purpose = purpose
	if !d.Allowed() {
		base.Decision = policy.Deny
		if err := s.writeEvents(ctx, c.TenantID, []audit.Event{base}); err != nil {
			return 0, err
		}
		return 0, errDenied(d)
	}
	deleted := 0
	err = pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM data.subjects WHERE id=$1::uuid AND vault_id=$2)`, subjectID, vaultID).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return errNoRecord
		}
		rows, err := tx.Query(ctx, `DELETE FROM data.records r USING data.record_subjects rs
			WHERE rs.record_id=r.id AND rs.subject_id=$1::uuid
			  AND NOT EXISTS (SELECT 1 FROM data.record_subjects o WHERE o.record_id=r.id AND o.subject_id<>$1::uuid)
			RETURNING r.id::text,r.field_id`, subjectID)
		if err != nil {
			return err
		}
		events := []audit.Event{}
		for rows.Next() {
			e := base
			e.EventID = newUUID()
			if err := rows.Scan(&e.RecordID, &e.FieldID); err != nil {
				rows.Close()
				return err
			}
			events = append(events, e)
			deleted++
		}
		rows.Close()
		if rows.Err() != nil {
			return rows.Err()
		}
		if _, err := tx.Exec(ctx, `DELETE FROM data.subjects WHERE id=$1::uuid`, subjectID); err != nil {
			return err
		}
		e := base
		e.EventID, e.Detail = newUUID(), `{"erased_subject":"`+subjectID+`"}`
		return audit.Append(ctx, tx, c.TenantID, append(events, e))
	})
	return deleted, err
}

// RestrictSubject applies or lifts an NDPA restriction; while set, nothing reveals.
func (s *Service) RestrictSubject(ctx context.Context, c Caller, vaultID, subjectID string, restricted bool, purpose string) error {
	purpose = s.cleanPurposeIn(vaultID, purpose)
	started := s.Now()
	if _, err := s.ownVault(ctx, c, vaultID); err != nil {
		return err
	}
	d, nets, err := s.decide(ctx, c, "delete", nil, purpose)
	if err != nil {
		return err
	}
	e := withDecision(s.event(c, vaultID, "delete", started), d, nets)
	e.Purpose = purpose
	if !d.Allowed() {
		e.Decision = policy.Deny
		if err := s.writeEvents(ctx, c.TenantID, []audit.Event{e}); err != nil {
			return err
		}
		return errDenied(d)
	}
	if restricted {
		e.Detail = `{"restricted":true,"subject":"` + subjectID + `"}`
	} else {
		e.Detail = `{"restricted":false,"subject":"` + subjectID + `"}`
	}
	return pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE data.subjects SET restricted=$3 WHERE id=$1::uuid AND vault_id=$2`, subjectID, vaultID, restricted)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return errNoRecord
		}
		return audit.Append(ctx, tx, c.TenantID, []audit.Event{e})
	})
}

// GetRecord reads a structured record (or a single value), each field per policy.
func (s *Service) GetRecord(ctx context.Context, c Caller, vaultID, id, purpose string) (map[string]DetokenizeResult, error) {
	rows, err := s.Pool.Query(ctx, `SELECT DISTINCT ON (r.id) t.token,r.field_id FROM data.records r JOIN data.tokens t ON t.record_id=r.id
		WHERE r.vault_id=$1 AND (r.record_group=$2::uuid OR r.id=$2::uuid) ORDER BY r.id,t.created_at DESC`, vaultID, id)
	if err != nil {
		return nil, err
	}
	var tokens, fieldIDs []string
	for rows.Next() {
		var t, f string
		if err := rows.Scan(&t, &f); err != nil {
			rows.Close()
			return nil, err
		}
		tokens, fieldIDs = append(tokens, t), append(fieldIDs, f)
	}
	rows.Close()
	if rows.Err() != nil {
		return nil, rows.Err()
	}
	if len(tokens) == 0 {
		return nil, errNoRecord
	}
	v, err := s.ownVault(ctx, c, vaultID)
	if err != nil {
		return nil, err
	}
	res, err := s.Detokenize(ctx, c, vaultID, tokens, purpose, true)
	if err != nil {
		return nil, err
	}
	out := map[string]DetokenizeResult{}
	for i, r := range res {
		if f := v.ByID[fieldIDs[i]]; f != nil {
			out[f.Name] = r
		}
	}
	return out, nil
}
