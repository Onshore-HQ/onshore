package vault

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"onshore/data-plane/internal/audit"
	"onshore/data-plane/internal/detect"
	"onshore/data-plane/internal/policy"
)

// FieldForEntity finds a field for a detected entity type.
func (v *VaultMeta) FieldForEntity(entity string) string {
	var best string
	for _, f := range v.Fields {
		if f.DataType == entity && f.Kind != "transient" && (best == "" || f.Name < best) {
			best = f.Name
		}
	}
	return best
}

// DeterministicFieldForEntity finds a field whose tokens stay searchable in logs.
func (v *VaultMeta) DeterministicFieldForEntity(entity string) string {
	var best string
	for _, f := range v.Fields {
		if f.DataType == entity && f.Kind == "deterministic" && (best == "" || f.Name < best) {
			best = f.Name
		}
	}
	return best
}

// AppendControlEvent writes one control-plane event to the tenant's chain.
func (s *Service) AppendControlEvent(ctx context.Context, e audit.Event) error {
	e.EventID, e.OccurredAt = newUUID(), s.Now()
	return s.writeEvents(ctx, e.TenantID, []audit.Event{e})
}

// SeedSandbox adds synthetic people to a sandbox vault, from the vault's own country:
// a German vault gets German names, IBANs and tax IDs. Every value is generated and
// passes its type's checks, so no real data can enter this way. Production is refused.
func (s *Service) SeedSandbox(ctx context.Context, vaultID string, count int) (int, error) {
	v, err := s.Vault(ctx, vaultID)
	if err != nil {
		return 0, err
	}
	if v.Environment != "sandbox" {
		return 0, errInvalid("only sandbox vaults can be seeded")
	}
	if count <= 0 || count > 200 {
		count = 25
	}
	gen := detect.NewSamples(s.Now().UnixNano(), v.Country)
	c := Caller{TenantID: v.TenantID, PrincipalID: "system:sandbox-seed", Kind: "system", Module: "console", System: true}
	for i := 0; i < count; i++ {
		ref := fmt.Sprintf("sandbox_cust_%04d", i+1)
		var items []TokenizeItem
		for _, f := range v.Fields {
			if val := gen.Value(f.DataType); val != "" && f.Kind != "transient" {
				items = append(items, TokenizeItem{Field: f.Name, Value: val, SubjectRef: ref})
			}
		}
		if len(items) == 0 {
			return 0, errInvalid("the vault has no fields to seed")
		}
		if _, err := s.Tokenize(ctx, c, vaultID, items, true, "tokenize"); err != nil {
			return 0, err
		}
	}
	return count, nil
}

// Resident checks run in the country and return only true or false. Unlike
// InCountry's resident functions they are a fixed list, not customer JavaScript,
// so that there is no code execution inside the vault to secure.
const (
	CheckEquals     = "equals"
	CheckNameMatch  = "name_match"
	CheckAgeAtLeast = "age_at_least"
	CheckAmountOver = "amount_at_least"
)

// ResidentCheck compares a stored value without revealing it. A yes or no is still
// an oracle, so it needs its own policy action and shares the lookup limit.
func (s *Service) ResidentCheck(ctx context.Context, c Caller, vaultID, token, check, arg, purpose string) (bool, error) {
	if c.System {
		return false, errInvalid("system callers cannot run checks")
	}
	purpose = s.cleanPurposeIn(vaultID, purpose)
	started := s.Now()
	v, err := s.ownVault(ctx, c, vaultID)
	if err != nil {
		return false, err
	}
	rows, err := s.loadTokens(ctx, vaultID, []string{token})
	if err != nil {
		return false, err
	}
	r := rows[token]
	var f *Field
	if r != nil {
		f = v.ByID[r.fieldID]
	}
	if f == nil {
		return false, errTokenNotFound
	}
	d, nets, err := s.decide(ctx, c, "compare", f, purpose)
	if err != nil {
		return false, err
	}
	e := withDecision(s.event(c, vaultID, "compare", started), d, nets)
	e.FieldID, e.RecordID, e.TokenHash, e.Purpose, e.Detail = f.ID, r.recordID, HashToken(token), purpose, `{"check":"`+check+`"}`
	if !d.Allowed() || r.restricted {
		e.Decision = policy.Deny
		if err := s.writeEvents(ctx, c.TenantID, []audit.Event{e}); err != nil {
			return false, err
		}
		return false, errDenied(d)
	}
	over, err := s.overLookupLimit(ctx, c)
	if err != nil {
		return false, err
	}
	if over {
		return false, errRateLimited
	}
	stored, err := s.decrypt(ctx, vaultID, r)
	if err != nil {
		return false, err
	}
	result, err := runCheck(f.DataType, check, stored, arg, s.Now())
	if err != nil {
		return false, err
	}
	// The result stays out of the audit log: it is itself information about the value.
	if err := s.writeEvents(ctx, c.TenantID, []audit.Event{e}); err != nil {
		return false, err
	}
	return result, nil
}

func runCheck(dataType, check, stored, arg string, now time.Time) (bool, error) {
	switch check {
	case CheckEquals:
		n, ok := Normalize(dataType, arg)
		if !ok {
			return false, errValidation
		}
		return subtle.ConstantTimeCompare([]byte(stored), []byte(n)) == 1, nil
	case CheckNameMatch:
		if dataType != "person_name" {
			return false, errInvalid("name_match needs a person_name field")
		}
		n, ok := Normalize(dataType, arg)
		if !ok {
			return false, errValidation
		}
		return nameTokens(stored) == nameTokens(n), nil
	case CheckAgeAtLeast:
		if dataType != "date" {
			return false, errInvalid("age_at_least needs a date field")
		}
		years, err := strconv.Atoi(arg)
		if err != nil || years < 0 || years > 150 {
			return false, errInvalid("arg must be a number of years")
		}
		dob, err := parseDOB(stored)
		if err != nil {
			return false, errInvalid("the stored date is not in a recognised format")
		}
		return !dob.AddDate(years, 0, 0).After(now), nil
	case CheckAmountOver:
		// Any amount field: the global "amount" type, or the older naira-only one.
		if dataType != "amount" && dataType != "amount_ngn" {
			return false, errInvalid("amount_at_least needs an amount field")
		}
		min, err1 := ParseAmount(arg)
		have, err2 := ParseAmount(stored)
		if err1 != nil || err2 != nil {
			return false, errInvalid("amounts must be numeric")
		}
		return have >= min, nil
	}
	return false, errInvalid("unknown check")
}

// nameTokens makes name order irrelevant: NIBSS and banks often store surname first.
// ParseAmount reads an amount as people write it: currency symbols and codes are
// ignored, and "1,250.50", "1.250,50" and "1 250,50" all mean 1250.5. When only
// one separator appears, it is the decimal mark if one or two digits follow it.
func ParseAmount(v string) (float64, error) {
	var b strings.Builder
	for _, r := range v {
		if (r >= '0' && r <= '9') || r == '.' || r == ',' || r == '-' {
			b.WriteRune(r)
		}
	}
	n := b.String()
	dot, comma := strings.LastIndex(n, "."), strings.LastIndex(n, ",")
	switch {
	case dot >= 0 && comma >= 0:
		if comma > dot {
			n = strings.ReplaceAll(n, ".", "")
			n = strings.Replace(n, ",", ".", 1)
		} else {
			n = strings.ReplaceAll(n, ",", "")
		}
	case comma >= 0:
		if tail := len(n) - comma - 1; strings.Count(n, ",") == 1 && tail >= 1 && tail <= 2 {
			n = strings.Replace(n, ",", ".", 1)
		} else {
			n = strings.ReplaceAll(n, ",", "")
		}
	case dot >= 0:
		if tail := len(n) - dot - 1; strings.Count(n, ".") > 1 || tail == 3 {
			n = strings.ReplaceAll(n, ".", "")
		}
	}
	return strconv.ParseFloat(n, 64)
}

func nameTokens(n string) string {
	parts := strings.Fields(n)
	sort.Strings(parts)
	return strings.Join(parts, " ")
}

func parseDOB(v string) (time.Time, error) {
	for _, layout := range []string{"2006-01-02", "02/01/2006", "2/1/2006", "02-01-2006", "2 January 2006", "2 Jan 2006"} {
		if t, err := time.Parse(layout, v); err == nil {
			return t, nil
		}
	}
	return time.Time{}, errors.New("unrecognised date")
}

// DecideRestore says what a caller may see of each entity type in an AI reply and
// records it. Anything short of plaintext comes back masked.
func (s *Service) DecideRestore(ctx context.Context, c Caller, vaultID, route, purpose string, entities map[string]int) (map[string]string, error) {
	purpose = s.cleanPurposeIn(vaultID, purpose)
	started := s.Now()
	v, err := s.ownVault(ctx, c, vaultID)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	var events []audit.Event
	for entity, count := range entities {
		out[entity] = policy.Masked
		name := v.FieldForEntity(entity)
		if name == "" {
			continue
		}
		f := v.Fields[name]
		d, nets, err := s.decide(ctx, c, "detokenize", f, purpose)
		if err != nil {
			return nil, err
		}
		if d.Effect == policy.Plaintext {
			over, err := s.overRevealLimit(ctx, c, d)
			if err != nil {
				return nil, err
			}
			if !over {
				out[entity] = policy.Plaintext
			}
		}
		e := withDecision(s.event(c, vaultID, "detokenize", started), d, nets)
		e.FieldID, e.Purpose, e.Decision = f.ID, purpose, out[entity]
		e.Detail = fmt.Sprintf(`{"ai_route":%q,"values":%d}`, route, count)
		events = append(events, e)
	}
	return out, s.writeEvents(ctx, c.TenantID, events)
}

// AuthorizeFile applies the file_redact action. With counts it records the outcome.
func (s *Service) AuthorizeFile(ctx context.Context, c Caller, vaultID, purpose string, counts map[string]int, low bool) (bool, error) {
	purpose = s.cleanPurposeIn(vaultID, purpose)
	if _, err := s.ownVault(ctx, c, vaultID); err != nil {
		return false, err
	}
	d, nets, err := s.decide(ctx, c, "file_redact", nil, purpose)
	if err != nil {
		return false, err
	}
	e := withDecision(s.event(c, vaultID, "file_redact", s.Now()), d, nets)
	e.Purpose = purpose
	if !d.Allowed() {
		e.Decision = policy.Deny
		if err := s.writeEvents(ctx, c.TenantID, []audit.Event{e}); err != nil {
			return false, err
		}
		return false, errDenied(d)
	}
	if counts == nil {
		return true, nil // the pre-check; the outcome is recorded once the file is done
	}
	detail, _ := json.Marshal(map[string]any{"findings": counts, "low_confidence": low})
	e.Detail = string(detail)
	return true, s.writeEvents(ctx, c.TenantID, []audit.Event{e})
}

// VerifyAudit runs a full chain verification.
func (s *Service) VerifyAudit(ctx context.Context, tenantID string) (audit.Result, error) {
	var pubB64 string
	err := s.Pool.QueryRow(ctx, `SELECT public_key FROM data.audit_keys WHERE tenant_id=$1`, tenantID).Scan(&pubB64)
	var pub ed25519.PublicKey
	if err == nil {
		pub, _ = base64.StdEncoding.DecodeString(pubB64)
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return audit.Result{}, err
	}
	return audit.Verify(ctx, s.Pool, tenantID, pub)
}

// SignForTenant signs a report with the tenant's audit key.
func (s *Service) SignForTenant(ctx context.Context, tenantID string, msg []byte) (string, string, error) {
	priv, pub, err := s.AuditKey(ctx, tenantID)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg)), base64.StdEncoding.EncodeToString(pub), nil
}

// KeyInfo describes one data key, never its material.
type KeyInfo struct {
	ID        string     `json:"id"`
	VaultID   string     `json:"vault_id"`
	Status    string     `json:"status"`
	KEKRef    string     `json:"kek_ref"`
	Algorithm string     `json:"algorithm"`
	CreatedAt time.Time  `json:"created_at"`
	RotatedAt *time.Time `json:"rotated_at"`
}

// KeyStatus reports key ages for the Keys & security page.
func (s *Service) KeyStatus(ctx context.Context, tenantID string) (map[string]any, error) {
	rows, err := s.Pool.Query(ctx, `SELECT k.id,k.vault_id,k.status,k.kek_ref,k.algorithm,k.created_at,k.rotated_at FROM data.data_keys k JOIN control.vaults v ON v.id=k.vault_id WHERE v.tenant_id=$1 ORDER BY k.created_at DESC`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := []KeyInfo{}
	for rows.Next() {
		var k KeyInfo
		if err := rows.Scan(&k.ID, &k.VaultID, &k.Status, &k.KEKRef, &k.Algorithm, &k.CreatedAt, &k.RotatedAt); err != nil {
			return nil, err
		}
		list = append(list, k)
	}
	if rows.Err() != nil {
		return nil, rows.Err()
	}
	health := "ok"
	hc, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := s.Keys.Health(hc); err != nil {
		health = "unavailable"
	}
	return map[string]any{"backend": s.Keys.Name(), "health": health, "data_keys": list}, nil
}

// Stats reports protected record counts by field and token kind.
func (s *Service) Stats(ctx context.Context, tenantID string) (map[string]any, error) {
	rows, err := s.Pool.Query(ctx, `SELECT r.vault_id,f.name,f.data_type,f.in_payment_scope,count(*),count(*) FILTER (WHERE t.kind='deterministic'),count(*) FILTER (WHERE t.kind='cell'),count(*) FILTER (WHERE t.kind='transient')
		FROM data.records r JOIN data.tokens t ON t.record_id=r.id JOIN control.vault_fields f ON f.id=r.field_id JOIN control.vaults v ON v.id=r.vault_id
		WHERE v.tenant_id=$1 GROUP BY 1,2,3,4 ORDER BY 1,2`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type row struct {
		Vault         string `json:"vault_id"`
		Field         string `json:"field"`
		DataType      string `json:"data_type"`
		InScope       bool   `json:"in_payment_scope"`
		Count         int64  `json:"count"`
		Deterministic int64  `json:"deterministic"`
		Cell          int64  `json:"cell"`
		Transient     int64  `json:"transient"`
	}
	out := []row{}
	var total int64
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.Vault, &r.Field, &r.DataType, &r.InScope, &r.Count, &r.Deterministic, &r.Cell, &r.Transient); err != nil {
			return nil, err
		}
		out = append(out, r)
		total += r.Count
	}
	if rows.Err() != nil {
		return nil, rows.Err()
	}
	var subjects int64
	if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM data.subjects su JOIN control.vaults v ON v.id=su.vault_id WHERE v.tenant_id=$1`, tenantID).Scan(&subjects); err != nil {
		return nil, err
	}
	return map[string]any{"by_field": out, "records": total, "subjects": subjects}, nil
}

// ---- background jobs ---------------------------------------------------------

// locked runs f only if no other replica is running this job right now.
func (s *Service) locked(ctx context.Context, key int64, f func(tx pgx.Tx) error) error {
	return pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		var got bool
		if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock($1)`, key).Scan(&got); err != nil {
			return err
		}
		if !got {
			return nil
		}
		return f(tx)
	})
}

// RunJobs runs periodic maintenance until ctx ends.
func (s *Service) RunJobs(ctx context.Context) {
	run := func() {
		for name, job := range map[string]func(context.Context) error{
			"purge":      s.purgeExpired,
			"checkpoint": s.signCheckpoints,
			"usage":      s.RollupUsage,
			"anomaly":    s.detectAnomalies,
			"custom":     s.purgeCustom,
		} {
			jobCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
			if err := job(jobCtx); err != nil && ctx.Err() == nil {
				// Only the SQLSTATE: a driver message can quote values from the query.
				var pgErr *pgconn.PgError
				if errors.As(err, &pgErr) {
					log.Printf("job %s failed: sqlstate %s", name, pgErr.Code)
				} else {
					log.Printf("job %s failed", name)
				}
			}
			cancel()
		}
	}
	run()
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			run()
		}
	}
}

// purgeAudit applies each tenant's retention, keeping the chain verifiable.
func (s *Service) purgeAudit(ctx context.Context) error {
	return s.locked(ctx, 727105, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id FROM control.tenants`)
		if err != nil {
			return err
		}
		var ids []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			ids = append(ids, id)
		}
		rows.Close()
		for _, id := range ids {
			if _, err := tx.Exec(ctx, `SELECT events.purge_audit($1)`, id); err != nil {
				return err
			}
		}
		return nil
	})
}

// renewKeyToken keeps the key service token alive, daily at most.
func (s *Service) renewKeyToken(ctx context.Context) error {
	r, ok := s.Keys.(interface{ Renew(context.Context) error })
	if !ok || s.Now().Sub(s.lastRenew) < 24*time.Hour {
		return nil
	}
	if err := r.Renew(ctx); err != nil {
		return err
	}
	s.lastRenew = s.Now()
	return nil
}

// rotateKEKOnSchedule honours a tenant's rotation period (InCountry offers 30, 60,
// 180 or 360 days). The KEK is per deployment, so the shortest period applies.
func (s *Service) rotateKEKOnSchedule(ctx context.Context) error {
	var tenant string
	var due bool
	err := s.Pool.QueryRow(ctx, `SELECT t.id, coalesce((SELECT max(a.occurred_at) FROM events.audit_events a WHERE a.action='key_rotate' AND a.detail LIKE '%kek%'), t.created_at) < now()-make_interval(days => t.kek_rotation_days)
		FROM control.tenants t WHERE t.kek_rotation_days IS NOT NULL ORDER BY t.kek_rotation_days LIMIT 1`).Scan(&tenant, &due)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && !due) {
		return nil
	}
	if err != nil {
		return err
	}
	return s.RotateKEK(ctx, Caller{TenantID: tenant, PrincipalID: "system:rotation-schedule", Kind: "system", Module: "console"})
}

// purgeExpired removes transient values at expiry and old operational rows.
func (s *Service) purgeExpired(ctx context.Context) error {
	return s.locked(ctx, 727101, func(tx pgx.Tx) error {
		for _, q := range []string{
			`DELETE FROM data.records WHERE expires_at IS NOT NULL AND expires_at<now()`,
			`DELETE FROM data.used_assertions WHERE expires_at<now()`,
			`DELETE FROM data.client_tokens WHERE expires_at<now()-interval '1 day'`,
			`DELETE FROM data.cloak_twins WHERE expires_at<now()`,
			`DELETE FROM data.rate_counters WHERE window_start<now()-interval '1 day'`,
			`DELETE FROM events.detection_events WHERE occurred_at<now()-interval '13 months'`,
		} {
			if _, err := tx.Exec(ctx, q); err != nil {
				return err
			}
		}
		return nil
	})
}

// signCheckpoints signs each finished day's last hash, in each organisation's own time zone.
func (s *Service) signCheckpoints(ctx context.Context) error {
	return s.locked(ctx, 727102, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT d.tenant_id,d.day::text,e.seq,e.hash FROM (
				SELECT a.tenant_id,(a.occurred_at AT TIME ZONE control.tenant_tz(a.tenant_id))::date AS day,max(a.seq) AS seq FROM events.audit_events a
				WHERE (a.occurred_at AT TIME ZONE control.tenant_tz(a.tenant_id))::date < (now() AT TIME ZONE control.tenant_tz(a.tenant_id))::date GROUP BY 1,2) d
			JOIN events.audit_events e ON e.seq=d.seq
			WHERE NOT EXISTS (SELECT 1 FROM events.audit_checkpoints c WHERE c.tenant_id=d.tenant_id AND c.day=d.day)`)
		if err != nil {
			return err
		}
		type cp struct {
			tenant, day, hash string
			seq               int64
		}
		var todo []cp
		for rows.Next() {
			var c cp
			if err := rows.Scan(&c.tenant, &c.day, &c.seq, &c.hash); err != nil {
				rows.Close()
				return err
			}
			todo = append(todo, c)
		}
		rows.Close()
		if rows.Err() != nil {
			return rows.Err()
		}
		for _, c := range todo {
			if err := s.SignCheckpoint(ctx, tx, c.tenant, c.day, c.seq, c.hash); err != nil {
				return err
			}
		}
		return nil
	})
}

// SignCheckpoint records a signature over one day's final hash.
func (s *Service) SignCheckpoint(ctx context.Context, tx pgx.Tx, tenant, day string, seq int64, hash string) error {
	priv, _, err := s.AuditKey(ctx, tenant)
	if err != nil {
		return err
	}
	sig := ed25519.Sign(priv, audit.CheckpointMessage(tenant, day, seq, hash))
	_, err = tx.Exec(ctx, `INSERT INTO events.audit_checkpoints(tenant_id,day,seq,hash,signature) VALUES ($1,$2::date,$3,$4,$5) ON CONFLICT DO NOTHING`, tenant, day, seq, hash, base64.StdEncoding.EncodeToString(sig))
	return err
}

// RollupUsage recomputes today's and yesterday's daily usage from events.
func (s *Service) RollupUsage(ctx context.Context) error {
	return s.locked(ctx, 727103, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO events.usage_daily(vault_id,date,tokenize_count,detokenize_count,denied_count,detections_by_type,p95_latency_ms)
			SELECT a.vault_id,a.day,
				count(*) FILTER (WHERE a.action IN ('tokenize','insert')),
				count(*) FILTER (WHERE a.action='detokenize'),
				count(*) FILTER (WHERE a.decision='denied'),
				coalesce((SELECT jsonb_object_agg(x.entity_type,x.n) FROM (SELECT d.entity_type,sum(d.count) n FROM events.detection_events d WHERE d.vault_id=a.vault_id AND (d.occurred_at AT TIME ZONE control.vault_tz(d.vault_id))::date=a.day GROUP BY 1) x),'{}'),
				percentile_disc(0.95) WITHIN GROUP (ORDER BY a.latency_ms)
			FROM (SELECT vault_id,action,decision,latency_ms,(occurred_at AT TIME ZONE control.vault_tz(vault_id))::date AS day
				FROM events.audit_events WHERE vault_id IS NOT NULL AND occurred_at>now()-interval '2 days') a
			GROUP BY a.vault_id,a.day
			ON CONFLICT (vault_id,date) DO UPDATE SET tokenize_count=EXCLUDED.tokenize_count,detokenize_count=EXCLUDED.detokenize_count,denied_count=EXCLUDED.denied_count,detections_by_type=EXCLUDED.detections_by_type,p95_latency_ms=EXCLUDED.p95_latency_ms`)
		return err
	})
}

// detectAnomalies raises an alert when someone's reveals in the last hour are well
// above their own 30-day hourly average. The alert id dedupes per person per hour.
func (s *Service) detectAnomalies(ctx context.Context) error {
	return s.locked(ctx, 727104, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO events.alerts(id,tenant_id,kind,principal_id,detail,event_at)
			SELECT md5(n.tenant_id||n.principal_id||date_trunc('hour',now())::text)::uuid,n.tenant_id,'reveal_spike',n.principal_id,
				jsonb_build_object('last_hour',n.c,'hourly_average',round(coalesce(b.avg_hour,0)::numeric,2)),n.first_at
			FROM (SELECT tenant_id,principal_id,count(*) c,min(occurred_at) first_at FROM events.audit_events
				WHERE action='detokenize' AND occurred_at>now()-interval '1 hour' AND principal_id IS NOT NULL GROUP BY 1,2) n
			LEFT JOIN (SELECT principal_id,count(*)/720.0 avg_hour FROM events.audit_events
				WHERE action='detokenize' AND occurred_at BETWEEN now()-interval '30 days' AND now()-interval '1 hour' GROUP BY 1) b ON b.principal_id=n.principal_id
			WHERE n.c>=50 AND n.c>5*greatest(coalesce(b.avg_hour,0),1)
			ON CONFLICT (id) DO NOTHING`)
		return err
	})
}
