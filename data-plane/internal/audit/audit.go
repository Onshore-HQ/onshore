// Package audit appends hash-chained events and verifies the chain.
package audit

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// GenesisHash anchors the first event of a tenant's chain.
const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// Event is one audit row. Events never carry sensitive values.
type Event struct {
	EventID       string
	OccurredAt    time.Time
	TenantID      string
	VaultID       string
	PrincipalID   string
	PrincipalKind string
	SourceIP      string
	GeoCountry    string
	Network       string
	Module        string
	Action        string
	FieldID       string
	RecordID      string
	TokenHash     string
	Purpose       string
	Decision      string
	PolicyID      string
	PolicyVersion int
	BreakGlass    bool
	RequestID     string
	LatencyMS     int
	Detail        string
}

// Canonical renders the hashed form: a JSON array in a fixed field order.
func Canonical(e Event, prevHash string) []byte {
	b, _ := json.Marshal([]any{
		e.EventID, e.OccurredAt.UTC().Format("2006-01-02T15:04:05.000000Z"), e.TenantID, e.VaultID, e.PrincipalID, e.PrincipalKind,
		e.SourceIP, e.GeoCountry, e.Network, e.Module, e.Action, e.FieldID, e.RecordID, e.TokenHash, e.Purpose, e.Decision,
		e.PolicyID, e.PolicyVersion, e.BreakGlass, e.RequestID, e.LatencyMS, e.Detail, prevHash,
	})
	return b
}

// Hash chains an event to its predecessor.
func Hash(e Event, prevHash string) string {
	sum := sha256.Sum256(Canonical(e, prevHash))
	return hex.EncodeToString(sum[:])
}

func nullIf(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// Append writes events inside tx, holding the tenant's chain head until commit,
// so a value is never returned unless its audit event is durable.
func Append(ctx context.Context, tx pgx.Tx, tenantID string, events []Event) error {
	if len(events) == 0 {
		return nil
	}
	if _, err := tx.Exec(ctx, `INSERT INTO events.audit_heads(tenant_id, head_hash) VALUES ($1,$2) ON CONFLICT DO NOTHING`, tenantID, GenesisHash); err != nil {
		return err
	}
	var prev string
	if err := tx.QueryRow(ctx, `SELECT head_hash FROM events.audit_heads WHERE tenant_id=$1 FOR UPDATE`, tenantID).Scan(&prev); err != nil {
		return err
	}
	batch := &pgx.Batch{}
	for i := range events {
		e := &events[i]
		e.TenantID = tenantID
		e.OccurredAt = e.OccurredAt.UTC().Truncate(time.Microsecond)
		h := Hash(*e, prev)
		batch.Queue(`INSERT INTO events.audit_events(event_id,occurred_at,tenant_id,vault_id,principal_id,principal_kind,source_ip,geo_country,network,module,action,field_id,record_id,token_hash,purpose,decision,policy_id,policy_version,break_glass,request_id,latency_ms,detail,prev_hash,hash)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13::uuid,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24)`,
			e.EventID, e.OccurredAt, tenantID, nullIf(e.VaultID), nullIf(e.PrincipalID), nullIf(e.PrincipalKind), nullIf(e.SourceIP), nullIf(e.GeoCountry), nullIf(e.Network),
			e.Module, e.Action, nullIf(e.FieldID), nullIf(e.RecordID), nullIf(e.TokenHash), nullIf(e.Purpose), nullIf(e.Decision), nullIf(e.PolicyID), e.PolicyVersion, e.BreakGlass,
			nullIf(e.RequestID), e.LatencyMS, nullIf(e.Detail), prev, h)
		prev = h
	}
	br := tx.SendBatch(ctx, batch)
	for range events {
		if _, err := br.Exec(); err != nil {
			br.Close()
			return err
		}
	}
	if err := br.Close(); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `UPDATE events.audit_heads SET head_hash=$2, head_seq=head_seq+$3 WHERE tenant_id=$1`, tenantID, prev, len(events))
	return err
}

// Result reports a chain verification.
type Result struct {
	OK             bool      `json:"ok"`
	Events         int64     `json:"events_checked"`
	Checkpoints    int       `json:"checkpoints_checked"`
	VerifiedTo     time.Time `json:"verified_to,omitempty"`
	FirstBrokenSeq int64     `json:"first_broken_seq,omitempty"`
	Reason         string    `json:"reason,omitempty"`
}

// Verify walks a tenant's chain, checks head and signed checkpoints.
func Verify(ctx context.Context, pool *pgxpool.Pool, tenantID string, publicKey ed25519.PublicKey) (Result, error) {
	cps := map[int64][3]string{} // seq -> hash, signature, day
	rows, err := pool.Query(ctx, `SELECT seq, hash, signature, day::text FROM events.audit_checkpoints WHERE tenant_id=$1`, tenantID)
	if err != nil {
		return Result{}, err
	}
	for rows.Next() {
		var seq int64
		var h, sig, day string
		if err := rows.Scan(&seq, &h, &sig, &day); err != nil {
			rows.Close()
			return Result{}, err
		}
		cps[seq] = [3]string{h, sig, day}
	}
	rows.Close()
	if rows.Err() != nil {
		return Result{}, rows.Err()
	}
	// A purge removes a signed prefix and leaves its last hash as the anchor.
	prev := GenesisHash
	var anchorSeq, removed int64
	if err := pool.QueryRow(ctx, `SELECT seq,hash,events_removed FROM events.audit_anchors WHERE tenant_id=$1`, tenantID).Scan(&anchorSeq, &prev, &removed); err != nil && err != pgx.ErrNoRows {
		return Result{}, err
	}
	for seq := range cps {
		if seq <= anchorSeq {
			delete(cps, seq)
		}
	}
	wantCheckpoints := len(cps)

	rows, err = pool.Query(ctx, `SELECT seq,event_id::text,occurred_at,tenant_id,coalesce(vault_id,''),coalesce(principal_id,''),coalesce(principal_kind,''),coalesce(source_ip,''),coalesce(geo_country,''),coalesce(network,''),module,action,coalesce(field_id,''),coalesce(record_id::text,''),coalesce(token_hash,''),coalesce(purpose,''),coalesce(decision,''),coalesce(policy_id,''),coalesce(policy_version,0),break_glass,coalesce(request_id,''),coalesce(latency_ms,0),coalesce(detail,''),prev_hash,hash
		FROM events.audit_events WHERE tenant_id=$1 ORDER BY seq`, tenantID)
	if err != nil {
		return Result{}, err
	}
	defer rows.Close()
	res := Result{OK: true}
	for rows.Next() {
		var e Event
		var seq int64
		var prevHash, h string
		if err := rows.Scan(&seq, &e.EventID, &e.OccurredAt, &e.TenantID, &e.VaultID, &e.PrincipalID, &e.PrincipalKind, &e.SourceIP, &e.GeoCountry, &e.Network, &e.Module, &e.Action, &e.FieldID, &e.RecordID, &e.TokenHash, &e.Purpose, &e.Decision, &e.PolicyID, &e.PolicyVersion, &e.BreakGlass, &e.RequestID, &e.LatencyMS, &e.Detail, &prevHash, &h); err != nil {
			return Result{}, err
		}
		if prevHash != prev {
			return fail(res, seq, "an event is missing or out of order"), nil
		}
		if Hash(e, prev) != h {
			return fail(res, seq, "an event's contents do not match its hash"), nil
		}
		if cp, ok := cps[seq]; ok {
			if cp[0] != h {
				return fail(res, seq, "checkpoint hash does not match the chain"), nil
			}
			sig, err := base64.StdEncoding.DecodeString(cp[1])
			if err != nil || publicKey == nil || !ed25519.Verify(publicKey, CheckpointMessage(tenantID, cp[2], seq, h), sig) {
				return fail(res, seq, "checkpoint signature is invalid"), nil
			}
			res.Checkpoints++
		}
		prev = h
		res.Events++
		res.VerifiedTo = e.OccurredAt
	}
	if rows.Err() != nil {
		return Result{}, rows.Err()
	}
	if res.Checkpoints != wantCheckpoints {
		return fail(res, 0, "a signed checkpoint refers to an event that no longer exists"), nil
	}
	var head string
	var headSeq int64
	err = pool.QueryRow(ctx, `SELECT head_hash, head_seq FROM events.audit_heads WHERE tenant_id=$1`, tenantID).Scan(&head, &headSeq)
	if err == nil && (head != prev || headSeq != res.Events+removed) {
		return fail(res, 0, "the chain head does not match the last event: events were removed from the end"), nil
	}
	if err != nil && err != pgx.ErrNoRows {
		return Result{}, err
	}
	return res, nil
}

func fail(r Result, seq int64, reason string) Result {
	r.OK, r.FirstBrokenSeq, r.Reason = false, seq, reason
	return r
}

// CheckpointMessage is the byte string signed for a daily checkpoint.
func CheckpointMessage(tenantID, day string, seq int64, hash string) []byte {
	return []byte(fmt.Sprintf("rv-audit-checkpoint|%s|%s|%d|%s", tenantID, day, seq, hash))
}
