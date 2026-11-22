package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"

	"onshore/data-plane/internal/audit"
)

// A digital twin is the sealed map from what an outside service saw (placeholders
// and stand-in names) back to the real values. The cloaked text itself is never
// kept here; the app holds it, and brings it back with the twin's id to uncloak.

// MaxTwinDays caps how long a twin is kept.
const MaxTwinDays = 365

var uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func twinAAD(vaultID, id string) []byte { return []byte(vaultID + "|twin|" + id) }

// SaveTwin seals items (JSON) and returns the twin's id. entities counts the real
// values by type; only the counts are stored in the clear.
func (s *Service) SaveTwin(ctx context.Context, c Caller, vaultID, route string, days int, items json.RawMessage, entities map[string]int) (string, error) {
	if days < 1 || days > MaxTwinDays {
		return "", errInvalid(fmt.Sprintf("keep a twin for 1 to %d days", MaxTwinDays))
	}
	started := s.Now()
	if _, err := s.ownVault(ctx, c, vaultID); err != nil {
		return "", err
	}
	dekID, key, err := s.activeDEK(ctx, vaultID)
	if err != nil {
		return "", err
	}
	id := newUUID()
	ct, nonce, err := Seal(key, items, twinAAD(vaultID, id))
	if err != nil {
		return "", err
	}
	counts, _ := json.Marshal(entities)
	var routeArg any
	if route != "" {
		routeArg = route
	}
	if _, err := s.Pool.Exec(ctx, `INSERT INTO data.cloak_twins(id,vault_id,route_id,dek_id,ciphertext,nonce,entities,created_by,expires_at) VALUES ($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9)`,
		id, vaultID, routeArg, dekID, ct, nonce, counts, c.PrincipalID, s.Now().Add(time.Duration(days)*24*time.Hour)); err != nil {
		return "", err
	}
	e := s.event(c, vaultID, "cloak", started)
	e.Detail = fmt.Sprintf(`{"twin":%q,"route":%q,"days":%d,"values":%s}`, id, route, days, counts)
	return id, s.writeEvents(ctx, c.TenantID, []audit.Event{e})
}

var errTwinGone = &Error{404, "not_found", "no such twin, or it has expired", ""}

// OpenTwin decrypts a twin and decides, for this caller and purpose, what they may
// see of each kind of value. The decision is audited like any reveal.
func (s *Service) OpenTwin(ctx context.Context, c Caller, vaultID, id, purpose string) (json.RawMessage, map[string]string, error) {
	if !uuidRe.MatchString(id) {
		return nil, nil, errTwinGone
	}
	if _, err := s.ownVault(ctx, c, vaultID); err != nil {
		return nil, nil, err
	}
	var dekID string
	var ct, nonce, counts []byte
	var route *string
	err := s.Pool.QueryRow(ctx, `SELECT dek_id,ciphertext,nonce,entities,route_id FROM data.cloak_twins WHERE id=$1::uuid AND vault_id=$2 AND expires_at>now()`, id, vaultID).Scan(&dekID, &ct, &nonce, &counts, &route)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, errTwinGone
	}
	if err != nil {
		return nil, nil, err
	}
	key, err := s.dekByID(ctx, vaultID, dekID, nil)
	if err != nil {
		return nil, nil, err
	}
	pt, err := Open(key, ct, nonce, twinAAD(vaultID, id))
	if err != nil {
		return nil, nil, fmt.Errorf("twin %s failed to decrypt", id)
	}
	var entities map[string]int
	if err := json.Unmarshal(counts, &entities); err != nil {
		return nil, nil, err
	}
	label := "twin:" + id
	if route != nil {
		label = *route + " twin:" + id
	}
	decisions, err := s.DecideRestore(ctx, c, vaultID, label, purpose, entities)
	if err != nil {
		return nil, nil, err
	}
	return pt, decisions, nil
}

// DeleteTwin removes a twin before it expires, for example when the customer
// asks to be forgotten.
func (s *Service) DeleteTwin(ctx context.Context, c Caller, vaultID, id string) error {
	if !uuidRe.MatchString(id) {
		return errTwinGone
	}
	if _, err := s.ownVault(ctx, c, vaultID); err != nil {
		return err
	}
	tag, err := s.Pool.Exec(ctx, `DELETE FROM data.cloak_twins WHERE id=$1::uuid AND vault_id=$2`, id, vaultID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return errTwinGone
	}
	e := s.event(c, vaultID, "delete", s.Now())
	e.Detail = fmt.Sprintf(`{"twin":%q}`, id)
	return s.writeEvents(ctx, c.TenantID, []audit.Event{e})
}

// reencryptTwins moves twins onto the vault's new key during rotation.
func (s *Service) reencryptTwins(ctx context.Context, vaultID, newID string, newKey []byte) error {
	for {
		rows, err := s.Pool.Query(ctx, `SELECT id::text,dek_id,ciphertext,nonce FROM data.cloak_twins WHERE vault_id=$1 AND dek_id<>$2 LIMIT 500`, vaultID, newID)
		if err != nil {
			return err
		}
		type twin struct {
			id, dek   string
			ct, nonce []byte
		}
		var batch []twin
		for rows.Next() {
			var t twin
			if err := rows.Scan(&t.id, &t.dek, &t.ct, &t.nonce); err != nil {
				rows.Close()
				return err
			}
			batch = append(batch, t)
		}
		rows.Close()
		if len(batch) == 0 {
			return nil
		}
		for _, t := range batch {
			old, err := s.dekByID(ctx, vaultID, t.dek, nil)
			if err != nil {
				return err
			}
			aad := twinAAD(vaultID, t.id)
			pt, err := Open(old, t.ct, t.nonce, aad)
			if err != nil {
				return fmt.Errorf("re-encrypt twin %s failed", t.id)
			}
			ct, nonce, err := Seal(newKey, pt, aad)
			if err != nil {
				return err
			}
			if _, err := s.Pool.Exec(ctx, `UPDATE data.cloak_twins SET ciphertext=$2,nonce=$3,dek_id=$4 WHERE id=$1::uuid`, t.id, ct, nonce, newID); err != nil {
				return err
			}
		}
	}
}

// RecordCloak audits a cloak call that kept no twin: counts only, never values.
func (s *Service) RecordCloak(ctx context.Context, c Caller, vaultID string, entities map[string]int) error {
	if _, err := s.ownVault(ctx, c, vaultID); err != nil {
		return err
	}
	counts, _ := json.Marshal(entities)
	e := s.event(c, vaultID, "cloak", s.Now())
	e.Detail = fmt.Sprintf(`{"values":%s}`, counts)
	return s.writeEvents(ctx, c.TenantID, []audit.Event{e})
}
