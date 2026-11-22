package vault

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"onshore/data-plane/internal/audit"
)

const (
	clientTokenDefaultTTL = 2 * time.Minute
	clientTokenMaxTTL     = 10 * time.Minute
	clientTokenMaxFields  = 10
	clientTokenMaxTokens  = 20
)

// ModuleEmbed is recorded in the audit log for anything done through a component.
const ModuleEmbed = "embed"

var embedOriginRe = regexp.MustCompile(`^https?://[a-z0-9.-]+(:[0-9]{1,5})?$`)

// appOriginRe names a native app, which has no web origin. It is a name and not proof: see
// docs/mobile-sdks.md. It can never be framed into, so it stays out of frame-ancestors.
var appOriginRe = regexp.MustCompile(`^rvapp://[a-z0-9][a-z0-9._-]{0,150}$`)

// IsAppOrigin reports a native app's name.
func IsAppOrigin(o string) bool { return appOriginRe.MatchString(o) }

// ValidEmbedOrigin guards a value that ends up in a Content-Security-Policy header.
func ValidEmbedOrigin(o string) bool { return embedOriginRe.MatchString(o) || IsAppOrigin(o) }

// ValidFrameOrigin reports an origin that can be listed in frame-ancestors.
func ValidFrameOrigin(o string) bool { return embedOriginRe.MatchString(o) }

// ErrClientToken is one answer for a token that is unknown, expired, used, or held by the
// wrong page, so that a caller cannot tell which.
var ErrClientToken = &Error{Status: 401, Code: "invalid_client_token", Message: "this client token is not valid; request a new one"}

// ClientTokenRequest is what a customer's backend asks for.
type ClientTokenRequest struct {
	Kind       string   `json:"kind"`
	Origin     string   `json:"origin"`
	Fields     []string `json:"fields"`
	Tokens     []string `json:"tokens"`
	Purpose    string   `json:"purpose"`
	OnBehalfOf string   `json:"on_behalf_of"`
	SubjectRef string   `json:"subject_ref"`
	BindIP     string   `json:"bind_ip"`
	TTLSeconds int      `json:"ttl_seconds"`
}

// ClientToken is a redeemable token as stored.
type ClientToken struct {
	ID, TenantID, VaultID, PrincipalID, Kind, Origin, Purpose, SubjectRef string
	Fields, Tokens                                                        []string
}

func hashClientToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// MintClientToken issues a single-use capability scoped to one page, and to named fields
// or named tokens. Policy is checked here so a mistake fails early, and again at redemption,
// which is the check that counts.
func (s *Service) MintClientToken(ctx context.Context, c Caller, vaultID string, r ClientTokenRequest) (string, time.Time, error) {
	v, err := s.ownVault(ctx, c, vaultID)
	if err != nil {
		return "", time.Time{}, err
	}
	allowed := false
	for _, o := range v.EmbedOrigins {
		if o == r.Origin {
			allowed = true
		}
	}
	if !allowed {
		return "", time.Time{}, &Error{Status: 403, Code: "origin_not_allowed", Message: "add this origin to the vault's secure components settings first"}
	}
	ttl := clientTokenDefaultTTL
	if r.TTLSeconds != 0 {
		ttl = time.Duration(r.TTLSeconds) * time.Second
		if ttl < 0 || ttl > clientTokenMaxTTL {
			return "", time.Time{}, errInvalid("ttl_seconds must be between 1 and 600")
		}
	}
	purpose := ""
	switch r.Kind {
	case "collect":
		if len(r.Fields) == 0 || len(r.Fields) > clientTokenMaxFields || len(r.Tokens) > 0 {
			return "", time.Time{}, errInvalid("collect names between 1 and 10 fields, and no tokens")
		}
		for _, name := range r.Fields {
			f := v.Fields[name]
			if f == nil {
				return "", time.Time{}, errInvalid("unknown field")
			}
			d, _, err := s.decide(ctx, c, "tokenize", f, "")
			if err != nil {
				return "", time.Time{}, err
			}
			if !d.Allowed() {
				return "", time.Time{}, errDenied(d)
			}
		}
	case "reveal":
		if len(r.Tokens) == 0 || len(r.Tokens) > clientTokenMaxTokens || len(r.Fields) > 0 {
			return "", time.Time{}, errInvalid("reveal names between 1 and 20 tokens, and no fields")
		}
		if strings.TrimSpace(r.Purpose) == "" || len(r.Purpose) > 500 || len(r.OnBehalfOf) > 200 {
			return "", time.Time{}, errInvalid("reveal needs a purpose of up to 500 characters")
		}
		purpose = r.Purpose
		if r.OnBehalfOf != "" {
			purpose += " [for " + r.OnBehalfOf + "]"
		}
		purpose = s.cleanPurposeIn(vaultID, purpose)
	default:
		return "", time.Time{}, errInvalid("kind must be collect or reveal")
	}
	raw := "rvct_" + randomString(base62, 40)
	sealedSubject, err := sealSubject(raw, r.SubjectRef)
	if err != nil {
		return "", time.Time{}, err
	}
	id := "ct_" + randomString(base62, 16)
	expires := s.Now().Add(ttl)
	if _, err := s.Pool.Exec(ctx, `INSERT INTO data.client_tokens(hash,id,tenant_id,vault_id,principal_id,kind,fields,tokens,origin,purpose,subject_ref,bind_ip,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
		hashClientToken(raw), id, c.TenantID, vaultID, c.PrincipalID, r.Kind, append([]string{}, r.Fields...), append([]string{}, r.Tokens...), r.Origin, purpose, sealedSubject, r.BindIP, expires); err != nil {
		return "", time.Time{}, err
	}
	e := s.event(c, vaultID, "client_token_mint", s.Now())
	detail, _ := json.Marshal(map[string]any{"client_token": id, "kind": r.Kind, "origin": r.Origin, "fields": r.Fields, "tokens": len(r.Tokens)})
	e.Detail = string(detail)
	e.Purpose = purpose
	if err := s.writeEvents(ctx, c.TenantID, []audit.Event{e}); err != nil {
		return "", time.Time{}, err
	}
	return raw, expires, nil
}

func scanClientToken(row pgx.Row, raw string) (*ClientToken, error) {
	t := &ClientToken{}
	var sealed string
	err := row.Scan(&t.ID, &t.TenantID, &t.VaultID, &t.PrincipalID, &t.Kind, &t.Fields, &t.Tokens, &t.Origin, &t.Purpose, &sealed)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrClientToken
	}
	if err != nil {
		return nil, err
	}
	if t.SubjectRef, err = openSubject(raw, sealed); err != nil {
		return nil, err
	}
	return t, nil
}

const clientTokenCols = `id,tenant_id,vault_id,principal_id,kind,fields,tokens,origin,purpose,subject_ref`

// PeekClientToken checks a token without using it up, for a frame loading and for a
// format check, so that a typo does not cost the user their session.
func (s *Service) PeekClientToken(ctx context.Context, raw, origin, ip string) (*ClientToken, error) {
	t, err := scanClientToken(s.Pool.QueryRow(ctx, `SELECT `+clientTokenCols+` FROM data.client_tokens WHERE hash=$1 AND used_at IS NULL AND expires_at>now() AND origin=$2 AND (bind_ip='' OR bind_ip=$3)`, hashClientToken(raw), origin, ip), raw)
	if err != nil {
		return nil, err
	}
	// Turning the vault's origin off stops tokens already issued.
	v, err := s.Vault(ctx, t.VaultID)
	if err != nil {
		return nil, ErrClientToken
	}
	for _, o := range v.EmbedOrigins {
		if o == origin {
			return t, nil
		}
	}
	return nil, ErrClientToken
}

// TakeClientToken uses a token up atomically: two racing requests cannot both win.
func (s *Service) TakeClientToken(ctx context.Context, raw, origin, ip string) (*ClientToken, error) {
	return scanClientToken(s.Pool.QueryRow(ctx, `UPDATE data.client_tokens SET used_at=now() WHERE hash=$1 AND used_at IS NULL AND expires_at>now() AND origin=$2 AND (bind_ip='' OR bind_ip=$3) RETURNING `+clientTokenCols, hashClientToken(raw), origin, ip), raw)
}

// FieldProblem is a format failure, naming the field but never echoing its value.
type FieldProblem struct {
	Field string `json:"field"`
	Code  string `json:"code"`
}

// CheckCollectValues validates submitted values against a token's fields.
func (s *Service) CheckCollectValues(ctx context.Context, t *ClientToken, values map[string]string) ([]FieldProblem, error) {
	v, err := s.Vault(ctx, t.VaultID)
	if err != nil {
		return nil, err
	}
	problems := []FieldProblem{}
	for _, name := range t.Fields {
		f := v.Fields[name]
		if f == nil {
			return nil, ErrClientToken
		}
		value, ok := values[name]
		if !ok || strings.TrimSpace(value) == "" {
			problems = append(problems, FieldProblem{name, "required"})
			continue
		}
		if _, ok := s.normalize(t.VaultID, f.DataType, value); !ok {
			problems = append(problems, FieldProblem{name, "validation_failed"})
		}
	}
	for name := range values {
		found := false
		for _, want := range t.Fields {
			found = found || want == name
		}
		if !found {
			return nil, errInvalid("a value was sent for a field this token does not cover")
		}
	}
	return problems, nil
}

// EmbedCollect stores values as the principal who minted the token.
func (s *Service) EmbedCollect(ctx context.Context, c Caller, t *ClientToken, values map[string]string) (map[string]string, error) {
	items := make([]TokenizeItem, len(t.Fields))
	for i, name := range t.Fields {
		items[i] = TokenizeItem{Field: name, Value: values[name], SubjectRef: t.SubjectRef}
	}
	res, err := s.Tokenize(ctx, c, t.VaultID, items, false, "tokenize")
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(res))
	for _, r := range res {
		if r.Error != nil {
			return nil, r.Error
		}
		out[t.Fields[r.Index]] = r.Token
	}
	return out, nil
}

// EmbedReveal reads values as the principal who minted the token, at the browser's address.
func (s *Service) EmbedReveal(ctx context.Context, c Caller, t *ClientToken) ([]DetokenizeResult, error) {
	return s.Detokenize(ctx, c, t.VaultID, t.Tokens, t.Purpose, true)
}

// FieldKind helps a frame choose a keyboard. It says nothing about a value.
func (s *Service) FieldKind(ctx context.Context, vaultID, name string) string {
	v, err := s.Vault(ctx, vaultID)
	if err != nil || v.Fields[name] == nil {
		return ""
	}
	return v.Fields[name].DataType
}
