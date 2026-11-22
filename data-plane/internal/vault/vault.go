// Package vault stores values encrypted and issues tokens. A value is returned
// only after its audit event commits, and only as far as policy allows.
package vault

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
	_ "time/tzdata" // zone rules built in: images without /usr/share/zoneinfo still know every zone

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"onshore/data-plane/internal/audit"
	"onshore/data-plane/internal/detect"
	"onshore/data-plane/internal/keys"
	"onshore/data-plane/internal/mask"
	"onshore/data-plane/internal/policy"
)

// Error carries an HTTP status and an API code. Messages never contain values.
type Error struct {
	Status  int    `json:"-"`
	Code    string `json:"code"`
	Message string `json:"message"`
	Policy  string `json:"policy,omitempty"`
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

func errInvalid(msg string) *Error { return &Error{400, "invalid_request", msg, ""} }

var (
	errVaultNotFound = &Error{404, "invalid_request", "unknown vault", ""}
	errTokenNotFound = &Error{404, "token_not_found", "unknown or expired token", ""}
	errNoRecord      = &Error{404, "invalid_request", "unknown record or subject", ""}
	errValidation    = &Error{422, "validation_failed", "value fails the field's format check", ""}
	errDuplicate     = &Error{409, "duplicate_value", "value exists in a field marked unique", ""}
	errKeys          = &Error{503, "key_service_unavailable", "the key service cannot be reached; nothing is decrypted", ""}
	errRateLimited   = &Error{429, "rate_limited", "reveal or request limit reached", ""}
)

func errDenied(d policy.Decision) *Error {
	return &Error{403, "policy_denied", "a policy denied the action", d.Label()}
}

// Caller identifies who is asking. System callers (log pipelines) skip policy
// because tokenizing exposes nothing; they can never detokenize.
type Caller struct {
	TenantID    string
	PrincipalID string
	Kind        string
	Roles       []string
	MFA         bool
	SourceIP    string
	RequestID   string
	Module      string
	System      bool
}

// Field is a configured vault column.
type Field struct {
	ID, Name, DataType, Kind, Format, MaskRule string
	GroupID                                    string
	TTL                                        time.Duration
	Searchable, Unique                         bool
}

// Scope is the namespace within which equal values share a deterministic token.
func (f *Field) Scope() string {
	if f.GroupID != "" {
		return f.GroupID
	}
	return f.ID
}

// VaultMeta is cached vault configuration.
type VaultMeta struct {
	EmbedOrigins                    []string
	ID, TenantID, Name, Environment string
	Country                         string            // where the vault keeps data
	Fields                          map[string]*Field // by name
	ByID                            map[string]*Field
	loaded                          time.Time
}

type netEntry struct {
	name string
	nets []*net.IPNet
}

type tenantCache struct {
	policies []policy.Active
	networks []netEntry
	zone     *time.Location // where the organisation's working hours are counted
	loaded   time.Time
}

type cachedKey struct {
	key     []byte
	expires time.Time
}

// Service is the vault core.
type Service struct {
	Pool   *pgxpool.Pool
	Keys   keys.Service
	Engine *detect.Engine
	// Rules holds each vault's compiled rule set; nil until StartRules.
	Rules detect.RuleSets
	Now   func() time.Time

	mu       sync.Mutex
	vaults   map[string]*VaultMeta
	tenants  map[string]*tenantCache
	deks     map[string]cachedKey
	indexKey map[string]cachedKey

	lastRenew time.Time
	batchers  map[string]*auditBatcher
	// Geo answers the country for an address. It is a recorded signal, never a gate.
	Geo interface{ Country(ip string) string }
}

const configTTL = 5 * time.Second
const keyCacheTTL = 5 * time.Minute

// New builds a Service.
func New(pool *pgxpool.Pool, k keys.Service) *Service {
	s := &Service{Pool: pool, Keys: k, Now: time.Now, vaults: map[string]*VaultMeta{}, tenants: map[string]*tenantCache{}, deks: map[string]cachedKey{}, indexKey: map[string]cachedKey{}}
	s.Engine = detect.New(s.engineConfig())
	return s
}

func (s *Service) isOwnToken(v string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var exists bool
	if err := s.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM data.tokens WHERE token=$1)`, v).Scan(&exists); err != nil {
		return false // unknown stays sensitive
	}
	return exists
}

// Vault loads configuration, cached briefly so changes apply within seconds.
func (s *Service) Vault(ctx context.Context, id string) (*VaultMeta, error) {
	s.mu.Lock()
	if v, ok := s.vaults[id]; ok && s.Now().Sub(v.loaded) < configTTL {
		s.mu.Unlock()
		return v, nil
	}
	s.mu.Unlock()
	v := &VaultMeta{ID: id, Fields: map[string]*Field{}, ByID: map[string]*Field{}, loaded: s.Now()}
	err := s.Pool.QueryRow(ctx, `SELECT tenant_id,name,environment,embed_origins,country FROM control.vaults WHERE id=$1 AND status='active'`, id).Scan(&v.TenantID, &v.Name, &v.Environment, &v.EmbedOrigins, &v.Country)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errVaultNotFound
	}
	if err != nil {
		return nil, err
	}
	rows, err := s.Pool.Query(ctx, `SELECT f.id,f.name,coalesce(ce.slug,f.data_type),coalesce(g.token_kind,f.token_kind),coalesce(g.token_format,f.token_format),f.mask_rule,coalesce(f.column_group_id,''),coalesce(f.ttl_seconds,coalesce(f.ttl_days,0)*86400),f.searchable,f.unique_values
		FROM control.vault_fields f LEFT JOIN control.column_groups g ON g.id=f.column_group_id LEFT JOIN control.custom_entities ce ON ce.id=f.custom_entity_id WHERE f.vault_id=$1`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		f := &Field{}
		var ttl int
		if err := rows.Scan(&f.ID, &f.Name, &f.DataType, &f.Kind, &f.Format, &f.MaskRule, &f.GroupID, &ttl, &f.Searchable, &f.Unique); err != nil {
			return nil, err
		}
		f.TTL = time.Duration(ttl) * time.Second
		v.Fields[f.Name], v.ByID[f.ID] = f, f
	}
	if rows.Err() != nil {
		return nil, rows.Err()
	}
	s.mu.Lock()
	s.vaults[id] = v
	s.mu.Unlock()
	return v, nil
}

func (s *Service) ownVault(ctx context.Context, c Caller, id string) (*VaultMeta, error) {
	v, err := s.Vault(ctx, id)
	if err != nil {
		return nil, err
	}
	if v.TenantID != c.TenantID {
		return nil, errVaultNotFound // never reveal another tenant's vault exists
	}
	return v, nil
}

func (s *Service) tenant(ctx context.Context, id string) (*tenantCache, error) {
	s.mu.Lock()
	if t, ok := s.tenants[id]; ok && s.Now().Sub(t.loaded) < configTTL {
		s.mu.Unlock()
		return t, nil
	}
	s.mu.Unlock()
	t := &tenantCache{loaded: s.Now(), zone: time.UTC}
	var zone string
	if err := s.Pool.QueryRow(ctx, `SELECT time_zone FROM control.tenants WHERE id=$1`, id).Scan(&zone); err == nil {
		if loc, err := time.LoadLocation(zone); err == nil {
			t.zone = loc
		}
	}
	rows, err := s.Pool.Query(ctx, `SELECT id,name,version,compiled_cel,source FROM control.policies WHERE tenant_id=$1 AND status='active'`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var a policy.Active
		var compiled, source []byte
		if err := rows.Scan(&a.ID, &a.Name, &a.Version, &compiled, &source); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(compiled, &a.Compiled); err != nil {
			continue // an unreadable policy grants nothing
		}
		var d policy.Doc
		if json.Unmarshal(source, &d) == nil {
			a.LimitPerHour = d.LimitPerHour
		}
		t.policies = append(t.policies, a)
	}
	if rows.Err() != nil {
		return nil, rows.Err()
	}
	nrows, err := s.Pool.Query(ctx, `SELECT name,cidrs FROM control.approved_networks WHERE tenant_id=$1`, id)
	if err != nil {
		return nil, err
	}
	defer nrows.Close()
	for nrows.Next() {
		var name string
		var cidrs []string
		if err := nrows.Scan(&name, &cidrs); err != nil {
			return nil, err
		}
		e := netEntry{name: name}
		for _, cidr := range cidrs {
			if _, n, err := net.ParseCIDR(cidr); err == nil {
				e.nets = append(e.nets, n)
			}
		}
		t.networks = append(t.networks, e)
	}
	if nrows.Err() != nil {
		return nil, nrows.Err()
	}
	s.mu.Lock()
	s.tenants[id] = t
	s.mu.Unlock()
	return t, nil
}

// NetworksFor names the approved networks a source IP belongs to.
func (s *Service) NetworksFor(ctx context.Context, tenantID, ip string) ([]string, error) {
	t, err := s.tenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return nil, nil
	}
	var out []string
	for _, e := range t.networks {
		for _, n := range e.nets {
			if n.Contains(parsed) {
				out = append(out, e.name)
				break
			}
		}
	}
	return out, nil
}

func (s *Service) decide(ctx context.Context, c Caller, action string, f *Field, purpose string) (policy.Decision, []string, error) {
	t, err := s.tenant(ctx, c.TenantID)
	if err != nil {
		return policy.Decision{}, nil, err
	}
	nets, err := s.NetworksFor(ctx, c.TenantID, c.SourceIP)
	if err != nil {
		return policy.Decision{}, nil, err
	}
	req := policy.Request{Action: action, PrincipalID: c.PrincipalID, Roles: c.Roles, MFA: c.MFA, Networks: nets, Purpose: purpose, Hour: s.Now().In(t.zone).Hour()}
	if f != nil {
		req.FieldName, req.FieldDataType = f.Name, f.DataType
	}
	return policy.Evaluate(t.policies, req), nets, nil
}

// Simulate evaluates a hypothetical request, optionally with a draft replacing
// the active version of the same name. It never touches data.
func (s *Service) Simulate(ctx context.Context, tenantID string, req policy.Request, draft *policy.Active) (policy.Decision, error) {
	t, err := s.tenant(ctx, tenantID)
	if err != nil {
		return policy.Decision{}, err
	}
	ps := make([]policy.Active, 0, len(t.policies)+1)
	for _, p := range t.policies {
		if draft == nil || p.Name != draft.Name {
			ps = append(ps, p)
		}
	}
	if draft != nil {
		ps = append(ps, *draft)
	}
	return policy.Evaluate(ps, req), nil
}

func newUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// HashToken is what the audit log stores in place of a token.
func HashToken(t string) string {
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:8])
}

func (s *Service) event(c Caller, vaultID, action string, started time.Time) audit.Event {
	geo := ""
	if s.Geo != nil && c.SourceIP != "" {
		geo = s.Geo.Country(c.SourceIP)
	}
	return audit.Event{GeoCountry: geo, EventID: newUUID(), OccurredAt: s.Now(), VaultID: vaultID, PrincipalID: c.PrincipalID, PrincipalKind: c.Kind, SourceIP: c.SourceIP, Module: moduleOf(c), Action: action, RequestID: c.RequestID, LatencyMS: int(s.Now().Sub(started).Milliseconds())}
}

func moduleOf(c Caller) string {
	if c.Module != "" {
		return c.Module
	}
	return "api"
}

func withDecision(e audit.Event, d policy.Decision, nets []string) audit.Event {
	e.Decision, e.PolicyID, e.PolicyVersion = d.Effect, d.PolicyID, d.Version
	if len(nets) > 0 {
		e.Network = nets[0]
	}
	return e
}

// CleanPurpose removes identifiers from free text before it reaches the audit log,
// since the audit log is exported and must never hold sensitive values.
func (s *Service) CleanPurpose(p string) string {
	return stripLongNumbers(detect.Replace(p, s.Engine.Scan(p), func(e detect.Entity, _ string) string { return "[" + string(e.Type) + " removed]" }))
}

// overLookupLimit counts a value-confirming query. Hitting the limit raises an
// alert at once: guessing identifiers is exactly what it looks like.
func (s *Service) overLookupLimit(ctx context.Context, c Caller) (bool, error) {
	n, err := s.bumpCounter(ctx, "lookup|"+c.PrincipalID, time.Minute)
	if err != nil {
		return false, err
	}
	if n <= lookupPerMinute {
		return false, nil
	}
	if n == lookupPerMinute+1 {
		if _, err := s.Pool.Exec(ctx, `INSERT INTO events.alerts(id,tenant_id,kind,principal_id,detail,event_at) VALUES ($1::uuid,$2,'lookup_spike',$3,$4,now())`, newUUID(), c.TenantID, c.PrincipalID, fmt.Sprintf(`{"per_minute_limit":%d}`, lookupPerMinute)); err != nil {
			return false, err
		}
	}
	return true, nil
}

// overRevealLimit applies a policy's hourly limit to one value about to be shown.
func (s *Service) overRevealLimit(ctx context.Context, c Caller, d policy.Decision) (bool, error) {
	if d.LimitPerHour <= 0 {
		return false, nil
	}
	n, err := s.bumpCounter(ctx, "reveal|"+c.PrincipalID, time.Hour)
	return n > d.LimitPerHour, err
}

// recordDenied writes denial events in their own transaction; a denied request
// still leaves evidence.
func (s *Service) writeEvents(ctx context.Context, tenantID string, events []audit.Event) error {
	if len(events) == 0 {
		return nil
	}
	return s.batcher(tenantID).write(ctx, events)
}

// auditBatcher group-commits a tenant's events. The chain needs one writer at a time,
// so concurrent requests would otherwise queue for a commit each. Requests still wait
// for their own events to be durable before any value is returned.
type auditBatcher struct {
	s      *Service
	tenant string
	jobs   chan auditJob
}

type auditJob struct {
	events []audit.Event
	done   chan error
}

func (s *Service) batcher(tenantID string) *auditBatcher {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.batchers == nil {
		s.batchers = map[string]*auditBatcher{}
	}
	b, ok := s.batchers[tenantID]
	if !ok {
		b = &auditBatcher{s: s, tenant: tenantID, jobs: make(chan auditJob, 1024)}
		s.batchers[tenantID] = b
		go b.run()
	}
	return b
}

func (b *auditBatcher) write(ctx context.Context, events []audit.Event) error {
	job := auditJob{events: events, done: make(chan error, 1)}
	select {
	case b.jobs <- job:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case err := <-job.done:
		return err
	case <-ctx.Done():
		return ctx.Err() // the caller gives up and returns no value; the event may still land
	}
}

func (b *auditBatcher) run() {
	for first := range b.jobs {
		jobs := []auditJob{first}
		n := len(first.events)
	drain:
		for n < 2000 {
			select {
			case j := <-b.jobs:
				jobs = append(jobs, j)
				n += len(j.events)
			default:
				break drain
			}
		}
		all := make([]audit.Event, 0, n)
		for _, j := range jobs {
			all = append(all, j.events...)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		err := pgx.BeginFunc(ctx, b.s.Pool, func(tx pgx.Tx) error { return audit.Append(ctx, tx, b.tenant, all) })
		cancel()
		for _, j := range jobs {
			j.done <- err
		}
	}
}

// ---- keys --------------------------------------------------------------------

func dekAAD(vaultID, id string) []byte { return []byte("rv-dek|" + vaultID + "|" + id) }
func idxAAD(vaultID string) []byte     { return []byte("rv-index|" + vaultID) }

func wrapErr(err error) error {
	if errors.Is(err, keys.ErrUnavailable) {
		return errKeys
	}
	return err
}

func (s *Service) activeDEK(ctx context.Context, vaultID string) (string, []byte, error) {
	var id string
	var wrapped []byte
	err := s.Pool.QueryRow(ctx, `SELECT id,wrapped_dek FROM data.data_keys WHERE vault_id=$1 AND status='active'`, vaultID).Scan(&id, &wrapped)
	if errors.Is(err, pgx.ErrNoRows) {
		return s.createDEK(ctx, vaultID)
	}
	if err != nil {
		return "", nil, err
	}
	k, err := s.dekByID(ctx, vaultID, id, wrapped)
	return id, k, err
}

func (s *Service) createDEK(ctx context.Context, vaultID string) (string, []byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", nil, err
	}
	id := "dek_" + newUUID()
	wrapped, ref, err := s.Keys.Wrap(ctx, key, dekAAD(vaultID, id))
	if err != nil {
		return "", nil, wrapErr(err)
	}
	tag, err := s.Pool.Exec(ctx, `INSERT INTO data.data_keys(id,vault_id,wrapped_dek,kek_ref) VALUES ($1,$2,$3,$4) ON CONFLICT (vault_id) WHERE status='active' DO NOTHING`, id, vaultID, wrapped, ref)
	if err != nil {
		return "", nil, err
	}
	if tag.RowsAffected() == 0 { // lost a race with another replica
		return s.activeDEK(ctx, vaultID)
	}
	s.cacheDEK(id, key)
	return id, key, nil
}

func (s *Service) cacheDEK(id string, key []byte) {
	s.mu.Lock()
	s.deks[id] = cachedKey{key, s.Now().Add(keyCacheTTL)}
	s.mu.Unlock()
}

func (s *Service) dekByID(ctx context.Context, vaultID, id string, wrapped []byte) ([]byte, error) {
	s.mu.Lock()
	if k, ok := s.deks[id]; ok && s.Now().Before(k.expires) {
		s.mu.Unlock()
		return k.key, nil
	}
	s.mu.Unlock()
	if wrapped == nil {
		if err := s.Pool.QueryRow(ctx, `SELECT wrapped_dek FROM data.data_keys WHERE id=$1 AND vault_id=$2`, id, vaultID).Scan(&wrapped); err != nil {
			return nil, err
		}
	}
	k, err := s.Keys.Unwrap(ctx, wrapped, dekAAD(vaultID, id))
	if err != nil {
		return nil, wrapErr(err)
	}
	s.cacheDEK(id, k)
	return k, nil
}

func (s *Service) blindKey(ctx context.Context, vaultID string) ([]byte, error) {
	s.mu.Lock()
	if k, ok := s.indexKey[vaultID]; ok && s.Now().Before(k.expires) {
		s.mu.Unlock()
		return k.key, nil
	}
	s.mu.Unlock()
	var wrapped []byte
	err := s.Pool.QueryRow(ctx, `SELECT wrapped_key FROM data.blind_index_keys WHERE vault_id=$1`, vaultID).Scan(&wrapped)
	var key []byte
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		w, ref, err := s.Keys.Wrap(ctx, key, idxAAD(vaultID))
		if err != nil {
			return nil, wrapErr(err)
		}
		tag, err := s.Pool.Exec(ctx, `INSERT INTO data.blind_index_keys(id,vault_id,wrapped_key,kek_ref) VALUES ($1,$2,$3,$4) ON CONFLICT (vault_id) DO NOTHING`, "idx_"+newUUID(), vaultID, w, ref)
		if err != nil {
			return nil, err
		}
		if tag.RowsAffected() == 0 {
			return s.blindKey(ctx, vaultID)
		}
	case err != nil:
		return nil, err
	default:
		if key, err = s.Keys.Unwrap(ctx, wrapped, idxAAD(vaultID)); err != nil {
			return nil, wrapErr(err)
		}
	}
	s.mu.Lock()
	s.indexKey[vaultID] = cachedKey{key, s.Now().Add(keyCacheTTL)}
	s.mu.Unlock()
	return key, nil
}

func blindIndex(key []byte, scope, normalized string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(scope + "|" + normalized))
	return m.Sum(nil)
}

// Seal encrypts with AES-256-GCM, a fresh 96-bit nonce and bound AAD, so a
// ciphertext copied to another row fails to decrypt.
func Seal(key []byte, plaintext, aad []byte) (ciphertext, nonce []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	return gcm.Seal(nil, nonce, plaintext, aad), nonce, nil
}

// Open reverses Seal.
func Open(key, ciphertext, nonce, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, aad)
}

func recordAAD(vaultID, fieldID, recordID string) []byte {
	return []byte(vaultID + "|" + fieldID + "|" + recordID)
}

// ---- tokens ------------------------------------------------------------------

const base62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// FPPrefixID marks format-preserving BVN, NIN and NUBAN tokens. No range can be
// truly reserved here: NIMC draws NINs at random and no source documents a BVN
// prefix, so a real value may start 99. The detector therefore skips a lookalike
// only when the token table holds it.
const FPPrefixID = "99"

// FPPrefixPhone cannot be a Nigerian number: the NCC's allocation table has no
// such mobile range, 01-07 hold fixed-line area codes (so the earlier 06 was
// wrong), and the international access prefix is 009.
const FPPrefixPhone = "000"

func randomString(alphabet string, n int) string {
	max := big.NewInt(int64(len(alphabet)))
	b := make([]byte, n)
	for i := range b {
		v, err := rand.Int(rand.Reader, max)
		if err != nil {
			panic(err)
		}
		b[i] = alphabet[v.Int64()]
	}
	return string(b)
}

var tokenTag = map[string]string{"bvn": "bvn", "nin": "nin", "ng_11_digit_id": "id", "nuban": "nuban", "phone_ng": "phone", "email": "email", "person_name": "name", "amount_ngn": "amt", "address": "addr", "date": "date", "free_text": "txt"}

// NewToken mints a token. Opaque tokens carry 131 bits of randomness (22 base62
// characters). Format-preserving ones map only through the vault.
func NewToken(dataType, format string) string {
	if strings.HasPrefix(dataType, "c_") {
		return "tok_" + dataType + "_" + randomString(base62, 22)
	}
	if format == "format_preserving" {
		switch dataType {
		case "bvn", "nin", "ng_11_digit_id":
			return FPPrefixID + randomString("0123456789", 9)
		case "nuban":
			return FPPrefixID + randomString("0123456789", 8)
		case "phone_ng":
			return FPPrefixPhone + randomString("0123456789", 8)
		}
	}
	tag := tokenTag[dataType]
	if tag == "" {
		tag = dataType // country-pack types read as themselves: tok_iban_…, tok_us_ssn_…
	}
	return "tok_" + tag + "_" + randomString(base62, 22)
}

// NewTokenFor mints a token for a value. A format-preserving custom token keeps the
// value's shape: separators and any leading letters stay, the rest is random in kind.
// Only the vault can map it back, and own-token checks stop it being detected again.
func NewTokenFor(dataType, format, value string) string {
	if format != "format_preserving" || !strings.HasPrefix(dataType, "c_") {
		return NewToken(dataType, format)
	}
	b := []byte(value)
	lead := 0
	for lead < len(b) && !(b[lead] >= '0' && b[lead] <= '9') {
		lead++
	}
	changed := 0
	for i := range b {
		switch c := b[i]; {
		case c >= '0' && c <= '9':
			b[i] = randomString("0123456789", 1)[0]
			changed++
		case i >= lead && c >= 'a' && c <= 'z':
			b[i] = randomString("abcdefghijklmnopqrstuvwxyz", 1)[0]
			changed++
		case i >= lead && c >= 'A' && c <= 'Z':
			b[i] = randomString("ABCDEFGHIJKLMNOPQRSTUVWXYZ", 1)[0]
			changed++
		}
	}
	// Too little entropy to be safe, or no digits to vary: use an opaque token.
	if changed < 6 {
		return NewToken(dataType, "opaque")
	}
	return string(b)
}

// SupportsFormatPreserving reports which types have a reserved numeric range.
func SupportsFormatPreserving(dataType string) bool {
	switch dataType {
	case "bvn", "nin", "ng_11_digit_id", "nuban", "phone_ng":
		return true
	}
	return false
}

// ---- tokenize ----------------------------------------------------------------

// TokenizeItem is one value to store.
type TokenizeItem struct {
	Field      string `json:"field"`
	Value      string `json:"value"`
	SubjectRef string `json:"subject_ref,omitempty"`
	group      string
}

type dryRunKey struct{}

// WithDryRun makes Tokenize check everything and store nothing.
func WithDryRun(ctx context.Context) context.Context {
	return context.WithValue(ctx, dryRunKey{}, true)
}

func isDryRun(ctx context.Context) bool { return ctx.Value(dryRunKey{}) != nil }

// ItemResult reports one batch position.
type ItemResult struct {
	Index    int    `json:"index"`
	Token    string `json:"token,omitempty"`
	Existing *bool  `json:"existing,omitempty"`
	Error    *Error `json:"error,omitempty"`
	field    *Field
	record   string
}

type prepared struct {
	index      int
	field      *Field
	normalized string
	blind      []byte
	subjectRef string
	group      string
}

// Tokenize stores values and returns tokens, batched in one transaction.
func (s *Service) Tokenize(ctx context.Context, c Caller, vaultID string, items []TokenizeItem, continueOnError bool, action string) ([]ItemResult, error) {
	started := s.Now()
	v, err := s.ownVault(ctx, c, vaultID)
	if err != nil {
		return nil, err
	}
	results := make([]ItemResult, len(items))
	for i := range results {
		results[i].Index = i
	}
	fail := func(i int, e *Error) error {
		results[i].Error = e
		if continueOnError {
			return nil
		}
		return e
	}
	idxKey, err := s.blindKey(ctx, vaultID)
	if err != nil {
		return nil, err
	}
	var denied []audit.Event
	var ready []prepared
	var firstErr error
	for i, it := range items {
		f := v.Fields[it.Field]
		if f == nil {
			if firstErr = fail(i, errInvalid("unknown field")); firstErr != nil {
				break
			}
			continue
		}
		if !c.System {
			d, nets, err := s.decide(ctx, c, action, f, "")
			if err != nil {
				return nil, err
			}
			if !d.Allowed() {
				e := withDecision(s.event(c, vaultID, action, started), d, nets)
				e.FieldID, e.Decision = f.ID, policy.Deny
				denied = append(denied, e)
				if firstErr = fail(i, errDenied(d)); firstErr != nil {
					break
				}
				continue
			}
		}
		n, ok := s.normalize(vaultID, f.DataType, it.Value)
		if !ok {
			if firstErr = fail(i, errValidation); firstErr != nil {
				break
			}
			continue
		}
		ready = append(ready, prepared{i, f, n, blindIndex(idxKey, f.Scope(), n), it.SubjectRef, it.group})
	}
	if len(denied) > 0 {
		if err := s.writeEvents(ctx, c.TenantID, denied); err != nil {
			return nil, err
		}
	}
	if firstErr != nil {
		return nil, firstErr
	}
	// A check run stops here: every value has been validated and every rule applied, and nothing is stored.
	if len(ready) == 0 || isDryRun(ctx) {
		return results, nil
	}
	dekID, dek, err := s.activeDEK(ctx, vaultID)
	if err != nil {
		return nil, err
	}
	// A consistent order stops concurrent batches deadlocking on the unique index.
	sort.SliceStable(ready, func(a, b int) bool { return string(ready[a].blind) < string(ready[b].blind) })

	events := make([]audit.Event, 0, len(ready))
	err = pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		events = events[:0]
		for _, p := range ready {
			tok, recordID, existing, err := s.store(ctx, tx, vaultID, p, dekID, dek)
			if err != nil {
				var ae *Error
				if errors.As(err, &ae) && continueOnError {
					results[p.index].Error = ae
					continue
				}
				return err
			}
			if p.subjectRef != "" {
				subjectID, err := s.ensureSubject(ctx, tx, vaultID, p.subjectRef, idxKey, dekID, dek)
				if err != nil {
					return err
				}
				if _, err := tx.Exec(ctx, `INSERT INTO data.record_subjects(record_id,subject_id) VALUES ($1::uuid,$2::uuid) ON CONFLICT DO NOTHING`, recordID, subjectID); err != nil {
					return err
				}
			}
			ex := existing
			results[p.index].Token, results[p.index].Existing = tok, &ex
			results[p.index].record = recordID
			e := s.event(c, vaultID, action, started)
			e.FieldID, e.RecordID, e.TokenHash = p.field.ID, recordID, HashToken(tok)
			events = append(events, e)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	// The event follows the data commit. A crash between them stores a value with no
	// event, but no token has reached the caller, because this call has not returned.
	if err := s.writeEvents(ctx, c.TenantID, events); err != nil {
		return nil, err
	}
	return results, nil
}

func (s *Service) store(ctx context.Context, tx pgx.Tx, vaultID string, p prepared, dekID string, dek []byte) (token, recordID string, existing bool, err error) {
	f := p.field
	recordID = newUUID()
	ct, nonce, err := Seal(dek, []byte(p.normalized), recordAAD(vaultID, f.ID, recordID))
	if err != nil {
		return "", "", false, err
	}
	// Expiry comes from the database clock, the same clock that enforces it.
	var ttlSeconds any
	if f.Kind == "transient" {
		ttl := f.TTL
		if ttl == 0 {
			ttl = 24 * time.Hour
		}
		ttlSeconds = int(ttl.Seconds())
	}
	var group any
	if p.group != "" {
		group = p.group
	}
	var blind any
	if f.Kind == "deterministic" || f.Searchable || f.Unique {
		blind = p.blind
	}
	switch f.Kind {
	case "deterministic":
		tag, err := tx.Exec(ctx, `INSERT INTO data.records(id,vault_id,field_id,record_group,dedup_scope,deterministic,ciphertext,nonce,dek_id,blind_index) VALUES ($1::uuid,$2,$3,$4::uuid,$5,true,$6,$7,$8,$9) ON CONFLICT (vault_id,dedup_scope,blind_index) WHERE deterministic DO NOTHING`, recordID, vaultID, f.ID, group, f.Scope(), ct, nonce, dekID, p.blind)
		if err != nil {
			return "", "", false, err
		}
		if tag.RowsAffected() == 0 {
			err := tx.QueryRow(ctx, `SELECT r.id::text,t.token FROM data.records r JOIN data.tokens t ON t.record_id=r.id WHERE r.vault_id=$1 AND r.dedup_scope=$2 AND r.blind_index=$3 AND r.deterministic LIMIT 1`, vaultID, f.Scope(), p.blind).Scan(&recordID, &token)
			return token, recordID, true, err
		}
	default:
		if f.Unique {
			var dup bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM data.records WHERE vault_id=$1 AND field_id=$2 AND blind_index=$3)`, vaultID, f.ID, p.blind).Scan(&dup); err != nil {
				return "", "", false, err
			}
			if dup {
				return "", "", false, errDuplicate
			}
		}
		if _, err := tx.Exec(ctx, `INSERT INTO data.records(id,vault_id,field_id,record_group,dedup_scope,deterministic,ciphertext,nonce,dek_id,blind_index,expires_at) VALUES ($1::uuid,$2,$3,$4::uuid,$5,false,$6,$7,$8,$9,now()+make_interval(secs => $10::int))`, recordID, vaultID, f.ID, group, f.Scope(), ct, nonce, dekID, blind, ttlSeconds); err != nil {
			return "", "", false, err
		}
	}
	// Format-preserving tokens have a small space; retry on the rare collision.
	for attempt := 0; attempt < 8; attempt++ {
		token = NewTokenFor(f.DataType, f.Format, p.normalized)
		tag, err := tx.Exec(ctx, `INSERT INTO data.tokens(token,vault_id,record_id,field_id,kind,format,expires_at) VALUES ($1,$2,$3::uuid,$4,$5,$6,now()+make_interval(secs => $7::int)) ON CONFLICT (token) DO NOTHING`, token, vaultID, recordID, f.ID, f.Kind, f.Format, ttlSeconds)
		if err != nil {
			return "", "", false, err
		}
		if tag.RowsAffected() == 1 {
			return token, recordID, false, nil
		}
	}
	return "", "", false, errors.New("could not allocate a unique token")
}

func (s *Service) ensureSubject(ctx context.Context, tx pgx.Tx, vaultID, ref string, idxKey []byte, dekID string, dek []byte) (string, error) {
	idx := blindIndex(idxKey, "subject", ref)
	id := newUUID()
	ct, nonce, err := Seal(dek, []byte(ref), []byte(vaultID+"|subject|"+id))
	if err != nil {
		return "", err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO data.subjects(id,vault_id,ref_index,ref_ciphertext,ref_nonce,dek_id) VALUES ($1::uuid,$2,$3,$4,$5,$6) ON CONFLICT (vault_id,ref_index) DO NOTHING`, id, vaultID, idx, ct, nonce, dekID); err != nil {
		return "", err
	}
	err = tx.QueryRow(ctx, `SELECT id::text FROM data.subjects WHERE vault_id=$1 AND ref_index=$2`, vaultID, idx).Scan(&id)
	return id, err
}

// InsertRecord stores a structured record, returning a token per field.
func (s *Service) InsertRecord(ctx context.Context, c Caller, vaultID string, fields map[string]string, subjectRef string) (string, map[string]string, error) {
	group := newUUID()
	names := make([]string, 0, len(fields))
	for n := range fields {
		names = append(names, n)
	}
	sort.Strings(names)
	items := make([]TokenizeItem, len(names))
	for i, n := range names {
		items[i] = TokenizeItem{Field: n, Value: fields[n], SubjectRef: subjectRef, group: group}
	}
	res, err := s.Tokenize(ctx, c, vaultID, items, false, "insert")
	if err != nil {
		return "", nil, err
	}
	tokens := map[string]string{}
	for i, r := range res {
		tokens[names[i]] = r.Token
	}
	return group, tokens, nil
}

// UpdateValue changes the value behind a cell token, which keeps pointing at it.
func (s *Service) UpdateValue(ctx context.Context, c Caller, vaultID, token, value string) error {
	started := s.Now()
	v, err := s.ownVault(ctx, c, vaultID)
	if err != nil {
		return err
	}
	var recordID, fieldID, kind string
	err = s.Pool.QueryRow(ctx, `SELECT record_id::text,field_id,kind FROM data.tokens WHERE token=$1 AND vault_id=$2 AND (expires_at IS NULL OR expires_at>now())`, token, vaultID).Scan(&recordID, &fieldID, &kind)
	if errors.Is(err, pgx.ErrNoRows) {
		return errTokenNotFound
	}
	if err != nil {
		return err
	}
	f := v.ByID[fieldID]
	if f == nil {
		return errTokenNotFound
	}
	if kind != "cell" {
		return errInvalid("only cell tokens can change value; deterministic tokens are bound to their value")
	}
	d, nets, err := s.decide(ctx, c, "insert", f, "")
	if err != nil {
		return err
	}
	base := withDecision(s.event(c, vaultID, "insert", started), d, nets)
	base.FieldID, base.RecordID, base.TokenHash = f.ID, recordID, HashToken(token)
	if !d.Allowed() {
		base.Decision = policy.Deny
		if err := s.writeEvents(ctx, c.TenantID, []audit.Event{base}); err != nil {
			return err
		}
		return errDenied(d)
	}
	n, ok := s.normalize(vaultID, f.DataType, value)
	if !ok {
		return errValidation
	}
	idxKey, err := s.blindKey(ctx, vaultID)
	if err != nil {
		return err
	}
	dekID, dek, err := s.activeDEK(ctx, vaultID)
	if err != nil {
		return err
	}
	ct, nonce, err := Seal(dek, []byte(n), recordAAD(vaultID, f.ID, recordID))
	if err != nil {
		return err
	}
	var blind any
	if f.Searchable || f.Unique {
		blind = blindIndex(idxKey, f.Scope(), n)
	}
	return pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE data.records SET ciphertext=$2,nonce=$3,dek_id=$4,blind_index=$5 WHERE id=$1::uuid`, recordID, ct, nonce, dekID, blind); err != nil {
			return err
		}
		return audit.Append(ctx, tx, c.TenantID, []audit.Event{base})
	})
}

// ---- detokenize --------------------------------------------------------------

// DetokenizeResult reports one token.
type DetokenizeResult struct {
	Index    int    `json:"index"`
	Decision string `json:"decision,omitempty"`
	Value    string `json:"value,omitempty"`
	Policy   string `json:"policy,omitempty"`
	Error    *Error `json:"error,omitempty"`
}

type tokenRow struct {
	token, recordID, fieldID, dekID string
	ciphertext, nonce               []byte
	restricted                      bool
}

func (s *Service) loadTokens(ctx context.Context, vaultID string, tokens []string) (map[string]*tokenRow, error) {
	rows, err := s.Pool.Query(ctx, `SELECT t.token,r.id::text,r.field_id,r.dek_id,r.ciphertext,r.nonce,
			EXISTS (SELECT 1 FROM data.record_subjects rs JOIN data.subjects su ON su.id=rs.subject_id WHERE rs.record_id=r.id AND su.restricted)
		FROM data.tokens t JOIN data.records r ON r.id=t.record_id
		WHERE t.vault_id=$1 AND t.token=ANY($2) AND (t.expires_at IS NULL OR t.expires_at>now())`, vaultID, tokens)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]*tokenRow{}
	for rows.Next() {
		r := &tokenRow{}
		if err := rows.Scan(&r.token, &r.recordID, &r.fieldID, &r.dekID, &r.ciphertext, &r.nonce, &r.restricted); err != nil {
			return nil, err
		}
		out[r.token] = r
	}
	return out, rows.Err()
}

// activeBreakGlass reports a live, approved grant for this person and vault.
func (s *Service) activeBreakGlass(ctx context.Context, c Caller, vaultID string) (bool, error) {
	if c.Kind != "user" {
		return false, nil
	}
	var ok bool
	err := s.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM control.break_glass_grants WHERE principal_id=$1 AND vault_id=$2 AND status='active' AND expires_at>now())`, c.PrincipalID, vaultID).Scan(&ok)
	return ok, err
}

// bumpCounter counts in a shared table so limits hold across replicas.
func (s *Service) bumpCounter(ctx context.Context, bucket string, window time.Duration) (int, error) {
	var n int
	err := s.Pool.QueryRow(ctx, `INSERT INTO data.rate_counters(bucket,window_start,count) VALUES ($1,$2,1)
		ON CONFLICT (bucket,window_start) DO UPDATE SET count=data.rate_counters.count+1 RETURNING count`, bucket, s.Now().UTC().Truncate(window)).Scan(&n)
	return n, err
}

func (s *Service) decrypt(ctx context.Context, vaultID string, r *tokenRow) (string, error) {
	dek, err := s.dekByID(ctx, vaultID, r.dekID, nil)
	if err != nil {
		return "", err
	}
	pt, err := Open(dek, r.ciphertext, r.nonce, recordAAD(vaultID, r.fieldID, r.recordID))
	if err != nil {
		return "", fmt.Errorf("decrypt record %s failed", r.recordID)
	}
	return string(pt), nil
}

// Detokenize returns values per policy. Values leave only after audit commits.
func (s *Service) Detokenize(ctx context.Context, c Caller, vaultID string, tokens []string, purpose string, continueOnError bool) ([]DetokenizeResult, error) {
	return s.DetokenizeNarrowed(ctx, c, vaultID, tokens, nil, purpose, continueOnError)
}

// DetokenizeNarrowed lets a caller ask for less than policy allows, per token
// (Skyflow's per-token redaction). A request can narrow a decision, never widen it.
func (s *Service) DetokenizeNarrowed(ctx context.Context, c Caller, vaultID string, tokens, narrow []string, purpose string, continueOnError bool) ([]DetokenizeResult, error) {
	if c.System {
		return nil, errInvalid("system callers cannot detokenize")
	}
	purpose = s.cleanPurposeIn(vaultID, purpose)
	started := s.Now()
	v, err := s.ownVault(ctx, c, vaultID)
	if err != nil {
		return nil, err
	}
	rows, err := s.loadTokens(ctx, vaultID, tokens)
	if err != nil {
		return nil, err
	}
	breakGlass, err := s.activeBreakGlass(ctx, c, vaultID)
	if err != nil {
		return nil, err
	}
	results := make([]DetokenizeResult, len(tokens))
	events := make([]audit.Event, 0, len(tokens))
	var firstErr error
	decisions := map[string]policy.Decision{}
	var nets []string
	for i, tok := range tokens {
		results[i].Index = i
		r := rows[tok]
		var f *Field
		if r != nil {
			f = v.ByID[r.fieldID]
		}
		if f == nil {
			results[i].Error = errTokenNotFound
			if firstErr == nil {
				firstErr = errTokenNotFound
			}
			continue
		}
		d, seen := decisions[f.ID]
		if !seen {
			var err error
			if d, nets, err = s.decide(ctx, c, "detokenize", f, purpose); err != nil {
				return nil, err
			}
			decisions[f.ID] = d
		}
		effect := d.Effect
		usedGlass := false
		if breakGlass && effect != policy.Plaintext {
			effect, usedGlass = policy.Plaintext, true
		}
		if r.restricted && !usedGlass {
			effect = policy.Deny // NDPA restriction overrides any allow
		}
		if i < len(narrow) && narrow[i] != "" && effect != policy.Deny {
			if narrow[i] == policy.TokenOnly || effect == policy.Plaintext {
				effect = narrow[i]
			}
		}
		e := withDecision(s.event(c, vaultID, "detokenize", started), d, nets)
		e.FieldID, e.RecordID, e.TokenHash, e.Purpose, e.BreakGlass = f.ID, r.recordID, HashToken(tok), purpose, usedGlass
		e.Decision = effect

		if effect == policy.Plaintext || effect == policy.Masked {
			if !usedGlass {
				over, err := s.overRevealLimit(ctx, c, d)
				if err != nil {
					return nil, err
				}
				if over {
					effect, e.Decision, e.Detail = policy.Deny, policy.Deny, `{"reason":"rate_limited"}`
					results[i].Error = errRateLimited
					if firstErr == nil {
						firstErr = errRateLimited
					}
				}
			}
		}
		switch effect {
		case policy.Plaintext, policy.Masked:
			pt, err := s.decrypt(ctx, vaultID, r)
			if err != nil {
				return nil, err
			}
			if effect == policy.Masked {
				pt = mask.Value(f.DataType, f.MaskRule, pt)
			}
			results[i].Value = pt
			e.Action = "detokenize"
		case policy.TokenOnly:
			results[i].Value = tok
		default:
			e.Action = "reveal_denied"
			if results[i].Error == nil {
				results[i].Error = errDenied(d)
				if firstErr == nil {
					firstErr = results[i].Error
				}
			}
		}
		if results[i].Error == nil {
			results[i].Decision, results[i].Policy = effect, d.Label()
		} else {
			results[i].Decision, results[i].Policy = policy.Deny, d.Label()
			results[i].Value = ""
		}
		events = append(events, e)
	}
	if err := s.writeEvents(ctx, c.TenantID, events); err != nil {
		return nil, err // fail closed: no audit, no value
	}
	if firstErr != nil && !continueOnError {
		return nil, firstErr
	}
	return results, nil
}

// ---- lookup ------------------------------------------------------------------

// lookupPerMinute caps value-confirmation attempts per principal.
const lookupPerMinute = 60

// Lookup finds a token by value via the blind index, never decrypting.
func (s *Service) Lookup(ctx context.Context, c Caller, vaultID, field, value string) (string, error) {
	started := s.Now()
	v, err := s.ownVault(ctx, c, vaultID)
	if err != nil {
		return "", err
	}
	f := v.Fields[field]
	if f == nil {
		return "", errInvalid("unknown field")
	}
	if !f.Searchable && f.Kind != "deterministic" {
		return "", errInvalid("field is not searchable")
	}
	d, nets, err := s.decide(ctx, c, "search", f, "")
	if err != nil {
		return "", err
	}
	e := withDecision(s.event(c, vaultID, "search", started), d, nets)
	e.FieldID = f.ID
	if !d.Allowed() {
		e.Decision = policy.Deny
		if err := s.writeEvents(ctx, c.TenantID, []audit.Event{e}); err != nil {
			return "", err
		}
		return "", errDenied(d)
	}
	over, err := s.overLookupLimit(ctx, c)
	if err != nil {
		return "", err
	}
	if over {
		return "", errRateLimited
	}
	normalized, ok := s.normalize(vaultID, f.DataType, value)
	if !ok {
		return "", errValidation
	}
	idxKey, err := s.blindKey(ctx, vaultID)
	if err != nil {
		return "", err
	}
	var token, recordID string
	err = s.Pool.QueryRow(ctx, `SELECT t.token,r.id::text FROM data.records r JOIN data.tokens t ON t.record_id=r.id
		WHERE r.vault_id=$1 AND r.dedup_scope=$2 AND r.blind_index=$3 AND (t.expires_at IS NULL OR t.expires_at>now()) ORDER BY t.created_at DESC LIMIT 1`, vaultID, f.Scope(), blindIndex(idxKey, f.Scope(), normalized)).Scan(&token, &recordID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}
	e.RecordID = recordID
	if token != "" {
		e.TokenHash = HashToken(token)
	}
	if err := s.writeEvents(ctx, c.TenantID, []audit.Event{e}); err != nil {
		return "", err
	}
	if token == "" {
		return "", errTokenNotFound
	}
	return token, nil
}

// ---- keys and signing --------------------------------------------------------

// RotateKEK creates a new KEK version and re-wraps every stored key.
func (s *Service) RotateKEK(ctx context.Context, c Caller) error {
	if err := s.Keys.RotateKEK(ctx); err != nil {
		return wrapErr(err)
	}
	type row struct {
		id, vault string
		wrapped   []byte
	}
	collect := func(q string) ([]row, error) {
		rs, err := s.Pool.Query(ctx, q)
		if err != nil {
			return nil, err
		}
		defer rs.Close()
		var out []row
		for rs.Next() {
			var r row
			if err := rs.Scan(&r.id, &r.vault, &r.wrapped); err != nil {
				return nil, err
			}
			out = append(out, r)
		}
		return out, rs.Err()
	}
	deks, err := collect(`SELECT id,vault_id,wrapped_dek FROM data.data_keys`)
	if err != nil {
		return err
	}
	for _, r := range deks {
		w, ref, err := s.Keys.Rewrap(ctx, r.wrapped, dekAAD(r.vault, r.id))
		if err != nil {
			return wrapErr(err)
		}
		if _, err := s.Pool.Exec(ctx, `UPDATE data.data_keys SET wrapped_dek=$2,kek_ref=$3,rotated_at=now() WHERE id=$1`, r.id, w, ref); err != nil {
			return err
		}
	}
	idx, err := collect(`SELECT id,vault_id,wrapped_key FROM data.blind_index_keys`)
	if err != nil {
		return err
	}
	for _, r := range idx {
		w, ref, err := s.Keys.Rewrap(ctx, r.wrapped, idxAAD(r.vault))
		if err != nil {
			return wrapErr(err)
		}
		if _, err := s.Pool.Exec(ctx, `UPDATE data.blind_index_keys SET wrapped_key=$2,kek_ref=$3 WHERE id=$1`, r.id, w, ref); err != nil {
			return err
		}
	}
	aud, err := collect(`SELECT tenant_id,tenant_id,wrapped_private_key FROM data.audit_keys`)
	if err != nil {
		return err
	}
	for _, r := range aud {
		w, ref, err := s.Keys.Rewrap(ctx, r.wrapped, auditAAD(r.id))
		if err != nil {
			return wrapErr(err)
		}
		if _, err := s.Pool.Exec(ctx, `UPDATE data.audit_keys SET wrapped_private_key=$2,kek_ref=$3 WHERE tenant_id=$1`, r.id, w, ref); err != nil {
			return err
		}
	}
	e := s.event(c, "", "key_rotate", s.Now())
	e.Detail = `{"kind":"kek"}`
	return s.writeEvents(ctx, c.TenantID, []audit.Event{e})
}

// RotateDEK sends new writes to a new key. With reencrypt, old rows move too and
// the old key is retired once nothing uses it.
func (s *Service) RotateDEK(ctx context.Context, c Caller, vaultID string, reencrypt bool) error {
	if _, err := s.ownVault(ctx, c, vaultID); err != nil {
		return err
	}
	if _, err := s.Pool.Exec(ctx, `UPDATE data.data_keys SET status='decrypt_only',rotated_at=now() WHERE vault_id=$1 AND status='active'`, vaultID); err != nil {
		return err
	}
	if _, _, err := s.createDEK(ctx, vaultID); err != nil {
		return err
	}
	e := s.event(c, vaultID, "key_rotate", s.Now())
	e.Detail = fmt.Sprintf(`{"kind":"dek","reencrypt":%t}`, reencrypt)
	if err := s.writeEvents(ctx, c.TenantID, []audit.Event{e}); err != nil {
		return err
	}
	if reencrypt {
		return s.reencrypt(ctx, vaultID)
	}
	return nil
}

func (s *Service) reencrypt(ctx context.Context, vaultID string) error {
	newID, newKey, err := s.activeDEK(ctx, vaultID)
	if err != nil {
		return err
	}
	for {
		rows, err := s.Pool.Query(ctx, `SELECT id::text,field_id,dek_id,ciphertext,nonce FROM data.records WHERE vault_id=$1 AND dek_id<>$2 LIMIT 500`, vaultID, newID)
		if err != nil {
			return err
		}
		type rec struct {
			id, field, dek string
			ct, nonce      []byte
		}
		var batch []rec
		for rows.Next() {
			var r rec
			if err := rows.Scan(&r.id, &r.field, &r.dek, &r.ct, &r.nonce); err != nil {
				rows.Close()
				return err
			}
			batch = append(batch, r)
		}
		rows.Close()
		if len(batch) == 0 {
			break
		}
		for _, r := range batch {
			old, err := s.dekByID(ctx, vaultID, r.dek, nil)
			if err != nil {
				return err
			}
			aad := recordAAD(vaultID, r.field, r.id)
			pt, err := Open(old, r.ct, r.nonce, aad)
			if err != nil {
				return fmt.Errorf("re-encrypt record %s failed", r.id)
			}
			ct, nonce, err := Seal(newKey, pt, aad)
			if err != nil {
				return err
			}
			if _, err := s.Pool.Exec(ctx, `UPDATE data.records SET ciphertext=$2,nonce=$3,dek_id=$4 WHERE id=$1::uuid`, r.id, ct, nonce, newID); err != nil {
				return err
			}
		}
	}
	// Subject references too, then retire any key nothing references.
	rows, err := s.Pool.Query(ctx, `SELECT id::text,dek_id,ref_ciphertext,ref_nonce FROM data.subjects WHERE vault_id=$1 AND dek_id<>$2`, vaultID, newID)
	if err != nil {
		return err
	}
	type sub struct {
		id, dek   string
		ct, nonce []byte
	}
	var subs []sub
	for rows.Next() {
		var r sub
		if err := rows.Scan(&r.id, &r.dek, &r.ct, &r.nonce); err != nil {
			rows.Close()
			return err
		}
		subs = append(subs, r)
	}
	rows.Close()
	for _, r := range subs {
		old, err := s.dekByID(ctx, vaultID, r.dek, nil)
		if err != nil {
			return err
		}
		aad := []byte(vaultID + "|subject|" + r.id)
		pt, err := Open(old, r.ct, r.nonce, aad)
		if err != nil {
			return err
		}
		ct, nonce, err := Seal(newKey, pt, aad)
		if err != nil {
			return err
		}
		if _, err := s.Pool.Exec(ctx, `UPDATE data.subjects SET ref_ciphertext=$2,ref_nonce=$3,dek_id=$4 WHERE id=$1::uuid`, r.id, ct, nonce, newID); err != nil {
			return err
		}
	}
	if err := s.reencryptTwins(ctx, vaultID, newID, newKey); err != nil {
		return err
	}
	_, err = s.Pool.Exec(ctx, `UPDATE data.data_keys k SET status='retired' WHERE vault_id=$1 AND status='decrypt_only'
		AND NOT EXISTS (SELECT 1 FROM data.records r WHERE r.dek_id=k.id) AND NOT EXISTS (SELECT 1 FROM data.subjects su WHERE su.dek_id=k.id)
		AND NOT EXISTS (SELECT 1 FROM data.cloak_twins t WHERE t.dek_id=k.id)`, vaultID)
	return err
}

func auditAAD(tenantID string) []byte { return []byte("rv-audit|" + tenantID) }

// AuditKey returns (creating on first use) the tenant's signing key.
func (s *Service) AuditKey(ctx context.Context, tenantID string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	var wrapped []byte
	err := s.Pool.QueryRow(ctx, `SELECT wrapped_private_key FROM data.audit_keys WHERE tenant_id=$1`, tenantID).Scan(&wrapped)
	if errors.Is(err, pgx.ErrNoRows) {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		w, ref, err := s.Keys.Wrap(ctx, priv.Seed(), auditAAD(tenantID))
		if err != nil {
			return nil, nil, wrapErr(err)
		}
		if _, err := s.Pool.Exec(ctx, `INSERT INTO data.audit_keys(tenant_id,wrapped_private_key,public_key,kek_ref) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING`, tenantID, w, base64.StdEncoding.EncodeToString(pub), ref); err != nil {
			return nil, nil, err
		}
		return s.AuditKey(ctx, tenantID)
	}
	if err != nil {
		return nil, nil, err
	}
	seed, err := s.Keys.Unwrap(ctx, wrapped, auditAAD(tenantID))
	if err != nil {
		return nil, nil, wrapErr(err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return priv, priv.Public().(ed25519.PublicKey), nil
}
