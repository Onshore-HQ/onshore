// Package auth verifies bearer tokens and exchanges service-account assertions.
package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"onshore/data-plane/internal/vault"
)

// TokenTTL is the life of an issued bearer token.
const TokenTTL = 15 * time.Minute

// MaxAssertionTTL bounds how long a signed assertion may claim to be valid.
const MaxAssertionTTL = 5 * time.Minute

// Audience is the required aud of assertions.
const Audience = "onshore"

var (
	ErrUnauthenticated = errors.New("missing or expired token")
	ErrForbiddenIP     = errors.New("source address is not on this key's allowlist")
)

// Authenticator validates tokens against the database.
type Authenticator struct {
	Pool         *pgxpool.Pool
	SigningKey   ed25519.PrivateKey // issues service-account tokens
	UserTokenKey ed25519.PublicKey  // verifies control-plane user tokens
	Trusted      []*net.IPNet       // proxies whose X-Forwarded-For we believe
	Now          func() time.Time

	mu    sync.Mutex
	cache map[string]cachedPrincipal
}

type cachedPrincipal struct {
	p      principalRow
	loaded time.Time
}

type principalRow struct {
	tenant, kind, status string
	mfa, mustChange      bool
	roles                []string
	validAfter           *time.Time
}

// PrincipalCacheTTL bounds how long a revoked principal could keep working.
const PrincipalCacheTTL = 5 * time.Second

func (a *Authenticator) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

// ParseCIDRs parses a comma-separated CIDR list.
func ParseCIDRs(s string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, c := range strings.Split(s, ",") {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			return nil, fmt.Errorf("bad CIDR %q", c)
		}
		out = append(out, n)
	}
	return out, nil
}

// ClientIP returns the caller's address. X-Forwarded-For is honoured only from a
// trusted proxy, reading right to left past trusted hops, since a client can put
// anything on the left of that header.
func (a *Authenticator) ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if !a.trusted(host) {
		return host
	}
	parts := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(parts) - 1; i >= 0; i-- {
		ip := strings.TrimSpace(parts[i])
		if ip == "" {
			continue
		}
		if !a.trusted(ip) {
			return ip
		}
		host = ip
	}
	return host
}

func (a *Authenticator) trusted(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range a.Trusted {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

func (a *Authenticator) principal(ctx context.Context, id string) (principalRow, error) {
	a.mu.Lock()
	if a.cache == nil {
		a.cache = map[string]cachedPrincipal{}
	}
	if c, ok := a.cache[id]; ok && a.now().Sub(c.loaded) < PrincipalCacheTTL {
		a.mu.Unlock()
		return c.p, nil
	}
	a.mu.Unlock()
	var p principalRow
	err := a.Pool.QueryRow(ctx, `SELECT p.tenant_id,p.kind,p.status,p.mfa_enabled,p.must_change_password,p.sessions_valid_after,
		coalesce(array_agg(r.name) FILTER (WHERE r.name IS NOT NULL),'{}')
		FROM control.principals p LEFT JOIN control.role_assignments ra ON ra.principal_id=p.id LEFT JOIN control.roles r ON r.id=ra.role_id
		WHERE p.id=$1 GROUP BY p.id`, id).Scan(&p.tenant, &p.kind, &p.status, &p.mfa, &p.mustChange, &p.validAfter, &p.roles)
	if err != nil {
		return p, err
	}
	a.mu.Lock()
	a.cache[id] = cachedPrincipal{p, a.now()}
	a.mu.Unlock()
	return p, nil
}

type tokenClaims struct {
	Tenant string `json:"tid"`
	Kind   string `json:"knd"`
	KeyID  string `json:"kid,omitempty"`
	MFA    bool   `json:"mfa,omitempty"`
	jwt.RegisteredClaims
}

// Authenticate turns a request into a Caller.
func (a *Authenticator) Authenticate(ctx context.Context, r *http.Request) (vault.Caller, error) {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return vault.Caller{}, ErrUnauthenticated
	}
	return a.AuthenticateToken(ctx, strings.TrimPrefix(h, "Bearer "), a.ClientIP(r))
}

// AuthenticateToken validates a bearer token presented from a given address.
func (a *Authenticator) AuthenticateToken(ctx context.Context, bearer, ip string) (vault.Caller, error) {
	var claims tokenClaims
	tok, err := jwt.ParseWithClaims(bearer, &claims, func(t *jwt.Token) (any, error) {
		iss, _ := t.Claims.GetIssuer()
		switch iss {
		case "rv-vault":
			return a.SigningKey.Public(), nil
		case "rv-control":
			if a.UserTokenKey == nil {
				return nil, ErrUnauthenticated
			}
			return a.UserTokenKey, nil
		}
		return nil, ErrUnauthenticated
	}, jwt.WithValidMethods([]string{"EdDSA"}), jwt.WithExpirationRequired(), jwt.WithTimeFunc(a.now), jwt.WithAudience(Audience))
	if err != nil || !tok.Valid {
		return vault.Caller{}, ErrUnauthenticated
	}
	// A user token cannot claim to be a service account or vice versa.
	if (claims.Issuer == "rv-control") != (claims.Kind == "user") {
		return vault.Caller{}, ErrUnauthenticated
	}
	p, err := a.principal(ctx, claims.Subject)
	if errors.Is(err, pgx.ErrNoRows) {
		return vault.Caller{}, ErrUnauthenticated
	}
	if err != nil {
		return vault.Caller{}, err
	}
	if p.status != "active" || p.tenant != claims.Tenant || p.kind != claims.Kind {
		return vault.Caller{}, ErrUnauthenticated
	}
	if p.kind == "user" && !(claims.MFA && p.mfa) {
		return vault.Caller{}, ErrUnauthenticated // MFA is mandatory for console users
	}
	// A password change ends every session issued before it.
	if p.validAfter != nil && (claims.IssuedAt == nil || !claims.IssuedAt.After(p.validAfter.Truncate(time.Second))) {
		return vault.Caller{}, ErrUnauthenticated
	}
	if p.kind == "user" && p.mustChange {
		return vault.Caller{}, ErrUnauthenticated
	}
	if p.kind == "service_account" {
		var allow []string
		var revokedOrExpired bool
		err := a.Pool.QueryRow(ctx, `SELECT ip_allowlist, revoked_at IS NOT NULL OR (expires_at IS NOT NULL AND expires_at<now()) FROM control.service_account_keys WHERE id=$1 AND principal_id=$2`, claims.KeyID, claims.Subject).Scan(&allow, &revokedOrExpired)
		if err != nil || revokedOrExpired {
			return vault.Caller{}, ErrUnauthenticated
		}
		if !ipAllowed(ip, allow) {
			return vault.Caller{}, ErrForbiddenIP
		}
	}
	return vault.Caller{TenantID: p.tenant, PrincipalID: claims.Subject, Kind: p.kind, Roles: p.roles, MFA: claims.MFA, SourceIP: ip}, nil
}

// CallerFor rebuilds a caller for a principal who minted a client token, at the address
// of the browser now using it. Status and roles are read again, so suspending someone or
// changing their roles stops tokens they already issued. A service account's IP allowlist
// is for its servers, not for browsers, so it applies at minting and not here.
func (a *Authenticator) CallerFor(ctx context.Context, principalID, tenantID, ip string) (vault.Caller, error) {
	p, err := a.principal(ctx, principalID)
	if err != nil || p.status != "active" || p.tenant != tenantID {
		return vault.Caller{}, ErrUnauthenticated
	}
	if p.kind == "service_account" {
		var live bool
		err := a.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM control.service_account_keys WHERE principal_id=$1 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>now()))`, principalID).Scan(&live)
		if err != nil || !live {
			return vault.Caller{}, ErrUnauthenticated
		}
	}
	return vault.Caller{TenantID: p.tenant, PrincipalID: principalID, Kind: p.kind, Roles: p.roles, MFA: p.mfa, SourceIP: ip}, nil
}

func ipAllowed(ip string, allow []string) bool {
	if len(allow) == 0 {
		return true
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, c := range allow {
		if _, n, err := net.ParseCIDR(c); err == nil && n.Contains(parsed) {
			return true
		}
		if single := net.ParseIP(c); single != nil && single.Equal(parsed) {
			return true
		}
	}
	return false
}

// ExchangeAssertion trades a customer-signed, single-use JWT for a 15-minute
// bearer token. The private key never leaves the customer.
func (a *Authenticator) ExchangeAssertion(ctx context.Context, assertion, ip string) (string, error) {
	var claims jwt.RegisteredClaims
	var keyID, subjectKey string
	tok, err := jwt.ParseWithClaims(assertion, &claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		sub, _ := t.Claims.GetSubject()
		if kid == "" || sub == "" {
			return nil, ErrUnauthenticated
		}
		var pubB64 string
		var bad bool
		var allow []string
		err := a.Pool.QueryRow(ctx, `SELECT public_key, ip_allowlist, revoked_at IS NOT NULL OR (expires_at IS NOT NULL AND expires_at<now()) FROM control.service_account_keys WHERE id=$1 AND principal_id=$2`, kid, sub).Scan(&pubB64, &allow, &bad)
		if err != nil || bad {
			return nil, ErrUnauthenticated
		}
		if !ipAllowed(ip, allow) {
			return nil, ErrForbiddenIP
		}
		pub, err := base64.StdEncoding.DecodeString(pubB64)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return nil, ErrUnauthenticated
		}
		keyID, subjectKey = kid, sub
		return ed25519.PublicKey(pub), nil
	}, jwt.WithValidMethods([]string{"EdDSA"}), jwt.WithExpirationRequired(), jwt.WithTimeFunc(a.now), jwt.WithAudience(Audience))
	if err != nil || !tok.Valid {
		if errors.Is(err, ErrForbiddenIP) {
			return "", ErrForbiddenIP
		}
		return "", ErrUnauthenticated
	}
	if claims.Issuer != claims.Subject || claims.ID == "" || claims.ExpiresAt.Sub(a.now()) > MaxAssertionTTL {
		return "", ErrUnauthenticated
	}
	sum := sha256.Sum256([]byte(subjectKey + "|" + claims.ID))
	tag, err := a.Pool.Exec(ctx, `INSERT INTO data.used_assertions(jti,expires_at) VALUES ($1,$2) ON CONFLICT DO NOTHING`, hex.EncodeToString(sum[:]), claims.ExpiresAt.Time)
	if err != nil {
		return "", err
	}
	if tag.RowsAffected() == 0 {
		return "", ErrUnauthenticated // replayed
	}
	p, err := a.principal(ctx, subjectKey)
	if err != nil || p.status != "active" || p.kind != "service_account" {
		return "", ErrUnauthenticated
	}
	if _, err := a.Pool.Exec(ctx, `UPDATE control.service_account_keys SET last_used_at=now() WHERE id=$1`, keyID); err != nil {
		return "", err
	}
	now := a.now()
	return jwt.NewWithClaims(jwt.SigningMethodEdDSA, tokenClaims{
		Tenant: p.tenant, Kind: p.kind, KeyID: keyID,
		RegisteredClaims: jwt.RegisteredClaims{Issuer: "rv-vault", Subject: subjectKey, Audience: jwt.ClaimStrings{Audience}, IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(TokenTTL))},
	}).SignedString(a.SigningKey)
}

// Limiter is a fixed-window per-key counter for unauthenticated traffic. It runs in
// the vault process because the stock edge image has no rate limiting. Counters
// are per replica, so the effective limit scales with replicas.
type Limiter struct {
	PerMinute int
	mu        sync.Mutex
	window    time.Time
	counts    map[string]int
}

// Allow records one attempt and reports whether it is within the limit.
func (l *Limiter) Allow(key string, now time.Time) bool {
	if l == nil || l.PerMinute <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	w := now.Truncate(time.Minute)
	if !w.Equal(l.window) || l.counts == nil {
		l.window, l.counts = w, map[string]int{}
	}
	l.counts[key]++
	return l.counts[key] <= l.PerMinute
}
