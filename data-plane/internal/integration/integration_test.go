// Package integration exercises the full data API against a real PostgreSQL.
// Set RV_TEST_DATABASE_URL to an owner connection on a disposable database.
package integration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"onshore/data-plane/internal/auth"
	"onshore/data-plane/internal/httpapi"
	"onshore/data-plane/internal/keys"
	"onshore/data-plane/internal/store"
	"onshore/data-plane/internal/vault"
)

const (
	vaultPW   = "testvaultpassword0001"
	controlPW = "testcontrolpassword01"
	internal  = "internal-test-token"
)

type env struct {
	t       *testing.T
	owner   *pgxpool.Pool
	svc     *vault.Service
	srv     *httptest.Server
	userKey ed25519.PrivateKey
	keysBox *flakyKeys
	tenant  string
	vault   string
	ctx     context.Context
}

// flakyKeys lets a test take the key service down.
type flakyKeys struct {
	keys.Service
	mu   sync.Mutex
	down bool
}

func (f *flakyKeys) set(v bool) { f.mu.Lock(); f.down = v; f.mu.Unlock() }
func (f *flakyKeys) isDown() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.down
}
func (f *flakyKeys) Unwrap(ctx context.Context, w, a []byte) ([]byte, error) {
	if f.isDown() {
		return nil, keys.ErrUnavailable
	}
	return f.Service.Unwrap(ctx, w, a)
}
func (f *flakyKeys) Wrap(ctx context.Context, p, a []byte) ([]byte, string, error) {
	if f.isDown() {
		return nil, "", keys.ErrUnavailable
	}
	return f.Service.Wrap(ctx, p, a)
}

var (
	setupOnce   sync.Once
	setupErr    error
	localOnce   sync.Once
	localErr    error
	sharedLocal *keys.LocalFile
)

func roleURL(ownerURL, user, pw string) string {
	u, _ := url.Parse(ownerURL)
	u.User = url.UserPassword(user, pw)
	return u.String()
}

func setup(t *testing.T) *env {
	t.Helper()
	ownerURL := os.Getenv("RV_TEST_DATABASE_URL")
	if ownerURL == "" {
		t.Skip("RV_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	setupOnce.Do(func() { _, setupErr = store.Migrate(ctx, ownerURL, vaultPW, controlPW) })
	if setupErr != nil {
		t.Fatal(setupErr)
	}
	owner, err := store.Open(ctx, ownerURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(owner.Close)
	pool, err := store.Open(ctx, roleURL(ownerURL, "rv_vault", vaultPW))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	// One KEK across tests: they share a database, and rotation covers all of it.
	localOnce.Do(func() {
		dir, err := os.MkdirTemp("", "rv-kek")
		if err == nil {
			sharedLocal, err = keys.NewLocalFile(filepath.Join(dir, "kek"))
		}
		localErr = err
	})
	if localErr != nil {
		t.Fatal(localErr)
	}
	box := &flakyKeys{Service: sharedLocal}
	svc := vault.New(pool, box)
	userPub, userPriv, _ := ed25519.GenerateKey(rand.Reader)
	_, signing, _ := ed25519.GenerateKey(rand.Reader)
	trusted, _ := auth.ParseCIDRs("")
	api := &httpapi.Server{Vault: svc, Auth: &auth.Authenticator{Pool: pool, SigningKey: signing, UserTokenKey: userPub, Trusted: trusted}, InternalToken: internal, Version: "test"}
	srv := httptest.NewServer(api.Handler())
	t.Cleanup(srv.Close)

	e := &env{t: t, owner: owner, svc: svc, srv: srv, userKey: userPriv, keysBox: box, ctx: ctx}
	e.tenant, e.vault = e.newTenant()
	return e
}

func id(prefix string) string {
	b := make([]byte, 6)
	rand.Read(b)
	return fmt.Sprintf("%s_%x", prefix, b)
}

func (e *env) exec(q string, args ...any) {
	e.t.Helper()
	if _, err := e.owner.Exec(e.ctx, q, args...); err != nil {
		e.t.Fatalf("%s: %v", q, err)
	}
}

// newTenant creates a tenant, a vault with common fields and the test policy.
func (e *env) newTenant() (string, string) {
	tenant, v := id("t"), id("v")
	e.exec(`INSERT INTO control.tenants(id,name) VALUES ($1,$1)`, tenant)
	e.exec(`INSERT INTO control.vaults(id,tenant_id,name,environment) VALUES ($1,$2,'main','sandbox')`, v, tenant)
	for _, f := range [][]string{
		{"bvn", "bvn", "deterministic", "opaque"}, {"phone", "phone_ng", "deterministic", "opaque"}, {"account_number", "nuban", "deterministic", "opaque"},
		{"nin_fp", "nin", "deterministic", "format_preserving"}, {"note", "free_text", "cell", "opaque"}, {"otp", "free_text", "transient", "opaque"}, {"email", "email", "deterministic", "opaque"},
	} {
		e.exec(`INSERT INTO control.vault_fields(id,vault_id,name,data_type,token_kind,token_format,ttl_seconds) VALUES ($1,$2,$3,$4,$5,$6,$7)`, id("f"), v, f[0], f[1], f[2], f[3], ttlFor(f[0]))
	}
	return tenant, v
}

func ttlFor(name string) any {
	if name == "otp" {
		return 1
	}
	return nil
}

const testPolicy = `{"limit_per_hour":0,"rules":[
 {"id":"svc","actions":["tokenize","insert","search"],"who":{"roles":["backend"]},"returns":"allow"},
 {"id":"svc-read","actions":["detokenize"],"who":{"roles":["backend"]},"returns":"plaintext"},
 {"id":"support-mask","actions":["detokenize"],"who":{"roles":["support"]},"what":{"fields":["bvn","account_number"]},"returns":"masked"},
 {"id":"support-phone","actions":["detokenize"],"who":{"roles":["support"]},"what":{"fields":["phone"]},"when":{"purpose_required":true},"returns":"plaintext"},
 {"id":"support-search","actions":["search"],"who":{"roles":["support"]},"returns":"allow"},
 {"id":"dpo","actions":["delete","export","search"],"who":{"roles":["dpo"]},"returns":"plaintext"}]}`

func (e *env) publish(tenant, name, source string, version int) {
	e.t.Helper()
	body, _ := json.Marshal(map[string]any{"name": name, "version": version, "source": json.RawMessage(source)})
	var out struct {
		Compiled json.RawMessage `json:"compiled"`
	}
	if st := e.call("POST", "/internal/policy/compile", internal, body, &out); st != 200 {
		e.t.Fatalf("compile: %d", st)
	}
	e.exec(`UPDATE control.policies SET status='archived' WHERE tenant_id=$1 AND name=$2 AND status='active'`, tenant, name)
	e.exec(`INSERT INTO control.policies(id,tenant_id,name,version,source,compiled_cel,status,created_by,approved_by,published_at) VALUES ($1,$2,$3,$4,$5,$6,'active','a','b',now())`, id("pol"), tenant, name, version, source, string(out.Compiled))
	time.Sleep(10 * time.Millisecond)
	e.svc.Now = func() time.Time { return time.Now().Add(configTTLBust()) }
}

// configTTLBust moves the clock so cached policies expire immediately in tests.
var bust int64
var bustMu sync.Mutex

func configTTLBust() time.Duration {
	bustMu.Lock()
	defer bustMu.Unlock()
	return time.Duration(bust) * 6 * time.Second
}
func nextTick() { bustMu.Lock(); bust++; bustMu.Unlock() }

type principal struct {
	id, token string
	key       ed25519.PrivateKey
	keyID     string
}

// user creates a console user with roles and returns a control-plane style token.
func (e *env) user(tenant string, roles ...string) principal {
	e.t.Helper()
	pid := id("usr")
	e.exec(`INSERT INTO control.principals(id,tenant_id,kind,display_name,email,mfa_enabled) VALUES ($1,$2,'user',$1,$3,true)`, pid, tenant, pid+"@example.ng")
	e.assign(tenant, pid, roles)
	tok, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{"iss": "rv-control", "sub": pid, "aud": auth.Audience, "tid": tenant, "knd": "user", "mfa": true, "exp": time.Now().Add(15 * time.Minute).Unix()}).SignedString(e.userKey)
	if err != nil {
		e.t.Fatal(err)
	}
	return principal{id: pid, token: tok}
}

func (e *env) assign(tenant, pid string, roles []string) {
	for _, r := range roles {
		rid := tenant + ":" + r
		e.exec(`INSERT INTO control.roles(id,tenant_id,name) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`, rid, tenant, r)
		e.exec(`INSERT INTO control.role_assignments(role_id,principal_id) VALUES ($1,$2)`, rid, pid)
	}
}

func (e *env) serviceAccount(tenant string, allow []string, roles ...string) principal {
	e.t.Helper()
	pid, kid := id("sa"), id("key")
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	e.exec(`INSERT INTO control.principals(id,tenant_id,kind,display_name) VALUES ($1,$2,'service_account',$1)`, pid, tenant)
	if allow == nil {
		allow = []string{}
	}
	e.exec(`INSERT INTO control.service_account_keys(id,principal_id,public_key,fingerprint,ip_allowlist) VALUES ($1,$2,$3,'fp',$4)`, kid, pid, base64.StdEncoding.EncodeToString(pub), allow)
	e.assign(tenant, pid, roles)
	return principal{id: pid, key: priv, keyID: kid}
}

func (e *env) assertion(p principal, jti string) string {
	t := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{"iss": p.id, "sub": p.id, "aud": auth.Audience, "jti": jti, "exp": time.Now().Add(2 * time.Minute).Unix()})
	t.Header["kid"] = p.keyID
	s, err := t.SignedString(p.key)
	if err != nil {
		e.t.Fatal(err)
	}
	return s
}

func (e *env) login(p principal) principal {
	e.t.Helper()
	var out struct {
		AccessToken string `json:"access_token"`
	}
	body, _ := json.Marshal(map[string]string{"assertion": e.assertion(p, id("j"))})
	if st := e.call("POST", "/v1/auth/token", "", body, &out); st != 200 {
		e.t.Fatalf("login: %d", st)
	}
	p.token = out.AccessToken
	return p
}

func (e *env) call(method, path, token string, body []byte, out any, headers ...string) int {
	e.t.Helper()
	req, _ := http.NewRequest(method, e.srv.URL+path, bytes.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	if out != nil {
		json.NewDecoder(resp.Body).Decode(out)
	}
	return resp.StatusCode
}

type tokResp struct {
	Results []struct {
		Index    int          `json:"index"`
		Token    string       `json:"token"`
		Existing *bool        `json:"existing"`
		Error    *vault.Error `json:"error"`
	} `json:"results"`
	Error *vault.Error `json:"error"`
}

func j(v any) []byte { b, _ := json.Marshal(v); return b }

func (e *env) tokenize(vaultID, token string, items ...map[string]string) (tokResp, int) {
	e.t.Helper()
	var out tokResp
	st := e.call("POST", "/v1/vaults/"+vaultID+"/tokenize", token, j(map[string]any{"items": items, "continue_on_error": true}), &out)
	return out, st
}

type detokResp struct {
	Results []struct {
		Decision string       `json:"decision"`
		Value    string       `json:"value"`
		Policy   string       `json:"policy"`
		Error    *vault.Error `json:"error"`
	} `json:"results"`
	Error *vault.Error `json:"error"`
}

func (e *env) detok(vaultID, token, purpose string, toks ...string) (detokResp, int) {
	e.t.Helper()
	items := make([]map[string]string, len(toks))
	for i, t := range toks {
		items[i] = map[string]string{"token": t}
	}
	var out detokResp
	st := e.call("POST", "/v1/vaults/"+vaultID+"/detokenize", token, j(map[string]any{"items": items, "purpose": purpose, "continue_on_error": true}), &out)
	return out, st
}

func ready(t *testing.T) (*env, principal) {
	e := setup(t)
	e.publish(e.tenant, "test", testPolicy, 1)
	nextTick()
	return e, e.login(e.serviceAccount(e.tenant, nil, "backend"))
}

func TestTokenizeIsDeterministicAndDetokenizeRoundTrips(t *testing.T) {
	e, sa := ready(t)
	r1, st := e.tokenize(e.vault, sa.token, map[string]string{"field": "bvn", "value": "22123456789", "subject_ref": "cust_1"}, map[string]string{"field": "account_number", "value": "0123456789", "subject_ref": "cust_1"})
	if st != 200 || r1.Results[0].Token == "" || *r1.Results[0].Existing {
		t.Fatalf("%d %+v", st, r1)
	}
	if !strings.HasPrefix(r1.Results[0].Token, "tok_bvn_") {
		t.Fatal(r1.Results[0].Token)
	}
	r2, _ := e.tokenize(e.vault, sa.token, map[string]string{"field": "bvn", "value": "221-2345-6789"})
	if r2.Results[0].Token != r1.Results[0].Token || !*r2.Results[0].Existing {
		t.Fatalf("normalised duplicate must reuse the token: %+v", r2)
	}
	d, st := e.detok(e.vault, sa.token, "test", r1.Results[0].Token, r1.Results[1].Token)
	if st != 200 || d.Results[0].Value != "22123456789" || d.Results[1].Value != "0123456789" || d.Results[0].Decision != "plaintext" {
		t.Fatalf("%d %+v", st, d)
	}
}

func TestNoPlaintextReachesTheDatabase(t *testing.T) {
	e, sa := ready(t)
	secret := "22987654321"
	ref := "customer-secret-ref-991"
	if r, st := e.tokenize(e.vault, sa.token, map[string]string{"field": "bvn", "value": secret, "subject_ref": ref}); st != 200 || r.Results[0].Error != nil {
		t.Fatalf("%d %+v", st, r)
	}
	for _, table := range []string{"data.records", "data.tokens", "data.subjects", "data.data_keys", "events.audit_events"} {
		var n int
		q := fmt.Sprintf(`SELECT count(*) FROM %s x WHERE x::text LIKE '%%'||$1||'%%' OR encode(convert_to(x::text,'UTF8'),'escape') LIKE '%%'||$1||'%%'`, table)
		for _, s := range []string{secret, ref} {
			if err := e.owner.QueryRow(e.ctx, q, s).Scan(&n); err != nil {
				t.Fatal(err)
			}
			if n != 0 {
				t.Errorf("%s holds plaintext %q", table, s)
			}
		}
	}
	var ct []byte
	if err := e.owner.QueryRow(e.ctx, `SELECT ciphertext FROM data.records WHERE vault_id=$1 LIMIT 1`, e.vault).Scan(&ct); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ct, []byte(secret)) {
		t.Fatal("ciphertext holds plaintext")
	}
}

func TestCiphertextMovedToAnotherRowFailsToDecrypt(t *testing.T) {
	e, sa := ready(t)
	a, _ := e.tokenize(e.vault, sa.token, map[string]string{"field": "bvn", "value": "22000000001"})
	b, _ := e.tokenize(e.vault, sa.token, map[string]string{"field": "bvn", "value": "22000000002"})
	e.exec(`UPDATE data.records SET ciphertext=src.ciphertext,nonce=src.nonce FROM (SELECT r.ciphertext,r.nonce FROM data.records r JOIN data.tokens t ON t.record_id=r.id WHERE t.token=$1) src
		WHERE id=(SELECT record_id FROM data.tokens WHERE token=$2)`, a.Results[0].Token, b.Results[0].Token)
	if _, st := e.detok(e.vault, sa.token, "t", b.Results[0].Token); st != 500 {
		t.Fatalf("expected a refusal, got %d", st)
	}
}

func TestPolicyDecisionsAndDefaultDeny(t *testing.T) {
	e, sa := ready(t)
	toks, _ := e.tokenize(e.vault, sa.token, map[string]string{"field": "bvn", "value": "22123456701"}, map[string]string{"field": "phone", "value": "08031234567"}, map[string]string{"field": "email", "value": "ada@example.ng"})
	bvn, phone, email := toks.Results[0].Token, toks.Results[1].Token, toks.Results[2].Token
	support := e.user(e.tenant, "support")

	d, _ := e.detok(e.vault, support.token, "Ticket 1", bvn, phone, email)
	if d.Results[0].Decision != "masked" || d.Results[0].Value != "*******6701" {
		t.Errorf("bvn: %+v", d.Results[0])
	}
	if d.Results[1].Decision != "plaintext" || d.Results[1].Value != "+2348031234567" {
		t.Errorf("phone: %+v", d.Results[1])
	}
	if d.Results[2].Decision != "denied" || d.Results[2].Value != "" || d.Results[2].Error.Code != "policy_denied" {
		t.Errorf("no rule for email must be denied: %+v", d.Results[2])
	}

	nobody := e.user(e.tenant, "marketing")
	d, _ = e.detok(e.vault, nobody.token, "curious", bvn)
	if d.Results[0].Decision != "denied" || d.Results[0].Value != "" {
		t.Errorf("%+v", d.Results[0])
	}
	if _, st := e.detok(e.vault, support.token, "", bvn); st != 400 {
		t.Errorf("purpose must be required, got %d", st)
	}
	// Writes are denied by default too.
	r, _ := e.tokenize(e.vault, nobody.token, map[string]string{"field": "bvn", "value": "22123456701"})
	if r.Results[0].Error == nil || r.Results[0].Error.Code != "policy_denied" {
		t.Errorf("%+v", r.Results[0])
	}
}

func TestTenantIsolation(t *testing.T) {
	e, sa := ready(t)
	toks, _ := e.tokenize(e.vault, sa.token, map[string]string{"field": "bvn", "value": "22123456702"})
	tenantB, vaultB := e.newTenant()
	e.publish(tenantB, "test", testPolicy, 1)
	nextTick()
	saB := e.login(e.serviceAccount(tenantB, nil, "backend"))

	if _, st := e.detok(e.vault, saB.token, "x", toks.Results[0].Token); st != 404 {
		t.Errorf("reaching across tenants must look like an unknown vault, got %d", st)
	}
	d, _ := e.detok(vaultB, saB.token, "x", toks.Results[0].Token)
	if d.Results[0].Error == nil || d.Results[0].Error.Code != "token_not_found" || d.Results[0].Value != "" {
		t.Errorf("another tenant's token must not resolve in my vault: %+v", d.Results[0])
	}
	if _, st := e.tokenize(e.vault, saB.token, map[string]string{"field": "bvn", "value": "22123456703"}); st != 404 {
		t.Errorf("got %d", st)
	}
	var out map[string]any
	if st := e.call("POST", "/v1/vaults/"+e.vault+"/subjects/search", saB.token, []byte(`{}`), &out); st != 404 {
		t.Errorf("got %d", st)
	}
}

func TestDatabaseRoleBoundaries(t *testing.T) {
	e := setup(t)
	ownerURL := os.Getenv("RV_TEST_DATABASE_URL")
	control, err := store.Open(e.ctx, roleURL(ownerURL, "rv_control", controlPW))
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	for _, q := range []string{`SELECT * FROM data.records LIMIT 1`, `SELECT * FROM data.data_keys LIMIT 1`, `INSERT INTO events.audit_events(event_id) VALUES (gen_random_uuid())`, `DELETE FROM events.audit_events`} {
		if _, err := control.Exec(e.ctx, q); err == nil {
			t.Errorf("rv_control must not be able to run %q", q)
		}
	}
	vaultRole, err := store.Open(e.ctx, roleURL(ownerURL, "rv_vault", vaultPW))
	if err != nil {
		t.Fatal(err)
	}
	defer vaultRole.Close()
	for _, q := range []string{`DELETE FROM events.audit_events`, `UPDATE events.audit_events SET purpose='x'`, `TRUNCATE events.audit_events`, `ALTER TABLE events.audit_events DISABLE TRIGGER audit_append_only`, `INSERT INTO control.tenants(id,name) VALUES ('x','x')`, `UPDATE control.policies SET status='active'`} {
		if _, err := vaultRole.Exec(e.ctx, q); err == nil {
			t.Errorf("rv_vault must not be able to run %q", q)
		}
	}
}

func TestAuditChainDetectsTampering(t *testing.T) {
	e, sa := ready(t)
	toks, _ := e.tokenize(e.vault, sa.token, map[string]string{"field": "bvn", "value": "22123456704"})
	e.detok(e.vault, sa.token, "first", toks.Results[0].Token)
	e.detok(e.vault, sa.token, "second", toks.Results[0].Token)

	verify := func() map[string]any {
		var out map[string]any
		if st := e.call("POST", "/internal/audit/verify", internal, j(map[string]string{"tenant_id": e.tenant}), &out); st != 200 {
			t.Fatalf("verify %d", st)
		}
		return out
	}
	if res := verify(); res["ok"] != true || res["events_checked"].(float64) < 3 {
		t.Fatalf("%+v", res)
	}
	// An attacker with database owner rights rewrites history.
	e.exec(`ALTER TABLE events.audit_events DISABLE TRIGGER audit_append_only`)
	defer e.exec(`ALTER TABLE events.audit_events ENABLE TRIGGER audit_append_only`)
	e.exec(`UPDATE events.audit_events SET purpose='nothing to see' WHERE tenant_id=$1 AND purpose='first'`, e.tenant)
	if res := verify(); res["ok"] != false {
		t.Fatalf("an edited event must fail verification: %+v", res)
	}
	e.exec(`UPDATE events.audit_events SET purpose='first' WHERE tenant_id=$1 AND purpose='nothing to see'`, e.tenant)
	if res := verify(); res["ok"] != true {
		t.Fatalf("restoring it must verify again: %+v", res)
	}
	e.exec(`DELETE FROM events.audit_events WHERE tenant_id=$1 AND purpose='second'`, e.tenant)
	if res := verify(); res["ok"] != false {
		t.Fatalf("a removed event must fail verification: %+v", res)
	}
}

func TestCheckpointSignatureVerifies(t *testing.T) {
	e, sa := ready(t)
	toks, _ := e.tokenize(e.vault, sa.token, map[string]string{"field": "bvn", "value": "22123456705"})
	e.detok(e.vault, sa.token, "p", toks.Results[0].Token)
	var seq int64
	var hash string
	if err := e.owner.QueryRow(e.ctx, `SELECT seq,hash FROM events.audit_events WHERE tenant_id=$1 ORDER BY seq DESC LIMIT 1`, e.tenant).Scan(&seq, &hash); err != nil {
		t.Fatal(err)
	}
	err := pgx.BeginFunc(e.ctx, e.svc.Pool, func(tx pgx.Tx) error {
		return e.svc.SignCheckpoint(e.ctx, tx, e.tenant, "2026-01-01", seq, hash)
	})
	if err != nil {
		t.Fatal(err)
	}
	var res map[string]any
	e.call("POST", "/internal/audit/verify", internal, j(map[string]string{"tenant_id": e.tenant}), &res)
	if res["ok"] != true || res["checkpoints_checked"].(float64) != 1 {
		t.Fatalf("%+v", res)
	}
	e.exec(`UPDATE events.audit_checkpoints SET signature=$2 WHERE tenant_id=$1`, e.tenant, base64.StdEncoding.EncodeToString(make([]byte, 64)))
	e.call("POST", "/internal/audit/verify", internal, j(map[string]string{"tenant_id": e.tenant}), &res)
	if res["ok"] != false {
		t.Fatalf("a forged checkpoint must fail: %+v", res)
	}
}

func TestUsageRollupCountsVaultActivity(t *testing.T) {
	e, sa := ready(t)
	toks, _ := e.tokenize(e.vault, sa.token, map[string]string{"field": "bvn", "value": "22123456707"})
	nobody := e.user(e.tenant, "marketing")
	e.detok(e.vault, sa.token, "allowed read", toks.Results[0].Token)
	e.detok(e.vault, nobody.token, "denied read", toks.Results[0].Token)
	for i := 0; i < 2; i++ { // The second run must update the same row, not fail on it.
		if err := e.svc.RollupUsage(e.ctx); err != nil {
			t.Fatal(err)
		}
	}
	var tokenized, revealed, denied int64
	if err := e.owner.QueryRow(e.ctx, `SELECT tokenize_count,detokenize_count,denied_count FROM events.usage_daily WHERE vault_id=$1`, e.vault).Scan(&tokenized, &revealed, &denied); err != nil {
		t.Fatal(err)
	}
	if tokenized < 1 || revealed != 1 || denied != 1 {
		t.Fatalf("tokenized=%d revealed=%d denied=%d", tokenized, revealed, denied)
	}
}

func TestEveryAccessIsAudited(t *testing.T) {
	e, sa := ready(t)
	toks, _ := e.tokenize(e.vault, sa.token, map[string]string{"field": "bvn", "value": "22123456706"})
	nobody := e.user(e.tenant, "marketing")
	e.detok(e.vault, sa.token, "allowed read", toks.Results[0].Token)
	e.detok(e.vault, nobody.token, "denied read", toks.Results[0].Token)
	var action, decision string
	if err := e.owner.QueryRow(e.ctx, `SELECT action,decision FROM events.audit_events WHERE tenant_id=$1 AND purpose='denied read'`, e.tenant).Scan(&action, &decision); err != nil {
		t.Fatal(err)
	}
	if action != "reveal_denied" || decision != "denied" {
		t.Fatalf("%s %s", action, decision)
	}
	if err := e.owner.QueryRow(e.ctx, `SELECT action,decision FROM events.audit_events WHERE tenant_id=$1 AND purpose='allowed read'`, e.tenant).Scan(&action, &decision); err != nil {
		t.Fatal(err)
	}
	if action != "detokenize" || decision != "plaintext" {
		t.Fatalf("%s %s", action, decision)
	}
}

func TestFailsClosedWithoutKeyService(t *testing.T) {
	e, sa := ready(t)
	toks, _ := e.tokenize(e.vault, sa.token, map[string]string{"field": "bvn", "value": "22123456707"})
	// Age out the in-memory DEK, then take the key service away.
	real := e.svc.Now
	e.svc.Now = func() time.Time { return real().Add(time.Hour) }
	e.keysBox.set(true)
	defer e.keysBox.set(false)
	d, st := e.detok(e.vault, sa.token, "x", toks.Results[0].Token)
	if st != 503 || d.Error == nil || d.Error.Code != "key_service_unavailable" {
		t.Fatalf("%d %+v", st, d)
	}
	var res map[string]any
	if st := e.call("GET", "/healthz", "", nil, &res); st != 200 {
		t.Logf("health reported %d", st) // the health probe uses the wrapped backend directly
	}
}

func TestAssertionReplayExpiryRevocationAndAllowlist(t *testing.T) {
	e, _ := ready(t)
	p := e.serviceAccount(e.tenant, nil, "backend")
	a := e.assertion(p, "single-use-"+id("j"))
	if st := e.call("POST", "/v1/auth/token", "", j(map[string]string{"assertion": a}), nil); st != 200 {
		t.Fatalf("first use %d", st)
	}
	if st := e.call("POST", "/v1/auth/token", "", j(map[string]string{"assertion": a}), nil); st != 401 {
		t.Fatalf("a replayed assertion must fail, got %d", st)
	}

	// A token signed by the wrong key.
	_, otherKey, _ := ed25519.GenerateKey(rand.Reader)
	bad := e.assertion(principal{id: p.id, key: otherKey, keyID: p.keyID}, id("j"))
	if st := e.call("POST", "/v1/auth/token", "", j(map[string]string{"assertion": bad}), nil); st != 401 {
		t.Fatalf("wrong key %d", st)
	}
	// alg=none must not be accepted as a bearer token.
	none, _ := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{"iss": "rv-control", "sub": p.id, "aud": auth.Audience, "tid": e.tenant, "knd": "user", "mfa": true, "exp": time.Now().Add(time.Minute).Unix()}).SignedString(jwt.UnsafeAllowNoneSignatureType)
	if _, st := e.tokenize(e.vault, none, map[string]string{"field": "bvn", "value": "22123456789"}); st != 401 {
		t.Fatalf("alg none %d", st)
	}

	// Revocation stops issued tokens at once, because the key is checked per request.
	logged := e.login(p)
	if _, st := e.tokenize(e.vault, logged.token, map[string]string{"field": "bvn", "value": "22123456708"}); st != 200 {
		t.Fatalf("%d", st)
	}
	e.exec(`UPDATE control.service_account_keys SET revoked_at=now() WHERE id=$1`, p.keyID)
	if _, st := e.tokenize(e.vault, logged.token, map[string]string{"field": "bvn", "value": "22123456708"}); st != 401 {
		t.Fatalf("a revoked key must stop working, got %d", st)
	}

	// Allowlist excludes the loopback address the test client uses.
	fenced := e.serviceAccount(e.tenant, []string{"203.0.113.0/24"}, "backend")
	body := j(map[string]string{"assertion": e.assertion(fenced, id("j"))})
	if st := e.call("POST", "/v1/auth/token", "", body, nil); st != 403 {
		t.Fatalf("allowlist %d", st)
	}

	// A user token without MFA is refused.
	u := e.user(e.tenant, "support")
	noMFA, _ := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{"iss": "rv-control", "sub": u.id, "aud": auth.Audience, "tid": e.tenant, "knd": "user", "mfa": false, "exp": time.Now().Add(time.Minute).Unix()}).SignedString(e.userKey)
	if _, st := e.detok(e.vault, noMFA, "x", "tok_x"); st != 401 {
		t.Fatalf("no mfa %d", st)
	}
	// Internal API needs its own token.
	if st := e.call("POST", "/internal/stats", logged.token, j(map[string]string{"tenant_id": e.tenant}), nil); st != 401 {
		t.Fatalf("internal %d", st)
	}
}

func TestErasureSharedValueSurvivesUntilLastOwner(t *testing.T) {
	e, sa := ready(t)
	shared := "08099990000"
	a, _ := e.tokenize(e.vault, sa.token, map[string]string{"field": "phone", "value": shared, "subject_ref": "alice"}, map[string]string{"field": "bvn", "value": "22123456709", "subject_ref": "alice"})
	b, _ := e.tokenize(e.vault, sa.token, map[string]string{"field": "phone", "value": shared, "subject_ref": "bola"})
	if a.Results[0].Token != b.Results[0].Token {
		t.Fatal("a shared line has one deterministic token")
	}
	dpo := e.user(e.tenant, "dpo")
	var list struct {
		Subjects []vault.SubjectSummary `json:"subjects"`
		Total    int                    `json:"total"`
	}
	if st := e.call("POST", "/v1/vaults/"+e.vault+"/subjects/search", dpo.token, j(map[string]string{"query": "alice"}), &list); st != 200 || list.Total != 1 || list.Subjects[0].Ref != "alice" {
		t.Fatalf("%d %+v", st, list)
	}
	aliceID := list.Subjects[0].ID
	var er map[string]any
	if st := e.call("DELETE", "/v1/vaults/"+e.vault+"/subjects/"+aliceID, dpo.token, nil, &er, "X-RV-Purpose", "NDPA erasure request 7"); st != 200 || er["erased_records"].(float64) != 1 {
		t.Fatalf("%d %+v", st, er)
	}
	d, _ := e.detok(e.vault, sa.token, "t", a.Results[1].Token)
	if d.Results[0].Error == nil || d.Results[0].Error.Code != "token_not_found" {
		t.Fatalf("alice's own value must be gone: %+v", d.Results[0])
	}
	d, _ = e.detok(e.vault, sa.token, "t", b.Results[0].Token)
	if d.Results[0].Value != "+2348099990000" {
		t.Fatalf("bola still uses the shared line: %+v", d.Results[0])
	}
	var n int
	if err := e.owner.QueryRow(e.ctx, `SELECT count(*) FROM events.audit_events WHERE tenant_id=$1 AND action='delete' AND purpose='NDPA erasure request 7'`, e.tenant).Scan(&n); err != nil || n < 2 {
		t.Fatalf("erasure must be audited: %d %v", n, err)
	}
}

func TestSubjectExportRestrictAndSearchByValue(t *testing.T) {
	e, sa := ready(t)
	e.tokenize(e.vault, sa.token, map[string]string{"field": "bvn", "value": "22123456710", "subject_ref": "chi"})
	dpo := e.user(e.tenant, "dpo")
	var list struct {
		Subjects []vault.SubjectSummary `json:"subjects"`
	}
	// Exact-value search reaches the subject through the blind index.
	if st := e.call("POST", "/v1/vaults/"+e.vault+"/subjects/search", dpo.token, j(map[string]string{"query": "22123456710"}), &list); st != 200 || len(list.Subjects) != 1 {
		t.Fatalf("%d %+v", st, list)
	}
	id := list.Subjects[0].ID
	var exp struct {
		Fields []map[string]string `json:"fields"`
	}
	if st := e.call("GET", "/v1/vaults/"+e.vault+"/subjects/"+id+"/export", dpo.token, nil, &exp, "X-RV-Purpose", "NDPA access request"); st != 200 || exp.Fields[0]["value"] != "22123456710" {
		t.Fatalf("%d %+v", st, exp)
	}
	nobody := e.user(e.tenant, "marketing")
	if st := e.call("GET", "/v1/vaults/"+e.vault+"/subjects/"+id+"/export", nobody.token, nil, nil, "X-RV-Purpose", "curious"); st != 403 {
		t.Fatalf("export must be policy-gated, got %d", st)
	}
	if st := e.call("POST", "/v1/vaults/"+e.vault+"/subjects/"+id+"/restrict", dpo.token, j(map[string]any{"restricted": true, "purpose": "objection"}), nil); st != 200 {
		t.Fatal(st)
	}
	var det vault.SubjectDetail
	e.call("GET", "/v1/vaults/"+e.vault+"/subjects/"+id, dpo.token, nil, &det)
	tok := det.Fields[0].Token
	d, _ := e.detok(e.vault, sa.token, "t", tok)
	if d.Results[0].Value != "" || d.Results[0].Decision != "denied" {
		t.Fatalf("restriction must override allow: %+v", d.Results[0])
	}
}

func TestLookupNeedsPermissionAndIsRateLimited(t *testing.T) {
	e, sa := ready(t)
	toks, _ := e.tokenize(e.vault, sa.token, map[string]string{"field": "bvn", "value": "22123456711"})
	var out struct {
		Token string       `json:"token"`
		Error *vault.Error `json:"error"`
	}
	if st := e.call("POST", "/v1/vaults/"+e.vault+"/lookup", sa.token, j(map[string]string{"field": "bvn", "value": "22123456711"}), &out); st != 200 || out.Token != toks.Results[0].Token {
		t.Fatalf("%d %+v", st, out)
	}
	if st := e.call("POST", "/v1/vaults/"+e.vault+"/lookup", sa.token, j(map[string]string{"field": "bvn", "value": "22000000000"}), nil); st != 404 {
		t.Fatalf("%d", st)
	}
	nobody := e.user(e.tenant, "marketing")
	if st := e.call("POST", "/v1/vaults/"+e.vault+"/lookup", nobody.token, j(map[string]string{"field": "bvn", "value": "22123456711"}), nil); st != 403 {
		t.Fatalf("%d", st)
	}
	var last int
	for i := 0; i < 70; i++ {
		last = e.call("POST", "/v1/vaults/"+e.vault+"/lookup", sa.token, j(map[string]string{"field": "bvn", "value": "22123456711"}), nil)
	}
	if last != 429 {
		t.Fatalf("lookups must be rate limited, got %d", last)
	}
}

func TestRevealLimit(t *testing.T) {
	e, sa := ready(t)
	e.publish(e.tenant, "limited", `{"limit_per_hour":3,"rules":[{"id":"r","actions":["detokenize"],"who":{"roles":["capped"]},"returns":"masked"}]}`, 1)
	nextTick()
	toks, _ := e.tokenize(e.vault, sa.token, map[string]string{"field": "bvn", "value": "22123456712"})
	u := e.user(e.tenant, "capped")
	var last detokResp
	for i := 0; i < 5; i++ {
		last, _ = e.detok(e.vault, u.token, "t", toks.Results[0].Token)
	}
	if last.Results[0].Error == nil || last.Results[0].Error.Code != "rate_limited" || last.Results[0].Value != "" {
		t.Fatalf("%+v", last.Results[0])
	}
}

func TestTokenKinds(t *testing.T) {
	e, sa := ready(t)
	// Format-preserving: right shape, and it round-trips.
	fp, _ := e.tokenize(e.vault, sa.token, map[string]string{"field": "nin_fp", "value": "31234567890"})
	tok := fp.Results[0].Token
	if len(tok) != 11 || !strings.HasPrefix(tok, vault.FPPrefixID) {
		t.Fatal(tok)
	}
	if d, _ := e.detok(e.vault, sa.token, "t", tok); d.Results[0].Value != "31234567890" {
		t.Fatalf("%+v", d)
	}
	// Cell: a new token per insert; updating keeps the pointer.
	c1, _ := e.tokenize(e.vault, sa.token, map[string]string{"field": "note", "value": "first"})
	c2, _ := e.tokenize(e.vault, sa.token, map[string]string{"field": "note", "value": "first"})
	if c1.Results[0].Token == c2.Results[0].Token {
		t.Fatal("cell tokens must differ per insert")
	}
	if st := e.call("PUT", "/v1/vaults/"+e.vault+"/tokens/"+c1.Results[0].Token, sa.token, j(map[string]string{"value": "changed"}), nil); st != 200 {
		t.Fatal(st)
	}
	if d, _ := e.detok(e.vault, sa.token, "t", c1.Results[0].Token); d.Results[0].Value != "changed" {
		t.Fatalf("%+v", d)
	}
	det, _ := e.tokenize(e.vault, sa.token, map[string]string{"field": "bvn", "value": "22123456713"})
	if st := e.call("PUT", "/v1/vaults/"+e.vault+"/tokens/"+det.Results[0].Token, sa.token, j(map[string]string{"value": "22123456714"}), nil); st != 400 {
		t.Fatalf("deterministic tokens are bound to their value: %d", st)
	}
	// Transient: gone once the TTL passes (1s in this test vault).
	tr, _ := e.tokenize(e.vault, sa.token, map[string]string{"field": "otp", "value": "123456"})
	if d, _ := e.detok(e.vault, sa.token, "t", tr.Results[0].Token); d.Results[0].Value != "123456" {
		t.Fatalf("%+v", d)
	}
	time.Sleep(1500 * time.Millisecond)
	if d, _ := e.detok(e.vault, sa.token, "t", tr.Results[0].Token); d.Results[0].Error == nil || d.Results[0].Error.Code != "token_not_found" {
		t.Fatalf("%+v", d)
	}
	// Full card numbers never enter the vault.
	r, _ := e.tokenize(e.vault, sa.token, map[string]string{"field": "note", "value": "card 4111 1111 1111 1111"})
	if r.Results[0].Error == nil || r.Results[0].Error.Code != "validation_failed" {
		t.Fatalf("%+v", r)
	}
}

func TestValidationErrorsNeverEchoTheValue(t *testing.T) {
	e, sa := ready(t)
	secret := "2212345"
	req, _ := http.NewRequest("POST", e.srv.URL+"/v1/vaults/"+e.vault+"/tokenize", bytes.NewReader(j(map[string]any{"items": []map[string]string{{"field": "bvn", "value": secret}}})))
	req.Header.Set("Authorization", "Bearer "+sa.token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	buf.ReadFrom(resp.Body)
	if resp.StatusCode != 422 || strings.Contains(buf.String(), secret) {
		t.Fatalf("%d %s", resp.StatusCode, buf.String())
	}
	// A malformed body whose content the decoder might quote.
	req, _ = http.NewRequest("POST", e.srv.URL+"/v1/vaults/"+e.vault+"/tokenize", strings.NewReader(`{"22123456789": true}`))
	req.Header.Set("Authorization", "Bearer "+sa.token)
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	buf.Reset()
	buf.ReadFrom(resp2.Body)
	if strings.Contains(buf.String(), "22123456789") {
		t.Fatalf("error echoed input: %s", buf.String())
	}
}

func TestSpecDetectExample(t *testing.T) {
	e, sa := ready(t)
	e.exec(`INSERT INTO control.vault_fields(id,vault_id,name,data_type,token_kind) VALUES ($1,$2,'amt','amount_ngn','deterministic')`, id("f"), e.vault)
	nextTick()
	var out struct {
		Text     string `json:"text"`
		Entities []struct {
			Type  string  `json:"type"`
			Start int     `json:"start"`
			End   int     `json:"end"`
			Score float64 `json:"score"`
		} `json:"entities"`
	}
	st := e.call("POST", "/v1/detect", sa.token, j(map[string]any{"text": "Transfer of N250,000 to 0123456789 failed. My BVN na 22123456789", "tokenize": true, "vault": e.vault}), &out)
	if st != 200 || len(out.Entities) != 3 {
		t.Fatalf("%d %+v", st, out)
	}
	for _, secret := range []string{"250,000", "0123456789", "22123456789"} {
		if strings.Contains(out.Text, secret) {
			t.Fatalf("%q left in %q", secret, out.Text)
		}
	}
	if !strings.Contains(out.Text, "tok_bvn_") || !strings.Contains(out.Text, "tok_nuban_") || !strings.Contains(out.Text, "tok_amt_") {
		t.Fatal(out.Text)
	}
}

func TestKeyRotation(t *testing.T) {
	e, sa := ready(t)
	toks, _ := e.tokenize(e.vault, sa.token, map[string]string{"field": "bvn", "value": "22123456715", "subject_ref": "rot"})
	tok := toks.Results[0].Token

	rotate := func(body map[string]any) {
		t.Helper()
		body["tenant_id"], body["principal_id"] = e.tenant, "admin"
		var out map[string]any
		if st := e.call("POST", "/internal/keys/rotate", internal, j(body), &out); st != 200 {
			t.Fatalf("%d %+v", st, out)
		}
	}
	rotate(map[string]any{"kind": "kek"})
	real := e.svc.Now
	e.svc.Now = func() time.Time { return real().Add(time.Hour) } // force re-unwrap under the new KEK
	if d, _ := e.detok(e.vault, sa.token, "after kek", tok); d.Results[0].Value != "22123456715" {
		t.Fatalf("%+v", d)
	}
	var oldDEK string
	if err := e.owner.QueryRow(e.ctx, `SELECT id FROM data.data_keys WHERE vault_id=$1 AND status='active'`, e.vault).Scan(&oldDEK); err != nil {
		t.Fatal(err)
	}
	rotate(map[string]any{"kind": "dek", "vault_id": e.vault, "reencrypt": true})
	if d, _ := e.detok(e.vault, sa.token, "after dek", tok); d.Results[0].Value != "22123456715" {
		t.Fatalf("%+v", d)
	}
	var status string
	if err := e.owner.QueryRow(e.ctx, `SELECT status FROM data.data_keys WHERE id=$1`, oldDEK).Scan(&status); err != nil || status != "retired" {
		t.Fatalf("%s %v", status, err)
	}
	var n int
	if err := e.owner.QueryRow(e.ctx, `SELECT count(*) FROM data.records WHERE dek_id=$1`, oldDEK).Scan(&n); err != nil || n != 0 {
		t.Fatalf("%d %v", n, err)
	}
	var res map[string]any
	e.call("POST", "/internal/audit/verify", internal, j(map[string]string{"tenant_id": e.tenant}), &res)
	if res["ok"] != true {
		t.Fatalf("%+v", res)
	}
}

func TestSimulatorExplainsDecision(t *testing.T) {
	e, _ := ready(t)
	var out struct {
		Decision string `json:"decision"`
		Rule     string `json:"rule"`
		Trace    []struct {
			Rule   string `json:"rule"`
			Failed string `json:"failed_slot"`
			Won    bool   `json:"won"`
		} `json:"trace"`
	}
	st := e.call("POST", "/internal/policy/simulate", internal, j(map[string]any{"tenant_id": e.tenant, "action": "detokenize", "principal_id": "x", "roles": []string{"support"}, "field_name": "bvn", "data_type": "bvn", "purpose": "t", "hour": 10}), &out)
	if st != 200 || out.Decision != "masked" || out.Rule != "support-mask" {
		t.Fatalf("%d %+v", st, out)
	}
	if len(out.Trace) < 2 {
		t.Fatalf("%+v", out)
	}
}

func TestConcurrentBatchesDoNotDeadlockAndChainHolds(t *testing.T) {
	e, sa := ready(t)
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			items := make([]map[string]string, 0, 40)
			for i := 0; i < 40; i++ {
				v := i
				if w%2 == 0 {
					v = 39 - i // opposite order, the classic deadlock shape
				}
				items = append(items, map[string]string{"field": "bvn", "value": fmt.Sprintf("2200000%04d", v)})
			}
			var out tokResp
			req, _ := http.NewRequest("POST", e.srv.URL+"/v1/vaults/"+e.vault+"/tokenize", bytes.NewReader(j(map[string]any{"items": items})))
			req.Header.Set("Authorization", "Bearer "+sa.token)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				errs <- err
				return
			}
			defer resp.Body.Close()
			json.NewDecoder(resp.Body).Decode(&out)
			if resp.StatusCode != 200 {
				errs <- fmt.Errorf("status %d: %+v", resp.StatusCode, out.Error)
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Error(err)
		}
	}
	var distinct int
	if err := e.owner.QueryRow(e.ctx, `SELECT count(*) FROM data.tokens WHERE vault_id=$1 AND token LIKE 'tok_bvn_%'`, e.vault).Scan(&distinct); err != nil || distinct != 40 {
		t.Fatalf("concurrent inserts must still yield one token per value: %d %v", distinct, err)
	}
	var res map[string]any
	e.call("POST", "/internal/audit/verify", internal, j(map[string]string{"tenant_id": e.tenant}), &res)
	if res["ok"] != true {
		t.Fatalf("%+v", res)
	}
}

func TestAuditPurgeKeepsChainVerifiable(t *testing.T) {
	e, sa := ready(t)
	toks, _ := e.tokenize(e.vault, sa.token, map[string]string{"field": "bvn", "value": "22123456720"})
	e.detok(e.vault, sa.token, "old", toks.Results[0].Token)
	var seq int64
	var hash string
	if err := e.owner.QueryRow(e.ctx, `SELECT seq,hash FROM events.audit_events WHERE tenant_id=$1 ORDER BY seq DESC LIMIT 1`, e.tenant).Scan(&seq, &hash); err != nil {
		t.Fatal(err)
	}
	if err := pgx.BeginFunc(e.ctx, e.svc.Pool, func(tx pgx.Tx) error {
		return e.svc.SignCheckpoint(e.ctx, tx, e.tenant, "2020-01-01", seq, hash)
	}); err != nil {
		t.Fatal(err)
	}
	e.detok(e.vault, sa.token, "new", toks.Results[0].Token)

	purge := func() int64 {
		var n int64
		if err := e.svc.Pool.QueryRow(e.ctx, `SELECT events.purge_audit($1)`, e.tenant).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if purge() != 0 {
		t.Fatal("events inside retention must stay")
	}
	// Age the signed prefix past retention, as the owner, the way time would.
	e.exec(`ALTER TABLE events.audit_events DISABLE TRIGGER audit_append_only`)
	e.exec(`UPDATE control.tenants SET audit_retention_days=365 WHERE id=$1`, e.tenant)
	e.exec(`UPDATE events.audit_events SET occurred_at=occurred_at-interval '400 days' WHERE tenant_id=$1 AND seq<=$2`, e.tenant, seq)
	e.exec(`ALTER TABLE events.audit_events ENABLE TRIGGER audit_append_only`)
	if purge() == 0 {
		t.Fatal("a signed, expired prefix should purge")
	}
	var res map[string]any
	e.call("POST", "/internal/audit/verify", internal, j(map[string]string{"tenant_id": e.tenant}), &res)
	if res["ok"] != true {
		t.Fatalf("the remaining chain must verify from the anchor: %+v", res)
	}
	// The application role still cannot delete directly.
	if _, err := e.svc.Pool.Exec(e.ctx, `DELETE FROM events.audit_events WHERE tenant_id=$1`, e.tenant); err == nil {
		t.Fatal("direct delete must stay refused")
	}
}
