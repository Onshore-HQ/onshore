package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

const parentOrigin = "https://app.example.ng"

func (e *env) setOrigins(origins ...string) {
	list := "{" + strings.Join(origins, ",") + "}"
	e.exec(`UPDATE control.vaults SET embed_origins=$1 WHERE id=$2`, list, e.vault)
	nextTick()
}

func (e *env) mint(token string, body map[string]any) (string, int, string) {
	t := e.t
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", e.srv.URL+"/v1/vaults/"+e.vault+"/client-tokens", bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	var out struct {
		ClientToken string `json:"client_token"`
	}
	json.Unmarshal(raw, &out)
	return out.ClientToken, res.StatusCode, string(raw)
}

func (e *env) embed(path string, body map[string]any, headers map[string]string) (int, string) {
	e.t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", e.srv.URL+path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(raw)
}

func collectBody(tok, value string) map[string]any {
	return map[string]any{"client_token": tok, "parent_origin": parentOrigin, "values": map[string]string{"bvn": value}}
}

func TestClientTokenMinting(t *testing.T) {
	e, sa := ready(t)
	collect := map[string]any{"kind": "collect", "origin": parentOrigin, "fields": []string{"bvn"}}
	if _, st, _ := e.mint(sa.token, collect); st != 403 {
		t.Fatalf("no origins configured means off: %d", st)
	}
	e.setOrigins(parentOrigin)
	if _, st, _ := e.mint(sa.token, map[string]any{"kind": "collect", "origin": "https://evil.example", "fields": []string{"bvn"}}); st != 403 {
		t.Fatalf("an unlisted origin: %d", st)
	}
	tok, st, body := e.mint(sa.token, collect)
	if st != 200 || !strings.HasPrefix(tok, "rvct_") {
		t.Fatalf("%d %s", st, body)
	}
	var stored int
	if err := e.owner.QueryRow(e.ctx, `SELECT count(*) FROM data.client_tokens WHERE hash=$1`, tok).Scan(&stored); err != nil || stored != 0 {
		t.Fatalf("the raw token must not be stored: %d %v", stored, err)
	}
	for name, bad := range map[string]map[string]any{
		"unknown field":      {"kind": "collect", "origin": parentOrigin, "fields": []string{"nope"}},
		"no fields":          {"kind": "collect", "origin": parentOrigin},
		"tokens on collect":  {"kind": "collect", "origin": parentOrigin, "fields": []string{"bvn"}, "tokens": []string{"t"}},
		"reveal, no purpose": {"kind": "reveal", "origin": parentOrigin, "tokens": []string{"t"}},
		"reveal, no tokens":  {"kind": "reveal", "origin": parentOrigin, "purpose": "p"},
		"unknown kind":       {"kind": "other", "origin": parentOrigin},
		"too long":           {"kind": "collect", "origin": parentOrigin, "fields": []string{"bvn"}, "ttl_seconds": 601},
	} {
		if _, st, _ := e.mint(sa.token, bad); st != 400 {
			t.Errorf("%s: %d", name, st)
		}
	}
	nobody := e.login(e.serviceAccount(e.tenant, nil, "marketing"))
	if _, st, _ := e.mint(nobody.token, collect); st != 403 {
		t.Fatalf("a principal who cannot tokenize cannot mint: %d", st)
	}
	other := e.user(e.tenant, "marketing")
	if _, st, _ := e.mint(other.token, collect); st != 403 {
		t.Fatalf("user without the action: %d", st)
	}
}

func TestCollectIsSingleUseAndKeepsATypo(t *testing.T) {
	e, sa := ready(t)
	e.setOrigins(parentOrigin)
	tok, _, _ := e.mint(sa.token, map[string]any{"kind": "collect", "origin": parentOrigin, "fields": []string{"bvn"}, "subject_ref": "cust_embed"})

	if st, _ := e.embed("/embed/v1/describe", map[string]any{"client_token": tok, "parent_origin": "https://evil.example"}, nil); st != 401 {
		t.Fatalf("another page holding the token: %d", st)
	}
	st, body := e.embed("/embed/v1/collect", collectBody(tok, "not-a-bvn"), nil)
	if st != 422 || strings.Contains(body, "not-a-bvn") {
		t.Fatalf("a typo: %d %s", st, body)
	}
	st, body = e.embed("/embed/v1/collect", collectBody(tok, "22123456722"), nil)
	if st != 200 || !strings.Contains(body, "tok_bvn_") || strings.Contains(body, "22123456722") {
		t.Fatalf("after correcting it: %d %s", st, body)
	}
	if st, _ := e.embed("/embed/v1/collect", collectBody(tok, "22123456722"), nil); st != 401 {
		t.Fatalf("a second use: %d", st)
	}
	var module string
	if err := e.owner.QueryRow(e.ctx, `SELECT module FROM events.audit_events WHERE tenant_id=$1 AND action='tokenize' ORDER BY seq DESC LIMIT 1`, e.tenant).Scan(&module); err != nil || module != "embed" {
		t.Fatalf("the audit log must show the component: %q %v", module, err)
	}
	// Racing redemptions: exactly one wins.
	race, _, _ := e.mint(sa.token, map[string]any{"kind": "collect", "origin": parentOrigin, "fields": []string{"bvn"}})
	wins := make(chan int, 8)
	for i := 0; i < 8; i++ {
		go func(i int) {
			st, _ := e.embed("/embed/v1/collect", collectBody(race, fmt.Sprintf("2212345673%d", i)), nil)
			wins <- st
		}(i)
	}
	won := 0
	for i := 0; i < 8; i++ {
		if <-wins == 200 {
			won++
		}
	}
	if won != 1 {
		t.Fatalf("%d redemptions won", won)
	}
}

func TestClientTokenScopeAndExpiry(t *testing.T) {
	e, sa := ready(t)
	e.setOrigins(parentOrigin)
	collect := map[string]any{"kind": "collect", "origin": parentOrigin, "fields": []string{"bvn"}}
	tok, _, _ := e.mint(sa.token, collect)
	if st, _ := e.embed("/embed/v1/collect", map[string]any{"client_token": tok, "parent_origin": parentOrigin, "values": map[string]string{"bvn": "22123456723", "email": "a@b.ng"}}, nil); st != 400 {
		t.Fatalf("a field outside the token: %d", st)
	}
	if st, _ := e.embed("/embed/v1/reveal", map[string]any{"client_token": tok, "parent_origin": parentOrigin}, nil); st != 401 {
		t.Fatalf("a collect token used to reveal: %d", st)
	}
	// Browser-set headers refuse any page but the frame.
	if st, _ := e.embed("/embed/v1/collect", collectBody(tok, "22123456723"), map[string]string{"Sec-Fetch-Site": "cross-site"}); st != 403 {
		t.Fatalf("cross-site: %d", st)
	}
	if st, _ := e.embed("/embed/v1/collect", collectBody(tok, "22123456723"), map[string]string{"Origin": "https://evil.example"}); st != 403 {
		t.Fatalf("a foreign Origin: %d", st)
	}
	e.exec(`UPDATE data.client_tokens SET expires_at=now()-interval '1 second' WHERE used_at IS NULL AND vault_id=$1`, e.vault)
	if st, _ := e.embed("/embed/v1/collect", collectBody(tok, "22123456723"), nil); st != 401 {
		t.Fatalf("expired: %d", st)
	}
	// bind_ip holds a stolen token to the browser it was meant for.
	bound, _, _ := e.mint(sa.token, map[string]any{"kind": "collect", "origin": parentOrigin, "fields": []string{"bvn"}, "bind_ip": "203.0.113.9"})
	if st, _ := e.embed("/embed/v1/collect", collectBody(bound, "22123456723"), nil); st != 401 {
		t.Fatalf("from another address: %d", st)
	}
	// Removing a site stops tokens already issued.
	live, _, _ := e.mint(sa.token, collect)
	e.setOrigins("https://other.example.ng")
	time.Sleep(10 * time.Millisecond)
	if st, _ := e.embed("/embed/v1/describe", map[string]any{"client_token": live, "parent_origin": parentOrigin}, nil); st != 401 {
		t.Fatalf("after removing the site: %d", st)
	}
}

func TestRevealFollowsPolicyAtRedemption(t *testing.T) {
	e, sa := ready(t)
	e.setOrigins(parentOrigin)
	toks, _ := e.tokenize(e.vault, sa.token, map[string]string{"field": "bvn", "value": "22123456724"})
	token := toks.Results[0].Token
	mint := map[string]any{"kind": "reveal", "origin": parentOrigin, "tokens": []string{token}, "purpose": "support ticket 7", "on_behalf_of": "agent ada"}
	tok, st, body := e.mint(sa.token, mint)
	if st != 200 {
		t.Fatalf("%d %s", st, body)
	}
	st, body = e.embed("/embed/v1/reveal", map[string]any{"client_token": tok, "parent_origin": parentOrigin}, nil)
	if st != 200 || !strings.Contains(body, `"decision"`) {
		t.Fatalf("%d %s", st, body)
	}
	if st, _ := e.embed("/embed/v1/reveal", map[string]any{"client_token": tok, "parent_origin": parentOrigin}, nil); st != 401 {
		t.Fatalf("a second reveal: %d", st)
	}
	var purpose, module string
	if err := e.owner.QueryRow(e.ctx, `SELECT purpose,module FROM events.audit_events WHERE tenant_id=$1 AND action='detokenize' ORDER BY seq DESC LIMIT 1`, e.tenant).Scan(&purpose, &module); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(purpose, "agent ada") || module != "embed" {
		t.Fatalf("%q %q", purpose, module)
	}
	// A principal without the action gets a refusal, even with a valid token.
	nobody := e.login(e.serviceAccount(e.tenant, nil, "marketing"))
	denied, st, body := e.mint(nobody.token, mint)
	if st != 200 {
		t.Fatalf("%d %s", st, body)
	}
	_, body = e.embed("/embed/v1/reveal", map[string]any{"client_token": denied, "parent_origin": parentOrigin}, nil)
	if strings.Contains(body, "22123456724") {
		t.Fatalf("denied, yet the value came back: %s", body)
	}
	// Suspending the minter stops what they issued.
	later, _, _ := e.mint(sa.token, mint)
	e.exec(`UPDATE control.service_account_keys SET revoked_at=now() WHERE principal_id=(SELECT principal_id FROM data.client_tokens ORDER BY created_at DESC LIMIT 1)`)
	if st, _ := e.embed("/embed/v1/reveal", map[string]any{"client_token": later, "parent_origin": parentOrigin}, nil); st != 401 {
		t.Fatalf("after revoking the key: %d", st)
	}
}

func TestFrameHeaders(t *testing.T) {
	e, _ := ready(t)
	get := func() *http.Response {
		res, err := http.Get(e.srv.URL + "/embed/frame/" + e.vault)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res
	}
	if res := get(); res.StatusCode != 404 || !strings.Contains(res.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Fatalf("off by default: %d %s", res.StatusCode, res.Header.Get("Content-Security-Policy"))
	}
	e.setOrigins(parentOrigin)
	res := get()
	csp := res.Header.Get("Content-Security-Policy")
	if res.StatusCode != 200 || !strings.Contains(csp, "frame-ancestors "+parentOrigin) || !strings.Contains(csp, "script-src 'self'") || strings.Contains(csp, "unsafe") {
		t.Fatalf("%d %s", res.StatusCode, csp)
	}
	if res.Header.Get("Referrer-Policy") != "no-referrer" {
		t.Fatal("referrer policy")
	}
}
