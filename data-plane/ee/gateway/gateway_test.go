package gateway

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"onshore/data-plane/ee/logproc"
	"onshore/data-plane/internal/detect"
	"onshore/data-plane/internal/netguard"
)

func TestValidPath(t *testing.T) {
	for _, p := range []string{"$", "$.a", "$.a.b_c", "$.items[*].id", "$.a[*].b[*]"} {
		if !ValidPath(p) {
			t.Errorf("%s should be valid", p)
		}
	}
	for _, p := range []string{"", "a.b", "$.", "$..a", "$.a b", "$.a[0]", "$.a['x']", "$.a;drop"} {
		if ValidPath(p) {
			t.Errorf("%s should be invalid", p)
		}
	}
}

func fakeTok(_ context.Context, _ *ProxyRoute, items []logproc.Item) ([]string, error) {
	out := make([]string, len(items))
	for i := range items {
		out[i] = "tok_x_AAAAAAAAAAAA"
	}
	return out, nil
}

func transformer() *Transformer {
	return &Transformer{Engine: detect.New(detect.Config{}), Tokenize: fakeTok}
}

func TestRedactPaths(t *testing.T) {
	r := &ProxyRoute{Mode: "process_and_store", Redact: []PathRule{{Path: "$.customer.secret"}, {Path: "$.items[*].ref"}}}
	out, _, err := transformer().Request(context.Background(), r, []byte(`{"customer":{"secret":"abc","keep":"yes"},"items":[{"ref":"r1"},{"ref":"r2"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, leak := range []string{"abc", "r1", "r2"} {
		if strings.Contains(s, `"`+leak+`"`) {
			t.Fatalf("%s leaked: %s", leak, s)
		}
	}
	if !strings.Contains(s, `"keep":"yes"`) {
		t.Fatal(s)
	}
}

func TestDLPCatchesWhatNoRuleNamed(t *testing.T) {
	r := &ProxyRoute{Mode: "process_and_store", DLP: true, DLPExcludedPaths: []string{"$.safe"}}
	out, _, err := transformer().Request(context.Background(), r, []byte(`{"note":"bvn 22123456789","safe":"bvn 22123456780"}`))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "22123456789") {
		t.Fatal(string(out))
	}
	if !strings.Contains(string(out), "22123456780") {
		t.Fatal("excluded paths stay as they are: " + string(out))
	}
}

func TestProcessOnlyNeverCallsTheVault(t *testing.T) {
	called := false
	tr := transformer()
	tr.Tokenize = func(context.Context, *ProxyRoute, []logproc.Item) ([]string, error) {
		called = true
		return nil, nil
	}
	r := &ProxyRoute{Mode: "process_only", DLP: true, Redact: []PathRule{{Path: "$.x"}}}
	out, _, err := tr.Request(context.Background(), r, []byte(`{"x":"secret","note":"bvn 22123456789"}`))
	if err != nil || called {
		t.Fatalf("err=%v called=%v", err, called)
	}
	if strings.Contains(string(out), "secret") || strings.Contains(string(out), "22123456789") {
		t.Fatal(string(out))
	}
}

func TestNonJSONFailsClosed(t *testing.T) {
	r := &ProxyRoute{Mode: "process_and_store", Redact: []PathRule{{Path: "$.x"}}}
	if _, _, err := transformer().Request(context.Background(), r, []byte("x=secret")); !errors.Is(err, ErrNotJSON) {
		t.Fatalf("err=%v", err)
	}
}

func TestVaultFailureFailsClosed(t *testing.T) {
	tr := transformer()
	tr.Tokenize = func(context.Context, *ProxyRoute, []logproc.Item) ([]string, error) { return nil, ErrVaultDown }
	r := &ProxyRoute{Mode: "process_and_store", Redact: []PathRule{{Path: "$.x"}}}
	if out, _, err := tr.Request(context.Background(), r, []byte(`{"x":"secret"}`)); err == nil || out != nil {
		t.Fatalf("must not produce a body: %s %v", out, err)
	}
}

func TestPathMatch(t *testing.T) {
	cases := []struct {
		pattern, path string
		want          bool
	}{{"/v1/kyc", "/v1/kyc", true}, {"/v1/*", "/v1/kyc", true}, {"/v1/*", "/v1/kyc/x", false}, {"/v1/**", "/v1/kyc/x", true}, {"/v1/**", "/v2/kyc", false}, {"/**", "/any/thing", true}}
	for _, c := range cases {
		if got := pathMatches(c.pattern, c.path); got != c.want {
			t.Errorf("%s %s = %v", c.pattern, c.path, got)
		}
	}
}

func TestHoldFrom(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{{"hello", 5}, {"see [", 4}, {"see [BVN", 4}, {"see [BVN_1", 4}, {"see [BVN_1]", 11}, {"a [link](x)", 11}, {"[lower", 6}}
	for _, c := range cases {
		if got := holdFrom(c.in); got != c.want {
			t.Errorf("%q = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestPlaceholderInPromptCannotRestoreAnyone(t *testing.T) {
	s := newSession([]byte(`{"a":"[BVN_7] bvn 22123456789"}`), nil)
	if p := s.placeholder(detect.BVN, "22123456789"); p != "[BVN_8]" {
		t.Fatalf("numbering must start above existing text: %s", p)
	}
	rs := &restorer{s: s, rt: &AIRoute{}}
	if got := rs.replace("[BVN_7]"); got != "[BVN_7]" {
		t.Fatalf("got %s", got)
	}
	if got := rs.replace("[BVN_8]"); got != "*******6789" {
		t.Fatalf("masked by default, got %s", got)
	}
}

func aiServer(t *testing.T, upstream http.HandlerFunc, mode string, models ...string) (*httptest.Server, func(string, string) (*http.Response, string)) {
	t.Helper()
	up := httptest.NewServer(upstream)
	t.Cleanup(up.Close)
	a := &AI{Engine: detect.New(detect.Config{}), AllowHTTP: true, Upstream: netguard.Client(5*time.Second, true), routes: map[string]*AIRoute{"r": {ID: "r", VaultID: "v", Name: "r", Upstream: up.URL, Provider: "x", Mode: mode, KeyHash: hashKey("k"), AllowedModels: models}}}
	srv := httptest.NewServer(a.Handler())
	t.Cleanup(srv.Close)
	return srv, func(endpoint, body string) (*http.Response, string) {
		req, _ := http.NewRequest("POST", srv.URL+"/r/v1/"+endpoint, strings.NewReader(body))
		req.Header.Set("X-RV-Route-Key", "k")
		req.Header.Set("Authorization", "Bearer provider-key")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, string(b)
	}
}

func TestAIProviderNeverSeesIdentifiersAndReplyIsMasked(t *testing.T) {
	var got, auth string
	_, post := aiServer(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got, auth = string(b), r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"Your BVN [BVN_1] and account [ACCOUNT_1] are noted. [BVN_99] stays."}}]}`))
	}, "enforcing", "gpt")
	resp, body := post("chat/completions", `{"model":"gpt","messages":[{"role":"user","content":"My BVN is 22123456789 and acct 0123456789"}]}`)
	if resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode, body)
	}
	if strings.Contains(got, "22123456789") || strings.Contains(got, "0123456789") {
		t.Fatalf("provider saw identifiers: %s", got)
	}
	if !strings.Contains(got, "[BVN_1]") || !strings.Contains(got, `"model":"gpt"`) || auth != "Bearer provider-key" {
		t.Fatalf("%s %s", got, auth)
	}
	if strings.Contains(body, "22123456789") || !strings.Contains(body, "*******6789") || !strings.Contains(body, "[BVN_99]") {
		t.Fatalf("no caller token means masked, and unknown placeholders stay: %s", body)
	}
}

func TestAIModelAllowlistAndUnknownEndpoint(t *testing.T) {
	calls := 0
	_, post := aiServer(t, func(http.ResponseWriter, *http.Request) { calls++ }, "enforcing", "allowed")
	if r, _ := post("chat/completions", `{"model":"other","messages":[]}`); r.StatusCode != 403 {
		t.Fatal(r.StatusCode)
	}
	if r, _ := post("files", `{"model":"allowed"}`); r.StatusCode != 404 {
		t.Fatal(r.StatusCode)
	}
	if calls != 0 {
		t.Fatal("nothing should have reached the provider")
	}
}

func TestAIRefusesImagesWhenEnforcing(t *testing.T) {
	calls := 0
	_, post := aiServer(t, func(http.ResponseWriter, *http.Request) { calls++ }, "enforcing", "m")
	r, _ := post("chat/completions", `{"model":"m","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:image/png;base64,AAAA"}}]}]}`)
	if r.StatusCode != 422 || calls != 0 {
		t.Fatalf("%d calls=%d", r.StatusCode, calls)
	}
}

func TestAIShadowForwardsUnchanged(t *testing.T) {
	var got string
	_, post := aiServer(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = string(b)
		w.Write([]byte(`{}`))
	}, "shadow", "m")
	body := `{"model":"m","messages":[{"role":"user","content":"BVN 22123456789"}]}`
	post("chat/completions", body)
	if got != body {
		t.Fatal(got)
	}
}

// A placeholder split across chunks must still be restored, and never leak its
// fragments to the user.
func TestAIStreamingRestoresSplitPlaceholders(t *testing.T) {
	_, post := aiServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		for _, c := range []string{"Your BVN is [", "BV", "N_", "1", "] ok. Array[0] too"} {
			io.WriteString(w, `data: {"choices":[{"index":0,"delta":{"content":"`+c+`"},"finish_reason":null}]}`+"\n\n")
			w.(http.Flusher).Flush()
		}
		io.WriteString(w, `data: {"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`+"\n\ndata: [DONE]\n\n")
	}, "enforcing", "m")
	_, body := post("chat/completions", `{"model":"m","stream":true,"messages":[{"role":"user","content":"BVN 22123456789"}]}`)
	var text strings.Builder
	for _, line := range strings.Split(body, "\n") {
		if d, ok := strings.CutPrefix(line, "data: "); ok && strings.Contains(d, `"content"`) {
			i := strings.Index(d, `"content":"`) + len(`"content":"`)
			text.WriteString(d[i : i+strings.Index(d[i:], `"`)])
		}
	}
	if got := text.String(); got != "Your BVN is *******6789 ok. Array[0] too" {
		t.Fatalf("got %q from\n%s", got, body)
	}
	if strings.Contains(body, "[BV") {
		t.Fatalf("placeholder fragment reached the client: %s", body)
	}
}

func TestAIAnthropicStream(t *testing.T) {
	_, post := aiServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		for _, c := range []string{"Ref [BV", "N_1] done"} {
			io.WriteString(w, "event: content_block_delta\n"+`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"`+c+`"}}`+"\n\n")
		}
	}, "enforcing", "claude")
	_, body := post("messages", `{"model":"claude","messages":[{"role":"user","content":"BVN 22123456789"}]}`)
	if !strings.Contains(body, "*******6789") || strings.Contains(body, "BVN_1") {
		t.Fatal(body)
	}
}

func TestAIDoesNotScanModelOrRole(t *testing.T) {
	var got string
	_, post := aiServer(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = string(b)
		w.Write([]byte(`{}`))
	}, "enforcing", "gpt-22123456789")
	post("chat/completions", `{"model":"gpt-22123456789","messages":[{"role":"user","content":"hi"}]}`)
	if !strings.Contains(got, `"model":"gpt-22123456789"`) {
		t.Fatal(got)
	}
}
