package gateway

import (
	"context"
	"errors"
	"strings"
	"testing"

	"onshore/data-plane/ee/logproc"
	"onshore/data-plane/internal/detect"
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
