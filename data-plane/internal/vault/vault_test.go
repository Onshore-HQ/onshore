package vault

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"onshore/data-plane/internal/mask"
)

func TestSealBindsAAD(t *testing.T) {
	key := make([]byte, 32)
	ct, nonce, err := Seal(key, []byte("22123456789"), recordAAD("v", "f", "r1"))
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := Open(key, ct, nonce, recordAAD("v", "f", "r1")); err != nil || string(pt) != "22123456789" {
		t.Fatalf("%v %s", err, pt)
	}
	if _, err := Open(key, ct, nonce, recordAAD("v", "f", "r2")); err == nil {
		t.Fatal("a ciphertext copied to another row must fail to decrypt")
	}
}

func TestNormalize(t *testing.T) {
	cases := []struct {
		typ, in, want string
		ok            bool
	}{
		{"phone_ng", "0803 123 4567", "+2348031234567", true},
		{"phone_ng", "+234 803 123 4567", "+2348031234567", true},
		{"phone_ng", "2348031234567", "+2348031234567", true},
		{"phone_ng", "+234(0)8031234567", "+2348031234567", true},
		{"phone_ng", "12345", "", false},
		{"bvn", "221-2345-6789", "22123456789", true},
		{"bvn", "2212345678", "", false},
		{"nuban", "0123456789", "0123456789", true},
		{"nuban", "01234567890", "", false},
		{"email", " Ada@Example.NG ", "ada@example.ng", true},
		{"person_name", "  Chioma   OKAFOR ", "chioma okafor", true},
		{"amount_ngn", "₦1,250,000", "1250000", true},
		{"free_text", "ordinary note", "ordinary note", true},
		{"free_text", "card 4111 1111 1111 1111 here", "", false},
	}
	for _, c := range cases {
		got, ok := Normalize(c.typ, c.in)
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("%s(%q) = %q,%v want %q,%v", c.typ, c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestTokens(t *testing.T) {
	tok := NewToken("bvn", "opaque")
	if !strings.HasPrefix(tok, "tok_bvn_") || len(strings.TrimPrefix(tok, "tok_bvn_")) != 22 {
		t.Fatal(tok) // 22 base62 characters is 131 bits, the spec's 128-bit minimum
	}
	if fp := NewToken("bvn", "format_preserving"); len(fp) != 11 || !strings.HasPrefix(fp, FPPrefixID) {
		t.Fatal(fp)
	}
	if fp := NewToken("nuban", "format_preserving"); len(fp) != 10 {
		t.Fatal(fp)
	}
}

func TestSpecMasks(t *testing.T) {
	cases := []struct{ typ, in, want string }{
		{"bvn", "22123458901", "*******8901"},
		{"nuban", "0123456789", "******6789"},
		{"phone_ng", "+2348031234567", "+234 *** *** 4567"},
		{"person_name", "chioma okafor", "ch**** o*****"},
		{"email", "chioma@example.com", "ch****@example.com"},
		{"amount_ngn", "250000", "₦**,***"},
	}
	for _, c := range cases {
		if got := mask.Value(c.typ, "default", c.in); got != c.want {
			t.Errorf("%s: %q want %q", c.typ, got, c.want)
		}
	}
}

func TestGeoTable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "geo.csv")
	if err := os.WriteFile(path, []byte("102.89.0.0,102.89.255.255,NG\n8.8.8.0,8.8.8.255,US\nbad,row,XX\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	g, err := LoadGeoCSV(path)
	if err != nil {
		t.Fatal(err)
	}
	for ip, want := range map[string]string{"102.89.1.1": "NG", "8.8.8.8": "US", "1.1.1.1": "", "junk": ""} {
		if got := g.Country(ip); got != want {
			t.Errorf("%s = %q, want %q", ip, got, want)
		}
	}
}
