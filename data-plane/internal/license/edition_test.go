package license

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"
)

func TestResolveEditions(t *testing.T) {
	now := time.Now()
	saved := PublicKeyB64
	defer func() { PublicKeyB64 = saved }()

	PublicKeyB64 = ""
	if s := resolve("", "", now); s.Edition != Development || !s.Has(Enterprise) {
		t.Fatalf("unkeyed build should be development: %+v", s)
	}
	if s := resolve("", "free", now); s.Edition != Free || s.Has(Business) {
		t.Fatalf("override should lower a development build: %+v", s)
	}

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	PublicKeyB64 = base64.StdEncoding.EncodeToString(pub)
	sign := func(mods []string, exp time.Time) string {
		b, _ := Sign(Licence{Customer: "Acme", Modules: mods, ExpiresAt: exp}, priv)
		return b
	}
	if s := resolve("", "", now); s.Edition != Free {
		t.Fatalf("no licence should be free: %+v", s)
	}
	if s := resolve("garbage.sig", "", now); s.Edition != Free || s.Note == "" {
		t.Fatalf("bad licence should be free with a note: %+v", s)
	}
	if s := resolve(sign([]string{"business"}, now.Add(time.Hour)), "", now); s.Edition != Business || !s.Has(Business) || s.Has(Enterprise) {
		t.Fatalf("business licence: %+v", s)
	}
	if s := resolve(sign([]string{"logs", "enterprise"}, now.Add(time.Hour)), "", now); s.Edition != Enterprise || !s.Has(Business) {
		t.Fatalf("enterprise implies business: %+v", s)
	}
	if s := resolve(sign([]string{"enterprise"}, now.Add(-time.Hour)), "", now); s.Edition != Enterprise || !s.Expired {
		t.Fatalf("expired keeps its edition: %+v", s)
	}
	if s := resolve(sign([]string{"business"}, now.Add(time.Hour)), "enterprise", now); s.Edition != Business {
		t.Fatalf("override must never raise: %+v", s)
	}
	if s := resolve(sign([]string{"development"}, now.Add(time.Hour)), "", now); s.Edition != Free {
		t.Fatalf("a licence cannot claim development: %+v", s)
	}
	if !IsTestVault("v_test_1") || IsTestVault("v_live_1") {
		t.Fatal("test vault prefix")
	}
}
