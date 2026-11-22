package license

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

func TestSignVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	blob, err := Sign(Licence{Customer: "Acme", Modules: []string{"logs"}, ExpiresAt: time.Now().Add(time.Hour)}, priv)
	if err != nil {
		t.Fatal(err)
	}
	l, err := Verify(blob, pub)
	if err != nil || l.Customer != "Acme" || l.Expired(time.Now()) {
		t.Fatalf("%v %+v", err, l)
	}
	if !l.Expired(time.Now().Add(2 * time.Hour)) {
		t.Fatal("should be expired")
	}
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := Verify(blob, otherPub); err == nil {
		t.Fatal("wrong key must fail")
	}
	p := strings.Split(blob, ".")
	if _, err := Verify(p[0]+"x."+p[1], pub); err == nil {
		t.Fatal("tampered payload must fail")
	}
}
