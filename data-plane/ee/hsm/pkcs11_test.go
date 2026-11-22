//go:build hsm

package hsm

import (
	"bytes"
	"context"
	"testing"
)

// Runs against SoftHSM2 in scripts/test-hsm.sh; a real HSM is configured the same way.
func TestPKCS11RoundTripRotateAndAAD(t *testing.T) {
	svc, err := NewPKCS11FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	secret := []byte("0123456789abcdef0123456789abcdef")
	w, ref, err := svc.Wrap(ctx, secret, []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(w, secret) {
		t.Fatal("wrapped form holds the key")
	}
	if pt, err := svc.Unwrap(ctx, w, []byte("aad")); err != nil || !bytes.Equal(pt, secret) {
		t.Fatalf("%v %q", err, pt)
	}
	if _, err := svc.Unwrap(ctx, w, []byte("other")); err == nil {
		t.Fatal("wrong AAD must fail")
	}
	if err := svc.RotateKEK(ctx); err != nil {
		t.Fatal(err)
	}
	if pt, err := svc.Unwrap(ctx, w, []byte("aad")); err != nil || !bytes.Equal(pt, secret) {
		t.Fatalf("an old version must still open: %v", err)
	}
	w2, ref2, err := svc.Rewrap(ctx, w, []byte("aad"))
	if err != nil || ref2 == ref {
		t.Fatalf("%v %s %s", err, ref, ref2)
	}
	if pt, err := svc.Unwrap(ctx, w2, []byte("aad")); err != nil || !bytes.Equal(pt, secret) {
		t.Fatal(err)
	}
	// The KEK must not be exportable.
	h := svc.(*PKCS11)
	k, err := h.find(1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.ctx.GetAttributeValue(h.session, k, valueAttr()); err == nil {
		t.Fatal("the HSM returned key material")
	}
}
