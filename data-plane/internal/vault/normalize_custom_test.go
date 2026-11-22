package vault

import (
	"regexp"
	"strings"
	"testing"
)

func TestCustomTokens(t *testing.T) {
	if tok := NewToken("c_loan_id", "opaque"); !regexp.MustCompile(`^tok_c_loan_id_[0-9A-Za-z]{22}$`).MatchString(tok) {
		t.Fatal(tok)
	}
	shape := regexp.MustCompile(`^LN-\d{8}$`)
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		tok := NewTokenFor("c_loan_id", "format_preserving", "LN-00412873")
		if !shape.MatchString(tok) {
			t.Fatalf("shape lost: %s", tok)
		}
		seen[tok] = true
	}
	if len(seen) < 190 {
		t.Fatalf("too little variety: %d", len(seen))
	}
	// Too few characters to vary safely: an opaque token, never a guessable one.
	if tok := NewTokenFor("c_short", "format_preserving", "AB-12"); !strings.HasPrefix(tok, "tok_c_short_") {
		t.Fatal(tok)
	}
	if tok := NewTokenFor("bvn", "opaque", "x"); !strings.HasPrefix(tok, "tok_bvn_") {
		t.Fatal(tok)
	}
}
