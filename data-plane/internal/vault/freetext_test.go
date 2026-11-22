package vault

import (
	"strings"
	"testing"
)

func TestStripLongNumbers(t *testing.T) {
	for in, want := range map[string]string{
		"support ticket 22555566671":   "support ticket [number removed]",
		"order 2255-556-6671 for ada":  "order [number removed] for ada",
		"ref 4111 1111 1111 1111":      "ref [number removed]",
		"ticket 123456789 is short":    "ticket 123456789 is short",
		"KYC review, case 4412":        "KYC review, case 4412",
		"[bvn removed] and 0123456789": "[bvn removed] and [number removed]",
	} {
		if got := stripLongNumbers(in); got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
}

func TestSealedSubject(t *testing.T) {
	sealed, err := sealSubject("rvct_a", "cust_1")
	if err != nil || sealed == "" || strings.Contains(sealed, "cust_1") {
		t.Fatalf("sealed %q, %v", sealed, err)
	}
	if got, err := openSubject("rvct_a", sealed); err != nil || got != "cust_1" {
		t.Fatalf("opened %q, %v", got, err)
	}
	if _, err := openSubject("rvct_b", sealed); err == nil {
		t.Fatal("another token opened the subject")
	}
	if s, _ := sealSubject("rvct_a", ""); s != "" {
		t.Fatal("no subject should stay empty, so that collect without one works")
	}
}
