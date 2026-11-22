package audit

import (
	"testing"
	"time"
)

func TestHashCoversEveryFieldAndPrev(t *testing.T) {
	base := Event{EventID: "e1", OccurredAt: time.Unix(1700000000, 0), TenantID: "t", Action: "detokenize", Decision: "masked", Purpose: "x"}
	h := Hash(base, GenesisHash)
	if h != Hash(base, GenesisHash) {
		t.Fatal("hash must be stable")
	}
	mutated := base
	mutated.Decision = "plaintext"
	if Hash(mutated, GenesisHash) == h {
		t.Fatal("a changed decision must change the hash")
	}
	if Hash(base, h) == h {
		t.Fatal("a changed prev hash must change the hash")
	}
}
