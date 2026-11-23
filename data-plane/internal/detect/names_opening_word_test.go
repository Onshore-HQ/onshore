package detect

import "testing"

// A capitalised verb or noun opening a sentence is never part of the name after it.
func TestOpeningWordIsNotPartOfTheName(t *testing.T) {
	rs := GlobalRuleSet(New(Config{}))
	for _, s := range []string{
		"Refund Sarah Johnson, card 4111 1111 1111 1111",
		"Email Sarah Johnson about it",
		"Call Sarah Johnson tomorrow",
		"Patient Sarah Johnson was seen at 10:00",
	} {
		var got []string
		for _, e := range rs.ScanFor("ai", "", s, "") {
			if e.Type == PersonName {
				got = append(got, s[e.Start:e.End])
			}
		}
		if len(got) != 1 || got[0] != "Sarah Johnson" {
			t.Errorf("%q: names %q, want just \"Sarah Johnson\"", s, got)
		}
	}
}
