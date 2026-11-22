package detect

import "testing"

func TestNameSpanSkipsPronouns(t *testing.T) {
	rs := BaseRuleSet(New(Config{})).WithPacks("NG", []string{"everywhere", "ng"})
	for in, want := range map[string]string{
		"Hi, I'm Sarah Johnson, my card": "Sarah Johnson",
		"I've spoken to Chinedu Okafor": "Chinedu Okafor",
		"Hi I'm Sarah Johnson":           "Sarah Johnson",
	} {
		var got []string
		for _, e := range rs.ScanFor("ai", "", in, "") {
			if e.Type == PersonName {
				got = append(got, in[e.Start:e.End])
			}
		}
		if len(got) != 1 || got[0] != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
}
