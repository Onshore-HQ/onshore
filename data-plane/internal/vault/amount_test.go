package vault

import "testing"

func TestParseAmount(t *testing.T) {
	for in, want := range map[string]float64{
		"1250": 1250, "1250.5": 1250.5, "£1,250.50": 1250.5, "1.250,50 €": 1250.5, "1 250,50": 1250.5,
		"₦850,000": 850000, "$8,500": 8500, "R$ 1.250,50": 1250.5, "12,5": 12.5, "1.250": 1250, "AED 1,250.50": 1250.5,
	} {
		got, err := ParseAmount(in)
		if err != nil || got != want {
			t.Errorf("%q: got %v, %v; want %v", in, got, err, want)
		}
	}
	if _, err := ParseAmount("no digits"); err == nil {
		t.Error("text with no number should fail")
	}
}
