package detect

import "testing"

func TestCountryPackValidators(t *testing.T) {
	cases := []struct {
		name  string
		v     Validator
		value string
		want  bool
	}{
		{"IBAN, UK", Validator{Type: "mod97", Value: 4}, "GB82 WEST 1234 5698 7654 32", true},
		{"IBAN, Germany", Validator{Type: "mod97", Value: 4}, "DE89 3704 0044 0532 0130 00", true},
		{"IBAN, one digit changed", Validator{Type: "mod97", Value: 4}, "GB82 WEST 1234 5698 7654 33", false},
		{"Singapore NRIC", Validator{Type: "letter_check", Values: []string{"JZIHGFEDCBA"}, Weights: []int{2, 7, 6, 5, 4, 3, 2}}, "S1234567D", true},
		{"Singapore NRIC, wrong letter", Validator{Type: "letter_check", Values: []string{"JZIHGFEDCBA"}, Weights: []int{2, 7, 6, 5, 4, 3, 2}}, "S1234567A", false},
		{"Spain DNI", Validator{Type: "letter_check", Values: []string{"TRWAGMYFPDXBNJZSQVHLCKE"}, Weights: []int{14, 6, 19, 18, 11, 8, 10, 1}}, "12345678-Z", true},
		{"Spain DNI, wrong letter", Validator{Type: "letter_check", Values: []string{"TRWAGMYFPDXBNJZSQVHLCKE"}, Weights: []int{14, 6, 19, 18, 11, 8, 10, 1}}, "12345678A", false},
		{"mod 11 with weights", Validator{Type: "mod11_weighted", Weights: []int{10, 9, 8, 7, 6, 5, 4, 3, 2}}, "0-306-40615-2", true},
		{"mod 11, X stands for 10", Validator{Type: "mod11_weighted", Weights: []int{10, 9, 8, 7, 6, 5, 4, 3, 2}}, "0-8044-2957-X", true},
		{"mod 11, wrong check", Validator{Type: "mod11_weighted", Weights: []int{10, 9, 8, 7, 6, 5, 4, 3, 2}}, "0-306-40615-3", false},
		{"mod 11, remainder form", Validator{Type: "mod11_weighted", Value: 1, Weights: []int{1, 2, 3, 4, 5, 6, 7, 8, 9}}, "0-306-40615-2", true},
		{"birth date inside an ID", Validator{Type: "date_embedded", Values: []string{"YYMMDD"}, Value: 1}, "8001015009087", true},
		{"no 13th month", Validator{Type: "date_embedded", Values: []string{"YYMMDD"}, Value: 1}, "8013015009087", false},
		{"29 February 2000", Validator{Type: "date_embedded", Values: []string{"YYMMDD"}, Value: 1}, "0002295009087", true},
		{"no 29 February 2001", Validator{Type: "date_embedded", Values: []string{"YYMMDD"}, Value: 1}, "0102295009087", false},
		{"date after letters, counted in digits", Validator{Type: "date_embedded", Values: []string{"DDMMYYYY"}, Value: 1}, "AB31122000-77", true},
		{"date from the third digit", Validator{Type: "date_embedded", Values: []string{"DDMMYY"}, Value: 3}, "77311299", true},
	}
	for _, c := range cases {
		if err := checkValidator(&c.v); err != nil {
			t.Fatalf("%s: validator refused: %v", c.name, err)
		}
		if got := RunValidator(&c.v, c.value); got != c.want {
			t.Errorf("%s: %q gave %v, want %v", c.name, c.value, got, c.want)
		}
	}
	for _, bad := range []Validator{{Type: "letter_check", Values: []string{"A"}, Weights: []int{1}}, {Type: "date_embedded", Values: []string{"MMYY"}}, {Type: "mod11_weighted"}, {Type: "mod97", Value: 99}} {
		if checkValidator(&bad) == nil {
			t.Errorf("%+v should be refused", bad)
		}
	}
}

func TestDefinitiveChecksRuleOutAMatch(t *testing.T) {
	d := CustomDef{Slug: "c_es_dni", Kind: KindPattern, Name: "DNI", Status: "enforcing", Threshold: 0.7,
		Definition:      Definition{Regex: `\b\d{8}-?[A-Z]\b`},
		Validator:       &Validator{Type: "letter_check", Values: []string{"TRWAGMYFPDXBNJZSQVHLCKE"}, Weights: []int{14, 6, 19, 18, 11, 8, 10, 1}},
		ContextPositive: []string{"DNI"}}
	rs, err := NewRuleSet(New(Config{}), 1, []CustomDef{d}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs.MatchesSample("c_es_dni", "DNI 12345678Z")) == 0 {
		t.Error("a valid DNI next to its cue word should match")
	}
	if len(rs.MatchesSample("c_es_dni", "DNI 12345678A")) != 0 {
		t.Error("a wrong check letter must not match, even next to its cue word")
	}
}
