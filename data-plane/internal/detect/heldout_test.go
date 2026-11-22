package detect

import "testing"

// TestHeldOutAwkward is written after tuning stopped and is NOT tuned against:
// its failures are logged as known gaps rather than fixed by adding keywords, so
// the printed score stays an honest estimate of behaviour on unfamiliar text.
func TestHeldOutAwkward(t *testing.T) {
	cases := []struct {
		text string
		want map[string]EntityType // sensitive spans a correct engine reports
	}{
		{"Kindly assist, the money I sent to 2093847561 never reach", map[string]EntityType{"2093847561": NUBAN}},
		{"acctno:0098765432", map[string]EntityType{"0098765432": NUBAN}},
		{"Beneficiary: 3012345678 / ZENITH", map[string]EntityType{"3012345678": NUBAN}},
		{"bank verification no. 22334455667", map[string]EntityType{"22334455667": BVN}},
		{"his bvn na 223-3445-5667 abeg", map[string]EntityType{"223-3445-5667": BVN}},
		{"NIN:12345678901,DOB:01-02-1988", map[string]EntityType{"12345678901": NIN, "01-02-1988": DOB}},
		{"reach me 0803-123-4567", map[string]EntityType{"0803-123-4567": PhoneNG}},
		{"+234(0)8031234567", map[string]EntityType{"+234(0)8031234567": PhoneNG}},
		{"sender_msisdn=2348031234567&amount=5000", map[string]EntityType{"2348031234567": PhoneNG}},
		{"chioma.okafor@gmail.com sent a complaint", map[string]EntityType{"chioma.okafor@gmail.com": Email}},
		{"Card: 5399-8312-3456-7894 expired", map[string]EntityType{"5399-8312-3456-7894": CardPAN}},
		{"from: OKAFOR CHIOMA JANE to GTB", map[string]EntityType{"OKAFOR CHIOMA JANE": PersonName}},
		{"acct name - Bode Thomas", map[string]EntityType{"Bode Thomas": PersonName}},
		{"i don pay 25,000 naira", map[string]EntityType{"25,000 naira": AmountNGN}},
		{"transfer of NGN2.5m", map[string]EntityType{"NGN2.5m": AmountNGN}},
		// Things that must NOT be reported.
		{"exit code 1234567890", nil},
		{"item 0123456789012 out of stock", nil},
		{"latency_ms=1234567890", nil},
		{"Toyota Camry Parked At Lekki", nil},
		{"version 2.11.1234567890", nil},
		{"cost 100 USD for 50000 units", nil},
		{"file 20261103123.log rotated", nil},
	}
	e := New(Config{})
	passed := 0
	for _, c := range cases {
		got := types(e.Scan(c.text), c.text)
		ok := len(got) == len(c.want)
		for k, v := range c.want {
			ok = ok && got[k] == v
		}
		if ok {
			passed++
		} else {
			t.Logf("GAP %q: got %v, want %v", c.text, got, c.want)
		}
	}
	t.Logf("held-out score: %d/%d", passed, len(cases))
}
