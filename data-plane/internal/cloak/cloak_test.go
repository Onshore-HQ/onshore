package cloak

import (
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC)

func TestGeneralize(t *testing.T) {
	cases := []struct{ entity, option, in, want string }{
		{"amount_ngn", Band, "₦850,000", "₦500k–₦1m"},
		{"amount_ngn", Band, "NGN 4,750,000", "₦1m–₦5m"},
		{"amount_ngn", Band, "N2.5m", "₦1m–₦5m"},
		{"amount_ngn", Band, "50k", "₦50k–₦100k"},
		{"amount_ngn", Band, "₦3,500", "under ₦10k"},
		{"amount_ngn", Band, "₦250,000,000", "over ₦100m"},
		{"date", AgeBand, "14/03/1988", "aged 35–44"},
		{"date", AgeBand, "1988-12-30", "aged 35–44"},
		{"date", AgeBand, "2010-01-01", "under 18"},
		{"date", AgeBand, "1950-01-01", "aged 65 or over"},
		{"date", Year, "14/03/1988", "1988"},
		{"phone_ng", Network, "0803 123 4567", "an MTN number"},
		{"phone_ng", Network, "+2348051234567", "a Glo number"},
		{"phone_ng", Last4, "08031234567", "****4567"},
		{"email", Domain, "chioma.okafor@Gmail.com", "a gmail.com address"},
		{"nuban", Last4, "0123456789", "****6789"},
		{"address", State, "Lekki", "Lagos"},
		{"address", Region, "Port Harcourt", "South-South Nigeria"},
		{"address", State, "Wuse II", "Abuja"},
	}
	for _, c := range cases {
		got, ok := Generalize(c.entity, c.option, c.in, now)
		if !ok || got != c.want {
			t.Errorf("Generalize(%s, %s, %q) = %q, %v; want %q", c.entity, c.option, c.in, got, ok, c.want)
		}
	}
	// Unreadable values fall back to a placeholder rather than passing through.
	for _, c := range [][3]string{{"amount_ngn", Band, "lots"}, {"phone_ng", Network, "0123"}, {"date", AgeBand, "soon"}, {"address", State, "Narnia"}, {"bvn", Band, "22123456789"}} {
		if got, ok := Generalize(c[0], c[1], c[2], now); ok {
			t.Errorf("Generalize(%v) = %q, want a fallback", c, got)
		}
	}
}

func TestFindPlaces(t *testing.T) {
	text := "She lives in Lekki, Lagos and works in Port Harcourt. Delta airline. Born in Delta State. lagos.example.com. Ojo called from Ikeja in Lagos State."
	got := FindPlaces(text)
	var spans []string
	for _, p := range got {
		spans = append(spans, text[p.Start:p.End]+"="+p.State)
	}
	want := []string{"Lekki, Lagos=Lagos", "Port Harcourt=Rivers", "Delta State=Delta", "Ikeja in Lagos State=Lagos"}
	if strings.Join(spans, "|") != strings.Join(want, "|") {
		t.Fatalf("got %v\nwant %v", spans, want)
	}
	if len(FindPlaces("Ilorin")) != 1 || len(FindPlaces("Ilorinx")) != 0 || len(FindPlaces("xLagos")) != 0 {
		t.Fatal("word boundaries")
	}
}

func TestNamer(t *testing.T) {
	n := NewNamer("Chioma Okafor wrote to Adaeze about it", func(int) int { return 0 })
	f1, parts := n.Fake("Chioma Okafor")
	if f1 == "" || strings.Contains(f1, "Adaeze") || strings.Contains(f1, "Okafor") {
		t.Fatalf("stand-in %q must avoid names in the text", f1)
	}
	if len(parts) != 2 || parts[0].Real != "Chioma" || parts[1].Real != "Okafor" {
		t.Fatalf("parts %v", parts)
	}
	if again, _ := n.Fake("Chioma Okafor"); again != f1 {
		t.Fatal("same real name must keep its stand-in")
	}
	f2, _ := n.Fake("Bola")
	if f2 == "" || strings.Fields(f2)[0] == strings.Fields(f1)[0] || strings.Contains(f2, " ") {
		t.Fatalf("second stand-in %q", f2)
	}
}

func TestValidate(t *testing.T) {
	if err := Validate(Options{"amount_ngn": Band, "address": Region}); err != nil {
		t.Fatal(err)
	}
	if Validate(Options{"bvn": Keep}) == nil || Validate(Options{"shoe_size": Keep}) == nil {
		t.Fatal("must refuse")
	}
	if (Options{}).For("address") != Keep || (Options{}).For("bvn") != Placeholder || (Options{}).For("c_staff_id") != Placeholder {
		t.Fatal("defaults")
	}
}

func TestMonthFirstInTheUS(t *testing.T) {
	// 03/04/1990 is 3 April in Lagos and 4 March in New York; 12/31/1988 only reads month first.
	if got, ok := GeneralizeIn("US", "date", AgeBand, "12/31/1988", now); !ok || got != "aged 35–44" {
		t.Fatalf("US: %q %v", got, ok)
	}
	if b, ok := birthDate("03/04/1990", true); !ok || b.Month() != 3 {
		t.Fatalf("month first: %v", b)
	}
	if b, ok := birthDate("03/04/1990", false); !ok || b.Month() != 4 {
		t.Fatalf("day first: %v", b)
	}
}

func TestAmountsInEveryCurrency(t *testing.T) {
	cases := map[string]string{
		"$8,500.00": "$5k–$10k", "€1.250,50": "€1k–€5k", "£12,000": "£10k–£50k", "KSh 85,000": "KSh 50k–KSh 100k",
		"R$ 1.200,00": "R$500–R$2.5k", "₹45,000": "₹10k–₹50k", "USD 2.5m": "$1m–$5m", "AED 4,500": "AED 2.5k–AED 5k", "250 euros": "€100–€500",
	}
	for in, want := range cases {
		if got, ok := GeneralizeIn("", "amount", Band, in, now); !ok || got != want {
			t.Errorf("%q: got %q %v, want %q", in, got, ok, want)
		}
	}
	// Settings saved before amounts went global still apply.
	if (Options{"amount_ngn": Band}).For("amount") != Band || (Options{"amount": Band}).For("amount_ngn") != Band {
		t.Fatal("amount_ngn and amount share one setting")
	}
}

func TestPlacesInEveryCountry(t *testing.T) {
	cases := []struct{ text, state, region string }{
		{"Brooklyn", "New York", "United States"}, {"Shoreditch", "England", "United Kingdom"}, {"Munich", "Bavaria", "Germany"},
		{"Dubai Marina", "Dubai", "United Arab Emirates"}, {"Sandton", "Gauteng", "South Africa"}, {"Westlands", "Nairobi County", "Kenya"},
		{"Koramangala", "Karnataka", "India"}, {"Tampines", "Singapore", "Singapore"}, {"Lekki", "Lagos", "South-West Nigeria"},
	}
	for _, c := range cases {
		st, ok1 := Generalize("address", State, c.text, now)
		rg, ok2 := Generalize("address", Region, c.text, now)
		if !ok1 || !ok2 || st != c.state || rg != c.region {
			t.Errorf("%q: state %q, region %q", c.text, st, rg)
		}
	}
	// A vault only searches its own countries' places.
	if len(FindPlacesIn("She lives in Brooklyn and works in Lekki", []string{"us"})) != 1 {
		t.Fatal("a US vault should find Brooklyn only")
	}
	if len(FindPlaces("I will be in Reading, it was Nice")) != 0 {
		t.Fatal("place names that are ordinary words are not listed")
	}
}

func TestStandInNamesFitTheCountry(t *testing.T) {
	us := NewNamerFor("", func(int) int { return 0 }, "US")
	if f, _ := us.Fake("Sarah Johnson"); f != "Emily Bennett" {
		t.Fatalf("US stand-in: %q", f)
	}
	de := NewNamerFor("", func(int) int { return 0 }, "DE")
	if f, _ := de.Fake("Anna Schmidt"); f != "Lukas Becker" {
		t.Fatalf("German stand-in: %q", f)
	}
	if f, _ := NewNamer("", func(int) int { return 0 }).Fake("Kim Lee"); f != "Alex Rivera" {
		t.Fatalf("no country: an international stand-in, got %q", f)
	}
}
