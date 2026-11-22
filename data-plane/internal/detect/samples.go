package detect

import (
	"fmt"
	"math/rand"
	"strconv"
	"strings"
)

// Samples makes made-up values that pass every check this package applies, for
// sandbox vaults and tests. Nothing here is a real person's data. Names, phones and
// amounts follow the vault's country, so a test vault in Germany looks German.
type Samples struct {
	r       *rand.Rand
	country string
	corpus  *Corpus
}

// NewSamples seeds a generator for a vault in country (ISO alpha-2).
func NewSamples(seed int64, country string) *Samples {
	return &Samples{r: rand.New(rand.NewSource(seed)), country: strings.ToUpper(country), corpus: NewCorpus(seed)}
}

func (s *Samples) digits(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteByte(byte('0' + s.r.Intn(10)))
	}
	return b.String()
}

func (s *Samples) pick(xs []string) string { return xs[s.r.Intn(len(xs))] }

// luhnDigit completes body so that body+digit passes Luhn.
func luhnDigit(body string) string {
	for d := byte('0'); d <= '9'; d++ {
		if ValidLuhn(body + string(d)) {
			return string(d)
		}
	}
	return "0"
}

var sampleNames = map[string][2][]string{
	"US": {{"Emily", "James", "Olivia", "Michael", "Sophia", "Daniel"}, {"Carter", "Bennett", "Hughes", "Mitchell", "Foster", "Collins"}},
	"GB": {{"Oliver", "Amelia", "Harry", "Isla", "George", "Grace"}, {"Walsh", "Hughes", "Ellis", "Graham", "Barnes", "Webb"}},
	"CA": {{"Liam", "Emma", "Noah", "Chloe", "Lucas", "Maya"}, {"Tremblay", "Roy", "Martin", "Gagnon", "Wilson", "Campbell"}},
	"IE": {{"Ciaran", "Aoife", "Declan", "Niamh", "Sean", "Siobhan"}, {"Murphy", "Kelly", "Walsh", "Byrne", "Ryan", "Doyle"}},
	"DE": {{"Lukas", "Lena", "Jonas", "Hanna", "Felix", "Clara"}, {"Becker", "Hoffmann", "Schulz", "Koch", "Richter", "Neumann"}},
	"FR": {{"Hugo", "Camille", "Louis", "Chloé", "Théo", "Manon"}, {"Moreau", "Laurent", "Girard", "Fontaine", "Lambert", "Bonnet"}},
	"NL": {{"Daan", "Sanne", "Bram", "Lotte", "Sem", "Femke"}, {"Jansen", "Bakker", "Visser", "Smit", "Meijer", "Mulder"}},
	"BR": {{"João", "Ana", "Pedro", "Beatriz", "Gabriel", "Larissa"}, {"Oliveira", "Souza", "Pereira", "Costa", "Almeida", "Ribeiro"}},
	"AE": {{"Omar", "Layla", "Khalid", "Noura", "Faisal", "Maryam"}, {"Haddad", "Mansour", "Nasser", "Saleh", "Rashid", "Hamdan"}},
	"SA": {{"Fahad", "Reem", "Saud", "Huda", "Turki", "Salma"}, {"Harbi", "Otaibi", "Qahtani", "Ghamdi", "Zahrani", "Shehri"}},
	"QA": {{"Hamad", "Maryam", "Nasser", "Aisha", "Khalid", "Noor"}, {"Kuwari", "Marri", "Thani", "Mohannadi", "Naimi", "Hajri"}},
	"EG": {{"Ahmed", "Nour", "Mostafa", "Yasmin", "Karim", "Salma"}, {"Elsayed", "Farouk", "Mahmoud", "Hassan", "Gamal", "Sherif"}},
	"IN": {{"Aarav", "Ananya", "Rohan", "Priya", "Arjun", "Kavya"}, {"Sharma", "Iyer", "Mehta", "Nair", "Reddy", "Kapoor"}},
	"SG": {{"Wei Ling", "Jun Jie", "Hui Min", "Siti", "Hafiz", "Darren"}, {"Tan", "Lim", "Ng", "Ong", "Wong", "Rahman"}},
	"GH": {{"Kwame", "Ama", "Kofi", "Akua", "Kwabena", "Abena"}, {"Mensah", "Boateng", "Owusu", "Asante", "Osei", "Appiah"}},
	"KE": {{"Wanjiru", "Otieno", "Akinyi", "Kamau", "Njeri", "Kiprop"}, {"Kamau", "Odhiambo", "Mutua", "Kimani", "Njoroge", "Wafula"}},
	"ZA": {{"Thabo", "Lerato", "Sipho", "Thandiwe", "Bongani", "Palesa"}, {"Nkosi", "Dlamini", "Ndlovu", "Khumalo", "Botha", "Naidoo"}},
}

func (s *Samples) name() string {
	if s.country == "NG" {
		return s.corpus.Name()
	}
	p, ok := sampleNames[s.country]
	if !ok {
		p = [2][]string{{"Alex", "Sam", "Elena", "Omar", "Maya", "Leo"}, {"Rivera", "Novak", "Silva", "Chen", "Larsen", "Costa"}}
	}
	return s.pick(p[0]) + " " + s.pick(p[1])
}

var samplePhones = map[string]func(s *Samples) string{
	"NG": func(s *Samples) string { return s.corpus.Phone() },
	"US": func(s *Samples) string { return "+1 212 555 0" + s.digits(3) },
	"CA": func(s *Samples) string { return "+1 416 555 0" + s.digits(3) },
	"GB": func(s *Samples) string { return "+44 7700 900" + s.digits(3) },
	"IE": func(s *Samples) string { return "+353 85 " + s.digits(3) + " " + s.digits(4) },
	"DE": func(s *Samples) string { return "+49 30 " + s.digits(8) },
	"FR": func(s *Samples) string { return "+33 6 " + s.digits(2) + " " + s.digits(2) + " " + s.digits(2) + " " + s.digits(2) },
	"NL": func(s *Samples) string { return "+31 6 " + s.digits(8) },
	"BR": func(s *Samples) string { return "+55 11 9" + s.digits(4) + " " + s.digits(4) },
	"AE": func(s *Samples) string { return "+971 50 " + s.digits(3) + " " + s.digits(4) },
	"SA": func(s *Samples) string { return "+966 50 " + s.digits(3) + " " + s.digits(4) },
	"QA": func(s *Samples) string { return "+974 55" + s.digits(2) + " " + s.digits(4) },
	"EG": func(s *Samples) string { return "+20 10 " + s.digits(4) + " " + s.digits(4) },
	"IN": func(s *Samples) string { return "+91 98" + s.digits(3) + " " + s.digits(5) },
	"SG": func(s *Samples) string { return "+65 9" + s.digits(3) + " " + s.digits(4) },
	"GH": func(s *Samples) string { return "+233 24 " + s.digits(3) + " " + s.digits(4) },
	"KE": func(s *Samples) string { return "+254 712 " + s.digits(3) + " " + s.digits(3) },
	"ZA": func(s *Samples) string { return "+27 82 " + s.digits(3) + " " + s.digits(4) },
}

var sampleCurrency = map[string]string{
	"US": "$", "CA": "CA$", "GB": "£", "IE": "€", "DE": "€", "FR": "€", "NL": "€", "BR": "R$", "AE": "AED ", "SA": "SAR ", "QA": "QAR ",
	"EG": "EGP ", "IN": "₹", "SG": "S$", "GH": "GH₵", "KE": "KSh ", "ZA": "ZAR ",
}

func (s *Samples) iban() string {
	// A valid German IBAN: bank code and account are random, the check digits computed.
	bban := s.digits(18)
	for cd := 2; cd <= 98; cd++ {
		v := fmt.Sprintf("DE%02d%s", cd, bban)
		if ValidIBAN(v) {
			return v
		}
	}
	return "DE89370400440532013000"
}

// Value returns a made-up value of a vault field's data type, or "" when the type
// has no generator (free text, custom types).
func (s *Samples) Value(dataType string) string {
	switch dataType {
	case "bvn":
		return s.corpus.BVN()
	case "nin":
		return s.corpus.NIN()
	case "nuban":
		return s.corpus.NUBAN()
	case "phone_ng":
		return s.corpus.Phone()
	case "amount_ngn":
		return s.corpus.Amount()
	case "person_name":
		return s.name()
	case "email":
		n := strings.ToLower(strings.ReplaceAll(s.name(), " ", "."))
		return n + "@example.com"
	case "date":
		return fmt.Sprintf("%04d-%02d-%02d", 1950+s.r.Intn(55), 1+s.r.Intn(12), 1+s.r.Intn(28))
	case "phone":
		if f, ok := samplePhones[s.country]; ok {
			return f(s)
		}
		return "+44 7700 900" + s.digits(3)
	case "amount":
		cur, ok := sampleCurrency[s.country]
		if !ok {
			cur = "$"
		}
		return cur + strconv.Itoa(100+s.r.Intn(9900)) + ".00"
	case "ghana_card":
		return "GHA-" + s.digits(9) + "-" + s.digits(1)
	case "ke_national_id":
		return strconv.Itoa(10000000 + s.r.Intn(89999999))
	case "ke_kra_pin":
		return "A" + s.digits(9) + string(byte('A'+s.r.Intn(26)))
	case "za_id":
		body := fmt.Sprintf("%02d%02d%02d", 60+s.r.Intn(40), 1+s.r.Intn(12), 1+s.r.Intn(28)) + s.digits(4) + "08"
		return body + luhnDigit(body)
	case "eg_national_id":
		return fmt.Sprintf("2%02d%02d%02d01", 60+s.r.Intn(40), 1+s.r.Intn(12), 1+s.r.Intn(28)) + s.digits(5)
	case "emirates_id":
		body := fmt.Sprintf("784%04d", 1960+s.r.Intn(45)) + s.digits(7)
		d := luhnDigit(body)
		return body[:3] + "-" + body[3:7] + "-" + body[7:] + "-" + d
	case "sa_national_id":
		body := "1" + s.digits(8)
		return body + luhnDigit(body)
	case "qa_id":
		return fmt.Sprintf("2%02d634", 60+s.r.Intn(40)) + s.digits(5)
	case "uk_nino":
		return "AB" + s.digits(6) + "C"
	case "uk_nhs":
		for {
			b := s.digits(9)
			for d := byte('0'); d <= '9'; d++ {
				if ValidNHS(b + string(d)) {
					return b + string(d)
				}
			}
		}
	case "uk_bank_account":
		return s.digits(2) + "-" + s.digits(2) + "-" + s.digits(2) + " " + s.digits(8)
	case "iban":
		return s.iban()
	case "eu_vat":
		return "DE" + s.digits(9)
	case "de_tax_id":
		for {
			b := string(byte('1'+s.r.Intn(9))) + s.digits(9)
			for d := byte('0'); d <= '9'; d++ {
				if ValidGermanTaxID(b + string(d)) {
					return b + string(d)
				}
			}
		}
	case "fr_nir":
		body := fmt.Sprintf("%d%02d%02d75%06d", 1+s.r.Intn(2), 60+s.r.Intn(40), 1+s.r.Intn(12), s.r.Intn(1000000))
		n, _ := strconv.ParseInt(body, 10, 64)
		return fmt.Sprintf("%s%02d", body, 97-n%97)
	case "us_ssn":
		return fmt.Sprintf("%03d-%02d-%04d", 100+s.r.Intn(565), 1+s.r.Intn(98), 1+s.r.Intn(9998))
	case "us_itin":
		return fmt.Sprintf("9%02d-7%d-%04d", s.r.Intn(100), s.r.Intn(10), s.r.Intn(10000))
	case "us_routing":
		for {
			b := s.digits(8)
			for d := byte('0'); d <= '9'; d++ {
				if ValidABA(b + string(d)) {
					return b + string(d)
				}
			}
		}
	case "ca_sin":
		body := string(byte('1'+s.r.Intn(7))) + s.digits(7)
		v := body + luhnDigit(body)
		return v[:3] + " " + v[3:6] + " " + v[6:]
	case "br_cpf":
		for {
			b := s.digits(9)
			for d := 0; d < 100; d++ {
				v := fmt.Sprintf("%s%02d", b, d)
				if ValidCPF(v) {
					return v[:3] + "." + v[3:6] + "." + v[6:9] + "-" + v[9:]
				}
			}
		}
	case "in_aadhaar":
		for {
			b := string(byte('2'+s.r.Intn(8))) + s.digits(10)
			for d := byte('0'); d <= '9'; d++ {
				if v := b + string(d); ValidVerhoeff(v) {
					return v[:4] + " " + v[4:8] + " " + v[8:]
				}
			}
		}
	case "in_pan":
		l := func() byte { return byte('A' + s.r.Intn(26)) }
		return string([]byte{l(), l(), l(), 'P', l()}) + s.digits(4) + string(l())
	case "sg_nric":
		for {
			b := "S" + s.digits(7)
			for c := byte('A'); c <= 'Z'; c++ {
				if ValidNRIC(b + string(c)) {
					return b + string(c)
				}
			}
		}
	}
	return ""
}
