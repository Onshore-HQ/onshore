package cloak

import (
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ---- places ------------------------------------------------------------------
//
// Each country pack has a gazetteer: first-level divisions (states, provinces,
// emirates, regions), their cities and well-known districts. "State" reduces a
// place to its division, "Region" to the country (or, in Nigeria, the
// geopolitical zone). Matching is case-sensitive, so "nice" or "reading" in
// prose is left alone; names that are also ordinary words are not listed.

type division struct {
	name, country, zone string
	towns               []string
}

type place struct{ state, country, zone string }

func (p place) region() string {
	if p.zone != "" {
		return p.zone + " " + p.country
	}
	return p.country
}

// Place is a place name found in text.
type Place struct {
	Start, End int
	State      string
}

var gazetteers = map[string][]division{
	"ng": {
		{"Abia", "Nigeria", "South-East", []string{"Umuahia", "Aba"}},
		{"Adamawa", "Nigeria", "North-East", []string{"Yola", "Mubi"}},
		{"Akwa Ibom", "Nigeria", "South-South", []string{"Uyo", "Eket", "Ikot Ekpene"}},
		{"Anambra", "Nigeria", "South-East", []string{"Awka", "Onitsha", "Nnewi", "Ekwulobia"}},
		{"Bauchi", "Nigeria", "North-East", nil},
		{"Bayelsa", "Nigeria", "South-South", []string{"Yenagoa"}},
		{"Benue", "Nigeria", "North-Central", []string{"Makurdi", "Gboko", "Otukpo"}},
		{"Borno", "Nigeria", "North-East", []string{"Maiduguri"}},
		{"Cross River", "Nigeria", "South-South", []string{"Calabar", "Ikom"}},
		{"Delta*", "Nigeria", "South-South", []string{"Asaba", "Warri", "Sapele", "Ughelli", "Agbor"}},
		{"Ebonyi", "Nigeria", "South-East", []string{"Abakaliki", "Afikpo"}},
		{"Edo", "Nigeria", "South-South", []string{"Benin City", "Auchi", "Ekpoma"}},
		{"Ekiti", "Nigeria", "South-West", []string{"Ado-Ekiti", "Ado Ekiti"}},
		{"Enugu", "Nigeria", "South-East", []string{"Nsukka"}},
		{"Abuja", "Nigeria", "North-Central", []string{"FCT", "Wuse", "Maitama", "Garki", "Asokoro", "Gwarinpa", "Kubwa", "Jabi", "Utako", "Lugbe", "Lokogoma", "Life Camp", "Katampe", "Durumi", "Nyanya", "Kuje", "Gwagwalada", "Bwari", "Jahi", "Wuye", "Dutse Alhaji", "Garki II", "Wuse II"}},
		{"Gombe", "Nigeria", "North-East", nil},
		{"Imo", "Nigeria", "South-East", []string{"Owerri", "Orlu", "Okigwe"}},
		{"Jigawa", "Nigeria", "North-West", []string{"Dutse"}},
		{"Kaduna", "Nigeria", "North-West", []string{"Zaria", "Kafanchan"}},
		{"Kano", "Nigeria", "North-West", nil},
		{"Katsina", "Nigeria", "North-West", nil},
		{"Kebbi", "Nigeria", "North-West", []string{"Birnin Kebbi"}},
		{"Kogi", "Nigeria", "North-Central", []string{"Lokoja", "Okene", "Anyigba"}},
		{"Kwara", "Nigeria", "North-Central", []string{"Ilorin", "Offa"}},
		{"Lagos", "Nigeria", "South-West", []string{"Lekki", "Ajah", "Ikoyi", "Victoria Island", "Yaba", "Surulere", "Ikorodu", "Apapa", "Festac", "Ikeja", "Gbagada", "Magodo", "Ojota", "Ogba", "Agege", "Oshodi", "Isolo", "Mushin", "Badagry", "Epe", "Sangotedo", "Ilupeju", "Ebute Metta", "Lagos Island", "Oniru", "Ketu", "Alimosho", "Egbeda", "Ikotun", "Ipaja", "Ogudu", "Ojodu", "Anthony Village", "Lekki Phase 1", "Chevy View", "Osapa London", "Ilasamaja", "Akoka", "Bariga", "Ijora", "Amuwo Odofin"}},
		{"Nasarawa", "Nigeria", "North-Central", []string{"Lafia", "Keffi", "Karu"}},
		{"Niger*", "Nigeria", "North-Central", []string{"Minna", "Suleja", "Bida"}},
		{"Ogun", "Nigeria", "South-West", []string{"Abeokuta", "Sagamu", "Shagamu", "Ijebu Ode", "Ijebu-Ode", "Sango Ota", "Mowe", "Ibafo"}},
		{"Ondo", "Nigeria", "South-West", []string{"Akure", "Owo"}},
		{"Osun", "Nigeria", "South-West", []string{"Osogbo", "Oshogbo", "Ile-Ife", "Ile Ife", "Ilesa", "Ilesha"}},
		{"Oyo", "Nigeria", "South-West", []string{"Ibadan", "Ogbomoso", "Iseyin"}},
		{"Plateau*", "Nigeria", "North-Central", []string{"Jos"}},
		{"Rivers*", "Nigeria", "South-South", []string{"Port Harcourt", "Obio-Akpor", "Eleme", "Rumuokoro", "Rumuola"}},
		{"Sokoto", "Nigeria", "North-West", nil},
		{"Taraba", "Nigeria", "North-East", []string{"Jalingo", "Wukari"}},
		{"Yobe", "Nigeria", "North-East", []string{"Damaturu", "Potiskum"}},
		{"Zamfara", "Nigeria", "North-West", []string{"Gusau"}},
	},
	"gh": {
		{"Greater Accra", "Ghana", "", []string{"Accra", "Tema", "East Legon", "Osu", "Madina", "Kaneshie", "Dansoman", "Spintex", "Cantonments", "Labadi"}},
		{"Ashanti", "Ghana", "", []string{"Kumasi", "Obuasi", "Ejisu"}},
		{"Western Region", "Ghana", "", []string{"Takoradi", "Sekondi", "Tarkwa"}},
		{"Northern Region", "Ghana", "", []string{"Tamale", "Yendi"}},
		{"Central Region", "Ghana", "", []string{"Cape Coast", "Winneba", "Kasoa"}},
		{"Eastern Region", "Ghana", "", []string{"Koforidua", "Nkawkaw"}},
		{"Volta", "Ghana", "", []string{"Hohoe", "Keta", "Aflao"}},
		{"Bono", "Ghana", "", []string{"Sunyani", "Techiman"}},
		{"Upper East", "Ghana", "", []string{"Bolgatanga", "Navrongo"}},
		{"Upper West", "Ghana", "", []string{"Wa"}},
	},
	"ke": {
		{"Nairobi County", "Kenya", "", []string{"Nairobi", "Westlands", "Kilimani", "Kibera", "Eastleigh", "Lavington", "Kileleshwa", "Parklands", "Embakasi", "Kasarani", "Upper Hill", "Gigiri", "Runda", "Langata"}},
		{"Mombasa County", "Kenya", "", []string{"Mombasa", "Nyali", "Likoni", "Bamburi"}},
		{"Kisumu County", "Kenya", "", []string{"Kisumu"}},
		{"Nakuru County", "Kenya", "", []string{"Nakuru", "Naivasha"}},
		{"Kiambu County", "Kenya", "", []string{"Kiambu", "Thika", "Ruiru", "Limuru"}},
		{"Uasin Gishu County", "Kenya", "", []string{"Eldoret"}},
		{"Machakos County", "Kenya", "", []string{"Machakos", "Athi River", "Mlolongo"}},
		{"Kilifi County", "Kenya", "", []string{"Malindi", "Kilifi", "Watamu"}},
		{"Nyeri County", "Kenya", "", []string{"Nyeri"}},
		{"Kajiado County", "Kenya", "", []string{"Kitengela", "Ngong", "Kajiado"}},
	},
	"za": {
		{"Gauteng", "South Africa", "", []string{"Johannesburg", "Pretoria", "Soweto", "Sandton", "Midrand", "Centurion", "Randburg", "Roodepoort", "Benoni", "Germiston", "Tembisa", "Rosebank"}},
		{"Western Cape", "South Africa", "", []string{"Cape Town", "Stellenbosch", "Paarl", "Somerset West", "Khayelitsha", "Bellville", "George"}},
		{"KwaZulu-Natal", "South Africa", "", []string{"Durban", "Pietermaritzburg", "Umhlanga", "Ballito", "Richards Bay"}},
		{"Eastern Cape", "South Africa", "", []string{"Gqeberha", "Port Elizabeth", "East London", "Mthatha"}},
		{"Free State", "South Africa", "", []string{"Bloemfontein", "Welkom"}},
		{"Limpopo", "South Africa", "", []string{"Polokwane", "Tzaneen"}},
		{"Mpumalanga", "South Africa", "", []string{"Mbombela", "Nelspruit", "Witbank", "Emalahleni"}},
		{"North West", "South Africa", "", []string{"Rustenburg", "Mahikeng", "Potchefstroom"}},
		{"Northern Cape", "South Africa", "", []string{"Kimberley", "Upington"}},
	},
	"eg": {
		{"Cairo Governorate", "Egypt", "", []string{"Cairo", "Nasr City", "Heliopolis", "Maadi", "Zamalek", "New Cairo", "Downtown Cairo", "Shubra", "Mokattam"}},
		{"Giza Governorate", "Egypt", "", []string{"Giza", "Sheikh Zayed", "Dokki", "Mohandessin", "Haram", "October City"}},
		{"Alexandria Governorate", "Egypt", "", []string{"Alexandria", "Smouha", "Sidi Gaber", "Montaza"}},
		{"Luxor Governorate", "Egypt", "", []string{"Luxor"}},
		{"Aswan Governorate", "Egypt", "", []string{"Aswan"}},
		{"Port Said Governorate", "Egypt", "", []string{"Port Said"}},
		{"Suez Governorate", "Egypt", "", []string{"Suez"}},
		{"Dakahlia Governorate", "Egypt", "", []string{"Mansoura"}},
		{"Gharbia Governorate", "Egypt", "", []string{"Tanta", "Mahalla"}},
		{"Red Sea Governorate", "Egypt", "", []string{"Hurghada"}},
		{"South Sinai Governorate", "Egypt", "", []string{"Sharm El Sheikh", "Dahab"}},
	},
	"ae": {
		{"Dubai", "United Arab Emirates", "", []string{"Dubai Marina", "Jumeirah", "Deira", "Business Bay", "Downtown Dubai", "Al Barsha", "Bur Dubai", "JLT", "Jebel Ali", "Al Quoz", "Mirdif"}},
		{"Abu Dhabi", "United Arab Emirates", "", []string{"Al Ain", "Khalifa City", "Al Reem Island", "Yas Island", "Mussafah"}},
		{"Sharjah", "United Arab Emirates", "", []string{"Al Nahda", "Al Majaz"}},
		{"Ajman", "United Arab Emirates", "", nil},
		{"Ras Al Khaimah", "United Arab Emirates", "", nil},
		{"Fujairah", "United Arab Emirates", "", nil},
		{"Umm Al Quwain", "United Arab Emirates", "", nil},
	},
	"sa": {
		{"Riyadh Province", "Saudi Arabia", "", []string{"Riyadh", "Olaya", "Al Malqa", "Diriyah"}},
		{"Makkah Province", "Saudi Arabia", "", []string{"Jeddah", "Mecca", "Makkah", "Taif"}},
		{"Eastern Province", "Saudi Arabia", "", []string{"Dammam", "Khobar", "Al Khobar", "Dhahran", "Jubail", "Al Ahsa"}},
		{"Madinah Province", "Saudi Arabia", "", []string{"Medina", "Madinah", "Yanbu"}},
		{"Asir Province", "Saudi Arabia", "", []string{"Abha", "Khamis Mushait"}},
		{"Qassim Province", "Saudi Arabia", "", []string{"Buraidah", "Unaizah"}},
		{"Tabuk Province", "Saudi Arabia", "", []string{"Tabuk", "NEOM"}},
	},
	"qa": {
		{"Doha", "Qatar", "", []string{"West Bay", "The Pearl", "Msheireb", "Al Sadd", "Old Airport", "Al Dafna"}},
		{"Al Rayyan", "Qatar", "", []string{"Education City", "Aspire Zone"}},
		{"Lusail", "Qatar", "", nil},
		{"Al Wakrah", "Qatar", "", []string{"Mesaieed"}},
		{"Al Khor", "Qatar", "", nil},
	},
	"gb": {
		{"England", "United Kingdom", "", []string{"London", "Manchester", "Birmingham", "Leeds", "Liverpool", "Bristol", "Sheffield", "Newcastle", "Nottingham", "Leicester", "Brighton", "Oxford", "Cambridge", "Southampton", "Camden", "Hackney", "Islington", "Croydon", "Westminster", "Shoreditch", "Canary Wharf", "Peckham", "Brixton", "Coventry", "Milton Keynes", "Bradford", "Wolverhampton"}},
		{"Scotland", "United Kingdom", "", []string{"Edinburgh", "Glasgow", "Aberdeen", "Dundee", "Inverness"}},
		{"Wales", "United Kingdom", "", []string{"Cardiff", "Swansea", "Newport"}},
		{"Northern Ireland", "United Kingdom", "", []string{"Belfast", "Derry", "Londonderry"}},
	},
	"eu": {
		{"Bavaria", "Germany", "", []string{"Munich", "München", "Nuremberg", "Nürnberg", "Augsburg", "Bayern"}},
		{"Berlin", "Germany", "", []string{"Kreuzberg", "Mitte", "Charlottenburg", "Prenzlauer Berg", "Neukölln"}},
		{"Hamburg", "Germany", "", nil},
		{"Hesse", "Germany", "", []string{"Frankfurt", "Wiesbaden", "Hessen"}},
		{"North Rhine-Westphalia", "Germany", "", []string{"Cologne", "Köln", "Düsseldorf", "Dortmund", "Essen", "Bonn", "Nordrhein-Westfalen"}},
		{"Baden-Württemberg", "Germany", "", []string{"Stuttgart", "Mannheim", "Karlsruhe", "Heidelberg"}},
		{"Saxony", "Germany", "", []string{"Leipzig", "Dresden", "Sachsen"}},
		{"Île-de-France", "France", "", []string{"Paris", "Boulogne-Billancourt", "Versailles", "Saint-Denis", "La Défense"}},
		{"Auvergne-Rhône-Alpes", "France", "", []string{"Lyon", "Grenoble"}},
		{"Provence-Alpes-Côte d'Azur", "France", "", []string{"Marseille", "Toulon", "Cannes"}},
		{"Occitanie", "France", "", []string{"Toulouse", "Montpellier"}},
		{"Nouvelle-Aquitaine", "France", "", []string{"Bordeaux"}},
		{"Hauts-de-France", "France", "", []string{"Lille"}},
		{"Leinster", "Ireland", "", []string{"Dublin", "Kildare", "Wicklow"}},
		{"Munster", "Ireland", "", []string{"Cork", "Limerick", "Waterford"}},
		{"Connacht", "Ireland", "", []string{"Galway"}},
		{"North Holland", "Netherlands", "", []string{"Amsterdam", "Haarlem", "Noord-Holland"}},
		{"South Holland", "Netherlands", "", []string{"Rotterdam", "The Hague", "Den Haag", "Leiden", "Zuid-Holland"}},
		{"Utrecht", "Netherlands", "", nil},
		{"North Brabant", "Netherlands", "", []string{"Eindhoven", "Noord-Brabant"}},
		{"Community of Madrid", "Spain", "", []string{"Madrid"}},
		{"Catalonia", "Spain", "", []string{"Barcelona", "Cataluña", "Catalunya"}},
		{"Andalusia", "Spain", "", []string{"Seville", "Sevilla", "Málaga", "Malaga"}},
		{"Lombardy", "Italy", "", []string{"Milan", "Milano", "Lombardia"}},
		{"Lazio", "Italy", "", []string{"Rome", "Roma"}},
		{"Brussels", "Belgium", "", []string{"Bruxelles", "Brussel"}},
		{"Flanders", "Belgium", "", []string{"Antwerp", "Antwerpen", "Ghent", "Gent"}},
		{"Lisbon", "Portugal", "", []string{"Lisboa"}},
	},
	"us": {
		{"California", "United States", "", []string{"Los Angeles", "San Francisco", "San Diego", "San Jose", "Oakland", "Sacramento", "Palo Alto", "Silicon Valley"}},
		{"New York", "United States", "", []string{"New York City", "NYC", "Brooklyn", "Manhattan", "Queens", "Bronx", "Staten Island", "Buffalo"}},
		{"Texas", "United States", "", []string{"Houston", "Dallas", "San Antonio", "Fort Worth", "El Paso"}},
		{"Florida", "United States", "", []string{"Miami", "Orlando", "Tampa", "Jacksonville"}},
		{"Illinois", "United States", "", []string{"Chicago"}},
		{"Washington State*", "United States", "", []string{"Seattle", "Tacoma"}},
		{"Massachusetts", "United States", "", []string{"Boston"}},
		{"Georgia*", "United States", "", []string{"Atlanta"}},
		{"Pennsylvania", "United States", "", []string{"Philadelphia", "Pittsburgh"}},
		{"Arizona", "United States", "", []string{"Phoenix", "Tucson"}},
		{"Colorado", "United States", "", []string{"Denver"}},
		{"Nevada", "United States", "", []string{"Las Vegas", "Reno"}},
		{"Michigan", "United States", "", []string{"Detroit"}},
		{"Minnesota", "United States", "", []string{"Minneapolis", "Saint Paul"}},
		{"Oregon", "United States", "", []string{"Portland"}},
		{"North Carolina", "United States", "", []string{"Raleigh"}},
		{"Tennessee", "United States", "", []string{"Nashville", "Memphis"}},
		{"Ohio", "United States", "", []string{"Cleveland", "Cincinnati"}},
		{"New Jersey", "United States", "", []string{"Newark", "Jersey City", "Hoboken"}},
		{"Maryland", "United States", "", []string{"Baltimore"}},
		{"District of Columbia", "United States", "", []string{"Washington DC", "Washington, DC", "Washington D.C."}},
		{"Utah", "United States", "", []string{"Salt Lake City"}},
		{"Louisiana", "United States", "", []string{"New Orleans"}},
		{"Missouri", "United States", "", []string{"St. Louis", "Kansas City"}},
	},
	"ca": {
		{"Ontario", "Canada", "", []string{"Toronto", "Ottawa", "Mississauga", "Brampton", "Waterloo", "Scarborough"}},
		{"Quebec", "Canada", "", []string{"Montreal", "Montréal", "Quebec City", "Québec", "Laval", "Gatineau"}},
		{"British Columbia", "Canada", "", []string{"Vancouver", "Surrey", "Burnaby"}},
		{"Alberta", "Canada", "", []string{"Calgary", "Edmonton"}},
		{"Manitoba", "Canada", "", []string{"Winnipeg"}},
		{"Nova Scotia", "Canada", "", []string{"Halifax"}},
		{"Saskatchewan", "Canada", "", []string{"Saskatoon"}},
	},
	"br": {
		{"São Paulo State*", "Brazil", "", []string{"São Paulo", "Sao Paulo", "Campinas", "Guarulhos"}},
		{"Rio de Janeiro State*", "Brazil", "", []string{"Rio de Janeiro", "Niterói", "Copacabana", "Ipanema"}},
		{"Minas Gerais", "Brazil", "", []string{"Belo Horizonte"}},
		{"Distrito Federal", "Brazil", "", []string{"Brasília", "Brasilia"}},
		{"Paraná", "Brazil", "", []string{"Curitiba"}},
		{"Rio Grande do Sul", "Brazil", "", []string{"Porto Alegre"}},
		{"Pernambuco", "Brazil", "", []string{"Recife"}},
		{"Ceará", "Brazil", "", []string{"Fortaleza"}},
		{"Bahia", "Brazil", "", []string{"Feira de Santana"}},
	},
	"in": {
		{"Maharashtra", "India", "", []string{"Mumbai", "Pune", "Nagpur", "Thane", "Navi Mumbai", "Bandra", "Andheri"}},
		{"Karnataka", "India", "", []string{"Bengaluru", "Bangalore", "Mysuru", "Mysore", "Koramangala", "Whitefield"}},
		{"Delhi", "India", "", []string{"New Delhi", "Dwarka", "Saket"}},
		{"Tamil Nadu", "India", "", []string{"Chennai", "Coimbatore", "Madurai"}},
		{"Telangana", "India", "", []string{"Hyderabad", "Secunderabad"}},
		{"West Bengal", "India", "", []string{"Kolkata"}},
		{"Gujarat", "India", "", []string{"Ahmedabad", "Surat", "Vadodara"}},
		{"Rajasthan", "India", "", []string{"Jaipur", "Udaipur", "Jodhpur"}},
		{"Uttar Pradesh", "India", "", []string{"Lucknow", "Noida", "Kanpur", "Varanasi"}},
		{"Kerala", "India", "", []string{"Kochi", "Thiruvananthapuram"}},
		{"Haryana", "India", "", []string{"Gurugram", "Gurgaon", "Faridabad"}},
	},
	"sg": {
		{"Singapore", "Singapore", "", []string{"Jurong", "Tampines", "Woodlands", "Orchard", "Bukit Timah", "Ang Mo Kio", "Toa Payoh", "Sentosa", "Bedok", "Punggol", "Sengkang", "Marina Bay", "Clementi"}},
	},
}

type placeName struct {
	text      string
	needState bool
	p         place
}

// byWord indexes each pack's names by first word, longest first.
var byWord = func() map[string]map[string][]placeName {
	all := map[string]map[string][]placeName{}
	for pack, divs := range gazetteers {
		m := map[string][]placeName{}
		add := func(text string, needState bool, p place) {
			w := firstWord(text)
			m[w] = append(m[w], placeName{text, needState, p})
		}
		for _, d := range divs {
			name, need := strings.CutSuffix(d.name, "*")
			// "Washington State*" counts only written in full; its bare name means the capital.
			if need && strings.HasSuffix(name, " State") {
				need = false
			}
			p := place{strings.TrimSuffix(name, " State"), d.country, d.zone}
			add(name, need, p)
			for _, t := range d.towns {
				add(t, false, p)
			}
		}
		for _, l := range m {
			sort.Slice(l, func(i, j int) bool { return len(l[i].text) > len(l[j].text) })
		}
		all[pack] = m
	}
	return all
}()

func firstWord(s string) string {
	for i, r := range s {
		if !unicode.IsLetter(r) {
			return s[:i]
		}
	}
	return s
}

func isWordRune(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) }

// lookupPlace finds which division and country a place belongs to, in any pack.
func lookupPlace(v string) (place, bool) {
	for _, p := range FindPlacesWithInfo(v, nil) {
		return p.info, true
	}
	return place{}, false
}

type foundPlace struct {
	Place
	info place
}

// FindPlaces finds places of every country.
func FindPlaces(text string) []Place { return FindPlacesIn(text, nil) }

// FindPlacesIn finds places of the given packs' countries; nil means every pack.
// Neighbouring names in one division, such as "Lekki, Lagos" or "Brooklyn, New
// York", become one span.
func FindPlacesIn(text string, packs []string) []Place {
	found := FindPlacesWithInfo(text, packs)
	out := make([]Place, len(found))
	for i, f := range found {
		out[i] = f.Place
	}
	return out
}

// FindPlacesWithInfo is FindPlacesIn with each place's division and country.
func FindPlacesWithInfo(text string, packs []string) []foundPlace {
	if packs == nil {
		for p := range gazetteers {
			packs = append(packs, p)
		}
		sort.Strings(packs)
	}
	var out []foundPlace
	for i := 0; i < len(text); {
		r, size := utf8.DecodeRuneInString(text[i:])
		prev, _ := utf8.DecodeLastRuneInString(text[:i])
		if !unicode.IsUpper(r) || (i > 0 && isWordRune(prev)) {
			i += size
			continue
		}
		w := firstWord(text[i:])
		var best *placeName
		bestEnd := 0
		for _, pack := range packs {
			for k, pn := range byWord[pack][w] {
				if !strings.HasPrefix(text[i:], pn.text) {
					continue
				}
				end := i + len(pn.text)
				if next, _ := utf8.DecodeRuneInString(text[end:]); end < len(text) && isWordRune(next) {
					continue
				}
				for _, suffix := range []string{" State", " state", " County", " Province"} {
					if strings.HasPrefix(text[end:], suffix) {
						if e2 := end + len(suffix); e2 == len(text) || !isWordRune(rune(text[e2])) {
							end = e2
						}
					}
				}
				if pn.needState && !strings.HasSuffix(strings.ToLower(text[i:end]), " state") {
					continue
				}
				if end > bestEnd {
					best, bestEnd = &byWord[pack][w][k], end
				}
				break
			}
		}
		if best != nil {
			out = append(out, foundPlace{Place{i, bestEnd, best.p.state}, best.p})
			i = bestEnd
			continue
		}
		i += len(w)
		if w == "" {
			i += size
		}
	}
	merged := out[:0]
	for _, p := range out {
		if n := len(merged); n > 0 && merged[n-1].State == p.State && merged[n-1].info.country == p.info.country {
			gap := strings.TrimSpace(text[merged[n-1].End:p.Start])
			if gap == "," || gap == "in" || gap == "" {
				merged[n-1].End = p.End
				continue
			}
		}
		merged = append(merged, p)
	}
	return merged
}

// ---- stand-in names -----------------------------------------------------------

type namePool struct{ first, last []string }

var pools = map[string]namePool{
	"intl": {
		[]string{"Alex", "Sam", "Jordan", "Taylor", "Morgan", "Robin", "Jamie", "Casey", "Avery", "Riley", "Quinn", "Rowan", "Elena", "Daniel", "Nadia", "Leo", "Maya", "Omar", "Lina", "Victor", "Iris", "Theo", "Zara", "Adrian"},
		[]string{"Rivera", "Novak", "Haddad", "Silva", "Bauer", "Moreau", "Chen", "Okafor", "Kowalski", "Petrov", "Larsen", "Costa", "Mendes", "Rahman", "Fischer", "Laurent", "Navarro", "Duarte", "Ivanova", "Kaplan"},
	},
	"en": {
		[]string{"Emily", "James", "Olivia", "Michael", "Sophie", "Daniel", "Grace", "Thomas", "Chloe", "Ryan", "Hannah", "Nathan", "Megan", "Ethan", "Laura", "Oliver", "Rachel", "Lucas", "Jessica", "Owen", "Amelia", "Harry", "Isla", "Connor"},
		[]string{"Bennett", "Hughes", "Carter", "Mitchell", "Foster", "Collins", "Reynolds", "Hayes", "Sullivan", "Morgan", "Ellis", "Graham", "Porter", "Walsh", "Brooks", "Hamilton", "Fletcher", "Barnes", "Spencer", "Webb"},
	},
	"de": {
		[]string{"Lukas", "Lena", "Jonas", "Hanna", "Felix", "Leonie", "Paul", "Marie", "Elias", "Clara", "Maximilian", "Johanna", "Moritz", "Lea", "Tobias", "Sophie"},
		[]string{"Becker", "Hoffmann", "Schulz", "Koch", "Richter", "Neumann", "Krüger", "Lehmann", "Wagner", "Braun", "Zimmermann", "Hartmann"},
	},
	"fr": {
		[]string{"Hugo", "Camille", "Louis", "Chloé", "Théo", "Manon", "Julien", "Inès", "Antoine", "Léa", "Nicolas", "Sarah", "Mathis", "Zoé", "Lucas", "Jade"},
		[]string{"Moreau", "Laurent", "Girard", "Fontaine", "Lambert", "Rousseau", "Bonnet", "Mercier", "Fournier", "Chevalier", "Perrin", "Garnier"},
	},
	"nl": {
		[]string{"Daan", "Sanne", "Bram", "Lotte", "Sem", "Femke", "Jesse", "Iris", "Thijs", "Noor", "Ruben", "Fleur"},
		[]string{"Jansen", "Bakker", "Visser", "Smit", "Meijer", "Mulder", "Dekker", "Brouwer", "Hendriks", "Vermeulen"},
	},
	"es": {
		[]string{"Lucía", "Pablo", "Sofía", "Diego", "Martina", "Javier", "Valentina", "Alejandro", "Giulia", "Matteo", "Chiara", "Lorenzo", "Carmen", "Marco"},
		[]string{"García", "Fernández", "Navarro", "Morales", "Ortega", "Romero", "Rossi", "Bianchi", "Ricci", "Colombo", "Moretti", "Herrera"},
	},
	"pt": {
		[]string{"João", "Ana", "Pedro", "Beatriz", "Gabriel", "Larissa", "Rafael", "Fernanda", "Gustavo", "Mariana", "Felipe", "Camila", "Thiago", "Juliana"},
		[]string{"Oliveira", "Souza", "Pereira", "Costa", "Almeida", "Carvalho", "Ribeiro", "Barbosa", "Araújo", "Cardoso", "Teixeira", "Moura"},
	},
	"ar": {
		[]string{"Omar", "Layla", "Khalid", "Noura", "Faisal", "Maryam", "Yousef", "Reem", "Tariq", "Salma", "Hamza", "Huda", "Karim", "Yasmin", "Ziad", "Rania"},
		[]string{"Haddad", "Mansour", "Nasser", "Saleh", "Khoury", "Farouk", "Hamdan", "Rashid", "Aziz", "Darwish", "Kamal", "Sabry"},
	},
	"in": {
		[]string{"Aarav", "Ananya", "Rohan", "Priya", "Arjun", "Kavya", "Vikram", "Diya", "Ishaan", "Sneha", "Kabir", "Meera", "Aditya", "Riya"},
		[]string{"Sharma", "Iyer", "Mehta", "Nair", "Reddy", "Kapoor", "Desai", "Joshi", "Menon", "Bose", "Malhotra", "Rao"},
	},
	"sg": {
		[]string{"Wei Ling", "Jun Jie", "Hui Min", "Ming Hao", "Siti", "Hafiz", "Priya", "Arjun", "Xin Yi", "Zhi Hao", "Nur Aisyah", "Darren"},
		[]string{"Tan", "Lim", "Ng", "Ong", "Wong", "Goh", "Chua", "Koh", "Teo", "Rahman", "Ismail", "Pillai"},
	},
	"gh": {
		[]string{"Kwame", "Ama", "Kofi", "Akua", "Kwabena", "Abena", "Yaw", "Efua", "Kojo", "Adwoa", "Kwesi", "Akosua"},
		[]string{"Mensah", "Boateng", "Owusu", "Asante", "Osei", "Agyeman", "Appiah", "Darko", "Ofori", "Addo", "Tetteh", "Quaye"},
	},
	"ke": {
		[]string{"Wanjiru", "Otieno", "Akinyi", "Kamau", "Njeri", "Kiprop", "Achieng", "Mwangi", "Chebet", "Kibet", "Wambui", "Onyango"},
		[]string{"Kamau", "Odhiambo", "Mutua", "Kimani", "Njoroge", "Cheruiyot", "Wafula", "Ochieng", "Macharia", "Musyoka", "Kiptoo", "Nyambura"},
	},
	"za": {
		[]string{"Thabo", "Lerato", "Sipho", "Thandiwe", "Bongani", "Palesa", "Mandla", "Zanele", "Tshepo", "Ayanda", "Kagiso", "Lindiwe"},
		[]string{"Nkosi", "Dlamini", "Ndlovu", "Khumalo", "Mokoena", "Molefe", "Botha", "Pretorius", "Venter", "Naidoo", "Mthembu", "Zulu"},
	},
	"ng": {
		[]string{"Adaeze", "Tunde", "Ngozi", "Ibrahim", "Funmilayo", "Emeka", "Zainab", "Olumide", "Chidinma", "Musa", "Folake", "Ikenna", "Halima", "Segun", "Amarachi", "Yusuf", "Temitope", "Obinna", "Hauwa", "Kunle", "Nkechi", "Bashir", "Yetunde", "Chukwudi"},
		[]string{"Okonkwo", "Adeyemi", "Bello", "Nwosu", "Balogun", "Danjuma", "Eze", "Afolabi", "Lawal", "Okafor", "Ogunleye", "Abubakar", "Nnaji", "Adebayo", "Usman", "Uzor", "Akande", "Ibekwe", "Garba", "Olaniyan"},
	},
}

var countryPool = map[string]string{
	"US": "en", "GB": "en", "CA": "en", "IE": "en", "DE": "de", "FR": "fr", "NL": "nl", "ES": "es", "IT": "es", "BR": "pt",
	"AE": "ar", "SA": "ar", "QA": "ar", "EG": "ar", "IN": "in", "SG": "sg", "GH": "gh", "KE": "ke", "ZA": "za", "NG": "ng", "PT": "pt", "BE": "fr", "AT": "de", "CH": "de", "AU": "en", "NZ": "en",
}

func poolFor(country string) namePool {
	if p, ok := pools[countryPool[strings.ToUpper(country)]]; ok {
		return p
	}
	return pools["intl"]
}

// ---- amounts in any currency ----------------------------------------------------

type currency struct {
	show   string  // how a band is written: "$", "€", "KSh "
	factor float64 // band edges are US-dollar-sized edges times this
}

// currencies by symbol or code. Edges scale to keep bands meaningful locally.
var currencies = []struct {
	marks []string
	c     currency
}{
	{[]string{"US$", "USD", "dollar"}, currency{"$", 1}},
	{[]string{"CA$", "C$", "CAD"}, currency{"CA$", 1}},
	{[]string{"A$", "AUD"}, currency{"A$", 1}},
	{[]string{"SG$", "S$", "SGD"}, currency{"S$", 1}},
	{[]string{"R$", "BRL", "reais", "real"}, currency{"R$", 5}},
	{[]string{"€", "EUR", "euro"}, currency{"€", 1}},
	{[]string{"£", "GBP", "pound"}, currency{"£", 1}},
	{[]string{"CHF"}, currency{"CHF ", 1}},
	{[]string{"₹", "INR", "rupee"}, currency{"₹", 100}},
	{[]string{"GH₵", "GH¢", "₵", "GHS", "cedi"}, currency{"GH₵", 10}},
	{[]string{"KSh", "KES", "shilling"}, currency{"KSh ", 100}},
	{[]string{"ZAR", "rand"}, currency{"R", 20}},
	{[]string{"E£", "EGP"}, currency{"EGP ", 50}},
	{[]string{"AED", "dirham"}, currency{"AED ", 5}},
	{[]string{"SAR", "riyal", "﷼"}, currency{"SAR ", 5}},
	{[]string{"QAR"}, currency{"QAR ", 5}},
	{[]string{"JPY"}, currency{"¥", 100}},
	{[]string{"CNY"}, currency{"CNY ", 5}},
	{[]string{"$"}, currency{"$", 1}},
}

// moneyBand turns "$8,500.00", "€1.250,50" or "KSh 85,000" into a range in the same currency.
func moneyBand(v string) (string, bool) {
	var cur currency
	found := false
	lower := strings.ToLower(v)
	for _, c := range currencies {
		for _, m := range c.marks {
			if strings.Contains(v, m) || strings.Contains(lower, strings.ToLower(m)) && len(m) > 2 {
				cur, found = c.c, true
				break
			}
		}
		if found {
			break
		}
	}
	if !found {
		return "", false
	}
	n, ok := parseAmount(v)
	if !ok {
		return "", false
	}
	edges := []float64{100, 500, 1e3, 5e3, 1e4, 5e4, 1e5, 5e5, 1e6, 5e6}
	for i := range edges {
		edges[i] *= cur.factor
	}
	show := func(x float64) string { return cur.show + short(x) }
	if n < edges[0] {
		return "under " + show(edges[0]), true
	}
	for i := 1; i < len(edges); i++ {
		if n < edges[i] {
			return show(edges[i-1]) + "–" + show(edges[i]), true
		}
	}
	return "over " + show(edges[len(edges)-1]), true
}

func short(x float64) string {
	switch {
	case x >= 1e6:
		return strconv.FormatFloat(x/1e6, 'f', -1, 64) + "m"
	case x >= 1e3:
		return strconv.FormatFloat(x/1e3, 'f', -1, 64) + "k"
	}
	return strconv.FormatFloat(x, 'f', -1, 64)
}

// parseAmount reads the number in an amount, with either "1,250.50" or "1.250,50"
// grouping, and k/m/bn suffixes.
func parseAmount(v string) (float64, bool) {
	start, end := -1, -1
	for i, r := range v {
		if r >= '0' && r <= '9' {
			if start < 0 {
				start = i
			}
			end = i + 1
		} else if start >= 0 && !(r == ',' || r == '.' || r == ' ' || r == ' ') {
			break
		}
	}
	if start < 0 {
		return 0, false
	}
	num := strings.TrimRight(strings.NewReplacer(" ", "", " ", "").Replace(v[start:end]), ".,")
	lastDot, lastComma := strings.LastIndex(num, "."), strings.LastIndex(num, ",")
	decimal := -1
	switch {
	case lastDot >= 0 && lastComma >= 0:
		decimal = max(lastDot, lastComma)
	case lastDot >= 0 && len(num)-lastDot-1 != 3:
		decimal = lastDot
	case lastComma >= 0 && len(num)-lastComma-1 != 3:
		decimal = lastComma
	}
	var b strings.Builder
	for i, r := range num {
		switch {
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case i == decimal:
			b.WriteByte('.')
		}
	}
	f, err := strconv.ParseFloat(b.String(), 64)
	if err != nil {
		return 0, false
	}
	rest := strings.ToLower(v[end:])
	switch {
	case strings.HasPrefix(strings.TrimSpace(rest), "bn"), strings.HasPrefix(strings.TrimSpace(rest), "billion"):
		f *= 1e9
	case strings.HasPrefix(strings.TrimSpace(rest), "m"):
		f *= 1e6
	case strings.HasPrefix(strings.TrimSpace(rest), "k"), strings.HasPrefix(strings.TrimSpace(rest), "thousand"):
		f *= 1e3
	}
	return f, true
}
