package detect

// worldNames are common first names and surnames from every region Onshore's
// country packs cover. They join the Nigerian list in one dictionary, so a name is
// found whichever country a vault is in. Like the Nigerian list, they are a
// starting dictionary, not a named-entity model.
var worldNames = []string{
	// English-speaking: United States, United Kingdom, Canada, Ireland
	"james", "john", "robert", "michael", "william", "richard", "joseph", "thomas", "charles", "christopher", "matthew", "anthony",
	"donald", "steven", "andrew", "joshua", "kenneth", "kevin", "brian", "george", "timothy", "ronald", "jason", "edward", "jeffrey",
	"ryan", "jacob", "gary", "nicholas", "eric", "jonathan", "stephen", "larry", "justin", "scott", "brandon", "benjamin", "gregory",
	"alexander", "patrick", "dennis", "tyler", "aaron", "nathan", "henry", "zachary", "douglas", "kyle", "noah", "ethan", "jeremy",
	"walter", "christian", "keith", "roger", "terry", "austin", "sean", "gerald", "carl", "harold", "dylan", "arthur", "lawrence",
	"jordan", "jesse", "bryan", "bruce", "gabriel", "logan", "alan", "albert", "elijah", "wayne", "vincent", "liam", "oliver",
	"lucas", "mason", "callum", "declan", "ciaran", "siobhan", "aoife", "niamh",
	"patricia", "jennifer", "linda", "elizabeth", "barbara", "susan", "jessica", "sarah", "karen", "lisa", "nancy", "betty", "sandra",
	"margaret", "ashley", "kimberly", "emily", "donna", "michelle", "carol", "amanda", "melissa", "deborah", "stephanie", "dorothy",
	"rebecca", "sharon", "laura", "cynthia", "amy", "kathleen", "angela", "shirley", "brenda", "emma", "anna", "pamela", "nicole",
	"samantha", "katherine", "christine", "helen", "debra", "rachel", "carolyn", "janet", "maria", "catherine", "heather", "diane",
	"olivia", "julie", "joyce", "ruth", "virginia", "lauren", "christina", "joan", "evelyn", "judith", "andrea", "hannah", "megan",
	"cheryl", "jacqueline", "martha", "madison", "teresa", "gloria", "sara", "janice", "kathryn", "abigail", "sophia", "isabella",
	"julia", "amber", "denise", "danielle", "marilyn", "beverly", "charlotte", "natalie", "theresa", "diana", "brittany", "kayla",
	"smith", "johnson", "williams", "jones", "garcia", "miller", "davis", "rodriguez", "martinez", "hernandez", "lopez", "gonzalez",
	"wilson", "anderson", "taylor", "moore", "jackson", "martin", "thompson", "harris", "sanchez", "clark", "ramirez", "lewis",
	"robinson", "walker", "allen", "wright", "torres", "nguyen", "flores", "adams", "nelson", "baker", "rivera", "campbell",
	"mitchell", "carter", "roberts", "evans", "turner", "phillips", "parker", "collins", "edwards", "stewart", "morris", "murphy",
	"rogers", "morgan", "cooper", "peterson", "bailey", "richardson", "watson", "bennett", "hughes", "sanders", "myers", "foster",
	"o'brien", "o'connor", "o'sullivan", "kennedy", "mcdonald", "macdonald", "fitzgerald",
	// Germany, Austria, Netherlands
	"lukas", "leon", "finn", "jonas", "elias", "felix", "maximilian", "luca", "emil", "anton", "matthias", "jürgen", "klaus",
	"wolfgang", "stefan", "andreas", "sabine", "ursula", "monika", "petra", "katrin", "anja", "lena", "leonie", "johanna",
	"müller", "mueller", "schmidt", "schneider", "fischer", "weber", "meyer", "wagner", "becker", "schulz", "hoffmann", "schäfer",
	"bauer", "richter", "schröder", "neumann", "zimmermann", "krüger", "hofmann", "hartmann", "schmitt", "werner", "krause",
	"meier", "lehmann", "daan", "sem", "pieter", "bram", "lotte", "sanne", "femke", "jansen", "bakker", "visser", "smit",
	"meijer", "mulder", "dekker",
	// France, Belgium
	"pierre", "louis", "michel", "philippe", "alain", "nicolas", "françois", "julien", "hugo", "théo", "antoine", "camille",
	"chloé", "manon", "inès", "léa", "sophie", "nathalie", "isabelle", "bernard", "dubois", "durand", "lefebvre", "leroy",
	"moreau", "laurent", "simon", "bertrand", "roux", "fournier", "morel", "girard", "andré", "mercier", "dupont", "lambert",
	"bonnet", "rousseau", "fontaine", "chevalier",
	// Spain, Italy, Portugal, Brazil
	"josé", "jose", "juan", "carlos", "luis", "miguel", "javier", "alejandro", "diego", "pablo", "sofía", "lucía", "valentina",
	"camila", "martina", "giulia", "francesco", "alessandro", "lorenzo", "matteo", "marco", "giovanni", "chiara", "joão", "pedro",
	"rafael", "gustavo", "felipe", "beatriz", "larissa", "fernanda", "fernández", "fernandez", "gómez", "gomez", "jiménez",
	"jimenez", "díaz", "diaz", "rossi", "russo", "ferrari", "esposito", "bianchi", "romano", "colombo", "ricci", "marino", "greco",
	"santos", "oliveira", "souza", "pereira", "ferreira", "rodrigues", "almeida", "carvalho", "gomes", "ribeiro", "alves",
	"barbosa", "araújo", "araujo", "cavalcanti",
	// Arabic: Gulf, Egypt
	"ali", "omar", "khalid", "khaled", "abdulrahman", "abdelrahman", "saud", "faisal", "sultan", "hamad", "rashid", "saeed",
	"salem", "nasser", "yousef", "youssef", "mahmoud", "mostafa", "mustafa", "hassan", "hussein", "tariq", "karim", "hamza",
	"ziad", "fahad", "turki", "majid", "nawaf", "mansour", "maryam", "noura", "layla", "hala", "reem", "huda", "salma", "amal",
	"nour", "yasmin", "rania", "hanan", "harbi", "otaibi", "qahtani", "ghamdi", "zahrani", "shehri", "dosari", "mansoori",
	"mazrouei", "kuwari", "marri", "hashimi", "suwaidi", "falasi", "shamsi", "nuaimi", "elsayed", "abdelaziz", "farouk",
	"fawzy", "gamal", "nabil", "sherif", "wael", "tamer", "abdallah",
	// India
	"aarav", "vivaan", "aditya", "vihaan", "arjun", "reyansh", "ishaan", "rohan", "rahul", "amit", "sanjay", "vijay", "ravi",
	"suresh", "ramesh", "rajesh", "anil", "sunil", "deepak", "manoj", "priya", "ananya", "aadhya", "saanvi", "pooja", "neha",
	"anjali", "sneha", "divya", "kavya", "lakshmi", "sunita", "sharma", "verma", "gupta", "singh", "kumar", "patel", "mehta",
	"reddy", "iyer", "nair", "pillai", "menon", "joshi", "desai", "chatterjee", "banerjee", "mukherjee", "agarwal", "malhotra",
	"kapoor", "khanna", "chopra",
	// Singapore and Malaysia
	"tan", "lim", "wong", "goh", "chua", "chan", "koh", "teo", "yeo", "chong", "chia", "nurul", "siti", "hafiz", "aisyah",
	"farah", "izzah", "wei", "jun", "jie", "ming", "hui",
	// Ghana
	"kwame", "kofi", "kwabena", "kwaku", "kojo", "kwesi", "akua", "abena", "adwoa", "afua", "akosua", "efua", "kweku",
	"mensah", "boateng", "owusu", "asante", "osei", "agyeman", "appiah", "amoah", "darko", "ofori", "acheampong", "addo",
	"antwi", "gyamfi", "asamoah", "opoku", "sarpong", "amponsah", "quaye", "tetteh", "quartey",
	// Kenya
	"wanjiru", "wambui", "njeri", "kamau", "mwangi", "otieno", "odhiambo", "ochieng", "onyango", "kiprop", "kipchoge",
	"cheruiyot", "chebet", "wafula", "wekesa", "mutua", "musyoka", "nyambura", "achieng", "akinyi", "atieno", "kibet",
	"kiptoo", "kimani", "njoroge", "macharia", "ruto",
	// South Africa
	"thabo", "sipho", "themba", "lerato", "nomvula", "thandiwe", "bongani", "mandla", "lindiwe", "zanele", "kagiso", "tshepo",
	"palesa", "ayanda", "nkosi", "dlamini", "ndlovu", "khumalo", "mthembu", "mokoena", "molefe", "botha", "pretorius",
	"venter", "naidoo", "pillay",
}

// worldAmbiguous are names that are also everyday words or places; alone they are
// weak evidence, as with the Nigerian list's "Grace" and "Sunday".
var worldAmbiguous = []string{
	"will", "mark", "jack", "rose", "june", "may", "bill", "art", "frank", "hope", "summer", "max", "april", "dawn", "ray",
	"sandy", "jordan", "white", "brown", "green", "young", "king", "hall", "wood", "long", "price", "gray", "grey", "cook",
	"ward", "reed", "said", "ben", "jean", "klein", "wolf", "lange", "lima", "costa", "nana", "simon", "martin", "louis",
	"carol", "amber", "diana", "virginia", "carter", "parker", "turner", "baker", "foster", "wei", "jun", "ming", "tan", "lim",
	"chan", "nour", "hala", "amal", "farah", "sem", "smit", "lee", "ali",
}

func init() {
	for _, n := range worldNames {
		nameSet[n] = true
	}
	for _, n := range worldAmbiguous {
		nameSet[n] = true
		ambiguousNames[n] = true
	}
}
