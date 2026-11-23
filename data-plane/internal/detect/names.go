package detect

// commonNames is the phase-1 dictionary of common Nigerian first and last
// names (Igbo, Yoruba, Hausa, Edo/Delta, plus widely used English given names).
// A named-entity model is out of scope for the MVP.
var commonNames = []string{
	"adaeze", "adaobi", "adanna", "amaka", "amarachi", "anayo", "azubuike", "chiamaka", "chibueze", "chidera", "chidi", "chidimma",
	"chiedu", "chigozie", "chijioke", "chika", "chima", "chinedu", "chinelo", "chinonso", "chinwe", "chinyere", "chioma", "chisom",
	"chukwudi", "chukwuemeka", "chukwuma", "ebuka", "ejiofor", "ekene", "emeka", "ifeanyi", "ifeoma", "ikechukwu", "ikenna", "kamsi", "kelechi",
	"kosisochukwu", "nkechi", "nkem", "nnamdi", "nneka", "nonso", "obinna", "obi", "ogechi", "okechukwu", "onyeka", "somto", "tochi", "tochukwu", "uchenna", "uche", "ugochi", "ugochukwu",
	"adebayo", "adebola", "adedayo", "adedeji", "adekunle", "ademola", "adenike", "adesola", "adewale", "adeola", "adetola", "adunni", "ayo", "ayodele", "ayodeji", "ayomide", "babajide", "babatunde", "bisi", "bolaji", "bolanle", "damilola", "dayo", "femi", "folake", "folasade", "funke", "funmilayo", "gbenga", "ibukun", "kayode", "kehinde", "kemi", "kunle", "lanre", "mojisola", "morenike", "niyi", "olamide", "olanrewaju", "olawale", "olayinka", "olubunmi", "olufemi", "olumide", "oluwaseun", "oluwatobi", "omolara", "opeyemi", "segun", "seun", "shade", "sola", "taiwo", "temitope", "titi", "tobi", "tola", "tolani", "tope", "tunde", "wale", "wasiu", "yemi", "yetunde", "yinka",
	"abdullahi", "abubakar", "adamu", "ahmad", "ahmed", "aisha", "aishatu", "aliyu", "amina", "aminu", "bala", "bashir", "bello", "binta", "dauda", "fatima", "garba", "habiba", "hadiza", "halima", "haruna", "hauwa", "hussaini", "ibrahim", "idris", "isa", "ismail", "jamila", "khadija", "kabiru", "lawal", "maryam", "muhammad", "muhammadu", "musa", "mustapha", "nasiru", "rabiu", "rakiya", "sadiq", "safiya", "salisu", "sani", "shehu", "suleiman", "umar", "usman", "yahaya", "yakubu", "yusuf", "zainab",
	"efe", "ese", "eseoghene", "oghenekaro", "oghenetega", "ejiro", "ufuoma", "edafe", "osagie", "osaze", "etinosa", "itohan", "ehis", "ekaette", "imaobong", "ini", "aniekan", "ubong", "emem", "tamuno", "ebiere", "preye", "tonye", "boma",
	"okafor", "okonkwo", "okoye", "okeke", "okoro", "okpara", "okereke", "nwosu", "nwachukwu", "nwankwo", "nwafor", "nwobi", "eze", "ezeokeke", "ezeh", "onyekachi", "onuoha", "obi", "ogbonna", "ibekwe", "igwe", "iwu", "anyanwu", "agu", "umeh", "chukwu", "madu", "mbah", "ani", "uzor",
	"adeyemi", "adeleke", "adeniyi", "adewole", "adeyinka", "afolabi", "ajayi", "akande", "akinola", "alabi", "aluko", "ayeni", "babalola", "balogun", "bamidele", "fashola", "ogunleye", "ogunbanjo", "ogundipe", "ojo", "olaniyan", "oyebanji", "oyelaran", "oyewole", "salami", "sanusi", "shittu", "sowemimo", "sulaimon", "tinubu", "lawani",
	"danjuma", "dangote", "gambo", "jibril", "kano", "maikano", "mohammed", "mohammad", "tanko", "tukur", "waziri",
	"blessing", "chiderah", "david", "emmanuel", "esther", "faith", "gift", "godwin", "grace", "john", "joseph", "joy", "kingsley", "mary", "michael", "patience", "paul", "peace", "peter", "precious", "samuel", "sunday", "victor", "victoria", "stella", "ngozi", "nkiru", "oluchi", "oge", "obiageli", "rita", "ruth", "sarah", "daniel", "james", "felix", "friday", "innocent", "benjamin", "charles", "christian", "francis", "gabriel", "henry", "isaac", "jacob", "sandra", "vivian", "juliet", "helen", "florence", "comfort", "deborah", "ibidun", "idowu", "alaba",
}

// ambiguousNames are dictionary words that are also ordinary English; they only
// count when another signal supports them.
var ambiguousNames = map[string]bool{
	"blessing": true, "faith": true, "gift": true, "grace": true, "joy": true, "patience": true, "peace": true,
	"precious": true, "sunday": true, "friday": true, "innocent": true, "comfort": true, "kano": true, "shade": true,
	"mary": false, "bala": false,
}

// nameStopwords never start or extend a capitalised name run.
var nameStopwords = map[string]bool{
	"the": true, "my": true, "your": true, "our": true, "this": true, "that": true, "please": true, "failed": true, "error": true,
	"bank": true, "account": true, "customer": true, "transfer": true, "payment": true, "user": true, "name": true, "and": true,
	"to": true, "from": true, "for": true, "with": true, "is": true, "was": true, "na": true, "abeg": true, "dear": true, "hello": true, "hi": true,
	// Pronouns and their contractions start with a capital at the start of a sentence
	// ("I'm Sarah Johnson"), but are never part of the name.
	"i": true, "i'm": true, "i've": true, "i'll": true, "i'd": true, "we": true, "we're": true, "you": true, "you're": true,
	"he": true, "she": true, "he's": true, "she's": true, "they": true, "it": true, "it's": true, "am": true, "this's": true,
	"thanks": true, "regards": true, "first": true, "access": true, "union": true, "zenith": true, "sterling": true, "wema": true, "polaris": true, "lagos": true, "abuja": true, "nigeria": true, "street": true, "road": true, "limited": true, "ltd": true, "plc": true,
	"service": true, "services": true, "team": true, "support": true, "office": true, "department": true, "officer": true, "desk": true, "center": true, "centre": true, "manager": true, "branch": true, "care": true, "agent": true, "group": true, "company": true,
	"january": true, "february": true, "march": true, "april": true, "may": true, "june": true, "july": true, "august": true, "september": true, "october": true, "november": true, "december": true,
	// Verbs and nouns that open a sentence or a note ("Refund Sarah Johnson", "Email
	// her"), capitalised there but never a name. Words that are also first names
	// (Bill, Will, Mark, Grant, Chase) stay out.
	"refund": true, "email": true, "call": true, "contact": true, "send": true, "check": true, "ask": true, "tell": true,
	"cancel": true, "update": true, "verify": true, "confirm": true, "charge": true, "pay": true, "notify": true, "remind": true,
	"invoice": true, "order": true, "ticket": true, "note": true, "urgent": true, "client": true, "patient": true, "attn": true,
	"approve": true, "block": true, "unblock": true, "close": true, "reset": true, "review": true, "escalate": true, "message": true,
	"re": true, "fw": true, "fwd": true, "kindly": true, "contacted": true, "called": true, "emailed": true, "refunded": true, "charged": true,
	"monday": true, "tuesday": true, "wednesday": true, "thursday": true, "saturday": true, "mr": true, "mrs": true, "miss": true, "ms": true, "dr": true, "chief": true, "alhaji": true, "alhaja": true, "engr": true, "prof": true, "sir": true, "madam": true, "mallam": true,
}
