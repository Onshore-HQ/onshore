package detect

import (
	"fmt"
	"math/rand"
	"strings"
)

// Label marks where a synthetic identifier sits in a generated sample.
type Label struct {
	Type       EntityType
	Start, End int
}

// Sample is one labelled corpus line. All identifiers are randomly generated;
// real customer data is never used to train or test.
type Sample struct {
	Text   string
	Labels []Label
}

// Corpus generates labelled logs, support messages, JSON and Pidgin snippets.
type Corpus struct{ r *rand.Rand }

func NewCorpus(seed int64) *Corpus { return &Corpus{r: rand.New(rand.NewSource(seed))} }

func (c *Corpus) digits(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte('0' + c.r.Intn(10))
	}
	return string(b)
}

// Intn exposes the generator's randomness to callers building synthetic data.
func (c *Corpus) Intn(n int) int { return c.r.Intn(n) }

// BVN makes no assumption about leading digits: no source supports a fixed prefix.
func (c *Corpus) BVN() string { return string(byte('1'+c.r.Intn(9))) + c.digits(10) }
func (c *Corpus) NIN() string { return string(byte('1'+c.r.Intn(9))) + c.digits(10) }

func (c *Corpus) NUBAN() string {
	code := Institutions[c.r.Intn(len(Institutions))].Code
	serial := c.digits(9)
	return fmt.Sprintf("%s%d", serial, NUBANCheckDigit(code, serial))
}

func (c *Corpus) Phone() string {
	prefix := []string{"0712", "0721", "0916", "0803", "0806", "0810", "0813", "0814", "0816", "0703", "0706", "0805", "0807", "0811", "0815", "0705", "0905", "0802", "0808", "0812", "0701", "0708", "0902", "0901", "0809", "0817", "0818", "0908", "0909"}
	p := prefix[c.r.Intn(len(prefix))] + c.digits(7)
	switch c.r.Intn(4) {
	case 0:
		return "+234" + p[1:]
	case 1:
		return "234" + p[1:]
	case 2:
		return p[:4] + " " + p[4:7] + " " + p[7:]
	}
	return p
}

func (c *Corpus) Card() string {
	var body string
	switch c.r.Intn(3) {
	case 0:
		body = "4" + c.digits(14)
	case 1:
		body = "5" + string(byte('1'+c.r.Intn(5))) + c.digits(13)
	default:
		body = "506" + string([]byte{'1', '0'}) + c.digits(10)
	}
	for d := 0; d < 10; d++ {
		n := body + string(byte('0'+d))
		if ValidLuhn(n) {
			if c.r.Intn(2) == 0 {
				return n[:4] + " " + n[4:8] + " " + n[8:12] + " " + n[12:]
			}
			return n
		}
	}
	return body
}

func (c *Corpus) Email() string {
	domains := []string{"gmail.com", "yahoo.com", "outlook.com", "example.ng", "mail.example.com.ng"}
	return strings.ToLower(c.Name()[:3]) + c.digits(3) + "@" + domains[c.r.Intn(len(domains))]
}

func (c *Corpus) Name() string {
	pick := func() string {
		for {
			n := commonNames[c.r.Intn(len(commonNames))]
			if !ambiguousNames[n] && len(n) >= 3 {
				return strings.ToUpper(n[:1]) + n[1:]
			}
		}
	}
	return pick() + " " + pick()
}

func (c *Corpus) Amount() string {
	n := 1000 + c.r.Intn(4_999_000)
	s := fmt.Sprintf("%d", n)
	if len(s) > 3 {
		s = s[:len(s)-3] + "," + s[len(s)-3:]
	}
	if len(s) > 7 {
		s = s[:len(s)-7] + "," + s[len(s)-7:]
	}
	switch c.r.Intn(3) {
	case 0:
		return "₦" + s
	case 1:
		return "NGN " + s
	}
	return "N" + s
}

func (c *Corpus) DOB() string {
	y, m, d := 1950+c.r.Intn(55), 1+c.r.Intn(12), 1+c.r.Intn(28)
	if c.r.Intn(2) == 0 {
		return fmt.Sprintf("%04d-%02d-%02d", y, m, d)
	}
	return fmt.Sprintf("%02d/%02d/%04d", d, m, y)
}

// template placeholders: {bvn} {nin} {nuban} {phone} {card} {email} {name} {amount} {dob}
// and {x:...} for unlabelled noise values.
var positiveTemplates = []string{
	// application logs
	`2026-11-03T10:15:22Z INFO transfer created account={nuban} amount={amount} status=pending`,
	`level=error msg="NIBSS name enquiry failed" bvn={bvn} account_number={nuban}`,
	`[payments] debit failed for acct {nuban}, customer phone {phone}`,
	`WARN kyc: verification mismatch nin={nin} name="{name}" dob={dob}`,
	`card declined pan={card} acct={nuban}`,
	`user {email} updated phone to {phone}`,
	`POST /v2/kyc 200 bvn={bvn} latency=23ms`,
	`processing payout to beneficiary account {nuban} ({name})`,
	`sms sent to {phone}: Your balance is {amount}`,
	`customer.email={email} customer.bvn={bvn}`,
	// JSON
	`{"event":"kyc.submitted","bvn":"{bvn}","nin":"{nin}","phone":"{phone}"}`,
	`{"account_number":"{nuban}","bank":"GTB","amount":"{amount}","customer_name":"{name}"}`,
	`{"user":{"email":"{email}","phone_number":"{phone}","date_of_birth":"{dob}"}}`,
	`{"payment":{"card_number":"{card}","holder":"{name}"}}`,
	// support messages
	`Hello, my BVN is {bvn} and my account number is {nuban}. Please help.`,
	`I transferred {amount} to {nuban} yesterday and it has not arrived.`,
	`Please call me on {phone}, my name is {name}.`,
	`My NIN is {nin}, date of birth {dob}.`,
	`Mr {name} reported a failed debit on his card {card}.`,
	`Customer name: {name}, email {email}, whatsapp {phone}`,
	`Kindly reverse {amount} debited from a/c {nuban}`,
	`Alhaji {name} said his national identity number is {nin}`,
	// Pidgin
	`Abeg check my BVN, na {bvn}`,
	`My acct no be {nuban}, dem never credit me`,
	`Oga abeg, I send {amount} enter {nuban} since morning`,
	`Abeg call my line {phone}, my name na {name}`,
	`Na {nin} be my NIN, dem say e no correct`,
	`Dem debit my account {nuban} {amount} and no alert`,
}

var negativeTemplates = []string{
	`ts={epoch} level=info msg="heartbeat ok"`,
	`timestamp: {epoch} service=ledger healthy`,
	`order_id={d10} status=shipped`,
	`Order {d10} has been dispatched.`,
	`session_id={d10} expired after 900s`,
	`ref={d11} completed`,
	`reference: {d11}`,
	`trace_id={hex32} span_id={hex16} duration=120ms`,
	`request_id={uuid} status=200`,
	`build version {d3}.{d2}.{d4} deployed`,
	`pid={d5} thread={d4} bytes={d7}`,
	`invoice {d10} sent to accounts team`,
	`Lagos branch opened at 9am, closed at 5pm.`,
	`The Access Bank mobile app was upgraded on 2026-10-14.`,
	`Please reset the password and try again.`,
	`The quick brown fox visited First Bank on Monday.`,
	`GET /api/v1/health 200 3ms`,
	`Grace period ends on Friday. Sunday service was moved.`,
	`meeting moved to 2026-11-05 for the Abuja team`,
	`N95 masks and N2 cells restocked`,
	`rrn={d12} approved`,
	`sku={d13} qty=2`,
	`request {d19} retried 3 times`,
	`Customer Service Team replied to the Lagos Office`,
}

// Sample generates one labelled line.
func (c *Corpus) Sample() Sample {
	if c.r.Intn(4) == 0 {
		return c.fill(negativeTemplates[c.r.Intn(len(negativeTemplates))])
	}
	return c.fill(positiveTemplates[c.r.Intn(len(positiveTemplates))])
}

func (c *Corpus) hex(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = "0123456789abcdef"[c.r.Intn(16)]
	}
	return string(b)
}

func (c *Corpus) fill(tpl string) Sample {
	var b strings.Builder
	var labels []Label
	for i := 0; i < len(tpl); {
		if tpl[i] != '{' {
			b.WriteByte(tpl[i])
			i++
			continue
		}
		end := strings.IndexByte(tpl[i:], '}')
		if end < 0 {
			b.WriteString(tpl[i:])
			break
		}
		key := tpl[i+1 : i+end]
		var v string
		var t EntityType
		switch key {
		case "bvn":
			v, t = c.BVN(), BVN
		case "nin":
			v, t = c.NIN(), NIN
		case "nuban":
			v, t = c.NUBAN(), NUBAN
		case "phone":
			v, t = c.Phone(), PhoneNG
		case "card":
			v, t = c.Card(), CardPAN
		case "email":
			v, t = c.Email(), Email
		case "name":
			v, t = c.Name(), PersonName
		case "amount":
			v, t = c.Amount(), AmountNGN
		case "dob":
			v, t = c.DOB(), DOB
		case "epoch":
			v = fmt.Sprintf("%d", 1700000000+c.r.Intn(90000000))
		case "hex32":
			v = c.hex(32)
		case "hex16":
			v = c.hex(16)
		case "uuid":
			v = c.hex(8) + "-" + c.hex(4) + "-" + c.hex(4) + "-" + c.hex(4) + "-" + c.hex(12)
		case "d2", "d3", "d4", "d5", "d7", "d10", "d11", "d12", "d13", "d19":
			var n int
			fmt.Sscanf(key[1:], "%d", &n)
			v = c.digits(n)
		default:
			// Literal JSON brace, not a placeholder.
			b.WriteByte('{')
			i++
			continue
		}
		if t != "" {
			labels = append(labels, Label{t, b.Len(), b.Len() + len(v)})
		}
		b.WriteString(v)
		i += end + 1
	}
	return Sample{Text: b.String(), Labels: labels}
}
