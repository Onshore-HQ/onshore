package detect

import (
	_ "embed"
	"encoding/json"
)

// NUBAN rules come from the CBN's "Revised Standards on Nigeria Uniform Bank
// Account Number (NUBAN) for Banks and Other Financial Institutions" (2019):
// a 16-digit structure ABCDEF-GHIJKLMNO-P, of which the customer sees the
// 10-digit GHIJKLMNOP. ABCDEF is a 3-digit DMB code with three leading zeros, or
// a 5-digit OFI code with a leading 9. Weights repeat 3,7,3 over 15 positions.
//
// Six-digit routing codes such as OPay's 999992 are not covered by the standard;
// they are tried as-is. Some newer institutions are reported to use non-standard
// numbers, so a failed check lowers confidence and never clears a value.

//go:embed institutions.json
var institutionsJSON []byte

// Institution is one financial institution code.
type Institution struct {
	Code string `json:"code"`
	Name string `json:"name"`
}

func loadInstitutions() []Institution {
	var f struct {
		Institutions []Institution `json:"institutions"`
	}
	if err := json.Unmarshal(institutionsJSON, &f); err != nil {
		panic("detect: bad institutions.json")
	}
	return f.Institutions
}

// Institutions lists the embedded codes.
var Institutions = loadInstitutions()

// nubanSeed builds the 6-digit ABCDEF prefix from an institution code.
func nubanSeed(code string) string {
	switch len(code) {
	case 3:
		return "000" + code
	case 5:
		return "9" + code
	}
	return code
}

var nubanWeights = [15]int{3, 7, 3, 3, 7, 3, 3, 7, 3, 3, 7, 3, 3, 7, 3}

// NUBANCheckDigit computes P for an institution code and 9-digit serial.
func NUBANCheckDigit(code, serial string) int {
	s := nubanSeed(code) + serial
	sum := 0
	for i := 0; i < len(nubanWeights) && i < len(s); i++ {
		sum += int(s[i]-'0') * nubanWeights[i]
	}
	return (10 - sum%10) % 10
}

// ValidNUBANFor reports whether a 10-digit number passes for this institution.
func ValidNUBANFor(code, n string) bool {
	return len(n) == 10 && NUBANCheckDigit(code, n[:9]) == int(n[9]-'0')
}

// ValidLuhn reports whether a digit string passes the Luhn check.
func ValidLuhn(n string) bool {
	sum, double := 0, false
	for i := len(n) - 1; i >= 0; i-- {
		d := int(n[i] - '0')
		if double {
			if d *= 2; d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return len(n) > 0 && sum%10 == 0
}

// isVerve covers both published descriptions: IINs 506099-506198, 507865-507964
// and 650002-650027 (16, 18 or 19 digits), and Paystack's wider client pattern,
// ^((506(0|1))|(507(8|9))|(6500))[0-9]{12,15}$. Paystack does not apply Luhn to
// Verve, so a Verve-shaped number counts without one.
func isVerve(n string) bool {
	if len(n) < 16 || len(n) > 19 {
		return false
	}
	p := n[:4]
	return p == "5060" || p == "5061" || p == "5078" || p == "5079" || p == "6500"
}

func knownCardBIN(n string) bool {
	if len(n) < 6 {
		return false
	}
	switch {
	case n[0] == '4':
		return len(n) == 13 || len(n) == 16 || len(n) == 19
	case n[0] == '5' && n[1] >= '1' && n[1] <= '5':
		return len(n) == 16
	case n[0] == '2' && n[1] >= '2' && n[1] <= '7':
		return len(n) == 16
	}
	return isVerve(n)
}
