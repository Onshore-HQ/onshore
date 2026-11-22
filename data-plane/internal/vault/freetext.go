package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"regexp"
)

// longNumber is ten or more digits, with the separators people type between them.
var longNumber = regexp.MustCompile(`\d(?:[ .\-/]?\d){9,}`)

// stripLongNumbers is the audit log's own rule, stricter than detection. In traffic, a
// word such as "ticket" or "order" before a number is good evidence it is not personal,
// and missing it there can be tuned. Free text bound for an exported, permanent log has
// no such allowance: "support ticket 22333444558" may hold a BVN, and a ten-digit
// reference is worth losing if the alternative is keeping one.
func stripLongNumbers(p string) string {
	return longNumber.ReplaceAllString(p, "[number removed]")
}

// A client token's subject ref waits in the database until the token is redeemed. The
// product does not keep subject refs readable, so it is sealed under a key derived from
// the raw token, which is stored only as a hash: a dump of the table cannot open it.
func subjectKey(raw string) (cipher.AEAD, error) {
	m := hmac.New(sha256.New, []byte(raw))
	m.Write([]byte("rv-client-token-subject-ref-v1"))
	b, err := aes.NewCipher(m.Sum(nil))
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

func sealSubject(raw, subject string) (string, error) {
	if subject == "" {
		return "", nil
	}
	a, err := subjectKey(raw)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, a.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(a.Seal(nonce, nonce, []byte(subject), nil)), nil
}

func openSubject(raw, sealed string) (string, error) {
	if sealed == "" {
		return "", nil
	}
	a, err := subjectKey(raw)
	if err != nil {
		return "", err
	}
	b, err := base64.RawStdEncoding.DecodeString(sealed)
	if err != nil || len(b) < a.NonceSize() {
		return "", errors.New("sealed subject is malformed")
	}
	p, err := a.Open(nil, b[:a.NonceSize()], b[a.NonceSize():], nil)
	return string(p), err
}
