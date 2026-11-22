// Package license checks offline, signed licence files. Expiry never cuts access
// to data: the product warns, and only upgrades stop (spec: licensing).
package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// PublicKeyB64 is set at build time with -ldflags -X. Empty means unlicensed builds
// (development) and every file is reported invalid.
var PublicKeyB64 = ""

// Licence is the signed payload.
type Licence struct {
	Customer   string    `json:"customer"`
	Modules    []string  `json:"modules"`
	Seats      int       `json:"seats"`
	MaxRecords int64     `json:"max_records"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// Sign produces "payload.signature".
func Sign(l Licence, priv ed25519.PrivateKey) (string, error) {
	b, err := json.Marshal(l)
	if err != nil {
		return "", err
	}
	p := base64.RawURLEncoding.EncodeToString(b)
	return p + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(p))), nil
}

// Verify checks a licence against a public key without any network access.
func Verify(blob string, pub ed25519.PublicKey) (Licence, error) {
	var l Licence
	parts := strings.Split(strings.TrimSpace(blob), ".")
	if len(parts) != 2 || len(pub) != ed25519.PublicKeySize {
		return l, errors.New("malformed licence")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || !ed25519.Verify(pub, []byte(parts[0]), sig) {
		return l, errors.New("licence signature is invalid")
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return l, err
	}
	return l, json.Unmarshal(b, &l)
}

// BuiltInKey returns the key compiled into this binary.
func BuiltInKey() (ed25519.PublicKey, error) {
	if PublicKeyB64 == "" {
		return nil, errors.New("this build has no licence public key")
	}
	b, err := base64.StdEncoding.DecodeString(PublicKeyB64)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("bad built-in licence key")
	}
	return b, nil
}

// Expired reports whether the licence has lapsed. Expired licences keep running.
func (l Licence) Expired(now time.Time) bool { return now.After(l.ExpiresAt) }
