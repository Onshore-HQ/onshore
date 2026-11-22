// Package keys wraps and unwraps data keys. The KEK never leaves the backend.
package keys

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// ErrUnavailable means nothing can be decrypted; callers must fail closed.
var ErrUnavailable = errors.New("key service unavailable")

// Service wraps data keys under a KEK held in Nigeria.
type Service interface {
	Wrap(ctx context.Context, plaintext, aad []byte) (wrapped []byte, kekRef string, err error)
	Unwrap(ctx context.Context, wrapped, aad []byte) ([]byte, error)
	// Rewrap re-encrypts a wrapped key under the newest KEK version without exposing it.
	Rewrap(ctx context.Context, wrapped, aad []byte) (newWrapped []byte, kekRef string, err error)
	// RotateKEK creates a new KEK version.
	RotateKEK(ctx context.Context) error
	Health(ctx context.Context) error
	Name() string
}

// openPKCS11 is set by the hsm build (data-plane/ee/hsm, built with -tags hsm),
// which needs cgo and the vendor's library.
var openPKCS11 func() (Service, error)

// RegisterPKCS11 installs the HSM backend. Called from data-plane/ee/hsm.
func RegisterPKCS11(f func() (Service, error)) { openPKCS11 = f }

// Open selects a backend from configuration.
func Open(backend string, production bool) (Service, error) {
	switch backend {
	case "openbao":
		return NewOpenBao(os.Getenv("OPENBAO_ADDR"), os.Getenv("OPENBAO_TOKEN"), envOr("OPENBAO_TRANSIT_KEY", "rv-kek"))
	case "local":
		if production {
			return nil, errors.New("KEY_BACKEND=local is for development only and is refused when RV_ENV=production")
		}
		return NewLocalFile(envOr("LOCAL_KEK_PATH", ".rv-dev-kek"))
	case "pkcs11":
		if openPKCS11 == nil {
			return nil, errors.New("KEY_BACKEND=pkcs11 needs the vault-api-hsm image")
		}
		return openPKCS11()
	}
	return nil, fmt.Errorf("unknown KEY_BACKEND %q", backend)
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

// LocalFile keeps KEK versions in a local file. Development only.
type LocalFile struct {
	path     string
	versions [][]byte
}

// NewLocalFile loads or creates the dev KEK file.
func NewLocalFile(path string) (*LocalFile, error) {
	l := &LocalFile{path: path}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := l.RotateKEK(context.Background()); err != nil {
			return nil, err
		}
		return l, nil
	}
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Fields(string(data)) {
		k, err := base64.StdEncoding.DecodeString(line)
		if err != nil || len(k) != 32 {
			return nil, fmt.Errorf("corrupt KEK file %s", path)
		}
		l.versions = append(l.versions, k)
	}
	if len(l.versions) == 0 {
		return nil, fmt.Errorf("empty KEK file %s", path)
	}
	return l, nil
}

func (l *LocalFile) Name() string                 { return "local" }
func (l *LocalFile) Health(context.Context) error { return nil }

func (l *LocalFile) RotateKEK(context.Context) error {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return err
	}
	l.versions = append(l.versions, k)
	var b strings.Builder
	for _, v := range l.versions {
		b.WriteString(base64.StdEncoding.EncodeToString(v) + "\n")
	}
	return os.WriteFile(l.path, []byte(b.String()), 0o600)
}

func (l *LocalFile) Wrap(_ context.Context, pt, aad []byte) ([]byte, string, error) {
	ver := len(l.versions) - 1
	gcm, err := newGCM(l.versions[ver])
	if err != nil {
		return nil, "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, "", err
	}
	out := append([]byte{byte(ver)}, nonce...)
	return gcm.Seal(out, nonce, pt, aad), fmt.Sprintf("local:v%d", ver+1), nil
}

func (l *LocalFile) Unwrap(_ context.Context, wrapped, aad []byte) ([]byte, error) {
	if len(wrapped) < 13 || int(wrapped[0]) >= len(l.versions) {
		return nil, errors.New("bad wrapped key")
	}
	gcm, err := newGCM(l.versions[wrapped[0]])
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, wrapped[1:13], wrapped[13:], aad)
}

func (l *LocalFile) Rewrap(ctx context.Context, wrapped, aad []byte) ([]byte, string, error) {
	pt, err := l.Unwrap(ctx, wrapped, aad)
	if err != nil {
		return nil, "", err
	}
	return l.Wrap(ctx, pt, aad)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

// OpenBao uses the transit secrets engine; the KEK never leaves OpenBao.
type OpenBao struct {
	addr, token, key string
	http             *http.Client
}

// NewOpenBao configures the transit backend.
func NewOpenBao(addr, token, key string) (*OpenBao, error) {
	if addr == "" || token == "" {
		return nil, errors.New("OPENBAO_ADDR and OPENBAO_TOKEN are required")
	}
	client := &http.Client{Timeout: 5 * time.Second}
	if ca := os.Getenv("OPENBAO_CACERT"); ca != "" {
		b, err := os.ReadFile(ca)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(b) {
			return nil, errors.New("OPENBAO_CACERT holds no certificates")
		}
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool}}
	}
	return &OpenBao{addr: strings.TrimRight(addr, "/"), token: token, key: key, http: client}, nil
}

func (o *OpenBao) Name() string { return "openbao" }

func (o *OpenBao) call(ctx context.Context, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, o.addr+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("X-Vault-Token", o.token)
	resp, err := o.http.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusServiceUnavailable {
		return fmt.Errorf("%w: sealed or standby", ErrUnavailable)
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("openbao %s: status %d", path, resp.StatusCode)
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

type transitResp struct {
	Data struct {
		Ciphertext string `json:"ciphertext"`
		Plaintext  string `json:"plaintext"`
	} `json:"data"`
}

func (o *OpenBao) Wrap(ctx context.Context, pt, aad []byte) ([]byte, string, error) {
	var r transitResp
	err := o.call(ctx, "POST", "/v1/transit/encrypt/"+o.key, map[string]string{
		"plaintext":       base64.StdEncoding.EncodeToString(pt),
		"associated_data": base64.StdEncoding.EncodeToString(aad),
	}, &r)
	if err != nil {
		return nil, "", err
	}
	return []byte(r.Data.Ciphertext), "openbao:" + o.key, nil
}

func (o *OpenBao) Unwrap(ctx context.Context, wrapped, aad []byte) ([]byte, error) {
	var r transitResp
	err := o.call(ctx, "POST", "/v1/transit/decrypt/"+o.key, map[string]string{
		"ciphertext":      string(wrapped),
		"associated_data": base64.StdEncoding.EncodeToString(aad),
	}, &r)
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(r.Data.Plaintext)
}

// Rewrap decrypts and re-encrypts, because OpenBao's transit/rewrap endpoint fails
// on ciphertext bound with associated_data. The key is in this process's memory
// only as long as a normal unwrap would keep it there.
func (o *OpenBao) Rewrap(ctx context.Context, wrapped, aad []byte) ([]byte, string, error) {
	pt, err := o.Unwrap(ctx, wrapped, aad)
	if err != nil {
		return nil, "", err
	}
	return o.Wrap(ctx, pt, aad)
}

// Renew extends the key service token. Without this the vault fails closed when
// the token's year runs out.
func (o *OpenBao) Renew(ctx context.Context) error {
	return o.call(ctx, "POST", "/v1/auth/token/renew-self", map[string]string{}, nil)
}

func (o *OpenBao) RotateKEK(ctx context.Context) error {
	return o.call(ctx, "POST", "/v1/transit/keys/"+o.key+"/rotate", map[string]string{}, nil)
}

func (o *OpenBao) Health(ctx context.Context) error {
	return o.call(ctx, "GET", "/v1/transit/keys/"+o.key, nil, nil)
}
