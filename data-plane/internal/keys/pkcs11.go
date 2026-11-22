//go:build hsm

package keys

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync"

	"github.com/miekg/pkcs11"
)

func init() { openPKCS11 = NewPKCS11FromEnv }

// PKCS11 wraps data keys under a KEK created inside the HSM, which never leaves it.
// Each KEK version is a separate non-extractable AES key, labelled <label>-<version>.
// The wrapped format is 1 version byte | 12 byte IV | AES-GCM ciphertext and tag.
type PKCS11 struct {
	mu      sync.Mutex
	ctx     *pkcs11.Ctx
	session pkcs11.SessionHandle
	label   string
	version int
}

// NewPKCS11FromEnv uses PKCS11_MODULE, PKCS11_SLOT_LABEL, PKCS11_PIN and PKCS11_KEY_LABEL.
func NewPKCS11FromEnv() (Service, error) {
	mod := os.Getenv("PKCS11_MODULE")
	c := pkcs11.New(mod)
	if c == nil {
		return nil, errors.New("could not load PKCS11_MODULE")
	}
	if err := c.Initialize(); err != nil {
		return nil, errors.New("the PKCS#11 module did not initialise")
	}
	slots, err := c.GetSlotList(true)
	if err != nil {
		return nil, errors.New("could not list HSM slots")
	}
	want := os.Getenv("PKCS11_SLOT_LABEL")
	var slot uint
	found := false
	for _, s := range slots {
		info, err := c.GetTokenInfo(s)
		if err == nil && trim(info.Label) == want {
			slot, found = s, true
			break
		}
	}
	if !found {
		return nil, errors.New("no HSM token has that PKCS11_SLOT_LABEL")
	}
	sess, err := c.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, errors.New("could not open an HSM session")
	}
	if err := c.Login(sess, pkcs11.CKU_USER, os.Getenv("PKCS11_PIN")); err != nil {
		return nil, errors.New("HSM login failed")
	}
	label := os.Getenv("PKCS11_KEY_LABEL")
	if label == "" {
		label = "rv-kek"
	}
	p := &PKCS11{ctx: c, session: sess, label: label}
	for v := 1; v < 256; v++ {
		if _, err := p.find(v); err != nil {
			break
		}
		p.version = v
	}
	if p.version == 0 {
		if err := p.RotateKEK(context.Background()); err != nil {
			return nil, err
		}
	}
	return p, nil
}

func trim(s string) string {
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == 0) {
		s = s[:len(s)-1]
	}
	return s
}

func (p *PKCS11) Name() string { return "pkcs11" }

func (p *PKCS11) labelFor(v int) string { return p.label + "-" + strconv.Itoa(v) }

func (p *PKCS11) find(v int) (pkcs11.ObjectHandle, error) {
	if err := p.ctx.FindObjectsInit(p.session, []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_LABEL, p.labelFor(v)), pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY)}); err != nil {
		return 0, fmt.Errorf("%w", ErrUnavailable)
	}
	defer p.ctx.FindObjectsFinal(p.session)
	objs, _, err := p.ctx.FindObjects(p.session, 1)
	if err != nil || len(objs) == 0 {
		return 0, errors.New("no such key version")
	}
	return objs[0], nil
}

// RotateKEK creates the next version inside the HSM, marked non-extractable.
func (p *PKCS11) RotateKEK(context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	next := p.version + 1
	if next > 255 {
		return errors.New("KEK version limit reached")
	}
	_, err := p.ctx.GenerateKey(p.session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil)}, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY), pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES), pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, 32),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true), pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true), pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true), pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true), pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true), pkcs11.NewAttribute(pkcs11.CKA_LABEL, p.labelFor(next)),
	})
	if err != nil {
		return ErrUnavailable
	}
	p.version = next
	return nil
}

func (p *PKCS11) Wrap(_ context.Context, pt, aad []byte) ([]byte, string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	k, err := p.find(p.version)
	if err != nil {
		return nil, "", ErrUnavailable
	}
	iv := make([]byte, 12)
	if _, err := rand.Read(iv); err != nil {
		return nil, "", err
	}
	m := pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, pkcs11.NewGCMParams(iv, aad, 128))
	if err := p.ctx.EncryptInit(p.session, []*pkcs11.Mechanism{m}, k); err != nil {
		return nil, "", ErrUnavailable
	}
	ct, err := p.ctx.Encrypt(p.session, pt)
	if err != nil {
		return nil, "", ErrUnavailable
	}
	return append(append([]byte{byte(p.version)}, iv...), ct...), p.labelFor(p.version), nil
}

func (p *PKCS11) Unwrap(_ context.Context, wrapped, aad []byte) ([]byte, error) {
	if len(wrapped) < 13 {
		return nil, errors.New("bad wrapped key")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	k, err := p.find(int(wrapped[0]))
	if err != nil {
		return nil, ErrUnavailable
	}
	m := pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, pkcs11.NewGCMParams(wrapped[1:13], aad, 128))
	if err := p.ctx.DecryptInit(p.session, []*pkcs11.Mechanism{m}, k); err != nil {
		return nil, ErrUnavailable
	}
	pt, err := p.ctx.Decrypt(p.session, wrapped[13:])
	if err != nil {
		return nil, errors.New("the key did not unwrap")
	}
	return pt, nil
}

func (p *PKCS11) Rewrap(ctx context.Context, wrapped, aad []byte) ([]byte, string, error) {
	pt, err := p.Unwrap(ctx, wrapped, aad)
	if err != nil {
		return nil, "", err
	}
	return p.Wrap(ctx, pt, aad)
}

func (p *PKCS11) Health(context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, err := p.find(p.version); err != nil {
		return ErrUnavailable
	}
	return nil
}

func valueAttr() []*pkcs11.Attribute {
	return []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil)}
}
