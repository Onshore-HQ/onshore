// Package tlsutil builds TLS 1.3 configurations for traffic between services,
// and issues the private CA and service certificates that `rv init` writes.
package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// ServerConfig requires TLS 1.3, and client certificates when clientCA is set.
func ServerConfig(clientCA string) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS13}
	if clientCA != "" {
		pool, err := loadPool(clientCA)
		if err != nil {
			return nil, err
		}
		cfg.ClientCAs, cfg.ClientAuth = pool, tls.RequireAndVerifyClientCert
	}
	return cfg, nil
}

func loadPool(path string) (*x509.CertPool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil, fmt.Errorf("no certificates in %s", path)
	}
	return pool, nil
}

// Client builds an HTTP client that verifies the internal CA and presents the
// service's own certificate. With no paths set it is a plain client (development).
func Client(cert, key, ca string, timeout time.Duration) (*http.Client, error) {
	c := &http.Client{Timeout: timeout}
	if ca == "" {
		return c, nil
	}
	pool, err := loadPool(ca)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool}
	if cert != "" {
		pair, err := tls.LoadX509KeyPair(cert, key)
		if err != nil {
			return nil, err
		}
		cfg.Certificates = []tls.Certificate{pair}
	}
	c.Transport = &http.Transport{TLSClientConfig: cfg}
	return c, nil
}

// Services lists who gets an internal certificate; each name is also its DNS name.
var Services = []string{"edge", "vault-api", "control-api", "console", "log-processor", "ai-gateway", "http-proxy", "adapters", "file-redactor", "nlp", "postgres", "keys", "tools"}

// IssueAll writes a CA and a certificate per service under dir/<service>/. The CA
// private key is discarded once the leaves exist, so no later certificate can be
// minted from this directory; re-running `rv init` issues a new set.
func IssueAll(dir string, validFor time.Duration) error {
	if _, err := os.Stat(filepath.Join(dir, "edge", "cert.pem")); err == nil {
		return errors.New(dir + " already holds certificates")
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	now := time.Now()
	caTpl := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "Onshore internal CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(validFor), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, MaxPathLenZero: true}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, caKey.Public(), caKey)
	if err != nil {
		return err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return err
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	for _, svc := range Services {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		tpl := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: svc}, DNSNames: []string{svc}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(validFor), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
		der, err := x509.CreateCertificate(rand.Reader, tpl, caCert, key.Public(), caKey)
		if err != nil {
			return err
		}
		keyDER, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return err
		}
		sd := filepath.Join(dir, svc)
		// World-readable inside a 0700 parent: each container runs as its own user,
		// and a bind mount cannot change ownership.
		if err := os.MkdirAll(sd, 0o755); err != nil {
			return err
		}
		for name, body := range map[string][]byte{"ca.pem": caPEM, "cert.pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), "key.pem": pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})} {
			if err := os.WriteFile(filepath.Join(sd, name), body, 0o644); err != nil {
				return err
			}
		}
	}
	return nil
}

func serial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		panic(err)
	}
	return n
}
