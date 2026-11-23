// Command vault-api serves the data API and internal API.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	_ "onshore/data-plane/ee/hsm"      // paid: HSM key backend (Enterprise, -tags hsm)
	_ "onshore/data-plane/ee/vaultapi" // paid: Business routes (see ee/LICENSE)
	"onshore/data-plane/internal/auth"
	"onshore/data-plane/internal/httpapi"
	"onshore/data-plane/internal/keys"
	"onshore/data-plane/internal/license"
	"onshore/data-plane/internal/store"
	"onshore/data-plane/internal/tlsutil"
	"onshore/data-plane/internal/vault"

	_ "onshore/data-plane/ee/nlp" // paid: language-model detection, when RV_NLP_URL is set
)

var version = "dev"

func must(k string) string {
	v := os.Getenv(k)
	if v == "" {
		log.Fatalf("%s is required", k)
	}
	return v
}

func authLimit() int {
	if v, err := strconv.Atoi(os.Getenv("RV_AUTH_FAILURES_PER_MINUTE")); err == nil {
		return v
	}
	return 120
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := store.Open(ctx, must("DATABASE_URL"))
	if err != nil {
		log.Fatal("database connection failed")
	}
	defer pool.Close()
	k, err := keys.Open(must("KEY_BACKEND"), os.Getenv("RV_ENV") == "production")
	if err != nil {
		log.Fatal(err)
	}
	license.LogStartup("vault-api")
	// An HSM without Enterprise only warns: a licence never cuts access to data.
	if k.Name() == "pkcs11" && !license.Current().Has(license.Enterprise) {
		log.Print("vault-api: the HSM key backend is part of Onshore Enterprise; this install has no Enterprise licence")
	}
	seed, err := base64.StdEncoding.DecodeString(must("RV_TOKEN_SIGNING_SEED"))
	if err != nil || len(seed) != ed25519.SeedSize {
		log.Fatal("RV_TOKEN_SIGNING_SEED must be 32 bytes of base64")
	}
	userPub, err := base64.StdEncoding.DecodeString(must("RV_USER_TOKEN_PUBLIC_KEY"))
	if err != nil || len(userPub) != ed25519.PublicKeySize {
		log.Fatal("RV_USER_TOKEN_PUBLIC_KEY must be an Ed25519 public key in base64")
	}
	trusted, err := auth.ParseCIDRs(os.Getenv("RV_TRUSTED_PROXIES"))
	if err != nil {
		log.Fatal(err)
	}
	svc := vault.New(pool, k)
	if path := os.Getenv("RV_GEOIP_CSV"); path != "" {
		g, err := vault.LoadGeoCSV(path)
		if err != nil {
			log.Fatal("could not read RV_GEOIP_CSV")
		}
		svc.Geo = g
	}
	srv := &httpapi.Server{
		Vault:         svc,
		Auth:          &auth.Authenticator{Pool: pool, SigningKey: ed25519.NewKeyFromSeed(seed), UserTokenKey: userPub, Trusted: trusted},
		InternalToken: must("RV_INTERNAL_TOKEN"),
		Version:       version,
		AuthLimiter:   &auth.Limiter{PerMinute: authLimit()},
	}
	svc.StartRules(ctx)
	go svc.RunJobs(ctx)

	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	hs := &http.Server{Addr: addr, Handler: srv.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 2 * time.Minute}
	go func() {
		<-ctx.Done()
		sc, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		hs.Shutdown(sc)
	}()
	log.Printf("vault-api %s listening on %s, key backend %s", version, addr, k.Name())
	if cert := os.Getenv("RV_TLS_CERT"); cert != "" {
		if hs.TLSConfig, err = tlsutil.ServerConfig(os.Getenv("RV_TLS_CLIENT_CA")); err != nil {
			log.Fatal(err)
		}
		err = hs.ListenAndServeTLS(cert, os.Getenv("RV_TLS_KEY"))
	} else {
		if os.Getenv("RV_ENV") == "production" {
			log.Fatal("RV_TLS_CERT is required when RV_ENV=production")
		}
		err = hs.ListenAndServe()
	}
	if err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
