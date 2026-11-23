// Command log-processor redacts logs between a collector and its destination.
package main

import (
	"context"
	"log"
	"net/http"
	"onshore/data-plane/internal/license"
	"onshore/data-plane/internal/rules"
	"os"
	"os/signal"
	"syscall"
	"time"

	"onshore/data-plane/ee/logproc"
	"onshore/data-plane/internal/detect"
	"onshore/data-plane/internal/netguard"
	"onshore/data-plane/internal/store"
	"onshore/data-plane/internal/tlsutil"
	"onshore/data-plane/internal/vault"

	_ "onshore/data-plane/ee/nlp" // paid: language-model detection, when RV_NLP_URL is set
)

func must(k string) string {
	v := os.Getenv(k)
	if v == "" {
		log.Fatalf("%s is required", k)
	}
	return v
}

func main() {
	license.LogStartup("log-processor") // paid service: see ee/LICENSE; the vault enforces the edition
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	pool, err := store.Open(ctx, must("DATABASE_URL"))
	if err != nil {
		log.Fatal("database connection failed")
	}
	defer pool.Close()
	vaultHTTP, err := tlsutil.Client(os.Getenv("RV_TLS_CERT"), os.Getenv("RV_TLS_KEY"), os.Getenv("RV_TLS_CLIENT_CA"), 10*time.Second)
	if err != nil {
		log.Fatal(err)
	}
	engineConfig := detect.Config{PaymentRefs: true, FormatPreservingPrefixes: []string{vault.FPPrefixID, vault.FPPrefixPhone}, IsOwnToken: func(v string) bool {
		c, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		var ok bool
		return pool.QueryRow(c, `SELECT EXISTS (SELECT 1 FROM data.tokens WHERE token=$1)`, v).Scan(&ok) == nil && ok
	}}
	st := &rules.Store{
		Source:    &rules.HTTPSource{BaseURL: must("VAULT_INTERNAL_URL"), Token: must("RV_INTERNAL_TOKEN"), HTTP: vaultHTTP},
		NewEngine: func(t map[string]float64) *detect.Engine { return detect.New(engineConfig.WithThresholds(t)) },
	}
	go st.Run(ctx, pool)
	s := &logproc.Server{
		Pool: pool,
		Processor: &logproc.Processor{Engine: detect.New(engineConfig), Rules: st, Tokenizer: &logproc.VaultClient{
			BaseURL: must("VAULT_INTERNAL_URL"), Token: must("RV_INTERNAL_TOKEN"), HTTP: vaultHTTP,
		}},
		Upstream:  netguard.Client(20*time.Second, os.Getenv("RV_ALLOW_PRIVATE_UPSTREAM") == "true"),
		AllowHTTP: os.Getenv("RV_ALLOW_HTTP_UPSTREAM") == "true",
	}
	s.Counters.Rules = st
	if err := s.Refresh(ctx); err != nil {
		log.Fatal("could not load pipelines")
	}
	go s.Run(ctx)
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":8090"
	}
	hs := &http.Server{Addr: addr, Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: time.Minute, WriteTimeout: time.Minute}
	go func() {
		<-ctx.Done()
		sc, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		hs.Shutdown(sc)
	}()
	log.Printf("log-processor listening on %s", addr)
	if cert := os.Getenv("RV_TLS_CERT"); cert != "" {
		if hs.TLSConfig, err = tlsutil.ServerConfig(os.Getenv("RV_TLS_CLIENT_CA")); err != nil {
			log.Fatal(err)
		}
		err = hs.ListenAndServeTLS(cert, os.Getenv("RV_TLS_KEY"))
	} else {
		err = hs.ListenAndServe()
	}
	if err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
