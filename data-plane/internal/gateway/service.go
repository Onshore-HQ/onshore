package gateway

import (
	"context"
	"log"
	"net/http"
	"onshore/data-plane/internal/detect"
	"onshore/data-plane/internal/rules"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"onshore/data-plane/internal/store"
	"onshore/data-plane/internal/tlsutil"
)

func must(k string) string {
	v := os.Getenv(k)
	if v == "" {
		log.Fatalf("%s is required", k)
	}
	return v
}

// Serve runs a gateway binary: database, vault client, config loop and mutual TLS.
func Serve(ctx context.Context, name, defaultAddr string, setup func(*Deps) (http.Handler, func(context.Context) error, func(context.Context))) {
	pool, err := store.Open(ctx, must("DATABASE_URL"))
	if err != nil {
		log.Fatal("database connection failed")
	}
	defer pool.Close()
	client, err := tlsutil.Client(os.Getenv("RV_TLS_CERT"), os.Getenv("RV_TLS_KEY"), os.Getenv("RV_TLS_CLIENT_CA"), 15*time.Second)
	if err != nil {
		log.Fatal(err)
	}
	deps := &Deps{ctx: ctx, Pool: pool, Vault: &VaultClient{BaseURL: must("VAULT_INTERNAL_URL"), Token: must("RV_INTERNAL_TOKEN"), HTTP: client}, AllowHTTP: os.Getenv("RV_ALLOW_HTTP_UPSTREAM") == "true", AllowPrivate: os.Getenv("RV_ALLOW_PRIVATE_UPSTREAM") == "true"}
	handler, refresh, run := setup(deps)
	if err := refresh(ctx); err != nil {
		log.Fatal("could not load routes")
	}
	go run(ctx)
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = defaultAddr
	}
	// No write timeout: AI replies stream. The handler bounds its own upstream call.
	hs := &http.Server{Addr: addr, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: time.Minute}
	go func() {
		<-ctx.Done()
		sc, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		hs.Shutdown(sc)
	}()
	log.Printf("%s listening on %s", name, addr)
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

// Deps are shared gateway dependencies.
type Deps struct {
	Pool                    *pgxpool.Pool
	Vault                   *VaultClient
	AllowHTTP, AllowPrivate bool
	ctx                     context.Context
}

// Rules starts a rule store for this service's engine settings.
func (d *Deps) Rules(cfg detect.Config) *rules.Store {
	st := &rules.Store{
		Source:    &rules.HTTPSource{BaseURL: d.Vault.BaseURL, Token: d.Vault.Token, HTTP: d.Vault.HTTP},
		NewEngine: func(t map[string]float64) *detect.Engine { return detect.New(cfg.WithThresholds(t)) },
	}
	go st.Run(d.ctx, d.Pool)
	return st
}
