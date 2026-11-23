// Command adapters tokenizes support tickets arriving by webhook.
package main

import (
	"context"
	"log"
	"net/http"
	"onshore/data-plane/internal/license"
	"os"
	"os/signal"
	"syscall"
	"time"

	"onshore/data-plane/ee/adapters"
	"onshore/data-plane/ee/gateway"
	"onshore/data-plane/internal/detect"
	"onshore/data-plane/internal/netguard"

	_ "onshore/data-plane/ee/nlp" // paid: language-model detection, when RV_NLP_URL is set
)

func main() {
	license.LogStartup("adapters") // paid service: see ee/LICENSE; the vault enforces the edition
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	secret := os.Getenv("RV_ADAPTER_SECRET")
	if secret == "" {
		log.Fatal("RV_ADAPTER_SECRET is required")
	}
	gateway.Serve(ctx, "adapters", ":8093", func(d *gateway.Deps) (http.Handler, func(context.Context) error, func(context.Context)) {
		st := d.Rules(detect.Config{})
		s := &adapters.Service{Pool: d.Pool, Vault: d.Vault, Engine: detect.New(detect.Config{}), Rules: st, Secret: secret, AllowHTTP: d.AllowHTTP, Client: netguard.Client(20*time.Second, d.AllowPrivate)}
		s.Counters.Rules = st
		run := func(c context.Context) {
			gateway.RunLoop(c, s.Refresh, func(f context.Context) error { return s.Counters.Flush(f, s.Pool) })
		}
		return s.Handler(), s.Refresh, run
	})
}
