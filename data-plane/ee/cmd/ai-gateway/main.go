// Command ai-gateway is an OpenAI-compatible proxy that keeps identifiers out of
// prompts and restores them in replies only as far as policy allows.
package main

import (
	"context"
	"net/http"
	"onshore/data-plane/internal/license"
	"os"
	"os/signal"
	"syscall"
	"time"

	"onshore/data-plane/ee/gateway"
	"onshore/data-plane/internal/detect"
	"onshore/data-plane/internal/netguard"

	_ "onshore/data-plane/ee/nlp" // paid: language-model detection, when RV_NLP_URL is set
)

func main() {
	license.LogStartup("ai-gateway") // paid service: see ee/LICENSE; the vault enforces the edition
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	gateway.Serve(ctx, "ai-gateway", ":8091", func(d *gateway.Deps) (http.Handler, func(context.Context) error, func(context.Context)) {
		cfg := detect.Config{PaymentRefs: true}
		st := d.Rules(cfg)
		a := &gateway.AI{Pool: d.Pool, Vault: d.Vault, Engine: detect.New(cfg), Rules: st, AllowHTTP: d.AllowHTTP, Upstream: netguard.Client(5*time.Minute, d.AllowPrivate)}
		a.Counters.Rules = st
		return a.Handler(), a.Refresh, a.Run
	})
}
