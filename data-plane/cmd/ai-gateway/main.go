// Command ai-gateway is an OpenAI-compatible proxy that keeps identifiers out of
// prompts and restores them in replies only as far as policy allows.
package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"onshore/data-plane/internal/detect"
	"onshore/data-plane/internal/gateway"
	"onshore/data-plane/internal/netguard"
)

func main() {
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
