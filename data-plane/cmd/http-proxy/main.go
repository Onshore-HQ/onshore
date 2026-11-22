// Command http-proxy applies JSON-path redact and unredact rules to any REST API.
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
	gateway.Serve(ctx, "http-proxy", ":8092", func(d *gateway.Deps) (http.Handler, func(context.Context) error, func(context.Context)) {
		st := d.Rules(detect.Config{})
		p := &gateway.Proxy{FileRedactorURL: os.Getenv("RV_FILE_REDACTOR_URL"), Pool: d.Pool, Vault: d.Vault, AllowHTTP: d.AllowHTTP, Upstream: netguard.Client(30*time.Second, d.AllowPrivate), T: &gateway.Transformer{Engine: detect.New(detect.Config{}), Rules: st}}
		p.Counters.Rules = st
		p.Wire()
		return p.Handler(), p.Refresh, p.Run
	})
}
