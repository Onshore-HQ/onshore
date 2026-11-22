// Command file-redactor redacts PDFs, images, recordings and text files.
package main

import (
	"context"
	"log"
	"net/http"
	"onshore/data-plane/internal/license"
	"onshore/data-plane/internal/rules"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"onshore/data-plane/ee/filered"
	"onshore/data-plane/ee/gateway"
	"onshore/data-plane/internal/detect"
	"onshore/data-plane/internal/tlsutil"
)

func must(k string) string {
	v := os.Getenv(k)
	if v == "" {
		log.Fatalf("%s is required", k)
	}
	return v
}

func main() {
	license.LogStartup("file-redactor") // paid service: see ee/LICENSE; the vault enforces the edition
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	client, err := tlsutil.Client(os.Getenv("RV_TLS_CERT"), os.Getenv("RV_TLS_KEY"), os.Getenv("RV_TLS_CLIENT_CA"), 15*time.Second)
	if err != nil {
		log.Fatal(err)
	}
	slots := runtime.NumCPU() / 2
	if slots < 1 {
		slots = 1
	}
	// No database here by design, so rule sets come from the vault API, on the poll alone.
	st := &rules.Store{
		Source:    &rules.HTTPSource{BaseURL: must("VAULT_INTERNAL_URL"), Token: must("RV_INTERNAL_TOKEN"), HTTP: client},
		NewEngine: func(t map[string]float64) *detect.Engine { return detect.New(detect.Config{}.WithThresholds(t)) },
	}
	go st.Run(ctx, nil)
	s := &filered.Server{
		R:     &filered.Redactor{Engine: detect.New(detect.Config{}), Rules: st, TmpDir: os.TempDir(), WhisperModel: os.Getenv("RV_WHISPER_MODEL")},
		Vault: &gateway.VaultClient{BaseURL: must("VAULT_INTERNAL_URL"), Token: must("RV_INTERNAL_TOKEN"), HTTP: client},
		Slots: make(chan struct{}, slots),
	}
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":8094"
	}
	hs := &http.Server{Addr: addr, Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 2 * time.Minute}
	go func() {
		<-ctx.Done()
		sc, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		hs.Shutdown(sc)
	}()
	log.Printf("file-redactor listening on %s", addr)
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
