// Command loadgen drives a test install from Go, to separate the product's limits from
// those of any one client. Point it only at your own test install: it skips TLS checks.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	vault "github.com/Onshore-HQ/onshore-go"
)

func main() {
	cfgPath := flag.String("cfg", "", "JSON with sa, kid, seed and vault, from RV_E2E_LOAD=1 scripts/e2e.sh")
	url := flag.String("url", "https://localhost:8443", "base URL")
	sni := flag.String("sni", "localhost", "TLS server name")
	h1 := flag.Bool("h1", false, "use HTTP/1.1 with one connection per client, instead of one shared HTTP/2 connection")
	secs := flag.Int("secs", 5, "seconds per step")
	connect := flag.String("connect", "", "dial this host:port whatever the URL says, to reach the edge from inside Docker")
	flag.Parse()
	raw, err := os.ReadFile(*cfgPath)
	if err != nil {
		log.Fatal(err)
	}
	var cfg struct{ SA, Kid, Seed, Vault string }
	if err := json.Unmarshal(raw, &cfg); err != nil {
		log.Fatal(err)
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: *sni}, MaxIdleConns: 256, MaxIdleConnsPerHost: 256, ForceAttemptHTTP2: !*h1}
	if *connect != "" {
		tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, *connect)
		}
	}
	if *h1 {
		tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	}
	c, err := vault.New(*url, cfg.SA, cfg.Kid, cfg.Seed)
	if err != nil {
		log.Fatal(err)
	}
	c.HTTP = &http.Client{Timeout: 30 * time.Second, Transport: tr}
	ctx := context.Background()
	var n atomic.Int64
	n.Store(time.Now().UnixMilli() % 1000000 * 1000)
	batch := func() []vault.Item {
		items := make([]vault.Item, 10)
		for i := range items {
			items[i] = vault.Item{Field: "phone", Value: fmt.Sprintf("0903%07d", n.Add(1)%10000000)}
		}
		return items
	}
	seeded, err := c.Tokenize(ctx, cfg.Vault, batch())
	if err != nil {
		log.Fatal(err)
	}
	toks := make([]string, len(seeded))
	for i, r := range seeded {
		toks[i] = r.Token
	}
	step := func(name string, conc int, f func() error) {
		var mu sync.Mutex
		var lat []float64
		var failed atomic.Int64
		var wg sync.WaitGroup
		stop := time.Now().Add(time.Duration(*secs) * time.Second)
		for range conc {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for time.Now().Before(stop) {
					s := time.Now()
					if err := f(); err != nil {
						if failed.Add(1) == 1 {
							log.Print(err)
						}
						continue
					}
					ms := float64(time.Since(s).Microseconds()) / 1000
					mu.Lock()
					lat = append(lat, ms)
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		if len(lat) == 0 {
			fmt.Printf("%-10s conc=%-3d all %d failed\n", name, conc, failed.Load())
			return
		}
		sort.Float64s(lat)
		fmt.Printf("%-10s conc=%-3d %6.0f batches/s  p50=%7.1f ms  p95=%7.1f ms  failed=%d\n", name, conc, float64(len(lat))/float64(*secs), lat[len(lat)/2], lat[len(lat)*95/100], failed.Load())
	}
	for _, conc := range []int{1, 10, 40} {
		step("tokenize", conc, func() error { _, err := c.Tokenize(ctx, cfg.Vault, batch()); return err })
	}
	for _, conc := range []int{1, 10, 40} {
		step("detokenize", conc, func() error { _, err := c.Detokenize(ctx, cfg.Vault, toks, "load test"); return err })
	}
}
