package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestLoadProfile measures the vault API with no edge, TLS or Node client in the way,
// and writes CPU, block and mutex profiles. It only runs on request:
//
//	RV_LOAD_PROFILE=/some/dir scripts/test-integration.sh -run TestLoadProfile
func TestLoadProfile(t *testing.T) {
	dir := os.Getenv("RV_LOAD_PROFILE")
	if dir == "" {
		t.Skip("RV_LOAD_PROFILE not set")
	}
	e, sa := ready(t)
	client := &http.Client{Transport: &http.Transport{MaxIdleConns: 256, MaxIdleConnsPerHost: 256}}
	post := func(path string, body any) error {
		b, _ := json.Marshal(body)
		req, _ := http.NewRequest("POST", e.srv.URL+path, bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer "+sa.token)
		req.Header.Set("Content-Type", "application/json")
		res, err := client.Do(req)
		if err != nil {
			return err
		}
		defer res.Body.Close()
		out, _ := io.ReadAll(res.Body)
		if res.StatusCode != 200 {
			return fmt.Errorf("%d %s", res.StatusCode, out)
		}
		return nil
	}
	var seq atomic.Int64
	tokenizeBody := func() any {
		items := make([]map[string]string, 10)
		for i := range items {
			items[i] = map[string]string{"field": "bvn", "value": fmt.Sprintf("22%09d", seq.Add(1))}
		}
		return map[string]any{"items": items, "continue_on_error": true}
	}
	seed, _ := e.tokenize(e.vault, sa.token, map[string]string{"field": "bvn", "value": "22999999990"})
	detokItems := make([]map[string]string, 10)
	for i := range detokItems {
		detokItems[i] = map[string]string{"token": seed.Results[0].Token}
	}
	detokBody := map[string]any{"items": detokItems, "purpose": "load", "continue_on_error": true}

	run := func(name string, conc int, d time.Duration, f func() error) {
		var mu sync.Mutex
		var lat []float64
		var wg sync.WaitGroup
		stop := time.Now().Add(d)
		var failed atomic.Int64
		for range conc {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for time.Now().Before(stop) {
					s := time.Now()
					if err := f(); err != nil {
						if failed.Add(1) == 1 {
							t.Log(err)
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
		sort.Float64s(lat)
		if len(lat) == 0 {
			t.Fatalf("%s: no successful requests", name)
		}
		fmt.Printf("%-10s conc=%-3d %7.0f req/s  p50=%7.1f ms  p95=%7.1f ms  failed=%d\n", name, conc, float64(len(lat))/d.Seconds(), lat[len(lat)/2], lat[len(lat)*95/100], failed.Load())
	}

	tok := func() error { return post("/v1/vaults/"+e.vault+"/tokenize", tokenizeBody()) }
	det := func() error { return post("/v1/vaults/"+e.vault+"/detokenize", detokBody) }
	for _, conc := range []int{1, 2, 5, 10, 20, 40} {
		run("tokenize", conc, 4*time.Second, tok)
	}
	for _, conc := range []int{1, 2, 5, 10, 20, 40} {
		run("detokenize", conc, 4*time.Second, det)
	}

	write := func(name string, f func(io.Writer) error) {
		w, err := os.Create(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		defer w.Close()
		if err := f(w); err != nil {
			t.Fatal(err)
		}
	}
	runtime.SetBlockProfileRate(100_000) // one sample per 100 µs blocked
	runtime.SetMutexProfileFraction(10)
	profile := func(prefix string, f func() error) {
		runtime.GC()
		pprof.Lookup("block")
		write(prefix+"-cpu.pprof", func(w io.Writer) error {
			if err := pprof.StartCPUProfile(w); err != nil {
				return err
			}
			run(prefix, 10, 15*time.Second, f)
			pprof.StopCPUProfile()
			return nil
		})
		write(prefix+"-block.pprof", func(w io.Writer) error { return pprof.Lookup("block").WriteTo(w, 0) })
		write(prefix+"-mutex.pprof", func(w io.Writer) error { return pprof.Lookup("mutex").WriteTo(w, 0) })
	}
	profile("tokenize", tok)
	profile("detokenize", det)
}
