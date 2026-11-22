package rules

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"onshore/data-plane/ee/logproc"
	"onshore/data-plane/internal/detect"
)

type fakeSource struct {
	mu      sync.Mutex
	version int64
	regex   string
	fail    error
}

func (f *fakeSource) set(version int64, regex string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.version, f.regex = version, regex
}

func (f *fakeSource) Versions(context.Context) (map[string]int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return nil, f.fail
	}
	return map[string]int64{"v1": f.version}, nil
}

func (f *fakeSource) Snapshot(context.Context, string) (*Snapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return nil, f.fail
	}
	return &Snapshot{Version: f.version, Entities: []detect.CustomDef{{Slug: "c_id", Kind: detect.KindPattern, Threshold: 0.5, Status: "enforcing", Version: int(f.version), Definition: detect.Definition{Regex: f.regex}}}}, nil
}

func newStore(src Source) *Store {
	return &Store{Source: src, NewEngine: func(t map[string]float64) *detect.Engine { return detect.New(detect.Config{}.WithThresholds(t)) }}
}

func TestNotReadyUntilFirstSync(t *testing.T) {
	src := &fakeSource{version: 1, regex: `ID-\d+`, fail: errors.New("vault down")}
	st := newStore(src)
	if st.For("v1") != nil {
		t.Fatal("before any sync, a store must say not ready")
	}
	if err := st.Sync(context.Background()); err == nil {
		t.Fatal("wanted the fetch error")
	}
	if st.For("v1") != nil {
		t.Fatal("a failed first sync must stay not ready, or traffic passes with built-ins alone")
	}
	src.mu.Lock()
	src.fail = nil
	src.mu.Unlock()
	if err := st.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r := st.For("v1"); r == nil || r.Custom("c_id") == nil {
		t.Fatal("after a sync, the entity is live")
	}
	if r := st.For("other"); r == nil || r.Custom("c_id") != nil {
		t.Fatal("a vault with nothing custom gets built-ins")
	}
}

func TestBadDefinitionKeepsLastGoodSet(t *testing.T) {
	src := &fakeSource{version: 1, regex: `ID-\d+`}
	st := newStore(src)
	if err := st.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	src.set(2, `(`) // cannot compile
	if err := st.Sync(context.Background()); err == nil {
		t.Fatal("wanted the compile error")
	}
	r := st.For("v1")
	if r == nil || r.Version != 1 || len(r.Scan("ID-7")) != 1 {
		t.Fatal("the last good set must stay in force")
	}
}

func TestFirstCompileFailureIsNotReadyForThatVault(t *testing.T) {
	st := newStore(&fakeSource{version: 1, regex: `(`})
	st.Sync(context.Background())
	if st.For("v1") != nil {
		t.Fatal("a vault that has never compiled is not ready, not unprotected")
	}
	if st.For("other") == nil {
		t.Fatal("other vaults carry on")
	}
}

type sinkTokenizer struct{}

func (sinkTokenizer) Tokenize(_ context.Context, _, _ string, items []logproc.Item) ([]string, error) {
	out := make([]string, len(items))
	for i := range items {
		out[i] = "tok_c_id_aaaaaaaaaaaa"
	}
	return out, nil
}

// The spec's hot-reload test: swap rule sets under load through the log processor's real
// code path, and confirm no line is dropped, none is half-processed, and each line sees
// one whole version. It runs at well over the spec's 20,000 lines per second.
func TestHotReloadUnderLoadDropsNothing(t *testing.T) {
	src := &fakeSource{version: 1, regex: `OLD-\d{6}`}
	st := newStore(src)
	if err := st.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	pr := &logproc.Processor{Engine: detect.New(detect.Config{}), Rules: st, Tokenizer: sinkTokenizer{}}
	p := &logproc.Pipeline{ID: "p", VaultID: "v1", Mode: "enforcing"}

	stop := make(chan struct{})
	var lines, leaked atomic.Int64
	var failures atomic.Int64
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				// Each set knows one of these shapes, so exactly one must go.
				var got string
				leaf := logproc.Leaf{Value: "a OLD-123456 b NEW-123456 c", Set: func(s string) { got = s }}
				out, err := pr.Process(context.Background(), p, []logproc.Leaf{leaf})
				if err != nil || !out.Changed {
					failures.Add(1)
					continue
				}
				redactedOld := got == "a tok_c_id_aaaaaaaaaaaa b NEW-123456 c"
				redactedNew := got == "a OLD-123456 b tok_c_id_aaaaaaaaaaaa c"
				if !redactedOld && !redactedNew {
					leaked.Add(1)
				}
				lines.Add(1)
			}
		}()
	}
	started := time.Now()
	swaps := 0
	for time.Since(started) < 3*time.Second {
		swaps++
		v := int64(swaps + 1)
		if swaps%2 == 1 {
			src.set(v, `NEW-\d{6}`)
		} else {
			src.set(v, `OLD-\d{6}`)
		}
		if err := st.Sync(context.Background()); err != nil {
			t.Fatal(err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	close(stop)
	wg.Wait()
	rate := float64(lines.Load()) / time.Since(started).Seconds()
	t.Logf("%d lines, %.0f per second, across %d swaps", lines.Load(), rate, swaps)
	if failures.Load() != 0 || leaked.Load() != 0 {
		t.Fatalf("failures %d, half-processed %d", failures.Load(), leaked.Load())
	}
	if rate < 20000 {
		t.Fatalf("under the spec's 20,000 lines per second: %.0f", rate)
	}
}
