package logproc

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	collogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	colmetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	coltrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	common "go.opentelemetry.io/proto/otlp/common/v1"
	logs "go.opentelemetry.io/proto/otlp/logs/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	trace "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"onshore/data-plane/internal/detect"
)

type fakeTok struct {
	calls int
	err   error
}

func (f *fakeTok) Tokenize(_ context.Context, _, _ string, items []Item) ([]string, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	out := make([]string, len(items))
	for i, it := range items {
		out[i] = "tok_" + it.Entity + "_AAAAAAAAAAAA"
	}
	return out, nil
}

func enforcing() *Pipeline {
	return &Pipeline{ID: "p", VaultID: "v", Mode: "enforcing", Actions: map[string]string{}}
}

func run(t *testing.T, p *Pipeline, tk Tokenizer, body string) (string, Outcome) {
	t.Helper()
	pl := ParseBody([]byte(body))
	pr := &Processor{Engine: detect.New(detect.Config{}), Tokenizer: tk}
	o, err := pr.Process(context.Background(), p, pl.Leaves)
	if err != nil {
		t.Fatal(err)
	}
	b, err := pl.Encode(o.Dropped)
	if err != nil {
		t.Fatal(err)
	}
	return string(b), o
}

func TestEnforcingTextNoRawValueLeaves(t *testing.T) {
	out, _ := run(t, enforcing(), &fakeTok{}, "transfer failed bvn=22123456789 acct 0123456789\nall good")
	for _, secret := range []string{"22123456789", "0123456789"} {
		if strings.Contains(out, secret) {
			t.Fatalf("leak: %s", out)
		}
	}
	if !strings.Contains(out, "tok_bvn_") || !strings.Contains(out, "all good") {
		t.Fatal(out)
	}
}

func TestShadowChangesNothingButCounts(t *testing.T) {
	p := enforcing()
	p.Mode = "shadow"
	body := "bvn=22123456789"
	tk := &fakeTok{}
	out, o := run(t, p, tk, body)
	if out != body || o.Counts[[2]string{"bvn", "passed"}] != 1 || tk.calls != 0 {
		t.Fatalf("%q %+v calls=%d", out, o.Counts, tk.calls)
	}
}

func TestJSONKeysValuesNumbersRedacted(t *testing.T) {
	out, _ := run(t, enforcing(), &fakeTok{}, `{"bvn":22123456789,"customer":{"phone":"08031234567"},"22123456780":{"x":1},"ok":"fine"}`)
	for _, secret := range []string{"22123456789", "08031234567", "22123456780"} {
		if strings.Contains(out, secret) {
			t.Fatalf("leak: %s", out)
		}
	}
	if !strings.Contains(out, `"ok":"fine"`) {
		t.Fatal(out)
	}
}

func TestSensitivePathSkipsScoring(t *testing.T) {
	p := enforcing()
	p.SensitivePaths = map[string]string{"$.customer.ref": "bvn"}
	out, _ := run(t, p, &fakeTok{}, `{"customer":{"ref":"abc"}}`)
	if strings.Contains(out, "abc") {
		t.Fatal(out)
	}
}

func TestCardNeverTokenized(t *testing.T) {
	tk := &fakeTok{}
	out, o := run(t, enforcing(), tk, "pan 4111 1111 1111 1111")
	if strings.Contains(out, "4111 1111 1111 1111") || !strings.Contains(out, "1111") || tk.calls != 0 || o.Counts[[2]string{"card_pan", "masked"}] != 1 {
		t.Fatalf("%q %+v calls=%d", out, o.Counts, tk.calls)
	}
}

func TestDropRemovesWholeRecord(t *testing.T) {
	p := enforcing()
	p.Actions["bvn"] = "drop"
	out, _ := run(t, p, &fakeTok{}, `[{"a":"bvn 22123456789"},{"a":"fine"}]`)
	if strings.Contains(out, "22123456789") || !strings.Contains(out, "fine") || strings.Contains(out, "rv:dropped") {
		t.Fatal(out)
	}
}

func TestNoTokenFieldFallsBackToMask(t *testing.T) {
	pr := &Processor{Engine: detect.New(detect.Config{}), Tokenizer: emptyTok{}}
	pl := ParseBody([]byte("bvn 22123456789"))
	o, err := pr.Process(context.Background(), enforcing(), pl.Leaves)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := pl.Encode(o.Dropped)
	if strings.Contains(string(b), "22123456789") {
		t.Fatal(string(b))
	}
}

type emptyTok struct{}

func (emptyTok) Tokenize(_ context.Context, _, _ string, items []Item) ([]string, error) {
	return make([]string, len(items)), nil
}

func TestTokenizerFailureIsAnError(t *testing.T) {
	pr := &Processor{Engine: detect.New(detect.Config{}), Tokenizer: &fakeTok{err: errors.New("vault down")}}
	pl := ParseBody([]byte("bvn 22123456789"))
	if _, err := pr.Process(context.Background(), enforcing(), pl.Leaves); err == nil {
		t.Fatal("the caller must get an error, so it can fail safe")
	}
}

func TestCacheAvoidsRepeatCalls(t *testing.T) {
	tk := &fakeTok{}
	pr := &Processor{Engine: detect.New(detect.Config{}), Tokenizer: tk}
	for i := 0; i < 3; i++ {
		pl := ParseBody([]byte("bvn 22123456789"))
		if _, err := pr.Process(context.Background(), enforcing(), pl.Leaves); err != nil {
			t.Fatal(err)
		}
	}
	if tk.calls != 1 {
		t.Fatalf("calls=%d", tk.calls)
	}
}

func TestOversizedValueNotForwarded(t *testing.T) {
	big := strings.Repeat("x", MaxLeafBytes+1)
	out, _ := run(t, enforcing(), &fakeTok{}, big)
	if strings.Contains(out, "xxxx") {
		t.Fatal("oversized value forwarded")
	}
}

func TestOTLPProtobufRoundTrip(t *testing.T) {
	req := &collogs.ExportLogsServiceRequest{ResourceLogs: []*logs.ResourceLogs{{ScopeLogs: []*logs.ScopeLogs{{LogRecords: []*logs.LogRecord{{
		Body: &common.AnyValue{Value: &common.AnyValue_StringValue{StringValue: "transfer to acct 0123456789"}},
		Attributes: []*common.KeyValue{
			{Key: "bvn", Value: &common.AnyValue{Value: &common.AnyValue_IntValue{IntValue: 22123456789}}},
			{Key: "nested", Value: &common.AnyValue{Value: &common.AnyValue_KvlistValue{KvlistValue: &common.KeyValueList{Values: []*common.KeyValue{{Key: "phone", Value: &common.AnyValue{Value: &common.AnyValue_StringValue{StringValue: "08031234567"}}}}}}}},
		},
	}}}}}}}
	raw, err := proto.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	pl, err := ParseOTLP(raw, false)
	if err != nil {
		t.Fatal(err)
	}
	pr := &Processor{Engine: detect.New(detect.Config{}), Tokenizer: &fakeTok{}}
	o, err := pr.Process(context.Background(), enforcing(), pl.Leaves)
	if err != nil {
		t.Fatal(err)
	}
	b, err := pl.Encode(o.Dropped)
	if err != nil {
		t.Fatal(err)
	}
	var back collogs.ExportLogsServiceRequest
	if err := proto.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	s := back.String()
	for _, secret := range []string{"0123456789", "22123456789", "08031234567"} {
		if strings.Contains(s, secret) {
			t.Fatalf("leak %s in %s", secret, s)
		}
	}
	if !strings.Contains(s, "tok_bvn_") {
		t.Fatal(s)
	}
}

func BenchmarkEnforcingLines(b *testing.B) {
	c := detect.NewCorpus(3)
	lines := make([]string, 1000)
	for i := range lines {
		lines[i] = c.Sample().Text
	}
	body := []byte(strings.Join(lines, "\n"))
	pr := &Processor{Engine: detect.New(detect.Config{}), Tokenizer: &fakeTok{}}
	p := enforcing()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pl := ParseBody(body)
		if _, err := pr.Process(context.Background(), p, pl.Leaves); err != nil {
			b.Fatal(err)
		}
		if _, err := pl.Encode(nil); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(b.N)*1000/b.Elapsed().Seconds(), "lines/s")
}

func TestTracesAndMetricsRedacted(t *testing.T) {
	bvnAttr := []*common.KeyValue{{Key: "customer.bvn", Value: &common.AnyValue{Value: &common.AnyValue_StringValue{StringValue: "22123456789"}}}}
	traces := &coltrace.ExportTraceServiceRequest{ResourceSpans: []*trace.ResourceSpans{{ScopeSpans: []*trace.ScopeSpans{{Spans: []*trace.Span{{
		Name: "GET /accounts/0123456789 acct", Attributes: bvnAttr, Events: []*trace.Span_Event{{Name: "fail", Attributes: bvnAttr}},
	}}}}}}}
	metrics := &colmetrics.ExportMetricsServiceRequest{ResourceMetrics: []*metricspb.ResourceMetrics{{ScopeMetrics: []*metricspb.ScopeMetrics{{Metrics: []*metricspb.Metric{{
		Name: "requests", Data: &metricspb.Metric_Sum{Sum: &metricspb.Sum{DataPoints: []*metricspb.NumberDataPoint{{Attributes: bvnAttr}}}},
	}}}}}}}
	pr := &Processor{Engine: detect.New(detect.Config{}), Tokenizer: &fakeTok{}}
	for name, c := range map[string]struct {
		in, out proto.Message
	}{"traces": {traces, &coltrace.ExportTraceServiceRequest{}}, "metrics": {metrics, &colmetrics.ExportMetricsServiceRequest{}}} {
		raw, err := proto.Marshal(c.in)
		if err != nil {
			t.Fatal(err)
		}
		pl, err := ParseOTLPSignal(c.out, raw, false)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pr.Process(context.Background(), enforcing(), pl.Leaves); err != nil {
			t.Fatal(err)
		}
		b, err := pl.Encode(nil)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "22123456789") || strings.Contains(string(b), "0123456789") {
			t.Errorf("%s leaked: %q", name, b)
		}
	}
}

// OTLP over gRPC against a real HTTP/2 TLS server, through the same handler.
func TestGRPCExportRedactsAndForwards(t *testing.T) {
	var got []byte
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = io.ReadAll(r.Body)
		if r.Header.Get("X-Rv-Pipeline-Key") != "" {
			t.Error("the pipeline key must not reach the destination")
		}
	}))
	defer up.Close()
	s := &Server{Processor: &Processor{Engine: detect.New(detect.Config{}), Tokenizer: &fakeTok{}}, Upstream: up.Client(), AllowHTTP: true,
		pipelines: map[string]*Pipeline{"p": {ID: "p", VaultID: "v", Mode: "enforcing", Actions: map[string]string{}, UpstreamURL: up.URL, KeyHash: HashKey("k")}}}
	srv := httptest.NewUnstartedServer(s.Handler())
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	conn, err := grpc.NewClient(strings.TrimPrefix(srv.URL, "https://"), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{InsecureSkipVerify: true}))) // #nosec test server
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := collogs.NewLogsServiceClient(conn)
	req := &collogs.ExportLogsServiceRequest{ResourceLogs: []*logs.ResourceLogs{{ScopeLogs: []*logs.ScopeLogs{{LogRecords: []*logs.LogRecord{{Body: &common.AnyValue{Value: &common.AnyValue_StringValue{StringValue: "bvn 22123456789"}}}}}}}}}
	if _, err := client.Export(context.Background(), req); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("no key must be refused: %v", err)
	}
	ctx := metadata.AppendToOutgoingContext(context.Background(), "x-rv-pipeline", "p", "x-rv-pipeline-key", "k")
	if _, err := client.Export(ctx, req); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), "22123456789") || !strings.Contains(string(got), "tok_bvn_") {
		t.Fatalf("%q", got)
	}
}
