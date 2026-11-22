package logproc

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	colmetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	coltrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/mem"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// MaxBodyBytes bounds a decompressed payload (zip bombs included).
const MaxBodyBytes = 32 << 20

// Server is the log processor's HTTP front-end.
type Server struct {
	Pool      *pgxpool.Pool
	Processor *Processor
	Upstream  *http.Client
	AllowHTTP bool

	mu        sync.RWMutex
	pipelines map[string]*Pipeline
	Counters  Counters
}

// Handler routes OTLP and generic HTTP ingestion.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"status":"ok"}`)) })
	mux.HandleFunc("POST /otlp/{pipeline}/v1/logs", func(w http.ResponseWriter, r *http.Request) { s.ingest(w, r, signalLogs) })
	mux.HandleFunc("POST /otlp/{pipeline}/v1/traces", func(w http.ResponseWriter, r *http.Request) { s.ingest(w, r, signalTraces) })
	mux.HandleFunc("POST /otlp/{pipeline}/v1/metrics", func(w http.ResponseWriter, r *http.Request) { s.ingest(w, r, signalMetrics) })
	mux.HandleFunc("POST /http/{pipeline}", func(w http.ResponseWriter, r *http.Request) { s.ingest(w, r, signalHTTP) })
	gs := grpc.NewServer(grpc.ForceServerCodecV2(rawCodec{}), grpc.MaxRecvMsgSize(MaxBodyBytes), grpc.UnknownServiceHandler(s.grpcExport))
	// OTLP over gRPC arrives on the same port, told apart by HTTP/2 and content type.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor == 2 && strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc") {
			gs.ServeHTTP(w, r)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

// HashKey hashes a pipeline ingest key for storage and comparison.
func HashKey(k string) string {
	sum := sha256.Sum256([]byte(k))
	return hex.EncodeToString(sum[:])
}

func (s *Server) readBody(r *http.Request) ([]byte, error) {
	var rd io.Reader = r.Body
	if r.Header.Get("Content-Encoding") == "gzip" {
		gz, err := gzip.NewReader(r.Body)
		if err != nil {
			return nil, err
		}
		defer gz.Close()
		rd = gz
	}
	b, err := io.ReadAll(io.LimitReader(rd, MaxBodyBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxBodyBytes {
		return nil, errTooLarge
	}
	return b, nil
}

const errTooLarge = stringError("payload too large")

type signal string

const (
	signalHTTP    signal = ""
	signalLogs    signal = "logs"
	signalTraces  signal = "traces"
	signalMetrics signal = "metrics"
)

func (s *Server) ingest(w http.ResponseWriter, r *http.Request, sig signal) {
	s.mu.RLock()
	p := s.pipelines[r.PathValue("pipeline")]
	s.mu.RUnlock()
	key := r.Header.Get("X-RV-Pipeline-Key")
	if p == nil || subtle.ConstantTimeCompare([]byte(HashKey(key)), []byte(p.KeyHash)) != 1 {
		http.Error(w, "unknown pipeline or bad key", http.StatusUnauthorized)
		return
	}
	body, err := s.readBody(r)
	if errors.Is(err, errTooLarge) {
		http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
		return
	}
	if err != nil {
		http.Error(w, "unreadable body", http.StatusBadRequest)
		return
	}
	contentType := r.Header.Get("Content-Type")

	// Shadow mode forwards the original bytes. A sampled batch skips scanning.
	if p.Mode != "enforcing" {
		scale := int64(1)
		if p.SampleRate > 0 && p.SampleRate < 1 {
			scale = int64(1 / p.SampleRate)
		}
		if p.SampleRate >= 1 || p.SampleRate <= 0 || rand.Float64() < p.SampleRate {
			if pl, err := parse(body, sig, contentType); err == nil {
				if o, err := s.Processor.Process(r.Context(), p, pl.Leaves); err == nil {
					s.record(p, o.Counts, scale)
				}
			}
		}
		s.forward(w, r, p, body, contentType, sig)
		return
	}

	pl, err := parse(body, sig, contentType)
	if err != nil {
		// Unparseable OTLP cannot be redacted, so it does not go out.
		http.Error(w, "unparseable payload", http.StatusBadRequest)
		return
	}
	o, err := s.Processor.Process(r.Context(), p, pl.Leaves)
	if err != nil {
		log.Printf("pipeline %s: tokenization unavailable, failure mode %s", p.ID, p.FailureMode)
		if p.FailureMode == "drop" {
			s.record(p, Counts{{"all", "dropped"}: int64(len(pl.Leaves))}, 1)
			w.WriteHeader(http.StatusAccepted)
			return
		}
		// Buffer: the collector keeps the batch in its own queue and retries.
		// Raw logs are never written to disk here and never forwarded.
		w.Header().Set("Retry-After", "5")
		http.Error(w, "vault unavailable; retry", http.StatusServiceUnavailable)
		return
	}
	out, err := pl.Encode(o.Dropped)
	if err != nil {
		http.Error(w, "encode failed", http.StatusInternalServerError)
		return
	}
	s.record(p, o.Counts, 1)
	s.forward(w, r, p, out, contentType, sig)
}

func parse(body []byte, sig signal, contentType string) (*Payload, error) {
	isJSON := strings.Contains(contentType, "json")
	switch sig {
	case signalLogs:
		return ParseOTLP(body, isJSON)
	case signalTraces:
		return ParseOTLPSignal(&coltrace.ExportTraceServiceRequest{}, body, isJSON)
	case signalMetrics:
		return ParseOTLPSignal(&colmetrics.ExportMetricsServiceRequest{}, body, isJSON)
	}
	return ParseBody(body), nil
}

// rawCodec passes gRPC payloads as bytes, so that one handler serves every signal.
type rawCodec struct{}

func (rawCodec) Marshal(v any) (mem.BufferSlice, error) {
	return mem.BufferSlice{mem.SliceBuffer(*(v.(*[]byte)))}, nil
}
func (rawCodec) Unmarshal(data mem.BufferSlice, v any) error {
	*(v.(*[]byte)) = data.Materialize()
	return nil
}
func (rawCodec) Name() string { return "rv-raw" }

var grpcSignals = map[string]signal{
	"/opentelemetry.proto.collector.logs.v1.LogsService/Export":       signalLogs,
	"/opentelemetry.proto.collector.trace.v1.TraceService/Export":     signalTraces,
	"/opentelemetry.proto.collector.metrics.v1.MetricsService/Export": signalMetrics,
}

// grpcExport handles OTLP over gRPC. The pipeline and key come from metadata.
func (s *Server) grpcExport(_ any, stream grpc.ServerStream) error {
	method, _ := grpc.MethodFromServerStream(stream)
	sig, ok := grpcSignals[method]
	if !ok {
		return status.Error(codes.Unimplemented, "unknown service")
	}
	md, _ := metadata.FromIncomingContext(stream.Context())
	first := func(k string) string {
		if v := md.Get(k); len(v) > 0 {
			return v[0]
		}
		return ""
	}
	s.mu.RLock()
	p := s.pipelines[first("x-rv-pipeline")]
	s.mu.RUnlock()
	if p == nil || subtle.ConstantTimeCompare([]byte(HashKey(first("x-rv-pipeline-key"))), []byte(p.KeyHash)) != 1 {
		return status.Error(codes.Unauthenticated, "unknown pipeline or bad key")
	}
	var body []byte
	if err := stream.RecvMsg(&body); err != nil {
		return err
	}
	pl, err := parse(body, sig, "application/x-protobuf")
	if err != nil {
		return status.Error(codes.InvalidArgument, "unparseable payload")
	}
	o, err := s.Processor.Process(stream.Context(), p, pl.Leaves)
	if err != nil {
		if p.FailureMode == "drop" {
			s.record(p, Counts{{"all", "dropped"}: int64(len(pl.Leaves))}, 1)
			empty := []byte{}
			return stream.SendMsg(&empty)
		}
		// The collector's retry queue holds the batch. Nothing is forwarded raw.
		return status.Error(codes.Unavailable, "vault unavailable; retry")
	}
	out := body
	if p.Mode == "enforcing" {
		if out, err = pl.Encode(o.Dropped); err != nil {
			return status.Error(codes.Internal, "encode failed")
		}
	}
	s.record(p, o.Counts, 1)
	target := strings.TrimRight(p.UpstreamURL, "/") + "/v1/" + string(sig)
	if u, err := url.Parse(target); err != nil || (u.Scheme != "https" && !(s.AllowHTTP && u.Scheme == "http")) {
		return status.Error(codes.FailedPrecondition, "pipeline upstream must be https")
	}
	req, err := http.NewRequestWithContext(stream.Context(), http.MethodPost, target, bytes.NewReader(out))
	if err != nil {
		return status.Error(codes.Internal, "bad upstream")
	}
	req.Header.Set("Content-Type", "application/x-protobuf")
	for k, vs := range md {
		if !strings.HasPrefix(k, "x-rv-") && !strings.HasPrefix(k, ":") && k != "content-type" && k != "user-agent" && k != "te" && k != "grpc-timeout" && k != "grpc-encoding" && k != "grpc-accept-encoding" {
			req.Header[http.CanonicalHeaderKey(k)] = vs
		}
	}
	resp, err := s.Upstream.Do(req)
	if err != nil {
		return status.Error(codes.Unavailable, "upstream unavailable; retry")
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		return status.Error(codes.Unavailable, "upstream refused; retry")
	}
	empty := []byte{}
	return stream.SendMsg(&empty)
}

var hopHeaders = map[string]bool{"Connection": true, "Keep-Alive": true, "Te": true, "Trailer": true, "Transfer-Encoding": true, "Upgrade": true, "Host": true, "Content-Length": true, "Content-Encoding": true, "X-Rv-Pipeline-Key": true, "X-Forwarded-For": true}

// forward sends the payload upstream. Vendor API keys arrive from the collector
// as headers and pass through, so this service stores no vendor credentials.
func (s *Server) forward(w http.ResponseWriter, r *http.Request, p *Pipeline, body []byte, contentType string, sig signal) {
	target := strings.TrimRight(p.UpstreamURL, "/")
	if sig != signalHTTP {
		target += "/v1/" + string(sig)
	}
	if u, err := url.Parse(target); err != nil || (u.Scheme != "https" && !(s.AllowHTTP && u.Scheme == "http")) {
		http.Error(w, "pipeline upstream must be https", http.StatusBadGateway)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		http.Error(w, "bad upstream", http.StatusBadGateway)
		return
	}
	for k, vs := range r.Header {
		if !hopHeaders[http.CanonicalHeaderKey(k)] {
			req.Header[k] = vs
		}
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := s.Upstream.Do(req)
	if err != nil {
		w.Header().Set("Retry-After", "5")
		http.Error(w, "upstream unavailable; retry", http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 500 {
		w.Header().Set("Retry-After", "5")
		http.Error(w, "upstream unavailable; retry", http.StatusServiceUnavailable)
		return
	}
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}

func (s *Server) record(p *Pipeline, c Counts, scale int64) {
	s.Counters.RecordTo(p.VaultID, "logs", p.ID, p.Destination, HostOf(p.UpstreamURL), c, scale)
}

// Flush writes accumulated counts to detection_events.
func (s *Server) Flush(ctx context.Context) error { return s.Counters.Flush(ctx, s.Pool) }

// Refresh reloads pipeline configuration.
func (s *Server) Refresh(ctx context.Context) error {
	rows, err := s.Pool.Query(ctx, `SELECT id,vault_id,name,source_type,destination,upstream_url,entity_types,action_per_type,sensitive_paths,sample_rate,mode,failure_mode,ingest_key_hash FROM control.log_pipelines`)
	if err != nil {
		return err
	}
	defer rows.Close()
	next := map[string]*Pipeline{}
	for rows.Next() {
		p := &Pipeline{EntityTypes: map[string]bool{}, Actions: map[string]string{}}
		var ents, sens []string
		var actions []byte
		var rate float32
		if err := rows.Scan(&p.ID, &p.VaultID, &p.Name, &p.SourceType, &p.Destination, &p.UpstreamURL, &ents, &actions, &sens, &rate, &p.Mode, &p.FailureMode, &p.KeyHash); err != nil {
			return err
		}
		for _, e := range ents {
			p.EntityTypes[e] = true
		}
		if err := json.Unmarshal(actions, &p.Actions); err != nil {
			return fmt.Errorf("pipeline %s: bad actions", p.ID)
		}
		p.SensitivePaths = ParseSensitivePaths(sens)
		p.SampleRate = float64(rate)
		next[p.ID] = p
	}
	if rows.Err() != nil {
		return rows.Err()
	}
	s.mu.Lock()
	s.pipelines = next
	s.mu.Unlock()
	return nil
}

// Run keeps configuration fresh and flushes counts until ctx ends.
func (s *Server) Run(ctx context.Context) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			fc, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			s.Flush(fc)
			return
		case <-t.C:
			if err := s.Refresh(ctx); err != nil && ctx.Err() == nil {
				log.Print("pipeline refresh failed")
			}
			if err := s.Flush(ctx); err != nil && ctx.Err() == nil {
				log.Print("detection flush failed")
			}
		}
	}
}

// VaultClient calls the vault API's internal tokenize endpoint.
type VaultClient struct {
	BaseURL, Token string
	HTTP           *http.Client
}

// Tokenize implements Tokenizer.
func (v *VaultClient) Tokenize(ctx context.Context, vaultID, pipelineID string, items []Item) ([]string, error) {
	b, err := json.Marshal(map[string]any{"vault": vaultID, "pipeline": pipelineID, "items": items})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.BaseURL+"/internal/logs/tokenize", bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+v.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := v.HTTP.Do(req)
	if err != nil {
		return nil, errors.New("vault unreachable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("vault returned %d", resp.StatusCode)
	}
	var out struct {
		Tokens []string `json:"tokens"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	if len(out.Tokens) != len(items) {
		return nil, errors.New("vault returned the wrong number of tokens")
	}
	return out.Tokens, nil
}
