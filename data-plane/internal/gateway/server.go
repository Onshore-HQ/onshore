package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"onshore/data-plane/internal/logproc"
)

// MaxBody bounds gateway bodies in both directions.
const MaxBody = 16 << 20

func hashKey(k string) string {
	s := sha256.Sum256([]byte(k))
	return hex.EncodeToString(s[:])
}

func keyOK(given, want string) bool {
	return want != "" && subtle.ConstantTimeCompare([]byte(hashKey(given)), []byte(want)) == 1
}

// VaultClient calls the vault's internal API over mutual TLS.
type VaultClient struct {
	BaseURL, Token string
	HTTP           *http.Client
}

func (v *VaultClient) post(ctx context.Context, p string, body, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.BaseURL+p, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+v.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := v.HTTP.Do(req)
	if err != nil {
		return ErrVaultDown
	}
	defer resp.Body.Close()
	if resp.StatusCode == 401 {
		return ErrCallerRejected
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("%w: status %d", ErrVaultDown, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

var (
	// ErrVaultDown means the request must fail closed.
	ErrVaultDown = errors.New("vault unavailable")
	// ErrDenied means policy refused the action.
	ErrDenied = errors.New("denied")
	// ErrCallerRejected means the caller token did not verify.
	ErrCallerRejected = errors.New("caller token rejected")
)

// Tokenize issues deterministic tokens for a gateway.
func (v *VaultClient) Tokenize(ctx context.Context, vaultID, source, module string, items []logproc.Item) ([]string, error) {
	var out struct {
		Tokens []string `json:"tokens"`
	}
	all := make([]string, 0, len(items))
	for start := 0; start < len(items); start += 500 {
		end := min(start+500, len(items))
		if err := v.post(ctx, "/internal/logs/tokenize", map[string]any{"vault": vaultID, "pipeline": source, "module": module, "items": items[start:end]}, &out); err != nil {
			return nil, err
		}
		all = append(all, out.Tokens...)
	}
	return all, nil
}

// Reveal restores tokens as the end user. A value the user may not see is absent.
func (v *VaultClient) Reveal(ctx context.Context, vaultID, caller, ip, module, purpose string, tokens []string) (map[string]string, error) {
	var out struct {
		Results []struct {
			Index    int    `json:"index"`
			Decision string `json:"decision"`
			Value    string `json:"value"`
		} `json:"results"`
	}
	if err := v.post(ctx, "/internal/gateway/reveal", map[string]any{"vault": vaultID, "caller_token": caller, "source_ip": ip, "module": module, "purpose": purpose, "tokens": tokens}, &out); err != nil {
		return nil, err
	}
	vals := map[string]string{}
	for _, r := range out.Results {
		if (r.Decision == "plaintext" || r.Decision == "masked") && r.Index < len(tokens) {
			vals[tokens[r.Index]] = r.Value
		}
	}
	return vals, nil
}

// AuthorizeFile checks the file_redact action first (with no counts), and records
// the findings afterwards. Only counts travel here; the file stays in the redactor.
func (v *VaultClient) AuthorizeFile(ctx context.Context, vaultID, caller, ip, purpose string, counts map[string]int, low bool) error {
	var out struct {
		Allowed bool `json:"allowed"`
	}
	if err := v.post(ctx, "/internal/gateway/file", map[string]any{"vault": vaultID, "caller_token": caller, "source_ip": ip, "purpose": purpose, "counts": counts, "low_confidence": low}, &out); err != nil {
		return err
	}
	if !out.Allowed {
		return ErrDenied
	}
	return nil
}

// Decide asks what a caller may see of each entity type in an AI reply.
func (v *VaultClient) Decide(ctx context.Context, vaultID, route, caller, ip, purpose string, entities map[string]int) (map[string]string, error) {
	var out struct {
		Decisions map[string]string `json:"decisions"`
	}
	err := v.post(ctx, "/internal/gateway/decide", map[string]any{"vault": vaultID, "route": route, "caller_token": caller, "source_ip": ip, "purpose": purpose, "entities": entities}, &out)
	return out.Decisions, err
}

// SaveTwin seals a request's map in the vault and returns its id.
func (v *VaultClient) SaveTwin(ctx context.Context, vaultID, route string, days int, items []TwinItem) (string, error) {
	var out struct {
		ID string `json:"id"`
	}
	err := v.post(ctx, "/internal/cloak/twin", map[string]any{"vault": vaultID, "route": route, "days": days, "items": items}, &out)
	if err == nil && out.ID == "" {
		err = errors.New("the vault returned no twin id")
	}
	return out.ID, err
}

var hopHeaders = map[string]bool{"Connection": true, "Keep-Alive": true, "Te": true, "Trailer": true, "Transfer-Encoding": true, "Upgrade": true, "Host": true, "Content-Length": true, "Content-Encoding": true, "Accept-Encoding": true, "X-Forwarded-For": true, "Cookie": true}

// copyRequestHeaders passes vendor credentials through, so that nothing here stores
// them, and strips everything meant for this gateway.
func copyRequestHeaders(dst, src http.Header) {
	for k, vs := range src {
		c := http.CanonicalHeaderKey(k)
		if hopHeaders[c] || strings.HasPrefix(c, "X-Rv-") {
			continue
		}
		dst[c] = vs
	}
}

func fail(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code, "message": msg}})
}

func readLimited(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, MaxBody+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxBody {
		return nil, errors.New("too large")
	}
	return b, nil
}

func clientIP(r *http.Request) string {
	// The edge overwrites this header, and only the edge can reach this service
	// because it needs a certificate from the internal CA.
	if f := r.Header.Get("X-Forwarded-For"); f != "" {
		parts := strings.Split(f, ",")
		return strings.TrimSpace(parts[len(parts)-1])
	}
	return ""
}

func safeUpstream(raw string, allowHTTP bool) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && !(allowHTTP && u.Scheme == "http")) {
		return nil, errors.New("the route's upstream must use https")
	}
	return u, nil
}

// ---- HTTP proxy ---------------------------------------------------------------

// Proxy serves JSON-path redaction for any REST API.
type Proxy struct {
	Pool      *pgxpool.Pool
	Vault     *VaultClient
	Upstream  *http.Client
	AllowHTTP bool
	T         *Transformer
	Counters  logproc.Counters
	// FileRedactorURL is where PDFs and images go on a route that redacts files.
	FileRedactorURL string

	mu     sync.RWMutex
	routes map[string]*ProxyRoute
	dest   map[string]string
}

// Handler routes /{route}/{rest...}.
func (p *Proxy) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(`{"status":"ok"}`)) })
	mux.HandleFunc("/{route}/{rest...}", p.serve)
	return mux
}

func pathMatches(pattern, rest string) bool {
	if pattern == "" || pattern == "/**" {
		return true
	}
	if prefix, ok := strings.CutSuffix(pattern, "/**"); ok {
		return rest == prefix || strings.HasPrefix(rest, prefix+"/")
	}
	ok, err := path.Match(pattern, rest)
	return err == nil && ok
}

func (p *Proxy) serve(w http.ResponseWriter, r *http.Request) {
	p.mu.RLock()
	rt := p.routes[r.PathValue("route")]
	p.mu.RUnlock()
	if rt == nil || !keyOK(r.Header.Get("X-RV-Route-Key"), rt.KeyHash) {
		fail(w, 401, "unauthenticated", "unknown route or bad key")
		return
	}
	rest := "/" + r.PathValue("rest")
	if !strings.EqualFold(r.Method, rt.Method) || !pathMatches(rt.PathPattern, rest) {
		fail(w, 405, "not_routed", "this route does not cover that method and path")
		return
	}
	body, err := readLimited(http.MaxBytesReader(w, r.Body, MaxBody+1))
	if err != nil {
		fail(w, 413, "too_large", "body too large")
		return
	}
	caller := r.Header.Get("X-RV-Caller-Token")
	limit := 30 * time.Second
	if rt.FilePolicy == FileRedact {
		limit = 150 * time.Second // reading a scanned PDF takes a while
	}
	ctx, cancel := context.WithTimeout(r.Context(), limit)
	defer cancel()
	ctx = withRequestMeta(ctx, clientIP(r))

	dlpIn := rt.DLP && rt.Direction != "outbound"
	out, contentType, counts, err := p.T.Body(ctx, rt, r.Header.Get("Content-Type"), r.Header.Get("Content-Encoding"), body, rt.Redact, rt.Unredact, caller, dlpIn)
	if err != nil {
		p.closed(w, rt, err)
		return
	}
	q := r.URL.Query()
	if len(rt.Query) > 0 {
		var items []logproc.Item
		var names []string
		for _, qr := range rt.Query {
			if v := q.Get(qr.Param); v != "" {
				items = append(items, logproc.Item{Field: qr.Field, Entity: "free_text", Value: v})
				names = append(names, qr.Param)
			}
		}
		if len(items) > 0 {
			toks := make([]string, len(items))
			if rt.Mode != "process_only" {
				if toks, err = p.T.Tokenize(ctx, rt, items); err != nil {
					p.closed(w, rt, err)
					return
				}
			}
			for i, n := range names {
				if toks[i] == "" {
					q.Del(n)
				} else {
					q.Set(n, toks[i])
				}
				counts[[2]string{"query_rule", "tokenized"}]++
			}
		}
	}
	if dlpIn {
		c, err := p.T.QueryDLP(ctx, rt, q)
		if err != nil {
			p.closed(w, rt, err)
			return
		}
		for k, n := range c {
			counts[k] += n
		}
	}
	base, err := safeUpstream(rt.UpstreamURL, p.AllowHTTP)
	if err != nil {
		fail(w, 502, "bad_upstream", err.Error())
		return
	}
	target := *base
	target.Path = strings.TrimRight(base.Path, "/") + rest
	target.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, r.Method, target.String(), bytes.NewReader(out))
	if err != nil {
		fail(w, 502, "bad_upstream", "could not build the request")
		return
	}
	copyRequestHeaders(req.Header, r.Header)
	// One value, written here: a second Content-Type could be read differently upstream.
	req.Header.Del("Content-Type")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	// The body may have been re-encoded, so a client's own encoding claim no longer holds.
	if len(rt.Redact)+len(rt.Unredact) > 0 || dlpIn {
		req.Header.Del("Content-Encoding")
	}
	hc, err := p.T.Headers(ctx, rt, req.Header, rt.RedactHeaders, rt.UnredactHeaders, caller, dlpIn)
	if err != nil {
		p.closed(w, rt, err)
		return
	}
	for k, n := range hc {
		counts[k] += n
	}
	// With rules to apply to the response, it has to arrive readable.
	if len(rt.ResponseRedact)+len(rt.ResponseUnredact) > 0 {
		req.Header.Del("Accept-Encoding")
	}
	resp, err := p.Upstream.Do(req)
	if err != nil {
		fail(w, 502, "upstream_unavailable", "the upstream cannot be reached")
		return
	}
	defer resp.Body.Close()
	respBody, err := readLimited(resp.Body)
	if err != nil {
		fail(w, 502, "too_large", "the upstream response is too large")
		return
	}
	finalBody, finalType, rc, err := p.T.Body(ctx, rt, resp.Header.Get("Content-Type"), resp.Header.Get("Content-Encoding"), respBody, rt.ResponseRedact, rt.ResponseUnredact, caller, false)
	if err != nil {
		p.closed(w, rt, err)
		return
	}
	for k, n := range rc {
		counts[k] += n
	}
	hr, err := p.T.Headers(ctx, rt, resp.Header, rt.ResponseRedactHeaders, rt.ResponseUnredactHeaders, caller, false)
	if err != nil {
		p.closed(w, rt, err)
		return
	}
	for k, n := range hr {
		counts[k] += n
	}
	p.mu.RLock()
	dest := p.dest[rt.ID]
	p.mu.RUnlock()
	p.Counters.RecordTo(rt.VaultID, "proxy", rt.ID, dest, logproc.HostOf(rt.UpstreamURL), counts, 1)
	for k, vs := range resp.Header {
		c := http.CanonicalHeaderKey(k)
		if !hopHeaders[c] && c != "Set-Cookie" {
			w.Header()[c] = vs
		}
	}
	if finalType != "" {
		w.Header().Set("Content-Type", finalType)
	}
	w.WriteHeader(resp.StatusCode)
	w.Write(finalBody)
}

func (p *Proxy) closed(w http.ResponseWriter, rt *ProxyRoute, err error) {
	switch {
	case errors.Is(err, ErrNotJSON):
		fail(w, 415, "unsupported_body", "this route has field rules, and this body has no fields to apply them to")
	case errors.Is(err, ErrUnreadable):
		fail(w, 415, "unsupported_body", "this body could not be read in full, so it was not forwarded")
	case errors.Is(err, ErrEncoded):
		fail(w, 415, "unsupported_body", "a compressed body cannot be checked, so it was not forwarded")
	case errors.Is(err, ErrFileRefused):
		fail(w, 415, "file_refused", "this route does not accept this file, so it was not forwarded")
	case errors.Is(err, ErrFileService):
		w.Header().Set("Retry-After", "5")
		fail(w, 503, "file_service_unavailable", "the file service cannot be reached; nothing was forwarded")
	case errors.Is(err, ErrCallerRejected):
		fail(w, 401, "unauthenticated", "caller token rejected")
	default:
		log.Printf("route %s: failing closed", rt.ID)
		w.Header().Set("Retry-After", "5")
		fail(w, 503, "vault_unavailable", "the vault cannot be reached; nothing was forwarded")
	}
}

type metaKey struct{}

func withRequestMeta(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, metaKey{}, ip)
}

func requestIP(ctx context.Context) string {
	ip, _ := ctx.Value(metaKey{}).(string)
	return ip
}

// Wire sets the vault-backed callbacks.
func (p *Proxy) Wire() {
	p.T.Tokenize = func(ctx context.Context, r *ProxyRoute, items []logproc.Item) ([]string, error) {
		return p.Vault.Tokenize(ctx, r.VaultID, r.ID, "proxy", items)
	}
	p.T.Reveal = func(ctx context.Context, r *ProxyRoute, caller string, tokens []string) (map[string]string, error) {
		return p.Vault.Reveal(ctx, r.VaultID, caller, requestIP(ctx), "proxy", "proxy route "+r.Name, tokens)
	}
	p.T.RedactFile = p.redactFile
}

// redactFile asks the file redactor, over the internal network, to clean one file.
func (p *Proxy) redactFile(ctx context.Context, r *ProxyRoute, body []byte) ([]byte, string, map[string]int, bool, error) {
	if p.FileRedactorURL == "" || p.Vault == nil || p.Vault.HTTP == nil {
		return nil, "", nil, false, ErrFileService
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(p.FileRedactorURL, "/")+"/internal/redact/"+url.PathEscape(r.VaultID), bytes.NewReader(body))
	if err != nil {
		return nil, "", nil, false, ErrFileService
	}
	req.Header.Set("Authorization", "Bearer "+p.Vault.Token)
	client := &http.Client{Transport: p.Vault.HTTP.Transport, Timeout: 140 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", nil, false, ErrFileService
	}
	defer resp.Body.Close()
	out, err := readLimited(resp.Body)
	if err != nil {
		return nil, "", nil, false, ErrFileService
	}
	switch {
	case resp.StatusCode == http.StatusOK:
	case resp.StatusCode == http.StatusUnsupportedMediaType || resp.StatusCode == http.StatusUnprocessableEntity:
		return nil, "", nil, false, ErrFileRefused
	default:
		return nil, "", nil, false, ErrFileService
	}
	found := map[string]int{}
	if err := json.Unmarshal([]byte(resp.Header.Get("X-RV-Findings")), &found); err != nil {
		return nil, "", nil, false, ErrFileService
	}
	return out, resp.Header.Get("Content-Type"), found, resp.Header.Get("X-RV-Low-Confidence") != "false", nil
}

// Refresh reloads proxy routes.
func (p *Proxy) Refresh(ctx context.Context) error {
	rows, err := p.Pool.Query(ctx, `SELECT id,vault_id,name,direction,method,path_pattern,upstream_url,mode,redact_paths,unredact_paths,response_redact_paths,response_unredact_paths,redact_query,dlp,dlp_excluded_paths,redact_headers,unredact_headers,response_redact_headers,response_unredact_headers,dlp_excluded_headers,dlp_excluded_params,file_policy,route_key_hash FROM control.proxy_routes`)
	if err != nil {
		return err
	}
	defer rows.Close()
	next, dest := map[string]*ProxyRoute{}, map[string]string{}
	for rows.Next() {
		r := &ProxyRoute{}
		var a, b, c, d, q, ha, hb, hc, hd []byte
		if err := rows.Scan(&r.ID, &r.VaultID, &r.Name, &r.Direction, &r.Method, &r.PathPattern, &r.UpstreamURL, &r.Mode, &a, &b, &c, &d, &q, &r.DLP, &r.DLPExcludedPaths, &ha, &hb, &hc, &hd, &r.DLPExcludedHeaders, &r.DLPExcludedParams, &r.FilePolicy, &r.KeyHash); err != nil {
			return err
		}
		for _, x := range []struct {
			raw []byte
			out any
		}{{a, &r.Redact}, {b, &r.Unredact}, {c, &r.ResponseRedact}, {d, &r.ResponseUnredact}, {q, &r.Query}, {ha, &r.RedactHeaders}, {hb, &r.UnredactHeaders}, {hc, &r.ResponseRedactHeaders}, {hd, &r.ResponseUnredactHeaders}} {
			if err := json.Unmarshal(x.raw, x.out); err != nil {
				return fmt.Errorf("route %s: bad rules", r.ID)
			}
		}
		if u, err := url.Parse(r.UpstreamURL); err == nil {
			dest[r.ID] = u.Hostname()
		}
		next[r.ID] = r
	}
	if rows.Err() != nil {
		return rows.Err()
	}
	p.mu.Lock()
	p.routes, p.dest = next, dest
	p.mu.Unlock()
	return nil
}

// Run keeps routes fresh and flushes counts.
func (p *Proxy) Run(ctx context.Context) {
	RunLoop(ctx, p.Refresh, func(c context.Context) error { return p.Counters.Flush(c, p.Pool) })
}

// RunLoop refreshes config and flushes counts every few seconds.
func RunLoop(ctx context.Context, refresh, flush func(context.Context) error) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			fc, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			flush(fc)
			return
		case <-t.C:
			if err := refresh(ctx); err != nil && ctx.Err() == nil {
				log.Print("route refresh failed")
			}
			if err := flush(ctx); err != nil && ctx.Err() == nil {
				log.Print("detection flush failed")
			}
		}
	}
}
