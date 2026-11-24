package gateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"onshore/data-plane/internal/cloak"
	"onshore/data-plane/internal/detect"
	"onshore/data-plane/internal/mask"
	"onshore/data-plane/internal/payload"
)

// AIRoute is one chatbot or agent-assist backend's path to a model provider.
type AIRoute struct {
	ID, VaultID, Name, Upstream, Provider, Mode, KeyHash string
	AllowedModels, EntityTypes                           []string
	Restore                                              bool
	// Cloak holds the route's cloak settings: its shared profile's when it has
	// one, else its own. Empty means a placeholder for every value.
	Cloak cloak.Options
	// TwinDays, when above zero, keeps each request's map in the vault for that
	// many days and returns its id in X-RV-Cloak-Id.
	TwinDays int
}

// AI is an OpenAI-compatible gateway. Provider API keys arrive from the caller and
// pass through, so it stores none.
type AI struct {
	Pool      *pgxpool.Pool
	Engine    *detect.Engine
	Rules     detect.RuleSets
	Vault     *VaultClient
	Upstream  *http.Client
	AllowHTTP bool
	Counters  payload.Counters

	mu     sync.RWMutex
	routes map[string]*AIRoute
}

// aiEndpoints are the forwarded paths. Anything else is refused, not passed along.
var aiEndpoints = map[string]bool{"chat/completions": true, "responses": true, "embeddings": true, "messages": true}

// Handler routes /{route}/v1/{endpoint...}.
func (a *AI) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(`{"status":"ok"}`)) })
	mux.HandleFunc("POST /{route}/v1/{endpoint...}", a.serve)
	return mux
}

// binaryParts are request parts the text detector cannot read. A KYC image in a
// prompt would otherwise leave the country untouched, so enforcing refuses them.
var binaryParts = map[string]bool{"image_url": true, "input_image": true, "input_audio": true, "file": true, "input_file": true, "image": true, "document": true}

func hasBinary(v any) bool {
	switch t := v.(type) {
	case map[string]any:
		for k, c := range t {
			if binaryParts[k] && c != nil {
				return true
			}
			if k == "type" {
				if s, ok := c.(string); ok && binaryParts[s] {
					return true
				}
			}
			if hasBinary(c) {
				return true
			}
		}
	case []any:
		for _, c := range t {
			if hasBinary(c) {
				return true
			}
		}
	}
	return false
}

var skipPaths = map[string]bool{"$.model": true, "$.role": true, "$.messages.role": true, "$.input.role": true}

func skipLeaf(path string) bool {
	if skipPaths[path] {
		return true
	}
	return strings.HasSuffix(path, ".role") || strings.HasSuffix(path, ".type") || strings.HasSuffix(path, ".model") || strings.HasSuffix(path, ".tool_choice")
}

func (a *AI) serve(w http.ResponseWriter, r *http.Request) {
	a.mu.RLock()
	rt := a.routes[r.PathValue("route")]
	a.mu.RUnlock()
	if rt == nil || !KeyOK(r.Header.Get("X-RV-Route-Key"), rt.KeyHash) {
		Fail(w, 401, "unauthenticated", "unknown route or bad key")
		return
	}
	endpoint := r.PathValue("endpoint")
	if !aiEndpoints[endpoint] {
		Fail(w, 404, "not_routed", "this gateway forwards chat/completions, responses, embeddings and messages")
		return
	}
	body, err := ReadLimited(http.MaxBytesReader(w, r.Body, MaxBody+1))
	if err != nil {
		Fail(w, 413, "too_large", "body too large")
		return
	}
	var head struct {
		Model string `json:"model"`
	}
	if err := json.Unmarshal(body, &head); err != nil {
		Fail(w, 400, "invalid_request", "the body must be JSON")
		return
	}
	allowed := false
	for _, m := range rt.AllowedModels {
		allowed = allowed || m == head.Model
	}
	if !allowed {
		Fail(w, 403, "model_not_allowed", "this route does not allow that model")
		return
	}
	entities := map[string]bool{}
	for _, e := range rt.EntityTypes {
		entities[e] = true
	}
	enforcing := rt.Mode == "enforcing"
	rules := detect.SetFor(a.Rules, a.Engine, rt.VaultID)
	if rules == nil {
		Fail(w, 503, "detection_not_ready", "detection rules are not loaded yet; nothing was sent")
		return
	}
	sess := newSession(body, rt.Cloak)
	counts := payload.Counts{}

	var doc any
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		Fail(w, 400, "invalid_request", "the body must be JSON")
		return
	}
	if enforcing && hasBinary(doc) {
		Fail(w, 422, "unsupported_content", "images, audio and files cannot be scanned, so they cannot pass this route")
		return
	}
	out := body
	pl := payload.ParseBody(body)
	for _, l := range pl.Leaves {
		if skipLeaf(l.Path) {
			continue
		}
		if v, changed := cloakText(rules, sess, l.Value, l.Path, l.Hint, entities, enforcing, counts); changed {
			l.Set(v)
		}
	}
	if enforcing {
		if out, err = pl.Encode(nil); err != nil {
			Fail(w, 500, "internal", "could not encode the request")
			return
		}
	}
	// A digital twin is sealed in the vault before anything leaves, so the app
	// can swap values back later. No twin, no request: the app asked for one.
	if enforcing && rt.TwinDays > 0 && len(sess.byPlaceholder) > 0 {
		id, err := a.Vault.SaveTwin(r.Context(), rt.VaultID, rt.ID, rt.TwinDays, sess.twin())
		if err != nil {
			Fail(w, 503, "vault_unavailable", "the digital twin could not be saved; nothing was sent")
			return
		}
		w.Header().Set("X-RV-Cloak-Id", id)
	}
	u, err := SafeUpstream(rt.Upstream, a.AllowHTTP)
	if err != nil {
		Fail(w, 502, "bad_upstream", err.Error())
		return
	}
	target := *u
	target.Path = strings.TrimRight(u.Path, "/") + "/" + endpoint
	target.RawQuery = r.URL.RawQuery
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(out))
	if err != nil {
		Fail(w, 502, "bad_upstream", "could not build the request")
		return
	}
	CopyRequestHeaders(req.Header, r.Header)
	resp, err := a.Upstream.Do(req)
	if err != nil {
		Fail(w, 502, "upstream_unavailable", "the provider cannot be reached")
		return
	}
	defer resp.Body.Close()
	a.Counters.RecordTo(rt.VaultID, "ai", rt.ID, rt.Provider, payload.HostOf(rt.Upstream), counts, 1)

	rs := &restorer{rules: rules, a: a, rt: rt, s: sess, caller: r.Header.Get("X-RV-Caller-Token"), ip: ClientIP(r), purpose: r.Header.Get("X-RV-Purpose")}
	if strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream") {
		for k, vs := range resp.Header {
			if c := http.CanonicalHeaderKey(k); !HopHeaders[c] {
				w.Header()[c] = vs
			}
		}
		w.WriteHeader(resp.StatusCode)
		rs.stream(ctx, w, resp)
		return
	}
	respBody, err := ReadLimited(resp.Body)
	if err != nil {
		Fail(w, 502, "too_large", "the provider response is too large")
		return
	}
	final, err := rs.document(ctx, respBody)
	if err != nil {
		rs.failClosed(w, err)
		return
	}
	for k, vs := range resp.Header {
		if c := http.CanonicalHeaderKey(k); !HopHeaders[c] {
			w.Header()[c] = vs
		}
	}
	w.WriteHeader(resp.StatusCode)
	w.Write(final)
}

// restorer swaps placeholders back. Plaintext needs a route that allows it and a
// caller whose policy permits it; everything else comes back masked.
type restorer struct {
	rules   *detect.RuleSet
	a       *AI
	rt      *AIRoute
	s       *session
	caller  string
	ip      string
	purpose string

	decided   bool
	decisions map[string]string
	held      map[string]string
}

func (rs *restorer) failClosed(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrCallerRejected) {
		Fail(w, 401, "unauthenticated", "caller token rejected")
		return
	}
	Fail(w, 503, "vault_unavailable", "the vault cannot be reached")
}

// decide runs at most once per request, and only if a placeholder came back.
func (rs *restorer) decide(ctx context.Context) error {
	if rs.decided {
		return nil
	}
	rs.decided = true
	if !rs.rt.Restore || rs.caller == "" || len(rs.s.byPlaceholder) == 0 {
		return nil
	}
	want := map[string]int{}
	for _, e := range rs.s.byPlaceholder {
		if e.entity != detect.CardPAN && !e.part { // cards never return in full
			want[string(e.entity)]++
		}
	}
	purpose := rs.purpose
	if purpose == "" {
		purpose = "AI reply on route " + rs.rt.Name
	}
	d, err := rs.a.Vault.Decide(ctx, rs.rt.VaultID, rs.rt.ID, rs.caller, rs.ip, purpose, want)
	if err != nil {
		return err
	}
	rs.decisions = d
	return nil
}

func (rs *restorer) value(p string) (string, bool) {
	e, ok := rs.s.byPlaceholder[p]
	if !ok {
		return "", false
	}
	if rs.decisions[string(e.entity)] == "plaintext" {
		return e.value, true
	}
	if e.entity == Place { // a place nobody may see in full comes back as its state
		if st, ok := cloak.Generalize(string(Place), cloak.State, e.value, time.Now()); ok {
			return st, true
		}
	}
	if rs.rules != nil {
		return rs.rules.MaskValue(e.entity, e.value), true
	}
	return mask.Value(string(e.entity), "default", e.value), true
}

func (rs *restorer) replace(text string) string {
	if len(rs.s.byPlaceholder) == 0 {
		return text
	}
	swap := func(m string) string {
		if v, ok := rs.value(m); ok {
			return v
		}
		return m
	}
	// Stand-in names first: a restored real value must never be read again as a
	// stand-in or a placeholder.
	if re := rs.s.synthRe(); re != nil {
		parts := placeholderRe.Split(text, -1)
		phs := placeholderRe.FindAllString(text, -1)
		var b strings.Builder
		for i, p := range parts {
			b.WriteString(re.ReplaceAllStringFunc(p, swap))
			if i < len(phs) {
				b.WriteString(swap(phs[i]))
			}
		}
		return b.String()
	}
	if !strings.Contains(text, "[") {
		return text
	}
	return placeholderRe.ReplaceAllStringFunc(text, swap)
}

func (rs *restorer) walk(v any) any {
	switch t := v.(type) {
	case string:
		return rs.replace(t)
	case []any:
		for i := range t {
			t[i] = rs.walk(t[i])
		}
	case map[string]any:
		for k := range t {
			t[k] = rs.walk(t[k])
		}
	}
	return v
}

func (rs *restorer) document(ctx context.Context, body []byte) ([]byte, error) {
	if len(rs.s.byPlaceholder) == 0 {
		return body, nil
	}
	if err := rs.decide(ctx); err != nil {
		return nil, err
	}
	var doc any
	d := json.NewDecoder(bytes.NewReader(body))
	d.UseNumber()
	if err := d.Decode(&doc); err != nil {
		return []byte(rs.replace(string(body))), nil
	}
	return encodeNoEscape(rs.walk(doc))
}

func encodeNoEscape(v any) ([]byte, error) {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if err := e.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(b.Bytes(), "\n"), nil
}

// holdFrom finds where text could be the start of a placeholder split across
// chunks. Everything before it is safe to emit now.
func holdFrom(text string) int {
	i := strings.LastIndexByte(text, '[')
	if i < 0 || len(text)-i > 40 || strings.IndexByte(text[i:], ']') >= 0 {
		return len(text)
	}
	for _, c := range text[i+1:] {
		if !(c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			return len(text)
		}
	}
	return i
}

func (rs *restorer) delta(key, text string, flush bool) string {
	if rs.held == nil {
		rs.held = map[string]string{}
	}
	text = rs.held[key] + text
	rs.held[key] = ""
	if !flush {
		cut := min(holdFrom(text), rs.s.nameHold(text))
		rs.held[key], text = text[cut:], text[:cut]
	}
	return rs.replace(text)
}

// stream restores placeholders in server-sent events, holding back any text that
// might be a placeholder split across chunks.
func (rs *restorer) stream(ctx context.Context, w http.ResponseWriter, resp *http.Response) {
	flusher, _ := w.(http.Flusher)
	flush := func() {
		if flusher != nil {
			flusher.Flush()
		}
	}
	if err := rs.decide(ctx); err != nil {
		// Headers are sent. End the stream rather than risk an unmasked placeholder map.
		fmt.Fprint(w, "event: error\ndata: {\"error\":{\"code\":\"vault_unavailable\"}}\n\n")
		flush()
		return
	}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64*1024), MaxBody)
	for sc.Scan() {
		line := sc.Text()
		data, isData := strings.CutPrefix(line, "data: ")
		if !isData {
			data, isData = strings.CutPrefix(line, "data:")
		}
		if !isData {
			fmt.Fprintln(w, line)
			if line == "" {
				flush()
			}
			continue
		}
		if strings.TrimSpace(data) == "[DONE]" {
			if tail := rs.flushAll(); tail != "" {
				out, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{"index": 0, "delta": map[string]any{"content": tail}}}})
				fmt.Fprintf(w, "data: %s\n\n", out)
			}
			fmt.Fprintln(w, line)
			continue
		}
		var ev map[string]any
		d := json.NewDecoder(strings.NewReader(data))
		d.UseNumber()
		if err := d.Decode(&ev); err != nil {
			fmt.Fprintf(w, "data: %s\n", rs.replace(data))
			continue
		}
		rs.event(ev)
		out, err := encodeNoEscape(ev)
		if err != nil {
			continue
		}
		fmt.Fprintf(w, "data: %s\n", out)
	}
	if tail := rs.flushAll(); tail != "" {
		out, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{"index": 0, "delta": map[string]any{"content": tail}}}})
		fmt.Fprintf(w, "data: %s\n\n", out)
	}
	flush()
}

func (rs *restorer) flushAll() string {
	var b strings.Builder
	for k, v := range rs.held {
		if v != "" {
			b.WriteString(rs.replace(v))
			rs.held[k] = ""
		}
	}
	return b.String()
}

// event handles the three streaming shapes: OpenAI chat, OpenAI responses and
// Anthropic messages. Whole-text fields in any other event are restored directly.
func (rs *restorer) event(ev map[string]any) {
	if choices, ok := ev["choices"].([]any); ok {
		for i, c := range choices {
			ch, ok := c.(map[string]any)
			if !ok {
				continue
			}
			key := fmt.Sprintf("c%d", i)
			if idx, ok := ch["index"]; ok {
				key = fmt.Sprintf("c%v", idx)
			}
			finished := ch["finish_reason"] != nil
			if delta, ok := ch["delta"].(map[string]any); ok {
				if text, ok := delta["content"].(string); ok {
					delta["content"] = rs.delta(key, text, finished)
				} else if finished && rs.held[key] != "" {
					delta["content"] = rs.delta(key, "", true)
				}
			}
			if msg, ok := ch["message"].(map[string]any); ok {
				rs.walk(msg)
			}
		}
		return
	}
	typ, _ := ev["type"].(string)
	switch {
	case strings.HasSuffix(typ, "output_text.delta"):
		if text, ok := ev["delta"].(string); ok {
			ev["delta"] = rs.delta(fmt.Sprintf("r%v.%v", ev["output_index"], ev["content_index"]), text, false)
		}
	case typ == "content_block_delta":
		if d, ok := ev["delta"].(map[string]any); ok {
			if text, ok := d["text"].(string); ok {
				d["text"] = rs.delta(fmt.Sprintf("a%v", ev["index"]), text, false)
			}
		}
	case typ == "content_block_stop":
		// A held tail cannot be added to a stop event; it is flushed before [DONE].
	default:
		rs.walk(ev)
	}
}

// Refresh reloads AI routes.
func (a *AI) Refresh(ctx context.Context) error {
	rows, err := a.Pool.Query(ctx, `SELECT r.id,r.vault_id,r.name,r.upstream_base_url,r.provider,r.mode,r.route_key_hash,r.allowed_models,r.entity_types,r.restore_in_response,r.twin_days,COALESCE(p.options,r.cloak_options,'{}'::jsonb)
		FROM control.ai_routes r LEFT JOIN control.cloak_profiles p ON p.id=r.cloak_profile_id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	next := map[string]*AIRoute{}
	for rows.Next() {
		r := &AIRoute{}
		if err := rows.Scan(&r.ID, &r.VaultID, &r.Name, &r.Upstream, &r.Provider, &r.Mode, &r.KeyHash, &r.AllowedModels, &r.EntityTypes, &r.Restore, &r.TwinDays, &r.Cloak); err != nil {
			return err
		}
		if cloak.Validate(r.Cloak) != nil {
			r.Cloak = nil // never guess at a setting this build does not know
		}
		if _, err := url.Parse(r.Upstream); err != nil {
			continue
		}
		next[r.ID] = r
	}
	if rows.Err() != nil {
		return rows.Err()
	}
	a.mu.Lock()
	a.routes = next
	a.mu.Unlock()
	return nil
}

// Run keeps routes fresh and flushes counts.
func (a *AI) Run(ctx context.Context) {
	RunLoop(ctx, a.Refresh, func(c context.Context) error { return a.Counters.Flush(c, a.Pool) })
}

// PreviewAI powers the console playground: what the provider would receive, and
// what the user would get back with no caller permission. Nothing is sent or stored.
func PreviewAI(rules *detect.RuleSet, opts cloak.Options, prompt, reply string) (string, string, string) {
	s := newSession([]byte(prompt), opts)
	sent, _ := cloakText(rules, s, prompt, "", "", nil, true, payload.Counts{})
	if reply == "" {
		reply = sent
	}
	rs := &restorer{s: s, rt: &AIRoute{}, rules: rules}
	return sent, reply, rs.replace(reply)
}
