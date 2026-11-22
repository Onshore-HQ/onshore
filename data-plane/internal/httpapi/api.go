// Package httpapi exposes the data API and the internal API used by the control
// plane and the log processor. /internal is never routed by the edge.
package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"time"

	"onshore/data-plane/internal/audit"
	"onshore/data-plane/internal/auth"
	"onshore/data-plane/internal/detect"
	"onshore/data-plane/internal/cloak"
	"onshore/data-plane/internal/gateway"
	"onshore/data-plane/internal/license"
	"onshore/data-plane/internal/logproc"
	"onshore/data-plane/internal/mask"
	"onshore/data-plane/internal/policy"
	"onshore/data-plane/internal/vault"
)

// MaxBatch is the largest tokenize or detokenize batch.
const MaxBatch = 500

// MaxBody bounds request bodies.
const MaxBody = 8 << 20

// MaxValueListBody fits the largest list: 100,000 rows of up to 200 characters.
const MaxValueListBody = 48 << 20

// Server wires handlers.
type Server struct {
	Vault         *vault.Service
	Auth          *auth.Authenticator
	InternalToken string
	Version       string
	AuthLimiter   *auth.Limiter
}

type ctxKey int

const callerKey ctxKey = 0

// Handler builds the router.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("POST /v1/auth/token", s.authToken)

	d := func(pattern string, h func(http.ResponseWriter, *http.Request, vault.Caller) error) {
		mux.HandleFunc(pattern, s.authed(h))
	}
	d("POST /v1/vaults/{vault}/tokenize", s.tokenize)
	d("POST /v1/vaults/{vault}/detokenize", s.detokenize)
	d("POST /v1/vaults/{vault}/records", s.insertRecord)
	d("POST /v1/vaults/{vault}/records/{id}/read", s.getRecordPost)
	d("GET /v1/vaults/{vault}/records/{id}", s.getRecord)
	d("PUT /v1/vaults/{vault}/tokens/{token}", s.updateValue)
	d("POST /v1/vaults/{vault}/lookup", s.lookup)
	d("POST /v1/vaults/{vault}/subjects/search", s.listSubjects)
	d("GET /v1/vaults/{vault}/subjects/{id}", s.getSubject)
	d("DELETE /v1/vaults/{vault}/subjects/{id}", s.eraseSubject)
	d("GET /v1/vaults/{vault}/subjects/{id}/export", s.exportSubject)
	d("POST /v1/vaults/{vault}/subjects/{id}/restrict", s.restrictSubject)
	d("POST /v1/detect", s.detect)
	d("POST /v1/vaults/{vault}/flows/{flow}/check", s.flowCheck)
	d("POST /v1/vaults/{vault}/client-tokens", s.clientTokenMint)
	d("POST /v1/vaults/{vault}/resident/check", s.residentCheck)
	d("POST /v1/resident/compare", s.residentCompare)
	d("POST /v1/vaults/{vault}/cloak", s.cloak)
	d("POST /v1/vaults/{vault}/uncloak", s.uncloak)
	d("DELETE /v1/vaults/{vault}/twins/{id}", s.deleteTwin)

	// Secure components. These authenticate by client token, not by bearer.
	mux.HandleFunc("GET /embed/rv.js", s.embedStatic("rv.js", "text/javascript; charset=utf-8", true))
	mux.HandleFunc("GET /embed/rv-watch.js", s.embedStatic("rv-watch.js", "text/javascript; charset=utf-8", true))
	mux.HandleFunc("GET /embed/frame.js", s.embedStatic("frame.js", "text/javascript; charset=utf-8", false))
	mux.HandleFunc("GET /embed/frame.css", s.embedStatic("frame.css", "text/css; charset=utf-8", false))
	mux.HandleFunc("GET /embed/frame/{vault}", s.embedFrame)
	mux.HandleFunc("POST /embed/v1/describe", s.embedDescribe)
	mux.HandleFunc("POST /embed/v1/collect", s.embedCollect)
	mux.HandleFunc("POST /embed/v1/reveal", s.embedReveal)

	i := func(pattern string, h http.HandlerFunc) { mux.HandleFunc(pattern, s.internal(h)) }
	i("POST /internal/policy/compile", s.policyCompile)
	i("POST /internal/policy/simulate", s.policySimulate)
	i("POST /internal/fields/preview", s.fieldPreview)
	i("POST /internal/logs/tokenize", s.logsTokenize)
	i("POST /internal/logs/preview", s.logsPreview)
	i("POST /internal/audit/verify", s.auditVerify)
	i("POST /internal/audit/sign", s.auditSign)
	i("POST /internal/audit/append", s.auditAppend)
	i("POST /internal/sandbox/seed", s.sandboxSeed)
	i("POST /internal/keys/status", s.keyStatus)
	i("POST /internal/keys/rotate", s.keyRotate)
	i("POST /internal/stats", s.stats)
	i("POST /internal/licence", s.licence)
	i("POST /internal/redact", s.redact)
	i("POST /internal/geo/country", s.geoCountry)
	i("POST /internal/gateway/reveal", s.gatewayReveal)
	i("POST /internal/gateway/decide", s.gatewayDecide)
	i("POST /internal/gateway/proxy-preview", s.proxyPreview)
	i("POST /internal/gateway/ai-preview", s.aiPreview)
	i("POST /internal/gateway/file", s.gatewayFile)
	i("POST /internal/cloak/twin", s.cloakTwinSave)
	i("POST /internal/cloak/options", s.cloakOptions)
	i("POST /internal/rulesets/versions", s.rulesetVersions)
	i("POST /internal/rulesets/snapshot", s.rulesetSnapshot)
	i("POST /internal/custom/check", s.customCheck)
	i("POST /internal/custom/bench", s.customBench)
	i("POST /internal/custom/samples/add", s.customSamplesAdd)
	i("POST /internal/custom/samples/delete", s.customSamplesDelete)
	i("POST /internal/custom/samples/run", s.customSamplesRun)
	i("POST /internal/custom/try", s.customTry)
	i("POST /internal/custom/values", s.customValues)
	i("POST /internal/custom/benchmark", s.customBenchmark)
	i("POST /internal/custom/quick-bench", s.customQuickBench)
	return s.middleware(mux)
}

func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := "req_" + randomID()
		w.Header().Set("X-Request-Id", id)
		w.Header().Set("Cache-Control", "no-store")
		limit := int64(MaxBody)
		if r.URL.Path == "/internal/custom/values" {
			limit = MaxValueListBody
		}
		r.Body = http.MaxBytesReader(w, r.Body, limit)
		req := r.WithContext(context.WithValue(r.Context(), ctxKey(1), id))
		rec := &statusRecorder{ResponseWriter: w, status: 200}
		started := time.Now()
		defer func() {
			// A panic value could hold sensitive data, so it is deliberately not logged.
			if p := recover(); p != nil {
				log.Printf("panic handling %s %s request_id=%s", req.Method, req.Pattern, id)
				writeJSON(w, 500, map[string]any{"error": map[string]string{"code": "internal", "message": "internal error"}, "request_id": id})
			}
			// The route pattern, never the URL: services do not log request contents.
			log.Printf("%s %d %dms request_id=%s", req.Pattern, rec.status, time.Since(started).Milliseconds(), id)
		}()
		next.ServeHTTP(rec, req)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (w *statusRecorder) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func randomID() string {
	b := make([]byte, 12)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func requestID(r *http.Request) string {
	id, _ := r.Context().Value(ctxKey(1)).(string)
	return id
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func decode(r *http.Request, v any) error {
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		// Decoder errors can echo input, so the message stays generic.
		return &vault.Error{Status: 400, Code: "invalid_request", Message: "malformed body or unknown field"}
	}
	return nil
}

func writeErr(w http.ResponseWriter, r *http.Request, err error) {
	var ae *vault.Error
	if errors.As(err, &ae) {
		writeJSON(w, ae.Status, map[string]any{"error": ae, "request_id": requestID(r)})
		return
	}
	// Details stay out of the response and the log: driver errors can quote values.
	log.Printf("internal error on %s request_id=%s", r.Pattern, requestID(r))
	writeJSON(w, 500, map[string]any{"error": map[string]string{"code": "internal", "message": "internal error"}, "request_id": requestID(r)})
}

func (s *Server) authed(h func(http.ResponseWriter, *http.Request, vault.Caller) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := s.Auth.Authenticate(r.Context(), r)
		if err != nil {
			if s.tooMany(w, r) {
				return
			}
			status, code := 401, "unauthenticated"
			if errors.Is(err, auth.ErrForbiddenIP) {
				status, code = 403, "policy_denied"
			}
			writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": err.Error()}, "request_id": requestID(r)})
			return
		}
		c.RequestID = requestID(r)
		if r.Header.Get("X-RV-Module") == "console" && c.Kind == "user" {
			c.Module = "console"
		}
		if err := h(w, r, c); err != nil {
			writeErr(w, r, err)
		}
	}
}

func (s *Server) internal(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("Authorization")
		want := "Bearer " + s.InternalToken
		if s.InternalToken == "" || subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
			writeJSON(w, 401, map[string]any{"error": map[string]string{"code": "unauthenticated", "message": "internal token required"}})
			return
		}
		h(w, r)
	}
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	// Reachable without a token, so it names no version or key backend.
	status := map[string]any{"database": "ok", "keys": "ok"}
	code := 200
	if err := s.Vault.Pool.Ping(ctx); err != nil {
		status["database"], code = "unavailable", 503
	}
	if err := s.Vault.Keys.Health(ctx); err != nil {
		status["keys"], code = "unavailable", 503
	}
	writeJSON(w, code, status)
}

func (s *Server) tooMany(w http.ResponseWriter, r *http.Request) bool {
	if s.AuthLimiter.Allow(s.Auth.ClientIP(r), time.Now()) {
		return false
	}
	w.Header().Set("Retry-After", "60")
	writeJSON(w, 429, map[string]any{"error": map[string]string{"code": "rate_limited", "message": "too many failed attempts"}, "request_id": requestID(r)})
	return true
}

func (s *Server) authToken(w http.ResponseWriter, r *http.Request) {
	if s.tooMany(w, r) {
		return
	}
	var body struct {
		Assertion string `json:"assertion"`
	}
	if err := decode(r, &body); err != nil {
		writeErr(w, r, err)
		return
	}
	tok, err := s.Auth.ExchangeAssertion(r.Context(), body.Assertion, s.Auth.ClientIP(r))
	if err != nil {
		status, code := 401, "unauthenticated"
		if errors.Is(err, auth.ErrForbiddenIP) {
			status, code = 403, "policy_denied"
		} else if !errors.Is(err, auth.ErrUnauthenticated) {
			writeErr(w, r, err)
			return
		}
		writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": "assertion rejected"}, "request_id": requestID(r)})
		return
	}
	writeJSON(w, 200, map[string]any{"access_token": tok, "token_type": "Bearer", "expires_in": int(auth.TokenTTL.Seconds())})
}

func tooBig(n int) error {
	if n == 0 {
		return &vault.Error{Status: 400, Code: "invalid_request", Message: "items is empty"}
	}
	if n > MaxBatch {
		return &vault.Error{Status: 400, Code: "invalid_request", Message: "a batch holds at most 500 items"}
	}
	return nil
}

func (s *Server) tokenize(w http.ResponseWriter, r *http.Request, c vault.Caller) error {
	var body struct {
		Items           []vault.TokenizeItem `json:"items"`
		ContinueOnError bool                 `json:"continue_on_error"`
		DryRun          bool                 `json:"dry_run"`
	}
	if err := decode(r, &body); err != nil {
		return err
	}
	if err := tooBig(len(body.Items)); err != nil {
		return err
	}
	ctx := r.Context()
	if body.DryRun {
		ctx = vault.WithDryRun(ctx)
	}
	res, err := s.Vault.Tokenize(ctx, c, r.PathValue("vault"), body.Items, body.ContinueOnError, "tokenize")
	if err != nil {
		return err
	}
	writeJSON(w, 200, map[string]any{"results": res, "request_id": c.RequestID})
	return nil
}

func requirePurpose(p string) error {
	if p == "" {
		return &vault.Error{Status: 400, Code: "invalid_request", Message: "purpose is required for every reveal"}
	}
	if len(p) > 500 {
		return &vault.Error{Status: 400, Code: "invalid_request", Message: "purpose is too long"}
	}
	return nil
}

func (s *Server) detokenize(w http.ResponseWriter, r *http.Request, c vault.Caller) error {
	var body struct {
		Items []struct {
			Token     string `json:"token"`
			Redaction string `json:"redaction"`
		} `json:"items"`
		Purpose         string `json:"purpose"`
		ContinueOnError bool   `json:"continue_on_error"`
	}
	if err := decode(r, &body); err != nil {
		return err
	}
	if err := tooBig(len(body.Items)); err != nil {
		return err
	}
	if err := requirePurpose(body.Purpose); err != nil {
		return err
	}
	tokens := make([]string, len(body.Items))
	for i, it := range body.Items {
		tokens[i] = it.Token
	}
	narrow := make([]string, len(body.Items))
	for i, it := range body.Items {
		if it.Redaction != "" && it.Redaction != policy.Masked && it.Redaction != policy.TokenOnly {
			return &vault.Error{Status: 400, Code: "invalid_request", Message: "redaction can only narrow: masked or token_only"}
		}
		narrow[i] = it.Redaction
	}
	res, err := s.Vault.DetokenizeNarrowed(r.Context(), c, r.PathValue("vault"), tokens, narrow, body.Purpose, body.ContinueOnError)
	if err != nil {
		return err
	}
	writeJSON(w, 200, map[string]any{"results": res, "request_id": c.RequestID})
	return nil
}

func (s *Server) insertRecord(w http.ResponseWriter, r *http.Request, c vault.Caller) error {
	var body struct {
		Fields     map[string]string `json:"fields"`
		SubjectRef string            `json:"subject_ref"`
	}
	if err := decode(r, &body); err != nil {
		return err
	}
	if err := tooBig(len(body.Fields)); err != nil {
		return err
	}
	id, tokens, err := s.Vault.InsertRecord(r.Context(), c, r.PathValue("vault"), body.Fields, body.SubjectRef)
	if err != nil {
		return err
	}
	writeJSON(w, 200, map[string]any{"id": id, "tokens": tokens, "request_id": c.RequestID})
	return nil
}

// getRecord takes purpose in a header: query strings end up in access logs.
func (s *Server) getRecord(w http.ResponseWriter, r *http.Request, c vault.Caller) error {
	purpose := r.Header.Get("X-RV-Purpose")
	if err := requirePurpose(purpose); err != nil {
		return err
	}
	return s.writeRecord(w, r, c, purpose)
}

func (s *Server) getRecordPost(w http.ResponseWriter, r *http.Request, c vault.Caller) error {
	var body struct {
		Purpose string `json:"purpose"`
	}
	if err := decode(r, &body); err != nil {
		return err
	}
	if err := requirePurpose(body.Purpose); err != nil {
		return err
	}
	return s.writeRecord(w, r, c, body.Purpose)
}

func (s *Server) writeRecord(w http.ResponseWriter, r *http.Request, c vault.Caller, purpose string) error {
	res, err := s.Vault.GetRecord(r.Context(), c, r.PathValue("vault"), r.PathValue("id"), purpose)
	if err != nil {
		return err
	}
	writeJSON(w, 200, map[string]any{"fields": res, "request_id": c.RequestID})
	return nil
}

func (s *Server) updateValue(w http.ResponseWriter, r *http.Request, c vault.Caller) error {
	var body struct {
		Value string `json:"value"`
	}
	if err := decode(r, &body); err != nil {
		return err
	}
	if err := s.Vault.UpdateValue(r.Context(), c, r.PathValue("vault"), r.PathValue("token"), body.Value); err != nil {
		return err
	}
	writeJSON(w, 200, map[string]any{"token": r.PathValue("token"), "request_id": c.RequestID})
	return nil
}

func (s *Server) lookup(w http.ResponseWriter, r *http.Request, c vault.Caller) error {
	var body struct {
		Field string `json:"field"`
		Value string `json:"value"`
	}
	if err := decode(r, &body); err != nil {
		return err
	}
	tok, err := s.Vault.Lookup(r.Context(), c, r.PathValue("vault"), body.Field, body.Value)
	if err != nil {
		return err
	}
	writeJSON(w, 200, map[string]any{"token": tok, "request_id": c.RequestID})
	return nil
}

func (s *Server) listSubjects(w http.ResponseWriter, r *http.Request, c vault.Caller) error {
	var q vault.SubjectQuery
	if err := decode(r, &q); err != nil {
		return err
	}
	if q.Offset < 0 {
		q.Offset = 0
	}
	res, total, err := s.Vault.ListSubjects(r.Context(), c, r.PathValue("vault"), q)
	if err != nil {
		return err
	}
	writeJSON(w, 200, map[string]any{"subjects": res, "total": total})
	return nil
}

func (s *Server) getSubject(w http.ResponseWriter, r *http.Request, c vault.Caller) error {
	d, err := s.Vault.GetSubject(r.Context(), c, r.PathValue("vault"), r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, 200, d)
	return nil
}

func (s *Server) eraseSubject(w http.ResponseWriter, r *http.Request, c vault.Caller) error {
	purpose := r.Header.Get("X-RV-Purpose")
	if err := requirePurpose(purpose); err != nil {
		return err
	}
	n, err := s.Vault.EraseSubject(r.Context(), c, r.PathValue("vault"), r.PathValue("id"), purpose)
	if err != nil {
		return err
	}
	writeJSON(w, 200, map[string]any{"erased_records": n, "request_id": c.RequestID})
	return nil
}

func (s *Server) exportSubject(w http.ResponseWriter, r *http.Request, c vault.Caller) error {
	purpose := r.Header.Get("X-RV-Purpose")
	if err := requirePurpose(purpose); err != nil {
		return err
	}
	res, err := s.Vault.ExportSubject(r.Context(), c, r.PathValue("vault"), r.PathValue("id"), purpose)
	if err != nil {
		return err
	}
	writeJSON(w, 200, map[string]any{"subject_id": r.PathValue("id"), "fields": res, "request_id": c.RequestID})
	return nil
}

func (s *Server) restrictSubject(w http.ResponseWriter, r *http.Request, c vault.Caller) error {
	var body struct {
		Restricted bool   `json:"restricted"`
		Purpose    string `json:"purpose"`
	}
	if err := decode(r, &body); err != nil {
		return err
	}
	if err := requirePurpose(body.Purpose); err != nil {
		return err
	}
	if err := s.Vault.RestrictSubject(r.Context(), c, r.PathValue("vault"), r.PathValue("id"), body.Restricted, body.Purpose); err != nil {
		return err
	}
	writeJSON(w, 200, map[string]any{"restricted": body.Restricted})
	return nil
}

// detect finds entities; with tokenize it also vaults them. Card numbers are
// always masked, never vaulted. A type with no matching field is masked too.
func (s *Server) detect(w http.ResponseWriter, r *http.Request, c vault.Caller) error {
	var body struct {
		Text          string   `json:"text"`
		Tokenize      bool     `json:"tokenize"`
		Vault         string   `json:"vault"`
		Entities      []string `json:"entities"`
		IncludeShadow bool     `json:"include_shadow"`
	}
	if err := decode(r, &body); err != nil {
		return err
	}
	if len(body.Text) > logproc.MaxLeafBytes {
		return &vault.Error{Status: 400, Code: "invalid_request", Message: "text exceeds 1 MiB"}
	}
	if body.Tokenize && body.Vault == "" {
		return &vault.Error{Status: 400, Code: "invalid_request", Message: "vault is required with tokenize"}
	}
	// Custom entities belong to a vault, so they apply only when the caller names one.
	rs := detect.GlobalRuleSet(s.Vault.Engine)
	var v *vault.VaultMeta
	if body.Vault != "" {
		var err error
		if v, err = s.Vault.Vault(r.Context(), body.Vault); err != nil {
			return err
		}
		if v.TenantID != c.TenantID {
			return &vault.Error{Status: 404, Code: "invalid_request", Message: "unknown vault"}
		}
		if rs = s.Vault.RulesFor(body.Vault); rs == nil {
			return &vault.Error{Status: 503, Code: "detection_not_ready", Message: "detection rules are not loaded yet"}
		}
	}
	wanted := func(t detect.EntityType) bool {
		if len(body.Entities) == 0 {
			return true
		}
		for _, n := range body.Entities {
			if n == string(t) {
				return true
			}
		}
		return false
	}
	ents, observed := rs.Split(rs.ScanFor("api", "", body.Text, ""))
	if rs.Version != 0 && body.Text != "" {
		// A JSON body also gets JSON path entities, placed by locating each value.
		ents = rs.AddPathMatches(body.Text, ents)
	}
	kept := make([]detect.Entity, 0, len(ents))
	for _, e := range ents {
		if wanted(e.Type) {
			kept = append(kept, e)
		}
	}
	ents = kept
	listed := append([]detect.Entity{}, ents...)
	if body.IncludeShadow {
		for _, e := range observed {
			if e.Shadow && wanted(e.Type) {
				listed = append(listed, e)
			}
		}
	}
	out := map[string]any{"entities": listed, "request_id": c.RequestID, "ruleset_version": rs.Version}
	if body.Tokenize {
		var items []vault.TokenizeItem
		itemFor := map[int]int{}
		for i, e := range ents {
			if act := rs.ModuleAction(e, "api"); act != "" && act != "tokenize" {
				continue
			}
			if name := v.FieldForEntity(string(e.Type)); name != "" && e.Type != detect.CardPAN {
				itemFor[i] = len(items)
				items = append(items, vault.TokenizeItem{Field: name, Value: body.Text[e.Start:e.End]})
			}
		}
		var res []vault.ItemResult
		if len(items) > 0 {
			if err := tooBig(len(items)); err != nil {
				return err
			}
			var err error
			if res, err = s.Vault.Tokenize(r.Context(), c, body.Vault, items, false, "tokenize"); err != nil {
				return err
			}
		}
		pos := 0
		out["text"] = detect.Replace(body.Text, ents, func(e detect.Entity, val string) string {
			i := pos
			pos++
			if j, ok := itemFor[i]; ok {
				return res[j].Token
			}
			if rs.ModuleAction(e, "api") == "drop" {
				return "[rv:dropped]"
			}
			return rs.MaskValue(e.Type, val)
		})
	}
	writeJSON(w, 200, out)
	return nil
}

// ---- internal ----------------------------------------------------------------

func (s *Server) policyCompile(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name    string          `json:"name"`
		Version int             `json:"version"`
		Source  json.RawMessage `json:"source"`
	}
	if err := decode(r, &body); err != nil {
		writeErr(w, r, err)
		return
	}
	d, err := policy.ParseDoc(body.Source)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": map[string]string{"code": "invalid_request", "message": "policy has unknown or malformed keys"}})
		return
	}
	c, err := policy.Compile(d)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": map[string]string{"code": "invalid_request", "message": err.Error()}})
		return
	}
	writeJSON(w, 200, map[string]any{"compiled": c, "readable": policy.Readable(body.Name, body.Version, d)})
}

func (s *Server) policySimulate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		TenantID    string   `json:"tenant_id"`
		Action      string   `json:"action"`
		PrincipalID string   `json:"principal_id"`
		Roles       []string `json:"roles"`
		MFA         bool     `json:"mfa"`
		Networks    []string `json:"networks"`
		SourceIP    string   `json:"source_ip"`
		FieldName   string   `json:"field_name"`
		DataType    string   `json:"data_type"`
		Purpose     string   `json:"purpose"`
		Hour        int      `json:"hour"`
		Draft       *struct {
			Name    string          `json:"name"`
			Version int             `json:"version"`
			Source  json.RawMessage `json:"source"`
		} `json:"draft"`
	}
	if err := decode(r, &body); err != nil {
		writeErr(w, r, err)
		return
	}
	var draft *policy.Active
	if body.Draft != nil {
		d, err := policy.ParseDoc(body.Draft.Source)
		if err == nil {
			var c *policy.Compiled
			if c, err = policy.Compile(d); err == nil {
				draft = &policy.Active{ID: "draft", Name: body.Draft.Name, Version: body.Draft.Version, LimitPerHour: d.LimitPerHour, Compiled: *c}
			}
		}
		if err != nil {
			writeJSON(w, 400, map[string]any{"error": map[string]string{"code": "invalid_request", "message": err.Error()}})
			return
		}
	}
	nets := body.Networks
	if body.SourceIP != "" {
		n, err := s.Vault.NetworksFor(r.Context(), body.TenantID, body.SourceIP)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		nets = n
	}
	d, err := s.Vault.Simulate(r.Context(), body.TenantID, policy.Request{Action: body.Action, PrincipalID: body.PrincipalID, Roles: body.Roles, MFA: body.MFA, Networks: nets, FieldName: body.FieldName, FieldDataType: body.DataType, Purpose: body.Purpose, Hour: body.Hour}, draft)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeJSON(w, 200, d)
}

// fieldPreview shows what a field would produce for a sample. Nothing is stored,
// and the control plane restricts it to sandbox vaults.
func (s *Server) fieldPreview(w http.ResponseWriter, r *http.Request) {
	var body struct {
		DataType    string `json:"data_type"`
		TokenFormat string `json:"token_format"`
		MaskRule    string `json:"mask_rule"`
		Value       string `json:"value"`
	}
	if err := decode(r, &body); err != nil {
		writeErr(w, r, err)
		return
	}
	n, ok := vault.Normalize(body.DataType, body.Value)
	res := map[string]any{"valid": ok}
	if ok {
		res["token"] = vault.NewToken(body.DataType, body.TokenFormat)
		res["masked"] = mask.Value(body.DataType, body.MaskRule, n)
		res["normalized_length"] = len(n)
	}
	ents := s.Vault.Engine.ScanWithHint(body.Value, body.DataType)
	det := []string{}
	var best float64
	for _, e := range ents {
		det = append(det, string(e.Type))
		if e.Score > best {
			best = e.Score
		}
	}
	res["detected_as"], res["score"] = det, best
	writeJSON(w, 200, res)
}

func (s *Server) logsTokenize(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Vault    string         `json:"vault"`
		Pipeline string         `json:"pipeline"`
		Module   string         `json:"module"`
		Items    []logproc.Item `json:"items"`
	}
	if err := decode(r, &body); err != nil {
		writeErr(w, r, err)
		return
	}
	if err := tooBig(len(body.Items)); err != nil {
		writeErr(w, r, err)
		return
	}
	v, err := s.Vault.Vault(r.Context(), body.Vault)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	tokens := make([]string, len(body.Items))
	var items []vault.TokenizeItem
	var pos []int
	for i, it := range body.Items {
		name := it.Field
		if name == "" {
			name = v.DeterministicFieldForEntity(it.Entity)
		}
		if name != "" {
			items = append(items, vault.TokenizeItem{Field: name, Value: it.Value})
			pos = append(pos, i)
		}
	}
	if len(items) > 0 {
		module := body.Module
		if module == "" {
			module = "logs"
		}
		c := vault.Caller{TenantID: v.TenantID, PrincipalID: module + ":" + body.Pipeline, Kind: "pipeline", Module: module, System: true, RequestID: requestID(r)}
		// continue_on_error: a value that fails validation is masked by the caller.
		res, err := s.Vault.Tokenize(r.Context(), c, body.Vault, items, true, "tokenize")
		if err != nil {
			writeErr(w, r, err)
			return
		}
		for j, it := range res {
			tokens[pos[j]] = it.Token
		}
	}
	writeJSON(w, 200, map[string]any{"tokens": tokens})
}

type previewTokenizer struct{}

func (previewTokenizer) Tokenize(_ context.Context, _, _ string, items []logproc.Item) ([]string, error) {
	out := make([]string, len(items))
	for i, it := range items {
		out[i] = vault.NewToken(it.Entity, "opaque")
	}
	return out, nil
}

// logsPreview shows exactly what a pipeline would forward, without vaulting.
func (s *Server) logsPreview(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Sample    string            `json:"sample"`
		Actions   map[string]string `json:"action_per_type"`
		Entities  []string          `json:"entity_types"`
		Sensitive []string          `json:"sensitive_paths"`
		Vault     string            `json:"vault_id"`
	}
	if err := decode(r, &body); err != nil {
		writeErr(w, r, err)
		return
	}
	p := &logproc.Pipeline{Mode: "enforcing", Actions: body.Actions, EntityTypes: map[string]bool{}, SensitivePaths: logproc.ParseSensitivePaths(body.Sensitive)}
	for _, e := range body.Entities {
		p.EntityTypes[e] = true
	}
	pl := logproc.ParseBody([]byte(body.Sample))
	pr := &logproc.Processor{Engine: s.Vault.Engine, Rules: staticRules{s.previewRules(body.Vault)}, Tokenizer: previewTokenizer{}}
	o, err := pr.Process(r.Context(), p, pl.Leaves)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	b, err := pl.Encode(o.Dropped)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	counts := map[string]int64{}
	for k, v := range o.Counts {
		counts[k[0]+":"+k[1]] = v
	}
	writeJSON(w, 200, map[string]any{"after": string(b), "counts": counts})
}

func (s *Server) auditVerify(w http.ResponseWriter, r *http.Request) {
	var body struct {
		TenantID string `json:"tenant_id"`
	}
	if err := decode(r, &body); err != nil {
		writeErr(w, r, err)
		return
	}
	res, err := s.Vault.VerifyAudit(r.Context(), body.TenantID)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeJSON(w, 200, res)
}

// redact removes identifiers from free text the control plane is about to store.
func (s *Server) redact(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Text string `json:"text"`
	}
	if err := decode(r, &body); err != nil {
		writeErr(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]string{"text": s.Vault.CleanPurpose(body.Text)})
}

// geoCountry answers the country for an address, as a hint for the residency map. It is
// empty when no table is loaded, and is never treated as the answer.
func (s *Server) geoCountry(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IP string `json:"ip"`
	}
	if err := decode(r, &body); err != nil {
		writeErr(w, r, err)
		return
	}
	country := ""
	if s.Vault.Geo != nil {
		country = s.Vault.Geo.Country(body.IP)
	}
	writeJSON(w, 200, map[string]string{"country": country})
}

func (s *Server) auditSign(w http.ResponseWriter, r *http.Request) {
	var body struct {
		TenantID string `json:"tenant_id"`
		Message  string `json:"message_b64"`
	}
	if err := decode(r, &body); err != nil {
		writeErr(w, r, err)
		return
	}
	msg, err := base64.StdEncoding.DecodeString(body.Message)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": map[string]string{"code": "invalid_request", "message": "bad base64"}})
		return
	}
	sig, pub, err := s.Vault.SignForTenant(r.Context(), body.TenantID, msg)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{"signature": sig, "public_key": pub})
}

func (s *Server) keyStatus(w http.ResponseWriter, r *http.Request) {
	var body struct {
		TenantID string `json:"tenant_id"`
	}
	if err := decode(r, &body); err != nil {
		writeErr(w, r, err)
		return
	}
	res, err := s.Vault.KeyStatus(r.Context(), body.TenantID)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeJSON(w, 200, res)
}

func (s *Server) keyRotate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		TenantID    string `json:"tenant_id"`
		PrincipalID string `json:"principal_id"`
		Kind        string `json:"kind"`
		VaultID     string `json:"vault_id"`
		Reencrypt   bool   `json:"reencrypt"`
	}
	if err := decode(r, &body); err != nil {
		writeErr(w, r, err)
		return
	}
	c := vault.Caller{TenantID: body.TenantID, PrincipalID: body.PrincipalID, Kind: "user", Module: "console", RequestID: requestID(r)}
	var err error
	switch body.Kind {
	case "kek":
		err = s.Vault.RotateKEK(r.Context(), c)
	case "dek":
		err = s.Vault.RotateDEK(r.Context(), c, body.VaultID, body.Reencrypt)
	default:
		err = &vault.Error{Status: 400, Code: "invalid_request", Message: "kind must be kek or dek"}
	}
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{"rotated": body.Kind})
}

func (s *Server) stats(w http.ResponseWriter, r *http.Request) {
	var body struct {
		TenantID string `json:"tenant_id"`
	}
	if err := decode(r, &body); err != nil {
		writeErr(w, r, err)
		return
	}
	res, err := s.Vault.Stats(r.Context(), body.TenantID)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeJSON(w, 200, res)
}

// auditAppend records control-plane actions (policy publish, login, key changes)
// on the same chain, which only the data plane's role can write.
func (s *Server) auditAppend(w http.ResponseWriter, r *http.Request) {
	var body struct {
		TenantID    string `json:"tenant_id"`
		VaultID     string `json:"vault_id"`
		PrincipalID string `json:"principal_id"`
		Kind        string `json:"principal_kind"`
		SourceIP    string `json:"source_ip"`
		Action      string `json:"action"`
		PolicyID    string `json:"policy_id"`
		PolicyVer   int    `json:"policy_version"`
		Decision    string `json:"decision"`
		BreakGlass  bool   `json:"break_glass"`
		Detail      string `json:"detail"`
	}
	if err := decode(r, &body); err != nil {
		writeErr(w, r, err)
		return
	}
	err := s.Vault.AppendControlEvent(r.Context(), audit.Event{TenantID: body.TenantID, VaultID: body.VaultID, PrincipalID: body.PrincipalID, PrincipalKind: body.Kind, SourceIP: body.SourceIP, Module: "console", Action: body.Action, PolicyID: body.PolicyID, PolicyVersion: body.PolicyVer, Decision: body.Decision, BreakGlass: body.BreakGlass, Detail: body.Detail, RequestID: requestID(r)})
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// sandboxSeed fills a sandbox vault with synthetic people. It refuses production.
func (s *Server) sandboxSeed(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Vault string `json:"vault"`
		Count int    `json:"count"`
	}
	if err := decode(r, &body); err != nil {
		writeErr(w, r, err)
		return
	}
	n, err := s.Vault.SeedSandbox(r.Context(), body.Vault, body.Count)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]int{"subjects": n})
}

// licence reports the installed licence, checked offline against the built-in key.
func (s *Server) licence(w http.ResponseWriter, r *http.Request) {
	blob := os.Getenv("RV_LICENCE")
	if blob == "" {
		writeJSON(w, 200, map[string]any{"installed": false})
		return
	}
	key, err := license.BuiltInKey()
	var l license.Licence
	if err == nil {
		l, err = license.Verify(blob, key)
	}
	if err != nil {
		writeJSON(w, 200, map[string]any{"installed": true, "valid": false})
		return
	}
	writeJSON(w, 200, map[string]any{"installed": true, "valid": true, "customer": l.Customer, "modules": l.Modules, "seats": l.Seats, "max_records": l.MaxRecords, "expires_at": l.ExpiresAt, "expired": l.Expired(time.Now())})
}

// caller authenticates the end user behind a gateway request.
func (s *Server) gatewayCaller(r *http.Request, token, ip, module string) (vault.Caller, error) {
	c, err := s.Auth.AuthenticateToken(r.Context(), token, ip)
	if err != nil {
		return vault.Caller{}, err
	}
	c.Module, c.RequestID = module, requestID(r)
	return c, nil
}

// gatewayReveal detokenizes for a gateway, as the end user whose token it carries.
func (s *Server) gatewayReveal(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Vault       string   `json:"vault"`
		CallerToken string   `json:"caller_token"`
		SourceIP    string   `json:"source_ip"`
		Module      string   `json:"module"`
		Purpose     string   `json:"purpose"`
		Tokens      []string `json:"tokens"`
	}
	if err := decode(r, &body); err != nil {
		writeErr(w, r, err)
		return
	}
	c, err := s.gatewayCaller(r, body.CallerToken, body.SourceIP, body.Module)
	if err != nil {
		writeJSON(w, 401, map[string]any{"error": map[string]string{"code": "unauthenticated", "message": "caller token rejected"}})
		return
	}
	res, err := s.Vault.Detokenize(r.Context(), c, body.Vault, body.Tokens, body.Purpose, true)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{"results": res})
}

// gatewayDecide answers what a caller may see of each entity type in an AI reply.
// The values sit in the gateway's memory for one request; only the decision and an
// audit event pass through here.
func (s *Server) gatewayDecide(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Vault       string         `json:"vault"`
		Route       string         `json:"route"`
		CallerToken string         `json:"caller_token"`
		SourceIP    string         `json:"source_ip"`
		Purpose     string         `json:"purpose"`
		Entities    map[string]int `json:"entities"`
	}
	if err := decode(r, &body); err != nil {
		writeErr(w, r, err)
		return
	}
	c, err := s.gatewayCaller(r, body.CallerToken, body.SourceIP, "ai")
	if err != nil {
		writeJSON(w, 401, map[string]any{"error": map[string]string{"code": "unauthenticated", "message": "caller token rejected"}})
		return
	}
	out, err := s.Vault.DecideRestore(r.Context(), c, body.Vault, body.Route, body.Purpose, body.Entities)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{"decisions": out})
}

// proxyPreview shows a route's rules applied to samples. Nothing is stored.
func (s *Server) proxyPreview(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Route    gateway.ProxyRoute `json:"route"`
		Request  string             `json:"request"`
		Response string             `json:"response"`
		Vault    string             `json:"vault_id"`
	}
	if err := decode(r, &body); err != nil {
		writeErr(w, r, err)
		return
	}
	t := &gateway.Transformer{Engine: s.Vault.Engine, Rules: staticRules{s.previewRules(body.Vault)}, Tokenize: gateway.ExampleTokens}
	reqOut, _, err1 := t.Request(r.Context(), &body.Route, []byte(body.Request))
	respOut, _, err2 := t.Response(r.Context(), &body.Route, []byte(body.Response), "")
	res := map[string]any{"request": string(reqOut), "response": string(respOut)}
	if err1 != nil {
		res["request_error"] = err1.Error()
	}
	if err2 != nil {
		res["response_error"] = err2.Error()
	}
	writeJSON(w, 200, res)
}

func (s *Server) residentCompare(w http.ResponseWriter, r *http.Request, c vault.Caller) error {
	var body struct {
		Vault   string `json:"vault"`
		Token   string `json:"token"`
		Value   string `json:"value"`
		Purpose string `json:"purpose"`
	}
	if err := decode(r, &body); err != nil {
		return err
	}
	if err := requirePurpose(body.Purpose); err != nil {
		return err
	}
	ok, err := s.Vault.ResidentCheck(r.Context(), c, body.Vault, body.Token, vault.CheckEquals, body.Value, body.Purpose)
	if err != nil {
		return err
	}
	writeJSON(w, 200, map[string]any{"result": ok, "request_id": c.RequestID})
	return nil
}

func (s *Server) residentCheck(w http.ResponseWriter, r *http.Request, c vault.Caller) error {
	var body struct {
		Token   string `json:"token"`
		Check   string `json:"check"`
		Arg     string `json:"arg"`
		Purpose string `json:"purpose"`
	}
	if err := decode(r, &body); err != nil {
		return err
	}
	if err := requirePurpose(body.Purpose); err != nil {
		return err
	}
	ok, err := s.Vault.ResidentCheck(r.Context(), c, r.PathValue("vault"), body.Token, body.Check, body.Arg, body.Purpose)
	if err != nil {
		return err
	}
	writeJSON(w, 200, map[string]any{"result": ok, "request_id": c.RequestID})
	return nil
}

func (s *Server) aiPreview(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Prompt  string        `json:"prompt"`
		Reply   string        `json:"reply"`
		Vault   string        `json:"vault_id"`
		Options cloak.Options `json:"options"`
	}
	if err := decode(r, &body); err != nil {
		writeErr(w, r, err)
		return
	}
	if err := cloak.Validate(body.Options); err != nil {
		writeErr(w, r, &vault.Error{Status: 400, Code: "invalid_request", Message: err.Error()})
		return
	}
	sent, reply, shown := gateway.PreviewAI(s.previewRules(body.Vault), body.Options, body.Prompt, body.Reply)
	writeJSON(w, 200, map[string]string{"provider_receives": sent, "provider_reply": reply, "user_sees": shown})
}

func (s *Server) gatewayFile(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Vault       string         `json:"vault"`
		CallerToken string         `json:"caller_token"`
		SourceIP    string         `json:"source_ip"`
		Purpose     string         `json:"purpose"`
		Counts      map[string]int `json:"counts"`
		Low         bool           `json:"low_confidence"`
	}
	if err := decode(r, &body); err != nil {
		writeErr(w, r, err)
		return
	}
	c, err := s.gatewayCaller(r, body.CallerToken, body.SourceIP, "files")
	if err != nil {
		writeJSON(w, 401, map[string]any{"error": map[string]string{"code": "unauthenticated", "message": "caller token rejected"}})
		return
	}
	ok, err := s.Vault.AuthorizeFile(r.Context(), c, body.Vault, body.Purpose, body.Counts, body.Low)
	if err != nil {
		var ae *vault.Error
		if errors.As(err, &ae) && ae.Status == 403 {
			writeJSON(w, 200, map[string]bool{"allowed": false})
			return
		}
		writeErr(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]bool{"allowed": ok})
}
