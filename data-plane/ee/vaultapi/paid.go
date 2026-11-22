package vaultapi

import (
	"context"
	"errors"
	"net/http"

	"onshore/data-plane/ee/cloak"
	"onshore/data-plane/ee/gateway"
	"onshore/data-plane/ee/logproc"
	"onshore/data-plane/internal/httpapi"
	"onshore/data-plane/internal/vault"
)

func (s *api) listSubjects(w http.ResponseWriter, r *http.Request, c vault.Caller) error {
	var q vault.SubjectQuery
	if err := httpapi.Decode(r, &q); err != nil {
		return err
	}
	if q.Offset < 0 {
		q.Offset = 0
	}
	res, total, err := s.Vault.ListSubjects(r.Context(), c, r.PathValue("vault"), q)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, 200, map[string]any{"subjects": res, "total": total})
	return nil
}

func (s *api) getSubject(w http.ResponseWriter, r *http.Request, c vault.Caller) error {
	d, err := s.Vault.GetSubject(r.Context(), c, r.PathValue("vault"), r.PathValue("id"))
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, 200, d)
	return nil
}

func (s *api) exportSubject(w http.ResponseWriter, r *http.Request, c vault.Caller) error {
	purpose := r.Header.Get("X-RV-Purpose")
	if err := httpapi.RequirePurpose(purpose); err != nil {
		return err
	}
	res, err := s.Vault.ExportSubject(r.Context(), c, r.PathValue("vault"), r.PathValue("id"), purpose)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, 200, map[string]any{"subject_id": r.PathValue("id"), "fields": res, "request_id": c.RequestID})
	return nil
}

func (s *api) restrictSubject(w http.ResponseWriter, r *http.Request, c vault.Caller) error {
	var body struct {
		Restricted bool   `json:"restricted"`
		Purpose    string `json:"purpose"`
	}
	if err := httpapi.Decode(r, &body); err != nil {
		return err
	}
	if err := httpapi.RequirePurpose(body.Purpose); err != nil {
		return err
	}
	if err := s.Vault.RestrictSubject(r.Context(), c, r.PathValue("vault"), r.PathValue("id"), body.Restricted, body.Purpose); err != nil {
		return err
	}
	httpapi.WriteJSON(w, 200, map[string]any{"restricted": body.Restricted})
	return nil
}

func (s *api) logsTokenize(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Vault    string         `json:"vault"`
		Pipeline string         `json:"pipeline"`
		Module   string         `json:"module"`
		Items    []logproc.Item `json:"items"`
	}
	if err := httpapi.Decode(r, &body); err != nil {
		httpapi.WriteErr(w, r, err)
		return
	}
	if err := httpapi.TooBig(len(body.Items)); err != nil {
		httpapi.WriteErr(w, r, err)
		return
	}
	v, err := s.Vault.Vault(r.Context(), body.Vault)
	if err != nil {
		httpapi.WriteErr(w, r, err)
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
		c := vault.Caller{TenantID: v.TenantID, PrincipalID: module + ":" + body.Pipeline, Kind: "pipeline", Module: module, System: true, RequestID: httpapi.RequestID(r)}
		// continue_on_error: a value that fails validation is masked by the caller.
		res, err := s.Vault.Tokenize(r.Context(), c, body.Vault, items, true, "tokenize")
		if err != nil {
			httpapi.WriteErr(w, r, err)
			return
		}
		for j, it := range res {
			tokens[pos[j]] = it.Token
		}
	}
	httpapi.WriteJSON(w, 200, map[string]any{"tokens": tokens})
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
func (s *api) logsPreview(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Sample    string            `json:"sample"`
		Actions   map[string]string `json:"action_per_type"`
		Entities  []string          `json:"entity_types"`
		Sensitive []string          `json:"sensitive_paths"`
		Vault     string            `json:"vault_id"`
	}
	if err := httpapi.Decode(r, &body); err != nil {
		httpapi.WriteErr(w, r, err)
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
		httpapi.WriteErr(w, r, err)
		return
	}
	b, err := pl.Encode(o.Dropped)
	if err != nil {
		httpapi.WriteErr(w, r, err)
		return
	}
	counts := map[string]int64{}
	for k, v := range o.Counts {
		counts[k[0]+":"+k[1]] = v
	}
	httpapi.WriteJSON(w, 200, map[string]any{"after": string(b), "counts": counts})
}

// caller authenticates the end user behind a gateway request.
func (s *api) gatewayCaller(r *http.Request, token, ip, module string) (vault.Caller, error) {
	c, err := s.Auth.AuthenticateToken(r.Context(), token, ip)
	if err != nil {
		return vault.Caller{}, err
	}
	c.Module, c.RequestID = module, httpapi.RequestID(r)
	return c, nil
}

// gatewayReveal detokenizes for a gateway, as the end user whose token it carries.
func (s *api) gatewayReveal(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Vault       string   `json:"vault"`
		CallerToken string   `json:"caller_token"`
		SourceIP    string   `json:"source_ip"`
		Module      string   `json:"module"`
		Purpose     string   `json:"purpose"`
		Tokens      []string `json:"tokens"`
	}
	if err := httpapi.Decode(r, &body); err != nil {
		httpapi.WriteErr(w, r, err)
		return
	}
	c, err := s.gatewayCaller(r, body.CallerToken, body.SourceIP, body.Module)
	if err != nil {
		httpapi.WriteJSON(w, 401, map[string]any{"error": map[string]string{"code": "unauthenticated", "message": "caller token rejected"}})
		return
	}
	res, err := s.Vault.Detokenize(r.Context(), c, body.Vault, body.Tokens, body.Purpose, true)
	if err != nil {
		httpapi.WriteErr(w, r, err)
		return
	}
	httpapi.WriteJSON(w, 200, map[string]any{"results": res})
}

// gatewayDecide answers what a caller may see of each entity type in an AI reply.
// The values sit in the gateway's memory for one request; only the decision and an
// audit event pass through here.
func (s *api) gatewayDecide(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Vault       string         `json:"vault"`
		Route       string         `json:"route"`
		CallerToken string         `json:"caller_token"`
		SourceIP    string         `json:"source_ip"`
		Purpose     string         `json:"purpose"`
		Entities    map[string]int `json:"entities"`
	}
	if err := httpapi.Decode(r, &body); err != nil {
		httpapi.WriteErr(w, r, err)
		return
	}
	c, err := s.gatewayCaller(r, body.CallerToken, body.SourceIP, "ai")
	if err != nil {
		httpapi.WriteJSON(w, 401, map[string]any{"error": map[string]string{"code": "unauthenticated", "message": "caller token rejected"}})
		return
	}
	out, err := s.Vault.DecideRestore(r.Context(), c, body.Vault, body.Route, body.Purpose, body.Entities)
	if err != nil {
		httpapi.WriteErr(w, r, err)
		return
	}
	httpapi.WriteJSON(w, 200, map[string]any{"decisions": out})
}

// proxyPreview shows a route's rules applied to samples. Nothing is stored.
func (s *api) proxyPreview(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Route    gateway.ProxyRoute `json:"route"`
		Request  string             `json:"request"`
		Response string             `json:"response"`
		Vault    string             `json:"vault_id"`
	}
	if err := httpapi.Decode(r, &body); err != nil {
		httpapi.WriteErr(w, r, err)
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
	httpapi.WriteJSON(w, 200, res)
}

func (s *api) aiPreview(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Prompt  string        `json:"prompt"`
		Reply   string        `json:"reply"`
		Vault   string        `json:"vault_id"`
		Options cloak.Options `json:"options"`
	}
	if err := httpapi.Decode(r, &body); err != nil {
		httpapi.WriteErr(w, r, err)
		return
	}
	if err := cloak.Validate(body.Options); err != nil {
		httpapi.WriteErr(w, r, &vault.Error{Status: 400, Code: "invalid_request", Message: err.Error()})
		return
	}
	sent, reply, shown := gateway.PreviewAI(s.previewRules(body.Vault), body.Options, body.Prompt, body.Reply)
	httpapi.WriteJSON(w, 200, map[string]string{"provider_receives": sent, "provider_reply": reply, "user_sees": shown})
}

func (s *api) gatewayFile(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Vault       string         `json:"vault"`
		CallerToken string         `json:"caller_token"`
		SourceIP    string         `json:"source_ip"`
		Purpose     string         `json:"purpose"`
		Counts      map[string]int `json:"counts"`
		Low         bool           `json:"low_confidence"`
	}
	if err := httpapi.Decode(r, &body); err != nil {
		httpapi.WriteErr(w, r, err)
		return
	}
	c, err := s.gatewayCaller(r, body.CallerToken, body.SourceIP, "files")
	if err != nil {
		httpapi.WriteJSON(w, 401, map[string]any{"error": map[string]string{"code": "unauthenticated", "message": "caller token rejected"}})
		return
	}
	ok, err := s.Vault.AuthorizeFile(r.Context(), c, body.Vault, body.Purpose, body.Counts, body.Low)
	if err != nil {
		var ae *vault.Error
		if errors.As(err, &ae) && ae.Status == 403 {
			httpapi.WriteJSON(w, 200, map[string]bool{"allowed": false})
			return
		}
		httpapi.WriteErr(w, r, err)
		return
	}
	httpapi.WriteJSON(w, 200, map[string]bool{"allowed": ok})
}
