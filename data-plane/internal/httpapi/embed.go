package httpapi

import (
	"embed"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"onshore/data-plane/internal/vault"
)

//go:embed embedstatic/*
var embedFS embed.FS

func (s *Server) clientTokenMint(w http.ResponseWriter, r *http.Request, c vault.Caller) error {
	var body vault.ClientTokenRequest
	if err := decode(r, &body); err != nil {
		return err
	}
	raw, expires, err := s.Vault.MintClientToken(r.Context(), c, r.PathValue("vault"), body)
	if err != nil {
		return err
	}
	writeJSON(w, 200, map[string]any{"client_token": raw, "expires_at": expires.UTC().Format(time.RFC3339), "request_id": c.RequestID})
	return nil
}

func (s *Server) embedStatic(name, contentType string, crossOrigin bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		b, err := embedFS.ReadFile("embedstatic/" + name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		h := w.Header()
		h.Set("Content-Type", contentType)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Cache-Control", "public, max-age=300")
		if crossOrigin {
			h.Set("Access-Control-Allow-Origin", "*")
			h.Set("Cross-Origin-Resource-Policy", "cross-origin")
		} else {
			h.Set("Cross-Origin-Resource-Policy", "same-origin")
		}
		w.Write(b)
	}
}

// embedFrame serves the page that holds the input. Only the vault's listed sites can frame
// it, and it loads nothing but its own script and stylesheet.
func (s *Server) embedFrame(w http.ResponseWriter, r *http.Request) {
	ancestors := "'none'"
	status := 404
	var body []byte
	if v, err := s.Vault.Vault(r.Context(), r.PathValue("vault")); err == nil && len(v.EmbedOrigins) > 0 {
		var ok []string
		for _, o := range v.EmbedOrigins {
			if vault.ValidFrameOrigin(o) {
				ok = append(ok, o)
			}
		}
		if len(ok) > 0 {
			ancestors = strings.Join(ok, " ")
			status = 200
			body, _ = embedFS.ReadFile("embedstatic/frame.html")
		}
	}
	h := w.Header()
	h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors "+ancestors)
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cross-Origin-Resource-Policy", "cross-origin")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	w.Write(body)
}

// embedGuard refuses anything that is not the frame itself calling home. A browser sets
// these headers and page script cannot change them, so a hostile host page cannot redeem
// a token from its own context. A stolen token used from outside a browser is what
// bind_ip is for.
func (s *Server) embedGuard(w http.ResponseWriter, r *http.Request) bool {
	refuse := func(msg string) bool {
		writeJSON(w, 403, map[string]any{"error": map[string]string{"code": "forbidden", "message": msg}})
		return false
	}
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		return refuse("this endpoint takes JSON")
	}
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" {
		return refuse("this endpoint is only for the component's own frame")
	}
	if o := r.Header.Get("Origin"); o != "" {
		u, err := url.Parse(o)
		host := r.Header.Get("X-Forwarded-Host")
		if host == "" {
			host = r.Host
		}
		if err != nil || !strings.EqualFold(u.Host, host) {
			return refuse("this endpoint is only for the component's own frame")
		}
	}
	return true
}

// embedFail answers one way for every bad token, and counts it against the address.
func (s *Server) embedFail(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, vault.ErrClientToken) && s.tooMany(w, r) {
		return
	}
	writeErr(w, r, err)
}

type embedBody struct {
	ClientToken  string            `json:"client_token"`
	ParentOrigin string            `json:"parent_origin"`
	Values       map[string]string `json:"values"`
}

func (s *Server) embedDescribe(w http.ResponseWriter, r *http.Request) {
	if !s.embedGuard(w, r) {
		return
	}
	var b embedBody
	if err := decode(r, &b); err != nil {
		writeErr(w, r, err)
		return
	}
	t, err := s.Vault.PeekClientToken(r.Context(), b.ClientToken, b.ParentOrigin, s.Auth.ClientIP(r))
	if err != nil {
		s.embedFail(w, r, err)
		return
	}
	fields := make([]map[string]string, len(t.Fields))
	for i, f := range t.Fields {
		fields[i] = map[string]string{"name": f, "data_type": s.Vault.FieldKind(r.Context(), t.VaultID, f)}
	}
	writeJSON(w, 200, map[string]any{"kind": t.Kind, "fields": fields, "tokens": len(t.Tokens)})
}

func (s *Server) embedCollect(w http.ResponseWriter, r *http.Request) {
	if !s.embedGuard(w, r) {
		return
	}
	var b embedBody
	if err := decode(r, &b); err != nil {
		writeErr(w, r, err)
		return
	}
	ip := s.Auth.ClientIP(r)
	peek, err := s.Vault.PeekClientToken(r.Context(), b.ClientToken, b.ParentOrigin, ip)
	if err == nil && peek.Kind != "collect" {
		err = vault.ErrClientToken
	}
	if err != nil {
		s.embedFail(w, r, err)
		return
	}
	// A typo keeps the token, so the person can correct it. Nothing is echoed.
	problems, err := s.Vault.CheckCollectValues(r.Context(), peek, b.Values)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	if len(problems) > 0 {
		writeJSON(w, 422, map[string]any{"error": map[string]any{"code": "validation_failed", "message": "check the highlighted fields", "fields": problems}})
		return
	}
	t, err := s.Vault.TakeClientToken(r.Context(), b.ClientToken, b.ParentOrigin, ip)
	if err != nil {
		s.embedFail(w, r, err)
		return
	}
	c, err := s.Auth.CallerFor(r.Context(), t.PrincipalID, t.TenantID, ip)
	if err != nil {
		s.embedFail(w, r, vault.ErrClientToken)
		return
	}
	c.RequestID, c.Module = requestID(r), vault.ModuleEmbed
	out, err := s.Vault.EmbedCollect(r.Context(), c, t, b.Values)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{"tokens": out})
}

func (s *Server) embedReveal(w http.ResponseWriter, r *http.Request) {
	if !s.embedGuard(w, r) {
		return
	}
	var b embedBody
	if err := decode(r, &b); err != nil {
		writeErr(w, r, err)
		return
	}
	ip := s.Auth.ClientIP(r)
	peek, err := s.Vault.PeekClientToken(r.Context(), b.ClientToken, b.ParentOrigin, ip)
	if err == nil && peek.Kind != "reveal" {
		err = vault.ErrClientToken
	}
	if err != nil {
		s.embedFail(w, r, err)
		return
	}
	t, err := s.Vault.TakeClientToken(r.Context(), b.ClientToken, b.ParentOrigin, ip)
	if err != nil {
		s.embedFail(w, r, err)
		return
	}
	c, err := s.Auth.CallerFor(r.Context(), t.PrincipalID, t.TenantID, ip)
	if err != nil {
		s.embedFail(w, r, vault.ErrClientToken)
		return
	}
	c.RequestID, c.Module = requestID(r), vault.ModuleEmbed
	res, err := s.Vault.EmbedReveal(r.Context(), c, t)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{"results": res})
}
