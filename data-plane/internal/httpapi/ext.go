package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"onshore/data-plane/internal/license"
	"onshore/data-plane/internal/vault"
)

// Paid features (data-plane/ee, under the Onshore Commercial Licence) add their
// routes through Register. The core server works without them.

// AuthedHandler handles a request from an authenticated caller.
type AuthedHandler func(http.ResponseWriter, *http.Request, vault.Caller) error

// Routes is how an extension adds routes. level is the edition a route needs
// (license.Business or license.Enterprise); test vaults never need one.
type Routes struct {
	Authed   func(pattern, level string, h AuthedHandler)
	Internal func(pattern, level string, h http.HandlerFunc)
	Public   func(pattern string, h http.HandlerFunc)
}

var extensions []func(*Server, Routes)

// Register adds an extension. Call it from an init function.
func Register(f func(*Server, Routes)) { extensions = append(extensions, f) }

// Exported helpers for extensions.

func WriteJSON(w http.ResponseWriter, status int, v any)         { writeJSON(w, status, v) }
func WriteErr(w http.ResponseWriter, r *http.Request, err error) { writeErr(w, r, err) }
func Decode(r *http.Request, v any) error                        { return decode(r, v) }
func RequestID(r *http.Request) string                           { return requestID(r) }
func RequirePurpose(p string) error                              { return requirePurpose(p) }
func TooBig(n int) error                                         { return tooBig(n) }

// TooMany answers 429 when the caller's address has failed authentication too often.
func (s *Server) TooMany(w http.ResponseWriter, r *http.Request) bool { return s.tooMany(w, r) }

// needs is the refusal for a paid feature on an edition without it.
func needs(level string) error {
	name := "Onshore Business"
	if level == license.Enterprise {
		name = "Onshore Enterprise"
	}
	return &vault.Error{Status: 403, Code: "needs_" + level, Message: "this feature needs " + name + "; it is free on test vaults"}
}

// allowed reports whether this install may use a feature, or whether the vault the
// request is for is a test vault (made-up data, so paid features are free there).
func (s *Server) allowed(ctx context.Context, level, vaultID string) bool {
	if license.Current().Has(level) || license.IsTestVault(vaultID) {
		return true
	}
	if vaultID == "" || s.Vault == nil {
		return false
	}
	v, err := s.Vault.Vault(ctx, vaultID)
	return err == nil && v.Environment == "sandbox"
}

func (s *Server) applyExtensions(mux *http.ServeMux) {
	routes := Routes{
		Authed: func(pattern, level string, h AuthedHandler) {
			mux.HandleFunc(pattern, s.authed(func(w http.ResponseWriter, r *http.Request, c vault.Caller) error {
				if !s.allowed(r.Context(), level, r.PathValue("vault")) {
					return needs(level)
				}
				return h(w, r, c)
			}))
		},
		Internal: func(pattern, level string, h http.HandlerFunc) {
			mux.HandleFunc(pattern, s.internal(func(w http.ResponseWriter, r *http.Request) {
				if !license.Current().Has(level) && !s.allowed(r.Context(), level, peekVault(r)) {
					writeErr(w, r, needs(level))
					return
				}
				h(w, r)
			}))
		},
		Public: func(pattern string, h http.HandlerFunc) { mux.HandleFunc(pattern, h) },
	}
	for _, f := range extensions {
		f(s, routes)
	}
}

// peekVault reads the "vault" field of a JSON body without consuming it.
func peekVault(r *http.Request) string {
	if r.Body == nil || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") && r.Header.Get("Content-Type") != "" {
		return ""
	}
	b, err := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewReader(b))
	if err != nil {
		return ""
	}
	var v struct {
		Vault string `json:"vault"`
	}
	json.Unmarshal(b, &v)
	return v.Vault
}
