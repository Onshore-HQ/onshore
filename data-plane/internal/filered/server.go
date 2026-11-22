package filered

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"onshore/data-plane/internal/gateway"
)

// MaxUpload bounds a single file.
const MaxUpload = 64 << 20

// Server exposes POST /{vault}/redact. It stores nothing. The caller's token decides
// access, through the file_redact policy action, and every call is audited.
type Server struct {
	R     *Redactor
	Vault *gateway.VaultClient
	// One slot per CPU-heavy job, so that uploads cannot exhaust the host.
	Slots chan struct{}
}

// Handler routes requests.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(`{"status":"ok"}`)) })
	mux.HandleFunc("POST /internal/redact/{vault}", s.redactInternal)
	mux.HandleFunc("POST /{vault}/redact", s.redact)
	return mux
}

func fail(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code, "message": msg}})
}

// redactInternal serves the HTTP proxy, which has already authenticated its route and
// counts what is found. The edge never forwards this path, and it needs the internal token
// as well, in case that changes.
func (s *Server) redactInternal(w http.ResponseWriter, r *http.Request) {
	token, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if s.Vault == nil || s.Vault.Token == "" || subtle.ConstantTimeCompare([]byte(token), []byte(s.Vault.Token)) != 1 {
		fail(w, 401, "unauthenticated", "the internal token is required")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxUpload))
	if err != nil {
		fail(w, 413, "too_large", "the file exceeds the limit")
		return
	}
	select {
	case s.Slots <- struct{}{}:
		defer func() { <-s.Slots }()
	case <-r.Context().Done():
		return
	}
	redactor, err := s.R.forVault(r.PathValue("vault"))
	if err != nil {
		fail(w, 503, "detection_not_ready", "detection rules are not loaded yet, so nothing is returned")
		return
	}
	res, err := redactor.Redact(r.Context(), body)
	if errors.Is(err, ErrUnsupported) {
		fail(w, 415, "unsupported_file", "this file type cannot be redacted, so it is refused")
		return
	}
	if err != nil {
		log.Printf("file redaction failed")
		fail(w, 422, "redaction_failed", "the file could not be processed, so nothing is returned")
		return
	}
	counts, _ := json.Marshal(res.Counts)
	w.Header().Set("Content-Type", res.ContentType)
	w.Header().Set("X-RV-Findings", string(counts))
	w.Header().Set("X-RV-Low-Confidence", fmt.Sprint(res.LowConfidence))
	w.Write(res.Body)
}

func (s *Server) redact(w http.ResponseWriter, r *http.Request) {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		fail(w, 401, "unauthenticated", "a bearer token is required")
		return
	}
	purpose := r.Header.Get("X-RV-Purpose")
	if purpose == "" {
		fail(w, 400, "invalid_request", "X-RV-Purpose is required")
		return
	}
	vaultID := r.PathValue("vault")
	ip := ""
	if f := r.Header.Get("X-Forwarded-For"); f != "" {
		parts := strings.Split(f, ",")
		ip = strings.TrimSpace(parts[len(parts)-1])
	}
	if err := s.Vault.AuthorizeFile(r.Context(), vaultID, token, ip, purpose, nil, false); err != nil {
		switch {
		case errors.Is(err, gateway.ErrCallerRejected):
			fail(w, 401, "unauthenticated", "token rejected")
		case errors.Is(err, gateway.ErrDenied):
			fail(w, 403, "policy_denied", "a policy denied the action")
		default:
			fail(w, 503, "vault_unavailable", "the vault cannot be reached")
		}
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxUpload))
	if err != nil {
		fail(w, 413, "too_large", "the file exceeds the limit")
		return
	}
	select {
	case s.Slots <- struct{}{}:
		defer func() { <-s.Slots }()
	case <-r.Context().Done():
		return
	}
	redactor, err := s.R.forVault(vaultID)
	if err != nil {
		fail(w, 503, "detection_not_ready", "detection rules are not loaded yet, so nothing is returned")
		return
	}
	res, err := redactor.Redact(r.Context(), body)
	if errors.Is(err, ErrUnsupported) {
		fail(w, 415, "unsupported_file", "this file type cannot be redacted, so it is refused")
		return
	}
	if err != nil {
		log.Printf("file redaction failed")
		fail(w, 422, "redaction_failed", "the file could not be processed, so nothing is returned")
		return
	}
	if err := s.Vault.AuthorizeFile(r.Context(), vaultID, token, ip, purpose, res.Counts, res.LowConfidence); err != nil {
		fail(w, 503, "vault_unavailable", "the result could not be audited, so it is withheld")
		return
	}
	counts, _ := json.Marshal(res.Counts)
	w.Header().Set("Content-Type", res.ContentType)
	w.Header().Set("X-RV-Findings", string(counts))
	w.Header().Set("X-RV-Low-Confidence", fmt.Sprint(res.LowConfidence))
	if res.Transcript != "" {
		// Audio returns a JSON envelope, so that the transcript travels with the file.
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"audio_wav": res.Body, "transcript": res.Transcript})
		return
	}
	w.Write(res.Body)
}
