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
	"strings"
	"time"

	"onshore/data-plane/internal/payload"
)

// MaxBody bounds gateway bodies in both directions.
const MaxBody = 16 << 20

func HashKey(k string) string {
	s := sha256.Sum256([]byte(k))
	return hex.EncodeToString(s[:])
}

func KeyOK(given, want string) bool {
	return want != "" && subtle.ConstantTimeCompare([]byte(HashKey(given)), []byte(want)) == 1
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
func (v *VaultClient) Tokenize(ctx context.Context, vaultID, source, module string, items []payload.Item) ([]string, error) {
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

var HopHeaders = map[string]bool{"Connection": true, "Keep-Alive": true, "Te": true, "Trailer": true, "Transfer-Encoding": true, "Upgrade": true, "Host": true, "Content-Length": true, "Content-Encoding": true, "Accept-Encoding": true, "X-Forwarded-For": true, "Cookie": true}

// copyRequestHeaders passes vendor credentials through, so that nothing here stores
// them, and strips everything meant for this gateway.
func CopyRequestHeaders(dst, src http.Header) {
	for k, vs := range src {
		c := http.CanonicalHeaderKey(k)
		if HopHeaders[c] || strings.HasPrefix(c, "X-Rv-") {
			continue
		}
		dst[c] = vs
	}
}

func Fail(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code, "message": msg}})
}

func ReadLimited(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, MaxBody+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxBody {
		return nil, errors.New("too large")
	}
	return b, nil
}

func ClientIP(r *http.Request) string {
	// The edge overwrites this header, and only the edge can reach this service
	// because it needs a certificate from the internal CA.
	if f := r.Header.Get("X-Forwarded-For"); f != "" {
		parts := strings.Split(f, ",")
		return strings.TrimSpace(parts[len(parts)-1])
	}
	return ""
}

func SafeUpstream(raw string, allowHTTP bool) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && !(allowHTTP && u.Scheme == "http")) {
		return nil, errors.New("the route's upstream must use https")
	}
	return u, nil
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
