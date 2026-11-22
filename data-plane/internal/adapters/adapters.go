// Package adapters tokenizes support tickets as they arrive. A webhook carries the
// text; the adapter writes the tokenized version back through the vendor's API.
//
// Freshdesk and Intercom follow their published API docs. Intercom's webhook body
// path and admin-note fields, and all of Zoho Desk and Salesforce, come from general
// knowledge of those APIs because their docs could not be read: test each against a
// real account before relying on it.
package adapters

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1" // #nosec Intercom's documented signature algorithm
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/hkdf"

	"onshore/data-plane/internal/detect"
	"onshore/data-plane/internal/gateway"
	"onshore/data-plane/internal/logproc"
)

// Adapter is one connected support tool.
type Adapter struct {
	ID, VaultID, Name, Kind, BaseURL, Mode string
	Credential                             map[string]string
	SecretHash, Secret                     string
}

// Decrypt opens a value sealed by the control plane with the shared adapter key.
func Decrypt(secret, enc string) (string, error) {
	r := hkdf.New(sha256.New, []byte(secret), nil, []byte("rv-adapter"))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return "", err
	}
	b, err := base64.StdEncoding.DecodeString(enc)
	if err != nil || len(b) < 28 {
		return "", errors.New("bad ciphertext")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	// Node writes iv | tag | ciphertext; Go's Open wants ciphertext | tag.
	pt, err := gcm.Open(nil, b[:12], append(append([]byte{}, b[28:]...), b[12:28]...), nil)
	return string(pt), err
}

// Update is one piece of ticket text to rewrite.
type Update struct {
	Ref  string // the vendor's object id
	Kind string // ticket, note or part
	Text string
	new  string
}

// Service handles webhooks.
type Service struct {
	Pool      *pgxpool.Pool
	Vault     *gateway.VaultClient
	Engine    *detect.Engine
	Rules     detect.RuleSets
	Client    *http.Client
	Secret    string
	AllowHTTP bool
	Counters  logproc.Counters

	mu   sync.RWMutex
	byID map[string]*Adapter
}

// Handler routes /{adapter}/webhook.
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(`{"status":"ok"}`)) })
	// Intercom validates a webhook URL with HEAD.
	mux.HandleFunc("HEAD /{adapter}/webhook", func(w http.ResponseWriter, _ *http.Request) {})
	mux.HandleFunc("POST /{adapter}/webhook", s.webhook)
	return mux
}

func fail(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"message": msg}})
}

// verify checks the sender. Intercom signs with HMAC-SHA1. The others carry a shared
// secret in a header set on the vendor's webhook rule.
func verify(a *Adapter, r *http.Request, body []byte) bool {
	if a.Kind == "intercom" {
		m := hmac.New(sha1.New, []byte(a.Secret))
		m.Write(body)
		return hmac.Equal([]byte("sha1="+hex.EncodeToString(m.Sum(nil))), []byte(r.Header.Get("X-Hub-Signature")))
	}
	got := sha256.Sum256([]byte(r.Header.Get("X-RV-Webhook-Secret")))
	return subtle.ConstantTimeCompare([]byte(hex.EncodeToString(got[:])), []byte(a.SecretHash)) == 1
}

func (s *Service) webhook(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	a := s.byID[r.PathValue("adapter")]
	s.mu.RUnlock()
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, gateway.MaxBody))
	if err != nil {
		fail(w, 413, "too large")
		return
	}
	if a == nil || !verify(a, r, body) {
		fail(w, 401, "unknown adapter or bad signature")
		return
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		fail(w, 400, "the webhook must be JSON")
		return
	}
	ticket, updates := Extract(a.Kind, doc)
	if len(updates) == 0 {
		w.WriteHeader(202)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	counts, changed, err := s.tokenize(ctx, a, updates)
	if err != nil {
		// Asking the vendor to retry keeps the text in its system, where it already is.
		w.Header().Set("Retry-After", "30")
		fail(w, 503, "vault unavailable")
		return
	}
	s.Counters.Record(a.VaultID, "support", a.ID, a.Kind, counts, 1)
	if a.Mode == "enforcing" && changed {
		if err := s.writeBack(ctx, a, ticket, updates); err != nil {
			log.Printf("adapter %s: vendor write-back failed", a.ID)
			fail(w, 502, "the support tool refused the update")
			return
		}
	}
	w.WriteHeader(200)
	w.Write([]byte(`{"ok":true}`))
}

// Extract reads the text fields each vendor sends.
func Extract(kind string, d map[string]any) (string, []*Update) {
	str := func(m map[string]any, k string) string {
		switch v := m[k].(type) {
		case string:
			return v
		case float64:
			return fmt.Sprintf("%.0f", v)
		}
		return ""
	}
	var out []*Update
	add := func(ref, k, text string) {
		if text != "" {
			out = append(out, &Update{Ref: ref, Kind: k, Text: text})
		}
	}
	switch kind {
	case "freshdesk":
		id := str(d, "ticket_id")
		add(id, "ticket", str(d, "description"))
		if c := str(d, "conversation_id"); c != "" {
			add(c, "note", str(d, "body"))
		}
		return id, out
	case "zoho_desk":
		id := str(d, "ticketId")
		add(id, "ticket", str(d, "description"))
		return id, out
	case "salesforce":
		id := str(d, "caseId")
		add(id, "Description", str(d, "Description"))
		add(id, "Subject", str(d, "Subject"))
		return id, out
	case "intercom":
		data, _ := d["data"].(map[string]any)
		item, _ := data["item"].(map[string]any)
		if item == nil {
			return "", nil
		}
		id := str(item, "id")
		if src, ok := item["source"].(map[string]any); ok {
			add(str(src, "id"), "source", str(src, "body"))
		}
		if parts, ok := item["conversation_parts"].(map[string]any); ok {
			if list, ok := parts["conversation_parts"].([]any); ok {
				for _, p := range list {
					if m, ok := p.(map[string]any); ok {
						add(str(m, "id"), "part", str(m, "body"))
					}
				}
			}
		}
		return id, out
	}
	return "", nil
}

func (s *Service) tokenize(ctx context.Context, a *Adapter, ups []*Update) (logproc.Counts, bool, error) {
	rules := detect.SetFor(s.Rules, s.Engine, a.VaultID)
	if rules == nil {
		return nil, false, detect.ErrRulesNotReady
	}
	counts := logproc.Counts{}
	changed := false
	for _, u := range ups {
		ents, observed := rules.Split(rules.ScanFor("api", "", u.Text, ""))
		for _, e := range observed {
			counts[[2]string{string(e.Type), detect.CountLabel(e)}]++
		}
		if len(ents) == 0 {
			continue
		}
		if a.Mode != "enforcing" {
			for _, e := range ents {
				counts[[2]string{string(e.Type), "passed"}]++
			}
			continue
		}
		var items []logproc.Item
		noToken := func(e detect.Entity) bool {
			act := rules.ModuleAction(e, "api")
			return e.Type == detect.CardPAN || (act != "" && act != "tokenize")
		}
		for _, e := range ents {
			if !noToken(e) {
				items = append(items, logproc.Item{Entity: string(e.Type), Value: u.Text[e.Start:e.End]})
			}
		}
		var toks []string
		if len(items) > 0 {
			var err error
			if toks, err = s.Vault.Tokenize(ctx, a.VaultID, a.ID, "support", items); err != nil {
				return nil, false, err
			}
		}
		next := 0
		u.new = detect.Replace(u.Text, ents, func(e detect.Entity, v string) string {
			if !noToken(e) {
				t := toks[next]
				next++
				if t != "" {
					counts[[2]string{string(e.Type), "tokenized"}]++
					return t
				}
			}
			counts[[2]string{string(e.Type), "masked"}]++
			return rules.MaskValue(e.Type, v)
		})
		changed = true
	}
	return counts, changed, nil
}

var safeRef = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

func (s *Service) call(ctx context.Context, a *Adapter, method, path string, body any) error {
	base, err := url.Parse(a.BaseURL)
	if err != nil || (base.Scheme != "https" && !(s.AllowHTTP && base.Scheme == "http")) {
		return errors.New("the adapter's base URL must use https")
	}
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(a.BaseURL, "/")+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	cred := a.Credential["token"]
	switch a.Kind {
	case "freshdesk":
		// Documented: the API key is the username, and any dummy password will do.
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(cred+":X")))
	case "intercom":
		req.Header.Set("Authorization", "Bearer "+cred)
		req.Header.Set("Intercom-Version", "2.17")
	case "zoho_desk":
		req.Header.Set("Authorization", "Zoho-oauthtoken "+cred)
		req.Header.Set("orgId", a.Credential["org_id"])
	case "salesforce":
		req.Header.Set("Authorization", "Bearer "+cred)
	}
	resp, err := s.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("vendor answered %d", resp.StatusCode)
	}
	return nil
}

func (s *Service) writeBack(ctx context.Context, a *Adapter, ticket string, ups []*Update) error {
	switch a.Kind {
	case "salesforce":
		fields := map[string]string{}
		for _, u := range ups {
			if u.new != "" {
				fields[u.Kind] = u.new
			}
		}
		if !safeRef.MatchString(ticket) {
			return errors.New("bad id")
		}
		return s.call(ctx, a, http.MethodPatch, "/services/data/v60.0/sobjects/Case/"+ticket, fields)
	}
	for _, u := range ups {
		if u.new == "" {
			continue
		}
		if !safeRef.MatchString(u.Ref) || !safeRef.MatchString(ticket) {
			return errors.New("bad id")
		}
		var err error
		switch a.Kind {
		case "freshdesk":
			if u.Kind == "ticket" {
				err = s.call(ctx, a, http.MethodPut, "/api/v2/tickets/"+u.Ref, map[string]string{"description": u.new})
			} else {
				err = s.call(ctx, a, http.MethodPut, "/api/v2/conversations/"+u.Ref, map[string]string{"body": u.new})
			}
		case "zoho_desk":
			err = s.call(ctx, a, http.MethodPatch, "/api/v1/tickets/"+u.Ref, map[string]string{"description": u.new})
		case "intercom":
			// Intercom cannot edit text, so the original is redacted and the tokenized
			// version is kept as an admin note.
			redact := map[string]string{"type": "conversation_part", "conversation_id": ticket, "conversation_part_id": u.Ref}
			if u.Kind == "source" {
				redact = map[string]string{"type": "source", "conversation_id": ticket, "source_id": u.Ref}
			}
			if err = s.call(ctx, a, http.MethodPost, "/conversations/redact", redact); err == nil {
				err = s.call(ctx, a, http.MethodPost, "/conversations/"+ticket+"/reply", map[string]string{"message_type": "note", "type": "admin", "admin_id": a.Credential["admin_id"], "body": u.new})
			}
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// Refresh reloads adapters and opens their credentials.
func (s *Service) Refresh(ctx context.Context) error {
	rows, err := s.Pool.Query(ctx, `SELECT id,vault_id,name,kind,base_url,mode,api_credential_enc,webhook_secret_hash,webhook_secret_enc FROM control.adapters`)
	if err != nil {
		return err
	}
	defer rows.Close()
	next := map[string]*Adapter{}
	for rows.Next() {
		a := &Adapter{}
		var credEnc, secretEnc string
		if err := rows.Scan(&a.ID, &a.VaultID, &a.Name, &a.Kind, &a.BaseURL, &a.Mode, &credEnc, &a.SecretHash, &secretEnc); err != nil {
			return err
		}
		cred, err1 := Decrypt(s.Secret, credEnc)
		sec, err2 := Decrypt(s.Secret, secretEnc)
		if err1 != nil || err2 != nil || json.Unmarshal([]byte(cred), &a.Credential) != nil {
			log.Printf("adapter %s: credentials do not open; skipping", a.ID)
			continue
		}
		a.Secret = sec
		next[a.ID] = a
	}
	if rows.Err() != nil {
		return rows.Err()
	}
	s.mu.Lock()
	s.byID = next
	s.mu.Unlock()
	return nil
}
