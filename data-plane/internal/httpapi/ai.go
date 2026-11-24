package httpapi

import (
	"net/http"

	"onshore/data-plane/internal/cloak"
	"onshore/data-plane/internal/detect"
	"onshore/data-plane/internal/gateway"
	"onshore/data-plane/internal/vault"
)

// The vault side of the AI gateway, and the rules snapshot every service loads.
// These are community edition (AGPL). Language models stay a Business feature:
// rules.Compile only turns them on with that edition, or on a sandbox vault.

func (s *Server) GatewayCaller(r *http.Request, token, ip, module string) (vault.Caller, error) {
	c, err := s.Auth.AuthenticateToken(r.Context(), token, ip)
	if err != nil {
		return vault.Caller{}, err
	}
	c.Module, c.RequestID = module, RequestID(r)
	return c, nil
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
	if err := Decode(r, &body); err != nil {
		WriteErr(w, r, err)
		return
	}
	c, err := s.GatewayCaller(r, body.CallerToken, body.SourceIP, "ai")
	if err != nil {
		WriteJSON(w, 401, map[string]any{"error": map[string]string{"code": "unauthenticated", "message": "caller token rejected"}})
		return
	}
	out, err := s.Vault.DecideRestore(r.Context(), c, body.Vault, body.Route, body.Purpose, body.Entities)
	if err != nil {
		WriteErr(w, r, err)
		return
	}
	WriteJSON(w, 200, map[string]any{"decisions": out})
}

func (s *Server) aiPreview(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Prompt  string        `json:"prompt"`
		Reply   string        `json:"reply"`
		Vault   string        `json:"vault_id"`
		Options cloak.Options `json:"options"`
	}
	if err := Decode(r, &body); err != nil {
		WriteErr(w, r, err)
		return
	}
	if err := cloak.Validate(body.Options); err != nil {
		WriteErr(w, r, &vault.Error{Status: 400, Code: "invalid_request", Message: err.Error()})
		return
	}
	sent, reply, shown := gateway.PreviewAI(s.PreviewRules(body.Vault), body.Options, body.Prompt, body.Reply)
	WriteJSON(w, 200, map[string]string{"provider_receives": sent, "provider_reply": reply, "user_sees": shown})
}

// cloakOptions lists every kind of data and its choices, for the console grid.
func (s *Server) cloakOptions(w http.ResponseWriter, r *http.Request) {
	WriteJSON(w, 200, map[string]any{"categories": cloak.Categories})
}

func (s *Server) rulesetVersions(w http.ResponseWriter, r *http.Request) {
	versions, err := (&vault.DBSource{S: s.Vault}).Versions(r.Context())
	if err != nil {
		WriteErr(w, r, err)
		return
	}
	WriteJSON(w, 200, map[string]any{"versions": versions})
}

func (s *Server) rulesetSnapshot(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Vault string `json:"vault"`
	}
	if err := Decode(r, &body); err != nil {
		WriteErr(w, r, err)
		return
	}
	snap, err := (&vault.DBSource{S: s.Vault}).Snapshot(r.Context(), body.Vault)
	if err != nil {
		WriteErr(w, r, err)
		return
	}
	WriteJSON(w, 200, snap)
}

// StaticRules answers one rule set, for previews.
type StaticRules struct{ RS *detect.RuleSet }

func (s StaticRules) For(string) *detect.RuleSet { return s.RS }

// PreviewRules gives a preview the vault's full rule set, so custom matches show there.
// An unnamed vault, or one still loading, previews with built-ins.
func (s *Server) PreviewRules(vault string) *detect.RuleSet {
	if vault != "" {
		if rs := s.Vault.RulesFor(vault); rs != nil {
			return rs
		}
	}
	// No vault, no country: look for every country's data rather than assume one.
	return detect.GlobalRuleSet(s.Vault.Engine)
}
