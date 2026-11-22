package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"

	"onshore/data-plane/internal/cloak"
	"onshore/data-plane/internal/gateway"
	"onshore/data-plane/internal/vault"
)

// The cloak API: text in, cloaked text (and optionally a digital twin id) out,
// then uncloak with the id as far as the caller's policy allows. It is the same
// engine as the AI gateway, for apps and agents that call a model some other way.

const maxCloakText = 256 * 1024

// cloakProfile loads a saved cloak setting of this vault.
func (s *Server) cloakProfile(ctx context.Context, vaultID, id string) (cloak.Options, error) {
	var opts cloak.Options
	err := s.Vault.Pool.QueryRow(ctx, `SELECT options FROM control.cloak_profiles WHERE id=$1 AND vault_id=$2`, id, vaultID).Scan(&opts)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, &vault.Error{Status: 404, Code: "not_found", Message: "no such cloak setting in this vault"}
	}
	if err != nil {
		return nil, err
	}
	if err := cloak.Validate(opts); err != nil {
		return nil, &vault.Error{Status: 409, Code: "invalid_setting", Message: err.Error()}
	}
	return opts, nil
}

func (s *Server) cloak(w http.ResponseWriter, r *http.Request, c vault.Caller) error {
	var body struct {
		Text      string        `json:"text"`
		ProfileID string        `json:"profile_id"`
		Options   cloak.Options `json:"options"`
		KeepDays  int           `json:"keep_days"`
	}
	if err := decode(r, &body); err != nil {
		return err
	}
	if len(body.Text) > maxCloakText {
		return &vault.Error{Status: 413, Code: "too_large", Message: "text is limited to 256 KB per call"}
	}
	vaultID := r.PathValue("vault")
	opts := body.Options
	if body.ProfileID != "" {
		if opts != nil {
			return &vault.Error{Status: 400, Code: "invalid_request", Message: "send profile_id or options, not both"}
		}
		var err error
		if opts, err = s.cloakProfile(r.Context(), vaultID, body.ProfileID); err != nil {
			return err
		}
	} else if err := cloak.Validate(opts); err != nil {
		return &vault.Error{Status: 400, Code: "invalid_request", Message: err.Error()}
	}
	if _, err := s.Vault.Vault(r.Context(), vaultID); err != nil {
		return err
	}
	rules := s.Vault.RulesFor(vaultID)
	if rules == nil {
		return &vault.Error{Status: 503, Code: "detection_not_ready", Message: "detection rules are not loaded yet; try again shortly"}
	}
	out := gateway.CloakText(rules, opts, body.Text)
	res := map[string]any{"text": out.Text, "changed": out.Counts, "request_id": c.RequestID}
	if body.KeepDays > 0 {
		items, _ := json.Marshal(out.Twin)
		id, err := s.Vault.SaveTwin(r.Context(), c, vaultID, "", body.KeepDays, items, gateway.TwinEntities(out.Twin))
		if err != nil {
			return err
		}
		res["id"] = id
	} else if err := s.Vault.RecordCloak(r.Context(), c, vaultID, out.Counts); err != nil {
		return err
	}
	writeJSON(w, 200, res)
	return nil
}

func (s *Server) uncloak(w http.ResponseWriter, r *http.Request, c vault.Caller) error {
	var body struct {
		ID      string `json:"id"`
		Text    string `json:"text"`
		Purpose string `json:"purpose"`
	}
	if err := decode(r, &body); err != nil {
		return err
	}
	if err := requirePurpose(body.Purpose); err != nil {
		return err
	}
	if len(body.Text) > maxCloakText {
		return &vault.Error{Status: 413, Code: "too_large", Message: "text is limited to 256 KB per call"}
	}
	vaultID := r.PathValue("vault")
	raw, decisions, err := s.Vault.OpenTwin(r.Context(), c, vaultID, body.ID, body.Purpose)
	if err != nil {
		return err
	}
	var items []gateway.TwinItem
	if err := json.Unmarshal(raw, &items); err != nil {
		return err
	}
	writeJSON(w, 200, map[string]any{"text": gateway.Uncloak(s.Vault.RulesFor(vaultID), items, decisions, body.Text), "decisions": decisions, "request_id": c.RequestID})
	return nil
}

func (s *Server) deleteTwin(w http.ResponseWriter, r *http.Request, c vault.Caller) error {
	if err := s.Vault.DeleteTwin(r.Context(), c, r.PathValue("vault"), r.PathValue("id")); err != nil {
		return err
	}
	writeJSON(w, 200, map[string]any{"deleted": true, "request_id": c.RequestID})
	return nil
}

// cloakTwinSave is the AI gateway sealing a request's map before it forwards it.
func (s *Server) cloakTwinSave(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Vault string             `json:"vault"`
		Route string             `json:"route"`
		Days  int                `json:"days"`
		Items []gateway.TwinItem `json:"items"`
	}
	if err := decode(r, &body); err != nil {
		writeErr(w, r, err)
		return
	}
	v, err := s.Vault.Vault(r.Context(), body.Vault)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	c := vault.Caller{TenantID: v.TenantID, PrincipalID: "ai:" + body.Route, Kind: "pipeline", Module: "ai", System: true, RequestID: requestID(r)}
	items, _ := json.Marshal(body.Items)
	id, err := s.Vault.SaveTwin(r.Context(), c, body.Vault, body.Route, body.Days, items, gateway.TwinEntities(body.Items))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]string{"id": id})
}

// cloakOptions lists every kind of data and its choices, for the console grid.
func (s *Server) cloakOptions(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"categories": cloak.Categories})
}
