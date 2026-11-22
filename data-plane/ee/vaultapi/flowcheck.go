package vaultapi

import (
	"net/http"
	"onshore/data-plane/internal/httpapi"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"

	"onshore/data-plane/ee/logproc"
	"onshore/data-plane/internal/vault"
)

var ownTokenRe = regexp.MustCompile(`\btok_([a-z][a-z0-9_]*?)_[A-Za-z0-9]{8,}\b`)

// flowCheck reads a batch a job is about to send somewhere Onshore cannot sit in the path. It
// keeps counts only, never the text, and those counts are the flow's evidence on the residency
// map. Identifiers found count as passed: the caller is about to send them.
func (s *api) flowCheck(w http.ResponseWriter, r *http.Request, c vault.Caller) error {
	vaultID, flowID := r.PathValue("vault"), r.PathValue("flow")
	var body struct {
		Text string `json:"text"`
	}
	if err := httpapi.Decode(r, &body); err != nil {
		return err
	}
	if len(body.Text) > logproc.MaxLeafBytes {
		return &vault.Error{Status: 400, Code: "invalid_request", Message: "text exceeds 1 MiB"}
	}
	v, err := s.Vault.Vault(r.Context(), vaultID)
	if err != nil {
		return err
	}
	if v.TenantID != c.TenantID {
		return &vault.Error{Status: 404, Code: "invalid_request", Message: "unknown vault"}
	}
	var host *string
	err = s.Vault.Pool.QueryRow(r.Context(), `SELECT dest_host FROM control.data_flows WHERE id=$1 AND vault_id=$2 AND retired_at IS NULL`, flowID, vaultID).Scan(&host)
	if err == pgx.ErrNoRows {
		return &vault.Error{Status: 404, Code: "invalid_request", Message: "unknown flow"}
	}
	if err != nil {
		return err
	}
	rs := s.Vault.RulesFor(vaultID)
	if rs == nil {
		return &vault.Error{Status: 503, Code: "detection_not_ready", Message: "detection rules are not loaded yet"}
	}
	ents, _ := rs.Split(rs.ScanFor("api", "", body.Text, ""))
	found := map[string]int64{}
	for _, e := range ents {
		found[string(e.Type)]++
	}
	tokens := map[string]int64{}
	for _, m := range ownTokenRe.FindAllStringSubmatch(body.Text, -1) {
		tokens[m[1]]++
	}
	dest := "check"
	if host != nil && *host != "" {
		dest = *host
	}
	minute := time.Now().UTC().Truncate(time.Minute)
	var identifiers, safe int64
	write := func(entity, action string, n int64) error {
		_, err := s.Vault.Pool.Exec(r.Context(), `INSERT INTO events.detection_events(occurred_at,vault_id,module,source_id,destination,dest_host,entity_type,action,count) VALUES ($1,$2,'check',$3,'check',$4,$5,$6,$7)
			ON CONFLICT (occurred_at,vault_id,module,source_id,destination,coalesce(dest_host,''),entity_type,action,coalesce(entity_version,0),coalesce(ruleset_version,0)) DO UPDATE SET count=events.detection_events.count+EXCLUDED.count`,
			minute, vaultID, flowID, dest, entity, action, n)
		return err
	}
	for t, n := range found {
		identifiers += n
		if err := write(t, "passed", n); err != nil {
			return err
		}
	}
	for t, n := range tokens {
		safe += n
		if err := write(t, "tokenized", n); err != nil {
			return err
		}
	}
	httpapi.WriteJSON(w, 200, map[string]any{"identifiers": identifiers, "tokens": safe, "clean": identifiers == 0, "by_type": found})
	return nil
}
