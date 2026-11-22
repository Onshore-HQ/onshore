package vaultapi

import (
	"context"
	"errors"
	"net/http"
	"onshore/data-plane/internal/httpapi"
	"time"

	"onshore/data-plane/internal/detect"
	"onshore/data-plane/internal/vault"
)

// writeDefErr answers with the spec's code for a definition that will not compile.
func writeDefErr(w http.ResponseWriter, r *http.Request, err error) {
	var de *detect.DefinitionError
	if errors.As(err, &de) {
		status := 422
		if de.Code == "invalid_request" {
			status = 400
		}
		httpapi.WriteErr(w, r, &vault.Error{Status: status, Code: de.Code, Message: de.Message})
		return
	}
	httpapi.WriteErr(w, r, err)
}

func (s *api) rulesetVersions(w http.ResponseWriter, r *http.Request) {
	versions, err := (&vault.DBSource{S: s.Vault}).Versions(r.Context())
	if err != nil {
		httpapi.WriteErr(w, r, err)
		return
	}
	httpapi.WriteJSON(w, 200, map[string]any{"versions": versions})
}

func (s *api) rulesetSnapshot(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Vault string `json:"vault"`
	}
	if err := httpapi.Decode(r, &body); err != nil {
		httpapi.WriteErr(w, r, err)
		return
	}
	snap, err := (&vault.DBSource{S: s.Vault}).Snapshot(r.Context(), body.Vault)
	if err != nil {
		httpapi.WriteErr(w, r, err)
		return
	}
	httpapi.WriteJSON(w, 200, snap)
}

type customBody struct {
	Vault   string           `json:"vault"`
	Entity  string           `json:"entity"`
	By      string           `json:"by"`
	Def     detect.CustomDef `json:"def"`
	Text    string           `json:"text"`
	Sample  string           `json:"sample_id"`
	Values  []string         `json:"values"`
	Samples []struct {
		Sample      string `json:"sample"`
		ExpectMatch bool   `json:"expect_match"`
	} `json:"samples"`
}

// customCheck validates a definition without storing anything.
func (s *api) customCheck(w http.ResponseWriter, r *http.Request) {
	var b customBody
	if err := httpapi.Decode(r, &b); err != nil {
		httpapi.WriteErr(w, r, err)
		return
	}
	if err := detect.CheckDefinition(&b.Def); err != nil {
		writeDefErr(w, r, err)
		return
	}
	httpapi.WriteJSON(w, 200, map[string]any{"ok": true})
}

func (s *api) customBench(w http.ResponseWriter, r *http.Request) {
	var b customBody
	if err := httpapi.Decode(r, &b); err != nil {
		httpapi.WriteErr(w, r, err)
		return
	}
	if len(b.Text) > 1<<20 {
		httpapi.WriteErr(w, r, &vault.Error{Status: 400, Code: "invalid_request", Message: "text exceeds 1 MiB"})
		return
	}
	matches, err := s.Vault.TestBench(r.Context(), b.Vault, b.Entity, &b.Def, b.Text)
	if err != nil {
		writeDefErr(w, r, err)
		return
	}
	httpapi.WriteJSON(w, 200, map[string]any{"matches": matches})
}

func (s *api) customSamplesAdd(w http.ResponseWriter, r *http.Request) {
	var b customBody
	if err := httpapi.Decode(r, &b); err != nil {
		httpapi.WriteErr(w, r, err)
		return
	}
	if err := s.Vault.AddSamples(r.Context(), b.Vault, b.Entity, b.By, b.Samples); err != nil {
		httpapi.WriteErr(w, r, err)
		return
	}
	httpapi.WriteJSON(w, 200, map[string]any{"ok": true})
}

func (s *api) customSamplesDelete(w http.ResponseWriter, r *http.Request) {
	var b customBody
	if err := httpapi.Decode(r, &b); err != nil {
		httpapi.WriteErr(w, r, err)
		return
	}
	if err := s.Vault.DeleteSample(r.Context(), b.Entity, b.Sample); err != nil {
		httpapi.WriteErr(w, r, err)
		return
	}
	httpapi.WriteJSON(w, 200, map[string]any{"ok": true})
}

func (s *api) customSamplesRun(w http.ResponseWriter, r *http.Request) {
	var b customBody
	if err := httpapi.Decode(r, &b); err != nil {
		httpapi.WriteErr(w, r, err)
		return
	}
	res, err := s.Vault.RunSamples(r.Context(), b.Vault, b.Entity, &b.Def)
	if err != nil {
		writeDefErr(w, r, err)
		return
	}
	httpapi.WriteJSON(w, 200, map[string]any{"results": res})
}

// customTry runs inline samples against a definition with no vault, for country packs.
func (s *api) customTry(w http.ResponseWriter, r *http.Request) {
	var b customBody
	if err := httpapi.Decode(r, &b); err != nil {
		httpapi.WriteErr(w, r, err)
		return
	}
	if len(b.Samples) > 200 {
		writeDefErr(w, r, &detect.DefinitionError{Code: "invalid_request", Message: "at most 200 samples"})
		return
	}
	in := make([]vault.SampleResult, 0, len(b.Samples))
	for _, x := range b.Samples {
		in = append(in, vault.SampleResult{Sample: x.Sample, ExpectMatch: x.ExpectMatch})
	}
	res, err := s.Vault.TrySamples(&b.Def, in)
	if err != nil {
		writeDefErr(w, r, err)
		return
	}
	httpapi.WriteJSON(w, 200, map[string]any{"results": res})
}

func (s *api) customValues(w http.ResponseWriter, r *http.Request) {
	var b customBody
	if err := httpapi.Decode(r, &b); err != nil {
		httpapi.WriteErr(w, r, err)
		return
	}
	res, err := s.Vault.UploadValues(r.Context(), b.Vault, b.Entity, b.Values)
	if err != nil {
		httpapi.WriteErr(w, r, err)
		return
	}
	httpapi.WriteJSON(w, 200, res)
}

// staticRules answers one rule set, for previews.
type staticRules struct{ rs *detect.RuleSet }

func (s staticRules) For(string) *detect.RuleSet { return s.rs }

// previewRules gives a preview the vault's full rule set, so custom matches show there.
// An unnamed vault, or one still loading, previews with built-ins.
func (s *api) previewRules(vault string) *detect.RuleSet {
	if vault != "" {
		if rs := s.Vault.RulesFor(vault); rs != nil {
			return rs
		}
	}
	// No vault, no country: look for every country's data rather than assume one.
	return detect.GlobalRuleSet(s.Vault.Engine)
}

// customQuickBench is the builder's cost estimate: a small sample, not the publish check.
func (s *api) customQuickBench(w http.ResponseWriter, r *http.Request) {
	var b customBody
	if err := httpapi.Decode(r, &b); err != nil {
		httpapi.WriteErr(w, r, err)
		return
	}
	res, err := s.Vault.BenchmarkDraftSize(r.Context(), b.Vault, b.Entity, &b.Def, 256<<10)
	if err != nil {
		writeDefErr(w, r, err)
		return
	}
	httpapi.WriteJSON(w, 200, res)
}

// customBenchmark runs the publish-time benchmark, which can take some time.
func (s *api) customBenchmark(w http.ResponseWriter, r *http.Request) {
	var b customBody
	if err := httpapi.Decode(r, &b); err != nil {
		httpapi.WriteErr(w, r, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	res, err := s.Vault.BenchmarkDraft(ctx, b.Vault, b.Entity, &b.Def)
	if err != nil {
		writeDefErr(w, r, err)
		return
	}
	httpapi.WriteJSON(w, 200, res)
}
