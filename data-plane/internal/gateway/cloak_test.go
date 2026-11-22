package gateway

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"onshore/data-plane/internal/cloak"
	"onshore/data-plane/internal/detect"
	"onshore/data-plane/internal/logproc"
	"onshore/data-plane/internal/netguard"
)

var cloakOpts = cloak.Options{"person_name": cloak.Synthetic, "amount_ngn": cloak.Band, "date": cloak.AgeBand, "address": cloak.State}

const cloakPrompt = "Customer Chioma Okafor (DOB 14/03/1988) of Lekki earns ₦850,000 a month. BVN 22123456789."

func cloakServer(t *testing.T, upstream http.HandlerFunc) func(body string) (*http.Response, string) {
	t.Helper()
	up := httptest.NewServer(upstream)
	t.Cleanup(up.Close)
	a := &AI{Engine: detect.New(detect.Config{}), AllowHTTP: true, Upstream: netguard.Client(5*time.Second, true), routes: map[string]*AIRoute{"r": {ID: "r", VaultID: "v", Name: "r", Upstream: up.URL, Provider: "x", Mode: "enforcing", KeyHash: hashKey("k"), AllowedModels: []string{"m"}, Cloak: cloakOpts}}}
	srv := httptest.NewServer(a.Handler())
	t.Cleanup(srv.Close)
	return func(body string) (*http.Response, string) {
		req, _ := http.NewRequest("POST", srv.URL+"/r/v1/chat/completions", strings.NewReader(body))
		req.Header.Set("X-RV-Route-Key", "k")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, string(b)
	}
}

var standIn = regexp.MustCompile(`Customer ([A-Z][a-z]+) ([A-Z][a-z]+) \(`)

func promptBody() string {
	b, _ := json.Marshal(map[string]any{"model": "m", "messages": []any{map[string]any{"role": "user", "content": cloakPrompt}}})
	return string(b)
}

func TestAICloakSettingsKeepTheMeaning(t *testing.T) {
	var sent string
	var fake []string
	post := cloakServer(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		sent = string(b)
		fake = standIn.FindStringSubmatch(sent)
		w.Header().Set("Content-Type", "application/json")
		if fake == nil {
			w.Write([]byte(`{}`))
			return
		}
		reply, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"role": "assistant", "content": "Dear " + fake[1] + ", we wrote to " + fake[1] + " " + fake[2] + " about [BVN_1]."}}}})
		w.Write(reply)
	})
	resp, body := post(promptBody())
	if resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode, body)
	}
	for _, real := range []string{"Chioma", "Okafor", "1988", "Lekki", "850,000", "22123456789"} {
		if strings.Contains(sent, real) {
			t.Fatalf("provider saw %q: %s", real, sent)
		}
	}
	for _, want := range []string{"aged 35–44", "of Lagos", "₦500k–₦1m", "[BVN_1]"} {
		if !strings.Contains(sent, want) {
			t.Fatalf("provider should see %q: %s", want, sent)
		}
	}
	if fake == nil {
		t.Fatalf("no stand-in name in %s", sent)
	}
	// No caller token: the stand-in becomes the masked real name, never the stand-in.
	if strings.Contains(body, fake[1]) || !strings.Contains(body, "Dear Ch") || !strings.Contains(body, "*******6789") {
		t.Fatalf("reply: %s", body)
	}
}

func TestAICloakStreamHoldsSplitStandIns(t *testing.T) {
	post := cloakServer(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		fake := standIn.FindStringSubmatch(string(b))
		w.Header().Set("Content-Type", "text/event-stream")
		full := fake[1] + " " + fake[2]
		for _, c := range []string{"Hello ", full[:2], full[2:5], full[5:], ", noted."} {
			d, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{"index": 0, "delta": map[string]any{"content": c}, "finish_reason": nil}}})
			io.WriteString(w, "data: "+string(d)+"\n\n")
			w.(http.Flusher).Flush()
		}
		io.WriteString(w, "data: [DONE]\n\n")
	})
	_, body := post(strings.Replace(promptBody(), `"model":"m"`, `"model":"m","stream":true`, 1))
	var text strings.Builder
	for _, line := range strings.Split(body, "\n") {
		if d, ok := strings.CutPrefix(line, "data: "); ok && d != "[DONE]" {
			var ev struct {
				Choices []struct {
					Delta struct {
						Content string `json:"content"`
					} `json:"delta"`
				} `json:"choices"`
			}
			json.Unmarshal([]byte(d), &ev)
			for _, c := range ev.Choices {
				text.WriteString(c.Delta.Content)
			}
		}
	}
	if got := text.String(); !strings.HasPrefix(got, "Hello Ch") || !strings.HasSuffix(got, ", noted.") || strings.Count(got, "*") == 0 {
		t.Fatalf("got %q", got)
	}
}

func TestTwinRoundTrip(t *testing.T) {
	rules := detect.BaseRuleSet(detect.New(detect.Config{}))
	c := CloakText(rules, cloakOpts, cloakPrompt)
	if strings.Contains(c.Text, "Chioma") || c.Counts["person_name"] != 1 || c.Counts["bvn"] != 1 {
		t.Fatalf("%+v", c)
	}
	fake := standIn.FindStringSubmatch(c.Text)
	reply := "Dear " + fake[1] + ", your BVN [BVN_1] is fine. [BVN_2] is unknown."
	full := Uncloak(rules, c.Twin, map[string]string{"person_name": "plaintext", "bvn": "plaintext"}, reply)
	if full != "Dear Chioma, your BVN 22123456789 is fine. [BVN_2] is unknown." {
		t.Fatalf("plaintext: %q", full)
	}
	masked := Uncloak(rules, c.Twin, map[string]string{"person_name": "plaintext"}, reply)
	if !strings.Contains(masked, "Dear Chioma") || strings.Contains(masked, "22123456789") {
		t.Fatalf("masked: %q", masked)
	}
	if e := TwinEntities(c.Twin); e["person_name"] != 1 || e["bvn"] != 1 || len(e) != 2 {
		t.Fatalf("entities %v", e)
	}
}

func TestPlacePlaceholderFallsBackToState(t *testing.T) {
	rules := detect.BaseRuleSet(detect.New(detect.Config{}))
	sent, _, shown := PreviewAI(rules, cloak.Options{"address": cloak.Placeholder}, "Deliver to Ikoyi, Lagos tomorrow", "")
	if sent != "Deliver to [PLACE_1] tomorrow" || shown != "Deliver to Lagos tomorrow" {
		t.Fatalf("%q %q", sent, shown)
	}
}

func TestCountryPacksCloak(t *testing.T) {
	rules := detect.BaseRuleSet(detect.New(detect.Config{})).WithPacks("GB", []string{"everywhere", "gb"})
	c := CloakText(rules, cloak.Options{"uk_nino": cloak.Last4}, "Customer NI number AB 12 34 56 C, NHS number 943 476 5919, BVN 22123456789.")
	if c.Text != "Customer NI number ****456C, NHS number [UK_NHS_1], BVN 22123456789." {
		t.Fatalf("%q", c.Text)
	}
	// Routes made before packs list only Nigerian types; pack types still pass their filter.
	s := newSession(nil, nil)
	out, _ := cloakText(rules, s, "SSN-free text, NHS 943 476 5919", "", "", map[string]bool{"bvn": true}, true, logproc.Counts{})
	if !strings.Contains(out, "[UK_NHS_1]") {
		t.Fatalf("pack types must pass an old route's filter: %q", out)
	}
}

// A vault in the United States, with nothing Nigerian about it.
func TestUSVaultCloaksLikeAUSVault(t *testing.T) {
	rules := detect.BaseRuleSet(detect.New(detect.Config{})).WithPacks("US", []string{"everywhere", "us"})
	opts := cloak.Options{"person_name": cloak.Synthetic, "amount": cloak.Band, "date": cloak.AgeBand, "address": cloak.State}
	c := CloakText(rules, opts, "Customer Sarah Johnson (DOB 03/14/1988) of Brooklyn says $8,500 left her account. SSN 123-45-6789, call +1 212 555 0100.")
	for _, real := range []string{"Sarah", "Johnson", "1988", "Brooklyn", "8,500", "123-45-6789", "555 0100"} {
		if strings.Contains(c.Text, real) {
			t.Fatalf("%q leaked: %s", real, c.Text)
		}
	}
	for _, want := range []string{"aged 35–44", "of New York", "$5k–$10k", "[US_SSN_1]", "[PHONE_1]"} {
		if !strings.Contains(c.Text, want) {
			t.Fatalf("want %q in %s", want, c.Text)
		}
	}
	fake := standIn.FindStringSubmatch(c.Text)
	if fake == nil || !strings.Contains("Emily James Olivia Michael Sophie Daniel Grace Thomas Chloe Ryan Hannah Nathan Megan Ethan Laura Oliver Rachel Lucas Jessica Owen Amelia Harry Isla Connor", fake[1]) {
		t.Fatalf("stand-in should be an English-speaking name: %s", c.Text)
	}
}
