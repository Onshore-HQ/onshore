package adapters

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"onshore/data-plane/internal/detect"
	"onshore/data-plane/internal/gateway"
)

type vendorCall struct{ method, path, auth, body string }

// setup runs the adapter against mock vendor and vault servers.
func setup(t *testing.T, kind, mode string, cred map[string]string) (*httptest.Server, *[]vendorCall, func(http.Header, string) int) {
	t.Helper()
	calls := &[]vendorCall{}
	vendor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		*calls = append(*calls, vendorCall{r.Method, r.URL.Path, r.Header.Get("Authorization"), string(b)})
		w.Write([]byte(`{}`))
	}))
	t.Cleanup(vendor.Close)
	vaultSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Items []any `json:"items"`
		}
		json.NewDecoder(r.Body).Decode(&in)
		toks := make([]string, len(in.Items))
		for i := range toks {
			toks[i] = "tok_x_AAAAAAAAAAAAAAAAAAAAAA"
		}
		json.NewEncoder(w).Encode(map[string]any{"tokens": toks})
	}))
	t.Cleanup(vaultSrv.Close)
	h := sha256.Sum256([]byte("whsec"))
	s := &Service{Engine: detect.New(detect.Config{}), AllowHTTP: true, Client: &http.Client{Timeout: 5 * time.Second}, Vault: &gateway.VaultClient{BaseURL: vaultSrv.URL, Token: "t", HTTP: http.DefaultClient},
		byID: map[string]*Adapter{"a": {ID: "a", VaultID: "v", Kind: kind, BaseURL: vendor.URL, Mode: mode, Credential: cred, SecretHash: hex.EncodeToString(h[:]), Secret: "whsec"}}}
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return srv, calls, func(hdr http.Header, body string) int {
		req, _ := http.NewRequest("POST", srv.URL+"/a/webhook", strings.NewReader(body))
		for k, v := range hdr {
			req.Header[k] = v
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}
}

func secretHeader() http.Header { return http.Header{"X-Rv-Webhook-Secret": {"whsec"}} }

func TestFreshdeskRewritesTicket(t *testing.T) {
	_, calls, post := setup(t, "freshdesk", "enforcing", map[string]string{"token": "key"})
	if st := post(secretHeader(), `{"ticket_id":42,"description":"My BVN is 22123456789"}`); st != 200 {
		t.Fatal(st)
	}
	c := (*calls)[0]
	if c.method != "PUT" || c.path != "/api/v2/tickets/42" || !strings.HasPrefix(c.auth, "Basic ") || strings.Contains(c.body, "22123456789") || !strings.Contains(c.body, "tok_x") {
		t.Fatalf("%+v", c)
	}
}

func TestShadowCountsAndWritesNothing(t *testing.T) {
	_, calls, post := setup(t, "freshdesk", "shadow", map[string]string{"token": "k"})
	if st := post(secretHeader(), `{"ticket_id":42,"description":"bvn 22123456789"}`); st != 200 || len(*calls) != 0 {
		t.Fatalf("%d %+v", st, *calls)
	}
}

func TestBadSecretRefused(t *testing.T) {
	_, calls, post := setup(t, "zoho_desk", "enforcing", map[string]string{"token": "k", "org_id": "1"})
	if st := post(http.Header{"X-Rv-Webhook-Secret": {"wrong"}}, `{"ticketId":"1","description":"bvn 22123456789"}`); st != 401 || len(*calls) != 0 {
		t.Fatal(st)
	}
}

func intercomSig(body string) http.Header {
	m := hmac.New(sha1.New, []byte("whsec"))
	m.Write([]byte(body))
	return http.Header{"X-Hub-Signature": {"sha1=" + hex.EncodeToString(m.Sum(nil))}}
}

func TestIntercomRedactsAndKeepsNote(t *testing.T) {
	_, calls, post := setup(t, "intercom", "enforcing", map[string]string{"token": "k", "admin_id": "9"})
	body := `{"data":{"item":{"id":"608","conversation_parts":{"conversation_parts":[{"id":"149","body":"bvn 22123456789"}]}}}}`
	if st := post(intercomSig(body), body); st != 200 {
		t.Fatal(st)
	}
	if len(*calls) != 2 || (*calls)[0].path != "/conversations/redact" || !strings.Contains((*calls)[0].body, `"conversation_part_id":"149"`) || (*calls)[1].path != "/conversations/608/reply" || strings.Contains((*calls)[1].body, "22123456789") {
		t.Fatalf("%+v", *calls)
	}
	if st := post(http.Header{"X-Hub-Signature": {"sha1=00"}}, body); st != 401 {
		t.Fatal(st)
	}
}

func TestSalesforceAndZoho(t *testing.T) {
	_, calls, post := setup(t, "salesforce", "enforcing", map[string]string{"token": "k"})
	post(secretHeader(), `{"caseId":"500x","Description":"call 08031234567","Subject":"nothing"}`)
	if c := (*calls)[0]; c.method != "PATCH" || c.path != "/services/data/v60.0/sobjects/Case/500x" || strings.Contains(c.body, "08031234567") {
		t.Fatalf("%+v", c)
	}
	_, zc, zpost := setup(t, "zoho_desk", "enforcing", map[string]string{"token": "k", "org_id": "1"})
	zpost(secretHeader(), `{"ticketId":"77","description":"bvn 22123456789"}`)
	if c := (*zc)[0]; c.method != "PATCH" || c.path != "/api/v1/tickets/77" || c.auth != "Zoho-oauthtoken k" {
		t.Fatalf("%+v", c)
	}
}

func TestPathInjectionInVendorIDRefused(t *testing.T) {
	_, calls, post := setup(t, "freshdesk", "enforcing", map[string]string{"token": "k"})
	if st := post(secretHeader(), `{"ticket_id":"../../admin","description":"bvn 22123456789"}`); st != 502 || len(*calls) != 0 {
		t.Fatalf("%d %+v", st, *calls)
	}
}

func TestCardsAreMaskedNotVaulted(t *testing.T) {
	_, calls, post := setup(t, "freshdesk", "enforcing", map[string]string{"token": "k"})
	post(secretHeader(), `{"ticket_id":1,"description":"pan 4111 1111 1111 1111"}`)
	if b := (*calls)[0].body; strings.Contains(b, "4111 1111") || !strings.Contains(b, "1111") || strings.Contains(b, "tok_") {
		t.Fatal(b)
	}
}
