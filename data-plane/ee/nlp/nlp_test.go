package nlp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"onshore/data-plane/internal/detect"
)

func TestFindMapsLabelsOffsetsAndScores(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in struct{ Text string }
		json.NewDecoder(r.Body).Decode(&in)
		var out []entity
		if i := strings.Index(in.Text, "Zoë Ádám"); i >= 0 {
			out = append(out, entity{i, i + len("Zoë Ádám"), "person", 0.95})
		}
		if i := strings.Index(in.Text, "Lekki"); i >= 0 {
			out = append(out, entity{i, i + len("Lekki"), "place", 0.4}) // below the minimum
		}
		out = append(out, entity{0, 2, "organisation", 0.99}) // not a label Onshore uses
		json.NewEncoder(w).Encode(map[string]any{"entities": out})
	}))
	defer srv.Close()
	c := &Client{URL: srv.URL, HTTP: srv.Client(), MinScore: 0.6}
	text := strings.Repeat("filler ", 4000) + "Zoë Ádám lives in Lekki"
	got, err := c.Find(text)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Type != detect.PersonName || text[got[0].Start:got[0].End] != "Zoë Ádám" {
		t.Fatalf("got %+v", got)
	}
}

func TestFindReportsAnUnreachableService(t *testing.T) {
	c := &Client{URL: "http://127.0.0.1:1", HTTP: http.DefaultClient}
	if _, err := c.Find("Ada Lovelace"); err == nil {
		t.Fatal("want an error")
	}
}
