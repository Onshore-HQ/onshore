package detect

import (
	"errors"
	"strings"
	"testing"
)

type fakeModel struct {
	ents []Entity
	err  error
	n    int
}

func (f *fakeModel) Find(string) ([]Entity, error) { f.n++; return f.ents, f.err }

func TestModelAddsToPatternsOnlyInItsModules(t *testing.T) {
	text := "Please call Adaeze Nwachukwu-Bello back about card 4111 1111 1111 1111"
	start := strings.Index(text, "Adaeze")
	m := &fakeModel{ents: []Entity{{Type: PersonName, Start: start, End: start + len("Adaeze Nwachukwu-Bello"), Score: 0.9}}}
	rs := BaseRuleSet(New(Config{})).WithModel(m, []string{"ai"})

	has := func(ents []Entity, typ EntityType) bool {
		for _, e := range ents {
			if e.Type == typ && !e.Observe {
				return true
			}
		}
		return false
	}
	got := rs.ScanFor("ai", "", text, "")
	if !has(got, PersonName) || !has(got, CardPAN) {
		t.Fatalf("ai: want the model's name and the pattern's card, got %+v", got)
	}
	m.n = 0
	got = rs.ScanFor("logs", "", text, "")
	if m.n != 0 {
		t.Fatal("the model was asked for a module it isn't on for")
	}
	if !has(got, CardPAN) {
		t.Fatal("patterns stopped working without the model")
	}
}

func TestModelErrorLeavesThePatterns(t *testing.T) {
	text := "card 4111 1111 1111 1111"
	rs := BaseRuleSet(New(Config{})).WithModel(&fakeModel{err: errors.New("down")}, []string{"api"})
	got := rs.ScanFor("api", "", text, "")
	if len(got) == 0 || got[0].Type != CardPAN {
		t.Fatalf("got %+v", got)
	}
}
