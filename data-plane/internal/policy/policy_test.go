package policy

import (
	"strings"
	"testing"
)

func doc(t *testing.T, js string) Active {
	t.Helper()
	d, err := ParseDoc([]byte(js))
	if err != nil {
		t.Fatal(err)
	}
	c, err := Compile(d)
	if err != nil {
		t.Fatal(err)
	}
	return Active{ID: "p1", Name: "support-agents-nigeria", Version: 3, LimitPerHour: d.LimitPerHour, Compiled: *c}
}

const specPolicy = `{"limit_per_hour":200,"rules":[
 {"id":"mask-ids","actions":["detokenize"],"who":{"roles":["support_agent"],"networks":["hq"]},"what":{"fields":["bvn","nuban"]},"returns":"masked"},
 {"id":"phone","actions":["detokenize"],"who":{"roles":["support_agent"]},"what":{"fields":["phone_ng"]},"when":{"purpose_required":true},"returns":"plaintext"}]}`

func TestDefaultDeny(t *testing.T) {
	if d := Evaluate(nil, Request{Action: "detokenize"}); d.Effect != Deny {
		t.Fatalf("got %s", d.Effect)
	}
}

func TestSpecPolicy(t *testing.T) {
	p := []Active{doc(t, specPolicy)}
	base := Request{Action: "detokenize", PrincipalID: "u1", Roles: []string{"support_agent"}, Purpose: "Ticket 1"}

	r := base
	r.FieldName, r.Networks = "bvn", []string{"hq"}
	if d := Evaluate(p, r); d.Effect != Masked || d.Label() != "support-agents-nigeria@v3" || d.LimitPerHour != 200 {
		t.Fatalf("%+v", d)
	}

	r = base
	r.FieldName = "bvn" // off the approved network
	if d := Evaluate(p, r); d.Effect != Deny || d.Trace[0].Failed != "who" {
		t.Fatalf("%+v", d)
	}

	r = base
	r.FieldName, r.Purpose = "phone_ng", ""
	if d := Evaluate(p, r); d.Effect != Deny {
		t.Fatalf("%+v", d)
	}

	r = base
	r.Roles = []string{"engineer"}
	r.FieldName = "phone_ng"
	if d := Evaluate(p, r); d.Effect != Deny {
		t.Fatalf("%+v", d)
	}
}

func TestMostRestrictiveWins(t *testing.T) {
	js := `{"rules":[
	 {"id":"a","actions":["detokenize"],"who":{"roles":["r"]},"returns":"plaintext"},
	 {"id":"b","actions":["detokenize"],"who":{"roles":["r"]},"returns":"masked"},
	 {"id":"c","actions":["detokenize"],"who":{"roles":["r"]},"what":{"fields":["bvn"]},"returns":"denied"}]}`
	p := []Active{doc(t, js)}
	if d := Evaluate(p, Request{Action: "detokenize", Roles: []string{"r"}, FieldName: "phone"}); d.Effect != Masked || d.Rule != "b" {
		t.Fatalf("%+v", d)
	}
	if d := Evaluate(p, Request{Action: "detokenize", Roles: []string{"r"}, FieldName: "bvn"}); d.Effect != Deny || d.Rule != "c" {
		t.Fatalf("%+v", d)
	}
}

func TestTightestLimitApplies(t *testing.T) {
	loose := doc(t, `{"limit_per_hour":200,"rules":[{"id":"a","actions":["detokenize"],"who":{"roles":["r"]},"returns":"masked"}]}`)
	tight := doc(t, `{"limit_per_hour":3,"rules":[{"id":"b","actions":["detokenize"],"who":{"roles":["r"]},"returns":"plaintext"}]}`)
	d := Evaluate([]Active{loose, tight}, Request{Action: "detokenize", Roles: []string{"r"}})
	if d.Effect != Masked || d.LimitPerHour != 3 {
		t.Fatalf("%+v", d)
	}
}

func TestHours(t *testing.T) {
	p := []Active{doc(t, `{"rules":[{"actions":["detokenize"],"who":{"roles":["r"]},"when":{"hour_from":8,"hour_to":18},"returns":"plaintext"}]}`)}
	if Evaluate(p, Request{Action: "detokenize", Roles: []string{"r"}, Hour: 9}).Effect != Plaintext {
		t.Fatal("inside hours")
	}
	if Evaluate(p, Request{Action: "detokenize", Roles: []string{"r"}, Hour: 22}).Effect != Deny {
		t.Fatal("outside hours")
	}
}

func TestCompileRejects(t *testing.T) {
	for name, js := range map[string]string{
		"no rules":   `{"rules":[]}`,
		"no who":     `{"rules":[{"actions":["detokenize"],"returns":"masked"}]}`,
		"injection":  `{"rules":[{"actions":["detokenize"],"who":{"roles":["x\"] || true || [\""]},"returns":"plaintext"}]}`,
		"bad action": `{"rules":[{"actions":["steal"],"who":{"roles":["r"]},"returns":"plaintext"}]}`,
		"bad return": `{"rules":[{"actions":["detokenize"],"who":{"roles":["r"]},"returns":"everything"}]}`,
		"allow leak": `{"rules":[{"actions":["detokenize"],"who":{"roles":["r"]},"returns":"allow"}]}`,
	} {
		d, err := ParseDoc([]byte(js))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if _, err := Compile(d); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestReadable(t *testing.T) {
	d, _ := ParseDoc([]byte(specPolicy))
	s := Readable("support-agents-nigeria", 3, d)
	for _, want := range []string{`policy "support-agents-nigeria" v3`, "allow DETOKENIZE on fields[bvn, nuban]", `role == "support_agent"`, "return MASKED", "limit 200 reveals"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in\n%s", want, s)
		}
	}
}
