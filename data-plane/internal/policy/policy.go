// Package policy compiles builder JSON to CEL and evaluates requests.
// Default deny: when several rules match, the most restrictive decision wins.
package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"cel.dev/cel-go/cel"
)

const (
	Plaintext = "plaintext"
	Masked    = "masked"
	TokenOnly = "token_only"
	Deny      = "denied"
	Allow     = "allow"
)

var rank = map[string]int{Deny: 0, TokenOnly: 1, Masked: 2, Plaintext: 3, Allow: 3}

// Actions a rule can grant.
var Actions = map[string]bool{"tokenize": true, "insert": true, "detokenize": true, "search": true, "delete": true, "export": true, "compare": true, "file_redact": true}

// Doc is the JSON the console builder writes.
type Doc struct {
	Rules        []Rule `json:"rules"`
	LimitPerHour int    `json:"limit_per_hour,omitempty"`
}

// Rule is one card in the builder: Who, What, When, Returns.
type Rule struct {
	ID      string   `json:"id"`
	Actions []string `json:"actions"`
	Who     struct {
		Roles      []string `json:"roles,omitempty"`
		Principals []string `json:"principals,omitempty"`
		Networks   []string `json:"networks,omitempty"`
		RequireMFA bool     `json:"require_mfa,omitempty"`
	} `json:"who"`
	What struct {
		Fields    []string `json:"fields,omitempty"`
		DataTypes []string `json:"data_types,omitempty"`
	} `json:"what"`
	When struct {
		PurposeRequired bool `json:"purpose_required,omitempty"`
		HourFrom        *int `json:"hour_from,omitempty"`
		HourTo          *int `json:"hour_to,omitempty"`
	} `json:"when"`
	Returns string `json:"returns"`
}

// Compiled holds CEL for each slot, so the simulator can say which one failed.
type Compiled struct {
	Rules []CompiledRule `json:"rules"`
}

// CompiledRule is one rule's CEL source.
type CompiledRule struct {
	ID      string `json:"id"`
	Action  string `json:"action"`
	Who     string `json:"who"`
	What    string `json:"what"`
	When    string `json:"when"`
	Returns string `json:"returns"`
}

var safeName = regexp.MustCompile(`^[A-Za-z0-9_.@:-]+$`)

func quoteList(items []string) (string, error) {
	q := make([]string, len(items))
	for i, it := range items {
		if !safeName.MatchString(it) {
			return "", fmt.Errorf("invalid name %q", it)
		}
		q[i] = `"` + it + `"`
	}
	return "[" + strings.Join(q, ", ") + "]", nil
}

// Compile validates a Doc and produces CEL, checking that every expression parses.
func Compile(d Doc) (*Compiled, error) {
	if len(d.Rules) == 0 {
		return nil, errors.New("a policy needs at least one rule")
	}
	if d.LimitPerHour < 0 {
		return nil, errors.New("limit_per_hour cannot be negative")
	}
	out := &Compiled{}
	for i, r := range d.Rules {
		id := r.ID
		if id == "" {
			id = fmt.Sprintf("rule-%d", i+1)
		}
		if _, ok := rank[r.Returns]; !ok {
			return nil, fmt.Errorf("%s: unknown returns %q", id, r.Returns)
		}
		if len(r.Who.Roles)+len(r.Who.Principals) == 0 {
			return nil, fmt.Errorf("%s: who must name at least one role or principal", id)
		}
		if len(r.Actions) == 0 {
			return nil, fmt.Errorf("%s: at least one action is required", id)
		}
		var who []string
		var subject []string
		if len(r.Who.Roles) > 0 {
			l, err := quoteList(r.Who.Roles)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", id, err)
			}
			subject = append(subject, "principal.roles.exists(r, r in "+l+")")
		}
		if len(r.Who.Principals) > 0 {
			l, err := quoteList(r.Who.Principals)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", id, err)
			}
			subject = append(subject, "principal.id in "+l)
		}
		who = append(who, "("+strings.Join(subject, " || ")+")")
		if len(r.Who.Networks) > 0 {
			l, err := quoteList(r.Who.Networks)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", id, err)
			}
			who = append(who, "networks.exists(n, n in "+l+")")
		}
		if r.Who.RequireMFA {
			who = append(who, "principal.mfa == true")
		}

		var what []string
		if len(r.What.Fields) > 0 {
			l, err := quoteList(r.What.Fields)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", id, err)
			}
			what = append(what, "field.name in "+l)
		}
		if len(r.What.DataTypes) > 0 {
			l, err := quoteList(r.What.DataTypes)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", id, err)
			}
			what = append(what, "field.data_type in "+l)
		}
		whatExpr := "true"
		if len(what) > 0 {
			whatExpr = strings.Join(what, " || ")
		}

		var when []string
		if r.When.PurposeRequired {
			when = append(when, `purpose != ""`)
		}
		if (r.When.HourFrom == nil) != (r.When.HourTo == nil) {
			return nil, fmt.Errorf("%s: hour_from and hour_to must be set together", id)
		}
		if r.When.HourFrom != nil {
			from, to := *r.When.HourFrom, *r.When.HourTo
			if from < 0 || from > 23 || to < 1 || to > 24 || from >= to {
				return nil, fmt.Errorf("%s: invalid hours %d-%d", id, from, to)
			}
			when = append(when, fmt.Sprintf("hour >= %d && hour < %d", from, to))
		}
		whenExpr := "true"
		if len(when) > 0 {
			whenExpr = strings.Join(when, " && ")
		}
		for _, a := range r.Actions {
			if !Actions[a] {
				return nil, fmt.Errorf("%s: unknown action %q", id, a)
			}
			if a == "detokenize" && r.Returns == Allow {
				return nil, fmt.Errorf("%s: detokenize must return plaintext, masked, token_only or denied", id)
			}
			cr := CompiledRule{ID: id, Action: a, Who: strings.Join(who, " && "), What: whatExpr, When: whenExpr, Returns: r.Returns}
			for _, expr := range []string{cr.Who, cr.What, cr.When} {
				if _, err := program(expr); err != nil {
					return nil, fmt.Errorf("%s: %w", id, err)
				}
			}
			out.Rules = append(out.Rules, cr)
		}
	}
	return out, nil
}

var (
	envOnce sync.Once
	env     *cel.Env
	envErr  error
	progs   sync.Map // expression -> cel.Program
)

func program(expr string) (cel.Program, error) {
	if p, ok := progs.Load(expr); ok {
		return p.(cel.Program), nil
	}
	envOnce.Do(func() {
		env, envErr = cel.NewEnv(
			cel.Variable("principal", cel.MapType(cel.StringType, cel.DynType)),
			cel.Variable("field", cel.MapType(cel.StringType, cel.DynType)),
			cel.Variable("networks", cel.ListType(cel.StringType)),
			cel.Variable("purpose", cel.StringType),
			cel.Variable("hour", cel.IntType),
		)
	})
	if envErr != nil {
		return nil, envErr
	}
	ast, iss := env.Compile(expr)
	if iss != nil && iss.Err() != nil {
		return nil, iss.Err()
	}
	p, err := env.Program(ast)
	if err != nil {
		return nil, err
	}
	progs.Store(expr, p)
	return p, nil
}

// Request is everything a decision may depend on.
type Request struct {
	Action        string
	PrincipalID   string
	Roles         []string
	MFA           bool
	Networks      []string
	FieldName     string
	FieldDataType string
	Purpose       string
	Hour          int // local time in the organisation's time zone
}

// Active is one published policy version.
type Active struct {
	ID           string
	Name         string
	Version      int
	LimitPerHour int
	Compiled     Compiled
}

// TraceEntry explains how one rule fared, for the simulator.
type TraceEntry struct {
	Policy  string `json:"policy"`
	Version int    `json:"version"`
	Rule    string `json:"rule"`
	Matched bool   `json:"matched"`
	Failed  string `json:"failed_slot,omitempty"`
	Returns string `json:"returns"`
	Won     bool   `json:"won"`
}

// Decision is the outcome of Evaluate.
type Decision struct {
	Effect       string       `json:"decision"`
	PolicyID     string       `json:"policy_id,omitempty"`
	PolicyName   string       `json:"policy,omitempty"`
	Version      int          `json:"policy_version,omitempty"`
	Rule         string       `json:"rule,omitempty"`
	LimitPerHour int          `json:"limit_per_hour,omitempty"`
	Trace        []TraceEntry `json:"trace,omitempty"`
}

// Label renders the policy reference returned to API callers.
func (d Decision) Label() string {
	if d.PolicyName == "" {
		return "default-deny"
	}
	return fmt.Sprintf("%s@v%d", d.PolicyName, d.Version)
}

// Allowed reports whether a non-reveal action may proceed.
func (d Decision) Allowed() bool { return d.Effect != Deny && d.Effect != TokenOnly }

// Evaluate applies every active policy to a request. Any evaluation error counts
// as a non-match, so a broken rule can only ever narrow access.
func Evaluate(policies []Active, req Request) Decision {
	roles := req.Roles
	if roles == nil {
		roles = []string{}
	}
	nets := req.Networks
	if nets == nil {
		nets = []string{}
	}
	vars := map[string]any{
		"principal": map[string]any{"id": req.PrincipalID, "roles": roles, "mfa": req.MFA},
		"field":     map[string]any{"name": req.FieldName, "data_type": req.FieldDataType},
		"networks":  nets,
		"purpose":   req.Purpose,
		"hour":      int64(req.Hour),
	}
	best := Decision{Effect: Deny}
	matched := false
	winner := -1
	limit := 0
	var trace []TraceEntry
	for _, p := range policies {
		for _, r := range p.Compiled.Rules {
			if r.Action != req.Action {
				continue
			}
			entry := TraceEntry{Policy: p.Name, Version: p.Version, Rule: r.ID, Returns: r.Returns}
			entry.Matched = true
			for _, slot := range []struct{ name, expr string }{{"who", r.Who}, {"what", r.What}, {"when", r.When}} {
				if !evalBool(slot.expr, vars) {
					entry.Matched, entry.Failed = false, slot.name
					break
				}
			}
			trace = append(trace, entry)
			if !entry.Matched {
				continue
			}
			// The tightest limit of any matching policy applies, whichever rule won.
			if p.LimitPerHour > 0 && (limit == 0 || p.LimitPerHour < limit) {
				limit = p.LimitPerHour
			}
			if !matched || rank[r.Returns] < rank[best.Effect] {
				best = Decision{Effect: r.Returns, PolicyID: p.ID, PolicyName: p.Name, Version: p.Version, Rule: r.ID}
				winner = len(trace) - 1
				matched = true
			}
		}
	}
	if winner >= 0 {
		trace[winner].Won = true
	}
	best.LimitPerHour = limit
	best.Trace = trace
	return best
}

func evalBool(expr string, vars map[string]any) bool {
	p, err := program(expr)
	if err != nil {
		return false
	}
	v, _, err := p.Eval(vars)
	if err != nil {
		return false
	}
	b, ok := v.Value().(bool)
	return ok && b
}

// Readable renders the policy text shown under the builder cards.
func Readable(name string, version int, d Doc) string {
	var b strings.Builder
	fmt.Fprintf(&b, "policy %q v%d\n", name, version)
	for _, r := range d.Rules {
		fields := "all fields"
		var whats []string
		whats = append(whats, r.What.Fields...)
		whats = append(whats, r.What.DataTypes...)
		if len(whats) > 0 {
			fields = "fields[" + strings.Join(whats, ", ") + "]"
		}
		fmt.Fprintf(&b, "  allow %s on %s\n", strings.ToUpper(strings.Join(r.Actions, ", ")), fields)
		var conds []string
		if len(r.Who.Roles) == 1 {
			conds = append(conds, fmt.Sprintf("role == %q", r.Who.Roles[0]))
		} else if len(r.Who.Roles) > 1 {
			conds = append(conds, "role in ["+strings.Join(r.Who.Roles, ", ")+"]")
		}
		if len(r.Who.Principals) > 0 {
			conds = append(conds, "person in ["+strings.Join(r.Who.Principals, ", ")+"]")
		}
		if len(r.Who.Networks) > 0 {
			conds = append(conds, "network in ["+strings.Join(r.Who.Networks, ", ")+"]")
		}
		if r.Who.RequireMFA {
			conds = append(conds, "mfa is on")
		}
		if r.When.PurposeRequired {
			conds = append(conds, "purpose is set")
		}
		if r.When.HourFrom != nil {
			conds = append(conds, fmt.Sprintf("hour between %02d:00 and %02d:00", *r.When.HourFrom, *r.When.HourTo))
		}
		fmt.Fprintf(&b, "    when %s\n", strings.Join(conds, " and "))
		fmt.Fprintf(&b, "    return %s\n", strings.ToUpper(r.Returns))
	}
	if d.LimitPerHour > 0 {
		fmt.Fprintf(&b, "  limit %d reveals per user per hour\n", d.LimitPerHour)
	}
	return b.String()
}

// ParseDoc decodes builder JSON, rejecting unknown keys.
func ParseDoc(raw []byte) (Doc, error) {
	var d Doc
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	err := dec.Decode(&d)
	return d, err
}
