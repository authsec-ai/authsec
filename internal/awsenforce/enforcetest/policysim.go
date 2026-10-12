package enforcetest

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Statement is one IAM policy statement, normalised: Action and Resource are
// always lists, Condition is operator -> key -> values.
type Statement struct {
	Sid       string
	Effect    string
	Action    []string
	NotAction []string
	Resource  []string
	Condition map[string]map[string][]string
}

// Policy is a list of statements.
type Policy struct{ Statements []Statement }

// PolicyFromDocument normalises a parsed (and resolved) policy document.
func PolicyFromDocument(doc any) (Policy, error) {
	m, ok := doc.(map[string]any)
	if !ok {
		return Policy{}, fmt.Errorf("policy document is not a mapping")
	}
	if m["Version"] != "2012-10-17" {
		return Policy{}, fmt.Errorf("policy Version = %v, want 2012-10-17", m["Version"])
	}
	raw, ok := m["Statement"].([]any)
	if !ok {
		return Policy{}, fmt.Errorf("Statement is not a list")
	}
	var p Policy
	for i, r := range raw {
		sm, ok := r.(map[string]any)
		if !ok {
			return Policy{}, fmt.Errorf("statement %d is not a mapping", i)
		}
		st := Statement{Condition: map[string]map[string][]string{}}
		st.Sid, _ = sm["Sid"].(string)
		st.Effect, _ = sm["Effect"].(string)
		var err error
		if st.Action, err = stringList(sm["Action"]); err != nil {
			return Policy{}, fmt.Errorf("statement %q Action: %w", st.Sid, err)
		}
		if st.NotAction, err = stringList(sm["NotAction"]); err != nil {
			return Policy{}, fmt.Errorf("statement %q NotAction: %w", st.Sid, err)
		}
		if st.Resource, err = stringList(sm["Resource"]); err != nil {
			return Policy{}, fmt.Errorf("statement %q Resource: %w", st.Sid, err)
		}
		if c, ok := sm["Condition"].(map[string]any); ok {
			for op, kv := range c {
				kvm, ok := kv.(map[string]any)
				if !ok {
					return Policy{}, fmt.Errorf("statement %q Condition %s is not a mapping", st.Sid, op)
				}
				st.Condition[op] = map[string][]string{}
				for k, v := range kvm {
					vals, err := stringList(v)
					if err != nil {
						return Policy{}, fmt.Errorf("statement %q Condition %s %s: %w", st.Sid, op, k, err)
					}
					st.Condition[op][k] = vals
				}
			}
		} else if sm["Condition"] != nil {
			return Policy{}, fmt.Errorf("statement %q Condition is not a mapping", st.Sid)
		}
		for k := range sm {
			switch k {
			case "Sid", "Effect", "Action", "NotAction", "Resource", "Condition":
			default:
				return Policy{}, fmt.Errorf("statement %q has unsupported element %s", st.Sid, k)
			}
		}
		p.Statements = append(p.Statements, st)
	}
	return p, nil
}

func stringList(v any) ([]string, error) {
	switch t := v.(type) {
	case nil:
		return nil, nil
	case string:
		return []string{t}, nil
	case bool:
		if t {
			return []string{"true"}, nil
		}
		return []string{"false"}, nil
	case []any:
		out := make([]string, 0, len(t))
		for _, x := range t {
			s, ok := x.(string)
			if !ok {
				return nil, fmt.Errorf("element %v is not a string (unresolved intrinsic?)", x)
			}
			out = append(out, s)
		}
		return out, nil
	}
	return nil, fmt.Errorf("%v is not a string or list (unresolved intrinsic?)", v)
}

// Request is one API call as IAM evaluates it.
type Request struct {
	Action   string
	Resource string
	// Context holds condition keys: iam:PermissionsBoundary,
	// aws:ResourceTag/<k>, ... A key absent from the map is absent from the
	// request.
	Context map[string]string
}

// Decision is the evaluation result.
type Decision struct {
	Allowed bool
	// By is the Sid of the deciding statement ("" for implicit deny).
	By string
	// Explicit is true when an explicit Deny decided.
	Explicit bool
}

// Evaluate decides a request: explicit Deny > Allow > implicit deny.
func (p Policy) Evaluate(r Request) Decision {
	allowedBy := ""
	for _, st := range p.Statements {
		if !st.matches(r) {
			continue
		}
		if st.Effect == "Deny" {
			return Decision{Allowed: false, By: st.Sid, Explicit: true}
		}
		if st.Effect == "Allow" && allowedBy == "" {
			allowedBy = st.Sid
		}
	}
	if allowedBy != "" {
		return Decision{Allowed: true, By: allowedBy}
	}
	return Decision{}
}

func (st Statement) matches(r Request) bool {
	if len(st.Action) > 0 && !anyGlob(st.Action, r.Action, true) {
		return false
	}
	if len(st.NotAction) > 0 && anyGlob(st.NotAction, r.Action, true) {
		return false
	}
	if len(st.Action) == 0 && len(st.NotAction) == 0 {
		return false
	}
	if !anyGlob(st.Resource, r.Resource, false) {
		return false
	}
	for op, kv := range st.Condition {
		for key, vals := range kv {
			got, present := r.Context[key]
			if !present {
				return false
			}
			if !conditionHolds(op, got, vals) {
				return false
			}
		}
	}
	return true
}

func conditionHolds(op, got string, vals []string) bool {
	for _, v := range vals {
		switch op {
		case "StringEquals", "ArnEquals":
			if got == v {
				return true
			}
		case "StringLike", "ArnLike":
			if glob(v, got, false) {
				return true
			}
		default:
			// An operator this simulator does not model never holds, so a
			// template that starts using one fails its tests loudly instead
			// of being simulated as permissive.
			return false
		}
	}
	return false
}

func anyGlob(patterns []string, s string, fold bool) bool {
	for _, p := range patterns {
		if glob(p, s, fold) {
			return true
		}
	}
	return false
}

func glob(pattern, s string, fold bool) bool {
	var b strings.Builder
	b.WriteString("^")
	if fold {
		b.WriteString("(?i)")
	}
	for _, r := range pattern {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteString("$")
	return regexp.MustCompile(b.String()).MatchString(s)
}

// AllowedActions lists every action named by an Allow statement, sorted.
func (p Policy) AllowedActions() []string {
	seen := map[string]bool{}
	for _, st := range p.Statements {
		if st.Effect == "Allow" {
			for _, a := range st.Action {
				seen[a] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for a := range seen {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}
