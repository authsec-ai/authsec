package authz

import "strings"

type Perm struct {
	R string   `json:"r"` // resource (e.g., "invoice")
	A []string `json:"a"` // actions/methods (e.g., ["read","void"])
}

// FromScopes turns ["invoice:read","invoice:write"] into
// [{r:"invoice", a:["read","write"]}].
func FromScopes(scopeNames []string) []Perm {
	type key struct{ r string }
	m := map[key]map[string]struct{}{}
	for _, sc := range scopeNames {
		parts := strings.SplitN(sc, ":", 2)
		if len(parts) != 2 {
			continue
		}
		r, a := parts[0], parts[1]
		k := key{r: r}
		if _, ok := m[k]; !ok {
			m[k] = map[string]struct{}{}
		}
		m[k][a] = struct{}{}
	}
	out := make([]Perm, 0, len(m))
	for k, acts := range m {
		as := make([]string, 0, len(acts))
		for a := range acts {
			as = append(as, a)
		}
		out = append(out, Perm{R: k.r, A: as})
	}
	return out
}

// MatchScope supports "resource:action" with simple wildcards:
// "invoice:*", "*:read", or "*:*".
func MatchScope(have []string, needed string) bool {
	np := strings.SplitN(needed, ":", 2)
	if len(np) != 2 {
		return false
	}
	nr, na := np[0], np[1]
	for _, s := range have {
		hp := strings.SplitN(s, ":", 2)
		if len(hp) != 2 {
			continue
		}
		hr, ha := hp[0], hp[1]
		if (hr == nr || hr == "*" || nr == "*") && (ha == na || ha == "*" || na == "*") {
			return true
		}
	}
	return false
}

// dedupe returns a new slice with duplicates removed, preserving first-seen order.
func dedupe(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
