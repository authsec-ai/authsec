package load

// The fixture is only worth measuring if the reads find in it what they find
// in a projected estate: a list total that is the generated inventory, a
// Used-by that is the generated fan-in, a Changes event attributed to its
// revision and run (D-26/D-27a), evidence with facts (D-24). A generator
// mistake -- a partition key the reads cannot rebuild, a time that is not a
// publication's published_at, a missing support row -- would otherwise make
// the reads FAST and wrong (a 404 is quick). TestP2LoadFixtureIntegrity
// proves the fixture reads back as generated before any timing is trusted.

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/google/uuid"
)

// TestP2LoadFixtureIntegrity checks the fixture's shape (the stated ratios)
// and that the real routes read it back as generated.
func TestP2LoadFixtureIntegrity(t *testing.T) {
	env := loadEnvFor(t)
	g := env.main
	t.Logf("fixture: %d rows generated in %s, written in %s (0 = reused)", env.rows, env.generate, env.built)

	// The shape, from the database: what RESULTS.md states.
	counts := loadTableCounts(t, env, g.ws)
	for _, c := range loadShapeReport(counts) {
		t.Log(c)
	}
	for table, min := range map[string]int64{
		"iga_workload": 10000, "iga_identity_accounts": 3500, "iga_policy": 1900, "iga_entitlements": 11000,
		"iga_resources": 9900, "iga_entitlement_target": 18000, "iga_access_edges": 20000,
		"iga_relationship": 15000, "iga_lifecycle_event": 30000, "iga_publication": 12,
	} {
		if counts[table] < min {
			t.Errorf("%s: %d rows, the stated shape needs at least %d", table, counts[table], min)
		}
	}

	api := env.api
	// The unfiltered workload list's total is every active generated workload.
	body := loadMustGet(t, api, "/workloads?limit=1")
	if got := loadNum(body, "meta", "total"); got != float64(g.h.activeWL) {
		t.Errorf("workloads total = %v, generated %d active", got, g.h.activeWL)
	}
	if got := loadNum(body, "meta", "rev"); got != float64(len(g.pubs)) {
		t.Errorf("rev = %v, generated %d publications", got, len(g.pubs))
	}
	body = loadMustGet(t, api, "/identities?limit=1")
	if got := loadNum(body, "meta", "total"); got != float64(g.h.activeIdent) {
		t.Errorf("identities total = %v, generated %d active", got, g.h.activeIdent)
	}
	body = loadMustGet(t, api, "/resources?limit=1")
	if got := loadNum(body, "meta", "total"); got != float64(g.h.activeRes) {
		t.Errorf("resources total = %v, generated %d", got, g.h.activeRes)
	}

	// The hub execution role's Used-by is the generated fan-in.
	body = loadMustGet(t, api, "/identities/"+g.h.hubRole.String()+"/used-by")
	if got := loadNum(body, "data", "workloads", "total"); got != float64(g.h.hubRoleUsers) {
		t.Errorf("hub role used-by workloads total = %v, generated %d", got, g.h.hubRoleUsers)
	}

	// Changes attribute every event to a revision and a run (D-26, D-27a): a
	// time that is not exactly one publication's published_at renders null.
	for _, w := range g.h.switchedWL[:5] {
		body = loadMustGet(t, api, "/workloads/"+w.String()+"/changes")
		events, _ := loadDig(body, "data").([]any)
		if len(events) == 0 {
			t.Errorf("workload %s: no Changes events", w)
		}
		for _, e := range events {
			if loadDig(e, "rev") == nil || loadDig(e, "run") == nil {
				t.Errorf("workload %s: event %v has no rev/run: the fixture's times are not publication times", w, loadDig(e, "id"))
			}
		}
	}

	// Evidence reads facts for a grant (D-24): the junction links observations
	// confirmed by the grant's last confirming run.
	for _, id := range g.h.grants[:5] {
		body = loadMustGet(t, api, "/evidence?claim=grant:"+id.String())
		if facts, _ := loadDig(body, "data", "facts").([]any); len(facts) == 0 {
			t.Errorf("grant %s: evidence has no facts", id)
		}
	}

	// Several accounts with the same workload names (the 40 mirrored names).
	var dup int64
	if err := env.db.Raw(`SELECT count(*) FROM (SELECT display_name FROM iga_workload WHERE workspace_id = ?
		GROUP BY display_name HAVING count(DISTINCT estate_scope_id) > 1) d`, g.ws).Scan(&dup).Error; err != nil {
		t.Fatal(err)
	}
	if dup < 40 {
		t.Errorf("%d workload names repeat across accounts, the fixture states at least 40", dup)
	}
}

// loadTableCounts counts the workspace's rows per fixture table.
func loadTableCounts(t *testing.T, env *loadEnv, ws uuid.UUID) map[string]int64 {
	t.Helper()
	out := map[string]int64{}
	for _, spec := range loadTableOrder {
		col := "workspace_id"
		if spec.name == "workspaces" {
			col = "id"
		}
		var n int64
		if err := env.db.Raw(`SELECT count(*) FROM `+spec.name+` WHERE `+col+` = ?`, ws).Scan(&n).Error; err != nil {
			t.Fatalf("count %s: %v", spec.name, err)
		}
		out[spec.name] = n
	}
	return out
}

// loadShapeReport renders the counts as the lines RESULTS.md carries.
func loadShapeReport(c map[string]int64) []string {
	var out []string
	for _, spec := range loadTableOrder {
		out = append(out, fmt.Sprintf("%-28s %8d", spec.name, c[spec.name]))
	}
	return out
}

/* ------------------------------- JSON helpers ------------------------------ */

// loadMustGet calls a route and fails the test unless it answers 200.
func loadMustGet(t *testing.T, api *loadAPI, path string) map[string]any {
	t.Helper()
	code, raw, _ := api.get(path)
	if code != 200 {
		t.Fatalf("GET %s: %d %s", path, code, loadClip(raw))
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("GET %s: body is not JSON: %v", path, err)
	}
	return out
}

// loadDig walks decoded JSON by keys and indexes; nil when a step is missing.
func loadDig(v any, path ...any) any {
	for _, p := range path {
		switch k := p.(type) {
		case string:
			m, ok := v.(map[string]any)
			if !ok {
				return nil
			}
			v = m[k]
		case int:
			s, ok := v.([]any)
			if !ok || k < 0 || k >= len(s) {
				return nil
			}
			v = s[k]
		default:
			return nil
		}
	}
	return v
}

// loadNum is loadDig for a number (-1 when absent).
func loadNum(v any, path ...any) float64 {
	if n, ok := loadDig(v, path...).(float64); ok {
		return n
	}
	return -1
}

// loadClip shortens a body for a failure message.
func loadClip(raw []byte) string {
	if len(raw) > 400 {
		return string(raw[:400]) + "..."
	}
	return string(raw)
}
