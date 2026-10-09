// The plan endpoint over HTTP — the wiring the service tests cannot reach.
//
// Everything between the actuation token and the served bytes lives in the
// controller: who is allowed to ask, which cluster they are told about, how the
// self-report is parsed off the query string, and when a 304 is correct. Each of
// those is a place a plausible-looking mistake produces a working-looking system
// that enforces the wrong thing, so they are exercised against a real router.
package ownership

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/authsec-ai/authsec/controllers/platform"
	"github.com/authsec-ai/authsec/models"
	"github.com/gin-gonic/gin"
)

// planRouter mounts the two plan routes exactly as routes.go does: the agent's
// surface authenticated by the actuation token and NOT by the console middleware,
// the console's surface behind a workspace claim.
func planRouter(t *testing.T, f planFixture) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	ctl := platform.NewGovernanceController(gormFor(t, f.raw))
	r := gin.New()
	r.GET("/authsec/provisioning/enforcement-plan", ctl.GetEnforcementPlan)
	r.GET("/authsec/governance/connectors/:id/enforcement-plans",
		func(c *gin.Context) { c.Set("workspace_id", f.ws.String()) },
		ctl.ListEnforcementPlans)
	return r
}

func get(t *testing.T, r *gin.Engine, path, token, ifNoneMatch string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if ifNoneMatch != "" {
		req.Header.Set("If-None-Match", ifNoneMatch)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

// The token is the only thing that says which cluster is asking, so an unauthenticated
// or wrong-token caller must learn nothing at all.
func TestPlanEndpointRefusesWithoutAValidActuationToken(t *testing.T) {
	f := newPlanFixture(t)
	r := planRouter(t, f)

	for name, token := range map[string]string{
		"no token":    "",
		"wrong token": "not-the-token",
	} {
		rec := get(t, r, "/authsec/provisioning/enforcement-plan", token, "")
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: want 401, got %d (%s)", name, rec.Code, rec.Body.String())
		}
		if rec.Body.Len() > 0 && jsonHas(t, rec.Body.Bytes(), "deny") {
			t.Errorf("%s: a rejected caller was served plan content", name)
		}
	}
}

func TestPlanEndpointServesTheClusterBehindTheToken(t *testing.T) {
	f := newPlanFixture(t)
	r := planRouter(t, f)
	if _, err := f.dm.QuarantineAgent(f.ws, f.agent, "suspicious egress", nil); err != nil {
		t.Fatalf("quarantine: %v", err)
	}

	rec := get(t, r, "/authsec/provisioning/enforcement-plan"+
		"?mode=observe&enforcing=0&denials=3", f.token, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var d models.EnforcementPlanDoc
	if err := json.Unmarshal(rec.Body.Bytes(), &d); err != nil {
		t.Fatalf("served body is not a plan: %v\n%s", err, rec.Body.String())
	}
	if d.Cluster != "prod-1" {
		t.Errorf("the token decides the cluster; got %q", d.Cluster)
	}
	if len(d.Deny) != 1 || d.Deny[0].Fingerprint != "fp-prov-1" {
		t.Fatalf("want our one contained agent, got %+v", d.Deny)
	}
	if !contains(d.Deny[0].Reason, "suspicious egress") {
		t.Errorf("the operator's words must reach the cluster, got %q", d.Deny[0].Reason)
	}

	// The self-report rides on the fetch. Without this the console can show a
	// cluster that fetched a plan and never said what it did with it.
	var mode string
	var version, denials int64
	if err := f.raw.QueryRow(`SELECT enforcement_mode, enforced_plan_version,
	                                 enforcement_denials_total
	                            FROM discovery_sources WHERE id = $1`, f.source).
		Scan(&mode, &version, &denials); err != nil {
		t.Fatalf("read report: %v", err)
	}
	if mode != "observe" || version != 0 || denials != 3 {
		t.Errorf("the query-string report was not folded in: mode=%q enforcing=%d denials=%d",
			mode, version, denials)
	}
}

// A garbled report must not cost the cluster its plan. Enforcement is not allowed
// to fail over telemetry.
func TestUnparseableReportStillServesThePlan(t *testing.T) {
	f := newPlanFixture(t)
	r := planRouter(t, f)

	rec := get(t, r, "/authsec/provisioning/enforcement-plan"+
		"?mode=nonsense&enforcing=abc&denials=-4", f.token, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("a bad self-report must not withhold the plan; got %d: %s",
			rec.Code, rec.Body.String())
	}
	var mode string
	if err := f.raw.QueryRow(`SELECT enforcement_mode FROM discovery_sources WHERE id = $1`,
		f.source).Scan(&mode); err != nil {
		t.Fatalf("read: %v", err)
	}
	if mode != "" {
		t.Errorf("an unknown mode must be rejected rather than stored, got %q", mode)
	}
}

// An agent reconnecting to a plan it already holds must not re-index.
func TestEtagYieldsA304AndChangesWhenThePlanDoes(t *testing.T) {
	f := newPlanFixture(t)
	r := planRouter(t, f)

	first := get(t, r, "/authsec/provisioning/enforcement-plan?mode=observe", f.token, "")
	etag := first.Header().Get("ETag")
	if etag == "" {
		t.Fatal("no ETag; every poll would re-send and re-index the whole plan")
	}

	again := get(t, r, "/authsec/provisioning/enforcement-plan?mode=observe", f.token, etag)
	if again.Code != http.StatusNotModified {
		t.Errorf("an unchanged plan must answer 304, got %d", again.Code)
	}
	if again.Body.Len() != 0 {
		t.Errorf("a 304 must carry no body, got %d bytes", again.Body.Len())
	}

	// A containment must break the ETag, or the cluster would keep its 304 and
	// never learn about the decision.
	if _, err := f.dm.QuarantineAgent(f.ws, f.agent, "hold", nil); err != nil {
		t.Fatalf("quarantine: %v", err)
	}
	changed := get(t, r, "/authsec/provisioning/enforcement-plan?mode=observe", f.token, etag)
	if changed.Code != http.StatusOK {
		t.Fatalf("a changed plan must be re-sent, got %d", changed.Code)
	}
	if changed.Header().Get("ETag") == etag {
		t.Error("the ETag did not change with the plan; the cluster would stay on a 304 " +
			"and never learn the agent was quarantined")
	}
}

// The console view exists to make the gap between a decision and its effect
// impossible to miss.
func TestConsoleViewReportsTheEnforcementGap(t *testing.T) {
	f := newPlanFixture(t)
	r := planRouter(t, f)

	// First poll: the agent holds nothing, so it honestly reports enforcing=0 and
	// receives v1 (an empty plan).
	get(t, r, "/authsec/provisioning/enforcement-plan?mode=observe&enforcing=0", f.token, "")
	// Second poll: it now holds v1 and says so. This is the state a healthy,
	// up-to-date cluster is in.
	get(t, r, "/authsec/provisioning/enforcement-plan?mode=observe&enforcing=1", f.token, "")

	// Now a decision is taken and published as v2, and the cluster has not polled
	// since. THAT is the gap: decided at v2, enforcing v1.
	if _, err := f.dm.QuarantineAgent(f.ws, f.agent, "hold", nil); err != nil {
		t.Fatalf("quarantine: %v", err)
	}
	if _, _, err := f.pm.Publish(f.ws, f.source); err != nil {
		t.Fatalf("publish: %v", err)
	}

	rec := get(t, r, "/authsec/governance/connectors/"+f.source.String()+"/enforcement-plans", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		PublishedVersion    int64  `json:"published_version"`
		EnforcedPlanVersion *int64 `json:"enforced_plan_version"`
		Behind              bool   `json:"behind"`
		Mode                string `json:"enforcement_mode"`
		Plans               []struct {
			Version int64 `json:"version"`
		} `json:"plans"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v\n%s", err, rec.Body.String())
	}
	if out.PublishedVersion != 2 {
		t.Errorf("want the latest published version 2, got %d", out.PublishedVersion)
	}
	if out.EnforcedPlanVersion == nil {
		t.Error("the cluster reported a version and it was not recorded")
	} else if *out.EnforcedPlanVersion != 1 {
		t.Errorf("want the cluster reported as enforcing v1, got v%d", *out.EnforcedPlanVersion)
	}
	if !out.Behind {
		t.Error("decided at v2, enforcing v1 — that IS the enforcement gap, and it must " +
			"be stated rather than left for the console to subtract")
	}
	if out.Mode != "observe" {
		t.Errorf("want the reported mode surfaced, got %q", out.Mode)
	}
	if len(out.Plans) != 2 || out.Plans[0].Version != 2 {
		t.Errorf("want both versions newest-first, got %+v", out.Plans)
	}
}

// A connector in another workspace must be invisible, not merely empty.
func TestConsoleViewIsWorkspaceScoped(t *testing.T) {
	f := newPlanFixture(t)
	gin.SetMode(gin.TestMode)
	ctl := platform.NewGovernanceController(gormFor(t, f.raw))
	r := gin.New()
	r.GET("/authsec/governance/connectors/:id/enforcement-plans",
		func(c *gin.Context) { c.Set("workspace_id", wsB) },
		ctl.ListEnforcementPlans)

	rec := get(t, r, "/authsec/governance/connectors/"+f.source.String()+"/enforcement-plans", "", "")
	if rec.Code != http.StatusNotFound {
		t.Errorf("another workspace's connector must be not-found, got %d: %s",
			rec.Code, rec.Body.String())
	}
}

func jsonHas(t *testing.T, body []byte, key string) bool {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil {
		return false
	}
	_, ok := m[key]
	return ok
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
