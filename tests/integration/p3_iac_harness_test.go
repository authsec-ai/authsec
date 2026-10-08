package integration

// Shared plumbing for T3.17 (SPEC-iga-phase3-policy.md §1.1 J1/J2, §8.11,
// §11): the T3.11 lab (real scan, projection, evaluation, proposals,
// compile and approval through /api/iga/v1/policy, a fake discovery-role
// live reader) plus a FAKE GitHub (iacpr.Fake) behind the GitHub App
// installation of a GitHub discovery source, the IaC-source routes on
// /authsec/discovery, and helpers that insert the deployment T3.16 would
// create and run the T3.17 steps under a claimed job. Prefixed p3i.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	platform "github.com/authsec-ai/authsec/controllers/platform"
	"github.com/authsec-ai/authsec/internal/iacpr"
	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/middlewares"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
)

type p3iLab struct {
	*p3aLab
	gh       *iacpr.Fake
	repo     string
	ds       uuid.UUID
	integ    uuid.UUID
	clock    time.Time
	delivery *services.GovIaCDelivery
	disc     *gin.Engine
}

func newP3iLab(t *testing.T, name string) *p3iLab {
	t.Helper()
	l := &p3iLab{p3aLab: newP3aLab(t, name), gh: iacpr.NewFake()}
	l.repo = "acme/infra-" + l.ws.String()[:8]
	l.clock = time.Now().UTC()
	services.SetGovIaCGitHub(l.gh)
	l.integ, l.ds = uuid.New(), uuid.New()
	inst := fmt.Sprint(time.Now().UnixNano())
	p3exec(t, l.db, `INSERT INTO iga_integrations (id, workspace_id, provider, provider_host, app_registration_id, installation_id,
		requested_permissions, granted_permissions, status, verified_at)
		VALUES (?, ?, 'github', 'github.com', 'app-p3i', ?, '{"contents":"read","metadata":"read"}', '{"contents":"read","metadata":"read"}', 'active', now())`,
		l.integ, l.ws, inst)
	p3exec(t, l.db, `INSERT INTO discovery_sources (id, workspace_id, kind, display_name, config) VALUES (?, ?, 'repo_scan', 'acme', ?::jsonb)`,
		l.ds, l.ws, fmt.Sprintf(`{"integration_id":%q,"installation_id":%q}`, l.integ.String(), inst))
	// Runs before the lab's purge (LIFO): rows the purge does not know.
	t.Cleanup(func() {
		services.SetGovIaCGitHub(nil)
		for _, q := range []string{
			`DELETE FROM iga_gov_artifact WHERE workspace_id = ?`,
			`DELETE FROM iga_gov_workload_migration WHERE workspace_id = ?`,
			`DELETE FROM iga_gov_iac_change WHERE workspace_id = ?`,
			`DELETE FROM iga_gov_verification WHERE workspace_id = ?`,
			`DELETE FROM iga_gov_deployment WHERE workspace_id = ?`,
			`DELETE FROM iga_gov_iac_source WHERE workspace_id = ?`,
			`DELETE FROM discovery_sources WHERE workspace_id = ?`,
			`DELETE FROM iga_integrations WHERE workspace_id = ?`,
		} {
			l.db.Exec(q, l.ws)
		}
	})
	l.delivery = services.NewGovIaCDelivery(l.db, l.gh, l.live).WithClock(func() time.Time { return l.clock })
	l.disc = gin.New()
	g := l.disc.Group("/authsec/discovery")
	g.Use(middlewares.AuthMiddleware())
	platform.RegisterIaCSourceRoutes(g, platform.NewCloudIaCSourceController(l.db).WithPolicyGate(l.policy), middlewares.Require)
	return l
}

// grantWrite records the installation's grant of contents / pull-request
// write (what GitHub reports after the customer accepts the request).
func (l *p3iLab) grantWrite() {
	p3exec(l.t, l.db, `UPDATE iga_integrations SET granted_permissions = '{"contents":"write","pull_requests":"write","metadata":"read"}' WHERE id = ?`, l.integ)
}

func (l *p3iLab) discCall(method, path string, m p3aMember, scope string, body any) (int, map[string]any) {
	l.t.Helper()
	var rd *bytes.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, "/authsec/discovery"+path, rd)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+l.token(l.ws, m, scope))
	w := httptest.NewRecorder()
	l.disc.ServeHTTP(w, req)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// mapSource seeds the repository directory and maps it to the account
// through the route.
func (l *p3iLab) mapSource(format, dir string, files map[string]string) uuid.UUID {
	l.t.Helper()
	l.gh.Seed(l.repo, "main", files)
	code, body := l.discCall(http.MethodPost, "/aws/connectors/"+l.a.conn.String()+"/iac-sources", l.author, "governance:enforce",
		map[string]any{"format": format, "discovery_source_id": l.ds.String(), "repository": l.repo, "base_branch": "main", "directory": dir})
	d := l.must(code, body, http.StatusCreated, "POST iac-sources")
	return uuid.MustParse(d["id"].(string))
}

// propose opens a proposal with a delivery and compiles version 1.
func (l *p3iLab) propose(delivery string, roleIDs ...string) (string, map[string]any) {
	l.t.Helper()
	var keys []map[string]any
	for _, r := range roleIDs {
		keys = append(keys, map[string]any{"provider": "aws", "role_id": r})
	}
	code, body := l.call(l.author, http.MethodPost, "/proposals", map[string]any{"template": "right_size_services", "keys": keys, "delivery": delivery})
	d := l.must(code, body, http.StatusCreated, "POST /proposals")
	policy := d["policy"].(map[string]any)["id"].(string)
	return policy, l.compile(policy, 1)
}

// planOf is the current plan of a kind in a plans view.
func p3iPlan(t *testing.T, plans map[string]any, kind string) map[string]any {
	t.Helper()
	for _, x := range plans["plans"].([]any) {
		p := x.(map[string]any)
		if p["kind"] == kind {
			return p
		}
	}
	t.Fatalf("no %s plan in %v", kind, plans["plans"])
	return nil
}

// deploy inserts the deployment of the version's current plan of kind in
// `queued`, as T3.16's rollout would.
func (l *p3iLab) deploy(policy string, no int, kind string) uuid.UUID {
	l.t.Helper()
	v := l.versionID(policy, no)
	var p models.IGAGovPlan
	if err := l.db.Where("workspace_id = ? AND version_id = ? AND kind = ? AND superseded_at IS NULL", l.ws, v, kind).Take(&p).Error; err != nil {
		l.t.Fatalf("plan %s: %v", kind, err)
	}
	approval := bdbID(l.t, l.p2Lab, `SELECT id FROM iga_gov_approval WHERE workspace_id = ? AND version_id = ? AND decision = 'approve' AND revoked_at IS NULL`, l.ws, v)
	id := uuid.New()
	p3exec(l.t, l.db, `INSERT INTO iga_gov_deployment (id, workspace_id, version_id, plan_id, control_id, approval_id, kind, delivery, state)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'queued')`, id, l.ws, v, p.ID, p.ControlID, approval, kind, p.Delivery)
	return id
}

// settle sets a deployment's state as T3.16 would after verification.
func (l *p3iLab) settle(dep uuid.UUID, state string) {
	p3exec(l.t, l.db, `UPDATE iga_gov_deployment SET state = ? WHERE id = ?`, state, dep)
}

// run claims a fresh job of kind (subject subj) for one T3.17 step.
func (l *p3iLab) run(kind string, subj uuid.UUID) *services.PolicyJobRun {
	l.t.Helper()
	repo := repositories.NewIGAGovJobRepository(l.db)
	p3exec(l.t, l.db, `UPDATE iga_gov_job SET status = 'complete', completed_at = now(), lease_owner = '', lease_expires_at = NULL
		WHERE workspace_id = ? AND status IN ('queued','running')`, l.ws)
	j := &models.IGAGovJob{WorkspaceID: l.ws, Kind: kind, DedupeKey: "p3i:" + uuid.NewString(), SubjectID: &subj, RunAfter: time.Now().Add(-time.Hour)}
	if _, err := repo.EnqueueTx(l.db, j); err != nil {
		l.t.Fatal(err)
	}
	c := p3ClaimOwn(l.t, l.db, l.ws, "p3i-worker", 2*time.Minute, time.Now(), kind)
	if c == nil || c.SubjectID == nil || *c.SubjectID != subj {
		l.t.Fatalf("claim %s %s: %+v", kind, subj, c)
	}
	return services.NewPolicyJobRun(l.db, *c, "p3i-worker")
}

func (l *p3iLab) deliver(dep uuid.UUID) *services.GovIaCOutcome {
	l.t.Helper()
	out, err := l.delivery.Deliver(context.Background(), l.run(repositories.GovJobDeploy, dep), l.ws, dep)
	if err != nil {
		l.t.Fatalf("deliver: %v", err)
	}
	return out
}

func (l *p3iLab) sync(change uuid.UUID) *services.GovIaCOutcome {
	l.t.Helper()
	out, err := l.delivery.Sync(context.Background(), l.run(repositories.GovJobIaCSync, change), l.ws, change)
	if err != nil {
		l.t.Fatalf("sync: %v", err)
	}
	return out
}

func (l *p3iLab) observe(dep uuid.UUID) *services.GovIaCOutcome {
	l.t.Helper()
	out, err := l.delivery.ObserveApply(context.Background(), l.run(repositories.GovJobIaCSync, dep), l.ws, dep)
	if err != nil {
		l.t.Fatalf("observe: %v", err)
	}
	return out
}

func (l *p3iLab) dep(id uuid.UUID) models.IGAGovDeployment {
	l.t.Helper()
	var d models.IGAGovDeployment
	if err := l.db.Where("id = ?", id).Take(&d).Error; err != nil {
		l.t.Fatal(err)
	}
	return d
}

func (l *p3iLab) change(dep uuid.UUID) models.IGAGovIaCChange {
	l.t.Helper()
	var c models.IGAGovIaCChange
	if err := l.db.Where("deployment_id = ?", dep).Take(&c).Error; err != nil {
		l.t.Fatal(err)
	}
	return c
}

func (l *p3iLab) verification(dep uuid.UUID) (string, map[string]any) {
	l.t.Helper()
	var v models.IGAGovVerification
	if err := l.db.Where("deployment_id = ? AND dimension = 'artifact'", dep).Take(&v).Error; err != nil {
		l.t.Fatal(err)
	}
	var ev map[string]any
	_ = json.Unmarshal(v.Evidence, &ev)
	return v.Outcome, ev
}

func (l *p3iLab) depEvents(dep uuid.UUID) []string {
	var out []string
	l.db.Raw(`SELECT event FROM iga_gov_event WHERE workspace_id = ? AND deployment_id = ? ORDER BY id`, l.ws, dep).Scan(&out)
	return out
}

// customerPolicy registers a customer-managed policy in the live reader.
func (l *p3iLab) customerPolicy(name, doc string, users ...igagov.AttachedEntity) string {
	arn := "arn:aws:iam::" + accountA + ":policy/" + name
	l.live.mu.Lock()
	defer l.live.mu.Unlock()
	l.live.policies[arn] = &igagov.LivePolicy{ARN: arn, Path: "/", Name: name, Tags: map[string]string{}, DefaultDocument: doc,
		VersionCount: 1, AttachmentSet: users}
	return arn
}

// livePolicy replaces (nil: deletes) a live policy.
func (l *p3iLab) livePolicy(arn string, p *igagov.LivePolicy) {
	l.live.mu.Lock()
	defer l.live.mu.Unlock()
	if p == nil {
		delete(l.live.policies, arn)
		return
	}
	l.live.policies[arn] = p
}

// setBoundary sets a live role's boundary.
func (l *p3iLab) setBoundary(roleARN, boundary string) {
	l.live.mu.Lock()
	defer l.live.mu.Unlock()
	l.live.roles[roleARN].BoundaryARN = boundary
}

func roleUse(name, roleID, usage string) igagov.AttachedEntity {
	return igagov.AttachedEntity{Kind: "role", ID: roleID, Name: name, Usage: usage}
}

// waitAudits waits for n audit rows of an action (the audit logger writes
// asynchronously).
func (l *p3iLab) waitAudits(action string, n int64) bool {
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if l.audits(action) >= n {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

func p3iHas(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func p3iNotes(p map[string]any) string {
	var out []string
	for _, n := range dig(p, "diff", "notes").([]any) {
		out = append(out, n.(string))
	}
	return strings.Join(out, " | ")
}
