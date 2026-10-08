package integration

// Review P1-6 (SPEC-iga-phase3-policy.md §3.4, §3.9) against REAL
// PostgreSQL, through the REAL scan worker with resource-policy collection
// (policy gate on), the REAL projection with evaluation, the REAL evidence
// bundle builder, readiness and the compiler behind the production routes.
// AWS is answered by internal/awsdiscovery/rpfake and the lab's fakes.
//
// A connector selecting a SUBSET of the account's enabled regions: the
// collector writes not_collected rows for the enabled-but-unselected
// regions, and the run freezes the enabled regions it saw. Every reader of
// the route analysis must report those regions not_analysed -- never "no
// route, coverage complete" -- and the first attachment is refused. A later
// scan selecting every enabled region completes coverage. Prefixed p3cov.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/internal/awsdiscovery/rpfake"
	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
)

// p3covWorld is an account with no resource policies anywhere: every form
// it can read is complete with nothing in it.
type p3covWorld struct {
	regions map[string]*rpfake.Region
	enabled *s2FakeRegions
}

func newP3covWorld(acct string, enabled ...string) *p3covWorld {
	w := &p3covWorld{regions: map[string]*rpfake.Region{}, enabled: s2Regions(enabled...)}
	for _, r := range append([]string{"us-west-2"}, enabled...) { // us-west-2: the MRAP control plane
		w.regions[r] = &rpfake.Region{Name: r, AccountID: acct}
	}
	return w
}

func (w *p3covWorld) wire(perm *services.AWSPermissionScanner) {
	perm.WithResourcePolicyClients(func(_ context.Context, region string) (awsdiscovery.ResourcePolicyClients, error) {
		r, ok := w.regions[region]
		if !ok {
			return awsdiscovery.ResourcePolicyClients{}, errors.New("no fake for " + region)
		}
		return awsdiscovery.ResourcePolicyClients{S3: r, S3Control: r, KMS: r, SQS: r, SNS: r, Lambda: r, Secrets: r}, nil
	}).WithRegionsAPI(w.enabled).
		WithCollectorOptions(awsdiscovery.CollectorOptions{MinCallInterval: -1, Backoff: time.Nanosecond,
			Sleep: func(context.Context, time.Duration) error { return nil }})
}

// publishCollected is one scan through the REAL worker WITH the policy gate,
// so resource-policy collection runs inside it, then one projection with
// evaluation. It returns the published run.
func (l *p3aLab) publishCollected(w *p3covWorld) models.CloudScanRun {
	l.t.Helper()
	scanSeq++
	queued, err := l.runs.Enqueue(l.ws, l.a.conn, "manual")
	if err != nil {
		l.t.Fatalf("enqueue: %v", err)
	}
	base := l.hook(l.a)
	worker := services.NewAWSScanWorker(l.db, l.a.svc).WithOwner(fmt.Sprintf("p3cov-scan-%d", scanSeq)).
		WithGraphProjection(l.gate).WithPolicyGate(l.policy).
		WithScannerHook(func(i *services.AWSIAMScanner, p *services.AWSPermissionScanner, wl *services.AWSWorkloadScanner) {
			base(i, p, wl)
			w.wire(p)
		})
	if worked, err := worker.RunOnce(context.Background()); err != nil || !worked {
		l.t.Fatalf("scan worker: worked=%v err=%v", worked, err)
	}
	var run models.CloudScanRun
	if err := l.db.First(&run, "id = ?", queued.ID).Error; err != nil || run.Status != models.CloudScanRunPublished {
		l.t.Fatalf("run %+v: %v", run, err)
	}
	l.projectOnly()
	if e := l.evaluation(l.latestRev()); e.Status != models.GovEvalComplete {
		l.t.Fatalf("evaluation %+v", e)
	}
	return run
}

// p3covPosture inserts a control and an sqs posture row for the role (the
// deploy observer's row; the evaluation only refreshes its route facts).
func p3covPosture(l *p3aLab, roleID, arn string, ident uuid.UUID) {
	l.t.Helper()
	policy, control := uuid.New(), uuid.New()
	p3exec(l.t, l.db, `INSERT INTO iga_gov_policy (id, workspace_id, name, family, provider, created_by) VALUES (?, ?, 'p3cov-posture', 'cloud_access', 'aws', ?)`,
		policy, l.ws, l.author.user)
	p3exec(l.t, l.db, `INSERT INTO iga_gov_control (id, workspace_id, connector_id, account_id, role_id, role_arn, identity_account_id, policy_id,
	                                                boundary_policy_arn, state)
	                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'planned')`,
		control, l.ws, l.a.conn, accountA, roleID, arn, ident, policy, "arn:aws:iam::"+accountA+":policy/authsec/AuthSecBoundary-"+roleID)
	p3exec(l.t, l.db, `INSERT INTO iga_gov_service_posture (workspace_id, account_id, role_id, service, control_id, exclusion, enforcement_seq,
	                                                        enforcement_observed_at, route_state, routes, evidence_rev)
	                   VALUES (?, ?, ?, 'sqs', ?, 'pending', 0, now(), 'not_analysed', '[]', 0)`, l.ws, accountA, roleID, control)
}

type p3covFacts struct {
	posture      string
	postureRoute string
	routeUsage   string
	bundle       *services.StoredBundle
	gaps         []string
	readiness    []string
}

// facts reads every consumer of the route analysis for the role's sqs.
func (l *p3aLab) p3covFacts(roleID string, ident uuid.UUID) p3covFacts {
	l.t.Helper()
	var f p3covFacts
	var post struct {
		RouteState string
		Routes     string
	}
	if err := l.db.Raw(`SELECT route_state, routes::text AS routes FROM iga_gov_service_posture
	                     WHERE workspace_id = ? AND role_id = ? AND service = 'sqs'`, l.ws, roleID).Scan(&post).Error; err != nil {
		l.t.Fatal(err)
	}
	f.posture, f.postureRoute = post.RouteState, post.Routes
	if err := l.db.Raw(`SELECT route_usage FROM iga_gov_activity_evidence WHERE workspace_id = ? AND rev = ? AND role_id = ? AND service = 'sqs'`,
		l.ws, l.latestRev(), roleID).Scan(&f.routeUsage).Error; err != nil {
		l.t.Fatal(err)
	}
	b, err := services.NewGovTargets(l.db).BuildEvidenceBundle(context.Background(), l.ws, ident, []string{"sqs"}, models.GovActorSystem, "p3cov")
	if err != nil {
		l.t.Fatal(err)
	}
	f.bundle = b
	for _, g := range b.Facts.Gaps {
		f.gaps = append(f.gaps, g.Key)
	}
	code, body := l.call(l.author, http.MethodGet, "/readiness", nil)
	if code != http.StatusOK {
		l.t.Fatalf("/readiness: %d %v", code, body)
	}
	for _, x := range digl(body, "data", "roles") {
		r := x.(map[string]any)
		if r["role_id"] != roleID {
			continue
		}
		for _, y := range r["reasons"].([]any) {
			f.readiness = append(f.readiness, y.(map[string]any)["code"].(string))
		}
	}
	return f
}

// The connector selects us-east-1 of the enabled us-east-1 + eu-west-1.
func TestP3CovUnselectedRegionsAreNotAnalysed(t *testing.T) {
	l := newP3aLab(t, "p3-cov-unselected")
	arn := l.role("CovRole", "AROACOVROLE0001", map[string]*time.Time{"s3": p3eTime(time.Hour), "sqs": nil})
	world := newP3covWorld(accountA, "eu-west-1", "us-east-1")
	l.publishCollected(world) // the role exists in the graph from here
	ident := bdbIdentity(t, l.p2Lab, "CovRole")
	p3covPosture(l, "AROACOVROLE0001", arn, ident)

	run := l.publishCollected(world)

	// The run froze the scope it collected under.
	cov := models.DecodeScanCoverage(run.Coverage)
	if cov.Regions == nil || strings.Join(cov.Regions.Selected, ",") != "us-east-1" ||
		strings.Join(cov.Regions.Enabled, ",") != "eu-west-1,us-east-1" || !cov.Regions.EnabledKnown {
		raw, _ := json.Marshal(cov.Regions)
		t.Fatalf("run region scope %s, want selected [us-east-1], enabled [eu-west-1 us-east-1], known", raw)
	}
	var unsel string
	l.db.Raw(`SELECT state FROM cloud_resource_policy_coverage WHERE workspace_id = ? AND scan_run_id = ?
	          AND resource_form = 'sqs_queue' AND region = 'eu-west-1'`, l.ws, run.ID).Scan(&unsel)
	if unsel != igagov.CoverageNotCollected {
		t.Fatalf("sqs_queue/eu-west-1 = %q, want the collector's not_collected row", unsel)
	}

	f := l.p3covFacts("AROACOVROLE0001", ident)
	// Posture route facts (evaluation): not_analysed, naming the region.
	if f.posture != igagov.RouteStateNotAnalysed || !strings.Contains(f.postureRoute, `"region":"eu-west-1"`) {
		t.Fatalf("posture route facts %s %s, want not_analysed naming sqs_queue in eu-west-1", f.posture, f.postureRoute)
	}
	// Activity evidence (finding evaluation): confirmation required.
	if f.routeUsage != igagov.RouteUsageConfirmRequired {
		t.Fatalf("route_usage %q, want confirm_required", f.routeUsage)
	}
	// Bundle: partial, the region a gap, the source's coverage partial.
	if f.bundle.Trust != igagov.TrustPartial || !p3eHas(f.gaps, "resource_policy_coverage:sqs_queue:eu-west-1") ||
		f.bundle.Facts.Sources[0].ResourcePolicyCoverage != igagov.CoveragePartial {
		t.Fatalf("bundle trust %s %v gaps %v source %+v, want partial with the sqs_queue/eu-west-1 gap",
			f.bundle.Trust, f.bundle.TrustReasons, f.gaps, f.bundle.Facts.Sources[0])
	}
	// Readiness: blocked by collection.
	if !p3eHas(f.readiness, "resource_policy_coverage_partial") {
		t.Fatalf("readiness reasons %v, want resource_policy_coverage_partial", f.readiness)
	}
	// The first attachment is refused, naming the region.
	policy, _ := l.proposeTemplate("AROACOVROLE0001")
	plans := l.compile(policy, 1)
	ap := plans["plans"].([]any)[0].(map[string]any)
	if ap["kind"] != "apply" || ap["first_attachment"] != true || ap["eligibility"] == "eligible" ||
		!strings.Contains(fmt.Sprint(ap), "sqs_queue in eu-west-1") {
		t.Fatalf("apply plan %v, want a first attachment refused for sqs_queue in eu-west-1", ap)
	}

	// The connector's LIVE selection changing does not rewrite what the
	// published run covered: the bundle still reads the frozen scope.
	p3exec(t, l.db, `UPDATE cloud_connector SET attrs = jsonb_set(attrs, '{regions}', '["us-east-1","eu-west-1"]') WHERE id = ?`, l.a.conn)
	p3exec(t, l.db, `UPDATE cloud_connector SET attrs = jsonb_set(attrs, '{regions}', '["us-east-1"]') WHERE id = ?`, l.a.conn)
	if b := l.p3covFacts("AROACOVROLE0001", ident).bundle; b.Trust != igagov.TrustPartial {
		t.Fatalf("bundle after a live attrs change: %s", b.Trust)
	}

	// A later scan selecting every enabled region completes coverage.
	l.a.svc.WithRegionsAPI(world.enabled)
	if _, _, err := l.a.svc.UpdateRegions(context.Background(), l.ws, l.a.conn, []string{"eu-west-1", "us-east-1"}); err != nil {
		t.Fatalf("select every enabled region: %v", err)
	}
	run2 := l.publishCollected(world)
	if c := models.DecodeScanCoverage(run2.Coverage); c.Regions == nil || strings.Join(c.Regions.Selected, ",") != "eu-west-1,us-east-1" {
		t.Fatalf("second run scope %+v", c.Regions)
	}
	f = l.p3covFacts("AROACOVROLE0001", ident)
	if f.posture != igagov.RouteStateNoneObserved || f.routeUsage != igagov.RouteUsageNoneObserved {
		t.Fatalf("after selecting every region: posture %s %s, route_usage %s, want none_observed", f.posture, f.postureRoute, f.routeUsage)
	}
	if f.bundle.Facts.Sources[0].ResourcePolicyCoverage != igagov.CoverageComplete || len(f.gaps) != 0 {
		t.Fatalf("after selecting every region: bundle %s source %+v gaps %v", f.bundle.Trust, f.bundle.Facts.Sources[0], f.gaps)
	}
	for _, r := range f.readiness {
		if strings.HasPrefix(r, "resource_policy_coverage") {
			t.Fatalf("readiness still %v", f.readiness)
		}
	}
	policy2, _ := l.proposeTemplate("AROACOVROLE0001")
	ap = l.compile(policy2, 1)["plans"].([]any)[0].(map[string]any)
	if ap["first_attachment"] != true || ap["eligibility"] != "eligible" {
		t.Fatalf("apply plan after complete coverage %v, want eligible", ap)
	}
}

// DescribeRegions refused at scan time: the run records the enabled regions
// as unknown, and every regional form is not_analysed (never complete).
func TestP3CovEnabledRegionsUnknownIsNotAnalysed(t *testing.T) {
	l := newP3aLab(t, "p3-cov-unknown")
	l.role("UnknownRole", "AROAUNKNOWN0001", map[string]*time.Time{"s3": p3eTime(time.Hour), "sqs": nil})
	world := newP3covWorld(accountA, "us-east-1")
	world.enabled.err = rpfake.APIError("UnauthorizedOperation")
	run := l.publishCollected(world)
	if c := models.DecodeScanCoverage(run.Coverage); c.Regions == nil || c.Regions.EnabledKnown {
		t.Fatalf("run scope %+v, want recorded with enabled unknown", c.Regions)
	}
	ident := bdbIdentity(t, l.p2Lab, "UnknownRole")
	f := l.p3covFacts("AROAUNKNOWN0001", ident)
	if f.routeUsage != igagov.RouteUsageConfirmRequired || f.bundle.Trust != igagov.TrustPartial ||
		!p3eHas(f.gaps, "resource_policy_coverage:sqs_queue:*") || !p3eHas(f.readiness, "resource_policy_coverage_partial") {
		t.Fatalf("unknown enabled regions: route_usage %s bundle %s gaps %v readiness %v", f.routeUsage, f.bundle.Trust, f.gaps, f.readiness)
	}
}
