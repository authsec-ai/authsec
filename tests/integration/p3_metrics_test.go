package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/awsenforce/enforcetest"
	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
)

// T3.18 (SPEC-iga-phase3-policy.md §8.12, §7.8; P-14; A19, A43, A48, A49):
// metrics_rollup over posture and history rows written by T3.16's REAL
// enforcement observer (deploy -> readback -> publication -> verify, undo),
// and GET /api/iga/v1/policy/metrics.
//
// Safeguards (mutation-checked, see the report): posture excludes retired
// controls; "removed" counts only the `removed` outcome (A43); changes come
// from history of deployments verified in the hour, already_excluded never
// (A48 / DB94); the workspace filter; the TimeZone pin (M9).

// mLab is dLab with a clock pinned 5 minutes into a fresh hour, so every
// step of a test lands in a known hour, and the metrics service on it.
type mLab struct {
	*dLab
	m  *services.GovMetrics
	h0 time.Time
}

func newMLab(t *testing.T) *mLab {
	t.Helper()
	d := newDLab(t)
	h0 := time.Now().UTC().Truncate(time.Hour).Add(time.Hour)
	d.advance(h0.Add(5 * time.Minute).Sub(time.Now()))
	return &mLab{dLab: d, m: services.NewGovMetrics(d.db, readTestCursorKey).WithClock(d.now), h0: h0}
}

// toHour moves the clock to 5 minutes into hour h.
func (l *mLab) toHour(h time.Time) {
	l.advance(h.Add(5 * time.Minute).Sub(l.now()))
}

// rollup computes hour h as the job would, after the hour ended (the clock
// moves to h+1h+1m if it is earlier).
func (l *mLab) rollup(h time.Time) models.IGAGovMetricsHourly {
	l.t.Helper()
	if l.now().Before(h.Add(time.Hour + time.Minute)) {
		l.toHour(h.Add(time.Hour))
	}
	r, err := l.m.Rollup(context.Background(), l.ws, h)
	if err != nil {
		l.t.Fatalf("rollup %s: %v", h, err)
	}
	return *r
}

type mCounts struct {
	Removed, Remain, Unknown, Pending, NewlyEx, NewlyUnex, RightSized, Eligible, Undos int
}

func counts(r models.IGAGovMetricsHourly) mCounts {
	return mCounts{r.PostureRemoved, r.PostureExcludedRoutesRemain, r.PostureExcludedRoutesUnknown, r.PosturePending,
		r.ChangesNewlyExcluded, r.ChangesNewlyUnexcluded, r.RolesRightSized, r.RolesEligible, r.Undos}
}

// A48 + A19, through the real observer: v1 excludes sqs (hour 0), v2
// excludes sqs and sns (hour 1), undo of v2 (hour 2). Posture 1, 2, then 1
// -- never 3; changes sqs +1, sns +1, sns -1 (already_excluded sqs in v2
// never counted); undo counted; sqs never reopened. Then GET /metrics over
// the three hours: summary subtracts the undone exclusion.
func TestP3T318MetricsSuccessiveDeploymentsAndUndoA48A19(t *testing.T) {
	l := newMLab(t)
	ctx := context.Background()
	x := l.role("M48Role", "/", nil)
	fSQS, fSNS := l.finding(x, "sqs"), l.finding(x, "sns")
	h0, h1, h2 := l.h0, l.h0.Add(time.Hour), l.h0.Add(2*time.Hour)

	tp1 := l.compile(l.fake.Discovery(), x, "sqs")
	l.applyAndVerify(x, l.storeApproved(x, tp1.Apply, *tp1.Undo))
	r0 := l.rollup(h0)
	if got, want := counts(r0), (mCounts{Removed: 1, NewlyEx: 1, RightSized: 1, Eligible: 1}); got != want {
		t.Fatalf("hour 0 (v1 sqs): %+v want %+v", got, want)
	}

	l.toHour(h1)
	tp2 := l.compile(l.fake.Discovery(), x, "sns", "sqs")
	s2 := l.storeApproved(x, tp2.Apply, *tp2.Undo)
	d2 := l.applyAndVerify(x, s2)
	var already int64
	l.db.Raw(`SELECT count(*) FROM iga_gov_service_outcome WHERE deployment_id = ? AND change = 'already_excluded'`, d2).Scan(&already)
	if already != 1 {
		t.Fatalf("v2 history must carry sqs as already_excluded (DB94 precondition): %d", already)
	}
	r1 := l.rollup(h1)
	if got, want := counts(r1), (mCounts{Removed: 2, NewlyEx: 1, RightSized: 1, Eligible: 1}); got != want {
		t.Fatalf("hour 1 (v2 sqs+sns): %+v want %+v (posture 2, never 3; sqs already_excluded not a change)", got, want)
	}

	l.toHour(h2)
	u, err := l.dep.Undo(ctx, l.ws, l.approver, d2, services.GovUndoRequest{}, false)
	if err != nil {
		t.Fatal(err)
	}
	l.mustRun("deploy", u.ID)
	arn := *tp1.Apply.DesiredBoundaryARN
	l.publish(x, l.now().Add(time.Second), arn, l.ledgerVersion(x, arn))
	l.mustRun("verify", u.ID)
	if l.state(u.ID) != "verified" || l.state(d2) != "undone" {
		t.Fatalf("undo: %s / v2 %s", l.state(u.ID), l.state(d2))
	}
	r2 := l.rollup(h2)
	// sns: not_removed (not counted); its finding reopened, so the role is
	// still eligible (once).
	if got, want := counts(r2), (mCounts{Removed: 1, NewlyUnex: 1, RightSized: 1, Eligible: 1, Undos: 1}); got != want {
		t.Fatalf("hour 2 (undo v2): %+v want %+v", got, want)
	}
	if l.findingStatus(fSQS) != "resolved" || l.findingStatus(fSNS) != "reopened" {
		t.Fatalf("findings: sqs %s (never reopened) sns %s", l.findingStatus(fSQS), l.findingStatus(fSNS))
	}
	if r2.ApplyToVerifiedP95Seconds == nil || r0.ApplyToVerifiedP95Seconds == nil {
		t.Fatalf("apply_to_verified p95 missing: %v %v", r0.ApplyToVerifiedP95Seconds, r2.ApplyToVerifiedP95Seconds)
	}

	// The API over the three hours (and one hour that has no row).
	api := p3NewOwnersAPI(t, l.db)
	tok := api.token(l.ws, l.user, uuid.Nil, "governance:read")
	q := "/metrics?from=" + url.QueryEscape(h0.Format(time.RFC3339)) + "&to=" + url.QueryEscape(h0.Add(4*time.Hour).Format(time.RFC3339))
	code, body := api.call(http.MethodGet, q, tok, nil)
	if code != http.StatusOK {
		t.Fatalf("GET /metrics: %d %v", code, body)
	}
	rows := body["data"].([]any)
	if len(rows) != 3 {
		t.Fatalf("rows: %d", len(rows))
	}
	removed := []float64{}
	for _, r := range rows {
		removed = append(removed, r.(map[string]any)["posture_removed"].(float64))
	}
	if removed[0] != 1 || removed[1] != 2 || removed[2] != 1 {
		t.Fatalf("posture_removed by hour: %v", removed)
	}
	sum := body["meta"].(map[string]any)["summary"].(map[string]any)
	if sum["removed"].(float64) != 1 || sum["newly_excluded"].(float64) != 2 || sum["newly_unexcluded"].(float64) != 1 ||
		sum["net_excluded"].(float64) != 1 || sum["undos"].(float64) != 1 || sum["hours_in_range"].(float64) != 4 ||
		sum["hours_missing"].(float64) != 1 {
		t.Fatalf("summary: %v", sum)
	}
	head := strings.Join(toStrings(sum["headline"]), " | ")
	for _, want := range []string{"1 service removed", "2 exclusions verified, 1 exclusion reversed (net +1)",
		"other controls may still restrict", "1 hour has no metrics row"} {
		if !strings.Contains(head, want) {
			t.Fatalf("headline lacks %q: %s", want, head)
		}
	}
	if strings.Contains(head, "3 services removed") || strings.Contains(strings.ToLower(head), "access restored") {
		t.Fatalf("headline: %s", head)
	}
}

func toStrings(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}

// compileWithQueueGrant compiles like dLab.compile, with the account's queue
// `refunds` granting principal sqs:ReceiveMessage in the plan's named scan.
func (l *mLab) compileWithQueueGrant(x *x3Role, principal string, remove ...string) igagov.TargetPlans {
	l.t.Helper()
	doc, err := igagov.DecodePolicyDocument(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"` + principal +
		`"},"Action":"sqs:ReceiveMessage","Resource":"arn:aws:sqs:us-east-1:` + testAccount + `:refunds"}]}`)
	if err != nil {
		l.t.Fatal(err)
	}
	ev := &igagov.ResourcePolicyEvidence{Coverage: x3Coverage(), Observations: []igagov.ResourcePolicyObservation{{
		Form: "sqs_queue", Region: "us-east-1", ResourceARN: "arn:aws:sqs:us-east-1:" + testAccount + ":refunds",
		PolicyPresent: true, DocumentHash: "refunds-policy", ParseState: igagov.ParseParsed, Document: &doc}}}
	tp, err := igagov.CompileTarget(igagov.TargetInput{Control: x.ref, Intent: l.intent(x, remove...), Live: l.live(l.fake.Discovery(), x),
		Evidence: l.evidenceWith(x, remove, ev), ScanEvidence: ev, EnabledRegions: []string{"us-east-1"}, AccountServices: []string{"ecr", "sqs"}})
	if err != nil {
		l.t.Fatalf("compile %s: %v", x.name, err)
	}
	return tp
}

// evidenceWith is x3Lab.evidence with the route analyses run over ev (the
// named scan's observations, not only its coverage).
func (l *mLab) evidenceWith(x *x3Role, remove []string, ev *igagov.ResourcePolicyEvidence) igagov.EvidenceRef {
	l.t.Helper()
	at := time.Now().UTC().Add(-3 * time.Hour)
	role := igagov.RoleRef{RoleID: x.role.RoleID, ARN: x.arn, Name: x.name, AccountID: testAccount}
	act := []igagov.BundleActivity{}
	var routes []igagov.RouteAnalysis
	for _, s := range remove {
		act = append(act, igagov.BundleActivity{Service: s, State: igagov.EvidenceCollected, Outcome: igagov.QualNoAttempt,
			GrantAgeBasis: igagov.GrantAgePredatesObservation, QualifiedDays: 112})
		routes = append(routes, igagov.AnalyzeRoutes(s, role, ev, []string{"us-east-1"}))
	}
	b, err := igagov.BuildBundle(igagov.BundleInput{BuiltAt: time.Now().UTC(),
		Sources: []igagov.BundleSourceInput{{Kind: igagov.SourceAWSPublication, Rev: 1, PublishedAt: at, ConnectorID: l.conn.ID.String(),
			ConnectorRun: l.scanRun.String(), Authenticated: true, Ordered: true, ActivityReportGeneratedAt: &at,
			ResourcePolicyCoverage: igagov.CoverageComplete, ResourcePolicyRun: l.scanRun.String()}},
		Target:          igagov.BundleTarget{AccountID: testAccount, RoleID: x.role.RoleID, RoleARN: x.arn},
		RemovedServices: remove, Consumers: []igagov.ImpactConsumer{{WorkloadID: uuid.NewString(), Relationship: "executes_as"}},
		Owners: []string{l.user.String()}, Activity: act, RouteAnalyses: routes}, igagov.DefaultTrustRules())
	if err != nil {
		l.t.Fatal(err)
	}
	l.bundles[b.Hash] = b
	return igagov.EvidenceRef{Bundle: b, EvidenceRev: 1, ScanRunID: l.scanRun.String()}
}

// A43: the queue policy names a SESSION of the role; after apply sqs is
// excluded_routes_remain, its finding mitigated, and metrics count it under
// routes remaining -- never removed, the role not right-sized; the headline
// names the route. sns (no route) is removed.
func TestP3T318MetricsKnownBypassNotRemovedA43(t *testing.T) {
	l := newMLab(t)
	x := l.role("M43Role", "/", nil)
	fSQS := l.finding(x, "sqs")
	session := "arn:aws:sts::" + testAccount + ":assumed-role/M43Role/worker"
	tp := l.compileWithQueueGrant(x, session, "sqs", "sns")
	if st, _ := routeStateOf(tp.Apply, "sqs"); st != igagov.RouteStateBypassKnown {
		t.Fatalf("precondition: sqs route state %s", st)
	}
	l.applyAndVerify(x, l.storeApproved(x, tp.Apply, *tp.Undo))
	if p := l.posture(x); p["sqs"] != "applied/excluded_routes_remain" || p["sns"] != "applied/removed" {
		t.Fatalf("posture: %v", p)
	}
	if l.findingStatus(fSQS) != "mitigated" {
		t.Fatalf("sqs finding: %s", l.findingStatus(fSQS))
	}
	r := l.rollup(l.h0)
	if got, want := counts(r), (mCounts{Removed: 1, Remain: 1, NewlyEx: 2, RightSized: 1, Eligible: 1}); got != want {
		t.Fatalf("A43 metrics: %+v want %+v", got, want)
	}

	// Hour 1: a second role excluding sqs alone (bypass): that role is NOT
	// right-sized; posture is cumulative, the change is the hour's.
	y := l.role("M43Only", "/", nil)
	tpy := l.compileWithQueueGrant(y, "arn:aws:sts::"+testAccount+":assumed-role/M43Only/w", "sqs")
	l.applyAndVerify(y, l.storeApproved(y, tpy.Apply, *tpy.Undo))
	r = l.rollup(l.h0.Add(time.Hour))
	if got, want := counts(r), (mCounts{Removed: 1, Remain: 2, NewlyEx: 1, RightSized: 1, Eligible: 2}); got != want {
		t.Fatalf("A43 second role: %+v want %+v", got, want)
	}

	api := p3NewOwnersAPI(t, l.db)
	tok := api.token(l.ws, l.user, uuid.Nil, "governance:read")
	code, body := api.call(http.MethodGet, "/metrics?from="+url.QueryEscape(l.h0.Format(time.RFC3339))+"&to="+
		url.QueryEscape(l.h0.Add(2*time.Hour).Format(time.RFC3339)), tok, nil)
	if code != http.StatusOK {
		t.Fatalf("GET /metrics: %d %v", code, body)
	}
	sum := body["meta"].(map[string]any)["summary"].(map[string]any)
	head := strings.Join(toStrings(sum["headline"]), " | ")
	if sum["removed"].(float64) != 1 || sum["excluded_routes_remain"].(float64) != 2 || sum["current_routes_remaining_total"].(float64) != 2 ||
		!strings.Contains(head, "1 service removed") ||
		!strings.Contains(head, "2 services excluded from IAM permissions but still reachable through a resource policy; not counted as removed") ||
		!strings.Contains(head, "sqs excluded from M43Role's IAM permissions; still reachable through the queue policy of refunds") {
		t.Fatalf("A43 summary: %v\n%s", sum, head)
	}
	routes := sum["current_routes_remaining"].([]any)
	first := routes[0].(map[string]any)
	if first["service"] != "sqs" || len(first["routes"].([]any)) != 1 ||
		first["routes"].([]any)[0].(map[string]any)["resource"] != "arn:aws:sqs:us-east-1:"+testAccount+":refunds" {
		t.Fatalf("named routes: %v", routes)
	}
}

func routeStateOf(p igagov.Plan, svc string) (string, int) {
	state := igagov.RouteStateNoneObserved
	n := 0
	for _, r := range p.Impact.Routes {
		if r.Service == svc && r.Effect == igagov.RouteEffectBypassKnown {
			state = igagov.RouteStateBypassKnown
			n++
		}
	}
	return state, n
}

// A49: two roles; A's deployment verifies, B's fails (a terminal AWS answer).
// Posture counts only A's services; B contributes no change and no
// posture, its findings stay open, and B stays in the eligible
// denominator (M4).
func TestP3T318MetricsPartialRolloutA49(t *testing.T) {
	l := newMLab(t)
	a := l.role("M49A", "/", nil)
	b := l.role("M49B", "/", nil)
	l.finding(a, "sqs")
	fB := l.finding(b, "sqs")
	tpa := l.compile(l.fake.Discovery(), a, "sqs", "sns")
	l.applyAndVerify(a, l.storeApproved(a, tpa.Apply, *tpa.Undo))
	// B is compiled against the newest scan (A's verification published one).
	tpb := l.compile(l.fake.Discovery(), b, "sqs", "sns")
	sb := l.storeApproved(b, tpb.Apply, *tpb.Undo)
	db := l.queue(b, sb, igagov.PlanApply)
	l.fake.Fail["iam:CreatePolicy"] = enforcetest.APIError("MalformedPolicyDocument", "rejected by the test")
	l.mustRun("deploy", db)
	delete(l.fake.Fail, "iam:CreatePolicy")
	if st := l.state(db); st != "failed" {
		t.Fatalf("B: %s (%s)", st, l.deployment(db).StateReason)
	}
	if p := l.posture(b); len(p) != 0 {
		t.Fatalf("B posture: %v", p)
	}
	r := l.rollup(l.h0)
	if got, want := counts(r), (mCounts{Removed: 2, NewlyEx: 2, RightSized: 1, Eligible: 2}); got != want {
		t.Fatalf("A49: %+v want %+v", got, want)
	}
	if l.findingStatus(fB) != "open" {
		t.Fatalf("B's finding: %s", l.findingStatus(fB))
	}
}

// Retired controls (§8.12 "Rows of controls in state removed are not
// counted") and the remaining columns (approval p50/p95 and pending,
// unexpected failures deduplicated per role) -- seeded directly where the
// writers' timing cannot be steered into a test hour: approvals and
// version_proposed events carry the database's clock, and an unexpected
// denial needs CloudTrail role events. The posture rows are the real
// observer's.
func TestP3T318MetricsRetiredControlsApprovalsFailures(t *testing.T) {
	l := newMLab(t)
	x := l.role("MRetA", "/", nil)
	y := l.role("MRetB", "/", nil)
	tpx := l.compile(l.fake.Discovery(), x, "sqs")
	sx := l.storeApproved(x, tpx.Apply, *tpx.Undo)
	dx := l.applyAndVerify(x, sx)
	tpy := l.compile(l.fake.Discovery(), y, "sqs", "sns")
	dy := l.applyAndVerify(y, l.storeApproved(y, tpy.Apply, *tpy.Undo))
	if c := counts(l.rollup(l.h0)); c.Removed != 3 || c.RightSized != 2 {
		t.Fatalf("before retirement: %+v", c)
	}
	// Retire y's control (as the role-gone path does): its rows stop counting.
	p3exec(t, l.db, `UPDATE iga_gov_control SET state = 'removed' WHERE id = ?`, y.control)
	if c := counts(l.rollup(l.h0)); c.Removed != 1 || c.RightSized != 1 || c.Eligible != 1 {
		t.Fatalf("after retiring y: %+v", c)
	}

	// Approvals decided in hour h1: proposed at +0/+10 min, decided at +20/+50 min.
	h1 := l.h0.Add(time.Hour)
	for _, p := range []struct{ proposed, decided time.Duration }{{0, 20 * time.Minute}, {10 * time.Minute, 50 * time.Minute}} {
		v := l.storeApproved(x, tpx.Apply, *tpx.Undo).version
		p3exec(t, l.db, `INSERT INTO iga_gov_event (workspace_id, occurred_at, event, actor_kind, version_id) VALUES (?, ?, 'version_proposed', 'system', ?)`,
			l.ws, h1.Add(p.proposed), v)
		p3exec(t, l.db, `INSERT INTO iga_gov_approval (workspace_id, version_id, decision, decided_by, channel, intent_hash, impact_hashes,
			plan_hashes, material_hashes, evidence_rev, reason, expires_at, decided_at)
			VALUES (?, ?, 'reject', ?, 'ui', 'x', ARRAY['x'], ARRAY['x'], ARRAY['x'], 1, 'test rejection', ?, ?)`,
			l.ws, v, l.approver, h1.Add(48*time.Hour), h1.Add(p.decided))
	}
	p3exec(t, l.db, `INSERT INTO iga_gov_policy_version (workspace_id, policy_id, version_no, intent, intent_hash, catalog_version,
		evidence_rev, created_by, status) VALUES (?, ?, 90, '{"kind":"right_size_services"}', 'ih-pending', 1, 1, ?, 'in_review')`, l.ws, x.policy, l.user)
	// Unexpected failures: two denials in h1 on x's deployment, the same
	// denial again on y's verification (other role: counted), a duplicate
	// on a second deployment of x (same role: once), one outside the hour.
	fails := func(evs ...time.Time) string {
		var list []map[string]any
		for _, e := range evs {
			list = append(list, map[string]any{"event_time": e, "action": "sqs:SendMessage", "session_name": "w", "error_code": "AccessDenied",
				"class": "denied_removed_service"})
		}
		raw, _ := json.Marshal(map[string]any{"canary": map[string]any{"unexpected_failures": list}})
		return string(raw)
	}
	t1, t2 := h1.Add(15*time.Minute), h1.Add(30*time.Minute)
	p3exec(t, l.db, `UPDATE iga_gov_verification SET evidence = ?::jsonb WHERE deployment_id = ? AND dimension = 'application_health'`,
		fails(t1, t2, h1.Add(-time.Minute)), dx)
	p3exec(t, l.db, `UPDATE iga_gov_verification SET evidence = ?::jsonb WHERE deployment_id = ? AND dimension = 'application_health'`,
		fails(t1), dy)
	dx2 := l.queue(x, sx, igagov.PlanApply)
	p3exec(t, l.db, `INSERT INTO iga_gov_verification (workspace_id, deployment_id, dimension, outcome, evidence)
		VALUES (?, ?, 'application_health', 'failed', ?::jsonb)`, l.ws, dx2, fails(t1))
	p3exec(t, l.db, `UPDATE iga_gov_deployment SET state = 'blocked' WHERE id = ?`, dx2)
	r := l.rollup(h1)
	if r.ApprovalP50Seconds == nil || r.ApprovalP95Seconds == nil || *r.ApprovalP50Seconds != 1800 || *r.ApprovalP95Seconds != 2340 {
		t.Fatalf("approval p50/p95: %v %v (want 1800, 2340)", r.ApprovalP50Seconds, r.ApprovalP95Seconds)
	}
	if r.ApprovalsPending != 1 || r.UnexpectedFailures != 3 {
		t.Fatalf("pending %d unexpected %d (want 1, 3)", r.ApprovalsPending, r.UnexpectedFailures)
	}
	if r.ChangesNewlyExcluded != 0 || r.ApplyToVerifiedP95Seconds != nil {
		t.Fatalf("h1 had no verified deployment: %+v", counts(r))
	}
}

// The job: hour from the dedupe key, aligned; an hour that has not ended is
// handed back; idempotent rerun; registered in the default worker with a
// schedule enqueuing the previous hour once per workspace; the 052 CHECK
// (DB12) holds whatever the session time zone (M9).
func TestP3T318MetricsRollupJobHourAlignmentIdempotence(t *testing.T) {
	l := newMLab(t)
	ctx := context.Background()
	x := l.role("MJobRole", "/", nil)
	tp := l.compile(l.fake.Discovery(), x, "sqs")
	l.applyAndVerify(x, l.storeApproved(x, tp.Apply, *tp.Undo))

	if _, err := services.ParseGovMetricsHour("hour:2026-10-07T10:05:00Z"); err == nil {
		t.Fatal("an unaligned hour must be refused")
	}
	if _, err := l.m.Rollup(ctx, l.ws, l.h0.Add(5*time.Minute)); err == nil {
		t.Fatal("RollupTx must refuse an unaligned hour")
	}
	var n int64
	l.db.Raw(`SELECT count(*) FROM iga_gov_metrics_hourly WHERE workspace_id = ?`, l.ws).Scan(&n)
	if n != 0 {
		t.Fatalf("rows after refusals: %d", n)
	}

	w := services.NewDefaultPolicyJobWorker(l.db)
	found, scheduled := false, false
	for _, k := range w.Kinds() {
		found = found || k == repositories.GovJobMetricsRollup
	}
	for _, n := range w.Scheduler().ScheduleNames() {
		scheduled = scheduled || n == repositories.GovJobMetricsRollup
	}
	if !found || !scheduled {
		t.Fatalf("metrics_rollup registered %v, scheduled %v in the default worker", found, scheduled)
	}
	// The schedule, at h0+1h+2m: the job for h0, once. (Its Due query is
	// run directly and only this workspace's subject enqueued, so no job is
	// left for another workspace in the shared database.)
	at := l.h0.Add(time.Hour + 2*time.Minute)
	sched := services.GovMetricsSchedule()
	due := func(now time.Time) *services.ScheduledPolicyJob {
		items, err := sched.Due(ctx, l.db, now)
		if err != nil {
			t.Fatal(err)
		}
		for i := range items {
			if items[i].WorkspaceID == l.ws {
				return &items[i]
			}
		}
		return nil
	}
	it := due(at)
	if it == nil || !it.Once || it.DedupeKey != services.GovMetricsDedupeKey(l.h0) || it.DedupeKey != "hour:"+l.h0.Format("2006-01-02T15:04:05Z") {
		t.Fatalf("due: %+v", it)
	}
	repo := repositories.NewIGAGovJobRepository(l.db)
	for i := 0; i < 2; i++ {
		if _, err := repo.EnqueueOnceTx(l.db, &models.IGAGovJob{WorkspaceID: l.ws, Kind: sched.Kind, DedupeKey: it.DedupeKey}); err != nil {
			t.Fatal(err)
		}
	}
	if again := due(at.Add(10 * time.Minute)); again != nil {
		t.Fatalf("the hour is due again after its job exists: %+v", again)
	}
	var jobs []models.IGAGovJob
	l.db.Where("workspace_id = ? AND kind = ?", l.ws, repositories.GovJobMetricsRollup).Find(&jobs)
	if len(jobs) != 1 {
		t.Fatalf("jobs: %+v", jobs)
	}
	run := func(now time.Time) error {
		t.Helper()
		// Claimed by hand (the worker's claim UPDATE, for this job only).
		p3exec(t, l.db, `UPDATE iga_gov_job SET status = 'running', lease_owner = 'metrics-t', lease_version = lease_version + 1,
			lease_expires_at = ?, attempts = attempts + 1 WHERE id = ?`, now.Add(2*time.Minute), jobs[0].ID)
		var j models.IGAGovJob
		l.db.Where("id = ?", jobs[0].ID).Take(&j)
		m := services.NewGovMetrics(l.db, nil).WithClock(func() time.Time { return now })
		err := m.RollupHandler(ctx, services.NewPolicyJobRun(l.db, j, "metrics-t"))
		p3exec(t, l.db, `UPDATE iga_gov_job SET status = 'complete', completed_at = now(), lease_owner = '', lease_expires_at = NULL WHERE id = ?`, j.ID)
		return err
	}
	// Before the hour ended: handed back, nothing written.
	if err := run(l.h0.Add(30 * time.Minute)); !isRetryLater(err) {
		t.Fatalf("an hour that has not ended: %v", err)
	}
	l.db.Raw(`SELECT count(*) FROM iga_gov_metrics_hourly WHERE workspace_id = ?`, l.ws).Scan(&n)
	if n != 0 {
		t.Fatalf("rows before the hour ended: %d", n)
	}
	if err := run(at); err != nil {
		t.Fatal(err)
	}
	var first models.IGAGovMetricsHourly
	l.db.Where("workspace_id = ? AND hour = ?", l.ws, l.h0).Take(&first)
	if first.PostureRemoved != 1 || first.ChangesNewlyExcluded != 1 || !first.ComputedAt.Equal(at) {
		t.Fatalf("job row: %+v", first)
	}
	// Idempotent rerun (a retried job): same numbers, one row, newer computed_at.
	if err := run(at.Add(5 * time.Minute)); err != nil {
		t.Fatal(err)
	}
	var again []models.IGAGovMetricsHourly
	l.db.Where("workspace_id = ?", l.ws).Find(&again)
	if len(again) != 1 || counts(again[0]) != counts(first) || !again[0].ComputedAt.Equal(at.Add(5*time.Minute)) {
		t.Fatalf("rerun: %+v", again)
	}
	// A malformed key is abandoned, not retried.
	bad := models.IGAGovJob{WorkspaceID: l.ws, Kind: repositories.GovJobMetricsRollup, DedupeKey: "hour:2026-10-07T10:05:00Z"}
	if err := services.NewGovMetrics(l.db, nil).RollupHandler(ctx, services.NewPolicyJobRun(l.db, bad, "metrics-t")); err == nil ||
		!strings.HasPrefix(err.Error(), "abandon:") {
		t.Fatalf("malformed key: %v", err)
	}
	// M9: a +05:30 session zone does not break the hour CHECK.
	err := l.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec(`SET LOCAL TIME ZONE 'Asia/Kolkata'`).Error; err != nil {
			return err
		}
		_, err := l.m.RollupTx(tx, l.ws, l.h0.Add(-time.Hour))
		return err
	})
	if err != nil {
		t.Fatalf("rollup in a +05:30 session: %v", err)
	}
}

// Isolation: another workspace's rollup never counts this workspace's rows
// and its reader never sees them; a cursor issued to one workspace is
// refused for the other; paging; parameters; permission.
func TestP3T318MetricsIsolationPagingAndAPI(t *testing.T) {
	l := newMLab(t)
	ctx := context.Background()
	x := l.role("MIsoRole", "/", nil)
	l.finding(x, "sqs")
	tp := l.compile(l.fake.Discovery(), x, "sqs")
	l.applyAndVerify(x, l.storeApproved(x, tp.Apply, *tp.Undo))
	other := p3NewGov(t, l.db, "p3metrics-other")
	for i := 0; i < 3; i++ {
		h := l.h0.Add(time.Duration(i) * time.Hour)
		l.rollup(h)
		if _, err := l.m.Rollup(ctx, other.ws, h); err != nil {
			t.Fatal(err)
		}
	}
	var o models.IGAGovMetricsHourly
	l.db.Where("workspace_id = ? AND hour = ?", other.ws, l.h0).Take(&o)
	if c := counts(o); c != (mCounts{}) {
		t.Fatalf("the other workspace counted this one's rows: %+v", c)
	}

	api := p3NewOwnersAPI(t, l.db)
	tok := api.token(l.ws, l.user, uuid.Nil, "governance:read")
	otherTok := api.token(other.ws, other.author, other.authorMember, "governance:read")
	rng := "from=" + url.QueryEscape(l.h0.Format(time.RFC3339)) + "&to=" + url.QueryEscape(l.h0.Add(3*time.Hour).Format(time.RFC3339))
	code, body := api.call(http.MethodGet, "/metrics?"+rng+"&limit=2", tok, nil)
	if code != http.StatusOK || len(body["data"].([]any)) != 2 {
		t.Fatalf("page 1: %d %v", code, body)
	}
	cur, _ := body["meta"].(map[string]any)["next_cursor"].(string)
	if cur == "" {
		t.Fatal("no next cursor")
	}
	code, body = api.call(http.MethodGet, "/metrics?"+rng+"&limit=2&cursor="+url.QueryEscape(cur), tok, nil)
	if code != http.StatusOK || len(body["data"].([]any)) != 1 || body["meta"].(map[string]any)["next_cursor"] != nil {
		t.Fatalf("page 2: %d %v", code, body)
	}
	if h := body["data"].([]any)[0].(map[string]any)["hour"]; h != l.h0.Add(2*time.Hour).Format(time.RFC3339) {
		t.Fatalf("page 2 hour: %v", h)
	}
	// The other workspace: its own (zero) rows only; this workspace's cursor refused.
	code, body = api.call(http.MethodGet, "/metrics?"+rng, otherTok, nil)
	if code != http.StatusOK || len(body["data"].([]any)) != 3 {
		t.Fatalf("other reader: %d %v", code, body)
	}
	for _, r := range body["data"].([]any) {
		if r.(map[string]any)["posture_removed"].(float64) != 0 {
			t.Fatalf("other workspace sees removed: %v", r)
		}
	}
	if code, body = api.call(http.MethodGet, "/metrics?"+rng+"&limit=2&cursor="+url.QueryEscape(cur), otherTok, nil); code != http.StatusBadRequest ||
		p3ErrCode(body) != "cursor_invalid" {
		t.Fatalf("cross-workspace cursor: %d %v", code, body)
	}
	// A cursor is bound to its range.
	if code, body = api.call(http.MethodGet, "/metrics?from="+url.QueryEscape(l.h0.Add(time.Hour).Format(time.RFC3339))+"&cursor="+url.QueryEscape(cur), tok, nil); code != http.StatusBadRequest {
		t.Fatalf("cursor on another range: %d %v", code, body)
	}
	for _, q := range []string{"?from=yesterday", "?to=x", "?from=" + url.QueryEscape(l.h0.Format(time.RFC3339)) + "&to=" + url.QueryEscape(l.h0.Format(time.RFC3339)), "?limit=201"} {
		if code, body := api.call(http.MethodGet, "/metrics"+q, tok, nil); code != http.StatusBadRequest || p3ErrCode(body) != "invalid_parameter" {
			t.Fatalf("GET /metrics%s: %d %v", q, code, body)
		}
	}
	// Default range: the last 24 hours (from now); the rows are in the future
	// of the real clock, so none.
	if code, body := api.call(http.MethodGet, "/metrics", tok, nil); code != http.StatusOK || len(body["data"].([]any)) != 0 {
		t.Fatalf("default range: %d %v", code, body)
	}
	// Permission: governance:read.
	if code, _ := api.call(http.MethodGet, "/metrics", api.token(l.ws, l.user, uuid.Nil, "iga:read"), nil); code != http.StatusForbidden {
		t.Fatalf("without governance:read: %d", code)
	}
}
