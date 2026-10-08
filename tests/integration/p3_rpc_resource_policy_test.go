package integration

// T3.03b (SPEC-iga-phase3-policy.md §3.9; scenarios A34, A38, A39, A44, A46
// of §14.2) against REAL PostgreSQL: resource-policy collection through the
// permission scanner and the scan worker, 056's immutable observations,
// content-addressed documents and per-(form, region) coverage, and what the
// compiler and the bundle builder read back (services.LoadResourcePolicyEvidence
// into igagov.AnalyzeRoutes). Every AWS call is answered by
// internal/awsdiscovery/rpfake; nothing reaches AWS.

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/internal/awsdiscovery/rpfake"
	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
)

const (
	rpRoleARN = "arn:aws:iam::" + testAccount + ":role/app"
	rpRoleID  = "AROAAPPROLEEXAMPLE01"
)

var rpRole = igagov.RoleRef{RoleID: rpRoleID, ARN: rpRoleARN, Name: "app", AccountID: testAccount}

func rpGrant(action string) string {
	return `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"` + rpRoleARN +
		`"},"Action":"` + action + `","Resource":"*"}]}`
}

// rpRegion is one region holding one resource of every regional form.
func rpRegion(name string) *rpfake.Region {
	fn := "arn:aws:lambda:" + name + ":" + testAccount + ":function:refund"
	return &rpfake.Region{
		Name: name, AccountID: testAccount, PageSize: 2,
		DirBuckets:   []rpfake.Named{{Name: "fast--az1--x-s3"}},
		AccessPoints: []rpfake.Named{{Name: "exports-ap"}},
		OLAPs:        []rpfake.Named{{Name: "redact"}},
		Keys:         []rpfake.ARNPolicy{{ARN: "arn:aws:kms:" + name + ":" + testAccount + ":key/k1", Policy: rpGrant("kms:Decrypt")}},
		Queues: []rpfake.Queue{
			{URL: "https://sqs." + name + ".amazonaws.com/" + testAccount + "/refunds", Policy: rpGrant("sqs:SendMessage")},
			{URL: "https://sqs." + name + ".amazonaws.com/" + testAccount + "/audit", Policy: rpGrant("sqs:SendMessage")},
			{URL: "https://sqs." + name + ".amazonaws.com/" + testAccount + "/plain"},
		},
		Topics:    []rpfake.ARNPolicy{{ARN: "arn:aws:sns:" + name + ":" + testAccount + ":alerts"}},
		Functions: []rpfake.Function{{Name: "refund", ARN: fn, Versions: []rpfake.Version{{Version: "1"}}, Aliases: []rpfake.Named{{Name: "live"}}}},
		Layers:    []rpfake.Layer{{ARN: "arn:aws:lambda:" + name + ":" + testAccount + ":layer:shared", Versions: []rpfake.LayerVersion{{Version: 1}}}},
		Secrets:   []rpfake.ARNPolicy{{ARN: "arn:aws:secretsmanager:" + name + ":" + testAccount + ":secret:db-AbCdEf"}},
	}
}

type rpWorld struct {
	regions map[string]*rpfake.Region
	enabled *s2FakeRegions
}

func newRPWorld() *rpWorld {
	east := rpRegion("us-east-1")
	east.Buckets = []rpfake.Bucket{{Name: "exports", Region: "us-east-1"}, {Name: "eu-logs", Region: "eu-west-1"}}
	east.BucketPolicies = map[string]string{"exports": rpGrant("s3:GetObject")}
	west := rpRegion("eu-west-1")
	west.BucketPolicies = map[string]string{} // eu-logs: no policy
	return &rpWorld{
		regions: map[string]*rpfake.Region{
			"us-east-1": east, "eu-west-1": west,
			"us-west-2": {Name: "us-west-2", AccountID: testAccount}, // multi-region access points: none
		},
		enabled: s2Regions("us-east-1", "eu-west-1", "ap-south-1"),
	}
}

func (w *rpWorld) clients() awsdiscovery.ResourcePolicyClientsFunc {
	return func(_ context.Context, region string) (awsdiscovery.ResourcePolicyClients, error) {
		r, ok := w.regions[region]
		if !ok {
			return awsdiscovery.ResourcePolicyClients{}, errors.New("no fake for " + region)
		}
		return awsdiscovery.ResourcePolicyClients{S3: r, S3Control: r, KMS: r, SQS: r, SNS: r, Lambda: r, Secrets: r}, nil
	}
}

func (w *rpWorld) wire(perm *services.AWSPermissionScanner) *services.AWSPermissionScanner {
	return perm.WithResourcePolicyClients(w.clients()).WithRegionsAPI(w.enabled).
		WithCollectorOptions(awsdiscovery.CollectorOptions{MinCallInterval: -1, Backoff: time.Nanosecond,
			Sleep: func(context.Context, time.Duration) error { return nil }})
}

type rpEnv struct {
	db   *gorm.DB
	ws   uuid.UUID
	conn uuid.UUID
	svc  *services.AWSOnboardingService
	gen  int
}

// newRPEnv onboards a connector on us-east-1 and eu-west-1 (stamped with the
// current template).
func newRPEnv(t *testing.T, name string) *rpEnv {
	t.Helper()
	db := igaDB(t)
	ws := newWorkspace(t, db, name)
	svc, _ := newOnboarding(db, okVerifier())
	c, _, err := svc.Onboard(context.Background(), ws, validInput(mustMint(t, ws)), "admin")
	if err != nil {
		t.Fatalf("onboard: %v", err)
	}
	if got := c.AWSAttrs().TemplateVersion; got != awsdiscovery.TemplateVersion {
		t.Fatalf("connector template = %q", got)
	}
	return &rpEnv{db: db, ws: ws, conn: c.ID, svc: svc}
}

// run records one published scan run to hang evidence on.
func (e *rpEnv) run(t *testing.T) uuid.UUID {
	t.Helper()
	e.gen++
	id := uuid.New()
	if err := e.db.Exec(`INSERT INTO cloud_scan_run (id, workspace_id, connector_id, generation, status, published_at)
		VALUES (?, ?, ?, ?, 'published', now())`, id, e.ws, e.conn, e.gen).Error; err != nil {
		t.Fatalf("scan run: %v", err)
	}
	return id
}

func (e *rpEnv) collect(t *testing.T, w *rpWorld, run uuid.UUID) *services.ResourcePolicyCollection {
	t.Helper()
	out, err := w.wire(services.NewAWSPermissionScanner(e.db, e.svc)).
		CollectResourcePolicies(context.Background(), e.ws, e.conn, run)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(out.WriteErrors) > 0 {
		t.Fatalf("write errors: %v", out.WriteErrors)
	}
	return out
}

func (e *rpEnv) coverage(t *testing.T, run uuid.UUID) map[string]models.CloudResourcePolicyCoverage {
	t.Helper()
	rows, err := repositories.NewCloudResourcePolicyRepository(e.db).CoverageForScan(e.ws, run)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]models.CloudResourcePolicyCoverage{}
	for _, r := range rows {
		out[r.ResourceForm+"/"+r.Region] = r
	}
	return out
}

func (e *rpEnv) observations(t *testing.T, run uuid.UUID) map[string]models.CloudResourcePolicyObservation {
	t.Helper()
	rows, err := repositories.NewCloudResourcePolicyRepository(e.db).ObservationsForScan(e.ws, run)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]models.CloudResourcePolicyObservation{}
	for _, r := range rows {
		out[r.ResourceARN] = r
	}
	return out
}

// snapshot is one scan's rows as JSON, for byte-equality across rescans.
func (e *rpEnv) snapshot(t *testing.T, run uuid.UUID) string {
	t.Helper()
	var s string
	if err := e.db.Raw(`SELECT json_build_object(
		  'coverage', (SELECT json_agg(c ORDER BY c.resource_form, c.region) FROM cloud_resource_policy_coverage c WHERE c.workspace_id = ? AND c.scan_run_id = ?),
		  'observations', (SELECT json_agg(o ORDER BY o.resource_arn) FROM cloud_resource_policy_observation o WHERE o.workspace_id = ? AND o.scan_run_id = ?),
		  'documents', (SELECT json_agg(d ORDER BY d.document_hash) FROM cloud_policy_document d
		                 WHERE d.workspace_id = ? AND d.document_hash IN (SELECT document_hash FROM cloud_resource_policy_observation
		                                                                    WHERE workspace_id = ? AND scan_run_id = ?)))::text`,
		e.ws, run, e.ws, run, e.ws, e.ws, run).Scan(&s).Error; err != nil {
		t.Fatal(err)
	}
	return s
}

var rpEnabled = []string{"eu-west-1", "us-east-1"}

func queueARN(region, name string) string {
	return "arn:aws:sqs:" + region + ":" + testAccount + ":" + name
}

// The scan's evidence: every form in every selected region plus the account
// rows and the enabled-but-unselected region; one observation per read
// resource including "no policy"; each document stored once under the hash
// igagov computes and the trigger recomputes; both unparseable shapes
// recorded as such; an unstorable policy counted as a failed read.
func TestP3RPCCollectionWritesImmutableEvidence(t *testing.T) {
	e := newRPEnv(t, "p3-rpc-evidence")
	w := newRPWorld()
	west := w.regions["eu-west-1"]
	west.Topics = append(west.Topics,
		rpfake.ARNPolicy{ARN: "arn:aws:sns:eu-west-1:" + testAccount + ":not-a-policy", Policy: `{"foo": 1}`},
		rpfake.ARNPolicy{ARN: "arn:aws:sns:eu-west-1:" + testAccount + ":dup-keys", Policy: `{"Version":"2012-10-17","Version":"2008-10-17","Statement":[]}`})
	east := w.regions["us-east-1"]
	east.Topics = append(east.Topics, rpfake.ARNPolicy{ARN: "arn:aws:sns:us-east-1:" + testAccount + ":nul", Policy: "{\"a\":\"\x00\"}"})

	run := e.run(t)
	out := e.collect(t, w, run)
	if !out.TemplateCurrent || !out.EnabledRegionsKnown {
		t.Fatalf("collection = %+v", out)
	}
	cov := e.coverage(t, run)
	if len(cov) != 2+11*3 {
		t.Fatalf("coverage rows = %d, want 2 account rows + 11 forms x (2 selected + 1 unselected)", len(cov))
	}
	for k, c := range cov {
		switch {
		case strings.HasSuffix(k, "/ap-south-1"):
			if c.State != models.ResourcePolicyNotCollected || c.Reason != awsdiscovery.ReasonRegionNotSelected {
				t.Errorf("%s = %+v", k, c)
			}
		case k == "sns_topic/us-east-1":
			if c.State != models.ResourcePolicyPartial || c.ReadFailed != 1 || !strings.Contains(c.Reason, "could not be stored") {
				t.Errorf("%s = %+v, want partial: the NUL policy cannot be stored", k, c)
			}
		default:
			if c.State != models.ResourcePolicyComplete || c.ReadOK != c.Enumerated || c.ReadFailed != 0 {
				t.Errorf("%s = %+v, want complete", k, c)
			}
		}
	}
	obs := e.observations(t, run)
	var okReads int
	for _, c := range cov {
		okReads += c.ReadOK
	}
	if len(obs) != okReads {
		t.Fatalf("observations = %d, want one per successful read (%d)", len(obs), okReads)
	}

	// "No policy" is an observation, with no document.
	if o := obs[queueARN("eu-west-1", "plain")]; o.PolicyPresent || o.DocumentHash != nil || o.ParseState != "parsed" {
		t.Errorf("plain queue = %+v", o)
	}
	// The same policy text on two queues and in two regions is ONE document,
	// under the hash igagov computes (and the insert trigger re-derived).
	refunds, audit := obs[queueARN("eu-west-1", "refunds")], obs[queueARN("us-east-1", "audit")]
	wantHash, err := igagov.DocumentHash(rpGrant("sqs:SendMessage"))
	if err != nil || refunds.DocumentHash == nil || *refunds.DocumentHash != wantHash || audit.DocumentHash == nil || *audit.DocumentHash != wantHash {
		t.Fatalf("queue documents %v / %v, want %s", refunds.DocumentHash, audit.DocumentHash, wantHash)
	}
	var n int64
	e.db.Model(&models.CloudPolicyDocument{}).Where("workspace_id = ? AND document_hash = ?", e.ws, wantHash).Count(&n)
	if n != 1 {
		t.Fatalf("documents with that hash = %d, want 1", n)
	}
	// Valid JSON that is not a policy: stored canonically, unparseable.
	if o := obs["arn:aws:sns:eu-west-1:"+testAccount+":not-a-policy"]; !o.PolicyPresent || o.ParseState != "unparseable" || o.DocumentHash == nil {
		t.Errorf("not-a-policy = %+v", o)
	}
	// Not I-JSON (a duplicate member): stored as the exact text in a JSON
	// string, unparseable -- never dropped, never "no policy".
	dup := obs["arn:aws:sns:eu-west-1:"+testAccount+":dup-keys"]
	if !dup.PolicyPresent || dup.ParseState != "unparseable" || dup.DocumentHash == nil {
		t.Fatalf("dup-keys = %+v", dup)
	}
	docs, _ := repositories.NewCloudResourcePolicyRepository(e.db).Documents(e.ws, []string{*dup.DocumentHash})
	var text string
	if err := json.Unmarshal([]byte(docs[*dup.DocumentHash].Canonical), &text); err != nil || !strings.Contains(text, `"Version":"2008-10-17"`) {
		t.Fatalf("dup-keys document = %q (%v)", docs[*dup.DocumentHash].Canonical, err)
	}

	// What the compiler reads: one scan's evidence, decoded.
	ev, err := services.LoadResourcePolicyEvidence(e.db, e.ws, run)
	if err != nil || ev == nil {
		t.Fatalf("load: %v", err)
	}
	sqsRoutes := igagov.AnalyzeRoutes("sqs", rpRole, ev, rpEnabled)
	if sqsRoutes.Usage != igagov.RouteUsageConfirmRequired || len(sqsRoutes.Routes) != 4 { // refunds + audit in two regions
		t.Fatalf("sqs routes = %+v", sqsRoutes)
	}
	for _, r := range sqsRoutes.Routes {
		if r.Effect != igagov.RouteEffectLimited || r.Form != "sqs_queue" || r.Principal != igagov.PrincipalRoleARN {
			t.Errorf("sqs route %+v", r)
		}
	}
	snsRoutes := igagov.AnalyzeRoutes("sns", rpRole, ev, rpEnabled)
	if snsRoutes.State != igagov.RouteStateNotAnalysed {
		t.Fatalf("sns routes = %+v, want not_analysed (partial coverage, unparseable policies)", snsRoutes)
	}
}

// A44: a stored document, observation or coverage row cannot change; a
// document with a wrong hash is refused (and its whole unit with it); the
// evidence reads the same afterwards.
func TestP3RPCA44EvidenceDocumentsCannotChange(t *testing.T) {
	e := newRPEnv(t, "p3-rpc-a44")
	run := e.run(t)
	e.collect(t, newRPWorld(), run)
	before, err := services.LoadResourcePolicyEvidence(e.db, e.ws, run)
	if err != nil {
		t.Fatal(err)
	}
	snap := e.snapshot(t, run)
	hash, _ := igagov.DocumentHash(rpGrant("sqs:SendMessage"))

	for _, q := range []string{
		`UPDATE cloud_policy_document SET canonical = '{"Version":"2012-10-17","Statement":[]}', document = '{"Version":"2012-10-17","Statement":[]}' WHERE workspace_id = ? AND document_hash = '` + hash + `'`,
		`UPDATE cloud_policy_document SET first_seen_at = now() WHERE workspace_id = ?`,
		`UPDATE cloud_resource_policy_observation SET policy_present = false, document_hash = NULL WHERE workspace_id = ?`,
		`UPDATE cloud_resource_policy_coverage SET state = 'complete', reason = '' WHERE workspace_id = ?`,
	} {
		if err := e.db.Exec(q, e.ws).Error; err == nil || !strings.Contains(err.Error(), "immutable") {
			t.Errorf("%s: err = %v, want the immutability trigger", q, err)
		}
	}

	// The writer's own path refuses a wrong hash (and a jsonb that differs
	// from the canonical text), and lands nothing of that unit.
	repo := repositories.NewCloudResourcePolicyRepository(e.db)
	run2 := e.run(t)
	canonical := []byte(`{"Statement":[],"Version":"2012-10-17"}`)
	for name, doc := range map[string]models.CloudPolicyDocument{
		"wrong hash":    {WorkspaceID: e.ws, DocumentHash: hash, Canonical: string(canonical), Document: canonical},
		"jsonb differs": {WorkspaceID: e.ws, DocumentHash: igagov.ContentHash(canonical), Canonical: string(canonical), Document: []byte(`{"Version":"2012-10-17"}`)},
	} {
		h := doc.DocumentHash
		_, err := repo.RecordForm(&models.CloudResourcePolicyCoverage{WorkspaceID: e.ws, ConnectorID: e.conn, ScanRunID: run2,
			ResourceForm: "sqs_queue", Region: "eu-west-1", State: "complete", Enumerated: 1, ReadOK: 1},
			[]models.CloudPolicyDocument{doc},
			[]models.CloudResourcePolicyObservation{{WorkspaceID: e.ws, ScanRunID: run2, ResourceForm: "sqs_queue", Region: "eu-west-1",
				ResourceARN: queueARN("eu-west-1", "refunds"), PolicyPresent: true, DocumentHash: &h, ParseState: "parsed", ReadAt: time.Now()}})
		if err == nil || !strings.Contains(err.Error(), "cloud_policy_document") {
			t.Errorf("%s: err = %v, want the insert trigger's refusal", name, err)
		}
	}
	if c := e.coverage(t, run2); len(c) != 0 {
		t.Fatalf("a refused unit left %d coverage rows", len(c))
	}

	after, err := services.LoadResourcePolicyEvidence(e.db, e.ws, run)
	if err != nil || !reflect.DeepEqual(before, after) || e.snapshot(t, run) != snap {
		t.Fatal("the evidence changed after refused writes")
	}
}

// A38: a plan reads scan N's observations only; rescans add their own rows
// (one sees a queue policy deleted) and scan N's evidence is unchanged.
func TestP3RPCA38EvidenceSurvivesRescans(t *testing.T) {
	e := newRPEnv(t, "p3-rpc-a38")
	w := newRPWorld()
	runN := e.run(t)
	e.collect(t, w, runN)
	snapN := e.snapshot(t, runN)
	evN, _ := services.LoadResourcePolicyEvidence(e.db, e.ws, runN)

	// Rescan 1: the refunds queue's policy is deleted.
	w.regions["eu-west-1"].Queues[0].Policy = ""
	run1 := e.run(t)
	e.collect(t, w, run1)
	// Rescan 2: unchanged.
	run2 := e.run(t)
	e.collect(t, w, run2)

	if e.snapshot(t, runN) != snapN {
		t.Fatal("scan N's evidence changed after two rescans")
	}
	if o := e.observations(t, runN)[queueARN("eu-west-1", "refunds")]; !o.PolicyPresent {
		t.Fatal("scan N lost its observation of the refunds policy")
	}
	if o := e.observations(t, run1)[queueARN("eu-west-1", "refunds")]; o.PolicyPresent || o.DocumentHash != nil {
		t.Fatalf("rescan 1 refunds = %+v, want no policy", o)
	}
	// The compiler, reading scan N, still sees the route; reading the rescan
	// it does not. The two plans would differ (a new plan_hash, re-approval).
	again, _ := services.LoadResourcePolicyEvidence(e.db, e.ws, runN)
	if !reflect.DeepEqual(evN, again) {
		t.Fatal("scan N reads differently after rescans")
	}
	routesN := igagov.AnalyzeRoutes("sqs", rpRole, again, rpEnabled)
	ev1, _ := services.LoadResourcePolicyEvidence(e.db, e.ws, run1)
	routes1 := igagov.AnalyzeRoutes("sqs", rpRole, ev1, rpEnabled)
	if len(routesN.Routes) != len(routes1.Routes)+1 {
		t.Fatalf("routes N %d, rescan %d: the rescan must lose exactly the deleted policy's route", len(routesN.Routes), len(routes1.Routes))
	}
	// Documents are shared, not copied: three scans, one document per text.
	var docs int64
	e.db.Model(&models.CloudPolicyDocument{}).Where("workspace_id = ?", e.ws).Count(&docs)
	if docs != 3 { // s3:GetObject, kms:Decrypt, sqs:SendMessage -- however many scans and resources carry them
		t.Fatalf("documents in the workspace: %d, want 3", docs)
	}
}

// A39: a function with no policy whose alias has one, and an S3 access point
// policy, are observations of their own forms, each covered, and the routes
// name the alias and the access point.
func TestP3RPCA39LambdaAliasAndAccessPointForms(t *testing.T) {
	e := newRPEnv(t, "p3-rpc-a39")
	w := newRPWorld()
	west := w.regions["eu-west-1"]
	west.Functions[0].Policy = ""
	west.Functions[0].Aliases[0].Policy = rpGrant("lambda:InvokeFunction")
	west.AccessPoints[0].Policy = rpGrant("s3:GetObject")
	run := e.run(t)
	e.collect(t, w, run)

	obs := e.observations(t, run)
	fnARN := "arn:aws:lambda:eu-west-1:" + testAccount + ":function:refund"
	apARN := "arn:aws:s3:eu-west-1:" + testAccount + ":accesspoint/exports-ap"
	if o := obs[fnARN]; o.ResourceForm != "lambda_function" || o.PolicyPresent {
		t.Errorf("function = %+v", o)
	}
	if o := obs[fnARN+":live"]; o.ResourceForm != "lambda_alias" || !o.PolicyPresent {
		t.Errorf("alias = %+v", o)
	}
	if o := obs[apARN]; o.ResourceForm != "s3_access_point" || !o.PolicyPresent {
		t.Errorf("access point = %+v", o)
	}
	cov := e.coverage(t, run)
	for _, k := range []string{"lambda_function/eu-west-1", "lambda_alias/eu-west-1", "lambda_function_version/eu-west-1", "s3_access_point/eu-west-1", "s3_bucket/us-east-1"} {
		if cov[k].State != "complete" {
			t.Errorf("%s = %+v", k, cov[k])
		}
	}

	ev, _ := services.LoadResourcePolicyEvidence(e.db, e.ws, run)
	lam := igagov.AnalyzeRoutes("lambda", rpRole, ev, rpEnabled)
	s3r := igagov.AnalyzeRoutes("s3", rpRole, ev, rpEnabled)
	has := func(ra igagov.RouteAnalysis, form, resource string) bool {
		for _, r := range ra.Routes {
			if r.Form == form && r.Resource == resource && r.Principal == igagov.PrincipalRoleARN {
				return true
			}
		}
		return false
	}
	if !has(lam, "lambda_alias", fnARN+":live") || has(lam, "lambda_function", fnARN) {
		t.Errorf("lambda routes = %+v", lam.Routes)
	}
	if !has(s3r, "s3_access_point", apARN) || !has(s3r, "s3_bucket", "arn:aws:s3:::exports") {
		t.Errorf("s3 routes = %+v", s3r.Routes)
	}
}

// A46: SQS queue policies become unreadable in one region; the rescan's
// coverage says denied there, the route analysis reports not_analysed for
// that form and region only, and restoring access restores it.
func TestP3RPCA46CoverageLostInOneRegion(t *testing.T) {
	e := newRPEnv(t, "p3-rpc-a46")
	w := newRPWorld()
	// No queue grants the role: a clean removal is possible.
	for _, r := range []string{"us-east-1", "eu-west-1"} {
		for i := range w.regions[r].Queues {
			w.regions[r].Queues[i].Policy = ""
		}
	}
	routesOf := func(run uuid.UUID) igagov.RouteAnalysis {
		ev, err := services.LoadResourcePolicyEvidence(e.db, e.ws, run)
		if err != nil {
			t.Fatal(err)
		}
		return igagov.AnalyzeRoutes("sqs", rpRole, ev, rpEnabled)
	}
	r1 := e.run(t)
	e.collect(t, w, r1)
	if ra := routesOf(r1); ra.State != igagov.RouteStateNoneObserved || ra.Usage != igagov.RouteUsageNoneObserved {
		t.Fatalf("before = %+v", ra)
	}

	w.regions["eu-west-1"].Errs = map[string]error{"GetQueueAttributes": rpfake.APIError("AccessDenied")}
	r2 := e.run(t)
	e.collect(t, w, r2)
	cov := e.coverage(t, r2)
	if c := cov["sqs_queue/eu-west-1"]; c.State != "denied" || c.ReadFailed != 3 || c.Reason == "" {
		t.Fatalf("eu-west-1 = %+v", c)
	}
	if c := cov["sqs_queue/us-east-1"]; c.State != "complete" {
		t.Fatalf("us-east-1 = %+v", c)
	}
	ra := routesOf(r2)
	if ra.State != igagov.RouteStateNotAnalysed || len(ra.Routes) != 1 || ra.Routes[0].Region != "eu-west-1" ||
		ra.Routes[0].Form != "sqs_queue" || ra.Routes[0].Reason != "denied" {
		t.Fatalf("after loss = %+v", ra)
	}

	w.regions["eu-west-1"].Errs = nil
	r3 := e.run(t)
	e.collect(t, w, r3)
	if ra := routesOf(r3); ra.State != igagov.RouteStateNoneObserved {
		t.Fatalf("after restore = %+v", ra)
	}
}

// A34 (the collection half): a connector on the older template records every
// collected form not_collected without a single AWS call; on the current
// template an unreadable access point policy makes s3_access_point partial;
// a queue policy with Deny + NotPrincipal is stored and decoded for the
// compiler; and uncollected forms (ECR) stay unanalysed whatever is collected.
func TestP3RPCA34OlderTemplateAndIncompleteForms(t *testing.T) {
	e := newRPEnv(t, "p3-rpc-a34")
	w := newRPWorld()
	if err := e.db.Exec(`UPDATE cloud_connector SET attrs = jsonb_set(attrs, '{template_version}', '"2026-09-24"') WHERE id = ?`, e.conn).Error; err != nil {
		t.Fatal(err)
	}
	r1 := e.run(t)
	out := e.collect(t, w, r1)
	if out.TemplateCurrent {
		t.Fatal("a 2026-09-24 stack was treated as granting collection")
	}
	cov := e.coverage(t, r1)
	if len(cov) != 2+11*2 {
		t.Fatalf("rows = %d", len(cov))
	}
	for k, c := range cov {
		if c.State != "not_collected" || !strings.Contains(c.Reason, services.ReasonTemplateUpdateNeeded) {
			t.Fatalf("%s = %+v", k, c)
		}
	}
	for name, r := range w.regions {
		if len(r.Calls) != 0 {
			t.Fatalf("region %s was called on the older template: %v", name, r.Calls)
		}
	}
	ev, _ := services.LoadResourcePolicyEvidence(e.db, e.ws, r1)
	if s := igagov.AnalyzeRoutes("s3", rpRole, ev, rpEnabled); s.State != igagov.RouteStateNotAnalysed {
		t.Fatalf("older template s3 = %+v", s)
	}

	// The stack is updated (the template stamp moves): one access point
	// policy is unreadable, and a queue carries Deny + NotPrincipal.
	if err := e.db.Exec(`UPDATE cloud_connector SET attrs = jsonb_set(attrs, '{template_version}', to_jsonb(?::text)) WHERE id = ?`,
		awsdiscovery.TemplateVersion, e.conn).Error; err != nil {
		t.Fatal(err)
	}
	west := w.regions["eu-west-1"]
	west.Errs = map[string]error{"GetAccessPointPolicy:exports-ap": rpfake.APIError("AccessDenied")}
	west.AccessPoints = append(west.AccessPoints, rpfake.Named{Name: "second-ap"})
	west.Queues[0].Policy = `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","NotPrincipal":{"AWS":"arn:aws:iam::` + testAccount +
		`:root"},"Action":"sqs:*","Resource":"*"}]}`
	r2 := e.run(t)
	e.collect(t, w, r2)
	cov = e.coverage(t, r2)
	if c := cov["s3_access_point/eu-west-1"]; c.State != "partial" || c.ReadFailed != 1 || c.ReadOK != 1 {
		t.Fatalf("access points = %+v", c)
	}
	ev, _ = services.LoadResourcePolicyEvidence(e.db, e.ws, r2)
	var denyDoc *igagov.PolicyDocument
	for _, o := range ev.Observations {
		if o.ResourceARN == queueARN("eu-west-1", "refunds") {
			denyDoc = o.Document
		}
	}
	if denyDoc == nil || len(denyDoc.Statements) != 1 || denyDoc.Statements[0].NotPrincipal == nil {
		t.Fatalf("the Deny + NotPrincipal policy did not reach the compiler decoded: %+v", denyDoc)
	}
	s3r := igagov.AnalyzeRoutes("s3", rpRole, ev, rpEnabled)
	found := false
	for _, r := range s3r.Routes {
		found = found || (r.Form == "s3_access_point" && r.Region == "eu-west-1" && r.Effect == igagov.RouteEffectNotAnalysed && r.Reason == "partial")
	}
	if !found {
		t.Fatalf("s3 routes = %+v, want s3_access_point/eu-west-1 not_analysed (partial)", s3r.Routes)
	}
	if ecr := igagov.AnalyzeRoutes("ecr", rpRole, ev, rpEnabled); ecr.State != igagov.RouteStateNotAnalysed {
		t.Fatalf("ecr = %+v, want not_analysed: an uncollected form is never empty", ecr)
	}
}

// RecordForm under a lost fence writes nothing; a second attempt of the same
// run keeps the first attempt's unit whole.
func TestP3RPCRecordFormFencedAndIdempotent(t *testing.T) {
	e := newRPEnv(t, "p3-rpc-fence")
	run := e.run(t)
	repo := repositories.NewCloudResourcePolicyRepository(e.db)
	cov := func(state string, n int) *models.CloudResourcePolicyCoverage {
		return &models.CloudResourcePolicyCoverage{WorkspaceID: e.ws, ConnectorID: e.conn, ScanRunID: run,
			ResourceForm: "sns_topic", Region: "eu-west-1", State: state, Enumerated: n, ReadOK: n, Reason: map[bool]string{true: "", false: "x"}[state == "complete"]}
	}
	obs := []models.CloudResourcePolicyObservation{{WorkspaceID: e.ws, ScanRunID: run, ResourceForm: "sns_topic", Region: "eu-west-1",
		ResourceARN: "arn:aws:sns:eu-west-1:" + testAccount + ":alerts", ParseState: "parsed", ReadAt: time.Now()}}

	_, err := repo.Fenced(repositories.ScanFence{RunID: run, Owner: "superseded", LeaseVersion: 99}).RecordForm(cov("complete", 1), nil, obs)
	if !errors.Is(err, repositories.ErrScanFenceLost) || len(e.coverage(t, run)) != 0 {
		t.Fatalf("fenced write: err=%v rows=%d", err, len(e.coverage(t, run)))
	}
	if wrote, err := repo.RecordForm(cov("complete", 1), nil, obs); !wrote || err != nil {
		t.Fatalf("first attempt: %v %v", wrote, err)
	}
	if wrote, err := repo.RecordForm(cov("partial", 0), nil, nil); wrote || err != nil {
		t.Fatalf("second attempt: wrote=%v err=%v, want kept as recorded", wrote, err)
	}
	if c := e.coverage(t, run)["sns_topic/eu-west-1"]; c.State != "complete" || len(e.observations(t, run)) != 1 {
		t.Fatalf("after the second attempt: %+v", c)
	}
}

// Through the REAL scan worker: collection runs inside the scan under the
// barrier only when IGA_POLICY is available, and its rows belong to the run.
func TestP3RPCWorkerCollectsUnderPolicyGate(t *testing.T) {
	l := newP2Lab(t, "p3-rpc-worker", true)
	a := l.account(testAccount, "us-east-1", "eu-west-1")
	a.role("app", rpRoleID)
	w := newRPWorld()
	scan := func(gate *services.PolicyGate, owner string) models.CloudScanRun {
		queued, err := l.runs.Enqueue(l.ws, a.conn, "manual")
		if err != nil {
			t.Fatalf("enqueue: %v", err)
		}
		base := a.hook()
		worker := services.NewAWSScanWorker(l.db, a.svc).WithOwner(owner).WithGraphProjection(l.gate).WithPolicyGate(gate).
			WithScannerHook(func(i *services.AWSIAMScanner, p *services.AWSPermissionScanner, wl *services.AWSWorkloadScanner) {
				base(i, p, wl)
				w.wire(p)
			})
		if worked, err := worker.RunOnce(context.Background()); err != nil || !worked {
			t.Fatalf("worker: %v %v", worked, err)
		}
		var run models.CloudScanRun
		if err := l.db.First(&run, "id = ?", queued.ID).Error; err != nil || run.Status != models.CloudScanRunPublished {
			t.Fatalf("run %+v: %v", run, err)
		}
		l.project(owner + "-projector")
		return run
	}

	off := services.NewPolicyGate(false, "", func() *services.GraphProjectionGate { return l.gate })
	r1 := scan(off, "p3-rpc-off")
	var n int64
	l.db.Model(&models.CloudResourcePolicyCoverage{}).Where("workspace_id = ?", l.ws).Count(&n)
	if n != 0 {
		t.Fatalf("IGA_POLICY off wrote %d coverage rows (run %s)", n, r1.ID)
	}

	on := services.NewPolicyGate(true, "", func() *services.GraphProjectionGate { return l.gate })
	if err := on.Verify(l.db); err != nil {
		t.Fatalf("the integration database must be at 056: %v", err)
	}
	r2 := scan(on, "p3-rpc-on")
	cov, err := repositories.NewCloudResourcePolicyRepository(l.db).CoverageForScan(l.ws, r2.ID)
	if err != nil || len(cov) != 2+11*3 {
		t.Fatalf("worker coverage = %d rows (%v)", len(cov), err)
	}
	for _, c := range cov {
		if c.ConnectorID != a.conn || (c.Region != "ap-south-1" && c.State != "complete") {
			t.Fatalf("row %+v", c)
		}
	}
}
