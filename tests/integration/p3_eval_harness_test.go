package integration

// Shared plumbing for the T3.06 / T3.06b scenarios (SPEC-iga-phase3-policy.md
// §2.5, §8.2, §2.11, §2.12, §7.1, §7.2): the P2-0 lab -- the REAL scan worker
// and the REAL projection service over the integration database, AWS answered
// by fakes -- with the IGA_POLICY gate on, so every publication runs the
// finding evaluation step inside the projection job. Prefixed p3e.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"gorm.io/gorm"

	platform "github.com/authsec-ai/authsec/controllers/platform"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/routes"
	"github.com/authsec-ai/authsec/services"
)

// p3Activity answers Access Advisor per principal: the job id is the ARN,
// each ARN has its own services, and an ARN in fail gets a FAILED job.
type p3Activity struct {
	mu        sync.Mutex
	services  map[string][]iamtypes.ServiceLastAccessed
	fail      map[string]bool
	completed time.Time
}

func newP3Activity() *p3Activity {
	return &p3Activity{services: map[string][]iamtypes.ServiceLastAccessed{}, fail: map[string]bool{},
		completed: time.Now().Add(-2 * time.Hour)}
}

// set records arn's report: service -> last attempt (nil: no attempt reported).
func (f *p3Activity) set(arn string, report map[string]*time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []iamtypes.ServiceLastAccessed
	for svc, last := range report {
		out = append(out, iamtypes.ServiceLastAccessed{ServiceNamespace: aws.String(svc),
			ServiceName: aws.String(svc), LastAuthenticated: last})
	}
	f.services[arn] = out
}

func (f *p3Activity) GenerateServiceLastAccessedDetails(_ context.Context, in *iam.GenerateServiceLastAccessedDetailsInput, _ ...func(*iam.Options)) (*iam.GenerateServiceLastAccessedDetailsOutput, error) {
	return &iam.GenerateServiceLastAccessedDetailsOutput{JobId: in.Arn}, nil
}

func (f *p3Activity) GetServiceLastAccessedDetails(_ context.Context, in *iam.GetServiceLastAccessedDetailsInput, _ ...func(*iam.Options)) (*iam.GetServiceLastAccessedDetailsOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	arn := aws.ToString(in.JobId)
	if f.fail[arn] {
		return &iam.GetServiceLastAccessedDetailsOutput{JobStatus: iamtypes.JobStatusTypeFailed,
			Error: &iamtypes.ErrorDetails{Message: aws.String("report unavailable")}}, nil
	}
	done := f.completed
	return &iam.GetServiceLastAccessedDetailsOutput{JobStatus: iamtypes.JobStatusTypeCompleted,
		JobCompletionDate: &done, ServicesLastAccessed: f.services[arn]}, nil
}

// p3eLab is the P2-0 lab with the IGA_POLICY gate on.
type p3eLab struct {
	*p2Lab
	policy *services.PolicyGate
	acts   map[uuid.UUID]*p3Activity
}

func newP3eLab(t *testing.T, name string) *p3eLab {
	t.Helper()
	l := newP2Lab(t, name, true)
	gate := services.NewPolicyGate(true, "", func() *services.GraphProjectionGate { return l.gate })
	if err := gate.Verify(l.db); err != nil || !gate.Available() {
		t.Fatalf("the policy gate must verify against the integration database (056): %v", err)
	}
	pl := &p3eLab{p2Lab: l, policy: gate, acts: map[uuid.UUID]*p3Activity{}}
	// Runs before the lab's own cleanup (LIFO): the Phase 3 rows reference
	// publications and runs the lab deletes, and iga_gov_event is append-only
	// outside a workspace purge.
	t.Cleanup(func() { p3ePurge(t, l.db, l.ws) })
	return pl
}

// p3ePurge deletes a workspace's Phase 3 rows, children first.
func p3ePurge(t *testing.T, db *gorm.DB, ws uuid.UUID) {
	err := db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec(`SET LOCAL authsec.workspace_purge = 'on'`).Error; err != nil {
			return err
		}
		for _, table := range []string{
			// Deployments (and the posture naming them) before the
			// revalidations and approvals they reference (T3.15).
			"iga_gov_event", "iga_gov_job", "iga_gov_acceptance", "iga_gov_service_posture",
			// The deployment jobs' rows (the rollout labs run them, T3.16).
			"iga_gov_attempt", "iga_gov_verification", "iga_gov_service_outcome", "iga_gov_validation_item",
			"iga_gov_validation", "iga_gov_health_report", "iga_gov_artifact", "iga_gov_deployment",
			"iga_gov_revalidation", "iga_gov_rollout",
			"iga_gov_approval", "iga_gov_owner_response", "iga_gov_owner_review",
			"iga_gov_finding_result", "iga_gov_activity_evidence",
			"iga_gov_finding", "iga_gov_evaluation",
			"iga_gov_plan", "iga_gov_target", "iga_gov_evidence_bundle", "iga_gov_control", "iga_gov_document",
			"iga_gov_policy_version", "iga_gov_owner", "iga_gov_owner_rule", "iga_gov_finding_rule",
			"iga_gov_settings", "iga_gov_iac_source", "cloud_enforcement_binding",
			"cloud_resource_policy_observation", "cloud_resource_policy_coverage", "cloud_policy_document",
		} {
			if table == "iga_gov_policy_version" {
				if err := tx.Exec(`UPDATE iga_gov_policy SET current_version_id = NULL WHERE workspace_id = ?`, ws).Error; err != nil {
					return err
				}
			}
			if err := tx.Exec(`DELETE FROM `+table+` WHERE workspace_id = ?`, ws).Error; err != nil {
				return fmt.Errorf("%s: %w", table, err)
			}
			if table == "iga_gov_policy_version" {
				if err := tx.Exec(`DELETE FROM iga_gov_policy WHERE workspace_id = ?`, ws).Error; err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Logf("phase 3 purge: %v", err)
	}
}

// activity returns the account's Access Advisor fake.
func (l *p3eLab) activity(a *p2Account) *p3Activity {
	f := l.acts[a.conn]
	if f == nil {
		f = newP3Activity()
		l.acts[a.conn] = f
	}
	return f
}

// hook is the account's lab hook with its per-principal activity fake.
func (l *p3eLab) hook(a *p2Account) services.ScannerHook {
	act := l.activity(a)
	return func(iamS *services.AWSIAMScanner, perm *services.AWSPermissionScanner, wl *services.AWSWorkloadScanner) {
		a.hook()(iamS, perm, wl)
		wl.WithActivityAPI(act, func(context.Context, time.Duration) error { return nil })
	}
}

// scanOnly runs one scan through the REAL worker (published, not projected).
func (l *p3eLab) scanOnly(a *p2Account) models.CloudScanRun {
	l.t.Helper()
	scanSeq++
	queued, err := l.runs.Enqueue(l.ws, a.conn, "manual")
	if err != nil {
		l.t.Fatalf("enqueue: %v", err)
	}
	w := services.NewAWSScanWorker(l.db, a.svc).WithOwner(fmt.Sprintf("p3e-scan-%d", scanSeq)).
		WithGraphProjection(l.gate).WithScannerHook(l.hook(a))
	if worked, err := w.RunOnce(context.Background()); err != nil || !worked {
		l.t.Fatalf("scan worker: worked=%v err=%v", worked, err)
	}
	var run models.CloudScanRun
	if err := l.db.First(&run, "id = ?", queued.ID).Error; err != nil {
		l.t.Fatalf("read run: %v", err)
	}
	if run.Status != models.CloudScanRunPublished {
		l.t.Fatalf("run %s is %s (%s), want published", run.ID, run.Status, run.LastError)
	}
	return run
}

// projector is the REAL projection service with this lab's policy gate and
// the given evaluator (nil: the default one).
func (l *p3eLab) projector(owner string, ev *services.GovEvaluator) *services.ProjectionService {
	svc := services.NewProjectionService(l.db,
		repositories.NewIGAProjectionJobRepository(l.db),
		repositories.NewIGAPipelineLeaseRepository(l.db),
		repositories.NewIGAGraphRepository(), owner, time.Minute).WithPolicyGate(l.policy)
	if ev != nil {
		svc = svc.WithEvaluator(ev)
	}
	return svc
}

// cycle is one scan and one projection pass (with evaluation), which must
// complete with the barrier idle. It returns the run and the new revision.
func (l *p3eLab) cycle(a *p2Account, ev *services.GovEvaluator) (models.CloudScanRun, int64) {
	l.t.Helper()
	run := l.scanOnly(a)
	worked, err := l.projector(fmt.Sprintf("p3e-projector-%d", scanSeq), ev).RunOnce(context.Background())
	if err != nil || !worked {
		l.t.Fatalf("projector: worked=%v err=%v", worked, err)
	}
	if n := l.count(`SELECT count(*) FROM iga_projection_job WHERE workspace_id = ? AND status <> 'complete'`, l.ws); n != 0 {
		l.t.Fatalf("%d projection jobs did not complete", n)
	}
	if b := l.barrier(); b != models.PipelineIdle {
		l.t.Fatalf("barrier is %s after the projection, want idle", b)
	}
	return run, l.latestRev()
}

func (l *p3eLab) latestRev() int64 {
	var rev int64
	l.db.Raw(`SELECT COALESCE(max(rev), 0) FROM iga_publication WHERE workspace_id = ?`, l.ws).Scan(&rev)
	return rev
}

// evaluation is iga_gov_evaluation(rev).
func (l *p3eLab) evaluation(rev int64) models.IGAGovEvaluation {
	l.t.Helper()
	var e models.IGAGovEvaluation
	if err := l.db.Where("workspace_id = ? AND rev = ?", l.ws, rev).Take(&e).Error; err != nil {
		l.t.Fatalf("evaluation rev %d: %v", rev, err)
	}
	return e
}

// oldRole adds a role created `age` ago (so its activity window is long
// enough for an unused_service claim) granted `doc` through a managed policy.
func p3eOldRole(a *p2Account, name, roleID string, age time.Duration, policyName, doc string) string {
	arn := a.role(name, roleID)
	for i := range a.iam.roles {
		if aws.ToString(a.iam.roles[i].RoleName) == name {
			a.iam.roles[i].CreateDate = ago(age)
		}
	}
	if doc != "" {
		a.attach(name, a.managed(policyName, doc))
	}
	return arn
}

// p3eFinding is one finding row joined with its result at a revision.
type p3eFinding struct {
	ID               uuid.UUID
	Kind             string
	DetailKey        string
	RoleID           string
	Status           string
	LastEvaluatedRev int64
	Confidence       string
	ResultRev        *int64
	ResultConfidence *string
	EvidenceScanRun  *uuid.UUID
}

// findingsAt lists the workspace's findings with their result at rev (nil
// when the condition does not hold at rev).
func (l *p3eLab) findingsAt(rev int64) map[string]p3eFinding {
	l.t.Helper()
	var rows []p3eFinding
	if err := l.db.Raw(`SELECT f.id, f.kind, f.detail_key, f.role_id, f.status, f.last_evaluated_rev, f.confidence,
	                           r.rev AS result_rev, r.confidence AS result_confidence, r.evidence_scan_run_id AS evidence_scan_run
	                      FROM iga_gov_finding f
	                      LEFT JOIN iga_gov_finding_result r ON r.workspace_id = f.workspace_id AND r.finding_id = f.id AND r.rev = ?
	                     WHERE f.workspace_id = ?`, rev, l.ws).Scan(&rows).Error; err != nil {
		l.t.Fatalf("findings: %v", err)
	}
	out := map[string]p3eFinding{}
	for _, r := range rows {
		out[r.Kind+"/"+r.RoleID+"/"+r.DetailKey] = r
	}
	return out
}

const p3eSQSS3 = `{"Version":"2012-10-17","Statement":[{"Sid":"Work","Effect":"Allow","Action":["sqs:SendMessage","s3:GetObject"],"Resource":"*"}]}`

func p3eTime(d time.Duration) *time.Time {
	t := time.Now().Add(-d).UTC().Truncate(time.Second)
	return &t
}

// p3eAPI is the PRODUCTION /api/iga/v1 surface (routes.SetupIGARoutes, the
// production AuthMiddleware and permission middleware) over the lab's
// database and policy gate, calling as a token of workspace ws.
type p3eAPI struct {
	t      *testing.T
	eng    *gin.Engine
	secret string
}

func (l *p3eLab) api() *p3eAPI {
	l.t.Helper()
	gin.SetMode(gin.TestMode)
	const secret = "p3-t306b-jwt-secret"
	l.t.Setenv("JWT_SDK_SECRET", secret)
	l.t.Setenv("JWT_DEF_SECRET", secret+"-default")
	l.t.Setenv("AUTH_EXPECT_ISS", "authsec-ai/auth-manager")
	l.t.Setenv("REQUIRE_SERVER_AUTH", "true")
	eng := gin.New()
	ctl := platform.NewIGAGraphReadControllerWith(l.db, l.gate, readTestCursorKey).WithPolicyGate(l.policy)
	routes.SetupIGARoutes(eng, platform.NewIGAController(l.db), ctl)
	return &p3eAPI{t: l.t, eng: eng, secret: secret}
}

// token is a bearer for workspace ws with the given scope.
func (a *p3eAPI) token(ws uuid.UUID, scope string) string {
	claims := jwt.MapClaims{"iss": "authsec-ai/auth-manager", "exp": time.Now().Add(time.Hour).Unix(),
		"workspace_id": ws.String(), "user_id": uuid.NewString()}
	if scope != "" {
		claims["scope"] = scope
	}
	s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(a.secret))
	if err != nil {
		a.t.Fatal(err)
	}
	return s
}

// do calls /api/iga/v1/policy<path> with a governance:read token of ws.
func (a *p3eAPI) do(ws uuid.UUID, method, path string, body any) (int, map[string]any) {
	a.t.Helper()
	var rd *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			a.t.Fatal(err)
		}
		rd = bytes.NewReader(raw)
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, "/api/iga/v1/policy"+path, rd)
	req.Header.Set("Authorization", "Bearer "+a.token(ws, "governance:read"))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	a.eng.ServeHTTP(w, req)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func (a *p3eAPI) get(ws uuid.UUID, path string) (int, map[string]any) {
	return a.do(ws, http.MethodGet, path, nil)
}

// p3eErr is the §7 error code of a body.
func p3eErr(body map[string]any) string {
	e, _ := body["error"].(map[string]any)
	s, _ := e["code"].(string)
	return s
}

// p3eList is body.data as a list of objects.
func p3eList(body map[string]any) []map[string]any {
	raw, _ := body["data"].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, x := range raw {
		m, _ := x.(map[string]any)
		out = append(out, m)
	}
	return out
}

func p3eMeta(body map[string]any, key string) any {
	m, _ := body["meta"].(map[string]any)
	return m[key]
}
