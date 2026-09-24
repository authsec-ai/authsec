package integration

// The §7.1 end-to-end lab (SPEC-iga-phase2-graph.md §7.1, T8.1) as far as the
// P2-0 lab's fakes can build it, for the BACKEND halves of gates E1-E16: what
// the real §5.3 routes must return at each step of each scenario, with every
// scan run by the REAL AWSScanWorker and every projection by the REAL
// ProjectionService under different owner names (p2_0_lab_test.go).
//
// The lab's own accounts are §7.1's:
//
//	A "production"  connected, regions eu-central-1 and us-east-1
//	  eu-central-1  Lambdas ticket-tools and refund-tools, both running as
//	                SharedToolRole
//	  us-east-1     ECS task definition ticket-worker (task role TicketTaskRole,
//	                execution role TicketExecRole); EC2 instance with the
//	                instance profile reports-profile (ReportsRole); Bedrock agent
//	                support-agent (BedrockAgentRole); AgentCore runtime
//	                triage-runtime and gateway tools-gateway (AgentCoreRole)
//	  SharedToolRole  TicketRead (Sid ReadTickets) and ToolboxRead (no Sid),
//	                both allowing s3:GetObject on arn:aws:s3:::support-tickets/*
//	  group ops     OpsRead; user priya (permissions boundary PowerUserAccess)
//	                is a member
//	  reader-access trusts B's data-reader; partner-access trusts C's root;
//	                guarded-role holds a Deny statement; gha-deploy trusts
//	                GitHub OIDC for repo:authsec-ai/authsec:*
//	B "sandbox"     connected, region eu-central-1
//	                Lambda ticket-tools (running as data-reader); data-reader
//	                holds SandboxTickets, naming the same support-tickets bucket;
//	                loop-a and loop-b trust each other
//	C "partner"     NEVER connected; trusted by A's partner-access
//
// What the fakes cannot give -- real AWS, the console, Playwright -- is listed
// per scenario in the test that stops short of it. Everything here is prefixed
// egates: other streams write tests in this package at the same time.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	bedrockagenttypes "github.com/aws/aws-sdk-go-v2/service/bedrockagent/types"
	agentcoretypes "github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol/types"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	platform "github.com/authsec-ai/authsec/controllers/platform"
	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
)

// egatesAccountC is §7.1's partner account: trusted by A, never connected.
const egatesAccountC = "300000000003"

// egatesRegion is one region's workload fakes. A nil field answers as the
// P2-0 lab does: an empty, successful listing.
type egatesRegion struct {
	ecs      *fakeECS
	ec2      *fakeEC2
	profiles *fakeInstanceProfile
	bedrock  *fakeBedrock
	core     *fakeAgentCore
}

// egatesAcct is one connected lab account with per-REGION workload fakes: the
// P2-0 lab's hook answers ECS, EC2, Bedrock and AgentCore with one empty fake
// for every region, and s3bFakes with one shared fake for every region, which
// would list a us-east-1 task definition in eu-central-1 as well.
type egatesAcct struct {
	*p2Account
	regions map[string]*egatesRegion
	// extra, when set, is applied after the account's own fakes on every scan
	// (a scenario's denial or throttle).
	extra services.ScannerHook
}

func egatesAccount(l *p2Lab, id string, regions ...string) *egatesAcct {
	return &egatesAcct{p2Account: l.account(id, regions...), regions: map[string]*egatesRegion{}}
}

func (a *egatesAcct) region(name string) *egatesRegion {
	r := a.regions[name]
	if r == nil {
		r = &egatesRegion{}
		a.regions[name] = r
	}
	return r
}

// hook is the P2-0 lab account's hook with this account's regional fakes.
func (a *egatesAcct) hook() services.ScannerHook {
	base := a.p2Account.hook()
	return func(iamS *services.AWSIAMScanner, perm *services.AWSPermissionScanner, wl *services.AWSWorkloadScanner) {
		base(iamS, perm, wl)
		wl.WithRegionalAPIs(a.regional)
		if a.extra != nil {
			a.extra(iamS, perm, wl)
		}
	}
}

// regional is one region's workload APIs: the account's own fakes for that
// region, and an empty, successful listing for every one it has none of.
func (a *egatesAcct) regional(region string) (awsdiscovery.LambdaAPI, awsdiscovery.ECSAPI,
	awsdiscovery.EC2API, awsdiscovery.InstanceProfileAPI, awsdiscovery.BedrockAgentAPI,
	awsdiscovery.AgentCoreAPI, awsdiscovery.CloudTrailAPI) {
	var lam awsdiscovery.LambdaAPI = &fakeLambda{}
	if f := a.lambdas[region]; f != nil {
		lam = f
	}
	r := a.regions[region]
	if r == nil {
		r = &egatesRegion{}
	}
	var ecsAPI awsdiscovery.ECSAPI = &fakeECS{defs: map[string]ecstypes.TaskDefinition{}}
	if r.ecs != nil {
		ecsAPI = r.ecs
	}
	var ec2API awsdiscovery.EC2API = &fakeEC2{}
	if r.ec2 != nil {
		ec2API = r.ec2
	}
	var prof awsdiscovery.InstanceProfileAPI = &fakeInstanceProfile{roleByProfileName: map[string]string{}}
	if r.profiles != nil {
		prof = r.profiles
	}
	var bed awsdiscovery.BedrockAgentAPI = &fakeBedrock{agents: map[string]bedrockagenttypes.Agent{}}
	if r.bedrock != nil {
		bed = r.bedrock
	}
	var core awsdiscovery.AgentCoreAPI = &fakeAgentCore{}
	if r.core != nil {
		core = r.core
	}
	return lam, ecsAPI, ec2API, prof, bed, core, &fakeCloudTrail{}
}

var egatesSeq int

// egatesScan runs ONE scan of the account through the REAL worker, required
// to publish, and returns the run.
func egatesScan(l *p2Lab, a *egatesAcct) models.CloudScanRun {
	l.t.Helper()
	egatesSeq++
	queued, err := l.runs.Enqueue(l.ws, a.conn, "manual")
	if err != nil {
		l.t.Fatalf("enqueue: %v", err)
	}
	w := services.NewAWSScanWorker(l.db, a.svc).WithOwner(fmt.Sprintf("egates-scan-%d", egatesSeq)).
		WithGraphProjection(l.gate).WithScannerHook(a.hook())
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

// egatesCycle is one scan and one projection pass (the pass must complete on
// its first attempt, p2Lab.project), under fresh owner names.
func egatesCycle(l *p2Lab, a *egatesAcct) models.CloudScanRun {
	l.t.Helper()
	run := egatesScan(l, a)
	l.project(fmt.Sprintf("egates-projector-%d", egatesSeq))
	return run
}

/* ------------------------------- the accounts ------------------------------ */

// Role and function names of the lab, used by every scenario.
const (
	egatesSharedRole = "SharedToolRole"
	egatesTicketRead = "TicketRead"
	egatesToolbox    = "ToolboxRead"
	egatesTickets    = "arn:aws:s3:::support-tickets/*"
	egatesPrimary    = "eu-central-1"
	egatesSecondary  = "us-east-1"
)

// egatesProduction is §7.1's account A, built (not yet scanned) in l.
func egatesProduction(t *testing.T, l *p2Lab) *egatesAcct {
	t.Helper()
	a := egatesAccount(l, accountA, egatesPrimary, egatesSecondary)
	shared := a.role(egatesSharedRole, "AROAEGATESSHARED0001")
	a.attach(egatesSharedRole, a.managed(egatesTicketRead, docTicketRead))
	a.attach(egatesSharedRole, a.managed(egatesToolbox, docToolboxRead))
	listsFunctions(a.p2Account, egatesPrimary, "ticket-tools", shared, "refund-tools", shared)

	// us-east-1: the other runtimes §7.1 lists, each with its own role.
	taskRole := a.role("TicketTaskRole", "AROAEGATESTASKROLE01")
	execRole := a.role("TicketExecRole", "AROAEGATESEXECROLE01")
	reports := a.role("ReportsRole", "AROAEGATESREPORTS001")
	bedrockRole := a.role("BedrockAgentRole", "AROAEGATESBEDROCK001")
	coreRole := a.role("AgentCoreRole", "AROAEGATESAGENTCORE1")
	us := a.region(egatesSecondary)
	tdARN := "arn:aws:ecs:" + egatesSecondary + ":" + a.id + ":task-definition/ticket-worker:1"
	us.ecs = &fakeECS{defs: map[string]ecstypes.TaskDefinition{tdARN: {
		TaskDefinitionArn: aws.String(tdARN), Family: aws.String("ticket-worker"),
		TaskRoleArn: aws.String(taskRole), ExecutionRoleArn: aws.String(execRole),
	}}}
	us.ec2 = &fakeEC2{instances: []ec2types.Instance{{
		InstanceId: aws.String("i-0egatesreports0001"),
		// Named: an untagged instance is projected with an empty name (a
		// question raised with this gate, not assumed away).
		Tags: []ec2types.Tag{{Key: aws.String("Name"), Value: aws.String("reports-host")}},
		IamInstanceProfile: &ec2types.IamInstanceProfile{
			Arn: aws.String("arn:aws:iam::" + a.id + ":instance-profile/reports-profile")},
		State: &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning},
	}}}
	us.profiles = &fakeInstanceProfile{roleByProfileName: map[string]string{"reports-profile": reports}}
	us.bedrock = &fakeBedrock{agents: map[string]bedrockagenttypes.Agent{"EGATESAGNT": {
		AgentId:              aws.String("EGATESAGNT"),
		AgentArn:             aws.String("arn:aws:bedrock:" + egatesSecondary + ":" + a.id + ":agent/EGATESAGNT"),
		AgentName:            aws.String("support-agent"),
		AgentResourceRoleArn: aws.String(bedrockRole),
	}}}
	us.core = &fakeAgentCore{
		runtimes: []agentcoretypes.AgentRuntime{{AgentRuntimeId: aws.String("rt-egates-triage"),
			AgentRuntimeArn:  aws.String("arn:aws:bedrock-agentcore:" + egatesSecondary + ":" + a.id + ":runtime/rt-egates-triage"),
			AgentRuntimeName: aws.String("triage-runtime")}},
		roleByID:        map[string]string{"rt-egates-triage": coreRole},
		gateways:        []agentcoretypes.GatewaySummary{{GatewayId: aws.String("gw-egates-tools"), Name: aws.String("tools-gateway")}},
		gatewayRoleByID: map[string]string{"gw-egates-tools": coreRole},
	}

	// ops and priya (E4's boundary case).
	boundary := s3aAWSManaged(a.p2Account, "PowerUserAccess", evidenceDoc(
		`{"Effect":"Allow","NotAction":["iam:*","organizations:*"],"Resource":"*"}`))
	s3aGroup(a.p2Account, "ops", "AGPAEGATESOPSGROUP01")
	s3aGroupAttach(t, a.p2Account, "ops", a.managed("OpsRead", evidenceDoc(
		`{"Sid":"ReadOps","Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::ops-bucket/*"}`)))
	s3aUser(a.p2Account, "priya", "AIDAEGATESPRIYA00001")
	s3aEditUser(t, a.p2Account, "priya", func(u *iamtypes.User) { u.PermissionsBoundary = s3aBoundary(boundary) })
	s3aJoin(a.p2Account, "priya", "ops")

	// Trust: B's data-reader (connected), C's root (never), GitHub OIDC; and
	// a role holding a Deny statement.
	trustRole(a.p2Account, "reader-access", "AROAEGATESREADERACC1", trustDoc(
		trustAllow(`{"AWS":"arn:aws:iam::`+accountB+`:role/data-reader"}`, "sts:AssumeRole")))
	trustRole(a.p2Account, "partner-access", "AROAEGATESPARTNER001", trustDoc(
		trustAllow(`{"AWS":"arn:aws:iam::`+egatesAccountC+`:root"}`, "sts:AssumeRole")))
	trustRole(a.p2Account, "gha-deploy", "AROAEGATESGHADEPLOY1", trustDoc(
		`{"Effect":"Allow","Principal":{"Federated":"`+trustGitHubProvider+`"},"Action":"sts:AssumeRoleWithWebIdentity",`+
			`"Condition":{"StringLike":{"token.actions.githubusercontent.com:sub":"repo:authsec-ai/authsec:*"}}}`))
	a.role("guarded-role", "AROAEGATESGUARDED001")
	a.attach("guarded-role", a.managed("GuardRails", evidenceDoc(
		`{"Sid":"NoDeletes","Effect":"Deny","Action":"s3:DeleteObject","Resource":"*"}`)))
	return a
}

// egatesSandbox is §7.1's account B, built (not yet scanned) in l.
func egatesSandbox(t *testing.T, l *p2Lab) *egatesAcct {
	t.Helper()
	b := egatesAccount(l, accountB, egatesPrimary)
	reader := b.role("data-reader", "AROAEGATESDATAREADR1")
	b.attach("data-reader", b.managed("SandboxTickets", s3aDoc("SandboxRead", "s3:GetObject", egatesTickets)))
	b.lambda(egatesPrimary, "ticket-tools", reader)
	loopA, loopB := b.roleARN("loop-a"), b.roleARN("loop-b")
	trustRole(b.p2Account, "loop-a", "AROAEGATESLOOPA00001", trustDoc(trustAllow(`{"AWS":"`+loopB+`"}`, "sts:AssumeRole")))
	trustRole(b.p2Account, "loop-b", "AROAEGATESLOOPB00001", trustDoc(trustAllow(`{"AWS":"`+loopA+`"}`, "sts:AssumeRole")))
	return b
}

/* --------------------------------- lookups -------------------------------- */

// egatesID is the id of the workspace's graph row of this name, preferring the
// active one, then the newest. table is the node table; account, when given,
// narrows by the ARN's account for identities and workloads (two ticket-tools).
func egatesID(t *testing.T, l *p2Lab, table, name, account string) uuid.UUID {
	t.Helper()
	q := `SELECT id FROM ` + table + ` WHERE workspace_id = ? AND display_name = ?`
	args := []any{l.ws, name}
	if table != "iga_workload" {
		q += ` AND provider = 'aws'`
	}
	if account != "" {
		q += ` AND source_key LIKE ?`
		args = append(args, "%:"+account+":%")
	}
	q += ` ORDER BY (lifecycle = 'active') DESC, created_at DESC LIMIT 1`
	var id uuid.UUID
	if err := l.db.Raw(q, args...).Row().Scan(&id); err != nil {
		t.Fatalf("no %s named %q (account %q): %v", table, name, account, err)
	}
	return id
}

func egatesWorkload(t *testing.T, l *p2Lab, name, account string) string {
	return refOf("workload", egatesID(t, l, "iga_workload", name, account))
}

func egatesIdentity(t *testing.T, l *p2Lab, name string) string {
	return refOf("identity", egatesID(t, l, "iga_identity_accounts", name, ""))
}

func egatesResource(t *testing.T, l *p2Lab, text string) string {
	return refOf("resource", egatesID(t, l, "iga_resources", text, ""))
}

/* ------------------------------- the routes ------------------------------- */

// egatesGet calls a §5.3 route through the real route table and requires 200.
func egatesGet(t *testing.T, api *readAPI, path string) map[string]any {
	t.Helper()
	code, body := api.get(path)
	mustStatus(t, "GET "+path, code, body, http.StatusOK)
	return body
}

// egatesRoute is a detail route of a typed ref: "/workloads/<uuid>".
func egatesRoute(t *testing.T, ref string, tail ...string) string {
	t.Helper()
	typ, id, ok := strings.Cut(ref, ":")
	if !ok {
		t.Fatalf("not a typed reference: %q", ref)
	}
	base := map[string]string{"workload": "/workloads/", "identity": "/identities/",
		"resource": "/resources/", "external_principal": "/external-principals/"}[typ]
	if base == "" {
		t.Fatalf("no detail route for %q", ref)
	}
	return base + id + strings.Join(tail, "")
}

// egatesJSON renders a value compactly, for failure messages.
func egatesJSON(v any) string {
	raw, _ := json.Marshal(v)
	return string(raw)
}

// egatesMeta asserts a response is at the pinned revision (§5.1: every
// response echoes meta.rev and meta.published_at).
func egatesMeta(t *testing.T, what string, body map[string]any, rev int64, publishedAt string) {
	t.Helper()
	if num(body, "meta", "rev") != rev || digs(body, "meta", "published_at") != publishedAt {
		t.Errorf("%s: meta rev=%v published_at=%v, want rev %d at %s", what,
			dig(body, "meta", "rev"), dig(body, "meta", "published_at"), rev, publishedAt)
	}
}

// egatesForbiddenWording is wording no response may use for a declared path
// (§2.14.8; E3 "Fails if: 'can access' wording anywhere"): a declared grant is
// not evaluated access.
var egatesForbiddenWording = []string{"can access", "has access", "can reach"}

// egatesNoAccessWording fails when a response uses access wording.
func egatesNoAccessWording(t *testing.T, what string, body map[string]any) {
	t.Helper()
	raw := strings.ToLower(egatesJSON(body))
	for _, w := range egatesForbiddenWording {
		if strings.Contains(raw, w) {
			t.Errorf("%s says %q: a declared grant is not evaluated access (§2.14.8)", what, w)
		}
	}
}

// egatesRows indexes a list's rows by a string field; a value seen twice fails.
func egatesRows(t *testing.T, rows []any, field string) map[string]map[string]any {
	t.Helper()
	out := map[string]map[string]any{}
	for _, r := range rows {
		m, _ := r.(map[string]any)
		k := digs(m, field)
		if _, dup := out[k]; dup {
			t.Fatalf("row %s=%q returned twice: %s", field, k, egatesJSON(rows))
		}
		out[k] = m
	}
	return out
}

// egatesSorted is a sorted copy.
func egatesSorted(s []string) []string {
	out := append([]string(nil), s...)
	sort.Strings(out)
	return out
}

// egatesWork runs the REAL scan worker once under owner, claiming whatever is
// queued (the run a route queued), and reports whether it did work.
func egatesWork(l *p2Lab, a *egatesAcct, owner string) bool {
	l.t.Helper()
	w := services.NewAWSScanWorker(l.db, a.svc).WithOwner(owner).
		WithGraphProjection(l.gate).WithScannerHook(a.hook())
	worked, err := w.RunOnce(context.Background())
	if err != nil {
		l.t.Fatalf("scan worker %s: %v", owner, err)
	}
	return worked
}

// egatesDiscovery is the existing /authsec/discovery AWS routes a scenario
// drives (queue a scan, read a run), mounted the way routes.go mounts them,
// with the token's workspace set as AuthMiddleware sets it. Permission
// middleware is not mounted: the discovery routes' permissions are not a
// Phase 2 contract.
type egatesDiscovery struct {
	t   *testing.T
	eng *gin.Engine
}

func egatesDiscoveryAPI(t *testing.T, l *p2Lab, a *egatesAcct) *egatesDiscovery {
	t.Helper()
	gin.SetMode(gin.TestMode)
	ctl := platform.NewCloudAWSController(l.db).WithOnboardingService(a.svc)
	eng := gin.New()
	g := eng.Group("/authsec/discovery")
	g.Use(func(c *gin.Context) { c.Set("workspace_id", l.ws.String()); c.Next() })
	g.POST("/aws/connectors/:id/scan", ctl.ScanIAM)
	g.GET("/aws/scan-runs/:id", ctl.GetScanRun)
	g.GET("/aws/connectors/:id/scan-runs", ctl.ListConnectorScanRuns)
	return &egatesDiscovery{t: t, eng: eng}
}

func (d *egatesDiscovery) do(method, path string) (int, map[string]any) {
	d.t.Helper()
	req := httptest.NewRequest(method, "/authsec/discovery"+path, nil)
	w := httptest.NewRecorder()
	d.eng.ServeHTTP(w, req)
	var out map[string]any
	if w.Body.Len() > 0 {
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			d.t.Fatalf("%s %s: status %d, body is not JSON: %q", method, path, w.Code, w.Body.String())
		}
	}
	return w.Code, out
}

// queueScan is POST /aws/connectors/:id/scan: 202 and the queued run's id.
func (d *egatesDiscovery) queueScan(a *egatesAcct) uuid.UUID {
	d.t.Helper()
	code, body := d.do(http.MethodPost, "/aws/connectors/"+a.conn.String()+"/scan")
	mustStatus(d.t, "POST scan", code, body, http.StatusAccepted)
	id, err := uuid.Parse(digs(body, "meta", "run_id"))
	if err != nil {
		d.t.Fatalf("POST scan returned no run id: %v", body)
	}
	return id
}
