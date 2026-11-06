package integration

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/agentcontain"
	"github.com/authsec-ai/authsec/internal/agentruntime"
	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/internal/awsenforce"
	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/services"
)

// Agent containment (SPEC-agent-runtime-visibility.md §5.8, §10; P3) over
// the integration database with a fake AWS account: per-workspace state
// (preview, contain, the agent_contain job to contained, release to the
// exact before-state, the deferred session revocation, behavioural
// verification), and isolation -- workspace B can neither preview, contain,
// read nor release workspace A's identity, workload or containment (404), and
// B's events never touch A's containment. Needs IGA_TEST_DSN (skipped
// otherwise).

/* --------------------------------- fake AWS -------------------------------- */

type acPolicy struct {
	doc      string
	tags     map[string]string
	attached map[string]bool
}

type acAWS struct {
	mu       sync.Mutex
	lambda   map[string]*int32
	policies map[string]*acPolicy
}

func newACAWS() *acAWS { return &acAWS{lambda: map[string]*int32{}, policies: map[string]*acPolicy{}} }

func (f *acAWS) GetFunctionConcurrency(_ context.Context, fn string) (*int32, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n, ok := f.lambda[fn]
	if !ok {
		return nil, agentcontain.ErrNotFound
	}
	if n == nil {
		return nil, nil
	}
	v := *n
	return &v, nil
}

func (f *acAWS) PutFunctionConcurrency(_ context.Context, fn string, n int32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.lambda[fn]; !ok {
		return agentcontain.ErrNotFound
	}
	f.lambda[fn] = &n
	return nil
}

func (f *acAWS) DeleteFunctionConcurrency(_ context.Context, fn string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lambda[fn] = nil
	return nil
}

func (f *acAWS) DescribeService(context.Context, string, string) (*agentcontain.ECSService, error) {
	return nil, nil
}
func (f *acAWS) SetServiceDesiredCount(context.Context, string, string, int32) error {
	return agentcontain.ErrNotFound
}
func (f *acAWS) DescribeScalableTarget(context.Context, string, string) (*agentcontain.ScalableTarget, error) {
	return nil, nil
}
func (f *acAWS) SetScalableTargetSuspended(context.Context, string, string, agentcontain.Suspended) error {
	return agentcontain.ErrNotFound
}

func (f *acAWS) CreatePolicy(_ context.Context, name, doc string, tags map[string]string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	arn := "arn:aws:iam::111111111111:policy/authsec/" + name
	f.policies[arn] = &acPolicy{doc: doc, tags: tags, attached: map[string]bool{}}
	return arn, nil
}

func (f *acAWS) DeletePolicy(_ context.Context, arn string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.policies, arn)
	return nil
}

func (f *acAWS) AttachPolicy(_ context.Context, p agentcontain.Principal, arn string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	pol, ok := f.policies[arn]
	if !ok {
		return agentcontain.ErrNotFound
	}
	pol.attached[p.Name] = true
	return nil
}

func (f *acAWS) DetachPolicy(_ context.Context, p agentcontain.Principal, arn string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if pol, ok := f.policies[arn]; ok {
		delete(pol.attached, p.Name)
	}
	return nil
}

func (f *acAWS) ReadPolicy(_ context.Context, arn string, p agentcontain.Principal) (*agentcontain.PolicyRead, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	pol, ok := f.policies[arn]
	if !ok {
		return &agentcontain.PolicyRead{}, nil
	}
	return &agentcontain.PolicyRead{Exists: true, Tags: pol.tags, DocumentHash: igagov.ContentHash([]byte(pol.doc)),
		AttachedToPrincipal: pol.attached[p.Name]}, nil
}

func (f *acAWS) ListAccessKeys(context.Context, string) ([]agentcontain.AccessKey, error) {
	return nil, nil
}
func (f *acAWS) SetAccessKeyStatus(context.Context, string, string, bool) error {
	return agentcontain.ErrNotFound
}

// acAccess hands every workspace the same fake account, recording which
// workspace opened it.
type acAccess struct {
	aws    *acAWS
	mu     sync.Mutex
	opened []uuid.UUID
}

func (a *acAccess) Open(_ context.Context, ws, _, _ uuid.UUID) (agentcontain.AWS, error) {
	a.mu.Lock()
	a.opened = append(a.opened, ws)
	a.mu.Unlock()
	return a.aws, nil
}
func (a *acAccess) ECSServicesOf(context.Context, uuid.UUID, uuid.UUID, string, string) ([]agentcontain.ECSService, error) {
	return nil, nil
}
func (a *acAccess) FunctionTags(context.Context, uuid.UUID, uuid.UUID, string) (map[string]string, error) {
	return map[string]string{}, nil
}
func (a *acAccess) EventSourceMappings(context.Context, uuid.UUID, uuid.UUID, string) (int, error) {
	return 0, nil
}

/* ---------------------------------- fixture -------------------------------- */

type acLab struct {
	t      *testing.T
	db     *gorm.DB
	fake   *acAWS
	access *acAccess
	clock  time.Time
	svc    *services.AgentContain
	worker *services.PolicyJobWorker
}

type acTenant struct {
	g        *p3Gov
	identity uuid.UUID
	roleARN  string
	roleID   string
	lambda   uuid.UUID
	fnARN    string
}

func newACLab(t *testing.T) *acLab {
	t.Helper()
	db := igaDB(t)
	pg := services.NewPolicyGate(true, p3GraphOn(t, db))
	if err := pg.Verify(db); err != nil {
		t.Fatal(err)
	}
	prevP := services.PolicyGateState()
	services.SetPolicyGate(pg)
	r2 := services.NewPolicyR2Gate(true)
	if err := r2.Verify(db); err != nil {
		t.Fatalf("R2 gate: %v", err)
	}
	prevR2 := services.PolicyR2GateState()
	services.SetPolicyR2Gate(r2)
	if err := services.VerifyAgentContainSchema(db); err != nil {
		t.Fatalf("the integration database must be at 159: %v", err)
	}
	l := &acLab{t: t, db: db, fake: newACAWS(), clock: time.Now().UTC()}
	l.access = &acAccess{aws: l.fake}
	services.SetAgentContainAccess(l.access)
	t.Cleanup(func() {
		services.SetAgentContainAccess(nil)
		services.SetPolicyR2Gate(prevR2)
		services.SetPolicyGate(prevP)
	})
	l.svc = services.NewAgentContain(db).WithClock(func() time.Time { return l.clock })
	l.worker = services.NewPolicyJobWorker(db, "p3-contain-"+uuid.NewString()[:8]).WithGate(func() bool { return true })
	l.worker.Register(services.PolicyJobKind{Kind: services.GovJobAgentContain, Handler: l.svc.Handler})
	return l
}

// tenant is one workspace with an AWS role, a verified template v2 binding
// with the containment capabilities, and one Lambda function on the role.
func (l *acLab) tenant(name string) *acTenant {
	l.t.Helper()
	g := p3NewGov(l.t, l.db, name)
	tn := &acTenant{g: g, identity: uuid.New(), lambda: uuid.New()}
	tn.roleID = "AROA" + strings.ToUpper(strings.ReplaceAll(tn.identity.String(), "-", ""))[:17]
	tn.roleARN = "arn:aws:iam::111111111111:role/agent-" + g.ws.String()[:8]
	tn.fnARN = "arn:aws:lambda:us-east-1:111111111111:function:agent-" + g.ws.String()[:8]
	p3exec(l.t, l.db, `INSERT INTO cloud_identity (id, workspace_id, connector_id, kind, native_id, name, attrs)
		VALUES (?, ?, ?, 'iam_role', ?, ?, jsonb_build_object('unique_id', ?::text, 'path', '/'))`,
		tn.identity, g.ws, g.conn, tn.roleARN, "agent-"+g.ws.String()[:8], tn.roleID)
	p3exec(l.t, l.db, `INSERT INTO cloud_workload (id, workspace_id, connector_id, identity_id, runtime_kind, native_id, name, region)
		VALUES (?, ?, ?, ?, 'lambda_function', ?, ?, 'us-east-1')`, tn.lambda, g.ws, g.conn, tn.identity, tn.fnARN, "agent-"+g.ws.String()[:8])
	caps := `{}`
	need := append(awsenforce.V2CapabilitiesFor(awsenforce.FeatureTemporaryGrants), awsenforce.CapWorkloadContainment)
	for i, c := range need {
		sep := ","
		if i == 0 {
			caps, sep = "{", ""
		}
		caps += sep + `"` + c + `":{"status":"ok","checked_at":"2026-11-05T00:00:00Z"}`
	}
	caps += "}"
	p3exec(l.t, l.db, `INSERT INTO cloud_enforcement_binding (workspace_id, connector_id, account_id, role_arn, template_version, state,
		capabilities, consented_by, verified_at) VALUES (?, ?, '111111111111', 'arn:aws:iam::111111111111:role/AuthSecEnforcement-x', ?, 'verified', ?::jsonb, ?, now())`,
		g.ws, g.conn, awsdiscovery.EnforcementTemplateVersionV2, caps, g.author)
	reserved := int32(7)
	l.fake.mu.Lock()
	l.fake.lambda[tn.fnARN] = &reserved
	l.fake.mu.Unlock()
	return tn
}

// run drives the containment's job until it stops moving (each pass is one
// claimed job, as the worker runs it; retry delays are skipped).
func (l *acLab) run(ws, id uuid.UUID) services.AgentContainment {
	l.t.Helper()
	ctx := context.Background()
	for pass := 0; pass < 10; pass++ {
		p3exec(l.t, l.db, `UPDATE iga_gov_job SET run_after = now() - interval '1 hour'
			WHERE workspace_id = ? AND kind = 'agent_contain' AND status = 'queued'`, ws)
		ran, err := l.worker.RunOnce(ctx)
		if err != nil {
			l.t.Fatal(err)
		}
		if !ran {
			break
		}
	}
	v, err := l.svc.Get(ctx, ws, id)
	if err != nil {
		l.t.Fatal(err)
	}
	return v.AgentContainment
}

func govStatus(err error) int {
	var ge *services.GovError
	if errors.As(err, &ge) {
		return ge.Status
	}
	return 0
}

/* ----------------------------------- tests ---------------------------------- */

func TestAgentContainWorkloadLevelPerWorkspace(t *testing.T) {
	l := newACLab(t)
	a := l.tenant("p3-contain-a")
	ctx := context.Background()

	p, err := l.svc.Preview(ctx, a.g.ws, services.AgentContainPreviewRequest{IdentityID: a.identity.String(), WorkloadIDs: []string{a.lambda.String()}})
	if err != nil {
		t.Fatal(err)
	}
	if o := p.Level(agentcontain.LevelWorkload); o == nil || !o.Offered {
		t.Fatalf("workload level not offered: %+v", o)
	}
	var n int64
	l.db.Table("agent_containment").Where("workspace_id = ?", a.g.ws).Count(&n)
	if n != 0 {
		t.Fatal("a preview stores nothing")
	}

	c, err := l.svc.Contain(ctx, a.g.ws, a.g.author, services.AgentContainRequest{IdentityID: a.identity.String(),
		WorkloadIDs: []string{a.lambda.String()}, Level: agentcontain.LevelWorkload, Reason: "agent exfiltrating"})
	if err != nil {
		t.Fatal(err)
	}
	if c.State != agentcontain.StatePreviewed {
		t.Fatalf("a new containment is previewed (queued), got %s", c.State)
	}
	// One live containment per (identity, level).
	if _, err := l.svc.Contain(ctx, a.g.ws, a.g.author, services.AgentContainRequest{IdentityID: a.identity.String(),
		WorkloadIDs: []string{a.lambda.String()}, Level: agentcontain.LevelWorkload, Reason: "again"}); govStatus(err) != http.StatusConflict {
		t.Fatalf("a second live containment: %v, want 409", err)
	}

	got := l.run(a.g.ws, c.ID)
	if got.State != agentcontain.StateContained || got.ContainedAt == nil {
		t.Fatalf("after the job: %s (%s)", got.State, got.StateReason)
	}
	if v := l.fake.lambda[a.fnARN]; v == nil || *v != 0 {
		t.Fatalf("reserved concurrency %v, want 0", v)
	}
	v, _ := l.svc.Get(ctx, a.g.ws, c.ID)
	var before agentcontain.LambdaBefore
	if len(v.Steps) == 1 {
		_ = json.Unmarshal(v.Steps[0].Before, &before)
	}
	if len(v.Steps) != 1 || v.Steps[0].State != agentcontain.StepApplied || before.Reserved == nil || *before.Reserved != 7 {
		t.Fatalf("steps %+v: the before-state (7) is recorded", v.Steps)
	}

	// Behavioural verification: past the grace with no late event -> verified.
	l.clock = l.clock.Add(agentcontain.VerifyGrace + time.Minute)
	// "None seen" needs CloudTrail evidence past the cutoff: the connector's
	// event stream delivered an event after contained_at + grace.
	p3exec(t, l.db, `INSERT INTO agent_event_stream (connector_id, workspace_id, secret_hash, secret_prefix, last_event_time)
		VALUES (?, ?, ?, 'p3test', ?)`, a.g.conn, a.g.ws, strings.Repeat("a", 64), l.clock)
	got = l.run(a.g.ws, c.ID)
	if got.VerifiedAt == nil || got.Effective == nil || !*got.Effective {
		t.Fatalf("verified_at %v effective %v", got.VerifiedAt, got.Effective)
	}

	if _, err := l.svc.Release(ctx, a.g.ws, a.g.author, c.ID, services.AgentContainReleaseRequest{Reason: "fixed"}); err != nil {
		t.Fatal(err)
	}
	got = l.run(a.g.ws, c.ID)
	if got.State != agentcontain.StateReleased || got.ReleasedAt == nil {
		t.Fatalf("after release: %s (%s)", got.State, got.StateReason)
	}
	if v := l.fake.lambda[a.fnARN]; v == nil || *v != 7 {
		t.Fatalf("reserved concurrency after release %v, want exactly 7", v)
	}
	var events int64
	l.db.Table("iga_gov_event").Where("workspace_id = ? AND event LIKE 'containment.%'", a.g.ws).Count(&events)
	if events < 5 {
		t.Fatalf("only %d containment events written", events)
	}
}

func TestAgentContainIdentityLevelDeferredRevocationAndVerification(t *testing.T) {
	l := newACLab(t)
	a := l.tenant("p3-contain-id")
	ctx := context.Background()
	c, err := l.svc.Contain(ctx, a.g.ws, a.g.author, services.AgentContainRequest{IdentityID: a.identity.String(),
		Level: agentcontain.LevelIdentity, Reason: "compromised"})
	if err != nil {
		t.Fatal(err)
	}
	got := l.run(a.g.ws, c.ID)
	if got.State != agentcontain.StateContained {
		t.Fatalf("identity level: %s (%s)", got.State, got.StateReason)
	}
	name := "agent-" + a.g.ws.String()[:8]
	attached := 0
	for _, p := range l.fake.policies {
		if p.attached[name] && p.tags[agentcontain.TagContainment] == c.ID.String() {
			attached++
		}
	}
	if attached != 2 {
		t.Fatalf("deny-all and the session revocation attached: %d, want 2", attached)
	}

	// A successful call by the identity after the grace: not effective.
	ev := agentruntime.Event{EventID: "late-1", EventTime: got.ContainedAt.Add(10 * time.Minute), EventSource: "s3.amazonaws.com",
		EventName: "GetObject", EventType: "AwsApiCall", SessionIssuerARN: a.roleARN, SessionIssuerPrincipalID: a.roleID}
	sink := services.NewAgentContainVerifySink(l.db)
	if err := sink.Process(ctx, a.g.ws, a.g.conn, []agentruntime.Event{ev, ev}); err != nil {
		t.Fatal(err)
	}
	v, _ := l.svc.Get(ctx, a.g.ws, c.ID)
	if v.Effective == nil || *v.Effective || !strings.Contains(string(v.Verification), "late-1") {
		t.Fatalf("effective %v verification %s", v.Effective, v.Verification)
	}

	if _, err := l.svc.Release(ctx, a.g.ws, a.g.author, c.ID, services.AgentContainReleaseRequest{Reason: "rotated"}); err != nil {
		t.Fatal(err)
	}
	got = l.run(a.g.ws, c.ID)
	if got.State != agentcontain.StateReleased || got.PendingRestoreAt == nil {
		t.Fatalf("release: %s pending %v; the revocation is deferred", got.State, got.PendingRestoreAt)
	}
	if len(l.fake.policies) != 1 {
		t.Fatalf("after release only the revocation remains, got %d policies", len(l.fake.policies))
	}
	l.clock = got.PendingRestoreAt.Add(time.Minute)
	got = l.run(a.g.ws, c.ID)
	if got.PendingRestoreAt != nil || len(l.fake.policies) != 0 {
		t.Fatalf("deferred restore: pending %v, %d policies left", got.PendingRestoreAt, len(l.fake.policies))
	}
}

func TestAgentContainIsolation(t *testing.T) {
	l := newACLab(t)
	a := l.tenant("p3-contain-iso-a")
	b := l.tenant("p3-contain-iso-b")
	ctx := context.Background()

	c, err := l.svc.Contain(ctx, a.g.ws, a.g.author, services.AgentContainRequest{IdentityID: a.identity.String(),
		WorkloadIDs: []string{a.lambda.String()}, Level: agentcontain.LevelWorkload, Reason: "A's containment"})
	if err != nil {
		t.Fatal(err)
	}

	// B cannot preview or contain A's identity, nor name A's workload.
	if _, err := l.svc.Preview(ctx, b.g.ws, services.AgentContainPreviewRequest{IdentityID: a.identity.String()}); govStatus(err) != http.StatusNotFound {
		t.Errorf("B previewing A's identity: %v, want 404", err)
	}
	if _, err := l.svc.Contain(ctx, b.g.ws, b.g.author, services.AgentContainRequest{IdentityID: a.identity.String(),
		Level: agentcontain.LevelModel, Reason: "x"}); govStatus(err) != http.StatusNotFound {
		t.Errorf("B containing A's identity: %v, want 404", err)
	}
	if _, err := l.svc.Contain(ctx, b.g.ws, b.g.author, services.AgentContainRequest{IdentityID: b.identity.String(),
		WorkloadIDs: []string{a.lambda.String()}, Level: agentcontain.LevelWorkload, Reason: "x"}); govStatus(err) != http.StatusNotFound {
		t.Errorf("B naming A's workload: %v, want 404", err)
	}
	// B cannot read or release A's containment; its list does not show it.
	if _, err := l.svc.Get(ctx, b.g.ws, c.ID); govStatus(err) != http.StatusNotFound {
		t.Errorf("B reading A's containment: %v, want 404", err)
	}
	if _, err := l.svc.Release(ctx, b.g.ws, b.g.author, c.ID, services.AgentContainReleaseRequest{Reason: "x"}); govStatus(err) != http.StatusNotFound {
		t.Errorf("B releasing A's containment: %v, want 404", err)
	}
	list, err := l.svc.List(ctx, b.g.ws, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range list {
		if x.ID == c.ID {
			t.Fatal("B's list shows A's containment")
		}
	}
	// Nothing B attempted moved A's containment; B's events never touch it.
	before, err := l.svc.Get(ctx, a.g.ws, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if before.State != agentcontain.StatePreviewed || before.ReleaseReason != "" {
		t.Fatalf("A's containment after B's attempts: %s %q", before.State, before.ReleaseReason)
	}
	got := l.run(a.g.ws, c.ID)
	if got.State != agentcontain.StateContained {
		t.Fatalf("A's containment: %s (%s)", got.State, got.StateReason)
	}
	ev := agentruntime.Event{EventID: "b-late", EventTime: got.ContainedAt.Add(time.Hour), EventSource: "lambda.amazonaws.com",
		EventName: "Invoke", EventType: "AwsApiCall", SessionIssuerARN: a.roleARN, SessionIssuerPrincipalID: a.roleID, SessionName: "agent-" + a.g.ws.String()[:8]}
	if err := services.NewAgentContainVerifySink(l.db).Process(ctx, b.g.ws, b.g.conn, []agentruntime.Event{ev}); err != nil {
		t.Fatal(err)
	}
	after, _ := l.svc.Get(ctx, a.g.ws, c.ID)
	if after.Effective != nil && !*after.Effective {
		t.Fatal("B's events marked A's containment not effective")
	}
	for _, ws := range l.access.opened {
		if ws != a.g.ws {
			t.Fatalf("A's containment opened AWS for workspace %s", ws)
		}
	}
}
