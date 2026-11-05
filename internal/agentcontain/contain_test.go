package agentcontain

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/agentruntime"
	"github.com/authsec-ai/authsec/internal/igagov"
)

/* -------------------------------- fake AWS -------------------------------- */

type fakePolicy struct {
	doc      string
	tags     map[string]string
	attached map[string]bool // principal name -> attached
}

type fakeAWS struct {
	lambda      map[string]*int32 // function ARN -> reserved (nil = unreserved); absent = no function
	ecs         map[string]int32  // service ARN -> desired count
	scaling     map[string]*ScalableTarget
	policies    map[string]*fakePolicy
	keys        map[string]map[string]bool // user -> key -> active
	protected   map[string]bool            // target -> tagged authsec:protected (refused like the template's deny)
	calls       []string
	failNext    map[string]error
	putCountsAt map[string]int
}

func newFake() *fakeAWS {
	return &fakeAWS{lambda: map[string]*int32{}, ecs: map[string]int32{}, scaling: map[string]*ScalableTarget{},
		policies: map[string]*fakePolicy{}, keys: map[string]map[string]bool{}, protected: map[string]bool{},
		failNext: map[string]error{}, putCountsAt: map[string]int{}}
}

func (f *fakeAWS) call(op, target string) error {
	f.calls = append(f.calls, op+" "+target)
	if err, ok := f.failNext[op]; ok {
		delete(f.failNext, op)
		return err
	}
	if f.protected[target] && !strings.HasPrefix(op, "Get") && !strings.HasPrefix(op, "Describe") && !strings.HasPrefix(op, "Read") && !strings.HasPrefix(op, "List") {
		return ErrDenied
	}
	return nil
}

func i32(n int32) *int32 { return &n }

func (f *fakeAWS) GetFunctionConcurrency(_ context.Context, fn string) (*int32, error) {
	if err := f.call("GetFunctionConcurrency", fn); err != nil {
		return nil, err
	}
	n, ok := f.lambda[fn]
	if !ok {
		return nil, ErrNotFound
	}
	if n == nil {
		return nil, nil
	}
	v := *n
	return &v, nil
}

func (f *fakeAWS) PutFunctionConcurrency(_ context.Context, fn string, n int32) error {
	if err := f.call("PutFunctionConcurrency", fn); err != nil {
		return err
	}
	if _, ok := f.lambda[fn]; !ok {
		return ErrNotFound
	}
	f.lambda[fn] = i32(n)
	f.putCountsAt[fn]++
	return nil
}

func (f *fakeAWS) DeleteFunctionConcurrency(_ context.Context, fn string) error {
	if err := f.call("DeleteFunctionConcurrency", fn); err != nil {
		return err
	}
	if _, ok := f.lambda[fn]; !ok {
		return ErrNotFound
	}
	f.lambda[fn] = nil
	return nil
}

func (f *fakeAWS) DescribeService(_ context.Context, cl, svc string) (*ECSService, error) {
	if err := f.call("DescribeService", svc); err != nil {
		return nil, err
	}
	n, ok := f.ecs[svc]
	if !ok {
		return nil, nil
	}
	return &ECSService{ClusterARN: cl, ServiceARN: svc, DesiredCount: n}, nil
}

func (f *fakeAWS) SetServiceDesiredCount(_ context.Context, cl, svc string, n int32) error {
	if err := f.call("UpdateService", svc); err != nil {
		return err
	}
	if _, ok := f.ecs[svc]; !ok {
		return ErrNotFound
	}
	f.ecs[svc] = n
	return nil
}

func (f *fakeAWS) DescribeScalableTarget(_ context.Context, region, id string) (*ScalableTarget, error) {
	if err := f.call("DescribeScalableTargets", id); err != nil {
		return nil, err
	}
	t, ok := f.scaling[id]
	if !ok {
		return nil, nil
	}
	c := *t
	return &c, nil
}

func (f *fakeAWS) SetScalableTargetSuspended(_ context.Context, region, id string, s Suspended) error {
	if err := f.call("RegisterScalableTarget", id); err != nil {
		return err
	}
	t, ok := f.scaling[id]
	if !ok {
		return ErrNotFound
	}
	t.Suspended = s
	return nil
}

func (f *fakeAWS) CreatePolicy(_ context.Context, name, doc string, tags map[string]string) (string, error) {
	arn := "arn:aws:iam::111111111111:policy/authsec/" + name
	if err := f.call("CreatePolicy", arn); err != nil {
		return "", err
	}
	if _, ok := f.policies[arn]; ok {
		return "", errors.New("EntityAlreadyExists")
	}
	f.policies[arn] = &fakePolicy{doc: doc, tags: tags, attached: map[string]bool{}}
	return arn, nil
}

func (f *fakeAWS) DeletePolicy(_ context.Context, arn string) error {
	if err := f.call("DeletePolicy", arn); err != nil {
		return err
	}
	if _, ok := f.policies[arn]; !ok {
		return ErrNotFound
	}
	delete(f.policies, arn)
	return nil
}

func (f *fakeAWS) AttachPolicy(_ context.Context, p Principal, arn string) error {
	if err := f.call("Attach", p.Name); err != nil {
		return err
	}
	pol, ok := f.policies[arn]
	if !ok {
		return ErrNotFound
	}
	pol.attached[p.Name] = true
	return nil
}

func (f *fakeAWS) DetachPolicy(_ context.Context, p Principal, arn string) error {
	if err := f.call("Detach", p.Name); err != nil {
		return err
	}
	pol, ok := f.policies[arn]
	if !ok {
		return ErrNotFound
	}
	delete(pol.attached, p.Name)
	return nil
}

func (f *fakeAWS) ReadPolicy(_ context.Context, arn string, p Principal) (*PolicyRead, error) {
	if err := f.call("ReadPolicy", arn); err != nil {
		return nil, err
	}
	pol, ok := f.policies[arn]
	if !ok {
		return &PolicyRead{}, nil
	}
	others := 0
	for n := range pol.attached {
		if n != p.Name {
			others++
		}
	}
	return &PolicyRead{Exists: true, Tags: pol.tags, DocumentHash: igagov.ContentHash([]byte(pol.doc)),
		AttachedToPrincipal: pol.attached[p.Name], OtherEntities: others}, nil
}

func (f *fakeAWS) ListAccessKeys(_ context.Context, user string) ([]AccessKey, error) {
	if err := f.call("ListAccessKeys", user); err != nil {
		return nil, err
	}
	var out []AccessKey
	for id, a := range f.keys[user] {
		out = append(out, AccessKey{ID: id, Active: a})
	}
	return out, nil
}

func (f *fakeAWS) SetAccessKeyStatus(_ context.Context, user, key string, active bool) error {
	if err := f.call("UpdateAccessKey", user); err != nil {
		return err
	}
	if _, ok := f.keys[user][key]; !ok {
		return ErrNotFound
	}
	f.keys[user][key] = active
	return nil
}

/* -------------------------------- fixtures -------------------------------- */

const (
	fnA   = "arn:aws:lambda:us-east-1:111111111111:function:agent-a"
	fnB   = "arn:aws:lambda:us-east-1:111111111111:function:agent-b"
	clARN = "arn:aws:ecs:us-east-1:111111111111:cluster/prod"
	svcA  = "arn:aws:ecs:us-east-1:111111111111:service/prod/agent-svc"
	tdA   = "arn:aws:ecs:us-east-1:111111111111:task-definition/agent-task:7"
	scID  = "service/prod/agent-svc"
)

func roleSubject() Subject {
	return Subject{IdentityID: uuid.New(), Kind: IdentityRole, ARN: "arn:aws:iam::111111111111:role/agent-role", Name: "agent-role",
		UniqueID: "AROAEXAMPLEROLE00001", Path: "/", AccountID: "111111111111", Partition: "aws", Label: agentruntime.LabelSuggestedAgent}
}

func userSubject() Subject {
	return Subject{IdentityID: uuid.New(), Kind: IdentityUser, ARN: "arn:aws:iam::111111111111:user/bot", Name: "bot",
		UniqueID: "AIDAEXAMPLEUSER00001", Path: "/", AccountID: "111111111111", Partition: "aws"}
}

type world struct {
	lambdaA, lambdaB, ecsW, ec2W, eksW Workload
}

func newWorld() world {
	return world{
		lambdaA: Workload{ID: uuid.New(), Kind: WorkloadLambda, NativeID: fnA, Name: "agent-a", Region: "us-east-1", Via: "runs_as", EventSourceMappings: 1},
		lambdaB: Workload{ID: uuid.New(), Kind: WorkloadLambda, NativeID: fnB, Name: "agent-b", Region: "us-east-1", Via: "runs_as"},
		ecsW: Workload{ID: uuid.New(), Kind: WorkloadECSTaskDef, NativeID: tdA, Name: "agent-task", Region: "us-east-1", Via: "runs_as",
			ECSServicesRead: true, ECSServices: []ECSService{{ClusterARN: clARN, ServiceARN: svcA, TaskDefinition: tdA, DesiredCount: 3}}},
		ec2W: Workload{ID: uuid.New(), Kind: WorkloadEC2, NativeID: "i-0abc", Name: "i-0abc", Region: "us-east-1", Via: "runs_as"},
		eksW: Workload{ID: uuid.New(), Kind: WorkloadEKSPod, NativeID: "system:serviceaccount:ai:agent", Name: "ai/agent", Via: "irsa"},
	}
}

func fullCap() Capability { return Capability{Binding: true, Workload: true} }

func hasCode(rs []Refusal, code string) bool {
	for _, r := range rs {
		if r.Code == code {
			return true
		}
	}
	return false
}

func hasEffect(es []SideEffect, code string) bool {
	for _, e := range es {
		if e.Code == code {
			return true
		}
	}
	return false
}

/* --------------------------------- preview -------------------------------- */

func TestPreviewBlastRadiusAndSideEffects(t *testing.T) {
	w := newWorld()
	p := BuildPreview(PreviewInput{Subject: roleSubject(), Workloads: []Workload{w.lambdaA, w.lambdaB, w.ecsW},
		Selected: []uuid.UUID{w.lambdaA.ID, w.ecsW.ID}, Cap: fullCap(),
		Usage: []ServiceUse{{Service: "s3", Source: "service_last_accessed"}, {Service: "bedrock", Source: "cloudtrail", Calls: 12}}})
	if !p.SharedRole {
		t.Fatal("three workloads on one role must be a shared role")
	}
	wl := p.Level(LevelWorkload)
	if !wl.Offered {
		t.Fatalf("workload level refused: %+v", wl.Refusals)
	}
	if len(wl.Stops) != 2 || len(wl.AlsoStops) != 0 {
		t.Fatalf("workload level stops %v also %v; want the two selected only", wl.Stops, wl.AlsoStops)
	}
	for _, code := range []string{EffectEventSourceMappings, EffectRunTaskNotStopped, EffectAutoScalingSuspend} {
		if !hasEffect(wl.SideEffects, code) {
			t.Errorf("workload level does not state side effect %s: %+v", code, wl.SideEffects)
		}
	}
	kinds := []string{}
	for _, s := range wl.Steps {
		kinds = append(kinds, s.Kind)
	}
	if strings.Join(kinds, ",") != "lambda_concurrency,ecs_autoscaling,ecs_desired" {
		t.Fatalf("workload steps %v; scaling must be suspended before the desired count is set", kinds)
	}
	id := p.Level(LevelIdentity)
	if !id.Offered || len(id.Stops) != 3 || len(id.AlsoStops) != 1 || id.AlsoStops[0].ID != w.lambdaB.ID {
		t.Fatalf("identity level: offered=%v stops=%v also=%v; want every workload, agent-b as the shared-role extra", id.Offered, id.Stops, id.AlsoStops)
	}
	if !hasEffect(id.SideEffects, EffectSharedRole) || !hasEffect(id.SideEffects, EffectSessionsRevoked) {
		t.Errorf("identity level side effects %+v", id.SideEffects)
	}
	m := p.Level(LevelModel)
	if !m.Offered || !hasEffect(m.SideEffects, EffectModelOnly) || len(m.Steps) != 1 || m.Steps[0].Kind != StepIAMPolicy {
		t.Errorf("model level: %+v", m)
	}
	if len(p.RecentServices) != 2 {
		t.Errorf("recent services %v", p.RecentServices)
	}
}

func TestPreviewRefusesServiceLinkedRole(t *testing.T) {
	s := roleSubject()
	s.ARN = "arn:aws:iam::111111111111:role/aws-service-role/ecs.amazonaws.com/AWSServiceRoleForECS"
	s.Path = "/aws-service-role/ecs.amazonaws.com/"
	w := newWorld()
	p := BuildPreview(PreviewInput{Subject: s, Workloads: []Workload{w.lambdaA}, Selected: []uuid.UUID{w.lambdaA.ID}, Cap: fullCap()})
	for _, l := range []string{LevelIdentity, LevelModel} {
		o := p.Level(l)
		if o.Offered || !hasCode(o.Refusals, RefuseServiceLinkedRole) {
			t.Errorf("%s level on a service-linked role: offered=%v refusals=%+v", l, o.Offered, o.Refusals)
		}
	}
	if o := p.Level(LevelWorkload); !o.Offered {
		t.Errorf("the workload level changes the workload, not the SLR; it should be offered: %+v", o.Refusals)
	}
}

func TestPreviewRefusesProtected(t *testing.T) {
	s := roleSubject()
	s.Tags = map[string]string{"authsec:protected": "true"}
	w := newWorld()
	w.lambdaA.Tags = map[string]string{"authsec:protected": "TRUE"}
	p := BuildPreview(PreviewInput{Subject: s, Workloads: []Workload{w.lambdaA}, Selected: []uuid.UUID{w.lambdaA.ID}, Cap: fullCap()})
	for _, l := range Levels {
		o := p.Level(l)
		if o.Offered || !hasCode(o.Refusals, RefuseProtected) {
			t.Errorf("%s level on protected resources: offered=%v refusals=%+v", l, o.Offered, o.Refusals)
		}
	}
	// A protected ECS service is refused too.
	w2 := newWorld()
	w2.ecsW.ECSServices[0].Tags = map[string]string{"authsec:protected": "true"}
	p = BuildPreview(PreviewInput{Subject: roleSubject(), Workloads: []Workload{w2.ecsW}, Selected: []uuid.UUID{w2.ecsW.ID}, Cap: fullCap()})
	if o := p.Level(LevelWorkload); o.Offered || !hasCode(o.Refusals, RefuseProtected) {
		t.Errorf("protected ECS service: %+v", o)
	}
}

func TestPreviewWorkloadLevelNotOfferedForEC2AndEKS(t *testing.T) {
	w := newWorld()
	for _, x := range []Workload{w.ec2W, w.eksW} {
		p := BuildPreview(PreviewInput{Subject: roleSubject(), Workloads: []Workload{x}, Selected: []uuid.UUID{x.ID}, Cap: fullCap()})
		o := p.Level(LevelWorkload)
		if o.Offered || !hasCode(o.Refusals, RefuseWorkloadNotOffered) {
			t.Errorf("%s: workload level offered=%v refusals=%+v", x.Kind, o.Offered, o.Refusals)
		}
		if !p.Level(LevelIdentity).Offered {
			t.Errorf("%s: the identity level must stay offered", x.Kind)
		}
	}
}

func TestPreviewWorkloadUnavailableWithoutParameter(t *testing.T) {
	w := newWorld()
	cap := Capability{Binding: true, Workload: false, WorkloadReason: "workload_containment: denied (AccessDeniedException)"}
	p := BuildPreview(PreviewInput{Subject: roleSubject(), Workloads: []Workload{w.lambdaA}, Selected: []uuid.UUID{w.lambdaA.ID}, Cap: cap})
	o := p.Level(LevelWorkload)
	if o.Offered || !hasCode(o.Refusals, RefuseWorkloadUnavailable) || !strings.Contains(o.Refusals[0].Message, "denied") {
		t.Fatalf("workload level without the parameter: %+v", o)
	}
	if !p.Level(LevelIdentity).Offered || !p.Level(LevelModel).Offered {
		t.Fatal("identity and model levels need no new permission (Q4)")
	}
	// An IAM user needs the parameter at every level.
	p = BuildPreview(PreviewInput{Subject: userSubject(), Cap: cap})
	for _, l := range []string{LevelIdentity, LevelModel} {
		if o := p.Level(l); o.Offered || !hasCode(o.Refusals, RefuseUserNeedsParameter) {
			t.Errorf("IAM user %s level without the parameter: %+v", l, o)
		}
	}
}

func TestPreviewECSWithoutService(t *testing.T) {
	w := newWorld()
	w.ecsW.ECSServices = nil
	p := BuildPreview(PreviewInput{Subject: roleSubject(), Workloads: []Workload{w.ecsW}, Selected: []uuid.UUID{w.ecsW.ID}, Cap: fullCap()})
	if o := p.Level(LevelWorkload); o.Offered || !hasCode(o.Refusals, RefuseNoECSService) {
		t.Fatalf("ECS task definition with no service: %+v", o)
	}
}

/* ---------------------------------- engine --------------------------------- */

func runOf(s Subject, level string) Run {
	return Run{ContainmentID: uuid.MustParse("0b9c6c2e-8f7d-4f56-9a3c-1d2e3f405162"), WorkspaceRef: "ws-test", Level: level, Subject: s,
		Cutoff: time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC)}
}

// contain runs Before (write-ahead) and Apply for every step, as the job does.
func contain(t *testing.T, e *Engine, steps []Step) []Step {
	t.Helper()
	ctx := context.Background()
	for i := range steps {
		st := &steps[i]
		if len(st.Before) == 0 {
			skip, err := e.Before(ctx, st)
			if err != nil {
				t.Fatalf("before %s %s: %v", st.Kind, st.Target, err)
			}
			if skip {
				st.State = StepSkipped
				continue
			}
		}
		st.State = StepPending
		if err := e.Apply(ctx, st); err != nil {
			var se *StepError
			if errors.As(err, &se) {
				st.State, st.Error = StepFailed, se.Error()
				continue
			}
			t.Fatalf("apply %s %s: %v", st.Kind, st.Target, err)
		}
		st.State = StepApplied
	}
	return steps
}

func release(t *testing.T, e *Engine, steps []Step, now time.Time) []Step {
	t.Helper()
	for i := len(steps) - 1; i >= 0; i-- {
		st := &steps[i]
		if st.RestoreAfter != nil && now.Before(*st.RestoreAfter) {
			continue
		}
		if err := e.Restore(context.Background(), st); err != nil {
			t.Fatalf("restore %s %s: %v", st.Kind, st.Target, err)
		}
		if st.State != StepSkipped && st.State != StepFailed {
			st.State = StepRestored
		}
	}
	return steps
}

func TestWorkloadLevelContainAndExactRelease(t *testing.T) {
	f := newFake()
	f.lambda[fnA] = i32(5) // reserved 5 before
	f.lambda[fnB] = nil    // unreserved before
	f.ecs[svcA] = 3
	f.scaling[scID] = &ScalableTarget{Suspended: Suspended{Scheduled: true}, MinCapacity: 1, MaxCapacity: 10}
	w := newWorld()
	wB := w.lambdaB
	p := BuildPreview(PreviewInput{Subject: roleSubject(), Workloads: []Workload{w.lambdaA, wB, w.ecsW},
		Selected: []uuid.UUID{w.lambdaA.ID, wB.ID, w.ecsW.ID}, Cap: fullCap()})
	e := &Engine{AWS: f, Run: runOf(roleSubject(), LevelWorkload)}
	steps := contain(t, e, WorkloadSteps(p.Level(LevelWorkload)))
	if got := Outcome(steps); got != StateContained {
		t.Fatalf("outcome %s: %+v", got, steps)
	}
	if *f.lambda[fnA] != 0 || *f.lambda[fnB] != 0 || f.ecs[svcA] != 0 || !f.scaling[scID].Suspended.All() {
		t.Fatalf("not contained: %v %v %v %+v", f.lambda[fnA], f.lambda[fnB], f.ecs[svcA], f.scaling[scID])
	}
	// Idempotent re-run: a pending step is applied again, its before kept.
	before := string(steps[0].Before)
	steps[0].State = StepPending
	if err := e.Apply(context.Background(), &steps[0]); err != nil {
		t.Fatal(err)
	}
	if string(steps[0].Before) != before {
		t.Fatal("a re-run must never re-read the before-state")
	}
	steps = release(t, e, steps, time.Now())
	if f.lambda[fnA] == nil || *f.lambda[fnA] != 5 {
		t.Errorf("agent-a reserved concurrency after release: %v, want 5", f.lambda[fnA])
	}
	if f.lambda[fnB] != nil {
		t.Errorf("agent-b must be unreserved again (DeleteFunctionConcurrency), got %v", *f.lambda[fnB])
	}
	if f.ecs[svcA] != 3 {
		t.Errorf("desired count after release %d, want 3", f.ecs[svcA])
	}
	if got := f.scaling[scID].Suspended; got != (Suspended{Scheduled: true}) {
		t.Errorf("scaling after release %+v, want exactly the recorded state (scheduled suspended only)", got)
	}
	if done, _ := ReleaseDone(steps, time.Now()); !done {
		t.Errorf("release not done: %+v", steps)
	}
}

func TestWorkloadLevelProtectedRefusedByAWS(t *testing.T) {
	f := newFake()
	f.lambda[fnA] = nil
	f.protected[fnA] = true // the template's deny on authsec:protected=true
	w := newWorld()
	p := BuildPreview(PreviewInput{Subject: roleSubject(), Workloads: []Workload{w.lambdaA}, Selected: []uuid.UUID{w.lambdaA.ID}, Cap: fullCap()})
	e := &Engine{AWS: f, Run: runOf(roleSubject(), LevelWorkload)}
	steps := contain(t, e, WorkloadSteps(p.Level(LevelWorkload)))
	if steps[0].State != StepFailed || !strings.Contains(steps[0].Error, "access_denied") {
		t.Fatalf("a refused write must fail the step with the reason: %+v", steps[0])
	}
	if Outcome(steps) != StateFailed {
		t.Fatalf("outcome %s", Outcome(steps))
	}
}

func TestIdentityLevelRoleContainAndRelease(t *testing.T) {
	f := newFake()
	s := roleSubject()
	r := runOf(s, LevelIdentity)
	e := &Engine{AWS: f, Run: r}
	steps := contain(t, e, r.IAMSteps())
	if Outcome(steps) != StateContained || len(steps) != 2 {
		t.Fatalf("outcome %s steps %+v", Outcome(steps), steps)
	}
	deny := f.policies[steps[0].Target]
	if deny == nil || !deny.attached[s.Name] || !strings.Contains(deny.doc, SidDenyAll) {
		t.Fatalf("deny-all policy not attached: %+v", deny)
	}
	if !strings.Contains(steps[0].Target, ":policy/authsec/AuthSecContain-"+s.UniqueID+"-0b9c6c2e") {
		t.Errorf("policy name %s", steps[0].Target)
	}
	if deny.tags[TagContainment] != r.ContainmentID.String() || deny.tags[igagov.TagManagedBy] != "authsec" {
		t.Errorf("policy tags %v", deny.tags)
	}
	rev := f.policies[steps[1].Target]
	if rev == nil || !rev.attached[s.Name] || !strings.Contains(rev.doc, "aws:TokenIssueTime") || !strings.Contains(rev.doc, "2026-11-05T10:00:00Z") {
		t.Fatalf("session revocation not attached with the request-time cutoff: %+v", rev)
	}
	// Re-run: nothing is created twice.
	creates := 0
	steps[0].State = StepPending
	if err := e.Apply(context.Background(), &steps[0]); err != nil {
		t.Fatal(err)
	}
	for _, c := range f.calls {
		if strings.HasPrefix(c, "CreatePolicy") {
			creates++
		}
	}
	if creates != 2 {
		t.Errorf("CreatePolicy called %d times, want 2 (one per policy)", creates)
	}
	// Release now: the deny-all goes, the revocation stays until its time.
	now := r.Cutoff.Add(time.Hour)
	steps = release(t, e, steps, now)
	if _, ok := f.policies[steps[0].Target]; ok {
		t.Error("the deny-all policy must be detached and deleted at release")
	}
	if _, ok := f.policies[steps[1].Target]; !ok {
		t.Error("the session revocation is deferred (P3-3)")
	}
	done, next := ReleaseDone(steps, now)
	if !done || next == nil || !next.Equal(r.Cutoff.Add(13*time.Hour)) {
		t.Fatalf("release done=%v next=%v; want done with the revocation due 13 h after the cutoff", done, next)
	}
	steps = release(t, e, steps, r.Cutoff.Add(14*time.Hour))
	if _, ok := f.policies[steps[1].Target]; ok {
		t.Error("the revocation must be removed once due")
	}
}

func TestIdentityLevelUserKeysRestoredExactly(t *testing.T) {
	f := newFake()
	s := userSubject()
	f.keys[s.Name] = map[string]bool{"AKIAACTIVE1": true, "AKIAINACTIVE": false}
	r := runOf(s, LevelIdentity)
	e := &Engine{AWS: f, Run: r}
	keySteps, err := AccessKeySteps(context.Background(), f, s.Name)
	if err != nil {
		t.Fatal(err)
	}
	if len(keySteps) != 1 || keySteps[0].Target != "AKIAACTIVE1" {
		t.Fatalf("key steps %+v: only Active keys are recorded", keySteps)
	}
	iam := r.IAMSteps()
	if len(iam) != 1 {
		t.Fatalf("an IAM user has no session revocation step (P3-4): %+v", iam)
	}
	steps := contain(t, e, append(iam, keySteps...))
	if Outcome(steps) != StateContained || f.keys[s.Name]["AKIAACTIVE1"] {
		t.Fatalf("user not contained: %s %v", Outcome(steps), f.keys)
	}
	if !f.policies[steps[0].Target].attached[s.Name] {
		t.Fatal("deny-all not attached to the user")
	}
	release(t, e, steps, time.Now())
	if !f.keys[s.Name]["AKIAACTIVE1"] || f.keys[s.Name]["AKIAINACTIVE"] {
		t.Fatalf("release must reactivate only the keys it deactivated: %v", f.keys[s.Name])
	}
}

func TestModelLevel(t *testing.T) {
	f := newFake()
	r := runOf(roleSubject(), LevelModel)
	e := &Engine{AWS: f, Run: r}
	steps := contain(t, e, r.IAMSteps())
	if len(steps) != 1 || Outcome(steps) != StateContained {
		t.Fatalf("model level: %+v", steps)
	}
	doc := f.policies[steps[0].Target].doc
	var d struct {
		Statement []struct {
			Effect string
			Action []string
		}
	}
	if err := json.Unmarshal([]byte(doc), &d); err != nil || d.Statement[0].Effect != "Deny" {
		t.Fatalf("model document %s: %v", doc, err)
	}
	if strings.Join(d.Statement[0].Action, ",") != "bedrock-agentcore:InvokeAgentRuntime,bedrock-agentcore:InvokeGateway,bedrock-mantle:*,bedrock:*" {
		t.Errorf("model actions %v", d.Statement[0].Action)
	}
	release(t, e, steps, time.Now())
	if len(f.policies) != 0 {
		t.Errorf("release left policies: %v", f.policies)
	}
}

func TestPolicyOwnedElsewhereRefused(t *testing.T) {
	f := newFake()
	r := runOf(roleSubject(), LevelModel)
	arn := r.IAMSteps()[0].Target
	f.policies[arn] = &fakePolicy{doc: "{}", tags: map[string]string{}, attached: map[string]bool{}}
	e := &Engine{AWS: f, Run: r}
	st := r.IAMSteps()[0]
	if _, err := e.Before(context.Background(), &st); err == nil {
		t.Fatal("a policy AuthSec did not write must refuse the step")
	}
}

func TestPartialOutcome(t *testing.T) {
	steps := []Step{{State: StepApplied}, {State: StepFailed}}
	if Outcome(steps) != StatePartial {
		t.Fatal("applied + failed is partially_contained")
	}
	if Outcome([]Step{{State: StepApplied}, {State: StepPending}}) != StateContaining {
		t.Fatal("a pending step keeps it containing")
	}
	if Outcome([]Step{{State: StepSkipped}}) != StateFailed {
		t.Fatal("nothing applied is failed")
	}
}

/* ------------------------------- verification ------------------------------ */

func TestBehaviouralVerification(t *testing.T) {
	at := time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC)
	s := roleSubject()
	ev := func(id string, tm time.Time, src, name, sess, errCode string) agentruntime.Event {
		return agentruntime.Event{EventID: id, EventTime: tm, EventSource: src, EventName: name, EventType: "AwsApiCall",
			SessionIssuerARN: s.ARN, SessionIssuerPrincipalID: s.UniqueID, SessionName: sess, ErrorCode: errCode}
	}
	events := []agentruntime.Event{
		ev("e1", at.Add(2*time.Minute), "s3.amazonaws.com", "GetObject", "agent-a", ""),            // inside the grace
		ev("e2", at.Add(10*time.Minute), "s3.amazonaws.com", "GetObject", "agent-b", ""),           // after: identity level not effective
		ev("e3", at.Add(11*time.Minute), "bedrock.amazonaws.com", "Converse", "agent-a", ""),       // model call after
		ev("e4", at.Add(12*time.Minute), "bedrock.amazonaws.com", "Converse", "x", "AccessDenied"), // refused: fine
	}
	other := events[1]
	other.SessionIssuerPrincipalID = "AROARECREATED0000001"
	other.EventID = "e5"
	events = append(events, other) // a recreated role with the same ARN is not this identity

	id := Late(Contained{Level: LevelIdentity, IdentityARN: s.ARN, UniqueID: s.UniqueID, ContainedAt: at}, events)
	if len(id) != 2 || id[0].EventID != "e2" || id[1].EventID != "e3" {
		t.Fatalf("identity level late events %+v", id)
	}
	m := Late(Contained{Level: LevelModel, IdentityARN: s.ARN, UniqueID: s.UniqueID, ContainedAt: at}, events)
	if len(m) != 1 || m[0].EventID != "e3" {
		t.Fatalf("model level counts model calls only: %+v", m)
	}
	wl := Late(Contained{Level: LevelWorkload, IdentityARN: s.ARN, UniqueID: s.UniqueID, ContainedAt: at, SessionNames: []string{"agent-a"}}, events)
	if len(wl) != 1 || wl[0].EventID != "e3" || !wl[0].Weak {
		t.Fatalf("workload level on a shared role matches the contained function's session only, weakly: %+v", wl)
	}
	none := Late(Contained{Level: LevelIdentity, IdentityARN: s.ARN, ContainedAt: at.Add(time.Hour)}, events)
	if len(none) != 0 {
		t.Fatalf("no call after the grace: %+v", none)
	}
	merged, changed := MergeLate(id, id)
	if changed || len(merged) != 2 {
		t.Fatal("the same event from the poller and the stream is recorded once")
	}
}
