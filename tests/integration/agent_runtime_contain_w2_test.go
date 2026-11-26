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

	"github.com/aws/smithy-go"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/agentcontain"
	"github.com/authsec-ai/authsec/internal/agentruntime"
	"github.com/authsec-ai/authsec/internal/awsbroker"
	"github.com/authsec-ai/authsec/internal/azure"
	"github.com/authsec-ai/authsec/internal/k8sgraph"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
)

// SecOps W2 (SPEC-secops-backend-upgrade.md P4, P13, P2/P3 holds): proof
// states, the new stop levels, holds released by a second person, narrowing,
// probes, the gateway deny list -- and isolation: workspace B can neither
// hold, release, approve, probe nor narrow workspace A's containment (404),
// and B's gateway deny list never shows A's stops. Needs IGA_TEST_DSN.

// w2Member is an active member of g's workspace holding perms.
func w2Member(t *testing.T, g *p3Gov, name string, perms ...string) uuid.UUID {
	t.Helper()
	u, _ := g.member(name+"-"+uuid.NewString()[:8]+"@w2.test", name, "active")
	role := g.roles[len(g.roles)-1]
	for _, p := range perms {
		p3exec(t, g.db, `INSERT INTO role_permissions (role_id, permission_id)
			SELECT ?, id FROM permissions WHERE full_permission_string = ? AND workspace_id IS NULL`, role, p)
	}
	t.Cleanup(func() { g.db.Exec(`DELETE FROM role_permissions WHERE role_id = ?`, role) })
	return u
}

// runOnly drives one containment's job (l.run claims whichever job of the
// workspace is first, and a live one with a long retry can starve another).
func (l *acLab) runOnly(ws, id uuid.UUID) services.AgentContainment {
	l.t.Helper()
	for pass := 0; pass < 10; pass++ {
		p3exec(l.t, l.db, `UPDATE iga_gov_job SET run_after = CASE WHEN subject_id = ? THEN now() - interval '1 hour' ELSE now() + interval '1 day' END
			WHERE workspace_id = ? AND kind = 'agent_contain' AND status = 'queued'`, id, ws)
		ran, err := l.worker.RunOnce(context.Background())
		if err != nil {
			l.t.Fatal(err)
		}
		if !ran {
			break
		}
	}
	return l.get(ws, id).AgentContainment
}

func (l *acLab) get(ws, id uuid.UUID) *services.AgentContainmentView {
	l.t.Helper()
	v, err := l.svc.Get(context.Background(), ws, id)
	if err != nil {
		l.t.Fatal(err)
	}
	return v
}

func (l *acLab) refusal(ws uuid.UUID, id uuid.UUID, policy, eventID string, at time.Time, src, name string) {
	l.t.Helper()
	v := l.get(ws, id)
	ev := agentruntime.Event{EventID: eventID, EventTime: at, EventSource: src, EventName: name, EventType: "AwsApiCall",
		SessionIssuerARN: v.IdentityARN, SessionIssuerPrincipalID: v.UniqueID, ErrorCode: "AccessDenied", AuthorizationDenied: true,
		ErrorMessage: "User: x is not authorized to perform: y with an explicit deny in an identity-based policy: arn:aws:iam::111111111111:policy/authsec/" + policy}
	if err := services.NewAgentContainVerifySink(l.db).Process(context.Background(), ws, v.ConnectorID, []agentruntime.Event{ev}); err != nil {
		l.t.Fatal(err)
	}
}

/* ------------------------------- proof states ------------------------------ */

func TestContainW2ProofStates(t *testing.T) {
	l := newACLab(t)
	a := l.tenant("w2-proof")
	ctx := context.Background()
	c, err := l.svc.Contain(ctx, a.g.ws, a.g.author, services.AgentContainRequest{IdentityID: a.identity.String(),
		Level: agentcontain.LevelIdentity, Reason: "compromised"})
	if err != nil {
		t.Fatal(err)
	}
	if c.ProofState != agentcontain.ProofRequested || c.TokenExpiryAt == nil || !c.TokenExpiryAt.Equal(c.CreatedAt.Add(13*time.Hour)) {
		t.Fatalf("requested, token expiry 13h after the cutoff: %s %v", c.ProofState, c.TokenExpiryAt)
	}
	got := l.run(a.g.ws, c.ID)
	if got.State != agentcontain.StateContained || got.ProofState != agentcontain.ProofApplied {
		t.Fatalf("contained and applied: %s %s", got.State, got.ProofState)
	}
	policy := agentcontain.ContainPolicyName(a.roleID, c.ID)
	l.refusal(a.g.ws, c.ID, policy, "deny-w2", got.ContainedAt.Add(8*time.Minute), "s3.amazonaws.com", "GetObject")
	v := l.get(a.g.ws, c.ID)
	if v.ProofState != agentcontain.ProofProven || v.ProvenByEventID == nil || *v.ProvenByEventID != "deny-w2" || v.SkewMs == nil || *v.SkewMs < 0 {
		t.Fatalf("proven by the event with its skew: %s %v %v", v.ProofState, v.ProvenByEventID, v.SkewMs)
	}
	// No other approver: the release applies alone (break-glass).
	out, err := l.svc.Release(ctx, a.g.ws, a.g.author, c.ID, services.AgentContainReleaseRequest{Reason: "rotated"})
	if err != nil {
		t.Fatal(err)
	}
	if !out.Applied || !out.Request.BreakGlass || out.Request.ReviewDueAt == nil {
		t.Fatalf("break-glass release: %+v", out.Request)
	}
	got = l.run(a.g.ws, c.ID)
	if got.State != agentcontain.StateReleased || got.ProofState != agentcontain.ProofKept {
		t.Fatalf("released with the revocation kept: %s %s", got.State, got.ProofState)
	}
	var n int64
	l.db.Table("iga_gov_event").Where("workspace_id = ? AND event = ?", a.g.ws, services.GovEventContainmentBreakGlass).Count(&n)
	if n != 1 {
		t.Fatalf("break-glass is recorded once: %d", n)
	}
}

/* ---------------------------------- holds ---------------------------------- */

func TestContainW2HoldsNeedASecondPerson(t *testing.T) {
	l := newACLab(t)
	a := l.tenant("w2-holds")
	ctx := context.Background()
	approver := w2Member(t, a.g, "Avery Approver", "governance:approve")
	case1, case2 := uuid.New(), uuid.New()
	c, err := l.svc.Contain(ctx, a.g.ws, a.g.author, services.AgentContainRequest{IdentityID: a.identity.String(),
		Level: agentcontain.LevelModel, Reason: "suspicious model use", CaseID: case1.String()})
	if err != nil {
		t.Fatal(err)
	}
	l.run(a.g.ws, c.ID)
	if _, err := l.svc.AddHold(ctx, a.g.ws, a.g.author, c.ID, services.AgentContainHoldRequest{CaseID: case2.String()}); err != nil {
		t.Fatal(err)
	}
	if _, err := l.svc.AddHold(ctx, a.g.ws, a.g.author, c.ID, services.AgentContainHoldRequest{CaseID: case2.String()}); govCode(err) != services.GovCodeHoldExists {
		t.Fatalf("a case holds once: %v", err)
	}
	if _, err := l.svc.Release(ctx, a.g.ws, a.g.author, c.ID, services.AgentContainReleaseRequest{Reason: "done"}); govCode(err) != services.GovCodeHeldByCases {
		t.Fatalf("the plain release is refused while cases hold it: %v", err)
	}
	r1, err := l.svc.ReleaseHold(ctx, a.g.ws, a.g.author, c.ID, case1, services.AgentContainReleaseRequest{Reason: "case 1 closed"})
	if err != nil {
		t.Fatal(err)
	}
	if r1.Applied || r1.Request.State != services.ReleaseRequestPending {
		t.Fatalf("another approver exists: the request waits: %+v", r1.Request)
	}
	if _, err := l.svc.ReleaseHold(ctx, a.g.ws, a.g.author, c.ID, case1, services.AgentContainReleaseRequest{Reason: "again"}); govCode(err) != services.GovCodeReleasePending {
		t.Fatalf("one pending request per hold: %v", err)
	}
	// The author cannot approve; a member without governance:approve cannot.
	if _, err := l.svc.ApproveRelease(ctx, a.g.ws, a.g.author, c.ID, r1.Request.ID, services.AgentContainDecisionRequest{}); govCode(err) != services.GovCodeSecondPersonRequired {
		t.Fatalf("author approving: %v", err)
	}
	if _, err := l.svc.ApproveRelease(ctx, a.g.ws, a.g.approver, c.ID, r1.Request.ID, services.AgentContainDecisionRequest{}); govStatus(err) != http.StatusForbidden {
		t.Fatalf("a member without governance:approve: %v", err)
	}
	ok, err := l.svc.ApproveRelease(ctx, a.g.ws, approver, c.ID, r1.Request.ID, services.AgentContainDecisionRequest{Reason: "agreed"})
	if err != nil {
		t.Fatal(err)
	}
	if !ok.Applied || ok.Containment.State != agentcontain.StateContained {
		t.Fatalf("one hold released, the other still holds: %+v %s", ok.Request, ok.Containment.State)
	}
	// The second case: rejected first, then approved -> the stop ends.
	r2, err := l.svc.ReleaseHold(ctx, a.g.ws, a.g.author, c.ID, case2, services.AgentContainReleaseRequest{Reason: "case 2 closed"})
	if err != nil {
		t.Fatal(err)
	}
	if rj, err := l.svc.RejectRelease(ctx, a.g.ws, approver, c.ID, r2.Request.ID, services.AgentContainDecisionRequest{Reason: "not yet"}); err != nil ||
		rj.State != services.ReleaseRequestRejected {
		t.Fatalf("reject: %v %+v", err, rj)
	}
	r2, err = l.svc.ReleaseHold(ctx, a.g.ws, a.g.author, c.ID, case2, services.AgentContainReleaseRequest{Reason: "case 2 closed now"})
	if err != nil {
		t.Fatal(err)
	}
	ok, err = l.svc.ApproveRelease(ctx, a.g.ws, approver, c.ID, r2.Request.ID, services.AgentContainDecisionRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if ok.Containment.State != agentcontain.StateReleasing {
		t.Fatalf("the last hold released: releasing, got %s", ok.Containment.State)
	}
	if got := l.run(a.g.ws, c.ID); got.State != agentcontain.StateReleased {
		t.Fatalf("released: %s", got.State)
	}
	v := l.get(a.g.ws, c.ID)
	if len(v.Holds) != 2 || v.Holds[0].State != services.HoldReleased || v.Holds[1].State != services.HoldReleased || len(v.ReleaseRequests) != 3 {
		t.Fatalf("holds %+v requests %d", v.Holds, len(v.ReleaseRequests))
	}
}

type w2Cases struct{ known map[uuid.UUID]uuid.UUID }

func (c w2Cases) CaseExists(_ *gorm.DB, ws, id uuid.UUID) (bool, error) {
	return c.known[id] == ws, nil
}

func TestContainW2CaseMustExistInTheWorkspace(t *testing.T) {
	l := newACLab(t)
	a := l.tenant("w2-case-a")
	b := l.tenant("w2-case-b")
	caseA := uuid.New()
	t.Cleanup(services.SetContainCaseChecker(w2Cases{known: map[uuid.UUID]uuid.UUID{caseA: a.g.ws}}))
	ctx := context.Background()
	if _, err := l.svc.Contain(ctx, b.g.ws, b.g.author, services.AgentContainRequest{IdentityID: b.identity.String(),
		Level: agentcontain.LevelModel, Reason: "x", CaseID: caseA.String()}); govCode(err) != services.GovCodeCaseNotFound {
		t.Fatalf("B naming A's case: %v", err)
	}
	if _, err := l.svc.Contain(ctx, a.g.ws, a.g.author, services.AgentContainRequest{IdentityID: a.identity.String(),
		Level: agentcontain.LevelModel, Reason: "x", CaseID: caseA.String()}); err != nil {
		t.Fatal(err)
	}
}

/* -------------------------------- isolation -------------------------------- */

func TestContainW2Isolation(t *testing.T) {
	l := newACLab(t)
	a := l.tenant("w2-iso-a")
	b := l.tenant("w2-iso-b")
	ctx := context.Background()
	w2Member(t, a.g, "Avery Approver", "governance:approve")
	bApprover := w2Member(t, b.g, "Bo Approver", "governance:approve")
	caseA := uuid.New()
	c, err := l.svc.Contain(ctx, a.g.ws, a.g.author, services.AgentContainRequest{IdentityID: a.identity.String(),
		Level: agentcontain.LevelIdentity, Reason: "A", CaseID: caseA.String()})
	if err != nil {
		t.Fatal(err)
	}
	l.run(a.g.ws, c.ID)
	rr, err := l.svc.ReleaseHold(ctx, a.g.ws, a.g.author, c.ID, caseA, services.AgentContainReleaseRequest{Reason: "A asks"})
	if err != nil {
		t.Fatal(err)
	}
	gwA, err := l.svc.Contain(ctx, a.g.ws, a.g.author, services.AgentContainRequest{Level: agentcontain.LevelGateway, Target: "agent:a-1", Reason: "A"})
	if err != nil {
		t.Fatal(err)
	}
	checks := map[string]error{}
	_, checks["add hold"] = l.svc.AddHold(ctx, b.g.ws, b.g.author, c.ID, services.AgentContainHoldRequest{CaseID: uuid.NewString()})
	_, checks["release hold"] = l.svc.ReleaseHold(ctx, b.g.ws, b.g.author, c.ID, caseA, services.AgentContainReleaseRequest{Reason: "x"})
	_, checks["release"] = l.svc.Release(ctx, b.g.ws, b.g.author, c.ID, services.AgentContainReleaseRequest{Reason: "x"})
	_, checks["approve"] = l.svc.ApproveRelease(ctx, b.g.ws, bApprover, c.ID, rr.Request.ID, services.AgentContainDecisionRequest{})
	_, checks["reject"] = l.svc.RejectRelease(ctx, b.g.ws, bApprover, c.ID, rr.Request.ID, services.AgentContainDecisionRequest{})
	_, checks["review"] = l.svc.ReviewRelease(ctx, b.g.ws, bApprover, c.ID, rr.Request.ID, services.AgentContainDecisionRequest{})
	_, checks["probe"] = l.svc.Probe(ctx, b.g.ws, b.g.author, c.ID)
	_, checks["narrow"] = l.svc.Narrow(ctx, b.g.ws, b.g.author, c.ID, services.AgentContainNarrowRequest{Level: agentcontain.LevelModel, Reason: "x"})
	_, checks["gateway on A's identity"] = l.svc.Contain(ctx, b.g.ws, b.g.author, services.AgentContainRequest{IdentityID: a.identity.String(),
		Level: agentcontain.LevelGateway, Target: "x", Reason: "x"})
	for what, err := range checks {
		if govStatus(err) != http.StatusNotFound {
			t.Errorf("B %s on A's containment: %v, want 404", what, err)
		}
	}
	stopsB, err := services.ActiveGatewayStops(ctx, l.db, b.g.ws)
	if err != nil {
		t.Fatal(err)
	}
	if len(stopsB) != 0 {
		t.Fatalf("B's deny list shows A's stops: %+v", stopsB)
	}
	stopsA, _ := services.ActiveGatewayStops(ctx, l.db, a.g.ws)
	if len(stopsA) != 1 || stopsA[0].ContainmentID != gwA.ID || stopsA[0].SubjectID != "agent:a-1" {
		t.Fatalf("A's deny list: %+v", stopsA)
	}
	v := l.get(a.g.ws, c.ID)
	if v.State != agentcontain.StateContained || len(v.Holds) != 1 || v.Holds[0].State != services.HoldActive ||
		v.ReleaseRequests[0].State != services.ReleaseRequestPending {
		t.Fatalf("nothing B did moved A's containment: %s %+v %+v", v.State, v.Holds, v.ReleaseRequests)
	}
}

/* ---------------------------- gateway, platform ---------------------------- */

func TestContainW2GatewayAndPlatform(t *testing.T) {
	l := newACLab(t)
	a := l.tenant("w2-gw")
	ctx := context.Background()
	if _, err := l.svc.Contain(ctx, a.g.ws, a.g.author, services.AgentContainRequest{Level: agentcontain.LevelGateway, Reason: "x"}); govStatus(err) != http.StatusBadRequest {
		t.Fatalf("a gateway stop names its subject: %v", err)
	}
	gw, err := l.svc.Contain(ctx, a.g.ws, a.g.author, services.AgentContainRequest{Level: agentcontain.LevelGateway, Target: "spiffe://x/agent", Reason: "runaway"})
	if err != nil {
		t.Fatal(err)
	}
	got := l.run(a.g.ws, gw.ID)
	if got.State != agentcontain.StateContained {
		t.Fatalf("a gateway stop is in place at once: %s %s", got.State, got.StateReason)
	}
	stops, _ := services.ActiveGatewayStops(ctx, l.db, a.g.ws)
	if len(stops) != 1 || stops[0].SubjectID != "spiffe://x/agent" {
		t.Fatalf("deny list %+v", stops)
	}
	l.clock = l.clock.Add(agentcontain.VerifyGrace + time.Minute)
	if got = l.run(a.g.ws, gw.ID); got.ProofState != agentcontain.ProofCannotVerify {
		t.Fatalf("a gateway stop cannot be proven from CloudTrail: %s", got.ProofState)
	}
	if _, err := l.svc.Release(ctx, a.g.ws, a.g.author, gw.ID, services.AgentContainReleaseRequest{Reason: "fine"}); err != nil {
		t.Fatal(err)
	}
	if got = l.run(a.g.ws, gw.ID); got.State != agentcontain.StateReleased {
		t.Fatalf("released: %s", got.State)
	}
	if stops, _ = services.ActiveGatewayStops(ctx, l.db, a.g.ws); len(stops) != 0 {
		t.Fatalf("a released stop leaves the deny list: %+v", stops)
	}

	pl, err := l.svc.Contain(ctx, a.g.ws, a.g.author, services.AgentContainRequest{Level: agentcontain.LevelPlatform, Target: "openai:org-1/key-9", Reason: "leaked key"})
	if err != nil {
		t.Fatal(err)
	}
	if pl.State != agentcontain.StateRequested {
		t.Fatalf("a platform stop is requested: %s", pl.State)
	}
	if got = l.run(a.g.ws, pl.ID); got.State != agentcontain.StateRequested {
		t.Fatalf("the job writes nothing for it: %s", got.State)
	}
	var n int64
	l.db.Table("iga_gov_event").Where("workspace_id = ? AND event = ? AND payload->>'containment_id' = ?", a.g.ws,
		services.GovEventAgentAskNeeded, pl.ID.String()).Count(&n)
	if n != 1 {
		t.Fatalf("agent.ask_needed: %d", n)
	}
	// The platform stop is a real ask (W4): about the containment, never
	// decided by the person who asked for the stop.
	var asks []struct {
		AboutKind       string
		RequesterUserID *uuid.UUID
		State           string
	}
	l.db.Table("agent_ask").Select("about_kind, requester_user_id, state").
		Where("workspace_id = ? AND about_id = ?", a.g.ws, pl.ID.String()).Scan(&asks)
	if len(asks) != 1 || asks[0].AboutKind != services.AskAboutContainment || asks[0].State != "open" ||
		asks[0].RequesterUserID == nil || *asks[0].RequesterUserID != a.g.author {
		t.Fatalf("platform stop ask: %+v", asks)
	}
}

/* ---------------------------------- narrow --------------------------------- */

func TestContainW2NarrowReleasesTheWiderOnceProven(t *testing.T) {
	l := newACLab(t)
	a := l.tenant("w2-narrow")
	ctx := context.Background()
	caseA := uuid.New()
	wide, err := l.svc.Contain(ctx, a.g.ws, a.g.author, services.AgentContainRequest{IdentityID: a.identity.String(),
		Level: agentcontain.LevelIdentity, Reason: "everything", CaseID: caseA.String()})
	if err != nil {
		t.Fatal(err)
	}
	l.run(a.g.ws, wide.ID)
	if _, err := l.svc.Narrow(ctx, a.g.ws, a.g.author, wide.ID, services.AgentContainNarrowRequest{Level: agentcontain.LevelKey, Reason: "x"}); govCode(err) != services.GovCodeNotNarrower {
		t.Fatalf("key is not narrower on a role: %v", err)
	}
	narrow, err := l.svc.Narrow(ctx, a.g.ws, a.g.author, wide.ID, services.AgentContainNarrowRequest{Level: agentcontain.LevelModel, Reason: "only the model use"})
	if err != nil {
		t.Fatal(err)
	}
	if narrow.NarrowedFrom == nil || *narrow.NarrowedFrom != wide.ID {
		t.Fatalf("linked: %v", narrow.NarrowedFrom)
	}
	got := l.runOnly(a.g.ws, narrow.ID)
	if got.State != agentcontain.StateContained {
		t.Fatalf("narrower contained: %s %s", got.State, got.StateReason)
	}
	if w := l.get(a.g.ws, wide.ID); w.State != agentcontain.StateContained {
		t.Fatalf("the wider one stays until the narrower is proven: %s", w.State)
	}
	nv := l.get(a.g.ws, narrow.ID)
	if len(nv.Holds) != 1 || nv.Holds[0].CaseID != caseA {
		t.Fatalf("the narrower one takes over the holds: %+v", nv.Holds)
	}
	l.refusal(a.g.ws, narrow.ID, agentcontain.ContainPolicyName(a.roleID, narrow.ID), "model-denied", got.ContainedAt.Add(8*time.Minute),
		agentruntime.SourceBedrock, "Converse")
	if nv = l.get(a.g.ws, narrow.ID); nv.ProofState != agentcontain.ProofProven {
		t.Fatalf("narrower proven: %s", nv.ProofState)
	}
	w := l.get(a.g.ws, wide.ID)
	if w.State != agentcontain.StateReleasing || w.Holds[0].State != services.HoldReleased {
		t.Fatalf("the wider one is released once the narrower is proven: %s %+v", w.State, w.Holds)
	}
	if got := l.runOnly(a.g.ws, wide.ID); got.State != agentcontain.StateReleased {
		t.Fatalf("wider released: %s", got.State)
	}
}

/* ---------------------------------- probe ---------------------------------- */

type w2Broker struct {
	mu   sync.Mutex
	reqs []awsbroker.Request
}

func (b *w2Broker) Assume(_ context.Context, r awsbroker.Request) (*awsbroker.Credentials, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.reqs = append(b.reqs, r)
	return &awsbroker.Credentials{AccessKeyID: "ASIAPROBE", SecretAccessKey: "s", SessionToken: "t", Expiration: time.Now().Add(15 * time.Minute)}, nil
}

func TestContainW2ProbeUsesOnlyAuthSecCredentials(t *testing.T) {
	l := newACLab(t)
	a := l.tenant("w2-probe")
	ctx := context.Background()
	c, err := l.svc.Contain(ctx, a.g.ws, a.g.author, services.AgentContainRequest{IdentityID: a.identity.String(),
		Level: agentcontain.LevelIdentity, Reason: "probe me"})
	if err != nil {
		t.Fatal(err)
	}
	l.run(a.g.ws, c.ID)
	if _, err := l.svc.Probe(ctx, a.g.ws, a.g.author, c.ID); govCode(err) != services.GovCodeProbeNotPossible {
		t.Fatalf("not a brokered role: %v", err)
	}
	p3exec(t, l.db, `INSERT INTO iga_gov_runtime_broker_role (workspace_id, connector_id, account_id, role_arn, created_by)
		VALUES (?, ?, '111111111111', ?, ?)`, a.g.ws, a.g.conn, a.roleARN, a.g.author)
	broker := &w2Broker{}
	prev := services.CurrentRuntimeBrokerDeps()
	services.SetRuntimeBrokerDeps(&services.RuntimeBrokerDeps{Broker: broker, Inputs: func(context.Context, uuid.UUID, uuid.UUID) (*services.RuntimeBrokerInputs, error) {
		return &services.RuntimeBrokerInputs{AccountID: "111111111111", ExternalID: "ext", Region: "us-east-1"}, nil
	}})
	t.Cleanup(func() { services.SetRuntimeBrokerDeps(prev) })
	policy := agentcontain.ContainPolicyName(a.roleID, c.ID)
	var used *awsbroker.Credentials
	t.Cleanup(services.SetContainProbeCaller(func(_ context.Context, cr *awsbroker.Credentials, _ string) error {
		used = cr
		return &smithy.GenericAPIError{Code: "AccessDenied", Message: "User: x is not authorized to perform: s3:ListAllMyBuckets with an explicit deny in an identity-based policy: arn:aws:iam::111111111111:policy/authsec/" + policy}
	}))
	res, err := l.svc.Probe(ctx, a.g.ws, a.g.author, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if res.Result != "proven" || res.Policy != policy || res.Containment.ProofState != agentcontain.ProofProven ||
		res.Containment.ProvenByEventID == nil || !strings.HasPrefix(*res.Containment.ProvenByEventID, "probe:") {
		t.Fatalf("probe %+v proof %s", res, res.Containment.ProofState)
	}
	if used == nil || used.AccessKeyID != "ASIAPROBE" || len(broker.reqs) != 1 || broker.reqs[0].RoleARN != a.roleARN ||
		!strings.Contains(broker.reqs[0].SessionPolicy, services.ContainProbeAction) {
		t.Fatalf("the probe ran on AuthSec's brokered session: %+v", broker.reqs)
	}
}

/* ------------------------------- chain, key -------------------------------- */

func TestContainW2ChainDeniesSameAccountAssumers(t *testing.T) {
	l := newACLab(t)
	a := l.tenant("w2-chain")
	ctx := context.Background()
	caller := uuid.New()
	callerARN := "arn:aws:iam::111111111111:role/caller-" + a.g.ws.String()[:8]
	p3exec(t, l.db, `INSERT INTO cloud_identity (id, workspace_id, connector_id, kind, native_id, name, attrs)
		VALUES (?, ?, ?, 'iam_role', ?, ?, jsonb_build_object('unique_id', 'AROACALLER00000000001'::text, 'path', '/'))`,
		caller, a.g.ws, a.g.conn, callerARN, "caller-"+a.g.ws.String()[:8])
	for _, e := range [][3]string{{models.AssumeSubjectIdentity, callerARN, models.AssumeMechanismSTSAssumeRole},
		{models.AssumeSubjectCIPipeline, "token.actions.githubusercontent.com", models.AssumeMechanismOIDCFederation}} {
		p3exec(t, l.db, `INSERT INTO cloud_assume_edge (workspace_id, connector_id, identity_id, subject_kind, subject, mechanism)
			VALUES (?, ?, ?, ?, ?, ?)`, a.g.ws, a.g.conn, a.identity, e[0], e[1], e[2])
	}
	p, err := l.svc.Preview(ctx, a.g.ws, services.AgentContainPreviewRequest{IdentityID: a.identity.String()})
	if err != nil {
		t.Fatal(err)
	}
	o := p.Level(agentcontain.LevelChain)
	if !o.Offered || len(p.Assumers) != 2 {
		t.Fatalf("chain offered with two assumers: %+v %+v", o.Refusals, p.Assumers)
	}
	c, err := l.svc.Contain(ctx, a.g.ws, a.g.author, services.AgentContainRequest{IdentityID: a.identity.String(), Level: agentcontain.LevelChain, Reason: "chain"})
	if err != nil {
		t.Fatal(err)
	}
	if got := l.run(a.g.ws, c.ID); got.State != agentcontain.StateContained {
		t.Fatalf("chain: %s %s", got.State, got.StateReason)
	}
	pol := l.fake.policies["arn:aws:iam::111111111111:policy/authsec/"+agentcontain.ChainPolicyName("AROACALLER00000000001", c.ID)]
	if pol == nil || !pol.attached["caller-"+a.g.ws.String()[:8]] || !strings.Contains(pol.doc, a.roleARN) {
		t.Fatalf("the assumer carries the chain deny on the role: %+v", pol)
	}
}

// w2KeyAWS is acAWS with IAM user access keys.
type w2KeyAWS struct {
	*acAWS
	keys map[string]map[string]bool
}

func (f *w2KeyAWS) ListAccessKeys(_ context.Context, user string) ([]agentcontain.AccessKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []agentcontain.AccessKey
	for id, on := range f.keys[user] {
		out = append(out, agentcontain.AccessKey{ID: id, Active: on})
	}
	return out, nil
}

func (f *w2KeyAWS) SetAccessKeyStatus(_ context.Context, user, key string, active bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.keys[user][key]; !ok {
		return agentcontain.ErrNotFound
	}
	f.keys[user][key] = active
	return nil
}

type w2Access struct {
	acAccess
	aws agentcontain.AWS
}

func (a *w2Access) Open(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) (agentcontain.AWS, error) {
	return a.aws, nil
}

func TestContainW2KeyLevelNeverReactivates(t *testing.T) {
	l := newACLab(t)
	a := l.tenant("w2-key")
	ctx := context.Background()
	user := uuid.New()
	name := "bot-" + a.g.ws.String()[:8]
	p3exec(t, l.db, `INSERT INTO cloud_identity (id, workspace_id, connector_id, kind, native_id, name, attrs)
		VALUES (?, ?, ?, 'iam_user', ?, ?, jsonb_build_object('unique_id', 'AIDABOT0000000000001'::text, 'path', '/'))`,
		user, a.g.ws, a.g.conn, "arn:aws:iam::111111111111:user/"+name, name)
	fake := &w2KeyAWS{acAWS: l.fake, keys: map[string]map[string]bool{name: {"AKIALEAKED": true, "AKIAOTHER": true}}}
	services.SetAgentContainAccess(&w2Access{aws: fake})
	c, err := l.svc.Contain(ctx, a.g.ws, a.g.author, services.AgentContainRequest{IdentityID: user.String(), Level: agentcontain.LevelKey,
		Target: "AKIALEAKED", Reason: "key on GitHub"})
	if err != nil {
		t.Fatal(err)
	}
	if got := l.run(a.g.ws, c.ID); got.State != agentcontain.StateContained {
		t.Fatalf("key: %s %s", got.State, got.StateReason)
	}
	if fake.keys[name]["AKIALEAKED"] || !fake.keys[name]["AKIAOTHER"] {
		t.Fatalf("only the named key: %+v", fake.keys)
	}
	// One live stop per (identity, level, key).
	if _, err := l.svc.Contain(ctx, a.g.ws, a.g.author, services.AgentContainRequest{IdentityID: user.String(), Level: agentcontain.LevelKey,
		Target: "AKIALEAKED", Reason: "again"}); govCode(err) != services.GovCodeContainmentExists {
		t.Fatalf("one live stop per key: %v", err)
	}
	if _, err := l.svc.Release(ctx, a.g.ws, a.g.author, c.ID, services.AgentContainReleaseRequest{Reason: "rotated"}); err != nil {
		t.Fatal(err)
	}
	got := l.run(a.g.ws, c.ID)
	if got.State != agentcontain.StateReleased || got.ProofState != agentcontain.ProofKept || fake.keys[name]["AKIALEAKED"] {
		t.Fatalf("released, key left inactive, proof kept: %s %s %+v", got.State, got.ProofState, fake.keys)
	}
}

/* ---------------------------------- entra ---------------------------------- */

type w2Graph struct {
	mu      sync.Mutex
	enabled map[string]bool
}

func (g *w2Graph) ServicePrincipalAccountEnabled(_ context.Context, _, id string) (bool, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.enabled[id], nil
}

func (g *w2Graph) SetServicePrincipalAccountEnabled(_ context.Context, _, id string, on bool) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.enabled[id] = on
	return nil
}

func TestContainW2EntraDisablesAndRestores(t *testing.T) {
	l := newACLab(t)
	a := l.tenant("w2-entra")
	ctx := context.Background()
	tenantConn, subConn, sp := uuid.New(), uuid.New(), uuid.New()
	tenantID := uuid.NewString()
	spObj := strings.ToLower(uuid.NewString())
	sub := strings.ToLower(uuid.NewString())
	attrs := func(granted bool) string {
		b, _ := json.Marshal(models.AzureTenantAttrs{TenantID: tenantID, GraphPermissions: []models.AzureGraphPermission{
			{Name: agentcontain.EntraGraphPermission, Granted: granted}}})
		return string(b)
	}
	p3exec(t, l.db, `INSERT INTO cloud_connector (id, workspace_id, provider, scope_kind, scope_id, auth_ref, attrs, status)
		VALUES (?, ?, 'azure', 'tenant', ?, 'vault://w2/t', ?::jsonb, 'active')`, tenantConn, a.g.ws, tenantID, attrs(false))
	p3exec(t, l.db, `INSERT INTO cloud_connector (id, workspace_id, provider, scope_kind, scope_id, auth_ref, attrs, status)
		VALUES (?, ?, 'azure', 'subscription', ?, 'vault://w2/s', jsonb_build_object('tenant_id', ?::text), 'active')`, subConn, a.g.ws, sub, tenantID)
	p3exec(t, l.db, `INSERT INTO cloud_identity (id, workspace_id, connector_id, kind, native_id, name) VALUES (?, ?, ?, 'entra_service_principal', ?, 'agent-sp')`,
		sp, a.g.ws, tenantConn, spObj)
	scope := "/subscriptions/" + sub + "/resourcegroups/rg"
	ra := azure.RoleAssignment{ID: scope + "/providers/Microsoft.Authorization/roleAssignments/ra1", Name: "ra1"}
	ra.Properties.Scope, ra.Properties.PrincipalID, ra.Properties.RoleDefinitionID = scope, spObj, "/subscriptions/"+sub+"/providers/Microsoft.Authorization/roleDefinitions/reader"
	rbac := &fakeRBAC{as: map[string]azure.RoleAssignment{strings.ToLower(ra.ID): ra}}
	graph := &w2Graph{enabled: map[string]bool{spObj: true}}
	tok := func(context.Context, uuid.UUID, string) (string, error) { return "tok", nil }
	t.Cleanup(services.SetAzureAccessDeps(&services.AzureAccessDeps{RBAC: rbac, Token: tok, Graph: graph, GraphToken: tok}))

	_, err := l.svc.Contain(ctx, a.g.ws, a.g.author, services.AgentContainRequest{IdentityID: sp.String(), Level: agentcontain.LevelEntra, Reason: "x"})
	if govCode(err) != services.GovCodeContainmentRefused || !strings.Contains(errDetail(err), agentcontain.RefusePermissionMissing) {
		t.Fatalf("without %s: %v %s", agentcontain.EntraGraphPermission, err, errDetail(err))
	}
	p3exec(t, l.db, `UPDATE cloud_connector SET attrs = ?::jsonb WHERE id = ?`, attrs(true), tenantConn)
	c, err := l.svc.Contain(ctx, a.g.ws, a.g.author, services.AgentContainRequest{IdentityID: sp.String(), Level: agentcontain.LevelEntra, Reason: "agent loose"})
	if err != nil {
		t.Fatal(err)
	}
	got := l.run(a.g.ws, c.ID)
	if got.State != agentcontain.StateContained || graph.enabled[spObj] || len(rbac.as) != 0 {
		t.Fatalf("disabled, assignment removed: %s %s %v %d", got.State, got.StateReason, graph.enabled[spObj], len(rbac.as))
	}
	if got.ProofState != agentcontain.ProofUnproven || got.TokenExpiryAt == nil {
		t.Fatalf("unproven until the tokens expire: %s %v", got.ProofState, got.TokenExpiryAt)
	}
	if _, err := l.svc.Release(ctx, a.g.ws, a.g.author, c.ID, services.AgentContainReleaseRequest{Reason: "fixed"}); err != nil {
		t.Fatal(err)
	}
	if got = l.run(a.g.ws, c.ID); got.State != agentcontain.StateReleased || !graph.enabled[spObj] || len(rbac.as) != 1 {
		t.Fatalf("re-enabled and the assignment back: %s %v %d", got.State, graph.enabled[spObj], len(rbac.as))
	}
}

func errDetail(err error) string {
	var ge *services.GovError
	if errors.As(err, &ge) {
		b, _ := json.Marshal(ge.Detail)
		return string(b)
	}
	return ""
}

/* -------------------------------- kubernetes ------------------------------- */

func TestContainW2KubernetesUnbindsThroughTheAgent(t *testing.T) {
	l := newACLab(t)
	a := l.tenant("w2-k8s")
	ctx := context.Background()
	if err := services.VerifyK8sAccessSchema(l.db); err != nil {
		t.Skip(err.Error())
	}
	src := uuid.New()
	cluster := "w2-" + a.g.ws.String()[:8]
	p3exec(t, l.db, `INSERT INTO discovery_sources (id, workspace_id, kind, display_name, cluster_name, actuation_token_hash, enforcement_bindings)
		VALUES (?, ?, ?, 'agent-w2', ?, 'hash', true)`, src, a.g.ws, models.DiscoverySourceK8sWebhook, cluster)
	t.Cleanup(func() {
		for _, table := range []string{"provisioning_instructions", "iga_k8s_sweep"} {
			l.db.Exec(`DELETE FROM `+table+` WHERE workspace_id = ?`, a.g.ws)
		}
	})
	at := time.Now().UTC().Truncate(time.Second).Add(-time.Hour)
	saSubj := models.K8sSubject{Kind: models.K8sSubjectServiceAccount, Name: "booker", Namespace: "agents"}
	snap := models.K8sRBACSnapshot{WorkspaceID: a.g.ws.String(), DiscoverySourceID: src.String(), Source: models.DiscoverySourceK8sWebhook,
		Cluster: cluster, ScanKind: "rbac", SweepStartedAt: at.Add(-30 * time.Second).Format(time.RFC3339), ObservedAt: at.Format(time.RFC3339),
		Complete: true, ClusterScoped: true, Namespaces: []string{"agents"},
		ServiceAccounts: []models.K8sServiceAccount{{Name: "booker", Namespace: "agents"}},
		Roles: []models.K8sRole{{Kind: models.K8sKindRole, Name: "secret-reader", Namespace: "agents",
			Rules: []models.K8sPolicyRule{{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}}}}},
		Bindings: []models.K8sBinding{{Kind: models.K8sKindRoleBinding, Name: "booker-secrets", Namespace: "agents", UID: "uid-1",
			RoleRef: models.K8sRoleRef{Kind: models.K8sKindRole, Name: "secret-reader"}, Subjects: []models.K8sSubject{saSubj}}}}
	if _, err := services.NewK8sRBACManager(l.db, p3GraphOn(t, l.db)()).Ingest(a.g.ws, snap); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	var ids []uuid.UUID
	l.db.Table("iga_identity_accounts").Where("workspace_id = ? AND source_key = ?", a.g.ws, k8sgraph.ServiceAccountKey(cluster, "agents", "booker")).Pluck("id", &ids)
	if len(ids) != 1 {
		t.Fatalf("service account: %v", ids)
	}
	c, err := l.svc.Contain(ctx, a.g.ws, a.g.author, services.AgentContainRequest{IdentityID: ids[0].String(), Level: agentcontain.LevelKubernetes, Reason: "sa token stolen"})
	if err != nil {
		t.Fatal(err)
	}
	answer := func(kind, result string) {
		t.Helper()
		var inst models.ProvisioningInstruction
		if err := l.db.Where("workspace_id = ? AND kind = ? AND status = ?", a.g.ws, kind, models.InstructionPending).Take(&inst).Error; err != nil {
			t.Fatalf("no pending %s: %v", kind, err)
		}
		if inst.DiscoverySourceID != src {
			t.Fatalf("sent to %s", inst.DiscoverySourceID)
		}
		p3exec(t, l.db, `UPDATE provisioning_instructions SET status = 'applied', applied_at = now(), result = ?::jsonb WHERE id = ?`, result, inst.ID)
	}
	if got := l.run(a.g.ws, c.ID); got.State != agentcontain.StateContaining {
		t.Fatalf("waiting for the agent: %s %s", got.State, got.StateReason)
	}
	answer(models.InstructionRemoveBindingSubject, `{"binding_uid":"uid-1","removed":true}`)
	if got := l.run(a.g.ws, c.ID); got.State != agentcontain.StateContained {
		t.Fatalf("contained once the agent removed it: %s %s", got.State, got.StateReason)
	}
	if _, err := l.svc.Release(ctx, a.g.ws, a.g.author, c.ID, services.AgentContainReleaseRequest{Reason: "rotated"}); err != nil {
		t.Fatal(err)
	}
	if got := l.run(a.g.ws, c.ID); got.State != agentcontain.StateReleasing {
		t.Fatalf("waiting for the agent to put it back: %s", got.State)
	}
	answer(models.InstructionRestoreBindingSubject, `{"binding_uid":"uid-1","restored":true}`)
	if got := l.run(a.g.ws, c.ID); got.State != agentcontain.StateReleased {
		t.Fatalf("released: %s %s", got.State, got.StateReason)
	}
}
