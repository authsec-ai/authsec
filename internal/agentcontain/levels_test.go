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
	"github.com/authsec-ai/authsec/internal/awsbroker"
	"github.com/authsec-ai/authsec/internal/azure"
)

/* ------------------------------- proof state ------------------------------- */

func TestProofStateOf(t *testing.T) {
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	yes, no := true, false
	later := now.Add(time.Hour)
	cases := []struct {
		name string
		in   ProofInput
		want string
	}{
		{"queued", ProofInput{State: StatePreviewed}, ProofRequested},
		{"platform ask", ProofInput{State: StateRequested}, ProofRequested},
		{"failed", ProofInput{State: StateFailed}, ProofRequested},
		{"in place, no verdict", ProofInput{Level: LevelIdentity, State: StateContained}, ProofApplied},
		{"verified by refusal", ProofInput{State: StateContained, Verified: true, Effective: &yes}, ProofProven},
		{"a call succeeded", ProofInput{State: StateContained, Effective: &no}, ProofUnproven},
		{"timed out without proof", ProofInput{State: StateContained, Unverifiable: true}, ProofUnproven},
		{"cannot be proven", ProofInput{State: StateContained, Unverifiable: true, UnverifiableFinal: true}, ProofCannotVerify},
		{"entra before token expiry", ProofInput{Level: LevelEntra, State: StateContained, TokenExpiry: &later, Now: now}, ProofUnproven},
		{"released, key left inactive", ProofInput{State: StateReleased, Kept: true, Verified: true, Effective: &yes}, ProofKept},
		{"released, proven", ProofInput{State: StateReleased, Verified: true, Effective: &yes}, ProofProven},
		{"released, never proven", ProofInput{State: StateReleased}, ProofUnproven},
	}
	for _, c := range cases {
		if got := ProofStateOf(c.in); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}

func TestTokenExpiryAt(t *testing.T) {
	cut := time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		level, kind string
		want        time.Duration
	}{
		{LevelIdentity, IdentityRole, 13 * time.Hour},
		{LevelIdentity, IdentityUser, 36 * time.Hour},
		{LevelKey, IdentityUser, 36 * time.Hour},
		{LevelSourceIdentity, IdentityRole, 13 * time.Hour},
		{LevelEntra, IdentityEntraSP, 90 * time.Minute},
		{LevelKubernetes, IdentityK8sSA, time.Hour},
	} {
		got := TokenExpiryAt(c.level, c.kind, cut)
		if got == nil || !got.Equal(cut.Add(c.want)) {
			t.Errorf("%s/%s: %v, want %v", c.level, c.kind, got, cut.Add(c.want))
		}
	}
	for _, l := range []string{LevelWorkload, LevelGateway, LevelPlatform} {
		if TokenExpiryAt(l, IdentityRole, cut) != nil {
			t.Errorf("%s stops no credential: want nil", l)
		}
	}
}

func TestNarrower(t *testing.T) {
	if ok, _ := Narrower(LevelIdentity, IdentityRole, LevelModel); !ok {
		t.Error("model is narrower than identity on a role")
	}
	if ok, _ := Narrower(LevelIdentity, IdentityUser, LevelKey); !ok {
		t.Error("key is narrower than identity on a user")
	}
	if ok, _ := Narrower(LevelModel, IdentityRole, LevelIdentity); ok {
		t.Error("identity is not narrower than model")
	}
	if ok, _ := Narrower(LevelIdentity, IdentityRole, LevelKey); ok {
		t.Error("a role has no keys")
	}
}

/* --------------------------------- previews -------------------------------- */

func TestPreviewKeyLevel(t *testing.T) {
	p := BuildPreview(PreviewInput{Subject: userSubject(), Cap: fullCap(), Target: "AKIAEXAMPLE000000001"})
	_ = p
	o := p.Level(LevelKey)
	if o == nil || !o.Offered || !hasEffect(o.SideEffects, EffectKeyNoUndo) || !hasEffect(o.SideEffects, EffectKeySessionsLive) {
		t.Fatalf("key level on a user: %+v", o)
	}
	if o := pv(PreviewInput{Subject: userSubject(), Cap: fullCap()}).Level(LevelKey); o.Offered || !hasCode(o.Refusals, RefuseNoAccessKey) {
		t.Errorf("key level without a key id: %+v", o.Refusals)
	}
	if o := pv(PreviewInput{Subject: roleSubject(), Cap: fullCap(), Target: "AKIA1"}).Level(LevelKey); o.Offered || !hasCode(o.Refusals, RefuseKeyNeedsUser) {
		t.Errorf("key level on a role: %+v", o.Refusals)
	}
	if o := pv(PreviewInput{Subject: userSubject(), Cap: Capability{Binding: true}, Target: "AKIA1"}).Level(LevelKey); o.Offered {
		t.Error("key level needs EnableWorkloadContainment")
	}
}

func assumers() []Assumer {
	return []Assumer{
		{Kind: AssumerRole, Subject: "arn:aws:iam::111111111111:role/caller", ARN: "arn:aws:iam::111111111111:role/caller", Name: "caller",
			UniqueID: "AROACALLER0000000001", Enforceable: true},
		{Kind: AssumerFederated, Subject: "token.actions.githubusercontent.com", Why: "federated sign-in is authorised by the trust policy alone"},
		{Kind: AssumerService, Subject: "lambda.amazonaws.com", Why: "an AWS service assumes the role with its own authority"},
	}
}

func TestPreviewChainLevelStatesWhatIsNotEnforceable(t *testing.T) {
	p := BuildPreview(PreviewInput{Subject: roleSubject(), Cap: fullCap(), Assumers: assumers()})
	o := p.Level(LevelChain)
	if !o.Offered {
		t.Fatalf("chain level: %+v", o.Refusals)
	}
	n := 0
	for _, s := range o.Steps {
		if s.Kind == StepAssumerPolicy {
			n++
		}
	}
	if n != 1 || !hasEffect(o.SideEffects, EffectChainNotEnforceable) {
		t.Fatalf("one assumer step and the not-enforceable effect: %+v", o)
	}
	for _, e := range o.SideEffects {
		if e.Code == EffectChainNotEnforceable && (!strings.Contains(e.Message, "token.actions") || !strings.Contains(e.Message, "lambda.amazonaws.com")) {
			t.Errorf("the effect names the principals that can still assume: %s", e.Message)
		}
	}
	none := pv(PreviewInput{Subject: roleSubject(), Cap: fullCap(), Assumers: assumers()[1:]}).Level(LevelChain)
	if none.Offered || !hasCode(none.Refusals, RefuseChainNothingEnforceable) {
		t.Errorf("only federated and service assumers: %+v", none.Refusals)
	}
}

func TestPreviewSourceIdentityNeedsBrokeredRoleAndAgent(t *testing.T) {
	if o := pv(PreviewInput{Subject: roleSubject(), Cap: fullCap(), Target: "agent-1"}).Level(LevelSourceIdentity); o.Offered ||
		!hasCode(o.Refusals, RefuseSourceIdentityNotBrokered) {
		t.Errorf("not brokered: %+v", o.Refusals)
	}
	if o := pv(PreviewInput{Subject: roleSubject(), Cap: fullCap(), Brokered: true}).Level(LevelSourceIdentity); o.Offered ||
		!hasCode(o.Refusals, RefuseSourceIdentityNoAgent) {
		t.Errorf("no agent: %+v", o.Refusals)
	}
	if o := pv(PreviewInput{Subject: roleSubject(), Cap: fullCap(), Brokered: true, Target: "agent-1"}).Level(LevelSourceIdentity); !o.Offered {
		t.Errorf("brokered role with an agent: %+v", o.Refusals)
	}
}

/* --------------------------------- engine ---------------------------------- */

func TestChainLevelDeniesAssumersAndRestores(t *testing.T) {
	f := newFake()
	r := runOf(roleSubject(), LevelChain)
	r.Assumers = assumers()
	e := &Engine{AWS: f, Run: r}
	steps := contain(t, e, r.IAMSteps())
	if len(steps) != 2 || steps[0].Kind != StepAssumerPolicy || steps[1].Kind != StepSessionRevoke {
		t.Fatalf("steps %+v", steps)
	}
	pol := f.policies[steps[0].Target]
	if pol == nil || !pol.attached["caller"] || pol.attached["agent-role"] {
		t.Fatalf("the chain deny is attached to the assumer only: %+v", pol)
	}
	if !strings.Contains(pol.doc, `"sts:AssumeRole"`) || !strings.Contains(pol.doc, roleSubject().ARN) {
		t.Errorf("document %s", pol.doc)
	}
	var b PolicyBefore
	_ = json.Unmarshal(steps[0].Before, &b)
	if b.PrincipalName != "caller" || b.PrincipalUniqueID != "AROACALLER0000000001" {
		t.Errorf("the assumer is recorded in the before-state: %+v", b)
	}
	// A later run has only the before-state (no Principal on the step).
	steps[0].Principal = nil
	if in, _, err := e.Readback(context.Background(), &steps[0]); err != nil || !in {
		t.Fatalf("readback from the before-state: %v %v", in, err)
	}
	steps = release(t, e, steps, r.Cutoff.Add(time.Hour))
	if _, ok := f.policies[steps[0].Target]; ok {
		t.Error("release removes the assumer's chain deny")
	}
	if _, ok := f.policies[steps[1].Target]; !ok {
		t.Error("the session revocation stays until its time")
	}
}

func TestSessionsBeforeAloneReleasesAtOnce(t *testing.T) {
	f := newFake()
	r := runOf(roleSubject(), LevelSessionsBefore)
	e := &Engine{AWS: f, Run: r}
	steps := contain(t, e, r.IAMSteps())
	if len(steps) != 1 || steps[0].Kind != StepSessionRevoke || steps[0].RestoreAfter != nil {
		t.Fatalf("one revocation, not deferred: %+v", steps)
	}
	if !strings.Contains(f.policies[steps[0].Target].doc, "aws:TokenIssueTime") {
		t.Error("the TokenIssueTime deny")
	}
	release(t, e, steps, r.Cutoff)
	if len(f.policies) != 0 {
		t.Error("release removes it at once")
	}
}

func TestSourceIdentityDocumentNamesTheAgent(t *testing.T) {
	f := newFake()
	r := runOf(roleSubject(), LevelSourceIdentity)
	r.Target = "client-agent-7"
	e := &Engine{AWS: f, Run: r}
	steps := contain(t, e, r.IAMSteps())
	if len(steps) != 1 || steps[0].State != StepApplied {
		t.Fatalf("steps %+v", steps)
	}
	doc := f.policies[steps[0].Target].doc
	if !strings.Contains(doc, awsbroker.AgentSourcePattern("client-agent-7")) || !strings.Contains(doc, "aws:PrincipalTag/authsec-agent") {
		t.Errorf("document %s", doc)
	}
}

func TestKeyStepNeverReactivates(t *testing.T) {
	f := newFake()
	f.keys["bot"] = map[string]bool{"AKIA1": true, "AKIA2": true, "AKIA3": false}
	st, skip, err := KeyStep(context.Background(), f, "bot", "AKIA1")
	if err != nil || skip {
		t.Fatal(err, skip)
	}
	r := runOf(userSubject(), LevelKey)
	e := &Engine{AWS: f, Run: r}
	steps := contain(t, e, []Step{st})
	if f.keys["bot"]["AKIA1"] || !f.keys["bot"]["AKIA2"] {
		t.Fatalf("only AKIA1 stopped: %+v", f.keys)
	}
	release(t, e, steps, r.Cutoff)
	if f.keys["bot"]["AKIA1"] || !KeyRotationRequired(steps[0]) {
		t.Error("release never reactivates the key and asks for a new one")
	}
	if _, skip, _ := KeyStep(context.Background(), f, "bot", "AKIA3"); !skip {
		t.Error("an Inactive key is skipped")
	}
	var se *StepError
	if _, _, err := KeyStep(context.Background(), f, "bot", "AKIA9"); !errors.As(err, &se) {
		t.Errorf("an unknown key is refused: %v", err)
	}
}

/* -------------------------------- verifier --------------------------------- */

func TestVerifySessionsBeforeAndSourceIdentity(t *testing.T) {
	c, ev := proofFixture()
	old := c.ContainedAt.Add(-time.Hour)
	fresh := c.ContainedAt.Add(time.Minute)
	late := c.ContainedAt.Add(10 * time.Minute)

	c.Level = LevelSessionsBefore
	a := ev("old-session", late, "", "")
	a.SessionCreatedAt = &old
	b := ev("new-session", late, "", "")
	b.SessionCreatedAt = &fresh
	got := Late(c, []agentruntime.Event{a, b})
	if len(got) != 1 || got[0].EventID != "old-session" {
		t.Fatalf("only a session issued before the stop counts against it: %+v", got)
	}
	if p := Proof(c, []agentruntime.Event{ev("deny", late, "AccessDenied", denyMsg(RevokePolicyName(c.UniqueID, c.ID)))}); p == nil {
		t.Error("a refusal naming the revocation proves sessions_before")
	}

	c.Level, c.Target = LevelSourceIdentity, "agent-x"
	mine := ev("mine", late, "", "")
	mine.SourceIdentity = awsbroker.BrokerSourceIdentity(uuid.NewString(), "agent-x")
	other := ev("other", late, "", "")
	other.SourceIdentity = awsbroker.BrokerSourceIdentity(uuid.NewString(), "agent-y")
	got = Late(c, []agentruntime.Event{mine, other})
	if len(got) != 1 || got[0].EventID != "mine" {
		t.Fatalf("only the agent's sessions count: %+v", got)
	}
	deny := ev("deny-other-agent", late, "AccessDenied", denyMsg(ContainPolicyName(c.UniqueID, c.ID)))
	deny.SourceIdentity = other.SourceIdentity
	if Proof(c, []agentruntime.Event{deny}) != nil {
		t.Error("another agent's refusal proves nothing")
	}
	deny.SourceIdentity = mine.SourceIdentity
	if Proof(c, []agentruntime.Event{deny}) == nil {
		t.Error("the agent's refusal naming the policy proves it")
	}
}

func TestVerifyChainByAssumerRefusal(t *testing.T) {
	c, ev := proofFixture()
	c.Level = LevelChain
	c.Assumers = assumers()[:1]
	late := c.ContainedAt.Add(10 * time.Minute)
	e := ev("assume-denied", late, "AccessDenied", denyMsg(ChainPolicyName("AROACALLER0000000001", c.ID)))
	e.SessionIssuerARN, e.SessionIssuerPrincipalID = "arn:aws:iam::111111111111:role/caller", "AROACALLER0000000001"
	e.EventSource, e.EventName = "sts.amazonaws.com", "AssumeRole"
	if p := Proof(c, []agentruntime.Event{e}); p == nil {
		t.Fatal("an assumer's refused AssumeRole naming the chain deny proves the stop")
	}
	if ok, _ := c.Unverifiable(); ok {
		t.Error("a chain stop can be proven")
	}
	for _, l := range []string{LevelKey, LevelEntra, LevelKubernetes, LevelGateway} {
		c.Level = l
		if ok, _ := c.Unverifiable(); !ok {
			t.Errorf("%s cannot be proven by a refusal", l)
		}
	}
}

func TestProbeProves(t *testing.T) {
	c, _ := proofFixture()
	if ProbeProves(c, denyMsg(ContainPolicyName(c.UniqueID, c.ID))) == "" {
		t.Error("a refusal naming the deny proves it")
	}
	if ProbeProves(c, "with an explicit deny in a service control policy") != "" {
		t.Error("an SCP refusal proves nothing")
	}
}

/* ---------------------------------- entra ---------------------------------- */

type fakeEntra struct {
	enabled map[string]bool
	ras     map[string]azure.RoleAssignment
	denyAll bool
}

func (f *fakeEntra) AccountEnabled(_ context.Context, id string) (bool, error) {
	on, ok := f.enabled[id]
	if !ok {
		return false, ErrNotFound
	}
	return on, nil
}
func (f *fakeEntra) SetAccountEnabled(_ context.Context, id string, on bool) error {
	if f.denyAll {
		return ErrDenied
	}
	f.enabled[id] = on
	return nil
}
func (f *fakeEntra) ListRoleAssignments(_ context.Context, sub, principal string) ([]azure.RoleAssignment, error) {
	var out []azure.RoleAssignment
	for _, a := range f.ras {
		if strings.HasPrefix(a.ID, "/subscriptions/"+sub) && a.Properties.PrincipalID == principal {
			out = append(out, a)
		}
	}
	return out, nil
}
func (f *fakeEntra) GetRoleAssignment(_ context.Context, id string) (*azure.RoleAssignment, error) {
	a, ok := f.ras[id]
	if !ok {
		return nil, nil
	}
	return &a, nil
}
func (f *fakeEntra) DeleteRoleAssignment(_ context.Context, id string) error {
	delete(f.ras, id)
	return nil
}
func (f *fakeEntra) PutRoleAssignment(_ context.Context, s azure.RoleAssignmentSpec) error {
	a := azure.RoleAssignment{ID: s.Scope + "/providers/microsoft.authorization/roleassignments/" + s.Name, Name: s.Name}
	a.Properties.Scope, a.Properties.PrincipalID, a.Properties.RoleDefinitionID = s.Scope, s.PrincipalID, s.RoleDefinitionID
	f.ras[a.ID] = a
	return nil
}

func entraRun(t *testing.T, e *EntraEngine, steps []Step) []Step {
	t.Helper()
	for i := range steps {
		st := &steps[i]
		skip, err := e.Before(context.Background(), st)
		if err != nil {
			t.Fatal(err)
		}
		if skip {
			st.State = StepSkipped
			continue
		}
		st.State = StepPending
		if err := e.Apply(context.Background(), st); err != nil {
			var se *StepError
			if errors.As(err, &se) {
				st.State, st.Error = StepFailed, se.Code
				continue
			}
			t.Fatal(err)
		}
		st.State = StepApplied
	}
	return steps
}

func TestEntraDisablesAndRestoresOnlyWhatItChanged(t *testing.T) {
	sp := "11111111-2222-3333-4444-555555555555"
	scope := "/subscriptions/sub1/resourcegroups/rg"
	ra := azure.RoleAssignment{ID: scope + "/providers/microsoft.authorization/roleassignments/ra1", Name: "ra1"}
	ra.Properties.Scope, ra.Properties.PrincipalID, ra.Properties.RoleDefinitionID = scope, sp, "/providers/x/roleDefinitions/reader"
	f := &fakeEntra{enabled: map[string]bool{sp: true}, ras: map[string]azure.RoleAssignment{ra.ID: ra}}
	e := &EntraEngine{API: f, ObjectID: sp, Subscriptions: []string{"sub1"}}
	steps, err := e.Plan(context.Background())
	if err != nil || len(steps) != 2 {
		t.Fatalf("plan %v %+v", err, steps)
	}
	steps = entraRun(t, e, steps)
	if f.enabled[sp] || len(f.ras) != 0 {
		t.Fatalf("disabled and assignments removed: %+v %+v", f.enabled, f.ras)
	}
	for i := len(steps) - 1; i >= 0; i-- {
		if err := e.Restore(context.Background(), &steps[i]); err != nil {
			t.Fatal(err)
		}
	}
	if !f.enabled[sp] || len(f.ras) != 1 {
		t.Fatalf("restored: %+v %+v", f.enabled, f.ras)
	}

	// Already disabled before the stop: skipped, and release leaves it disabled.
	f.enabled[sp] = false
	steps = entraRun(t, e, []Step{{Kind: StepEntraAccount, Target: sp}})
	if steps[0].State != StepSkipped {
		t.Fatalf("an already disabled account is skipped: %+v", steps[0])
	}
	_ = e.Restore(context.Background(), &steps[0])
	if f.enabled[sp] {
		t.Error("release re-enables only what AuthSec disabled")
	}

	// Without the Graph permission: permission_missing.
	f.enabled[sp], f.denyAll = true, true
	steps = entraRun(t, e, []Step{{Kind: StepEntraAccount, Target: sp}})
	if steps[0].State != StepFailed || steps[0].Error != "permission_missing" {
		t.Errorf("a refused PATCH is permission_missing: %+v", steps[0])
	}
}

/* --------------------------------- broker ---------------------------------- */

func TestBrokerSourceIdentityFormat(t *testing.T) {
	h := "0b9c6c2e-8f7d-4f56-9a3c-1d2e3f405162"
	si := awsbroker.BrokerSourceIdentity(h, "client-1")
	if !strings.HasPrefix(si, "authsec-0b9c6c2e8f7d4f569a3c1d2e-a") || len(si) > 64 {
		t.Fatalf("source identity %q", si)
	}
	if awsbroker.BrokerSourceIdentity(h, "") != "authsec-0b9c6c2e8f7d4f569a3c1d2e" {
		t.Error("without an agent the old format")
	}
	if ok, _ := pathMatch(awsbroker.AgentSourcePattern("client-1"), si); !ok {
		t.Error("the agent pattern matches its sessions")
	}
	if ok, _ := pathMatch(awsbroker.AgentSourcePattern("client-2"), si); ok {
		t.Error("another agent's pattern does not")
	}
	if err := awsbroker.Validate(awsbroker.Request{RoleARN: "r", ExternalID: "x", SessionName: "authsec-rt-1", SourceIdentity: si,
		SessionPolicy: "{}", DurationSeconds: 900}); err != nil {
		t.Errorf("STS accepts the format: %v", err)
	}
}

func pv(in PreviewInput) *Preview {
	p := BuildPreview(in)
	return &p
}
