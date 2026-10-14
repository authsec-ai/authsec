package igagov

import (
	"strings"
	"testing"
)

func classify(t testing.TB, s *simAccount, p Plan) Classification {
	t.Helper()
	c, err := Classify(p, s.readFor(roleID, p))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// The classifier walks a first deployment through every prefix (A13, A25)
// and recognises conflicts by fact.
func TestClassify_FirstDeployment(t *testing.T) {
	s := newSim()
	s.addRole(baseRole())
	tp := mustCompile(t, targetIn(t, s, DeliveryDirect, "ec2"))
	ap, u := tp.Apply, *tp.Undo
	docs := planDocs(ap, u)

	if c := classify(t, s, ap); c.Class != ClassBefore || c.NextOp != 0 || c.Visible != 0 {
		t.Fatalf("fresh: %+v", c)
	}
	if c := classify(t, s, u); c.Class != ClassAfter {
		t.Fatalf("before the apply ran, the undo's desired state already holds: %+v", c)
	}
	s.run(t, roleID, ap, 0, 1, docs) // CreatePolicy only (A13: crash before attaching)
	if c := classify(t, s, ap); c.Class != ClassIntermediate || c.NextOp != 1 {
		t.Fatalf("after CreatePolicy: %+v", c)
	}
	s.run(t, roleID, ap, 1, 2, docs) // A25: crash after PutRolePermissionsBoundary
	if c := classify(t, s, ap); c.Class != ClassAfter || c.NextOp != 2 || c.Visible != c.Total {
		t.Fatalf("after Put: %+v", c)
	}
	if c := classify(t, s, u); c.Class != ClassBefore || c.NextOp != 0 {
		t.Fatalf("undo before: %+v", c)
	}
	// A27: crash during undo after DeleteRolePermissionsBoundary.
	s.run(t, roleID, u, 0, 1, docs)
	if c := classify(t, s, u); c.Class != ClassIntermediate || c.NextOp != 1 {
		t.Fatalf("undo mid-way: %+v", c)
	}
	s.run(t, roleID, u, 1, len(u.Ops), docs)
	if c := classify(t, s, u); c.Class != ClassAfter || c.NextOp != 3 {
		t.Fatalf("undo done: %+v", c)
	}
	if c := classify(t, s, ap); c.Class != ClassBefore {
		t.Fatalf("after undo the apply is back to before: %+v", c)
	}
}

func TestClassify_Conflicts(t *testing.T) {
	setup := func() (*simAccount, TargetPlans) {
		s := newSim()
		s.addRole(baseRole())
		tp := mustCompile(t, targetIn(t, s, DeliveryDirect, "ec2"))
		return s, tp
	}
	// The policy created with another document: plan_changed.
	s, tp := setup()
	s.addPolicy(authsecARN(), `{"Statement":[{"Effect":"Allow","NotAction":"sqs:*","Resource":"*"}]}`,
		map[string]string{TagManagedBy: TagManagedByValue, TagWorkspace: wsRef, TagControl: ctlID}, 1)
	if c := classify(t, s, tp.Apply); c.Class != ClassConflict || c.Reason != ConflictPlanChanged {
		t.Fatalf("other document: %+v", c)
	}
	// Another workspace's policy of the same name: artifact_owned_elsewhere.
	s.policies[authsecARN()].tags[TagWorkspace] = "other-ws"
	h := tp.Apply.Documents[0]
	s.policies[authsecARN()].doc = h.Canonical
	if c := classify(t, s, tp.Apply); c.Class != ClassConflict || c.Reason != ConflictOwnedElsewhere {
		t.Fatalf("owned elsewhere: %+v", c)
	}
	// A third boundary: plan_changed.
	s, tp = setup()
	s.addPolicy(teamBoundaryARN, customerBoundary, nil, 1)
	s.roles[roleID].BoundaryARN = teamBoundaryARN
	if c := classify(t, s, tp.Apply); c.Class != ClassConflict || c.Reason != ConflictPlanChanged {
		t.Fatalf("third boundary: %+v", c)
	}
	// Recreated and deleted role.
	s, tp = setup()
	r := s.roles[roleID]
	delete(s.roles, roleID)
	if c, _ := Classify(tp.Apply, s.read(roleID, authsecARN())); c.Class != ClassConflict || c.Reason != ConflictRoleGone {
		t.Fatalf("gone: %+v", c)
	}
	r.RoleID = "AROAEXAMPLERECREATED1"
	s.roles[roleID] = r
	if c := classify(t, s, tp.Apply); c.Class != ClassConflict || c.Reason != ConflictRoleRecreated {
		t.Fatalf("recreated: %+v", c)
	}
	// The role's own policies changed before the first write: the apply's
	// precondition no longer holds (plan_changed). After the first write
	// they no longer decide recovery (D33).
	s, tp = setup()
	s.roles[roleID].ManagedPolicies = append(s.roles[roleID].ManagedPolicies, PolicyRef{Ref: "arn:aws:iam::aws:policy/ReadOnlyAccess", DocumentHash: "sha256:9"})
	if c := classify(t, s, tp.Apply); c.Class != ClassConflict || c.Reason != ConflictRoleDefinition {
		t.Fatalf("role definition: %+v", c)
	}
	s.run(t, roleID, tp.Apply, 0, 1, planDocs(tp.Apply))
	if c := classify(t, s, tp.Apply); c.Class != ClassIntermediate {
		t.Fatalf("role definition mid-way: %+v", c)
	}
}

// A15: a customer edit of AuthSec's policy before undo blocks it with the
// diff; A35: a new user of the policy blocks it as consumers changed.
func TestClassify_UndoBlocked_A15_A35(t *testing.T) {
	s := newSim()
	s.addRole(baseRole())
	tp := mustCompile(t, targetIn(t, s, DeliveryDirect, "ec2"))
	docs := planDocs(tp.Apply, *tp.Undo)
	s.run(t, roleID, tp.Apply, 0, 2, docs)
	s.policies[authsecARN()].doc = `{"Statement":[{"Effect":"Allow","NotAction":"ec2:Run*","Resource":"*"}]}`
	c := classify(t, s, *tp.Undo)
	if c.Class != ClassConflict || c.Reason != ConflictChangedOutside || len(c.Conflicts) != 1 || c.Conflicts[0].Kind != FactPolicyDocument {
		t.Fatalf("A15: %+v", c)
	}
	// A35: attached to a second role, as boundary then as permissions policy.
	for _, usage := range []string{UsageBoundary, UsagePermissions} {
		s := newSim()
		s.addRole(baseRole())
		s.run(t, roleID, tp.Apply, 0, 2, docs)
		b := s.addRole(roleB())
		if usage == UsageBoundary {
			b.BoundaryARN = authsecARN()
		} else {
			s.policies[authsecARN()].permUsers = []AttachedEntity{{Kind: "role", ID: roleBID, Name: "ReportsRole", Usage: UsagePermissions}}
		}
		if c := classify(t, s, *tp.Undo); c.Class != ClassConflict || c.Reason != ConflictConsumersChanged {
			t.Fatalf("A35 %s: %+v", usage, c)
		}
	}
}

// A35 / A40 / A41: the role-only recovery plan — its own hash, verified
// with the second role untouched, and a crash after the detach recognised
// as done without ever deleting the policy.
func TestRoleOnlyRecovery_A35_A40_A41(t *testing.T) {
	s := newSim()
	s.addRole(baseRole())
	tp := mustCompile(t, targetIn(t, s, DeliveryDirect, "ec2"))
	docs := planDocs(tp.Apply, *tp.Undo)
	s.run(t, roleID, tp.Apply, 0, 2, docs)
	b := s.addRole(roleB())
	b.BoundaryARN = authsecARN()

	ev := evidenceFor(t, []string{"ec2"}, evOpts{})
	rp, err := CompileRoleOnlyRecovery(RecoveryInput{Control: testControl(), Undo: *tp.Undo, UndoneDeploymentID: depID,
		Live: s.read(roleID), Evidence: ev})
	if err != nil {
		t.Fatal(err)
	}
	if !rp.Eligible() || rp.Kind != PlanUndo || rp.DesiredAttachment != AttachmentAbsent || rp.ArtifactDisposition != DispositionRetainShared ||
		deref(rp.ReplacedBoundaryARN) != authsecARN() || opNames(rp) != "DeleteRolePermissionsBoundary" {
		t.Fatalf("recovery: %+v %v", rp, rp.Refusals)
	}
	if rp.PlanHash == tp.Undo.PlanHash || rp.PreconditionHash == tp.Undo.PreconditionHash {
		t.Fatal("the recovery plan needs its own approval: its hashes differ from the undo's")
	}
	if c := classify(t, s, rp); c.Class != ClassBefore {
		t.Fatalf("%+v", c)
	}
	snapB, docBefore := s.roles[roleBID].BoundaryARN, s.policies[authsecARN()].doc
	// A41: the detach happened, the worker crashed; the new owner classifies.
	s.run(t, roleID, rp, 0, 1, docs)
	c := classify(t, s, rp)
	if c.Class != ClassAfter || c.NextOp != len(rp.Ops) {
		t.Fatalf("A41: %+v", c)
	}
	for _, op := range rp.Ops {
		if op.Op == OpDeletePolicy {
			t.Fatal("a retain_shared plan never deletes the policy")
		}
	}
	if s.roles[roleBID].BoundaryARN != snapB || s.policies[authsecARN()].doc != docBefore || s.roles[roleID].BoundaryARN != "" {
		t.Fatal("A40: the second role and the policy must be unchanged")
	}

	// Earlier-document case: a -u policy holding the earlier document.
	s2, v1 := authsecWorld(t, []string{"sqs"}, 1)
	tp2 := mustCompile(t, targetIn(t, s2, DeliveryDirect, "sns", "sqs"))
	s2.run(t, roleID, tp2.Apply, 0, len(tp2.Apply.Ops), planDocs(tp2.Apply, *tp2.Undo))
	b2 := s2.addRole(roleB())
	b2.BoundaryARN = authsecARN()
	uarn, _ := RecoveryPolicyARN("aws", acct, roleID, depID)
	ev2 := evidenceFor(t, []string{"sns", "sqs"}, evOpts{})
	rp2, err := CompileRoleOnlyRecovery(RecoveryInput{Control: testControl(), Undo: *tp2.Undo, UndoneDeploymentID: depID,
		EarlierDocument: v1, Live: s2.read(roleID, uarn), Evidence: ev2})
	if err != nil {
		t.Fatal(err)
	}
	if !rp2.Eligible() || rp2.DesiredAttachment != AttachmentPresent || deref(rp2.DesiredBoundaryARN) != uarn ||
		!strings.HasSuffix(uarn, "-ud0e1f2a3") || deref(rp2.ReplacedBoundaryARN) != authsecARN() ||
		rp2.ArtifactDisposition != DispositionRetainShared || opNames(rp2) != "CreatePolicy,PutRolePermissionsBoundary" {
		t.Fatalf("-u recovery: %+v %v", rp2, rp2.Refusals)
	}
	s2.run(t, roleID, rp2, 0, len(rp2.Ops), planDocs(rp2))
	if c := classify(t, s2, rp2); c.Class != ClassAfter {
		t.Fatalf("-u after: %+v", c)
	}
	// Without other users, the ordinary undo is the plan to run.
	s3 := newSim()
	s3.addRole(baseRole())
	s3.run(t, roleID, tp.Apply, 0, 2, docs)
	rp3, err := CompileRoleOnlyRecovery(RecoveryInput{Control: testControl(), Undo: *tp.Undo, UndoneDeploymentID: depID, Live: s3.read(roleID), Evidence: ev})
	if err != nil || rp3.Eligible() || !hasRefusal(rp3, RefuseRoleOnlyNotNeeded) {
		t.Fatalf("not needed: %v %v", err, rp3.Refusals)
	}
}

// A60 / A64: undo of a J2 split copy is verified only when the copy is gone
// and the shared policy and role B are unchanged; any combination is
// pending for IaC; a third user of the copy blocks it and the role-only
// recovery re-points the role leaving the copy to its users.
func TestSplitUndo_A60_A64(t *testing.T) {
	s := customerWorld(true)
	tp := mustCompile(t, targetIn(t, s, DeliveryIaCPR, "sqs"))
	docs := planDocs(tp.Apply, *tp.Undo)
	s.run(t, roleID, tp.Apply, 0, len(tp.Apply.Ops), docs)
	if c := classify(t, s, tp.Apply); c.Class != ClassAfter || c.NextOp != -1 {
		t.Fatalf("split applied: %+v", c)
	}
	u := *tp.Undo
	copyARN := deref(u.ReplacedBoundaryARN)
	// The pipeline re-points the role first and is held (A64).
	s.roles[roleID].BoundaryARN = teamBoundaryARN
	c := classify(t, s, u)
	if c.Class != ClassIntermediate || c.Visible != 1 || c.Total != 2 {
		t.Fatalf("mid-way: %+v", c)
	}
	// The same state is NOT a prefix of a direct undo's op order... and a
	// state AuthSec would never produce (copy deleted while still used) is
	// pending for IaC but a conflict for direct delivery.
	s2 := customerWorld(true)
	s2.run(t, roleID, tp.Apply, 0, len(tp.Apply.Ops), docs)
	lr := s2.readFor(roleID, u)
	lr.Policies[copyARN] = nil // NoSuchEntity while the role still names it
	if c, _ := Classify(u, lr); c.Class != ClassIntermediate {
		t.Fatalf("IaC any combination: %+v", c)
	}
	direct := u
	direct.Delivery = DeliveryDirect
	if c, _ := Classify(direct, lr); c.Class != ClassConflict || c.Reason != ConflictNotAPrefix {
		t.Fatalf("direct non-prefix: %+v", c)
	}
	// Finish: copy gone → after.
	s.run(t, roleID, u, 1, len(u.Ops), docs)
	if c := classify(t, s, u); c.Class != ClassAfter {
		t.Fatalf("after: %+v", c)
	}
	// A third policy attached by the pipeline to the role: conflict.
	s.addPolicy("arn:aws:iam::"+acct+":policy/Third", `{"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`, nil, 1)
	s.roles[roleID].BoundaryARN = "arn:aws:iam::" + acct + ":policy/Third"
	if c := classify(t, s, u); c.Class != ClassConflict || c.Reason != ConflictChangedOutside {
		t.Fatalf("third boundary: %+v", c)
	}

	// The copy gains a third role: undo blocked; role-only recovery.
	s = customerWorld(true)
	s.run(t, roleID, tp.Apply, 0, len(tp.Apply.Ops), docs)
	third := LiveRole{RoleID: roleCID, ARN: "arn:aws:iam::" + acct + ":role/Third", Name: "Third", Path: "/", AccountID: acct, BoundaryARN: copyARN}
	s.addRole(third)
	if c := classify(t, s, u); c.Class != ClassConflict || c.Reason != ConflictConsumersChanged {
		t.Fatalf("copy shared: %+v", c)
	}
	rp, err := CompileRoleOnlyRecovery(RecoveryInput{Control: testControl(), Undo: u, UndoneDeploymentID: depID, Live: s.read(roleID),
		Evidence: evidenceFor(t, []string{"sqs"}, evOpts{})})
	if err != nil {
		t.Fatal(err)
	}
	if !rp.Eligible() || deref(rp.DesiredBoundaryARN) != teamBoundaryARN || deref(rp.ReplacedBoundaryARN) != copyARN ||
		rp.ArtifactDisposition != DispositionRetainShared || opNames(rp) != "PutRolePermissionsBoundary" {
		t.Fatalf("split recovery: %+v %v", rp, rp.Refusals)
	}
	s.run(t, roleID, rp, 0, 1, planDocs(rp))
	if c := classify(t, s, rp); c.Class != ClassAfter || s.roles[roleCID].BoundaryARN != copyARN {
		t.Fatalf("split recovery after: %+v", c)
	}
}

// §8.1: an unknown attempt resolves from the state before or after the op.
func TestResolveUnknownOp(t *testing.T) {
	s, _ := authsecWorld(t, []string{"sqs"}, 1)
	tp := mustCompile(t, targetIn(t, s, DeliveryDirect, "sns", "sqs"))
	ap := tp.Apply // CreatePolicyVersion, TagPolicy
	r, err := ResolveUnknownOp(ap, 0, s.readFor(roleID, ap))
	if err != nil || r.Resolution != ResolvedNotApplied {
		t.Fatalf("not applied: %+v %v", r, err)
	}
	s.run(t, roleID, ap, 0, 1, planDocs(ap))
	if r, _ := ResolveUnknownOp(ap, 0, s.readFor(roleID, ap)); r.Resolution != ResolvedApplied {
		t.Fatalf("applied (A26/A58a): %+v", r)
	}
	// A26: classified as post-state; the next op is the idempotent tag.
	if c := classify(t, s, ap); c.Class != ClassAfter || c.NextOp != 1 || ap.Ops[c.NextOp].Op != OpTagPolicy {
		t.Fatalf("A26: %+v", c)
	}
	if r, _ := ResolveUnknownOp(ap, 1, s.readFor(roleID, ap)); r.Resolution != ResolvedUnobservable {
		t.Fatalf("tag: %+v", r)
	}
	s.policies[authsecARN()].doc = `{"Statement":[{"Effect":"Allow","NotAction":"kms:*","Resource":"*"}]}`
	if r, _ := ResolveUnknownOp(ap, 0, s.readFor(roleID, ap)); r.Resolution != ResolvedConflict {
		t.Fatalf("conflict: %+v", r)
	}
	if _, err := ResolveUnknownOp(ap, 7, s.readFor(roleID, ap)); err == nil {
		t.Fatal("out of range")
	}
}

// §8.5 response table.
func TestClassifyOpResponse(t *testing.T) {
	s := newSim()
	s.addRole(baseRole())
	tp := mustCompile(t, targetIn(t, s, DeliveryDirect, "ec2"))
	ap, u := tp.Apply, *tp.Undo
	docs := planDocs(ap, u)
	empty := s.readFor(roleID, ap)
	check := func(name string, got OpOutcome, want, reason string) {
		t.Helper()
		if got.Outcome != want || (reason != "" && got.Reason != reason) {
			t.Errorf("%s: %+v, want %s %s", name, got, want, reason)
		}
	}
	check("ok", ClassifyOpResponse(ap, 0, RespOK, "", empty), OutcomeOK, "")
	check("no answer", ClassifyOpResponse(ap, 0, RespNoAnswer, "", empty), OutcomeUnknown, "")
	check("5xx", ClassifyOpResponse(ap, 0, RespError, "ServiceFailure", empty), OutcomeUnknown, "")
	check("throttled", ClassifyOpResponse(ap, 0, RespError, "Throttling", empty), OutcomeRetryable, "")
	s.run(t, roleID, ap, 0, 1, docs)
	check("exists, ours", ClassifyOpResponse(ap, 0, RespError, "EntityAlreadyExists", s.readFor(roleID, ap)), OutcomeRecognisedDone, "")
	s.policies[authsecARN()].tags[TagWorkspace] = "other-ws"
	check("exists, elsewhere", ClassifyOpResponse(ap, 0, RespError, "EntityAlreadyExists", s.readFor(roleID, ap)), OutcomeTerminal, ConflictOwnedElsewhere)
	s.policies[authsecARN()].tags[TagWorkspace] = wsRef
	check("put denied", ClassifyOpResponse(ap, 1, RespError, "AccessDenied", s.readFor(roleID, ap)), OutcomeTerminal, "binding_partial")
	check("put role gone", ClassifyOpResponse(ap, 1, RespError, "NoSuchEntity", s.readFor(roleID, ap)), OutcomeTerminal, ConflictRoleGone)
	s.run(t, roleID, ap, 1, 2, docs)
	check("put already", ClassifyOpResponse(ap, 1, RespError, "AccessDenied", s.readFor(roleID, ap)), OutcomeRecognisedDone, "")
	check("delete policy gone", ClassifyOpResponse(u, 2, RespError, "NoSuchEntity", s.readFor(roleID, u)), OutcomeRecognisedDone, "")
	check("delete conflict", ClassifyOpResponse(u, 2, RespError, "DeleteConflict", s.readFor(roleID, u)), OutcomeTerminal, "attached_elsewhere")
	check("version gone", ClassifyOpResponse(u, 1, RespError, "NoSuchEntity", s.readFor(roleID, u)), OutcomeRecognisedDone, "")
	s.roles[roleID].BoundaryARN = ""
	check("detach already", ClassifyOpResponse(u, 0, RespError, "NoSuchEntity", s.readFor(roleID, u)), OutcomeRecognisedDone, "")
	s.roles[roleID].BoundaryARN = teamBoundaryARN
	s.addPolicy(teamBoundaryARN, customerBoundary, nil, 1)
	check("detach another", ClassifyOpResponse(u, 0, RespError, "AccessDenied", s.readFor(roleID, u)), OutcomeTerminal, "blocked: another boundary is attached")

	s2, _ := authsecWorld(t, []string{"sqs"}, 5)
	v2 := mustCompile(t, targetIn(t, s2, DeliveryDirect, "sns", "sqs")).Apply
	check("limit after prune", ClassifyOpResponse(v2, 1, RespError, "LimitExceeded", s2.readFor(roleID, v2)), OutcomeTerminal, "version_limit_after_prune")
	s2.run(t, roleID, v2, 0, 2, planDocs(v2))
	check("version not needed", ClassifyOpResponse(v2, 1, RespError, "LimitExceeded", s2.readFor(roleID, v2)), OutcomeNotNeeded, "")
}

// §8.10: remove AuthSec control restores the baseline.
func TestCompileRemoveControl(t *testing.T) {
	ev := func() EvidenceRef { return evidenceFor(t, []string{"ec2"}, evOpts{}) }
	// Baseline: no boundary. AuthSec boundary deployed.
	s := newSim()
	s.addRole(baseRole())
	tp := mustCompile(t, targetIn(t, s, DeliveryDirect, "ec2"))
	s.run(t, roleID, tp.Apply, 0, 2, planDocs(tp.Apply))
	last := BoundaryRef{ARN: authsecARN(), DocumentHash: deref(tp.Apply.DesiredDocumentHash)}
	in := RemoveControlInput{Control: testControl(), LastDeployed: last, Delivery: DeliveryDirect, Live: s.read(roleID), Evidence: ev(),
		ExcludedServices: []string{"ec2"}}
	p, err := CompileRemoveControl(in)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Eligible() || p.Kind != PlanRemoveControl || p.DesiredAttachment != AttachmentAbsent || p.ArtifactDisposition != DispositionDelete ||
		deref(p.ReplacedBoundaryARN) != authsecARN() || opNames(p) != "DeleteRolePermissionsBoundary,DeletePolicyVersion,DeletePolicy" ||
		len(p.Impact.Restored) != 1 || p.Impact.Restored[0].Service != "ec2" {
		t.Fatalf("remove (none baseline): %+v %v", p, p.Refusals)
	}
	s.run(t, roleID, p, 0, len(p.Ops), planDocs(p))
	if c := classify(t, s, p); c.Class != ClassAfter {
		t.Fatalf("%+v", c)
	}
	// The policy gained another user: retain_shared, detach only.
	s = newSim()
	s.addRole(baseRole())
	s.run(t, roleID, tp.Apply, 0, 2, planDocs(tp.Apply))
	b := s.addRole(roleB())
	b.BoundaryARN = authsecARN()
	in.Live = s.read(roleID)
	p, _ = CompileRemoveControl(in)
	if p.ArtifactDisposition != DispositionRetainShared || opNames(p) != "DeleteRolePermissionsBoundary" {
		t.Fatalf("retain shared: %+v", p)
	}
	// The customer changed the boundary since: blocked with the diff.
	s.policies[authsecARN()].doc = `{"Statement":[{"Effect":"Allow","NotAction":"ec2:Run*","Resource":"*"}]}`
	in.Live = s.read(roleID)
	if p, _ := CompileRemoveControl(in); p.Eligible() || !hasRefusal(p, RefuseChangedOutsideAuthSec) {
		t.Fatalf("changed: %v", p.Refusals)
	}
	// No boundary at all: nothing to remove.
	s = newSim()
	s.addRole(baseRole())
	in.Live = s.read(roleID)
	if _, err := CompileRemoveControl(in); err == nil || !strings.Contains(err.Error(), ErrCodeNoArtifact) {
		t.Fatal(err)
	}

	// Baseline: exclusive customer boundary narrowed in place.
	s = customerWorld(false)
	ctp := mustCompile(t, targetIn(t, s, DeliveryIaCPR, "sqs"))
	s.run(t, roleID, ctp.Apply, 0, len(ctp.Apply.Ops), planDocs(ctp.Apply))
	baseHash, _ := DocumentHash(customerBoundary)
	cin := RemoveControlInput{Control: testControl(), Baseline: Baseline{BoundaryARN: strPtr(teamBoundaryARN), DocumentHash: strPtr(baseHash), Document: customerBoundary},
		LastDeployed: BoundaryRef{teamBoundaryARN, deref(ctp.Apply.DesiredDocumentHash)}, Delivery: DeliveryIaCPR, Live: s.read(roleID), Evidence: ev()}
	p, err = CompileRemoveControl(cin)
	if err != nil {
		t.Fatal(err)
	}
	if p.Eligibility != EligibilityIaCOnly || p.DesiredAttachment != AttachmentPresent || deref(p.DesiredDocumentHash) != baseHash ||
		p.ArtifactDisposition != DispositionKeep || opNames(p) != "CreatePolicyVersion" {
		t.Fatalf("in place: %+v %v", p, p.Refusals)
	}
	cin.Delivery = DeliveryDirect
	if p, _ := CompileRemoveControl(cin); p.Eligible() || !hasRefusal(p, RefuseDirectNeedsAuthSecTarget) {
		t.Fatalf("direct on a customer boundary: %v", p.Refusals)
	}
	cin.Delivery = DeliveryIaCPR
	b = s.addRole(roleB())
	b.BoundaryARN = teamBoundaryARN
	cin.Live = s.read(roleID)
	if p, _ := CompileRemoveControl(cin); !hasRefusal(p, RefuseConsumersChanged) {
		t.Fatalf("in place with a new user: %v", p.Refusals)
	}

	// Baseline: shared boundary split → re-point, delete the copy.
	s = customerWorld(true)
	stp := mustCompile(t, targetIn(t, s, DeliveryIaCPR, "sqs"))
	s.run(t, roleID, stp.Apply, 0, len(stp.Apply.Ops), planDocs(stp.Apply))
	copyARN := deref(stp.Apply.DesiredBoundaryARN)
	s.policies[teamBoundaryARN].doc = `{"Statement":[{"Sid":"Changed","Effect":"Allow","Action":"s3:*","Resource":"*"}]}`
	sin := RemoveControlInput{Control: testControl(), Baseline: Baseline{BoundaryARN: strPtr(teamBoundaryARN), DocumentHash: strPtr(baseHash), Document: customerBoundary},
		LastDeployed: BoundaryRef{copyARN, deref(stp.Apply.DesiredDocumentHash)}, Delivery: DeliveryExport, Live: s.read(roleID), Evidence: ev()}
	p, err = CompileRemoveControl(sin)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Eligible() || deref(p.DesiredBoundaryARN) != teamBoundaryARN || deref(p.ReplacedBoundaryARN) != copyARN ||
		p.ArtifactDisposition != DispositionDelete || opNames(p) != "PutRolePermissionsBoundary,DeletePolicyVersion,DeletePolicy" ||
		!strings.Contains(strings.Join(p.Diff.Notes, ","), NoteBaselineDocChanged) {
		t.Fatalf("re-point: %+v %v", p, p.Refusals)
	}
	for _, op := range p.Ops {
		if op.PolicyARN == teamBoundaryARN && op.Op != OpPutRolePermissionsBoundary {
			t.Fatal("restoring a baseline never writes a shared document")
		}
	}
}

// §11: split and split_revert.
func TestCompileSplit(t *testing.T) {
	s := newSim()
	src := baseRole()
	s.addRole(src)
	newARN := "arn:aws:iam::" + acct + ":role/refund-reconciler-role"
	ev := evidenceFor(t, nil, evOpts{})
	intent := DedicatedIdentityIntent{Kind: IntentDedicatedIdentity,
		Source:   Subject{IdentityAccountID: identityID, RoleID: roleID, AccountID: acct},
		Workload: DedicatedWorkload{WorkloadID: identityID, BindingKind: BindingLambdaRole, BindingRef: "arn:aws:lambda:us-east-1:" + acct + ":function:refund"},
		NewRole: NewRole{Name: "refund-reconciler-role", Path: "/", TrustPolicyHash: src.TrustPolicyHash,
			ManagedPolicyARNs: []string{src.ManagedPolicies[0].Ref},
			InlinePolicies:    []InlinePolicyRef{{Name: "refund-inline", DocumentHash: src.InlinePolicies[0].DocumentHash}}},
		Delivery: DeliveryIaCPR}
	queueARN := "arn:aws:sqs:us-east-1:" + acct + ":refunds"
	scan := &ResourcePolicyEvidence{Coverage: completeCoverage(), Observations: []ResourcePolicyObservation{
		queue(t, "refunds", `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"`+roleARN+`"},"Action":"sqs:*","Resource":"*"}]}`)}}
	lr := s.read(roleID)
	lr.Roles = map[string]*LiveRole{newARN: nil}
	in := SplitInput{Control: testControl(), Intent: intent, Live: lr, Evidence: ev, SubjectKind: SubjectLambdaFunction,
		SubjectARN: intent.Workload.BindingRef, FromWorkloadKeys: []string{"lambda:refund"}, Aliases: []string{"live"},
		UnaliasedVersions: []string{"refund:3"}, ScanEvidence: scan, AccountServices: []string{"sqs"},
		MappedResources: map[string]bool{queueARN: true}, MigrationEvidenceAvailable: true}
	sp, err := CompileSplit(in)
	if err != nil {
		t.Fatal(err)
	}
	p := sp.Split
	if !p.Eligible() || p.Kind != PlanSplit || p.DesiredAttachment != AttachmentUnchanged || p.Eligibility != EligibilityIaCOnly ||
		p.DesiredBoundaryARN != nil || p.ArtifactDisposition != DispositionKeep ||
		opNames(p) != "CreateRole,AttachRolePolicy,PutRolePolicy,AddResourcePolicyPrincipal,BindSubject" {
		t.Fatalf("split: %+v %v", p, p.Refusals)
	}
	var keys []string
	for _, u := range p.Unanalysed {
		keys = append(keys, u.Key)
	}
	if strings.Join(keys, ",") != "kms_grants,lambda_version_without_alias:refund:3,other_accounts,scp_rcp" {
		t.Fatalf("unanalysed: %v", keys)
	}
	if p.Diff.Split == nil || len(p.Diff.Split.Compatibility) != 1 || p.Diff.Split.Compatibility[0].Handling != HandlingPR {
		t.Fatalf("compat: %+v", p.Diff.Split)
	}
	rv := sp.Revert
	if rv == nil || rv.Kind != PlanSplitRevert || rv.DesiredAttachment != AttachmentUnchanged ||
		opNames(*rv) != "BindSubject,RemoveResourcePolicyPrincipal,DeleteRole" || !rv.Ops[2].OnlyIfUnused {
		t.Fatalf("revert: %+v", rv)
	}
	// Classifier over split facts: subject moved + new role present → after.
	newRole := LiveRole{RoleID: "AROANEWROLE00000001", ARN: newARN, TrustPolicyHash: src.TrustPolicyHash,
		ManagedPolicies: src.ManagedPolicies, InlinePolicies: src.InlinePolicies}
	live := s.read(roleID)
	live.Roles = map[string]*LiveRole{newARN: &newRole}
	live.Bindings = map[string]string{in.SubjectARN: newARN}
	if c, err := Classify(p, live); err != nil || c.Class != ClassAfter {
		t.Fatalf("split after: %+v %v", c, err)
	}
	if c, _ := Classify(*rv, live); c.Class != ClassBefore {
		t.Fatalf("revert before: %+v", c)
	}
	live.Bindings[in.SubjectARN] = roleARN
	if c, _ := Classify(p, live); c.Class != ClassIntermediate {
		t.Fatalf("role created, not moved: %+v", c)
	}
	// Not baseline-preserving; no migration evidence; wrong binding.
	bad := in
	bad.Intent.NewRole.ManagedPolicyARNs = nil
	bad.MigrationEvidenceAvailable = false
	bad.SubjectKind = SubjectECSService
	sp, _ = CompileSplit(bad)
	if sp.Split.Eligible() || !hasRefusal(sp.Split, RefuseNewRoleNotBaselinePreserve) || !hasRefusal(sp.Split, RefuseMigrationEvidence) ||
		!hasRefusal(sp.Split, RefuseSubjectBindingMismatch) || sp.Revert != nil {
		t.Fatalf("refusals: %v", sp.Split.Refusals)
	}
	// DB40: a split delivered direct is refused by the intent and the CHECK.
	dir := in
	dir.Intent.Delivery = DeliveryDirect
	if _, err := CompileSplit(dir); err == nil {
		t.Fatal("a direct split must not compile")
	}
	x := p
	x.Delivery = DeliveryDirect
	if err := x.CheckStorable(); err == nil || !strings.Contains(err.Error(), "iga_gov_plan_kind_chk") {
		t.Fatal("DB40 mirror")
	}
}
