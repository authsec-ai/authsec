package igagov

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// A1 / A29: no boundary → AuthSecBoundary-<RoleId> with the exclusion-only
// document; identity statements of any shape (NotAction) do not block; the
// undo names the policy it installed and deletes it.
func TestCompile_FirstAttachment_A1_A29(t *testing.T) {
	s := newSim()
	r := baseRole()
	// An identity statement using NotAction is irrelevant to compilation.
	r.InlinePolicies = append(r.InlinePolicies, PolicyRef{Ref: "broad-notaction", DocumentHash: "sha256:" + strings.Repeat("5", 64)})
	s.addRole(r)
	tp := mustCompile(t, targetIn(t, s, DeliveryDirect, "ec2"))
	ap := tp.Apply
	if ap.Eligibility != EligibilityEligible || ap.Kind != PlanApply || ap.DesiredAttachment != AttachmentPresent ||
		deref(ap.DesiredBoundaryARN) != authsecARN() || ap.ReplacedBoundaryARN != nil || ap.ArtifactDisposition != DispositionKeep ||
		!ap.FirstAttachment || deref(ap.ResourcePolicyScanRunID) != runA1 || ap.BeforeDocumentHash != nil {
		t.Fatalf("apply shape: %+v refusals %v", ap, ap.Refusals)
	}
	want := `{"Statement":[{"Effect":"Allow","NotAction":["ec2:*"],"Resource":"*","Sid":"AuthSecAllowAllExceptRemoved"}],"Version":"2012-10-17"}`
	if len(ap.Documents) != 1 || ap.Documents[0].Canonical != want || ap.Documents[0].Hash != deref(ap.DesiredDocumentHash) {
		t.Fatalf("boundary document: %+v", ap.Documents)
	}
	if opNames(ap) != "CreatePolicy,PutRolePermissionsBoundary" || ap.Ops[0].Path != "/authsec/" ||
		ap.Ops[0].PolicyName != "AuthSecBoundary-"+roleID || ap.Ops[0].Tags[TagControl] != ctlID ||
		ap.Ops[0].Tags[TagWorkspace] != wsRef || ap.Ops[0].Tags[TagChange] != DeploymentPlaceholder || ap.Ops[1].RoleName != roleName {
		t.Fatalf("ops: %+v", ap.Ops)
	}
	if ap.Diff.Case != CaseNoneToAuthSec || strings.Join(ap.Diff.NewlyExcluded, ",") != "ec2" {
		t.Fatalf("diff: %+v", ap.Diff)
	}
	u := tp.Undo
	if u == nil || u.Kind != PlanUndo || u.DesiredAttachment != AttachmentAbsent || deref(u.ReplacedBoundaryARN) != authsecARN() ||
		u.ArtifactDisposition != DispositionDelete || u.DesiredBoundaryARN != nil || u.FirstAttachment ||
		opNames(*u) != "DeleteRolePermissionsBoundary,DeletePolicyVersion,DeletePolicy" ||
		strings.Join(u.Diff.NewlyUnexcluded, ",") != "ec2" || len(u.Impact.Restored) != 1 {
		t.Fatalf("undo: %+v", u)
	}
	// The undo's precondition is artifact_state after the apply: this
	// boundary, its document, attachment set = {this role}.
	var pre struct {
		ArtifactState ArtifactStateFacts `json:"artifact_state"`
	}
	if err := json.Unmarshal(u.Precondition, &pre); err != nil {
		t.Fatal(err)
	}
	if deref(pre.ArtifactState.BoundaryARN) != authsecARN() || deref(pre.ArtifactState.BoundaryDocumentHash) != deref(ap.DesiredDocumentHash) ||
		len(pre.ArtifactState.AttachmentSet) != 1 || pre.ArtifactState.AttachmentSet[0].ID != roleID {
		t.Fatalf("undo precondition: %s", u.Precondition)
	}
	h, _ := StatePreconditionHash(pre.ArtifactState)
	if h != u.PreconditionHash {
		t.Fatal("undo precondition hash is not StatePreconditionHash of its precondition")
	}
	ah, _ := ApplyPreconditionFor(s.read(roleID))
	if x, _ := ApplyPreconditionHash(ah); x != ap.PreconditionHash {
		t.Fatal("apply precondition hash is not ApplyPreconditionHash of the live read")
	}
	if ap.PlanHash == u.PlanHash || ap.MaterialHash == u.MaterialHash {
		t.Fatal("apply and undo must hash differently")
	}
	// Applying the ops really excludes ec2 and nothing else (A29).
	d, _ := DecodePolicyDocument(ap.Documents[0].Canonical)
	if !BoundaryExcludes(d, "ec2") || BoundaryExcludes(d, "s3") || BoundaryExcludes(d, "sqs") {
		t.Fatal("the boundary must exclude only ec2")
	}
}

// A34: the first-attachment proof refuses, in turn, an older template, an
// unreadable access-point form, an exempting Deny + NotPrincipal; then
// offers the plan with the unanalysed set to accept.
func TestFirstAttachmentProof_A34(t *testing.T) {
	s := newSim()
	s.addRole(baseRole())
	base := func() TargetInput { return targetIn(t, s, DeliveryDirect, "ec2") }

	// (a) Older template: every collected form not_collected.
	in := base()
	notCollected := []CoverageRow{}
	for _, c := range completeCoverage() {
		c.State = CoverageNotCollected
		notCollected = append(notCollected, c)
	}
	in.ScanEvidence = &ResourcePolicyEvidence{Coverage: notCollected}
	p := mustCompile(t, in).Apply
	if p.Eligible() || !hasRefusal(p, RefuseEvidenceIncomplete) || len(p.Ops) != 0 {
		t.Fatalf("older template: %v", p.Refusals)
	}
	// No resource-policy evidence at all: the same refusal.
	in.ScanEvidence = nil
	if p := mustCompile(t, in).Apply; p.Eligible() || !hasRefusal(p, RefuseEvidenceIncomplete) {
		t.Fatal("no evidence must refuse a first attachment")
	}

	// (b) One S3 access point region partial, named.
	in = base()
	rows := completeCoverage()
	for i := range rows {
		if rows[i].Form == "s3_access_point" && rows[i].Region == "eu-west-1" {
			rows[i].State = CoveragePartial
		}
	}
	in.ScanEvidence = &ResourcePolicyEvidence{Coverage: rows}
	p = mustCompile(t, in).Apply
	if p.Eligible() || p.IneligibleReason != "resource_policy_evidence_incomplete: s3_access_point in eu-west-1 partial" {
		t.Fatalf("partial access point: %q", p.IneligibleReason)
	}

	// (c) A queue policy Deny + NotPrincipal listing the role's account.
	in = base()
	deny := `{"Statement":[{"Sid":"OnlyUs","Effect":"Deny","NotPrincipal":{"AWS":"arn:aws:iam::` + acct + `:root"},"Action":"sqs:*","Resource":"*"}]}`
	in.ScanEvidence = &ResourcePolicyEvidence{Coverage: completeCoverage(), Observations: []ResourcePolicyObservation{queue(t, "refunds", deny)}}
	p = mustCompile(t, in).Apply
	if p.Eligible() || !hasRefusal(p, RefuseBlocksBoundary) || !strings.Contains(p.IneligibleReason, ":refunds") {
		t.Fatalf("deny notprincipal: %q", p.IneligibleReason)
	}
	// A NotPrincipal naming another account does not exempt this role.
	in.ScanEvidence.Observations[0] = queue(t, "refunds", strings.ReplaceAll(deny, acct, "111122223333"))
	if p := mustCompile(t, in).Apply; !p.Eligible() {
		t.Fatalf("foreign NotPrincipal must not block: %v", p.Refusals)
	}
	// An unparseable observed policy blocks.
	ob := queue(t, "broken", "")
	ob.PolicyPresent, ob.ParseState = true, ParseUnparseable
	in.ScanEvidence.Observations = []ResourcePolicyObservation{ob}
	if p := mustCompile(t, in).Apply; p.Eligible() || !strings.Contains(p.IneligibleReason, "unparseable") {
		t.Fatalf("unparseable: %q", p.IneligibleReason)
	}

	// (d) Complete with ECR uncollected: offered, unanalysed listed.
	in = base()
	in.AccountServices = []string{"ecr", "s3", "sqs"}
	p = mustCompile(t, in).Apply
	var keys []string
	for _, u := range p.Unanalysed {
		keys = append(keys, u.Key)
	}
	if !p.Eligible() || strings.Join(keys, ",") != "other_accounts,unanalysed_form:ecr_registry,unanalysed_form:ecr_repository" {
		t.Fatalf("unanalysed: %v (%v)", keys, p.Refusals)
	}
	if p.Diff.FirstAttachment == nil || p.Diff.FirstAttachment.Blocked() {
		t.Fatal("the proof must be recorded and unblocked")
	}
}

// D24: an uncollected form already a bundle gap (the removed namespace's
// own form) is not asked for again as an unanalysed item.
func TestFirstAttachment_DedupesBundleGaps(t *testing.T) {
	s := newSim()
	s.addRole(baseRole())
	in := targetIn(t, s, DeliveryDirect, "ecr")
	in.AccountServices = []string{"ecr"}
	if len(in.Evidence.Bundle.Facts.Gaps) != 2 || in.Evidence.Bundle.Trust != TrustPartial {
		t.Fatalf("the ecr removal must carry its uncollected forms as gaps: %+v", in.Evidence.Bundle.Facts.Gaps)
	}
	p := mustCompile(t, in).Apply
	if len(p.Unanalysed) != 1 || p.Unanalysed[0].Key != unanalysedOtherAccount {
		t.Fatalf("unanalysed must not repeat gaps: %+v", p.Unanalysed)
	}
	if strings.Join(p.Diff.FirstAttachment.CoveredByGaps, ",") != "ecr_registry,ecr_repository" || len(p.GapRefs) != 2 {
		t.Fatalf("covered by gaps: %+v", p.Diff.FirstAttachment)
	}
}

// A11: ineligible roles, with reasons, and nothing to run.
func TestCompile_IneligibleRoles_A11(t *testing.T) {
	cases := []struct {
		name string
		edit func(*LiveRole)
		code string
	}{
		{"service-linked", func(r *LiveRole) { r.Path = "/aws-service-role/ecs.amazonaws.com/" }, RefuseServiceLinked},
		{"aws-reserved", func(r *LiveRole) { r.Path = "/aws-reserved/sso.amazonaws.com/" }, RefuseAWSReserved},
		{"protected", func(r *LiveRole) { r.Tags["authsec:protected"] = "true" }, RefuseProtectedRole},
		{"ManagedBy=AuthSec, customer name", func(r *LiveRole) { r.Name = "PaymentsWorker"; r.Tags["ManagedBy"] = "AuthSec" }, RefuseAuthSecManagedRole},
		{"ManagedBy case-folded", func(r *LiveRole) { r.Tags["ManagedBy"] = "authsec" }, RefuseAuthSecManagedRole},
		{"recognition only", func(r *LiveRole) { r.Continuity = ContinuityRecognition }, RefuseRecognitionOnly},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newSim()
			r := baseRole()
			c.edit(&r)
			s.addRole(r)
			tp := mustCompile(t, targetIn(t, s, DeliveryDirect, "ec2"))
			if tp.Apply.Eligible() || !hasRefusal(tp.Apply, c.code) || len(tp.Apply.Ops) != 0 || tp.Undo != nil {
				t.Fatalf("%s: %+v", c.name, tp.Apply.Refusals)
			}
		})
	}
	t.Run("oversized document", func(t *testing.T) {
		s := newSim()
		s.addRole(baseRole())
		var many []string
		for i := 0; i < 700; i++ {
			many = append(many, "svc"+strings.Repeat("x", i%7)+string(rune('a'+i%26))+string(rune('a'+(i/26)%26)))
		}
		many = sortedUnique(many)
		in := targetIn(t, s, DeliveryDirect, many...)
		in.Intent = intentFor(DeliveryDirect, many)
		p := mustCompile(t, in).Apply
		if p.Eligible() || !hasRefusal(p, RefuseDocumentTooLarge) {
			t.Fatalf("oversized: %v", p.Refusals)
		}
	})
	t.Run("role gone and recreated", func(t *testing.T) {
		s := newSim()
		p := mustCompile(t, targetIn(t, s, DeliveryDirect, "ec2")).Apply
		if !hasRefusal(p, RefuseRoleGone) {
			t.Fatal(p.Refusals)
		}
		r := baseRole()
		r.RoleID = "AROAEXAMPLERECREATED1"
		s.addRole(r)
		in := targetIn(t, s, DeliveryDirect, "ec2")
		in.Live = s.read(r.RoleID, authsecARN())
		if p := mustCompile(t, in).Apply; !hasRefusal(p, RefuseRoleRecreated) {
			t.Fatal(p.Refusals)
		}
	})
}

// §3.4 (1): every removal justified.
func TestCompile_RemovalJustification(t *testing.T) {
	s := newSim()
	s.addRole(baseRole())
	in := targetIn(t, s, DeliveryDirect, "logs")
	in.DependencyContexts = []DependencyContext{{Context: CtxLambdaExecution}}
	if p := mustCompile(t, in).Apply; p.Eligible() || p.IneligibleReason != "removal_is_dependency: logs (lambda-execution@1)" {
		t.Fatalf("dependency: %q", p.IneligibleReason)
	}
	in = targetIn(t, s, DeliveryDirect, "sqs")
	in.Evidence = evidenceFor(t, []string{"sqs"}, evOpts{actOverride: map[string]BundleActivity{"sqs": {Service: "sqs",
		State: EvidenceCollected, Outcome: QualObserved, GrantAgeBasis: GrantAgePredatesObservation, QualifiedDays: 112}}})
	if p := mustCompile(t, in).Apply; !hasRefusal(p, RefuseRemovalNotJustified) {
		t.Fatalf("observed: %v", p.Refusals)
	}
	in.Evidence = evidenceFor(t, []string{"sqs"}, evOpts{actOverride: map[string]BundleActivity{"sqs": {Service: "sqs",
		State: EvidenceCollected, Outcome: QualNoAttempt, GrantAgeBasis: GrantAgePredatesObservation, QualifiedDays: 12}}})
	if p := mustCompile(t, in).Apply; !hasRefusal(p, RefuseRemovalNotJustified) {
		t.Fatalf("short window: %v", p.Refusals)
	}
	// A removal with no activity fact: the bundle is untrusted, which blocks
	// compilation outright (§2.11).
	in.Evidence = evidenceFor(t, []string{"sqs"}, evOpts{skipActFor: map[string]bool{"sqs": true}})
	var ce *CompileError
	if _, err := CompileTarget(in); !errors.As(err, &ce) || ce.Code != ErrCodeEvidenceUntrusted {
		t.Fatalf("untrusted evidence must not compile: %v", err)
	}
	// justifyRemovals alone names a missing report line.
	if rs := justifyRemovals([]RemoveEntry{rmEntry("glue")}, nil, nil); len(rs) != 1 || rs[0].Code != RefuseNotInActivityReport {
		t.Fatal(rs)
	}
}

// A9 / A52: duplicate and independent grants are all named in the impact;
// the boundary removes the namespace whatever grants it.
func TestCompile_IndependentGrants_A9_A52(t *testing.T) {
	s := newSim()
	s.addRole(baseRole())
	in := targetIn(t, s, DeliveryDirect, "sqs")
	in.Evidence = evidenceFor(t, []string{"sqs"}, evOpts{grants: []BundleGrant{
		{PolicyARN: "arn:aws:iam::" + acct + ":policy/PolicyA", AssignmentKind: AssignAttached, StatementKey: "PA#0", StatementHash: "sha256:aa", Services: []string{"sqs"}},
		{PolicyARN: "arn:aws:iam::" + acct + ":policy/PolicyB", AssignmentKind: AssignAttached, StatementKey: "PB#0", StatementHash: "sha256:bb", Services: []string{"sqs"}},
		{PolicyARN: "arn:aws:iam::" + acct + ":policy/PolicyC", AssignmentKind: AssignAttached, StatementKey: "PC#0", StatementHash: "sha256:cc", Services: []string{"s3"}},
	}})
	p := mustCompile(t, in).Apply
	if strings.Join(p.Impact.StatementRevisions, ",") != "sha256:aa,sha256:bb" {
		t.Fatalf("statement revisions: %v", p.Impact.StatementRevisions)
	}
	d, _ := DecodePolicyDocument(p.Documents[0].Canonical)
	if !BoundaryExcludes(d, "sqs") {
		t.Fatal("sqs must be excluded")
	}
}

// A42 / A43: route usage and route effect enter the impact (and its hash).
func TestCompile_RoutesInImpact_A42_A43(t *testing.T) {
	s := newSim()
	s.addRole(baseRole())
	grant := func(principal string) string {
		return `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"` + principal + `"},"Action":"sqs:ReceiveMessage","Resource":"*"}]}`
	}
	compile := func(principal string) Plan {
		ev := &ResourcePolicyEvidence{Coverage: completeCoverage(), Observations: []ResourcePolicyObservation{queue(t, "refunds", grant(principal))}}
		in := targetIn(t, s, DeliveryDirect, "sqs")
		in.ScanEvidence = ev
		in.Evidence = evidenceFor(t, []string{"sqs"}, evOpts{scanEv: ev})
		return mustCompile(t, in).Apply
	}
	a42 := compile(roleARN)
	a43 := compile("arn:aws:sts::" + acct + ":assumed-role/" + roleName + "/worker")
	if len(a42.Impact.Routes) != 1 || a42.Impact.Routes[0].Effect != RouteEffectLimited ||
		len(a43.Impact.Routes) != 1 || a43.Impact.Routes[0].Effect != RouteEffectBypassKnown {
		t.Fatalf("routes: %+v / %+v", a42.Impact.Routes, a43.Impact.Routes)
	}
	if a42.ImpactHash == a43.ImpactHash || a42.MaterialHash == a43.MaterialHash {
		t.Fatal("a route change is material")
	}
	if !a42.Eligible() || !a43.Eligible() {
		t.Fatal("routes do not block compilation; they gate approval (409 route_unconfirmed)")
	}
}

func authsecWorld(t testing.TB, v1Remove []string, versions int) (*simAccount, string) {
	s := newSim()
	r := baseRole()
	r.BoundaryARN = authsecARN()
	s.addRole(r)
	doc, _, err := ExcludeOnlyDocument(v1Remove)
	if err != nil {
		t.Fatal(err)
	}
	s.addPolicy(authsecARN(), string(doc), map[string]string{TagManagedBy: TagManagedByValue, TagWorkspace: wsRef, TagControl: ctlID, TagPolicy: polID}, versions)
	return s, string(doc)
}

// A48: v1 excludes sqs; v2 excludes sqs and sns; undo of v2 restores v1.
func TestCompile_AuthSecVersion_A48(t *testing.T) {
	s, v1 := authsecWorld(t, []string{"sqs"}, 1)
	in := targetIn(t, s, DeliveryDirect, "sns", "sqs")
	tp := mustCompile(t, in)
	ap, u := tp.Apply, tp.Undo
	v1h, _ := DocumentHash(v1)
	if !ap.Eligible() || ap.FirstAttachment || deref(ap.BeforeDocumentHash) != v1h || deref(ap.DesiredBoundaryARN) != authsecARN() ||
		opNames(ap) != "CreatePolicyVersion,TagPolicy" || strings.Join(ap.Diff.NewlyExcluded, ",") != "sns" ||
		strings.Join(ap.Diff.AlreadyExcluded, ",") != "sqs" || len(ap.Unanalysed) != 0 {
		t.Fatalf("v2 apply: %+v %v", ap.Diff, ap.Refusals)
	}
	if u.DesiredAttachment != AttachmentPresent || deref(u.DesiredDocumentHash) != v1h || u.ReplacedBoundaryARN != nil ||
		u.ArtifactDisposition != DispositionKeep || opNames(*u) != "CreatePolicyVersion,TagPolicy" ||
		strings.Join(u.Diff.NewlyUnexcluded, ",") != "sns" || strings.Join(u.Diff.AlreadyExcluded, ",") != "sqs" {
		t.Fatalf("undo of v2: %+v", u.Diff)
	}
	// Five versions: prune the oldest non-default first, in apply and undo.
	s5, _ := authsecWorld(t, []string{"sqs"}, 5)
	tp5 := mustCompile(t, targetIn(t, s5, DeliveryDirect, "sns", "sqs"))
	if opNames(tp5.Apply) != "DeletePolicyVersion,CreatePolicyVersion,TagPolicy" || opNames(*tp5.Undo) != "DeletePolicyVersion,CreatePolicyVersion,TagPolicy" ||
		tp5.Apply.Ops[0].Select != SelectOldestNonDefault || tp5.Apply.Ops[0].IfVersionsAtLeast != 5 {
		t.Fatalf("prune: %s / %s", opNames(tp5.Apply), opNames(*tp5.Undo))
	}
	// Already in place: no ops either way.
	same := mustCompile(t, targetIn(t, s, DeliveryDirect, "sqs"))
	if len(same.Apply.Ops) != 0 || len(same.Undo.Ops) != 0 || same.Apply.Diff.Notes[0] != NoteAlreadyInPlace {
		t.Fatalf("already in place: %s", opNames(same.Apply))
	}
}

// §2.3 / §3.2: an AuthSec-path boundary that is not this control's.
func TestCompile_AuthSecBoundaryOwnership(t *testing.T) {
	s, _ := authsecWorld(t, []string{"sqs"}, 1)
	s.policies[authsecARN()].tags[TagWorkspace] = "other-ws"
	if p := mustCompile(t, targetIn(t, s, DeliveryDirect, "sqs", "sns")).Apply; !hasRefusal(p, RefuseArtifactOwnedElsewhere) {
		t.Fatal(p.Refusals)
	}
	s, _ = authsecWorld(t, []string{"sqs"}, 1)
	s.policies[authsecARN()].tags[TagControl] = "another-control"
	if p := mustCompile(t, targetIn(t, s, DeliveryDirect, "sqs", "sns")).Apply; !hasRefusal(p, RefuseArtifactOtherControl) {
		t.Fatal(p.Refusals)
	}
	// AuthSec's boundary already used by a second role: consumers changed.
	s, _ = authsecWorld(t, []string{"sqs"}, 1)
	b := roleB()
	b.BoundaryARN = authsecARN()
	s.addRole(b)
	if p := mustCompile(t, targetIn(t, s, DeliveryDirect, "sqs", "sns")).Apply; !hasRefusal(p, RefuseConsumersChanged) {
		t.Fatal(p.Refusals)
	}
	// A leftover policy with this role's name, no boundary on the role.
	s2 := newSim()
	s2.addRole(baseRole())
	s2.addPolicy(authsecARN(), `{"Statement":[{"Effect":"Allow","NotAction":"sqs:*","Resource":"*"}]}`, map[string]string{TagManagedBy: TagManagedByValue, TagWorkspace: wsRef, TagControl: ctlID}, 1)
	if p := mustCompile(t, targetIn(t, s2, DeliveryDirect, "ec2")).Apply; !hasRefusal(p, RefusePolicyNameInUse) {
		t.Fatal(p.Refusals)
	}
}

func customerWorld(shared bool) *simAccount {
	s := newSim()
	r := baseRole()
	r.BoundaryARN = teamBoundaryARN
	s.addRole(r)
	s.addPolicy(teamBoundaryARN, customerBoundary, nil, 2)
	if shared {
		b := roleB()
		b.BoundaryARN = teamBoundaryARN
		s.addRole(b)
	}
	return s
}

// A4: customer boundaries — J3 refused; exclusive narrowed in place with
// Sids and conditions kept; shared → split copy, the shared document and
// the second role unchanged; NotAction → ineligible.
func TestCompile_CustomerBoundary_A4(t *testing.T) {
	// Direct is refused.
	s := customerWorld(false)
	if p := mustCompile(t, targetIn(t, s, DeliveryDirect, "sqs")).Apply; !hasRefusal(p, RefuseCustomerBoundaryDirect) || p.Eligible() {
		t.Fatalf("J3 must be refused: %v", p.Refusals)
	}
	// Exclusive: narrowed in place through a PR.
	tp := mustCompile(t, targetIn(t, s, DeliveryIaCPR, "sqs"))
	ap := tp.Apply
	wantDoc := `{"Statement":[{"Action":["ec2:Describe*","s3:GetObject"],"Condition":{"StringEquals":{"aws:RequestedRegion":"us-east-1"}},"Effect":"Allow","Resource":"*","Sid":"Compute"},{"Action":"iam:*","Effect":"Deny","Resource":"*","Sid":"NoIam"}],"Version":"2012-10-17"}`
	var narrowed string
	for _, d := range ap.Documents {
		if d.Hash == deref(ap.DesiredDocumentHash) {
			narrowed = d.Canonical
		}
	}
	if ap.Eligibility != EligibilityIaCOnly || deref(ap.DesiredBoundaryARN) != teamBoundaryARN || narrowed != wantDoc ||
		ap.FirstAttachment || ap.ReplacedBoundaryARN != nil || opNames(ap) != "CreatePolicyVersion" {
		t.Fatalf("exclusive: %s %s %v", ap.Eligibility, narrowed, ap.Refusals)
	}
	n := ap.Diff.Narrowing
	if n == nil || !n.SubsetProof || n.Statements[0].Result != NarrowNarrowed || n.Statements[1].Result != NarrowDeleted ||
		n.Statements[2].Result != NarrowKept || strings.Join(n.Statements[0].RemovedActions, ",") != "sqs:SendMessage" {
		t.Fatalf("narrowing record: %+v", n)
	}
	u := tp.Undo
	if u.DesiredAttachment != AttachmentPresent || deref(u.DesiredBoundaryARN) != teamBoundaryARN ||
		deref(u.DesiredDocumentHash) != deref(ap.BeforeDocumentHash) || u.ArtifactDisposition != DispositionKeep {
		t.Fatalf("exclusive undo: %+v", u)
	}

	// Shared: split copy for this role only.
	s = customerWorld(true)
	tp = mustCompile(t, targetIn(t, s, DeliveryIaCPR, "sqs"))
	ap = tp.Apply
	copyARN := "arn:aws:iam::" + acct + ":policy/boundaries/TeamBoundary-" + roleID
	if deref(ap.DesiredBoundaryARN) != copyARN || deref(ap.ReplacedBoundaryARN) != teamBoundaryARN ||
		ap.ArtifactDisposition != DispositionKeep || opNames(ap) != "CreatePolicy,PutRolePermissionsBoundary" ||
		ap.Ops[0].Path != "/boundaries/" || ap.Ops[0].PolicyName != "TeamBoundary-"+roleID {
		t.Fatalf("split apply: %+v", ap)
	}
	for _, op := range ap.Ops {
		if op.PolicyARN == teamBoundaryARN && op.Op != OpPutRolePermissionsBoundary {
			t.Fatal("the shared document must never be written")
		}
	}
	u = tp.Undo
	if deref(u.DesiredBoundaryARN) != teamBoundaryARN || deref(u.ReplacedBoundaryARN) != copyARN ||
		u.ArtifactDisposition != DispositionDelete || opNames(*u) != "PutRolePermissionsBoundary,DeletePolicyVersion,DeletePolicy" {
		t.Fatalf("split undo (DB108): %+v", u)
	}
	// Applying and undoing leaves the shared policy and role B untouched.
	before := s.snapshot()
	docs := planDocs(ap, *u)
	s.run(t, roleID, ap, 0, len(ap.Ops), docs)
	if s.roles[roleBID].BoundaryARN != teamBoundaryARN || s.policies[teamBoundaryARN].doc != customerBoundary {
		t.Fatal("role B or the shared document changed")
	}
	s.run(t, roleID, *u, 0, len(u.Ops), docs)
	if s.snapshot() != before {
		t.Fatalf("undo(apply) differs:\n%s\n---\n%s", before, s.snapshot())
	}

	// NotAction, "*" and namespace wildcards are not narrowable.
	for _, bad := range []string{
		`{"Statement":[{"Effect":"Allow","NotAction":"iam:*","Resource":"*"}]}`,
		`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`,
		`{"Statement":[{"Effect":"Allow","Action":["s*:Get*"],"Resource":"*"}]}`,
	} {
		s := customerWorld(false)
		s.policies[teamBoundaryARN].doc = bad
		tp := mustCompile(t, targetIn(t, s, DeliveryIaCPR, "sqs"))
		if tp.Apply.Eligible() || !hasRefusal(tp.Apply, RefuseNotNarrowable) || tp.Undo != nil {
			t.Fatalf("%s: %v", bad, tp.Apply.Refusals)
		}
	}
	// A boundary whose only Allow is the removed namespace would be empty.
	s = customerWorld(false)
	s.policies[teamBoundaryARN].doc = `{"Statement":{"Sid":"Q","Effect":"Allow","Action":"sqs:*","Resource":"*"}}`
	if p := mustCompile(t, targetIn(t, s, DeliveryIaCPR, "sqs")).Apply; !hasRefusal(p, RefuseNarrowedEmpty) {
		t.Fatal(p.Refusals)
	}
	// Nothing to narrow: the customer boundary already excludes sqs.
	s = customerWorld(true)
	s.policies[teamBoundaryARN].doc = `{"Statement":[{"Sid":"S3","Effect":"Allow","Action":"s3:*","Resource":"*"}]}`
	tp = mustCompile(t, targetIn(t, s, DeliveryExport, "sqs"))
	if len(tp.Apply.Ops) != 0 || deref(tp.Apply.DesiredBoundaryARN) != teamBoundaryARN || tp.Apply.ReplacedBoundaryARN != nil {
		t.Fatalf("nothing to narrow: %+v", tp.Apply)
	}
}

func TestNarrowCustomerBoundary_StructurePreserved(t *testing.T) {
	doc := `{"Version":"2012-10-17","Id":"keep-me","Statement":{"Sid":"One","Effect":"Allow","Action":["sqs:Send*","SQS:Receive*","s3:Get*"],"NotResource":"arn:aws:s3:::secret/*","Condition":{"Bool":{"aws:SecureTransport":"true"}}}}`
	c, _, n, ref, err := NarrowCustomerBoundary(doc, []string{"sqs"})
	if err != nil || ref != nil {
		t.Fatal(err, ref)
	}
	want := `{"Id":"keep-me","Statement":{"Action":["s3:Get*"],"Condition":{"Bool":{"aws:SecureTransport":"true"}},"Effect":"Allow","NotResource":"arn:aws:s3:::secret/*","Sid":"One"},"Version":"2012-10-17"}`
	if string(c) != want || !n.SubsetProof || strings.Join(n.Statements[0].RemovedActions, ",") != "sqs:Send*,SQS:Receive*" {
		t.Fatalf("got %s %+v", c, n)
	}
}

// A20: one live control per role.
func TestResolveControl_A20(t *testing.T) {
	cs := []LiveControl{{ID: "c-old", PolicyID: "p-old", AccountID: acct, RoleID: roleID, State: "removed"},
		{ID: "c1", PolicyID: "p1", AccountID: acct, RoleID: roleID, State: "active"}}
	var e *ErrRoleControlledByPolicy
	if _, err := ResolveControl(cs, acct, roleID, "p2"); !errors.As(err, &e) || e.PolicyID != "p1" {
		t.Fatalf("A20: %v", err)
	}
	if c, err := ResolveControl(cs, acct, roleID, "p1"); err != nil || c.ID != "c1" {
		t.Fatal(c, err)
	}
	if c, err := ResolveControl(cs, acct, roleBID, "p2"); err != nil || c != nil {
		t.Fatal("a new control is created for an uncontrolled role")
	}
}

func TestCompile_InputErrors(t *testing.T) {
	s := newSim()
	s.addRole(baseRole())
	in := targetIn(t, s, DeliveryDirect, "ec2")
	in.Evidence.EvidenceRev = 813
	var ce *CompileError
	if _, err := CompileTarget(in); !errors.As(err, &ce) || ce.Code != ErrCodeEvidenceMismatch {
		t.Fatal(err)
	}
	in = targetIn(t, s, DeliveryDirect, "ec2")
	in.Intent.Remove = append(in.Intent.Remove, rmEntry("sns"))
	if _, err := CompileTarget(in); !errors.As(err, &ce) || ce.Code != ErrCodeEvidenceMismatch {
		t.Fatal("a bundle for another removal set must be refused", err)
	}
	in = targetIn(t, s, DeliveryDirect, "ec2")
	in.Intent.Remove[0].QualifiedDays = 3
	if _, err := CompileTarget(in); !errors.As(err, &ce) || ce.Code != ErrCodeInvalidIntent {
		t.Fatal(err)
	}
	in = targetIn(t, s, DeliveryDirect, "ec2")
	delete(in.Live.Policies, authsecARN())
	in.Live.Role.BoundaryARN = teamBoundaryARN
	if _, err := CompileTarget(in); !errors.As(err, &ce) || ce.Code != ErrCodeLiveIncomplete {
		t.Fatal(err)
	}
}

// §3.2: the compiler's exclusion-only document for {sqs, ec2} is the spec's
// example, byte for byte after canonicalisation, and is within the size
// limit; order and case of the removal list do not matter.
func TestExcludeOnlyDocument_IsSpecExample(t *testing.T) {
	c, h, err := ExcludeOnlyDocument([]string{"SQS", "ec2", "sqs"})
	if err != nil {
		t.Fatal(err)
	}
	sc, sh, err := CanonicalDocument(specBoundary)
	if err != nil || string(c) != string(sc) || h != sh {
		t.Fatalf("%s\n%s", c, sc)
	}
	if PolicyChars(c) > MaxPolicyChars || PolicyChars([]byte("a b\n\tc")) != 3 {
		t.Fatal("size accounting")
	}
	if _, _, err := ExcludeOnlyDocument(nil); err == nil {
		t.Fatal("an empty exclusion list is refused")
	}
	if _, _, err := ExcludeOnlyDocument([]string{"sqs:*"}); err == nil {
		t.Fatal("a removal is a namespace, not a pattern")
	}
}
