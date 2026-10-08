package igagovschema_test

// T3.05: plans compiled by internal/igagov satisfy every iga_gov_plan CHECK
// of 050, proved against PostgreSQL. The plans are inserted into a temporary
// copy of iga_gov_plan made with LIKE ... INCLUDING CONSTRAINTS, which keeps
// every column type, NOT NULL and CHECK (with its name) but no foreign key:
// this proves the compiler's columns, not the FK chain (workspace, version,
// target, bundle, publication, scan run, documents), which the service that
// stores plans builds (T3.11). The documents a plan archives are checked to
// hash, in PostgreSQL, exactly as the iga_gov_document insert trigger
// recomputes them. Negative controls prove the copy enforces the CHECKs.

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/igagov"
)

const (
	cpAcct    = "429418377036"
	cpRoleID  = "AROAEXAMPLEREFUND01"
	cpRoleARN = "arn:aws:iam::429418377036:role/app/RefundTaskRole"
	cpRole    = "RefundTaskRole"
	cpCtl     = "6f1c2a52-58e3-4bb6-9a2e-0f7d8f0b1c11"
	cpScan    = "a1a1a1a1-0000-4000-8000-000000000001"
	cpShared  = "arn:aws:iam::429418377036:policy/boundaries/TeamBoundary"
	cpIdent   = "c41d2f3a-1b2c-4d5e-8f90-a1b2c3d4e5f6"
)

var cpNow = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

const cpCustomer = `{"Version":"2012-10-17","Statement":[{"Sid":"Compute","Effect":"Allow","Action":["ec2:Describe*","sqs:SendMessage"],"Resource":"*"},{"Sid":"NoIam","Effect":"Deny","Action":"iam:*","Resource":"*"}]}`

func cpControl() igagov.ControlRef {
	return igagov.ControlRef{ID: cpCtl, PolicyID: "7a2d3b63-69f4-4cc7-8b3f-1e8e9f0c2d22", AccountID: cpAcct, RoleID: cpRoleID,
		WorkspaceRef: "ws-7f3a", OwnedPolicyARNs: []string{igagov.AuthSecBoundaryARN("aws", cpAcct, cpRoleID)}}
}

func cpCoverage(regions []string) []igagov.CoverageRow {
	var rows []igagov.CoverageRow
	for _, f := range igagov.AllForms() {
		if f.State != igagov.FormCollected {
			continue
		}
		if f.Scope == igagov.ScopeAccount {
			rows = append(rows, igagov.CoverageRow{Form: f.Name, Region: "us-east-1", State: igagov.CoverageComplete})
			continue
		}
		for _, r := range regions {
			rows = append(rows, igagov.CoverageRow{Form: f.Name, Region: r, State: igagov.CoverageComplete})
		}
	}
	return rows
}

func cpEvidence(t *testing.T, remove []string) igagov.EvidenceRef {
	t.Helper()
	cov := &igagov.ResourcePolicyEvidence{Coverage: cpCoverage([]string{"us-east-1"})}
	at := cpNow.Add(-3 * time.Hour)
	act := []igagov.BundleActivity{}
	var routes []igagov.RouteAnalysis
	role := igagov.RoleRef{RoleID: cpRoleID, ARN: cpRoleARN, Name: cpRole, AccountID: cpAcct}
	for _, s := range remove {
		act = append(act, igagov.BundleActivity{Service: s, State: igagov.EvidenceCollected, Outcome: igagov.QualNoAttempt,
			GrantAgeBasis: igagov.GrantAgePredatesObservation, QualifiedDays: 112})
		routes = append(routes, igagov.AnalyzeRoutes(s, role, cov, []string{"us-east-1"}))
	}
	b, err := igagov.BuildBundle(igagov.BundleInput{BuiltAt: cpNow,
		Sources: []igagov.BundleSourceInput{{Kind: igagov.SourceAWSPublication, Rev: 812, PublishedAt: at, ConnectorID: uuid.NewString(),
			ConnectorRun: cpScan, Authenticated: true, Ordered: true, ActivityReportGeneratedAt: &at,
			ResourcePolicyCoverage: igagov.CoverageComplete, ResourcePolicyRun: cpScan}},
		Target:          igagov.BundleTarget{AccountID: cpAcct, RoleID: cpRoleID, RoleARN: cpRoleARN},
		RemovedServices: remove, Consumers: []igagov.ImpactConsumer{{WorkloadID: uuid.NewString(), Relationship: "executes_as"}},
		Owners: []string{uuid.NewString()}, Activity: act, RouteAnalyses: routes}, igagov.DefaultTrustRules())
	if err != nil {
		t.Fatal(err)
	}
	return igagov.EvidenceRef{Bundle: b, EvidenceRev: 812, ScanRunID: cpScan}
}

func cpRoleLive(boundary string) *igagov.LiveRole {
	return &igagov.LiveRole{RoleID: cpRoleID, ARN: cpRoleARN, Name: cpRole, Path: "/app/", AccountID: cpAcct, Partition: "aws",
		Tags: map[string]string{}, BoundaryARN: boundary, TrustPolicyHash: "sha256:" + strings.Repeat("3", 64),
		ManagedPolicies: []igagov.PolicyRef{{Ref: "arn:aws:iam::" + cpAcct + ":policy/RefundAccess", DocumentHash: "sha256:" + strings.Repeat("1", 64)}}}
}

func cpIntent(delivery string, remove ...string) igagov.RightSizeIntent {
	in := igagov.RightSizeIntent{Kind: igagov.IntentRightSizeServices,
		Subjects:        []igagov.Subject{{IdentityAccountID: cpIdent, RoleID: cpRoleID, AccountID: cpAcct}},
		ObservationDays: 7, Delivery: delivery, EvidenceRev: 812}
	for _, s := range remove {
		in.Remove = append(in.Remove, igagov.RemoveEntry{Service: s, Basis: igagov.RemoveNoAttempt, QualifiedDays: 112,
			GrantAgeBasis: igagov.GrantAgePredatesObservation})
	}
	return in
}

// compiledPlans compiles one plan of every kind, attachment and
// disposition, plus ineligible ones.
func compiledPlans(t *testing.T) map[string]igagov.Plan {
	t.Helper()
	out := map[string]igagov.Plan{}
	authsec := igagov.AuthSecBoundaryARN("aws", cpAcct, cpRoleID)
	target := func(name string, delivery string, live igagov.LiveRead, scanEv *igagov.ResourcePolicyEvidence, remove ...string) igagov.TargetPlans {
		tp, err := igagov.CompileTarget(igagov.TargetInput{Control: cpControl(), Intent: cpIntent(delivery, remove...), Live: live,
			Evidence: cpEvidence(t, remove), ScanEvidence: scanEv, EnabledRegions: []string{"us-east-1"}, AccountServices: []string{"ecr", "sqs"}})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		out[name+".apply"] = tp.Apply
		if tp.Undo != nil {
			out[name+".undo"] = *tp.Undo
		}
		return tp
	}
	cov := &igagov.ResourcePolicyEvidence{Coverage: cpCoverage([]string{"us-east-1"})}

	// none → AuthSec boundary (first attachment), and its undo.
	none := igagov.LiveRead{ReadAt: cpNow, Role: cpRoleLive(""), Policies: map[string]*igagov.LivePolicy{authsec: nil}}
	first := target("first", igagov.DeliveryDirect, none, cov, "ec2", "sqs")
	// First attachment refused (no evidence): ineligible apply.
	target("first_refused", igagov.DeliveryDirect, none, nil, "ec2")
	// Service-linked role: ineligible.
	sl := none
	sl.Role = cpRoleLive("")
	sl.Role.Path = "/aws-service-role/ecs.amazonaws.com/"
	target("service_linked", igagov.DeliveryDirect, sl, cov, "ec2")

	// AuthSec boundary → new version (with prune), and its undo.
	doc, _, _ := igagov.ExcludeOnlyDocument([]string{"sqs"})
	owned := map[string]string{igagov.TagManagedBy: igagov.TagManagedByValue, igagov.TagWorkspace: "ws-7f3a", igagov.TagControl: cpCtl}
	self := igagov.AttachedEntity{Kind: "role", ID: cpRoleID, Name: cpRole, Usage: igagov.UsageBoundary}
	av := igagov.LiveRead{ReadAt: cpNow, Role: cpRoleLive(authsec), Policies: map[string]*igagov.LivePolicy{authsec: {ARN: authsec,
		Path: "/authsec/", Name: "AuthSecBoundary-" + cpRoleID, Tags: owned, DefaultDocument: string(doc), VersionCount: 5,
		AttachmentSet: []igagov.AttachedEntity{self}}}}
	target("authsec_version", igagov.DeliveryDirect, av, cov, "sns", "sqs")

	// Customer boundary: exclusive (in place), shared (split copy), J3 refused.
	cust := func(shared bool) igagov.LiveRead {
		set := []igagov.AttachedEntity{self}
		if shared {
			set = append(set, igagov.AttachedEntity{Kind: "role", ID: "AROAEXAMPLEROLEB0001", Name: "ReportsRole", Usage: igagov.UsageBoundary})
		}
		copyARN, _ := igagov.SplitCopyARN("aws", cpAcct, "/boundaries/", "TeamBoundary", cpRoleID)
		return igagov.LiveRead{ReadAt: cpNow, Role: cpRoleLive(cpShared), Policies: map[string]*igagov.LivePolicy{
			cpShared: {ARN: cpShared, Path: "/boundaries/", Name: "TeamBoundary", DefaultDocument: cpCustomer, VersionCount: 1, AttachmentSet: set},
			copyARN:  nil}}
	}
	target("customer_in_place", igagov.DeliveryIaCPR, cust(false), cov, "sqs")
	split := target("customer_split", igagov.DeliveryExport, cust(true), cov, "sqs")
	target("customer_direct", igagov.DeliveryDirect, cust(false), cov, "sqs")

	// Role-only recovery: absent + retain_shared (the AuthSec boundary
	// gained a user), and a split copy that gained a user.
	firstDoc := *first.Apply.DesiredDocumentHash
	var firstText string
	for _, d := range first.Apply.Documents {
		if d.Hash == firstDoc {
			firstText = d.Canonical
		}
	}
	userB := igagov.AttachedEntity{Kind: "role", ID: "AROAEXAMPLEROLEB0001", Name: "ReportsRole", Usage: igagov.UsageBoundary}
	applied := igagov.LiveRead{ReadAt: cpNow, Role: cpRoleLive(authsec), Policies: map[string]*igagov.LivePolicy{authsec: {ARN: authsec,
		Path: "/authsec/", Tags: owned, DefaultDocument: firstText, VersionCount: 1, AttachmentSet: []igagov.AttachedEntity{self, userB}}}}
	rp, err := igagov.CompileRoleOnlyRecovery(igagov.RecoveryInput{Control: cpControl(), Undo: *first.Undo,
		UndoneDeploymentID: uuid.NewString(), Live: applied, Evidence: cpEvidence(t, []string{"ec2", "sqs"})})
	if err != nil {
		t.Fatal(err)
	}
	out["role_only.detach"] = rp
	copyARN := *split.Apply.DesiredBoundaryARN
	splitApplied := igagov.LiveRead{ReadAt: cpNow, Role: cpRoleLive(copyARN), Policies: map[string]*igagov.LivePolicy{
		copyARN:  {ARN: copyARN, DefaultDocument: split.Apply.Documents[0].Canonical, VersionCount: 1, AttachmentSet: []igagov.AttachedEntity{self, userB}},
		cpShared: {ARN: cpShared, DefaultDocument: cpCustomer, VersionCount: 1, AttachmentSet: []igagov.AttachedEntity{userB}}}}
	for _, d := range split.Apply.Documents {
		if d.Hash == *split.Apply.DesiredDocumentHash {
			splitApplied.Policies[copyARN].DefaultDocument = d.Canonical
		}
	}
	rs, err := igagov.CompileRoleOnlyRecovery(igagov.RecoveryInput{Control: cpControl(), Undo: *split.Undo,
		UndoneDeploymentID: uuid.NewString(), Live: splitApplied, Evidence: cpEvidence(t, []string{"sqs"})})
	if err != nil {
		t.Fatal(err)
	}
	out["role_only.split"] = rs

	// Remove control: baseline none (delete), and re-point to a split baseline.
	exclusive := applied
	exclusive.Policies = map[string]*igagov.LivePolicy{authsec: {ARN: authsec, Path: "/authsec/", Tags: owned, DefaultDocument: firstText,
		VersionCount: 1, AttachmentSet: []igagov.AttachedEntity{self}}}
	rc, err := igagov.CompileRemoveControl(igagov.RemoveControlInput{Control: cpControl(), Delivery: igagov.DeliveryDirect, Live: exclusive,
		LastDeployed: igagov.BoundaryRef{ARN: authsec, DocumentHash: firstDoc}, Evidence: cpEvidence(t, []string{"ec2", "sqs"})})
	if err != nil {
		t.Fatal(err)
	}
	out["remove_control.delete"] = rc
	sharedHash, _ := igagov.DocumentHash(cpCustomer)
	rr, err := igagov.CompileRemoveControl(igagov.RemoveControlInput{Control: cpControl(), Delivery: igagov.DeliveryIaCPR, Live: splitApplied,
		Baseline:     igagov.Baseline{BoundaryARN: ptr(cpShared), DocumentHash: ptr(sharedHash), Document: cpCustomer},
		LastDeployed: igagov.BoundaryRef{ARN: copyARN, DocumentHash: *split.Apply.DesiredDocumentHash}, Evidence: cpEvidence(t, []string{"sqs"})})
	if err != nil {
		t.Fatal(err)
	}
	out["remove_control.repoint_retain"] = rr

	// Dedicated identity: split and split_revert.
	newARN := "arn:aws:iam::" + cpAcct + ":role/refund-reconciler-role"
	sl2 := igagov.LiveRead{ReadAt: cpNow, Role: cpRoleLive(""), Policies: map[string]*igagov.LivePolicy{}, Roles: map[string]*igagov.LiveRole{newARN: nil}}
	src := sl2.Role
	sp, err := igagov.CompileSplit(igagov.SplitInput{Control: cpControl(), Live: sl2, Evidence: cpEvidence(t, nil),
		Intent: igagov.DedicatedIdentityIntent{Kind: igagov.IntentDedicatedIdentity,
			Source:   igagov.Subject{IdentityAccountID: cpIdent, RoleID: cpRoleID, AccountID: cpAcct},
			Workload: igagov.DedicatedWorkload{WorkloadID: cpIdent, BindingKind: igagov.BindingECSTaskRole, BindingRef: "arn:aws:ecs:us-east-1:" + cpAcct + ":service/payments/refund"},
			NewRole: igagov.NewRole{Name: "refund-reconciler-role", Path: "/", TrustPolicyHash: src.TrustPolicyHash,
				ManagedPolicyARNs: []string{src.ManagedPolicies[0].Ref}},
			Delivery: igagov.DeliveryIaCPR},
		SubjectKind: igagov.SubjectECSService, SubjectARN: "arn:aws:ecs:us-east-1:" + cpAcct + ":service/payments/refund",
		TaskFamily: "refund", MigrationEvidenceAvailable: true})
	if err != nil {
		t.Fatal(err)
	}
	out["split"] = sp.Split
	out["split_revert"] = *sp.Revert
	return out
}

func ptr(s string) *string { return &s }

func nullable(p *string) any {
	if p == nil {
		return nil
	}
	return *p
}

func insertPlan(tx execer, p igagov.Plan) error {
	js := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			panic(err)
		}
		return string(b)
	}
	_, err := tx.Exec(`INSERT INTO probe_plan (workspace_id, version_id, target_id, control_id, kind, delivery, eligibility,
		ineligible_reason, basis, basis_read_at, precondition, precondition_hash, before_document_hash, desired_attachment,
		desired_boundary_arn, desired_document_hash, replaced_boundary_arn, artifact_disposition, evidence_bundle_id,
		evidence_rev, resource_policy_scan_run_id, first_attachment, unanalysed, impact, impact_hash, operations, diff,
		plan_hash, material_hash)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23::jsonb,$24::jsonb,
		$25,$26::jsonb,$27::jsonb,$28,$29)`,
		uuid.NewString(), uuid.NewString(), uuid.NewString(), p.ControlID, p.Kind, p.Delivery, p.Eligibility,
		p.IneligibleReason, p.Basis, p.BasisReadAt, string(p.Precondition), p.PreconditionHash, nullable(p.BeforeDocumentHash),
		p.DesiredAttachment, nullable(p.DesiredBoundaryARN), nullable(p.DesiredDocumentHash), nullable(p.ReplacedBoundaryARN),
		p.ArtifactDisposition, uuid.NewString(), p.EvidenceRev, nullable(p.ResourcePolicyScanRunID), p.FirstAttachment,
		js(p.Unanalysed), js(p.Impact), p.ImpactHash, js(p.Ops), js(p.Diff), p.PlanHash, p.MaterialHash)
	return err
}

func TestCompiledPlansSatisfyPlanChecks(t *testing.T) {
	db, _ := testDB(t)
	plans := compiledPlans(t)
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback() //nolint:errcheck
	if _, err := tx.Exec(`CREATE TEMP TABLE probe_plan (LIKE iga_gov_plan INCLUDING DEFAULTS INCLUDING CONSTRAINTS) ON COMMIT DROP`); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for name, p := range plans {
		if _, err := tx.Exec(`SAVEPOINT p`); err != nil {
			t.Fatal(err)
		}
		if err := insertPlan(tx, p); err != nil {
			t.Errorf("%s (%s/%s/%s/%s): refused: %s", name, p.Kind, p.DesiredAttachment, p.ArtifactDisposition, p.Eligibility, describe(err))
			_, _ = tx.Exec(`ROLLBACK TO SAVEPOINT p`)
			continue
		}
		seen[p.Kind+"/"+p.DesiredAttachment+"/"+p.ArtifactDisposition+"/"+p.Eligibility] = true
		// Every archived document hashes in PostgreSQL as the
		// iga_gov_document insert trigger recomputes it.
		for _, d := range p.Documents {
			var ok bool
			if err := tx.QueryRow(`SELECT 'sha256:' || encode(sha256(convert_to($1, 'UTF8')), 'hex') = $2 AND $1::jsonb IS NOT NULL`,
				d.Canonical, d.Hash).Scan(&ok); err != nil || !ok {
				t.Errorf("%s: document %s does not hash as the trigger computes (%v)", name, d.Hash, err)
			}
		}
	}
	// The shapes covered: every kind, attachment and disposition.
	for _, want := range []string{"apply/present/keep/eligible", "apply/present/keep/iac_only", "apply/present/keep/ineligible",
		"undo/absent/delete/eligible", "undo/present/keep/eligible", "undo/present/keep/iac_only", "undo/present/delete/iac_only",
		"undo/absent/retain_shared/eligible", "undo/present/retain_shared/iac_only", "remove_control/absent/delete/eligible",
		"remove_control/present/retain_shared/iac_only", "split/unchanged/keep/iac_only", "split_revert/unchanged/keep/iac_only"} {
		if !seen[want] {
			t.Errorf("no compiled plan of shape %s was stored", want)
		}
	}
	// Negative controls: the temporary copy enforces 050's CHECKs.
	bad := []struct {
		name string
		edit func(*igagov.Plan)
		want outcome
	}{
		{"apply claiming an unchanged boundary", func(p *igagov.Plan) {
			p.DesiredAttachment, p.DesiredBoundaryARN, p.DesiredDocumentHash, p.FirstAttachment = igagov.AttachmentUnchanged, nil, nil, false
		}, checkViolation("iga_gov_plan_kind_chk")},
		{"DB58 absent that keeps the artifact", func(p *igagov.Plan) {
			*p = plans["first.undo"]
			p.ArtifactDisposition = igagov.DispositionKeep
		}, checkViolation("iga_gov_plan_disposition_chk")},
		{"DB25 present without document", func(p *igagov.Plan) { p.DesiredDocumentHash = nil }, checkViolation("iga_gov_plan_attachment_chk")},
		{"DB40 split direct", func(p *igagov.Plan) { *p = plans["split"]; p.Delivery = igagov.DeliveryDirect }, checkViolation("iga_gov_plan_kind_chk")},
		{"DB106 delete without naming", func(p *igagov.Plan) { *p = plans["first.undo"]; p.ReplacedBoundaryARN = nil }, checkViolation("iga_gov_plan_disposition_chk")},
		{"first attachment without scan", func(p *igagov.Plan) { p.ResourcePolicyScanRunID = nil }, checkViolation("iga_gov_plan_first_attachment_chk")},
	}
	for _, b := range bad {
		p := plans["first.apply"]
		b.edit(&p)
		if _, err := tx.Exec(`SAVEPOINT n`); err != nil {
			t.Fatal(err)
		}
		err := insertPlan(tx, p)
		if ok, why := b.want.match(err); !ok {
			t.Errorf("%s: %s", b.name, why)
		}
		if err := p.CheckStorable(); err == nil {
			t.Errorf("%s: the Go mirror accepted what PostgreSQL refuses", b.name)
		}
		_, _ = tx.Exec(`ROLLBACK TO SAVEPOINT n`)
	}
}
