package igagov

import (
	"sort"
	"strings"
)

// This file compiles §11's dedicated-identity isolation: one `split` plan
// and its inverse `split_revert`, both desired_attachment `unchanged`,
// delivered only as iac_pr or export, on the SOURCE role's control (050
// iga_gov_plan_kind_chk). The new role keeps the source role's authorization
// (same managed policies by ARN, copies of its inline policies, the same
// trust policy and boundary); no permission is removed for anyone (A61).
// The per-compute-type migration evidence and the IaC rendering are T3.17's;
// the plan here fixes WHAT changes, its facts, its compatibility list and
// its unanalysed items.

// Dedicated-identity steps (the J2/J1 step list; AuthSec never runs them).
const (
	OpCreateRole                     = "CreateRole"
	OpAttachRolePolicy               = "AttachRolePolicy"
	OpPutRolePolicy                  = "PutRolePolicy"
	OpAddResourcePolicyPrincipal     = "AddResourcePolicyPrincipal"
	OpRemoveResourcePolicyPrincipal  = "RemoveResourcePolicyPrincipal"
	OpAddTrustPolicyPrincipal        = "AddTrustPolicyPrincipal"
	OpRemoveTrustPolicyPrincipal     = "RemoveTrustPolicyPrincipal"
	OpBindSubject                    = "BindSubject"
	OpDeleteRole                     = "DeleteRole"
	domainSplitPrecondition          = "authsec.igagov.precondition.split.v1"
	domainSplitRevertPrecondition    = "authsec.igagov.precondition.split_revert.v1"
	domainDedicatedRole              = "authsec.igagov.dedicated_role.v1"
	RefuseMigrationEvidence          = "migration_evidence_unavailable"
	RefuseSubjectBindingMismatch     = "subject_binding_mismatch"
	RefuseNewRoleNameInUse           = "new_role_name_in_use"
	RefuseNewRoleNotBaselinePreserve = "new_role_not_baseline_preserving"
	RefuseSplitDirect                = "split_requires_iac"
)

// Migration subject kinds (051 iga_gov_workload_migration.subject_kind).
const (
	SubjectECSService      = "ecs_service"
	SubjectLambdaFunction  = "lambda_function"
	SubjectEC2ASG          = "ec2_auto_scaling_group"
	SubjectEC2Instance     = "ec2_instance"
	HandlingPR             = "pr_adds_new_role"
	HandlingOwnerConfirm   = "owner_confirmation"
	HandlingEffectUnknown  = "effect_unknown"
	CompatResourcePolicy   = "resource_policy"
	CompatTrustPolicy      = "trust_policy"
	CompatPrincipalCondKey = "principal_condition"
)

// CompatibilityItem is one reference to the source role that does not
// follow it to the new role (§11 "Compatibility checks").
type CompatibilityItem struct {
	Kind      string `json:"kind"`
	Resource  string `json:"resource"`
	Form      string `json:"form,omitempty"`
	Principal string `json:"principal,omitempty"`
	Handling  string `json:"handling"`
}

// SplitDetail is the split's part of iga_gov_plan.diff.
type SplitDetail struct {
	SourceRoleARN    string              `json:"source_role_arn"`
	NewRoleARN       string              `json:"new_role_arn"`
	NewRoleHash      string              `json:"new_role_hash"`
	SubjectKind      string              `json:"subject_kind"`
	SubjectARN       string              `json:"subject_arn"`
	FromWorkloadKeys []string            `json:"from_workload_keys"`
	Compatibility    []CompatibilityItem `json:"compatibility"`
}

// SplitInput is what a dedicated-identity version compiles from.
type SplitInput struct {
	Control  ControlRef // the source role's control
	Intent   DedicatedIdentityIntent
	Live     LiveRead // the source role; Roles[new role ARN] read (nil = free)
	Evidence EvidenceRef
	// The migration subject (§11 "The migration subject").
	SubjectKind      string
	SubjectARN       string
	FromWorkloadKeys []string
	// ECS: the task family (standalone tasks are unanalysed). Lambda: the
	// aliases moved and the versions behind no alias (unanalysed).
	TaskFamily        string
	Aliases           []string
	UnaliasedVersions []string
	ScanEvidence      *ResourcePolicyEvidence
	AccountServices   []string
	// TrustReferences are roles whose trust policy allows the source role
	// to assume them (collected by IAM discovery).
	TrustReferences []string
	// MappedResources are resource and role ARNs whose policies live in the
	// mapped IaC source: the PR adds the new role there; anything else needs
	// owner confirmation.
	MappedResources map[string]bool
	// MigrationEvidenceAvailable: the connector's discovery template has the
	// migration-evidence reads (§11); otherwise no isolation is offered.
	MigrationEvidenceAvailable bool
}

// SplitPlans is a dedicated-identity version's plan pair; Revert is nil when
// the split is ineligible.
type SplitPlans struct {
	Split  Plan
	Revert *Plan
}

// dedicatedRoleHash identifies a dedicated role's authorization as a read
// shows it: trust policy, managed ARNs, inline document hashes, boundary.
func dedicatedRoleHash(r *LiveRole) (string, error) {
	var managed []string
	for _, m := range r.ManagedPolicies {
		managed = append(managed, m.Ref)
	}
	return dedicatedSpecHash(r.TrustPolicyHash, managed, r.InlinePolicies, r.BoundaryARN)
}

func dedicatedSpecHash(trust string, managed []string, inline []PolicyRef, boundary string) (string, error) {
	return HashCanonicalTagged(domainDedicatedRole, struct {
		Trust    string      `json:"trust_policy_hash"`
		Managed  []string    `json:"managed_policy_arns"`
		Inline   []PolicyRef `json:"inline_policies"`
		Boundary string      `json:"boundary_arn"`
	}{trust, sortedUnique(managed), sortedRefs(inline), boundary})
}

func bindingSubjectOK(binding, subject string) bool {
	switch binding {
	case BindingECSTaskRole:
		return subject == SubjectECSService
	case BindingLambdaRole:
		return subject == SubjectLambdaFunction
	case BindingEC2InstanceProfile:
		return subject == SubjectEC2ASG || subject == SubjectEC2Instance
	}
	return false
}

// bindSteps names the native steps that move the subject (§11 table).
func bindSteps(subject string, aliases []string, toSource bool) []string {
	switch subject {
	case SubjectECSService:
		return []string{"RegisterTaskDefinition:taskRoleArn", "UpdateService"}
	case SubjectLambdaFunction:
		out := []string{"UpdateFunctionConfiguration:Role", "PublishVersion"}
		for _, a := range sortedUnique(aliases) {
			out = append(out, "UpdateAlias:"+a)
		}
		return out
	case SubjectEC2ASG:
		if toSource {
			return []string{"CreateLaunchTemplateVersion:source_profile", "StartInstanceRefresh"}
		}
		return []string{"CreateInstanceProfile", "AddRoleToInstanceProfile", "CreateLaunchTemplateVersion", "StartInstanceRefresh"}
	case SubjectEC2Instance:
		if toSource {
			return []string{"ReplaceIamInstanceProfileAssociation:source_profile"}
		}
		return []string{"CreateInstanceProfile", "AddRoleToInstanceProfile", "ReplaceIamInstanceProfileAssociation"}
	}
	return nil
}

// compatibilityItems scans the named scan's observations for references to
// the source role (§11 table): grants naming its ARN or a session, and
// aws:PrincipalArn / aws:userid conditions (effect unknown). DECISION D55:
// whether the PR can add the new role is the caller's knowledge of the mapped
// IaC source (MappedResources, T3.17); everything else is owner
// confirmation. The items enter the impact as routes of the form's
// namespace, so they are material.
func compatibilityItems(role RoleRef, ev *ResourcePolicyEvidence, trustRefs []string, mapped map[string]bool) []CompatibilityItem {
	handling := func(resource string) string {
		if mapped[resource] {
			return HandlingPR
		}
		return HandlingOwnerConfirm
	}
	seen := map[string]bool{}
	var out []CompatibilityItem
	add := func(it CompatibilityItem) {
		k := it.Kind + "\x1f" + it.Resource + "\x1f" + it.Principal
		if !seen[k] {
			seen[k] = true
			out = append(out, it)
		}
	}
	if ev != nil {
		for _, ob := range ev.Observations {
			if !ob.PolicyPresent || ob.Document == nil {
				continue
			}
			for _, st := range ob.Document.Statements {
				if st.Principal != nil {
					for _, v := range st.Principal.Values["AWS"] {
						if k := classifyAWSPrincipal(v, role); k == PrincipalRoleARN || k == PrincipalRoleSession {
							add(CompatibilityItem{Kind: CompatResourcePolicy, Resource: ob.ResourceARN, Form: ob.Form, Principal: k, Handling: handling(ob.ResourceARN)})
						}
					}
				}
				for _, c := range st.Conditions {
					key := strings.ToLower(c.Key)
					if key == "aws:principalarn" || key == "aws:userid" {
						add(CompatibilityItem{Kind: CompatPrincipalCondKey, Resource: ob.ResourceARN, Form: ob.Form, Handling: HandlingEffectUnknown})
					}
				}
			}
		}
	}
	for _, r := range sortedUnique(trustRefs) {
		add(CompatibilityItem{Kind: CompatTrustPolicy, Resource: r, Handling: handling(r)})
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Resource != b.Resource {
			return a.Resource < b.Resource
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Principal < b.Principal
	})
	if out == nil {
		out = []CompatibilityItem{}
	}
	return out
}

// CompileSplit compiles §11's split and split_revert plans.
func CompileSplit(in SplitInput) (SplitPlans, error) {
	if err := in.Control.validate(); err != nil {
		return SplitPlans{}, err
	}
	if err := ValidateIntent(Intent{Kind: IntentDedicatedIdentity, DedicatedIdentity: &in.Intent}); err != nil {
		return SplitPlans{}, compileErr(ErrCodeInvalidIntent, err.Error())
	}
	if in.Intent.Source.RoleID != in.Control.RoleID || in.Intent.Source.AccountID != in.Control.AccountID {
		return SplitPlans{}, compileErr(ErrCodeInput, "the intent's source is not the control's role")
	}
	if in.SubjectARN == "" {
		return SplitPlans{}, compileErr(ErrCodeInput, "a split moves a named subject")
	}
	if err := in.Evidence.validate(in.Control.RoleID); err != nil {
		return SplitPlans{}, err
	}
	sp := in.Evidence.plan(in.Control.ID, PlanSplit, in.Intent.Delivery, in.Live.ReadAt)
	sp.Eligibility = EligibilityIaCOnly
	sp.DesiredAttachment = AttachmentUnchanged
	f := in.Evidence.Bundle.Facts
	sp.Impact = Impact{Consumers: f.Consumers, OwnerUserIDs: f.Owners, Removed: []ImpactService{}, Retained: []ImpactService{},
		StatementRevisions: []string{}, Routes: []Route{}}

	if rs := checkIncarnation(in.Live, in.Control.RoleID); rs != nil {
		sp.refuse(rs...)
		if err := goneRolePrecondition(&sp, in.Live, in.Control.RoleID); err != nil {
			return SplitPlans{}, err
		}
		return SplitPlans{Split: sp}, sp.seal()
	}
	src := in.Live.Role
	sp.refuse(RoleEligibility(*src)...)
	if !in.MigrationEvidenceAvailable {
		sp.refuse(Refusal{RefuseMigrationEvidence, "the connector's discovery template cannot read migration evidence; update the template"})
	}
	if !bindingSubjectOK(in.Intent.Workload.BindingKind, in.SubjectKind) {
		sp.refuse(Refusal{RefuseSubjectBindingMismatch, in.Intent.Workload.BindingKind + " cannot move a " + in.SubjectKind})
	}
	nr := in.Intent.NewRole
	newARN := "arn:" + src.partition() + ":iam::" + src.AccountID + ":role" + nr.Path + nr.Name
	if r, ok := in.Live.Roles[newARN]; !ok {
		return SplitPlans{}, compileErr(ErrCodeLiveIncomplete, "the new role "+newARN+" was not read")
	} else if r != nil {
		sp.refuse(Refusal{RefuseNewRoleNameInUse, newARN})
	}
	// Baseline-preserving contents (§11).
	var srcManaged []string
	for _, m := range src.ManagedPolicies {
		srcManaged = append(srcManaged, m.Ref)
	}
	var intentInline []PolicyRef
	for _, ip := range nr.InlinePolicies {
		intentInline = append(intentInline, PolicyRef{Ref: ip.Name, DocumentHash: ip.DocumentHash})
	}
	mismatch := func(field string) {
		sp.refuse(Refusal{RefuseNewRoleNotBaselinePreserve, field + " differs from the source role's"})
	}
	if nr.TrustPolicyHash != src.TrustPolicyHash {
		mismatch("trust policy")
	}
	if strings.Join(sortedUnique(nr.ManagedPolicyARNs), ",") != strings.Join(sortedUnique(srcManaged), ",") {
		mismatch("managed policies")
	}
	if c1, _ := CanonicalizeValue(sortedRefs(intentInline)); string(c1) != func() string {
		c2, _ := CanonicalizeValue(sortedRefs(src.InlinePolicies))
		return string(c2)
	}() {
		mismatch("inline policies")
	}
	if nr.BoundaryARN != src.BoundaryARN {
		mismatch("permissions boundary")
	}
	newHash, err := dedicatedSpecHash(nr.TrustPolicyHash, nr.ManagedPolicyARNs, intentInline, nr.BoundaryARN)
	if err != nil {
		return SplitPlans{}, err
	}

	// Precondition: the source's artifact state, the subject on the source
	// role, the new role absent.
	st, err := ArtifactState(in.Live)
	if err != nil {
		return SplitPlans{}, err
	}
	type subj struct {
		Kind    string `json:"kind"`
		ARN     string `json:"arn"`
		RoleARN string `json:"role_arn"`
	}
	pre := struct {
		ArtifactState ArtifactStateFacts `json:"artifact_state"`
		Subject       subj               `json:"subject"`
		NewRole       struct {
			ARN    string `json:"arn"`
			Exists bool   `json:"exists"`
		} `json:"new_role"`
	}{ArtifactState: st, Subject: subj{in.SubjectKind, in.SubjectARN, src.ARN}}
	pre.NewRole.ARN = newARN
	if sp.Precondition, err = CanonicalizeValue(pre); err != nil {
		return SplitPlans{}, err
	}
	sp.PreconditionHash = taggedHash(domainSplitPrecondition, sp.Precondition)
	sp.BeforeDocumentHash = st.BoundaryDocumentHash

	compat := compatibilityItems(src.ref(), in.ScanEvidence, in.TrustReferences, in.MappedResources)
	for _, it := range compat {
		if it.Kind == CompatResourcePolicy || it.Kind == CompatPrincipalCondKey {
			eff := RouteEffectEffectUnknown
			if it.Principal == PrincipalRoleSession {
				eff = RouteEffectBypassKnown
			} else if it.Principal == PrincipalRoleARN {
				eff = RouteEffectLimited
			}
			svc := ""
			if f, ok := LookupForm(it.Form); ok {
				svc = f.Namespace
			}
			sp.Impact.Routes = append(sp.Impact.Routes, Route{Service: svc, Form: it.Form, Resource: it.Resource, Principal: it.Principal, Effect: eff, Reason: it.Handling})
		}
	}

	// Unanalysed (§11 table): KMS grants, SCPs/RCPs, other accounts,
	// uncollected forms, standalone ECS tasks, unaliased Lambda versions.
	proof := ProveFirstAttachment(src.ref(), in.Evidence.ScanRunID, nil, nil, in.AccountServices, in.Evidence.gaps())
	un := append([]UnanalysedItem{}, proof.Unanalysed...)
	un = append(un, UnanalysedItem{Key: "kms_grants", Reason: "kms_grants_not_collected"},
		UnanalysedItem{Key: "scp_rcp", Reason: "organization_policies_not_analysed"})
	if in.SubjectKind == SubjectECSService && in.TaskFamily != "" {
		un = append(un, UnanalysedItem{Key: "standalone_tasks:" + in.TaskFamily, Reason: "standalone_or_scheduled_tasks"})
	}
	for _, v := range sortedUnique(in.UnaliasedVersions) {
		un = append(un, UnanalysedItem{Key: "lambda_version_without_alias:" + v, Reason: "direct_invocation_by_qualified_arn"})
	}
	sp.Unanalysed = sortedUnanalysed(un)

	tags := map[string]string{}
	for k, v := range src.Tags {
		if !strings.HasPrefix(k, "authsec:") {
			tags[k] = v
		}
	}
	sp.Ops = []Op{{Op: OpCreateRole, RoleARN: newARN, Path: nr.Path, TrustPolicyHash: nr.TrustPolicyHash, Tags: tags}}
	for _, m := range sortedUnique(nr.ManagedPolicyARNs) {
		sp.Ops = append(sp.Ops, Op{Op: OpAttachRolePolicy, RoleARN: newARN, PolicyARN: m})
	}
	for _, ip := range sortedRefs(intentInline) {
		sp.Ops = append(sp.Ops, Op{Op: OpPutRolePolicy, RoleARN: newARN, InlineName: ip.Ref, DocumentHash: ip.DocumentHash})
	}
	if nr.BoundaryARN != "" {
		sp.Ops = append(sp.Ops, Op{Op: OpPutRolePermissionsBoundary, RoleARN: newARN, PolicyARN: nr.BoundaryARN})
	}
	var revertCompat []Op
	for _, it := range compat {
		if it.Handling != HandlingPR {
			continue
		}
		switch it.Kind {
		case CompatResourcePolicy:
			sp.Ops = append(sp.Ops, Op{Op: OpAddResourcePolicyPrincipal, ResourceARN: it.Resource, Principal: newARN})
			revertCompat = append(revertCompat, Op{Op: OpRemoveResourcePolicyPrincipal, ResourceARN: it.Resource, Principal: newARN})
		case CompatTrustPolicy:
			sp.Ops = append(sp.Ops, Op{Op: OpAddTrustPolicyPrincipal, RoleARN: it.Resource, Principal: newARN})
			revertCompat = append(revertCompat, Op{Op: OpRemoveTrustPolicyPrincipal, RoleARN: it.Resource, Principal: newARN})
		}
	}
	sp.Ops = append(sp.Ops, Op{Op: OpBindSubject, SubjectARN: in.SubjectARN, RoleARN: newARN, Binding: in.Intent.Workload.BindingKind,
		Steps: bindSteps(in.SubjectKind, in.Aliases, false)})

	detail := &SplitDetail{SourceRoleARN: src.ARN, NewRoleARN: newARN, NewRoleHash: newHash, SubjectKind: in.SubjectKind,
		SubjectARN: in.SubjectARN, FromWorkloadKeys: sortedUnique(in.FromWorkloadKeys), Compatibility: compat}
	sp.Diff.Case = CaseSplitIsolate
	sp.Diff.Split = detail
	srcBoundary := src.BoundaryARN
	if srcBoundary == "" {
		srcBoundary = ValueNone
	}
	sp.Facts = []Fact{factRole(src.RoleID), factBoundary(srcBoundary, srcBoundary),
		{Key: factKey(FactBinding, in.SubjectARN), Kind: FactBinding, Subject: in.SubjectARN, Before: src.ARN, After: newARN},
		{Key: factKey(FactNewRole, newARN), Kind: FactNewRole, Subject: newARN, Before: ValueAbsent, After: newHash}}
	if in.Intent.Delivery == DeliveryDirect {
		sp.refuse(Refusal{RefuseSplitDirect, "isolation is delivered only as a PR or export (§11)"})
	}
	if err := sp.seal(); err != nil {
		return SplitPlans{}, err
	}
	if !sp.Eligible() {
		return SplitPlans{Split: sp}, nil
	}

	// split_revert: precondition is the split's post-state.
	rv := in.Evidence.plan(in.Control.ID, PlanSplitRevert, in.Intent.Delivery, in.Live.ReadAt)
	rv.Eligibility = EligibilityIaCOnly
	rv.DesiredAttachment = AttachmentUnchanged
	rv.Impact = sp.Impact
	rpre := struct {
		NewRole struct {
			ARN  string `json:"arn"`
			Hash string `json:"hash"`
		} `json:"new_role"`
		Subject   subj     `json:"subject"`
		Consumers []string `json:"new_role_consumers"`
	}{Subject: subj{in.SubjectKind, in.SubjectARN, newARN}, Consumers: []string{in.SubjectARN}}
	rpre.NewRole.ARN, rpre.NewRole.Hash = newARN, newHash
	if rv.Precondition, err = CanonicalizeValue(rpre); err != nil {
		return SplitPlans{}, err
	}
	rv.PreconditionHash = taggedHash(domainSplitRevertPrecondition, rv.Precondition)
	rv.BeforeDocumentHash = st.BoundaryDocumentHash
	rv.Ops = []Op{{Op: OpBindSubject, SubjectARN: in.SubjectARN, RoleARN: src.ARN, Binding: in.Intent.Workload.BindingKind,
		Steps: bindSteps(in.SubjectKind, in.Aliases, true)}}
	rv.Ops = append(rv.Ops, revertCompat...)
	del := []string{}
	if nr.BoundaryARN != "" {
		del = append(del, "DeleteRolePermissionsBoundary")
	}
	for _, ip := range sortedRefs(intentInline) {
		del = append(del, "DeleteRolePolicy:"+ip.Ref)
	}
	for _, m := range sortedUnique(nr.ManagedPolicyARNs) {
		del = append(del, "DetachRolePolicy:"+m)
	}
	if in.SubjectKind == SubjectEC2ASG || in.SubjectKind == SubjectEC2Instance {
		del = append(del, "RemoveRoleFromInstanceProfile", "DeleteInstanceProfile")
	}
	del = append(del, "DeleteRole")
	// "If anything else now runs as the new role, the revert restores the
	// binding only and leaves the role" (§11): the delete is conditional.
	rv.Ops = append(rv.Ops, Op{Op: OpDeleteRole, RoleARN: newARN, OnlyIfUnused: true, Steps: del})
	rv.Diff.Case = CaseSplitRevert
	rv.Diff.Split = detail
	rv.Facts = []Fact{factRole(src.RoleID), factBoundary(srcBoundary, srcBoundary),
		{Key: factKey(FactBinding, in.SubjectARN), Kind: FactBinding, Subject: in.SubjectARN, Before: newARN, After: src.ARN},
		{Key: factKey(FactNewRole, newARN), Kind: FactNewRole, Subject: newARN, Before: newHash, After: ValueAbsent}}
	if err := rv.seal(); err != nil {
		return SplitPlans{}, err
	}
	return SplitPlans{Split: sp, Revert: &rv}, nil
}
