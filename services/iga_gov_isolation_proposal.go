package services

import (
	"context"
	"fmt"
	"strings"

	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// IsolationProposalInput asks for a new identity with the source role's exact
// permissions. Policy and trust hashes are read by the server, never supplied
// by the browser. No unused-service finding or right-sizing policy is needed.
type IsolationProposalInput struct {
	Workload igagov.DedicatedWorkload `json:"workload"`
	RoleName string                   `json:"role_name"`
	RolePath string                   `json:"role_path"`
}

func (a *GovAuthoring) createIsolationProposal(ctx context.Context, ws, actor uuid.UUID, req ProposalRequest) (*ProposalResult, error) {
	if err := ValidateTargetKeys(req.Keys); err != nil {
		return nil, err
	}
	if req.Delivery == "" {
		req.Delivery = igagov.DeliveryExport
	}
	if req.Delivery != igagov.DeliveryExport && req.Delivery != igagov.DeliveryIaCPR {
		return nil, GovBadParam("delivery", "Dedicated identities use iac_pr or export; direct migration is not supported.")
	}
	resolved, err := a.targets.Resolve(ctx, ws, req.Keys)
	if err != nil {
		return nil, err
	}
	var roles []*proposalRole
	if err := a.readWorkspace(ctx, ws, func(tx *gorm.DB) error {
		var e error
		roles, _, e = a.checkResolved(tx, ws, resolved)
		return e
	}); err != nil {
		return nil, err
	}
	if len(roles) != 1 {
		return nil, GovBadParam("keys", "Resolve exactly one AWS role.")
	}
	target := roles[0].target
	identity := target.Identity
	wid, err := uuid.Parse(req.Isolation.Workload.WorkloadID)
	if err != nil {
		return nil, GovBadParam("isolation.workload.workload_id", "Choose a discovered workload.")
	}
	var runtime string
	for _, consumer := range target.Consumers {
		if consumer.WorkloadID == wid && consumer.Relationship == models.RelTypeExecutesAs {
			runtime = consumer.RuntimeKind
		}
	}
	expected := map[string]string{models.WorkloadLambdaFunction: igagov.BindingLambdaRole,
		models.WorkloadECSTaskDefinition: igagov.BindingECSTaskRole, models.WorkloadEC2Instance: igagov.BindingEC2InstanceProfile}
	if expected[runtime] == "" || expected[runtime] != req.Isolation.Workload.BindingKind {
		return nil, GovBadParam("isolation.workload", "Choose a Lambda, ECS task-role or EC2 workload currently running as this role. Task execution roles cannot be split here.")
	}
	if req.Isolation.Workload.BindingKind == igagov.BindingEC2InstanceProfile && strings.Contains(req.Isolation.Workload.BindingRef, ":autoscaling:") {
		return nil, GovBadParam("isolation.workload.binding_ref", "Choose the discovered EC2 instance ARN for this proposal.")
	}
	b, source, _, err := a.targets.buildBasis(ctx, ws, identity.ID, nil)
	if err != nil {
		return nil, err
	}
	if b.Trust == igagov.TrustUntrusted {
		return nil, (StoredBundle{Trust: b.Trust, TrustReasons: b.TrustReasons, Facts: b.Facts}).UntrustedError()
	}
	if a.live == nil || target.Evidence == nil || target.Evidence.ConnectorID == nil {
		return nil, govUnprocessable(GovCodeDiscoveryUnavail, "A live discovery-role read is required to copy this role.", nil)
	}
	live, err := a.live.ReadRole(ctx, LiveReadRequest{WorkspaceID: ws, ConnectorID: *target.Evidence.ConnectorID,
		AccountID: identity.AccountID, RoleID: identity.RoleID, RoleARN: identity.ARN})
	if err != nil {
		return nil, err
	}
	if live.Role == nil || live.Role.RoleID != identity.RoleID {
		return nil, govConflict(GovCodePlanChanged, "The source role changed or no longer exists. Rescan before creating a dedicated identity.", nil)
	}
	path := strings.TrimSpace(req.Isolation.RolePath)
	if path == "" {
		path = "/"
	}
	nr := igagov.NewRole{Name: strings.TrimSpace(req.Isolation.RoleName), Path: path,
		TrustPolicyHash: live.Role.TrustPolicyHash, BoundaryARN: live.Role.BoundaryARN,
		ManagedPolicyARNs: []string{}, InlinePolicies: []igagov.InlinePolicyRef{}}
	for _, p := range live.Role.ManagedPolicies {
		nr.ManagedPolicyARNs = append(nr.ManagedPolicyARNs, p.Ref)
	}
	for _, p := range live.Role.InlinePolicies {
		nr.InlinePolicies = append(nr.InlinePolicies, igagov.InlinePolicyRef{Name: p.Ref, DocumentHash: p.DocumentHash})
	}
	subject := igagov.Subject{IdentityAccountID: identity.ID.String(), RoleID: identity.RoleID, AccountID: identity.AccountID}
	di := igagov.DedicatedIdentityIntent{Kind: igagov.IntentDedicatedIdentity, Source: subject,
		Workload: req.Isolation.Workload, NewRole: nr, Delivery: req.Delivery}
	intent := igagov.Intent{Kind: di.Kind, DedicatedIdentity: &di}
	if err := igagov.ValidateIntent(intent); err != nil {
		return nil, intentProblems(err)
	}
	canon, hash, err := igagov.CanonicalIntent(intent)
	if err != nil {
		return nil, err
	}
	// Validate the actual migration subject, new ARN and copied documents before
	// reserving the source role. Propose repeats these reads before owner review.
	check := models.IGAGovControl{ID: uuid.New(), PolicyID: uuid.New(), WorkspaceID: ws,
		ConnectorID: *target.Evidence.ConnectorID, AccountID: identity.AccountID, RoleID: identity.RoleID,
		RoleARN: identity.ARN, IdentityAccountID: identity.ID}
	ct, blocked, err := a.compileIsolationOne(ctx, ws, di, models.IGAGovTarget{}, check, directCall)
	if err != nil {
		return nil, err
	}
	if blocked != nil {
		return nil, blocked.Err
	}
	if !ct.Plans.Apply.Eligible() {
		return nil, govUnprocessable(GovCodeTargetIneligible, "This workload cannot be migrated from the available evidence.", map[string]any{"plan": ct.Plans.Apply})
	}
	k, aid := userActor(actor)
	stored, err := a.targets.storeBundle(ctx, ws, identity.ID, b, k, aid)
	if err != nil {
		return nil, err
	}
	evidence := ProposalEvidence{IdentityAccountID: identity.ID, RoleID: identity.RoleID, BundleID: stored.ID,
		BundleHash: stored.Hash, Trust: stored.Trust, TrustReasons: stored.TrustReasons, Gaps: stored.Facts.Gaps}
	res := &ProposalResult{Evidence: evidence, EvidenceTargets: []ProposalEvidence{evidence}, EvaluatedRev: source.Rev,
		Recommendation: ProposalRecommendation{Consumers: target.Consumers, Warnings: []string{"Isolation copies permissions. It removes no services; right-sizing is a separate reviewed change."}}}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = "Dedicated identity: " + nr.Name
	}
	err = a.inWorkspace(ctx, ws, func(tx *gorm.DB) error {
		now := a.now()
		pol := models.IGAGovPolicy{ID: uuid.New(), WorkspaceID: ws, Name: name, Purpose: req.Purpose, Family: "cloud_access", Provider: "aws", Lifecycle: "active", CreatedBy: actor, CreatedAt: now, UpdatedAt: now}
		if err := tx.Create(&pol).Error; err != nil {
			if isUniqueViolation(err, "") {
				return govConflict(GovCodePolicyNameTaken, "Another policy has this name.", map[string]any{"name": name})
			}
			return err
		}
		controls, err := a.bindSubjectsTx(tx, ws, pol.ID, []igagov.Subject{subject})
		if err != nil {
			return err
		}
		v, _, err := a.insertVersionTx(tx, ws, pol.ID, actor, 1, &igagov.RightSizeIntent{EvidenceRev: source.Rev}, canon, hash, controls)
		if err != nil {
			return err
		}
		res.Policy.ID, res.Policy.Name, res.Policy.Family, res.Policy.Provider = pol.ID, pol.Name, pol.Family, pol.Provider
		res.Version.ID, res.Version.No, res.Version.Status, res.Version.Intent, res.Version.IntentHash = v.ID, 1, v.Status, canon, hash
		if err := a.event(tx, ws, "policy_created", k, aid, &pol.ID, nil, map[string]any{"name": name, "family": pol.Family}); err != nil {
			return err
		}
		return a.event(tx, ws, "proposal_created", k, aid, &pol.ID, &v.ID, map[string]any{"kind": di.Kind, "version_no": 1, "intent_hash": hash, "source": "template", "workload_id": wid, "description": fmt.Sprintf("Copy %s into %s", identity.Name, nr.Name)})
	})
	return res, err
}
