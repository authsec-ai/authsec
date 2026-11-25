package services

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/agentcontain"
	"github.com/authsec-ai/authsec/internal/azure"
	"github.com/authsec-ai/authsec/internal/k8sgraph"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
)

// The W2 levels outside the AWS engine's preview (agentcontain/levels.go
// says what each enforces): entra and kubernetes (their own step runners),
// gateway and platform (a row only), and the inventory reads the AWS W2
// levels need (a role's assumers, whether the broker opens sessions on it).

/* ------------------------------- AWS inputs -------------------------------- */

// containAssumersTx classifies the role's trust principals for the chain
// level: a role or user of the same account AuthSec has in its inventory
// (with its unique id) can be denied sts:AssumeRole; nothing else can.
func containAssumersTx(tx *gorm.DB, ws uuid.UUID, id models.CloudIdentity, edges []models.CloudAssumeEdge) ([]agentcontain.Assumer, error) {
	if id.Kind != agentcontain.IdentityRole {
		return nil, nil
	}
	_, _, _, account, _, _ := agentcontain.ARNParts(id.NativeID)
	out := []agentcontain.Assumer{}
	for _, e := range edges {
		a := agentcontain.Assumer{EdgeID: e.ID, Subject: e.Subject}
		switch {
		case e.SubjectKind == models.AssumeSubjectCloudService:
			a.Kind, a.Why = agentcontain.AssumerService, "an AWS service assumes the role with its own authority"
		case e.SubjectKind == models.AssumeSubjectExternal:
			a.Kind, a.Why = agentcontain.AssumerAccount, "the trust names an account (or *), which admits any of its principals whose own policy allows it"
		case e.Mechanism == models.AssumeMechanismOIDCFederation || e.Mechanism == models.AssumeMechanismEKSPodIdentity ||
			e.SubjectKind == models.AssumeSubjectK8sSA || e.SubjectKind == models.AssumeSubjectCIPipeline:
			a.Kind, a.Why = agentcontain.AssumerFederated, "federated sign-in is authorised by the trust policy alone"
		case e.SubjectKind == models.AssumeSubjectIdentity:
			_, svc, _, acct, res, ok := agentcontain.ARNParts(e.Subject)
			switch {
			case !ok || svc != "iam":
				a.Kind, a.Why = agentcontain.AssumerExternal, "not an IAM role or user ARN"
			case acct != account:
				a.Kind, a.Why = agentcontain.AssumerExternal, "another account's principal answers to that account's IAM"
			case strings.HasPrefix(res, "role/") || strings.HasPrefix(res, "user/"):
				a.Kind = agentcontain.AssumerRole
				if strings.HasPrefix(res, "user/") {
					a.Kind = agentcontain.AssumerUser
				}
				a.ARN, a.Name = e.Subject, agentcontain.IdentityNameOf(e.Subject)
				var ids []models.CloudIdentity
				if err := tx.Where("workspace_id = ? AND lower(native_id) = lower(?)", ws, e.Subject).Limit(1).Find(&ids).Error; err != nil {
					return nil, err
				}
				if len(ids) == 0 {
					a.Why = "not in AuthSec's inventory: scan the account again"
					break
				}
				at := ids[0].AWSAttrs()
				iid := ids[0].ID
				a.IdentityID, a.UniqueID, a.Tags = &iid, at.UniqueID, at.Tags
				path := at.Path
				if path == "" {
					path = agentcontain.IdentityPathOf(e.Subject)
				}
				switch {
				case a.UniqueID == "":
					a.Why = "its unique id is unknown: scan the account again"
				case agentcontain.Protected(at.Tags):
					a.Why = "tagged authsec:protected=true"
				case at.Tags["ManagedBy"] == "AuthSec":
					a.Why = "one of AuthSec's own roles"
				case strings.HasPrefix(path, "/aws-service-role/") || strings.HasPrefix(path, "/aws-reserved/"):
					a.Why = "a service-linked or reserved role takes no policy"
				default:
					a.Enforceable = true
				}
			default:
				a.Kind, a.Why = agentcontain.AssumerExternal, "an assumed-role session or other principal: deny the role or user it comes from"
			}
		default:
			a.Kind, a.Why = agentcontain.AssumerExternal, "unrecognised trust principal"
		}
		out = append(out, a)
	}
	return out, nil
}

// containBrokeredTx reports whether AuthSec's broker opens sessions on the
// role (an active iga_gov_runtime_broker_role of ws).
func containBrokeredTx(tx *gorm.DB, ws uuid.UUID, roleARN string) (bool, error) {
	var n int64
	err := tx.Model(&models.IGAGovRuntimeBrokerRole{}).Where("workspace_id = ? AND role_arn = ? AND state = ?", ws, roleARN, "active").Count(&n).Error
	return n > 0, err
}

/* ------------------------------ other families ----------------------------- */

// containOtherPreview is the stored preview of a non-AWS level.
type containOtherPreview struct {
	Level       string                     `json:"level"`
	Subject     map[string]any             `json:"subject"`
	Steps       []agentcontain.PlannedStep `json:"steps"`
	SideEffects []agentcontain.SideEffect  `json:"side_effects"`
	Summary     string                     `json:"summary"`
	// Entra.
	TenantID      string   `json:"tenant_id,omitempty"`
	Subscriptions []string `json:"subscriptions,omitempty"`
	// Kubernetes.
	K8sBindings []containK8sBinding `json:"k8s_bindings,omitempty"`
}

// containK8sBinding is one binding naming the ServiceAccount.
type containK8sBinding struct {
	Source      uuid.UUID `json:"discovery_source_id"`
	Cluster     string    `json:"cluster"`
	BindingKind string    `json:"binding_kind"`
	Namespace   string    `json:"namespace"`
	Name        string    `json:"name"`
	RoleKind    string    `json:"role_kind"`
	RoleName    string    `json:"role_name"`
	SANamespace string    `json:"sa_namespace"`
	SAName      string    `json:"sa_name"`
}

func (b containK8sBinding) target() string {
	return b.Cluster + ":" + b.BindingKind + "/" + b.Namespace + "/" + b.Name + ":" + b.SANamespace + "/" + b.SAName
}

func containRefused(level string, refusals []agentcontain.Refusal) error {
	return govUnprocessable(GovCodeContainmentRefused, "This identity cannot be contained at the "+level+" level.",
		map[string]any{"level": level, "refusals": refusals})
}

// containOther records an entra, kubernetes, gateway or platform stop.
func (s *AgentContain) containOther(ctx context.Context, ws, actor uuid.UUID, level, reason string, req AgentContainRequest, caseID, narrowedFrom *uuid.UUID) (*AgentContainmentView, error) {
	now := s.now().UTC().Truncate(time.Second)
	row := AgentContainment{ID: uuid.New(), WorkspaceID: ws, WorkloadIDs: pq.StringArray{}, Level: level, State: agentcontain.StatePreviewed,
		Reason: reason, CreatedBy: actor, Verification: json.RawMessage(`{}`), CreatedAt: now, UpdatedAt: now,
		ProofState: agentcontain.ProofRequested, NarrowedFrom: narrowedFrom}
	var pv containOtherPreview
	var err error
	switch level {
	case agentcontain.LevelEntra:
		pv, err = s.entraPreview(ctx, ws, req.IdentityID, &row)
	case agentcontain.LevelKubernetes:
		pv, err = s.k8sPreview(ctx, ws, req.IdentityID, &row)
	case agentcontain.LevelGateway, agentcontain.LevelPlatform:
		pv, err = s.recordPreview(ctx, ws, level, req, &row)
	default:
		return nil, GovBadParam("level", "unknown level "+level+".")
	}
	if err != nil {
		return nil, err
	}
	row.TokenExpiryAt = agentcontain.TokenExpiryAt(level, row.IdentityKind, now)
	raw, err := json.Marshal(pv)
	if err != nil {
		return nil, err
	}
	row.Preview = raw
	if err := s.recordContainment(ctx, ws, actor, &row, caseID, map[string]any{"steps": pv.Steps, "side_effects": pv.SideEffects}); err != nil {
		return nil, err
	}
	return &AgentContainmentView{AgentContainment: row}, nil
}

// containSubjectIdentity resolves identity_id among ws's cloud identities (404
// otherwise, whatever workspace has it).
func containSubjectIdentity(tx *gorm.DB, ws uuid.UUID, raw string) (*models.CloudIdentity, error) {
	id, err := uuid.Parse(strings.TrimSpace(raw))
	if err != nil {
		if strings.TrimSpace(raw) == "" {
			return nil, GovBadParam("identity_id", "identity_id is required.")
		}
		return nil, GovNotFound()
	}
	var ids []models.CloudIdentity
	if err := tx.Where("workspace_id = ? AND id = ?", ws, id).Limit(1).Find(&ids).Error; err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, GovNotFound()
	}
	return &ids[0], nil
}

/* ---------------------------------- entra ---------------------------------- */

func graphPermissionGranted(perms []models.AzureGraphPermission) bool {
	want := map[string]bool{strings.ToLower(agentcontain.EntraGraphPermission): true}
	for _, p := range agentcontain.EntraAgentGraphPermissions {
		want[strings.ToLower(p)] = true
	}
	for _, p := range perms {
		if p.Granted && want[strings.ToLower(p.Name)] {
			return true
		}
	}
	return false
}

func (s *AgentContain) entraPreview(ctx context.Context, ws uuid.UUID, identity string, row *AgentContainment) (containOtherPreview, error) {
	pv := containOtherPreview{Level: agentcontain.LevelEntra}
	var refusals []agentcontain.Refusal
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		id, err := containSubjectIdentity(tx, ws, identity)
		if err != nil {
			return err
		}
		switch id.Kind {
		case agentcontain.IdentityEntraSP, agentcontain.IdentityEntraAgent:
		case "entra_managed_identity":
			refusals = append(refusals, agentcontain.Refusal{Code: agentcontain.RefuseManagedIdentity,
				Message: "A managed identity cannot be disabled through Graph; stop the resource it belongs to, or remove its role assignments with an Azure access block."})
		default:
			refusals = append(refusals, agentcontain.Refusal{Code: agentcontain.RefuseLevelNotForIdentity,
				Message: "The entra level stops an Entra service principal or agent identity (this identity is " + id.Kind + ")."})
		}
		var conns []models.CloudConnector
		if err := tx.Where("workspace_id = ? AND id = ?", ws, id.ConnectorID).Limit(1).Find(&conns).Error; err != nil {
			return err
		}
		if len(conns) == 0 || conns[0].Provider != models.CloudProviderAzure {
			return GovNotFound()
		}
		ta := conns[0].AzureTenantAttrs()
		pv.TenantID = ta.TenantID
		if !graphPermissionGranted(ta.GraphPermissions) {
			refusals = append(refusals, agentcontain.Refusal{Code: agentcontain.RefusePermissionMissing,
				Message: "Disabling a service principal needs the Microsoft Graph application permission " + agentcontain.EntraGraphPermission +
					" (an agent identity: " + strings.Join(agentcontain.EntraAgentGraphPermissions, " or ") + ", UNVERIFIED names) granted to AuthSec's app in this tenant; the tenant has not granted it."})
		}
		if ta.ServicePrincipalObjectID != "" && strings.EqualFold(ta.ServicePrincipalObjectID, id.NativeID) {
			refusals = append(refusals, agentcontain.Refusal{Code: agentcontain.RefuseAuthSecOwned, Message: "This is AuthSec's own service principal."})
		}
		var subs []models.CloudConnector
		if err := tx.Where("workspace_id = ? AND provider = ? AND scope_kind = ? AND status = ?", ws, models.CloudProviderAzure,
			models.CloudScopeSubscription, models.CloudConnectorActive).Order("scope_id").Find(&subs).Error; err != nil {
			return err
		}
		for _, sc := range subs {
			if strings.EqualFold(sc.AzureSubscriptionAttrs().TenantID, ta.TenantID) {
				pv.Subscriptions = append(pv.Subscriptions, strings.ToLower(sc.ScopeID))
			}
		}
		row.ConnectorID, row.IdentityID, row.IdentityKind = id.ConnectorID, id.ID, id.Kind
		row.IdentityARN, row.UniqueID = strings.ToLower(id.NativeID), strings.ToLower(id.NativeID)
		pv.Subject = map[string]any{"identity_id": id.ID, "object_id": id.NativeID, "name": id.Name, "kind": id.Kind, "tenant_id": ta.TenantID}
		return nil
	})
	if err != nil {
		return pv, err
	}
	if d := currentAzureAccessDeps(); d == nil || d.Graph == nil || d.GraphToken == nil {
		refusals = append(refusals, agentcontain.Refusal{Code: agentcontain.RefusePermissionMissing, Message: "Azure access is not configured on this server."})
	}
	if len(refusals) > 0 {
		return pv, containRefused(agentcontain.LevelEntra, refusals)
	}
	pv.Steps = append(pv.Steps, agentcontain.PlannedStep{Kind: agentcontain.StepEntraAccount, Target: row.IdentityARN,
		Detail: "PATCH accountEnabled=false on the service principal (Microsoft Graph); release re-enables it only if AuthSec disabled it."})
	for _, sub := range pv.Subscriptions {
		pv.Steps = append(pv.Steps, agentcontain.PlannedStep{Kind: agentcontain.StepAzureRoleAssignment, Target: "/subscriptions/" + sub,
			Detail: "Remove every role assignment of the principal in subscription " + sub + " (each recorded and recreated on release)."})
	}
	pv.SideEffects = []agentcontain.SideEffect{
		{Code: agentcontain.EffectTokensLiveUntilExpiry, Message: "Access tokens issued before the stop stay valid until they expire (about 60-90 minutes; longer for continuous-access-evaluation tokens): the stop is unproven until token_expiry_at."},
		{Code: agentcontain.EffectRoleAssignmentsRemoved, Message: "Every Azure role assignment of the principal in the connected subscriptions is removed; anything else relying on them stops too. Assignments inherited from a management group are not changed."},
	}
	pv.Summary = "Disables the service principal in Entra and removes its Azure role assignments."
	return pv, nil
}

// entraAPI adapts the Azure clients to agentcontain.Entra for one tenant.
type entraAPI struct {
	deps   *AzureAccessDeps
	ws     uuid.UUID
	tenant string
	graph  string
	arm    string
}

func (a *entraAPI) graphToken(ctx context.Context) (string, error) {
	if a.graph == "" {
		t, err := a.deps.GraphToken(ctx, a.ws, a.tenant)
		if err != nil {
			return "", err
		}
		a.graph = t
	}
	return a.graph, nil
}

func (a *entraAPI) armToken(ctx context.Context) (string, error) {
	if a.arm == "" {
		t, err := a.deps.Token(ctx, a.ws, a.tenant)
		if err != nil {
			return "", err
		}
		a.arm = t
	}
	return a.arm, nil
}

func mapAzureErr(err error) error {
	if err == nil {
		return nil
	}
	switch azure.APIStatus(err) {
	case http.StatusForbidden, http.StatusUnauthorized:
		return fmt.Errorf("%w: %v", agentcontain.ErrDenied, err)
	case http.StatusNotFound:
		return fmt.Errorf("%w: %v", agentcontain.ErrNotFound, err)
	}
	return err
}

func (a *entraAPI) AccountEnabled(ctx context.Context, objectID string) (bool, error) {
	t, err := a.graphToken(ctx)
	if err != nil {
		return false, err
	}
	on, err := a.deps.Graph.ServicePrincipalAccountEnabled(ctx, t, objectID)
	return on, mapAzureErr(err)
}

func (a *entraAPI) SetAccountEnabled(ctx context.Context, objectID string, enabled bool) error {
	t, err := a.graphToken(ctx)
	if err != nil {
		return err
	}
	return mapAzureErr(a.deps.Graph.SetServicePrincipalAccountEnabled(ctx, t, objectID, enabled))
}

func (a *entraAPI) ListRoleAssignments(ctx context.Context, sub, principal string) ([]azure.RoleAssignment, error) {
	t, err := a.armToken(ctx)
	if err != nil {
		return nil, err
	}
	out, err := a.deps.RBAC.ListRoleAssignmentsForPrincipal(ctx, t, sub, principal)
	return out, mapAzureErr(err)
}

func (a *entraAPI) GetRoleAssignment(ctx context.Context, id string) (*azure.RoleAssignment, error) {
	t, err := a.armToken(ctx)
	if err != nil {
		return nil, err
	}
	r, err := a.deps.RBAC.GetRoleAssignment(ctx, t, id)
	return r, mapAzureErr(err)
}

func (a *entraAPI) DeleteRoleAssignment(ctx context.Context, id string) error {
	t, err := a.armToken(ctx)
	if err != nil {
		return err
	}
	return mapAzureErr(a.deps.RBAC.DeleteRoleAssignment(ctx, t, id))
}

func (a *entraAPI) PutRoleAssignment(ctx context.Context, spec azure.RoleAssignmentSpec) error {
	t, err := a.armToken(ctx)
	if err != nil {
		return err
	}
	_, err = a.deps.RBAC.PutRoleAssignment(ctx, t, spec)
	return mapAzureErr(err)
}

func (j *containJob) openEntra(ctx context.Context) (*agentcontain.EntraEngine, error) {
	deps := currentAzureAccessDeps()
	if deps == nil || deps.Graph == nil || deps.GraphToken == nil || deps.Token == nil {
		return nil, PolicyJobRetryLater(5*time.Minute, "Azure access is not configured on this server")
	}
	var pv containOtherPreview
	_ = json.Unmarshal(j.row.Preview, &pv)
	return &agentcontain.EntraEngine{API: &entraAPI{deps: deps, ws: j.ws, tenant: pv.TenantID}, ObjectID: j.row.IdentityARN,
		Subscriptions: pv.Subscriptions}, nil
}

/* -------------------------------- kubernetes ------------------------------- */

func (s *AgentContain) k8sPreview(ctx context.Context, ws uuid.UUID, identity string, row *AgentContainment) (containOtherPreview, error) {
	pv := containOtherPreview{Level: agentcontain.LevelKubernetes}
	var refusals []agentcontain.Refusal
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		id, err := uuid.Parse(strings.TrimSpace(identity))
		if err != nil {
			return GovNotFound()
		}
		var accs []models.IGAIdentityAccount
		if err := tx.Where("workspace_id = ? AND id = ?", ws, id).Limit(1).Find(&accs).Error; err != nil {
			return err
		}
		if len(accs) == 0 {
			return GovNotFound()
		}
		sa, ok := k8sgraph.ParseKey(accs[0].SourceKey)
		if accs[0].AccountKind != models.K8sAccountKindServiceAccount || !ok || sa.Type != "serviceaccount" {
			return containRefused(agentcontain.LevelKubernetes, []agentcontain.Refusal{{Code: agentcontain.RefuseLevelNotForIdentity,
				Message: "The kubernetes level stops a Kubernetes ServiceAccount."}})
		}
		var as []struct {
			SourceKey         string
			DiscoverySourceID *uuid.UUID
			PolicySourceKey   string
		}
		if err := tx.Table("iga_policy_assignment a").Select("a.source_key, a.discovery_source_id, p.source_key AS policy_source_key").
			Joins("JOIN iga_policy p ON p.workspace_id = a.workspace_id AND p.id = a.policy_id").
			Where("a.workspace_id = ? AND a.holder_identity_account_id = ? AND a.state <> ? AND a.assignment_kind IN ?", ws, id, "ended",
				[]string{models.K8sAssignmentRoleBinding, models.K8sAssignmentClusterRoleBinding}).Order("a.source_key").Scan(&as).Error; err != nil {
			return err
		}
		agents := map[uuid.UUID]*k8sAgentLimits{}
		for _, a := range as {
			b, ok := bindingOfAssignment(a.SourceKey)
			role, rok := k8sgraph.ParseKey(a.PolicySourceKey)
			if !ok || !rok || a.DiscoverySourceID == nil {
				continue
			}
			lim, seen := agents[*a.DiscoverySourceID]
			if !seen {
				var src []models.DiscoverySource
				if err := tx.Where("workspace_id = ? AND id = ?", ws, *a.DiscoverySourceID).Limit(1).Find(&src).Error; err != nil {
					return err
				}
				lim = k8sAgentLimitsOf(src)
				agents[*a.DiscoverySourceID] = lim
			}
			kb := containK8sBinding{Source: *a.DiscoverySourceID, Cluster: b.Cluster, BindingKind: k8sBindingKind(b), Namespace: b.Namespace,
				Name: b.Name, RoleKind: k8sRoleKind(role), RoleName: role.Name, SANamespace: sa.Namespace, SAName: sa.Name}
			switch {
			case !lim.canAct:
				refusals = append(refusals, agentcontain.Refusal{Code: agentcontain.RefuseK8sAgentCannotAct,
					Message: "The agent in cluster " + b.Cluster + " may not change bindings: turn enforcement on for it and enforcement.bindings in its chart."})
			case strings.HasPrefix(role.Name, "system:"):
				refusals = append(refusals, agentcontain.Refusal{Code: agentcontain.RefuseK8sAgentCannotAct,
					Message: "Binding " + b.Name + " grants the cluster's own " + role.Name + ": AuthSec never changes it."})
			case lim.roles != nil && !containsString(lim.roles, role.Name):
				refusals = append(refusals, agentcontain.Refusal{Code: agentcontain.RefuseK8sAgentCannotAct,
					Message: "The agent in cluster " + b.Cluster + " may not change bindings of " + role.Name + ": add it to enforcement.bindings.roles."})
			case kb.BindingKind == models.K8sKindClusterRoleBinding && lim.cluster != nil && !*lim.cluster && !lim.allRoles:
				refusals = append(refusals, agentcontain.Refusal{Code: agentcontain.RefuseK8sAgentCannotAct,
					Message: "The agent in cluster " + b.Cluster + " may not change ClusterRoleBindings: turn on enforcement.bindings.clusterWide."})
			case kb.BindingKind == models.K8sKindRoleBinding && len(lim.namespaces) > 0 && !containsString(lim.namespaces, b.Namespace) && (lim.cluster == nil || !*lim.cluster):
				refusals = append(refusals, agentcontain.Refusal{Code: agentcontain.RefuseK8sAgentCannotAct,
					Message: "The agent in cluster " + b.Cluster + " may not change RoleBindings in " + b.Namespace + "."})
			}
			var n int64
			if err := tx.Model(&models.IGAGovK8sAccess{}).Where("workspace_id = ? AND identity_account_id = ? AND cluster = ? AND binding_kind = ? AND binding_namespace = ? AND binding_name = ? AND state IN ?",
				ws, id, b.Cluster, kb.BindingKind, b.Namespace, b.Name, k8sLiveStates).Count(&n).Error; err != nil {
				return err
			}
			if n > 0 {
				refusals = append(refusals, agentcontain.Refusal{Code: agentcontain.RefuseK8sAgentCannotAct,
					Message: "An access policy already holds the ServiceAccount out of " + b.Name + "; end it first."})
			}
			pv.K8sBindings = append(pv.K8sBindings, kb)
		}
		if len(pv.K8sBindings) == 0 {
			refusals = append(refusals, agentcontain.Refusal{Code: agentcontain.RefuseK8sNoBinding,
				Message: accs[0].DisplayName + " holds no RoleBinding or ClusterRoleBinding AuthSec has seen."})
		}
		row.IdentityID, row.IdentityKind, row.IdentityARN, row.UniqueID = id, agentcontain.IdentityK8sSA, accs[0].SourceKey, accs[0].ImmutableKey
		if len(pv.K8sBindings) > 0 {
			row.ConnectorID = pv.K8sBindings[0].Source
		}
		pv.Subject = map[string]any{"identity_account_id": id, "cluster": sa.Cluster, "namespace": sa.Namespace, "name": sa.Name}
		return nil
	})
	if err != nil {
		return pv, err
	}
	if len(refusals) > 0 {
		return pv, containRefused(agentcontain.LevelKubernetes, refusals)
	}
	for _, b := range pv.K8sBindings {
		pv.Steps = append(pv.Steps, agentcontain.PlannedStep{Kind: agentcontain.StepK8sBindingSubject, Target: b.target(),
			Detail: "Take " + b.SANamespace + "/" + b.SAName + " out of " + b.BindingKind + " " + b.Name + " (" + b.RoleName + "); put back on release."})
	}
	pv.SideEffects = []agentcontain.SideEffect{
		{Code: agentcontain.EffectK8sTokensValid, Message: "The ServiceAccount's tokens stay valid (the cluster agent cannot delete or rotate token Secrets yet): they lose the permissions of these bindings at once, since RBAC is checked on every request."},
		{Code: agentcontain.EffectK8sOtherPaths, Message: "Access through groups (system:serviceaccounts, system:authenticated), bindings AuthSec has not seen, or a cloud role the pods assume (IRSA, Pod Identity) is unchanged; contain that role separately."},
	}
	pv.Summary = fmt.Sprintf("Takes the ServiceAccount out of %d binding(s).", len(pv.K8sBindings))
	return pv, nil
}

// k8sContainRunner drives the kubernetes level through the cluster agent's
// instruction channel (remove_binding_subject / restore_binding_subject).
type k8sContainRunner struct{ j *containJob }

func (r *k8sContainRunner) bindings() []containK8sBinding {
	var pv containOtherPreview
	_ = json.Unmarshal(r.j.row.Preview, &pv)
	return pv.K8sBindings
}

func (r *k8sContainRunner) plan() []agentcontain.Step {
	var out []agentcontain.Step
	for _, b := range r.bindings() {
		raw, _ := json.Marshal(b)
		out = append(out, agentcontain.Step{Kind: agentcontain.StepK8sBindingSubject, Target: b.target(), Before: raw})
	}
	return out
}

func (r *k8sContainRunner) binding(st *agentcontain.Step) (containK8sBinding, error) {
	var b containK8sBinding
	if err := json.Unmarshal(st.Before, &b); err != nil || b.Name == "" {
		return b, fmt.Errorf("binding step %s has no before-state", st.Target)
	}
	return b, nil
}

func (r *k8sContainRunner) Before(context.Context, *agentcontain.Step) (bool, error) {
	return false, nil
}

// instructions are the step's instructions of kind, oldest first.
func (r *k8sContainRunner) instructions(ctx context.Context, st *agentcontain.Step, kind string) ([]models.ProvisioningInstruction, error) {
	var out []models.ProvisioningInstruction
	err := r.j.run.ReadTx(ctx, func(tx *gorm.DB) error {
		return tx.Where("workspace_id = ? AND fingerprint = ? AND kind = ?", r.j.ws, r.j.row.ID.String()+":"+st.Target, kind).
			Order("created_at, id").Find(&out).Error
	})
	return out, err
}

func (r *k8sContainRunner) instruct(ctx context.Context, st *agentcontain.Step, b containK8sBinding, kind string, n int, uid string) error {
	payload := map[string]any{"binding_kind": b.BindingKind, "namespace": b.Namespace, "name": b.Name, "role_kind": b.RoleKind,
		"role_name": b.RoleName, "subject": map[string]any{"kind": models.K8sSubjectServiceAccount, "namespace": b.SANamespace, "name": b.SAName},
		"containment_id": r.j.row.ID.String(), "deployment_id": r.j.row.ID.String(), "reason": "AuthSec containment " + r.j.row.ID.String()}
	if uid != "" {
		payload["binding_uid"] = uid
	}
	raw, _ := json.Marshal(payload)
	key := fmt.Sprintf("agent_contain:%s:%s:%s:%d", r.j.row.ID, st.ID, kind, n)
	return r.j.run.InTx(ctx, func(tx *gorm.DB) error {
		inst := models.ProvisioningInstruction{ID: uuid.New(), WorkspaceID: r.j.ws, DiscoverySourceID: b.Source, Kind: kind, Payload: raw,
			Fingerprint: r.j.row.ID.String() + ":" + st.Target, IdempotencyKey: key, Status: models.InstructionPending, CreatedBy: "policy-worker"}
		return tx.Create(&inst).Error
	})
}

// Apply hands the removal to the cluster agent; ErrWaiting until it reports.
func (r *k8sContainRunner) Apply(ctx context.Context, st *agentcontain.Step) error {
	b, err := r.binding(st)
	if err != nil {
		return err
	}
	insts, err := r.instructions(ctx, st, models.InstructionRemoveBindingSubject)
	if err != nil {
		return err
	}
	if n := len(insts); n > 0 {
		last := insts[n-1]
		switch last.Status {
		case models.InstructionPending, models.InstructionLeased:
			return agentcontain.ErrWaiting
		case models.InstructionFailed:
			return &agentcontain.StepError{Code: "k8s_agent_failed", Message: "the cluster agent could not remove the subject: " + last.Error}
		case models.InstructionApplied:
			if st.State != agentcontain.StepApplied {
				st.After = append(json.RawMessage(nil), last.Result...)
				return nil
			}
		}
	}
	if err := r.instruct(ctx, st, b, models.InstructionRemoveBindingSubject, len(insts), ""); err != nil {
		return err
	}
	return agentcontain.ErrWaiting
}

// Restore puts the subject back (only where the agent removed it).
func (r *k8sContainRunner) Restore(ctx context.Context, st *agentcontain.Step) error {
	switch st.State {
	case agentcontain.StepSkipped, agentcontain.StepFailed, agentcontain.StepRestored:
		return nil
	}
	b, err := r.binding(st)
	if err != nil {
		return nil // never recorded: never applied
	}
	removes, err := r.instructions(ctx, st, models.InstructionRemoveBindingSubject)
	if err != nil {
		return err
	}
	var rm k8sRemoved
	for i := len(removes) - 1; i >= 0; i-- {
		if removes[i].Status == models.InstructionApplied {
			var x k8sRemoved
			if json.Unmarshal(removes[i].Result, &x) == nil && x.Removed && rm.BindingUID == "" {
				rm = x
			}
		}
	}
	if rm.BindingUID == "" {
		st.Error = "the subject was never taken out of the binding by AuthSec; nothing to put back"
		return nil
	}
	restores, err := r.instructions(ctx, st, models.InstructionRestoreBindingSubject)
	if err != nil {
		return err
	}
	if n := len(restores); n > 0 {
		switch restores[n-1].Status {
		case models.InstructionPending, models.InstructionLeased:
			return agentcontain.ErrWaiting
		case models.InstructionApplied:
			return nil
		case models.InstructionFailed:
			return &agentcontain.StepError{Code: "k8s_agent_failed", Message: "the cluster agent could not put the subject back: " + restores[n-1].Error}
		}
	}
	if err := r.instruct(ctx, st, b, models.InstructionRestoreBindingSubject, len(restores), rm.BindingUID); err != nil {
		return err
	}
	return agentcontain.ErrWaiting
}

// Readback: drifted when an RBAC sweep well after the removal still lists
// the subject in the binding.
func (r *k8sContainRunner) Readback(ctx context.Context, st *agentcontain.Step) (bool, string, error) {
	b, err := r.binding(st)
	if err != nil {
		return false, "", err
	}
	insts, err := r.instructions(ctx, st, models.InstructionRemoveBindingSubject)
	if err != nil {
		return false, "", err
	}
	var at *time.Time
	for _, i := range insts {
		if i.Status == models.InstructionApplied && i.AppliedAt != nil {
			at = i.AppliedAt
		}
	}
	if at == nil {
		return true, "removal pending", nil
	}
	key := k8sgraph.BindingKey(b.Cluster, models.K8sBinding{Name: b.Name, Namespace: b.Namespace}) + k8sgraph.Sep +
		k8sgraph.ServiceAccountKey(b.Cluster, b.SANamespace, b.SAName)
	var n int64
	if err := r.j.run.ReadTx(ctx, func(tx *gorm.DB) error {
		return tx.Model(&models.IGAPolicyAssignment{}).Where("workspace_id = ? AND source_key = ? AND state <> ? AND last_confirmed_at > ?",
			r.j.ws, key, "ended", at.Add(k8sDriftMargin)).Count(&n).Error
	}); err != nil {
		return false, "", err
	}
	return n == 0, "subject in binding", nil
}

/* ----------------------------- gateway, platform --------------------------- */

func (s *AgentContain) recordPreview(ctx context.Context, ws uuid.UUID, level string, req AgentContainRequest, row *AgentContainment) (containOtherPreview, error) {
	pv := containOtherPreview{Level: level}
	if req.Target == "" {
		what := "the gateway subject id of the agent"
		if level == agentcontain.LevelPlatform {
			what = "the platform principal (e.g. openai:org-x/key-y)"
		}
		return pv, GovBadParam("target", "target is required: "+what+".")
	}
	row.Target, row.IdentityARN = req.Target, level+":"+req.Target
	row.IdentityKind = agentcontain.IdentityGatewayAgent
	if level == agentcontain.LevelPlatform {
		row.IdentityKind = agentcontain.IdentityPlatformAgent
	}
	if strings.TrimSpace(req.IdentityID) != "" {
		if err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
			id, err := containSubjectIdentity(tx, ws, req.IdentityID)
			if err != nil {
				return err
			}
			row.IdentityID, row.ConnectorID = id.ID, id.ConnectorID
			return nil
		}); err != nil {
			return pv, err
		}
	} else {
		row.IdentityID = uuid.NewSHA1(ws, []byte(level+"\x1f"+req.Target))
	}
	pv.Subject = map[string]any{"target": req.Target}
	switch level {
	case agentcontain.LevelGateway:
		pv.SideEffects = []agentcontain.SideEffect{{Code: agentcontain.EffectGatewayOnly,
			Message: "Only calls through the AuthSec gateway are refused (the gateway reads the deny list); the agent calling a provider or tool directly is not stopped."}}
		pv.Summary = "The gateway refuses " + req.Target + "."
	default:
		row.State = agentcontain.StateRequested
		pv.SideEffects = []agentcontain.SideEffect{{Code: agentcontain.EffectNothingWritten,
			Message: "AuthSec cannot stop this on the platform itself: the stop is recorded and asked of whoever administers it."}}
		pv.Summary = "Asks for " + req.Target + " to be stopped on its platform."
	}
	return pv, nil
}

// recordRunner is the gateway and platform levels: nothing to write.
type recordRunner struct{}

func (recordRunner) Before(context.Context, *agentcontain.Step) (bool, error) { return true, nil }
func (recordRunner) Apply(context.Context, *agentcontain.Step) error          { return nil }
func (recordRunner) Restore(context.Context, *agentcontain.Step) error        { return nil }
func (recordRunner) Readback(context.Context, *agentcontain.Step) (bool, string, error) {
	return true, "", nil
}
