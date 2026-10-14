package azuregraph

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ErrSuperseded means a newer pass over the connector has started: its rows
// will be projected by that pass, and this one's must not be applied over them.
var ErrSuperseded = errors.New("azuregraph: a newer pass over this connector exists")

// Result is what one pass's projection did.
type Result struct {
	Identities    int `json:"identities"`
	Resources     int `json:"resources"`
	Entitlements  int `json:"entitlements"`
	Workloads     int `json:"workloads"`
	Credentials   int `json:"credentials"`
	AccessEdges   int `json:"access_edges"`
	Relationships int `json:"relationships"`
	// Unresolved counts grants and edges whose subject or target is not in the
	// graph (the tenant pass has not been projected, or the principal is from
	// another tenant). Skipped, never invented.
	Unresolved int             `json:"unresolved"`
	Reconcile  ReconcileResult `json:"reconcile"`
	// AKSServiceAccountsJoined counts federation subjects newly tied to a
	// Kubernetes ServiceAccount in the graph.
	AKSServiceAccountsJoined int `json:"aks_service_accounts_joined"`
}

// ProjectPass applies one finished pass to the graph, in the caller's
// transaction: its nodes, their support, its edges, then reconciliation of the
// partitions it owns. Fenced: a pass superseded by a newer one returns
// ErrSuperseded and writes nothing.
func ProjectPass(tx *gorm.DB, p Pass, now time.Time) (*Result, error) {
	var generation int
	if err := tx.Raw(`SELECT scan_generation FROM cloud_connector
		WHERE workspace_id = ? AND id = ? AND provider = ? FOR UPDATE`,
		p.WorkspaceID, p.ConnectorID, models.CloudProviderAzure).Scan(&generation).Error; err != nil {
		return nil, err
	}
	if generation != p.Generation {
		return nil, ErrSuperseded
	}

	w := &writer{tx: tx, p: p, now: now, res: &Result{}}
	tenantScope, err := w.estateScope("tenant", p.TenantID, nil, "")
	if err != nil {
		return nil, fmt.Errorf("tenant scope: %w", err)
	}
	w.tenantScope = tenantScope
	if p.ScopeKind == models.CloudScopeTenant {
		err = w.projectTenant()
	} else {
		var subScope uuid.UUID
		subScope, err = w.estateScope("subscription", p.ScopeID, &tenantScope, p.Stage)
		if err == nil {
			w.subScope = &subScope
			err = w.projectSubscription()
		}
	}
	if err != nil {
		return nil, err
	}
	rr, err := reconcile(tx, p, now)
	if err != nil {
		return nil, fmt.Errorf("reconcile: %w", err)
	}
	w.res.Reconcile = *rr
	joined, err := resolveAKSServiceAccounts(tx, p.WorkspaceID, now)
	if err != nil {
		return nil, fmt.Errorf("aks service accounts: %w", err)
	}
	w.res.AKSServiceAccountsJoined = int(joined)
	return w.res, nil
}

// aksJoinRule names how an Azure federation subject was tied to a Kubernetes
// service account, recorded on the resolution so a reader can weigh it.
const aksJoinRule = "aks_oidc_issuer_and_cluster_name"

// resolveAKSServiceAccounts ties AKS workload identity together across the two
// halves AuthSec reads separately (PRD D1: the ServiceAccount annotation plus a
// federated credential is the join key).
//
// Azure holds one half: a federated credential trusting
// system:serviceaccount:<ns>:<name> from an AKS cluster's OIDC issuer (an
// external principal), and the cluster itself with that issuer (a workload).
// The Kubernetes connector holds the other: the ServiceAccount, keyed by the
// cluster name its agent reports. The two meet when the agent's cluster name is
// the AKS cluster's -- the default for an agent installed on AKS -- so the
// resolution is recorded as derived, with that rule, never as asserted.
// Only unresolved principals are touched: a resolution a person made stands.
func resolveAKSServiceAccounts(tx *gorm.DB, workspaceID uuid.UUID, now time.Time) (int64, error) {
	res := tx.Exec(`
		UPDATE iga_external_principal ep
		   SET resolved_identity_account_id = k.id,
		       resolution_basis = ?, resolution_rule = ?, last_seen_at = ?
		  FROM iga_workload w, iga_identity_accounts k
		 WHERE ep.workspace_id = ? AND ep.source_key LIKE ?
		   AND ep.resolved_identity_account_id IS NULL AND ep.resolved_workload_id IS NULL
		   AND ep.resolution_basis = ''
		   AND ep.subject_claim LIKE 'system:serviceaccount:%'
		   AND w.workspace_id = ep.workspace_id AND w.provider = ? AND w.lifecycle <> 'retired'
		   AND w.runtime_kind = 'microsoft.containerservice/managedclusters'
		   AND lower(w.provider_attrs->>'oidc_issuer') = lower(ep.issuer)
		   AND k.workspace_id = ep.workspace_id AND k.provider = ? AND k.lifecycle <> 'retired'
		   AND k.source_key = ? || w.display_name || ? || split_part(ep.subject_claim, ':', 3)
		                        || ? || split_part(ep.subject_claim, ':', 4)`,
		models.BasisDerived, aksJoinRule, now,
		workspaceID, models.ProviderAzure+Sep+"%",
		models.ProviderAzure, models.ProviderK8s,
		models.ProviderK8s+Sep, Sep+"serviceaccount"+Sep, Sep)
	return res.RowsAffected, res.Error
}

type writer struct {
	tx          *gorm.DB
	p           Pass
	now         time.Time
	res         *Result
	tenantScope uuid.UUID
	subScope    *uuid.UUID
	// agentListed are the object ids Microsoft Entra Agent ID listed, whose
	// edges belong to the agent can_assume partition.
	agentListed map[string]bool
}

/* --------------------------------- loading ---------------------------------- */

// azureGrantRow is one cloud_permission row confirmed by this pass, with the
// native ids of who holds it and what it points at.
type azureGrantRow struct {
	models.CloudPermission
	SubjectNativeID  string `gorm:"column:subject_native_id"`
	ResourceNativeID string `gorm:"column:resource_native_id"`
	ResourceKind     string `gorm:"column:resource_kind"`
	ResourceName     string `gorm:"column:resource_name"`
}

type azureEdgeRow struct {
	models.CloudAssumeEdge
	TargetNativeID string `gorm:"column:target_native_id"`
}

type azureWorkloadRow struct {
	models.CloudWorkload
	IdentityNativeID string `gorm:"column:identity_native_id"`
}

type azureSecretRow struct {
	models.CloudSecret
	OwnerNativeID string `gorm:"column:owner_native_id"`
}

// confirmed scopes a query to the rows THIS pass confirmed.
func (w *writer) confirmed(alias string) string {
	return alias + ".workspace_id = ? AND " + alias + ".connector_id = ? AND " + alias + ".last_seen_generation = ?"
}

func (w *writer) args() []interface{} {
	return []interface{}{w.p.WorkspaceID, w.p.ConnectorID, w.p.Generation}
}

func (w *writer) loadGrants() ([]azureGrantRow, error) {
	var rows []azureGrantRow
	err := w.tx.Table("cloud_permission p").
		Select("p.*, i.native_id AS subject_native_id, COALESCE(r.native_id, '') AS resource_native_id, "+
			"COALESCE(r.kind, '') AS resource_kind, COALESCE(r.name, '') AS resource_name").
		Joins("JOIN cloud_identity i ON i.id = p.identity_id").
		Joins("LEFT JOIN cloud_resource r ON r.id = p.resource_id").
		Where(w.confirmed("p"), w.args()...).
		Scan(&rows).Error
	return rows, err
}

func (w *writer) loadEdges() ([]azureEdgeRow, error) {
	var rows []azureEdgeRow
	err := w.tx.Table("cloud_assume_edge e").
		Select("e.*, i.native_id AS target_native_id").
		Joins("JOIN cloud_identity i ON i.id = e.identity_id").
		Where(w.confirmed("e"), w.args()...).
		Scan(&rows).Error
	return rows, err
}

/* --------------------------------- the tenant -------------------------------- */

func (w *writer) projectTenant() error {
	var identities []models.CloudIdentity
	if err := w.tx.Table("cloud_identity c").Where(w.confirmed("c"), w.args()...).Find(&identities).Error; err != nil {
		return fmt.Errorf("load identities: %w", err)
	}
	identityKeys := make([]string, 0, len(identities))
	for i := range identities {
		if err := w.upsertIdentity(identities[i]); err != nil {
			return fmt.Errorf("identity %s: %w", identities[i].NativeID, err)
		}
		identityKeys = append(identityKeys, IdentityKey(w.p.TenantID, identities[i].NativeID))
	}
	w.res.Identities = len(identities)
	identityIDs, err := w.idsByKey("iga_identity_accounts", identityKeys)
	if err != nil {
		return err
	}
	if err := w.support("identity_account_id", identityIDs, TargetNode, models.ObjectIdentity); err != nil {
		return err
	}
	// What Agent ID listed is supported by that listing too.
	w.agentListed = map[string]bool{}
	agentIDs := map[string]uuid.UUID{}
	for _, c := range identities {
		var a struct {
			Listed bool `json:"agent_listed"`
		}
		_ = json.Unmarshal(c.Attrs, &a)
		if !a.Listed {
			continue
		}
		w.agentListed[c.NativeID] = true
		key := IdentityKey(w.p.TenantID, c.NativeID)
		if id, ok := identityIDs[key]; ok {
			agentIDs[key] = id
		}
	}
	if err := w.support("identity_account_id", agentIDs, TargetAgentNode, models.ObjectIdentity); err != nil {
		return err
	}

	// Credentials: metadata of app and service principal secrets.
	var secrets []azureSecretRow
	if err := w.tx.Table("cloud_secret s").Select("s.*, i.native_id AS owner_native_id").
		Joins("JOIN cloud_identity i ON i.id = s.identity_id").
		Where(w.confirmed("s"), w.args()...).Scan(&secrets).Error; err != nil {
		return fmt.Errorf("load secrets: %w", err)
	}
	for _, s := range secrets {
		holder, ok := identityIDs[IdentityKey(w.p.TenantID, s.OwnerNativeID)]
		if !ok {
			w.res.Unresolved++
			continue
		}
		if err := w.upsertCredential(s, holder); err != nil {
			return fmt.Errorf("credential %s: %w", s.NativeID, err)
		}
		w.res.Credentials++
	}

	// API-plane resources: one per permission an API exposes.
	if err := w.projectResources(); err != nil {
		return err
	}

	// Grants: directory roles, application and delegated permissions.
	if err := w.projectGrants(identityIDs); err != nil {
		return err
	}

	// Group membership, from the member ids the groups surface recorded.
	byObject := make(map[string]uuid.UUID, len(identityIDs))
	for k, v := range identityIDs {
		byObject[k] = v
	}
	part := w.p.Partition(TargetRelationship, models.RelTypeMemberOf).Key()
	for _, g := range identities {
		if g.Kind != models.CloudIdentityEntraGroup {
			continue
		}
		var attrs struct {
			MemberIDs []string `json:"member_ids"`
		}
		_ = json.Unmarshal(g.Attrs, &attrs)
		groupKey := IdentityKey(w.p.TenantID, g.NativeID)
		groupID, ok := byObject[groupKey]
		if !ok {
			continue
		}
		for _, m := range attrs.MemberIDs {
			memberKey := IdentityKey(w.p.TenantID, m)
			memberID, ok := byObject[memberKey]
			if !ok {
				// A device or an object the directory listing did not return.
				continue
			}
			if err := w.upsertRelationship(models.RelTypeMemberOf, relEnd{identity: &memberID}, groupID,
				RelationshipKey(w.p.TenantID, models.RelTypeMemberOf, memberKey, groupKey), part, ""); err != nil {
				return fmt.Errorf("member_of: %w", err)
			}
		}
	}

	// An app registration's credentials sign in as its service principal (the
	// same appId), which holds what the app was granted.
	if err := w.projectAppRegistrations(identities, byObject); err != nil {
		return err
	}

	// Federated credentials on app registrations.
	return w.projectFederation(identityIDs)
}

/* ------------------------------ the subscription ------------------------------ */

func (w *writer) projectSubscription() error {
	if err := w.projectResources(); err != nil {
		return err
	}
	if err := w.projectGrants(nil); err != nil {
		return err
	}
	if err := w.projectWorkloads(); err != nil {
		return err
	}
	return w.projectFederation(nil)
}

/* ---------------------------------- nodes ----------------------------------- */

func (w *writer) upsertIdentity(c models.CloudIdentity) error {
	attrs := map[string]interface{}{}
	_ = json.Unmarshal(c.Attrs, &attrs)
	attrs["object_id"] = c.NativeID
	attrs["enabled"] = c.Enabled
	// The unified inventory's scope (internal/igaread): an Entra object is
	// the tenant's.
	attrs["native_id"] = c.NativeID
	w.tenantScopeAttrs(attrs)
	if c.LastUsedAt != nil {
		attrs["last_sign_in_at"] = c.LastUsedAt
	}
	if c.ProviderCreatedAt != nil {
		attrs["created_at"] = c.ProviderCreatedAt
	}
	// Group member ids live on the member_of edges, not repeated here.
	delete(attrs, "member_ids")
	raw, err := json.Marshal(attrs)
	if err != nil {
		return err
	}
	key := IdentityKey(w.p.TenantID, c.NativeID)
	row := map[string]interface{}{
		"id": uuid.New(), "workspace_id": w.p.WorkspaceID, "estate_scope_id": w.tenantScope,
		"display_name": c.Name, "account_kind": c.Kind, "identity_backing": "provider",
		"lifecycle": models.IGALifecycleActive, "provider": models.ProviderAzure, "source_key": key,
		// An Entra object id never changes and is never reused: a deleted and
		// recreated user is a new object. Immutable is the true claim here.
		"continuity": models.ContinuityImmutable, "immutable_key": strings.ToLower(c.NativeID),
		"provider_attrs": raw, "first_seen_at": w.now, "last_seen_at": w.now,
		"created_at": w.now, "updated_at": w.now,
	}
	return w.tx.Table("iga_identity_accounts").Clauses(conflictOn(liveByLifecycle, map[string]interface{}{
		"display_name": c.Name, "account_kind": c.Kind, "provider_attrs": raw,
		"estate_scope_id": w.tenantScope, "last_seen_at": w.now, "updated_at": w.now,
	})).Create(row).Error
}

func (w *writer) projectResources() error {
	var resources []models.CloudResource
	if err := w.tx.Table("cloud_resource c").Where(w.confirmed("c"), w.args()...).Find(&resources).Error; err != nil {
		return fmt.Errorf("load resources: %w", err)
	}
	keys := make([]string, 0, len(resources))
	for _, r := range resources {
		key := ResourceKey(w.p.TenantID, r.NativeID)
		ra := map[string]interface{}{
			"native_id": r.NativeID, "account": r.ResourceAccount,
			"sensitivity": r.Sensitivity, "sensitivity_source": r.SensitivitySource,
			"sensitivity_reason": r.SensitivityReason,
		}
		w.nodeScopeAttrs(ra, r.NativeID, "")
		raw, err := json.Marshal(ra)
		if err != nil {
			return err
		}
		// The rule's own words say whether it rated the resource production
		// (tagged so, or inside a production resource group or subscription).
		stage := "unknown"
		if strings.Contains(r.SensitivityReason, "production") {
			stage = "production"
		}
		row := map[string]interface{}{
			"id": uuid.New(), "workspace_id": w.p.WorkspaceID, "estate_scope_id": w.scopeForNodes(),
			"resource_kind": r.Kind, "display_name": r.Name, "stage": stage,
			"lifecycle": models.IGALifecycleActive, "provider": models.ProviderAzure, "source_key": key,
			// An ARM id is a name: a resource deleted and recreated under it is
			// indistinguishable here. Recognition is all that is earned.
			"continuity": models.ContinuityRecognitionOnly, "provider_attrs": raw,
			"first_seen_at": w.now, "last_seen_at": w.now, "created_at": w.now, "updated_at": w.now,
		}
		if err := w.tx.Table("iga_resources").Clauses(conflictOn(liveByLifecycle, map[string]interface{}{
			"display_name": r.Name, "resource_kind": r.Kind, "stage": stage, "provider_attrs": raw,
			"last_seen_at": w.now, "updated_at": w.now,
		})).Create(row).Error; err != nil {
			return fmt.Errorf("resource %s: %w", r.NativeID, err)
		}
		keys = append(keys, key)
	}
	w.res.Resources = len(resources)
	ids, err := w.idsByKey("iga_resources", keys)
	if err != nil {
		return err
	}
	return w.support("resource_id", ids, TargetNode, models.ObjectResource)
}

// The scope kinds the unified inventory (internal/igaread) shows an Azure row
// under, written into provider_attrs as Kubernetes and GitHub rows state
// theirs: scope_kind, scope_id, scope_label, sub_scope and native_id. The
// scope id is the lowercased tenant or subscription id, the id the shared
// connections list gives the same connection.
const (
	ScopeKindTenant       = "azure_tenant"
	ScopeKindSubscription = "azure_subscription"
)

// tenantScopeAttrs states the tenant as a row's scope.
func (w *writer) tenantScopeAttrs(attrs map[string]interface{}) {
	t := strings.ToLower(w.p.TenantID)
	attrs["scope_kind"], attrs["scope_id"], attrs["scope_label"] = ScopeKindTenant, t, t
	delete(attrs, "sub_scope")
}

// nodeScopeAttrs states a resource's or workload's scope: its subscription,
// with its resource group (else its region) as the sub-scope, when the pass is
// a subscription's and the ARM id is under it; the tenant otherwise (an
// API-plane resource such as an app role).
func (w *writer) nodeScopeAttrs(attrs map[string]interface{}, armID, region string) {
	sub := strings.ToLower(w.p.ScopeID)
	id := strings.ToLower(armID)
	if w.p.ScopeKind != models.CloudScopeSubscription || sub == "" || !strings.HasPrefix(id, "/subscriptions/"+sub) {
		w.tenantScopeAttrs(attrs)
		return
	}
	label := w.p.ScopeLabel
	if label == "" {
		label = sub
	}
	attrs["scope_kind"], attrs["scope_id"], attrs["scope_label"] = ScopeKindSubscription, sub, label
	if rg := armResourceGroup(armID); rg != "" {
		attrs["sub_scope"] = rg
	} else if region != "" {
		attrs["sub_scope"] = region
	} else {
		delete(attrs, "sub_scope")
	}
}

// armResourceGroup is the resource group an ARM id names, as written, or "".
func armResourceGroup(armID string) string {
	parts := strings.Split(armID, "/")
	for i := 0; i+1 < len(parts); i++ {
		if strings.EqualFold(parts[i], "resourceGroups") {
			return parts[i+1]
		}
	}
	return ""
}

// scopeForNodes is the estate scope a pass's resources and workloads sit in.
func (w *writer) scopeForNodes() uuid.UUID {
	if w.subScope != nil {
		return *w.subScope
	}
	return w.tenantScope
}

func (w *writer) upsertCredential(s azureSecretRow, holder uuid.UUID) error {
	key := CredentialKey(w.p.TenantID, s.NativeID)
	lifecycle := "active"
	if s.ExpiresAt != nil && s.ExpiresAt.Before(w.now) {
		lifecycle = "expired"
	}
	values := map[string]interface{}{
		"identity_account_id": holder, "credential_type": s.Kind, "issuer": "entra",
		"key_identifier": s.NativeID, "issued_at": s.ProviderCreatedAt, "expires_at": s.ExpiresAt,
		"last_used_at": s.LastUsedAt, "lifecycle": lifecycle, "retired_reason": "",
		"last_seen_at": w.now, "updated_at": w.now,
	}
	// uq_iga_credentials_source_key leaves expired and revoked rows out, so an
	// ON CONFLICT upsert would insert a fresh expired row on every pass. The
	// row is found by key whatever its lifecycle, and updated in place.
	var existing struct{ ID uuid.UUID }
	if err := w.tx.Table("iga_credentials").Select("id").
		Where("workspace_id = ? AND source_key = ?", w.p.WorkspaceID, key).
		Order("updated_at DESC").Limit(1).Scan(&existing).Error; err != nil {
		return err
	}
	if existing.ID != uuid.Nil {
		return w.tx.Table("iga_credentials").Where("id = ?", existing.ID).Updates(values).Error
	}
	values["id"] = uuid.New()
	values["workspace_id"] = w.p.WorkspaceID
	values["provider"] = models.ProviderAzure
	values["source_key"] = key
	values["continuity"] = models.ContinuityRecognitionOnly
	values["rotation_posture"] = "unknown"
	values["first_seen_at"] = w.now
	values["created_at"] = w.now
	return w.tx.Table("iga_credentials").Create(values).Error
}

/* ---------------------------------- grants ---------------------------------- */

// grantShape is how one cloud_permission row reads as a grant.
type grantShape struct {
	kind, pathKind, nativeScope string
	calculation, conclusion     string
}

func shapeOf(g azureGrantRow) grantShape {
	roleName := ""
	if g.RoleName != nil {
		roleName = *g.RoleName
	}
	switch {
	case g.ResourceKind == models.CloudResourceEntraAppRole:
		// An application permission is in the app's token whoever signs in:
		// no deny exists for it.
		return grantShape{"entra_app_role", "entra_app_permission", apiName(roleName), "complete", "effective"}
	case g.ResourceKind == models.CloudResourceEntraDelegatedScope:
		// Only ever on behalf of a signed-in user and capped by that user's own
		// access: what it reaches depends on who signs in.
		return grantShape{"entra_delegated_scope", "entra_delegated_permission", apiName(roleName), "partial", "unknown"}
	case g.Plane == models.PermissionPlaneAPI:
		// An active Microsoft Entra role assignment: Entra has no deny over it.
		// A scoped one (an administrative unit, or one application) reaches
		// only its scope, which the condition names.
		return grantShape{"entra_directory_role", "entra_directory_role", directoryRoleScopeOf(g.Condition), "complete", "effective"}
	case strings.Contains(g.NativeID, "/accesspolicies/"):
		vault := g.NativeID[:strings.Index(g.NativeID, "/accesspolicies/")]
		if g.ConstraintState == models.ConstraintConditional {
			return grantShape{"key_vault_access_policy", "key_vault_access_policy", vault, "partial", "unknown"}
		}
		return grantShape{"key_vault_access_policy", "key_vault_access_policy", vault, "complete", "effective"}
	}
	// Azure RBAC. Deny assignments are not read and ABAC conditions are not
	// evaluated, so the conclusion is left open rather than claimed.
	return grantShape{"azure_role_definition", "azure_rbac", rbacScope(g.NativeID), "partial", "unknown"}
}

// directoryRoleScopeOf is a Microsoft Entra role assignment's scope:
// "directory" for the whole tenant, else its directory or app scope id.
func directoryRoleScopeOf(condition *string) string {
	if condition == nil || *condition == "" {
		return "directory"
	}
	var c struct {
		DirectoryScopeID string `json:"directory_scope_id"`
		AppScopeID       string `json:"app_scope_id"`
	}
	if json.Unmarshal([]byte(*condition), &c) != nil {
		return "directory"
	}
	if c.DirectoryScopeID != "" {
		return "directory" + c.DirectoryScopeID
	}
	if c.AppScopeID != "" {
		return "directory/app" + c.AppScopeID
	}
	return "directory"
}

// apiName is the API half of "Microsoft Graph: Mail.Read".
func apiName(roleName string) string {
	if i := strings.Index(roleName, ": "); i > 0 {
		return roleName[:i]
	}
	return roleName
}

// rbacScope is the scope of a role assignment, from its ARM id.
func rbacScope(assignmentID string) string {
	const marker = "/providers/microsoft.authorization/roleassignments/"
	if i := strings.Index(strings.ToLower(assignmentID), marker); i >= 0 {
		if i == 0 {
			return "/"
		}
		return assignmentID[:i]
	}
	return assignmentID
}

func (w *writer) projectGrants(tenantIdentityIDs map[string]uuid.UUID) error {
	grants, err := w.loadGrants()
	if err != nil {
		return fmt.Errorf("load grants: %w", err)
	}
	subjectIDs := tenantIdentityIDs
	if subjectIDs == nil {
		keys := make([]string, 0, len(grants))
		for _, g := range grants {
			keys = append(keys, IdentityKey(w.p.TenantID, g.SubjectNativeID))
		}
		if subjectIDs, err = w.idsByKey("iga_identity_accounts", keys); err != nil {
			return err
		}
	}
	resourceKeys := make([]string, 0, len(grants))
	for _, g := range grants {
		if g.ResourceNativeID != "" {
			resourceKeys = append(resourceKeys, ResourceKey(w.p.TenantID, g.ResourceNativeID))
		}
	}
	resourceIDs, err := w.idsByKey("iga_resources", resourceKeys)
	if err != nil {
		return err
	}

	// Entitlements first, by content.
	entKeys := map[string]bool{}
	var entKeyList []string
	for _, g := range grants {
		shape := shapeOf(g)
		key := w.entitlementKey(g, shape)
		if entKeys[key] {
			continue
		}
		entKeys[key] = true
		if err := w.upsertEntitlement(g, shape, key); err != nil {
			return fmt.Errorf("entitlement: %w", err)
		}
		entKeyList = append(entKeyList, key)
	}
	w.res.Entitlements += len(entKeyList)
	entIDs, err := w.idsByKey("iga_entitlements", entKeyList)
	if err != nil {
		return err
	}
	if err := w.support("entitlement_id", entIDs, TargetNode, models.ObjectEntitlement); err != nil {
		return err
	}

	part := w.p.Partition(TargetAccessEdge, TargetAccessEdge).Key()
	agentPart := w.p.Partition(TargetAccessEdge, ClassAccessEdgeAgent).Key()
	for _, g := range grants {
		subject, ok := subjectIDs[IdentityKey(w.p.TenantID, g.SubjectNativeID)]
		if !ok {
			w.res.Unresolved++
			continue
		}
		shape := shapeOf(g)
		// A grant an agent inherits from its blueprint is derived, not read
		// off the agent, and lives or ends with the Agent ID reading.
		part, basis := part, models.BasisObserved
		if strings.Contains(g.NativeID, models.InheritedGrantMarker) {
			part, basis = agentPart, models.BasisDerived
		}
		row := map[string]interface{}{
			"id": uuid.New(), "workspace_id": w.p.WorkspaceID,
			"subject_kind": "identity_account", "subject_id": subject, "subject_identity_account_id": subject,
			"provider": models.ProviderAzure, "direction": "outbound", "path_kind": shape.pathKind,
			"basis": basis, "calculation_state": shape.calculation,
			"effective_conclusion": shape.conclusion, "native_scope": shape.nativeScope,
			"state": models.RelCurrent, "valid_from": w.now, "last_confirmed_at": w.now,
			"last_confirmed_by": w.p.RunID, "connector_id": w.p.ConnectorID, "observed_at": w.now,
			"source_key":    GrantKey(w.p.TenantID, g.SubjectNativeID, g.NativeID, g.ResourceNativeID),
			"partition_key": part, "created_at": w.now, "updated_at": w.now,
		}
		update := map[string]interface{}{
			"calculation_state": shape.calculation, "effective_conclusion": shape.conclusion,
			"native_scope": shape.nativeScope, "path_kind": shape.pathKind,
			"state": models.RelCurrent, "last_confirmed_at": w.now, "last_confirmed_by": w.p.RunID,
			"connector_id": w.p.ConnectorID, "partition_key": part, "observed_at": w.now, "updated_at": w.now,
		}
		if id, ok := entIDs[w.entitlementKey(g, shape)]; ok {
			row["entitlement_id"], update["entitlement_id"] = id, id
		}
		if g.ResourceNativeID != "" {
			if id, ok := resourceIDs[ResourceKey(w.p.TenantID, g.ResourceNativeID)]; ok {
				row["resource_id"], update["resource_id"] = id, id
			}
		}
		if err := w.tx.Table("iga_access_edges").Clauses(conflictOn(liveEdge, update)).Create(row).Error; err != nil {
			return fmt.Errorf("access edge: %w", err)
		}
		w.res.AccessEdges++
	}
	return nil
}

func (w *writer) entitlementKey(g azureGrantRow, shape grantShape) string {
	roleName := ""
	if g.RoleName != nil {
		roleName = *g.RoleName
	}
	return EntitlementKey(w.p.TenantID, shape.kind, roleName, g.Actions, g.NotActions)
}

func (w *writer) upsertEntitlement(g azureGrantRow, shape grantShape, key string) error {
	roleName := ""
	if g.RoleName != nil {
		roleName = *g.RoleName
	}
	native := map[string]interface{}{
		"role_name": roleName, "actions": g.Actions, "not_actions": g.NotActions,
	}
	if g.Condition != nil {
		native["condition"] = json.RawMessage(*g.Condition)
	}
	nativeRaw, err := json.Marshal(native)
	if err != nil {
		return err
	}
	normRaw, err := json.Marshal(map[string]interface{}{
		"actions": g.Actions, "sensitivity": g.Sensitivity, "wildcard": hasWildcard(g.Actions),
	})
	if err != nil {
		return err
	}
	hash := ContentHash(roleName, g.Actions, g.NotActions)
	row := map[string]interface{}{
		"id": uuid.New(), "workspace_id": w.p.WorkspaceID, "native_grant_kind": shape.kind,
		"native_rights": nativeRaw, "normalized_rights": normRaw, "lifecycle": models.IGALifecycleActive,
		"provider": models.ProviderAzure, "source_key": key, "continuity": models.ContinuityRecognitionOnly,
		"statement_key": key, "content_hash": hash, "effect": "allow",
		"negated": len(g.NotActions) > 0, "conditional": g.Condition != nil,
		"first_seen_at": w.now, "last_seen_at": w.now, "created_at": w.now, "updated_at": w.now,
	}
	return w.tx.Table("iga_entitlements").Clauses(conflictOn(liveByLifecycle, map[string]interface{}{
		"native_rights": nativeRaw, "normalized_rights": normRaw, "last_seen_at": w.now, "updated_at": w.now,
	})).Create(row).Error
}

func hasWildcard(actions []string) bool {
	for _, a := range actions {
		if a == "*" || strings.HasSuffix(a, "/*") {
			return true
		}
	}
	return false
}

/* --------------------------------- workloads --------------------------------- */

func (w *writer) projectWorkloads() error {
	var rows []azureWorkloadRow
	if err := w.tx.Table("cloud_workload c").
		Select("c.*, COALESCE(i.native_id, '') AS identity_native_id").
		Joins("LEFT JOIN cloud_identity i ON i.id = c.identity_id").
		Where(w.confirmed("c"), w.args()...).Scan(&rows).Error; err != nil {
		return fmt.Errorf("load workloads: %w", err)
	}
	identityKeys := make([]string, 0, len(rows))
	for _, r := range rows {
		if r.IdentityNativeID != "" {
			identityKeys = append(identityKeys, IdentityKey(w.p.TenantID, r.IdentityNativeID))
		}
	}
	identityIDs, err := w.idsByKey("iga_identity_accounts", identityKeys)
	if err != nil {
		return err
	}

	keys := make([]string, 0, len(rows))
	for _, r := range rows {
		key := WorkloadKey(w.p.TenantID, r.NativeID)
		identityKey := ""
		state, ref := "none", ""
		if r.IdentityNativeID != "" {
			identityKey = IdentityKey(w.p.TenantID, r.IdentityNativeID)
		}
		var attrs map[string]interface{}
		_ = json.Unmarshal(r.Attrs, &attrs)
		if attrs == nil {
			attrs = map[string]interface{}{}
		}
		armID, _ := attrs["resource_id"].(string)
		if armID == "" {
			armID = strings.SplitN(r.NativeID, "#", 2)[0]
		}
		attrs["native_id"] = armID
		w.nodeScopeAttrs(attrs, armID, r.Region)
		wattrs, err := json.Marshal(attrs)
		if err != nil {
			return err
		}
		if identityKey != "" {
			if _, ok := identityIDs[identityKey]; ok {
				state = "resolved"
			} else {
				state, ref = "not_in_inventory", r.IdentityNativeID
			}
		} else if pid, _ := attrs["principal_id"].(string); pid != "" {
			state, ref = "not_in_inventory", pid
		}
		row := map[string]interface{}{
			"id": uuid.New(), "workspace_id": w.p.WorkspaceID, "estate_scope_id": w.scopeForNodes(),
			"provider": models.ProviderAzure, "runtime_kind": r.RuntimeKind, "display_name": r.Name,
			"region": r.Region, "lifecycle": models.IGALifecycleActive, "source_key": key,
			"continuity": models.ContinuityRecognitionOnly, "provider_attrs": wattrs,
			"execution_role_state": state, "execution_role_arn": ref,
			"first_seen_at": w.now, "last_seen_at": w.now, "created_at": w.now, "updated_at": w.now,
		}
		if err := w.tx.Table("iga_workload").Clauses(conflictOn(liveWorkload, map[string]interface{}{
			"display_name": r.Name, "runtime_kind": r.RuntimeKind, "region": r.Region,
			"provider_attrs": wattrs, "execution_role_state": state, "execution_role_arn": ref,
			"last_seen_at": w.now, "updated_at": w.now,
		})).Create(row).Error; err != nil {
			return fmt.Errorf("workload %s: %w", r.NativeID, err)
		}
		keys = append(keys, key)
	}
	w.res.Workloads = len(rows)
	ids, err := w.idsByKey("iga_workload", keys)
	if err != nil {
		return err
	}
	if err := w.support("workload_id", ids, TargetNode, models.ObjectWorkload); err != nil {
		return err
	}

	part := w.p.Partition(TargetRelationship, models.RelTypeExecutesAs).Key()
	for _, r := range rows {
		if r.IdentityNativeID == "" {
			continue
		}
		identityKey := IdentityKey(w.p.TenantID, r.IdentityNativeID)
		target, ok := identityIDs[identityKey]
		if !ok {
			w.res.Unresolved++
			continue
		}
		wid, ok := ids[WorkloadKey(w.p.TenantID, r.NativeID)]
		if !ok {
			continue
		}
		key := RelationshipKey(w.p.TenantID, models.RelTypeExecutesAs, WorkloadKey(w.p.TenantID, r.NativeID), identityKey)
		if err := w.upsertRelationship(models.RelTypeExecutesAs, relEnd{workload: &wid}, target, key, part, ""); err != nil {
			return fmt.Errorf("executes_as: %w", err)
		}
	}
	return nil
}

/* ----------------------------- app registrations ----------------------------- */

// projectAppRegistrations links each app registration to its service principal
// in the tenant (the same appId) as can_assume: the app registration holds the
// secrets and certificates, the service principal what they unlock. An app
// registration with no service principal here has nothing to link to.
func (w *writer) projectAppRegistrations(identities []models.CloudIdentity, ids map[string]uuid.UUID) error {
	appIDOf := func(c models.CloudIdentity) string {
		var a struct {
			AppID string `json:"app_id"`
		}
		_ = json.Unmarshal(c.Attrs, &a)
		return strings.ToLower(a.AppID)
	}
	spByApp := map[string]string{}
	for _, c := range identities {
		if c.Kind != models.CloudIdentityEntraServicePrincipal {
			continue
		}
		if appID := appIDOf(c); appID != "" {
			spByApp[appID] = c.NativeID
		}
	}
	part := w.p.Partition(TargetRelationship, models.RelTypeCanAssume).Key()
	agentPart := w.p.Partition(TargetRelationship, ClassCanAssumeAgent).Key()
	for _, app := range identities {
		if app.Kind != models.CloudIdentityEntraApplication {
			continue
		}
		spNative, ok := spByApp[appIDOf(app)]
		if !ok {
			continue
		}
		appKey := IdentityKey(w.p.TenantID, app.NativeID)
		spKey := IdentityKey(w.p.TenantID, spNative)
		appID, ok1 := ids[appKey]
		spID, ok2 := ids[spKey]
		if !ok1 || !ok2 {
			continue
		}
		edgePart := part
		if w.agentListed[spNative] {
			edgePart = agentPart
		}
		if err := w.upsertRelationship(models.RelTypeCanAssume, relEnd{identity: &appID}, spID,
			RelationshipKey(w.p.TenantID, models.RelTypeCanAssume, appKey, spKey), edgePart,
			models.AssumeMechanismEntraAppRegistration); err != nil {
			return fmt.Errorf("app registration: %w", err)
		}
	}
	return nil
}

/* -------------------------------- federation --------------------------------- */

func (w *writer) projectFederation(tenantIdentityIDs map[string]uuid.UUID) error {
	edges, err := w.loadEdges()
	if err != nil {
		return fmt.Errorf("load federated credentials: %w", err)
	}
	ids := tenantIdentityIDs
	if ids == nil {
		keys := make([]string, 0, len(edges)*2)
		for _, e := range edges {
			keys = append(keys, IdentityKey(w.p.TenantID, e.TargetNativeID), IdentityKey(w.p.TenantID, e.Subject))
		}
		if ids, err = w.idsByKey("iga_identity_accounts", keys); err != nil {
			return err
		}
	}
	part := w.p.Partition(TargetRelationship, models.RelTypeCanAssume).Key()
	agentPart := w.p.Partition(TargetRelationship, ClassCanAssumeAgent).Key()
	for _, e := range edges {
		edgePart := part
		if w.agentListed[e.TargetNativeID] {
			edgePart = agentPart
		}
		targetKey := IdentityKey(w.p.TenantID, e.TargetNativeID)
		target, ok := ids[targetKey]
		if !ok {
			w.res.Unresolved++
			continue
		}
		issuer := ""
		if e.Issuer != nil {
			issuer = *e.Issuer
		}
		var from relEnd
		var fromKey string
		// A credential trusting another Entra identity (a managed identity used
		// as a federated credential) is an identity-to-identity edge when that
		// identity is in the graph; anything else is an outside principal.
		if e.SubjectKind == models.AssumeSubjectIdentity {
			if src, ok := ids[IdentityKey(w.p.TenantID, e.Subject)]; ok {
				from, fromKey = relEnd{identity: &src}, IdentityKey(w.p.TenantID, e.Subject)
			}
		}
		if from.identity == nil {
			extKey := ExternalPrincipalKey(w.p.TenantID, issuer, e.Subject)
			ext, err := w.externalPrincipal(extKey, issuer, e.Subject, e.Mechanism)
			if err != nil {
				return fmt.Errorf("external principal: %w", err)
			}
			from, fromKey = relEnd{external: &ext}, extKey
		}
		key := RelationshipKey(w.p.TenantID, models.RelTypeCanAssume, fromKey, targetKey)
		if err := w.upsertRelationship(models.RelTypeCanAssume, from, target, key, edgePart, e.Mechanism); err != nil {
			return fmt.Errorf("can_assume: %w", err)
		}
	}
	return nil
}

func (w *writer) externalPrincipal(key, issuer, subject, mechanism string) (uuid.UUID, error) {
	row := map[string]interface{}{
		"id": uuid.New(), "workspace_id": w.p.WorkspaceID, "issuer": issuer, "subject_claim": subject,
		"mechanism": mechanism, "source_key": key, "first_seen_at": w.now, "last_seen_at": w.now,
	}
	if err := w.tx.Table("iga_external_principal").Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "workspace_id"}, {Name: "source_key"}},
		DoUpdates: clause.Assignments(map[string]interface{}{"last_seen_at": w.now}),
	}).Create(row).Error; err != nil {
		return uuid.Nil, err
	}
	var out struct{ ID uuid.UUID }
	err := w.tx.Table("iga_external_principal").Select("id").
		Where("workspace_id = ? AND source_key = ?", w.p.WorkspaceID, key).Scan(&out).Error
	return out.ID, err
}

/* ------------------------------- relationships ------------------------------- */

// relEnd is the source of a relationship: exactly one of the three.
type relEnd struct {
	identity, workload, external *uuid.UUID
}

func (w *writer) upsertRelationship(relType string, from relEnd, target uuid.UUID, key, partition, mechanism string) error {
	row := map[string]interface{}{
		"id": uuid.New(), "workspace_id": w.p.WorkspaceID, "relationship_type": relType,
		"target_identity_account_id": target, "basis": models.BasisObserved, "state": models.RelCurrent,
		"valid_from": w.now, "last_confirmed_at": w.now, "last_confirmed_by": w.p.RunID,
		"source_key": key, "partition_key": partition, "connector_id": w.p.ConnectorID,
		"mechanism": mechanism, "created_at": w.now, "updated_at": w.now,
	}
	switch {
	case from.identity != nil:
		row["source_identity_account_id"] = *from.identity
	case from.workload != nil:
		row["source_workload_id"] = *from.workload
	case from.external != nil:
		row["source_external_principal_id"] = *from.external
	}
	if err := w.tx.Table("iga_relationship").Clauses(conflictOn(liveRelationship, map[string]interface{}{
		"state": models.RelCurrent, "last_confirmed_at": w.now, "last_confirmed_by": w.p.RunID,
		"connector_id": w.p.ConnectorID, "partition_key": partition, "updated_at": w.now,
	})).Create(row).Error; err != nil {
		return err
	}
	w.res.Relationships++
	return nil
}

/* ---------------------------------- support ---------------------------------- */

// support records, for each object, that THIS pass of THIS connector saw it.
// Reconciliation reads these: an object lives exactly as long as some source
// still supports it (§2.10B), so a resource seen by two subscriptions' passes,
// or an entitlement shared by a tenant and a subscription, survives either one
// going blind.
func (w *writer) support(col string, ids map[string]uuid.UUID, target, class string) error {
	part := w.p.Partition(target, class).Key()
	for _, id := range ids {
		row := map[string]interface{}{
			"id": uuid.New(), "workspace_id": w.p.WorkspaceID, col: id,
			"connector_id": w.p.ConnectorID, "partition_key": part, "state": models.RelCurrent,
			"first_seen_at": w.now, "last_confirmed_run_id": w.p.RunID, "last_confirmed_at": w.now,
		}
		if err := w.tx.Table("iga_object_support").Clauses(clause.OnConflict{
			Columns: []clause.Column{
				{Name: "workspace_id"}, {Name: col}, {Name: "source_ref"}, {Name: "partition_key"},
			},
			TargetWhere: clause.Where{Exprs: []clause.Expression{gorm.Expr(col + " IS NOT NULL")}},
			DoUpdates: clause.Assignments(map[string]interface{}{
				// Re-confirming revives a row a previous pass ended or marked
				// stale: the object is plainly here again.
				"state": models.RelCurrent, "ended_reason": "",
				"last_confirmed_run_id": w.p.RunID, "last_confirmed_at": w.now,
			}),
		}).Create(row).Error; err != nil {
			return fmt.Errorf("%s support: %w", col, err)
		}
	}
	return nil
}

/* ---------------------------------- helpers ---------------------------------- */

func (w *writer) estateScope(kind, id string, parent *uuid.UUID, stage string) (uuid.UUID, error) {
	key := ScopeKey(kind, id)
	row := map[string]interface{}{
		"id": uuid.New(), "workspace_id": w.p.WorkspaceID, "scope_kind": kind,
		"display_name": strings.ToLower(id), "source_key": key, "created_at": w.now, "updated_at": w.now,
	}
	update := map[string]interface{}{"updated_at": w.now}
	if stage != "" {
		row["stage"], update["stage"] = stage, stage
	}
	if parent != nil {
		row["parent_scope_id"], update["parent_scope_id"] = *parent, *parent
	}
	if err := w.tx.Table("iga_estate_scopes").Clauses(clause.OnConflict{
		Columns:     []clause.Column{{Name: "workspace_id"}, {Name: "source_key"}},
		TargetWhere: clause.Where{Exprs: []clause.Expression{gorm.Expr("source_key <> ''")}},
		DoUpdates:   clause.Assignments(update),
	}).Create(row).Error; err != nil {
		return uuid.Nil, err
	}
	var out struct{ ID uuid.UUID }
	err := w.tx.Table("iga_estate_scopes").Select("id").
		Where("workspace_id = ? AND source_key = ?", w.p.WorkspaceID, key).Scan(&out).Error
	return out.ID, err
}

// idsByKey maps live source keys of one graph table to row ids. Read back
// rather than remembered: an upsert that hit an existing row kept that row's id.
func (w *writer) idsByKey(table string, keys []string) (map[string]uuid.UUID, error) {
	out := make(map[string]uuid.UUID, len(keys))
	const chunk = 1000
	for start := 0; start < len(keys); start += chunk {
		end := start + chunk
		if end > len(keys) {
			end = len(keys)
		}
		var rows []struct {
			ID        uuid.UUID
			SourceKey string
		}
		if err := w.tx.Table(table).Select("id, source_key").
			Where("workspace_id = ? AND provider = ? AND lifecycle <> ? AND source_key IN ?",
				w.p.WorkspaceID, models.ProviderAzure, models.IGALifecycleRetired, keys[start:end]).
			Scan(&rows).Error; err != nil {
			return nil, err
		}
		for _, r := range rows {
			out[r.SourceKey] = r.ID
		}
	}
	return out, nil
}

// The partial-index predicates, restated so ON CONFLICT can infer the index
// (Postgres will not infer a partial index from its columns alone).
const (
	liveByLifecycle  = "source_key <> '' AND lifecycle <> 'retired'"
	liveWorkload     = "lifecycle <> 'retired'"
	liveEdge         = "source_key <> '' AND state <> 'ended'"
	liveRelationship = "state <> 'ended'"
)

func conflictOn(predicate string, updates map[string]interface{}) clause.OnConflict {
	return clause.OnConflict{
		Columns:     []clause.Column{{Name: "workspace_id"}, {Name: "source_key"}},
		TargetWhere: clause.Where{Exprs: []clause.Expression{gorm.Expr(predicate)}},
		DoUpdates:   clause.Assignments(updates),
	}
}
