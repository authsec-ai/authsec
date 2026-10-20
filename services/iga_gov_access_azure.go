package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/azure"
	"github.com/authsec-ai/authsec/internal/azuregraph"
	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
)

// Access policies on Azure resources (144). The rule is the same intent as
// on AWS (roles, a resource, block or allow, a window); its deployment is
// role assignments, one iga_gov_azure_access row per principal:
//
//	allow  AuthSec creates one role assignment -- a built-in role for the
//	       access level -- for the principal on the resource, named so the
//	       write is idempotent, and deletes it at the end. Azure assignments
//	       carry no expiry, so the end depends on AuthSec's job running.
//	block  Azure RBAC has no customer deny. AuthSec removes the principal's
//	       own role assignments on the resource (or below it) whose role
//	       grants the access, records each exactly before deleting it, and
//	       restores them at the end, on Pause or on End. An assignment at a
//	       broader scope (resource group, subscription) that also grants the
//	       access cannot be removed for one resource: that is a blocker, not a
//	       silent partial block. Group-inherited access is not examined.
//
// Writes use AuthSec's Azure app in the customer's tenant, which needs a
// role-assignment administrator role on the subscription (readiness checks
// Microsoft.Authorization/roleAssignments write and delete).

// Azure access-policy codes.
const (
	GovCodeAzureWriteMissing = "azure_write_access_missing"
	GovCodeAzureInherited    = "azure_inherited_access"
	GovCodeAzureUnavailable  = "azure_unavailable"
)

// AzureRBACClient is the role-assignment surface access policies use
// (*azure.Client in production; a fake in tests).
type AzureRBACClient interface {
	ListRoleAssignmentsForPrincipal(ctx context.Context, armToken, subscriptionID, principalID string) ([]azure.RoleAssignment, error)
	ListRoleDefinitions(ctx context.Context, armToken, subscriptionID string) ([]azure.RoleDefinition, error)
	PutRoleAssignment(ctx context.Context, armToken string, spec azure.RoleAssignmentSpec) (string, error)
	GetRoleAssignment(ctx context.Context, armToken, id string) (*azure.RoleAssignment, error)
	DeleteRoleAssignment(ctx context.Context, armToken, id string) error
	CallerPermissions(ctx context.Context, armToken, subscriptionID string) ([]azure.Permission, error)
}

// AzureAccessDeps is the process's Azure access: the client and an ARM token
// for AuthSec's app in a workspace's tenant.
type AzureAccessDeps struct {
	RBAC  AzureRBACClient
	Token func(ctx context.Context, ws uuid.UUID, tenantID string) (string, error)
}

var azureAccess struct {
	sync.RWMutex
	deps *AzureAccessDeps
}

// SetAzureAccessDeps installs the Azure access (cmd/main.go; tests) and
// returns a function restoring the previous one.
func SetAzureAccessDeps(d *AzureAccessDeps) (restore func()) {
	azureAccess.Lock()
	prev := azureAccess.deps
	azureAccess.deps = d
	azureAccess.Unlock()
	return func() { SetAzureAccessDeps(prev) }
}

func currentAzureAccessDeps() *AzureAccessDeps {
	azureAccess.RLock()
	defer azureAccess.RUnlock()
	return azureAccess.deps
}

// AccessDeps is the production Azure access of this service: its client, and
// an app-only ARM token from the tenant connector's app (AuthSec's, or the
// customer's own).
func (s *AzureOnboardingService) AccessDeps() *AzureAccessDeps {
	return &AzureAccessDeps{RBAC: s.api, Token: func(ctx context.Context, ws uuid.UUID, tenantID string) (string, error) {
		cfg, err := s.resolveDiscoveryConfig(ws, tenantID)
		if err != nil {
			return "", err
		}
		return s.api.AppToken(ctx, cfg, tenantID, azure.ScopeARMApp)
	}}
}

/* ---------------------------------------------------------------------------- */
/*                                  Planning                                    */
/* ---------------------------------------------------------------------------- */

// azureTarget is a resolved Azure resource.
type azureTarget struct {
	TenantID       string
	SubscriptionID string
	Scope          string // the ARM resource id (lower case, as the graph keys it)
	Name           string
	Kind           string
	ConnectorID    uuid.UUID // the subscription's connector
	Storage        bool
	TypePath       string // e.g. "microsoft.storage/storageaccounts"
}

// azurePrincipal is a resolved Azure role.
type azurePrincipal struct {
	IdentityID uuid.UUID
	ObjectID   string
	Name       string
	Kind       string
}

// azurePlan is the Azure part of an access plan.
type azurePlan struct {
	target     azureTarget
	principals []azurePrincipal
	roleGUID   string // allow
	roleName   string
	// revocable / inherited per principal (block), from the live read.
	revocable map[string][]azure.RoleAssignment
	inherited map[string][]azure.RoleAssignment
}

var azureEligibleKinds = map[string]bool{
	models.CloudIdentityEntraServicePrincipal: true,
	models.CloudIdentityEntraManagedIdentity:  true,
	models.CloudIdentityEntraAgentIdentity:    true,
}

func azureKeyParts(sourceKey string) []string { return strings.Split(sourceKey, azuregraph.Sep) }

// resolveAzureTarget reads an iga_resources row's Azure key.
func resolveAzureTarget(tx *gorm.DB, ws uuid.UUID, row models.IGAResource) (*azureTarget, error) {
	parts := azureKeyParts(row.SourceKey)
	if len(parts) < 4 || parts[0] != models.ProviderAzure || parts[2] != "resource" {
		return nil, govUnprocessable(GovCodeResourceNotSupported, "This Azure resource cannot be targeted.", map[string]any{"field": "resource.resource_id"})
	}
	scope := strings.ToLower(strings.Join(parts[3:], azuregraph.Sep))
	if !strings.HasPrefix(scope, "/subscriptions/") {
		return nil, govUnprocessable(GovCodeResourceNotSupported, "Only Azure Resource Manager resources can be targeted.", map[string]any{"field": "resource.resource_id"})
	}
	segs := strings.Split(strings.TrimPrefix(scope, "/"), "/")
	t := &azureTarget{TenantID: parts[1], SubscriptionID: segs[1], Scope: scope, Name: row.DisplayName, Kind: row.ResourceKind}
	if i := indexOf(segs, "providers"); i >= 0 && i+2 < len(segs) {
		tp := []string{segs[i+1], segs[i+2]}
		for j := i + 4; j < len(segs); j += 2 {
			tp = append(tp, segs[j])
		}
		t.TypePath = strings.Join(tp, "/")
	} else {
		return nil, govUnprocessable(GovCodeResourceNotSupported, "Pick a resource, not a resource group or subscription.", map[string]any{"field": "resource.resource_id"})
	}
	t.Storage = strings.HasPrefix(t.TypePath, "microsoft.storage/storageaccounts")
	var conns []models.CloudConnector
	if err := tx.Where("workspace_id = ? AND provider = ? AND scope_kind = ? AND lower(scope_id) = ? AND status = ?",
		ws, models.CloudProviderAzure, models.CloudScopeSubscription, t.SubscriptionID, models.CloudConnectorActive).
		Limit(1).Find(&conns).Error; err != nil {
		return nil, err
	}
	if len(conns) == 0 {
		return nil, govUnprocessable(GovCodeResourceNotSupported, "The resource's subscription is not connected to this workspace.",
			map[string]any{"field": "resource.resource_id", "subscription_id": t.SubscriptionID})
	}
	t.ConnectorID = conns[0].ID
	return t, nil
}

func indexOf(s []string, v string) int {
	for i, x := range s {
		if x == v {
			return i
		}
	}
	return -1
}

// azureActions are the actions an access level stands for on the target
// (control-plane actions, and for storage the blob data actions and the key
// listing that gives the same data access).
func azureActions(t *azureTarget, access []string) (actions, dataActions []string) {
	for _, a := range access {
		switch {
		case t.Storage && a == igagov.AccessRead:
			dataActions = append(dataActions, "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read")
			actions = append(actions, "Microsoft.Storage/storageAccounts/listKeys/action")
		case t.Storage && a == igagov.AccessWrite:
			dataActions = append(dataActions, "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write")
			actions = append(actions, "Microsoft.Storage/storageAccounts/listKeys/action")
		case t.Storage && a == igagov.AccessDelete:
			dataActions = append(dataActions, "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete")
			actions = append(actions, "Microsoft.Storage/storageAccounts/listKeys/action")
		case a == igagov.AccessRead:
			actions = append(actions, t.TypePath+"/read")
		case a == igagov.AccessWrite:
			actions = append(actions, t.TypePath+"/write")
		case a == igagov.AccessDelete:
			actions = append(actions, t.TypePath+"/delete")
		case a == igagov.AccessAll:
			actions = append(actions, t.TypePath+"/read", t.TypePath+"/write", t.TypePath+"/delete")
			if t.Storage {
				actions = append(actions, "Microsoft.Storage/storageAccounts/listKeys/action")
				dataActions = append(dataActions, "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
					"Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write",
					"Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete")
			}
		}
	}
	return sortedUniqueStrings(actions), sortedUniqueStrings(dataActions)
}

// azureAllowRole is the built-in role an allow assigns.
func azureAllowRole(t *azureTarget, access []string) (guid, name string) {
	writes := false
	for _, a := range access {
		writes = writes || a == igagov.AccessWrite || a == igagov.AccessDelete
	}
	switch {
	case t.Storage && writes:
		return azure.RoleStorageBlobDataContributor, "Storage Blob Data Contributor"
	case t.Storage:
		return azure.RoleStorageBlobDataReader, "Storage Blob Data Reader"
	case writes:
		return azure.RoleContributor, "Contributor"
	}
	return azure.RoleReader, "Reader"
}

// roleGrants reports whether a role definition grants any of the actions.
func roleGrants(def azure.RoleDefinition, actions, dataActions []string) bool {
	for _, p := range def.Properties.Permissions {
		ctl := []azure.Permission{{Actions: p.Actions, NotActions: p.NotActions}}
		data := []azure.Permission{{Actions: p.DataActions, NotActions: p.NotDataActions}}
		for _, a := range actions {
			if azure.AllowsAction(ctl, a) {
				return true
			}
		}
		for _, a := range dataActions {
			if azure.AllowsAction(data, a) {
				return true
			}
		}
	}
	return false
}

// azureSplit sorts a principal's assignments that grant the access into those
// on the resource or below it (revocable) and those at a broader scope
// (inherited: a block on one resource cannot remove them).
func azureSplit(t *azureTarget, as []azure.RoleAssignment, defs map[string]azure.RoleDefinition, actions, dataActions []string) (revocable, inherited []azure.RoleAssignment) {
	for _, a := range as {
		def, ok := defs[strings.ToLower(a.Properties.RoleDefinitionID)]
		if !ok || !roleGrants(def, actions, dataActions) {
			continue
		}
		scope := strings.ToLower(strings.TrimSuffix(a.Properties.Scope, "/"))
		switch {
		case scope == t.Scope || strings.HasPrefix(scope, t.Scope+"/"):
			revocable = append(revocable, a)
		case strings.HasPrefix(t.Scope, scope+"/"):
			inherited = append(inherited, a)
		}
	}
	return revocable, inherited
}

func azureDefs(defs []azure.RoleDefinition) map[string]azure.RoleDefinition {
	out := make(map[string]azure.RoleDefinition, len(defs))
	for _, d := range defs {
		out[strings.ToLower(d.ID)] = d
	}
	return out
}

// planAzure resolves the Azure part of the plan (called from plan()).
func (s *GovAccess) planAzure(ctx context.Context, ws uuid.UUID, p *accessPlan, row models.IGAResource) error {
	if p.intent.Resource.Prefix != "" {
		return govUnprocessable(GovCodeAccessInvalid, "A prefix applies to S3 buckets only.", map[string]any{"field": "resource.prefix"})
	}
	ap := &azurePlan{revocable: map[string][]azure.RoleAssignment{}, inherited: map[string][]azure.RoleAssignment{}}
	if err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		t, err := resolveAzureTarget(tx, ws, row)
		if err != nil {
			return err
		}
		ap.target = *t
		for i, r := range p.intent.Roles {
			field := fmt.Sprintf("roles[%d].identity_account_id", i)
			var ids []models.IGAIdentityAccount
			if err := tx.Where("workspace_id = ? AND id = ?", ws, r.IdentityAccountID).Limit(1).Find(&ids).Error; err != nil {
				return err
			}
			if len(ids) == 0 {
				return govErr(http.StatusNotFound, "not_found", "Not found.", map[string]any{"field": field})
			}
			id := ids[0]
			parts := azureKeyParts(id.SourceKey)
			if id.Provider != models.ProviderAzure || len(parts) < 4 || parts[2] != "object" || !azureEligibleKinds[id.AccountKind] {
				return govUnprocessable(GovCodeRoleIneligible, "Only Azure service principals, managed identities and agent identities can be targeted.",
					map[string]any{"field": field, "account_kind": id.AccountKind})
			}
			if parts[1] != t.TenantID {
				return govUnprocessable(GovCodeRoleNotInAccount, "The identity is in another Entra tenant than the resource.", map[string]any{"field": field})
			}
			ap.principals = append(ap.principals, azurePrincipal{IdentityID: id.ID, ObjectID: parts[3], Name: id.DisplayName, Kind: id.AccountKind})
		}
		return nil
	}); err != nil {
		return err
	}
	if p.intent.Effect == igagov.AccessEffectAllow {
		ap.roleGUID, ap.roleName = azureAllowRole(&ap.target, p.intent.Access)
		if ap.roleGUID == azure.RoleContributor {
			p.warnings = append(p.warnings, AccessIssue{Code: "azure_broad_role",
				Message: "Azure has no built-in role for only " + strings.Join(p.intent.Access, ", ") + " on this resource type: Contributor allows every management write on it."})
		}
		p.warnings = append(p.warnings, AccessIssue{Code: "azure_end_by_job",
			Message: "An Azure role assignment has no expiry of its own: AuthSec removes it at the end time."})
	}
	p.azure = ap
	doc, _ := json.Marshal(azureDocument(p, ap))
	p.doc = doc
	p.docHash = igagov.ContentHash(doc)
	return nil
}

// azureDocument is what the preview and the detail show as the change.
func azureDocument(p *accessPlan, ap *azurePlan) map[string]any {
	if p.intent.Effect == igagov.AccessEffectAllow {
		return map[string]any{"provider": "azure", "create_role_assignment": map[string]any{"scope": ap.target.Scope,
			"role": ap.roleName, "role_definition_id": azure.RoleDefinitionResourceID(ap.target.SubscriptionID, ap.roleGUID)}}
	}
	acts, data := azureActions(&ap.target, p.intent.Access)
	return map[string]any{"provider": "azure", "remove_role_assignments_granting": map[string]any{"scope": ap.target.Scope,
		"actions": acts, "data_actions": data}}
}

// azureChecks is checks() for Azure: AuthSec's write access to the
// subscription, and for a block the live split of each principal's
// assignments (inherited access is a blocker).
func (s *GovAccess) azureChecks(ctx context.Context, ws uuid.UUID, p *accessPlan) []error {
	ap := p.azure
	deps := currentAzureAccessDeps()
	if deps == nil || deps.RBAC == nil || deps.Token == nil {
		return []error{govErr(http.StatusServiceUnavailable, GovCodeAzureUnavailable, "Azure access is not configured on this server.", nil)}
	}
	token, err := deps.Token(ctx, ws, ap.target.TenantID)
	if err != nil {
		return []error{govConflict(GovCodeAzureWriteMissing, "AuthSec cannot get a token for this Azure tenant: "+err.Error(), nil)}
	}
	perms, err := deps.RBAC.CallerPermissions(ctx, token, ap.target.SubscriptionID)
	if err != nil {
		return []error{govConflict(GovCodeAzureWriteMissing, "AuthSec cannot read its own permissions on the subscription: "+err.Error(), nil)}
	}
	if !azure.AllowsAction(perms, "Microsoft.Authorization/roleAssignments/write") || !azure.AllowsAction(perms, "Microsoft.Authorization/roleAssignments/delete") {
		return []error{govConflict(GovCodeAzureWriteMissing,
			"AuthSec's Azure app cannot manage role assignments on subscription "+ap.target.SubscriptionID+
				": give it the Role Based Access Control Administrator role there.", map[string]any{"subscription_id": ap.target.SubscriptionID})}
	}
	if p.intent.Effect == igagov.AccessEffectAllow {
		return nil
	}
	defs, err := deps.RBAC.ListRoleDefinitions(ctx, token, ap.target.SubscriptionID)
	if err != nil {
		return []error{govConflict(GovCodeAzureUnavailable, "AuthSec cannot read the subscription's roles: "+err.Error(), nil)}
	}
	dm := azureDefs(defs)
	acts, data := azureActions(&ap.target, p.intent.Access)
	var errs []error
	for i, pr := range ap.principals {
		as, err := deps.RBAC.ListRoleAssignmentsForPrincipal(ctx, token, ap.target.SubscriptionID, pr.ObjectID)
		if err != nil {
			errs = append(errs, govConflict(GovCodeAzureUnavailable, "AuthSec cannot read "+pr.Name+"'s role assignments: "+err.Error(), nil))
			continue
		}
		rev, inh := azureSplit(&ap.target, as, dm, acts, data)
		ap.revocable[pr.ObjectID], ap.inherited[pr.ObjectID] = rev, inh
		if len(inh) > 0 {
			var where []string
			for _, a := range inh {
				where = append(where, a.Properties.Scope)
			}
			errs = append(errs, govUnprocessable(GovCodeAzureInherited,
				pr.Name+" gets this access from a broader scope ("+strings.Join(where, ", ")+"), which a block on one resource cannot remove.",
				map[string]any{"field": fmt.Sprintf("roles[%d].identity_account_id", i)}))
			continue
		}
		if len(rev) == 0 {
			p.warnings = append(p.warnings, AccessIssue{Code: "azure_nothing_to_remove",
				Message: pr.Name + " has no role assignment on this resource that grants this access now; AuthSec removes any that appear while the block is on."})
		}
	}
	p.warnings = append(p.warnings, AccessIssue{Code: "azure_groups_not_checked",
		Message: "Access through Entra group membership is not examined."})
	return errs
}

// azureSentence is the preview's one line.
func azureSentence(in igagov.AccessIntent, t azureTarget, names []string) string {
	name := t.Name
	if name == "" {
		name = t.Scope[strings.LastIndex(t.Scope, "/")+1:]
	}
	verb := "Allow"
	if in.Effect == igagov.AccessEffectBlock {
		verb = "Block"
	}
	out := verb + " " + strings.Join(in.Access, ", ") + " on Azure " + t.TypePath + " " + name + " for " + strings.Join(names, ", ")
	if in.StartsAt != nil {
		out += " from " + igagov.AWSTime(*in.StartsAt)
	}
	if in.EndsAt != nil {
		out += " until " + igagov.AWSTime(*in.EndsAt)
	}
	return out + "."
}

// accessLiveCount counts the policy's deployment rows still in the cloud
// (AWS and Azure).
func accessLiveCount(tx *gorm.DB, ws, policyID uuid.UUID) (int64, error) {
	var aws, az int64
	if err := tx.Model(&models.IGAGovTempGrant{}).Where("workspace_id = ? AND policy_id = ? AND state IN ?", ws, policyID, accessLiveStates).
		Count(&aws).Error; err != nil {
		return 0, err
	}
	if err := tx.Model(&models.IGAGovAzureAccess{}).Where("workspace_id = ? AND policy_id = ? AND state IN ?", ws, policyID,
		[]string{models.R2StateApproved, models.R2StateDeploying, models.R2StateActive, models.R2StateExpiring}).Count(&az).Error; err != nil {
		return 0, err
	}
	return aws + az, nil
}

// accessSupersedeTx: once every Azure row of the applied version is active,
// the older versions' rows end (as accessAfterActiveTx does for AWS).
func accessSupersedeTx(tx *gorm.DB, ws, policyID, versionID uuid.UUID) error {
	var v []models.IGAGovAccessPolicyVersion
	if err := tx.Where("workspace_id = ? AND id = ? AND status = ?", ws, versionID, models.AccessVersionApplied).
		Limit(1).Find(&v).Error; err != nil || len(v) == 0 {
		return err
	}
	var pending int64
	if err := tx.Model(&models.IGAGovAzureAccess{}).Where("workspace_id = ? AND policy_id = ? AND version_id = ? AND state <> ?",
		ws, policyID, versionID, models.R2StateActive).Count(&pending).Error; err != nil || pending > 0 {
		return err
	}
	_, err := endRowsTx(tx, ws, policyID, &versionID, accessEndSuperseded, nil, time.Now().UTC())
	return err
}

/* ---------------------------------------------------------------------------- */
/*                               Deployment rows                                */
/* ---------------------------------------------------------------------------- */

// deployAzureTx writes one approved row per principal and queues its job.
func (s *GovAccess) deployAzureTx(tx *gorm.DB, ws, actor, policyID uuid.UUID, v *models.IGAGovAccessPolicyVersion, p *accessPlan, now time.Time) error {
	ap := p.azure
	exp := igagov.AccessNoEnd
	if p.intent.EndsAt != nil {
		exp = *p.intent.EndsAt
	}
	effect := "allow"
	if p.intent.Effect == igagov.AccessEffectBlock {
		effect = "deny"
	}
	access, _ := json.Marshal(p.intent.Access)
	for _, pr := range ap.principals {
		row := models.IGAGovAzureAccess{ID: uuid.New(), WorkspaceID: ws, PolicyID: policyID, VersionID: v.ID, ConnectorID: ap.target.ConnectorID,
			IdentityAccountID: pr.IdentityID, TenantID: ap.target.TenantID, SubscriptionID: ap.target.SubscriptionID,
			PrincipalID: pr.ObjectID, PrincipalType: "ServicePrincipal", PrincipalName: pr.Name, Scope: ap.target.Scope,
			Effect: effect, Access: access, Revoked: json.RawMessage(`[]`), State: models.R2StateApproved,
			StartsAt: p.intent.StartsAt, ExpiresAt: exp, CreatedBy: actor, Ops: json.RawMessage(`[]`), CreatedAt: now, UpdatedAt: now}
		if effect == "allow" {
			row.RoleDefinitionID = azure.RoleDefinitionResourceID(ap.target.SubscriptionID, ap.roleGUID)
			row.AssignmentName = azure.RoleAssignmentName(ap.target.Scope, pr.ObjectID, row.RoleDefinitionID+"/"+v.ID.String())
		}
		if err := tx.Create(&row).Error; err != nil {
			return err
		}
		if err := azureEnqueueTx(tx, ws, row.ID, now); err != nil {
			return err
		}
	}
	return nil
}

// azureEnqueueTx asks for the row's job now (pulling an open one forward, as
// r2EnqueueTx does).
func azureEnqueueTx(tx *gorm.DB, ws, id uuid.UUID, at time.Time) error {
	sub := id
	key := "azure_access:" + id.String()
	created, err := repositories.NewIGAGovJobRepository(tx).EnqueueTx(tx, &models.IGAGovJob{WorkspaceID: ws, Kind: repositories.GovJobAzureAccess,
		SubjectID: &sub, DedupeKey: key, RunAfter: at})
	if err != nil || created {
		return err
	}
	return tx.Model(&models.IGAGovJob{}).
		Where("workspace_id = ? AND kind = ? AND dedupe_key = ? AND status = ? AND run_after > ?", ws, repositories.GovJobAzureAccess, key, "queued", at).
		Update("run_after", at).Error
}

// endAzureRowsTx ends the policy's live Azure rows (all versions, or all but
// keep), as endRowsTx does for AWS rows.
func endAzureRowsTx(tx *gorm.DB, ws, policyID uuid.UUID, keep *uuid.UUID, reason string, now time.Time) (int, error) {
	q := tx.Where("workspace_id = ? AND policy_id = ? AND state IN ?", ws, policyID,
		[]string{models.R2StateApproved, models.R2StateDeploying, models.R2StateActive, models.R2StateExpiring})
	if keep != nil {
		q = q.Where("version_id <> ?", *keep)
	}
	var rows []models.IGAGovAzureAccess
	if err := q.Clauses(lockForUpdate()).Find(&rows).Error; err != nil {
		return 0, err
	}
	n := 0
	for _, r := range rows {
		set := map[string]any{"end_reason": reason, "updated_at": now}
		switch r.State {
		case models.R2StateApproved:
			set["state"], set["ended_at"] = models.R2StateRevoked, now
		case models.R2StateExpiring:
			continue
		default:
			set["state"] = models.R2StateExpiring
		}
		if err := tx.Model(&models.IGAGovAzureAccess{}).Where("workspace_id = ? AND id = ? AND state = ?", ws, r.ID, r.State).
			Updates(set).Error; err != nil {
			return n, err
		}
		if set["state"] == models.R2StateExpiring {
			if err := azureEnqueueTx(tx, ws, r.ID, now); err != nil {
				return n, err
			}
		}
		n++
	}
	return n, nil
}

// azureAsGrant presents an Azure row in the shape the status and views read.
func azureAsGrant(a models.IGAGovAzureAccess) models.IGAGovTempGrant {
	pid, vid := a.PolicyID, a.VersionID
	label := a.Scope
	if a.Effect == "allow" && a.AssignmentName != "" {
		label = a.Scope + "/providers/Microsoft.Authorization/roleAssignments/" + a.AssignmentName
	}
	return models.IGAGovTempGrant{ID: a.ID, WorkspaceID: a.WorkspaceID, ConnectorID: a.ConnectorID, IdentityAccountID: a.IdentityAccountID,
		AccountID: a.SubscriptionID, RoleID: a.PrincipalID, RoleARN: "azure:" + a.PrincipalName, PolicyARN: label,
		State: a.State, StateReason: a.StateReason, EndReason: a.EndReason, Drift: a.Drift, ExpiresAt: a.ExpiresAt,
		StartsAt: a.StartsAt, DeployedAt: a.DeployedAt, VerifiedAt: a.VerifiedAt, LastReadbackAt: a.LastReadbackAt, EndedAt: a.EndedAt,
		CreatedAt: a.CreatedAt, UpdatedAt: a.UpdatedAt, Effect: a.Effect, PolicyID: &pid, VersionID: &vid,
		DocumentHash: "azure:" + a.ID.String()}
}

// azureRowDocument is the detail's document of an Azure row.
func azureRowDocument(a models.IGAGovAzureAccess) json.RawMessage {
	doc := map[string]any{"provider": "azure", "scope": a.Scope, "principal_id": a.PrincipalID}
	if a.Effect == "allow" {
		doc["create_role_assignment"] = map[string]any{"name": a.AssignmentName, "role_definition_id": a.RoleDefinitionID}
	} else {
		doc["removed_role_assignments"] = json.RawMessage(a.Revoked)
	}
	raw, _ := json.Marshal(doc)
	return raw
}

/* ---------------------------------------------------------------------------- */
/*                                   The job                                    */
/* ---------------------------------------------------------------------------- */

const azureCheckEvery = 10 * time.Minute

// AzureAccessHandler is the azure_access job (subject: the row).
func (s *GovAccess) AzureAccessHandler(ctx context.Context, run *PolicyJobRun) error {
	if run.Job.SubjectID == nil {
		return PolicyJobAbandon("azure_access needs a row subject")
	}
	ws := run.Job.WorkspaceID
	var row models.IGAGovAzureAccess
	if err := run.ReadTx(ctx, func(tx *gorm.DB) error {
		return tx.Where("workspace_id = ? AND id = ?", ws, *run.Job.SubjectID).Take(&row).Error
	}); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return PolicyJobAbandon("row not found")
		}
		return err
	}
	deps := currentAzureAccessDeps()
	if deps == nil || deps.RBAC == nil || deps.Token == nil {
		return PolicyJobRetryLater(5*time.Minute, "Azure access is not configured")
	}
	var token string
	if err := run.External(ctx, 0, func(ctx context.Context) error {
		var err error
		token, err = deps.Token(ctx, ws, row.TenantID)
		return err
	}); err != nil {
		if isLeaseErr(err) {
			return err
		}
		return PolicyJobRetryLater(2*time.Minute, "Azure token: "+err.Error())
	}
	h := azureHandler{s: s, run: run, deps: deps, token: token, row: row}
	now := time.Now().UTC()
	switch row.State {
	case models.R2StateApproved:
		if !now.Before(row.ExpiresAt) {
			return h.finish(ctx, models.R2StateExpired, r2EndReasonNeverDeployed)
		}
		if row.StartsAt != nil && now.Before(*row.StartsAt) {
			return PolicyJobRetryLater(time.Until(*row.StartsAt), "starts at "+igagov.AWSTime(*row.StartsAt))
		}
		if err := h.move(ctx, models.R2StateApproved, models.R2StateDeploying, nil); err != nil {
			return err
		}
		h.row.State = models.R2StateDeploying
		return h.apply(ctx, false)
	case models.R2StateDeploying:
		return h.apply(ctx, false)
	case models.R2StateActive:
		if !now.Before(row.ExpiresAt) {
			if err := h.move(ctx, models.R2StateActive, models.R2StateExpiring, map[string]any{"end_reason": r2EndReasonExpired}); err != nil {
				return err
			}
			h.row.State, h.row.EndReason = models.R2StateExpiring, r2EndReasonExpired
			return h.remove(ctx)
		}
		return h.apply(ctx, true)
	case models.R2StateExpiring:
		return h.remove(ctx)
	}
	return nil
}

type azureHandler struct {
	s     *GovAccess
	run   *PolicyJobRun
	deps  *AzureAccessDeps
	token string
	row   models.IGAGovAzureAccess
}

func (h azureHandler) event(tx *gorm.DB, name string, payload map[string]any) error {
	pid, vid := h.row.PolicyID, h.row.VersionID
	payload["deployment_id"] = h.row.ID
	payload["principal_id"] = h.row.PrincipalID
	return appendGovEvent(tx, h.row.WorkspaceID, name, models.GovActorSystem, "policy-worker", govEventRefs{PolicyID: &pid, VersionID: &vid}, payload)
}

func (h azureHandler) move(ctx context.Context, from, to string, set map[string]any) error {
	if set == nil {
		set = map[string]any{}
	}
	set["state"], set["updated_at"] = to, time.Now().UTC()
	return h.run.InTx(ctx, func(tx *gorm.DB) error {
		res := tx.Model(&models.IGAGovAzureAccess{}).Where("workspace_id = ? AND id = ? AND state = ?", h.row.WorkspaceID, h.row.ID, from).Updates(set)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected != 1 {
			return PolicyJobRetryLater(time.Second, "the row's state moved; reloading")
		}
		return nil
	})
}

func (h azureHandler) external(ctx context.Context, fn func(ctx context.Context) error) error {
	return h.run.External(ctx, 0, fn)
}

func (h azureHandler) fail(ctx context.Context, reason string) error {
	err := h.run.InTx(ctx, func(tx *gorm.DB) error {
		if err := tx.Model(&models.IGAGovAzureAccess{}).Where("workspace_id = ? AND id = ? AND state = ?", h.row.WorkspaceID, h.row.ID, h.row.State).
			Updates(map[string]any{"state": models.R2StateFailed, "state_reason": reason, "ended_at": time.Now().UTC(), "updated_at": time.Now().UTC()}).Error; err != nil {
			return err
		}
		return h.event(tx, GovEventAccessFailed, map[string]any{"reason": reason})
	})
	return err
}

// azureLive reads the principal's assignments that grant the access on the
// target, split into revocable and inherited.
func (h azureHandler) live(ctx context.Context) (rev, inh []azure.RoleAssignment, err error) {
	var access []string
	_ = json.Unmarshal(h.row.Access, &access)
	segs := strings.Split(strings.TrimPrefix(h.row.Scope, "/"), "/")
	t := &azureTarget{Scope: strings.ToLower(h.row.Scope), SubscriptionID: h.row.SubscriptionID}
	if i := indexOf(segs, "providers"); i >= 0 && i+2 < len(segs) {
		tp := []string{segs[i+1], segs[i+2]}
		for j := i + 4; j < len(segs); j += 2 {
			tp = append(tp, segs[j])
		}
		t.TypePath = strings.ToLower(strings.Join(tp, "/"))
	}
	t.Storage = strings.HasPrefix(t.TypePath, "microsoft.storage/storageaccounts")
	acts, data := azureActions(t, access)
	err = h.external(ctx, func(ctx context.Context) error {
		defs, err := h.deps.RBAC.ListRoleDefinitions(ctx, h.token, h.row.SubscriptionID)
		if err != nil {
			return err
		}
		as, err := h.deps.RBAC.ListRoleAssignmentsForPrincipal(ctx, h.token, h.row.SubscriptionID, h.row.PrincipalID)
		if err != nil {
			return err
		}
		rev, inh = azureSplit(t, as, azureDefs(defs), acts, data)
		return nil
	})
	return rev, inh, err
}

func (h azureHandler) allowSpec() azure.RoleAssignmentSpec {
	return azure.RoleAssignmentSpec{Scope: h.row.Scope, Name: h.row.AssignmentName, RoleDefinitionID: h.row.RoleDefinitionID,
		PrincipalID: h.row.PrincipalID, PrincipalType: h.row.PrincipalType,
		Description: "AuthSec access policy " + h.row.PolicyID.String() + "; removed by AuthSec at " + igagov.AWSTime(h.row.ExpiresAt)}
}

// apply converges toward "in place": the allow's assignment exists; the
// block's assignments are gone. check: an active row's 10-minute check
// (re-applies drift).
func (h azureHandler) apply(ctx context.Context, check bool) error {
	now := time.Now().UTC()
	drift := ""
	var ops []map[string]any
	if h.row.Effect == "allow" {
		id := h.row.Scope + "/providers/Microsoft.Authorization/roleAssignments/" + h.row.AssignmentName
		var got *azure.RoleAssignment
		if err := h.external(ctx, func(ctx context.Context) error {
			var err error
			got, err = h.deps.RBAC.GetRoleAssignment(ctx, h.token, id)
			return err
		}); err != nil {
			return h.retry(err)
		}
		if got == nil {
			if check {
				drift = R2ReasonDeleted
			}
			if err := h.external(ctx, func(ctx context.Context) error {
				_, err := h.deps.RBAC.PutRoleAssignment(ctx, h.token, h.allowSpec())
				return err
			}); err != nil {
				return h.retry(err)
			}
			ops = append(ops, map[string]any{"op": "PutRoleAssignment", "id": id, "at": now})
		}
	} else {
		rev, inh, err := h.live(ctx)
		if err != nil {
			return h.retry(err)
		}
		if len(inh) > 0 && !check {
			return h.fail(ctx, GovCodeAzureInherited+": the principal gets this access from a broader scope")
		}
		if len(rev) > 0 {
			if check {
				drift = R2ReasonDetached
			}
			// Write-ahead: each assignment is recorded before it is deleted, so
			// the restore never loses one.
			var revoked []azure.RoleAssignmentSpec
			_ = json.Unmarshal(h.row.Revoked, &revoked)
			for _, a := range rev {
				revoked = append(revoked, azure.SpecOf(a))
			}
			raw, _ := json.Marshal(revoked)
			if err := h.run.InTx(ctx, func(tx *gorm.DB) error {
				return tx.Model(&models.IGAGovAzureAccess{}).Where("workspace_id = ? AND id = ?", h.row.WorkspaceID, h.row.ID).
					Updates(map[string]any{"revoked": raw, "updated_at": now}).Error
			}); err != nil {
				return err
			}
			h.row.Revoked = raw
			for _, a := range rev {
				a := a
				if err := h.external(ctx, func(ctx context.Context) error {
					return h.deps.RBAC.DeleteRoleAssignment(ctx, h.token, a.ID)
				}); err != nil {
					return h.retry(err)
				}
				ops = append(ops, map[string]any{"op": "DeleteRoleAssignment", "id": a.ID, "at": now})
			}
		}
	}
	opsRaw, _ := json.Marshal(ops)
	err := h.run.InTx(ctx, func(tx *gorm.DB) error {
		set := map[string]any{"verified_at": now, "last_readback_at": now, "drift": "", "state_reason": "", "updated_at": now}
		if len(ops) > 0 {
			set["ops"] = gorm.Expr("ops || ?::jsonb", string(opsRaw))
		}
		if !check {
			set["state"], set["deployed_at"] = models.R2StateActive, gorm.Expr("COALESCE(deployed_at, ?)", now)
		}
		res := tx.Model(&models.IGAGovAzureAccess{}).Where("workspace_id = ? AND id = ? AND state = ?", h.row.WorkspaceID, h.row.ID, h.row.State).Updates(set)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected != 1 {
			return PolicyJobRetryLater(time.Second, "the row's state moved; reloading")
		}
		if check && drift != "" {
			if err := h.event(tx, GovEventAccessDrifted, map[string]any{"classification": drift, "note": "AuthSec re-applies the policy."}); err != nil {
				return err
			}
			return h.event(tx, GovEventAccessReapplied, map[string]any{"was": drift, "ops": ops})
		}
		if !check {
			if err := h.event(tx, GovEventAccessConfirmed, map[string]any{"scope": h.row.Scope, "ops": ops}); err != nil {
				return err
			}
			return accessSupersedeTx(tx, h.row.WorkspaceID, h.row.PolicyID, h.row.VersionID)
		}
		return nil
	})
	if err != nil {
		return err
	}
	return PolicyJobRetryLater(r2Wait(h.row.ExpiresAt), "active; checked every 10 minutes")
}

// remove converges toward "gone": the allow's assignment deleted; the
// block's recorded assignments restored.
func (h azureHandler) remove(ctx context.Context) error {
	now := time.Now().UTC()
	var ops []map[string]any
	if h.row.Effect == "allow" {
		if h.row.AssignmentName != "" {
			id := h.row.Scope + "/providers/Microsoft.Authorization/roleAssignments/" + h.row.AssignmentName
			if err := h.external(ctx, func(ctx context.Context) error {
				return h.deps.RBAC.DeleteRoleAssignment(ctx, h.token, id)
			}); err != nil {
				return h.retry(err)
			}
			ops = append(ops, map[string]any{"op": "DeleteRoleAssignment", "id": id, "at": now})
		}
	} else {
		var revoked []azure.RoleAssignmentSpec
		_ = json.Unmarshal(h.row.Revoked, &revoked)
		for _, spec := range revoked {
			spec := spec
			if err := h.external(ctx, func(ctx context.Context) error {
				_, err := h.deps.RBAC.PutRoleAssignment(ctx, h.token, spec)
				return err
			}); err != nil {
				return h.retry(err)
			}
			ops = append(ops, map[string]any{"op": "PutRoleAssignment", "restored": spec.Scope + "/" + spec.Name, "at": now})
		}
	}
	h.row.Ops = mustOps(ops)
	return h.finish(ctx, grantFinal(h.row.EndReason), h.row.EndReason)
}

func mustOps(ops []map[string]any) json.RawMessage {
	raw, _ := json.Marshal(ops)
	return raw
}

func (h azureHandler) finish(ctx context.Context, final, endReason string) error {
	now := time.Now().UTC()
	return h.run.InTx(ctx, func(tx *gorm.DB) error {
		set := map[string]any{"state": final, "ended_at": now, "state_reason": "", "updated_at": now}
		if endReason != "" {
			set["end_reason"] = endReason
		}
		res := tx.Model(&models.IGAGovAzureAccess{}).Where("workspace_id = ? AND id = ? AND state = ?", h.row.WorkspaceID, h.row.ID, h.row.State).Updates(set)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected != 1 {
			return PolicyJobRetryLater(time.Second, "the row's state moved; reloading")
		}
		name := GovEventAccessRemoved
		if final == models.R2StateExpired {
			name = GovEventAccessExpired
		}
		return h.event(tx, name, map[string]any{"state": final, "end_reason": endReason, "ops": json.RawMessage(h.row.Ops)})
	})
}

// retry turns an Azure error into a retry (a lost lease is returned as is).
func (h azureHandler) retry(err error) error {
	if isLeaseErr(err) {
		return err
	}
	_ = h.run.InTx(context.Background(), func(tx *gorm.DB) error {
		return tx.Model(&models.IGAGovAzureAccess{}).Where("workspace_id = ? AND id = ?", h.row.WorkspaceID, h.row.ID).
			Updates(map[string]any{"state_reason": err.Error(), "updated_at": time.Now().UTC()}).Error
	})
	return PolicyJobRetryLater(time.Minute, "Azure: "+err.Error())
}

// RegisterAzureAccessJobs installs the azure_access handler and its
// 10-minute schedule of live rows.
func RegisterAzureAccessJobs(w *PolicyJobWorker, db *gorm.DB) {
	s := NewGovAccess(db)
	w.Register(PolicyJobKind{Kind: repositories.GovJobAzureAccess, Handler: s.AzureAccessHandler})
	w.Scheduler().Add(PolicyJobSchedule{Name: repositories.GovJobAzureAccess, Kind: repositories.GovJobAzureAccess, Every: azureCheckEvery,
		Due: func(ctx context.Context, db *gorm.DB, now time.Time) ([]ScheduledPolicyJob, error) {
			if !PolicyR2On() {
				return nil, nil
			}
			var rows []struct {
				WorkspaceID uuid.UUID
				ID          uuid.UUID
			}
			// TENANT-EXEMPT: the schedule's scan of live Azure rows across
			// workspaces; each job then runs in its row's own workspace.
			if err := db.Table("iga_gov_azure_access").Select("workspace_id, id").
				Where("state IN ?", []string{models.R2StateApproved, models.R2StateDeploying, models.R2StateActive, models.R2StateExpiring}).
				Scan(&rows).Error; err != nil {
				return nil, err
			}
			out := make([]ScheduledPolicyJob, 0, len(rows))
			for _, r := range rows {
				id := r.ID
				out = append(out, ScheduledPolicyJob{WorkspaceID: r.WorkspaceID, SubjectID: &id, DedupeKey: "azure_access:" + id.String()})
			}
			return out, nil
		}})
}
