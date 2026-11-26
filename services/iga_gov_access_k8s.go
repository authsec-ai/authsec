package services

// Access policies on Kubernetes (146; block only in this release). A block
// names a Role or ClusterRole (the resource) and ServiceAccounts (the roles):
// for each ServiceAccount AuthSec takes it out of every binding of that role
// through the in-cluster agent (instruction remove_binding_subject), records
// the binding's uid, and at the end puts it back into that same object
// (restore_binding_subject). One deployment row per (ServiceAccount, binding),
// run by the k8s_access job.
//
// Kubernetes cannot take away part of a binding, so the only access level is
// "all". An allow would create RoleBindings, which needs the agent to hold
// `bind` on every role customers want to grant; it is not offered yet.
//
// A subject put back into a binding outside AuthSec is drift: the next RBAC
// sweep that shows it again (well after the removal) makes the job remove it
// again, as AWS and Azure re-apply.

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
	"gorm.io/gorm/clause"

	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/internal/k8sgraph"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
)

// Kubernetes access-policy names.
const (
	accessTypeK8sRole = "k8s_role"
	// GovCodeK8sAgentCannotAct: the cluster's agent may not change bindings.
	GovCodeK8sAgentCannotAct = "k8s_agent_cannot_act"
	// GovCodeK8sNoBinding: the ServiceAccount holds no binding of the role.
	GovCodeK8sNoBinding = "k8s_no_binding"
	// GovCodeK8sPolicyConflict: another live block already holds this subject.
	GovCodeK8sPolicyConflict = "k8s_policy_conflict"

	k8sCheckEvery = 10 * time.Minute
	// k8sDriftMargin: a sweep observed this long after the removal still
	// listing the subject means it was put back (a sweep that started before
	// the removal may still list it).
	k8sDriftMargin = 15 * time.Minute
	k8sPoll        = 30 * time.Second
	k8sStale       = 30 * time.Minute
)

// k8sPlan is the Kubernetes part of an access plan.
type k8sPlan struct {
	role     k8sgraph.ObjectKey
	roleName string // as the console shows it: name, or namespace/name
	subjects []k8sSubjectPlan
}

type k8sSubjectPlan struct {
	identity uuid.UUID
	name     string
	sa       k8sgraph.ObjectKey
	bindings []k8sBindingPlan
}

type k8sBindingPlan struct {
	key       k8sgraph.ObjectKey // rolebinding / clusterrolebinding
	connector uuid.UUID
}

/* ------------------------------------------------------------------------- */
/*                                   Schema                                  */
/* ------------------------------------------------------------------------- */

// VerifyK8sAccessSchema checks 146: the table, and the job and instruction
// kinds the work needs.
func VerifyK8sAccessSchema(db *gorm.DB) error {
	ok, err := repositories.HasRelation(db, "iga_gov_k8s_access")
	if err != nil {
		return fmt.Errorf("Kubernetes access-policy schema verification could not run: %w", err)
	}
	if !ok {
		return fmt.Errorf("Kubernetes access policies need migration 146; missing: iga_gov_k8s_access")
	}
	for _, c := range []struct{ table, name, want string }{
		{"iga_gov_job", "iga_gov_job_kind_check", repositories.GovJobK8sAccess},
		{"provisioning_instructions", "provisioning_instructions_kind_chk", models.InstructionRestoreBindingSubject},
	} {
		ok, err := repositories.ConstraintAdmits(db, c.table, c.name, c.want)
		if err != nil {
			return fmt.Errorf("Kubernetes access-policy schema verification could not run: %w", err)
		}
		if !ok {
			return fmt.Errorf("Kubernetes access policies need migration 146; missing: constraint %s.%s admitting %s", c.table, c.name, c.want)
		}
	}
	return nil
}

var k8sSchema struct {
	sync.Mutex
	ok     bool
	reason string
	at     time.Time
}

// K8sAccessSchemaStatus is VerifyK8sAccessSchema, re-checked at most once a
// minute until it passes.
func K8sAccessSchemaStatus(db *gorm.DB) (bool, string) {
	k8sSchema.Lock()
	defer k8sSchema.Unlock()
	if k8sSchema.ok || time.Since(k8sSchema.at) < time.Minute && !k8sSchema.at.IsZero() {
		return k8sSchema.ok, k8sSchema.reason
	}
	err := VerifyK8sAccessSchema(db)
	k8sSchema.ok, k8sSchema.at, k8sSchema.reason = err == nil, time.Now(), ""
	if err != nil {
		k8sSchema.reason = err.Error()
	}
	return k8sSchema.ok, k8sSchema.reason
}

/* ------------------------------------------------------------------------- */
/*                                    Plan                                   */
/* ------------------------------------------------------------------------- */

// accessK8sRoleRows reads the Kubernetes Roles and ClusterRoles among ids as
// resource rows (an access policy may name one by its graph id).
func accessK8sRoleRows(db *gorm.DB, ws uuid.UUID, ids []string) ([]models.IGAResource, error) {
	var valid []uuid.UUID
	for _, id := range ids {
		if u, err := uuid.Parse(id); err == nil {
			valid = append(valid, u)
		}
	}
	if len(valid) == 0 {
		return nil, nil
	}
	var pols []models.IGAPolicy
	if err := db.Where("workspace_id = ? AND id IN ? AND provider = ? AND policy_kind IN ?", ws, valid, models.ProviderK8s,
		[]string{models.K8sPolicyKindRole, models.K8sPolicyKindClusterRole}).Find(&pols).Error; err != nil {
		return nil, err
	}
	out := make([]models.IGAResource, 0, len(pols))
	for _, p := range pols {
		out = append(out, models.IGAResource{ID: p.ID, WorkspaceID: p.WorkspaceID, ResourceKind: p.PolicyKind, DisplayName: p.DisplayName,
			Provider: models.ProviderK8s, SourceKey: p.SourceKey})
	}
	return out, nil
}

// k8sRoleLabel is a role as the console names it.
func k8sRoleLabel(k k8sgraph.ObjectKey) string {
	if k.Namespace == "" {
		return k.Name
	}
	return k.Namespace + "/" + k.Name
}

// bindingOfAssignment reads the binding half of an assignment's source key
// (BindingKey ␟ SubjectKey).
func bindingOfAssignment(sourceKey string) (k8sgraph.ObjectKey, bool) {
	parts := strings.Split(sourceKey, k8sgraph.Sep)
	n := 0
	switch {
	case len(parts) >= 4 && parts[2] == "clusterrolebinding":
		n = 4
	case len(parts) >= 5 && parts[2] == "rolebinding":
		n = 5
	default:
		return k8sgraph.ObjectKey{}, false
	}
	return k8sgraph.ParseKey(strings.Join(parts[:n], k8sgraph.Sep))
}

// planK8s resolves a Kubernetes block: every binding of the role that names
// each ServiceAccount.
func (s *GovAccess) planK8s(ctx context.Context, ws uuid.UUID, p *accessPlan, row models.IGAResource) error {
	// TENANT-EXEMPT: the 146 schema check reads the Postgres catalog only.
	if ok, reason := K8sAccessSchemaStatus(s.db); !ok {
		return govErr(http.StatusServiceUnavailable, GovCodeAccessUnavailable, "Kubernetes access policies are not available on this server.",
			map[string]any{"reason": reason})
	}
	if p.intent.Effect != igagov.AccessEffectBlock {
		return govUnprocessable(GovCodeAccessInvalid, "Kubernetes roles can only be blocked in this release.", map[string]any{"field": "effect"})
	}
	if len(p.intent.Access) != 1 || p.intent.Access[0] != igagov.AccessAll {
		return govUnprocessable(GovCodeAccessInvalid, "Kubernetes cannot take away part of a binding: choose all access.", map[string]any{"field": "access"})
	}
	if p.intent.Resource.Prefix != "" {
		return govUnprocessable(GovCodeAccessInvalid, "A prefix applies to S3 buckets only.", map[string]any{"field": "resource.prefix"})
	}
	role, ok := k8sgraph.ParseKey(row.SourceKey)
	if !ok || (role.Type != "role" && role.Type != "clusterrole") {
		return govUnprocessable(GovCodeResourceNotSupported, "This Kubernetes object cannot be targeted.", map[string]any{"field": "resource.resource_id"})
	}
	kp := &k8sPlan{role: role, roleName: k8sRoleLabel(role)}
	if err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		for i, r := range p.intent.Roles {
			field := fmt.Sprintf("roles[%d].identity_account_id", i)
			var ids []models.IGAIdentityAccount
			if err := tx.Where("workspace_id = ? AND id = ?", ws, r.IdentityAccountID).Limit(1).Find(&ids).Error; err != nil {
				return err
			}
			if len(ids) == 0 {
				return govErr(http.StatusNotFound, "not_found", "Not found.", map[string]any{"field": field})
			}
			sa, ok := k8sgraph.ParseKey(ids[0].SourceKey)
			if ids[0].AccountKind != models.K8sAccountKindServiceAccount || !ok || sa.Type != "serviceaccount" {
				return govUnprocessable(GovCodeRoleIneligible, "Only Kubernetes ServiceAccounts can be targeted on a Kubernetes role.",
					map[string]any{"field": field, "account_kind": ids[0].AccountKind})
			}
			if sa.Cluster != role.Cluster {
				return govUnprocessable(GovCodeRoleNotInAccount, "The ServiceAccount is in another cluster than the role.", map[string]any{"field": field})
			}
			// The source of a binding is the agent whose sweep last confirmed
			// it (discovery_source_id): the one that acts on it.
			var as []struct {
				SourceKey         string
				DiscoverySourceID *uuid.UUID
			}
			if err := tx.Table("iga_policy_assignment").Select("source_key, discovery_source_id").
				Where("workspace_id = ? AND policy_id = ? AND holder_identity_account_id = ? AND state <> ? AND assignment_kind IN ?",
					ws, row.ID, ids[0].ID, "ended", []string{models.K8sAssignmentRoleBinding, models.K8sAssignmentClusterRoleBinding}).
				Order("source_key").Scan(&as).Error; err != nil {
				return err
			}
			sp := k8sSubjectPlan{identity: ids[0].ID, name: ids[0].DisplayName, sa: sa}
			for _, a := range as {
				b, ok := bindingOfAssignment(a.SourceKey)
				if !ok || a.DiscoverySourceID == nil {
					continue
				}
				sp.bindings = append(sp.bindings, k8sBindingPlan{key: b, connector: *a.DiscoverySourceID})
			}
			if len(sp.bindings) == 0 {
				return govUnprocessable(GovCodeK8sNoBinding, ids[0].DisplayName+" holds no binding of "+kp.roleName+" that AuthSec has seen.",
					map[string]any{"field": field})
			}
			kp.subjects = append(kp.subjects, sp)
		}
		return nil
	}); err != nil {
		return err
	}
	p.k8s = kp
	p.resource = AccessResourceView{ResourceID: p.intent.Resource.ResourceID, ARN: row.SourceKey, Name: kp.roleName, AccountID: role.Cluster,
		ResourceType: accessTypeK8sRole, Provider: models.ProviderK8s, Kind: row.ResourceKind}
	doc, _ := json.Marshal(k8sDocument(kp))
	p.doc, p.docHash = doc, igagov.ContentHash(doc)
	p.warnings = append(p.warnings,
		AccessIssue{Code: "k8s_whole_binding", Message: "Each ServiceAccount is taken out of every binding of this role that names it, and put back at the end."},
		AccessIssue{Code: "k8s_other_paths", Message: "Access the ServiceAccount gets from other roles, or through a group such as system:serviceaccounts, is not changed."},
		AccessIssue{Code: "k8s_gitops", Message: "If a GitOps tool (Argo CD, Flux) manages a binding, it may put the ServiceAccount back; AuthSec then removes it again at its next check."})
	for _, sp := range kp.subjects {
		for _, b := range sp.bindings {
			if b.key.Type == "clusterrolebinding" {
				p.warnings = append(p.warnings, AccessIssue{Code: "k8s_cluster_binding",
					Message: sp.name + " is removed from ClusterRoleBinding " + b.key.Name + ", which grants the role in every namespace."})
			}
		}
	}
	return nil
}

// k8sDocument is the preview's document: what the agent will change.
func k8sDocument(kp *k8sPlan) map[string]any {
	var remove []map[string]any
	for _, sp := range kp.subjects {
		for _, b := range sp.bindings {
			remove = append(remove, map[string]any{"binding_kind": k8sBindingKind(b.key), "namespace": b.key.Namespace, "name": b.key.Name,
				"subject": map[string]any{"kind": models.K8sSubjectServiceAccount, "namespace": sp.sa.Namespace, "name": sp.sa.Name}})
		}
	}
	return map[string]any{"provider": models.ProviderK8s, "cluster": kp.role.Cluster, "role": kp.roleName, "remove_subjects": remove}
}

func k8sBindingKind(k k8sgraph.ObjectKey) string {
	if k.Type == "clusterrolebinding" {
		return models.K8sKindClusterRoleBinding
	}
	return models.K8sKindRoleBinding
}

func k8sRoleKind(k k8sgraph.ObjectKey) string {
	if k.Type == "clusterrole" {
		return models.K8sKindClusterRole
	}
	return models.K8sKindRole
}

// k8sAgentLimits is what a cluster's agent says it may do to bindings. The
// agent reports enforcement_bindings on its plan poll; iga-agent 0.6.1+ also
// reports, on its heartbeat, the roles, namespaces and ClusterRoleBinding switch
// its chart allows. Nil means not reported (an older agent): only the switch
// is checked, and the agent itself refuses what it may not do.
type k8sAgentLimits struct {
	canAct     bool
	allRoles   bool
	roles      []string
	namespaces []string
	cluster    *bool
}

func k8sAgentLimitsOf(src []models.DiscoverySource) *k8sAgentLimits {
	if len(src) == 0 {
		return &k8sAgentLimits{}
	}
	lim := &k8sAgentLimits{canAct: src[0].ActuationTokenHash != "" && src[0].EnforcementBindings}
	var rt struct {
		Roles      []string `json:"binding_roles"`
		Namespaces []string `json:"binding_namespaces"`
		Cluster    *bool    `json:"cluster_bindings"`
	}
	if json.Unmarshal(src[0].Runtime, &rt) == nil {
		lim.roles, lim.namespaces, lim.cluster = rt.Roles, rt.Namespaces, rt.Cluster
	}
	if containsString(lim.roles, "*") {
		// Every role (iga-agent 0.6.2+), ClusterRoleBindings included; the
		// agent itself refuses system: roles and the cluster's own namespaces.
		lim.allRoles, lim.roles = true, nil
	}
	return lim
}

// k8sChecks is checks() for Kubernetes: the agent of every binding may change
// bindings, and no other live block already holds the subject.
func (s *GovAccess) k8sChecks(ctx context.Context, ws uuid.UUID, p *accessPlan) []error {
	var errs []error
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		agents := map[uuid.UUID]*k8sAgentLimits{}
		refused := map[string]bool{}
		refuse := func(msg string, details map[string]any) {
			if !refused[msg] {
				refused[msg] = true
				errs = append(errs, govUnprocessable(GovCodeK8sAgentCannotAct, msg, details))
			}
		}
		for _, sp := range p.k8s.subjects {
			for _, b := range sp.bindings {
				lim, ok := agents[b.connector]
				if !ok {
					var src []models.DiscoverySource
					if err := tx.Where("workspace_id = ? AND id = ?", ws, b.connector).Limit(1).Find(&src).Error; err != nil {
						return err
					}
					lim = k8sAgentLimitsOf(src)
					agents[b.connector] = lim
				}
				switch {
				case !lim.canAct:
					refuse("The agent in cluster "+p.k8s.role.Cluster+" may not change bindings: turn enforcement on for it (Connections > the cluster > Enforcement), and turn on enforcement.bindings in its chart with "+p.k8s.role.Name+" in enforcement.bindings.roles.",
						map[string]any{"field": "resource.resource_id", "connector_id": b.connector})
				case strings.HasPrefix(p.k8s.role.Name, "system:"):
					refuse("AuthSec never changes bindings of the cluster's own system: roles.",
						map[string]any{"field": "resource.resource_id", "role": p.k8s.role.Name})
				case lim.roles != nil && !containsString(lim.roles, p.k8s.role.Name):
					refuse("The agent in cluster "+p.k8s.role.Cluster+" may not change bindings of "+p.k8s.role.Name+" yet: add it to enforcement.bindings.roles in its chart.",
						map[string]any{"field": "resource.resource_id", "connector_id": b.connector, "role": p.k8s.role.Name, "allowed_roles": lim.roles})
				case k8sBindingKind(b.key) == models.K8sKindClusterRoleBinding && lim.cluster != nil && !*lim.cluster && !lim.allRoles:
					refuse("The agent in cluster "+p.k8s.role.Cluster+" may not change ClusterRoleBindings: turn on enforcement.bindings.clusterWide in its chart.",
						map[string]any{"field": "resource.resource_id", "connector_id": b.connector, "role": p.k8s.role.Name})
				case k8sBindingKind(b.key) == models.K8sKindRoleBinding && len(lim.namespaces) > 0 && !containsString(lim.namespaces, b.key.Namespace) && (lim.cluster == nil || !*lim.cluster):
					refuse("The agent in cluster "+p.k8s.role.Cluster+" may not change RoleBindings in "+b.key.Namespace+": add it to enforcement.bindings.namespaces in its chart, or clear that list for every namespace.",
						map[string]any{"field": "resource.resource_id", "connector_id": b.connector, "namespace": b.key.Namespace})
				}
				q := tx.Model(&models.IGAGovK8sAccess{}).Where("workspace_id = ? AND identity_account_id = ? AND cluster = ? AND binding_kind = ? AND binding_namespace = ? AND binding_name = ? AND state IN ?",
					ws, sp.identity, b.key.Cluster, k8sBindingKind(b.key), b.key.Namespace, b.key.Name, k8sLiveStates)
				if p.self != nil {
					q = q.Where("policy_id <> ?", *p.self)
				}
				var n int64
				if err := q.Count(&n).Error; err != nil {
					return err
				}
				if n > 0 {
					errs = append(errs, govUnprocessable(GovCodeK8sPolicyConflict,
						"Another access policy already holds "+sp.name+" out of "+b.key.Name+". End it first.", map[string]any{"field": "roles"}))
				}
			}
		}
		return nil
	})
	if err != nil {
		return []error{err}
	}
	return errs
}

var k8sLiveStates = []string{models.R2StateApproved, models.R2StateDeploying, models.R2StateActive, models.R2StateExpiring}

// K8sAccessLiveOnSource counts the access-policy deployments still live on a
// cluster's agent: a deployment it has yet to apply, or a removal it must
// still put back. 0 when access policies on Kubernetes are not installed.
func K8sAccessLiveOnSource(db *gorm.DB, ws, source uuid.UUID) (int64, error) {
	if ok, _ := K8sAccessSchemaStatus(db); !ok { // TENANT-EXEMPT: Postgres catalog check, no tenant rows
		return 0, nil
	}
	var n int64
	err := tenancy.InWorkspaceRead(context.Background(), db, ws, func(tx *gorm.DB) error {
		return tx.Model(&models.IGAGovK8sAccess{}).
			Where("workspace_id = ? AND connector_id = ? AND state IN ?", ws, source, k8sLiveStates).Count(&n).Error
	})
	return n, err
}

// k8sSentence is the preview's sentence.
func k8sSentence(in igagov.AccessIntent, kp *k8sPlan, names []string) string {
	out := "Block all access on Kubernetes " + k8sRoleKind(kp.role) + " " + kp.roleName + " (cluster " + kp.role.Cluster + ") for " + strings.Join(names, ", ")
	if in.StartsAt != nil {
		out += " from " + igagov.AWSTime(*in.StartsAt)
	}
	if in.EndsAt != nil {
		return out + " until " + igagov.AWSTime(*in.EndsAt) + "."
	}
	return out + ", with no end date."
}

/* ------------------------------------------------------------------------- */
/*                               Deployment rows                              */
/* ------------------------------------------------------------------------- */

// deployK8sTx writes one approved row per (ServiceAccount, binding) and
// queues its job.
func (s *GovAccess) deployK8sTx(tx *gorm.DB, ws, actor, policyID uuid.UUID, v *models.IGAGovAccessPolicyVersion, p *accessPlan, now time.Time) error {
	exp := igagov.AccessNoEnd
	if p.intent.EndsAt != nil {
		exp = *p.intent.EndsAt
	}
	access, _ := json.Marshal(p.intent.Access)
	for _, sp := range p.k8s.subjects {
		subject, _ := json.Marshal(map[string]string{"kind": models.K8sSubjectServiceAccount, "namespace": sp.sa.Namespace, "name": sp.sa.Name})
		for _, b := range sp.bindings {
			row := models.IGAGovK8sAccess{ID: uuid.New(), WorkspaceID: ws, PolicyID: policyID, VersionID: v.ID, ConnectorID: b.connector,
				IdentityAccountID: sp.identity, Cluster: b.key.Cluster, BindingKind: k8sBindingKind(b.key), BindingNamespace: b.key.Namespace,
				BindingName: b.key.Name, RoleKind: k8sRoleKind(p.k8s.role), RoleName: p.k8s.role.Name, Subject: subject, Effect: "deny",
				Access: access, Removed: json.RawMessage(`{}`), State: models.R2StateApproved, StartsAt: p.intent.StartsAt, ExpiresAt: exp,
				CreatedBy: actor, Ops: json.RawMessage(`[]`), CreatedAt: now, UpdatedAt: now}
			if err := tx.Create(&row).Error; err != nil {
				return err
			}
			if err := k8sEnqueueTx(tx, ws, row.ID, now); err != nil {
				return err
			}
		}
	}
	return nil
}

// k8sEnqueueTx asks for the row's job now.
func k8sEnqueueTx(tx *gorm.DB, ws, id uuid.UUID, at time.Time) error {
	sub := id
	key := "k8s_access:" + id.String()
	created, err := repositories.NewIGAGovJobRepository(tx).EnqueueTx(tx, &models.IGAGovJob{WorkspaceID: ws, Kind: repositories.GovJobK8sAccess,
		SubjectID: &sub, DedupeKey: key, RunAfter: at})
	if err != nil || created {
		return err
	}
	return tx.Model(&models.IGAGovJob{}).
		Where("workspace_id = ? AND kind = ? AND dedupe_key = ? AND status = ? AND run_after > ?", ws, repositories.GovJobK8sAccess, key, "queued", at).
		Update("run_after", at).Error
}

// endK8sRowsTx ends the policy's live Kubernetes rows (all versions, or all
// but keep): a row never applied ends at once, any other restores first.
func endK8sRowsTx(tx *gorm.DB, ws, policyID uuid.UUID, keep *uuid.UUID, reason string, now time.Time) (int, error) {
	if ok, _ := K8sAccessSchemaStatus(tx); !ok {
		return 0, nil
	}
	q := tx.Where("workspace_id = ? AND policy_id = ? AND state IN ?", ws, policyID, k8sLiveStates)
	if keep != nil {
		q = q.Where("version_id <> ?", *keep)
	}
	var rows []models.IGAGovK8sAccess
	if err := q.Clauses(lockForUpdate()).Find(&rows).Error; err != nil {
		return 0, err
	}
	n := 0
	for _, r := range rows {
		set := map[string]any{"end_reason": reason, "updated_at": now}
		switch {
		case r.State == models.R2StateApproved:
			set["state"], set["ended_at"] = models.R2StateRevoked, now
		case r.State == models.R2StateExpiring:
			continue
		default:
			set["state"] = models.R2StateExpiring
		}
		if err := tx.Model(&models.IGAGovK8sAccess{}).Where("workspace_id = ? AND id = ? AND state = ?", ws, r.ID, r.State).
			Updates(set).Error; err != nil {
			return n, err
		}
		if set["state"] == models.R2StateExpiring {
			if err := k8sEnqueueTx(tx, ws, r.ID, now); err != nil {
				return n, err
			}
		}
		n++
	}
	return n, nil
}

// k8sLiveCount counts the policy's Kubernetes rows still acting.
func k8sLiveCount(tx *gorm.DB, ws, policyID uuid.UUID) (int64, error) {
	if ok, _ := K8sAccessSchemaStatus(tx); !ok {
		return 0, nil
	}
	var n int64
	err := tx.Model(&models.IGAGovK8sAccess{}).Where("workspace_id = ? AND policy_id = ? AND state IN ?", ws, policyID, k8sLiveStates).Count(&n).Error
	return n, err
}

// k8sBindingRef is a binding as a deployment names it.
func k8sBindingRef(a models.IGAGovK8sAccess) string {
	if a.BindingNamespace == "" {
		return "k8s:" + a.Cluster + "/clusterrolebinding/" + a.BindingName
	}
	return "k8s:" + a.Cluster + "/rolebinding/" + a.BindingNamespace + "/" + a.BindingName
}

// k8sSubjectName is the ServiceAccount's namespace/name.
func k8sSubjectName(a models.IGAGovK8sAccess) string {
	var s struct{ Namespace, Name string }
	_ = json.Unmarshal(a.Subject, &s)
	return s.Namespace + "/" + s.Name
}

// k8sAsGrant presents a Kubernetes row in the shape the status and views read.
func k8sAsGrant(a models.IGAGovK8sAccess) models.IGAGovTempGrant {
	pid, vid := a.PolicyID, a.VersionID
	return models.IGAGovTempGrant{ID: a.ID, WorkspaceID: a.WorkspaceID, ConnectorID: a.ConnectorID, IdentityAccountID: a.IdentityAccountID,
		AccountID: a.Cluster, RoleID: k8sSubjectName(a), RoleARN: "k8s:" + k8sSubjectName(a), PolicyARN: k8sBindingRef(a),
		State: a.State, StateReason: a.StateReason, EndReason: a.EndReason, Drift: a.Drift, ExpiresAt: a.ExpiresAt,
		StartsAt: a.StartsAt, DeployedAt: a.DeployedAt, VerifiedAt: a.VerifiedAt, LastReadbackAt: a.LastReadbackAt, EndedAt: a.EndedAt,
		CreatedAt: a.CreatedAt, UpdatedAt: a.UpdatedAt, Effect: a.Effect, PolicyID: &pid, VersionID: &vid,
		DocumentHash: "k8s:" + a.ID.String()}
}

// k8sRowDocument is the detail's document of a Kubernetes row.
func k8sRowDocument(a models.IGAGovK8sAccess) json.RawMessage {
	raw, _ := json.Marshal(map[string]any{"provider": models.ProviderK8s, "cluster": a.Cluster,
		"remove_subject": map[string]any{"binding_kind": a.BindingKind, "namespace": a.BindingNamespace, "name": a.BindingName,
			"subject": json.RawMessage(a.Subject)}, "removed": json.RawMessage(a.Removed)})
	return raw
}

/* ------------------------------------------------------------------------- */
/*                                   The job                                  */
/* ------------------------------------------------------------------------- */

// k8sRemoved is what the agent reported taking out.
type k8sRemoved struct {
	BindingUID string `json:"binding_uid"`
	// Removed is false when the subject was already absent.
	Removed bool `json:"removed"`
}

// K8sAccessHandler is the k8s_access job (subject: the row).
func (s *GovAccess) K8sAccessHandler(ctx context.Context, run *PolicyJobRun) error {
	if run.Job.SubjectID == nil {
		return PolicyJobAbandon("k8s_access needs a row subject")
	}
	ws := run.Job.WorkspaceID
	var row models.IGAGovK8sAccess
	if err := run.ReadTx(ctx, func(tx *gorm.DB) error {
		return tx.Where("workspace_id = ? AND id = ?", ws, *run.Job.SubjectID).Take(&row).Error
	}); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return PolicyJobAbandon("row not found")
		}
		return err
	}
	h := k8sHandler{run: run, row: row}
	now := time.Now().UTC()
	switch row.State {
	case models.R2StateApproved:
		if !now.Before(row.ExpiresAt) {
			return h.finish(ctx, models.R2StateExpired, r2EndReasonNeverDeployed, "")
		}
		if row.StartsAt != nil && now.Before(*row.StartsAt) {
			return PolicyJobRetryLater(time.Until(*row.StartsAt), "starts at "+igagov.AWSTime(*row.StartsAt))
		}
		return h.instruct(ctx, models.R2StateApproved, models.R2StateDeploying, models.InstructionRemoveBindingSubject, nil)
	case models.R2StateDeploying:
		return h.deploying(ctx)
	case models.R2StateActive:
		if !now.Before(row.ExpiresAt) {
			return h.startRestore(ctx, models.R2StateActive, r2EndReasonExpired)
		}
		return h.active(ctx)
	case models.R2StateExpiring:
		return h.expiring(ctx)
	}
	return nil
}

type k8sHandler struct {
	run *PolicyJobRun
	row models.IGAGovK8sAccess
}

func (h k8sHandler) event(tx *gorm.DB, name string, payload map[string]any) error {
	pid, vid := h.row.PolicyID, h.row.VersionID
	payload["deployment_id"] = h.row.ID
	payload["binding"] = k8sBindingRef(h.row)
	payload["subject"] = k8sSubjectName(h.row)
	return appendGovEvent(tx, h.row.WorkspaceID, name, models.GovActorSystem, "policy-worker", govEventRefs{PolicyID: &pid, VersionID: &vid}, payload)
}

// payload is the instruction's payload for the row.
func (h k8sHandler) payload(kind string) map[string]any {
	var subject map[string]any
	_ = json.Unmarshal(h.row.Subject, &subject)
	out := map[string]any{"binding_kind": h.row.BindingKind, "namespace": h.row.BindingNamespace, "name": h.row.BindingName,
		"role_kind": h.row.RoleKind, "role_name": h.row.RoleName, "subject": subject, "deployment_id": h.row.ID.String(),
		"policy_id": h.row.PolicyID.String(), "reason": "AuthSec access policy " + h.row.PolicyID.String()}
	if kind == models.InstructionRestoreBindingSubject {
		var rm k8sRemoved
		_ = json.Unmarshal(h.row.Removed, &rm)
		out["binding_uid"] = rm.BindingUID
	}
	return out
}

// instruct queues an instruction for the row and records it, moving the row
// from -> to (equal for a re-issue) in the same transaction.
func (h k8sHandler) instruct(ctx context.Context, from, to, kind string, set map[string]any) error {
	if set == nil {
		set = map[string]any{}
	}
	err := h.run.InTx(ctx, func(tx *gorm.DB) error {
		var ops []map[string]any
		_ = json.Unmarshal(h.row.Ops, &ops)
		raw, _ := json.Marshal(h.payload(kind))
		key := fmt.Sprintf("k8s_access:%s:%s:%d", h.row.ID, kind, len(ops))
		inst := models.ProvisioningInstruction{ID: uuid.New(), WorkspaceID: h.row.WorkspaceID, DiscoverySourceID: h.row.ConnectorID, Kind: kind,
			Payload: raw, Fingerprint: h.row.ID.String(), IdempotencyKey: key, Status: models.InstructionPending, CreatedBy: "policy-worker"}
		res := tx.Clauses(clause.OnConflict{
			Columns:     []clause.Column{{Name: "discovery_source_id"}, {Name: "idempotency_key"}},
			TargetWhere: clause.Where{Exprs: []clause.Expression{gorm.Expr("status IN ('pending','leased')")}},
			DoNothing:   true,
		}).Create(&inst)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			if err := tx.Where("workspace_id = ? AND discovery_source_id = ? AND idempotency_key = ? AND status IN ?", h.row.WorkspaceID,
				h.row.ConnectorID, key, []string{models.InstructionPending, models.InstructionLeased}).Take(&inst).Error; err != nil {
				return err
			}
		}
		ops = append(ops, map[string]any{"op": kind, "instruction_id": inst.ID, "at": time.Now().UTC()})
		set["ops"], set["instruction_id"], set["state"], set["updated_at"] = mustOps(ops), inst.ID, to, time.Now().UTC()
		upd := tx.Model(&models.IGAGovK8sAccess{}).Where("workspace_id = ? AND id = ? AND state = ?", h.row.WorkspaceID, h.row.ID, from).Updates(set)
		if upd.Error != nil {
			return upd.Error
		}
		if upd.RowsAffected != 1 {
			return PolicyJobRetryLater(time.Second, "the row's state moved; reloading")
		}
		return nil
	})
	if err != nil {
		return err
	}
	return PolicyJobRetryLater(k8sPoll, "waiting for the cluster agent")
}

// instruction reads the row's current instruction.
func (h k8sHandler) instruction(ctx context.Context) (*models.ProvisioningInstruction, error) {
	if h.row.InstructionID == nil {
		return nil, nil
	}
	var inst []models.ProvisioningInstruction
	if err := h.run.ReadTx(ctx, func(tx *gorm.DB) error {
		return tx.Where("workspace_id = ? AND id = ?", h.row.WorkspaceID, *h.row.InstructionID).Limit(1).Find(&inst).Error
	}); err != nil || len(inst) == 0 {
		return nil, err
	}
	return &inst[0], nil
}

// waiting notes an instruction the agent has not finished and polls again.
func (h k8sHandler) waiting(ctx context.Context, inst *models.ProvisioningInstruction) error {
	if time.Since(inst.CreatedAt) > k8sStale {
		reason := "waiting for the agent in cluster " + h.row.Cluster + " to pick up the change since " + igagov.AWSTime(inst.CreatedAt)
		if err := h.run.InTx(ctx, func(tx *gorm.DB) error {
			return tx.Model(&models.IGAGovK8sAccess{}).Where("workspace_id = ? AND id = ?", h.row.WorkspaceID, h.row.ID).
				Updates(map[string]any{"state_reason": reason, "updated_at": time.Now().UTC()}).Error
		}); err != nil {
			return err
		}
	}
	return PolicyJobRetryLater(k8sPoll, "waiting for the cluster agent")
}

func (h k8sHandler) deploying(ctx context.Context) error {
	inst, err := h.instruction(ctx)
	if err != nil {
		return err
	}
	if inst == nil || inst.Status == models.InstructionSuperseded {
		return h.instruct(ctx, models.R2StateDeploying, models.R2StateDeploying, models.InstructionRemoveBindingSubject, nil)
	}
	switch inst.Status {
	case models.InstructionPending, models.InstructionLeased:
		return h.waiting(ctx, inst)
	case models.InstructionFailed:
		return h.finish(ctx, models.R2StateFailed, r2EndReasonFailed, "the cluster agent could not remove the subject: "+inst.Error)
	}
	var rm k8sRemoved
	_ = json.Unmarshal(inst.Result, &rm)
	raw, _ := json.Marshal(rm)
	now := time.Now().UTC()
	return h.run.InTx(ctx, func(tx *gorm.DB) error {
		res := tx.Model(&models.IGAGovK8sAccess{}).Where("workspace_id = ? AND id = ? AND state = ?", h.row.WorkspaceID, h.row.ID, models.R2StateDeploying).
			Updates(map[string]any{"state": models.R2StateActive, "removed": raw, "deployed_at": now, "verified_at": now, "last_readback_at": now,
				"state_reason": "", "drift": "", "updated_at": now})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected != 1 {
			return PolicyJobRetryLater(time.Second, "the row's state moved; reloading")
		}
		if err := h.event(tx, GovEventAccessConfirmed, map[string]any{"removed": rm.Removed, "binding_uid": rm.BindingUID}); err != nil {
			return err
		}
		return k8sSupersedeTx(tx, h.row.WorkspaceID, h.row.PolicyID, h.row.VersionID)
	})
}

// active settles a re-removal in flight, then looks for the subject back in
// the binding (the RBAC sweeps are the readback).
func (h k8sHandler) active(ctx context.Context) error {
	if inst, err := h.instruction(ctx); err != nil {
		return err
	} else if inst != nil && inst.Kind == models.InstructionRemoveBindingSubject && h.row.Drift != "" {
		switch inst.Status {
		case models.InstructionPending, models.InstructionLeased:
			return h.waiting(ctx, inst)
		case models.InstructionApplied:
			now := time.Now().UTC()
			set := map[string]any{"drift": "", "state_reason": "", "deployed_at": now, "verified_at": now, "updated_at": now}
			// This removal took the subject out: it is what the end puts back.
			var rm k8sRemoved
			_ = json.Unmarshal(inst.Result, &rm)
			if rm.Removed && rm.BindingUID != "" {
				raw, _ := json.Marshal(rm)
				set["removed"] = raw
			}
			return h.run.InTx(ctx, func(tx *gorm.DB) error {
				return tx.Model(&models.IGAGovK8sAccess{}).Where("workspace_id = ? AND id = ? AND state = ?", h.row.WorkspaceID, h.row.ID, models.R2StateActive).
					Updates(set).Error
			})
		case models.InstructionFailed:
			return h.run.InTx(ctx, func(tx *gorm.DB) error {
				return tx.Model(&models.IGAGovK8sAccess{}).Where("workspace_id = ? AND id = ?", h.row.WorkspaceID, h.row.ID).
					Updates(map[string]any{"state_reason": "the cluster agent could not remove the subject again: " + inst.Error, "updated_at": time.Now().UTC()}).Error
			})
		}
	}
	if h.row.DeployedAt == nil {
		return nil
	}
	back, err := h.subjectBack(ctx)
	if err != nil || !back {
		return err
	}
	if err := h.run.InTx(ctx, func(tx *gorm.DB) error {
		return h.event(tx, GovEventAccessDrifted, map[string]any{"classification": "subject_readded", "note": "AuthSec removes it again."})
	}); err != nil {
		return err
	}
	return h.instruct(ctx, models.R2StateActive, models.R2StateActive, models.InstructionRemoveBindingSubject, map[string]any{"drift": "subject_readded"})
}

// subjectBack reports a sweep, well after the removal, that still lists the
// subject in the binding.
func (h k8sHandler) subjectBack(ctx context.Context) (bool, error) {
	var s struct{ Namespace, Name string }
	_ = json.Unmarshal(h.row.Subject, &s)
	b := models.K8sBinding{Name: h.row.BindingName, Namespace: h.row.BindingNamespace}
	key := k8sgraph.BindingKey(h.row.Cluster, b) + k8sgraph.Sep + k8sgraph.ServiceAccountKey(h.row.Cluster, s.Namespace, s.Name)
	var n int64
	err := h.run.ReadTx(ctx, func(tx *gorm.DB) error {
		return tx.Model(&models.IGAPolicyAssignment{}).Where("workspace_id = ? AND source_key = ? AND state <> ? AND last_confirmed_at > ?",
			h.row.WorkspaceID, key, "ended", h.row.DeployedAt.Add(k8sDriftMargin)).Count(&n).Error
	})
	return n > 0, err
}

// startRestore moves the row to expiring; the next run restores.
func (h k8sHandler) startRestore(ctx context.Context, from, endReason string) error {
	err := h.run.InTx(ctx, func(tx *gorm.DB) error {
		res := tx.Model(&models.IGAGovK8sAccess{}).Where("workspace_id = ? AND id = ? AND state = ?", h.row.WorkspaceID, h.row.ID, from).
			Updates(map[string]any{"state": models.R2StateExpiring, "end_reason": endReason, "updated_at": time.Now().UTC()})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected != 1 {
			return PolicyJobRetryLater(time.Second, "the row's state moved; reloading")
		}
		return nil
	})
	if err != nil {
		return err
	}
	return PolicyJobRetryLater(time.Second, "restoring")
}

func (h k8sHandler) expiring(ctx context.Context) error {
	inst, err := h.instruction(ctx)
	if err != nil {
		return err
	}
	if inst != nil && inst.Kind == models.InstructionRemoveBindingSubject {
		switch inst.Status {
		case models.InstructionPending:
			// Never picked up: take it back; nothing was removed by it.
			if err := h.run.InTx(ctx, func(tx *gorm.DB) error {
				return tx.Model(&models.ProvisioningInstruction{}).Where("workspace_id = ? AND id = ? AND status = ?", h.row.WorkspaceID, inst.ID,
					models.InstructionPending).Updates(map[string]any{"status": models.InstructionSuperseded, "updated_at": time.Now().UTC()}).Error
			}); err != nil {
				return err
			}
			if h.row.DeployedAt == nil {
				return h.finish(ctx, models.R2StateExpired, h.row.EndReason, "")
			}
		case models.InstructionLeased:
			return h.waiting(ctx, inst)
		case models.InstructionApplied:
			var rm k8sRemoved
			_ = json.Unmarshal(inst.Result, &rm)
			if h.row.DeployedAt == nil && rm.BindingUID != "" {
				raw, _ := json.Marshal(rm)
				h.row.Removed = raw
				if err := h.run.InTx(ctx, func(tx *gorm.DB) error {
					return tx.Model(&models.IGAGovK8sAccess{}).Where("workspace_id = ? AND id = ?", h.row.WorkspaceID, h.row.ID).
						Updates(map[string]any{"removed": raw, "updated_at": time.Now().UTC()}).Error
				}); err != nil {
					return err
				}
			}
		}
		var rm k8sRemoved
		_ = json.Unmarshal(h.row.Removed, &rm)
		if rm.BindingUID == "" {
			// Nothing was taken out (never applied, or the subject was absent):
			// nothing to put back.
			return h.finish(ctx, models.R2StateExpired, h.row.EndReason, "")
		}
		return h.instruct(ctx, models.R2StateExpiring, models.R2StateExpiring, models.InstructionRestoreBindingSubject, nil)
	}
	if inst == nil || inst.Status == models.InstructionSuperseded {
		var rm k8sRemoved
		_ = json.Unmarshal(h.row.Removed, &rm)
		if rm.BindingUID == "" {
			return h.finish(ctx, models.R2StateExpired, h.row.EndReason, "")
		}
		return h.instruct(ctx, models.R2StateExpiring, models.R2StateExpiring, models.InstructionRestoreBindingSubject, nil)
	}
	switch inst.Status {
	case models.InstructionPending, models.InstructionLeased:
		return h.waiting(ctx, inst)
	case models.InstructionFailed:
		return h.finish(ctx, models.R2StateFailed, r2EndReasonFailed, "the cluster agent could not put the subject back: "+inst.Error)
	}
	var out struct {
		Outcome string `json:"outcome"`
	}
	_ = json.Unmarshal(inst.Result, &out)
	note := ""
	switch out.Outcome {
	case "binding_gone":
		note = "not restored: the binding was deleted outside AuthSec"
	case "binding_replaced":
		note = "not restored: the binding was deleted and re-created outside AuthSec"
	}
	return h.finish(ctx, models.R2StateExpired, h.row.EndReason, note)
}

func (h k8sHandler) finish(ctx context.Context, final, endReason, note string) error {
	now := time.Now().UTC()
	return h.run.InTx(ctx, func(tx *gorm.DB) error {
		set := map[string]any{"state": final, "ended_at": now, "state_reason": note, "updated_at": now}
		if endReason != "" {
			set["end_reason"] = endReason
		}
		res := tx.Model(&models.IGAGovK8sAccess{}).Where("workspace_id = ? AND id = ? AND state = ?", h.row.WorkspaceID, h.row.ID, h.row.State).Updates(set)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected != 1 {
			return PolicyJobRetryLater(time.Second, "the row's state moved; reloading")
		}
		name := GovEventAccessRemoved
		switch final {
		case models.R2StateExpired:
			name = GovEventAccessExpired
		case models.R2StateFailed:
			name = GovEventAccessFailed
		}
		return h.event(tx, name, map[string]any{"state": final, "end_reason": endReason, "note": note})
	})
}

// k8sSupersedeTx: once every Kubernetes row of the applied version is active,
// the older versions' rows end.
func k8sSupersedeTx(tx *gorm.DB, ws, policyID, versionID uuid.UUID) error {
	var v []models.IGAGovAccessPolicyVersion
	if err := tx.Where("workspace_id = ? AND id = ? AND status = ?", ws, versionID, models.AccessVersionApplied).
		Limit(1).Find(&v).Error; err != nil || len(v) == 0 {
		return err
	}
	var pending int64
	if err := tx.Model(&models.IGAGovK8sAccess{}).Where("workspace_id = ? AND policy_id = ? AND version_id = ? AND state <> ?",
		ws, policyID, versionID, models.R2StateActive).Count(&pending).Error; err != nil || pending > 0 {
		return err
	}
	_, err := endRowsTx(tx, ws, policyID, &versionID, accessEndSuperseded, nil, time.Now().UTC())
	return err
}

// RegisterK8sAccessJobs installs the k8s_access handler and its periodic
// check of live rows.
func RegisterK8sAccessJobs(w *PolicyJobWorker, db *gorm.DB) {
	s := NewGovAccess(db)
	w.Register(PolicyJobKind{Kind: repositories.GovJobK8sAccess, Handler: s.K8sAccessHandler})
	w.Scheduler().Add(PolicyJobSchedule{Name: repositories.GovJobK8sAccess, Kind: repositories.GovJobK8sAccess, Every: k8sCheckEvery,
		Due: func(ctx context.Context, db *gorm.DB, now time.Time) ([]ScheduledPolicyJob, error) {
			// TENANT-EXEMPT: the 146 schema check reads the Postgres catalog only.
			if ok, _ := K8sAccessSchemaStatus(db); !ok {
				return nil, nil
			}
			var rows []struct {
				WorkspaceID uuid.UUID
				ID          uuid.UUID
			}
			// TENANT-EXEMPT: the schedule's scan of live Kubernetes rows across
			// workspaces; each job then runs in its row's own workspace.
			if err := db.Table("iga_gov_k8s_access").Select("workspace_id, id").Where("state IN ?", k8sLiveStates).Scan(&rows).Error; err != nil {
				return nil, err
			}
			out := make([]ScheduledPolicyJob, 0, len(rows))
			for _, r := range rows {
				id := r.ID
				out = append(out, ScheduledPolicyJob{WorkspaceID: r.WorkspaceID, SubjectID: &id, DedupeKey: "k8s_access:" + id.String()})
			}
			return out, nil
		}})
}
