package services

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/gorm"
)

/* azure_evidence.go records WHY each Azure row exists: for every identity,
   grant, resource and workload a pass confirmed, which Microsoft API returned
   it, under which coverage surface, how complete that surface's read was, and
   when -- in cloud_observation, the same evidence table and writer AWS uses.

   A reviewer asked to act on "Asif Ali is Global Administrator" can then see
   the receipt: read by GET /v1.0/roleManagement/directory/roleAssignments, in scan run X,
   at time T, from a complete read -- and how many runs have confirmed it since.

   Facts are the stable, identifying part of each row -- never a secret (none
   is ever stored), and never what changes on every read (sign-in times), so an
   unchanged object is CONFIRMED again rather than re-recorded: the writer
   dedupes on content and bumps confirmation_count instead.

   Written at the end of a pass, while it still holds its run's lease: the
   writer fences every write on the run's owner and lease version, so a pass
   that lost its connector to a newer one cannot confirm anything. */

// azureIdentitySource is the Graph listing each identity kind comes from.
var azureIdentitySource = map[string][2]string{
	models.CloudIdentityEntraUser:             {"GET /v1.0/users", models.SurfaceEntraUsers},
	models.CloudIdentityEntraGroup:            {"GET /v1.0/groups", models.SurfaceEntraGroups},
	models.CloudIdentityEntraApplication:      {"GET /v1.0/applications", models.SurfaceEntraApplications},
	models.CloudIdentityEntraServicePrincipal: {"GET /v1.0/servicePrincipals", models.SurfaceEntraServicePrincipals},
	models.CloudIdentityEntraManagedIdentity:  {"GET /v1.0/servicePrincipals", models.SurfaceEntraServicePrincipals},
	models.CloudIdentityEntraAgentIdentity:    {"GET /v1.0/servicePrincipals", models.SurfaceEntraServicePrincipals},
	models.CloudIdentityEntraAgentUser:        {"GET /v1.0/users", models.SurfaceEntraUsers},
}

// azureAgentSource is the Agent ID listing an object came from when that
// listing returned it (attrs.agent_listed); otherwise its base listing did.
var azureAgentSource = map[string][2]string{
	models.CloudIdentityEntraAgentIdentity: {"GET /v1.0/servicePrincipals/microsoft.graph.agentIdentity", models.SurfaceEntraAgentIdentities},
	models.CloudIdentityEntraAgentUser:     {"GET /beta/users/microsoft.graph.agentUser", models.SurfaceEntraAgentUsers},
	models.AgentTypeBlueprint:              {"GET /v1.0/applications/microsoft.graph.agentIdentityBlueprint", models.SurfaceEntraAgentBlueprints},
	models.AgentTypeBlueprintPrincipal:     {"GET /v1.0/servicePrincipals/microsoft.graph.agentIdentityBlueprintPrincipal", models.SurfaceEntraAgentBlueprintPrincipals},
}

// azureIdentityFactKeys are the attrs that identify an object and do not
// change with use; sign-in times and group member lists are left out.
var azureIdentityFactKeys = []string{
	"user_principal_name", "user_type", "app_id", "sign_in_audience",
	"service_principal_type", "app_owner_tenant_id", "managed_identity_resource",
	"managed_identity_assignment", "security_enabled", "role_assignable",
	"agent_type", "agent_blueprint_app_id", "agent_identity_id",
}

// azureEvidenceBatch is how many observations one transaction writes. Each
// write asserts the run's fence (FOR SHARE on the run row, held to commit) in
// a savepoint of its own, so a batch stays small: the run's heartbeat is not
// held up, and the savepoints stay few.
const azureEvidenceBatch = 50

// azureObservation is one observation a pass's evidence will record.
type azureObservation struct {
	subject   ObservationSubject
	api       string
	surface   string
	state     string
	nativeID  string
	facts     map[string]interface{}
	errPrefix string // prefixed to a write error, as "grant <id>: "
}

// recordEvidence writes the pass's evidence. Logged, never fatal: evidence
// explains rows the pass already wrote, and losing it must not lose them.
//
// The rows the pass confirmed are read in one read-only transaction under
// row-level security for the run's workspace; the observations are then
// written azureEvidenceBatch at a time, each batch in a transaction of its
// own for that workspace.
func (s *AzureOnboardingService) recordEvidence(pass *azurePass, scopeKind string, cov models.ScanCoverage, counters map[string]int) {
	run := pass.run
	// No run to anchor evidence to (NewObservationWriter would be nil):
	// nothing to write.
	if run.ID == uuid.Nil || run.Generation <= 0 {
		counters["evidence_written"], counters["evidence_confirmed"] = 0, 0
		return
	}
	ctx := context.Background()
	var obs []azureObservation
	err := tenancy.InWorkspaceRead(ctx, s.db, run.WorkspaceID, func(tx *gorm.DB) error {
		var err error
		if scopeKind == models.CloudScopeTenant {
			obs, err = tenantEvidence(tx, run, cov)
		} else {
			obs, err = subscriptionEvidence(tx, run, cov)
		}
		return err
	})
	written, unchanged := 0, 0
	if err == nil {
		written, unchanged, err = s.writeEvidence(ctx, run, obs)
	}
	counters["evidence_written"] = written
	counters["evidence_confirmed"] = unchanged
	if err != nil {
		log.Printf("[azure] evidence for pass %s on connector %s stopped: %v", run.ID, run.ConnectorID, err)
	}
}

// writeEvidence records obs in batches, stopping at the first write that
// fails. What was written before it is kept: a failed write rolls back only
// its own savepoint, and its batch commits the writes before it.
func (s *AzureOnboardingService) writeEvidence(ctx context.Context, run *models.CloudScanRun, obs []azureObservation) (written, unchanged int, err error) {
	fence := repositories.ScanFence{RunID: run.ID, Owner: azureRunOwner, LeaseVersion: run.LeaseVersion}
	for start := 0; start < len(obs) && err == nil; start += azureEvidenceBatch {
		batch := obs[start:min(start+azureEvidenceBatch, len(obs))]
		var recErr error
		var w, u int
		txErr := tenancy.InWorkspace(ctx, s.db, run.WorkspaceID, func(tx *gorm.DB) error {
			ow := NewObservationWriter(tx, run.WorkspaceID, run.ConnectorID, run.ID, run.Generation).WithFence(fence)
			for _, o := range batch {
				if recErr = ow.Record(o.subject, o.api, o.surface, o.state, time.Now(), o.nativeID, o.facts); recErr != nil {
					if o.errPrefix != "" {
						recErr = fmt.Errorf("%s%w", o.errPrefix, recErr)
					}
					break
				}
			}
			w, u = ow.Counts()
			return nil // commit what was written before any failure
		})
		if txErr != nil {
			return written, unchanged, txErr
		}
		written, unchanged, err = written+w, unchanged+u, recErr
	}
	return written, unchanged, err
}

// confirmedBy scopes a cloud_* query to the rows this pass confirmed.
func confirmedBy(run *models.CloudScanRun) (string, []interface{}) {
	return "workspace_id = ? AND connector_id = ? AND last_seen_generation = ?",
		[]interface{}{run.WorkspaceID, run.ConnectorID, run.Generation}
}

// tenantEvidence is the observations of a tenant pass, read through tx.
func tenantEvidence(tx *gorm.DB, run *models.CloudScanRun, cov models.ScanCoverage) ([]azureObservation, error) {
	where, args := confirmedBy(run)
	var identities []models.CloudIdentity
	if err := tx.Where(where, args...).Find(&identities).Error; err != nil {
		return nil, err
	}
	var out []azureObservation
	for _, i := range identities {
		src, ok := azureIdentitySource[i.Kind]
		if !ok {
			continue
		}
		attrs := map[string]interface{}{}
		_ = json.Unmarshal(i.Attrs, &attrs)
		if listed, _ := attrs["agent_listed"].(bool); listed {
			agentKey := i.Kind
			if t, _ := attrs["agent_type"].(string); t != "" {
				agentKey = t
			}
			if a, ok := azureAgentSource[agentKey]; ok {
				src = a
			}
		}
		facts := map[string]interface{}{"kind": i.Kind, "name": i.Name, "enabled": i.Enabled, "object_id": i.NativeID}
		for _, k := range azureIdentityFactKeys {
			if v, ok := attrs[k]; ok && v != nil && v != "" {
				facts[k] = v
			}
		}
		out = append(out, azureObservation{subject: IdentitySubject(i.ID), api: src[0], surface: src[1],
			state: SurfaceStateOf(cov, src[1]), nativeID: i.NativeID, facts: facts})
	}
	grants, err := grantEvidence(tx, run, cov)
	if err != nil {
		return nil, err
	}
	resources, err := resourceEvidence(tx, run, cov)
	if err != nil {
		return nil, err
	}
	return append(append(out, grants...), resources...), nil
}

// subscriptionEvidence is the observations of a subscription pass, read
// through tx.
func subscriptionEvidence(tx *gorm.DB, run *models.CloudScanRun, cov models.ScanCoverage) ([]azureObservation, error) {
	out, err := resourceEvidence(tx, run, cov)
	if err != nil {
		return nil, err
	}
	grants, err := grantEvidence(tx, run, cov)
	if err != nil {
		return nil, err
	}
	out = append(out, grants...)
	where, args := confirmedBy(run)
	var workloads []models.CloudWorkload
	if err := tx.Where(where, args...).Find(&workloads).Error; err != nil {
		return nil, err
	}
	for _, wl := range workloads {
		attrs := map[string]interface{}{}
		_ = json.Unmarshal(wl.Attrs, &attrs)
		facts := map[string]interface{}{
			"runtime_kind": wl.RuntimeKind, "name": wl.Name, "region": wl.Region,
			"principal_id": attrs["principal_id"], "identity_assignment": attrs["identity_assignment"],
		}
		api, surface := "Microsoft.ResourceGraph/resources (identity)", models.SurfaceAzureWorkloads
		if fk, _ := attrs["foundry_kind"].(string); fk != "" {
			api, surface = azureFoundryAPI, models.SurfaceAzureFoundry
			if wl.RuntimeKind == models.AzureFoundryRuntimeKinds[2] {
				api = azureMLAPI
			}
			facts["foundry_kind"] = fk
			for _, k := range []string{"resource_kind", "local_auth_enabled", "public_network_access", "account_id", "is_default",
				"hub_id", "isolation_mode"} {
				if v, ok := attrs[k]; ok {
					facts[k] = v
				}
			}
			for _, k := range []string{"deployments", "connections", "agent_applications"} {
				if v, ok := attrs[k].([]interface{}); ok {
					facts[k+"_count"] = len(v)
				}
			}
		}
		out = append(out, azureObservation{subject: WorkloadSubject(wl.ID), api: api, surface: surface,
			state: SurfaceStateOf(cov, surface), nativeID: wl.NativeID, facts: facts})
	}
	return out, nil
}

func resourceEvidence(tx *gorm.DB, run *models.CloudScanRun, cov models.ScanCoverage) ([]azureObservation, error) {
	where, args := confirmedBy(run)
	var resources []models.CloudResource
	if err := tx.Where(where, args...).Find(&resources).Error; err != nil {
		return nil, err
	}
	out := make([]azureObservation, 0, len(resources))
	for _, r := range resources {
		api, surface := "Microsoft.ResourceGraph/resources", models.SurfaceAzureResources
		switch r.Kind {
		case models.CloudResourceEntraAppRole:
			api, surface = "GET /v1.0/servicePrincipals (appRoles)", models.SurfaceEntraAppRoleAssignments
		case models.CloudResourceEntraDelegatedScope:
			api, surface = "GET /v1.0/oauth2PermissionGrants", models.SurfaceEntraDelegatedGrants
		}
		facts := map[string]interface{}{
			"kind": r.Kind, "name": r.Name, "account": r.ResourceAccount,
			"sensitivity": r.Sensitivity, "sensitivity_reason": r.SensitivityReason,
		}
		out = append(out, azureObservation{subject: ResourceSubject(r.ID), api: api, surface: surface,
			state: SurfaceStateOf(cov, surface), nativeID: r.NativeID, facts: facts})
	}
	return out, nil
}

// azureGrantEvidenceRow is a grant with who holds it and what it points at.
type azureGrantEvidenceRow struct {
	ID              uuid.UUID
	NativeID        string
	Plane           string
	RoleName        *string
	Actions         pq.StringArray `gorm:"type:text[]"`
	NotActions      pq.StringArray `gorm:"type:text[]"`
	ScopeKind       string
	ConstraintState string
	Condition       *string
	Sensitivity     string
	SubjectNativeID string
	ResourceNative  string
	ResourceKind    string
}

func grantEvidence(tx *gorm.DB, run *models.CloudScanRun, cov models.ScanCoverage) ([]azureObservation, error) {
	var grants []azureGrantEvidenceRow
	if err := tx.Table("cloud_permission p").
		Select(`p.id, p.native_id, p.plane, p.role_name, p.actions, p.not_actions, p.scope_kind,
			p.constraint_state, p.condition::text AS condition, p.sensitivity,
			i.native_id AS subject_native_id, COALESCE(r.native_id, '') AS resource_native, COALESCE(r.kind, '') AS resource_kind`).
		Joins("JOIN cloud_identity i ON i.id = p.identity_id").
		Joins("LEFT JOIN cloud_resource r ON r.id = p.resource_id").
		Where("p.workspace_id = ? AND p.connector_id = ? AND p.last_seen_generation = ?",
			run.WorkspaceID, run.ConnectorID, run.Generation).
		Scan(&grants).Error; err != nil {
		return nil, err
	}
	out := make([]azureObservation, 0, len(grants))
	for _, g := range grants {
		api, surface := grantSource(g)
		role := ""
		if g.RoleName != nil {
			role = *g.RoleName
		}
		facts := map[string]interface{}{
			"holder_object_id": g.SubjectNativeID, "role_name": role, "plane": g.Plane,
			"actions": []string(g.Actions), "not_actions": []string(g.NotActions),
			"scope_kind": g.ScopeKind, "constraint_state": g.ConstraintState,
			"resource": g.ResourceNative, "sensitivity": g.Sensitivity,
		}
		if g.Condition != nil {
			facts["condition"] = json.RawMessage(*g.Condition)
		}
		out = append(out, azureObservation{subject: PermissionSubject(g.ID), api: api, surface: surface,
			state: SurfaceStateOf(cov, surface), nativeID: g.NativeID, facts: facts,
			errPrefix: "grant " + g.NativeID + ": "})
	}
	return out, nil
}

// grantSource is the API and surface one grant was read from.
func grantSource(g azureGrantEvidenceRow) (string, string) {
	switch {
	case strings.Contains(g.NativeID, models.InheritedGrantMarker):
		return "GET /v1.0/applications/{id}/microsoft.graph.agentIdentityBlueprint/inheritablePermissions, " +
			"with the blueprint principal's grant", models.SurfaceEntraAgentInheritance
	case g.ResourceKind == models.CloudResourceEntraAppRole:
		return "GET /v1.0/servicePrincipals/{api}/appRoleAssignedTo", models.SurfaceEntraAppRoleAssignments
	case g.ResourceKind == models.CloudResourceEntraDelegatedScope:
		return "GET /v1.0/oauth2PermissionGrants", models.SurfaceEntraDelegatedGrants
	case g.Plane == models.PermissionPlaneAPI:
		return "GET /v1.0/roleManagement/directory/roleAssignments", models.SurfaceEntraDirectoryRoles
	case strings.Contains(g.NativeID, "/accesspolicies/"):
		return "Microsoft.ResourceGraph/resources (Microsoft.KeyVault/vaults accessPolicies)", models.SurfaceAzureKeyVaultAccessPolicies
	}
	return "Microsoft.Authorization/roleAssignments", models.SurfaceAzureRoleAssignments
}
