package repositories

import (
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

/* cloud_azure_repository.go owns an Azure subscription's inventory pass on
   the shared tables: allocating a generation on its cloud_connector row,
   writing the coverage that says what that generation read, and the
   cloud_resource rows it found.

   WHY NOT cloud_scan_run. The AWS scan worker claims every queued run with no
   provider predicate (cloud_scan_run_repository.go claim), so an Azure run
   enqueued there would be picked up and scanned as an AWS account. Azure's
   inventory is one Resource Graph query per subscription and runs inline;
   the generation lives on the connector row exactly as GCP's does
   (cloud_gcp_scan_repository.go), with the same atomic allocation.

   WHY EVERY STATEMENT CARRIES provider = 'azure'. The same structural guard
   the GCP repository uses: nothing here can bump the generation of, write
   coverage onto, or delete the resources of an AWS or GCP connector, even
   given the wrong id. */

// CloudAzureRepository is the inventory lifecycle of an Azure connector row.
type CloudAzureRepository interface {
	// AllocateGeneration advances scan_generation by one and returns it, in a
	// single statement.
	AllocateGeneration(workspaceID, connectorID uuid.UUID) (int, error)

	// BeginRun records a running pass over the connector in cloud_scan_run and
	// gives it the connector's next generation, in one transaction. A previous
	// pass whose lease lapsed (its process stopped) is abandoned first.
	// ErrScanAlreadyLive when another pass still holds the connector.
	BeginRun(workspaceID, connectorID uuid.UUID, owner, trigger string, lease time.Duration) (*models.CloudScanRun, error)
	// RenewRun extends a pass's lease; ErrLeaseLost when it is no longer held.
	RenewRun(runID uuid.UUID, owner string, lease time.Duration) error
	// FinishRun ends a pass: published with its final coverage, or failed
	// with reason when the pass read nothing. ErrLeaseLost when not held.
	FinishRun(runID uuid.UUID, owner string, coverage models.ScanCoverage) error
	// DueTenants lists active Azure tenant connectors, in every workspace,
	// whose last pass finished before finishedBefore or never finished. A pass
	// still reported running counts as never finished once it started before
	// runningStartedBefore: its process stopped mid-pass.
	DueTenants(finishedBefore, runningStartedBefore time.Time) ([]models.CloudConnector, error)

	// WriteCoverage replaces coverage, only while the connector is still on
	// generation; ErrScanSuperseded otherwise.
	WriteCoverage(workspaceID, connectorID uuid.UUID, generation int, coverage json.RawMessage) error

	// UpsertResources records resources seen by generation, keyed on
	// (workspace_id, native_id). Returns how many rows were written.
	UpsertResources(workspaceID, connectorID uuid.UUID, generation int, rows []models.CloudResource) (int, error)

	// ListResources lists Azure resources in the workspace, optionally for
	// one connector.
	ListResources(workspaceID uuid.UUID, f AzureListFilter) ([]models.CloudResource, int64, error)

	// UpsertIdentities records directory objects seen by generation, keyed on
	// (workspace_id, native_id).
	UpsertIdentities(workspaceID, connectorID uuid.UUID, generation int, rows []models.CloudIdentity) (int, error)
	// UpsertSecrets records credential metadata seen by generation.
	UpsertSecrets(workspaceID, connectorID uuid.UUID, generation int, rows []models.CloudSecret) (int, error)
	// UpsertPermissions records grants seen by generation, keyed on
	// (identity_id, native_id, resource_id).
	UpsertPermissions(workspaceID, connectorID uuid.UUID, generation int, rows []models.CloudPermission) (int, error)

	// IdentityIDs maps Azure identity native ids (Entra object ids) to their
	// cloud_identity ids. Ids with no Azure identity are absent.
	IdentityIDs(workspaceID uuid.UUID, nativeIDs []string) (map[string]uuid.UUID, error)
	// ResourceIDs maps Azure resource native ids to their cloud_resource ids.
	ResourceIDs(workspaceID uuid.UUID, nativeIDs []string) (map[string]uuid.UUID, error)

	// UpsertAssumeEdges records who may become an identity (federated
	// credentials), keyed on (identity_id, subject_kind, subject).
	UpsertAssumeEdges(workspaceID, connectorID uuid.UUID, generation int, rows []models.CloudAssumeEdge) (int, error)
	// UpsertWorkloads records resources that run as an identity, keyed on
	// (workspace_id, native_id).
	UpsertWorkloads(workspaceID, connectorID uuid.UUID, generation int, rows []models.CloudWorkload) (int, error)
	// UpsertUsage records sign-in evidence, keyed on (identity_id, service,
	// source).
	UpsertUsage(workspaceID, connectorID uuid.UUID, generation int, rows []models.CloudUsage) (int, error)

	// ManagedIdentityIDs maps the ARM id of a managed identity's resource (the
	// user-assigned identity itself, or the resource a system-assigned one
	// belongs to) to its cloud_identity id.
	ManagedIdentityIDs(workspaceID uuid.UUID, resourceIDs []string) (map[string]uuid.UUID, error)
	// ServicePrincipalIDsByAppID maps an application (client) id, lowercased,
	// to the cloud_identity id of its service principal in the workspace's
	// Azure tenants.
	ServicePrincipalIDsByAppID(workspaceID uuid.UUID, appIDs []string) (map[string]uuid.UUID, error)

	// RBACGrants lists the connector's Azure RBAC grants (not Key Vault access
	// policies) with the object id of who holds each.
	RBACGrants(workspaceID, connectorID uuid.UUID) ([]AzureRBACGrant, error)
	// SetLastExercised moves each grant's last_exercised_at forward to the
	// given time; never backward.
	SetLastExercised(workspaceID, connectorID uuid.UUID, at map[uuid.UUID]time.Time) error
	// MarkAppPermissionsExercised stamps the tenant connector's application
	// permissions with the last sign-in their holder made to their API.
	MarkAppPermissionsExercised(workspaceID, tenantConnectorID uuid.UUID) (int64, error)

	// MergeAttrs merges patch into the connector's attrs, only while it is
	// still on generation; ErrScanSuperseded otherwise.
	MergeAttrs(workspaceID, connectorID uuid.UUID, generation int, patch map[string]interface{}) error

	// Reconcile deletes, in one transaction, the connector's rows NOT seen in
	// generation -- only in the tables parts names. The caller names a table
	// only when every surface that writes it was read in full.
	Reconcile(workspaceID, connectorID uuid.UUID, generation int, parts AzureReconcileParts) (AzureReconcileCounts, error)

	ListIdentities(workspaceID uuid.UUID, f AzureIdentityFilter) ([]models.CloudIdentity, int64, error)
	ListGrants(workspaceID uuid.UUID, f AzureGrantFilter) ([]AzureGrant, int64, error)
	ListSecrets(workspaceID uuid.UUID, f AzureListFilter) ([]AzureSecret, int64, error)
	ListFederation(workspaceID uuid.UUID, f AzureListFilter) ([]AzureFederationEdge, int64, error)
	ListWorkloads(workspaceID uuid.UUID, f AzureListFilter) ([]AzureWorkload, int64, error)
	// ListFoundry returns every Foundry account and project row, and who
	// each one's managed identity can become.
	ListFoundry(workspaceID uuid.UUID, connectorID *uuid.UUID) ([]AzureWorkload, []AzureFoundryTrust, error)
	// ScanRuns lists a connector's discovery passes, newest first.
	ScanRuns(workspaceID, connectorID uuid.UUID, limit int) ([]models.CloudScanRun, error)
	ListUsage(workspaceID uuid.UUID, f AzureUsageFilter) ([]AzureUsage, int64, error)
}

// Grant sources, derived from where a cloud_permission row came from.
const (
	AzureGrantSourceDirectoryRole = "directory_role"
	AzureGrantSourceApplication   = "application_permission"
	AzureGrantSourceDelegated     = "delegated_permission"
	AzureGrantSourceRBAC          = "rbac_role_assignment"
	AzureGrantSourceKeyVault      = "key_vault_access_policy"
)

// azureGrantSourceSQL derives a grant's source from its row: the API-plane
// resource kind for API permissions, the native id's shape for access policies.
const azureGrantSourceSQL = `CASE
	WHEN res.kind = 'entra_app_role' THEN 'application_permission'
	WHEN res.kind = 'entra_delegated_scope' THEN 'delegated_permission'
	WHEN p.plane = 'api' THEN 'directory_role'
	WHEN p.native_id LIKE '%/accesspolicies/%' THEN 'key_vault_access_policy'
	ELSE 'rbac_role_assignment' END`

// AzureRBACGrant is one Azure RBAC grant with who holds it.
type AzureRBACGrant struct {
	ID              uuid.UUID
	NativeID        string
	Actions         pq.StringArray `gorm:"type:text[]"`
	NotActions      pq.StringArray `gorm:"type:text[]"`
	SubjectNativeID string
}

// AzureFederationEdge is one cloud_assume_edge row with its identity's name.
type AzureFederationEdge struct {
	models.CloudAssumeEdge
	IdentityName string `json:"identity_name"`
	IdentityKind string `json:"identity_kind"`
	// SubjectName names the subject when it is a directory object AuthSec
	// recorded (an owner, a blueprint, another identity).
	SubjectName string `json:"subject_name,omitempty"`
}

// AzureWorkload is one cloud_workload row with its identity's name.
type AzureWorkload struct {
	models.CloudWorkload
	IdentityName string `json:"identity_name"`
	IdentityKind string `json:"identity_kind"`
}

// AzureFoundryTrust is one identity a Foundry resource's managed identity can
// become: an application whose federated credential trusts that managed
// identity -- for a Foundry agent, its agent identity blueprint -- and, one
// row each, the agent identities the blueprint obtains tokens for.
type AzureFoundryTrust struct {
	PrincipalID       string     `json:"principal_id"`
	TrustedIdentityID uuid.UUID  `json:"trusted_identity_id"`
	TrustedName       string     `json:"trusted_name"`
	TrustedKind       string     `json:"trusted_kind"`
	TrustedAgentType  string     `json:"trusted_agent_type"`
	AgentIdentityID   *uuid.UUID `json:"agent_identity_id,omitempty"`
	AgentName         string     `json:"agent_name,omitempty"`
	AgentObjectID     string     `json:"agent_object_id,omitempty"`
}

// azureFoundryRowCap bounds one ListFoundry read; a workspace with more
// Foundry accounts and projects than this pages through /workloads instead.
const azureFoundryRowCap = 2000

// AzureUsage is one cloud_usage row with its identity's name.
type AzureUsage struct {
	models.CloudUsage
	IdentityName string `json:"identity_name"`
	IdentityKind string `json:"identity_kind"`
}

// AzureUsageFilter narrows ListUsage.
type AzureUsageFilter struct {
	IdentityID *uuid.UUID
	// AIOnly keeps sign-ins to Azure AI services.
	AIOnly bool
	Limit  int
	Offset int
}

// AzureReconcileParts names the tables one Reconcile may age rows out of.
type AzureReconcileParts struct {
	Permissions, Usage, Edges, Secrets, Workloads, Resources, Identities bool
	// Foundry ends the workload rows the Foundry surface owns
	// (models.AzureFoundryRuntimeKinds); Workloads ends every other one.
	Foundry bool
	// KeepAgentListed spares what Microsoft Entra Agent ID listed
	// (attrs.agent_listed) -- the objects, their secrets, the edges landing
	// on them, and the grants agents inherit from their blueprints -- when this
	// pass could not read Agent ID in full: what a listing missed stays as it
	// was.
	KeepAgentListed bool
}

// AzureReconcileCounts is how many stale rows each table lost.
type AzureReconcileCounts struct {
	Permissions, Usage, Edges, Secrets, Workloads, Resources, Identities, Foundry int64
}

// AzureListFilter narrows the inventory lists (resources, secrets, federation,
// workloads). Each list honours the fields that mean something for it.
type AzureListFilter struct {
	ConnectorID *uuid.UUID
	// IdentityID scopes to one identity: its secrets, the federated
	// credentials trusting it, the workloads running as it.
	IdentityID *uuid.UUID
	// Kind is a resource kind or a workload runtime kind.
	Kind   string
	Search string
	Limit  int
	Offset int
}

// AzureIdentityFilter narrows ListIdentities.
type AzureIdentityFilter struct {
	ConnectorID *uuid.UUID
	Kind        string
	// AgentType is attrs.agent_type: a blueprint (an application) or a
	// blueprint principal (a service principal).
	AgentType string
	Search    string
	Limit     int
	Offset    int
}

// AzureGrantFilter narrows ListGrants.
type AzureGrantFilter struct {
	ConnectorID *uuid.UUID
	IdentityID  *uuid.UUID
	// ResourceID scopes to grants on one resource: who can reach it.
	ResourceID *uuid.UUID
	Plane      string
	// Source is one of the AzureGrantSource* values.
	Source string
	Limit  int
	Offset int
}

// AzureGrant is one cloud_permission row with the names a reader needs to
// understand it: who holds it, and on what.
type AzureGrant struct {
	ID           uuid.UUID  `json:"id"`
	ConnectorID  uuid.UUID  `json:"connector_id"`
	IdentityID   uuid.UUID  `json:"identity_id"`
	IdentityName string     `json:"identity_name"`
	IdentityKind string     `json:"identity_kind"`
	ResourceID   *uuid.UUID `json:"resource_id,omitempty"`
	ResourceName string     `json:"resource_name,omitempty"`
	ResourceKind string     `json:"resource_kind,omitempty"`
	Source       string     `json:"source"`
	// Inherited is a grant an agent identity inherits from its blueprint's
	// principal: derived, never granted to the agent itself.
	Inherited       bool           `json:"inherited"`
	Condition       *string        `json:"condition,omitempty"`
	LastExercisedAt *time.Time     `json:"last_exercised_at,omitempty"`
	Plane           string         `json:"plane"`
	RoleName        string         `json:"role_name"`
	ScopeKind       string         `json:"scope_kind"`
	ConstraintState string         `json:"constraint_state"`
	Sensitivity     string         `json:"sensitivity"`
	Actions         pq.StringArray `json:"actions" gorm:"type:text[]"`
	NotActions      pq.StringArray `json:"not_actions" gorm:"type:text[]"`
	NativeID        string         `json:"native_id"`
	LastSeenAt      time.Time      `json:"last_seen_at"`
}

// AzureSecret is one cloud_secret row with its owner's name.
type AzureSecret struct {
	models.CloudSecret
	IdentityName string `json:"identity_name"`
	IdentityKind string `json:"identity_kind"`
}

type cloudAzureRepository struct{ db *gorm.DB }

// NewCloudAzureRepository constructs the repository.
func NewCloudAzureRepository(db *gorm.DB) CloudAzureRepository {
	return &cloudAzureRepository{db: db}
}

func (r *cloudAzureRepository) AllocateGeneration(workspaceID, connectorID uuid.UUID) (int, error) {
	var generation int
	res := r.db.Raw(`
		UPDATE cloud_connector
		   SET scan_generation = scan_generation + 1,
		       updated_at      = now()
		 WHERE workspace_id = ?
		   AND id           = ?
		   AND provider     = ?
		RETURNING scan_generation
	`, workspaceID, connectorID, models.CloudProviderAzure).Scan(&generation)
	if res.Error != nil {
		return 0, res.Error
	}
	if res.RowsAffected == 0 {
		return 0, ErrCloudConnectorNotFound
	}
	return generation, nil
}

func (r *cloudAzureRepository) BeginRun(workspaceID, connectorID uuid.UUID, owner, trigger string, lease time.Duration) (*models.CloudScanRun, error) {
	if owner == "" {
		return nil, errors.New("cloud azure scan: a run needs an owner")
	}
	now := time.Now()
	var run *models.CloudScanRun
	err := r.db.Transaction(func(tx *gorm.DB) error {
		var n int64
		if err := tx.Model(&models.CloudConnector{}).
			Where("workspace_id = ? AND id = ? AND provider = ?", workspaceID, connectorID, models.CloudProviderAzure).
			Count(&n).Error; err != nil {
			return err
		}
		if n == 0 {
			return ErrCloudConnectorNotFound
		}
		// A pass whose lease lapsed belongs to a process that stopped: it will
		// never finish, and as a live run it would block every later pass.
		if err := tx.Model(&models.CloudScanRun{}).
			Where("workspace_id = ? AND connector_id = ? AND status = ? AND lease_expires_at <= ?",
				workspaceID, connectorID, models.CloudScanRunRunning, now).
			Updates(map[string]interface{}{
				"status":           models.CloudScanRunAbandoned,
				"lease_owner":      "",
				"lease_expires_at": nil,
				"last_error":       "the process running this pass stopped before finishing",
				"updated_at":       now,
			}).Error; err != nil {
			return err
		}
		var generation int
		if err := tx.Raw(`
			UPDATE cloud_connector
			   SET scan_generation = scan_generation + 1,
			       updated_at      = now()
			 WHERE workspace_id = ? AND id = ? AND provider = ?
			RETURNING scan_generation
		`, workspaceID, connectorID, models.CloudProviderAzure).Scan(&generation).Error; err != nil {
			return err
		}
		expires := now.Add(lease)
		run = &models.CloudScanRun{
			WorkspaceID:    workspaceID,
			ConnectorID:    connectorID,
			Generation:     generation,
			Status:         models.CloudScanRunRunning,
			Trigger:        trigger,
			LeaseOwner:     owner,
			LeaseExpiresAt: &expires,
			LeaseVersion:   1,
			Attempts:       1,
			RequestedAt:    now,
			StartedAt:      &now,
			UpdatedAt:      now,
			Coverage:       json.RawMessage("{}"),
		}
		// uq_cloud_scan_run_live refuses a second live run for the connector:
		// the arbiter between replicas, which no in-process check can be.
		if err := tx.Create(run).Error; err != nil {
			if isUniqueViolation(err) {
				return ErrScanAlreadyLive
			}
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return run, nil
}

func (r *cloudAzureRepository) RenewRun(runID uuid.UUID, owner string, lease time.Duration) error {
	res := r.db.Model(&models.CloudScanRun{}).
		Where("id = ? AND lease_owner = ? AND status = ?", runID, owner, models.CloudScanRunRunning).
		Updates(map[string]interface{}{"lease_expires_at": time.Now().Add(lease), "updated_at": time.Now()})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrLeaseLost
	}
	return nil
}

func (r *cloudAzureRepository) FinishRun(runID uuid.UUID, owner string, coverage models.ScanCoverage) error {
	raw, err := json.Marshal(coverage)
	if err != nil {
		return err
	}
	now := time.Now()
	updates := map[string]interface{}{
		"lease_owner":      "",
		"lease_expires_at": nil,
		"coverage":         raw,
		"updated_at":       now,
	}
	if coverage.Status == models.ScanStatusFailed {
		updates["status"] = models.CloudScanRunFailed
		updates["last_error"] = firstNonEmptyString(coverage.Error, "the pass read nothing")
	} else {
		// Published means finished, not complete: the coverage stored with it
		// says how much was read, and only a complete one licenses deletion.
		updates["status"] = models.CloudScanRunPublished
		updates["published_at"] = now
	}
	res := r.db.Model(&models.CloudScanRun{}).
		Where("id = ? AND lease_owner = ? AND status = ?", runID, owner, models.CloudScanRunRunning).
		Updates(updates)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrLeaseLost
	}
	return nil
}

func (r *cloudAzureRepository) DueTenants(finishedBefore, runningStartedBefore time.Time) ([]models.CloudConnector, error) {
	var out []models.CloudConnector
	err := r.db.Where(`provider = ? AND scope_kind = ? AND status = ?
		AND (
		      (COALESCE(coverage->>'status', '') <> ?
		       AND (coverage->>'finished_at' IS NULL OR (coverage->>'finished_at')::timestamptz < ?))
		   OR (coverage->>'status' = ?
		       AND (coverage->>'started_at' IS NULL OR (coverage->>'started_at')::timestamptz < ?))
		)`,
		models.CloudProviderAzure, models.CloudScopeTenant, models.CloudConnectorActive,
		models.ScanStatusRunning, finishedBefore,
		models.ScanStatusRunning, runningStartedBefore).
		Order("updated_at").Find(&out).Error
	return out, err
}

func firstNonEmptyString(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func (r *cloudAzureRepository) WriteCoverage(workspaceID, connectorID uuid.UUID, generation int, coverage json.RawMessage) error {
	if len(coverage) == 0 {
		return errors.New("cloud azure scan: refusing to write an empty coverage blob")
	}
	res := r.db.Model(&models.CloudConnector{}).
		Where("workspace_id = ? AND id = ? AND provider = ? AND scan_generation = ?",
			workspaceID, connectorID, models.CloudProviderAzure, generation).
		Updates(map[string]interface{}{
			"coverage":   coverage,
			"updated_at": time.Now(),
		})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrScanSuperseded
	}
	return nil
}

// azureUpsertBatch keeps one INSERT's bind parameters well under Postgres'
// 65535 limit (14 columns per row).
const azureUpsertBatch = 500

func (r *cloudAzureRepository) UpsertResources(workspaceID, connectorID uuid.UUID, generation int, rows []models.CloudResource) (int, error) {
	rows = dedupeLast(rows, func(res models.CloudResource) string { return res.NativeID })
	if len(rows) == 0 {
		return 0, nil
	}
	if err := r.assertAzure(workspaceID, connectorID); err != nil {
		return 0, err
	}
	now := time.Now()
	for i := range rows {
		rows[i].WorkspaceID = workspaceID
		rows[i].ConnectorID = connectorID
		rows[i].LastSeenGeneration = generation
		if rows[i].ID == uuid.Nil {
			rows[i].ID = uuid.New()
		}
		rows[i].FirstSeenAt = now
		rows[i].LastSeenAt = now
		rows[i].RowUpdatedAt = now
	}
	err := r.db.Transaction(func(tx *gorm.DB) error {
		return tx.Clauses(clause.OnConflict{
			Columns: []clause.Column{{Name: "workspace_id"}, {Name: "native_id"}},
			// first_seen_at is kept: a resource's first sighting is evidence.
			// Sensitivity follows AuthSec's rule only while AuthSec's rule set
			// it: a customer's own classification is never stamped over.
			DoUpdates: clause.Assignments(map[string]interface{}{
				"sensitivity": gorm.Expr("CASE WHEN cloud_resource.sensitivity_source = ? THEN EXCLUDED.sensitivity ELSE cloud_resource.sensitivity END",
					models.SensitivityFromHeuristic),
				"sensitivity_reason": gorm.Expr("CASE WHEN cloud_resource.sensitivity_source = ? THEN EXCLUDED.sensitivity_reason ELSE cloud_resource.sensitivity_reason END",
					models.SensitivityFromHeuristic),
				"connector_id":         gorm.Expr("EXCLUDED.connector_id"),
				"kind":                 gorm.Expr("EXCLUDED.kind"),
				"name":                 gorm.Expr("EXCLUDED.name"),
				"resource_account":     gorm.Expr("EXCLUDED.resource_account"),
				"is_external":          gorm.Expr("EXCLUDED.is_external"),
				"object_key":           gorm.Expr("EXCLUDED.object_key"),
				"last_seen_generation": gorm.Expr("EXCLUDED.last_seen_generation"),
				"last_seen_at":         gorm.Expr("EXCLUDED.last_seen_at"),
				"row_updated_at":       gorm.Expr("EXCLUDED.row_updated_at"),
			}),
		}).CreateInBatches(&rows, azureUpsertBatch).Error
	})
	if err != nil {
		return 0, err
	}
	return len(rows), nil
}

func (r *cloudAzureRepository) ListResources(workspaceID uuid.UUID, f AzureListFilter) ([]models.CloudResource, int64, error) {
	azureConnectors := r.db.Model(&models.CloudConnector{}).Select("id").
		Where("workspace_id = ? AND provider = ?", workspaceID, models.CloudProviderAzure)
	q := r.db.Model(&models.CloudResource{}).
		Where("workspace_id = ? AND connector_id IN (?)", workspaceID, azureConnectors)
	if f.ConnectorID != nil {
		q = q.Where("connector_id = ?", *f.ConnectorID)
	}
	if f.Kind != "" {
		q = q.Where("kind = ?", strings.ToLower(f.Kind))
	}
	if f.Search != "" {
		like := "%" + f.Search + "%"
		q = q.Where("(name ILIKE ? OR native_id ILIKE ?)", like, like)
	}
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var out []models.CloudResource
	if err := q.Order("CASE sensitivity WHEN 'high' THEN 0 WHEN 'med' THEN 1 ELSE 2 END, kind, name, id").
		Limit(clampLimit(f.Limit)).Offset(f.Offset).Find(&out).Error; err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

/* ------------------------------ identity discovery ------------------------------ */

// azureConnectorIDs is the subquery every Azure read and delete is bounded by.
func (r *cloudAzureRepository) azureConnectorIDs(workspaceID uuid.UUID) *gorm.DB {
	return r.db.Model(&models.CloudConnector{}).Select("id").
		Where("workspace_id = ? AND provider = ?", workspaceID, models.CloudProviderAzure)
}

// dedupeLast keeps the last row for each conflict key. One INSERT ... ON
// CONFLICT DO UPDATE may not touch the same row twice (SQLSTATE 21000), and a
// provider listing can repeat an object.
func dedupeLast[T any](rows []T, key func(T) string) []T {
	at := make(map[string]int, len(rows))
	out := make([]T, 0, len(rows))
	for _, row := range rows {
		k := key(row)
		if i, ok := at[k]; ok {
			out[i] = row
			continue
		}
		at[k] = len(out)
		out = append(out, row)
	}
	return out
}

func (r *cloudAzureRepository) UpsertIdentities(workspaceID, connectorID uuid.UUID, generation int, rows []models.CloudIdentity) (int, error) {
	rows = dedupeLast(rows, func(i models.CloudIdentity) string { return i.NativeID })
	if len(rows) == 0 {
		return 0, nil
	}
	if err := r.assertAzure(workspaceID, connectorID); err != nil {
		return 0, err
	}
	now := time.Now()
	for i := range rows {
		rows[i].WorkspaceID = workspaceID
		rows[i].ConnectorID = connectorID
		rows[i].LastSeenGeneration = generation
		if rows[i].ID == uuid.Nil {
			rows[i].ID = uuid.New()
		}
		if len(rows[i].Attrs) == 0 {
			rows[i].Attrs = json.RawMessage("{}")
		}
		rows[i].FirstSeenAt, rows[i].LastSeenAt, rows[i].RowUpdatedAt = now, now, now
	}
	err := r.db.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "workspace_id"}, {Name: "native_id"}},
		// first_seen_at is kept: when AuthSec first saw a principal is evidence.
		DoUpdates: clause.Assignments(map[string]interface{}{
			"connector_id": gorm.Expr("EXCLUDED.connector_id"),
			"kind":         gorm.Expr("EXCLUDED.kind"),
			"name":         gorm.Expr("EXCLUDED.name"),
			"created_at":   gorm.Expr("EXCLUDED.created_at"),
			"enabled":      gorm.Expr("EXCLUDED.enabled"),
			"attrs":        gorm.Expr("EXCLUDED.attrs"),
			// nil is UNKNOWN (sign-in activity not read this pass), never
			// "unused": keep what an earlier pass learned.
			"last_used_at":         gorm.Expr("COALESCE(EXCLUDED.last_used_at, cloud_identity.last_used_at)"),
			"last_seen_generation": gorm.Expr("EXCLUDED.last_seen_generation"),
			"last_seen_at":         gorm.Expr("EXCLUDED.last_seen_at"),
			"row_updated_at":       gorm.Expr("EXCLUDED.row_updated_at"),
		}),
	}).CreateInBatches(&rows, azureUpsertBatch).Error
	if err != nil {
		return 0, err
	}
	return len(rows), nil
}

func (r *cloudAzureRepository) UpsertSecrets(workspaceID, connectorID uuid.UUID, generation int, rows []models.CloudSecret) (int, error) {
	rows = dedupeLast(rows, func(s models.CloudSecret) string { return s.NativeID })
	if len(rows) == 0 {
		return 0, nil
	}
	if err := r.assertAzure(workspaceID, connectorID); err != nil {
		return 0, err
	}
	now := time.Now()
	for i := range rows {
		rows[i].WorkspaceID = workspaceID
		rows[i].ConnectorID = connectorID
		rows[i].LastSeenGeneration = generation
		if rows[i].ID == uuid.Nil {
			rows[i].ID = uuid.New()
		}
		if len(rows[i].Attrs) == 0 {
			rows[i].Attrs = json.RawMessage("{}")
		}
		rows[i].FirstSeenAt, rows[i].LastSeenAt, rows[i].RowUpdatedAt = now, now, now
	}
	err := r.db.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "workspace_id"}, {Name: "native_id"}},
		DoUpdates: clause.Assignments(map[string]interface{}{
			"connector_id":         gorm.Expr("EXCLUDED.connector_id"),
			"identity_id":          gorm.Expr("EXCLUDED.identity_id"),
			"kind":                 gorm.Expr("EXCLUDED.kind"),
			"created_at":           gorm.Expr("EXCLUDED.created_at"),
			"expires_at":           gorm.Expr("EXCLUDED.expires_at"),
			"status":               gorm.Expr("EXCLUDED.status"),
			"attrs":                gorm.Expr("EXCLUDED.attrs"),
			"last_used_at":         gorm.Expr("COALESCE(EXCLUDED.last_used_at, cloud_secret.last_used_at)"),
			"last_seen_generation": gorm.Expr("EXCLUDED.last_seen_generation"),
			"last_seen_at":         gorm.Expr("EXCLUDED.last_seen_at"),
			"row_updated_at":       gorm.Expr("EXCLUDED.row_updated_at"),
		}),
	}).CreateInBatches(&rows, azureUpsertBatch).Error
	if err != nil {
		return 0, err
	}
	return len(rows), nil
}

func (r *cloudAzureRepository) UpsertPermissions(workspaceID, connectorID uuid.UUID, generation int, rows []models.CloudPermission) (int, error) {
	rows = dedupeLast(rows, func(p models.CloudPermission) string {
		res := ""
		if p.ResourceID != nil {
			res = p.ResourceID.String()
		}
		return p.IdentityID.String() + "|" + p.NativeID + "|" + res
	})
	if len(rows) == 0 {
		return 0, nil
	}
	if err := r.assertAzure(workspaceID, connectorID); err != nil {
		return 0, err
	}
	now := time.Now()
	for i := range rows {
		rows[i].WorkspaceID = workspaceID
		rows[i].ConnectorID = connectorID
		rows[i].LastSeenGeneration = generation
		if rows[i].ID == uuid.Nil {
			rows[i].ID = uuid.New()
		}
		rows[i].FirstSeenAt, rows[i].LastSeenAt, rows[i].RowUpdatedAt = now, now, now
	}
	err := r.db.Clauses(clause.OnConflict{
		// uq_cloud_permission_grant, NULLS NOT DISTINCT: a subscription-wide
		// grant (resource_id NULL) still conflicts with itself.
		Columns: []clause.Column{{Name: "identity_id"}, {Name: "native_id"}, {Name: "resource_id"}},
		DoUpdates: clause.Assignments(map[string]interface{}{
			"connector_id":         gorm.Expr("EXCLUDED.connector_id"),
			"plane":                gorm.Expr("EXCLUDED.plane"),
			"effect":               gorm.Expr("EXCLUDED.effect"),
			"role_name":            gorm.Expr("EXCLUDED.role_name"),
			"actions":              gorm.Expr("EXCLUDED.actions"),
			"not_actions":          gorm.Expr("EXCLUDED.not_actions"),
			"condition":            gorm.Expr("EXCLUDED.condition"),
			"constraint_state":     gorm.Expr("EXCLUDED.constraint_state"),
			"scope_kind":           gorm.Expr("EXCLUDED.scope_kind"),
			"sensitivity":          gorm.Expr("EXCLUDED.sensitivity"),
			"last_seen_generation": gorm.Expr("EXCLUDED.last_seen_generation"),
			"last_seen_at":         gorm.Expr("EXCLUDED.last_seen_at"),
			"row_updated_at":       gorm.Expr("EXCLUDED.row_updated_at"),
		}),
	}).CreateInBatches(&rows, azureUpsertBatch).Error
	if err != nil {
		return 0, err
	}
	return len(rows), nil
}

// azureLookupChunk bounds one IN (...) list.
const azureLookupChunk = 1000

func (r *cloudAzureRepository) IdentityIDs(workspaceID uuid.UUID, nativeIDs []string) (map[string]uuid.UUID, error) {
	return r.lookupIDs(&models.CloudIdentity{}, workspaceID, nativeIDs)
}

func (r *cloudAzureRepository) ResourceIDs(workspaceID uuid.UUID, nativeIDs []string) (map[string]uuid.UUID, error) {
	return r.lookupIDs(&models.CloudResource{}, workspaceID, nativeIDs)
}

func (r *cloudAzureRepository) lookupIDs(model interface{}, workspaceID uuid.UUID, nativeIDs []string) (map[string]uuid.UUID, error) {
	out := make(map[string]uuid.UUID, len(nativeIDs))
	for start := 0; start < len(nativeIDs); start += azureLookupChunk {
		end := start + azureLookupChunk
		if end > len(nativeIDs) {
			end = len(nativeIDs)
		}
		var rows []struct {
			ID       uuid.UUID
			NativeID string
		}
		err := r.db.Model(model).Select("id, native_id").
			Where("workspace_id = ? AND native_id IN ? AND connector_id IN (?)",
				workspaceID, nativeIDs[start:end], r.azureConnectorIDs(workspaceID)).
			Scan(&rows).Error
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			out[row.NativeID] = row.ID
		}
	}
	return out, nil
}

func (r *cloudAzureRepository) Reconcile(workspaceID, connectorID uuid.UUID, generation int, parts AzureReconcileParts) (AzureReconcileCounts, error) {
	var counts AzureReconcileCounts
	if err := r.assertAzure(workspaceID, connectorID); err != nil {
		return counts, err
	}
	// Children before parents, so each count is the table's own stale rows,
	// not rows a cascade took along. An identity that left the directory still
	// takes with it what other connectors recorded for it (Azure RBAC grants,
	// federation edges): a deleted principal holds nothing.
	steps := []struct {
		on    bool
		model interface{}
		n     *int64
		// kinds narrows a workload step to its owner's runtime kinds.
		kinds string
	}{
		{parts.Permissions, &models.CloudPermission{}, &counts.Permissions, ""},
		{parts.Usage, &models.CloudUsage{}, &counts.Usage, ""},
		{parts.Edges, &models.CloudAssumeEdge{}, &counts.Edges, ""},
		{parts.Secrets, &models.CloudSecret{}, &counts.Secrets, ""},
		{parts.Workloads, &models.CloudWorkload{}, &counts.Workloads, "runtime_kind NOT IN ?"},
		{parts.Foundry, &models.CloudWorkload{}, &counts.Foundry, "runtime_kind IN ?"},
		{parts.Resources, &models.CloudResource{}, &counts.Resources, ""},
		{parts.Identities, &models.CloudIdentity{}, &counts.Identities, ""},
	}
	err := r.db.Transaction(func(tx *gorm.DB) error {
		for _, st := range steps {
			if !st.on {
				continue
			}
			q := tx.Where("workspace_id = ? AND connector_id = ? AND last_seen_generation < ?",
				workspaceID, connectorID, generation)
			if st.kinds != "" {
				q = q.Where(st.kinds, models.AzureFoundryRuntimeKinds)
			}
			if parts.KeepAgentListed {
				switch st.model.(type) {
				case *models.CloudIdentity:
					q = q.Where("COALESCE(attrs->>'agent_listed', '') <> 'true'")
				case *models.CloudSecret, *models.CloudAssumeEdge:
					q = q.Where(`identity_id NOT IN (SELECT id FROM cloud_identity
						WHERE workspace_id = ? AND attrs->>'agent_listed' = 'true')`, workspaceID)
				case *models.CloudPermission:
					// Derived from the blueprint listing: without it, unknown.
					q = q.Where("strpos(native_id, ?) = 0", models.InheritedGrantMarker)
				}
			}
			res := q.Delete(st.model)
			if res.Error != nil {
				return res.Error
			}
			*st.n = res.RowsAffected
		}
		return nil
	})
	return counts, err
}

func (r *cloudAzureRepository) UpsertAssumeEdges(workspaceID, connectorID uuid.UUID, generation int, rows []models.CloudAssumeEdge) (int, error) {
	rows = dedupeLast(rows, func(e models.CloudAssumeEdge) string {
		return e.IdentityID.String() + "|" + e.SubjectKind + "|" + e.Subject
	})
	if len(rows) == 0 {
		return 0, nil
	}
	if err := r.assertAzure(workspaceID, connectorID); err != nil {
		return 0, err
	}
	now := time.Now()
	for i := range rows {
		e := &rows[i]
		e.WorkspaceID, e.ConnectorID, e.LastSeenGeneration = workspaceID, connectorID, generation
		if e.ID == uuid.Nil {
			e.ID = uuid.New()
		}
		if len(e.Attrs) == 0 {
			e.Attrs = json.RawMessage("{}")
		}
		e.FirstSeenAt, e.LastSeenAt, e.RowUpdatedAt = now, now, now
	}
	err := r.db.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "identity_id"}, {Name: "subject_kind"}, {Name: "subject"}},
		DoUpdates: clause.Assignments(map[string]interface{}{
			"connector_id":         gorm.Expr("EXCLUDED.connector_id"),
			"issuer":               gorm.Expr("EXCLUDED.issuer"),
			"mechanism":            gorm.Expr("EXCLUDED.mechanism"),
			"k8s_ref":              gorm.Expr("EXCLUDED.k8s_ref"),
			"attrs":                gorm.Expr("EXCLUDED.attrs"),
			"last_seen_generation": gorm.Expr("EXCLUDED.last_seen_generation"),
			"last_seen_at":         gorm.Expr("EXCLUDED.last_seen_at"),
			"row_updated_at":       gorm.Expr("EXCLUDED.row_updated_at"),
		}),
	}).CreateInBatches(&rows, azureUpsertBatch).Error
	if err != nil {
		return 0, err
	}
	return len(rows), nil
}

func (r *cloudAzureRepository) UpsertWorkloads(workspaceID, connectorID uuid.UUID, generation int, rows []models.CloudWorkload) (int, error) {
	rows = dedupeLast(rows, func(w models.CloudWorkload) string { return w.NativeID })
	if len(rows) == 0 {
		return 0, nil
	}
	if err := r.assertAzure(workspaceID, connectorID); err != nil {
		return 0, err
	}
	now := time.Now()
	for i := range rows {
		w := &rows[i]
		w.WorkspaceID, w.ConnectorID, w.LastSeenGeneration = workspaceID, connectorID, generation
		if w.ID == uuid.Nil {
			w.ID = uuid.New()
		}
		if len(w.Attrs) == 0 {
			w.Attrs = json.RawMessage("{}")
		}
		w.FirstSeenAt, w.LastSeenAt, w.RowUpdatedAt = now, now, now
	}
	err := r.db.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "workspace_id"}, {Name: "native_id"}},
		DoUpdates: clause.Assignments(map[string]interface{}{
			"connector_id":         gorm.Expr("EXCLUDED.connector_id"),
			"identity_id":          gorm.Expr("EXCLUDED.identity_id"),
			"runtime_kind":         gorm.Expr("EXCLUDED.runtime_kind"),
			"name":                 gorm.Expr("EXCLUDED.name"),
			"region":               gorm.Expr("EXCLUDED.region"),
			"attrs":                gorm.Expr("EXCLUDED.attrs"),
			"last_seen_generation": gorm.Expr("EXCLUDED.last_seen_generation"),
			"last_seen_at":         gorm.Expr("EXCLUDED.last_seen_at"),
			"row_updated_at":       gorm.Expr("EXCLUDED.row_updated_at"),
		}),
	}).CreateInBatches(&rows, azureUpsertBatch).Error
	if err != nil {
		return 0, err
	}
	return len(rows), nil
}

func (r *cloudAzureRepository) UpsertUsage(workspaceID, connectorID uuid.UUID, generation int, rows []models.CloudUsage) (int, error) {
	rows = dedupeLast(rows, func(u models.CloudUsage) string {
		return u.IdentityID.String() + "|" + u.Service + "|" + u.Source
	})
	if len(rows) == 0 {
		return 0, nil
	}
	if err := r.assertAzure(workspaceID, connectorID); err != nil {
		return 0, err
	}
	now := time.Now()
	for i := range rows {
		u := &rows[i]
		u.WorkspaceID, u.ConnectorID, u.LastSeenGeneration = workspaceID, connectorID, generation
		if u.ID == uuid.Nil {
			u.ID = uuid.New()
		}
		if len(u.Attrs) == 0 {
			u.Attrs = json.RawMessage("{}")
		}
		u.FirstSeenAt, u.LastSeenAt, u.RowUpdatedAt = now, now, now
	}
	err := r.db.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "identity_id"}, {Name: "service"}, {Name: "source"}},
		DoUpdates: clause.Assignments(map[string]interface{}{
			"connector_id": gorm.Expr("EXCLUDED.connector_id"),
			// The sign-in window slides: the most recent use AuthSec has seen
			// stands until a newer one replaces it.
			"last_used_at":         gorm.Expr("GREATEST(EXCLUDED.last_used_at, cloud_usage.last_used_at)"),
			"generated_at":         gorm.Expr("EXCLUDED.generated_at"),
			"attrs":                gorm.Expr("EXCLUDED.attrs"),
			"last_seen_generation": gorm.Expr("EXCLUDED.last_seen_generation"),
			"last_seen_at":         gorm.Expr("EXCLUDED.last_seen_at"),
			"row_updated_at":       gorm.Expr("EXCLUDED.row_updated_at"),
		}),
	}).CreateInBatches(&rows, azureUpsertBatch).Error
	if err != nil {
		return 0, err
	}
	return len(rows), nil
}

func (r *cloudAzureRepository) ManagedIdentityIDs(workspaceID uuid.UUID, resourceIDs []string) (map[string]uuid.UUID, error) {
	out := make(map[string]uuid.UUID, len(resourceIDs))
	for start := 0; start < len(resourceIDs); start += azureLookupChunk {
		end := start + azureLookupChunk
		if end > len(resourceIDs) {
			end = len(resourceIDs)
		}
		var rows []struct {
			ID       uuid.UUID
			Resource string
		}
		err := r.db.Model(&models.CloudIdentity{}).
			Select("id, attrs->>'managed_identity_resource' AS resource").
			Where("workspace_id = ? AND kind = ? AND attrs->>'managed_identity_resource' IN ? AND connector_id IN (?)",
				workspaceID, models.CloudIdentityEntraManagedIdentity, resourceIDs[start:end], r.azureConnectorIDs(workspaceID)).
			Scan(&rows).Error
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			out[row.Resource] = row.ID
		}
	}
	return out, nil
}

func (r *cloudAzureRepository) ServicePrincipalIDsByAppID(workspaceID uuid.UUID, appIDs []string) (map[string]uuid.UUID, error) {
	out := make(map[string]uuid.UUID, len(appIDs))
	for start := 0; start < len(appIDs); start += azureLookupChunk {
		end := start + azureLookupChunk
		if end > len(appIDs) {
			end = len(appIDs)
		}
		var rows []struct {
			ID    uuid.UUID
			AppID string
		}
		err := r.db.Model(&models.CloudIdentity{}).
			Select("id, lower(attrs->>'app_id') AS app_id").
			Where("workspace_id = ? AND kind IN ? AND lower(attrs->>'app_id') IN ? AND connector_id IN (?)",
				workspaceID, []string{models.CloudIdentityEntraServicePrincipal, models.CloudIdentityEntraManagedIdentity},
				appIDs[start:end], r.azureConnectorIDs(workspaceID)).
			Scan(&rows).Error
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			out[row.AppID] = row.ID
		}
	}
	return out, nil
}

func (r *cloudAzureRepository) RBACGrants(workspaceID, connectorID uuid.UUID) ([]AzureRBACGrant, error) {
	var out []AzureRBACGrant
	err := r.db.Table("cloud_permission p").
		Select("p.id, p.native_id, p.actions, p.not_actions, i.native_id AS subject_native_id").
		Joins("JOIN cloud_identity i ON i.id = p.identity_id").
		Where("p.workspace_id = ? AND p.connector_id = ? AND p.plane = ? AND p.native_id NOT LIKE ?",
			workspaceID, connectorID, models.PermissionPlaneCloud, "%/accesspolicies/%").
		Scan(&out).Error
	return out, err
}

func (r *cloudAzureRepository) SetLastExercised(workspaceID, connectorID uuid.UUID, at map[uuid.UUID]time.Time) error {
	if len(at) == 0 {
		return nil
	}
	return r.db.Transaction(func(tx *gorm.DB) error {
		for id, t := range at {
			if err := tx.Exec(`UPDATE cloud_permission
				   SET last_exercised_at = GREATEST(last_exercised_at, ?), row_updated_at = now()
				 WHERE workspace_id = ? AND connector_id = ? AND id = ?`,
				t, workspaceID, connectorID, id).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

func (r *cloudAzureRepository) MarkAppPermissionsExercised(workspaceID, tenantConnectorID uuid.UUID) (int64, error) {
	if err := r.assertAzure(workspaceID, tenantConnectorID); err != nil {
		return 0, err
	}
	// An app role resource's native id is "<api service principal>/approles/<role>";
	// a sign-in names the API by its appId (resource_app_id on the usage row),
	// which the API's own service principal carries in attrs.app_id.
	res := r.db.Exec(`
		UPDATE cloud_permission p
		   SET last_exercised_at = GREATEST(p.last_exercised_at, u.last_used_at), row_updated_at = now()
		  FROM cloud_resource res, cloud_identity api, cloud_usage u
		 WHERE p.workspace_id = ? AND p.connector_id = ?
		   AND res.id = p.resource_id AND res.kind = ?
		   AND api.workspace_id = p.workspace_id AND api.native_id = split_part(res.native_id, '/', 1)
		   AND u.workspace_id = p.workspace_id AND u.identity_id = p.identity_id AND u.source = ?
		   AND u.attrs->>'resource_app_id' = api.attrs->>'app_id'
		   AND u.last_used_at IS NOT NULL`,
		workspaceID, tenantConnectorID, models.CloudResourceEntraAppRole, models.UsageSourceEntraSignIn)
	return res.RowsAffected, res.Error
}

func (r *cloudAzureRepository) MergeAttrs(workspaceID, connectorID uuid.UUID, generation int, patch map[string]interface{}) error {
	raw, err := json.Marshal(patch)
	if err != nil {
		return err
	}
	res := r.db.Exec(`
		UPDATE cloud_connector
		   SET attrs      = COALESCE(attrs, '{}'::jsonb) || ?::jsonb,
		       updated_at = now()
		 WHERE workspace_id    = ?
		   AND id              = ?
		   AND provider        = ?
		   AND scan_generation = ?
	`, string(raw), workspaceID, connectorID, models.CloudProviderAzure, generation)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrScanSuperseded
	}
	return nil
}

func (r *cloudAzureRepository) ListIdentities(workspaceID uuid.UUID, f AzureIdentityFilter) ([]models.CloudIdentity, int64, error) {
	q := r.db.Model(&models.CloudIdentity{}).
		Where("workspace_id = ? AND connector_id IN (?)", workspaceID, r.azureConnectorIDs(workspaceID))
	if f.ConnectorID != nil {
		q = q.Where("connector_id = ?", *f.ConnectorID)
	}
	if f.Kind != "" {
		q = q.Where("kind = ?", f.Kind)
	}
	if f.AgentType != "" {
		q = q.Where("attrs->>'agent_type' = ?", f.AgentType)
	}
	if f.Search != "" {
		like := "%" + f.Search + "%"
		q = q.Where("(name ILIKE ? OR native_id ILIKE ? OR attrs->>'user_principal_name' ILIKE ?)", like, like, like)
	}
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var out []models.CloudIdentity
	if err := q.Order("kind, name, id").Limit(clampLimit(f.Limit)).Offset(f.Offset).Find(&out).Error; err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

func (r *cloudAzureRepository) ListGrants(workspaceID uuid.UUID, f AzureGrantFilter) ([]AzureGrant, int64, error) {
	q := r.db.Table("cloud_permission p").
		Joins("JOIN cloud_identity i ON i.id = p.identity_id").
		Joins("LEFT JOIN cloud_resource res ON res.id = p.resource_id").
		Where("p.workspace_id = ? AND p.connector_id IN (?)", workspaceID, r.azureConnectorIDs(workspaceID))
	if f.ConnectorID != nil {
		q = q.Where("p.connector_id = ?", *f.ConnectorID)
	}
	if f.IdentityID != nil {
		q = q.Where("p.identity_id = ?", *f.IdentityID)
	}
	if f.Plane != "" {
		q = q.Where("p.plane = ?", f.Plane)
	}
	if f.Source != "" {
		q = q.Where("("+azureGrantSourceSQL+") = ?", f.Source)
	}
	if f.ResourceID != nil {
		q = q.Where("p.resource_id = ?", *f.ResourceID)
	}
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var out []AzureGrant
	err := q.Select(`p.id, p.connector_id, p.identity_id, i.name AS identity_name, i.kind AS identity_kind,
			p.resource_id, COALESCE(res.name, '') AS resource_name, COALESCE(res.kind, '') AS resource_kind,
			` + azureGrantSourceSQL + ` AS source, strpos(p.native_id, '` + models.InheritedGrantMarker + `') > 0 AS inherited,
			p.condition::text AS condition, p.last_exercised_at,
			p.plane, COALESCE(p.role_name, '') AS role_name,
			p.scope_kind, p.constraint_state, p.sensitivity, p.actions, p.not_actions, p.native_id, p.last_seen_at`).
		Order("CASE p.sensitivity WHEN 'high' THEN 0 WHEN 'med' THEN 1 ELSE 2 END, role_name, identity_name, p.id").
		Limit(clampLimit(f.Limit)).Offset(f.Offset).Scan(&out).Error
	if err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

func (r *cloudAzureRepository) ListFederation(workspaceID uuid.UUID, f AzureListFilter) ([]AzureFederationEdge, int64, error) {
	q := r.db.Table("cloud_assume_edge e").
		Joins("JOIN cloud_identity i ON i.id = e.identity_id").
		Where("e.workspace_id = ? AND e.connector_id IN (?)", workspaceID, r.azureConnectorIDs(workspaceID))
	if f.IdentityID != nil {
		q = q.Where("e.identity_id = ?", *f.IdentityID)
	}
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var out []AzureFederationEdge
	err := q.Select(`e.*, i.name AS identity_name, i.kind AS identity_kind,
			CASE WHEN e.subject_kind = 'identity' THEN (SELECT s.name FROM cloud_identity s
				WHERE s.workspace_id = e.workspace_id AND s.native_id = lower(e.subject) LIMIT 1) END AS subject_name`).
		Order("e.subject_kind, i.name, e.subject, e.id").
		Limit(clampLimit(f.Limit)).Offset(f.Offset).Scan(&out).Error
	if err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

func (r *cloudAzureRepository) ListWorkloads(workspaceID uuid.UUID, f AzureListFilter) ([]AzureWorkload, int64, error) {
	q := r.db.Table("cloud_workload w").
		Joins("LEFT JOIN cloud_identity i ON i.id = w.identity_id").
		Where("w.workspace_id = ? AND w.connector_id IN (?)", workspaceID, r.azureConnectorIDs(workspaceID))
	if f.IdentityID != nil {
		q = q.Where("w.identity_id = ?", *f.IdentityID)
	}
	if f.Kind != "" {
		q = q.Where("w.runtime_kind = ?", strings.ToLower(f.Kind))
	}
	if f.Search != "" {
		like := "%" + f.Search + "%"
		q = q.Where("(w.name ILIKE ? OR w.native_id ILIKE ?)", like, like)
	}
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var out []AzureWorkload
	err := q.Select("w.*, COALESCE(i.name, '') AS identity_name, COALESCE(i.kind, '') AS identity_kind").
		Order("w.runtime_kind, w.name, w.id").
		Limit(clampLimit(f.Limit)).Offset(f.Offset).Scan(&out).Error
	if err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

func (r *cloudAzureRepository) ListFoundry(workspaceID uuid.UUID, connectorID *uuid.UUID) ([]AzureWorkload, []AzureFoundryTrust, error) {
	q := r.db.Table("cloud_workload w").
		Joins("LEFT JOIN cloud_identity i ON i.id = w.identity_id").
		Where("w.workspace_id = ? AND w.connector_id IN (?) AND w.runtime_kind IN ?",
			workspaceID, r.azureConnectorIDs(workspaceID), models.AzureFoundryRuntimeKinds)
	if connectorID != nil {
		q = q.Where("w.connector_id = ?", *connectorID)
	}
	var rows []AzureWorkload
	if err := q.Select("w.*, COALESCE(i.name, '') AS identity_name, COALESCE(i.kind, '') AS identity_kind").
		Order("w.runtime_kind, w.name, w.id").Limit(azureFoundryRowCap).Scan(&rows).Error; err != nil {
		return nil, nil, err
	}
	principals := make([]string, 0, len(rows))
	for _, w := range rows {
		var attrs struct {
			PrincipalID string `json:"principal_id"`
		}
		if json.Unmarshal(w.Attrs, &attrs) == nil && attrs.PrincipalID != "" {
			principals = append(principals, strings.ToLower(attrs.PrincipalID))
		}
	}
	var trusts []AzureFoundryTrust
	if len(principals) == 0 {
		return rows, trusts, nil
	}
	// e1: a federated credential naming the managed identity as its subject.
	// e2: an agent identity whose tokens that credential's holder obtains.
	err := r.db.Table("cloud_assume_edge e1").
		Joins("JOIN cloud_identity h ON h.id = e1.identity_id").
		Joins("LEFT JOIN cloud_assume_edge e2 ON e2.workspace_id = e1.workspace_id AND e2.mechanism = ? AND lower(e2.subject) = lower(h.native_id)",
			models.AssumeMechanismAgentBlueprint).
		Joins("LEFT JOIN cloud_identity a ON a.id = e2.identity_id").
		Where("e1.workspace_id = ? AND e1.connector_id IN (?) AND e1.subject_kind = ? AND lower(e1.subject) IN ?",
			workspaceID, r.azureConnectorIDs(workspaceID), models.AssumeSubjectIdentity, principals).
		Select(`lower(e1.subject) AS principal_id, h.id AS trusted_identity_id, h.name AS trusted_name,
			h.kind AS trusted_kind, COALESCE(h.attrs->>'agent_type', '') AS trusted_agent_type,
			a.id AS agent_identity_id, COALESCE(a.name, '') AS agent_name, COALESCE(a.native_id, '') AS agent_object_id`).
		Order("h.name, a.name").Scan(&trusts).Error
	if err != nil {
		return nil, nil, err
	}
	return rows, trusts, nil
}

func (r *cloudAzureRepository) ListUsage(workspaceID uuid.UUID, f AzureUsageFilter) ([]AzureUsage, int64, error) {
	q := r.db.Table("cloud_usage u").
		Joins("JOIN cloud_identity i ON i.id = u.identity_id").
		Where("u.workspace_id = ? AND u.connector_id IN (?)", workspaceID, r.azureConnectorIDs(workspaceID))
	if f.IdentityID != nil {
		q = q.Where("u.identity_id = ?", *f.IdentityID)
	}
	if f.AIOnly {
		q = q.Where("(u.attrs->>'ai_service')::boolean")
	}
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var out []AzureUsage
	err := q.Select("u.*, i.name AS identity_name, i.kind AS identity_kind").
		Order("u.last_used_at DESC NULLS LAST, i.name, u.service, u.id").
		Limit(clampLimit(f.Limit)).Offset(f.Offset).Scan(&out).Error
	if err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

func (r *cloudAzureRepository) ListSecrets(workspaceID uuid.UUID, f AzureListFilter) ([]AzureSecret, int64, error) {
	q := r.db.Table("cloud_secret s").
		Joins("JOIN cloud_identity i ON i.id = s.identity_id").
		Where("s.workspace_id = ? AND s.connector_id IN (?)", workspaceID, r.azureConnectorIDs(workspaceID))
	if f.IdentityID != nil {
		q = q.Where("s.identity_id = ?", *f.IdentityID)
	}
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var out []AzureSecret
	err := q.Select("s.*, i.name AS identity_name, i.kind AS identity_kind").
		Order("s.expires_at NULLS LAST, s.id").
		Limit(clampLimit(f.Limit)).Offset(f.Offset).Scan(&out).Error
	if err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

func (r *cloudAzureRepository) ScanRuns(workspaceID, connectorID uuid.UUID, limit int) ([]models.CloudScanRun, error) {
	var out []models.CloudScanRun
	err := r.db.Where("workspace_id = ? AND connector_id = ? AND connector_id IN (?)",
		workspaceID, connectorID, r.azureConnectorIDs(workspaceID)).
		Order("requested_at DESC, id DESC").Limit(clampLimit(limit)).Find(&out).Error
	return out, err
}

// assertAzure refuses an id that is not an Azure connector in this workspace,
// before any resource row is written or deleted under it.
func (r *cloudAzureRepository) assertAzure(workspaceID, connectorID uuid.UUID) error {
	var n int64
	if err := r.db.Model(&models.CloudConnector{}).
		Where("workspace_id = ? AND id = ? AND provider = ?", workspaceID, connectorID, models.CloudProviderAzure).
		Count(&n).Error; err != nil {
		return err
	}
	if n == 0 {
		return ErrCloudConnectorNotFound
	}
	return nil
}
