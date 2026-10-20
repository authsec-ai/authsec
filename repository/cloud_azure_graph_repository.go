package repositories

import (
	"encoding/json"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

/* cloud_azure_graph_repository.go reads the Azure slice of the shared IGA
   graph (provider 'azure', written by internal/azuregraph). Read-only: the
   projector is the only writer. */

// AzureGraphCount is how many graph rows of one kind are in one state.
type AzureGraphCount struct {
	Table string `json:"table"`
	Kind  string `json:"kind"`
	State string `json:"state"`
	Count int64  `json:"count"`
}

// AzureReach is one identity an identity's access flows through: itself, a
// group it is (transitively) a member of, or an identity it can become.
type AzureReach struct {
	IdentityID  uuid.UUID `json:"identity_id"`
	DisplayName string    `json:"display_name"`
	AccountKind string    `json:"account_kind"`
	// Via is self, member_of or can_assume; Depth how many hops away.
	Via   string `json:"via"`
	Depth int    `json:"depth"`
}

// AzureReachGrant is one grant reachable from the identity.
type AzureReachGrant struct {
	EdgeID              uuid.UUID       `json:"edge_id"`
	HolderID            uuid.UUID       `json:"holder_id"`
	HolderName          string          `json:"holder_name"`
	Via                 string          `json:"via"`
	PathKind            string          `json:"path_kind"`
	NativeScope         string          `json:"native_scope"`
	State               string          `json:"state"`
	CalculationState    string          `json:"calculation_state"`
	EffectiveConclusion string          `json:"effective_conclusion"`
	EntitlementKind     string          `json:"entitlement_kind"`
	Rights              json.RawMessage `json:"rights"`
	ResourceName        string          `json:"resource_name"`
	ResourceKind        string          `json:"resource_kind"`
	Sensitivity         string          `json:"sensitivity"`
	LastConfirmedAt     time.Time       `json:"last_confirmed_at"`
}

// AzureBlastRadius is everything one identity can reach in the graph.
type AzureBlastRadius struct {
	Identity *AzureReach       `json:"identity"`
	Reach    []AzureReach      `json:"reach"`
	Grants   []AzureReachGrant `json:"grants"`
}

// AzureEvidence is one receipt: which API said a fact, how complete that read
// was, and how many runs have confirmed it since.
type AzureEvidence struct {
	ID                uuid.UUID       `json:"id"`
	Subject           string          `json:"subject"`
	SubjectNativeID   string          `json:"subject_native_id"`
	SourceAPI         string          `json:"source_api"`
	Surface           string          `json:"surface"`
	SurfaceState      string          `json:"surface_state"`
	ScanRunID         uuid.UUID       `json:"scan_run_id"`
	ObservedAt        time.Time       `json:"observed_at"`
	LastConfirmedAt   *time.Time      `json:"last_confirmed_at,omitempty"`
	ConfirmationCount int             `json:"confirmation_count"`
	Facts             json.RawMessage `json:"facts"`
}

// AzureEvidenceFor returns the evidence behind one Entra object and every
// grant it holds, most recently confirmed first.
func AzureEvidenceFor(db *gorm.DB, workspaceID uuid.UUID, objectID string, limit int) ([]AzureEvidence, error) {
	var out []AzureEvidence
	// TENANT-EXEMPT: a read bound to workspace_id = ? from the authenticated token (Azure graph reads)
	err := db.Raw(`
		SELECT o.id, CASE WHEN o.identity_id IS NOT NULL THEN 'identity' ELSE 'grant' END AS subject,
		       o.subject_native_id, o.source_api, o.surface, o.surface_state, o.scan_run_id,
		       o.observed_at, o.last_confirmed_at, o.confirmation_count, o.sanitized_facts AS facts
		  FROM cloud_observation o
		 WHERE o.workspace_id = ?
		   AND o.connector_id IN (SELECT id FROM cloud_connector WHERE workspace_id = ? AND provider = ?)
		   AND (o.identity_id IN (SELECT id FROM cloud_identity WHERE workspace_id = ? AND native_id = lower(?))
		        OR o.permission_id IN (SELECT p.id FROM cloud_permission p
		                                 JOIN cloud_identity i ON i.id = p.identity_id
		                                WHERE p.workspace_id = ? AND i.native_id = lower(?)))
		 ORDER BY o.identity_id IS NULL, o.last_confirmed_at DESC NULLS LAST, o.id
		 LIMIT ?`,
		workspaceID, workspaceID, models.CloudProviderAzure, workspaceID, objectID, workspaceID, objectID,
		clampLimit(limit)).Scan(&out).Error
	return out, err
}

// azureReachDepth bounds the walk through nested groups and federation: deep
// enough for real nesting, and a stop against a cycle.
const azureReachDepth = 6

// AzureGraphSummary counts the workspace's Azure graph rows by kind and state.
func AzureGraphSummary(db *gorm.DB, workspaceID uuid.UUID) ([]AzureGraphCount, error) {
	var out []AzureGraphCount
	// TENANT-EXEMPT: a read bound to workspace_id = ? from the authenticated token (Azure graph reads)
	err := db.Raw(`
		SELECT 'identity' AS "table", account_kind AS kind, lifecycle AS state, count(*) AS count
		  FROM iga_identity_accounts WHERE workspace_id = ? AND provider = ? GROUP BY 2, 3
		UNION ALL
		SELECT 'resource', resource_kind, lifecycle, count(*)
		  FROM iga_resources WHERE workspace_id = ? AND provider = ? GROUP BY 2, 3
		UNION ALL
		SELECT 'entitlement', native_grant_kind, lifecycle, count(*)
		  FROM iga_entitlements WHERE workspace_id = ? AND provider = ? GROUP BY 2, 3
		UNION ALL
		SELECT 'workload', runtime_kind, lifecycle, count(*)
		  FROM iga_workload WHERE workspace_id = ? AND provider = ? GROUP BY 2, 3
		UNION ALL
		SELECT 'credential', credential_type, lifecycle, count(*)
		  FROM iga_credentials WHERE workspace_id = ? AND provider = ? GROUP BY 2, 3
		UNION ALL
		SELECT 'access_edge', path_kind, state, count(*)
		  FROM iga_access_edges WHERE workspace_id = ? AND provider = ? GROUP BY 2, 3
		UNION ALL
		SELECT 'relationship', relationship_type, state, count(*)
		  FROM iga_relationship WHERE workspace_id = ? AND source_key LIKE ? GROUP BY 2, 3
		ORDER BY 1, 2, 3`,
		workspaceID, models.ProviderAzure, workspaceID, models.ProviderAzure,
		workspaceID, models.ProviderAzure, workspaceID, models.ProviderAzure,
		workspaceID, models.ProviderAzure, workspaceID, models.ProviderAzure,
		workspaceID, models.ProviderAzure+"\x1f%").Scan(&out).Error
	return out, err
}

// AzureBlastRadiusOf walks from one Entra object (by object id) through the
// groups it is a member of and the identities it can become, and returns every
// live grant held anywhere on that path, most sensitive first. A role given
// to a group is reached through membership rather than copied onto the member
// (§2.6), so this walk is where it is attributed.
func AzureBlastRadiusOf(db *gorm.DB, workspaceID uuid.UUID, objectID string) (*AzureBlastRadius, error) {
	var reach []AzureReach
	// TENANT-EXEMPT: a read bound to workspace_id = ? from the authenticated token (Azure graph reads)
	err := db.Raw(`
		WITH RECURSIVE reach(identity_id, via, depth) AS (
		    SELECT id, 'self'::text, 0
		      FROM iga_identity_accounts
		     WHERE workspace_id = ? AND provider = ? AND lifecycle <> 'retired'
		       AND provider_attrs->>'object_id' = lower(?)
		  UNION
		    SELECT r.target_identity_account_id, r.relationship_type, reach.depth + 1
		      FROM iga_relationship r
		      JOIN reach ON r.source_identity_account_id = reach.identity_id
		     WHERE r.workspace_id = ? AND r.state <> 'ended'
		       AND r.relationship_type IN ('member_of', 'can_assume')
		       AND reach.depth < ?
		)
		SELECT DISTINCT ON (i.id) i.id AS identity_id, i.display_name, i.account_kind, reach.via, reach.depth
		  FROM reach JOIN iga_identity_accounts i ON i.id = reach.identity_id
		 ORDER BY i.id, reach.depth`,
		workspaceID, models.ProviderAzure, objectID, workspaceID, azureReachDepth).Scan(&reach).Error
	if err != nil {
		return nil, err
	}
	out := &AzureBlastRadius{Reach: []AzureReach{}, Grants: []AzureReachGrant{}}
	if len(reach) == 0 {
		return out, nil
	}
	ids := make([]uuid.UUID, 0, len(reach))
	via := make(map[uuid.UUID]AzureReach, len(reach))
	for _, r := range reach {
		ids = append(ids, r.IdentityID)
		via[r.IdentityID] = r
		if r.Depth == 0 {
			self := r
			out.Identity = &self
		} else {
			out.Reach = append(out.Reach, r)
		}
	}

	var grants []AzureReachGrant
	// TENANT-EXEMPT: a read bound to workspace_id = ? from the authenticated token (Azure graph reads)
	err = db.Raw(`
		SELECT e.id AS edge_id, e.subject_identity_account_id AS holder_id, i.display_name AS holder_name,
		       e.path_kind, e.native_scope, e.state, e.calculation_state, e.effective_conclusion,
		       COALESCE(en.native_grant_kind, '') AS entitlement_kind,
		       COALESCE(en.native_rights, '{}'::jsonb) AS rights,
		       COALESCE(r.display_name, '') AS resource_name, COALESCE(r.resource_kind, '') AS resource_kind,
		       COALESCE(NULLIF(en.normalized_rights->>'sensitivity', ''), r.provider_attrs->>'sensitivity', 'low') AS sensitivity,
		       e.last_confirmed_at
		  FROM iga_access_edges e
		  JOIN iga_identity_accounts i ON i.id = e.subject_identity_account_id
		  LEFT JOIN iga_entitlements en ON en.id = e.entitlement_id
		  LEFT JOIN iga_resources r ON r.id = e.resource_id
		 WHERE e.workspace_id = ? AND e.provider = ? AND e.state <> 'ended'
		   AND e.subject_identity_account_id IN ?
		 ORDER BY CASE COALESCE(NULLIF(en.normalized_rights->>'sensitivity', ''), r.provider_attrs->>'sensitivity', 'low')
		            WHEN 'high' THEN 0 WHEN 'med' THEN 1 ELSE 2 END,
		          i.display_name, e.path_kind, e.id`,
		workspaceID, models.ProviderAzure, ids).Scan(&grants).Error
	if err != nil {
		return nil, err
	}
	for i := range grants {
		grants[i].Via = via[grants[i].HolderID].Via
	}
	out.Grants = grants
	return out, nil
}
