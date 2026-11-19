package platform

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/internal/gcp"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// The Google Cloud console reads: identities, IAM bindings and the resources
// those bindings name. Every query is fenced to the caller's workspace (from
// the token, never the request) and to its GCP connectors.

// gcpKindsParam reads ?kind=a,b (or repeated ?kind=). Empty means every kind.
func gcpKindsParam(c *gin.Context) []string {
	var out []string
	for _, raw := range c.QueryArray("kind") {
		for _, k := range strings.Split(raw, ",") {
			if k = strings.TrimSpace(k); k != "" {
				out = append(out, k)
			}
		}
	}
	return out
}

// ListIdentities handles GET /authsec/discovery/gcp/identities.
func (ctl *CloudGCPController) ListIdentities(c *gin.Context) {
	workspaceID, _, err := ctl.workspaceAndActor(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	id, err := parseOptionalUUID(c.Query("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	connectorID, err := parseOptionalUUID(c.Query("connector_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid connector_id"})
		return
	}
	filter := repositories.GCPIdentityFilter{
		ID: id, ConnectorID: connectorID, Kinds: gcpKindsParam(c),
		Limit: atoiDefault(c.Query("limit"), 100), Offset: atoiDefault(c.Query("offset"), 0),
	}
	rows, total, err := repositories.NewCloudGCPReadRepository(ctl.db).ListIdentities(workspaceID, filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"data": rows,
		"meta": gin.H{
			"as_of": time.Now().UTC(), "total": total, "limit": filter.Limit, "offset": filter.Offset,
			"note": "service accounts, principals named only in IAM bindings, and the project owner of API keys; " +
				"candidate identities, not agents",
		},
	})
}

// ListBindings handles GET /authsec/discovery/gcp/bindings.
func (ctl *CloudGCPController) ListBindings(c *gin.Context) {
	workspaceID, _, err := ctl.workspaceAndActor(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	identityID, err := parseOptionalUUID(c.Query("identity_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid identity_id"})
		return
	}
	resourceID, err := parseOptionalUUID(c.Query("resource_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid resource_id"})
		return
	}
	connectorID, err := parseOptionalUUID(c.Query("connector_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid connector_id"})
		return
	}
	filter := repositories.GCPBindingFilter{
		IdentityID: identityID, ResourceID: resourceID, ConnectorID: connectorID,
		Limit: atoiDefault(c.Query("limit"), 100), Offset: atoiDefault(c.Query("offset"), 0),
	}
	rows, total, err := repositories.NewCloudGCPReadRepository(ctl.db).ListBindings(workspaceID, filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"data": rows,
		"meta": gin.H{
			"as_of": time.Now().UTC(), "total": total, "limit": filter.Limit, "offset": filter.Offset,
			"note": "each binding is stored once, where it is attached; inherited access is not expanded here. " +
				"Conditions are recorded, never evaluated. Basic roles are not expanded into permissions",
		},
	})
}

// ListResources handles GET /authsec/discovery/gcp/resources.
func (ctl *CloudGCPController) ListResources(c *gin.Context) {
	workspaceID, _, err := ctl.workspaceAndActor(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	id, err := parseOptionalUUID(c.Query("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	connectorID, err := parseOptionalUUID(c.Query("connector_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid connector_id"})
		return
	}
	filter := repositories.GCPIdentityFilter{
		ID: id, ConnectorID: connectorID, Kinds: gcpKindsParam(c),
		Limit: atoiDefault(c.Query("limit"), 100), Offset: atoiDefault(c.Query("offset"), 0),
	}
	rows, total, err := repositories.NewCloudGCPReadRepository(ctl.db).ListResources(workspaceID, filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"data": rows,
		"meta": gin.H{
			"as_of": time.Now().UTC(), "total": total, "limit": filter.Limit, "offset": filter.Offset,
			"note": "a resource is here only because it carries its own IAM policy; " +
				"this is not an inventory of everything in the project",
		},
	})
}

// ListEdges handles GET /authsec/discovery/gcp/edges (GCP-4).
//
// identity_id: who can become this identity. With include_scopes=true and a
// service account, edges stored once on its project, folders and organization
// (attrs.via_scope) are included, since they reach it too.
// subject_identity_id: what this identity can become.
func (ctl *CloudGCPController) ListEdges(c *gin.Context) {
	workspaceID, _, err := ctl.workspaceAndActor(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	identityID, err := parseOptionalUUID(c.Query("identity_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid identity_id"})
		return
	}
	subjectID, err := parseOptionalUUID(c.Query("subject_identity_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid subject_identity_id"})
		return
	}
	connectorID, err := parseOptionalUUID(c.Query("connector_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid connector_id"})
		return
	}
	repo := repositories.NewCloudGCPReadRepository(ctl.db)
	filter := repositories.GCPEdgeFilter{
		SubjectIdentityID: subjectID, ConnectorID: connectorID,
		Limit: atoiDefault(c.Query("limit"), 100), Offset: atoiDefault(c.Query("offset"), 0),
	}
	if identityID != nil {
		filter.IdentityIDs = []uuid.UUID{*identityID}
		if c.Query("include_scopes") == "true" {
			above, err := ctl.scopeRowsAbove(repo, workspaceID, *identityID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
			filter.IdentityIDs = append(filter.IdentityIDs, above...)
		}
	}
	rows, total, err := repo.ListEdges(workspaceID, filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"data": rows,
		"meta": gin.H{
			"as_of": time.Now().UTC(), "total": total, "limit": filter.Limit, "offset": filter.Offset,
			"note": "derived from IAM bindings; an edge with attrs.via_scope sits on a project, folder or organization " +
				"and reaches every service account beneath it. Conditions are on the source bindings and are not evaluated",
		},
	})
}

// scopeRowsAbove returns the project/folder/organization rows above a service
// account, read from the workspace's own rows and connector (never another's).
func (ctl *CloudGCPController) scopeRowsAbove(repo *repositories.CloudGCPReadRepository, workspaceID, identityID uuid.UUID) ([]uuid.UUID, error) {
	ids, _, err := repo.ListIdentities(workspaceID, repositories.GCPIdentityFilter{ID: &identityID, Limit: 1})
	if err != nil || len(ids) == 0 || ids[0].Kind != models.CloudIdentityGCPServiceAccount {
		return nil, err
	}
	ident := ids[0]
	a := ident.GCPAttrs()
	const crm = "//cloudresourcemanager.googleapis.com/"
	var natives []string
	if a.ProjectNumber != "" {
		natives = append(natives, crm+"projects/"+a.ProjectNumber)
	}
	if a.ProjectID != "" {
		natives = append(natives, crm+"projects/"+a.ProjectID)
	}
	var connector models.CloudConnector
	if err := ctl.db.Where("workspace_id = ? AND id = ?", workspaceID, ident.ConnectorID).First(&connector).Error; err == nil {
		var tree gcp.ScopeTree
		if raw := connector.GCPAttrs().ScopeTree; len(raw) > 0 && json.Unmarshal(raw, &tree) == nil {
			byKey := map[string]gcp.ScopeNode{}
			parent := ""
			for _, n := range tree.Nodes {
				switch n.Kind {
				case gcp.ScopeNodeFolder:
					byKey["folders/"+n.ID] = n
				case gcp.ScopeNodeOrganization:
					byKey["organizations/"+n.ID] = n
				case gcp.ScopeNodeProject:
					if n.ID == a.ProjectID {
						parent = n.Parent
					}
				}
			}
			for hops := 0; parent != "" && hops < 64; hops++ {
				natives = append(natives, crm+parent)
				next, ok := byKey[parent]
				if !ok {
					break
				}
				parent = next.Parent
			}
		}
	}
	return repo.ScopeIdentityIDsAbove(workspaceID, ident.ConnectorID, natives)
}
