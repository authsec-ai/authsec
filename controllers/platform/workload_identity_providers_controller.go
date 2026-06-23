package platform

import (
	"net/http"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/controllers/shared"
	"github.com/authsec-ai/authsec/models"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/lib/pq"
)

// WorkloadIdentityProvidersController is workspace-scoped CRUD for the external
// token issuers workloads authenticate with (kind 'spiffe' = a SPIRE trust
// domain for multi-cluster; kind 'oidc' = a generic OIDC issuer such as GitHub
// Actions). The token validator (authenticateSPIFFESVID) resolves issuers from
// this table. Replaces the single global SPIFFE_OIDC_ISSUER env.
//
// Routes (workspace admin JWT):
//
//	GET    /authsec/workload-identity-providers       list
//	POST   /authsec/workload-identity-providers       create
//	DELETE /authsec/workload-identity-providers/:id    delete
type WorkloadIdentityProvidersController struct{}

func NewWorkloadIdentityProvidersController() *WorkloadIdentityProvidersController {
	return &WorkloadIdentityProvidersController{}
}

type listWIPResponse struct {
	Items []models.WorkloadIdentityProvider `json:"items"`
}

type createWIPBody struct {
	Name             string   `json:"name"`
	Kind             string   `json:"kind"` // "spiffe" | "oidc"
	Issuer           string   `json:"issuer"`
	JWKSUri          string   `json:"jwks_uri,omitempty"`
	TrustDomain      string   `json:"trust_domain,omitempty"`
	AllowedAudiences []string `json:"allowed_audiences,omitempty"`
	SubjectClaim     string   `json:"subject_claim,omitempty"`
}

// List handles GET /authsec/workload-identity-providers.
func (ctrl *WorkloadIdentityProvidersController) List(c *gin.Context) {
	wsID, err := shared.ResolveWorkspaceIDFromToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id required in JWT"})
		return
	}
	var items []models.WorkloadIdentityProvider
	if err := config.DB.WithContext(c.Request.Context()).
		Where("workspace_id = ?", wsID).
		Order("created_at DESC").
		Find(&items).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "message": "couldn't list providers"})
		return
	}
	if items == nil {
		items = []models.WorkloadIdentityProvider{}
	}
	c.JSON(http.StatusOK, listWIPResponse{Items: items})
}

// Create handles POST /authsec/workload-identity-providers.
func (ctrl *WorkloadIdentityProvidersController) Create(c *gin.Context) {
	wsID, err := shared.ResolveWorkspaceIDFromToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id required in JWT"})
		return
	}
	var body createWIPBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "message": err.Error()})
		return
	}
	if body.Name == "" || body.Issuer == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "message": "name and issuer are required"})
		return
	}
	kind := body.Kind
	if kind == "" {
		kind = "spiffe"
	}
	if kind != "spiffe" && kind != "oidc" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "message": "kind must be 'spiffe' or 'oidc'"})
		return
	}
	subjectClaim := body.SubjectClaim
	if subjectClaim == "" {
		subjectClaim = "sub"
	}

	now := time.Now().UTC()
	p := models.WorkloadIdentityProvider{
		ID:               uuid.New(),
		WorkspaceID:      wsID,
		Name:             body.Name,
		Kind:             kind,
		Issuer:           body.Issuer,
		AllowedAudiences: pq.StringArray(body.AllowedAudiences),
		SubjectClaim:     subjectClaim,
		Status:           "active",
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	if p.AllowedAudiences == nil {
		p.AllowedAudiences = pq.StringArray{}
	}
	if body.JWKSUri != "" {
		p.JWKSUri = &body.JWKSUri
	}
	if body.TrustDomain != "" {
		p.TrustDomain = &body.TrustDomain
	}

	if err := config.DB.WithContext(c.Request.Context()).Create(&p).Error; err != nil {
		if isDuplicateKeyError(err) {
			c.JSON(http.StatusConflict, gin.H{"error": "conflict", "message": "a provider for that issuer already exists"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "message": "couldn't create provider"})
		return
	}
	c.JSON(http.StatusCreated, p)
}

// Delete handles DELETE /authsec/workload-identity-providers/:id.
func (ctrl *WorkloadIdentityProvidersController) Delete(c *gin.Context) {
	wsID, err := shared.ResolveWorkspaceIDFromToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id required in JWT"})
		return
	}
	id, perr := uuid.Parse(c.Param("id"))
	if perr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	res := config.DB.WithContext(c.Request.Context()).
		Where("id = ? AND workspace_id = ?", id, wsID).
		Delete(&models.WorkloadIdentityProvider{})
	if res.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}
	if res.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"deleted": id.String()})
}
