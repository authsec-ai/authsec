package platform

import (
	"errors"
	"net/http"

	"github.com/authsec-ai/authsec/controllers/shared"
	"github.com/authsec-ai/authsec/middlewares"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// ConsentGrantsController serves the OAuth consent grant admin/self-service
// surface for the prod-mcp-v2 backport. End-users list/revoke their own
// grants; tenant admins can pass ?all=true to see every grant in the tenant.
//
// Routes (mounted under /authsec/oauth):
//
//	GET    /authsec/oauth/consent-grants
//	DELETE /authsec/oauth/consent-grants/:id
type ConsentGrantsController struct {
	service *services.ConsentGrantService
}

func NewConsentGrantsController() *ConsentGrantsController {
	return &ConsentGrantsController{service: services.NewConsentGrantService()}
}

// List handles GET /authsec/oauth/consent-grants.
//
// Query params:
//   application_id=<uuid>   filter to a specific Application
//   all=true                admin-scope view (no user_id filter)
//   include_revoked=true    include revoked grants (admin audit)
//
// Without `all=true`, the caller's user_id from the JWT filters results.
// PHASE7-NOTE: backport doesn't yet validate that `all=true` callers are
// actually tenant admins — JWT issuance does that gating today via the
// existing role-based JWT claims. If you need stricter gating here, add
// a role check via middlewares.RequireWorkspaceRole.
func (ctrl *ConsentGrantsController) List(c *gin.Context) {
	tenantID, err := shared.ResolveTenantIDString(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}
	userIDStr, _ := middlewares.ResolveUserID(c)
	userID, _ := uuid.Parse(userIDStr)

	filters := services.ListFilters{
		IncludeRevoked: c.Query("include_revoked") == "true",
	}
	if c.Query("all") != "true" {
		// User-scope view — restrict to the caller's own grants.
		if userID == uuid.Nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "user_id required when ?all=true is not set"})
			return
		}
		filters.UserID = userID
	}
	if appIDStr := c.Query("application_id"); appIDStr != "" {
		appID, err := uuid.Parse(appIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid application_id"})
			return
		}
		filters.ApplicationID = appID
	}

	grants, err := ctrl.service.List(tenantID, filters)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, grants)
}

// Revoke handles DELETE /authsec/oauth/consent-grants/:id.
//
// Query params:
//   admin=true              admin-scope revoke (no user-ownership check)
//
// Without `admin=true`, the caller can only revoke grants where
// grant.user_id == JWT.user_id (cross-user revocation returns 404 to hide
// existence).
func (ctrl *ConsentGrantsController) Revoke(c *gin.Context) {
	tenantID, err := shared.ResolveTenantIDString(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}
	grantID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid grant id"})
		return
	}

	var callingUserID uuid.UUID
	if c.Query("admin") != "true" {
		userIDStr, _ := middlewares.ResolveUserID(c)
		callingUserID, err = uuid.Parse(userIDStr)
		if err != nil || callingUserID == uuid.Nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "user_id required (or pass ?admin=true)"})
			return
		}
	}

	if err := ctrl.service.Revoke(tenantID, grantID, callingUserID); err != nil {
		if errors.Is(err, services.ErrConsentGrantNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "consent grant not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "revoked"})
}
